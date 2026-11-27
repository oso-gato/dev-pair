#!/usr/bin/env python3
"""Submit and follow a protected dev-pair job through the checklist host adapter."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time

import checklist_candidate as candidate
import host_handoff as h
import job_protocol as p
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private

ROOT = candidate.ROOT
KIT = candidate.KIT
CATALOGUE = ROOT / 'product-jobs'
JOBS = CATALOGUE / 'jobs'
PROFILES = CATALOGUE / 'profiles'
Q_CLIENT = Path('/etc/dev-pair/checklist-client')
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'
HOST_PORT = 19425
TERMINAL = {'passed', 'blocked'}


def plan(raw):
    value = p.loads(raw)
    p.fields(value, 'schema job_id adapter agreement startup_sha256')
    p.number(value['schema'], 1, 1)
    job, agreement = value['job_id'], value['agreement']
    p.require(type(job) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', job), 'invalid product job ID')
    p.require(value['adapter'] == 'checklist-quadlet', 'product job requires an authorized validation adapter')
    p.fields(agreement, 'repository initial_commit brief host_seconds build_seconds turn_seconds')
    p.text(agreement['repository'], 201)
    p.digest(agreement['initial_commit'], 40)
    brief = agreement['brief']
    p.require(type(brief) is str and 0 < len(brief.encode()) <= 5000 and
              all(char in '\n\t' or ord(char) >= 32 for char in brief), 'invalid protected product brief')
    p.number(agreement['host_seconds'], 25, 60)
    p.number(agreement['build_seconds'], 20, 240)
    p.number(agreement['turn_seconds'], 5, 120)
    p.digest(value['startup_sha256'])
    return value


def durable_json(path, value):
    data = p.canonical(value).encode()
    p.require(len(data) <= p.MAX_MESSAGE, 'durable product record exceeds its limit')
    fd, name = tempfile.mkstemp(prefix='.publish-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def agreement_sha(value):
    return p.identity({'adapter': value['adapter'], **value['agreement']})


def source_approval(value):
    agreement = value['agreement']
    raw, approval = candidate.checkout_approval(value['job_id'], agreement['repository'], agreement_sha(value))
    p.require(approval['acquired_commit'] == agreement['initial_commit'] and
              approval['startup_sha256'] == value['startup_sha256'], 'approved acquisition or startup differs from brief')
    return raw, approval


def job_path(job):
    p.require(type(job) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', job), 'invalid product job ID')
    return JOBS / job


def registered_contract(value):
    agreement = value['agreement']
    return p.envelope('job', job_id=value['job_id'], standards_sha=p.STANDARDS,
                      agreement_sha256=agreement_sha(value),
                      selection={'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
                                 'runtime_sha256': profile(value['job_id'], 'development')['runtime_sha256'],
                                 'verification': 'unverified-record-only'},
                      budgets={'seconds': agreement['host_seconds'], 'artifact_bytes': 8192, 'spend_usd': 0},
                      max_requests=2)


def profile(job, role):
    row = p.loads(candidate.protected_file(PROFILES / job / role / 'profile.json', 8192))
    p.fields(row, 'runtime_sha256 binary_sha256 layout_sha256 credential_ref grant')
    for key in ('runtime_sha256', 'binary_sha256', 'layout_sha256'):
        p.digest(row[key])
    p.token(row['credential_ref'])
    return row


def closed_write(path, body):
    """Replace a protected per-turn seed leaf, preserving its release SELinux label."""
    node = path.lstat()
    p.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1 and
              not node.st_mode & 0o222 and len(body) <= p.MAX_MESSAGE, 'invalid protected turn seed leaf')
    metadata = {key: os.getxattr(path, key) for key in os.listxattr(path)}
    path.unlink()
    write_private(path, body)
    os.chown(path, node.st_uid, node.st_gid)
    path.chmod(stat.S_IMODE(node.st_mode))
    for key, value in metadata.items():
        os.setxattr(path, key, value)
    sync_directory(path.parent)


def proposal(events):
    last = None
    for line in events.splitlines():
        event = json.loads(line)
        item = event.get('item')
        if event.get('type') == 'item.completed' and type(item) is dict and item.get('type') == 'agent_message':
            last = item.get('text')
    p.require(type(last) is str and last, 'development returned no final candidate message')
    last = last.strip()
    fenced = re.fullmatch(r'```(?:json)?\s*([^`]+)\s*```', last, re.DOTALL)
    row = p.loads((fenced[1].strip() if fenced else last).encode())
    p.fields(row, 'candidate_sha summary')
    p.digest(row['candidate_sha'], 40)
    p.text(row['summary'], 1000)
    return row


def read_role(path, uid, limit):
    for part in (path, *path.parents):
        info = part.lstat()
        p.require(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, uid) and not info.st_mode & 0o022,
                  'provider result is outside the protected job placement')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1 and
                  0 < info.st_size <= limit, 'unbound or oversized provider result')
        data = stream.read(limit + 1)
        p.require(len(data) == info.st_size, 'provider result changed while reading')
        return data


class FedoraJob:
    def __init__(self, settings):
        import renewal
        import gptbox_runtime as gptbox
        self.renewal = renewal
        self.gptbox = gptbox
        self.controller = renewal.Renewal(ROOT, renewal.SiteDriver(renewal.DEFAULT_DRIVER),
                                          ledger_user=renewal.LEDGER_USER)
        self.runtime = h.host_runtime()
        self.plan = settings
        self.job = settings['job_id']
        self.agreement = settings['agreement']
        self.agreement_sha = agreement_sha(settings)
        self.approval_raw, self.approval = source_approval(settings)

    def ledger(self, action, body):
        with self.runtime.dispatch_gate():
            uid = pwd.getpwnam(self.runtime.ACCOUNT)
            inputs = self.runtime.HOME / 'conductor-inputs'
            info = inputs.lstat()
            p.require(inputs.resolve(strict=True) == inputs and stat.S_ISDIR(info.st_mode) and
                      info.st_uid == uid.pw_uid and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe ledger transfer leaf')
            with tempfile.NamedTemporaryFile(dir=inputs) as owned:
                os.fchown(owned.fileno(), uid.pw_uid, uid.pw_gid)
                owned.write(p.canonical(body).encode())
                owned.flush()
                os.fsync(owned.fileno())
                output = candidate.invoke(candidate.as_role(self.runtime.ACCOUNT, PYTHON, '-EBs',
                    KIT / 'tools/jobs.py', '--state', self.runtime.HOME / 'ledger', action, owned.name),
                    time.monotonic() + 12)
        p.require(p.loads(output) == body, 'durable ledger acknowledgement changed')

    def build(self, ordinal, revision):
        with self.runtime.dispatch_gate():
            end = time.monotonic() + self.agreement['build_seconds']
            path, admitted = candidate.build(self.job, self.agreement['repository'], self.agreement_sha, revision, end)
            if ordinal == 2:
                candidate.mirror_maintenance(self.job, self.approval, revision, end)
            checkpoint = p.envelope('checkpoint', job_id=self.job, checkpoint_id=self.job + '-c' + str(ordinal),
                                candidate=admitted['candidate'], test=h.recipe_identity(host=True),
                                summary='Source verified in the rootless checklist build adapter',
                                evidence=['candidate-receipt-sha256:' + p.sha256(candidate.protected_file(path))])
            self.ledger('checkpoint', checkpoint)
        return checkpoint

    def stage_turn(self, role, operation, prompt, checkpoint, saved_profile):
        # Seeds are prepared once from the approved role image and its MCS-labelled job layout.
        seed = PROFILES / self.job / role / 'seed'
        self.runtime.protected(seed, file=False)
        configuration = candidate.protected_file(seed / 'loaders/config.toml', 8192)
        requirements = candidate.protected_file(seed / 'requirements/requirements.toml', p.MAX_MESSAGE)
        startup = candidate.protected_file(seed / 'turn/startup/manifest.json', 4096)
        p.require(p.sha256(startup) == self.plan['startup_sha256'] and
                  candidate.protected_file(seed / 'turn/approval.json', 4096) == self.approval_raw,
                  'turn seed is bound to a different startup corpus or repository')
        request = {
            'schema': 2, 'operation': operation, 'action': 'start', 'role': role, 'job': self.job,
            'logical_session': role, 'session_uuid': None, 'workspace': '/work/job', 'provider': 'gptbox',
            'model': 'gpt-6.2-sol', 'effort': 'high', 'standards_sha': p.STANDARDS,
            'repository': self.agreement['repository'], 'candidate_sha': checkpoint['candidate']['source_revision'],
            'agreement_sha256': self.agreement_sha, 'requirements_sha256': p.sha256(requirements),
            'config_sha256': p.sha256(configuration), 'prompt_sha256': p.sha256(prompt),
            'startup_sha256': self.plan['startup_sha256'], 'turn_seconds': self.agreement['turn_seconds'],
        }
        raw = p.canonical(request).encode()
        digest = p.sha256(raw)
        self.gptbox.job_selection(raw, digest, role, self.job, operation)
        target = ROOT / 'turn-inputs' / role / self.job / operation
        self.runtime.protected(target.parent, file=False)
        if os.path.lexists(target):
            p.require(candidate.protected_file(target / 'turn/request.json', 4096) == raw and
                      candidate.protected_file(target / 'turn/prompt.txt', 16384) == prompt, 'staged operation changed')
        else:
            with tempfile.TemporaryDirectory(prefix='.stage-', dir=target.parent) as scratch:
                created = Path(scratch) / 'turn'
                self.renewal.TreeCopy(6 * 1024 * 1024, time.monotonic() + 10).visit(seed, created)
                closed_write(created / 'turn/request.json', raw)
                closed_write(created / 'turn/prompt.txt', prompt)
                p.require(not os.path.lexists(target), 'provider operation already staged')
                created.rename(target)
                sync_directory(target.parent)

        from provider_broker import grant_document, load_allowance
        account = pwd.getpwnam({'maintenance': 'dp-maint', 'development': 'dp-dev'}[role])
        defaults = saved_profile['grant']
        p.require(type(defaults) is dict and not {'schema', 'request_sha256', 'peer_uid', 'peer_gid'} & set(defaults),
                  'provider grant defaults are not a protected profile')
        grant = dict(defaults, schema=1, request_sha256=digest, peer_uid=account.pw_uid, peer_gid=account.pw_gid)
        verified = grant_document(p.canonical(grant).encode())
        load_allowance(self.job, verified['allowance_sha256']).validate_grant(request, verified)
        path = ROOT / 'renewal/provider-grants' / (digest + '.json')
        self.runtime.protected(path.parent, file=False)
        if path.exists():
            p.require(p.loads(candidate.protected_file(path, 8192)) == verified, 'provider grant changed after staging')
        else:
            p.require(verified['expires_unix'] > time.time() + self.agreement['turn_seconds'] + 20,
                      'provider authorization expires before the bounded operation can run')
            durable_json(path, verified)
        return request, digest, account

    def turn(self, role, checkpoint, first=None):
        operation = self.job + ('-maintenance' if role == 'maintenance' else '-development')
        brief = self.agreement['brief']
        if role == 'maintenance':
            prompt = ('Review the approved product brief and confirm the host-only checklist persistence check. '
                      'Use the fixed host recipe. Do not execute administrative commands or change the checkout.\n\n' + brief)
        else:
            diagnostic = p.canonical(first)
            prompt = ('Complete the approved brief in this authorized repository. The durable host check result below '
                      'is tied to the current Git candidate. If it reports a failure, diagnose and repair '
                      'the product. Test locally, commit the candidate, and emit a final JSON object with '
                      'candidate_sha (full 40-character HEAD) and summary (one line). Leave the protected host '
                      'executor and approval alone.\n\nBrief:\n' + brief + '\n\nHost result:\n' + diagnostic)
        raw = prompt.encode()
        p.require(len(raw) <= 16384, 'bound role prompt exceeds its approved limit')
        saved_profile = profile(self.job, role)
        with self.runtime.dispatch_gate():
            request, digest, account = self.stage_turn(role, operation, raw, checkpoint, saved_profile)
        controller, job, live_cp = self.controller.ledger.checkpoint(self.job)
        p.require(live_cp == checkpoint, 'host checkpoint no longer matches the staged role turn')
        binding = {
            'role': role, 'controller_id': controller, 'job_id': self.job, 'checkpoint_id': checkpoint['checkpoint_id'],
            'checkpoint_sha256': p.identity(checkpoint), 'source_sha256': checkpoint['candidate']['artifact_sha256'],
            'runtime_sha256': saved_profile['runtime_sha256'], 'binary_sha256': saved_profile['binary_sha256'],
            'layout_sha256': saved_profile['layout_sha256'], 'policy_sha256': request['config_sha256'],
            'standards_sha': p.STANDARDS, 'agreement_sha256': self.agreement_sha, 'job_sha256': p.identity(job),
            'source_revision': checkpoint['candidate']['source_revision'], 'provider': 'gptbox',
            'model': request['model'], 'effort': request['effort'], 'credential_ref': saved_profile['credential_ref'],
            'startup_sha256': self.plan['startup_sha256'],
        }
        self.controller.register(binding)
        result = self.controller.role_turn({'role': role, 'operation': operation, 'job': self.job,
                                            'logical_session': role, 'session_uuid': None, 'request_sha256': digest}, prompt)
        p.require(result['state'] == 'completed-turn' and result['uuid'] is not None,
                  'role operation remains unresolved in the renewal registry')
        prepared = ROOT / role / 'state' / self.job / 'turns' / operation
        output = p.loads(read_role(prepared / 'result.json', account.pw_uid, 8192))
        events = read_role(prepared / 'events.jsonl', account.pw_uid, 4 * 1024 * 1024)
        p.require(output['request_sha256'] == digest and output['session_uuid'] == result['uuid'] and
                  output['events_sha256'] == p.sha256(events) and output['events_bytes'] == len(events) and
                  output['runtime_admitted'] is True and output['status'] == 'completed-turn' and
                  self.gptbox.completed_turn(events) == result['uuid'], 'retained authenticated role result changed')
        return {'session_uuid': result['uuid'], 'operation': operation, 'events_sha256': output['events_sha256'],
                **(proposal(events) if role == 'development' else {})}

    def host_test(self, ordinal, checkpoint):
        controller, job, checked = self.controller.ledger.checkpoint(self.job)
        p.require(checked == checkpoint, 'host test requires the current durable checkpoint')
        context, peer, principals = h.tls_principal(Q_CLIENT, maintenance=False)
        request = h.produce_request(checkpoint, self.job + '-r' + str(ordinal), controller, principals,
                                    job['budgets'], host=True)

        def exchange(operation):
            try:
                result = h.exchange(HOST_PORT, context, peer, operation, request)
            except OSError as exc:
                # The next bounded worker attempt consults the same durable request first.
                raise BlockingIOError('checklist result transport was interrupted') from exc
            h.check_reply(operation, result, request, controller)
            return result

        try:
            status = exchange('status')
        except ValueError as exc:
            if str(exc) != 'unknown request':
                raise
            status = None
        if status is None or status['state'] == 'pending':
            with self.runtime.dispatch_gate():
                source = checkpoint['candidate']['source_revision']
                receipt = candidate.envelope_path(self.job, source)
                record = self.runtime.issue_approval(receipt, request, 300)
                self.runtime.publish_approval(record)
                if status is None:
                    exchange('submit')
                exchange('execute')
        elif status['state'] == 'in-flight':
            exchange('reconcile')
        return exchange('consume')


def execute(value, state, backend, save):
    def step(key, phase, action, *args):
        if state[key] is None:
            state['phase'] = phase
            save(state)
            state[key] = action(*args)
            save(state)
        return state[key]

    initial = step('initial', 'building', backend.build, 1, value['agreement']['initial_commit'])
    step('maintenance', 'maintenance-turn', backend.turn, 'maintenance', initial)
    first = step('first', 'host-check', backend.host_test, 1, initial)
    p.require(first['progress'] in ('host-checks-passed', 'repair-required'), 'first host check is blocked')
    developed = step('development', 'development-turn', backend.turn, 'development', initial, first)
    revised = developed['candidate_sha']
    if revised == initial['candidate']['source_revision']:
        p.require(first['progress'] == 'host-checks-passed', 'DevBox did not produce a changed candidate after failure')
        state['final'] = first
    else:
        repaired = step('repair', 'building-repair', backend.build, 2, revised)
        result = step('final', 'host-retest', backend.host_test, 2, repaired)
        p.require(result['progress'] == 'host-checks-passed', 'the reviewed retest budget ended without a pass')
    state['phase'] = 'passed'
    save(state)


def read_state(root):
    return p.loads(read_private(root / 'state.json', p.MAX_MESSAGE))


def work(job):
    root = trusted_directory(job_path(job))
    value = plan(read_private(root / 'plan.json', p.MAX_MESSAGE))
    p.require(value['job_id'] == job, 'durable product plan identity changed')
    lock_path = trusted_directory(CATALOGUE) / 'owner.lock'
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(lock_path, flags), 'rb') as lock:
        p.private_file(lock_path)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = read_state(root)
        if state['phase'] in TERMINAL:
            return state
        try:
            backend = FedoraJob(value)
            backend.ledger('job', registered_contract(value))
            execute(value, state, backend, lambda item: durable_json(root / 'state.json', item))
        except BlockingIOError:
            raise
        except (OSError, ValueError, KeyError, ImportError, subprocess.SubprocessError) as exc:
            if str(exc) in ('checklist dispatch is frozen by renewal', 'role dispatch frozen by renewal'):
                raise BlockingIOError('renewal owns dispatch') from exc
            state['failed_stage'] = state['phase']
            state['phase'] = 'blocked'
            reason = str(exc) if type(exc) is ValueError else type(exc).__name__
            state['diagnostics'] = h.bounded_diagnostic(reason)
            durable_json(root / 'state.json', state)
        return state


def submit(path):
    raw = candidate.protected_file(path)
    value = plan(raw)
    source_approval(value)
    parent, target = trusted_directory(JOBS), job_path(value['job_id'])
    if not os.path.lexists(target):
        with tempfile.TemporaryDirectory(prefix='.submit-', dir=parent) as scratch:
            owned = Path(scratch) / 'job'
            owned.mkdir(mode=0o700)
            write_private(owned / 'plan.json', p.canonical(value).encode())
            status = dict.fromkeys(('initial', 'maintenance', 'first', 'development', 'repair', 'final'))
            status.update(job_id=value['job_id'], phase='submitted', agreement_sha256=agreement_sha(value),
                          repository=value['agreement']['repository'], startup_sha256=value['startup_sha256'])
            write_private(owned / 'state.json', p.canonical(status).encode())
            sync_directory(owned)
            try:
                owned.rename(target)
            except OSError:
                p.require(target.exists(), 'durable job publication failed')
            sync_directory(parent)
    target = trusted_directory(target)
    p.require(plan(read_private(target / 'plan.json', p.MAX_MESSAGE)) == value, 'job ID is already bound to another brief')
    candidate.invoke([SYSTEMCTL, 'start', '--no-block', 'dev-pair-product@' + value['job_id'] + '.service'],
                     time.monotonic() + 10)
    return read_state(target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    entries = parser.add_subparsers(dest='action', required=True)
    entries.add_parser('submit').add_argument('approved_plan', type=Path)
    entries.add_parser('agreement-id').add_argument('approved_plan', type=Path)
    for action in ('status', 'reattach', 'work'):
        entries.add_parser(action).add_argument('job')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        p.require(os.geteuid() == 0, 'authorized product controller required')
        if args.action == 'agreement-id':
            print(agreement_sha(plan(candidate.protected_file(args.approved_plan))))
            return 0
        if args.action == 'submit':
            result = submit(args.approved_plan)
        elif args.action == 'work':
            result = work(args.job)
        else:
            root = trusted_directory(job_path(args.job))
            previous = None
            end = time.monotonic() + 120
            while True:
                result = read_state(root)
                if args.action == 'status' or result['phase'] in TERMINAL or time.monotonic() >= end:
                    break
                if result != previous:
                    print(p.canonical(result), flush=True)
                    previous = result
                time.sleep(1)
        print(p.canonical(result), flush=True)
        return 2 if result['phase'] == 'blocked' else 0
    except BlockingIOError:
        return 75
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, 'Product job unavailable (' + type(exc).__name__ + ').\n')


if __name__ == '__main__':
    raise SystemExit(main())
