#!/usr/bin/env python3
"""Submit and follow a protected dev-pair product job."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import ssl
import stat
import subprocess
import tempfile
import time
import uuid

import candidate_git
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
CHECKLIST_ADAPTER = 'checklist-quadlet'
LOCAL_ADAPTER = 'devbox-development'
EXTERNAL_ADAPTER = 'devbox-development-needs-host'
TERMINAL = {'passed', 'blocked', 'local-validation-recorded', 'awaiting-external-validation'}
LOCAL_HEAD_MARKER = 'dev-pair-local-head:'
LOCAL_HEAD_COMMAND = (
    'test -z "$(/usr/bin/git -C /work/job status --porcelain=v1 --untracked-files=all)" && '
    """printf 'dev-pair-local-head:%s\\n' "$(/usr/bin/git -C /work/job rev-parse --verify HEAD)" """
).strip()
LOCAL_TEST_PREFIX = 'cd /work/job && ' + LOCAL_HEAD_COMMAND + ' && ('
LOCAL_TEST_SUFFIX = ') && ' + LOCAL_HEAD_COMMAND
RENEWAL_PAUSES = {'checklist dispatch is frozen by renewal', 'role dispatch frozen by renewal',
                  'role dispatch frozen pending host observation'}
RETRY_SECONDS = 180
RETRY_OBSERVATIONS = 18
RETRY_INTERVAL = 10


class HostReplyLost(BlockingIOError):
    def __init__(self, operation):
        super().__init__('checklist result transport was interrupted')
        self.operation = operation


def plan(raw):
    value = p.loads(raw)
    p.fields(value, 'schema job_id adapter agreement startup_sha256')
    p.number(value['schema'], 1, 1)
    job, agreement = value['job_id'], value['agreement']
    p.require(type(job) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', job), 'invalid product job ID')
    p.require(value['adapter'] in (CHECKLIST_ADAPTER, LOCAL_ADAPTER, EXTERNAL_ADAPTER),
              'product job requires an authorized validation adapter')
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


def proposal(events, *, local=False, source=False):
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
    blocker = (local or source) and type(row) is dict and 'validation_blocker' in row
    revision = 'base_sha' if source else 'candidate_sha'
    p.fields(row, revision + ' summary' + (' validation_blocker' if blocker else ''))
    p.digest(row[revision], 40)
    p.text(row['summary'], 1000)
    if blocker:
        p.text(row['validation_blocker'], 500)
        return row
    if source:
        row['local_validation'] = observed_source_validation(events)
    elif local:
        row['local_validation'] = observed_validation(events, row['candidate_sha'])
    return row


def local_validation_script(command, prefix, suffix):
    if type(command) is not str or not 0 < len(command.encode()) <= 12288:
        return False
    if command.startswith(prefix):
        script = command
    else:
        try:
            argv = shlex.split(command)
        except ValueError:
            return False
        if (len(argv) < 3 or argv[0] not in ('bash', 'sh', '/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh')
                or argv[1:-1] not in (['-c'], ['-lc'], ['-l', '-c'])):
            return False
        script = argv[-1]
    return (script.startswith(prefix) and script.endswith(suffix) and bool(script[len(prefix):-len(suffix)].strip()))


def observed_validation(events, revision):
    """Read a stock command result and its Git witness from the retained turn."""
    matched = observed_command(events, LOCAL_HEAD_MARKER, 40, LOCAL_TEST_PREFIX, LOCAL_TEST_SUFFIX, expected=revision)
    p.require(matched is not None, 'no successful stock test witnessed the final commit before and after local validation')
    return dict(matched[1], candidate_sha=revision)


def observed_source_validation(events):
    prefix, suffix = candidate_git.witness()
    matched = observed_command(events, candidate_git.snapshot.MARKER, 64, prefix, suffix)
    p.require(matched is not None, 'no successful stock test witnessed the same source bytes before and after local validation')
    return dict(matched[1], snapshot_sha256=matched[0])


def observed_command(events, marker, digest_length, prefix, suffix, *, expected=None):
    starts, matched = {}, None
    for line in events.splitlines():
        event = json.loads(line)
        item = event.get('item')
        if type(item) is not dict or item.get('type') != 'command_execution':
            continue
        item_id, command = item.get('id'), item.get('command')
        if type(item_id) is not str or not re.fullmatch(r'item_[0-9]{1,6}', item_id):
            continue
        if event.get('type') == 'item.started':
            if local_validation_script(command, prefix, suffix):
                p.require(item_id not in starts, 'duplicate stock local validation start')
                starts[item_id] = command
        elif event.get('type') == 'item.completed' and item_id in starts:
            started_command = starts.pop(item_id)
            output = item.get('aggregated_output')
            if command != started_command or type(output) is not str:
                continue
            lines = output.splitlines()
            if not lines or not lines[0].startswith(marker):
                continue
            observed = lines[0][len(marker):]
            if not re.fullmatch('[0-9a-f]{%s}' % digest_length, observed) or expected is not None and observed != expected:
                continue
            matched = None
            if (item.get('status') == 'completed' and type(item.get('exit_code')) is int and item['exit_code'] == 0
                    and len(lines) >= 2 and lines[-1] == lines[0] and
                    [row for row in lines if row.startswith(marker)] == [lines[0], lines[0]]):
                matched = (observed, {'item_id': item_id, 'exit_status': 0,
                                    'command_sha256': p.sha256(command.encode()), 'output_sha256': p.sha256(output.encode())})
    return matched


def local_recipe():
    implementation = p.sha256(Path(__file__).read_bytes())
    return {'recipe': 'devbox-local-command-observation-v1',
            'revision': implementation, 'recipe_sha256': implementation}


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
        if self.plan['adapter'] != CHECKLIST_ADAPTER:
            return self.local_checkpoint(ordinal, revision)
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

    def local_checkpoint(self, ordinal, revision):
        with self.runtime.dispatch_gate():
            end = time.monotonic() + self.agreement['build_seconds']
            app = ROOT / 'development/workspaces' / self.job
            git = candidate.git_runner(app, 'dp-dev', end)
            tree = candidate.approved_checkout(git, app, self.approval, revision)
            p.require(not git('status', '--porcelain=v1', '--untracked-files=all'),
                      'development candidate has retained changes outside the tested commit')
            if ordinal == 2:
                candidate.mirror_maintenance(self.job, self.approval, revision, end, checklist=False)
                mirror = ROOT / 'maintenance/workspaces' / self.job
                target = candidate.git_runner(mirror, 'dp-maint', end)
                p.require(candidate.approved_checkout(target, mirror, self.approval, revision) == tree and
                          not target('status', '--porcelain=v1', '--untracked-files=all'),
                          'maintenance candidate differs from the tested commit')
                p.require(candidate.approved_checkout(git, app, self.approval, revision) == tree and
                          not git('status', '--porcelain=v1', '--untracked-files=all'),
                          'development candidate changed during final verification')
            source = p.identity({'repository': self.agreement['repository'], 'revision': revision, 'tree': tree})
            checkpoint = p.envelope('checkpoint', job_id=self.job, checkpoint_id=self.job + '-c' + str(ordinal),
                candidate={'source_revision': revision, 'artifact_sha256': source}, test=local_recipe(),
                summary='Verified Git candidate and tree for confined DevBox validation', evidence=['git-tree:' + tree])
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
        local = self.plan['adapter'] != CHECKLIST_ADAPTER
        if local and role == 'maintenance':
            prompt = ('Review the agreed product outcome and validation scope. Inspect the approved repository read-only. '
                      'Record which validation is possible in DevBox and which requested boundary needs a separate adapter. '
                      'Keep the checkout clean. Take no host or external actions.\n\n' + brief)
        elif role == 'maintenance':
            prompt = ('Review the approved product brief and confirm the host-only checklist persistence check. '
                      'Use the fixed host recipe. Do not execute administrative commands or change the checkout.\n\n' + brief)
        else:
            prefix, suffix = candidate_git.witness()
            context = ('Record agreed scope, acceptance and validation boundaries in the project requirements and architecture.'
                       if local else 'Use the durable host result below to diagnose and repair the checklist.')
            prompt = ('Implement the approved agreement in this confined DevBox workspace. ' + context +
                      '\nLeave intended source edits and new source files in place for the trusted candidate publisher. '
                      'Git metadata is read-only. Use the declared build directory for generated files. '
                      'External operations require a separate admitted adapter. Run a real relevant local test with this '
                      'exact prefix and suffix around the repository test command:\n' +
                      prefix + '<repo test command>' + suffix +
                      '\nThe witness must report the same source digest before and after the test. End with only JSON '
                      'containing base_sha (the unchanged full Git HEAD) and summary (one line). '
                      'If the agreed check cannot run, also include validation_blocker (one line).\n\n' + brief)
            if not local:
                prompt += '\n\nHost result:\n' + p.canonical(first)
        raw = prompt.encode()
        p.require(len(raw) <= 16384, 'bound role prompt exceeds its approved limit')
        saved_profile = profile(self.job, role)
        with self.runtime.dispatch_gate():
            if role == 'development':
                self.approve_development_base(operation, checkpoint)
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
                  output.get('owned_cleanup') == 'reaped' and
                  self.gptbox.completed_turn(events) == result['uuid'], 'retained authenticated role result changed')
        return {'session_uuid': result['uuid'], 'operation': operation, 'events_sha256': output['events_sha256'],
                'request_sha256': digest, **(proposal(events, source=True) if role == 'development' else {})}

    def approve_development_base(self, operation, checkpoint):
        base = checkpoint['candidate']['source_revision']
        path = trusted_directory(job_path(self.job)) / 'development-base.json'
        value = {'operation': operation, 'job_id': self.job, 'base_sha': base,
                 'checkpoint_sha256': p.identity(checkpoint), 'agreement_sha256': self.agreement_sha}
        if os.path.lexists(path):
            saved = p.loads(read_private(path, 4096))
            snapshot_sha256 = saved.pop('base_snapshot_sha256')
            p.digest(snapshot_sha256)
            p.require(saved == value, 'development operation base changed')
            return
        self.runtime.protected(candidate_git.SCANNER, file=True)
        end = time.monotonic() + 25
        workspace, git = candidate_git.workspace_at(ROOT, self.job, base, self.approval, end)
        p.require(not git('status', '--porcelain=v1', '--untracked-files=all', cap=candidate_git.GIT_METADATA),
                  'development source contains prior work outside this operation')
        baseline, _ = candidate_git.capture(workspace, git, end)
        durable_json(path, dict(value, base_snapshot_sha256=baseline))

    def materialize(self, checkpoint, development):
        p.require(development['operation'] == self.job + '-development' and
                  development['base_sha'] == checkpoint['candidate']['source_revision'],
                  'tested source no longer matches the authorized development operation')
        observed = development['local_validation']
        p.require(observed['exit_status'] == 0, 'local test must pass before materializing the candidate')
        p.require(str(uuid.UUID(development['session_uuid'])) == development['session_uuid'],
                  'candidate publication requires the original authenticated session')
        for name in ('events_sha256', 'request_sha256'):
            p.digest(development[name])
        p.digest(observed['snapshot_sha256'])
        root = trusted_directory(job_path(self.job))
        binding = dict(job_id=self.job, operation=development['operation'], base_sha=development['base_sha'],
                       checkpoint_sha256=p.identity(checkpoint), agreement_sha256=self.agreement_sha,
                       approval_sha256=p.sha256(self.approval_raw), startup_sha256=self.plan['startup_sha256'],
                       session_uuid=development['session_uuid'], events_sha256=development['events_sha256'],
                       request_sha256=development['request_sha256'], snapshot_sha256=observed['snapshot_sha256'],
                       validation_sha256=p.identity(observed))
        with self.runtime.dispatch_gate():
            _, _, current = self.controller.ledger.checkpoint(self.job)
            p.require(current == checkpoint, 'authoritative checkpoint changed before candidate publication')
            before = p.loads(read_private(root / 'development-base.json', 4096))
            binding['base_snapshot_sha256'] = before.pop('base_snapshot_sha256')
            p.digest(binding['base_snapshot_sha256'])
            p.require(before == {key: binding[key] for key in (
                'operation', 'job_id', 'base_sha', 'checkpoint_sha256', 'agreement_sha256')},
                'candidate publication lacks the authorized original checkout')
            self.runtime.protected(candidate_git.SCANNER, file=True)
            role = pwd.getpwnam('dp-dev')
            path = ROOT / 'development/state' / self.job / 'turns' / development['operation']
            output = p.loads(read_role(path / 'result.json', role.pw_uid, 8192))
            events = read_role(path / 'events.jsonl', role.pw_uid, 4 * 1024 * 1024)
            p.require(output.get('owned_cleanup') == 'reaped' and output.get('runtime_admitted') is True and
                      output.get('status') == 'completed-turn' and
                      output.get('request_sha256') == binding['request_sha256'] and
                      output.get('session_uuid') == binding['session_uuid'] and
                      output.get('events_sha256') == binding['events_sha256'] == p.sha256(events) and
                      output.get('events_bytes') == len(events) and self.gptbox.completed_turn(events) == binding['session_uuid'] and
                      observed_source_validation(events) == observed,
                      'retained role termination or tested source evidence changed')
            return candidate_git.materialize(ROOT, root, self.approval, binding,
                                             time.monotonic() + self.agreement['build_seconds'])

    def host_test(self, ordinal, checkpoint):
        controller, job, checked = self.controller.ledger.checkpoint(self.job)
        p.require(checked == checkpoint, 'host test requires the current durable checkpoint')
        context, peer, principals = h.tls_principal(Q_CLIENT, maintenance=False)
        request = h.produce_request(checkpoint, self.job + '-r' + str(ordinal), controller, principals,
                                    job['budgets'], host=True)

        def exchange(operation):
            try:
                result = h.exchange(HOST_PORT, context, peer, operation, request)
            except (ConnectionError, TimeoutError, ssl.SSLEOFError) as exc:
                raise HostReplyLost(operation) from exc
            except ValueError as exc:
                if str(exc) == 'truncated transport frame':
                    raise HostReplyLost(operation) from exc
                raise
            h.check_reply(operation, result, request, controller)
            return result

        def read_status():
            try:
                return exchange('status')
            except ValueError as exc:
                if str(exc) != 'unknown request':
                    raise
                return None

        try:
            status = read_status()
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
        except HostReplyLost as exc:
            # After a lost mutation reply, the only immediate follow-up is the
            # same authenticated status. A completed result can be consumed as-is.
            if exc.operation != 'status':
                saved = read_status()
                if saved is not None and saved['state'] == 'completed':
                    return exchange('consume')
            raise


def execute(value, state, backend, save):
    def step(key, phase, action, *args):
        if state[key] is None:
            state['phase'] = phase
            save(state)
            state[key] = action(*args)
            state.pop('retry', None)
            save(state)
        return state[key]

    def revision_for(developed):
        p.require('validation_blocker' not in developed,
                  'DevBox local validation stopped. ' + developed.get('validation_blocker', ''))
        if 'base_sha' not in developed:
            return developed['candidate_sha']
        state.setdefault('materialized', None)
        retained = step('materialized', 'materializing-candidate', backend.materialize, initial, developed)
        p.require(retained['binding']['base_sha'] == developed['base_sha'] and
                  retained['binding']['snapshot_sha256'] == developed['local_validation']['snapshot_sha256'],
                  'retained commit differs from the tested source')
        return retained['candidate_sha']

    initial = step('initial', 'building', backend.build, 1, value['agreement']['initial_commit'])
    step('maintenance', 'maintenance-turn', backend.turn, 'maintenance', initial)
    if value['adapter'] != CHECKLIST_ADAPTER:
        development = step('development', 'development-turn', backend.turn, 'development', initial)
        revision = revision_for(development)
        evidence = development['local_validation']
        p.require(evidence.get('candidate_sha', revision) == revision and evidence['exit_status'] == 0,
                  'observed local validation does not bind the proposed candidate')
        final = step('repair', 'binding-local-candidate', backend.build, 2, revision)
        p.require(final['candidate']['source_revision'] == revision, 'verified checkout differs from tested candidate')
        state['local_validation'] = dict(evidence, candidate_sha=revision,
                                         base_sha=initial['candidate']['source_revision'], session_uuid=development['session_uuid'],
                                         events_sha256=development['events_sha256'], checkpoint_id=final['checkpoint_id'],
                                         source_changed=revision != initial['candidate']['source_revision'])
        external = value['adapter'] == EXTERNAL_ADAPTER
        state['phase'] = 'awaiting-external-validation' if external else 'local-validation-recorded'
        observed = f'Local DevBox command completed with exit 0 at Git {revision}.'
        state['diagnostics'] = (observed + ' The requested external check requires an approved adapter.'
                                if external else observed)
        state.pop('retry', None)
        save(state)
        return
    first = step('first', 'host-check', backend.host_test, 1, initial)
    p.require(first['progress'] in ('host-checks-passed', 'repair-required'), 'first host check is blocked')
    developed = step('development', 'development-turn', backend.turn, 'development', initial, first)
    revised = revision_for(developed)
    if revised == initial['candidate']['source_revision']:
        p.require(first['progress'] == 'host-checks-passed', 'DevBox did not produce a changed candidate after failure')
        state['final'] = first
    else:
        repaired = step('repair', 'building-repair', backend.build, 2, revised)
        result = step('final', 'host-retest', backend.host_test, 2, repaired)
        p.require(result['progress'] == 'host-checks-passed', 'the reviewed retest budget ended without a pass')
    state['phase'] = 'passed'
    state.pop('retry', None)
    save(state)


def read_state(root):
    return p.loads(read_private(root / 'state.json', p.MAX_MESSAGE))


def pause_reason(error):
    if isinstance(error, HostReplyLost):
        return 'host-reply-interrupted'
    if isinstance(error, BlockingIOError):
        return 'dispatch-lease-busy'
    if isinstance(error, ValueError) and str(error) in RENEWAL_PAUSES:
        return 'renewal-observation'
    return None


def record_pause(state, reason, now):
    previous = state.get('retry', {})
    phase = state['phase']
    if previous.get('phase') == phase:
        cutoff, observations = previous['until_unix'], previous['observations'] + 1
    else:
        cutoff, observations = now + RETRY_SECONDS, 1
    state['phase'] = 'waiting'
    state['retry'] = {'phase': phase, 'reason': reason, 'until_unix': cutoff, 'observations': observations,
                      'automatic': now < cutoff and observations < RETRY_OBSERVATIONS}


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
        if state['phase'] == 'waiting':
            state['phase'] = state['retry']['phase']
        try:
            backend = FedoraJob(value)
            backend.ledger('job', registered_contract(value))
            execute(value, state, backend, lambda item: durable_json(root / 'state.json', item))
        except (OSError, ValueError, KeyError, ImportError, subprocess.SubprocessError) as exc:
            retry = pause_reason(exc)
            if retry is not None:
                record_pause(state, retry, int(time.time()))
            else:
                state['failed_stage'] = state['phase']
                state['phase'] = 'blocked'
                state.pop('retry', None)
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
            while result['phase'] == 'waiting' and result['retry']['automatic']:
                print(p.canonical(result), flush=True)
                time.sleep(RETRY_INTERVAL)
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
        if args.action == 'work' and result['phase'] == 'waiting':
            return 76
        return 2 if result['phase'] == 'blocked' else 0
    except BlockingIOError:
        return 75
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, 'Product job unavailable (' + type(exc).__name__ + ').\n')


if __name__ == '__main__':
    raise SystemExit(main())
