#!/usr/bin/python3 -I
"""Discover an attested platform agent release and offer it to ordinary renewal."""
import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import NamedTuple
import zipfile

INSTALL = Path('/usr/libexec/dev-pair/tools')
UNIT = 'dev-pair-renewal@agent.service'
WORKFLOW = 'agent-refresh.yml'
REPOSITORY = 'oso-gato/dev-pair'
TOKYO = timezone(timedelta(hours=9))
OBSERVATION_SECONDS = 300
NIGHT_LENGTH = timedelta(hours=5, minutes=15, seconds=30)
NIGHT_TERMINAL = {'publisher-failed', 'missed-publication', 'missed-observation', 'publication-expired',
                  'observation-unavailable', 'queued', 'no-new-image', 'rejected'}
TOOL_FIELDS = ('codex_version', 'codex_source_sha', 'codex_sha256')
BINDING_FIELDS = {'schema', 'release_sha256', 'platform_sha256', 'base_platform_sha256',
                  'site_config_sha256', 'plan_sha256', 'intake_sha256'}


class BridgeError(ValueError):
    pass


class Publication(NamedTuple):
    status: str
    run: int | None


class Candidate(NamedTuple):
    run: int
    source: str
    digest: str
    index: dict


def require(condition, reason):
    if not condition:
        raise BridgeError(reason)


def nightly_period(now):
    local = now.astimezone(TOKYO)
    start = local.replace(hour=4, minute=0, second=0, microsecond=0)
    if now < start:
        start -= timedelta(days=1)
    return start.astimezone(timezone.utc), (start + NIGHT_LENGTH).astimezone(timezone.utc)


def selection_window(now, on_demand):
    if on_demand:
        return now - timedelta(hours=6), now, 'workflow_dispatch'
    start, cutoff = nightly_period(now)
    return (start, now, 'schedule') if now <= cutoff else None


def publisher_run_in_scope(row, source, event):
    require(type(row) is dict, 'invalid protected publisher run')
    return (row.get('event') == event and row.get('head_sha') == source and row.get('head_branch') == 'main'
            and row.get('path') == '.github/workflows/' + WORKFLOW
            and all(type(row.get(key)) is dict and row[key].get('full_name') == REPOSITORY
                    for key in ('repository', 'head_repository')))


def publisher_run(row):
    run, attempt = row.get('id'), row.get('run_attempt')
    require(type(run) is int and 0 < run < 2**63 and type(attempt) is int and 0 < attempt < 2**63,
            'invalid protected publisher run or attempt ID')
    stamp = row.get('created_at')
    require(type(stamp) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', stamp),
            'invalid protected publisher creation time')
    try:
        created = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    except ValueError:
        raise BridgeError('invalid protected publisher creation time') from None
    status, conclusion = row.get('status'), row.get('conclusion')
    require(type(status) is str and bool(status.strip()) and 'conclusion' in row and
            (conclusion is None or type(conclusion) is str and bool(conclusion.strip())),
            'invalid protected publisher state')
    return created, run, status, conclusion


def matching_runs(values, source, window):
    start, end, event = window
    rows = values.get('workflow_runs') if type(values) is dict else None
    require(type(rows) is list and len(rows) <= 8, 'unexpected publisher run inventory')
    runs = []
    for row in rows:
        if publisher_run_in_scope(row, source, event):
            parsed = publisher_run(row)
            if row['run_attempt'] == 1 and start <= parsed[0] <= end:
                runs.append(parsed)
    require(len({run for _, run, _, _ in runs}) == len(runs), 'ambiguous publisher run ID')
    return sorted(runs, reverse=True)


def publisher_runs(values, source, window):
    return [run for _, run, status, conclusion in matching_runs(values, source, window)
            if status == 'completed' and conclusion == 'success']


def protected_main(intake, protocol, end):
    intake.protected(intake.ROOT, directory=True)
    branch = intake.read_api('branches/main', end)
    require(type(branch) is dict and branch.get('protected') is True and branch.get('name') == 'main' and
            type(branch.get('commit')) is dict,
            'agent publisher requires independently protected main')
    return protocol.hex_id(branch['commit'].get('sha'), 40)


def confirm_publisher_read(intake, protocol, end):
    """Check both reads used by the fixed poll, without looking for an offer."""
    source = protected_main(intake, protocol, end)
    for event in ('schedule', 'workflow_dispatch'):
        endpoint = f'actions/workflows/{WORKFLOW}/runs?branch=main&event={event}&head_sha={source}&per_page=1'
        value = intake.read_api(endpoint, end)
        require(type(value) is dict, 'invalid protected publisher read inventory')
        count, rows = value.get('total_count'), value.get('workflow_runs')
        require(type(count) is int and 0 <= count < 2**63 and type(rows) is list and len(rows) == min(count, 1),
                'invalid protected publisher read inventory')
        if rows:
            row, = rows
            require(publisher_run_in_scope(row, source, event),
                    'protected publisher read returned a foreign or stale run')
            publisher_run(row)


def stable_version(version):
    require(type(version) is str and re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})', version),
            'invalid stable tooling identity')
    return tuple(int(part) for part in version.split('.'))


def eligible(candidate, binding, previous):
    index = candidate.index
    require(index['kind'] == 'dev-pair-agent-release', 'agent publisher returned a full platform')
    require(index['base_platform_sha256'] == binding['base_platform_sha256'],
            'publisher changes the retained host and DevBox base')
    if candidate.digest == binding['platform_sha256']:
        return False
    if index['schema'] == 2:
        require(index['previous_platform_sha256'] == binding['platform_sha256'],
                'publisher has a stale signed predecessor')
    else:
        require(index['schema'] == 3 and index['previous_platform_sha256'] is None,
                'unsigned site-specific portable predecessor')
    old, new = (row['components']['maintenance-agent'] for row in (previous, index))
    before, after = (stable_version(row['codex_version']) for row in (old, new))
    require(after >= before, 'agent publisher attempts to roll back the stable tooling version')
    if before == after:
        require(all(old[key] == new[key] for key in TOOL_FIELDS),
                'the upstream signing source or executable changed at the same stable version')
    images = ('maintenance-agent', 'development-agent')
    changes = [index['components'][role]['oci_manifest_sha256'] != previous['components'][role]['oci_manifest_sha256']
               for role in images]
    require(after == before or all(changes), 'new stable tooling must change both exact agent images')
    return any(changes)


class Site:
    def __init__(self, renewal, site, intake, protocol):
        self.renewal, self.site, self.intake, self.protocol = renewal, site, intake, protocol
        self.controller = renewal.Renewal(renewal.DEFAULT_ROOT, None)
        self.resolver = site.Resolver(self.controller)
        self.control = self.controller.control
        self.offer = renewal.trusted_directory(self.control / 'offers') / 'agent.json'
        self.nightly_status = self.control / 'agent-nightly.json'
        self.offer_owner = self.control / 'agent-bridge-offer.json'

    @contextlib.contextmanager
    def lease(self):
        path = self.control / 'agent-bridge.lock'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            node = os.fstat(fd)
            require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_uid == 0 and
                    stat.S_IMODE(node.st_mode) == 0o600, 'unsafe agent discovery lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def live(self):
        r = self.renewal
        current = self.controller.live_release()
        require(r.read_json(self.control / 'site-current.json') == current, 'site release switch is incomplete')
        binding = r.read_json(self.control / 'platform-bindings' / (current + '.json'))
        require(type(binding) is dict and set(binding) == BINDING_FIELDS and type(binding['schema']) is int
                and binding['schema'] == 1 and binding['release_sha256'] == current,
                'current release lacks an exact installed site binding')
        for key in BINDING_FIELDS - {'schema'}:
            self.protocol.hex_id(binding[key])
        _, index, receipt = self.resolver.index(binding['platform_sha256'])
        require(receipt == binding['intake_sha256'] and
                (index['base_platform_sha256'] or binding['platform_sha256']) == binding['base_platform_sha256'],
                'active portable trust or base evidence changed')
        return binding, index

    def transition(self):
        _, state = self.controller.transition()
        if ((state is not None and state['phase'] not in self.renewal.TERMINAL)
                or os.path.lexists(self.controller.root / 'renewal-fence' / 'frozen')):
            return 'busy', state
        return 'ready', state

    @contextlib.contextmanager
    def discovery_directory(self):
        directory = self.control / 'agent-discovery'
        directory.mkdir(mode=0o700, exist_ok=True)
        node = directory.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid == os.geteuid() and
                stat.S_IMODE(node.st_mode) == 0o700, 'unsafe owned agent discovery directory')
        subject = directory / 'platform.json'

        def reset():
            if os.path.lexists(subject):
                node = subject.lstat()
                require(stat.S_ISREG(node.st_mode) and node.st_uid == os.geteuid() and node.st_nlink == 1
                        and not node.st_mode & 0o022, 'unsafe retained partial agent discovery subject')
                subject.unlink()

        reset()
        require(not any(directory.iterdir()), 'unexpected entry in owned agent discovery directory')
        try:
            yield directory
        finally:
            reset()

    def publisher(self, window, end):
        f = self.intake
        source = protected_main(f, self.protocol, end)
        event = window[2]
        rows = f.read_api(f'actions/workflows/{WORKFLOW}/runs?branch=main&event={event}&per_page=8', end)
        return source, matching_runs(rows, source, window)

    def discover(self, window):
        f, p = self.intake, self.protocol
        end = time.monotonic() + OBSERVATION_SECONDS
        source, runs = self.publisher(window, end)
        if not runs:
            return Publication('awaiting-publication', None)
        _, run, status, conclusion = runs[0]
        if status != 'completed':
            return Publication('publisher-running', run)
        if conclusion != 'success':
            return Publication('publisher-failed', run)
        f.checked_run(f.read_api(f'actions/runs/{run}', end), source, run, True)
        artifacts = f.artifacts(f.read_api(f'actions/runs/{run}/artifacts?per_page=100', end), source, True)
        with self.discovery_directory() as stage:
            name = f.release.artifact_name('subjects', source)
            f.fetch_artifact(artifacts, name, stage, {'platform.json': (None, p.CONTROL_LIMIT)}, end)
            raw = (stage / 'platform.json').read_bytes()
            index = p.portable_index(p.json_bytes(raw), source, run)
            require(raw == p.canonical(index), 'publisher index has noncanonical bytes')
        return Candidate(run, source, hashlib.sha256(raw).hexdigest(), index)

    def record_nightly(self, start, result):
        with self.controller.lock():
            status, _ = self.transition()
            if status != 'ready':
                return result
            binding, index = self.live()
            prior = self.renewal.read_json(self.nightly_status) if os.path.lexists(self.nightly_status) else {}
            period = start.isoformat()
            if prior.get('scheduled_at', '') > period:
                raise BridgeError('nightly observation time regressed')
            if (prior.get('scheduled_at') == period and prior.get('status') in NIGHT_TERMINAL and
                    result['status'] not in NIGHT_TERMINAL):
                return result
            observed = {'schema': 1, 'scheduled_at': period, 'status': result['status'], 'run': result.get('run'),
                        'retained_release_sha256': binding['release_sha256'],
                        'retained_platform_sha256': binding['platform_sha256'],
                        'retained_codex_version': index['components']['maintenance-agent']['codex_version']}
            if 'platform_sha256' in result:
                observed['candidate_platform_sha256'] = result['platform_sha256']
            if prior != observed:
                self.renewal.replace_json(self.nightly_status, observed)
            return result

    def nightly(self, now):
        start, cutoff = nightly_period(now)
        if now <= cutoff:
            return self.record_nightly(start, self.cycle((start, now, 'schedule')))
        with self.lease():
            if os.path.lexists(self.nightly_status):
                prior = self.renewal.read_json(self.nightly_status)
                if prior.get('scheduled_at') == start.isoformat() and prior.get('status') in NIGHT_TERMINAL:
                    return prior
            try:
                _, runs = self.publisher((start, cutoff, 'schedule'), time.monotonic() + OBSERVATION_SECONDS)
                if not runs:
                    result = {'status': 'missed-publication'}
                else:
                    _, run, status, conclusion = runs[0]
                    outcome = ('publication-expired' if status != 'completed' else
                               'missed-observation' if conclusion == 'success' else 'publisher-failed')
                    result = {'status': outcome, 'run': run}
            except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
                result = {'status': 'observation-unavailable'}
            return self.record_nightly(start, result)

    def stage(self, candidate, binding):
        f = self.intake
        prior = binding['platform_sha256']
        if os.path.lexists(f.ROOT / candidate.digest):
            directory, index, _ = self.resolver.index(candidate.digest)
            require(index == candidate.index, 'retained index differs from the selected publisher run')
            end = time.monotonic() + OBSERVATION_SECONDS
            for role in ('maintenance', 'development'):
                f.verify_subject(directory / 'platform.json', candidate.digest, candidate.source, candidate.run, role, end)
        else:
            self.run_tool('platform_release_intake.py', '--source', candidate.source, '--run-id', str(candidate.run),
                          '--platform-sha256', candidate.digest, '--previous', prior, '--agent-only',
                          timeout=f.CONTROL_SECONDS + 15)
        directory, index, _ = self.resolver.index(candidate.digest)
        require(index == candidate.index, 'verified intake selected different portable bytes')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        path = directory / 'installed.json'
        if os.path.lexists(path):
            existing = self.renewal.loads(self.site.protected_bytes(path, 65536))
        else:
            existing = None
        if existing is None or existing['boot_id'] != boot:
            self.run_tool('platform_release_install.py', '--platform-sha256', candidate.digest,
                          '--site-config-sha256', binding['site_config_sha256'], timeout=915)
        installation = self.renewal.loads(self.site.protected_bytes(path, 65536))
        self.site.installed_row(installation, index_sha=candidate.digest, index=index,
                                base=binding['base_platform_sha256'], site_sha=binding['site_config_sha256'], boot=boot)

    def run_tool(self, name, *arguments, timeout):
        tool = self.intake.protected(INSTALL / name)
        subprocess.run(['/usr/bin/python3', '-EBs', str(tool), *arguments], env=self.intake.native_env(),
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=timeout, check=True)

    def owned(self):
        if not os.path.lexists(self.offer_owner):
            return []
        own = self.renewal.read_json(self.offer_owner)
        require(type(own) is dict and set(own) == {'schema', 'offers'} and type(own['schema']) is int and
                own['schema'] == 1 and type(own['offers']) is list and 0 < len(own['offers']) <= 2,
                'invalid agent bridge offer ownership')
        return [self.protocol.hex_id(value) for value in own['offers']]

    def publish_offer(self, offer):
        r = self.renewal
        owned = self.owned()
        previous = r.identity(r.read_json(self.offer)) if os.path.lexists(self.offer) else None
        identity = r.identity(offer)
        custody = [previous, identity] if previous in owned and previous != identity else [identity]
        r.replace_json(self.offer_owner, {'schema': 1, 'offers': custody})
        r.replace_json(self.offer, offer)
        if len(custody) > 1:
            r.replace_json(self.offer_owner, {'schema': 1, 'offers': [identity]})

    def supersedable(self, old, binding, candidate, state):
        r = self.renewal
        if (r.identity(old) not in self.owned() or old['previous_release_sha256'] != binding['release_sha256'] or
                old['site_config_sha256'] != binding['site_config_sha256'] or
                (state is not None and state['request']['operation'] == old['operation'])):
            return False
        request = self.control / 'requests' / 'agent.json'
        if os.path.lexists(request):
            return False
        attempts = self.control / 'attempts'
        for position, attempt in enumerate(attempts.iterdir()):
            require(position < r.MAX_ATTEMPTS, 'renewal attempt inventory exceeds its bound')
            journal = r.read_json(r.trusted_directory(attempt) / 'journal.json')
            if journal['request']['operation'] == old['operation']:
                return False
        _, previous, _ = self.resolver.index(old['platform_sha256'])
        a, b = (stable_version(value['components']['maintenance-agent']['codex_version'])
                for value in (previous, candidate.index))
        return a < b

    def pending(self, offer, binding, state, candidate=None):
        if not os.path.lexists(self.offer):
            return False
        r = self.renewal
        old = self.site.offer_record(r.read_json(self.offer), 'agent')
        if old == offer:
            if state is not None and state['request']['operation'] == old['operation'] and \
                    state['phase'] in ('rejected', 'rolled-back'):
                return 'rejected'
            return 'queued'
        if old['platform_sha256'] == binding['platform_sha256']:
            return False
        if state is not None and state['request']['operation'] == old['operation'] and \
                state['phase'] in ('rejected', 'rolled-back'):
            return False
        if candidate is not None and self.supersedable(old, binding, candidate, state):
            return 'supersede-owned'
        return 'other-offer'

    def dispatch(self):
        subprocess.run(['/usr/bin/systemctl', 'start', '--no-block', UNIT], env=self.intake.ENV,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=15, check=True)

    def cycle(self, window):
        with self.lease():
            with self.controller.lock():
                status, _ = self.transition()
                if status != 'ready':
                    return {'status': 'renewal-busy'}
                binding, previous = self.live()
            candidate = self.discover(window)
            if candidate is None:
                return {'status': 'awaiting-publication'}
            if isinstance(candidate, Publication):
                return {'status': candidate.status} if candidate.run is None else {'status': candidate.status, 'run': candidate.run}
            if not eligible(candidate, binding, previous):
                return {'status': 'no-new-image', 'run': candidate.run}
            offer = {'schema': 2, 'scope': 'agent', 'operation': f'agent-ci-{candidate.run}-{candidate.digest[:24]}',
                     'platform_sha256': candidate.digest, 'previous_release_sha256': binding['release_sha256'],
                     'site_config_sha256': binding['site_config_sha256'], 'affected_jobs': [],
                     'reason': f'Independently verified protected Actions run {candidate.run}'}
            self.site.offer_record(offer, 'agent')
            with self.controller.lock():
                status, state = self.transition()
                if status != 'ready' or self.live()[0] != binding:
                    return {'status': 'predecessor-changed'}
                pending = self.pending(offer, binding, state, candidate)
                if pending and pending not in ('queued', 'supersede-owned'):
                    return {'status': pending, 'run': candidate.run}
                old_offer = self.renewal.identity(self.renewal.read_json(self.offer)) if pending == 'supersede-owned' else None
            self.stage(candidate, binding)
            if pending == 'supersede-owned':
                version = candidate.index['components']['maintenance-agent']['codex_version']
                require(self.intake.release.official_version() == version, 'replacement is not the current official stable')
            with self.controller.lock():
                status, state = self.transition()
                if status != 'ready' or self.live()[0] != binding:
                    return {'status': 'predecessor-changed'}
                final_pending = self.pending(offer, binding, state, candidate)
                if final_pending and (final_pending not in ('queued', 'supersede-owned') or
                                      final_pending == 'supersede-owned' and
                                      self.renewal.identity(self.renewal.read_json(self.offer)) != old_offer):
                    return {'status': 'other-offer' if final_pending == 'supersede-owned' else final_pending,
                            'run': candidate.run}
                self.resolver.resolve(offer)
                if final_pending != 'queued':
                    self.publish_offer(offer)
            self.dispatch()
        return {'status': 'queued', 'run': candidate.run, 'platform_sha256': candidate.digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    trigger = parser.add_mutually_exclusive_group(required=True)
    trigger.add_argument('--nightly', action='store_true')
    trigger.add_argument('--poll', action='store_true', help='poll scheduled and recent on-demand publishers')
    trigger.add_argument('--on-demand', action='store_true', help='select a recent protected manual workflow run')
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0, 'protected agent bridge operator required')
    os.umask(0o077)
    now = datetime.now(timezone.utc)
    sys.path.insert(0, str(INSTALL))
    import platform_release_intake as intake
    import platform_release_protocol as protocol
    import renewal
    import renewal_site

    site = Site(renewal, renewal_site, intake, protocol)
    if args.on_demand:
        result = site.cycle(selection_window(now, True))
    else:
        result = site.nightly(now)
        if args.poll and result['status'] not in ('queued', 'renewal-busy'):
            manual = site.cycle(selection_window(now, True))
            if manual['status'] != 'awaiting-publication':
                result = manual
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f'Agent release bridge stopped: {error}', file=sys.stderr)
        sys.exit(2)
