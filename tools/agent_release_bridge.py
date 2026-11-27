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
import tempfile
import time
from typing import NamedTuple
import zipfile

INSTALL = Path('/usr/libexec/dev-pair/tools')
UNIT = 'dev-pair-renewal@agent.service'
WORKFLOW = 'agent-refresh.yml'
REPOSITORY = 'oso-gato/dev-pair'
TOKYO = timezone(timedelta(hours=9))
OBSERVATION_SECONDS = 300
TOOL_FIELDS = ('codex_version', 'codex_source_sha', 'codex_sha256')
BINDING_FIELDS = {'schema', 'release_sha256', 'platform_sha256', 'base_platform_sha256',
                  'site_config_sha256', 'plan_sha256', 'intake_sha256'}


class BridgeError(ValueError):
    pass


class Candidate(NamedTuple):
    run: int
    source: str
    digest: str
    index: dict


def require(condition, reason):
    if not condition:
        raise BridgeError(reason)


def selection_window(now, on_demand):
    if on_demand:
        return now - timedelta(hours=6), now, 'workflow_dispatch'
    local = now.astimezone(TOKYO)
    start = local.replace(hour=4, minute=0, second=0, microsecond=0)
    if not start <= local <= start + timedelta(hours=5, minutes=15):
        return None
    return start.astimezone(timezone.utc), now, 'schedule'


def publisher_runs(values, source, window):
    start, end, event = window
    rows = values.get('workflow_runs')
    require(type(rows) is list and len(rows) <= 8, 'unexpected publisher run inventory')
    runs = []
    for row in rows:
        run = row.get('id')
        if (row.get('event') != event or row.get('head_sha') != source or row.get('head_branch') != 'main'
                or row.get('status') != 'completed' or row.get('conclusion') != 'success'
                or row.get('run_attempt') != 1 or row.get('path') != '.github/workflows/' + WORKFLOW
                or row.get('repository', {}).get('full_name') != REPOSITORY
                or row.get('head_repository', {}).get('full_name') != REPOSITORY):
            continue
        require(type(run) is int and 0 < run < 2**63, 'invalid protected publisher run ID')
        stamp = row.get('created_at')
        require(type(stamp) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', stamp),
                'invalid protected publisher creation time')
        created = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if start <= created <= end:
            runs.append((created, run))
    require(len({run for _, run in runs}) == len(runs), 'ambiguous publisher run ID')
    return [run for _, run in sorted(runs, reverse=True)]


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

    def discover(self, window):
        f, p = self.intake, self.protocol
        end = time.monotonic() + OBSERVATION_SECONDS
        f.protected(f.ROOT, directory=True)
        branch = f.read_api('branches/main', end)
        require(branch.get('protected') is True, 'agent publisher requires independently protected main')
        source = p.hex_id(branch.get('commit', {}).get('sha'), 40)
        event = window[2]
        rows = f.read_api(f'actions/workflows/{WORKFLOW}/runs?branch=main&event={event}&status=completed&per_page=8', end)
        runs = publisher_runs(rows, source, window)
        if not runs:
            return None
        run = runs[0]
        f.checked_run(f.read_api(f'actions/runs/{run}', end), source, run, True)
        artifacts = f.artifacts(f.read_api(f'actions/runs/{run}/artifacts?per_page=100', end), source, True)
        with tempfile.TemporaryDirectory(dir=f.ROOT, prefix='.agent-discovery-') as directory:
            stage = Path(directory)
            name = f.release.artifact_name('subjects', source)
            f.fetch_artifact(artifacts, name, stage, {'platform.json': (None, p.CONTROL_LIMIT)}, end)
            raw = (stage / 'platform.json').read_bytes()
            index = p.portable_index(p.json_bytes(raw), source, run)
            require(raw == p.canonical(index), 'publisher index has noncanonical bytes')
        return Candidate(run, source, hashlib.sha256(raw).hexdigest(), index)

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

    def pending(self, offer, binding, state):
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
                pending = self.pending(offer, binding, state)
                if pending and pending != 'queued':
                    return {'status': pending, 'run': candidate.run}
            self.stage(candidate, binding)
            with self.controller.lock():
                status, state = self.transition()
                if status != 'ready' or self.live()[0] != binding:
                    return {'status': 'predecessor-changed'}
                pending = self.pending(offer, binding, state)
                if pending and pending != 'queued':
                    return {'status': pending, 'run': candidate.run}
                self.resolver.resolve(offer)
                if not pending:
                    self.renewal.replace_json(self.offer, offer)
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
    windows = [selection_window(now, args.on_demand)]
    if args.poll:
        windows.append(selection_window(now, True))
    windows = [window for window in windows if window is not None]
    if not windows:
        print('{"status":"outside-nightly-window"}')
        return
    sys.path.insert(0, str(INSTALL))
    import platform_release_intake as intake
    import platform_release_protocol as protocol
    import renewal
    import renewal_site

    site = Site(renewal, renewal_site, intake, protocol)
    for window in windows:
        result = site.cycle(window)
        if result['status'] not in ('awaiting-publication', 'no-new-image'):
            break
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f'Agent release bridge stopped: {error}', file=sys.stderr)
        sys.exit(2)
