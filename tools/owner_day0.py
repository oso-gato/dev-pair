"""Owner-run start, status and resume for the reviewed hPanel bootstrap."""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import getpass
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import warnings

from bootstrap import ATTENDED_ACCESS, ATTENDED_RECEIPT, Blocked, Bootstrap, STATE as BOOTSTRAP, TRUST_SIGNERS

REPO = Path(__file__).resolve().parents[1]
STATE = Path('/var/lib/dev-pair-day0')
HANDOFF = Path('/etc/dev-pair/day0')
ROOT = Path('/var/lib/dev-pair')
GIT = Path('/usr/bin/git')
OWNER_KITS = Path('/root')
INITIAL_MAINTENANCE_SOURCE = 'a160b1c1724fb70d38d9992ad377ab791b2db0ee'
INITIAL_MAINTENANCE_PRODUCTION_TREE = 'a0f038de4d44844a743d338998ca14deee4ac3cc08fea9ef53db85d7d466c595'
MIB = 1024**2
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'PYTHONDONTWRITEBYTECODE': '1', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}


def require(value, reason):
    if not value:
        raise Blocked(reason)


def pin(value, length=64):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{%d}' % length, value), 'expected a complete pinned SHA')
    return value


def local_file(path):
    for node in (path, *path.parents):
        info = node.lstat()
        proper = stat.S_ISREG(info.st_mode) and info.st_nlink == 1 if node == path else stat.S_ISDIR(info.st_mode)
        require(proper and info.st_uid == 0 and not info.st_mode & 0o022, 'protected local path required')
    return path


def checksum(path):
    with local_file(path).open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def kit_source(repo, supplied=None):
    """Verify the checked archive's own manifest before bootstrapping signed Git."""
    package = repo.parent
    marker, manifest = package / 'SOURCE', package / 'MANIFEST.sha256'
    if not os.path.lexists(marker) and not os.path.lexists(manifest):
        return pin(supplied, 40), False
    if not os.path.lexists(manifest):
        revision = pin(local_file(marker).read_text().removesuffix('\n'), 40)
        require(supplied is None or supplied == revision, 'staged public source differs from the supplied pin')
        return revision, False
    revision = pin(local_file(marker).read_text().removesuffix('\n'), 40)
    require(supplied is None or supplied == revision, 'source argument differs from the verified owner kit')
    manifest = local_file(manifest)
    require(manifest.stat().st_size <= 2 * MIB, 'owner kit manifest exceeds its bound')
    seen = set()
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._/+@-]+)', line)
        require(match, 'owner kit manifest contains an invalid path')
        digest, name = match.groups()
        leaf = PurePosixPath(name)
        require(leaf.as_posix() == name and not leaf.is_absolute() and '..' not in leaf.parts and
                name not in seen and (name in ('SOURCE', 'README.txt') or leaf.parts[0] == repo.name),
                'owner kit manifest path is outside its approved source')
        seen.add(name)
        # Git may update only its index metadata. The clean exact objects are
        # checked on every run after Git is available.
        if name == f'{repo.name}/.git/index' and GIT.is_file():
            local_file(package / name)
        else:
            require(checksum(package / name) == digest, 'owner kit bytes differ from the verified manifest')
    required = {'SOURCE', f'{repo.name}/day0.sh', f'{repo.name}/tools/owner_day0.py', f'{repo.name}/.git/HEAD'}
    require(required <= seen, 'owner kit is incomplete')
    return revision, True


def secure_directory(path):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'protected day-zero state ancestry required')
    path.mkdir(mode=0o700, exist_ok=True)
    node = path.lstat()
    require(stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and stat.S_IMODE(node.st_mode) == 0o700,
            'protected day-zero state directory required')
    return path


def record(path):
    if not os.path.lexists(path):
        return None
    node = local_file(path).stat()
    require(node.st_size <= 65536 and not node.st_mode & 0o077, 'day-zero record must be private and bounded')
    return json.loads(path.read_bytes())


def save(app, path, value):
    old = record(path)
    if old == value:
        return
    before = path.read_text() if old is not None else None
    app.atomic(str(path), json.dumps(value, sort_keys=True) + '\n', expected=before)


@contextmanager
def tty_open():
    with ExitStack() as stack:
        try:
            incoming = stack.enter_context(open('/dev/tty', encoding='utf-8'))
            outgoing = stack.enter_context(open('/dev/tty', 'w', encoding='utf-8', buffering=1))
        except OSError as error:
            raise Blocked('Open an interactive hPanel root terminal and run one command on its own line.') from error
        yield SimpleNamespace(incoming=incoming, outgoing=outgoing)


def answer(tty, prompt):
    tty.outgoing.write(prompt + ' ')
    tty.outgoing.flush()
    line = tty.incoming.readline(1025)
    require(line.endswith('\n') and len(line) <= 1024, 'interactive answer was interrupted or too long')
    return line.strip()


def secret_answer(tty, prompt):
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(prompt + ' ', stream=tty.outgoing)


@contextmanager
def secret_file(contents):
    with tempfile.TemporaryDirectory(prefix='dev-pair-day0-', dir='/run') as work:
        path = Path(work) / 'credential'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(contents + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        try:
            yield path
        finally:
            contents = ''


class DayZero:
    def __init__(self, repo=REPO, app=None):
        self.repo = repo
        self.app = app or Bootstrap()
        self.progress = STATE / 'progress.json'

    def call(self, name, *args, timeout=900, capture=True, checkout=None):
        script = local_file((checkout or self.repo) / 'tools' / name)
        connection = {name: os.environ[name] for name in ('SSH_CONNECTION', 'SSH_CLIENT') if name in os.environ}
        result = subprocess.run(['/usr/bin/python3', '-EBs', str(script), *map(str, args)], env={**ENV, **connection},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else None,
                                timeout=timeout, check=False, text=True)
        require(result.returncode == 0, f'{name} paused. Read the controller message above, then run ./day0.sh resume.')
        return json.loads(result.stdout) if capture else None

    def original(self, revision=None):
        current = self.app.console_inspect(revision)
        release = dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']*)', current['os_release'], re.M))
        require((release.get('ID'), release.get('VERSION_ID'), current['arch'], current['pid1']) ==
                ('fedora', '44', 'x86_64', 'systemd'), 'Day 0 requires Fedora 44 x86_64 with systemd.')
        return current

    def status(self, source=None):
        item = self.original()
        protected = record(STATE / 'continuation-progress.json') or record(self.progress)
        report = self.app.status()
        print(f"Host {item['host']} | Fedora 44 | SELinux { {'1': 'enforcing', '0': 'permissive'}.get(item['selinux'], item['selinux'])}")
        physical = os.statvfs('/var/lib')
        print(f'Physical /var/lib free {physical.f_bavail * physical.f_frsize // MIB} MiB | {physical.f_favail} inodes')
        print('Source ' + (protected['source_sha'] if protected else source or 'awaiting the verified owner kit'))
        print('Day 0 phase ' + (protected['phase'] if protected else 'ready for inspection'))
        desired = record(Path(BOOTSTRAP) / 'desired.json') if report['prepared'] else None
        probe = Path(BOOTSTRAP) / 'gptbox-adapter' / pin(desired['gptbox_context_sha256']) / 'result.json' if desired else None
        maintenance = 'probe completion recorded' if probe and record(probe) else 'build and probes pending'
        initializer = record(Path(BOOTSTRAP) / 'initialize.json')
        if initializer is not None and (type(initializer) is not dict or initializer.get('phase') != 'complete'):
            maintenance = 'original setup reconciliation pending'
        print('Maintenance gptbox ' + maintenance)
        print('Tailnet enrollment ' + ('recorded' if report['enrollment_recorded'] else 'pending'))
        access = report.get('access_scope')
        print('SSH access ' + report['phase'] + (' | workload access pending' if access == 'core' else ''))
        print('Next ' + (protected['next'] if protected else 'Run ./day0.sh start in the selected hPanel root terminal.'))

    def stage(self, identity, revision, phase, next_step):
        save(self.app, self.progress, {'schema': 1, 'machine_id': identity['machine_id'], 'source_sha': revision,
                                       'phase': phase, 'next': next_step})
        print(phase.replace('-', ' ').capitalize() + '. ' + next_step, flush=True)

    def ensure_git(self, revision, archive):
        if not GIT.is_file():
            require(archive, 'Use the verified pre-Git owner kit when Git is absent.')
            print('Installing the signed Fedora Git prerequisite.', flush=True)
            subprocess.run(['/usr/bin/dnf', '-y', '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1',
                            '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'],
                           env=ENV, stdin=subprocess.DEVNULL, timeout=420, check=True)
        return self.app.destination_source(revision)

    def transport(self, tty, identity, revision):
        saved = record(STATE / 'transport.json')
        observed = self.app.observed_ssh_peer()
        if observed:
            remote = observed['remote']
            network = f'{remote}/{remote.max_prefixlen}'
            require(saved in (None, {'mode': 'observed-ssh', 'network': network}) or
                    self.app.status()['phase'] == 'tailnet-only',
                    'The current SSH peer differs from the authorized original route. Use the original route or independent recovery.')
            if saved is None:
                message = (f'Observed SSH source {network}. Open a second independent hPanel root terminal and confirm it works. '
                           f'Type yes to scope temporary SSH to this observed source only.')
                if answer(tty, message).lower() != 'yes':
                    return None
                save(self.app, STATE / 'transport.json', {'mode': 'observed-ssh', 'network': network})
            self.app.validate_bootstrap_access([network])
            return ['--bootstrap-source', network]
        provider = HANDOFF / 'provider-console.json'
        if os.path.lexists(provider) and os.path.lexists(Path(TRUST_SIGNERS)):
            require(saved in (None, {'mode': 'verified-provider-console'}), 'Protected initial transport differs.')
            self.app.validate_bootstrap_access([], str(provider))
            save(self.app, STATE / 'transport.json', {'mode': 'verified-provider-console'})
            return ['--console-receipt', str(provider)]
        require(saved in (None, {'mode': ATTENDED_ACCESS}), 'Protected initial transport differs.')
        if self.attended(tty, identity, revision):
            save(self.app, STATE / 'transport.json', {'mode': ATTENDED_ACCESS})
            return ['--console-receipt', ATTENDED_RECEIPT]
        return None

    def attended(self, tty, identity, revision):
        receipt = Path(ATTENDED_RECEIPT)
        runtime = secure_directory(receipt.parent)
        prior = record(receipt)
        if prior and (prior.get('boot_id'), prior.get('source_sha')) == (identity['boot_id'], revision) and \
                0 <= time.time() - prior.get('created_at', 0) <= 1800:
            self.app.validate_bootstrap_access([], ATTENDED_RECEIPT)
            return True
        require(self.app.ssh_ancestors() == [] and not os.environ.get('SSH_CLIENT') and
                not os.environ.get('SSH_CONNECTION'), 'Open the recovery challenge from the local hPanel root terminal.')
        challenge = {'schema': 1, 'machine_id': identity['machine_id'], 'boot_id': identity['boot_id'],
                     'source_sha': revision, 'owner_checkout': str(self.repo), 'created_at': int(time.time()),
                     'origin_session': os.getsid(0),
                     'code': secrets.token_hex(4)}
        save(self.app, runtime / 'challenge.json', challenge)
        print('In a second hPanel root terminal for the same VPS, enter this checkout and run', flush=True)
        print(f'  cd {self.repo} && ./day0.sh resume --confirm-recovery', flush=True)
        print(f'Recovery challenge {challenge["code"]}', flush=True)
        answer(tty, 'Press Enter here after confirming in the second terminal.')
        observed = record(receipt)
        if not observed or any(observed.get(key) != challenge[key] for key in ('created_at', 'origin_session')):
            return False
        self.app.validate_bootstrap_access([], ATTENDED_RECEIPT)
        return True

    def confirm_recovery(self, tty, source):
        revision, _ = kit_source(self.repo, source)
        identity = self.original(revision)
        require(self.app.ssh_ancestors() == [] and not os.environ.get('SSH_CLIENT') and
                not os.environ.get('SSH_CONNECTION'), 'Open the second local hPanel root terminal, then confirm again.')
        receipt = Path(ATTENDED_RECEIPT)
        challenge = record(receipt.with_name('challenge.json'))
        require(challenge and challenge['schema'] == 1 and challenge['source_sha'] == revision and
                challenge['owner_checkout'] == str(self.repo) and
                all(challenge[key] == identity[key] for key in ('machine_id', 'boot_id')) and
                0 <= time.time() - challenge['created_at'] <= 600 and challenge['origin_session'] != os.getsid(0),
                'No matching request from a different current hPanel session. Resume in the first terminal.')
        code = secret_answer(tty, 'Enter the recovery challenge shown in the first terminal.')
        require(secrets.compare_digest(code, challenge['code']), 'Recovery challenge did not match.')
        fields = {name: challenge[name] for name in ('schema', 'machine_id', 'boot_id', 'source_sha', 'owner_checkout', 'created_at', 'origin_session')}
        save(self.app, receipt, {**fields, 'kind': ATTENDED_ACCESS, 'confirmed_session': os.getsid(0)})
        print('Separate current-boot root recovery confirmed. Continue in the first terminal.')

    def selinux(self, identity, revision, tty):
        observed = self.call('selinux_bootstrap.py', 'inspect')
        state = ROOT / 'selinux-bootstrap/intent.json'
        if (observed['live'] == 'Enforcing' and observed['persistent'] == 'enforcing' and
                observed['policy_present'] and not os.path.lexists(state) and not os.path.lexists('/.autorelabel')):
            return True
        from selinux_bootstrap import code_digest
        self.stage(identity, revision, 'selinux-transition', 'Keep an independent hPanel root recovery session available.')
        if observed['live'] != 'Enforcing':
            if answer(tty, 'Type yes to start the checked relabel and its bounded setup reboots.').lower() != 'yes':
                return False
            extra = ('--reboot',)
        else:
            extra = ()
        result = self.call('selinux_bootstrap.py', 'converge', '--apply', '--expected-code-sha256', code_digest(),
                           '--source-sha', revision, *extra)
        if result.get('phase') not in ('enforcing', 'already-enforcing'):
            self.stage(identity, revision, 'selinux-reboot-pending', 'Reconnect after the relabel and run ./day0.sh resume.')
            return False
        return True

    def storage_geometry(self):
        existing = record(Path('/var/lib/dev-pair-managed-storage.json'))
        observed = os.statvfs('/var/lib')
        free = observed.f_bavail * observed.f_frsize // MIB
        print(f'Physical /var/lib free {free} MiB | {observed.f_favail} inodes.', flush=True)
        if existing:
            require(free >= 8192 and observed.f_favail >= existing['reserve_inodes'],
                    'The enrolled host lacks its physical recovery reserve.')
            return existing['filesystem']['mib'], existing['filesystem']['inodes'], existing['reserve_inodes']
        size = min(20480, ((free - 9216) // 256) * 256)
        require(size >= 16384 and observed.f_favail >= 4096 + 16,
                'The inspected /var/lib filesystem lacks managed capacity plus the required 8 GiB physical reserve.')
        print(f'This host can reserve a {size} MiB managed filesystem for the pair.', flush=True)
        return size, 262144, 4096

    def managed_storage(self, revision, access, geometry):
        size, inodes, reserve = geometry
        self.call('destination_release.py', 'managed-storage', '--apply', '--platform-sha', revision,
                  '--managed-mib', size, '--managed-inodes', inodes, '--reserve-inodes', reserve, *access)

    def checked_inputs(self, path, revision):
        from public_inputs import read_manifest

        approved = record(path / 'admission.json')
        require(type(approved) is dict and set(approved) == {'source_sha', 'manifest_sha256', 'context_sha256'} and
                approved['source_sha'] == revision, 'protected maintenance context source changed')
        manifest = read_manifest(path / 'manifest.json', pin(approved['manifest_sha256']))
        expected = pin(approved['context_sha256'])
        require(manifest['source_sha'] == revision and manifest['context_sha256'] == expected,
                'verified public maintenance context differs from the protected handoff')
        self.app.check_gptbox_inputs(path / 'context/context', expected)
        return path / 'context/context', path / 'context/distrobox', expected

    def inputs(self, revision):
        store = secure_directory(ROOT / 'day0-inputs')
        selected = store / revision
        work = store / '.maintenance-work'
        if os.path.lexists(work):
            secure_directory(work)
            marker = record(work / 'owner.json')
            owned = marker == {'source_sha': revision, 'kind': 'day0-maintenance-public-inputs'}
            require((owned or not any(work.iterdir())) and not any(os.path.ismount(path) for path in work.rglob('*')),
                    'Unexpected day-zero input staging is preserved for recovery.')
            shutil.rmtree(work)
        if os.path.lexists(selected):
            return self.checked_inputs(selected, revision)
        secure_directory(work)
        save(self.app, work / 'owner.json', {'source_sha': revision, 'kind': 'day0-maintenance-public-inputs'})
        cache, handoff, result = (work / name for name in ('cache', 'handoff', 'result'))
        secure_directory(result)
        self.call('public_inputs.py', 'fetch', '--output', cache)
        measured = self.call('public_inputs.py', 'build', '--cache', cache, '--distrobox-source', cache / 'distrobox',
                             '--output', handoff, '--role', 'maintenance')
        admission = {key: measured[key] for key in ('source_sha', 'manifest_sha256', 'context_sha256')}
        require(admission['source_sha'] == revision, 'public maintenance input producer returned another source')
        self.call('public_inputs.py', 'extract', '--payload', handoff / 'maintenance-inputs.tar.gz',
                  '--manifest', handoff / 'manifest.json', '--expected-manifest-sha256', pin(admission['manifest_sha256']),
                  '--output', result / 'context', '--role', 'maintenance')
        shutil.copyfile(handoff / 'manifest.json', result / 'manifest.json')
        save(self.app, result / 'admission.json', admission)
        self.checked_inputs(result, revision)
        require(not os.path.lexists(selected), 'a maintenance context appeared outside the day-zero lock')
        result.rename(selected)
        descriptor = os.open(store, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        shutil.rmtree(work)
        return self.checked_inputs(selected, revision)

    def maintenance_receipt(self, revision, context):
        from gptbox import Gptbox

        app = Gptbox()
        app.target = BOOTSTRAP + '/gptbox-adapter/' + context
        path = Path(app.target) / 'result.json'
        if not os.path.lexists(path):
            return None
        observed = record(path)
        image = pin(observed['assembled_image_id'])
        self.probes(observed, revision, context)
        app.maintenance_host_readiness(context)
        app.local_maintenance_completion(context, revision, image)
        return image

    @staticmethod
    def probes(observed, revision, context):
        require(type(observed) is dict and observed.get('kind') == 'maintenance-gptbox-probe-candidate' and
                observed.get('source_sha') == revision and observed.get('context_sha256') == context and
                type(observed.get('boundary_and_version_cycles')) is int and observed['boundary_and_version_cycles'] == 2 and
                observed.get('runtime_container_removed') is True and observed.get('job_admission') is False,
                'The confined maintenance gptbox and both offline probe cycles are still pending.')
        return pin(observed.get('assembled_image_id'))

    def prepare(self, revision, access, input_paths, tty, *, already_prepared=False):
        context, upstream, expected = input_paths
        checkout = Path(context).parent / 'dev-pair'
        for entry in ('bootstrap.py', 'gptbox.py'):
            require(checksum(checkout / 'tools' / entry) == checksum(self.repo / 'tools' / entry),
                    'Sanitized public-input checkout does not contain the exact owner source.')
        common = ('--apply', '--source-sha', revision, '--expected-context-sha256', expected, '--distrobox-source', upstream)
        if already_prepared:
            attempt = Path(BOOTSTRAP) / 'gptbox-adapter' / expected / 'attempt.json'
            retry = ('--retry',) if os.path.lexists(attempt) else ()
            result = self.call('gptbox.py', 'assemble-prepared-maintenance', *common, '--context', context,
                               *retry, timeout=1850, checkout=checkout)
            return self.probes(result, revision, expected)
        if access[0] == '--console-receipt' and access[1] != ATTENDED_RECEIPT:
            # Signed provider evidence uses the ordinary clean-checkout source
            # verifier. Its closed receipt does not carry an alternate checkout.
            checkout = self.repo
        options = [*common, '--gptbox-context', context, *access]
        if access[0] == '--bootstrap-source':
            options.append('--provider-ssh')
        if os.path.lexists(Path(BOOTSTRAP) / 'initialize.json'):
            options.append('--retry')
        if os.path.lexists(Path(BOOTSTRAP) / 'operator-password-set'):
            result = self.call('bootstrap.py', 'initialize', *options, timeout=2500, checkout=checkout)
        else:
            value = secret_answer(tty, 'Set the named core console and sudo password.')
            confirmation = secret_answer(tty, 'Repeat the core password.')
            require(value and value == confirmation, 'The core passwords must be nonempty and match.')
            with secret_file(value) as credential:
                result = self.call('bootstrap.py', 'initialize', *options, '--password-file', credential,
                                   timeout=2500, checkout=checkout)
        require(result.get('phase') == result.get('maintenance_gptbox') == 'complete',
                'The combined host preparation and maintenance gptbox are incomplete.')
        return self.probes(result['result'], revision, expected)

    def resume_maintenance(self, identity, revision, expected, tty):
        journal = record(Path(BOOTSTRAP) / 'initialize.json')
        incomplete = False
        if journal is not None:
            target = journal.get('target') if type(journal) is dict else None
            require(type(target) is dict and journal.get('phase') in ('prepare', 'maintenance-gptbox', 'complete') and
                    target.get('source_sha') == revision and target.get('context_sha256') == expected,
                    'The combined initializer journal does not match this prepared host.')
            incomplete = journal['phase'] != 'complete'
        if not incomplete:
            if self.maintenance_receipt(revision, expected) is not None:
                return True
            require(journal is None, 'The completed initializer is missing its exact sealed maintenance proof.')
        access = ()
        if incomplete:
            access = self.transport(tty, identity, revision)
            if access is None:
                self.stage(identity, revision, 'recovery-confirmation-pending',
                           'Confirm the original recovery route to resume the interrupted combined initializer.')
                return False
        self.stage(identity, revision, 'maintenance-gptbox',
                   'Resuming the original initializer and its owned resources.' if incomplete else
                   'Resuming the prepared host without resetting core or ingress.')
        paths = self.inputs(revision)
        require(paths[2] == expected, 'The prepared host uses different verified maintenance inputs.')
        image = self.prepare(revision, access, paths, tty, already_prepared=not incomplete)
        require(self.maintenance_receipt(revision, expected) == image, 'The maintenance probe evidence did not read back.')
        return True

    def enroll(self, tty):
        current = self.app.status()
        if current['enrollment_recorded']:
            admitted = record(Path(BOOTSTRAP) / 'enrollment-intent.json')
            live = json.loads(self.app.run('/usr/bin/tailscale', 'status', '--json', timeout=15))
            require(live.get('BackendState') == 'Running', 'Previously enrolled Tailscale is not running. Keep the recovery console open.')
            self.app.check_node(live, admitted['tailnet'])
            return True
        existing = record(Path(BOOTSTRAP) / 'enrollment-intent.json')
        tailnet = existing['tailnet'] if existing else answer(tty, 'Expected Tailscale network name, or press Enter to finish host bootstrap and enroll later.')
        if not tailnet:
            return False
        key = secret_answer(tty, 'Tailscale auth key, or press Enter for browser/device sign-in.')
        if key:
            require(re.fullmatch(r'tskey-auth-[A-Za-z0-9-]{10,250}', key), 'Expected a Tailscale auth key.')
            with secret_file(key) as credential:
                self.app.enroll(str(credential), tailnet)
        else:
            print('Open the Tailscale sign-in address in this terminal and approve this host in the intended network.', flush=True)

            def browser(command):
                subprocess.run(command, env=ENV, stdin=tty.incoming, stdout=tty.outgoing, stderr=tty.outgoing,
                               timeout=620, check=True)

            self.app.enroll(None, tailnet, browser=browser)
        return True

    def finalize(self):
        if self.app.status()['phase'] == 'tailnet-only':
            self.app.verify_final_guard()
            self.app.verify_final_ssh()
            return True
        admitted = HANDOFF / 'cutover.json'
        if os.path.lexists(admitted):
            self.app.finalize(str(admitted))
            return True
        print('Independent access review still needs named tailnet and provider vantage points.')
        print('Use ./day0.sh access-request to export the live host selection to the independent verifier.')
        return False

    @contextmanager
    def owner_lock(self):
        secure_directory(STATE)
        descriptor = os.open(STATE / 'owner.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe day-zero ownership lock.')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def compatible_predecessor(self, historical):
        pin(historical, 40)
        if historical == INITIAL_MAINTENANCE_SOURCE:
            return True
        for name in (historical, historical[:12]):
            parent = OWNER_KITS / ('dev-pair-day0-' + name)
            marker = parent / 'SOURCE'
            if not os.path.lexists(marker):
                continue
            require(local_file(marker).read_text() == historical + '\n', 'Original owner checkout source pin differs.')
            checkout = parent / 'dev-pair'
            local_file(checkout / 'day0.sh')
            local_file(checkout / '.git/HEAD')
            git = ['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', str(checkout)]

            def capture(*args):
                return subprocess.check_output([*git, *args], env=ENV, timeout=10)

            require(capture('rev-parse', '--verify', 'HEAD').strip() == historical.encode() and
                    not capture('status', '--porcelain=v1', '--untracked-files=all'),
                    'Original owner checkout differs from its recorded pin.')
            entries = capture('ls-tree', '-r', '-z', historical)
            require(len(entries) <= 256 * 1024, 'Original owner checkout tree exceeds its bound.')
            production = [row for row in entries.split(b'\0') if row and not row.split(b'\t', 1)[1].startswith(b'tests/')]
            return sha256(b'\0'.join(production)).hexdigest() == INITIAL_MAINTENANCE_PRODUCTION_TREE
        return False

    def select_source(self, identity, revision, previous):
        if previous is None or previous['source_sha'] == revision:
            require(record(STATE / 'continuation.json') is None,
                    'Use the reviewed continuation checkout for this machine.')
            return revision, None
        historical = previous['source_sha']
        require(self.compatible_predecessor(historical),
                'This machine has day-zero progress under an unsupported pinned source.')
        desired_path = Path(BOOTSTRAP) / 'desired.json'
        journal_path = Path(BOOTSTRAP) / 'initialize.json'
        desired, journal = record(desired_path), record(journal_path)
        ready = record(Path(BOOTSTRAP) / 'host-ready.json')
        require(type(desired) is dict and type(journal) is dict and type(ready) is dict and
                ready.get('source_sha') == historical and
                journal.get('phase') == journal.get('maintenance_gptbox') == 'complete',
                'Finish maintenance initialization using the original reviewed checkout first.')
        context = pin(desired['gptbox_context_sha256'])
        image = self.maintenance_receipt(historical, context)
        require(image and self.probes(journal['result'], historical, context) == image and
                journal['target']['context_sha256'] == context and
                journal['target']['source_sha'] == historical,
                'The original sealed maintenance image does not match its completed initialization.')
        checkpoint = {'schema': 1, 'machine_id': identity['machine_id'], 'controller_source_sha': revision,
                      'maintenance_source_sha': historical, 'image_id': image,
                      'context_sha256': context, 'initializer_sha256': checksum(journal_path),
                      'desired_sha256': checksum(desired_path)}
        path = STATE / 'continuation.json'
        retained = record(path)
        require(retained is None or retained == checkpoint, 'Protected Day 0 continuation differs from this exact source or host.')
        if retained is None:
            save(self.app, path, checkpoint)
        self.progress = STATE / 'continuation-progress.json'
        return historical, image

    def access_exchange(self, source, response=None, *, workload=False, role=None):
        from destination_observation import encoding, read_access_envelope

        revision, archive = kit_source(self.repo, source)
        identity = self.original()
        with self.owner_lock():
            previous = record(STATE / 'progress.json')
            require(previous and previous['machine_id'] == identity['machine_id'] and identity['selinux'] == '1' and
                    not os.path.lexists('/.autorelabel'), 'Complete checked Day 0 maintenance setup and Tailscale enrollment first.')
            self.ensure_git(revision, archive)
            historical, image = self.select_source(identity, revision, previous)
            expected = pin(record(Path(BOOTSTRAP) / 'desired.json')['gptbox_context_sha256'])
            journal = record(Path(BOOTSTRAP) / 'initialize.json')
            require(journal is None or journal['phase'] == journal['maintenance_gptbox'] == 'complete',
                    'Resume the original maintenance initializer before requesting cutover.')
            require(image or self.maintenance_receipt(historical, expected), 'Complete the confined maintenance gptbox and probes first.')
            if role:
                driver = local_file(Path('/usr/libexec/dev-pair/renewal/driver'))
                connection = {key: os.environ[key] for key in ('SSH_CONNECTION', 'SSH_CLIENT') if key in os.environ}
                subprocess.run(['/usr/bin/python3', '-IB', str(driver), 'access-probe'], env={**ENV, **connection},
                               input=encoding({'role': role, 'source_sha': revision}), timeout=450, check=True)
                return
            if response is None:
                sys.stdout.buffer.write(encoding(self.app.access_cutover_binding(revision, workload=workload)))
                return
            payload, signature = read_access_envelope(response)
            # A verified signed pair is one bounded envelope in the transport.
            # The bootstrap verifier checks the exact bytes again under its lock.
            with tempfile.TemporaryDirectory(prefix='cutover-', dir=STATE) as temporary:
                document = Path(temporary) / 'receipt.json'
                document.write_bytes(payload)
                document.with_name('receipt.json.sig').write_bytes(signature)
                completed = self.app.finalize(str(document))
            message = ('Named core access is tailnet-only. Independent workload access remains held.'
                       if completed['access_scope'] == 'core' else 'The independent access review is accepted.')
            self.stage(identity, revision, 'access-cutover-complete', message + ' Run ./day0.sh resume to continue.')

    def commission(self, identity, revision):
        self.stage(identity, revision, 'host-bootstrap-complete',
                   'Confined maintenance gptbox and both offline probes verified. Workloads require an independently approved release and site.')
        if not (self.repo / 'tools/commission_host.py').is_file():
            return
        observed = self.call('commission_host.py', 'apply', '--source-sha', revision, timeout=1800)
        phase = observed.get('phase', 'unknown')
        if phase in ('pending', 'source-gap'):
            self.stage(identity, revision, 'host-bootstrap-complete', observed['message'])
        elif phase == 'ready':
            terminal = observed.get('owner_terminal')
            if terminal == '/usr/local/bin/dev-pair' and 'owner-intake' not in observed.get('held_features', []):
                self.stage(identity, revision, 'owner-terminal-ready',
                           'The named core tailnet terminal is available for approved jobs.')
            else:
                core_only = self.app.status().get('access_scope') == 'core'
                self.stage(identity, revision, 'managed-listener-ready',
                           'The managed checklist listener is ready. Export ./day0.sh access-request --workloads for independent role checks.'
                           if core_only else
                           'The managed checklist listener is ready. The owner terminal and workload activation remain held.')
        else:
            self.stage(identity, revision, 'commissioning-pending',
                       'The protected commissioning controller is still waiting. Run ./day0.sh resume.')

    def start(self, source, tty):
        revision, archive = kit_source(self.repo, source)
        identity = self.original()
        with self.owner_lock():
            prior = record(STATE / 'progress.json')
            require(prior is None or prior['machine_id'] == identity['machine_id'],
                    'The day-zero progress belongs to a different machine.')
            if prior is None:
                message = f"Selected host {identity['host']} | machine {identity['machine_id']} | Fedora 44 x86_64. Continue here? Type yes."
                if answer(tty, message).lower() != 'yes':
                    return
                self.stage(identity, revision, 'host-identified', 'Checking the pinned source and signed Fedora prerequisites.')
            self.ensure_git(revision, archive)
            historical, image = self.select_source(identity, revision, prior)
            report = self.app.status()
            if not report['prepared']:
                geometry = self.storage_geometry()
                access = self.transport(tty, identity, revision)
                if access is None:
                    self.stage(identity, revision, 'recovery-confirmation-pending',
                               'Source and capacity checks are complete. Confirm the separate provider recovery route, then run ./day0.sh resume.')
                    return
                if not self.selinux(identity, revision, tty):
                    return
                self.stage(identity, revision, 'managed-storage', 'Verifying the protected allocation and recovery reserve.')
                self.managed_storage(revision, access, geometry)
                self.stage(identity, revision, 'maintenance-gptbox', 'Checking public inputs, building the confined host gptbox and running both offline probes.')
                paths = self.inputs(revision)
                image = self.prepare(revision, access, paths, tty)
                require(self.maintenance_receipt(revision, paths[2]) == image, 'The completed maintenance probe evidence did not read back.')
            else:
                require(identity['selinux'] == '1' and not os.path.lexists('/.autorelabel'),
                        'An enrolled host requires checked enforcing SELinux before continuing. Keep recovery available.')
                desired = record(Path(BOOTSTRAP) / 'desired.json')
                expected = pin(desired['gptbox_context_sha256'])
                if not image and not self.resume_maintenance(identity, historical, expected, tty):
                    return
            self.stage(identity, revision, 'host-bootstrap-complete',
                       'The confined maintenance gptbox passed both offline probe cycles. Workloads remain held.')
            if not self.enroll(tty):
                self.stage(identity, revision, 'host-bootstrap-complete',
                           'Maintenance gptbox verified. Run ./day0.sh resume to enroll Tailscale when ready.')
                return
            if not self.finalize():
                self.stage(identity, revision, 'host-bootstrap-complete',
                           'Maintenance gptbox and tailnet enrollment are verified. Independent access handoff and workload activation remain pending.')
                return
            self.commission(identity, revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('start', 'status', 'resume', 'access-request', 'access-response', 'access-probe'))
    parser.add_argument('role', nargs='?', choices=('maintenance', 'development'))
    parser.add_argument('--source-sha')
    parser.add_argument('--confirm-recovery', action='store_true')
    parser.add_argument('--workloads', action='store_true')
    args = parser.parse_args()

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        require(os.getuid() == os.geteuid() == 0, 'Open the selected VPS root terminal in hPanel.')
        require((args.role is not None) == (args.stage == 'access-probe') and
                (not args.workloads or args.stage == 'access-request'), 'Select the exact access request or fixed role probe.')
        os.umask(0o077)
        day0 = DayZero()
        if args.confirm_recovery:
            require(args.stage == 'resume', 'Run ./day0.sh resume --confirm-recovery in the second terminal.')
            with tty_open() as tty:
                day0.confirm_recovery(tty, args.source_sha)
        elif args.stage == 'status':
            day0.status(args.source_sha)
        elif args.stage in ('access-request', 'access-response', 'access-probe'):
            day0.access_exchange(args.source_sha, sys.stdin.buffer if args.stage == 'access-response' else None,
                                 workload=args.workloads, role=args.role)
        else:
            with tty_open() as tty:
                day0.start(args.source_sha, tty)
        return 0
    except KeyboardInterrupt:
        print('Day 0 interrupted. Run ./day0.sh resume in the selected hPanel terminal.', file=sys.stderr)
        return 2
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, getpass.GetPassWarning) as error:
        print(f'Day 0 paused. {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
