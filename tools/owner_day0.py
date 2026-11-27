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

from bootstrap import ATTENDED_ACCESS, ATTENDED_RECEIPT, Blocked, Bootstrap, STATE as BOOTSTRAP, TRUST_SIGNERS, checked_file

REPO = Path(__file__).resolve().parents[1]
STATE = Path('/var/lib/dev-pair-day0')
HANDOFF = Path('/etc/dev-pair/day0')
ROOT = Path('/var/lib/dev-pair')
GIT = Path('/usr/bin/git')
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
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._/+-]+)', line)
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

    def call(self, name, *args, timeout=900, capture=True):
        script = local_file(self.repo / 'tools' / name)
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
        protected = record(self.progress)
        report = self.app.status()
        print(f"Host {item['host']} | Fedora 44 | SELinux { {'1': 'enforcing', '0': 'permissive'}.get(item['selinux'], item['selinux'])}")
        print('Source ' + (protected['source_sha'] if protected else source or 'awaiting the verified owner kit'))
        print('Day 0 phase ' + (protected['phase'] if protected else 'ready for inspection'))
        print('Maintenance gateway ' + ('recorded' if report['prepared'] else 'pending'))
        print('Tailnet enrollment ' + ('recorded' if report['enrollment_recorded'] else 'pending'))
        print('SSH access ' + report['phase'])
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
                     'source_sha': revision, 'created_at': int(time.time()), 'origin_session': os.getsid(0),
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
                all(challenge[key] == identity[key] for key in ('machine_id', 'boot_id')) and
                0 <= time.time() - challenge['created_at'] <= 600 and challenge['origin_session'] != os.getsid(0),
                'No matching request from a different current hPanel session. Resume in the first terminal.')
        code = secret_answer(tty, 'Enter the recovery challenge shown in the first terminal.')
        require(secrets.compare_digest(code, challenge['code']), 'Recovery challenge did not match.')
        fields = {name: challenge[name] for name in ('schema', 'machine_id', 'boot_id', 'source_sha', 'created_at', 'origin_session')}
        save(self.app, receipt, {**fields, 'kind': ATTENDED_ACCESS, 'confirmed_session': os.getsid(0)})
        print('Separate current-boot root recovery confirmed. Continue in the first terminal.')

    def selinux(self, identity, revision, tty):
        observed = self.call('selinux_bootstrap.py', 'inspect')
        state = ROOT / 'selinux-bootstrap/intent.json'
        if (observed['live'] == 'Enforcing' and observed['persistent'] == 'enforcing' and
                observed['policy_present'] and not os.path.lexists(state)):
            return True
        from selinux_bootstrap import code_digest
        self.stage(identity, revision, 'selinux-transition', 'Keep an independent hPanel root recovery session available.')
        if observed['live'] != 'Enforcing':
            if answer(tty, 'Verify the second hPanel root terminal on this VPS. Type yes to start the checked relabel and its bounded setup reboots.').lower() != 'yes':
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

    def managed_storage(self, revision, access):
        existing = record(Path('/var/lib/dev-pair-managed-storage.json'))
        if existing:
            size = existing['filesystem']['mib']
            inodes, reserve = existing['filesystem']['inodes'], existing['reserve_inodes']
        else:
            observed = os.statvfs('/var/lib')
            free = observed.f_bavail * observed.f_frsize // MIB
            size = min(20480, ((free - 9216) // 256) * 256)
            require(size >= 16384 and observed.f_favail >= 4096 + 262144,
                    'The inspected /var/lib filesystem lacks managed capacity plus the required 8 GiB physical reserve.')
            inodes, reserve = 262144, 4096
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

    def prepare(self, revision, access, input_paths, tty):
        context, upstream, expected = input_paths
        options = ['--apply', '--source-sha', revision, '--context', context, '--expected-context-sha256', expected,
                   '--distrobox-source', upstream, *access]
        if access[0] == '--bootstrap-source':
            options.append('--provider-ssh')
        if os.path.lexists(Path(BOOTSTRAP) / 'prepare-maintenance-host.json'):
            options.append('--retry')
        if os.path.lexists(Path(BOOTSTRAP) / 'operator-password-set'):
            self.call('gptbox.py', 'prepare-maintenance-host', *options)
            return
        value = secret_answer(tty, 'Set the named core console and sudo password.')
        confirmation = secret_answer(tty, 'Repeat the core password.')
        require(value and value == confirmation, 'The core passwords must be nonempty and match.')
        with secret_file(value) as credential:
            self.call('gptbox.py', 'prepare-maintenance-host', *options, '--password-file', credential)

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

    def finalize(self, identity, revision):
        if self.app.status()['phase'] == 'tailnet-only':
            self.app.verify_final_guard()
            self.app.verify_final_ssh()
            return True
        admitted = HANDOFF / 'cutover.json'
        if os.path.lexists(admitted):
            self.app.finalize(str(admitted))
            return True
        live, dns = self.app.tailscale_state()
        tailnet, node_id = self.app.identity_fields(live)
        path = STATE / 'cutover-request.json'
        pubkeys = checked_file(Path('/etc/ssh/dev-pair-keys/core'))
        save(self.app, path, {'version': 1, 'source_sha': revision, 'machine_id': identity['machine_id'],
                              'boot_id': identity['boot_id'], 'dns_name': dns, 'node_id': node_id, 'tailnet': tailnet,
                              'keys_sha256': sha256(pubkeys.read_bytes()).hexdigest()})
        print(f'Open a second independent hPanel root terminal and test SSH as core at {dns} from the intended tailnet.')
        print(f'Give {path} to the independent access verifier. Keep both sessions available until cutover is confirmed.')
        return False

    def commission(self, identity, revision, policy_sha):
        self.stage(identity, revision, 'host-bootstrap-complete',
                   'The maintenance gateway and tailnet-only SSH are ready. Workloads remain held for a separately approved release and site plan.')
        bound = STATE / 'commission-policy.json'
        prior = record(bound)
        if prior:
            require(prior['machine_id'] == identity['machine_id'] and prior['source_sha'] == revision and
                    policy_sha in (None, prior['policy_sha256']), 'The protected commissioning policy selection differs from this host or supplied digest.')
            policy_sha = prior['policy_sha256']
        if not policy_sha:
            return
        policy = HANDOFF / 'commission-policy.json'
        require(os.path.lexists(policy) and (self.repo / 'tools/commission_host.py').is_file(),
                'The independently approved commissioning policy and compatible controller must be staged before workload activation.')
        require(checksum(policy) == pin(policy_sha), 'Commissioning policy bytes differ from the independently delivered digest.')
        arguments = ('--source-sha', revision, '--policy', policy, '--policy-sha256', policy_sha)
        self.call('commission_host.py', 'inspect', *arguments)
        save(self.app, bound, {'schema': 1, 'machine_id': identity['machine_id'], 'source_sha': revision,
                               'policy_sha256': policy_sha})
        observed = self.call('commission_host.py', 'apply', *arguments, timeout=1800)
        phase = observed.get('phase', 'unknown')
        self.stage(identity, revision, 'commissioned' if phase == 'ready' else 'commissioning-pending',
                   'Use the named core tailnet route for admitted work.' if phase == 'ready' else
                   'The protected commissioning controller is still waiting. Run ./day0.sh resume.')

    def start(self, source, policy_sha, tty):
        revision, archive = kit_source(self.repo, source)
        identity = self.original()
        secure_directory(STATE)
        lock = STATE / 'owner.lock'
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe day-zero ownership lock.')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            prior = record(self.progress)
            require(prior is None or (prior['source_sha'], prior['machine_id']) == (revision, identity['machine_id']),
                    'This machine has day-zero progress under a different pinned source.')
            if prior is None:
                message = f"Selected host {identity['host']} | machine {identity['machine_id']} | Fedora 44 x86_64. Continue here? Type yes."
                if answer(tty, message).lower() != 'yes':
                    return
                self.stage(identity, revision, 'host-identified', 'Checking the pinned source and signed Fedora prerequisites.')
            self.ensure_git(revision, archive)
            if not self.selinux(identity, revision, tty):
                return
            report = self.app.status()
            if not report['prepared']:
                access = self.transport(tty, identity, revision)
                if access is None:
                    self.stage(identity, revision, 'recovery-confirmation-pending',
                               'Source and SELinux checks are complete. Confirm the separate provider recovery route, then run ./day0.sh resume.')
                    return
                self.stage(identity, revision, 'managed-storage', 'Verifying the protected allocation and recovery reserve.')
                self.managed_storage(revision, access)
                self.stage(identity, revision, 'maintenance-gateway', 'Verifying public build inputs and preparing the restricted role gateway.')
                self.prepare(revision, access, self.inputs(revision), tty)
            else:
                desired = record(Path(BOOTSTRAP) / 'desired.json')
                from gptbox import Gptbox
                Gptbox().maintenance_host_readiness(pin(desired['gptbox_context_sha256']))
            if not self.enroll(tty):
                self.stage(identity, revision, 'host-bootstrap-complete',
                           'Maintenance gateway ready. Tailscale enrollment is pending and workloads are held. Run ./day0.sh resume to enroll.')
                return
            if not self.finalize(identity, revision):
                self.stage(identity, revision, 'host-bootstrap-complete',
                           'The verified tailnet is enrolled. Independent access review and workload activation are pending. Run ./day0.sh resume after review.')
                return
            self.commission(identity, revision, policy_sha)
        finally:
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('start', 'status', 'resume'))
    parser.add_argument('--source-sha')
    parser.add_argument('--confirm-recovery', action='store_true')
    parser.add_argument('--commission-policy-sha')
    args = parser.parse_args()

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        require(os.getuid() == os.geteuid() == 0, 'Open the selected VPS root terminal in hPanel.')
        os.umask(0o077)
        day0 = DayZero()
        if args.confirm_recovery:
            require(args.stage == 'resume', 'Run ./day0.sh resume --confirm-recovery in the second terminal.')
            with tty_open() as tty:
                day0.confirm_recovery(tty, args.source_sha)
        elif args.stage == 'status':
            day0.status(args.source_sha)
        else:
            with tty_open() as tty:
                day0.start(args.source_sha, args.commission_policy_sha, tty)
        return 0
    except KeyboardInterrupt:
        print('Day 0 interrupted. Run ./day0.sh resume in the selected hPanel terminal.', file=sys.stderr)
        return 2
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, getpass.GetPassWarning) as error:
        print(f'Day 0 paused. {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
