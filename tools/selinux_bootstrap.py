#!/usr/bin/python3
"""Checked, resumable Fedora 44 initial SELinux convergence; no workload admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import stat
import sys

from bootstrap import Bootstrap, Blocked

STATE = '/var/lib/dev-pair/selinux-bootstrap'
INSTALL = '/usr/local/libexec/dev-pair-selinux'
HELPER = INSTALL + '/selinux_bootstrap.py'
OVERRIDE = '/etc/systemd/system/selinux-autorelabel.service.d/90-dev-pair-checked.conf'
FINALIZER = '/etc/systemd/system/dev-pair-selinux-finalize.service'
DROPIN = f'''# dev-pair checked Fedora 44 initial relabel
[Unit]
StartLimitIntervalSec=1h
StartLimitBurst=2
[Service]
ExecStart=
ExecStart=/usr/bin/python3 {HELPER} _relabel --apply
TimeoutStartSec=35min
TimeoutStopSec=10s
KillMode=control-group
Restart=on-failure
RestartSec=10s
'''
UNIT = f'''[Unit]
Description=Finish checked dev-pair initial SELinux transition
After=local-fs.target
ConditionPathExists={STATE}/intent.json
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {HELPER} _finalize --apply
TimeoutStartSec=5min
TimeoutStopSec=10s
KillMode=control-group
[Install]
WantedBy=multi-user.target
'''


def code_digest(directory=None):
    directory = Path(directory) if directory else Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for name in ('bootstrap.py', 'selinux_bootstrap.py'):
        digest.update(name.encode() + b'\0' + (directory / name).read_bytes())
    return digest.hexdigest()


def config_mode(content, wanted=None):
    modes = re.findall(r'^\s*SELINUX\s*=\s*[\"\']?(enforcing|permissive|disabled)[\"\']?\s*(?:#.*)?$', content, re.M)
    assignments = re.findall(r'^\s*SELINUX\s*=', content, re.M)
    policy = re.findall(r'^\s*SELINUXTYPE\s*=\s*[\"\']?([\w-]+)[\"\']?\s*(?:#.*)?$', content, re.M)
    if len(modes) != 1 or len(assignments) != 1 or policy != ['targeted']:
        raise Blocked('SELinux config must have one valid mode and targeted policy; inspect without guessing')
    if wanted is None:
        return modes[0]
    return re.sub(r'^(\s*SELINUX\s*=\s*)[\"\']?(?:enforcing|permissive|disabled)[\"\']?(\s*(?:#.*)?)$',
                  lambda match: match[1] + wanted + match[2], content, flags=re.M)


class Commands:
    """Bound direct children and their process groups, including manual invocations."""
    def __call__(self, *args, ok=(0,), input_text=None, timeout=900):
        environment = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
        try:
            process = subprocess.Popen(args, env=environment, text=True, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        except OSError:
            raise Blocked('SELinux command could not start; output withheld') from None
        try:
            output, _ = process.communicate(input=input_text, timeout=timeout)
        except BaseException as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                raise Blocked('SELinux command group cleanup did not complete; recovery required') from None
            if isinstance(error, subprocess.TimeoutExpired):
                raise Blocked('SELinux command timed out; process group terminated and child reaped') from None
            raise
        if process.returncode not in ok:
            raise Blocked('SELinux command failed; output withheld')
        return output


class SELinuxBootstrap(Bootstrap):
    def __init__(self, root=Path('/'), run=None):
        super().__init__(root, run or Commands())
        self.state = self.path(STATE)

    def state_json(self, name, default=None):
        text = self.text(f'{STATE}/{name}.json')
        value = json.loads(text) if text else default
        if value is not None and not isinstance(value, dict):
            raise Blocked('invalid protected transition record')
        return value

    def record(self, name, value):
        target = f'{STATE}/{name}.json'
        self.atomic(target, json.dumps(value, sort_keys=True) + '\n', expected=self.text(target) or None)

    def protected(self, path):
        target = self.path(path)
        for entry in [target, *target.parents]:
            if entry.exists() or entry.is_symlink():
                info = entry.lstat()
                if stat.S_ISLNK(info.st_mode) or info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                    raise Blocked('transition path must be owned, nonsymlink and protected')
            if entry == self.root:
                break
        return target

    def inspect(self):
        if os.geteuid() != 0:
            raise Blocked('root is required')
        release = self.text('/etc/os-release')
        if not re.search(r'^ID=[\"\']?fedora[\"\']?$', release, re.M) or not re.search(r'^VERSION_ID=[\"\']?44[\"\']?$', release, re.M):
            raise Blocked('only Fedora 44 initial SELinux setup is supported')
        if self.text('/proc/1/comm').strip() != 'systemd':
            raise Blocked('host systemd PID 1 is required')
        command_line = self.text('/proc/cmdline')
        if re.search(r'\bautorelabel\b', command_line):
            raise Blocked('persistent kernel autorelabel trigger would loop; bootloader changes are not automatic')
        args = command_line.split()
        for arg in args:
            if ((arg.startswith('selinux=') and arg != 'selinux=1')
                    or (arg.startswith('enforcing=') and arg != 'enforcing=1')
                    or (arg.startswith('security=') and arg != 'security=selinux')
                    or (arg.startswith('lsm=') and 'selinux' not in arg[4:].split(','))):
                raise Blocked('kernel SELinux arguments conflict with managed transition; bootloader changes are not automatic')
        boot = self.text('/proc/sys/kernel/random/boot_id').strip()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
            raise Blocked('cannot establish current boot identity')
        self.protected('/etc/selinux/config')
        config = self.text('/etc/selinux/config')
        mode = config_mode(config)
        live = self.run('/usr/sbin/getenforce').strip()
        if live not in ('Disabled', 'Permissive', 'Enforcing'):
            raise Blocked('unexpected live SELinux mode')
        if live != 'Enforcing' and 'enforcing=1' in args:
            raise Blocked('kernel enforcing=1 prevents the required permissive relabel boot')
        policy = any(self.path('/etc/selinux/targeted/policy').glob('policy.*'))
        return {'live': live, 'persistent': mode, 'boot_id': boot, 'policy_present': policy,
                'phase': self.state_json('complete', {}).get('phase', 'initial-or-incomplete'),
                'runtime_confinement': 'not verified; workloads remain gated by bootstrap admission'}

    def vendor_configuration(self, require_vendor=False):
        for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system'):
            path = self.path(base + '/selinux-autorelabel.service')
            if path.exists() or path.is_symlink():
                raise Blocked('foreign autorelabel unit override or mask must be resolved explicitly')
        for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system'):
            directory = self.path(base + '/selinux-autorelabel.service.d')
            if directory.exists() or directory.is_symlink():
                self.protected(base + '/selinux-autorelabel.service.d')
                if any(str(path) != str(self.path(OVERRIDE)) for path in directory.iterdir()):
                    raise Blocked('foreign autorelabel drop-ins must be resolved explicitly')
        if require_vendor:
            unit = '/usr/lib/systemd/system/selinux-autorelabel.service'
            target = self.protected(unit)
            if not target.is_file():
                raise Blocked('signed Fedora autorelabel unit is missing')
            owner = self.run('/usr/bin/rpm', '-q', '--qf', '%{NAME}\n', '-f', unit).strip()
            if owner != 'policycoreutils':
                raise Blocked('unexpected autorelabel unit package provenance')
            native = '/usr/bin/setfiles'
            program = self.protected(native)
            if not program.is_file() or not program.stat().st_mode & 0o111:
                raise Blocked('native setfiles executable is missing')
            if self.run('/usr/bin/rpm', '-q', '--qf', '%{NAME}\n', '-f', native).strip() != 'policycoreutils':
                raise Blocked('unexpected native setfiles package provenance')
            verification = self.run('/usr/bin/rpm', '-V', '--nomtime', '-f', unit, ok=(0, 1))
            if any(line.rstrip().endswith((unit, native)) for line in verification.splitlines()):
                raise Blocked('installed signed autorelabel unit or native setfiles has changed')

    def restore_labels(self):
        paths = [INSTALL, STATE, '/etc/selinux/config', OVERRIDE, FINALIZER]
        existing = [str(self.path(path)) for path in paths if self.path(path).exists()]
        self.run('/usr/sbin/restorecon', '-RF', *existing)

    def install(self, expected, source_sha):
        if not re.fullmatch(r'[0-9a-f]{64}', expected or '') or expected != code_digest():
            raise Blocked('reviewed two-file code digest does not match this installer')
        if not re.fullmatch(r'[0-9a-f]{40}', source_sha or ''):
            raise Blocked('full reviewed source revision is required')
        source = Path(__file__).resolve().parent
        if self.root == Path('/'):
            for name in ('bootstrap.py', 'selinux_bootstrap.py'):
                for entry in [source / name, *source.parents, source]:
                    info = entry.lstat()
                    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                        raise Blocked('reviewed installer source must be root-owned and protected')
        self.directory(INSTALL, mode=0o755)
        for name in ('bootstrap.py', 'selinux_bootstrap.py'):
            self.atomic(INSTALL + '/' + name, (source / name).read_text(), mode=0o555)
        self.atomic(OVERRIDE, DROPIN, mode=0o644)
        self.atomic(FINALIZER, UNIT, mode=0o644)
        self.restore_labels()
        self.run('/usr/bin/systemctl', 'daemon-reload')
        self.run('/usr/bin/systemctl', 'enable', 'dev-pair-selinux-finalize.service')

    def verify_installed(self, intent):
        self.vendor_configuration(require_vendor=True)
        for name in ('bootstrap.py', 'selinux_bootstrap.py'):
            path = self.protected(INSTALL + '/' + name)
            if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o555:
                raise Blocked('installed transition code is missing or mutable')
        if (code_digest(self.path(INSTALL)) != intent.get('code_sha256')
                or code_digest() != intent.get('code_sha256')):
            raise Blocked('installed transition code provenance mismatch')
        override_ok = self.text(OVERRIDE) == DROPIN or (not self.path(OVERRIDE).exists() and self.state_json('complete'))
        if not override_ok or self.text(FINALIZER) != UNIT:
            raise Blocked('managed transition unit configuration conflicts')
        self.protected(OVERRIDE)
        self.protected(FINALIZER)

    def observe_transition_boot(self, intent, boot):
        if self.state_json('complete'):
            return
        record = self.state_json('boots', {'ids': [intent['origin_boot_id']]})
        ids = record.get('ids')
        if not isinstance(ids, list) or not ids or ids[0] != intent['origin_boot_id']:
            raise Blocked('invalid transition boot history')
        if boot not in ids:
            if len(ids) >= 4:
                raise Blocked('total initial-transition boot budget exhausted; recovery required')
            ids.append(boot)
        self.record('boots', {'ids': ids})

    def context_identity(self):
        base = '/etc/selinux/targeted/contexts/files/file_contexts'
        identity = {}
        for suffix in ('', '.bin', '.local', '.local.bin', '.homedirs', '.homedirs.bin', '.subs', '.subs_dist'):
            path = self.protected(base + suffix)
            if path.exists() and not path.is_file():
                raise Blocked('file-context input must be a protected regular file')
            identity[suffix or 'main'] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        if identity['main'] is None:
            raise Blocked('targeted file-context specification is missing')
        return identity

    def relabel_plan(self):
        # Match Fedora's rw+seclabel filesystem selection. setfiles 3.11 itself
        # uses physical traversal, XDEV and non-seclabel exclusions; do not pass -m.
        mounts = {}
        text = self.text('/proc/self/mounts')
        if not text or len(text) > 1048576:
            raise Blocked('mount inventory is unavailable or over limit')
        for line in text.splitlines():
            fields = line.split()
            if len(fields) != 6:
                raise Blocked('malformed mount inventory')
            point = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[1])
            options = set(fields[3].split(','))
            if (not point.startswith('/') or '..' in Path(point).parts
                    or any(ord(char) < 32 or ord(char) == 127 for char in point)
                    or any(char in point for char in '*?[]\\')):
                raise Blocked('unsafe mountpoint in inventory')
            entry = {'type': fields[2], 'options': sorted(options)}
            if point in mounts and mounts[point] != entry:
                raise Blocked('overmounted filesystem needs explicit inspection')
            mounts[point] = entry
        if len(mounts) > 1024:
            raise Blocked('mount inventory exceeds initial bootstrap scope')
        writable, readonly = [], []
        for point, entry in mounts.items():
            options = set(entry['options'])
            if 'seclabel' in options:
                if any(option.startswith(('context=', 'fscontext=', 'defcontext=')) for option in options):
                    raise Blocked('context-mounted filesystem requires explicit inspection')
                if 'rw' in options and 'ro' not in options:
                    writable.append(point)
                elif 'ro' in options and 'rw' not in options:
                    readonly.append(point)
                else:
                    raise Blocked('ambiguous labeled filesystem access mode')
        if '/' not in writable:
            raise Blocked('writable seclabel root filesystem is required for checked full relabel')
        critical = ('/usr', '/etc', '/var', '/root', '/home', '/boot')
        def contains(parent, child):
            return parent == '/' or child == parent or child.startswith(parent.rstrip('/') + '/')
        for path in critical:
            covering = max((point for point in mounts if contains(point, path)), key=len)
            if covering not in writable:
                raise Blocked('a required system tree is not on a writable labeled filesystem')
        for point in mounts:
            # EFI's vfat mount has no security.selinux xattrs and is handled by
            # the native non-seclabel exclusion. Other mounted system subtrees
            # cannot disappear from a claimed checked OS relabel.
            if (point != '/boot/efi' and any(contains(root, point) for root in critical)
                    and point not in writable):
                raise Blocked('mounted system subtree cannot be covered by checked relabel')
        persistent = {}
        for point in sorted(writable + readonly):
            if mounts[point]['type'] in ('tmpfs', 'devtmpfs', 'ramfs'):
                continue
            if len(persistent) >= 64:
                raise Blocked('too many persistent filesystems for bounded initial bootstrap')
            raw = self.run('/usr/bin/findmnt', '--json', '--output', 'UUID,FSROOT',
                           '--mountpoint', str(self.path(point)), timeout=5)
            rows = json.loads(raw).get('filesystems', [])
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                raise Blocked('cannot establish persistent filesystem identity')
            uuid, fsroot = rows[0].get('uuid'), rows[0].get('fsroot')
            if (not isinstance(uuid, str) or not re.fullmatch(r'[0-9A-Fa-f-]{8,128}', uuid)
                    or not isinstance(fsroot, str) or not fsroot.startswith('/')
                    or '..' in Path(fsroot).parts or any(ord(char) < 32 for char in fsroot)):
                raise Blocked('persistent filesystem UUID or filesystem-root identity is unavailable')
            persistent[point] = {'uuid': uuid.lower(), 'fsroot': fsroot,
                                 'type': mounts[point]['type'], 'writable': point in writable}
        for path in critical:
            covering = max((point for point in mounts if contains(point, path)), key=len)
            if covering not in persistent or not persistent[covering]['writable']:
                raise Blocked('required system trees must have persistent writable label coverage')
        for point in mounts:
            if (point != '/boot/efi' and any(contains(root, point) for root in critical)
                    and not any(contains(cache, point) for cache in ('/var/tmp', '/var/run', '/var/lock'))
                    and point not in persistent):
                raise Blocked('transient mount cannot shadow required system code or durable state')
        excluded = []
        file = self.protected('/etc/selinux/fixfiles_exclude_dirs')
        if file.exists():
            if file.stat().st_size > 16384:
                raise Blocked('relabel exclusion configuration exceeds initial scope')
            for line in file.read_text().splitlines():
                path = line.strip()
                # Preserve vendor semantics for comments, relative and absent directories.
                if not path or path.startswith('#') or not path.startswith('/'):
                    continue
                if '..' in Path(path).parts or any(ord(char) < 32 for char in path):
                    raise Blocked('unsafe configured relabel exclusion')
                if not self.path(path).is_dir():
                    continue
                if any(contains(path, root) or contains(root, path) for root in critical):
                    raise Blocked('configured relabel exclusion covers required system code; preserving it for recovery')
                excluded.append(path)
        excluded = sorted(set(excluded + readonly))
        implicit_excluded = [point for point, entry in mounts.items() if 'seclabel' not in entry['options']]
        if any(contains(exclude, point) for exclude in excluded + implicit_excluded for point in writable):
            raise Blocked('an excluded ancestor would hide an admitted writable filesystem from native relabel')
        if len(excluded) > 128:
            raise Blocked('too many relabel exclusions for initial bootstrap')
        contexts = self.protected('/etc/selinux/targeted/contexts/files/file_contexts')
        if not contexts.is_file() or not contexts.stat().st_size:
            raise Blocked('targeted file-context specification is missing')
        return {'method': 'checked-setfiles', 'mounts': sorted(writable), 'excluded': excluded,
                'persistent_filesystems': persistent, 'contexts': self.context_identity(),
                'exclusion_config_sha256': hashlib.sha256(file.read_bytes()).hexdigest() if file.exists() else None}

    def checked_relabel(self):
        if self.path('/usr/sbin/genhomedircon').exists():
            self.run('/usr/sbin/genhomedircon', timeout=120)
        plan = self.relabel_plan()
        self.record('relabel-plan', plan)
        arguments = ['/usr/bin/setfiles', '-E', '-C', '-F', '-I', '-T', '1']
        for path in plan['excluded']:
            arguments.extend(('-e', str(self.path(path))))
        arguments.append(str(self.path('/etc/selinux/targeted/contexts/files/file_contexts')))
        arguments.extend(str(self.path(path)) for path in plan['mounts'])
        # Native setfiles aggregates actual errors and counted skipped errors in
        # its exit status. Fedora's fixfiles restore wrapper overwrites that status.
        self.run(*arguments, timeout=1800)
        return plan

    def verify_completion(self, intent, done):
        plan = self.state_json('relabel-plan', {})
        boot = done.get('boot_id')
        if (not isinstance(boot, str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot)
                or done.get('method') != 'checked-setfiles' or done.get('code_sha256') != intent['code_sha256']
                or done.get('boot_id') == intent['origin_boot_id']
                or done.get('plan_sha256') != hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()):
            raise Blocked('checked native relabel evidence is missing or inconsistent')

    def recover_marker_reboot(self, intent, done, boot):
        self.verify_completion(intent, done)
        if boot in (intent['origin_boot_id'], done['boot_id']):
            raise Blocked('marker recovery requires a distinct later boot')
        recovery = self.state_json('marker-recovery')
        if recovery is None:
            marker = self.protected('/.autorelabel')
            if not marker.exists() or marker.read_text() != '-F\n':
                raise Blocked('unexpected later relabel-target boot without an owned marker')
            recovery = {'boot_id': boot, 'relabel_boot_id': done['boot_id'],
                        'code_sha256': intent['code_sha256']}
            # Consume the single extra-boot allowance before marker removal or reboot.
            self.record('marker-recovery', recovery)
        if (recovery.get('boot_id') != boot or recovery.get('relabel_boot_id') != done['boot_id']
                or recovery.get('code_sha256') != intent['code_sha256']):
            raise Blocked('post-relabel marker recovery allowance is exhausted')
        self.remove_marker()
        return self.reboot(intent, boot, recovery=True)

    def reboot(self, intent, boot, recovery=False):
        self.observe_transition_boot(intent, boot)
        done = self.state_json('relabel-done')
        expected_boot = done.get('boot_id') if done else intent['origin_boot_id']
        if done:
            self.verify_completion(intent, done)
        if recovery:
            allowance = self.state_json('marker-recovery', {})
            if not done or allowance != {'boot_id': boot, 'relabel_boot_id': done['boot_id'], 'code_sha256': intent['code_sha256']}:
                raise Blocked('no matching consumed marker-recovery allowance')
            expected_boot = boot
        if self.state_json('complete') or boot != expected_boot:
            raise Blocked('unexpected transition phase cannot request another reboot')
        if not intent.get('reboot_authorized'):
            return {'phase': 'pending-explicit-reboot', 'boot_id': boot}
        counts = self.state_json('reboots', {})
        attempts = counts.get(boot, 0)
        if (not isinstance(attempts, int) or any(not isinstance(value, int) or value < 0 for value in counts.values())
                or attempts >= 3 or sum(counts.values()) >= 6):
            raise Blocked('reboot retry budget exhausted for this boot; inspect recovery route')
        counts[boot] = attempts + 1
        self.record('reboots', counts)
        self.event('setup-reboot', 'requested')
        self.run('/usr/bin/systemctl', 'reboot')
        return {'phase': 'reboot-requested', 'boot_id': boot}

    def converge(self, *, apply=False, reboot=False, expected=None, source_sha=None):
        observed = self.inspect()
        self.vendor_configuration()
        if not apply:
            return {**observed, 'preview': True, 'would_reboot': False}
        with self.lock():
            intent = self.state_json('intent')
            if intent:
                self.verify_installed(intent)
                self.observe_transition_boot(intent, observed['boot_id'])
                if expected and expected != intent.get('code_sha256'):
                    raise Blocked('changed transition code requires separately reviewed recovery')
                if reboot and not intent.get('reboot_authorized'):
                    intent['reboot_authorized'] = True
                    self.record('intent', intent)
                if self.state_json('complete'):
                    return self.finish()
                done = self.state_json('relabel-done')
                if done:
                    self.verify_completion(intent, done)
                    if observed['boot_id'] == done['boot_id']:
                        self.remove_marker()
                        return self.reboot(intent, observed['boot_id'])
                    recovery = self.state_json('marker-recovery', {})
                    if self.path('/.autorelabel').exists() or recovery.get('boot_id') == observed['boot_id']:
                        return self.recover_marker_reboot(intent, done, observed['boot_id'])
                    return self.finalize()
                if observed['boot_id'] != intent['origin_boot_id']:
                    raise Blocked('unexpected boot without checked relabel completion; no rearming or reboot')
                attempt = self.state_json('relabel-attempt', {})
                if attempt.get('count', 0) >= 2:
                    raise Blocked('checked relabel retry budget exhausted; recovery required')
                if not attempt:
                    self.arm(intent)
                return self.reboot(intent, observed['boot_id'])
            if observed['live'] == 'Enforcing':
                if not observed['policy_present']:
                    raise Blocked('persistent targeted policy is missing')
                if self.path('/.autorelabel').exists():
                    raise Blocked('existing relabel request needs explicit recovery; enforcing host unchanged')
                if observed['persistent'] != 'enforcing':
                    before = self.text('/etc/selinux/config')
                    self.atomic('/etc/selinux/config', config_mode(before, 'enforcing'), mode=stat.S_IMODE(self.path('/etc/selinux/config').stat().st_mode), expected=before)
                    self.run('/usr/sbin/restorecon', str(self.path('/etc/selinux/config')))
                return {**self.inspect(), 'phase': 'already-enforcing', 'reboot_requested': False}
            # Code binding is checked before package, configuration or boot changes.
            if expected != code_digest() or not re.fullmatch(r'[0-9a-f]{40}', source_sha or ''):
                raise Blocked('reviewed code digest and full source revision are required')
            self.step('selinux-packages', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                      '--setopt=localpkg_gpgcheck=1', '--disablerepo=*', '--enablerepo=fedora',
                      '--enablerepo=updates', 'install', 'selinux-policy-targeted', 'policycoreutils', 'libselinux-utils'))
            if not self.inspect()['policy_present']:
                raise Blocked('targeted policy is missing after signed prerequisite installation')
            self.vendor_configuration(require_vendor=True)
            before = self.text('/etc/selinux/config')
            permissive = config_mode(before, 'permissive')
            marker = self.protected('/.autorelabel')
            if marker.exists() and marker.read_text() not in ('', '-F\n'):
                raise Blocked('foreign relabel request conflicts')
            self.install(expected, source_sha)
            intent = {'schema': 1, 'code_sha256': expected, 'source_sha': source_sha,
                      'origin_boot_id': observed['boot_id'], 'reboot_authorized': reboot,
                      'config_permissive_sha256': hashlib.sha256(permissive.encode()).hexdigest(),
                      'config_enforcing_sha256': hashlib.sha256(config_mode(before, 'enforcing').encode()).hexdigest()}
            self.atomic(f'{STATE}/config-original', before)
            self.record('intent', intent)
            self.arm(intent)
            self.event('selinux-transition', 'armed')
            return self.reboot(intent, observed['boot_id'])

    def arm(self, intent):
        before = self.text(f'{STATE}/config-original')
        permissive = config_mode(before, 'permissive')
        if hashlib.sha256(permissive.encode()).hexdigest() != intent['config_permissive_sha256']:
            raise Blocked('original transition configuration provenance mismatch')
        current = self.text('/etc/selinux/config')
        if current not in (before, permissive):
            raise Blocked('configuration changed before relabel; preserving foreign state')
        marker = self.protected('/.autorelabel')
        if marker.exists() and marker.read_text() not in ('', '-F\n'):
            raise Blocked('foreign relabel marker preserved')
        self.atomic('/etc/selinux/config', permissive,
                    mode=stat.S_IMODE(self.path('/etc/selinux/config').stat().st_mode), expected=current)
        self.atomic('/.autorelabel', '-F\n', expected=marker.read_text() if marker.exists() else None)
        self.restore_labels()

    def remove_marker(self):
        marker = self.protected('/.autorelabel')
        if marker.exists():
            if marker.read_text() != '-F\n':
                raise Blocked('foreign relabel marker preserved')
            marker.unlink()
        descriptor = os.open(self.root, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def relabel(self):
        with self.lock():
            observed = self.inspect()
            intent = self.state_json('intent')
            if not intent:
                raise Blocked('checked relabel has no protected intent')
            self.verify_installed(intent)
            self.observe_transition_boot(intent, observed['boot_id'])
            if self.state_json('complete'):
                raise Blocked('completed transition cannot consume a future relabel request; recover stale override')
            if observed['boot_id'] == intent['origin_boot_id'] or observed['live'] != 'Permissive':
                raise Blocked('relabel requires a different, permissive boot; no mode downgrade')
            if observed['persistent'] != 'permissive' or not observed['policy_present']:
                raise Blocked('permissive targeted relabel configuration is missing')
            done = self.state_json('relabel-done')
            if done:
                self.verify_completion(intent, done)
                if done.get('boot_id') != observed['boot_id']:
                    return self.recover_marker_reboot(intent, done, observed['boot_id'])
                self.remove_marker()
                return self.reboot(intent, observed['boot_id'])
            attempt = self.state_json('relabel-attempt', {})
            if attempt.get('count', 0) >= 2:
                raise Blocked('checked relabel retry budget exhausted; no automatic reboot')
            if self.text('/.autorelabel') != '-F\n':
                raise Blocked('managed relabel marker missing or changed')
            self.record('relabel-attempt', {'boot_id': observed['boot_id'], 'count': attempt.get('count', 0) + 1})
            self.event('checked-full-relabel', 'begin')
            # No sourced config/marker commands or unchecked shell wrapper.
            plan = self.checked_relabel()
            self.restore_labels()
            self.record('relabel-done', {'boot_id': observed['boot_id'], 'code_sha256': intent['code_sha256'],
                                         'method': plan['method'], 'plan_sha256': hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()})
            self.event('checked-full-relabel', 'complete')
            self.remove_marker()
            return self.reboot(intent, observed['boot_id'])

    def finalize(self):
        # Called by the narrow normal-boot unit or an explicitly applying recovery command.
        observed = self.inspect()
        intent, done = self.state_json('intent'), self.state_json('relabel-done')
        if not intent or not done:
            raise Blocked('checked relabel completion is missing; permissive state is insufficient')
        self.verify_installed(intent)
        self.observe_transition_boot(intent, observed['boot_id'])
        self.verify_completion(intent, done)
        recorded_plan = self.state_json('relabel-plan')
        current_plan = self.relabel_plan()
        for field in ('persistent_filesystems', 'contexts', 'exclusion_config_sha256'):
            if current_plan.get(field) != recorded_plan.get(field):
                raise Blocked('persistent filesystem or labeling policy changed after relabel; no enforcement')
        if (done.get('code_sha256') != intent['code_sha256'] or done.get('boot_id') == intent['origin_boot_id']
                or observed['boot_id'] in (intent['origin_boot_id'], done.get('boot_id'))):
            raise Blocked('enforcement requires a distinct post-relabel boot and matching checked evidence')
        if self.path('/.autorelabel').exists():
            raise Blocked('relabel marker remains; no completion or disarm')
        before = self.text('/etc/selinux/config')
        if hashlib.sha256(before.encode()).hexdigest() not in (intent['config_permissive_sha256'], intent['config_enforcing_sha256']):
            raise Blocked('SELinux configuration changed during transition; preserving it for recovery')
        if observed['live'] not in ('Permissive', 'Enforcing') or not observed['policy_present']:
            raise Blocked('post-relabel policy is not active')
        if observed['live'] != 'Enforcing':
            self.run('/usr/sbin/setenforce', '1')
        if self.run('/usr/sbin/getenforce').strip() != 'Enforcing':
            raise Blocked('live enforcement failed; transition remains armed')
        self.atomic('/etc/selinux/config', config_mode(before, 'enforcing'),
                    mode=stat.S_IMODE(self.path('/etc/selinux/config').stat().st_mode), expected=before)
        self.restore_labels()
        if self.inspect()['persistent'] != 'enforcing':
            raise Blocked('persistent enforcement observation failed')
        self.record('complete', {'phase': 'enforcing', 'boot_id': observed['boot_id'],
                                'relabel_boot_id': done['boot_id'], 'code_sha256': intent['code_sha256']})
        return self.finish()

    def finish(self):
        observed = self.inspect()
        if observed['live'] != 'Enforcing' or observed['persistent'] != 'enforcing':
            raise Blocked('completed transition lost enforcement; no automatic permissive fallback')
        if self.path(OVERRIDE).exists():
            if self.text(OVERRIDE) != DROPIN:
                raise Blocked('foreign autorelabel override preserved')
            self.protected(OVERRIDE).unlink()
        self.run('/usr/bin/systemctl', 'disable', 'dev-pair-selinux-finalize.service')
        self.run('/usr/bin/systemctl', 'daemon-reload')
        self.event('selinux-transition', 'complete')
        return {**observed, 'phase': 'enforcing', 'runtime_confinement': 'not verified'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('inspect', 'converge', 'code-digest', '_relabel', '_finalize'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--reboot', action='store_true', help='authorize the bounded setup reboots')
    parser.add_argument('--expected-code-sha256')
    parser.add_argument('--source-sha')
    args = parser.parse_args()
    try:
        tool = SELinuxBootstrap()
        if args.reboot and not args.apply:
            raise Blocked('--reboot requires --apply')
        if args.stage == 'code-digest':
            print(code_digest())
            return 0
        if args.stage == 'inspect':
            result = tool.inspect()
        elif args.stage == 'converge':
            result = tool.converge(apply=args.apply, reboot=args.reboot,
                                  expected=args.expected_code_sha256, source_sha=args.source_sha)
        elif args.stage == '_relabel':
            if not args.apply:
                raise Blocked('internal relabel requires explicit --apply and protected intent')
            result = tool.relabel()
        else:
            if not args.apply:
                raise Blocked('internal finalization requires explicit --apply and protected intent')
            with tool.lock():
                result = tool.finalize()
        print(json.dumps(result, indent=2))
        return 0
    except (Blocked, OSError, ValueError, KeyError):
        print('SELinux transition blocked; inspect protected state and local journal; no runtime acceptance', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
