#!/usr/bin/python3
"""Provision the isolated checklist executor and deploy one verified release on erebus."""
import argparse
import contextlib
import fcntl
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
import uuid

from bootstrap import Blocked, Bootstrap, SUDO_PACKAGE_QUERY, checked_file, relay
from release_trust import DIGEST, SHA, ReleaseTrust, protect, require

ROOT = '/var/lib/dev-pair'
HOME = ROOT + '/checklist-executor'
VALIDATION = ROOT + '/checklist-validation'
LIVE = ROOT + '/checklist-live'
CONTROL = ROOT + '/checklist-release'
FENCE = ROOT + '/renewal-fence'
RECEIPTS = ROOT + '/checklist-receipts'
CODE = '/usr/libexec/dev-pair/checklist'
TRUST_CODE = '/usr/libexec/dev-pair/tools'
OWNER = 'dp-checklist'
CONTAINER = 'dp-checklist-app'
UNIT = CONTAINER + '.service'
GATE = '/etc/dev-pair/checklist'
PROVISION = CONTROL + '/provision.json'
ACTIVATION = CONTROL + '/release.json'
MANAGED_INTENT = '/var/lib/dev-pair-managed-storage.json'
MANAGED_IMAGE = '/var/lib/dev-pair-managed.ext4'
MANAGED_INODES = 1310720
STORAGE = {'validation': VALIDATION, 'live': LIVE}
NETWORKS = {'validation': 'dev-pair-checklist-internal', 'live': 'dev-pair-checklist-release'}
FILES = ('tools/host_handoff.py', 'tools/job_protocol.py', 'tools/ledger_recovery.py', 'tools/jobs.py',
         'runtime/checklist/checklist_quadlet.py', 'runtime/checklist/acceptance.container',
         'examples/checklist/checklist.py')
EXECUTOR = 'dev-pair-checklist-executor@.service'
EXECUTOR_OVERRIDE = '/etc/systemd/system/' + EXECUTOR + '.d/checklist-release.conf'
RENEWAL = ROOT + '/renewal'
PORT = 18279
PROXY = f'http://127.0.0.1:{PORT}'
TLS_FILES = ('cert.pem', 'peer.pem', 'key.pem')
COMPATIBILITY = 'checklist-sqlite-v1'
RUNUSER = '/usr/sbin/runuser'
SYSTEMCTL = '/usr/bin/systemctl'
TAILSCALE = '/usr/bin/tailscale'
MIB = 1024**2


def inventory_digest(items):
    require(type(items) is list and len(items) <= 1000, 'checklist inventory is outside the supported data contract')
    last = 0
    for row in items:
        require(type(row) is dict and set(row) == {'id', 'title', 'done'} and type(row['id']) is int
                and last < row['id'] <= 2**63 - 1 and type(row['title']) is str and 1 <= len(row['title']) <= 120
                and type(row['done']) is bool, 'invalid checklist inventory row')
        last = row['id']
    return hashlib.sha256(json.dumps(items, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def record_text(value):
    return json.dumps(value, sort_keys=True) + '\n'


class Destination(Bootstrap):
    def record(self, path):
        return json.loads(checked_file(path).read_bytes(), object_pairs_hook=relay.unique)

    def account(self):
        user = pwd.getpwnam(OWNER)
        require(user.pw_uid == user.pw_gid >= 1000 and user.pw_dir == HOME and user.pw_shell == '/usr/sbin/nologin'
                and grp.getgrgid(user.pw_gid).gr_name == OWNER and os.getgrouplist(OWNER, user.pw_gid) == [user.pw_gid],
                'checklist account must be a dedicated nonlogin identity with one private group')
        fields = self.run('/usr/bin/passwd', '-S', OWNER, timeout=10).split()
        require(len(fields) >= 2 and fields[:2] in ([OWNER, 'L'], [OWNER, 'LK']), 'checklist password is not locked')
        return user.pw_uid

    def subprocess_role(self, uid, *args, timeout=30, **options):
        runtime = f'/run/user/{uid}'
        return self.run(RUNUSER, '-u', OWNER, '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin',
                        f'HOME={HOME}', f'USER={OWNER}', f'LOGNAME={OWNER}', 'LC_ALL=C.UTF-8',
                        f'XDG_RUNTIME_DIR={runtime}', f'DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus',
                        *args, timeout=timeout, **options)

    def user_unit(self, uid, *args):
        return self.subprocess_role(uid, SYSTEMCTL, '--user', *args)

    def podman(self, uid, role, *args, timeout=30):
        suffix = '-live' if role == 'live' else ''
        return self.subprocess_role(uid, '/usr/bin/env', f'TMPDIR={STORAGE[role]}/image-copy',
                                    'CONTAINERS_CONF=' + GATE + '/' + role + '-containers.conf',
                                    '/usr/bin/podman', '--root', STORAGE[role] + '/graph',
                                    '--runroot', f'/run/user/{uid}/dev-pair-checklist{suffix}-runroot',
                                    *args, timeout=timeout)

    def owned_directory(self, path, uid):
        self._directory_as(path, 0o700, uid, uid, change_owner=True, check_gid=True)

    def subid(self, file, flag, uid, start, live):
        lines = protect(file).read_text().splitlines()
        end = start + 65536
        owned = []
        for line in lines:
            user, lower, count = line.split(':')
            lower, count = int(lower), int(count)
            require(lower > 0 and count > 0 and lower + count <= 2**32 - 1, 'invalid existing subordinate ID range')
            if user in (OWNER, str(uid)):
                owned.append((lower, count))
            else:
                require(not lower <= uid < lower + count and (lower + count <= start or end <= lower),
                        'selected checklist primary or subordinate IDs overlap an existing range')
        require(not any(start <= value < end for value in live) and owned in ([], [(start, 65536)]),
                'selected checklist subordinate IDs overlap a live identity or existing allocation')
        if not owned and flag:
            self.run('/usr/sbin/usermod', flag, f'{start}-{end - 1}', OWNER, timeout=15)
            require(self.subid(file, None, uid, start, live), 'checklist subordinate allocation did not persist')
        return bool(owned)

    def storage_ready(self, path, uid):
        # Use the same native filesystem, byte/inode and ownership oracle as the host executor.
        command = ('import sys; sys.path[:0] = [sys.argv[1] + "/tools", sys.argv[1] + "/runtime/checklist"]; '
                   'import checklist_quadlet as check; from pathlib import Path; '
                   'assert check.storage_identity(Path(sys.argv[2]))')
        if path == VALIDATION:
            self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', command, CODE, path)
        else:
            self.mount_observation(path, self.record(PROVISION)['mounts']['live'])

    def mount_observation(self, path, spec, *, max_inodes=65536):
        mounted = json.loads(self.run('/usr/bin/findmnt', '--json', '--mountpoint', path,
                                      '--output', 'SOURCE,FSTYPE,OPTIONS,UUID', timeout=10))['filesystems']
        require(len(mounted) == 1 and mounted[0]['fstype'] == 'ext4' and mounted[0]['uuid'] == spec['uuid'],
                'checklist requires its exact dedicated ext4 mount')
        options = mounted[0]['options'].split(',')
        require({'rw', 'nodev', 'nosuid'}.issubset(options) and 'discard' not in options,
                'checklist mount does not enforce the private data boundary')
        source = mounted[0]['source']
        device = Path(path).stat().st_dev
        require(re.fullmatch(r'/dev/loop[0-9]+', source) and device != Path(path).parent.stat().st_dev,
                'checklist mount does not have its own reserved backing device')
        if 'loop' in spec:
            require(source == spec['loop'], 'managed storage did not recover its enrolled loop device')
        backing = Path(f'/sys/dev/block/{os.major(device)}:{os.minor(device)}/loop/backing_file').read_text().strip()
        image = protect(backing)
        info = image.stat()
        require(str(image) == spec['image'] and info.st_size == spec['mib'] * MIB
                and info.st_blocks * 512 >= spec['mib'] * MIB and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600,
                'checklist mount does not use its fully reserved owned backing file')
        geometry = os.statvfs(path)
        require(0 < geometry.f_blocks * geometry.f_frsize <= spec['mib'] * MIB
                and 0 < geometry.f_files <= max_inodes
                and geometry.f_files <= spec['inodes'] + (4096 if max_inodes == MANAGED_INODES else 512),
                'checklist mount exceeds declared geometry')
        matches = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                   if line.split()[2] == f'{os.major(device)}:{os.minor(device)}']
        require(len(matches) == 1 and matches[0].split()[3:5] == ['/', path],
                'checklist storage is not the unique dedicated filesystem root')

    def allocate(self, spec, receipt, reserve_mib, reserve_inodes):
        image = Path(spec['image'])
        size = spec['mib'] * MIB
        previous = self.record(receipt) if os.path.lexists(receipt) else None
        open_type = 0 if previous else os.O_CREAT | os.O_EXCL
        descriptor = os.open(image, open_type | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            if not previous:
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o600)
            protect(image)
            old = os.fstat(descriptor)
            identity = {'image': str(image), 'device': old.st_dev, 'inode': old.st_ino,
                        'size': size, 'fs_uuid': spec['uuid']}
            require(stat.S_IMODE(old.st_mode) == 0o600 and old.st_uid == old.st_gid == 0
                    and old.st_size in (0, size) and old.st_nlink == 1, 'unexpected dedicated backing file')
            if previous:
                require(previous == {**identity, 'state': previous.get('state')}
                        and previous.get('state') in ('created', 'formatting', 'formatted'), 'protected backing object identity changed')
            else:
                previous = {**identity, 'state': 'created'}
                self.atomic(receipt, record_text(previous))
            remaining = max(size - old.st_blocks * 512, 0)
            space = os.statvfs(image.parent)
            require(space.f_bavail * space.f_frsize >= reserve_mib * MIB + remaining
                    and 0 < space.f_files and space.f_favail >= reserve_inodes, 'selected VPS cannot preserve the declared free reserve')
            if remaining:
                os.posix_fallocate(descriptor, 0, size)
                os.fsync(descriptor)
            current = os.fstat(descriptor)
            require(current.st_size == size and current.st_blocks * 512 >= size, 'checklist backing is not fully allocated')
        finally:
            os.close(descriptor)
        remaining = os.statvfs(image.parent)
        require(remaining.f_bavail * remaining.f_frsize >= reserve_mib * MIB and remaining.f_favail >= reserve_inodes,
                'filesystem reserve was not preserved after allocation')
        observed = self.run('/usr/sbin/blkid', '-p', '-o', 'export', str(image), ok=(0, 2), timeout=10)
        expected = {'UUID': spec['uuid'], 'TYPE': 'ext4'}
        if not observed:
            require(previous['state'] == 'created', 'previous filesystem formatting remains uncertain; preserved backing bytes')
            formatting = {**previous, 'state': 'formatting'}
            self.atomic(receipt, record_text(formatting), expected=record_text(previous))
            previous = formatting
            self.run('/usr/sbin/mkfs.ext4', '-F', '-q', '-N', str(spec['inodes']), '-m', '0', '-U', spec['uuid'],
                     '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', str(image), timeout=120)
            observed = self.run('/usr/sbin/blkid', '-p', '-o', 'export', str(image), timeout=10)
        fields = dict(line.split('=', 1) for line in observed.splitlines())
        require(all(fields.get(key) == value for key, value in expected.items()), 'foreign checklist backing filesystem')
        self.atomic(receipt, record_text({**identity, 'state': 'formatted'}), expected=record_text(previous))

    def mount(self, path, spec, *, max_inodes=65536):
        image = spec['image']
        if self.has_mount_at(path):
            self.mount_observation(path, spec, max_inodes=max_inodes)
        unit = self.run('/usr/bin/systemd-escape', '--path', '--suffix=mount', path, timeout=10).strip()
        require(re.fullmatch(r'[a-z0-9\\x-]+\.mount', unit), 'unexpected checklist mount unit name')
        # An unmounted mount point remains root-owned. Only the mounted filesystem is role-owned.
        if not Path(path).exists():
            self.directory(path, mode=0o755)
        loop = 'loop=' + spec['loop'] if 'loop' in spec else 'loop'
        self.atomic('/etc/systemd/system/' + unit,
                    '[Unit]\nDescription=Dedicated Dev-pair checklist storage\n'
                    f'[Mount]\nWhat={image}\nWhere={path}\nType=ext4\nOptions={loop},nodiscard,nodev,nosuid\n'
                    '[Install]\nWantedBy=local-fs.target\n', mode=0o644)
        self.run(SYSTEMCTL, 'daemon-reload', timeout=15)
        self.run(SYSTEMCTL, 'enable', '--now', unit, timeout=40)
        self.mount_observation(path, spec, max_inodes=max_inodes)

    @staticmethod
    def has_mount_at(path):
        return any(row.split()[4] == path for row in Path('/proc/self/mountinfo').read_text().splitlines())

    def managed_storage(self, args):
        require(1024 <= args.managed_mib <= 20480 and 4096 <= args.managed_inodes <= MANAGED_INODES - 512
                and args.reserve_inodes >= 4096, 'invalid bounded managed filesystem geometry or physical inode reserve')
        self.destination_source(args.platform_sha)
        self.validate_bootstrap_access(args.bootstrap_source, args.console_receipt)
        if args.bootstrap_source:
            require(self.observed_ssh_peer(), 'SSH-backed hPanel storage requires an observed SSH peer in the approved scope')
        previous_umask = os.umask(0o077)
        try:
            lock = os.open('/run/dev-pair-managed-storage.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        finally:
            os.umask(previous_umask)
        try:
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'unexpected managed-storage lock identity')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = self.record(MANAGED_INTENT) if os.path.lexists(MANAGED_INTENT) else None
            if not state:
                self.preflight()
                root = Path(ROOT)
                require(not self.has_mount_at(ROOT) and not os.path.lexists(MANAGED_IMAGE)
                        and not root.is_symlink() and (not root.exists() or root.is_dir() and not any(root.iterdir())),
                        'refusing to mount managed storage over an occupied or unowned existing root')
            loop = state['filesystem']['loop'] if state else self.run('/usr/sbin/losetup', '--find', timeout=10).strip()
            require(re.fullmatch(r'/dev/loop[0-9]+', loop), 'cannot enroll an exact managed loop device')
            spec = {'mib': args.managed_mib, 'inodes': args.managed_inodes, 'image': MANAGED_IMAGE, 'loop': loop,
                    'uuid': state['filesystem']['uuid'] if state else str(uuid.uuid4())}
            wanted = {'version': 1, 'machine_id': self.destination_identity()['machine_id'], 'filesystem': spec,
                      'reserve_inodes': args.reserve_inodes}
            require(not state or state == wanted, 'managed-storage retry differs from the protected intent')
            if not self.has_mount_at(ROOT) and Path(ROOT).exists():
                require(Path(ROOT).is_dir() and not Path(ROOT).is_symlink() and not any(Path(ROOT).iterdir()),
                        'refusing to hide existing files beneath the managed ext4 root')
            self.atomic(MANAGED_INTENT, record_text(wanted))
            self.allocate(spec, MANAGED_INTENT + '.backing', 8192, args.reserve_inodes)
            self.mount(ROOT, spec, max_inodes=MANAGED_INODES)
            self.directory(ROOT, mode=0o755)
            self.run('/usr/sbin/restorecon', '-F', ROOT, timeout=10)
            return {'path': ROOT, 'filesystem': spec, 'physical_reserve_mib': 8192}
        finally:
            os.close(lock)

    def reserve(self, path, spec, uid, reserve_mib, reserve_inodes):
        self.directory(ROOT + '/checklist-storage', mode=0o711)
        receipt = CONTROL + '/backing-' + Path(spec['image']).stem + '.json'
        self.allocate(spec, receipt, reserve_mib, reserve_inodes)
        self.mount(path, spec)
        root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(root)
            require(info.st_uid in (0, uid) and info.st_gid in (0, uid), 'foreign checklist filesystem owner')
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, uid, 0o700):
                os.fchown(root, uid, uid)
                os.fchmod(root, 0o700)
                os.fsync(root)
        finally:
            os.close(root)
        for name in ('graph', 'attempts', 'image-copy') if path == VALIDATION else ('graph', 'data', 'backups', 'image-copy'):
            self.owned_directory(path + '/' + name, uid)

    def role_secret(self, directory, name, data, uid):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, 'checklist secret directory is not private')
            try:
                file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            except FileNotFoundError:
                file = None
            if file is not None:
                with os.fdopen(file, 'rb') as stream:
                    existing = os.fstat(stream.fileno())
                    require(stat.S_ISREG(existing.st_mode) and existing.st_nlink == 1 and existing.st_uid == uid
                            and stat.S_IMODE(existing.st_mode) == 0o600 and stream.read(len(data) + 1) == data,
                            'existing checklist secret differs from the independently supplied profile')
                return
            part = '.hold-' + uuid.uuid4().hex
            try:
                with os.fdopen(os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                                       dir_fd=descriptor), 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fchown(stream.fileno(), uid, uid)
                    os.fsync(stream.fileno())
                os.link(part, name, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(part, dir_fd=descriptor)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def source_files(self, source):
        self.destination_source(source)
        repo = Path(__file__).absolute().parents[1]
        files = (*FILES, 'runtime/checklist/' + EXECUTOR, 'tools/release_trust.py', 'tools/bootstrap.py',
                 'tools/native_io.py', 'tools/native_relay.py', 'tools/selected_payload.py', 'tools/destination_release.py')
        selected = {}
        for name in files:
            actual = protect(repo / name).read_text()
            require(self.run('/usr/bin/git', '-C', str(repo), 'show', source + ':' + name, timeout=15) == actual,
                    'checklist installation code differs from the admitted platform source')
            selected[name] = actual
        return selected

    def provision(self, args):
        if not os.path.lexists(PROVISION):
            self.preflight()
        require(Path('/sys/fs/cgroup/cgroup.controllers').is_file() and self.text('/proc/sys/kernel/hostname').strip() == 'erebus'
                and self.run('/usr/sbin/getenforce', timeout=10).strip() == 'Enforcing',
                'checklist provisioning requires erebus with cgroup v2')
        require(1000 <= args.uid < 2**31 and 65536 <= args.subid_start <= 2**32 - 1 - 65536
                and args.reserve_mib >= 1024 and args.reserve_inodes >= 128,
                'invalid checklist identity or protected free reserve')
        sizing = {'validation': (args.validation_mib, args.validation_inodes), 'live': (args.live_mib, args.live_inodes)}
        require(all(128 <= size <= 2048 and 1024 <= inodes <= 65024 for size, inodes in sizing.values()),
                'selected checklist filesystem geometry is outside the supported bounds')
        code = self.source_files(args.platform_sha)
        managed_listener = os.path.lexists(EXECUTOR_OVERRIDE)
        require(managed_listener != args.commissioning,
                'install the protected renewal entry first or explicitly select commissioning without its drop-in')
        if managed_listener:
            for path in (EXECUTOR_OVERRIDE, '/usr/libexec/dev-pair/renewal/checklist-entry',
                         RENEWAL + '/current.json', RENEWAL + '/site-current.json'):
                protect(path)
        managed = self.record(MANAGED_INTENT)
        require(managed['machine_id'] == self.destination_identity()['machine_id'], 'managed ext4 belongs to a different host')
        self.mount_observation(ROOT, managed['filesystem'], max_inodes=MANAGED_INODES)
        physical = os.statvfs(Path(MANAGED_IMAGE).parent)
        require(physical.f_bavail * physical.f_frsize >= 8192 * MIB and physical.f_favail >= managed['reserve_inodes'],
                'physical storage reserve is no longer available')
        secrets = {file: checked_file(Path(args.tls_profile) / file, secret=True).read_bytes() for file in TLS_FILES}
        require(all(0 < len(value) <= 8192 for value in secrets.values()), 'invalid checklist TLS profile size')
        live_groups = [entry.gr_gid for entry in grp.getgrall()]
        live_users = [entry.pw_uid for entry in pwd.getpwall()]
        require(not args.subid_start <= args.uid < args.subid_start + 65536, 'checklist UID overlaps its subordinate range')
        with self.lock('checklist-release.lock'):
            self.directory(CONTROL)
            previous = self.record(PROVISION) if Path(PROVISION).exists() else {}
            if not previous:
                require(args.uid not in live_users and args.uid not in live_groups
                        and all(user.pw_name != OWNER for user in pwd.getpwall())
                        and all(group.gr_name != OWNER for group in grp.getgrall()), 'refusing to adopt an existing checklist identity')
                for role in STORAGE:
                    require(not os.path.lexists(STORAGE[role]) and not os.path.lexists(ROOT + '/checklist-storage/' + role + '.img'),
                            'refusing to adopt existing checklist storage without an owned intent')
            specs = {role: {'mib': size, 'inodes': inodes, 'image': ROOT + '/checklist-storage/' + role + '.img',
                            'uuid': previous['mounts'][role]['uuid'] if previous else str(uuid.uuid4())}
                     for role, (size, inodes) in sizing.items()}
            identity = self.destination_identity()['machine_id']
            intent = {'version': 1, 'machine_id': identity, 'platform_sha': args.platform_sha, 'uid': args.uid,
                      'subid_start': args.subid_start, 'reserve_mib': args.reserve_mib, 'reserve_inodes': args.reserve_inodes,
                      'mounts': specs, 'tls': {name: hashlib.sha256(value).hexdigest() for name, value in secrets.items()}}
            if previous:
                require(previous == intent, 'provisioning retry changes protected host intent')
            for file, live in (('/etc/subuid', live_users), ('/etc/subgid', live_groups)):
                self.subid(file, None, args.uid, args.subid_start, live)
            self.atomic(PROVISION, record_text(intent))
            if not any(user.pw_name == OWNER for user in pwd.getpwall()):
                self.run('/usr/sbin/useradd', '--no-create-home', '--home-dir', HOME, '--user-group', '--uid',
                         str(args.uid), '--shell', '/usr/sbin/nologin', '-K', 'SUB_UID_COUNT=0', '-K', 'SUB_GID_COUNT=0', OWNER,
                         timeout=20)
            self.run('/usr/sbin/usermod', '--lock', OWNER, timeout=10)
            uid = self.account()
            require(uid == args.uid, 'checklist account changed from protected intent')
            self.run('/usr/sbin/visudo', '-c', timeout=10)
            package = self.run(*SUDO_PACKAGE_QUERY, timeout=10, sudo_package=True)
            self.run('/usr/bin/sudo', '-l', '-U', OWNER, timeout=10,
                     sudo_probe={'role': OWNER, 'host_verified': True, 'package': package})
            for file, flag, live in (('/etc/subuid', '--add-subuids', live_users), ('/etc/subgid', '--add-subgids', live_groups)):
                self.subid(file, flag, uid, args.subid_start, live)
            for relative, contents in code.items():
                if relative.endswith('/' + EXECUTOR):
                    target = '/etc/systemd/system/' + EXECUTOR
                elif relative in FILES:
                    target = CODE + '/' + relative
                else:
                    target = TRUST_CODE + '/' + Path(relative).name
                self.atomic(target, contents, mode=0o644)
            self.directory(GATE, mode=0o755)
            self.directory(FENCE, mode=0o755)
            self.atomic(FENCE + '/owner.lock', '', mode=0o644)
            self.directory(RECEIPTS)
            for path in (HOME, HOME + '/tls'):
                self.owned_directory(path, uid)
            for name, value in secrets.items():
                self.role_secret(HOME + '/tls', name, value, uid)
            for role, path in STORAGE.items():
                self.reserve(path, specs[role], uid, args.reserve_mib, args.reserve_inodes)
                self.atomic(GATE + '/' + role + '-containers.conf',
                            f'[engine]\nimage_copy_tmp_dir="{path}/image-copy"\n', mode=0o644)
            self.atomic(f'/etc/systemd/system/user@{uid}.service.d/60-dev-pair-checklist.conf',
                        '[Unit]\nRequiresMountsFor=' + VALIDATION + ' ' + LIVE + '\n', mode=0o644)
            self.run('/usr/sbin/restorecon', '-RF', CODE, TRUST_CODE, '/etc/systemd/system/' + EXECUTOR, timeout=15)
            self.run(SYSTEMCTL, 'daemon-reload', timeout=15)
            self.run('/usr/bin/loginctl', 'enable-linger', OWNER, timeout=15)
            self.run(SYSTEMCTL, 'start', f'user@{uid}.service', timeout=30)
            self.user_unit(uid, 'show', '--property=Version')
            runtime = f'/run/user/{uid}'
            require(self.run('/usr/bin/findmnt', '-n', '-o', 'FSTYPE', '-T', runtime, timeout=10).strip() == 'tmpfs'
                    and Path(runtime).stat().st_uid == uid, 'checklist run root must live in its user manager tmpfs')
            temporary = os.statvfs(runtime)
            require(temporary.f_blocks > 0 and temporary.f_files > 0, 'checklist user runtime lacks finite tmpfs geometry')
            for role, path in STORAGE.items():
                self.storage_ready(path, uid)
                backing = specs[role]['image']
                self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c',
                                     'import os,sys; os.stat(sys.argv[1]); assert not os.access(sys.argv[1], os.R_OK)', backing)
                self.setup_network(uid, role)
            was_ready = os.path.lexists(CONTROL + '/ready.json')
            unit, needs_recovery = self.start_executor(uid, managed_listener, was_ready)
            self.atomic(CONTROL + '/ready.json', record_text(intent))
            if needs_recovery:
                self.run(SYSTEMCTL, 'enable', '--now', 'dev-pair-renewal-recovery.service', timeout=120)
            return {'provisioned': True, 'uid': uid, 'platform_sha': args.platform_sha, 'executor': unit,
                    'listener_mode': 'managed' if managed_listener else 'commissioning'}

    def start_executor(self, uid, managed_listener, was_ready):
        unit = f'dev-pair-checklist-executor@{uid}.service'
        if was_ready:
            history = Path(HOME + '/execution-history').lstat()
            require(stat.S_ISDIR(history.st_mode) and history.st_uid == uid and stat.S_IMODE(history.st_mode) == 0o700,
                    'protected prior provisioning lacks its independent execution history')
        active = self.run(SYSTEMCTL, 'is-active', unit, ok=(0, 3, 4), timeout=10).strip() == 'active'
        if active:
            self.executor_ready(unit, uid)
        else:
            self.subprocess_role(uid, '/usr/bin/python3', '-EBs', CODE + '/tools/host_handoff.py', 'initialize-host-history')
        if managed_listener:
            self.run(SYSTEMCTL, 'enable', unit, timeout=30)
            if not active:
                self.run(SYSTEMCTL, 'start', 'dev-pair-renewal-boot-fence.service', timeout=30)
                self.run(SYSTEMCTL, 'start', 'dev-pair-renewal-host-observe.service', timeout=60)
            protect(FENCE + '/selected-host.json')
        else:
            self.run(SYSTEMCTL, 'enable', '--now', unit, timeout=30)
        self.executor_ready(unit, uid)
        return unit, managed_listener and (not active or os.path.lexists(FENCE + '/frozen'))

    def executor_ready(self, unit, uid):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            pid = self.run(SYSTEMCTL, 'show', '--property=MainPID', '--value', unit, timeout=3).strip()
            listeners = self.run('/usr/bin/ss', '-H', '-ltnp', 'sport = :19425', timeout=3).splitlines()
            if re.fullmatch(r'[1-9][0-9]+', pid) and len(listeners) == 1 and len(listeners[0].split()) >= 6:
                actual = listeners[0].split()[3]
                if actual == '127.0.0.1:19425' and re.findall(r'pid=(\d+),', listeners[0]) == [pid]:
                    if Path('/proc/' + pid).stat().st_uid == uid:
                        return
            time.sleep(0.2)
        raise Blocked('checklist executor did not acquire its exact owned loopback listener')

    def setup_network(self, uid, role):
        info = json.loads(self.podman(uid, role, 'info', '--format', 'json'))
        host = info['host']
        suffix = '-live' if role == 'live' else ''
        require(host['security']['rootless'] is True and host['security']['selinuxEnabled'] is True
                and host['cgroupVersion'] == 'v2' and host['cgroupManager'] == 'systemd'
                and info['store']['graphRoot'] == STORAGE[role] + '/graph'
                and info['store']['runRoot'] == f'/run/user/{uid}/dev-pair-checklist{suffix}-runroot'
                and info['store']['imageCopyTmpDir'] == STORAGE[role] + '/image-copy',
                'checklist Podman confinement prerequisites differ')
        name = NETWORKS[role]
        rows = json.loads(self.podman(uid, role, 'network', 'ls', '--format', 'json'))
        if not any(row.get('name') == name for row in rows):
            self.podman(uid, role, 'network', 'create', '--driver', 'bridge', '--internal', name)
        network, = json.loads(self.podman(uid, role, 'network', 'inspect', name))
        require(network['name'] == name and network['driver'] == 'bridge' and network['internal'] is True,
                'checklist rootless bridge is not internal')

    @contextlib.contextmanager
    def release_gate(self, *, require_cutover=True):
        with self.lock('checklist-release.lock'):
            fence = protect(FENCE + '/owner.lock')
            with fence.open('rb') as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise Blocked('checklist release is frozen by renewal') from exc
                require(not os.path.lexists(FENCE + '/frozen'), 'checklist release is frozen by renewal')
                ready = self.record(CONTROL + '/ready.json')
                require(ready == self.record(PROVISION) and ready['machine_id'] == self.destination_identity()['machine_id'],
                        'checklist destination lacks same-machine protected provisioning')
                uid = self.account()
                require(uid == ready['uid'] and self.run('/usr/sbin/getenforce', timeout=10).strip() == 'Enforcing',
                        'release requires the isolated checklist account and enforcing SELinux')
                managed = self.record(MANAGED_INTENT)
                self.mount_observation(ROOT, managed['filesystem'], max_inodes=MANAGED_INODES)
                physical = os.statvfs(Path(MANAGED_IMAGE).parent)
                require(physical.f_bavail * physical.f_frsize >= 8192 * MIB and physical.f_favail >= managed['reserve_inodes'],
                        'physical storage reserve is no longer available')
                dns = None
                if require_cutover:
                    guard = self.verify_final_guard()
                    _, dns = self.tailscale_state()
                    require(guard['target']['dns_name'] == dns, 'checklist proxy differs from independently verified cutover')
                    self.storage_ready(LIVE, uid)
                else:
                    self.guard_hash()
                    self.run(SYSTEMCTL, 'is-active', 'dev-pair-bootstrap-guard.service', timeout=10)
                    self.storage_ready(VALIDATION, uid)
                    self.executor_ready(f'dev-pair-checklist-executor@{uid}.service', uid)
                yield ready, uid, dns

    def pull(self, uid, role, image, secret):
        auth = []
        path = None
        try:
            if secret:
                data = checked_file(secret, secret=True).read_bytes()
                directory = f'/run/user/{uid}'
                name = 'dev-pair-registry-' + uuid.uuid4().hex
                self.role_secret(directory, name, data, uid)
                path = Path(directory) / name
                auth = ['--authfile', str(path)]
            self.podman(uid, role, 'pull', '--quiet', '--platform', 'linux/amd64', *auth, image, timeout=180)
        finally:
            if path:
                path.unlink(missing_ok=True)

    def image_identity(self, uid, role, image, source, *, production):
        metadata, = json.loads(self.podman(uid, role, 'image', 'inspect', image))
        labels = metadata.get('Labels') or metadata['Config']['Labels']
        digest = image.rsplit('@', 1)[1]
        ident = metadata['Id'].removeprefix('sha256:')
        require(metadata['Architecture'] == 'amd64' and metadata['Os'] == 'linux' and re.fullmatch(DIGEST, ident)
                and metadata['Digest'] == digest and image in metadata['RepoDigests']
                and labels['org.opencontainers.image.revision'] == source,
                'Podman image manifest, platform or source differs from the held release')
        require(not production or labels.get('dev-pair.data-compatibility') == COMPATIBILITY,
                'checklist image does not declare the supported rollback data format')
        return ident

    def preload_validation(self, receipt_path, secret):
        with self.release_gate(require_cutover=False) as (_, uid, _dns):
            receipt = protect(receipt_path)
            require(receipt.parent == Path(RECEIPTS), 'validation receipt must be held by the protected build conductor')
            result = self.record(receipt)
            require(set(result) == {'version', 'job_id', 'candidate', 'image'} and type(result['version']) is int
                    and result['version'] == 1 and type(result['job_id']) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{0,79}', result['job_id']),
                    'validation receipt has an invalid shape')
            candidate, image = result['candidate'], result['image']
            require(set(candidate) == {'source_revision', 'artifact_sha256'} and re.fullmatch(SHA, candidate['source_revision'])
                    and re.fullmatch(DIGEST, candidate['artifact_sha256'])
                    and re.fullmatch(r'(?:localhost|ghcr\.io/oso-gato)/[a-z0-9][a-z0-9/_.-]*@sha256:' + candidate['artifact_sha256'], image),
                    'validation receipt does not pin the conductor-approved exact image')
            if not image.startswith('localhost/'):
                self.pull(uid, 'validation', image, secret)
            ident = self.image_identity(uid, 'validation', image, candidate['source_revision'], production=False)
            return {'job_id': result['job_id'], 'image_id': ident, 'receipt_sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()}

    def serve_config(self, dns):
        status = json.loads(self.run(TAILSCALE, 'serve', 'status', '--json', timeout=10), object_pairs_hook=relay.unique)
        expected = {'TCP': {'443': {'HTTPS': True}},
                    'Web': {f'{dns}:443': {'Handlers': {'/': {'Proxy': PROXY}}}}}
        require(status in (None, {}, expected), 'unexpected Tailscale route or Funnel state conflicts with checklist ingress')
        return bool(status)

    def publish_route(self, dns):
        if not self.serve_config(dns):
            self.run(TAILSCALE, 'serve', '--bg', '--https=443', PROXY, timeout=40)
        require(self.serve_config(dns), 'tailnet HTTPS route did not converge')

    def render_unit(self, uid, dns, release):
        source = protect(CODE + '/tools/host_handoff.py')
        unit = self.run('/usr/bin/python3', '-EBs', str(source), 'render-release', '--image', release['subject'],
                        '--hostname', dns, '--port', str(PORT), '--uid', str(uid), timeout=10)
        return unit + f'\n[Service]\nEnvironment=CONTAINERS_CONF={GATE}/live-containers.conf TMPDIR={LIVE}/image-copy\n'

    def unit_path(self, uid):
        return f'/etc/containers/systemd/users/{uid}/{CONTAINER}.container'

    def current_unit(self, uid, allowed):
        path = self.unit_path(uid)
        previous = protect(path).read_text() if os.path.lexists(path) else ''
        require(previous in allowed, 'refusing to change an unowned checklist Quadlet')
        return previous

    def install_unit(self, uid, dns, release, allowed):
        previous = self.current_unit(uid, allowed)
        wanted = self.render_unit(uid, dns, release)
        require(hashlib.sha256(wanted.encode()).hexdigest() == release['unit_sha256'], 'release does not bind its exact Quadlet')
        self.atomic(self.unit_path(uid), wanted, mode=0o644, expected=previous or None)
        self.user_unit(uid, 'daemon-reload')
        self.user_unit(uid, 'restart', UNIT)

    def health(self, uid, dns, release, expected_data=None):
        fields = dict(line.split('=', 1) for line in self.user_unit(uid, 'show', '--property=SourcePath,FragmentPath,DropInPaths,ActiveState,InvocationID', UNIT).splitlines())
        generators = {'generator', 'generator.early', 'generator.late'}
        require(fields['SourcePath'] == self.unit_path(uid) and fields['DropInPaths'] == ''
                and fields['FragmentPath'] in {f'/run/user/{uid}/systemd/{name}/{UNIT}' for name in generators}
                and fields['ActiveState'] == 'active' and re.fullmatch('[0-9a-f]{32}', fields['InvocationID']),
                'checklist service is not the protected generated Quadlet')
        fmt = ('{{.Image}}\n{{.State.Running}}\n{{.ProcessLabel}}\n{{.MountLabel}}\n'
               '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}} {{.HostConfig.PidsLimit}} {{.Config.User}}')
        ident, running, process, mount, config = self.podman(uid, 'live', 'container', 'inspect', '--format', fmt, CONTAINER).splitlines()
        process, mount = process.split(':', 3), mount.split(':', 3)
        data_label = os.getxattr(LIVE + '/data', 'security.selinux').decode('ascii').rstrip('\0').split(':', 3)
        require(ident.removeprefix('sha256:') == release['image_id'] and running == 'true'
                and config == 'true false 32 65532:65532' and len(process) == len(mount) == len(data_label) == 4
                and process[2] == 'container_t' and mount[2] == 'container_file_t' and mount[2:] == data_label[2:]
                and process[3] == mount[3] and re.fullmatch(r's0:c[0-9]+,c[0-9]+', process[3]),
                'checklist runtime digest, privilege or SELinux data label differs')
        published = self.podman(uid, 'live', 'port', CONTAINER, '8000/tcp').strip()
        require(published == f'127.0.0.1:{PORT}', 'checklist listener is not restricted to its assigned loopback port')
        deadline = time.monotonic() + 8
        while True:
            try:
                with contextlib.closing(http.client.HTTPConnection('127.0.0.1', PORT, timeout=1)) as connection:
                    connection.request('GET', '/', headers={'Host': dns})
                    response = connection.getresponse()
                    require(response.status == 200 and b'<title>Checklist</title>' in response.read(16384),
                            'checklist loopback browser journey did not respond')
                with contextlib.closing(http.client.HTTPConnection('127.0.0.1', PORT, timeout=1)) as connection:
                    connection.request('GET', '/items', headers={'Host': dns})
                    response = connection.getresponse()
                    raw = response.read(1024**2 + 1)
                    require(response.status == 200 and len(raw) <= 1024**2, 'checklist inventory endpoint did not respond')
                    observed = inventory_digest(json.loads(raw, object_pairs_hook=relay.unique))
                    require(expected_data is None or observed == expected_data, 'actual checklist items changed during rollout')
                    return fields['InvocationID']
            except OSError:
                if time.monotonic() >= deadline:
                    raise Blocked('checklist loopback service did not become ready') from None
                time.sleep(0.2)

    def data_items(self, uid, path):
        tool = protect(CODE + '/examples/checklist/checklist.py')
        code = ("from contextlib import closing; from pathlib import Path; import json,os,sys; "
                "p=Path(sys.argv[2]); assert p.is_file() and p.resolve(strict=True)==p; "
                "sys.path.insert(0, str(Path(sys.argv[1]).parent)); import checklist as c\n"
                "with closing(c.connect(p,readonly=True)) as db:\n"
                " c.verify_database(db); assert db.execute(\"SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'\").fetchall()==[('table','items',c.SCHEMA)]; "
                "print(json.dumps([c.item_object(row) for row in db.execute("
                "'SELECT id,title,done FROM items ORDER BY id')]))")
        raw = self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', code, str(tool), path)
        return json.loads(raw, object_pairs_hook=relay.unique)

    def data_snapshot(self, uid, path):
        return inventory_digest(self.data_items(uid, path))

    @staticmethod
    def database_path():
        return LIVE + '/data/checklist.sqlite3'

    def backup(self, uid, attempt):
        require(re.fullmatch(r'[0-9a-f]{32}', attempt), 'invalid checklist backup attempt')
        source = self.database_path()
        backup = LIVE + '/backups/' + attempt + '.sqlite3'
        restored = backup + '.test-restore'
        tool = protect(CODE + '/examples/checklist/checklist.py')
        target = self.data_snapshot(uid, source)
        if not os.path.lexists(backup):
            self.subprocess_role(uid, '/usr/bin/python3', '-IB', str(tool), 'backup', '--database', source, '--output', backup)
        if not os.path.lexists(restored):
            self.subprocess_role(uid, '/usr/bin/python3', '-IB', str(tool), 'restore', '--backup', backup, '--database', restored)
        require(self.data_snapshot(uid, backup) == self.data_snapshot(uid, restored) == target,
                'checklist backup and clean restore contents do not match quiesced data')
        self.subprocess_role(uid, '/usr/bin/rm', '--', restored)
        return {'path': backup, 'inventory_sha256': target}

    def archive_failed_data(self, uid, attempt):
        require(re.fullmatch(r'[0-9a-f]{32}', attempt), 'invalid checklist preservation attempt')
        target = LIVE + '/backups/' + attempt + '.failed-sqlite3'
        code = ("import os,stat,sys\n"
                "source,target=sys.argv[1:]\n"
                "for suffix in ('','-journal','-wal','-shm'):\n"
                " a,b=source+suffix,target+suffix\n"
                " if not os.path.lexists(a): continue\n"
                " current=os.lstat(a); assert stat.S_ISREG(current.st_mode) and current.st_uid==os.getuid()\n"
                " if not os.path.lexists(b): os.link(a,b,follow_symlinks=False)\n"
                " saved=os.lstat(b); assert (current.st_dev,current.st_ino)==(saved.st_dev,saved.st_ino)\n"
                " for path in (a,b):\n"
                "  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)\n"
                " os.unlink(a)\n"
                " for path in (os.path.dirname(a),os.path.dirname(b)):\n"
                "  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)\n")
        self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', code, self.database_path(), target)
        return target if os.path.lexists(target) else None

    def restore_failed_data(self, uid, pending):
        baseline = pending['baseline']
        expected = baseline['inventory_sha256']
        require(self.data_snapshot(uid, baseline['path']) == expected, 'protected rollout snapshot contents changed')
        source = self.database_path()
        sidecars = any(os.path.lexists(source + suffix) for suffix in ('-journal', '-wal', '-shm'))
        if not sidecars and os.path.lexists(source):
            try:
                if self.data_snapshot(uid, source) == expected:
                    return
            except (Blocked, ValueError):
                pass
        self.archive_failed_data(uid, pending['attempt'])
        tool = protect(CODE + '/examples/checklist/checklist.py')
        self.subprocess_role(uid, '/usr/bin/python3', '-IB', str(tool), 'restore', '--backup', baseline['path'], '--database', source)
        require(self.data_snapshot(uid, source) == expected, 'restored live checklist inventory differs from the pre-activation snapshot')

    def save_activation(self, state):
        self.atomic(ACTIVATION, record_text(state), expected=self.text(ACTIVATION) or None)

    def initial_activation(self):
        if os.path.lexists(ACTIVATION):
            return self.record(ACTIVATION)
        return {'version': 2, 'active': None, 'previous': None, 'pending': None, 'confirmed': None, 'route_pending': False}

    def quiesce(self, uid, dns, allowed):
        current = self.current_unit(uid, allowed)
        if self.serve_config(dns):
            self.run(TAILSCALE, 'serve', '--https=443', 'off', timeout=20)
        require(not self.serve_config(dns), 'checklist route did not close before the data transaction')
        if current:
            self.user_unit(uid, 'stop', UNIT)
        require(not self.run('/usr/bin/ss', '-H', '-ltnp', f'sport = :{PORT}', timeout=10).strip(),
                'checklist listener did not quiesce')
        return current

    def finish_route(self, state, dns):
        # Promotion is already durable. A failed/ambiguous proxy command must not
        # restore an older snapshot, because the new app could have served writes.
        self.publish_route(dns)
        settled = {**state, 'route_pending': False}
        if settled != state:
            self.save_activation(settled)
        return settled

    def activate(self, uid, dns, state, release, operation):
        active, pending = state['active'], state['pending']
        old = self.render_unit(uid, dns, active) if active else ''
        new = self.render_unit(uid, dns, release)
        if pending:
            require(pending['operation'] == operation and pending['release'] == release,
                    'interrupted rollout requires exact completion or protected rollback')
        else:
            if not active:
                require(not self.serve_config(dns) and not os.path.lexists(self.database_path()),
                        'refusing to adopt an existing checklist proxy or database without deployment state')
            free = os.statvfs(LIVE)
            require(free.f_bavail * free.f_frsize >= 16 * MIB and free.f_favail >= 16,
                    'live image and rollback snapshots cannot overlap in the bounded checklist allocation')
            self.current_unit(uid, (old,))
            pending = {'operation': operation, 'release': release, 'attempt': uuid.uuid4().hex,
                       'phase': 'reserved', 'baseline': None}
            state = {**state, 'pending': pending}
            self.save_activation(state)
        try:
            self.quiesce(uid, dns, (old, new))
            if pending['phase'] == 'reserved':
                baseline = self.backup(uid, pending['attempt']) if active else None
                pending = {**pending, 'phase': 'prepared', 'baseline': baseline}
                state = {**state, 'pending': pending}
                self.save_activation(state)
            elif active:
                self.restore_failed_data(uid, pending)
            self.install_unit(uid, dns, release, (old, new))
            expected = pending['baseline']['inventory_sha256'] if active else inventory_digest([])
            self.health(uid, dns, release, expected)
            require(self.data_snapshot(uid, self.database_path()) == expected,
                    'stored checklist data changed during isolated rollout')
        except Exception:
            self.recover(uid, dns, state)
            raise
        result = {**state, 'active': {**release, 'backup': pending['baseline']}, 'previous': active,
                  'pending': None, 'confirmed': release['artifact_sha256'] if operation == 'rollback' else None,
                  'route_pending': True}
        self.save_activation(result)
        return self.finish_route(result, dns)

    def deploy(self, source, image, run_id, secret):
        with self.release_gate() as (_, uid, dns):
            state = self.initial_activation()
            self.serve_config(dns)
            release = ReleaseTrust(self.run).verify('checklist', source, image, run_id)
            active, pending = state['active'], state['pending']
            if pending:
                require(pending['operation'] == 'deploy' and all(pending['release'].get(key) == value for key, value in release.items()),
                        'an interrupted different release requires rollback before further deployment')
            elif active and all(active.get(key) == value for key, value in release.items()):
                self.health(uid, dns, active)
                return self.finish_route(state, dns)
            require(not active or state['confirmed'] == active['artifact_sha256'],
                    'current release requires independent destination confirmation before replacement')
            self.pull(uid, 'live', image, secret)
            release.update(image_id=self.image_identity(uid, 'live', image, source, production=True), dns_name=dns,
                           compatibility=COMPATIBILITY)
            release['unit_sha256'] = hashlib.sha256(self.render_unit(uid, dns, release).encode()).hexdigest()
            ReleaseTrust(self.run).main(source)
            return self.activate(uid, dns, state, release, 'deploy')

    def recover(self, uid, dns, state):
        active, pending = state['active'], state['pending']
        wanted = pending['release']
        new = self.render_unit(uid, dns, wanted)
        old = self.render_unit(uid, dns, active) if active else ''
        current = self.quiesce(uid, dns, ('', old, new))
        if active:
            require(active['compatibility'] == COMPATIBILITY and active['dns_name'] == dns
                    and self.image_identity(uid, 'live', active['subject'], active['source_sha'], production=True) == active['image_id'],
                    'prior compatible checksum is unavailable for recovery')
            baseline = pending['baseline']
            if pending['phase'] == 'prepared':
                self.restore_failed_data(uid, pending)
            expected = baseline['inventory_sha256'] if baseline else self.data_snapshot(uid, self.database_path())
            self.install_unit(uid, dns, active, ('', old, new))
            self.health(uid, dns, active, expected)
            require(self.data_snapshot(uid, self.database_path()) == expected, 'recovered checklist inventory changed')
            result = {**state, 'pending': None, 'route_pending': True,
                      'last_failed': {'attempt': pending['attempt'], 'release': wanted, 'baseline': baseline}}
            self.save_activation(result)
            return self.finish_route(result, dns)
        if current:
            Path(self.unit_path(uid)).unlink()
            self.user_unit(uid, 'daemon-reload')
        archive = self.archive_failed_data(uid, pending['attempt'])
        require(not os.path.lexists(self.database_path()) and not self.serve_config(dns),
                'failed initial rollout still owns live data or ingress')
        result = {**state, 'pending': None,
                  'last_failed': {'attempt': pending['attempt'], 'release': wanted, 'data_archive': archive}}
        self.save_activation(result)
        return result

    def rollback(self):
        with self.release_gate() as (_, uid, dns):
            state = self.initial_activation()
            if state['pending']:
                return self.recover(uid, dns, state)
            active, prior = state['active'], state['previous']
            require(active and prior and prior.get('verified_destination') is True
                    and prior['compatibility'] == active['compatibility'] == COMPATIBILITY
                    and prior['dns_name'] == dns and active['dns_name'] == dns,
                    'no known compatible previous checklist release')
            require(self.image_identity(uid, 'live', prior['subject'], prior['source_sha'], production=True) == prior['image_id'],
                    'previous exact digest is unavailable for rollback')
            return self.activate(uid, dns, state, prior, 'rollback')

    def confirm(self, evidence):
        with self.release_gate() as (setup, uid, dns):
            state = self.initial_activation()
            release = state['active']
            require(release and not state['pending'] and not state['route_pending'], 'no settled rollout to confirm')
            data = self.recent_destination_evidence(evidence, 'dev-pair-access-review',
                                                    {'release_source', 'image', 'dns_name', 'guard_sha256', 'probes',
                                                     'item_id', 'item_title_sha256'}, lifetime=1800)
            cutover = self.verify_final_guard()
            require(data['source_sha'] == setup['platform_sha'] and data['release_source'] == release['source_sha']
                    and data['image'] == release['subject'] and data['dns_name'] == dns
                    and data['guard_sha256'] == cutover['guard_sha256']
                    and type(data['item_id']) is int and 0 < data['item_id'] < 2**63
                    and type(data['item_title_sha256']) is str and re.fullmatch(DIGEST, data['item_title_sha256']),
                    'external destination evidence lacks exact successful release/access checks')
            endpoint = f'https://{dns}/'
            expected = {}
            for family in ('ipv4', 'ipv6'):
                address = cutover['public_addresses'][family]
                public = self.public_probe_host(address, family, cutover['provider_recovery'])
                for action, vantage, effect in (
                    ('browser-add-and-complete', 'authorized', 'allow'), ('restart-same-item', 'authorized', 'allow'),
                    ('reboot-same-item', 'authorized', 'allow'), ('clean-restore-same-item', 'authorized', 'allow'),
                    ('public-app', 'public', 'deny'), ('unauthorized-app', 'denied', 'deny'),
                    ('tailnet-loss-app', 'authorized', 'deny'), ('tailnet-recovery-app', 'authorized', 'allow'),
                ):
                    target = (f'https://{public}:443/' if address is not None else public) if vantage == 'public' else endpoint
                    expected[action, family] = (target, vantage, effect)
                if state['previous'] and state['previous'].get('verified_destination'):
                    expected['rollback-same-item', family] = (endpoint, 'authorized', 'allow')
                expected['remote-root', family] = (f'ssh://root@{dns}:22', 'authorized', 'deny')
            self.verify_access_probes(data, expected)
            items = self.data_items(uid, self.database_path())
            inventory = inventory_digest(items)
            require(any(row['id'] == data['item_id'] and row['done'] is True
                        and hashlib.sha256(row['title'].encode()).hexdigest() == data['item_title_sha256'] for row in items),
                    'the independently exercised item is absent from the live checklist')
            self.health(uid, dns, release, inventory)
            require(self.serve_config(dns), 'checklist tailnet route is unavailable')
            state['confirmed'] = release['artifact_sha256']
            state['active'] = {**release, 'verified_destination': True,
                               'destination_receipt_sha256': hashlib.sha256(protect(evidence).read_bytes()).hexdigest()}
            self.save_activation(state)
            return {'url': f'https://{dns}/', 'source_sha': release['source_sha'], 'image': release['subject'], 'confirmed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest='stage', required=True)
    storage = stages.add_parser('managed-storage')
    storage.add_argument('--platform-sha', required=True)
    for option in ('managed-mib', 'managed-inodes', 'reserve-inodes'):
        storage.add_argument('--' + option, required=True, type=int)
    transport = storage.add_mutually_exclusive_group(required=True)
    transport.add_argument('--bootstrap-source', action='append')
    transport.add_argument('--console-receipt')
    provision = stages.add_parser('provision')
    provision.add_argument('--platform-sha', required=True)
    provision.add_argument('--tls-profile', required=True)
    provision.add_argument('--commissioning', action='store_true', help='start the direct Q executor before the renewal override exists')
    for option in ('uid', 'subid-start', 'validation-mib', 'validation-inodes', 'live-mib', 'live-inodes', 'reserve-mib', 'reserve-inodes'):
        provision.add_argument('--' + option, required=True, type=int)
    preload = stages.add_parser('preload-validation')
    preload.add_argument('--receipt', required=True)
    deploy = stages.add_parser('deploy')
    deploy.add_argument('--source-sha', required=True)
    deploy.add_argument('--image', required=True)
    deploy.add_argument('--run-id', required=True, type=int)
    for stage in (preload, deploy):
        stage.add_argument('--registry-auth-file')
    rollback = stages.add_parser('rollback')
    confirm = stages.add_parser('confirm')
    confirm.add_argument('--evidence', required=True)
    for stage in (storage, provision, preload, deploy, rollback, confirm):
        stage.add_argument('--apply', action='store_true', required=True)
    stages.add_parser('status')
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'use the authorized root destination controller')
        app = Destination()
        if args.stage == 'managed-storage':
            result = app.managed_storage(args)
        elif args.stage == 'provision':
            result = app.provision(args)
        elif args.stage == 'preload-validation':
            result = app.preload_validation(args.receipt, args.registry_auth_file)
        elif args.stage == 'deploy':
            result = app.deploy(args.source_sha, args.image, args.run_id, args.registry_auth_file)
        elif args.stage == 'rollback':
            result = app.rollback()
        elif args.stage == 'confirm':
            result = app.confirm(args.evidence)
        else:
            result = app.initial_activation()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        print('checklist destination blocked: ' + (str(exc) if isinstance(exc, Blocked) else 'required protected destination evidence unavailable'), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
