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

from bootstrap import Blocked, Bootstrap, SUDO_PACKAGE_QUERY, TRUST_SIGNERS, checked_file, relay
import managed_backing
from release_trust import DIGEST, SHA, ReleaseTrust, protect, require
from selinux_bootstrap import INSTALL as SELINUX_INSTALL, OVERRIDE as SELINUX_OVERRIDE, code_digest as selinux_code_digest

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
MANAGED_READY = ROOT + '/.managed-storage-ready'
MANAGED_LOOP_SERVICE = 'dev-pair-managed-loop.service'
TRANSITION = ROOT + '/selinux-bootstrap'
PRESERVED_TRANSITION = '/var/lib/dev-pair-selinux-preserved'
TRANSITION_FILES = {'boots.json', 'complete.json', 'config-original', 'intent.json', 'journal.jsonl', 'lock',
                    'marker-recovery.json', 'reboot.json', 'reboots.json', 'relabel-attempt.json', 'relabel-done.json', 'relabel-plan.json'}
STORAGE = {'validation': VALIDATION, 'live': LIVE}
NETWORKS = {'validation': 'dev-pair-checklist-internal', 'live': 'dev-pair-checklist-release'}
FILES = ('tools/host_handoff.py', 'tools/job_protocol.py', 'tools/ledger_recovery.py', 'tools/jobs.py',
         'runtime/checklist/checklist_quadlet.py', 'runtime/checklist/acceptance.container',
         'examples/checklist/checklist.py')
EXECUTOR = 'dev-pair-checklist-executor@.service'
EXECUTOR_OVERRIDE = '/etc/systemd/system/' + EXECUTOR + '.d/checklist-release.conf'
RENEWAL = ROOT + '/renewal'
MANAGED_LISTENER = CONTROL + '/managed-listener.json'
U_HOST_VERIFY = '/usr/libexec/dev-pair/renewal/host-release'
U_BOOT_FENCE = 'dev-pair-renewal-boot-fence.service'
U_OBSERVE = 'dev-pair-renewal-host-observe.service'
U_RECOVERY = 'dev-pair-renewal-recovery.service'
ROLE_ANCESTORS = (Path('/etc/dev-pair'), Path('/usr/libexec/dev-pair'), Path('/etc/containers/systemd/users'))
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
        number = f'{os.major(device)}:{os.minor(device)}'
        require(re.fullmatch(r'/dev/loop[0-9]+', source) and device != Path(path).parent.stat().st_dev,
                'checklist mount does not have its own reserved backing device')
        if 'loop' in spec:
            require(source == spec['loop'], 'managed storage did not recover its enrolled loop device')
        loop = Path(f'/sys/dev/block/{number}/loop')
        backing = (loop / 'backing_file').read_text().strip()
        image = protect(backing)
        info = image.stat()
        require(str(image) == spec['image'] and info.st_size == spec['mib'] * MIB
                and info.st_blocks * 512 >= spec['mib'] * MIB and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600,
                'checklist mount does not use its fully reserved owned backing file')
        stable = managed_backing.verify_backing(image, info, Blocked)
        if stable is not None:
            self.observe_btrfs_loop(image, info, source, number)
            expected = {'image': str(image), 'inode': info.st_ino, 'size': info.st_size, 'fs_uuid': spec['uuid'],
                        'btrfs': stable, 'state': 'formatted'}
            require(self.record(MANAGED_INTENT + '.backing') == expected,
                    'mounted Btrfs backing differs from the protected record')
        geometry = os.statvfs(path)
        require(0 < geometry.f_blocks * geometry.f_frsize <= spec['mib'] * MIB
                and 0 < geometry.f_files <= max_inodes
                and geometry.f_files <= spec['inodes'] + (4096 if max_inodes == MANAGED_INODES else 512),
                'checklist mount exceeds declared geometry')
        matches = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                   if line.split()[2] == number]
        require(len(matches) == 1 and matches[0].split()[3:5] == ['/', path],
                'checklist storage is not the unique dedicated filesystem root')

    def physical_reserve(self, reserve_inodes):
        return managed_backing.observe(Path(MANAGED_IMAGE).parent, Blocked).check(
            8192 * MIB, reserve_inodes, Blocked, 'physical storage reserve is no longer available')

    def observe_btrfs_loop(self, image, node, source, number):
        value = json.loads(self.run('/usr/sbin/losetup', '--list', '--json', '--associated', str(image),
                                   '--output', 'NAME,MAJ:MIN,BACK-MAJ:MIN,BACK-INO,OFFSET,SIZELIMIT,RO', timeout=10))
        rows = value.get('loopdevices')
        require(type(rows) is list and len(rows) == 1, 'Btrfs backing loop ownership is ambiguous')
        row = rows[0]
        backing_dev = f'{os.major(node.st_dev)}:{os.minor(node.st_dev)}'
        require(row['name'] == source and row['maj:min'] == number and row['back-maj:min'] == backing_dev
                and str(row['back-ino']) == str(node.st_ino) and str(row['offset']) == str(row['sizelimit']) == '0'
                and row['ro'] is False, 'mounted loop does not match the protected Btrfs backing')

    def allocate(self, spec, receipt, reserve_mib, reserve_inodes):
        image = Path(spec['image'])
        size = spec['mib'] * MIB
        previous = self.record(receipt) if os.path.lexists(receipt) else None
        reserve = reserve_mib * MIB
        reserve_message = 'selected VPS cannot preserve the declared free reserve'
        if not previous and not os.path.lexists(image):
            managed_backing.provisioning_space(image.parent, Blocked, reserve_inodes).check(
                reserve + size, reserve_inodes, Blocked, reserve_message)
        open_type = 0 if previous else os.O_CREAT | os.O_EXCL
        descriptor = os.open(image, open_type | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        try:
            if not previous:
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o600)
            saved = protect(image).stat()
            old = os.fstat(descriptor)
            require(stat.S_ISREG(old.st_mode) and stat.S_IMODE(old.st_mode) == 0o600 and old.st_uid == old.st_gid == 0
                    and old.st_size in (0, size) and old.st_nlink == 1
                    and (old.st_dev, old.st_ino) == (saved.st_dev, saved.st_ino), 'unexpected dedicated backing file')
            base = {'image': str(image), 'inode': old.st_ino, 'size': size, 'fs_uuid': spec['uuid']}
            legacy = {**base, 'device': old.st_dev}
            space = managed_backing.provisioning_space(image.parent, Blocked, reserve_inodes)
            identity = ({**base, 'btrfs': managed_backing.btrfs_identity(descriptor, Blocked)}
                        if space.kind == 'btrfs' else legacy)
            if previous:
                state = previous.get('state')
                require(state in ('created', 'formatting', 'formatted'), 'unexpected protected backing state')
                if previous not in ({**identity, 'state': state}, {**legacy, 'state': state}):
                    # V1 stored Btrfs's anonymous device number. After it changes,
                    # migrate only a fully formatted, older inode matching the protected
                    # record. The allocation and exact ext4 UUID are verified below.
                    legacy_device = previous.get('device')
                    require(space.kind == 'btrfs' and state == 'formatted' and type(legacy_device) is int
                            and 0 < legacy_device < 2**32 and os.major(legacy_device) == 0
                            and previous == {**legacy, 'device': legacy_device, 'state': state}
                            and managed_backing.birth_ns(descriptor, Blocked) <= protect(receipt).stat().st_mtime_ns,
                            'protected backing object identity changed')
            else:
                previous = {**identity, 'state': 'created'}
                self.atomic(receipt, record_text(previous))
            remaining = max(size - old.st_blocks * 512, 0)
            space.check(reserve + remaining, reserve_inodes, Blocked, reserve_message)
            if space.kind == 'btrfs':
                require(not remaining or previous['state'] == 'created', 'recorded Btrfs backing allocation changed')
                managed_backing.prepare_btrfs(descriptor, empty=old.st_size == old.st_blocks == 0, error=Blocked)
            if remaining:
                os.posix_fallocate(descriptor, 0, size)
                os.fsync(descriptor)
            current = os.fstat(descriptor)
            require(current.st_size == size and current.st_blocks * 512 >= size, 'checklist backing is not fully allocated')
            if space.kind == 'btrfs':
                managed_backing.verify_btrfs(descriptor, size, Blocked)
        finally:
            os.close(descriptor)
        managed_backing.provisioning_space(image.parent, Blocked, reserve_inodes).check(
            reserve, reserve_inodes, Blocked, 'filesystem reserve was not preserved after allocation')
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
        if space.kind == 'btrfs':
            require(managed_backing.verify_backing(image, current, Blocked) == identity['btrfs'],
                    'Btrfs backing changed before protected publication')
            managed_backing.provisioning_space(image.parent, Blocked, reserve_inodes).check(
                reserve, reserve_inodes, Blocked, 'filesystem reserve was not preserved after formatting')
        self.atomic(receipt, record_text({**identity, 'state': 'formatted'}), expected=record_text(previous))

    def managed_loop_unit(self, source):
        index = int(source.removeprefix('/dev/loop'))
        # Fedora may load the loop module with no pre-created slots. Create
        # the exact enrolled slot without attaching, detaching or probing others.
        command = ('import errno, fcntl, os\n'
                   'fd = os.open("/dev/loop-control", os.O_RDWR | os.O_NOFOLLOW)\n'
                   f'try: fcntl.ioctl(fd, 0x4C80, {index})\n'
                   'except OSError as error:\n'
                   ' if error.errno != errno.EEXIST: raise\n')
        wait = 'ExecStart=/usr/bin/udevadm wait --timeout=10'
        content = ('[Unit]\nDescription=Prepare the enrolled Dev-pair loop device\n'
                   'DefaultDependencies=no\nAfter=systemd-udevd.service\nBefore=local-fs.target\n'
                   '[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=30s\n'
                   'ExecStart=/usr/sbin/modprobe loop\n'
                   f'{wait} --initialized=no /dev/loop-control\n'
                   f'ExecStart=/usr/bin/python3 -IB -c {json.dumps(command)}\n'
                   f'{wait} --initialized=no {source}\n')
        self.atomic('/etc/systemd/system/' + MANAGED_LOOP_SERVICE, content, mode=0o644,
                    expected=content.replace(f'{wait} --initialized=no', wait))

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
        dependencies = ''
        if 'loop' in spec:
            self.managed_loop_unit(spec['loop'])
            dependencies = f'Requires={MANAGED_LOOP_SERVICE}\nAfter={MANAGED_LOOP_SERVICE}\n'
        header = '[Unit]\nDescription=Dedicated Dev-pair checklist storage\n'
        mount_config = (f'[Mount]\nWhat={image}\nWhere={path}\nType=ext4\nOptions={loop},nodiscard,nodev,nosuid\n'
                        '[Install]\nWantedBy=local-fs.target\n')
        self.atomic('/etc/systemd/system/' + unit, header + dependencies + mount_config,
                    mode=0o644, expected=header + mount_config if dependencies else None)
        self.run(SYSTEMCTL, 'daemon-reload', timeout=15)
        self.run(SYSTEMCTL, 'enable', '--now', unit, timeout=40)
        self.mount_observation(path, spec, max_inodes=max_inodes)

    @staticmethod
    def has_mount_at(path):
        return any(row.split()[4] == path for row in Path('/proc/self/mountinfo').read_text().splitlines())

    @staticmethod
    def transition_contents(directory):
        directory = Path(directory)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'SELinux transition directory has unrecognized ownership')
        contents = {}
        for path in directory.iterdir():
            require(path.name in TRANSITION_FILES, 'unrecognized state beside the SELinux transition must be preserved')
            info = protect(path).stat()
            require(info.st_size <= 256 * 1024 and stat.S_IMODE(info.st_mode) == 0o600, 'SELinux transition file is not protected')
            contents[path.name] = path.read_bytes().decode('utf-8')
        require({'intent.json', 'complete.json', 'relabel-done.json', 'config-original', 'lock'} <= contents.keys(),
                'finish the existing SELinux transition before enrolling storage')
        return contents

    @contextlib.contextmanager
    def previous_transition(self, *, expected):
        directory = PRESERVED_TRANSITION if os.path.lexists(PRESERVED_TRANSITION) else TRANSITION
        if not os.path.lexists(directory):
            require(expected is None, 'recorded SELinux transition archive is unavailable')
            yield None
            return
        lock = protect(Path(directory) / 'lock')
        with os.fdopen(os.open(lock, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            contents = self.transition_contents(directory)
            fingerprint = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in contents.items()}
            if expected is not None:
                require(fingerprint == expected, 'recorded SELinux transition bytes changed')
            else:
                require(directory == TRANSITION and not os.path.lexists('/.autorelabel')
                        and not os.path.lexists(SELINUX_OVERRIDE),
                        'SELinux transition must be complete and disarmed before migration')
                self.preflight()
                original = json.loads(contents['intent.json'])
                relabeled = json.loads(contents['relabel-done.json'])
                complete = json.loads(contents['complete.json'])
                for name in ('bootstrap.py', 'selinux_bootstrap.py'):
                    require(stat.S_IMODE(protect(Path(SELINUX_INSTALL) / name).stat().st_mode) == 0o555,
                            'installed SELinux transition code is not immutable')
                require(complete['phase'] == 'enforcing'
                        and complete['code_sha256'] == original['code_sha256'] == relabeled['code_sha256']
                        and complete['code_sha256'] == selinux_code_digest(Path(SELINUX_INSTALL))
                        and complete['relabel_boot_id'] == relabeled['boot_id']
                        and len({complete['boot_id'], relabeled['boot_id'], original['origin_boot_id']}) == 3
                        and self.run(SYSTEMCTL, 'is-enabled', 'dev-pair-selinux-finalize.service', ok=(0, 1), timeout=10).strip() == 'disabled',
                        'only a completed, disarmed SELinux transition can be relocated')
            yield directory, contents, fingerprint

    @staticmethod
    def sync_path(path):
        fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

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
            mounted = self.has_mount_at(ROOT)
            if not state:
                self.preflight(require_enforcing=False)
                require(not mounted and not os.path.lexists(MANAGED_IMAGE) and not os.path.lexists(PRESERVED_TRANSITION),
                        'refusing to adopt existing managed storage or transition archive')
            transition = state.get('transition') if state else None
            migration = self.previous_transition(expected=transition) if not state or transition else contextlib.nullcontext(None)
            with migration as previous:
                return self.enroll_managed_storage(args, state, mounted, previous)
        finally:
            os.close(lock)

    def enroll_managed_storage(self, args, state, mounted, previous):
        root = Path(ROOT)
        if not mounted and os.path.lexists(root):
            expected = {'selinux-bootstrap'} if previous and previous[0] == TRANSITION else set()
            require(not root.is_symlink() and root.is_dir() and {entry.name for entry in root.iterdir()} == expected,
                    'refusing to hide unrelated files beneath the managed ext4 root')
        loop = state['filesystem']['loop'] if state else self.run('/usr/sbin/losetup', '--find', timeout=10).strip()
        require(re.fullmatch(r'/dev/loop[0-9]+', loop), 'cannot enroll an exact managed loop device')
        spec = {'mib': args.managed_mib, 'inodes': args.managed_inodes, 'image': MANAGED_IMAGE, 'loop': loop,
                'uuid': state['filesystem']['uuid'] if state else str(uuid.uuid4())}
        wanted = {'version': 1, 'machine_id': self.destination_identity()['machine_id'], 'filesystem': spec,
                  'reserve_inodes': args.reserve_inodes}
        if previous:
            wanted['transition'] = previous[2]
        require(not state or state == wanted, 'managed-storage retry differs from the protected intent')
        self.atomic(MANAGED_INTENT, record_text(wanted))
        self.allocate(spec, MANAGED_INTENT + '.backing', 8192, args.reserve_inodes)
        if previous and previous[0] == TRANSITION:
            require(not mounted and not os.path.lexists(PRESERVED_TRANSITION), 'unexpected transition archive conflict')
            os.rename(TRANSITION, PRESERVED_TRANSITION)
            self.sync_path(ROOT)
            self.sync_path(Path(PRESERVED_TRANSITION).parent)
        self.mount(ROOT, spec, max_inodes=MANAGED_INODES)
        self.directory(ROOT, mode=0o755)
        if previous and not os.path.lexists(MANAGED_READY):
            self.directory(TRANSITION)
            for name, text in previous[1].items():
                self.atomic(TRANSITION + '/' + name, text)
            require(self.transition_contents(TRANSITION) == previous[1], 'copied SELinux transition does not match preserved record')
        elif previous:
            current = self.transition_contents(TRANSITION)
            require(all(current.get(name) == previous[1][name] for name in ('intent.json', 'complete.json', 'relabel-done.json')),
                    'admitted SELinux transition authority changed')
        if self.run('/usr/sbin/getenforce', timeout=10).strip() != 'Disabled':
            self.run('/usr/sbin/restorecon', '-RF' if previous else '-F', TRANSITION if previous else ROOT, timeout=20)
        self.atomic(MANAGED_READY, record_text(wanted))
        return {'path': ROOT, 'filesystem': spec, 'physical_reserve_mib': 8192, 'preserved_transition': bool(previous)}

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
        files = (*FILES, 'runtime/checklist/' + EXECUTOR, 'tools/release_trust.py', 'tools/bootstrap.py', 'tools/selinux_bootstrap.py',
                 'tools/native_io.py', 'tools/native_relay.py', 'tools/selected_payload.py', 'tools/destination_release.py',
                 'tools/managed_backing.py', 'tools/storage.py')
        if os.path.lexists(repo / 'tools/platform_release_protocol.py'):
            files += ('tools/platform_release_protocol.py',)
        selected = {}
        for name in files:
            actual = protect(repo / name).read_text()
            require(self.run('/usr/bin/git', '-C', str(repo), 'show', source + ':' + name, timeout=15) == actual,
                    'checklist installation code differs from the admitted platform source')
            selected[name] = actual
        return selected

    @staticmethod
    def role_path_info(path):
        info = path.lstat()
        require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
                'checklist executable path must be protected and root-owned')
        return info

    def role_search_plan(self, files, directories, uid, *, listing=()):
        selected = {Path(path) for path in (*files, *directories)}
        listing = {Path(path) for path in listing}
        parents = {part for path in selected for part in path.parents} | {Path(path) for path in directories}
        needed = selected | parents
        grant, hidden = [], set()
        for directory in sorted(parents):
            if not os.path.lexists(directory):
                continue
            info = self.role_path_info(directory)
            require(stat.S_ISDIR(info.st_mode), 'fixed checklist ancestor is not a directory')
            bits = 0o005 if directory in listing else 0o001
            if info.st_mode & bits == bits:
                continue
            access = 'r-x' if directory in listing else '--x'
            require(any(directory.is_relative_to(root) for root in ROLE_ANCESTORS)
                    and stat.S_IMODE(info.st_mode) in (0o700, 0o700 | (bits << 3)),
                    'fixed checklist ancestor lacks its dedicated protected search policy')
            acl = self.run('/usr/bin/getfacl', '--omit-header', '--absolute-names', '--numeric', '--', str(directory), timeout=5)
            entries = acl.strip().splitlines()
            plain = ['user::rwx', 'group::---', 'other::---']
            exact = ['user::rwx', f'user:{uid}:{access}', 'group::---', f'mask::{access}', 'other::---']
            require(entries in (plain, exact), 'existing ancestor ACL conflicts with a dedicated checklist search grant')
            if entries == plain:
                grant.append((directory, info.st_dev, info.st_ino, access))
            for child_dir in parents:
                if child_dir.is_relative_to(directory) and os.path.lexists(child_dir):
                    for child in child_dir.iterdir():
                        if child in needed:
                            continue
                        require(child_dir not in listing, 'Quadlet input directory contains an unowned entry')
                        private = self.role_path_info(child)
                        if child == Path('/etc/dev-pair/limits.json'):
                            require(stat.S_ISREG(private.st_mode) and private.st_nlink == 1,
                                    'fixed public limits are not a protected regular file')
                            continue
                        require(not private.st_mode & 0o077, 'search grant would expose an unrelated existing checklist sibling')
                        hidden.add(str(child))
        return grant, sorted(hidden)

    def grant_role_search(self, grants, uid):
        for directory, device, inode, access in grants:
            info = self.role_path_info(directory)
            require((info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)) == (device, inode, 0o700),
                    'protected checklist search directory changed before grant')
            self.run('/usr/bin/setfacl', '--modify', f'user:{uid}:{access}', '--', str(directory), timeout=5)

    def managed_role_files(self):
        site = self.record(RENEWAL + '/site-current.json')
        require(type(site) is str and re.fullmatch(DIGEST, site), 'protected initial host selection reference is invalid')
        raw = checked_file(RENEWAL + '/releases/' + site + '.json').read_bytes()
        require(hashlib.sha256(raw).hexdigest() == site, 'selected host release manifest differs from its protected digest')
        release = json.loads(raw, object_pairs_hook=relay.unique)
        digest = release['components']['host']['artifact_sha256']
        require(type(digest) is str and re.fullmatch(DIGEST, digest), 'invalid selected host bundle identity')
        directory = Path('/usr/libexec/dev-pair/host-releases') / digest
        manifest = protect(directory / 'manifest.json')
        require(manifest.stat().st_size <= 1024**2 and hashlib.sha256(manifest.read_bytes()).hexdigest() == digest,
                'selected managed host bundle manifest differs')
        rows = json.loads(manifest.read_bytes(), object_pairs_hook=relay.unique)['files']
        result = {str(directory / name): rows[name] for name in FILES if not name.startswith('examples/')}
        wrapper = protect('/usr/libexec/dev-pair/renewal/checklist-entry')
        require(wrapper.stat().st_size <= 65536, 'managed checklist entry exceeds its audit bound')
        result[str(wrapper)] = hashlib.sha256(wrapper.read_bytes()).hexdigest()
        result[str(manifest)] = digest
        return result

    def verify_role_paths(self, uid, digests, directories, hidden, *, listing=()):
        code = ("import hashlib,json,os,sys\n"
                "uid,files,dirs,hidden,listing=json.loads(sys.stdin.buffer.read())\n"
                "assert os.getuid()==os.geteuid()==os.getgid()==os.getegid()==uid\n"
                "for path in dirs: assert os.path.isdir(path) and os.access(path,os.X_OK)\n"
                "for path in listing:\n"
                " with os.scandir(path): pass\n"
                "for path,expected in files.items():\n"
                " with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:\n"
                "  data=stream.read(4*1024**2+1); assert len(data)<=4*1024**2 and hashlib.sha256(data).hexdigest()==expected\n"
                "for path in hidden: assert not os.access(path,os.R_OK) and not os.access(path,os.X_OK)\n")
        proof = json.dumps([uid, digests, directories, hidden, listing], separators=(',', ':'))
        require(len(proof.encode()) <= 16384, 'checklist role path attestation inputs exceed their bound')
        self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', code, input_text=proof, timeout=20)

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
        self.physical_reserve(managed['reserve_inodes'])
        secrets = {file: checked_file(Path(args.tls_profile) / file, secret=True).read_bytes() for file in TLS_FILES}
        require(all(0 < len(value) <= 8192 for value in secrets.values()), 'invalid checklist TLS profile size')
        role_files = {CODE + '/' + name: code[name] for name in FILES}
        for role, path in STORAGE.items():
            role_files[GATE + '/' + role + '-containers.conf'] = f'[engine]\nimage_copy_tmp_dir="{path}/image-copy"\n'
        role_hashes = {path: hashlib.sha256(contents.encode()).hexdigest() for path, contents in role_files.items()}
        if managed_listener:
            role_hashes.update(self.managed_role_files())
        direct_dirs = [GATE, str(Path(self.unit_path(args.uid)).parent)]
        listing = (direct_dirs[1],)
        approval = GATE + '/approval.json'
        if os.path.lexists(approval):
            role_hashes[approval] = hashlib.sha256(checked_file(approval).read_bytes()).hexdigest()
        quadlet = self.unit_path(args.uid)
        if os.path.lexists(quadlet):
            state = self.initial_activation()
            digest = hashlib.sha256(checked_file(quadlet).read_bytes()).hexdigest()
            known = [state['active'], state['pending']['release'] if state['pending'] else None]
            require(any(item and item['unit_sha256'] == digest for item in known), 'unknown installed checklist Quadlet')
            role_hashes[quadlet] = digest
        live_groups = [entry.gr_gid for entry in grp.getgrall()]
        live_users = [entry.pw_uid for entry in pwd.getpwall()]
        require(not args.subid_start <= args.uid < args.subid_start + 65536, 'checklist UID overlaps its subordinate range')
        with self.lock('checklist-release.lock'):
            grants, private_siblings = self.role_search_plan(role_hashes, direct_dirs, args.uid, listing=listing)
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
            uid = self.account()
            require(uid == args.uid, 'checklist account changed from protected intent')
            self.run('/usr/sbin/visudo', '-c', timeout=10)
            package = self.run(*SUDO_PACKAGE_QUERY, timeout=10, sudo_package=True)
            self.run('/usr/bin/sudo', '-l', '-U', OWNER, timeout=10,
                     sudo_probe={'role': OWNER, 'host_verified': True, 'package': package})
            self.grant_role_search(grants, uid)
            for path in direct_dirs:
                if not os.path.lexists(path):
                    self.directory(path, mode=0o755)
            for path, content in role_files.items():
                self.atomic(path, content, mode=0o644)
            for path in (HOME, HOME + '/tls'):
                self.owned_directory(path, uid)
            for name in ('cert.pem', 'peer.pem'):
                value = secrets[name]
                self.role_secret(HOME + '/tls', name, value, uid)
                role_hashes[HOME + '/tls/' + name] = hashlib.sha256(value).hexdigest()
            self.run('/usr/sbin/restorecon', '-RF', CODE, GATE, direct_dirs[1], HOME + '/tls', timeout=15)
            self.verify_role_paths(uid, role_hashes, direct_dirs, sorted({*private_siblings, TRUST_SIGNERS}), listing=listing)
            self.role_secret(HOME + '/tls', 'key.pem', secrets['key.pem'], uid)
            for file, flag, live in (('/etc/subuid', '--add-subuids', live_users), ('/etc/subgid', '--add-subgids', live_groups)):
                self.subid(file, flag, uid, args.subid_start, live)
            if (not os.path.lexists(TRUST_CODE)
                    and not Path(TRUST_CODE).parent.lstat().st_mode & stat.S_IXOTH):
                self.directory(TRUST_CODE, mode=0o700)
            for relative, contents in code.items():
                if relative not in FILES:
                    target = ('/etc/systemd/system/' + EXECUTOR if relative.endswith('/' + EXECUTOR)
                              else TRUST_CODE + '/' + Path(relative).name)
                    self.atomic(target, contents, mode=0o644)
            self.directory(FENCE, mode=0o755)
            self.atomic(FENCE + '/owner.lock', '', mode=0o644)
            self.directory(RECEIPTS)
            for role, path in STORAGE.items():
                self.reserve(path, specs[role], uid, args.reserve_mib, args.reserve_inodes)
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
            unit, readiness = self.start_executor(uid, managed_listener, was_ready)
            if readiness == 'ready':
                self.atomic(CONTROL + '/ready.json', record_text(intent))
            return {'provisioned': readiness == 'ready', 'uid': uid, 'platform_sha': args.platform_sha,
                    'executor': unit, 'listener_state': readiness, 'listener_mode': 'managed' if managed_listener else 'commissioning'}

    def start_executor(self, uid, managed_listener, was_ready):
        unit = f'dev-pair-checklist-executor@{uid}.service'
        history_path = Path(HOME + '/execution-history')
        if os.path.lexists(history_path):
            history = history_path.lstat()
            require(stat.S_ISDIR(history.st_mode) and history.st_uid == uid and stat.S_IMODE(history.st_mode) == 0o700,
                    'protected prior provisioning lacks its independent execution history')
        else:
            require(not was_ready and not os.path.lexists(FENCE + '/frozen'),
                    'cannot recreate missing execution history on a previously provisioned or fenced host')
            require(self.run(SYSTEMCTL, 'is-active', unit, ok=(0, 3, 4), timeout=10).strip() != 'active',
                    'active checklist executor has no provisioned history')
            self.subprocess_role(uid, '/usr/bin/python3', '-EBs', CODE + '/tools/host_handoff.py', 'initialize-host-history')
        if managed_listener:
            return unit, self.managed_executor(unit, uid)
        require(not os.path.lexists(MANAGED_LISTENER), 'managed executor intent cannot return to direct commissioning')
        self.run(SYSTEMCTL, 'enable', '--now', unit, timeout=30)
        self.executor_ready(unit, uid)
        return unit, 'ready'

    def manager_job(self, unit):
        output = self.run(SYSTEMCTL, 'show', '--all', '--property=Job,ActiveState,Result', unit, timeout=10)
        fields = dict(row.split('=', 1) for row in output.splitlines())
        require(set(fields) == {'Job', 'ActiveState', 'Result'} and re.fullmatch(r'[0-9]*', fields['Job']),
                'systemd manager job readback is incomplete')
        return bool(int(fields['Job'] or '0')) or fields['ActiveState'] in ('activating', 'deactivating'), fields['Result']

    def verify_managed_executor(self, site, uid):
        protect(U_HOST_VERIFY)
        selector = self.record(FENCE + '/selected-host.json')
        returned = json.loads(self.run(U_HOST_VERIFY, 'verify', site, timeout=30), object_pairs_hook=relay.unique)
        require(returned['boot_id'] == self.destination_identity()['boot_id']
                and returned['component']['artifact_sha256'] == selector['artifact_sha256']
                and returned['handoff']['unit'] == f'dev-pair-checklist-executor@{uid}.service',
                'renewal host verifier did not attest this live selected executor')
        self.executor_ready(returned['handoff']['unit'], uid)

    def require_boot_fence(self):
        require(self.record(FENCE + '/frozen') == 'boot', 'commissioning requires the owned boot dispatch fence')

    def ensure_boot_fence(self):
        if not os.path.lexists(FENCE + '/frozen'):
            # The oneshot may still be active even after its marker was consumed.
            self.run(SYSTEMCTL, 'restart', U_BOOT_FENCE, timeout=30)
        self.require_boot_fence()

    def recovery_start(self):
        value = self.run(SYSTEMCTL, 'show', '--property=ExecMainStartTimestampMonotonic', '--value',
                         U_RECOVERY, timeout=10).strip()
        require(re.fullmatch(r'[0-9]{1,20}', value), 'renewal recovery start witness is unavailable')
        return int(value)

    def require_recovery_enabled(self):
        enabled = self.run(SYSTEMCTL, 'is-enabled', U_RECOVERY, ok=(0, 1), timeout=10).strip()
        require(enabled == 'enabled', 'renewal recovery is not enabled for the next boot')

    def managed_executor(self, unit, uid):
        site, boot = self.record(RENEWAL + '/site-current.json'), self.destination_identity()['boot_id']
        require(type(site) is str and re.fullmatch(DIGEST, site), 'protected initial host selection reference is invalid')
        prior = self.record(MANAGED_LISTENER) if os.path.lexists(MANAGED_LISTENER) else None
        record = {'version': 2, 'site': site, 'boot': boot, 'phase': 'queue-observe'}
        if prior and prior.get('version') == 2 and (prior['site'], prior['boot']) == (site, boot):
            record = prior
        else:
            self.atomic(MANAGED_LISTENER, record_text(record), expected=record_text(prior) if prior else None)
        if record['phase'] == 'queue-observe':
            recovery_running, _ = self.manager_job(U_RECOVERY)
            if recovery_running:
                return 'renewal-readback-running'
            if 'recovery_after' not in record:
                before = record
                record = {**record, 'recovery_after': self.recovery_start()}
                self.atomic(MANAGED_LISTENER, record_text(record), expected=record_text(before))
            running, _ = self.manager_job(U_OBSERVE)
            if running:
                self.require_boot_fence()
                self.atomic(MANAGED_LISTENER, record_text({**record, 'phase': 'observe'}), expected=record_text(record))
                return 'host-observation-running'
            self.run(SYSTEMCTL, 'enable', unit, timeout=30)
            self.ensure_boot_fence()
            self.run(SYSTEMCTL, 'start', '--no-block', U_OBSERVE, timeout=15)
            self.atomic(MANAGED_LISTENER, record_text({**record, 'phase': 'observe'}), expected=record_text(record))
            return 'host-observation-queued'
        if record['phase'] == 'observe':
            running, result = self.manager_job(U_OBSERVE)
            if running:
                return 'host-observation-running'
            if result not in ('success', ''):
                raise Blocked('managed host observation failed; inspect the owned renewal service before replay')
            self.verify_managed_executor(site, uid)
            advanced = {**record, 'phase': 'queue-recovery'}
            self.atomic(MANAGED_LISTENER, record_text(advanced), expected=record_text(record))
            record = advanced
        if record['phase'] == 'queue-recovery':
            running, result = self.manager_job(U_RECOVERY)
            if self.recovery_start() > record['recovery_after']:
                require(running or result == 'success', 'owned renewal recovery failed during commissioning')
                self.run(SYSTEMCTL, 'enable', U_RECOVERY, timeout=20)
            else:
                self.ensure_boot_fence()
                self.run(SYSTEMCTL, 'enable', '--now', '--no-block', U_RECOVERY, timeout=20)
            self.atomic(MANAGED_LISTENER, record_text({**record, 'phase': 'recovery'}), expected=record_text(record))
            return 'renewal-readback-running' if running else 'renewal-readback-queued'
        require(record['phase'] in ('recovery', 'ready'), 'unknown managed listener commissioning state')
        running, result = self.manager_job(U_RECOVERY)
        if running:
            return 'renewal-readback-running'
        if result not in ('success', ''):
            raise Blocked('owned renewal recovery failed; dispatch remains fenced')
        self.verify_managed_executor(site, uid)
        if os.path.lexists(FENCE + '/frozen'):
            return 'renewal-readback-fenced'
        require(result == 'success' and self.recovery_start() > record['recovery_after'],
                'renewal recovery has no fresh successful manager witness for this commissioning')
        self.require_recovery_enabled()
        if record['phase'] != 'ready':
            self.atomic(MANAGED_LISTENER, record_text({**record, 'phase': 'ready'}), expected=record_text(record))
        return 'ready'

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
                self.physical_reserve(managed['reserve_inodes'])
                dns = None
                if require_cutover:
                    listener = self.record(MANAGED_LISTENER)
                    site = self.record(RENEWAL + '/site-current.json')
                    require(listener['version'] == 2 and listener['phase'] == 'ready' and listener['site'] == site,
                            'production release requires current completed managed listener readback')
                    self.verify_managed_executor(site, uid)
                    recovery_running, recovery_result = self.manager_job(U_RECOVERY)
                    same_boot = listener['boot'] == self.destination_identity()['boot_id']
                    minimum_start = listener['recovery_after'] if same_boot else 0
                    require(not recovery_running and recovery_result == 'success' and self.recovery_start() > minimum_start,
                            'production release requires current boot renewal recovery')
                    self.require_recovery_enabled()
                    guard = self.verify_workload_access()
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

    def image_identity(self, uid, role, image, source, *, production, base=None):
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
        require(not production or base and labels.get('dev-pair.checklist.base') == base['image']
                and labels.get('dev-pair.checklist.base-proof') == base['proof_sha256'],
                'checklist image does not bind its independently verified signed base')
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
                observed = self.browser_inventory(dns)
                require(expected_data is None or observed == expected_data, 'actual checklist items changed during rollout')
                return fields['InvocationID']
            except OSError:
                if time.monotonic() >= deadline:
                    raise Blocked('checklist loopback service did not become ready') from None
                time.sleep(0.2)

    @staticmethod
    def browser_inventory(dns):
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
            return inventory_digest(json.loads(raw, object_pairs_hook=relay.unique))

    def data_items(self, uid, path):
        tool = protect(CODE + '/examples/checklist/checklist.py')
        code = ("from contextlib import closing; from pathlib import Path; import json,os,sys; "
                "p=Path(sys.argv[2]); assert p.is_file() and p.resolve(strict=True)==p; "
                "sys.path.insert(0, str(Path(sys.argv[1]).parent)); import checklist as c\n"
                "with closing(c.connect(p,readonly=True)) as db:\n"
                " c.verify_database(db); assert db.execute(\"SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'\").fetchall()==[('table','items',c.SCHEMA)]; "
                "sys.stdout.buffer.write(json.dumps([c.item_object(row) for row in db.execute("
                "'SELECT id,title,done FROM items ORDER BY id')],ensure_ascii=False,separators=(',',':')).encode('utf-8'))")
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
        self.sync_database(uid, backup)
        return {'path': backup, 'inventory_sha256': target}

    def sync_database(self, uid, path):
        sync = ('import os,sys; p=sys.argv[1]; '
                'f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); os.fsync(f); os.close(f); '
                'd=os.open(os.path.dirname(p),os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(d); os.close(d)')
        self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', sync, path)

    def archive_failed_data(self, uid, attempt):
        require(re.fullmatch(r'[0-9a-f]{32}', attempt), 'invalid checklist preservation attempt')
        target = LIVE + '/backups/' + attempt + '.failed-sqlite3'
        code = ("import os,stat,sys\n"
                "source,target=sys.argv[1:]\n"
                "for suffix in ('','-journal','-wal','-shm'):\n"
                " a=source+suffix\n"
                " if not os.path.lexists(a): continue\n"
                " current=os.lstat(a); assert stat.S_ISREG(current.st_mode) and current.st_uid==os.getuid()\n"
                " b=target+suffix+'.'+str(current.st_ino)\n"
                " if not os.path.lexists(b): os.link(a,b,follow_symlinks=False)\n"
                " saved=os.lstat(b); assert (current.st_dev,current.st_ino)==(saved.st_dev,saved.st_ino)\n"
                " for path in (a,b):\n"
                "  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)\n"
                " os.unlink(a)\n"
                " for path in (os.path.dirname(a),os.path.dirname(b)):\n"
                "  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)\n")
        self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', code, self.database_path(), target)
        archives = sorted(path for path in Path(target).parent.glob(Path(target).name + '.*')
                          if re.fullmatch(re.escape(target) + r'\.[1-9][0-9]*', str(path)))
        if archives:
            return str(archives[-1])
        return None

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
        self.sync_database(uid, source)

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
        allowed = ('', old, new) if active and active.get('quarantined') else (old, new)
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
            if active:
                self.data_snapshot(uid, self.database_path())
            self.current_unit(uid, ('', old) if active and active.get('quarantined') else (old,))
            pending = {'operation': operation, 'release': release, 'attempt': uuid.uuid4().hex,
                       'phase': 'reserved', 'baseline': None}
            state = {**state, 'pending': pending}
            self.save_activation(state)
        try:
            self.quiesce(uid, dns, allowed)
            if pending['phase'] == 'reserved':
                baseline = self.backup(uid, pending['attempt']) if active else None
                pending = {**pending, 'phase': 'prepared', 'baseline': baseline}
                state = {**state, 'pending': pending}
                self.save_activation(state)
            elif active:
                self.restore_failed_data(uid, pending)
            self.install_unit(uid, dns, release, allowed)
            expected = pending['baseline']['inventory_sha256'] if active else inventory_digest([])
            self.health(uid, dns, release, expected)
            require(self.data_snapshot(uid, self.database_path()) == expected,
                    'stored checklist data changed during isolated rollout')
            self.sync_database(uid, self.database_path())
        except Exception:
            self.recover(uid, dns, state)
            raise
        previous = state['previous'] if active and active.get('quarantined') else active
        result = {**state, 'active': {**release, 'backup': pending['baseline']}, 'previous': previous,
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
                require(not active.get('quarantined'), 'a rejected digest requires an independently approved correction')
                self.health(uid, dns, active)
                return self.finish_route(state, dns)
            require(not active or active.get('quarantined') or state['confirmed'] == active['artifact_sha256'],
                    'current release requires independent destination confirmation before replacement')
            require(not active or not active.get('quarantined') or image != active['subject'],
                    'correction must use another independently approved artifact digest')
            self.pull(uid, 'live', image, secret)
            release.update(image_id=self.image_identity(uid, 'live', image, source, production=True, base=release.get('base')), dns_name=dns,
                           compatibility=COMPATIBILITY)
            release['unit_sha256'] = hashlib.sha256(self.render_unit(uid, dns, release).encode()).hexdigest()
            ReleaseTrust(self.run).main(source)
            return self.activate(uid, dns, state, release, 'deploy')

    def recover(self, uid, dns, state):
        active, pending = state['active'], state['pending']
        if pending['operation'] == 'reject':
            return self.quarantine(uid, dns, state)
        wanted = pending['release']
        new = self.render_unit(uid, dns, wanted)
        old = self.render_unit(uid, dns, active) if active else ''
        current = self.quiesce(uid, dns, ('', old, new))
        if active:
            require(active['compatibility'] == COMPATIBILITY and active['dns_name'] == dns,
                    'prior compatible checksum is unavailable for recovery')
            baseline = pending['baseline']
            if pending['phase'] == 'prepared':
                self.restore_failed_data(uid, pending)
            if active.get('quarantined'):
                self.remove_unit(uid, current)
                result = {**state, 'pending': None, 'route_pending': False,
                          'last_failed': {'attempt': pending['attempt'], 'release': wanted, 'baseline': baseline}}
                self.save_activation(result)
                return result
            require(self.image_identity(uid, 'live', active['subject'], active['source_sha'], production=True,
                                        base=active.get('base')) == active['image_id'],
                    'prior exact digest is unavailable for recovery')
            expected = baseline['inventory_sha256'] if baseline else self.data_snapshot(uid, self.database_path())
            self.install_unit(uid, dns, active, ('', old, new))
            self.health(uid, dns, active, expected)
            require(self.data_snapshot(uid, self.database_path()) == expected, 'recovered checklist inventory changed')
            result = {**state, 'pending': None, 'route_pending': True,
                      'last_failed': {'attempt': pending['attempt'], 'release': wanted, 'baseline': baseline}}
            self.save_activation(result)
            return self.finish_route(result, dns)
        self.remove_unit(uid, current)
        archive = self.archive_failed_data(uid, pending['attempt'])
        require(not os.path.lexists(self.database_path()) and not self.serve_config(dns),
                'failed initial rollout still owns live data or ingress')
        result = {**state, 'pending': None,
                  'last_failed': {'attempt': pending['attempt'], 'release': wanted, 'data_archive': archive}}
        self.save_activation(result)
        return result

    def remove_unit(self, uid, current):
        if current:
            path = Path(self.unit_path(uid))
            path.unlink()
            self.sync_path(path.parent)
            self.user_unit(uid, 'daemon-reload')

    def quarantine(self, uid, dns, state):
        pending, active = state['pending'], state['active']
        current = self.quiesce(uid, dns, ('', self.render_unit(uid, dns, active)))
        baseline = self.backup(uid, pending['attempt'])
        self.remove_unit(uid, current)
        result = {**state, 'pending': None, 'route_pending': False,
                  'active': {**active, 'quarantined': True},
                  'last_rejected': {'attempt': pending['attempt'], 'release': active, 'baseline': baseline,
                                    'evidence_sha256': pending['evidence_sha256']}}
        self.save_activation(result)
        return result

    def reject(self, evidence):
        with self.release_gate() as (setup, uid, dns):
            state = self.initial_activation()
            active = state['active']
            require(active and not active.get('quarantined') and not state['confirmed'] and not state['previous']
                    and not state['pending'], 'rejection requires a first release awaiting external confirmation')
            data = self.recent_destination_evidence(evidence, 'dev-pair-access-review',
                                                    {'release_source', 'image', 'dns_name', 'failed_check', 'observation_sha256'},
                                                    lifetime=1800)
            require(data['source_sha'] == setup['platform_sha'] and data['release_source'] == active['source_sha']
                    and data['image'] == active['subject'] and data['dns_name'] == dns
                    and data['failed_check'] in ('authorized-browser', 'public-denial', 'unauthorized-denial',
                                                 'tailnet-loss', 'restart', 'reboot', 'clean-restore', 'remote-root')
                    and type(data['observation_sha256']) is str and re.fullmatch(DIGEST, data['observation_sha256']),
                    'rejection evidence does not bind this first release and its failed destination check')
            self.data_snapshot(uid, self.database_path())
            state = {**state, 'pending': {'operation': 'reject', 'attempt': uuid.uuid4().hex, 'release': active,
                                         'evidence_sha256': hashlib.sha256(protect(evidence).read_bytes()).hexdigest()}}
            self.save_activation(state)
            return self.quarantine(uid, dns, state)

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
            require(self.image_identity(uid, 'live', prior['subject'], prior['source_sha'], production=True,
                                        base=prior.get('base')) == prior['image_id'],
                    'previous exact digest is unavailable for rollback')
            return self.activate(uid, dns, state, prior, 'rollback')

    def confirm(self, evidence):
        with self.release_gate() as (setup, uid, dns):
            state = self.initial_activation()
            release = state['active']
            require(release and not release.get('quarantined') and not state['pending'] and not state['route_pending'],
                    'no settled rollout to confirm')
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
    reject = stages.add_parser('reject')
    reject.add_argument('--evidence', required=True)
    for stage in (storage, provision, preload, deploy, rollback, confirm, reject):
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
        elif args.stage == 'reject':
            result = app.reject(args.evidence)
        else:
            listener = app.record(MANAGED_LISTENER) if os.path.lexists(MANAGED_LISTENER) else None
            result = {**app.initial_activation(), 'managed_listener': listener,
                      'renewal_fenced': os.path.lexists(FENCE + '/frozen')}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        print('checklist destination blocked: ' + (str(exc) if isinstance(exc, Blocked) else 'required protected destination evidence unavailable'), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
