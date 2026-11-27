#!/usr/bin/env python3
"""Prepare and prove one credential-free DevBox placement on continuing Fedora 44."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

import devbox
import fedora_oci
from bootstrap import Blocked as BootstrapBlocked, SUDO_PACKAGE_QUERY, role_subordinate_range
from gptbox import (DEVELOPMENT_ARTIFACTS, DEVELOPMENT_ROOT, RELEASE_ARCHIVE, DevelopmentGptbox,
                    capture_release_file, image_diff_ids, image_inputs_bytes, sync_directory)
from native_io import verify_inactive_cgroup
from storage import GUEST_RESERVE, MANAGED_CEILING

db = devbox.db
ROOT = Path('/var/lib/dev-pair/native-placements')
ENV = db.local_env()
SOURCE = Path(__file__).resolve().parent.parent
SYS = '/usr/bin/systemctl'
PODMAN = (db.PODMAN, '--remote=false', '--runtime=' + db.CRUN, '--cgroup-manager=systemd')
OUTER_FILES = ('Containerfile', 'controller.py', 'containers.conf', 'enter-podman')
ENTRY_FILES = ('tools/devbox.py', 'runtime/devbox/controller.py', 'runtime/devbox/host-containers.conf')
INODE_CEILING = 524288
JOB_LIMIT = 48
TOOLING_RECIPE = f"""FROM {fedora_oci.IMAGE}
LABEL dev-pair.role=devbox-tooling dev-pair.tooling.base-config={fedora_oci.CONFIG}
RUN dnf -y --refresh --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 \\
    --setopt=install_weak_deps=False --disablerepo="*" --enablerepo=fedora --enablerepo=updates \\
    install podman crun shadow-utils python3 libcap policycoreutils && dnf clean all
RUN rpm -qa --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' | sort > /usr/lib/dev-pair-tooling-rpms.txt
""".encode()


def require(ok, reason):
    db.require(ok, reason)


def present(path):
    return os.path.lexists(path)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


def command(*args, seconds=10, allowed=(0,)):
    try:
        return db.bounded([str(arg) for arg in args], time.monotonic() + seconds, env=ENV,
                          seconds=seconds, allowed=allowed)
    except (db.Blocked, subprocess.TimeoutExpired) as error:
        raise db.Blocked(f'{Path(args[0]).name}: {error}') from None


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def write_atomic(path, data, mode=0o600):
    """Used only beneath protected, root-owned directories."""
    stage = path.with_name(path.name + '.new')
    # Reap a prior staging file only when its durable parent belongs to root.
    if present(stage):
        info = stage.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                'ambiguous protected staging file preserved')
        stage.unlink()
    fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(stage, path)
    sync_directory(path.parent)


def role_account(producer):
    account = pwd.getpwnam('dp-dev')
    uid, gid = account.pw_uid, account.pw_gid
    want = image_inputs_bytes({'name': 'dp-dev', 'shell': '/usr/sbin/nologin', 'substart': 1065536})
    require(producer.protected_bytes(Path('/var/lib/dev-pair/bootstrap/identity-dp-dev.json'), 4096, 0o600) == want
            and account.pw_dir == '/home/dp-dev' and account.pw_shell == '/usr/sbin/nologin'
            and uid >= 1000 and gid >= 1000
            and command('/usr/bin/id', '-nG', 'dp-dev')[1].split() == [b'dp-dev']
            and command('/usr/bin/hostnamectl', '--static')[1].strip() == b'erebus',
            'managed dp-dev identity or prepared host differs')
    status = command('/usr/bin/passwd', '-S', 'dp-dev')[1].split()
    require(len(status) >= 2 and status[0] == b'dp-dev' and status[1] in (b'L', b'LK'),
            'managed dp-dev password must remain locked')
    for name in ('subuid', 'subgid'):
        content = producer.protected_bytes(Path('/etc') / name, 65536).decode('ascii')
        require(role_subordinate_range(content, 'dp-dev', str(uid), 1065536),
                'managed dp-dev subordinate allocation differs')
    package = producer.run(*SUDO_PACKAGE_QUERY, timeout=10, sudo_package=True)
    proof = producer.run('/usr/bin/sudo', '-l', '-U', 'dp-dev', timeout=10,
                         sudo_probe={'role': 'dp-dev', 'host_verified': True, 'package': package})
    require(type(proof) is dict and proof.get('outcome') == 'denied',
            'live dp-dev sudo denial was not verified')
    limits = db.json_data(producer.protected_bytes(Path('/etc/dev-pair/limits.json'), 4096, 0o644))
    require(limits.get('jobs_enabled') is False
            and limits.get('storage_budget_bytes') == MANAGED_CEILING
            and limits.get('minimum_free_bytes') == GUEST_RESERVE,
            'credential-free placement requires the existing closed admission and storage limits')
    producer.protected(devbox.ROOT.parent)
    producer.protected(Path('/home'))
    for name in ('builds', 'evidence', *db.JOB_TARGETS):
        devbox.private_dir(devbox.ROOT / name, account)
    devbox.private_dir(devbox.ROOT, account)
    runtime = Path(f'/run/user/{uid}')
    devbox.private_dir(runtime, account)
    require(stat.S_ISSOCK((runtime / 'bus').lstat().st_mode)
            and command('/usr/bin/findmnt', '-n', '-o', 'FSTYPE', '--target', runtime)[1].strip() == b'tmpfs',
            'managed dp-dev user manager and tmpfs runtime required')
    return account


def verified_source(producer, revision, upstream):
    producer.protect_host_sources(upstream, revision)
    producer.source(revision)

    def exact(checkout, commit, name):
        path = producer.protected(checkout / name)
        data = producer.protected_bytes(path, 1024 * 1024)
        recorded = command('/usr/bin/git', '-C', checkout, 'show', commit + ':' + name)[1]
        require(data == recorded, f'{name} differs from exact Git bytes')
        return data

    require(command('/usr/bin/git', '-C', upstream, 'rev-parse', 'HEAD')[1].strip() == db.DISTROBOX.encode(),
            'upstream Distrobox checkout does not identify the pinned commit')
    enter = exact(upstream, db.DISTROBOX, 'distrobox-enter')
    require(hashlib.sha256(enter).hexdigest() == db.ENTER_SHA256, 'pinned Distrobox entry hash differs')
    for name in ('tools/native_placements.py', 'tools/storage.py'):
        exact(SOURCE, revision, name)
    entry_files = {name: exact(SOURCE, revision, name) for name in ENTRY_FILES}
    outer_files = {name: exact(SOURCE, revision, 'runtime/devbox/' + name) for name in OUTER_FILES}
    return entry_files, {'distrobox-enter': enter, **outer_files}


def protected_publication(producer, revision, context):
    producer.target = DEVELOPMENT_ROOT + '/' + context
    attempt = producer.read_attempt(context, revision)
    receipt = producer.read_publication(attempt)
    release = Path(DEVELOPMENT_ARTIFACTS) / context / 'release'
    require(receipt is not None and receipt['phase'] == 'ready'
            and not present(release.with_name('release.pending')),
            'sealed development release requires the producer’s protected ready publication')
    return producer.read_release(release, receipt), release / RELEASE_ARCHIVE


def used_categories():
    _, raw = command('/usr/bin/ps', '-e', '-o', 'label=')
    found = set()
    for value in raw.decode('ascii').splitlines():
        value = value.strip()
        parts = value.split(':', 3)
        if len(parts) < 4 or not parts[2].startswith('container_') or parts[3] == 's0':
            continue
        label = db.selinux_label(value)
        require(label is not None, 'live container MCS allocation cannot be verified')
        found.update(label[3])
    return found


def allocate_categories(occupied):
    available = [category for category in range(1023, -1, -1) if category not in occupied]
    require(len(available) >= 3, 'three exclusive SELinux categories are unavailable')
    outer = sorted(available[:3])
    return {'outer': outer, 'inner': outer[:2]}


def new_record(request, occupied):
    return {'schema': 1, 'request': request, 'categories': allocate_categories(occupied),
            'owner': os.urandom(32).hex(), 'volumes': {}, 'activity': None, 'images': None,
            'manifest': None, 'report': None, 'leaves': {}, 'attempts': {}, 'assembly_attempts': 0,
            'last_failure': None}


@contextmanager
def directory_fd(path):
    """Anchor a path whose intermediate directories may belong to dp-dev."""
    require(path.is_absolute() and '..' not in path.parts, 'invalid directory path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def set_label(fd, label):
    actual = os.getxattr(fd, 'security.selinux').decode('ascii').rstrip('\x00')
    if actual != label and not db.same_label(actual, label):
        os.setxattr(fd, 'security.selinux', label.encode('ascii') + b'\x00')
    observed = os.getxattr(fd, 'security.selinux').decode('ascii').rstrip('\x00')
    require(observed == label or db.same_label(observed, label), 'SELinux label did not apply')


@contextmanager
def private_child(parent, name, uid, gid, *, mode=0o700, create=True, label=None):
    """Create only the named leaf and never reset the metadata of an existing leaf."""
    created = False
    if create:
        try:
            os.mkdir(name, mode, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        node = os.fstat(fd)
        if created:
            require(node.st_uid == 0 and not node.st_mode & 0o022 and not os.listdir(fd),
                    'new directory was replaced before ownership was set')
            os.fchmod(fd, mode)
            if label:
                set_label(fd, label)
            os.fchown(fd, uid, gid)
            os.fsync(parent)
        node = os.fstat(fd)
        require((node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode)) == (uid, gid, mode),
                f'{name} is not an owned private directory')
        if label:
            actual = os.getxattr(fd, 'security.selinux').decode('ascii')
            require(db.same_label(actual, label), f'{name} SELinux label differs')
        yield fd, created
    finally:
        os.close(fd)


def free_space(path):
    sample = os.statvfs(path)
    return sample.f_bavail * sample.f_frsize


def mount_rows():
    with Path('/proc/self/mountinfo').open() as source:
        raw = source.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'mount inventory limit exceeded')
    return [line.split() for line in raw.splitlines()]


def by_target(rows, target):
    return [row for row in rows if row[4] == str(target)]


def block_id(device):
    info = device.stat()
    require(stat.S_ISBLK(info.st_mode), 'loop path is not a kernel block device')
    return f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'


def associated(image):
    _, raw = command('/usr/sbin/losetup', '--list', '--json', '--associated', image,
                     '--output=NAME,BACK-FILE,OFFSET,SIZELIMIT,RO,AUTOCLEAR')
    objects = db.json_data(raw)['loopdevices']
    require(type(objects) is list and len(objects) <= 1, 'ambiguous loop association preserved')
    if not objects:
        return None
    row = objects[0]
    require(re.fullmatch(r'/dev/loop[0-9]+', row.get('name', '')) and row['back-file'] == str(image)
            and row['offset'] == row['sizelimit'] == 0 and row['ro'] is row['autoclear'] is False,
            'loop association differs from protected backing file')
    return Path(row['name'])


def mount_owned(device, target, fd):
    # Resolve the already opened target in the calling controller's namespace.
    # A renamed/replaced path never redirects the privileged mount.
    command('/usr/bin/mount', '--no-canonicalize', '-t', 'ext4', '-o', 'rw,nosuid,nodev,noatime',
            device, f'/proc/{os.getpid()}/fd/{fd}', seconds=30)
    require(by_target(mount_rows(), target), 'owned mount did not land at its recorded target')


def validate_mount(device, path, capacity):
    number = block_id(device)
    rows = mount_rows()
    relevant = [row for row in rows if row[2] == number or row[4] == str(path)]
    require(len(relevant) == 1 and relevant[0][2:5] == [number, '/', str(path)],
            'loop volume is mounted somewhere other than its unique recorded root')
    row = relevant[0]
    separator = row.index('-')
    require(row[separator + 1:separator + 3] == ['ext4', str(device)]
            and {'rw', 'nodev', 'nosuid'} <= set(row[5].split(','))
            and 'discard' not in row[separator + 3].split(','),
            'loop filesystem type, source or mount options differ')
    require(not any(row[4].startswith(str(path) + '/') for row in rows),
            'foreign or still-active descendant mount preserved')
    node = path.stat()
    require(number == f'{os.major(node.st_dev)}:{os.minor(node.st_dev)}', 'mounted directory device changed')
    info = os.statvfs(path)
    size = info.f_blocks * info.f_frsize
    require(0 < size <= capacity and 0 < info.f_files <= INODE_CEILING and info.f_favail > 0,
            'filesystem exceeds its storage/inode limits or is out of inodes')
    return {'device': number, 'type': 'ext4', 'bytes': size, 'available_bytes': info.f_bavail * info.f_frsize,
            'inodes': info.f_files, 'available_inodes': info.f_favail}


def filesystem_uuid(device):
    status, raw = command('/usr/sbin/blkid', '-p', '-s', 'TYPE', '-s', 'UUID', '-o', 'export',
                          device, allowed=(0, 2))
    if status == 2 and not raw:
        return None
    values = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())
    require(values.get('TYPE') == 'ext4' and re.fullmatch(r'[0-9a-f-]{36}', values.get('UUID', '')),
            'conflicting filesystem signature preserved')
    return values['UUID']


def reserve(path, additional=0):
    require(free_space(path) >= GUEST_RESERVE + additional, 'eight GiB host reserve would be crossed')


class Volume:
    def __init__(self, placement, name, target, capacity):
        self.placement, self.name, self.target = placement, name, target
        self.capacity = capacity
        self.backing = placement.record.parent / (name + '.ext4')
        self.staging = self.backing.with_suffix('.mount')
        self.info = placement.state['volumes'].get(name)

    def backing_file(self):
        if self.info is None:
            reserve(self.backing.parent, self.capacity)
            with self.backing.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
                self.info = {'backing': identity(os.fstat(stream.fileno())), 'uuid': str(uuid.uuid4()),
                             'mountpoint': None, 'prepared': False}
                self.placement.state['volumes'][self.name] = self.info
                self.placement.save()
        fd = os.open(self.backing, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            node = os.fstat(fd)
            require(identity(node) == self.info['backing'] and node.st_uid == 0 and node.st_nlink == 1
                    and stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o600
                    and node.st_size <= self.capacity, 'unowned or changed loop backing preserved')
            if node.st_size != self.capacity or node.st_blocks * 512 < self.capacity:
                require(not self.info['prepared'], 'prepared loop backing allocation changed')
                reserve(self.backing.parent, self.capacity - min(node.st_blocks * 512, node.st_size))
                os.posix_fallocate(fd, 0, self.capacity)
                os.fsync(fd)
            node = os.fstat(fd)
            require(node.st_size == self.capacity and node.st_blocks * 512 >= self.capacity,
                    'loop backing must be fully allocated')
        finally:
            os.close(fd)
        reserve(self.backing.parent)

    def mount(self, initialize):
        self.backing_file()
        device = associated(self.backing)
        if device is None:
            _, raw = command('/usr/sbin/losetup', '--find', '--show', '--nooverlap', self.backing)
            device = associated(self.backing)
            require(device is not None and raw.decode('ascii').strip() == str(device),
                    'new kernel loop association could not be established')
        number = block_id(device)
        uid = filesystem_uuid(device)
        if uid is None:
            require(not self.info['prepared'] and not any(row[2] == number for row in mount_rows()),
                    'unverified prepared filesystem preserved')
            command('/usr/sbin/mkfs.ext4', '-q', '-U', self.info['uuid'], '-m', '0', '-N', '262144',
                    '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', device, seconds=90)
            uid = filesystem_uuid(device)
        require(uid == self.info['uuid'], 'mounted filesystem UUID differs from the protected lease')
        if by_target(mount_rows(), self.target):
            require(self.info['prepared'] and self.info['mountpoint'] is not None,
                    'unprepared mount at the final target preserved')
            return self.observe(device)

        if not self.info['prepared']:
            self.staging.mkdir(mode=0o700, exist_ok=True)
            if not by_target(mount_rows(), self.staging):
                require(not any(row[2] == number for row in mount_rows()), 'foreign loop mount preserved')
                with directory_fd(self.staging) as fd:
                    require(os.fstat(fd).st_uid == 0 and not os.listdir(fd), 'nonempty or foreign staging mountpoint')
                    mount_owned(device, self.staging, fd)
            validate_mount(device, self.staging, self.capacity)
            with directory_fd(self.staging) as fd:
                initialize(fd)
                os.fsync(fd)
            self.info['prepared'] = True
            self.placement.save()
        if by_target(mount_rows(), self.staging):
            validate_mount(device, self.staging, self.capacity)
            command('/usr/bin/umount', '--no-canonicalize', self.staging, seconds=30)
        require(not any(row[2] == number for row in mount_rows()), 'loop device already mounted elsewhere')
        account = self.placement.account
        with directory_fd(self.target.parent) as parent:
            with private_child(parent, self.target.name, account.pw_uid, account.pw_gid) as (fd, _):
                node = identity(os.fstat(fd))
                require(not os.listdir(fd) and self.info['mountpoint'] in (None, node),
                        'existing image store or replaced mountpoint preserved')
                self.info['mountpoint'] = node
                self.placement.save()
                mount_owned(device, self.target, fd)
        return self.observe(device)

    def observe(self, device):
        devbox.private_dir(self.target, self.placement.account)
        return validate_mount(device, self.target, self.capacity)


def current_boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f-]{36}', value), 'host boot identity is unavailable')
    return value


def stable_file(parent, name, data, label):
    """Publish a bounded read-only input on the dedicated filesystem."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        stage = name + '.new'
        # The root-owned inputs directory is bound by inode in the placement lease.
        try:
            old = os.stat(stage, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and old.st_nlink == 1,
                    'unknown stage object preserved')
            os.unlink(stage, dir_fd=parent)
        fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as output:
            data(output)
            set_label(output.fileno(), label)
            os.fchmod(output.fileno(), 0o444)
            output.flush()
            os.fsync(output.fileno())
        os.rename(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o444
                and db.same_label(os.getxattr(stream.fileno(), 'security.selinux').decode('ascii'), label),
                'staged candidate file ownership, permissions or SELinux label differ')


def image_shape(row):
    require(row.get('Architecture') == 'amd64' and row.get('Os') == 'linux',
            'local image architecture or OS differs')
    digest = row.get('Digest')
    require(type(digest) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', digest),
            'local OCI manifest digest is unavailable')
    return {'config_id': db.engine_id(row.get('Id')), 'oci_manifest_digest': digest,
            'diff_ids': image_diff_ids(row['RootFS']['Layers'])}


class Placement:
    def __init__(self, producer, account, request, files, inner, archive, cache):
        self.producer, self.account = producer, account
        self.entry_files, self.files = files
        self.inner, self.archive, self.cache = inner, archive, cache
        self.job = request['job']
        self.boot = current_boot()
        self.stage = 'previous activity'
        self.build_path = devbox.ROOT / 'builds' / self.job
        self.outer_path = Path(account.pw_dir) / '.local/share/containers/storage'
        self.inputs_path = self.build_path / 'inputs'
        self.copy_path = self.build_path / 'host-copy'
        self.record = ROOT / 'records' / self.job / 'placement.json'
        self.recipes = ROOT / 'recipes' / self.job
        self.entry = self.recipes / 'entry'
        producer.directory(str(ROOT), mode=0o755)
        producer.directory(str(ROOT / 'records'), mode=0o700)
        producer.directory(str(ROOT / 'recipes'), mode=0o755)
        producer.directory(str(self.record.parent), mode=0o700)
        producer.directory(str(self.recipes), mode=0o755)
        occupied = self.peer_allocations(request)
        if present(self.record):
            self.state = self.read_record(self.record)
            require(self.state['request'] == request, 'placement is bound to different source, storage or release')
            require(not occupied.intersection(self.state['categories']['outer']), 'persisted MCS reservations overlap')
        else:
            require(not any(present(devbox.ROOT / key / self.job)
                            for key in ('builds', 'evidence', *db.JOB_TARGETS)),
                    'placement already has unowned role leaves')
            self.state = new_record(request, occupied | used_categories())
            self.save()
        self.outer_label = db.file_label(self.state, 'outer')
        self.inner_label = db.file_label(self.state, 'inner')

    def read_record(self, path):
        value = db.json_data(self.producer.protected_bytes(path, db.MANIFEST_LIMIT, 0o600))
        db.fields(value, 'schema request categories owner volumes activity images manifest report leaves attempts '
                  'assembly_attempts last_failure',
                  'native placement lease')
        require(type(value['schema']) is int and value['schema'] == 1, 'unknown native placement record')
        db.hex_id(value['owner'])
        return value

    def save(self):
        data = json_bytes(self.state)
        require(len(data) <= db.MANIFEST_LIMIT, 'native placement evidence exceeds its bound')
        write_atomic(self.record, data)

    def fail(self, error):
        message = ''.join(character if character.isprintable() else ' ' for character in str(error))
        self.state['last_failure'] = {'stage': self.stage, 'boot_id': self.boot, 'diagnostic': message[:4096]}
        self.save()

    def peer_allocations(self, request):
        occupied = set()
        total = request['outer_bytes'] + request['build_bytes']
        for node in (ROOT / 'records').iterdir():
            if node.name == self.job:
                continue
            require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', node.name), 'unrecognized native placement lease preserved')
            peer = self.read_record(node / 'placement.json')
            require(peer['request']['job'] == node.name, 'another placement has ambiguous ownership')
            occupied.update(peer['categories']['outer'])
            total += peer['request']['outer_bytes'] + peer['request']['build_bytes']
        require(total <= MANAGED_CEILING, 'native placement volume reservations exceed twenty GiB')
        return occupied

    def check_categories(self):
        require(not used_categories().intersection(self.state['categories']['outer']),
                'live host container overlaps the reserved MCS categories')

    def reconcile(self, *, interrupted):
        entry = self.state['activity']
        if entry is None:
            return
        db.fields(entry, 'unit boot deadline', 'native activity')
        require(re.fullmatch(r'dev-pair-gptbox-[0-9a-f]{64}\.service', entry['unit']),
                'unrecognized managed unit identity; native state preserved')
        unit = entry['unit']
        description = 'dev-pair-owned-' + unit
        def observe():
            _, raw = command(SYS, 'show', '--property=LoadState,Description,User,ActiveState',
                             unit, allowed=(0, 1, 4))
            return dict(line.split('=', 1) for line in raw.decode('utf-8').splitlines())

        values = observe()
        if values.get('LoadState') != 'not-found':
            require(values.get('Description') == description and values.get('User') == 'dp-dev',
                    'foreign systemd unit preserved')
            if values.get('ActiveState') not in ('inactive', 'failed'):
                command(SYS, 'stop', unit, seconds=15)
                values = observe()
        require(values.get('ActiveState') in ('inactive', 'failed'), 'managed systemd unit remains active')
        if values.get('LoadState') == 'not-found' and interrupted and self.boot == entry['boot']:
            require(time.monotonic() >= entry['deadline'],
                    'previous systemd launch remains ambiguous until its protected deadline')
        verify_inactive_cgroup(unit)
        self.state['activity'] = None
        self.save()

    def managed(self, *args, seconds=30, copy=False, allowed=(0,)):
        token = hashlib.sha256((self.state['owner'] + os.urandom(32).hex()).encode()).hexdigest()
        unit = 'dev-pair-gptbox-' + token + '.service'
        _, raw = command(SYS, 'show', '--property=LoadState,ActiveState', unit, allowed=(0, 1, 4))
        require(dict(row.split(b'=', 1) for row in raw.splitlines())
                == {b'LoadState': b'not-found', b'ActiveState': b'inactive'}, 'native unit name is not pristine')
        self.state['activity'] = {'unit': unit, 'boot': self.boot, 'deadline': time.monotonic() + seconds + 30}
        self.save()
        environment = devbox.host_env(self.account)
        runtime = self.entry / 'runtime/devbox'
        environment.update(XDG_CONFIG_HOME=str(runtime), CONTAINERS_CONF=str(runtime / 'host-containers.conf'))
        if copy:
            environment['TMPDIR'] = str(self.copy_path)
        try:
            status, output = command('/usr/bin/timeout', '--kill-after=5s', f'{seconds + 16}s',
                                     '/usr/bin/systemd-run', '--unit=' + unit, '--description=dev-pair-owned-' + unit,
                                     '--uid=dp-dev', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
                                     '--property=Slice=system.slice', '--property=LimitCORE=0', '--property=UMask=0077',
                                     '--property=TimeoutStartSec=5s', '--property=TimeoutStopSec=10s',
                                     '--property=KillMode=control-group', '--property=MemoryMax=2G',
                                     '--property=MemorySwapMax=0', '--property=TasksMax=512',
                                     '--property=CPUQuota=100%', f'--property=RuntimeMaxSec={seconds}s',
                                     '/usr/bin/env', '-i', *(f'{key}={value}' for key, value in environment.items()),
                                     *args, seconds=seconds + 22, allowed=allowed)
        except BaseException as error:
            try:
                self.reconcile(interrupted=not re.search(r'command exit [1-9][0-9]?(?:\D|$)', str(error)))
            except (db.Blocked, OSError, ValueError, subprocess.SubprocessError) as cleanup:
                raise db.Blocked(f'{error}. Managed unit cleanup unresolved: {cleanup}') from None
            raise
        self.reconcile(interrupted=False)
        return status, output

    def engine(self, *args, timeout=30):
        _, raw = self.managed(*PODMAN, *args, seconds=timeout, copy=True)
        return raw

    def inspect(self, kind, image):
        raw = self.engine('inspect', '--type=' + kind, image, timeout=10)
        rows = db.json_data(raw)
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
                'ambiguous managed image inspection')
        return rows[0]

    def root_mode(self, fd):
        os.fchown(fd, self.account.pw_uid, self.account.pw_gid)
        os.fchmod(fd, 0o700)

    def initialize_outer(self, fd):
        _, raw = command('/usr/sbin/matchpathcon', '-n', self.outer_path)
        label = raw.decode('ascii').strip()
        require(re.fullmatch(r'[A-Za-z0-9_:.,-]{1,128}', label) is not None,
                'default SELinux context for managed outer graph is unavailable')
        set_label(fd, label)
        self.root_mode(fd)

    def initialize_build(self, fd):
        uid, gid = self.account.pw_uid, self.account.pw_gid
        for name in ('graph', 'image-copy'):
            with private_child(fd, name, uid, gid, label=self.outer_label):
                pass
        with private_child(fd, 'host-copy', uid, gid):
            pass
        with private_child(fd, 'inputs', 0, 0, mode=0o755, label=self.outer_label) as (inputs, _):
            def copy_archive(output):
                capture = capture_release_file(self.archive, self.inner['archive_bytes'], 0, output=output)
                require(capture[:2] == (self.inner['archive_sha256'], self.inner['archive_bytes']),
                        'protected archive changed before placement')
            stable_file(inputs, RELEASE_ARCHIVE, copy_archive, self.outer_label)
            self.state['volumes']['build']['inputs'] = identity(os.fstat(inputs))
        self.root_mode(fd)

    def verify_archive(self):
        archive = self.inputs_path / RELEASE_ARCHIVE
        expected = self.inner['archive_sha256'], self.inner['archive_bytes']
        deadline = time.monotonic() + 120
        require(db.file_hash(archive, self.inner['archive_bytes'], deadline)[:2] == expected,
                'staged archive differs from the protected publication')
        db.check_archive_image(archive, self.inner, self.state['request']['build_bytes'], deadline)

    def leaves(self):
        uid, gid = self.account.pw_uid, self.account.pw_gid
        for key in db.JOB_TARGETS:
            root = devbox.ROOT / key
            recorded = self.state['leaves'].get(key)
            with directory_fd(root) as parent:
                with private_child(parent, self.job, uid, gid, create=recorded is None,
                                   label=self.inner_label) as (fd, created):
                    node = identity(os.fstat(fd))
                    require(created if recorded is None else node == recorded,
                            f'{key} has an unowned or changed placement leaf')
                    require(not os.listdir(fd), f'{key} contains data; preserve the active or prior job')
                    if created:
                        self.state['leaves'][key] = node
                        self.save()

    def establish_storage(self):
        reserve(devbox.ROOT)
        reserve(self.outer_path.parents[3])
        home = Path(self.account.pw_dir)
        for parent in reversed(self.outer_path.parents[:3]):
            with directory_fd(parent.parent) as fd:
                try:
                    os.mkdir(parent.name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    child = os.open(parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        require(not os.listdir(child) and os.fstat(child).st_uid == 0,
                                'new outer graph ancestor changed before ownership')
                        os.fchown(child, self.account.pw_uid, self.account.pw_gid)
                    finally:
                        os.close(child)
                node = os.stat(parent.name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISDIR(node.st_mode) and (node.st_uid, node.st_gid) ==
                        (self.account.pw_uid, self.account.pw_gid) and not node.st_mode & 0o022,
                        'outer graph ancestor is foreign or writable by another account')
        devbox.private_dir(home, self.account)
        request = self.state['request']
        outer = Volume(self, 'outer', self.outer_path, request['outer_bytes'])
        build = Volume(self, 'build', self.build_path, request['build_bytes'])
        # Check both targets before creating either backing or covering a host directory.
        for volume in (outer, build):
            if volume.info is None and present(volume.target):
                with directory_fd(volume.target) as target:
                    info = os.fstat(target)
                    require(not by_target(mount_rows(), volume.target) and not os.listdir(target)
                            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                            (self.account.pw_uid, self.account.pw_gid, 0o700),
                            'unowned existing image store or build mount preserved')
        additional = sum(volume.capacity for volume in (outer, build) if volume.info is None)
        reserve(self.record.parent, additional)
        outer_sample = outer.mount(self.initialize_outer)
        build_sample = build.mount(self.initialize_build)
        reserve(devbox.ROOT)
        reserve(home)
        self.leaves()
        return {'outer': outer_sample, 'build': build_sample, 'minimum_host_free_bytes': GUEST_RESERVE}

    def recipe(self, parent, name, data):
        path = parent / name
        if present(path):
            require(self.producer.protected_bytes(path, 1024 * 1024, 0o444) == data,
                    'protected outer build recipe changed')
        else:
            write_atomic(path, data, 0o444)

    def engine_store(self):
        info = db.json_data(self.engine('info', '--format=json'))
        store = info['store']
        runtime = Path(f'/run/user/{self.account.pw_uid}')
        runroot = Path(store['runRoot'])
        require(info['host']['security']['rootless'] is True
                and info['host']['security']['selinuxEnabled'] is True
                and store['graphRoot'] == str(self.outer_path)
                and store['imageCopyTmpDir'] == str(self.copy_path)
                and runroot == runtime / 'containers' and runroot.resolve(strict=True) == runroot
                and runroot.stat().st_uid == self.account.pw_uid and runroot.stat().st_dev == runtime.stat().st_dev,
                'managed rootless graph, runroot or image-copy path differs')
        return {'graphroot': store['graphRoot'], 'runroot': str(runroot),
                'image_copy_tmp_dir': store['imageCopyTmpDir'], 'driver': store['graphDriverName']}

    def stage_entry(self):
        for name, data in self.entry_files.items():
            path = self.entry / name
            self.producer.directory(str(path.parent), mode=0o755)
            self.recipe(path.parent, path.name, data)

    def prepare_images(self, retry):
        request = self.state['request']
        store = self.engine_store()
        if self.state['images'] is None:
            attempts = self.state['assembly_attempts']
            require(type(attempts) is int and 0 <= attempts < 2 and (not attempts or retry),
                    'outer image setup requires explicit --retry within the two-attempt budget')
            self.state['assembly_attempts'] = attempts + 1
            self.save()
            tooling = self.recipes / 'tooling'
            outer = self.recipes / 'devbox'
            for path in (tooling, outer):
                self.producer.directory(str(path), mode=0o755)
            self.recipe(tooling, 'Containerfile', TOOLING_RECIPE)
            for name, data in self.files.items():
                self.recipe(outer, name, data)
            with fedora_oci.verified(self.cache, temporary_parent=self.inputs_path) as (plain, signature):
                base = fedora_oci.import_image(lambda *args, timeout: self.engine(*args, timeout=timeout),
                                               plain, uid=self.account.pw_uid)
            prefix = ('build', '--quiet', '--pull=never', '--http-proxy=false', '--format=oci')
            tool_id = db.engine_id(self.engine(*prefix, '--network=slirp4netns:allow_host_loopback=false',
                                               '--file', str(tooling / 'Containerfile'), str(tooling),
                                               timeout=600).decode('ascii').strip())
            outer_id = db.engine_id(self.engine(*prefix, '--network=none',
                                                '--build-arg', 'TOOLING_IMAGE=sha256:' + tool_id,
                                                '--build-arg', 'SOURCE_SHA=' + request['source_sha'],
                                                '--file', str(outer / 'Containerfile'), str(outer),
                                                timeout=600).decode('ascii').strip())
            self.state['images'] = {'base': base, 'signature': signature,
                                    'tooling': image_shape(self.inspect('image', tool_id)),
                                    'outer': image_shape(self.inspect('image', outer_id)),
                                    'build_context_sha256': hashlib.sha256(json_bytes(
                                        {key: hashlib.sha256(data).hexdigest() for key, data in self.files.items()}
                                    )).hexdigest(),
                                    'tooling_recipe_sha256': hashlib.sha256(TOOLING_RECIPE).hexdigest()}
            self.save()
        images = self.state['images']
        fedora_oci.validate_import_proof(images['base'])
        fedora_oci.imported([self.inspect('image', fedora_oci.IMAGE)])
        tooling_diffs = images['tooling']['diff_ids']
        outer_diffs = images['outer']['diff_ids']
        require(tooling_diffs[0] == 'sha256:' + fedora_oci.DIFF
                and outer_diffs[:len(tooling_diffs)] == tooling_diffs
                and len(outer_diffs) > len(tooling_diffs),
                'outer image layer chain does not extend the verified tooling and Fedora base')
        for key in ('tooling', 'outer'):
            row = self.inspect('image', images[key]['config_id'])
            require(image_shape(row) == images[key], f'locally prepared {key} image identity changed')
            if key == 'tooling':
                labels = row.get('Labels') or row.get('Config', {}).get('Labels', {})
                require(labels.get('dev-pair.role') == 'devbox-tooling'
                        and labels.get('dev-pair.tooling.base-config') == fedora_oci.CONFIG,
                        'tooling image lacks its signed Fedora input binding')
        db.immutable_image(self, {'outer': {'source_sha': request['source_sha'],
                                           'image_id': images['outer']['config_id']}}, 'outer')
        return store

    def write_manifest(self):
        request, images = self.state['request'], self.state['images']
        candidate = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': db.STANDARDS,
                     'job': self.job, 'storage_bytes': request['build_bytes'], 'inner': self.inner,
                     'outer': {'source_sha': request['source_sha'], 'image_id': images['outer']['config_id']},
                     'categories': self.state['categories']}
        raw = json_bytes(candidate)
        digest = hashlib.sha256(raw).hexdigest()
        require(self.state['manifest'] in (None, digest), 'placement manifest differs from its durable digest')
        with directory_fd(self.inputs_path) as fd:
            require(identity(os.fstat(fd)) == self.state['volumes']['build']['inputs'],
                    'bounded input directory was exchanged')
            stable_file(fd, 'manifest.json', lambda stream: stream.write(raw), self.outer_label)
        manifest = self.inputs_path / 'manifest.json'
        require(db.read_manifest(manifest, digest, time.monotonic() + 5) == candidate,
                'stored placement manifest does not match admitted candidate')
        self.state['manifest'] = digest
        self.save()
        return manifest, digest

    def run(self, *, retry):
        self.reconcile(interrupted=True)
        self.stage = 'storage and MCS reservation'
        self.check_categories()
        storage = self.establish_storage()
        self.stage = 'protected development archive'
        self.verify_archive()
        self.stage = 'immutable outer image'
        self.stage_entry()
        store = self.prepare_images(retry)
        self.stage = 'independently hashed manifest'
        manifest, digest = self.write_manifest()
        receipt = self.state['report']
        if receipt and receipt['boot_id'] == self.boot:
            return {**receipt, 'reused': True, 'storage': storage}
        attempts = self.state['attempts'].get(self.boot, 0)
        require(attempts < 2 and (not attempts or retry),
                'native probe requires explicit --retry within the two-attempt boot budget')
        require(len(self.state['attempts']) < 16 or self.boot in self.state['attempts'],
                'native placement boot history limit reached')
        self.state['attempts'][self.boot] = attempts + 1
        self.save()
        self.stage = 'managed nested entry'
        self.check_categories()
        _, raw = self.managed('/usr/bin/python3', '-I', '-B', self.entry / 'tools/devbox.py', 'run',
                              '--manifest', manifest, '--sha256', digest,
                              seconds=db.OUTER_SECONDS + 10)
        consumer = db.json_data(raw)
        require(consumer.get('manifest_sha256') == digest and consumer.get('job_admission') is False
                and consumer.get('inner_removed') is True and consumer.get('outer_removed') is True
                and consumer.get('outer_image_id') == self.state['images']['outer']['config_id']
                and consumer.get('archive_sha256') == self.inner['archive_sha256'],
                'managed DevBox result does not prove the exact offline placement')
        self.check_categories()
        reserve(devbox.ROOT)
        reserve(self.record.parent)
        after_storage = self.establish_storage()
        report = {'kind': 'dev-pair-native-placement-v1', 'job': self.job, 'boot_id': self.boot,
                  'job_admission': False, 'result': consumer, 'storage': after_storage, 'store': store,
                  'images': self.state['images'], 'manifest_sha256': digest, 'reused': False}
        self.state['report'] = report
        self.save()
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('run',))
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--context-sha256', required=True)
    parser.add_argument('--distrobox-source', required=True, type=Path)
    parser.add_argument('--fedora-cache', required=True, type=Path)
    parser.add_argument('--job', required=True)
    parser.add_argument('--storage-gib', type=int, default=14, choices=range(8, 17))
    parser.add_argument('--outer-storage-gib', type=int, default=6, choices=range(4, 9))
    parser.add_argument('--retry', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, db.interrupt)
    signal.setitimer(signal.ITIMER_REAL, 2280)
    try:
        db.hex_id(args.source_sha, 40)
        db.hex_id(args.context_sha256)
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', args.job)
                and len(args.job) <= JOB_LIMIT, 'invalid placement job name')
        require((args.storage_gib + args.outer_storage_gib) * db.GIB <= MANAGED_CEILING,
                'both volume reservations must fit in twenty GiB')
        require(os.geteuid() == os.getuid() == 0 and platform.machine() == 'x86_64',
                'authorized root operator on Fedora 44 x86_64 required')
        producer = DevelopmentGptbox()
        producer.preflight()
        for path in ('/usr/sbin/mkfs.ext4', '/usr/sbin/losetup', '/usr/sbin/blkid', db.PODMAN, db.CRUN):
            require(os.access(path, os.X_OK), f'required preinstalled Fedora tooling is unavailable: {path}')
        files = verified_source(producer, args.source_sha, args.distrobox_source)
        for name, (_, size, _) in fedora_oci.ARTIFACTS.items():
            node = producer.protected(args.fedora_cache / name).lstat()
            require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_size == size,
                    'pinned Fedora base inputs are absent from the protected cache')
        request = {'job': args.job, 'source_sha': args.source_sha, 'context_sha256': args.context_sha256,
                   'build_bytes': args.storage_gib * db.GIB, 'outer_bytes': args.outer_storage_gib * db.GIB}
        with producer.lock():
            producer.verify_host_readiness(args.source_sha, args.context_sha256)
            account = role_account(producer)
            inner, archive = protected_publication(producer, args.source_sha, args.context_sha256)
            placement = Placement(producer, account, request, files, inner, archive, args.fedora_cache)
            try:
                report = placement.run(retry=args.retry)
            except (db.Blocked, BootstrapBlocked, OSError, ValueError, KeyError, TypeError,
                    IndexError, subprocess.SubprocessError) as error:
                placement.fail(error)
                raise
        print(json.dumps(report, sort_keys=True))
        return 0
    except (BootstrapBlocked, db.Blocked, OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.SubprocessError) as error:
        print(f'Native placement blocked: {error}', file=sys.stderr)
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    sys.exit(main())
