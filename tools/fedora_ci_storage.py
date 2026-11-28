"""Fixed physical storage for the disposable Fedora CI controller."""
import fcntl
import json
import os
import pathlib
import re
import signal
import stat
import struct
import sys

GIB = 1024 ** 3
MIB = 1024 ** 2
HOST_RESERVE = 3 * GIB
OVERHEAD_LIMIT = 4 * GIB
OVERLAY_LIMIT = 16 * GIB
PARENT_HEADROOM = 16 * MIB
BLOCK_BYTES = 4096
MOUNTINFO_LIMIT = MIB
TOOLS = ('/usr/sbin/losetup', '/usr/sbin/mkfs.ext4', '/usr/bin/mount', '/usr/bin/umount')
FIEMAP = 0xC020660B
FIEMAP_HEADER = struct.Struct('=QQIIII')
FIEMAP_EXTENT = struct.Struct('=QQQQQIIII')
EXTENT_LIMIT = 2048


class StorageBlocked(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise StorageBlocked(message)


def identity(node):
    return node.st_dev, node.st_ino


def device_name(device):
    return f'{os.major(device)}:{os.minor(device)}'


def mount_table():
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(MOUNTINFO_LIMIT + 1)
    require(len(raw) <= MOUNTINFO_LIMIT, 'kernel mount inventory exceeds its bound')
    rows = []
    for row in os.fsdecode(raw).rstrip('\n').split('\n'):
        left, separator, right = row.partition(' - ')
        fields, superblock = left.split(' '), right.split(' ')
        require(separator and len(fields) >= 6 and len(superblock) == 3, 'invalid kernel mount inventory')
        paths = [pathlib.Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), field)) for field in fields[3:5]]
        rows.append((fields[0], fields[2], *paths, fields[5].split(','), fields[6:], superblock[0], superblock[2].split(',')))
    return rows


def fd_mount_id(fd):
    with open(f'/proc/self/fdinfo/{fd}', 'rb') as stream:
        data = stream.read(4096)
    match = re.search(rb'^mnt_id:\s+([0-9]+)$', data, re.M)
    require(match is not None, 'kernel mount identity unavailable')
    return match[1].decode()


def open_directory(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)


def verify_extents(fd, size):
    """Require a contiguous logical range of real allocated ext4 extents."""
    data = bytearray(FIEMAP_HEADER.size + EXTENT_LIMIT * FIEMAP_EXTENT.size)
    FIEMAP_HEADER.pack_into(data, 0, 0, size, 1, 0, EXTENT_LIMIT, 0)  # FIEMAP_FLAG_SYNC
    fcntl.ioctl(fd, FIEMAP, data)
    _, _, _, count, _, _ = FIEMAP_HEADER.unpack_from(data)
    require(0 < count <= EXTENT_LIMIT, 'physical backing extent inventory is unavailable')
    end = 0
    for index in range(count):
        logical, physical, length, _, _, flags, *_ = FIEMAP_EXTENT.unpack_from(
            data, FIEMAP_HEADER.size + index * FIEMAP_EXTENT.size)
        require(logical == end and physical > 0 and length > 0 and not flags & ~(0x1 | 0x800) and
                bool(flags & 0x1) == (index == count - 1),
                'backing extents are sparse, shared, delayed or incomplete')
        end += length
    require(end >= size, 'physical backing extent length is incomplete')


def verify_native_device(device):
    path = (pathlib.Path('/sys/dev/block') / device).resolve(strict=True)
    disk = path.parent if (path / 'partition').is_file() else path
    require(re.fullmatch(r'(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+)', disk.name) and
            (disk / 'slaves').is_dir() and not any((disk / 'slaves').iterdir()),
            'backing mount is not on a supported direct runner block device')


class Volume:
    def __init__(self, root, name, size, inodes, privileged):
        self.name = name
        self.path = root / name
        self.backing = root / (name + '.ext4')
        self.size = size
        self.inodes = inodes
        self.privileged = privileged
        self.backing_identity = None
        self.directory_identity = None
        self.mount_id = None

    def backing_node(self):
        node = self.backing.lstat()
        require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o600 and node.st_nlink == 1 and
                node.st_uid == os.getuid() and identity(node) == self.backing_identity,
                f'{self.name} backing file ownership changed')
        return node

    def physical_allocation(self, node):
        require(node.st_size == self.size and node.st_blocks * 512 >= self.size,
                f'{self.name} backing file is sparse, resized or incompletely allocated')
        return node.st_blocks * 512

    def associated_loop(self):
        node = self.backing_node()
        output = self.privileged('/usr/sbin/losetup', '--list', '--json', '--associated', str(self.backing),
                                 '--output', 'NAME,MAJ:MIN,BACK-MAJ:MIN,BACK-INO,OFFSET,SIZELIMIT,RO')
        value = json.loads(output)
        rows = value.get('loopdevices') if type(value) is dict else None
        require(type(rows) is list and len(rows) <= 1, f'{self.name} loop ownership is ambiguous')
        if not rows:
            return None
        row = rows[0]
        require(type(row) is dict and type(row.get('name')) is str and re.fullmatch(r'/dev/loop[0-9]+', row['name']) and
                str(row.get('back-ino')) == str(node.st_ino) and row.get('back-maj:min') == device_name(node.st_dev) and
                str(row.get('offset')) == '0' and str(row.get('sizelimit')) == str(self.size) and row.get('ro') is False,
                f'{self.name} loop does not match its admitted backing')
        block = os.stat(row['name'], follow_symlinks=False)
        require(stat.S_ISBLK(block.st_mode) and row.get('maj:min') == device_name(block.st_rdev),
                f'{self.name} loop device identity changed')
        sectors = pathlib.Path('/sys/dev/block') / row['maj:min'] / 'size'
        require(sectors.read_text().strip() == str(self.size // 512), f'{self.name} loop size changed')
        return row['name'], row['maj:min']

    def configure(self):
        self.path.mkdir(mode=0o700)
        self.directory_identity = identity(self.path.lstat())
        fd = os.open(self.backing, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            self.backing_identity = identity(os.fstat(fd))
            os.posix_fallocate(fd, 0, self.size)
            os.fsync(fd)
            self.physical_allocation(os.fstat(fd))
            verify_extents(fd, self.size)
        finally:
            os.close(fd)
        require(self.associated_loop() is None, f'{self.name} backing already has a loop')
        attached = self.privileged('/usr/sbin/losetup', '--find', '--show', '--nooverlap',
                                   '--sizelimit', str(self.size), '--', str(self.backing)).decode().strip()
        loop = self.associated_loop()
        require(loop and attached == loop[0], f'{self.name} loop creation could not be verified')
        self.privileged('/usr/sbin/mkfs.ext4', '-q', '-F', '-b', str(BLOCK_BYTES), '-I', '256', '-m', '0', '-N',
                        str(self.inodes), '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', loop[0], seconds=45)
        self.privileged('/usr/bin/mount', '-i', '-n', '-t', 'ext4', '-o', 'rw,nodev,nosuid,nodiscard', '--', loop[0], str(self.path))
        rows = mount_table()
        mounted = self.owned_mount(rows, loop)
        require(mounted is not None, f'{self.name} mount not found')
        self.mount_id = mounted[0]
        self.privileged('/usr/bin/chown', f'{os.getuid()}:{os.getgid()}', '--', str(self.path))
        self.privileged('/usr/bin/chmod', '0755', '--', str(self.path))
        fd = os.open(self.backing, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(identity(os.fstat(fd)) == self.backing_identity, f'{self.name} backing identity changed')
            verify_extents(fd, self.size)
        finally:
            os.close(fd)
        self.observe(rows)

    def owned_mount(self, rows, loop):
        mounts = [row for row in rows if row[3] == self.path]
        if not mounts:
            return None
        require(len(mounts) == 1 and loop is not None, f'{self.name} mount ownership is ambiguous')
        mounted = mounts[0]
        _, device, source, _, flags, propagation, fstype, options = mounted
        require(device == loop[1] and source == pathlib.Path('/') and fstype == 'ext4' and
                {'rw', 'nodev', 'nosuid'} <= set(flags) and 'discard' not in options and not propagation and
                (self.mount_id is None or mounted[0] == self.mount_id), f'{self.name} mount identity changed')
        return mounted

    def filesystem(self, rows):
        require(self.mount_id is not None, f'{self.name} capacity is unavailable')
        fd = open_directory(self.path)
        try:
            node = os.fstat(fd)
            mounted = self.owned_mount(rows, (None, device_name(node.st_dev)))
            require(mounted is not None and fd_mount_id(fd) == mounted[0] and node.st_ino == 2 and node.st_uid == os.getuid() and
                    not node.st_mode & 0o022, f'{self.name} volume directory changed')
            return os.fstatvfs(fd)
        finally:
            os.close(fd)

    def observe(self, rows):
        allocated = self.physical_allocation(self.backing_node())
        fs = self.filesystem(rows)
        require(fs.f_frsize == BLOCK_BYTES and 0 < fs.f_blocks * BLOCK_BYTES <= self.size and fs.f_files == self.inodes and
                0 < fs.f_bavail <= fs.f_bfree <= fs.f_blocks and 0 < fs.f_favail <= fs.f_ffree <= fs.f_files,
                f'{self.name} volume capacity, geometry or inode reserve blocked')
        return {'backing_allocated_bytes': allocated, 'filesystem_bytes': fs.f_blocks * BLOCK_BYTES,
                'available_bytes': fs.f_bavail * BLOCK_BYTES, 'total_inodes': fs.f_files, 'available_inodes': fs.f_favail}

    def release(self):
        rows = mount_table()
        require(not any(self.path in row[3].parents for row in rows), f'{self.name} still contains an active mount')
        loop = self.associated_loop() if self.backing_identity is not None else None
        mounted = self.owned_mount(rows, loop)
        if mounted is not None:
            self.privileged('/usr/bin/umount', '-i', '-n', '--', str(self.path))
            require(not any(row[3] == self.path or self.path in row[3].parents for row in mount_table()),
                    f'{self.name} mount removal is unresolved')
        if self.directory_identity is not None:
            node = self.path.lstat()
            require(stat.S_ISDIR(node.st_mode) and identity(node) == self.directory_identity and node.st_uid == os.getuid(),
                    f'{self.name} mountpoint ownership changed')
        if loop is not None:
            require(self.associated_loop() == loop, f'{self.name} loop changed before detach')
            self.privileged('/usr/sbin/losetup', '--detach', '--', loop[0])
            require(self.associated_loop() is None, f'{self.name} loop detach is unresolved')
        if self.backing_identity is not None:
            self.backing_node()
            self.backing.unlink()
        if self.directory_identity is not None:
            self.path.rmdir()


class KernelStorage:
    def __init__(self, lease, privileged):
        self.lease = lease
        self.lease_identity = identity(lease.lstat())
        self.overhead = Volume(lease, 'overhead', OVERHEAD_LIMIT, 65536, privileged)
        self.overlay = Volume(lease, 'overlay', OVERLAY_LIMIT, 4096, privileged)
        self.volumes = (self.overhead, self.overlay)
        self.parent_mount = None
        self.started = False

    def parent_free(self, pending=0, *, rows=None, reserve=True):
        fd = open_directory(self.lease)
        try:
            node = os.fstat(fd)
            require(identity(node) == self.lease_identity and node.st_uid == os.getuid() and not node.st_mode & 0o022,
                    'owned backing directory identity changed')
            mount_id = fd_mount_id(fd)
            table = mount_table() if rows is None else rows
            matches = [row for row in table if row[0] == mount_id]
            require(len(matches) == 1 and matches[0][1] == device_name(node.st_dev) and matches[0][6] == 'ext4' and
                    matches[0][2] == pathlib.Path('/') and not matches[0][5] and
                    (self.parent_mount is None or mount_id == self.parent_mount),
                    'physical backing requires a private native ext4 runner mount')
            if self.parent_mount is None:
                verify_native_device(matches[0][1])
                self.parent_mount = mount_id
            fs = os.fstatvfs(fd)
        finally:
            os.close(fd)
        free = fs.f_bavail * fs.f_frsize
        if reserve:
            require(free >= HOST_RESERVE + pending and fs.f_favail >= 4, 'physical backing or host recovery reserve insufficient')
        return free

    def configure(self):
        initial_free = self.parent_free(OVERHEAD_LIMIT + OVERLAY_LIMIT + PARENT_HEADROOM)
        self.started = True
        self.overhead.configure()
        self.parent_free(OVERLAY_LIMIT + PARENT_HEADROOM)
        self.overlay.configure()
        result = self.observe()
        result['initial_parent_free_bytes'] = initial_free
        return result

    def observe(self):
        rows = mount_table()
        return {'parent_free_bytes': self.parent_free(rows=rows),
                **{volume.name: volume.observe(rows) for volume in self.volumes}}

    def verify_engine_mount(self):
        rows = mount_table()
        self.parent_free(rows=rows, reserve=False)
        self.overhead.filesystem(rows)

    def release(self):
        rows = mount_table()
        require(not any(row[3] == self.lease for row in rows), 'owned backing directory is covered by a mount')
        if self.started:
            self.parent_free(rows=rows, reserve=False)
            for volume in reversed(self.volumes):
                volume.release()
        require(not any(row[3] == self.lease or self.lease in row[3].parents for row in mount_table()),
                'owned backing directory still contains active mounts')


def stop_namespace_children(expected_namespace):
    """This helper can signal only children of the probe's private PID 1."""
    require(os.geteuid() == 0 and os.readlink('/proc/self/ns/pid') == expected_namespace,
            'native process namespace identity changed')
    with open('/proc/1/cmdline', 'rb') as stream:
        init = stream.read(4096).split(b'\0')
    controller = os.fsencode(pathlib.Path(__file__).with_name('fedora_ci.py').resolve())
    require(controller in init and b'--namespace-parent' in init and os.getpid() > 1,
            'native process namespace controller is unavailable')

    ancestry = {os.getpid()}
    pid = os.getppid()
    while pid > 1 and len(ancestry) < 16:
        ancestry.add(pid)
        data = pathlib.Path(f'/proc/{pid}/stat').read_bytes().rsplit(b')', 1)[1].split()
        pid = int(data[1])
    require(pid == 1, 'native cleanup helper has foreign ancestry')
    ancestry.add(1)

    candidates = sorted(int(name) for name in os.listdir('/proc') if name.isascii() and name.isdecimal())
    require(len(candidates) <= 2048, 'native process inventory exceeds its bound')
    for pid in reversed(candidates):
        if pid in ancestry:
            continue
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            continue
        try:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            os.close(fd)


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != 'stop-children':
        raise SystemExit(2)
    stop_namespace_children(sys.argv[2])
