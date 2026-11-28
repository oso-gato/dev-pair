"""Physical reserve and fixed loop backing checks for the managed ext4 store."""
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import struct
import time
import uuid

from storage import StorageBlocked, filesystem_type, mount_id, root_fd

MIB = 1024 ** 2
BTRFS_SYSFS = Path('/sys/fs/btrfs')
BTRFS_IOC_FS_INFO = 0x8400941F
BTRFS_BLOCK_GROUP_METADATA = 4
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_COMPR_FL = 0x00000004
FS_NOCOW_FL = 0x00800000
FIEMAP = 0xC020660B
FIEMAP_HEADER = struct.Struct('=QQIIII')
FIEMAP_EXTENT = struct.Struct('=QQQQQIIII')
FIEMAP_LAST = 0x1
FIEMAP_UNWRITTEN = 0x800
EXTENTS_PER_QUERY = 128


@dataclass(frozen=True)
class ParentSpace:
    kind: str
    available_bytes: int
    available_inodes: int | None
    metadata_bytes: int | None = None
    nodesize: int | None = None

    def check(self, required_bytes, required_inodes, error, message):
        if self.available_bytes < required_bytes:
            raise error(message)
        if self.kind == 'btrfs':
            # Budget two metadata nodes per requested recovery inode. Keep
            # allocated metadata space available independently of data space.
            if self.metadata_bytes < 2 * required_inodes * self.nodesize:
                raise error(message + ' (Btrfs metadata reserve is too low)')
        elif self.available_inodes < required_inodes:
            raise error(message)

    def display(self):
        if self.kind == 'btrfs':
            return f'{self.metadata_bytes // MIB} MiB Btrfs metadata free'
        return f'{self.available_inodes} inodes'


def read_counter(path):
    with path.open('rb') as stream:
        raw = stream.read(22)
    if not 2 <= len(raw) <= 21 or not raw.endswith(b'\n') or not raw[:-1].isdigit():
        raise ValueError('invalid Btrfs allocation counter')
    return int(raw)


def btrfs_metadata(fd):
    info = bytearray(1024)
    fcntl.ioctl(fd, BTRFS_IOC_FS_INFO, info)
    _, devices, fsid, nodesize = struct.unpack_from('=QQ16sI', info)
    if devices != 1 or not any(fsid) or nodesize not in (4096, 8192, 16384, 32768, 65536):
        raise ValueError('unsupported Btrfs physical geometry')
    metadata = BTRFS_SYSFS / str(uuid.UUID(bytes=fsid)) / 'allocation/metadata'
    if read_counter(metadata / 'flags') != BTRFS_BLOCK_GROUP_METADATA:
        raise ValueError('Btrfs requires dedicated metadata allocation')
    total = read_counter(metadata / 'total_bytes')
    # bytes_may_use already accounts for the kernel's global block reserve.
    occupied = sum(read_counter(metadata / name) for name in
                   ('bytes_used', 'bytes_pinned', 'bytes_reserved', 'bytes_may_use',
                    'bytes_readonly', 'bytes_zone_unusable'))
    return max(0, total - occupied), nodesize


def observe(path, error):
    try:
        parent = root_fd(path)
        try:
            kind = filesystem_type(mount_id(parent))
            fs = os.fstatvfs(parent)
            if kind not in ('ext4', 'xfs', 'btrfs') or not (
                    fs.f_frsize > 0 and 0 <= fs.f_bavail <= fs.f_bfree <= fs.f_blocks
                    and not fs.f_flag & os.ST_RDONLY):
                raise ValueError('unsupported physical filesystem')
            free = fs.f_bavail * fs.f_frsize
            if kind != 'btrfs':
                if not 0 <= fs.f_favail <= fs.f_ffree <= fs.f_files or fs.f_files == 0:
                    raise ValueError('finite inode capacity unavailable')
                return ParentSpace(kind, free, fs.f_favail)
            # Btrfs exposes no fixed inode table. Its actual available
            # metadata is observed through an fd bound to this mount.
            fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent)
            try:
                metadata, nodesize = btrfs_metadata(fd)
            finally:
                os.close(fd)
            return ParentSpace(kind, free, None, metadata, nodesize)
        finally:
            os.close(parent)
    except (OSError, ValueError) as exc:
        raise error('physical storage byte or finite inode geometry is unavailable') from exc


def prepare_btrfs(fd, *, empty, error):
    """Set NOCOW on a new empty file before reserving any extents."""
    flags = bytearray(8)
    fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags)
    (current,) = struct.unpack_from('=I', flags)
    wanted = (current | FS_NOCOW_FL) & ~FS_COMPR_FL
    if empty and current != wanted:
        struct.pack_into('=I', flags, 0, wanted)
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, flags)
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags)
        (current,) = struct.unpack_from('=I', flags)
    if current & (FS_NOCOW_FL | FS_COMPR_FL) != FS_NOCOW_FL:
        raise error('Btrfs backing must have NOCOW and no compression before allocation')


def verify_btrfs(fd, size, error):
    """Verify the full file is exclusive, uncompressed and physically allocated."""
    prepare_btrfs(fd, empty=False, error=error)
    end = time.monotonic() + 30
    cursor = 0
    data = bytearray(FIEMAP_HEADER.size + EXTENTS_PER_QUERY * FIEMAP_EXTENT.size)
    while cursor < size:
        if time.monotonic() >= end:
            raise error('Btrfs backing extent verification exceeded its deadline')
        FIEMAP_HEADER.pack_into(data, 0, cursor, size - cursor, 1, 0, EXTENTS_PER_QUERY, 0)
        fcntl.ioctl(fd, FIEMAP, data)
        _, _, _, count, _, _ = FIEMAP_HEADER.unpack_from(data)
        if not 0 < count <= EXTENTS_PER_QUERY:
            raise error('Btrfs backing extent inventory is incomplete')
        for index in range(count):
            logical, physical, length, _, _, flags, *_ = FIEMAP_EXTENT.unpack_from(
                data, FIEMAP_HEADER.size + index * FIEMAP_EXTENT.size)
            if (logical != cursor or physical == 0 or length == 0 or logical + length > size
                    or flags & ~(FIEMAP_LAST | FIEMAP_UNWRITTEN)
                    or (flags & FIEMAP_LAST and logical + length != size)):
                raise error('Btrfs backing extents are sparse, shared, compressed or incomplete')
            cursor += length


def verify_backing(path, node, error):
    """Recheck a protected Btrfs backing before admission or receipt publication."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        if (node.st_dev, node.st_ino, node.st_size) != (current.st_dev, current.st_ino, current.st_size):
            raise error('protected backing identity changed')
        if filesystem_type(mount_id(fd)) == 'btrfs':
            verify_btrfs(fd, node.st_size, error)
    except StorageBlocked as exc:
        raise error('protected backing filesystem identity unavailable') from exc
    finally:
        os.close(fd)
