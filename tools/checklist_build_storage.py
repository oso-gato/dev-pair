"""The protected checklist builder's single disposable OCI transfer slot."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import sys
import time

import job_protocol as p
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private
from storage import mount_id

IDLE_SECONDS = 7 * 24 * 60 * 60
INODE_HEADROOM = 4096
IMAGE_HEADROOM = 64 * 1024 ** 2
ARCHIVE = 'candidate.oci'


class StoragePressure(BlockingIOError):
    def __init__(self):
        super().__init__('checklist build paused for bounded filesystem bytes or inodes')


@contextmanager
def transfer_reader(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        # The engine inherits this open file description as stdin. Closing the
        # conductor's copy cannot drop a surviving helper's shared lock.
        fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield stream


def free_space(fd):
    info = os.fstatvfs(fd)
    p.require(info.f_frsize > 0 and info.f_files > 0, 'checklist storage has no finite inode evidence')
    return {'bytes': info.f_bavail * info.f_frsize, 'inodes': info.f_favail}


def enough(space, archive_limit):
    # Simultaneous transfer, engine staging and imported content can overlap.
    required = reserve(archive_limit)
    return space['bytes'] >= required['bytes'] and space['inodes'] >= required['inodes']


def reserve(archive_limit):
    return {'bytes': 3 * archive_limit + IMAGE_HEADROOM, 'inodes': INODE_HEADROOM}


def replace_private(staged, target, raw):
    if os.path.lexists(staged):
        node = staged.lstat()
        p.require(stat.S_ISREG(node.st_mode) and node.st_uid == node.st_gid == 0 and node.st_nlink == 1
                  and stat.S_IMODE(node.st_mode) == 0o600 and node.st_size <= 4096,
                  'ambiguous checklist lifecycle record preserved')
        staged.unlink()
    write_private(staged, raw)
    os.replace(staged, target)
    sync_directory(staged.parent)
    if staged.parent != target.parent:
        sync_directory(target.parent)


class Spool:
    def __init__(self, control, storage, device, archive_limit):
        self.control = trusted_directory(control)
        self.path = storage / '.build-transfer'
        self.device = device
        self.limit = archive_limit
        self.lease = self.control / 'lease.json'

    @contextmanager
    def locked(self, *, create):
        fd = os.open(self.control / 'owner.lock',
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            node = os.fstat(fd)
            p.require(stat.S_ISREG(node.st_mode) and node.st_uid == node.st_gid == 0 and node.st_nlink == 1
                      and stat.S_IMODE(node.st_mode) == 0o600, 'checklist build lock ownership changed')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if create:
                try:
                    self.path.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                else:
                    sync_directory(self.path.parent)
            try:
                fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except FileNotFoundError:
                p.require(not create and not os.path.lexists(self.lease),
                          'owned checklist transfer directory is missing')
                yield None
                return
            try:
                self.identity(fd)
                yield fd
            finally:
                os.close(fd)

    def identity(self, fd):
        node = os.fstat(fd)
        current = self.path.lstat()
        p.require((node.st_ino, node.st_dev) == (current.st_ino, current.st_dev)
                  and node.st_dev == self.device and node.st_uid == node.st_gid == 0
                  and stat.S_IMODE(node.st_mode) == 0o700, 'checklist transfer directory ownership changed')
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            p.require(mount_id(fd) == mount_id(parent), 'checklist transfer directory crosses its bounded mount')
        finally:
            os.close(parent)
        return [os.fstatvfs(fd).f_fsid, node.st_ino]

    def record(self, fd):
        try:
            value = p.loads(read_private(self.lease, 2048))
        except FileNotFoundError:
            return None
        p.fields(value, 'schema directory job revision reserved_at')
        identity = value['directory']
        p.require(type(value['schema']) is int and value['schema'] == 1
                  and type(identity) is list and len(identity) == 2 and all(type(part) is int for part in identity)
                  and identity == self.identity(fd),
                  'checklist transfer lease directory identity changed')
        p.token(value['job'])
        p.digest(value['revision'], 40)
        p.number(value['reserved_at'], 1, 2 ** 53)
        return value

    def occupied(self, fd):
        # The slot contains only one fixed name and never needs a directory scan.
        with os.scandir(fd) as entries:
            entry = next(entries, None)
            if entry is None:
                return False
            p.require(entry.name == ARCHIVE and next(entries, None) is None,
                      'foreign checklist transfer object preserved')
            return True

    def reclaim(self, fd, *, before_build=False, now=None):
        before = free_space(fd)
        record = self.record(fd)
        occupied = self.occupied(fd)
        if record is None:
            p.require(not occupied, 'unleased checklist transfer object preserved')
            return {'event': 'empty', 'before': before, 'after': before}
        now = int(time.time()) if now is None else now
        expired = now >= record['reserved_at'] + IDLE_SECONDS
        pressure = not enough(before, self.limit)
        if not (before_build or expired or pressure):
            return {'event': 'retained', 'before': before, 'after': before}
        if occupied and not self.remove_inactive_transfer(fd):
            return {'event': 'active-transfer-retained', 'job': record['job'], 'revision': record['revision'],
                    'before': before, 'after': free_space(fd)}
        self.lease.unlink()
        sync_directory(self.control)
        after = free_space(fd)
        event = 'lease-cleared'
        if occupied:
            event = ('reclaimed' if any(after[key] > before[key] for key in before)
                     else 'transfer-removed-capacity-unobserved')
        return {'event': event, 'job': record['job'], 'revision': record['revision'],
                'before': before, 'after': after}

    def remove_inactive_transfer(self, fd):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        node = os.stat(ARCHIVE, dir_fd=fd, follow_symlinks=False)
        p.require(stat.S_ISREG(node.st_mode) and node.st_uid == node.st_gid == 0 and node.st_nlink == 1
                  and stat.S_IMODE(node.st_mode) == 0o600 and node.st_size <= self.limit,
                  'foreign or ambiguous checklist transfer object preserved')
        with os.fdopen(os.open(ARCHIVE, flags, dir_fd=fd), 'rb') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            p.require(os.fstat(stream.fileno()) == node, 'checklist transfer changed while establishing cleanup')
            os.unlink(ARCHIVE, dir_fd=fd)
            os.fsync(fd)
        return True

    @contextmanager
    def transfer(self, fd, job, revision):
        recovered = self.reclaim(fd, before_build=True)
        if recovered['event'] == 'active-transfer-retained':
            raise BlockingIOError('checklist transfer engine still holds the owned archive')
        if not enough(recovered['after'], self.limit):
            print(p.canonical({'event': 'checklist-build-pressure', 'job': job, 'revision': revision,
                               'reconciliation': recovered, 'required': reserve(self.limit)}),
                  file=sys.stderr, flush=True)
            raise StoragePressure()
        # The only stage file lives beneath the protected identity in this record.
        # Publish the record before an interruption can strand any archive bytes.
        record = {'schema': 1, 'directory': self.identity(fd), 'job': job, 'revision': revision,
                  'reserved_at': int(time.time())}
        replace_private(self.control / 'lease.new', self.lease, p.canonical(record).encode())
        archive = Path(f'/proc/self/fd/{fd}') / ARCHIVE
        observations = {'before_build': recovered}
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            with os.fdopen(os.open(ARCHIVE, flags, 0o600, dir_fd=fd), 'w+b') as stream:
                yield archive, stream, observations
        finally:
            observations['completion'] = self.reclaim(fd, before_build=True)
