#!/usr/bin/env python3
"""Read-only bounded storage samples and pure peak arithmetic; no quota/backend."""
import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat
import time

GIB = 1024 ** 3
MANAGED_CEILING = 20 * GIB
GUEST_RESERVE = 8 * GIB
OVERLAY_CEILING = 16 * GIB
OVERHEAD_CEILING = 4 * GIB
RUNNER_RESERVE = 3 * GIB


class StorageBlocked(ValueError):
    """Only fixed reason codes, never OS error/path representations."""


def require(value, reason):
    if not value:
        raise StorageBlocked(reason)


def number(value, name):
    require(type(value) is int and 0 <= value < 2 ** 63, 'unknown-or-invalid-' + name)
    return value


@dataclass(frozen=True)
class Bounds:
    entries: int = 100000
    depth: int = 64
    seconds: float = 10
    name_bytes: int = 8 * 1024 ** 2

    def validate(self):
        require(type(self.entries) is int and 0 < self.entries <= 1000000 and type(self.depth) is int and 0 < self.depth <= 128 and
                type(self.seconds) in (int, float) and 0 < self.seconds <= 30 and type(self.name_bytes) is int and 0 < self.name_bytes <= 32 * 1024 ** 2,
                'invalid-inventory-bounds')


@dataclass(frozen=True)
class Space:
    available_bytes: int | None
    available_inodes: int | None

    def validate(self, name):
        number(self.available_bytes, name + '-available-bytes')
        number(self.available_inodes, name + '-available-inodes')


def mount_id(fd):
    with open('/proc/self/fdinfo/' + str(fd), 'rb') as source:
        data = source.read(4097)
    require(len(data) <= 4096, 'mount-identity-unavailable')
    matches = re.findall(rb'^mnt_id:\s*([0-9]{1,20})$', data, re.M)
    require(len(matches) == 1, 'mount-identity-unavailable')
    return int(matches[0])


def filesystem_type(identity):
    with open('/proc/self/mountinfo', 'rb') as source:
        data = source.read(1024 ** 2 + 1)
    require(len(data) <= 1024 ** 2, 'mount-table-bound')
    matches = []
    for line in data.splitlines():
        before, separator, after = line.partition(b' - ')
        fields, filesystem = before.split(), after.split()
        if separator and fields and fields[0] == str(identity).encode():
            require(filesystem and re.fullmatch(rb'[A-Za-z0-9_.-]{1,32}', filesystem[0]), 'filesystem-type-unavailable')
            matches.append(filesystem[0].decode('ascii'))
    require(len(matches) == 1, 'filesystem-type-unavailable')
    # This component does not attempt remote/FUSE traversal with a Python timer.
    require(matches[0] in {'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay'}, 'unsupported-observation-filesystem')
    return matches[0]


def root_fd(root):
    path = Path(root)
    require(path.is_absolute() and '..' not in path.parts, 'absolute-nonsymlink-root-required')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns)


def inventory(root, bounds=Bounds()):
    """Two matching no-follow scans. Callers still must prove writers stopped.

    Deadline checks bound work on supported local filesystems; an external native
    timeout remains necessary for pathological kernel/filesystem stalls.
    """
    bounds.validate()
    end = time.monotonic() + bounds.seconds
    fd = None
    def deadline():
        require(time.monotonic() < end, 'inventory-deadline')
    try:
        fd = root_fd(root)
        root_info = os.fstat(fd)
        boundary = mount_id(fd)
        kind = filesystem_type(boundary)
        deadline()
        def scan():
            signatures, unique, references = {}, {}, {}
            names = 0
            def visit(node, parts):
                nonlocal names
                deadline()
                require(len(signatures) < bounds.entries, 'inventory-entry-bound')
                require(len(parts) <= bounds.depth, 'inventory-depth-bound')
                names += sum(len(os.fsencode(part)) + 1 for part in parts)
                require(names <= bounds.name_bytes, 'inventory-name-bound')
                info = os.fstat(node)
                require(mount_id(node) == boundary and info.st_dev == root_info.st_dev, 'inventory-mount-crossing')
                require(info.st_blocks >= 0 and info.st_size >= 0, 'inode-allocation-unknown')
                signatures[parts] = metadata(info)
                inode = (info.st_dev, info.st_ino)
                if inode in unique:
                    require(unique[inode] == metadata(info), 'inventory-changing-inode')
                unique[inode] = metadata(info)
                references[inode] = references.get(inode, 0) + 1
                if stat.S_ISDIR(info.st_mode):
                    directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=node)
                    try:
                        require(metadata(os.fstat(directory)) == metadata(info), 'inventory-changing-directory')
                        with os.scandir(directory) as entries:
                            for entry in entries:
                                deadline()
                                child = os.open(entry.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                                try:
                                    visit(child, (*parts, entry.name))
                                finally:
                                    os.close(child)
                        require(metadata(os.fstat(directory)) == metadata(info), 'inventory-changing-directory')
                    finally:
                        os.close(directory)
            visit(fd, ())
            return signatures, unique, references
        first, unique, references = scan()
        second, _, _ = scan()
        require(first == second, 'inventory-changing-tree')
        check = root_fd(root)
        try:
            require((os.fstat(check).st_dev, os.fstat(check).st_ino, mount_id(check)) ==
                    (root_info.st_dev, root_info.st_ino, boundary), 'inventory-root-replaced')
        finally:
            os.close(check)
        filesystem = os.fstatvfs(fd)
        bytes_known = filesystem.f_frsize > 0 and filesystem.f_blocks > 0 and 0 <= filesystem.f_bavail <= filesystem.f_bfree <= filesystem.f_blocks
        inodes_known = filesystem.f_files > 0 and 0 <= filesystem.f_favail <= filesystem.f_ffree <= filesystem.f_files
        blockers = ([] if bytes_known else ['filesystem-byte-capacity-unknown']) + ([] if inodes_known else ['filesystem-inode-capacity-unknown'])
        deadline()
        counts = {'directories': 0, 'regular_files': 0, 'symlinks': 0, 'special': 0}
        apparent, allocated, external = 0, 0, 0
        for inode, item in unique.items():
            mode = item[2]
            name = 'directories' if stat.S_ISDIR(mode) else 'regular_files' if stat.S_ISREG(mode) else 'symlinks' if stat.S_ISLNK(mode) else 'special'
            counts[name] += 1
            allocated += item[7] * 512
            if stat.S_ISREG(mode):
                apparent += item[6]
                external += item[3] > references[inode]
        return {'sample': 'two-matching-bounded-scans', 'capacity_known': not blockers, 'blockers': blockers, 'quiescence_proven': False, 'enforces_capacity': False,
                'device': root_info.st_dev, 'root_inode': root_info.st_ino, 'mount_id': boundary, 'filesystem_type': kind,
                'entries': len(first), 'unique_inodes': len(unique), 'hardlink_references': len(first) - len(unique),
                'files_with_possible_external_links': external, 'allocated_bytes': allocated, 'regular_apparent_bytes': apparent,
                'inode_types': counts, 'filesystem': {'total_bytes': filesystem.f_blocks * filesystem.f_frsize if bytes_known else None,
                    'available_bytes': filesystem.f_bavail * filesystem.f_frsize if bytes_known else None, 'total_inodes': filesystem.f_files if inodes_known else None,
                    'available_inodes': filesystem.f_favail if inodes_known else None}, 'bounds': asdict(bounds),
                'allocation_semantics': 'st_blocks*512 per unique device/inode; shared extents/compression/open-unlinked data not inferred'}
    except OSError:
        raise StorageBlocked('inventory-inaccessible-or-changed') from None
    finally:
        if fd is not None:
            os.close(fd)


def admit(*, guest: Space, runner: Space, existing_managed_bytes, new_managed_bytes, outstanding_managed_bytes,
          existing_unreserved_growth_bytes, platform_growth_bytes, guest_metadata_margin_bytes, guest_growth_inodes,
          runner_growth_inodes, overlay_current_bytes, overlay_growth_upper_bound_bytes, overhead_current_bytes,
          overhead_growth_upper_bound_bytes):
    """Pure arithmetic only; supplied maxima need independent controller evidence.

    overlay_current_bytes is the greater observed file length/allocated bytes;
    its growth bound covers BOTH length and allocation growth, including qcow
    metadata/stale COW clusters. These conservative maxima are caller evidence.
    Existing materialized reservations are already charged to guest free space.
    Outstanding commitments are unmaterialized; growth maxima include overlapping
    phase peaks/rollback/copy/COW metadata, never image-inspect logical Size.
    """
    require(type(guest) is Space and type(runner) is Space, 'unknown-or-invalid-filesystem-space')
    guest.validate('guest')
    runner.validate('runner')
    values = locals().copy()
    for name, value in values.items():
        if name not in ('guest', 'runner'):
            number(value, name.replace('_', '-'))
    managed = existing_managed_bytes + new_managed_bytes + outstanding_managed_bytes
    guest_charge = new_managed_bytes + outstanding_managed_bytes + existing_unreserved_growth_bytes + platform_growth_bytes + guest_metadata_margin_bytes
    overlay_peak = overlay_current_bytes + overlay_growth_upper_bound_bytes
    overhead_peak = overhead_current_bytes + overhead_growth_upper_bound_bytes
    runner_charge = overlay_growth_upper_bound_bytes + overhead_growth_upper_bound_bytes
    blockers = []
    for condition, code in (
        (managed <= MANAGED_CEILING, 'managed-aggregate-20gib'),
        (guest.available_bytes - guest_charge >= GUEST_RESERVE, 'guest-8gib-reserve'),
        (guest_growth_inodes <= guest.available_inodes, 'guest-inode-capacity'),
        (overlay_growth_upper_bound_bytes >= guest_charge, 'qcow-growth-bound-below-guest-growth'),
        (overlay_peak <= OVERLAY_CEILING, 'ci-overlay-16gib'),
        (overhead_peak <= OVERHEAD_CEILING, 'ci-overhead-4gib'),
        (runner.available_bytes - runner_charge >= RUNNER_RESERVE, 'runner-3gib-reserve'),
        (runner_growth_inodes <= runner.available_inodes, 'runner-inode-capacity')):
        if not condition:
            blockers.append(code)
    return {'fits_capacity_plan': not blockers, 'runtime_admitted': False, 'enforces_capacity': False, 'blockers': blockers,
            'managed_reserved_after_bytes': managed, 'guest_peak_additional_bytes': guest_charge,
            'guest_remaining_bytes': guest.available_bytes - guest_charge, 'guest_remaining_inodes': guest.available_inodes - guest_growth_inodes,
            'overlay_peak_bytes': overlay_peak, 'overhead_peak_bytes': overhead_peak, 'runner_peak_additional_bytes': runner_charge,
            'runner_remaining_bytes': runner.available_bytes - runner_charge, 'runner_remaining_inodes': runner.available_inodes - runner_growth_inodes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--max-entries', type=int, default=100000)
    parser.add_argument('--max-depth', type=int, default=64)
    parser.add_argument('--seconds', type=float, default=10)
    args = parser.parse_args()
    try:
        result = inventory(args.root, Bounds(entries=args.max_entries, depth=args.max_depth, seconds=args.seconds))
        print(json.dumps(result, sort_keys=True))
        return 0 if result['capacity_known'] else 2
    except StorageBlocked as error:
        print(json.dumps({'sample': 'blocked', 'reason': str(error), 'enforces_capacity': False}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
