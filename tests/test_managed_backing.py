"""Physical host recovery headroom and Btrfs reserved loop backing."""
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

import managed_backing as backing


class BackingTests(unittest.TestCase):
    def test_stable_identity_uses_the_held_inode_and_subvolume(self):
        fsid = UUID('aabbccdd-eeff-4411-9988-020301020304')
        subvol = UUID('12345678-abcd-4411-9988-020301020304')

        def fill(fd, command, data):
            self.assertEqual(fd, 10)
            if command == backing.BTRFS_IOC_FS_INFO:
                struct.pack_into('=QQ16sI', data, 0, 1, 1, fsid.bytes, 16384)
            elif command == backing.BTRFS_IOC_GET_SUBVOL_INFO:
                struct.pack_into('=Q', data, 0, 259)
                data[296:312] = subvol.bytes
            elif command == backing.FS_IOC_GETVERSION:
                struct.pack_into('=I', data, 0, 48)
            else:
                self.fail('unexpected backing ioctl')

        with patch.object(backing.fcntl, 'ioctl', side_effect=fill):
            self.assertEqual(backing.btrfs_identity(10, RuntimeError),
                             {'filesystem_uuid': str(fsid), 'subvolume_id': 259,
                              'subvolume_uuid': str(subvol), 'inode_generation': 48})
        with (patch.object(backing.fcntl, 'ioctl', side_effect=OSError),
              self.assertRaisesRegex(RuntimeError, 'stable Btrfs')):
            backing.btrfs_identity(10, RuntimeError)

    def test_space_uses_native_type_and_does_not_invent_inodes(self):
        fs = SimpleNamespace(f_frsize=4096, f_bavail=8192, f_bfree=8193, f_blocks=8194,
                             f_flag=0, f_files=0, f_ffree=0, f_favail=0)
        with (TemporaryDirectory() as parent, patch.object(backing, 'filesystem_type') as kind,
              patch.object(backing.os, 'fstatvfs', return_value=fs), patch.object(backing, 'btrfs_metadata') as measure):
            for name in ('overlay', 'ext4', 'xfs'):
                kind.return_value = name
                with self.assertRaisesRegex(RuntimeError, 'geometry is unavailable'):
                    backing.observe(parent, RuntimeError)
            measure.assert_not_called()
            fs.f_files, fs.f_ffree, fs.f_favail = 16384, 8192, 4096
            self.assertEqual(backing.observe(parent, RuntimeError).available_inodes, 4096)
            fs.f_files, fs.f_ffree, fs.f_favail = 0, 0, 0
            kind.return_value = 'btrfs'
            measure.return_value = 128 * backing.MIB, 16384
            space = backing.observe(parent, RuntimeError)
            self.assertIsNone(space.available_inodes)
            space.check(space.available_bytes, 4096, RuntimeError, 'reserve missing')
            with self.assertRaisesRegex(RuntimeError, 'reserve missing'):
                space.check(space.available_bytes + 1, 4096, RuntimeError, 'reserve missing')
            with self.assertRaisesRegex(RuntimeError, 'Btrfs metadata'):
                space.check(space.available_bytes, 4097, RuntimeError, 'reserve missing')

    def test_metadata_headroom_excludes_all_live_kernel_reservations(self):
        fsid = UUID('aabbccdd-eeff-4411-9988-020301020304')
        counters = {'flags': 4, 'total_bytes': 1000, 'bytes_used': 100, 'bytes_pinned': 101,
                    'bytes_reserved': 102, 'bytes_may_use': 103, 'bytes_readonly': 104, 'bytes_zone_unusable': 105}
        with TemporaryDirectory() as parent:
            path = Path(parent) / str(fsid) / 'allocation/metadata'
            path.mkdir(parents=True)
            for name, value in counters.items():
                (path / name).write_text(f'{value}\n')

            def fill(fd, command, args):
                self.assertEqual((fd, command, len(args)), (5, backing.BTRFS_IOC_FS_INFO, 1024))
                struct.pack_into('=QQ16sI', args, 0, 1, 1, fsid.bytes, 16384)

            with patch.object(backing, 'BTRFS_SYSFS', Path(parent)), patch.object(backing.fcntl, 'ioctl', side_effect=fill):
                self.assertEqual(backing.btrfs_metadata(5), (385, 16384))
                (path / 'flags').write_text('5\n')
                with self.assertRaisesRegex(ValueError, 'dedicated metadata'):
                    backing.btrfs_metadata(5)

    def test_provisioning_rechecks_once_after_settling_transient_reservations(self):
        pending = backing.ParentSpace('btrfs', 28 * 1024 * backing.MIB, None, 0, 16384)
        settled = backing.ParentSpace('btrfs', 28 * 1024 * backing.MIB, None, 160 * backing.MIB, 16384)
        with (patch.object(backing, 'observe', side_effect=(pending, settled)) as observe,
              patch.object(backing.subprocess, 'run') as sync):
            self.assertEqual(backing.provisioning_space('/var/lib', RuntimeError, 4096), settled)
            self.assertEqual(observe.call_count, 2)
            sync.assert_called_once()
            self.assertEqual(sync.call_args.args, (('/usr/bin/sync', '-f', '--', '/var/lib'),))
        with (patch.object(backing, 'observe', return_value=pending),
              patch.object(backing.subprocess, 'run') as sync):
            space = backing.provisioning_space('/var/lib', RuntimeError, 4096)
            with self.assertRaisesRegex(RuntimeError, 'Btrfs metadata'):
                space.check(8 * 1024 * backing.MIB, 4096, RuntimeError, 'reserve missing')
            sync.assert_called_once()

    def test_nocow_is_enrolled_only_before_allocating_extents(self):
        flags = backing.FS_COMPR_FL

        def fill(fd, command, data):
            nonlocal flags
            if command == backing.FS_IOC_GETFLAGS:
                struct.pack_into('=I', data, 0, flags)
            elif command == backing.FS_IOC_SETFLAGS:
                flags = struct.unpack_from('=I', data)[0]
            else:
                self.fail('unexpected backing ioctl')

        with patch.object(backing.fcntl, 'ioctl', side_effect=fill) as ioctl:
            with self.assertRaisesRegex(RuntimeError, 'NOCOW'):
                backing.prepare_btrfs(5, empty=False, error=RuntimeError)
            self.assertEqual([call.args[1] for call in ioctl.call_args_list], [backing.FS_IOC_GETFLAGS])
            backing.prepare_btrfs(5, empty=True, error=RuntimeError)
            self.assertEqual(flags, backing.FS_NOCOW_FL)

    def test_backing_extent_ranges_must_be_contiguous_exclusive_and_uncompressed(self):
        end_flags = backing.FIEMAP_LAST | backing.FIEMAP_UNWRITTEN
        cases = ((4096, 4096, end_flags), (8192, 4096, end_flags), (4096, 0, end_flags),
                 (4096, 4096, end_flags | 0x2000), (4096, 4096, end_flags | 0x8),
                 (4096, 4096, end_flags | 0x4))
        for logical, physical, flags in cases:
            requests = []

            def fill(_fd, command, data):
                if command == backing.FS_IOC_GETFLAGS:
                    struct.pack_into('=I', data, 0, backing.FS_NOCOW_FL)
                    return
                self.assertEqual(command, backing.FIEMAP)
                start, length, _, _, count, _ = backing.FIEMAP_HEADER.unpack_from(data)
                requests.append((start, length))
                backing.FIEMAP_HEADER.pack_into(data, 0, start, length, 0, 1, count, 0)
                extent = (logical, physical, 4096, flags) if start else (0, 8192, 4096, backing.FIEMAP_UNWRITTEN)
                backing.FIEMAP_EXTENT.pack_into(data, backing.FIEMAP_HEADER.size,
                                                *extent[:3], 0, 0, extent[3], 0, 0, 0)

            with self.subTest(logical=logical, physical=physical, flags=flags), patch.object(backing.fcntl, 'ioctl', side_effect=fill):
                if (logical, physical, flags) == cases[0]:
                    backing.verify_btrfs(5, 8192, RuntimeError)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'sparse, shared, compressed or incomplete'):
                        backing.verify_btrfs(5, 8192, RuntimeError)
                self.assertEqual(requests, [(0, 8192), (4096, 4096)])


if __name__ == '__main__':
    unittest.main()
