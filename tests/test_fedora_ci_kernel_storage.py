import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from textwrap import dedent
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fedora_ci as ci
import fedora_ci_storage as storage


class FedoraKernelStorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.lease = Path(temporary.name)
        self.privileged = mock.Mock()
        self.storage = storage.KernelStorage(self.lease, self.privileged)

    def mount_in_namespace(self, script, *, pid=False):
        unshare = shutil.which('unshare')
        if not unshare:
            self.skipTest('private namespace tool unavailable')
        args = [unshare, '--user', '--map-root-user', '--mount', '--propagation', 'private']
        if pid:
            args += ['--pid', '--mount-proc', '--kill-child=SIGKILL']
        result = subprocess.run([*args, sys.executable, '-B', '-c', dedent(script), str(self.lease),
                                 str(ROOT / 'tools'), str(ROOT / 'tools/fedora_ci.py'), '--namespace-parent'],
                                capture_output=True, timeout=15)
        if result.returncode == 77 or (result.returncode and result.stderr.startswith(b'unshare:') and
                                       b'Operation not permitted' in result.stderr):
            self.skipTest('private user or mount namespace unavailable')
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_actual_fiemap_distinguishes_allocated_and_sparse_files(self):
        path = self.lease / 'backing'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.ftruncate(fd, storage.MIB)
            with self.assertRaisesRegex(storage.StorageBlocked, 'extent'):
                storage.verify_extents(fd, storage.MIB)
            os.posix_fallocate(fd, 0, storage.MIB)
            os.fsync(fd)
            storage.verify_extents(fd, storage.MIB)
            self.assertGreaterEqual(os.fstat(fd).st_blocks * 512, storage.MIB)
        finally:
            os.close(fd)

    def test_physical_parent_reserve_is_required_before_either_allocation(self):
        fd = storage.open_directory(self.lease)
        try:
            mount = storage.fd_mount_id(fd)
            device = storage.device_name(os.fstat(fd).st_dev)
        finally:
            os.close(fd)
        row = (mount, device, Path('/'), Path('/'), ['rw'], [], 'ext4', ['rw'])
        initial = storage.HOST_RESERVE + storage.OVERHEAD_LIMIT + storage.OVERLAY_LIMIT + storage.PARENT_HEADROOM
        stat = SimpleNamespace(f_frsize=storage.BLOCK_BYTES, f_bavail=initial // storage.BLOCK_BYTES - 1, f_favail=100)
        with mock.patch.object(storage, 'mount_table', return_value=[row]), \
             mock.patch.object(storage, 'verify_native_device') as native, \
             mock.patch.object(storage.os, 'fstatvfs', return_value=stat), \
             mock.patch.object(self.storage.overhead, 'configure') as overhead, \
             mock.patch.object(self.storage.overlay, 'configure') as overlay:
            with self.assertRaisesRegex(storage.StorageBlocked, 'recovery reserve'):
                self.storage.configure()
            native.assert_called_once_with(device)
            overhead.assert_not_called()
            overlay.assert_not_called()
        self.assertFalse(self.storage.started)
        self.privileged.assert_not_called()

    def test_loop_detach_requires_exact_backing_and_no_overmount_or_live_mount(self):
        volume = self.storage.overhead
        volume.path.mkdir()
        volume.directory_identity = storage.identity(volume.path.lstat())
        volume.backing.touch(mode=0o600)
        volume.backing_identity = storage.identity(volume.backing.lstat())
        loop = ('/dev/loop253', '7:253')
        mounted = ('423', loop[1], Path('/'), volume.path, ['rw', 'nodev', 'nosuid'], [], 'ext4', ['rw'])
        volume.mount_id = mounted[0]
        foreign = (*mounted[:3], volume.path / 'foreign', *mounted[4:])
        with mock.patch.object(storage, 'mount_table', return_value=[mounted, foreign]):
            with self.assertRaisesRegex(storage.StorageBlocked, 'active mount'):
                volume.release()
        self.privileged.assert_not_called()
        with mock.patch.object(storage, 'mount_table', return_value=[mounted]), \
             mock.patch.object(volume, 'associated_loop', return_value=('/dev/loop254', '7:254')):
            with self.assertRaisesRegex(storage.StorageBlocked, 'mount identity changed'):
                volume.release()
        self.privileged.assert_not_called()
        with mock.patch.object(storage, 'mount_table', side_effect=[[mounted], []]), \
             mock.patch.object(volume, 'associated_loop', side_effect=[loop, loop, loop]):
            with self.assertRaisesRegex(storage.StorageBlocked, 'detach is unresolved'):
                volume.release()
        self.assertEqual(self.privileged.call_args_list, [
            mock.call('/usr/bin/umount', '-i', '-n', '--', str(volume.path)),
            mock.call('/usr/sbin/losetup', '--detach', '--', loop[0]),
        ])
        self.assertTrue(volume.backing.exists())
        self.assertTrue(volume.path.exists())

    def test_volume_provisions_fixed_full_backing_and_disables_discard(self):
        volume = storage.Volume(self.lease, 'fixture', storage.MIB, 64, self.privileged)
        loop = ('/dev/loop252', '7:252')
        mounted = ('424', loop[1], Path('/'), volume.path, ['rw', 'nodev', 'nosuid'], [], 'ext4', ['rw'])

        def privileged(command, *args, **kwargs):
            self.assertGreaterEqual(volume.backing.stat().st_blocks * 512, volume.size)
            return loop[0].encode() if command == '/usr/sbin/losetup' else b''

        self.privileged.side_effect = privileged
        with (
            mock.patch.object(volume, 'associated_loop', side_effect=[None, loop]),
            mock.patch.object(storage, 'mount_table', return_value=[mounted]),
            mock.patch.object(volume, 'observe') as observe,
        ):
            volume.configure()
        self.assertEqual(volume.mount_id, mounted[0])
        self.assertEqual(volume.backing.stat().st_size, volume.size)
        attach, mkfs, mount, *_ = self.privileged.call_args_list
        self.assertEqual(attach.args[-4:], ('--sizelimit', str(volume.size), '--', str(volume.backing)))
        self.assertIn('nodiscard,lazy_itable_init=0,lazy_journal_init=0', mkfs.args)
        self.assertIn('rw,nodev,nosuid,nodiscard', mount.args)
        observe.assert_called_once_with([mounted])

    def test_real_kernel_split_caps_charge_unlinked_bytes_and_inodes(self):
        self.mount_in_namespace('''
            import ctypes
            import errno
            import os
            from pathlib import Path
            import sys

            lease = Path(sys.argv[1])
            overhead, overlay = lease / 'overhead', lease / 'overlay'
            overhead.mkdir()
            overlay.mkdir()
            libc = ctypes.CDLL(None, use_errno=True)
            for path in (overhead, overlay):
                result = libc.mount(b'tmpfs', os.fsencode(path), b'tmpfs', 6, b'size=64k,nr_inodes=8')
                if result:
                    err = ctypes.get_errno()
                    if err in (errno.EACCES, errno.EPERM, errno.ENOSYS):
                        sys.exit(77)
                    raise OSError(err, os.strerror(err))
            available = lambda path: os.statvfs(path).f_bavail
            baseline = available(overlay)
            with open(overhead / 'unlinked-spool', 'wb', buffering=0) as spool:
                (overhead / 'unlinked-spool').unlink()
                spool.write(b'a' * 65536)
                assert available(overhead) == 0
                assert available(overlay) == baseline
                try:
                    spool.write(b'a')
                except OSError as error:
                    assert error.errno == errno.ENOSPC
                else:
                    raise AssertionError('unlinked file escaped the bound')
            assert available(overhead) > 0
            for inode in range(os.statvfs(overlay).f_favail):
                (overlay / str(inode)).touch(exist_ok=False)
            assert os.statvfs(overlay).f_favail == 0
            assert available(overhead) > 0 and available(overlay) == baseline
            try:
                (overlay / 'extra').touch(exist_ok=False)
            except OSError as error:
                assert error.errno == errno.ENOSPC
            else:
                raise AssertionError('inode limit was unenforced')
        ''')

    def test_namespace_cleanup_stops_an_owned_detached_process_before_unmount(self):
        self.mount_in_namespace('''
            import os
            from pathlib import Path
            import signal
            import subprocess
            import sys

            assert os.getpid() == 1
            tool = Path(sys.argv[2]) / 'fedora_ci_storage.py'
            sleeper = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(60)'],
                                       start_new_session=True)
            namespace = os.readlink('/proc/self/ns/pid')
            subprocess.run([sys.executable, '-B', str(tool), 'stop-children', namespace], check=True, timeout=4)
            assert sleeper.wait(timeout=2) == -signal.SIGKILL
            assert not (Path('/proc') / str(sleeper.pid)).exists()
        ''', pid=True)

    def test_native_command_samples_kernel_without_calling_recursive_scanner(self):
        probe = ci.Probe('a' * 40, self.lease)
        sample = {'parent_free_bytes': storage.HOST_RESERVE,
                  'overhead': {'available_bytes': ci.fedora_oci.UNLINKED_RESERVE - 1}, 'overlay': {}}
        with mock.patch.object(ci, 'measure_storage', side_effect=AssertionError('recursive scan reached')), \
                mock.patch.object(probe.storage, 'observe', return_value=sample) as observe:
            self.assertEqual(probe.bounded([sys.executable, '-c', 'print("kernel fixture")'], 5, 'fixture'),
                             b'kernel fixture\n')
            self.assertGreaterEqual(observe.call_count, 1)
            self.assertEqual(probe.report['kernel_storage_last_sample'], sample)
            probe.image_copy_active = True
            with self.assertRaisesRegex(ci.Blocked, 'unlinked spool reserve'):
                probe.storage_measurement()
            self.assertIs(probe.storage_measurement(live=True), sample)
            self.assertTrue(probe.image_copy_active)

    def test_vm_only_mounts_overlay_for_creation_and_boot(self):
        probe = ci.Probe('a' * 40, self.lease)
        overlay = '--volume=' + str(probe.overlay) + ':/overlay:rw'
        overhead = '--volume=' + str(probe.root / 'disks') + ':/disks:rw'
        self.assertNotIn(overlay, probe.run_args('/usr/bin/genisoimage'))
        self.assertIn(overlay, probe.run_args('/usr/bin/qemu-img', overlay=True))
        self.assertIn(overlay, probe.run_args('/usr/bin/python3', vm=True))
        self.assertIn(overhead, probe.run_args('/usr/bin/python3', vm=True))
        self.assertNotEqual(probe.overlay, probe.root / 'disks')

    def test_outer_runner_enters_private_namespaces_with_only_declared_environment(self):
        with (
            mock.patch.object(Path, 'is_file', return_value=True),
            mock.patch.dict(os.environ, {'GITHUB_RUN_ID': '123', 'GITHUB_TOKEN': 'sentinel'}, clear=True),
            mock.patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)) as invoke,
        ):
            self.assertEqual(ci.run_in_private_mount_namespace('a' * 40, 'maintenance'), 2)
        args = invoke.call_args.args[0]
        for value in ('--mount', '--pid', '--mount-proc', '--kill-child=SIGKILL', '--pdeathsig=keep', 'GITHUB_RUN_ID=123'):
            self.assertIn(value, args)
        self.assertNotIn('GITHUB_TOKEN', ' '.join(args))
        self.assertNotIn('GITHUB_TOKEN', invoke.call_args.kwargs['env'])
        self.assertEqual(invoke.call_args.kwargs['timeout'], ci.CONTROLLER_SECONDS + 5)

    def test_cleanup_preserves_storage_when_owned_process_exit_is_unproved(self):
        probe = ci.Probe('a' * 40, self.lease)
        probe.storage.started = True
        with mock.patch.object(probe, 'reconcile_processes', side_effect=ci.Blocked('owned process still runs')), \
                mock.patch.object(probe.storage, 'release') as release, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ci.Blocked, 'still runs'):
                probe.cleanup()
        release.assert_not_called()
        self.assertTrue(self.lease.is_dir())
