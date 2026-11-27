"""Local storage ownership, release custody and managed-entry checks for the native bridge."""

import hashlib
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_devbox import manifest, oci_archive

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_placements as n
from gptbox import DevelopmentGptbox, RELEASE_INNER, image_inputs_bytes

db = n.db


class TestProtectedPublication(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(TemporaryDirectory())
        self.root = Path(scratch)
        self.producer = DevelopmentGptbox(self.root)
        self.inner = manifest()['inner']
        self.context = self.inner['context_sha256']
        self.revision = self.inner['source_sha']
        self.attempt = {'source_sha': self.revision, 'context_sha256': self.context,
                        'distrobox_sha': db.DISTROBOX, 'count': 1}
        self.target = self.root / n.DEVELOPMENT_ROOT.lstrip('/') / self.context
        self.target.mkdir(parents=True)
        self.artifacts = self.root / n.DEVELOPMENT_ARTIFACTS.lstrip('/')
        self.release = self.artifacts / self.context / 'release'
        self.release.mkdir(parents=True, mode=0o700)
        self.archive = self.release / n.RELEASE_ARCHIVE
        self.inner.update(oci_archive(self.archive))
        self.archive.chmod(0o444)
        self.write(self.release / RELEASE_INNER, self.inner, 0o444)
        self.write(self.target / 'attempt.json', self.attempt, 0o600)
        self.receipt = {'schema': 1, 'attempt': self.attempt, 'phase': 'ready',
                        'directory': n.identity(self.release.stat()), 'inner': self.inner,
                        'inner_sha256': hashlib.sha256(image_inputs_bytes(self.inner)).hexdigest()}
        self.write(self.target / 'publication.json', self.receipt, 0o600)
        self.enterContext(patch.object(n, 'DEVELOPMENT_ARTIFACTS', str(self.artifacts)))

    def write(self, destination, value, mode):
        if destination.exists():
            destination.chmod(0o600)
        destination.write_bytes(image_inputs_bytes(value))
        destination.chmod(mode)

    def read(self, revision=None):
        return n.protected_publication(self.producer, revision or self.revision, self.context)

    def test_uses_exact_producer_receipt_and_archive(self):
        inner, archive = self.read()
        self.assertEqual((inner, archive), (self.inner, self.archive))
        db.check_archive_image(archive, inner, db.GIB, n.time.monotonic() + 1)
        self.archive.chmod(0o600)
        original = self.archive.read_bytes()
        self.archive.write_bytes(b'X' + original[1:])
        self.archive.chmod(0o444)
        with self.assertRaisesRegex(n.BootstrapBlocked, 'no longer matches'):
            self.read()

    def test_pending_or_wrong_source_blocks_the_published_directory(self):
        with self.assertRaisesRegex(n.BootstrapBlocked, 'attempt record'):
            self.read('a' * 40)
        self.write(self.target / 'publication.json', {**self.receipt, 'phase': 'verified'}, 0o600)
        with self.assertRaisesRegex(db.Blocked, 'protected ready'):
            self.read()
        self.write(self.target / 'publication.json', self.receipt, 0o600)
        self.release.with_name('release.pending').mkdir()
        with self.assertRaisesRegex(db.Blocked, 'protected ready'):
            self.read()


class TestKernelOwnership(unittest.TestCase):
    def test_anchors_directories_and_rejects_a_symlink_parent(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            real = root / 'real'
            real.mkdir()
            alias = root / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            with n.directory_fd(real) as fd:
                self.assertEqual(os.fstat(fd).st_ino, real.stat().st_ino)
                renamed = root / 'renamed'
                real.rename(renamed)
                real.mkdir()
                self.assertEqual(os.fstat(fd).st_ino, renamed.stat().st_ino)
                self.assertNotEqual(os.fstat(fd).st_ino, real.stat().st_ino)
            with self.assertRaises(OSError), n.directory_fd(alias):
                self.fail('followed untrusted parent')

    def test_loop_lookup_rejects_aliases_offsets_and_multiple_results(self):
        image = Path('/protected/backing.ext4')
        row = {'name': '/dev/loop5', 'back-file': str(image), 'offset': 0, 'sizelimit': 0,
               'ro': False, 'autoclear': False}
        for rows, answer in (([], None), ([row], Path('/dev/loop5'))):
            with patch.object(n, 'command', return_value=(0, n.json_bytes({'loopdevices': rows}))):
                self.assertEqual(n.associated(image), answer)
        for rows in ([row, row], [{**row, 'offset': 4096}], [{**row, 'back-file': str(image) + ' (deleted)'}]):
            with self.subTest(rows=rows), patch.object(n, 'command',
                    return_value=(0, n.json_bytes({'loopdevices': rows}))), self.assertRaises(db.Blocked):
                n.associated(image)

    def test_mount_reports_finite_space_and_inodes_and_rejects_alias(self):
        target = Path(self.enterContext(TemporaryDirectory()))
        device = Path('/dev/loop5')
        number = f'{os.major(target.stat().st_dev)}:{os.minor(target.stat().st_dev)}'
        row = f'34 21 {number} / {target} rw,nosuid,nodev,noatime - ext4 /dev/loop5 rw'.split()
        fs = SimpleNamespace(f_blocks=10000, f_bavail=8000, f_frsize=4096, f_files=400, f_favail=391)
        with patch.object(n, 'block_id', return_value=number), patch.object(n.os, 'statvfs', return_value=fs):
            with patch.object(n, 'mount_rows', return_value=[row]):
                proof = n.validate_mount(device, target, 50000000)
                self.assertEqual(proof['bytes'], 40960000)
                self.assertEqual(proof['inodes'], 400)
                self.assertEqual(proof['available_inodes'], 391)
                fs.f_files = n.INODE_CEILING + 1
                with self.assertRaisesRegex(db.Blocked, 'storage/inode'):
                    n.validate_mount(device, target, 50000000)
            alias = f'35 21 {number} / {target}-alias rw,nosuid,nodev - ext4 /dev/loop5 rw'.split()
            with patch.object(n, 'mount_rows', return_value=[row, alias]), self.assertRaisesRegex(db.Blocked, 'unique'):
                n.validate_mount(device, target, 50000000)
            child = f'36 34 0:2 / {target}/graph rw,nosuid,nodev - tmpfs tmpfs rw'.split()
            with patch.object(n, 'mount_rows', return_value=[row, child]), self.assertRaisesRegex(db.Blocked, 'descendant'):
                n.validate_mount(device, target, 50000000)

    def test_reserve_is_charged_before_allocating_a_new_volume(self):
        with TemporaryDirectory() as scratch:
            placement = SimpleNamespace(record=Path(scratch) / 'lease.json', state={'volumes': {}}, save=Mock())
            volume = n.Volume(placement, 'build', Path('/native/build'), 16 * db.GIB)
            with patch.object(n, 'free_space', return_value=23 * db.GIB), self.assertRaisesRegex(db.Blocked, 'reserve'):
                volume.backing_file()
            self.assertFalse(volume.backing.exists())
            placement.save.assert_not_called()

    def test_reserved_categories_are_disjoint_from_live_and_durable_roles(self):
        used = {1023, 1020, 1018}
        assigned = n.allocate_categories(used)
        self.assertEqual(assigned, {'outer': [1019, 1021, 1022], 'inner': [1019, 1021]})
        self.assertTrue(used.isdisjoint(assigned['outer']))
        with self.assertRaisesRegex(db.Blocked, 'three exclusive'):
            n.allocate_categories(set(range(1022)))


class TestManagedEntry(unittest.TestCase):
    def placement(self):
        candidate = n.Placement.__new__(n.Placement)
        candidate.boot = 'fixture-boot'
        candidate.state = n.new_record({'source_sha': manifest()['outer']['source_sha']}, set())
        candidate.account = SimpleNamespace(pw_uid=1234, pw_dir='/home/dp-dev')
        candidate.entry = Path('/protected/entry')
        candidate.copy_path = Path('/bounded/host-copy')
        candidate.save = Mock()
        return candidate

    def test_fixed_dp_dev_service_preserves_the_consumer_failure(self):
        candidate = self.placement()
        failure = db.Blocked('timeout: command exit 2 — DevBox blocked: exact entry failure')
        missing = (4, b'LoadState=not-found\nActiveState=inactive\n')
        with patch.object(n, 'command', side_effect=[missing, failure, missing]) as control, \
                patch.object(n, 'verify_inactive_cgroup') as proof:
            with self.assertRaisesRegex(db.Blocked, 'exact entry failure'):
                candidate.managed('/usr/bin/python3', '-I', '/protected/entry/tools/devbox.py', 'run', seconds=610)
        launch = control.call_args_list[1].args
        for option in ('--uid=dp-dev', '--property=RuntimeMaxSec=610s', '--property=MemoryMax=2G',
                       '--property=MemorySwapMax=0', '--property=TasksMax=512', '--property=CPUQuota=100%',
                       'CONTAINERS_CONF=/protected/entry/runtime/devbox/host-containers.conf'):
            self.assertIn(option, launch)
        self.assertIn(('-i', 'PATH=/usr/bin:/usr/sbin:/bin'), tuple(zip(launch, launch[1:])))
        self.assertNotIn('TMPDIR=/bounded/host-copy', launch)
        proof.assert_called_once()
        self.assertIsNone(candidate.state['activity'])

    def test_disappeared_uncertain_launch_retains_recovery_record(self):
        candidate = self.placement()
        unit = 'dev-pair-gptbox-' + 'a' * 64 + '.service'
        record = {'unit': unit, 'boot': candidate.boot, 'deadline': n.time.monotonic() + 60}
        candidate.state['activity'] = record
        missing = (4, b'LoadState=not-found\nActiveState=inactive\n')
        with patch.object(n, 'command', return_value=missing), patch.object(n, 'verify_inactive_cgroup') as proof:
            with self.assertRaisesRegex(db.Blocked, 'ambiguous'):
                candidate.reconcile(interrupted=True)
            self.assertEqual(candidate.state['activity'], record)
            proof.assert_not_called()
            candidate.boot = 'new-boot'
            candidate.reconcile(interrupted=True)
            proof.assert_called_once_with(unit)
            self.assertIsNone(candidate.state['activity'])

    def test_foreign_unit_is_never_stopped(self):
        candidate = self.placement()
        unit = 'dev-pair-gptbox-' + 'a' * 64 + '.service'
        record = {'unit': unit, 'boot': candidate.boot, 'deadline': n.time.monotonic() + 60}
        candidate.state['activity'] = record
        foreign = (0, b'LoadState=loaded\nActiveState=active\nDescription=unowned\nUser=dp-dev\n')
        with patch.object(n, 'command', return_value=foreign) as control:
            with self.assertRaisesRegex(db.Blocked, 'foreign systemd unit preserved'):
                candidate.reconcile(interrupted=True)
            control.assert_called_once()
        self.assertEqual(candidate.state['activity'], record)

    def test_image_record_keeps_config_id_and_manifest_digest_distinct(self):
        row = {'Architecture': 'amd64', 'Os': 'linux', 'Id': 'sha256:' + 'a' * 64,
               'Digest': 'sha256:' + 'b' * 64, 'RootFS': {'Layers': ['sha256:' + 'c' * 64]}}
        record = n.image_shape(row)
        self.assertEqual(record, {'config_id': 'a' * 64, 'oci_manifest_digest': 'sha256:' + 'b' * 64,
                                  'diff_ids': ['sha256:' + 'c' * 64]})
        row['Digest'] = 'latest'
        with self.assertRaisesRegex(db.Blocked, 'manifest digest'):
            n.image_shape(row)

    def completion_fixture(self, candidate):
        candidate.job = 'test-entry'
        candidate.reconcile = Mock()
        candidate.check_categories = Mock()
        candidate.establish_storage = Mock(return_value={'build': {'inodes': 8}})
        candidate.verify_archive = Mock()
        candidate.stage_entry = Mock()
        candidate.prepare_images = Mock(return_value={'graphroot': '/bounded/outer'})
        digest = 'd' * 64
        candidate.write_manifest = Mock(return_value=(Path('/bounded/manifest.json'), digest))
        candidate.record = Path('/protected/job/placement.json')
        candidate.inner = manifest()['inner']
        candidate.state['images'] = {'outer': {'config_id': 'e' * 64}}
        receipt = {'manifest_sha256': digest, 'job_admission': False, 'inner_removed': True, 'outer_removed': True,
                   'outer_image_id': 'e' * 64, 'archive_sha256': candidate.inner['archive_sha256']}
        candidate.managed = Mock(return_value=(0, n.json_bytes(receipt)))
        return receipt

    def test_same_boot_reapply_reuses_exact_result_and_new_boot_reproves(self):
        candidate = self.placement()
        self.completion_fixture(candidate)
        with patch.object(n, 'reserve'):
            first = candidate.run(retry=False)
            self.assertFalse(first['reused'])
            self.assertFalse(first['job_admission'])
            replay = candidate.run(retry=False)
            self.assertTrue(replay['reused'])
            candidate.managed.assert_called_once()
            candidate.boot = 'different-boot'
            reboot = candidate.run(retry=False)
            self.assertFalse(reboot['reused'])
            self.assertEqual(reboot['boot_id'], 'different-boot')
            self.assertEqual(candidate.managed.call_count, 2)

    def test_failed_devbox_proof_stays_unpublished_and_retry_is_bounded(self):
        candidate = self.placement()
        receipt = self.completion_fixture(candidate)
        candidate.managed.return_value = (0, n.json_bytes({**receipt, 'job_admission': True}))
        with self.assertRaisesRegex(db.Blocked, 'does not prove'):
            candidate.run(retry=False)
        self.assertIsNone(candidate.state['report'])
        with self.assertRaisesRegex(db.Blocked, 'explicit --retry'):
            candidate.run(retry=False)
        with self.assertRaisesRegex(db.Blocked, 'does not prove'):
            candidate.run(retry=True)
        with self.assertRaisesRegex(db.Blocked, 'two-attempt'):
            candidate.run(retry=True)
        self.assertEqual(candidate.managed.call_count, 2)


if __name__ == '__main__':
    unittest.main()
