"""Real no-mount filesystem samples and pure capacity counterexamples."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import storage as s


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.root = self.parent / 'private-name-sentinel'
        self.root.mkdir()

    def plan(self, **changes):
        values = dict(guest=s.Space(24 * s.GIB, 10000), runner=s.Space(32 * s.GIB, 10000), existing_managed_bytes=10 * s.GIB,
                      new_managed_bytes=4 * s.GIB, outstanding_managed_bytes=s.GIB, existing_unreserved_growth_bytes=0,
                      platform_growth_bytes=s.GIB, guest_metadata_margin_bytes=s.GIB, guest_growth_inodes=1000, runner_growth_inodes=1000,
                      overlay_current_bytes=2 * s.GIB, overlay_growth_upper_bound_bytes=8 * s.GIB,
                      overhead_current_bytes=s.GIB, overhead_growth_upper_bound_bytes=s.GIB)
        values.update(changes)
        return values

    def test_real_hardlinks_unique_inodes_and_no_private_path_output(self):
        first = self.root / 'content-private-sentinel'
        first.write_bytes(b'private-content-sentinel' * 300)
        os.link(first, self.root / 'second-private-sentinel')
        os.link(first, self.parent / 'outside-link')
        result = s.inventory(self.root)
        expected = (self.root.stat().st_blocks + first.stat().st_blocks) * 512
        self.assertEqual(result['allocated_bytes'], expected)
        self.assertEqual(result['unique_inodes'], 2)
        self.assertEqual(result['hardlink_references'], 1)
        self.assertEqual(result['files_with_possible_external_links'], 1)
        self.assertEqual(result['regular_apparent_bytes'], first.stat().st_size)
        self.assertNotIn('private', json.dumps(result))
        self.assertFalse(result['quiescence_proven'])
        self.assertFalse(result['enforces_capacity'])

    def test_real_sparse_apparent_space_distinct_and_symlink_fifo_not_opened_for_content(self):
        sparse = self.root / 'sparse'
        with sparse.open('wb') as output:
            output.seek(8 * 1024 ** 2 - 1)
            output.write(b'x')
        outside = self.parent / 'external-secret-sentinel'
        outside.mkdir()
        (outside / 'must-not-follow').write_bytes(b'x' * 4096)
        (self.root / 'alias').symlink_to(outside, target_is_directory=True)
        os.mkfifo(self.root / 'fifo')
        started = time.monotonic()
        result = s.inventory(self.root)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(result['inode_types'], {'directories': 1, 'regular_files': 1, 'symlinks': 1, 'special': 1})
        self.assertEqual(result['regular_apparent_bytes'], 8 * 1024 ** 2)
        self.assertLess(result['allocated_bytes'], result['regular_apparent_bytes'])
        self.assertNotIn('external-secret', json.dumps(result))
        alias = self.parent / 'root-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(s.StorageBlocked):
            s.inventory(alias)

    def test_mount_identity_detects_same_device_crossing_and_missing_identity_blocks(self):
        child = self.root / 'nested'
        child.mkdir()
        self.assertEqual(child.stat().st_dev, self.root.stat().st_dev)
        actual = s.mount_id
        inode = child.stat().st_ino
        def different(fd):
            return actual(fd) + (1 if os.fstat(fd).st_ino == inode else 0)
        # A synthetic mount-ID substitution tests the same-device branch;
        # this test creates no mount or bind and claims no native mount proof.
        with patch.object(s, 'mount_id', side_effect=different):
            with self.assertRaisesRegex(s.StorageBlocked, 'mount-crossing'):
                s.inventory(self.root)
        with patch('builtins.open', return_value=__import__('io').BytesIO(b'no mount identity')):
            with self.assertRaisesRegex(s.StorageBlocked, 'mount-identity'):
                s.inventory(self.root)

    def test_real_entry_depth_name_and_elapsed_bounds_block_without_zero_sample(self):
        nested = self.root / 'nested'
        nested.mkdir()
        (nested / 'file').write_text('x')
        for bounds, code in ((s.Bounds(entries=1), 'entry-bound'), (s.Bounds(depth=1), 'depth-bound'),
                             (s.Bounds(name_bytes=1), 'name-bound')):
            with self.assertRaisesRegex(s.StorageBlocked, code):
                s.inventory(self.root, bounds)
        original = os.scandir
        @contextlib.contextmanager
        def slow(fd):
            time.sleep(.02)
            with original(fd) as entries:
                yield entries
        with patch.object(s.os, 'scandir', side_effect=slow):
            with self.assertRaisesRegex(s.StorageBlocked, 'deadline'):
                s.inventory(self.root, s.Bounds(seconds=.005))
        with self.assertRaises(s.StorageBlocked):
            s.inventory(self.root, s.Bounds(seconds=float('inf')))

    def test_actual_directory_permission_failure_and_unknown_inode_counters_block(self):
        hidden = self.root / 'hidden'
        hidden.mkdir()
        hidden.chmod(0)
        try:
            if os.geteuid() != 0:
                with self.assertRaisesRegex(s.StorageBlocked, 'inaccessible'):
                    s.inventory(self.root)
            else:
                # Drop authority in only this harmless child; no account changes.
                self.parent.chmod(0o755)
                self.root.chmod(0o755)
                code = 'import os,sys;os.setgid(65534);os.setuid(65534);sys.path.insert(0,sys.argv[1]);import storage as s\ntry:s.inventory(sys.argv[2]);raise SystemExit(9)\nexcept s.StorageBlocked:raise SystemExit(0)'
                result = subprocess.run([sys.executable, '-c', code, str(Path(s.__file__).parent), str(self.root)], timeout=2)
                self.assertEqual(result.returncode, 0)
        finally:
            hidden.chmod(0o700)
        actual = os.statvfs(self.root)
        values = list(actual)
        values[5] = 0  # f_files unavailable, not a reportable zero inode capacity.
        with patch.object(s.os, 'fstatvfs', return_value=os.statvfs_result(values)):
            result = s.inventory(self.root)
            self.assertFalse(result['capacity_known'])
            self.assertIsNone(result['filesystem']['available_inodes'])
            self.assertIsNone(result['filesystem']['total_inodes'])
            self.assertIn('filesystem-inode-capacity-unknown', result['blockers'])
            self.assertGreater(result['unique_inodes'], 0)
            with self.assertRaises(s.StorageBlocked):
                s.admit(**self.plan(guest=s.Space(result['filesystem']['available_bytes'], result['filesystem']['available_inodes'])))

    def test_live_file_change_between_real_scans_is_blocked(self):
        file = self.root / 'live'
        file.write_text('before')
        original = os.scandir
        calls = 0
        @contextlib.contextmanager
        def mutate(fd):
            nonlocal calls
            with original(fd) as entries:
                yield entries
            calls += 1
            if calls == 1:
                file.write_text('changed between samples')
        with patch.object(s.os, 'scandir', side_effect=mutate):
            with self.assertRaisesRegex(s.StorageBlocked, 'changing-tree'):
                s.inventory(self.root)

    def test_nofollow_dirfd_race_cannot_admit_replaced_root(self):
        child = self.root / 'entry'
        child.mkdir()
        (child / 'inside').write_text('x')
        original = os.open
        done = False
        def replace(path, flags, *args, **kwargs):
            nonlocal done
            fd = original(path, flags, *args, **kwargs)
            if path == 'entry' and flags & os.O_PATH and not done:
                done = True
                child.rename(self.parent / 'old-child')
                child.symlink_to(self.parent, target_is_directory=True)
            return fd
        with patch.object(s.os, 'open', side_effect=replace):
            with self.assertRaises(s.StorageBlocked):
                s.inventory(self.root)
        self.assertTrue(done)

    def test_peak_plan_reserves_and_existing_preallocation_not_double_charged(self):
        values = self.plan(existing_managed_bytes=14 * s.GIB)
        result = s.admit(**values)
        self.assertTrue(result['fits_capacity_plan'])
        self.assertEqual(result['managed_reserved_after_bytes'], 19 * s.GIB)
        self.assertEqual(result['guest_peak_additional_bytes'], 7 * s.GIB)
        self.assertEqual(result['runner_peak_additional_bytes'], 9 * s.GIB)
        self.assertFalse(result['runtime_admitted'])
        self.assertFalse(result['enforces_capacity'])
        unchanged = s.admit(**self.plan(existing_managed_bytes=20 * s.GIB, new_managed_bytes=0, outstanding_managed_bytes=0,
                                        platform_growth_bytes=0, guest_metadata_margin_bytes=0, guest=s.Space(8 * s.GIB, 10000)))
        self.assertTrue(unchanged['fits_capacity_plan'])

    def test_existing_unreserved_growth_must_be_within_full_declared_existing_maximum(self):
        values = {name: 0 for name in self.plan() if name not in ('guest', 'runner')}
        values.update(guest=s.Space(32 * s.GIB, 100), runner=s.Space(32 * s.GIB, 100))
        for existing, growth in ((0, s.GIB), (s.GIB, 15 * s.GIB)):
            with self.subTest(existing=existing, growth=growth), self.assertRaisesRegex(s.StorageBlocked, 'contradictory-existing-managed-growth'):
                s.admit(**{**values, 'existing_managed_bytes': existing, 'existing_unreserved_growth_bytes': growth,
                           'overlay_growth_upper_bound_bytes': growth})
        admitted = s.admit(**{**values, 'existing_managed_bytes': 20 * s.GIB, 'existing_unreserved_growth_bytes': s.GIB,
                             'overlay_growth_upper_bound_bytes': s.GIB})
        self.assertTrue(admitted['fits_capacity_plan'])
        self.assertEqual(admitted['managed_reserved_after_bytes'], 20 * s.GIB)
        self.assertEqual(admitted['guest_peak_additional_bytes'], s.GIB)
        rejected = s.admit(**{**values, 'existing_managed_bytes': 20 * s.GIB, 'new_managed_bytes': 1,
                             'existing_unreserved_growth_bytes': s.GIB, 'overlay_growth_upper_bound_bytes': s.GIB + 1})
        self.assertIn('managed-aggregate-20gib', rejected['blockers'])

    def test_independent_guest_ci_and_aggregate_limits_cannot_substitute_for_each_other(self):
        cases = (({'existing_managed_bytes': 16 * s.GIB}, 'managed-aggregate-20gib'),
                 ({'guest': s.Space(14 * s.GIB, 10000)}, 'guest-8gib-reserve'),
                 ({'guest': s.Space(24 * s.GIB, 999)}, 'guest-inode-capacity'),
                 ({'overlay_current_bytes': 9 * s.GIB}, 'ci-overlay-16gib'),
                 ({'overhead_current_bytes': 4 * s.GIB}, 'ci-overhead-4gib'),
                 ({'runner': s.Space(11 * s.GIB, 10000)}, 'runner-3gib-reserve'),
                 ({'runner': s.Space(32 * s.GIB, 999)}, 'runner-inode-capacity'),
                 ({'overlay_growth_upper_bound_bytes': 0}, 'qcow-growth-bound-below-guest-growth'))
        for change, expected in cases:
            with self.subTest(expected=expected):
                result = s.admit(**self.plan(**change))
                self.assertFalse(result['fits_capacity_plan'])
                self.assertIn(expected, result['blockers'])
        # Large virtual guest free space never overrides the physical qcow cap.
        result = s.admit(**self.plan(guest=s.Space(100 * s.GIB, 10000), new_managed_bytes=15 * s.GIB,
                                    existing_managed_bytes=0, overlay_growth_upper_bound_bytes=19 * s.GIB))
        self.assertIn('ci-overlay-16gib', result['blockers'])

    def test_unknown_mistyped_measurements_block_and_reserve_boundaries_are_exact(self):
        for name in self.plan():
            values = self.plan(**{name: None})
            with self.subTest(name=name), self.assertRaises(s.StorageBlocked):
                s.admit(**values)
        for value in (-1, True, 1.0):
            with self.assertRaises(s.StorageBlocked):
                s.admit(**self.plan(platform_growth_bytes=value))
        baseline = s.admit(**self.plan())
        guest_needed = baseline['guest_peak_additional_bytes'] + s.GUEST_RESERVE
        runner_needed = baseline['runner_peak_additional_bytes'] + s.RUNNER_RESERVE
        exact = s.admit(**self.plan(guest=s.Space(guest_needed, 1000), runner=s.Space(runner_needed, 1000)))
        self.assertTrue(exact['fits_capacity_plan'])
        for name, space in (('guest', s.Space(guest_needed - 1, 1000)), ('runner', s.Space(runner_needed - 1, 1000))):
            self.assertFalse(s.admit(**self.plan(**{name: space}))['fits_capacity_plan'])
        with self.assertRaises(s.StorageBlocked):
            s.admit(**self.plan(guest=s.Space(10 * s.GIB, None)))


if __name__ == '__main__':
    unittest.main()
