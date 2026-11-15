import io
import contextlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import threading
import shutil
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fedora_ci as ci
import fedora_ci_guest as guest


def fixture_inputs():
    return {**{key: 'c' * length for key, length in guest.INPUT_LENGTHS.items()}, 'source_sha': 'a' * 40, 'payload_bytes': 123}


class FedoraCITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def test_resolved_witness_projection_is_bounded_closed_and_target_aware(self):
        expected=fixture_inputs();state=self.root/'state';state.mkdir()
        witness={'version':1,'status':'blocked','reason':'discovery-listener-remains',
                 'bootstrap_sha256':'a'*64,'source_sha':expected['source_sha'],
                 'context_sha256':expected['context_sha256'],'directory_mode':0o755,'file_mode':0o644,
                 'owner_and_type_verified':True,'stock_labels_match':True,'runtime_discovery_disabled':True}
        path=state/'resolved-discovery.json';path.write_text(json.dumps(witness))
        observed=guest.public_diagnostics(state,expected)['resolved_discovery']
        self.assertEqual(observed['reason'],'discovery-listener-remains')
        self.assertEqual(observed['directory_mode'],0o755)
        for malformed in ([], None, 'SECRET-STRING', 123, True):
            path.write_text(json.dumps(malformed))
            observed=guest.public_diagnostics(state,expected)['resolved_discovery']
            self.assertEqual(observed,{'status':'unavailable'})
            self.assertNotIn('SECRET',json.dumps(observed))
        for key,value in (('reason','SECRET-UNRECOGNIZED'),('source_sha','d'*40),
                          ('directory_mode',True),('stock_labels_match','SECRET')):
            wrong=dict(witness);wrong[key]=value;path.write_text(json.dumps(wrong))
            observed=guest.public_diagnostics(state,expected)['resolved_discovery']
            self.assertEqual(observed,{'status':'unavailable'})
            self.assertNotIn('SECRET',json.dumps(observed))

    def test_actual_official_checksum_signature_and_tamper_rejection(self):
        inputs = ROOT / 'tests/data/fedora44'
        result = ci.verify_checksum(inputs / 'fedora.gpg', inputs / 'CHECKSUM', self.root / 'good')
        self.assertEqual(result['sha256'], ci.IMAGE_SHA256)
        self.assertEqual(result['bytes'], ci.IMAGE_BYTES)
        changed = self.root / 'CHECKSUM'
        changed.write_bytes((inputs / 'CHECKSUM').read_bytes().replace(ci.IMAGE_SHA256.encode(), b'f' * 64))
        with self.assertRaisesRegex(ci.Blocked, 'signature verification failed'):
            ci.verify_checksum(inputs / 'fedora.gpg', changed, self.root / 'bad')
        with mock.patch.object(ci, 'FINGERPRINT', '0' * 40):
            with self.assertRaisesRegex(ci.Blocked, 'signing key absent'):
                ci.verify_checksum(inputs / 'fedora.gpg', inputs / 'CHECKSUM', self.root / 'wrong-key')

    def test_checksum_parser_rejects_duplicate_wrong_digest_and_length(self):
        original = (ROOT / 'tests/data/fedora44/CHECKSUM').read_text()
        line = 'SHA256 (' + ci.IMAGE_NAME + ') = ' + ci.IMAGE_SHA256
        for malformed in (original + '\n' + line, original.replace(ci.IMAGE_SHA256, 'f' * 64),
                          original.replace(str(ci.IMAGE_BYTES) + ' bytes', '1 bytes')):
            with self.assertRaisesRegex(ci.Blocked, 'identity mismatch'):
                ci.checksum_identity(malformed)

    def test_native_file_limit_stops_real_child_before_disk_growth(self):
        target = self.root / 'limited'
        code = ('import pathlib,sys;sys.path.insert(0,sys.argv[1]);'
                'from fedora_ci_qemu import limit_output_bytes;limit_output_bytes(4096);'
                'pathlib.Path(sys.argv[2]).write_bytes(b"x"*8192)')
        result = subprocess.run([sys.executable, '-c', code, str(ROOT / 'tools'), str(target)],
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertLessEqual(target.stat().st_size, 4096)
        self.assertIn(b'File too large', result.stderr)

    def test_real_process_deadline_kills_descendant_and_log_overflow_is_bounded(self):
        probe = ci.Probe('a' * 40, self.root)
        marker = self.root / 'should-not-appear'
        code = ('import os,time,pathlib,sys;pid=os.fork();'
                'time.sleep(2) if pid==0 else time.sleep(10);'
                'pathlib.Path(sys.argv[1]).write_text("escaped")')
        with self.assertRaisesRegex(ci.Blocked, 'deadline exceeded'):
            probe.bounded([sys.executable, '-c', code, str(marker)], .1, 'test timeout', disk_check=False)
        time.sleep(2.1)
        self.assertFalse(marker.exists())
        with mock.patch.object(ci, 'LOG_LIMIT', 4096):
            with self.assertRaisesRegex(ci.Blocked, 'diagnostic byte limit'):
                probe.bounded([sys.executable, '-c', 'import os;os.write(1,b"x"*8192)'],
                              5, 'overflow', disk_check=False)

    def test_public_dependency_wall_deadline_interrupts_real_blocking_process(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ci.Blocked, 'wall-time budget'):
            with ci.deadline(.05):
                time.sleep(5)
        self.assertLess(time.monotonic() - started, 1)

    def test_guest_capture_bounds_real_output_and_runtime(self):
        code, output = guest.capture([sys.executable, '-c', 'print("local process only")'])
        self.assertEqual((code, output), (0, b'local process only\n'))
        with self.assertRaisesRegex(ValueError, 'byte limit'):
            guest.capture([sys.executable, '-c', 'import os;os.write(1,b"x"*8192)'], maximum=1024)
        with self.assertRaisesRegex(ValueError, 'deadline'):
            guest.capture([sys.executable, '-c', 'import time;time.sleep(5)'], timeout=.1)

    def test_listener_inventory_is_bounded_diagnostic_with_explicit_failure(self):
        def captured(argv, timeout):
            self.assertEqual(timeout, 15)
            if argv[0] == '/usr/bin/ss':
                self.assertEqual(argv, ['/usr/bin/ss', '-H', '-lntup'])
                return 1, b'x' * 4000 + b'\nlocal parser fixture only\n'
            return 0, b''
        with mock.patch.object(guest, 'capture', side_effect=captured):
            observed = guest.diagnostics()['listener_inventory']
        self.assertEqual(observed['exit_status'], 1)
        self.assertEqual(len(observed['tail']), 3000)
        self.assertTrue(observed['tail'].startswith('[truncated] '))
        self.assertTrue(observed['tail'].endswith('local parser fixture only\n'))
        with mock.patch.object(guest, 'capture', side_effect=ValueError('diagnostic deadline exceeded')):
            observed = guest.diagnostics()['listener_inventory']
        self.assertEqual(observed, {'status': 'unavailable', 'detail': 'diagnostic deadline exceeded'})

    def serial_result(self):
        return {'version': guest.REPORT_VERSION, 'source_sha': 'a' * 40, 'guest_sha256': 'b' * 64,
                'inputs': fixture_inputs(), 'initialization': {},
                'phases': {key: {'status': 'blocked', 'detail': 'synthetic parser test only'} for key in
                           guest.GUEST_PHASES},
                'identity': {}, 'diagnostics': {}}

    def test_serial_consumer_requires_one_complete_candidate_bound_result(self):
        report = self.serial_result()
        serial = guest.encode_report(report)
        self.assertEqual(ci.parse_serial(serial, 'a' * 40, 'b' * 64, fixture_inputs()), report)
        for malformed in (serial + serial, b'no result', b'console\n' + serial, serial.replace(b'"version": 4', b'"version": true'),
                          serial.replace(b'"source_sha":', b'"version":1,"source_sha":')):
            with self.assertRaises((ci.Blocked, ValueError)):
                ci.parse_serial(malformed, 'a' * 40, 'b' * 64, fixture_inputs())
        with self.assertRaisesRegex(ci.Blocked, 'identity mismatch'):
            ci.parse_serial(serial, 'c' * 40, 'b' * 64, fixture_inputs())
        del report['phases']['maintenance-gptbox']
        with self.assertRaisesRegex(ci.Blocked, 'missing guest phases'):
            ci.parse_serial(guest.encode_report(report), 'a' * 40, 'b' * 64, fixture_inputs())

    def payload_archive(self, malicious=False):
        payload = self.root / ('payload-bad' if malicious else 'payload')
        payload.mkdir()
        (payload / 'source.bundle').write_bytes(b'public Git bundle test bytes, not runtime evidence')
        with tarfile.open(payload / 'source.tar', 'w') as archive:
            member = tarfile.TarInfo('tools/bootstrap.py')
            data = b'# public source parser fixture\n'
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
            if malicious:
                link = tarfile.TarInfo('tools/escape')
                link.type = tarfile.SYMTYPE
                link.linkname = str(self.root / 'victim')
                archive.addfile(link)
        return payload

    def test_guest_source_staging_checks_bytes_rejects_links_and_preserves_public_objects(self):
        payload = self.payload_archive()
        source = guest.stage_source(payload, self.root / 'staging', ci.file_hash(payload / 'source.tar'),
                                    ci.file_hash(payload / 'source.bundle'))
        self.assertEqual((source / 'tools/bootstrap.py').stat().st_mode & 0o777, 0o400)
        self.assertEqual((self.root / 'staging/source.bundle').read_bytes(), (payload / 'source.bundle').read_bytes())
        with self.assertRaisesRegex(ValueError, 'handoff'):
            guest.stage_source(payload, self.root / 'wrong-digest', 'f' * 64, ci.file_hash(payload / 'source.bundle'))
        victim = self.root / 'victim'
        victim.write_text('preserve')
        bad = self.payload_archive(malicious=True)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            guest.stage_source(bad, self.root / 'bad-staging', ci.file_hash(bad / 'source.tar'), ci.file_hash(bad / 'source.bundle'))
        self.assertEqual(victim.read_text(), 'preserve')

    def test_capacity_requires_full_overlay_reservation_and_controls_are_escaped(self):
        disk = type('Disk', (), {})()
        disk.free = ci.HOST_RESERVE + ci.OVERLAY_LIMIT - 1
        with mock.patch.object(ci.shutil, 'disk_usage', return_value=disk):
            with self.assertRaisesRegex(ci.Blocked, 'capacity blocked'):
                ci.check_capacity(self.root, before_boot=True)
            self.assertEqual(ci.check_capacity(self.root), disk.free)
        self.assertNotIn('::error', ci.sanitize(b'::error::untrusted\x1b[31m\x00'))
        self.assertNotIn('\x1b', ci.sanitize(b'bad\x1b[31m'))
        with self.assertRaisesRegex(ci.Blocked, 'invalid payload identity'):
            ci.seed_data('a' * 39 + '\n', fixture_inputs(), 'd' * 64)

    def test_realistic_runner_temp_uses_short_owned_engine_paths(self):
        old_root = pathlib.Path('/home/runner/work/_temp/dev-pair-fedora-abcdefgh')
        self.assertGreater(len(os.fsencode(old_root / 'runroot')), 50)
        runner_temp = self.root / 'home/runner/work/_temp'
        runner_temp.mkdir(parents=True)
        short = ci.scratch_root(str(runner_temp))
        self.addCleanup(lambda: shutil.rmtree(short, ignore_errors=True))
        probe = ci.Probe('a' * 40, short)
        self.assertEqual(short.parent, pathlib.Path('/tmp'))
        self.assertEqual(short.stat().st_uid, os.getuid())
        self.assertEqual(short.stat().st_mode & 0o022, 0)
        for name in ('graph', 'runroot', 'tmp'):
            self.assertLessEqual(len(os.fsencode(short / name)), 50)
            self.assertIn(str(short / name), ' '.join(probe.podman))

    def test_preflight_failure_removes_owned_scratch_without_engine_or_sudo(self):
        short = ci.scratch_root(str(self.root))
        self.addCleanup(lambda: shutil.rmtree(short, ignore_errors=True))
        (short / 'partial-public-input').write_text('preserve diagnostics in report, not scratch')
        probe = ci.Probe('a' * 40, short)
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), \
             mock.patch.object(probe, 'preflight', side_effect=ci.Blocked('engine initialization rejected')), \
             mock.patch.object(ci.subprocess, 'run', side_effect=AssertionError('no engine/sudo should be needed')):
            self.assertEqual(probe.execute(), 2)
        self.assertFalse(short.exists())
        self.assertEqual(probe.report['phases']['cleanup']['status'], 'pass')
        report = next(json.loads(line.split(' ', 1)[1]) for line in captured.getvalue().splitlines()
                      if line.startswith('DP_REPORT '))
        self.assertEqual(report['blocker'], 'engine initialization rejected')

    def test_engine_version_directory_creation_does_not_break_next_phase(self):
        short = ci.scratch_root(str(self.root))
        self.addCleanup(lambda: shutil.rmtree(short, ignore_errors=True))
        probe = ci.Probe('a' * 40, short)
        def version_probe():
            # Actual filesystem behavior of Podman version with explicit paths,
            # without installing/running Podman on the development machine.
            for name in ('graph', 'runroot', 'tmp'):
                (short / name).mkdir(parents=True, exist_ok=True)
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), \
             mock.patch.object(probe, 'preflight', side_effect=version_probe), \
             mock.patch.object(probe, 'inputs', side_effect=ci.Blocked('reached input phase')) as inputs:
            self.assertEqual(probe.execute(), 2)
        inputs.assert_called_once_with()
        self.assertEqual(probe.report['blocker'], 'reached input phase')
        self.assertEqual(probe.report['phases']['cleanup']['status'], 'pass')
        self.assertFalse(short.exists())

    def test_directory_initialization_rejects_symlink_or_foreign_write_mode(self):
        probe = ci.Probe('a' * 40, self.root)
        target = self.root / 'preserved'
        target.mkdir()
        (self.root / 'graph').symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ci.Blocked, 'unsafe'):
            probe.initialize_directories()
        self.assertTrue(target.is_dir())
        (self.root / 'graph').unlink()
        (self.root / 'graph').mkdir()
        (self.root / 'graph').chmod(0o777)
        with self.assertRaisesRegex(ci.Blocked, 'unsafe'):
            probe.initialize_directories()

    def test_active_engine_failure_or_mount_preserves_owned_scratch(self):
        probe = ci.Probe('a' * 40, self.root)
        probe.engine_activity = True
        evidence = self.root / 'evidence'
        evidence.write_text('retain')
        with mock.patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'engine failed')) as run:
            with self.assertRaisesRegex(ci.Blocked, 'scratch preserved'):
                probe.cleanup()
            self.assertEqual(run.call_count, 1)
        with mock.patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
             mock.patch.object(ci, 'mounts_below', return_value=True):
            with self.assertRaisesRegex(ci.Blocked, 'active scratch mounts'):
                probe.cleanup()
        with mock.patch.object(ci.subprocess, 'run', side_effect=[
                subprocess.CompletedProcess([], 0, b'', b''),
                subprocess.CompletedProcess([], 0, b'active-buildah-resource\n', b'')]):
            with self.assertRaisesRegex(ci.Blocked, 'inventory unresolved'):
                probe.cleanup()
        self.assertEqual(evidence.read_text(), 'retain')

    def test_cleanup_refuses_replaced_owned_directory(self):
        original = self.root / 'original'
        original.mkdir()
        probe = ci.Probe('a' * 40, original)
        original.rename(self.root / 'retained-original')
        original.mkdir()
        marker = original / 'replacement'
        marker.write_text('retain')
        with self.assertRaisesRegex(ci.Blocked, 'identity changed'):
            probe.cleanup()
        self.assertEqual(marker.read_text(), 'retain')

    def test_real_du_churn_is_provisional_then_stabilizes_without_ignoring_permissions(self):
        tree = self.root / 'churn'
        tree.mkdir()
        for index in range(10000):
            (tree / str(index)).touch()
        code = ('import pathlib,sys;root=pathlib.Path(sys.argv[1]);\n'
                'while True:\n for path in root.iterdir():\n'
                '  path.unlink(missing_ok=True);path.touch()\n')
        process = subprocess.Popen([sys.executable, '-c', code, str(tree)])
        observed = False
        try:
            for _ in range(30):
                result = subprocess.run(['/usr/bin/du', '--summarize', '--block-size=1',
                                         '--one-file-system', '--exclude=guest.qcow2', str(self.root)],
                                        env=ci.SAFE_ENV, capture_output=True, timeout=5)
                _, vanished = ci.parse_du(self.root, result)
                observed |= vanished
                # Real live traversal can tolerate only classified ENOENT.
                measurement = ci.measure_storage(self.root, live=True, sudo=False)
                self.assertLessEqual(measurement['bytes'], ci.OVERHEAD_LIMIT)
                if observed:
                    break
            self.assertTrue(observed, 'real removed/recreated-file race was not exercised')
        finally:
            process.kill()
            process.wait(timeout=5)
        stable = ci.measure_storage(self.root, sudo=False)
        self.assertFalse(stable['provisional'])
        restricted = self.root / 'inaccessible'
        restricted.mkdir()
        restricted.chmod(0)
        try:
            if os.geteuid() != 0:
                with self.assertRaisesRegex(ci.Blocked, 'non-disappearance'):
                    ci.measure_storage(self.root, live=True, sudo=False)
        finally:
            restricted.chmod(0o700)

    def test_storage_retries_do_not_turn_unstable_or_invalid_measurement_into_stable_pass(self):
        output = ('100\t' + str(self.root) + '\n').encode()
        disappearance = ("du: cannot access '" + str(self.root / 'gone') + "': No such file or directory\n").encode()
        result = subprocess.CompletedProcess([], 1, output, disappearance)
        with mock.patch.object(ci, 'capture_du', return_value=result) as run:
            self.assertTrue(ci.measure_storage(self.root, live=True, sudo=False)['provisional'])
            self.assertEqual(run.call_count, 3)
            with self.assertRaisesRegex(ci.Blocked, 'did not stabilize'):
                ci.measure_storage(self.root, sudo=False)
        for error in (b'du: Input/output error\n', b'sudo: permission denied\n',
                      ("du: cannot access '" + str(self.root) + "/../outside': No such file or directory\n").encode(),
                      b"du: cannot access '/outside/gone': No such file or directory\n"):
            with self.assertRaises(ci.Blocked):
                ci.parse_du(self.root, subprocess.CompletedProcess([], 1, output, error))
        huge = subprocess.CompletedProcess([], 0, (str(ci.OVERHEAD_LIMIT + 1) + '\t' + str(self.root) + '\n').encode(), b'')
        with mock.patch.object(ci, 'capture_du', return_value=huge):
            with self.assertRaisesRegex(ci.Blocked, 'overhead limit'):
                ci.measure_storage(self.root, live=True, sudo=False)

    def test_real_gnu_du_deleted_path_volume_keeps_bounded_failure_diagnostics(self):
        # Deterministic queued-path disappearance, not claimed proof of the
        # runner's still-unknown teardown errno. Real GNU du emits >64KiB here.
        paths = [self.root / ('deleted-' + str(index) + '-' + 'x' * 80) for index in range(1000)]
        for path in paths:
            path.touch()
        for path in paths:
            path.unlink()
        argv = ['/usr/bin/du', '--summarize', '--block-size=1', *map(str, paths), str(self.root)]
        actual = subprocess.run(argv, capture_output=True, env=ci.SAFE_ENV, timeout=5)
        self.assertEqual(actual.returncode, 1)
        self.assertGreater(len(actual.stderr), ci.DU_CAPTURE_LIMIT)
        complete = ci.du_diagnostics(self.root, actual)
        self.assertEqual(complete['retained_line_types']['access_enoent'], 1000)
        self.assertEqual(complete['retained_line_types']['other'], 0)
        with self.assertRaisesRegex(ci.StorageMeasurementBlocked, 'diagnostic limit') as caught:
            ci.capture_du(self.root, argv)
        detail = caught.exception.diagnostics
        self.assertTrue(detail['truncated'])
        self.assertGreater(detail['stderr_bytes_seen'], ci.DU_CAPTURE_LIMIT)
        self.assertGreater(detail['retained_line_types']['access_enoent'], 0)
        self.assertIn('No such file or directory', detail['stderr_tail'])
        self.assertLess(len(ci.safe_json(detail)), 5000)
        probe = ci.Probe('a' * 40, self.root)
        with mock.patch.object(ci, 'capture_du', side_effect=caught.exception):
            with self.assertRaises(ci.StorageMeasurementBlocked):
                probe.storage_measurement(live=True)
        self.assertEqual(probe.report['storage_measurement_failure'], detail)

    def test_storage_failure_retains_other_error_and_still_rejects_it(self):
        output = ('0\t' + str(self.root) + '\n').encode()
        stderr = b'du: Input/output error ##[warning] ::error::\n'
        with self.assertRaisesRegex(ci.StorageMeasurementBlocked, 'non-disappearance') as caught:
            ci.parse_du(self.root, subprocess.CompletedProcess([], 1, output, stderr))
        detail = caught.exception.diagnostics
        self.assertFalse(detail['truncated'])
        self.assertEqual(detail['retained_line_types']['other'], 1)
        self.assertEqual(detail['stderr_tail'], stderr.decode())
        encoded = ci.safe_json(detail)
        self.assertNotIn('##[', encoded)
        self.assertNotIn('::', encoded)
        self.assertEqual(json.loads(encoded), detail)

    def test_storage_capture_cap_kills_real_unprivileged_descendant(self):
        marker = self.root / 'scan-descendant'
        code = ('import os,time,pathlib,sys\n'
                'if os.fork()==0:\n time.sleep(1);pathlib.Path(sys.argv[1]).write_text("escaped");os._exit(0)\n'
                'os.write(2,b"x"*131072);time.sleep(5)\n')
        with self.assertRaisesRegex(ci.StorageMeasurementBlocked, 'diagnostic limit'):
            ci.capture_du(self.root, [sys.executable, '-c', code, str(marker)])
        time.sleep(1.1)
        self.assertFalse(marker.exists())

    def test_privileged_measurement_has_fixed_root_side_timeout(self):
        summary = ('4096\t' + str(self.root) + '\n').encode()
        with mock.patch.object(ci, 'capture_du', return_value=subprocess.CompletedProcess([], 0, summary, b'')) as capture:
            ci.measure_storage(self.root)
        argv = capture.call_args.args[1]
        self.assertEqual(argv[:7], ['sudo', '-n', '/usr/bin/timeout', '--signal=TERM', '--kill-after=1s', '5s', '/usr/bin/du'])

    def test_captured_fatal_fts_witness_retries_without_inventing_totals(self):
        captured_root = pathlib.Path('/tmp/dpvm-0n1yt9k2')
        captured = subprocess.CompletedProcess([], 1, b'',
            b'/usr/bin/du: fts_read failed: /tmp/dpvm-0n1yt9k2/graph/overlay: No such file or directory\n')
        self.assertEqual(ci.parse_du(captured_root, captured), (None, True))
        fatal = subprocess.CompletedProcess([], 1, b'',
            ('/usr/bin/du: fts_read failed: ' + str(self.root / 'graph/overlay') + ': No such file or directory\n').encode())
        complete = subprocess.CompletedProcess([], 0, ('4096\t' + str(self.root) + '\n').encode(), b'')
        partial = subprocess.CompletedProcess([], 1, ('8192\t' + str(self.root) + '\n').encode(),
            ("du: cannot access '" + str(self.root / 'gone') + "': No such file or directory\n").encode())
        with mock.patch.object(ci, 'capture_du', side_effect=[fatal, complete]) as capture:
            sample = ci.measure_storage(self.root, sudo=False)
            self.assertEqual((sample['bytes'], sample['missing_total_samples'], sample['usable_samples']), (4096, 1, 1))
            self.assertFalse(sample['provisional'])
            self.assertEqual(capture.call_count, 2)
        with mock.patch.object(ci, 'capture_du', side_effect=[partial, fatal, complete]):
            self.assertEqual(ci.measure_storage(self.root, sudo=False)['bytes'], 8192)
        with mock.patch.object(ci, 'capture_du', side_effect=[partial, fatal, fatal]):
            provisional = ci.measure_storage(self.root, live=True, sudo=False)
            self.assertEqual((provisional['bytes'], provisional['missing_total_samples']), (8192, 2))
            self.assertTrue(provisional['provisional'])
        with mock.patch.object(ci, 'capture_du', return_value=fatal) as capture:
            with self.assertRaisesRegex(ci.StorageMeasurementBlocked, 'no usable total') as caught:
                ci.measure_storage(self.root, live=True, sudo=False)
            self.assertEqual(capture.call_count, 3)
            self.assertIsNone(caught.exception.diagnostics['max_observed_bytes'])
            self.assertEqual(caught.exception.diagnostics['missing_total_samples'], 3)
            self.assertEqual(caught.exception.diagnostics['retained_line_types']['fatal_fts_enoent'], 1)
        with mock.patch.object(ci, 'capture_du', side_effect=[partial, fatal, fatal]):
            with self.assertRaisesRegex(ci.StorageMeasurementBlocked, 'did not stabilize'):
                ci.measure_storage(self.root, sudo=False)
        bad = [subprocess.CompletedProcess([], 0, b'', b''),
               subprocess.CompletedProcess([], 1, b'', partial.stderr),
               subprocess.CompletedProcess([], 1, b'\n', fatal.stderr)]
        for error in (b'Permission denied', b'Input/output error'):
            bad.append(subprocess.CompletedProcess([], 1, b'', fatal.stderr.replace(b'No such file or directory', error)))
        bad.append(subprocess.CompletedProcess([], 1, b'', fatal.stderr.replace(str(self.root).encode(), b'/outside')))
        for result in bad:
            with mock.patch.object(ci, 'capture_du', return_value=result) as capture:
                with self.assertRaises(ci.StorageMeasurementBlocked):
                    ci.measure_storage(self.root, live=True, sudo=False)
                self.assertEqual(capture.call_count, 1)

    def test_real_gnu_du_overlay_root_churn_never_turns_missing_summary_into_zero(self):
        graph = self.root / 'graph'
        graph.mkdir()
        overlay = graph / 'overlay'
        stop = threading.Event()
        def churn():
            while not stop.is_set():
                shutil.rmtree(overlay, ignore_errors=True)
                overlay.mkdir(exist_ok=True)
                for index in range(30):
                    directory = overlay / str(index)
                    directory.mkdir()
                    (directory / 'x').touch()
        worker = threading.Thread(target=churn)
        worker.start()
        try:
            for _ in range(100):
                actual = ci.capture_du(self.root, ['/usr/bin/du', '--summarize', '--block-size=1',
                                                '--one-file-system', str(self.root)])
                size, incomplete = ci.parse_du(self.root, actual)
                if size is None:
                    self.assertTrue(incomplete)
                    self.assertIn(b'fts_read failed:', actual.stderr)
                else:
                    self.assertGreater(size, 0)
        finally:
            stop.set()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        stable = ci.measure_storage(self.root, sudo=False)
        self.assertFalse(stable['provisional'])
        self.assertGreater(stable['bytes'], 0)

    def test_real_removed_recreated_directories_and_exact_read_directory_enoent(self):
        # The same FTS race has two proven GNU forms. Exercise the exact
        # read-directory variant deterministically, then real directory churn;
        # do not make CI depend on which sub-millisecond race a kernel exposes.
        summary = ('4096\t' + str(self.root) + '\n').encode()
        read_directory = ("du: cannot read directory '" + str(self.root / 'gone') +
                          "': No such file or directory\n").encode()
        self.assertEqual(ci.parse_du(self.root, subprocess.CompletedProcess([], 1, summary, read_directory)),
                         (4096, True))
        for malformed in (read_directory.replace(b'No such file or directory', b'Permission denied'),
                          read_directory.replace(b'No such file or directory', b'Input/output error'),
                          read_directory.replace(str(self.root).encode(), b'/outside')):
            with self.assertRaisesRegex(ci.Blocked, 'non-disappearance'):
                ci.parse_du(self.root, subprocess.CompletedProcess([], 1, summary, malformed))
        for index in range(1500):
            directory = self.root / str(index)
            directory.mkdir()
            (directory / 'x').touch()
        stop = threading.Event()
        def churn():
            while not stop.is_set():
                for directory in self.root.iterdir():
                    if stop.is_set():
                        break
                    try:
                        shutil.rmtree(directory)
                        directory.mkdir()
                        (directory / 'x').touch()
                    except FileNotFoundError:
                        pass
        worker = threading.Thread(target=churn)
        worker.start()
        disappearance_seen = False
        try:
            for _ in range(250):
                result = subprocess.run(['/usr/bin/du', '--summarize', '--block-size=1',
                                         '--one-file-system', '--exclude=guest.qcow2', str(self.root)],
                                        env=ci.SAFE_ENV, capture_output=True, timeout=5)
                _, vanished = ci.parse_du(self.root, result)
                disappearance_seen |= vanished
                if b'cannot read directory' in result.stderr:
                    break
            self.assertTrue(disappearance_seen, 'real directory removal race was not exercised')
        finally:
            stop.set()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        self.assertFalse(ci.measure_storage(self.root, sudo=False)['provisional'])

    def test_all_public_emitters_neutralize_both_runner_commands_without_losing_json_evidence(self):
        attack = '::error::modern :::notice:::: overlap ##[warning]legacy ###['
        original = {'identity##[error]': {'diagnostics': [attack, 'unicode é "quoted" \\u003a']}}
        captured = io.StringIO()
        probe = ci.Probe('a' * 40, self.root)
        probe.report['guest'] = original
        probe.report['tooling'] = {'rpm_manifest': attack}
        with contextlib.redirect_stdout(captured), mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}):
            ci.emit_json('DP_JSON_TEST', original)
            for prefix in ('DP_SERIAL_TAIL\n', 'DP_TOOL_RPMS\n', 'DP_BLOCKED '):
                ci.emit_text(prefix, attack)
            with self.assertRaises(ci.Blocked):
                probe.bounded([sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', attack],
                              5, 'local output failure', disk_check=False)
            with mock.patch.object(probe, 'preflight', side_effect=ci.Blocked(attack)), \
                 mock.patch.object(probe, 'cleanup', side_effect=lambda: probe.phase('cleanup', 'pass', attack)):
                self.assertEqual(probe.execute(), 2)
        public = captured.getvalue()
        self.assertNotIn('::', public)
        self.assertNotIn('##[', public)
        decoded = {line.split(' ', 1)[0]: json.loads(line.split(' ', 1)[1])
                   for line in public.splitlines() if line.startswith(('DP_JSON_TEST ', 'DP_REPORT '))}
        self.assertEqual(decoded['DP_JSON_TEST'], original)
        self.assertEqual(decoded['DP_REPORT']['guest'], original)
        self.assertEqual(decoded['DP_REPORT']['tooling']['rpm_manifest'], attack)
        self.assertEqual(decoded['DP_REPORT']['blocker'], attack)


if __name__ == '__main__':
    unittest.main()
