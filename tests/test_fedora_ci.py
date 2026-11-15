import io
import contextlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fedora_ci as ci
import fedora_ci_guest as guest


class FedoraCITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

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

    def serial_result(self):
        return {'version': 1, 'source_sha': 'a' * 40, 'guest_sha256': 'b' * 64,
                'phases': {key: {'status': 'blocked', 'detail': 'synthetic parser test only'} for key in
                           ('fedora-preflight', 'bootstrap-inspect', 'bootstrap-status', 'bootstrap-prepare', 'maintenance-gptbox')},
                'identity': {}, 'diagnostics': {}}

    def test_serial_consumer_requires_one_complete_candidate_bound_result(self):
        report = self.serial_result()
        serial = b'boot output\r\nDP_FEDORA_RESULT ' + json.dumps(report).encode() + b'\r\n'
        self.assertEqual(ci.parse_serial(serial, 'a' * 40, 'b' * 64), report)
        for malformed in (serial + serial, b'no result', serial.replace(b'"version": 1', b'"version": true'),
                          serial.replace(b'"source_sha":', b'"version":1,"source_sha":')):
            with self.assertRaises((ci.Blocked, ValueError)):
                ci.parse_serial(malformed, 'a' * 40, 'b' * 64)
        with self.assertRaisesRegex(ci.Blocked, 'identity mismatch'):
            ci.parse_serial(serial, 'c' * 40, 'b' * 64)
        del report['phases']['maintenance-gptbox']
        with self.assertRaisesRegex(ci.Blocked, 'missing guest phases'):
            ci.parse_serial(b'DP_FEDORA_RESULT ' + json.dumps(report).encode() + b'\n', 'a' * 40, 'b' * 64)

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
            ci.seed_data('a' * 39 + '\n', 'b' * 64, 'c' * 64, 'd' * 64)

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
        with mock.patch.object(ci.subprocess, 'run', return_value=result) as run:
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
        with mock.patch.object(ci.subprocess, 'run', return_value=huge):
            with self.assertRaisesRegex(ci.Blocked, 'overhead limit'):
                ci.measure_storage(self.root, live=True, sudo=False)

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
