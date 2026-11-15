"""Actual local relay subprocesses; Fedora UID/label admission stays explicit."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
import time
from unittest.mock import patch, mock_open
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_relay as r

HELPER = Path(r.__file__)
SHA = hashlib.sha256(HELPER.read_bytes()).hexdigest()
CODE = ('import sys;sys.path.insert(0,sys.argv[1]);import native_relay as r;'
        'r.verify_process=lambda uid:"unconfined_service_t";r.verify_fds=lambda value:None;'
        'sys.argv=["relay",*sys.argv[2:]];raise SystemExit(r.main())')


def launch(script, *, data=None, maximum=262144, seconds=2):
    args = [sys.executable, '-c', CODE, str(HELPER.parent), '--uid', str(os.getuid()),
            '--stdin', str(int(data is not None)), '--maximum', str(maximum),
            '--deadline', str(time.monotonic() + seconds), '--helper', SHA, '--', sys.executable, '-c', script]
    return subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)


def frame(kind, body):
    return r.HEADER.pack(kind, r.MAGIC, len(body)) + body


def control(status=0):
    return frame(b'C', json.dumps({'v': 1, 'done': True, 'status': status, 'uid': os.getuid(),
                                  'domain': 'unconfined_service_t', 'helper': SHA}, separators=(',', ':')).encode())


class RelayTests(unittest.TestCase):
    def capture(self, script, **kwargs):
        data = kwargs.get('data')
        process = launch(script, **kwargs)
        try:
            out, wire = process.communicate(data, timeout=4)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        return process.returncode, out, wire

    def decode(self, wire, status):
        decoder = r.Decoder(262144)
        data = b''.join(chunk for offset in range(0, len(wire), 7) for chunk in decoder.feed(wire[offset:offset + 7]))
        decoder.finish(status, os.getuid(), SHA)
        return data

    def test_real_stderr_framing_cannot_forge_completion_and_allowed_statuses(self):
        forged = control(0)
        for status in (0, 1, 4, 125):
            actual, out, wire = self.capture('import os;os.write(1,b"stdout");os.write(2,' + repr(forged) + ');raise SystemExit(' + str(status) + ')')
            self.assertEqual(actual, status)
            self.assertEqual(out, b'stdout')
            self.assertEqual(self.decode(wire, status), forged)
        for status in (1, 4, 250):
            with self.assertRaises(ValueError):
                r.Decoder(262144).finish(status, os.getuid(), SHA)

    def test_complete_control_required_no_duplicates_trailing_truncation_or_mismatch(self):
        valid = control()
        for wire in (b'', valid[:-1], valid + valid, valid + b'x', b'not a frame', frame(b'D', b'x') + frame(b'D', b'y') + valid):
            with self.subTest(length=len(wire)), self.assertRaises((ValueError, json.JSONDecodeError)):
                decoder = r.Decoder(262144)
                decoder.feed(wire)
                decoder.finish(0, os.getuid(), SHA)
        for status, uid, sha in ((1, os.getuid(), SHA), (0, os.getuid() + 1, SHA), (0, os.getuid(), '0'*64)):
            decoder = r.Decoder(262144); decoder.feed(valid)
            with self.assertRaises(ValueError):
                decoder.finish(status, uid, sha)
        decoder = r.Decoder(262144); decoder.feed(control(250))
        with self.assertRaises(ValueError):
            decoder.finish(250, os.getuid(), SHA)

    def test_real_mixed_output_exact_cap_overflow_and_framing_bound(self):
        actual, out, wire = self.capture('import os;[(os.write(1,b"x"*1024),os.write(2,b"y"*1024)) for _ in range(128)]')
        self.assertEqual(actual, 0)
        self.assertEqual(len(out) + len(self.decode(wire, actual)), 262144)
        self.assertLessEqual(len(wire), 131072 + r.overhead(262144))
        actual, _, wire = self.capture('import os;os.write(2,b"x"*262145)')
        self.assertEqual(actual, r.ERROR_STATUS)
        with self.assertRaises(ValueError):
            self.decode(wire, actual)
        self.assertEqual([r.overhead(n) for n in r.MAXIMA], [768, 2304, 8448])

    def test_real_input_empty_limit_oversize_signal_and_payload_descriptor_isolation(self):
        for data in (b'', b'NONCREDENTIAL' + b'x'*(16384-13)):
            actual, out, wire = self.capture('import sys;v=sys.stdin.buffer.read();print(len(v))', data=data)
            self.assertEqual(actual, 0)
            self.assertEqual(out, str(len(data)).encode()+b'\n')
            self.decode(wire, actual)
        actual, out, wire = self.capture('print("should not run")', data=b'x'*16385)
        self.assertEqual((actual, out, wire), (250, b'', b''))
        actual, _, wire = self.capture('import os,signal;os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual(actual, -signal.SIGTERM)
        with self.assertRaises(ValueError):
            self.decode(wire, actual)
        actual, out, wire = self.capture('import os,json;print(json.dumps([os.readlink("/proc/self/fd/"+str(i)) for i in range(3)]))', data=b'')
        self.assertTrue(all(value.startswith('pipe:[') for value in json.loads(out)))
        self.decode(wire, actual)

    def test_real_hang_and_consumer_death_are_finite(self):
        actual, _, wire = self.capture('import time;time.sleep(5)', seconds=.1)
        self.assertEqual(actual, 250)
        with self.assertRaises(ValueError):
            self.decode(wire, actual)
        process = launch('import os;os.write(1,b"x"*65536)')
        process.stdout.close()
        try:
            process.wait(timeout=2)
            self.assertEqual(process.returncode, 250)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=2)
            process.stderr.close()

    def test_privacy_is_actual_and_failure_precedes_input_read(self):
        actual, out, wire = self.capture('import os;print("payload")')
        self.assertEqual(actual, 0)
        self.decode(wire, actual)
        result = subprocess.run([sys.executable, '-c', 'import sys,ctypes,resource;sys.path.insert(0,sys.argv[1]);import native_relay as r;r.privacy();print(ctypes.CDLL(None).prctl(3,0,0,0,0),resource.getrlimit(resource.RLIMIT_CORE))', str(HELPER.parent)], capture_output=True, timeout=2)
        self.assertEqual(result.stdout, b'0 (0, 0)\n')
        with patch.object(r, 'privacy', side_effect=ValueError()), patch.object(r.os, 'read') as read:
            self.assertEqual(r.main(), 250)
            read.assert_not_called()

    def test_actual_uid_and_captured_context_terminator_are_checked(self):
        with self.assertRaises(ValueError):
            r.verify_process(os.getuid() + 1)
        for text, accepted in (('system_u:system_r:unconfined_service_t:s0\0', True),
                               ('system_u:system_r:cloud_init_t:s0\0', False), ('malformed', False)):
            with patch('builtins.open', mock_open(read_data=text)):
                if accepted:
                    self.assertEqual(r.verify_process(os.getuid()), 'unconfined_service_t')
                else:
                    with self.assertRaises(ValueError):
                        r.verify_process(os.getuid())

    def test_pipe_capacities_and_child_no_extra_inherited_descriptor(self):
        import fcntl
        for _ in range(3):
            reader, writer = r.pipe_pair()
            try:
                self.assertEqual(fcntl.fcntl(reader, fcntl.F_GETPIPE_SZ), 4096)
                self.assertFalse(os.get_inheritable(reader))
                self.assertFalse(os.get_inheritable(writer))
            finally:
                os.close(reader); os.close(writer)
        fd = os.open('/dev/null', os.O_RDONLY)
        os.set_inheritable(fd, True)
        try:
            actual, out, wire = self.capture('import os;v=[]\nfor i in range(3,256):\n try:os.fstat(i);v.append(i)\n except OSError:pass\nprint(v)')
            self.assertEqual((actual, out), (0, b'[]\n'))
            self.decode(wire, actual)
            if os.getuid() != 0:
                actual, out, wire = self.capture('import os\ntry:os.open("/proc/"+str(os.getppid())+"/fd/2",os.O_WRONLY);raise SystemExit(3)\nexcept PermissionError:print("blocked")')
                self.assertEqual((actual, out), (0, b'blocked\n'))
                self.decode(wire, actual)
        finally:
            os.close(fd)

    def test_immutable_staged_helper_real_file_collision_and_symlink_checks(self):
        import native_io as io
        import tempfile
        import stat
        # Only root ownership is injected. Actual regular files, modes, links,
        # protected ancestry, exclusive creation and bytes are exercised.
        lstat, fstat = Path.lstat, os.fstat
        def root_info(info):
            fields = list(info); fields[4] = 0
            return os.stat_result(fields)
        with tempfile.TemporaryDirectory(dir='/workspace') as temp:
            base = Path(temp)
            (base / 'tools').mkdir(mode=0o755)
            source = base / 'tools/native_relay.py'
            source.write_bytes(HELPER.read_bytes()); source.chmod(0o644)
            with patch.object(io, '__file__', str(base / 'tools/native_io.py')), \
                    patch.object(io, 'RELAY_ROOT', base / 'libexec'), \
                    patch.object(Path, 'lstat', lambda path: root_info(lstat(path))), \
                    patch.object(io.os, 'fstat', lambda fd: root_info(fstat(fd))):
                target, sha = io.stage_relay()
                self.assertEqual(target.read_bytes(), source.read_bytes())
                self.assertEqual(sha, SHA)
                self.assertEqual(stat.S_IMODE(lstat(target).st_mode), 0o444)
                self.assertEqual(io.stage_relay(), (target, sha))
                target.chmod(0o644)
                with self.assertRaisesRegex(ValueError, 'collision'):
                    io.stage_relay()
                target.write_bytes(b'tampered'); target.chmod(0o444)
                with self.assertRaisesRegex(ValueError, 'collision'):
                    io.stage_relay()
                source.unlink(); source.symlink_to(HELPER)
                with self.assertRaisesRegex(ValueError, 'Unprotected relay source'):
                    io.stage_relay()

    def test_full_stderr_all_dispatch_limits_have_finite_exact_overhead(self):
        for maximum in r.MAXIMA:
            actual, out, wire = self.capture('import os;os.write(2,b"x"*' + str(maximum) + ')', maximum=maximum)
            self.assertEqual((actual, out), (0, b''))
            self.assertLessEqual(len(wire), maximum + r.overhead(maximum))
            decoder = r.Decoder(maximum)
            count = sum(len(part) for offset in range(0, len(wire), 8192) for part in decoder.feed(wire[offset:offset+8192]))
            self.assertEqual(count, maximum)
            decoder.finish(0, os.getuid(), SHA)

    def test_allocation_and_spawn_failure_have_no_terminal_control(self):
        for attribute, failure in (('pipe_pair', OSError('synthetic allocation failure')),):
            with patch.object(r, attribute, side_effect=failure), self.assertRaises(OSError):
                r.pump([sys.executable, '-c', 'pass'], None, 262144, time.monotonic() + 1, {})
        blocking = {fd: os.get_blocking(fd) for fd in (1, 2)}
        try:
            with patch.object(r.subprocess, 'Popen', side_effect=OSError('synthetic spawn failure')), self.assertRaises(OSError):
                r.pump([sys.executable, '-c', 'pass'], None, 262144, time.monotonic() + 1, {})
        finally:
            for fd, value in blocking.items():
                os.set_blocking(fd, value)

    def test_fixed_native_user_allowlist_and_missing_account_block(self):
        import native_io as io
        self.assertEqual(io.expected_uid(()), 0)
        self.assertEqual(io.expected_uid(('--uid=root',)), 0)
        with self.assertRaisesRegex(ValueError, 'Unexpected native relay user'):
            io.expected_uid(('--uid=nobody',))
        with patch.object(io.pwd, 'getpwnam', side_effect=KeyError()):
            with self.assertRaisesRegex(ValueError, 'account unavailable'):
                io.expected_uid(('--uid=dp-maint',))

    def test_expired_absolute_deadline_blocks_before_secret_read_and_payload_launch(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'read-or-launch'
            # A real delayed manager/helper startup consumes the original wall
            # budget. The input-read hook records only that a read happened.
            code = ('import time;time.sleep(.15);' + CODE.replace(
                'sys.argv=["relay",*sys.argv[2:]];',
                'original_read=r.os.read;r.os.read=lambda *a: (__import__("pathlib").Path(' + repr(str(marker)) + ').write_text("read"),original_read(*a))[1];sys.argv=["relay",*sys.argv[2:]];'))
            args = [sys.executable, '-c', code, str(HELPER.parent), '--uid', str(os.getuid()),
                    '--stdin', '1', '--maximum', '262144', '--deadline', str(time.monotonic() + .05),
                    '--helper', SHA, '--', sys.executable, '-c', 'print("must-not-launch")']
            result = subprocess.run(args, input=b'NONCREDENTIAL', capture_output=True, timeout=2)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (250, b'', b''))
            self.assertFalse(marker.exists())

    def test_real_startup_delay_does_not_restart_payload_budget(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'late'
            code = 'import time;time.sleep(.15);' + CODE
            args = [sys.executable, '-c', code, str(HELPER.parent), '--uid', str(os.getuid()),
                    '--stdin', '0', '--maximum', '262144', '--deadline', str(time.monotonic() + .25),
                    '--helper', SHA, '--', sys.executable, '-c',
                    'import time;from pathlib import Path;time.sleep(.2);Path(' + repr(str(marker)) + ').write_text("escaped")']
            started = time.monotonic()
            result = subprocess.run(args, capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 250)
            self.assertLess(time.monotonic() - started, .6)
            time.sleep(.25)
            self.assertFalse(marker.exists())

    def test_expiry_during_admission_blocks_actual_spawn_and_closes_allocations(self):
        original = r.pipe_pair
        pairs = []
        def slow_pair():
            pair = original(); pairs.append(pair); time.sleep(.03)
            return pair
        blocking = {fd: os.get_blocking(fd) for fd in (1, 2)}
        try:
            with patch.object(r, 'pipe_pair', side_effect=slow_pair), patch.object(r.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    r.pump([sys.executable, '-c', 'pass'], None, 262144, time.monotonic() + .02, {})
                spawn.assert_not_called()
            for pair in pairs:
                for fd in pair:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
        finally:
            for fd, value in blocking.items():
                os.set_blocking(fd, value)

    def test_manager_signal_mappings_never_admit_a_signaled_payload(self):
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGPIPE, signal.SIGKILL):
            for native_status in (0, 255, -signum, 128 + signum):
                decoder = r.Decoder(262144); decoder.feed(control(-signum))
                with self.subTest(signal=signum, native_status=native_status), self.assertRaises(ValueError):
                    decoder.finish(native_status, os.getuid(), SHA)
