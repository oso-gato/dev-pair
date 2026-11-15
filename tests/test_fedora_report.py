import base64
import contextlib
import io
import json
import os
import pathlib
import pty
import select
import subprocess
import sys
import tempfile
import threading
import time
import termios
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fedora_ci as ci
import fedora_ci_guest as guest


class FedoraReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.probe = ci.Probe('a' * 40, self.root)

    def report(self):
        return {'version': 1, 'source_sha': 'a' * 40, 'guest_sha256': 'b' * 64,
                'phases': {name: {'status': 'blocked', 'detail': 'local transport test, no Fedora evidence'} for name in
                           ('fedora-preflight', 'bootstrap-inspect', 'bootstrap-status', 'bootstrap-prepare', 'maintenance-gptbox')},
                'identity': {}, 'diagnostics': {}}

    def writer(self, pipe, data, console=b'', delay=0, held=False, exit_code=0):
        code = ('import os,sys,time,base64,pathlib\n'
                'time.sleep(float(sys.argv[4]));fd=os.open(sys.argv[1],os.O_WRONLY);data=base64.b64decode(sys.argv[2])\n'
                'os.write(1,base64.b64decode(sys.argv[3]))\n'
                'for offset in range(0,len(data),37):\n os.write(fd,data[offset:offset+37]);time.sleep(.0001)\n'
                'if sys.argv[5]=="hold" and os.fork()==0:\n time.sleep(3);pathlib.Path(sys.argv[6]).write_text("escaped");os._exit(0)\n'
                'os.close(fd);raise SystemExit(int(sys.argv[7]))\n')
        return [sys.executable, '-c', code, str(pipe.base) + '.out', base64.b64encode(data).decode(),
                base64.b64encode(console).decode(), str(delay), 'hold' if held else 'no-hold',
                str(self.root / 'escaped-writer'), str(exit_code)]

    def test_real_delayed_fragmented_fifo_writer_with_concurrent_console(self):
        frame = guest.encode_report(self.report())
        with ci.ReportPipe(self.root) as pipe:
            reader = pipe.reader
            self.assertEqual((pathlib.Path(str(pipe.base) + '.out')).stat().st_mode & 0o777, 0o600)
            console, result = self.probe.bounded(self.writer(pipe, frame, b'console\r\n##[warning] ::error::\n', .1),
                                                5, 'local FIFO writer', disk_check=False, report_pipe=pipe)
            self.assertEqual(result, frame)
            self.assertIn(b'console\r\n', console)
            self.assertEqual(ci.parse_serial(result, 'a' * 40, 'b' * 64), self.report())
        with self.assertRaises(OSError):
            os.fstat(reader)
        self.assertFalse(pathlib.Path(str(pipe.base) + '.in').exists())
        self.assertFalse(pathlib.Path(str(pipe.base) + '.out').exists())
        witness = self.probe.report['dedicated_report_witness']
        self.assertEqual(base64.b64decode(witness['retained_base64']), frame)
        self.assertEqual(witness['sha256'], ci.sha256(frame))
        self.assertTrue(witness['framing_complete'])
        self.assertNotIn('::', ci.safe_json(witness))
        self.assertNotIn('##[', ci.safe_json(witness))

    def test_absent_partial_duplicate_failed_and_mismatched_results_do_not_pass(self):
        frame = guest.encode_report(self.report())
        for data in (b'', frame[:-1], frame + frame, b'console\n' + frame,
                     b'DP_FEDORA_RESULT ' + json.dumps(self.report()).encode() + b'\n'):
            with ci.ReportPipe(self.root) as pipe:
                _, result = self.probe.bounded(self.writer(pipe, data), 5, 'invalid local writer',
                                               disk_check=False, report_pipe=pipe)
            with self.assertRaises((ci.Blocked, ValueError)):
                ci.parse_serial(result, 'a' * 40, 'b' * 64)
        with self.assertRaisesRegex(ci.Blocked, 'identity mismatch'):
            ci.parse_serial(frame, 'c' * 40, 'b' * 64)
        with ci.ReportPipe(self.root) as pipe, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ci.Blocked, 'exit 7'):
                self.probe.bounded(self.writer(pipe, frame, exit_code=7), 5, 'failed writer',
                                   disk_check=False, report_pipe=pipe)

    def test_exact_frame_limit_and_one_byte_overflow_are_real_fifo_bounds(self):
        report = self.report()
        report['diagnostics']['padding'] = ''
        report['diagnostics']['padding'] = 'x' * (guest.REPORT_LIMIT - len(json.dumps(report, sort_keys=True).encode()))
        frame = guest.encode_report(report)
        self.assertEqual(len(frame), guest.REPORT_FRAME_LIMIT)
        # Use larger writes for the exact-cap case so this test exercises pipe
        # backpressure rather than spending seconds on artificial fragmentation.
        code = 'import os,sys,base64;f=os.open(sys.argv[1],os.O_WRONLY);d=base64.b64decode(sys.argv[2]);p=0\nwhile p<len(d):p+=os.write(f,d[p:])\nos.close(f)'
        with ci.ReportPipe(self.root) as pipe:
            argv = [sys.executable, '-c', code, str(pipe.base) + '.out', base64.b64encode(frame).decode()]
            _, actual = self.probe.bounded(argv, 5, 'exact cap', disk_check=False, report_pipe=pipe)
            self.assertEqual(actual, frame)
            self.assertEqual(ci.parse_serial(actual, 'a' * 40, 'b' * 64), report)
        with ci.ReportPipe(self.root) as pipe, contextlib.redirect_stdout(io.StringIO()):
            argv = [sys.executable, '-c', code, str(pipe.base) + '.out', base64.b64encode(frame + b'x').decode()]
            with self.assertRaisesRegex(ci.Blocked, 'report frame byte limit'):
                self.probe.bounded(argv, 5, 'overflow', disk_check=False, report_pipe=pipe)
        witness = self.probe.report['dedicated_report_witness']
        self.assertTrue(witness['overflow'])
        self.assertFalse(witness['framing_complete'])
        self.assertEqual(witness['retained_bytes'], guest.REPORT_FRAME_LIMIT + 1)

    def test_aggregate_limit_timeout_and_held_writer_cleanup(self):
        with ci.ReportPipe(self.root) as pipe, mock.patch.object(ci, 'LOG_LIMIT', 1000), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ci.Blocked, 'aggregate diagnostic'):
                self.probe.bounded(self.writer(pipe, b'', b'x' * 2000), 5, 'aggregate overflow',
                                   disk_check=False, report_pipe=pipe)
        self.probe.log_used = 0
        with ci.ReportPipe(self.root) as pipe, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ci.Blocked, 'deadline exceeded'):
                self.probe.bounded(self.writer(pipe, b'', delay=3), .1, 'delayed timeout',
                                   disk_check=False, report_pipe=pipe)
        frame = guest.encode_report(self.report())
        with ci.ReportPipe(self.root) as pipe:
            started = time.monotonic()
            _, actual = self.probe.bounded(self.writer(pipe, frame, held=True), 5, 'held writer',
                                           disk_check=False, report_pipe=pipe)
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(actual, frame)
        time.sleep(3.1)
        self.assertFalse((self.root / 'escaped-writer').exists())

    def test_pipe_base_regular_file_symlink_and_wrong_mode_reject_safely(self):
        base = self.root / 'result'
        base.write_text('preserve')
        with self.assertRaises(ci.Blocked):
            with ci.ReportPipe(self.root):
                pass
        self.assertEqual(base.read_text(), 'preserve')
        base.unlink()
        victim = self.root / 'victim'
        victim.write_text('preserve')
        endpoint = self.root / 'result.out'
        endpoint.symlink_to(victim)
        with self.assertRaises(OSError):
            with ci.ReportPipe(self.root):
                pass
        self.assertEqual(victim.read_text(), 'preserve')
        self.assertFalse((self.root / 'result.in').exists())
        endpoint.unlink()
        old = os.umask(0o777)
        try:
            with self.assertRaises(ci.Blocked):
                with ci.ReportPipe(self.root):
                    pass
        finally:
            os.umask(old)
        self.assertFalse((self.root / 'result.in').exists())

    def test_real_pty_guest_writer_handles_short_writes_eagain_and_raw_framing(self):
        master, slave = pty.openpty()
        path = os.ttyname(slave)
        frame = guest.encode_report(self.report())
        received = bytearray()
        stopped = threading.Event()
        def read_terminal():
            while not stopped.is_set():
                if select.select([master], [], [], .05)[0]:
                    received.extend(os.read(master, 4096))
        reader = threading.Thread(target=read_terminal)
        reader.start()
        original = os.write
        calls = []
        def short(fd, data):
            calls.append(1)
            if len(calls) == 1:
                raise BlockingIOError()
            return original(fd, data[:17])
        try:
            with mock.patch.object(guest.os, 'write', side_effect=short):
                guest.write_report(self.report(), path=path, timeout=2)
            attributes = termios.tcgetattr(slave)
            self.assertEqual(attributes[4:6], [termios.B115200, termios.B115200])
            self.assertFalse(attributes[1] & termios.OPOST)
            limit = time.monotonic() + 1
            while len(received) < len(frame) and time.monotonic() < limit:
                time.sleep(.01)
            self.assertEqual(received, frame)
            self.assertGreater(len(calls), 2)
        finally:
            stopped.set()
            reader.join(timeout=1)
            os.close(master)
            os.close(slave)

    def test_real_terminal_backpressure_has_finite_deadline_without_console_fallback(self):
        master, slave = pty.openpty()
        report = self.report()
        report['diagnostics']['padding'] = 'x' * 60000
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                guest.write_report(report, path=os.ttyname(slave), timeout=.1)
            self.assertLess(time.monotonic() - started, 1)
        finally:
            os.close(master)
            os.close(slave)

    def test_guest_drain_call_is_inside_the_same_deadline(self):
        master, slave = pty.openpty()
        try:
            with mock.patch.object(guest.termios, 'tcdrain', side_effect=lambda fd: time.sleep(3)):
                with self.assertRaisesRegex(ValueError, 'deadline'):
                    guest.write_report(self.report(), path=os.ttyname(slave), timeout=.1)
        finally:
            os.close(master)
            os.close(slave)


if __name__ == '__main__':
    unittest.main()
