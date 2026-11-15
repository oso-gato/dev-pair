"""Real FIFOs/process/record failures with an explicit synthetic manager boundary."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap as b
import gptbox as g
import native_io as io
import fedora_ci_guest as guest
from native_io_fixture import install, manager
VERIFY_LABELS = io.verify_labels

UNIT = 'dev-pair-gptbox-' + 'a' * 64 + '.service'
PREFIX = ('/usr/bin/systemd-run', '--unit=' + UNIT, '--description=dev-pair-owned-' + UNIT, '--wait', '--collect', '--property=RuntimeMaxSec=30')


class NativeIOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = install(self, self.tmp.name)
        self.calls = []
        original = subprocess.Popen
        self.dispatch = patch.object(b.subprocess, 'Popen', side_effect=manager(original, self.calls))
        self.dispatch.start()
        self.addCleanup(self.dispatch.stop)

    def test_separate_fifo_stdout_stderr_launcher_is_not_forwarded_and_cleanup(self):
        run = b.Commands()
        text = run(*PREFIX, sys.executable, '-c', 'import os;os.write(1,b"application\\n");os.write(2,b"diagnostic\\n")')
        self.assertEqual(text, 'application\n')
        native = next(args for args in self.calls if args[0] == '/usr/bin/systemd-run')
        self.assertNotIn('--pipe', native)
        self.assertIn('--property=StandardInput=null', native)
        self.assertFalse(any('LimitFSIZE' in value for value in native))
        self.assertEqual(list((self.root / 'records').iterdir()), [])
        self.assertFalse((self.root / 'streams' / UNIT).exists())

    def test_guest_image_observation_retains_narrow_256k_transport_cap(self):
        source = Path(__file__).resolve().parents[1]
        script = 'import os,sys;os.write(1,b"x"*int(sys.argv[1]))'
        self.assertEqual(len(guest.native_image_capture(source, (*PREFIX, sys.executable, '-c', script, '262144'), 3)), 262144)
        with self.assertRaisesRegex(ValueError, 'Native image observation blocked'):
            guest.native_image_capture(source, (*PREFIX, sys.executable, '-c', script, '262145'), 3)
        self.assertEqual(list((self.root / 'records').iterdir()), [])

    def test_secret_zero_and_utf8_stdin_withheld_and_budget_precedes_launch(self):
        run = b.Commands()
        records = []
        run.diagnostic = records.append
        for value in ('', 'synthetic-secret', '\u00e9' * 8192):
            self.assertEqual(run(*PREFIX, sys.executable, '-c', 'import sys;v=sys.stdin.read();print(v);print(v,file=sys.stderr)', input_text=value), '')
        before = len(self.calls)
        with self.assertRaisesRegex(b.Blocked, 'stdin byte'):
            run(*PREFIX, sys.executable, '-c', 'pass', input_text='\u00e9' * 8193)
        self.assertEqual(len(self.calls), before)
        self.assertNotIn('synthetic-secret', json.dumps(records))
        self.assertNotIn('stdin_sha', json.dumps(records))
        self.assertEqual(list((self.root / 'records').iterdir()), [])

    def test_commands_and_probe_exact_combined_output_budgets(self):
        for run, maximum in ((b.Commands(), 1048576), (g.ProbeCommands(), 1048576)):
            self.assertEqual(len(run(*PREFIX, sys.executable, '-c', 'import os,sys;os.write(1,b"x"*int(sys.argv[1]))', str(maximum))), maximum)
            with self.assertRaises(b.Blocked):
                run(*PREFIX, sys.executable, '-c', 'import os,sys;os.write(1,b"x"*int(sys.argv[1]));os.write(2,b"y")', str(maximum))
        run = g.ProbeCommands()
        captures = []
        run.diagnostic = lambda buffers, status: captures.append((sum(map(len, buffers.values())), status))
        maximum = 4194304
        self.assertEqual(len(run(*PREFIX, sys.executable, '-c', 'import os,sys;os.write(1,b"x"*int(sys.argv[1]))', str(maximum))), maximum)
        with self.assertRaises(b.Blocked):
            run(*PREFIX, sys.executable, '-c', 'import os,sys;os.write(1,b"x"*int(sys.argv[1]));os.write(2,b"y")', str(maximum))
        self.assertEqual(captures[0], (maximum, 0))
        self.assertLessEqual(captures[-1][0], maximum)

    def test_exit_before_fifo_eof_and_never_reading_stdin_timeout(self):
        marker = Path(self.tmp.name) / 'late'
        script = 'import os,time,pathlib,sys;pid=os.fork();os._exit(0) if pid else None;time.sleep(.35);pathlib.Path(sys.argv[1]).write_text("escaped")'
        with self.assertRaises(b.Blocked):
            b.Commands()(*PREFIX, sys.executable, '-c', script, str(marker), timeout=.2)
        self.assertTrue(any(args[0] == '/usr/bin/systemd-run' for args in self.calls))
        time.sleep(.4)
        self.assertFalse(marker.exists())
        with self.assertRaises(b.Blocked):
            b.Commands()(*PREFIX, sys.executable, '-c', 'import time;time.sleep(5)', input_text='synthetic-secret', timeout=.2)
        self.assertEqual(list((self.root / 'records').iterdir()), [])

    def test_empty_output_launcher_bytes_count_but_never_become_application_stdout(self):
        original = subprocess.Popen
        base = manager(original, self.calls)
        def noisy(args, **kwargs):
            if args[0] == '/usr/bin/systemd-run':
                os.write(kwargs['stdout'], b'launcher-only-output')
                os.write(kwargs['stderr'], b'launcher-only-diagnostic')
            return base(args, **kwargs)
        with patch.object(b.subprocess, 'Popen', side_effect=noisy):
            self.assertEqual(b.Commands()(*PREFIX, sys.executable, '-c', 'pass'), '')
            self.assertEqual(b.Commands()(*PREFIX, sys.executable, '-c', 'print("application")'), 'application\n')
        self.assertEqual(list((self.root / 'records').iterdir()), [])

    def test_alternating_streams_exact_aggregate_and_unrelated_payload_file_unrestricted(self):
        script = 'import os;[(os.write(1,b"x"*1024),os.write(2,b"y"*1024)) for _ in range(512)]'
        self.assertEqual(len(b.Commands()(*PREFIX, sys.executable, '-c', script)), 524288)
        with self.assertRaises(b.Blocked):
            b.Commands()(*PREFIX, sys.executable, '-c', script + ';os.write(2,b"!")')
        target = Path(self.tmp.name) / 'unrelated-payload-file'
        b.Commands()(*PREFIX, sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"x"*(2*1024**2))', str(target))
        self.assertEqual(target.stat().st_size, 2097152)

    def test_consumer_death_breaks_real_fifo_writer_without_retained_reader(self):
        transport = io.NativeTransport(UNIT)
        transport.setup(None)
        transport.open_streams()
        original = subprocess.Popen
        process = original([sys.executable, '-c', 'import os,sys,time;f=os.open(sys.argv[1],os.O_WRONLY);print("ready",flush=True);time.sleep(.1)\ntry:os.write(f,b"x");raise SystemExit(3)\nexcept BrokenPipeError:print("reader-closed",flush=True)', str(transport.path / 'stdout')],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            self.assertTrue(selector.select(2))
            self.assertEqual(process.stdout.readline(), b'ready\n')
            transport.close()
            out, error = process.communicate(timeout=2)
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        self.assertEqual(process.returncode, 0)
        self.assertIn(b'reader-closed', out)
        io.NativeTransport.recover(UNIT)  # No native service was started in this fixture.

    def test_partial_cleanup_restarts_and_foreign_or_conflicting_stdio_is_rejected(self):
        transport = io.NativeTransport(UNIT)
        transport.setup(b'synthetic-secret')
        unlink = Path.unlink
        def fail(path, *args, **kwargs):
            if path.name == 'stderr':
                raise OSError('injected cleanup failure')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail):
            with self.assertRaises(OSError):
                io.NativeTransport.recover(UNIT)
        self.assertTrue(json.loads(transport.record.read_text())['cleanup_started'])
        io.NativeTransport.recover(UNIT)
        self.assertFalse(transport.path.exists())
        with self.assertRaises(b.Blocked):
            b.Commands()(*PREFIX, '--property=StandardOutput=journal', sys.executable, '-c', 'pass')
        with patch.object(b.Commands, '__call__', return_value='Description=foreign\nUser=other\nLoadState=loaded\nActiveState=inactive\n') as observed:
            with self.assertRaises(b.Blocked):
                b.Commands.reconcile_native(PREFIX, {})
            self.assertEqual(observed.call_count, 1)

    def test_persist_before_secret_and_partial_proof_collision_replacements_preserved(self):
        transport = io.NativeTransport(UNIT)
        original = transport.save
        def save(first=False):
            if 'stdin' in transport.state['nodes']:
                self.assertEqual((transport.path / 'stdin').read_bytes(), b'')
            original(first)
        with patch.object(transport, 'save', side_effect=save):
            transport.setup(b'synthetic-secret')
        raw = transport.record.read_text()
        self.assertNotIn('synthetic-secret', raw)
        with self.assertRaises(FileExistsError):
            io.NativeTransport(UNIT).setup(None)
        replacement = transport.path / 'foreign'
        replacement.write_text('foreign preserved')
        with self.assertRaises(ValueError):
            io.NativeTransport.recover(UNIT)
        self.assertEqual(replacement.read_text(), 'foreign preserved')
        replacement.unlink()
        stdout = transport.path / 'stdout'
        stdout.unlink()
        stdout.symlink_to(replacement)
        with self.assertRaises(ValueError):
            io.NativeTransport.recover(UNIT)
        self.assertTrue(stdout.is_symlink())

    def test_real_controller_sigkill_retains_proven_input_until_exact_restart_recovery(self):
        # The subprocess uses only this synthetic ownership fixture; no native
        # unit or credential is started. Persistence and SIGKILL are real.
        code = 'import sys,os,time;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import native_io as io;io.ROOT=Path(sys.argv[2]);io.STREAM_ROOT=io.ROOT/"streams";io.PROFILE_ROOT=io.ROOT/"system";io.protected_directory=lambda p:Path(p);io.guard_root=lambda:None;t=io.NativeTransport(sys.argv[3]);t.setup(b"synthetic-secret");print("ready",flush=True);time.sleep(10)'
        original = subprocess.Popen
        process = original([sys.executable, '-c', code, str(Path(io.__file__).parent), str(self.root), UNIT],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            self.assertTrue(selector.select(2))
            self.assertEqual(process.stdout.readline(), b'ready\n')
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            directory = self.root / 'streams' / UNIT
            self.assertEqual((directory / 'stdin').read_bytes(), b'synthetic-secret')
            self.assertNotIn('synthetic-secret', (self.root / 'records' / (UNIT + '.json')).read_text())
            io.NativeTransport.recover(UNIT)  # This test knows no unit was launched.
            self.assertFalse(directory.exists())
        finally:
            selector.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            process.stdout.close()
            process.stderr.close()

    def test_crash_restart_known_proof_cleanup_and_unproven_node_retention(self):
        transport = io.NativeTransport(UNIT)
        transport.setup(b'synthetic-secret')
        io.NativeTransport.recover(UNIT)
        self.assertFalse(transport.path.exists())
        partial = io.NativeTransport(UNIT)
        original = partial.save
        def interrupted(first=False):
            if 'stdin' in partial.state['nodes']:
                raise OSError('injected ownership-save failure')
            original(first)
        with patch.object(partial, 'save', side_effect=interrupted):
            with self.assertRaises(OSError):
                partial.setup(b'must-not-be-written')
        self.assertEqual((partial.path / 'stdin').read_bytes(), b'')
        with self.assertRaises(ValueError):
            io.NativeTransport.recover(UNIT)
        self.assertTrue(partial.record.exists())

    def test_positive_helper_completion_required_even_for_allowed_startup_failure_codes(self):
        from native_io_fixture import launch_payload
        original = subprocess.Popen
        base = manager(original, self.calls)
        for status in (1, 4, 125, 250):
            # A real service/launcher that never reaches the helper cannot emit
            # terminal evidence, even when its number was accepted by a caller.
            def fail_start(args, **kwargs):
                if args[0] == '/usr/bin/systemd-run':
                    args = tuple(value for value in args if value != '-I')
                    return launch_payload(original, args, kwargs, [sys.executable, '-c', 'raise SystemExit(' + str(status) + ')'])
                return base(args, **kwargs)
            with patch.object(b.subprocess, 'Popen', side_effect=fail_start), self.assertRaises(b.Blocked):
                b.Commands()(*PREFIX, sys.executable, '-c', 'pass', ok=(status,))
            self.assertEqual(list((self.root / 'records').iterdir()), [])
        for status in (1, 4, 125):
            records = []
            run = b.Commands(); run.metadata_diagnostic = records.append
            self.assertEqual(run(*PREFIX, sys.executable, '-c', 'raise SystemExit(' + str(status) + ')', ok=(status,)), '')
            self.assertTrue(records[-1]['relay_verified'])
            self.assertEqual(records[-1]['native_exit_status'], status)
            self.assertEqual(records[-1]['relay']['status'], status)
            self.assertEqual(records[-1]['relay']['uid'], os.getuid())
            self.assertEqual(records[-1]['relay']['helper'], __import__('hashlib').sha256(Path(io.relay.__file__).read_bytes()).hexdigest())

    def test_legacy_layout_and_unknown_version_are_preserved(self):
        legacy = self.root / UNIT
        legacy.mkdir(mode=0o700)
        (legacy / 'stdin').write_bytes(b'NONCREDENTIAL')
        with self.assertRaisesRegex(ValueError, 'Legacy'):
            io.NativeTransport(UNIT).setup(None)
        with self.assertRaisesRegex(ValueError, 'Legacy'):
            io.NativeTransport.recover(UNIT)
        self.assertEqual((legacy / 'stdin').read_bytes(), b'NONCREDENTIAL')
        (legacy / 'stdin').unlink(); legacy.rmdir()
        transport = io.NativeTransport(UNIT); transport.setup(None)
        state = json.loads(transport.record.read_text()); state['version'] = 1
        transport.record.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, 'Invalid transport ownership record'):
            io.NativeTransport.recover(UNIT)
        self.assertTrue(transport.path.exists())
        state['version'] = 3; transport.record.write_text(json.dumps(state))
        io.NativeTransport.recover(UNIT)

    def test_exact_expected_and_observed_standard_labels_both_required(self):
        # Kernel labels cannot be set by this unprivileged local test. Exercise
        # exact checks with injected observations, never claim Fedora evidence.
        transport = io.NativeTransport(UNIT); transport.setup(None)
        class Control:
            def _call(self, *args, **kwargs):
                return (io.EXPECTED_CONTEXT + '\n') * (len(args) - 2)
        with patch.object(io.os, 'getxattr', return_value=(io.EXPECTED_CONTEXT + '\0').encode()):
            VERIFY_LABELS(transport, Control(), 1)
        with patch.object(io.os, 'getxattr', return_value=b'system_u:object_r:var_run_t:s0\0'):
            with self.assertRaisesRegex(ValueError, 'context mismatch'):
                VERIFY_LABELS(transport, Control(), 1)
        io.NativeTransport.recover(UNIT)

    def test_finite_native_start_and_active_timers_share_original_stricter_budget(self):
        original = subprocess.Popen
        base = manager(original, self.calls)
        observed = []
        def delayed(args, **kwargs):
            if args[0] == '/usr/bin/systemd-run':
                observed.append(args)
                time.sleep(.04)  # Real startup delay before the exact helper.
            return base(args, **kwargs)
        prefix = tuple('--property=RuntimeMaxSec=0.8' if value.startswith('--property=RuntimeMaxSec=') else value for value in PREFIX)
        started = time.monotonic()
        with patch.object(b.subprocess, 'Popen', side_effect=delayed):
            self.assertEqual(b.Commands()(*prefix, sys.executable, '-c', 'print("bounded")', timeout=2), 'bounded\n')
        native = observed[0]
        startup = float(next(value.rsplit('=', 1)[1][:-1] for value in native if value.startswith('--property=TimeoutStartSec=')))
        active = float(next(value.rsplit('=', 1)[1][:-1] for value in native if value.startswith('--property=RuntimeMaxSec=')))
        self.assertGreaterEqual(startup, .001)
        self.assertGreaterEqual(active, .001)
        self.assertLessEqual(startup + active, .8)
        self.assertLessEqual(startup, 5)
        self.assertNotIn('--seconds', native)
        self.assertLessEqual(float(native[native.index('--deadline') + 1]), started + .8)
        for supplied in ('--property=TimeoutStartSec=infinity', '--property=TimeoutStartSec=0'):
            with self.assertRaises(b.Blocked):
                b.Commands()(*PREFIX, supplied, sys.executable, '-c', 'pass')
        before = len(self.calls)
        tiny = tuple('--property=RuntimeMaxSec=0.001' if value.startswith('--property=RuntimeMaxSec=') else value for value in PREFIX)
        with self.assertRaises(b.Blocked):
            b.Commands()(*tiny, sys.executable, '-c', 'pass')
        self.assertFalse(any(args[0] == '/usr/bin/systemd-run' for args in self.calls[before:]))

    def test_real_helper_signal_remains_failure_when_manager_maps_status_to_success(self):
        from native_io_fixture import launch_payload
        original = subprocess.Popen
        base = manager(original, self.calls)
        for mapped in (0, 255):
            def mapped_manager(args, **kwargs):
                if args[0] != '/usr/bin/systemd-run':
                    return base(args, **kwargs)
                child = launch_payload(original, args, kwargs, ())
                class Manager:
                    # Transport process descriptors/pid are real; only manager
                    # exit translation is injected from v259's source contract.
                    def __getattr__(self, name):
                        return getattr(child, name)
                    @property
                    def returncode(self):
                        return None if child.returncode is None else mapped
                    def poll(self):
                        result = child.poll()
                        return None if result is None else mapped
                    def wait(self, timeout=None):
                        child.wait(timeout=timeout)
                        return mapped
                return Manager()
            run = b.Commands(); records = []; run.metadata_diagnostic = records.append
            with patch.object(b.subprocess, 'Popen', side_effect=mapped_manager), self.assertRaises(b.Blocked):
                run(*PREFIX, sys.executable, '-c', 'import os,signal;os.kill(os.getpid(),signal.SIGTERM)', ok=(0, 255, -15))
            self.assertFalse(records[-1]['accepted_exit'])
            self.assertEqual(records[-1]['native_exit_status'], mapped)
            self.assertEqual(records[-1]['relay']['status'], -15)
            self.assertEqual(list((self.root / 'records').iterdir()), [])

    def test_controller_journal_nodes_match_actual_helper_fds_before_payload(self):
        original = subprocess.Popen
        token = 'r.verify_fds=lambda value:setattr(value,"diagnostic_ready",True);'
        # Preserve actual consumer FD verification; inject only root ownership
        # because local named FIFOs belong to this unprivileged test user.
        injection = ('import types;original_stat=r.os.fstat;'
                     'r.os.fstat=lambda fd:types.SimpleNamespace(**{key:getattr(original_stat(fd),key) for key in '
                     '("st_mode","st_dev","st_ino","st_nlink","st_size","st_rdev")},st_uid=0);')
        launches = []
        def native_process(args, **kwargs):
            args = list(args)
            if len(args) > 2 and args[1] == '-c' and token in args[2]:
                args[2] = args[2].replace(token, injection)
            return original(args, **kwargs)
        base = manager(native_process, self.calls)
        def observed(args, **kwargs):
            if args[0] == '/usr/bin/systemd-run':
                state = json.loads((self.root / 'records' / (UNIT + '.json')).read_text())
                for name, node in state['nodes'].items():
                    option = '--' + name + '-node'
                    self.assertEqual(args[args.index(option)+1], str(node['device'])+':'+str(node['inode']))
                self.assertEqual('--stdin-node' in args, 'stdin' in state['nodes'])
                launches.append(args)
            return base(args, **kwargs)
        for index, data in enumerate((None, '', 'NONCREDENTIAL')):
            effect = Path(self.tmp.name) / ('fd-effect-' + str(index))
            script = 'import sys,pathlib;data=sys.stdin.buffer.read();pathlib.Path(sys.argv[1]).write_text(str(len(data)));print("executed")'
            with patch.object(b.subprocess, 'Popen', side_effect=observed):
                result = b.Commands()(*PREFIX, sys.executable, '-c', script, str(effect), input_text=data)
            self.assertEqual(result, 'executed\n' if data is None else '')
            self.assertEqual(effect.read_text(), str(len(data or '')))
        self.assertEqual(len(launches), 3)
