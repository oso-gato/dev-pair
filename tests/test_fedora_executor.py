"""Native-executor source/FD contracts only; no Fedora or systemd service execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fedora_ci as ci
import fedora_ci_guest as guest


def inputs():
    return {**{key: 'c' * length for key, length in guest.INPUT_LENGTHS.items()}, 'source_sha': 'a' * 40, 'payload_bytes': 123}


def mask_fixture():
    return {'path': str(guest.SERVICE_MASK), 'device': 1, 'inode': 2, 'sha256': guest.EMPTY_SHA256}


class FedoraExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_rendered_unit_null_stdio_direct_argv_no_cloud_final_dependency_and_bounds(self):
        expected = inputs()
        text = guest.service_unit(expected, 'b' * 64)
        self.assertIn('Type=exec\n', text)
        self.assertIn('User=root\nGroup=root', text)
        self.assertIn('RuntimeMaxSec=2445s', text)
        self.assertIn('TimeoutStopSec=5s', text)
        self.assertIn('KillMode=control-group', text)
        self.assertIn('Restart=no', text)
        for setting in ('TimeoutStopFailureMode=kill', 'SendSIGKILL=yes', 'FinalKillSignal=SIGKILL'):
            self.assertIn(setting, text)
        for stream in ('Input', 'Output', 'Error'):
            self.assertIn('Standard' + stream + '=null', text)
        for forbidden in ('cloud-final', 'SELinuxContext', 'runcon', 'setenforce', '/bin/sh', '--pipe', 'EnvironmentFile', 'PassEnvironment'):
            self.assertNotIn(forbidden, text)
        argv = shlex.split(next(line[10:] for line in text.splitlines() if line.startswith('ExecStart=')))
        self.assertEqual(argv[:2], ['/usr/bin/env', '-i'])
        self.assertIn('-I', argv)
        self.assertEqual(json.loads(argv[argv.index('--inputs-json') + 1]), expected)
        self.assertIn('--native-service', argv)
        self.assertLessEqual(180 + guest.SERVICE_SECONDS + guest.SERVICE_STOP_SECONDS, ci.VM_SECONDS)
        seed = ci.seed_data(expected['source_sha'], expected, 'b' * 64)
        self.assertIn('--stage-systemd', seed)
        self.assertNotIn('--native-service', seed)

    def test_real_control_child_inherits_only_null_stdio_no_secret_environment_or_extra_fd(self):
        output = self.root / 'fd-observation.json'
        inherited = os.open(self.root / 'private-canary', os.O_WRONLY | os.O_CREAT, 0o600)
        os.set_inheritable(inherited, True)
        code = ('import os,json,pathlib,sys; '
                'r={"stdio":[os.readlink("/proc/self/fd/"+str(i)) for i in range(3)],'
                '"extra":os.path.exists("/proc/self/fd/"+sys.argv[2]),"secret":os.getenv("PARENT_SECRET")};'
                'pathlib.Path(sys.argv[1]).write_text(json.dumps(r))')
        try:
            with mock.patch.dict(os.environ, {'PARENT_SECRET': 'synthetic-environment-sentinel'}):
                guest.executor_control([sys.executable, '-c', code, str(output), str(inherited)], time.monotonic() + 5)
        finally:
            os.close(inherited)
        observed = json.loads(output.read_text())
        self.assertEqual(observed['stdio'], ['/dev/null'] * 3)
        self.assertFalse(observed['extra'])
        self.assertIsNone(observed['secret'])
        with self.assertRaises(ValueError):
            guest.executor_control([sys.executable, '-c', 'raise SystemExit(9)'], time.monotonic() + 2)

    def test_staging_rejects_nonroot_and_source_mismatch_before_side_effects(self):
        with mock.patch.object(guest.os, 'getuid', return_value=1000), mock.patch.object(guest.os, 'geteuid', return_value=1000), \
                mock.patch.object(guest, 'executor_file') as write:
            with self.assertRaisesRegex(ValueError, 'root'):
                guest.stage_executor(inputs(), 'b' * 64)
            write.assert_not_called()
        with mock.patch.object(guest.os, 'getuid', return_value=0), mock.patch.object(guest.os, 'geteuid', return_value=0), \
                mock.patch.object(guest, 'executor_file') as write:
            with self.assertRaisesRegex(guest.ExecutorStagingError, 'source-identity'):
                guest.stage_executor(inputs(), 'b' * 64)
            write.assert_not_called()

    def test_real_exclusive_file_creation_never_follows_unknown_preexisting_path(self):
        # Real non-root ownership denial or root-owned protected path semantics;
        # no local root service or host directory is created.
        target = self.root / 'unknown'
        target.symlink_to(self.root / 'outside')
        with self.assertRaises((ValueError, FileExistsError)):
            guest.executor_file(target, b'never publish', 0o444)
        self.assertFalse((self.root / 'outside').exists())

    def test_staging_order_nonblocking_start_requires_observed_ack_and_restores_standard_contexts(self):
        writes, calls = [], []
        def write(path, data, mode):
            writes.append((path, data, mode))
        def control(args, end):
            calls.append(args)
        with mock.patch.object(guest.os, 'getuid', return_value=0), mock.patch.object(guest.os, 'geteuid', return_value=0), \
                mock.patch.object(guest, 'executor_file', side_effect=write), mock.patch.object(guest, 'executor_control', side_effect=control), \
                mock.patch.object(guest, 'observe_executor_start', side_effect=lambda end: calls.append(['ack'])), \
                mock.patch.object(guest, 'mask_identity', return_value=mask_fixture()), \
                mock.patch.object(guest.pathlib.Path, 'read_text', return_value='system_u:system_r:cloud_init_t:s0\x00'):
            request = guest.stage_executor(inputs(), guest.digest(Path(guest.__file__)))
        self.assertEqual([row[2] for row in writes], [0o444, 0o644, 0o600, 0o644])
        self.assertEqual(calls[0][0], '/usr/sbin/restorecon')
        self.assertEqual(calls[1], ['/usr/bin/systemctl', 'daemon-reload'])
        self.assertEqual(calls[2], ['/usr/bin/systemctl', '--no-block', 'start', guest.SERVICE_NAME])
        self.assertEqual(calls[3], ['ack'])
        self.assertEqual(request['unit_sha256'], hashlib.sha256(writes[3][1]).hexdigest())
        self.assertEqual(writes[1][1], b'')
        self.assertEqual(request['mask'], mask_fixture())
        self.assertIn(str(guest.SERVICE_MASK), calls[0])
        self.assertIn(str(guest.SERVICE_MASK.parent), calls[0])
        self.assertEqual(request['guest_sha256'], hashlib.sha256(writes[0][1]).hexdigest())
        self.assertLessEqual(request['admission_deadline'] - time.monotonic(), guest.GUEST_ADMISSION_SECONDS)

    def test_selected_startup_query_uses_regular_output_and_reports_exec_failure_without_passing_frame(self):
        request = self.root / 'request.json'
        def failed(args, **kwargs):
            self.assertIn('--property=ExecMainStatus', args)
            self.assertNotIn('journal', ' '.join(args))
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertTrue(stat.S_ISREG(os.fstat(kwargs['stdout'].fileno()).st_mode))
            kwargs['stdout'].write(b'LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainStatus=203\n')
            kwargs['stdout'].flush()
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(guest, 'SERVICE_REQUEST', request), mock.patch.object(guest.subprocess, 'run', side_effect=failed):
            with self.assertRaises(guest.ExecutorStartupError) as caught:
                guest.observe_executor_start(time.monotonic() + 10)
        self.assertEqual(caught.exception.fields['ExecMainStatus'], '203')
        self.assertEqual(caught.exception.query_exit_status, 0)
        argv = ['guest.py', '--stage-systemd', '--source', 'a' * 40, '--inputs-json', json.dumps(inputs()), '--guest-sha256', 'b' * 64]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(guest, 'stage_executor', side_effect=caught.exception), \
                mock.patch.object(guest, 'write_startup_failure') as witness, mock.patch.object(guest, 'write_report') as report:
            guest.main()
        report.assert_not_called()
        self.assertEqual(witness.call_args.args[0]['outcome'], 'blocked')
        self.assertEqual(witness.call_args.args[0]['startup_properties']['ExecMainStatus'], '203')

    def staging_fixture(self):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.object(guest, 'mask_identity', return_value=mask_fixture()))
        stack.enter_context(mock.patch.object(guest.os, 'getuid', return_value=0))
        stack.enter_context(mock.patch.object(guest.os, 'geteuid', return_value=0))
        stack.enter_context(mock.patch.object(guest.pathlib.Path, 'read_text', return_value='system_u:system_r:cloud_init_t:s0\x00'))
        self.addCleanup(stack.close)
        return stack

    def test_real_missing_control_executable_records_fixed_step_and_errno_without_exception_text(self):
        self.staging_fixture()
        actual_control = guest.executor_control
        def missing(args, end):
            actual_control([str(self.root / 'synthetic-secret-not-an-executable')], end)
        with mock.patch.object(guest, 'executor_file'), mock.patch.object(guest, 'executor_control', side_effect=missing):
            with self.assertRaises(guest.ExecutorStagingError) as caught:
                guest.stage_executor(inputs(), guest.digest(Path(guest.__file__)))
        self.assertEqual(caught.exception.fields['step'], 'restore-contexts')
        self.assertEqual(caught.exception.fields['kind'], 'os-error')
        self.assertEqual(caught.exception.fields['errno'], 2)
        self.assertNotIn('synthetic-secret', json.dumps(caught.exception.fields))

    def test_real_control_exit_and_timeout_keep_status_but_discard_output_and_arguments(self):
        for code, kind, status in (("print('synthetic-secret');raise SystemExit(7)", 'control-exit', 7),
                                   ("import time;print('synthetic-secret');time.sleep(2)", 'timeout', None)):
            started = time.monotonic()
            try:
                guest.executor_control([sys.executable, '-c', code], started + .1)
            except (ValueError, subprocess.SubprocessError) as error:
                classified = guest.ExecutorStagingError('reload-manager', error, started)
            else:
                self.fail('Real bounded control did not reject')
            self.assertEqual(classified.fields['kind'], kind)
            self.assertEqual(classified.fields['exit_status'], status)
            self.assertLess(time.monotonic() - started, 1)
            self.assertNotIn('synthetic-secret', json.dumps(classified.fields))

    def test_real_untrusted_parent_metadata_preserves_denial_without_raw_path(self):
        self.staging_fixture()
        with mock.patch.object(guest, 'SERVICE_SCRIPT', self.root / 'guest.py'):
            with self.assertRaises(guest.ExecutorStagingError) as caught:
                guest.stage_executor(inputs(), guest.digest(Path(guest.__file__)))
        metadata = caught.exception.fields
        self.assertEqual(metadata['step'], 'install-script')
        self.assertEqual(metadata['kind'], 'validation')
        self.assertIn('path_metadata', metadata)
        self.assertNotIn(str(self.root), json.dumps(metadata))
        self.assertFalse((self.root / 'guest.py').exists())

    def test_fixed_public_control_stderr_uses_real_bounded_regular_file_and_ordinary_commands_stay_withheld(self):
        original = subprocess.run
        request = self.root / 'request.json'
        code = "import os; os.write(2,b'fixed public control failure\\n'+b'x'*900);raise SystemExit(7)"
        def real_child(args, **kwargs):
            self.assertTrue(stat.S_ISREG(os.fstat(kwargs['stderr'].fileno()).st_mode))
            self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
            return original([sys.executable, '-c', code], **kwargs)
        with mock.patch.object(guest, 'SERVICE_REQUEST', request), mock.patch.object(guest.subprocess, 'run', side_effect=real_child):
            with self.assertRaises(guest.ExecutorControlError) as caught:
                guest.executor_control(['/usr/bin/systemctl', 'daemon-reload'], time.monotonic() + 5)
        diagnostic = caught.exception.public_diagnostic
        self.assertEqual(caught.exception.status, 7)
        self.assertEqual(diagnostic['captured_bytes'], 929)
        self.assertTrue(diagnostic['tail_truncated'])
        self.assertLessEqual(len(diagnostic['tail']), 768)
        self.assertEqual(list(self.root.iterdir()), [])
        error = guest.ExecutorStagingError('reload-manager', caught.exception, time.monotonic())
        self.assertEqual(error.fields['control_diagnostic'], diagnostic)

    def test_real_empty_mask_snapshot_rejects_content_mode_links_and_nonregular_inputs(self):
        path = self.root / '10-timeout-abort.conf'
        path.write_bytes(b'')
        path.chmod(0o644)
        identity, owner = guest.read_mask_file(path)
        self.assertEqual(owner, os.geteuid())
        self.assertEqual(identity['inode'], path.stat().st_ino)
        self.assertEqual(identity['sha256'], guest.EMPTY_SHA256)
        path.write_text('unreviewed vendor or replacement content')
        with self.assertRaises(ValueError):
            guest.read_mask_file(path)
        path.write_bytes(b'')
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            guest.read_mask_file(path)
        path.chmod(0o644)
        linked = self.root / 'hardlink'
        os.link(path, linked)
        with self.assertRaises(ValueError):
            guest.read_mask_file(path)
        linked.unlink()
        alias = self.root / 'alias'
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            guest.read_mask_file(alias)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o644)
        started = time.monotonic()
        for target in (fifo, Path('/dev/null')):
            with self.assertRaises(ValueError):
                guest.read_mask_file(target)
        self.assertLess(time.monotonic() - started, .2)
        with mock.patch.object(guest, 'SERVICE_MASK', path):
            # Actual user-owned or unsafe /tmp ancestors cannot become an
            # admitted root-owned mask merely through an empty-file digest.
            with self.assertRaisesRegex(ValueError, 'ownership/protection'):
                guest.mask_identity()

    def test_real_mask_snapshot_detects_path_replacement_and_records_exact_inode(self):
        path, replacement = self.root / 'mask', self.root / 'replacement'
        for target in (path, replacement):
            target.write_bytes(b'')
            target.chmod(0o644)
        original, _ = guest.read_mask_file(path)
        actual_read = os.read
        def replace(fd, count):
            data = actual_read(fd, count)
            os.replace(replacement, path)
            return data
        with mock.patch.object(guest.os, 'read', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'path identity changed'):
                guest.read_mask_file(path)
        current, _ = guest.read_mask_file(path)
        self.assertNotEqual(current['inode'], original['inode'])
        actual_read = os.read
        def change_mode(fd, count):
            data = actual_read(fd, count)
            os.chmod(path, 0o600)
            return data
        with mock.patch.object(guest.os, 'read', side_effect=change_mode):
            with self.assertRaisesRegex(ValueError, 'path identity changed'):
                guest.read_mask_file(path)
        path.chmod(0o644)
        with mock.patch.object(guest, 'SERVICE_MASK', path):
            guest.validate_mask_record(current)
            for change in ({'path': '/usr/lib/systemd/system/service.d/10-timeout-abort.conf'}, {'sha256': 'f' * 64},
                           {'device': True}, {'inode': 0}, {'unknown': 1}):
                with self.assertRaises(ValueError):
                    guest.validate_mask_record({**current, **change})

    def test_known_long_mask_path_is_lossless_in_failure_witness_and_executor_proof_rejects_substitution(self):
        self.assertGreater(len(str(guest.SERVICE_MASK)), 64)
        self.assertEqual(guest.startup_property_value('DropInPaths', str(guest.SERVICE_MASK)), str(guest.SERVICE_MASK))
        self.assertEqual(guest.startup_property_value('FragmentPath', str(guest.SERVICE_UNIT)), str(guest.SERVICE_UNIT))
        from test_fedora_prepare import executor_fixture
        expected = inputs()
        proof = executor_fixture(expected, 'b' * 64)
        guest.validate_executor(proof, expected, 'b' * 64)
        for change in ({'path': '/usr/lib/systemd/system/service.d/10-timeout-abort.conf'}, {'sha256': 'f' * 64}, {'inode': False}):
            bad = copy.deepcopy(proof)
            bad['mask'].update(change)
            with self.assertRaises(ValueError):
                guest.validate_executor(bad, expected, 'b' * 64)

    def test_real_scaled_reload_allocation_and_shared_deadline_without_general_timeout_override(self):
        original_run, original_remaining = subprocess.run, guest.remaining
        allocations = []
        marker = self.root / 'completed'
        def scale(end, maximum):
            allocations.append(maximum)
            return original_remaining(end, maximum / 100)
        def child(args, **kwargs):
            # Preserve the actual computed timeout and FD/cleanup contract;
            # substitute a harmless local process for the fixed system command.
            return original_run([sys.executable, '-c',
                                 "import pathlib,time,sys;print('synthetic-secret');time.sleep(.12);pathlib.Path(sys.argv[1]).write_text('completed')",
                                 str(marker)], **kwargs)
        with mock.patch.object(guest, 'SERVICE_REQUEST', self.root / 'request.json'), \
                mock.patch.object(guest, 'remaining', side_effect=scale), mock.patch.object(guest.subprocess, 'run', side_effect=child):
            started = time.monotonic()
            guest.executor_control(['/usr/bin/systemctl', 'daemon-reload'], started + 2)
            self.assertTrue(marker.exists())
            self.assertGreater(time.monotonic() - started, .1)
            marker.unlink()
            for args, seconds in ((['/usr/bin/systemctl', '--no-block', 'start', guest.SERVICE_NAME], 2),
                                  (['/usr/bin/systemctl', 'daemon-reload', '--extra'], 2),
                                  (['systemctl', 'daemon-reload'], 2),
                                  (['/usr/bin/systemctl', 'daemon-reload'], .04)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    guest.executor_control(args, time.monotonic() + seconds)
            self.assertEqual(allocations, [30, 5, 5, 5, 30])
        time.sleep(.15)
        self.assertFalse(marker.exists(), 'Timed-out real child performed a late effect')
        self.assertEqual(list(self.root.iterdir()), [], 'Diagnostic anonymous file leaked')

    def test_fixed_control_real_child_cannot_grow_diagnostic_beyond_native_file_ceiling(self):
        original = subprocess.run
        def oversized(args, **kwargs):
            return original([sys.executable, '-c', "import os;os.write(2,b'x'*10000);raise SystemExit(7)"], **kwargs)
        with mock.patch.object(guest, 'SERVICE_REQUEST', self.root / 'request.json'), mock.patch.object(guest.subprocess, 'run', side_effect=oversized):
            with self.assertRaises(guest.ExecutorControlError) as caught:
                guest.executor_control(['/usr/bin/systemctl', 'daemon-reload'], time.monotonic() + 5)
        self.assertEqual(caught.exception.public_diagnostic['captured_bytes'], 4096)
        self.assertTrue(caught.exception.public_diagnostic['capture_limit_reached'])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_main_staging_failure_keeps_exact_fixed_operation_and_no_sensitive_exception(self):
        self.staging_fixture()
        argv = ['guest.py', '--stage-systemd', '--source', 'a' * 40, '--inputs-json', json.dumps(inputs()),
                '--guest-sha256', guest.digest(Path(guest.__file__))]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(guest, 'executor_file', side_effect=PermissionError(13, 'synthetic-secret', '/private/synthetic-secret')), \
                mock.patch.object(guest, 'write_startup_failure') as capture, mock.patch.object(guest, 'write_report') as report:
            guest.main()
        value = capture.call_args.args[0]
        guest.validate_startup_witness(value, inputs(), argv[-1])
        self.assertEqual(value['staging']['step'], 'install-script')
        self.assertEqual(value['staging']['errno'], 13)
        self.assertNotIn('synthetic-secret', json.dumps(value))
        report.assert_not_called()

    def test_maximum_escaped_selected_failure_witness_fits_unchanged_console_cap(self):
        expected = inputs()
        error = guest.ExecutorStartupError({key: guest.startup_property_value(key, '"' * 64) for key in guest.startup_properties()}, 0)
        failure = guest.ExecutorStagingError('observe-startup', error, time.monotonic() - 60)
        failure.fields['path_metadata'] = {'position': 15, 'uid': 4294967295, 'gid': 4294967295,
                                           'mode': 0o7777, 'type': stat.S_IFDIR, 'bytes': 2 ** 63 - 1}
        value = {'version': 1, 'operation': 'native-executor-staging', 'outcome': 'blocked',
                 'source_sha': expected['source_sha'], 'controller_sha256': expected['controller_sha256'],
                 'guest_sha256': 'b' * 64, 'requested_unit_sha256': hashlib.sha256(guest.service_unit(expected, 'b' * 64).encode()).hexdigest(),
                 'staging': failure.fields, 'startup_properties': failure.startup}
        guest.validate_startup_witness(value, expected, 'b' * 64)
        data = guest.STARTUP_MARKER + json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
        self.assertLessEqual(len(data), 4096)
        self.assertEqual(ci.startup_witness(data, expected, 'b' * 64)['diagnostic'], value)
        value['startup_properties']['DropInPaths'] = str(guest.SERVICE_MASK)
        data = guest.STARTUP_MARKER + json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
        self.assertLessEqual(len(data), 4096)
        self.assertEqual(ci.startup_witness(data, expected, 'b' * 64)['diagnostic']['startup_properties']['DropInPaths'], str(guest.SERVICE_MASK))

    def test_failure_witness_survives_shutdown_tail_and_cannot_supply_a_report(self):
        expected = inputs()
        failure = guest.ExecutorStagingError('restore-contexts', FileNotFoundError(2, 'synthetic-secret'), time.monotonic())
        value = {'version': 1, 'operation': 'native-executor-staging', 'outcome': 'blocked',
                 'source_sha': expected['source_sha'], 'controller_sha256': expected['controller_sha256'],
                 'guest_sha256': 'b' * 64, 'requested_unit_sha256': hashlib.sha256(guest.service_unit(expected, 'b' * 64).encode()).hexdigest(),
                 'staging': failure.fields, 'startup_properties': failure.startup}
        encoded = guest.STARTUP_MARKER + json.dumps(value).encode() + b'\r\n'
        console = b'boot\n' + encoded + b'shutdown\n' * 5000
        captured = ci.startup_witness(console, expected, 'b' * 64)
        self.assertEqual(captured['availability'], 'validated-failure-only')
        self.assertEqual(captured['diagnostic'], value)
        self.assertEqual(__import__('base64').b64decode(captured['retained_base64']), encoded)
        self.assertNotIn(guest.STARTUP_MARKER, console[-24000:])
        with self.assertRaises(ci.Blocked):
            ci.parse_serial(encoded, expected['source_sha'], 'b' * 64, expected)
        for bad in (console + encoded, encoded[:50], encoded.replace(b'"blocked"', b'"pass"'),
                    encoded.replace(expected['source_sha'].encode(), b'f' * 40), guest.STARTUP_MARKER + b'x' * 4096 + b'\n', guest.STARTUP_MARKER + b'[' * 1500 + b']' * 1500 + b'\n'):
            self.assertNotEqual(ci.startup_witness(bad, expected, 'b' * 64)['availability'], 'validated-failure-only')
        self.assertNotIn('synthetic-secret', json.dumps(captured))

    def test_captured_proc_context_terminator_is_normalized_but_malformed_or_cloud_init_proof_rejects(self):
        self.assertEqual(guest.observed_context('system_u:system_r:cloud_init_t:s0\x00'), 'system_u:system_r:cloud_init_t:s0')
        self.assertEqual(guest.observed_context('system_u:system_r:unconfined_service_t:s0\x00'), 'system_u:system_r:unconfined_service_t:s0')
        for value in ('malformed', 'system_u:system_r:service_t:s0\x00extra', 'system_u:system_r:service_t:s0\nextra'):
            with self.assertRaises(ValueError):
                guest.observed_context(value)
        from test_fedora_prepare import executor_fixture
        expected = inputs()
        proof = executor_fixture(expected, 'b' * 64)
        guest.validate_executor(proof, expected, 'b' * 64)
        for key, value in (('context', 'system_u:system_r:cloud_init_t:s0'), ('main_pid', 54321),
                           ('controller_sha256', 'f' * 64), ('configuration_sha256', 'f' * 64)):
            with self.assertRaises(ValueError):
                guest.validate_executor({**proof, key: value}, expected, 'b' * 64)

    def test_effective_profile_rejects_dropins_stream_forwarding_and_changed_native_limits(self):
        observed = {**guest.executor_profile(), 'RuntimeMaxUSec': '40min 45s', 'TimeoutStopUSec': '5s'}
        self.assertEqual(guest.verify_executor_profile(observed), guest.executor_profile_hash())
        for key, value in (('DropInPaths', '/run/systemd/unknown.conf'), ('DropInPaths', '/usr/lib/systemd/system/service.d/10-timeout-abort.conf'),
                           ('DropInPaths', str(guest.SERVICE_MASK) + ' /run/systemd/extra.conf'), ('TimeoutStopFailureMode', 'abort'),
                           ('SendSIGKILL', 'no'), ('FinalKillSignal', '6'), ('StandardOutput', 'journal'),
                           ('SELinuxContext', 'forced'), ('RuntimeMaxUSec', 'infinity'), ('TimeoutStopUSec', '10s')):
            with self.assertRaises(ValueError):
                guest.verify_executor_profile({**observed, key: value})

    def test_target_binding_checks_actual_script_unit_and_complete_controller_tuple(self):
        expected = inputs()
        script = b'public controlled executor fixture\n'
        guest_sha = hashlib.sha256(script).hexdigest()
        unit = guest.service_unit(expected, guest_sha).encode()
        request = {'version': 2, 'mask': mask_fixture(), 'source_sha': expected['source_sha'], 'inputs': expected, 'guest_sha256': guest_sha,
                   'unit_sha256': hashlib.sha256(unit).hexdigest(), 'launcher_context': 'fixture', 'admission_deadline': time.monotonic() + 30}
        self.assertEqual(guest.verify_executor_target(request, expected, guest_sha, script, unit), request['unit_sha256'])
        with self.assertRaisesRegex(ValueError, 'controller-bound target'):
            guest.verify_executor_target(request, expected, guest_sha, script + b'tampered', unit)
        with self.assertRaisesRegex(ValueError, 'controller-bound target'):
            guest.verify_executor_target(request, expected, guest_sha, script, unit + b'EnvironmentFile=/private\n')
        changed = copy.deepcopy(request)
        changed['inputs']['controller_sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            guest.verify_executor_target(changed, expected, guest_sha, script, unit)


if __name__ == '__main__':
    unittest.main()
