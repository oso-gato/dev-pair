"""Public-input/guest integration contracts and local processes, never Fedora evidence."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
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
import fedora_ci_qemu as qemu


def identities():
    return {**{key: 'c' * length for key, length in guest.INPUT_LENGTHS.items()}, 'source_sha': 'a' * 40, 'payload_bytes': 123}


def executor_fixture(expected, guest_sha):
    # Contract fixture only, never evidence of a running systemd executor.
    return {'kind': 'native-systemd-service', 'source_sha': expected['source_sha'], 'controller_sha256': expected['controller_sha256'],
            'unit': guest.SERVICE_NAME, 'mask': {'path': str(guest.SERVICE_MASK), 'device': 1, 'inode': 2, 'sha256': guest.EMPTY_SHA256}, 'configuration_sha256': guest.executor_profile_hash(), 'unit_sha256': ci.sha256(guest.service_unit(expected, guest_sha).encode()),
            'script_sha256': guest_sha, 'uid': 0, 'euid': 0, 'main_pid': 12345, 'manager_main_pid': 12345,
            'cgroup': '0::/system.slice/' + guest.SERVICE_NAME, 'context': 'system_u:system_r:fixture_t:s0',
            'launcher_context': 'system_u:system_r:cloud_init_t:s0', 'admission_deadline': 12345.0}


def state(prepare='complete', maintenance='blocked'):
    expected = identities()
    result = {'target': {'source_sha': expected['source_sha'], 'context_sha256': expected['context_sha256'],
                        'distrobox_sha': expected['distrobox_sha'], 'bootstrap_sources': ['192.0.2.9/32']},
              'phase': 'complete' if maintenance == 'complete' else 'maintenance-gptbox',
              'prepare': prepare, 'maintenance_gptbox': maintenance, 'job_admission': False}
    if maintenance == 'complete':
        result['result'] = {'source_sha': expected['source_sha'], 'context_sha256': expected['context_sha256'],
                            'distrobox_sha': expected['distrobox_sha'], 'boundary_and_version_cycles': 2,
                            'runtime_container_removed': True, 'job_admission': False, 'assembled_image_id': 'e' * 64}
    return result


class FedoraPrepareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_partial_result_identity_and_strict_consumer_do_not_promote_stale_or_unobserved_images(self):
        expected = identities()
        partial = guest.initialize_projection(state(), expected, 2)
        self.assertEqual((partial['prepare'], partial['maintenance_gptbox']), ('complete', 'blocked'))
        self.assertFalse(partial['prepared_image_verified'])
        changed = state()
        changed['target']['context_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'target'):
            guest.initialize_projection(changed, expected, 0)
        report = {'version': guest.REPORT_VERSION, 'source_sha': expected['source_sha'], 'guest_sha256': 'b' * 64,
                  'inputs': expected, 'initialization': partial, 'identity': {'provisioning_executor': executor_fixture(expected, 'b' * 64)}, 'diagnostics': {},
                  'phases': {name: {'status': 'blocked', 'detail': 'synthetic protocol fixture only'} for name in guest.GUEST_PHASES}}
        report['phases']['bootstrap-prepare']['status'] = 'pass'
        with self.assertRaisesRegex(ci.Blocked, 'actual preparation evidence'):
            ci.parse_serial(guest.encode_report(report), expected['source_sha'], 'b' * 64, expected)
        partial.update(prepared_image_id='d' * 64, prepared_image_verified=True, packages_sha256='f' * 64, package_count=3)
        self.assertEqual(ci.parse_serial(guest.encode_report(report), expected['source_sha'], 'b' * 64, expected), report)
        report['phases']['maintenance-gptbox']['status'] = 'pass'
        with self.assertRaisesRegex(ci.Blocked, 'actual assembly evidence'):
            ci.parse_serial(guest.encode_report(report), expected['source_sha'], 'b' * 64, expected)
        report['phases']['maintenance-gptbox']['status'] = 'blocked'
        partial['unknown'] = 'denied'
        with self.assertRaisesRegex(ValueError, 'fields'):
            ci.parse_serial(guest.encode_report(report), expected['source_sha'], 'b' * 64, expected)

    def test_actual_image_evidence_and_failure_keep_verified_prerequisite_separate(self):
        expected = identities()
        source = self.root / 'source'
        (source / 'tools').mkdir(parents=True)
        (source / 'tools/bootstrap.py').write_text('synthetic code identity only\n')
        (self.root / 'prepared').write_text(json.dumps({'gptbox_context_sha256': expected['context_sha256'],
                 'standards_sha': expected['standards_sha'], 'bootstrap_sha256': guest.digest(source / 'tools/bootstrap.py')}))
        (self.root / 'gptbox-image.json').write_text(json.dumps({'image_id': 'sha256:' + 'd' * 64,
                 'source_sha': expected['source_sha'], 'context_sha256': expected['context_sha256'], 'codex_sha256': expected['codex_sha256']}))
        (self.root / 'packages.txt').write_text('podman-fixture\ndistrobox-fixture\ntailscale-fixture\n')
        labels = {'dev-pair.context': expected['context_sha256'], 'org.opencontainers.image.revision': expected['source_sha'],
                  'dev-pair.role': 'maintenance', 'dev-pair.standards': expected['standards_sha'], 'dev-pair.codex.version': '0.169.0'}
        rows = [{'Id': 'sha256:' + 'd' * 64, 'Architecture': 'amd64', 'Os': 'linux', 'Labels': labels},
                {'Id': 'sha256:' + 'e' * 64, 'Architecture': 'amd64', 'Os': 'linux',
                 'Labels': {'dev-pair.context': expected['context_sha256'], 'org.opencontainers.image.revision': expected['source_sha'],
                            'dev-pair.distrobox': expected['distrobox_sha']}}]
        with mock.patch.object(guest.pwd, 'getpwnam', return_value=type('UID', (), {'pw_uid': 1001})()), \
                mock.patch.object(guest, 'native_image_capture', side_effect=lambda source, argv, timeout: json.dumps(rows).encode()) as command:
            projected = guest.initialize_projection(state(maintenance='complete'), expected, 0)
            guest.image_evidence(expected, projected, self.root, source, time.monotonic() + 20)
            self.assertTrue(projected['prepared_image_verified'])
            self.assertTrue(projected['assembled_image_verified'])
            self.assertEqual(projected['package_count'], 3)
            self.assertIn('--uid=dp-maint', command.call_args.args[1])
            rows[1]['Labels']['org.opencontainers.image.revision'] = 'f' * 40
            projected = guest.initialize_projection(state(maintenance='complete'), expected, 0)
            with self.assertRaisesRegex(ValueError, 'identity/source'):
                guest.image_evidence(expected, projected, self.root, source, time.monotonic() + 20)
            self.assertTrue(projected['prepared_image_verified'])
            self.assertFalse(projected['assembled_image_verified'])

    def test_input_identity_unknown_version_mismatch_and_untrusted_extractor_reject_before_launch(self):
        expected = identities()
        payload = self.root / 'payload'
        payload.mkdir()
        (payload / 'public_inputs.py').write_text('untrusted extractor fixture')
        with mock.patch.object(guest, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'extractor implementation'):
                guest.admit_inputs(payload, expected, self.root / 'never-created')
            command.assert_not_called()
        for malformed in ({**expected, 'unexpected': True}, {**expected, 'payload_bytes': True}):
            with self.assertRaises(ValueError):
                guest.validate_inputs(malformed)
        complete = guest.initialize_projection(state(maintenance='complete'), expected, 0)
        complete.update(prepared_image_id='d' * 64, prepared_image_verified=True, assembled_image_verified=True, packages_sha256='f' * 64, package_count=3)
        report = {'version': guest.REPORT_VERSION, 'source_sha': expected['source_sha'], 'guest_sha256': 'b' * 64,
                  'inputs': expected, 'initialization': complete, 'identity': {'provisioning_executor': executor_fixture(expected, 'b' * 64)}, 'diagnostics': {},
                  'phases': {name: {'status': 'pass', 'detail': 'synthetic contract only; no host acceptance'} for name in guest.GUEST_PHASES}}
        changed = {**expected, 'payload_sha256': 'f' * 64}
        with self.assertRaisesRegex(ci.Blocked, 'public input identity'):
            ci.parse_serial(guest.encode_report(report), expected['source_sha'], 'b' * 64, changed)
        report['version'] = 1
        with self.assertRaisesRegex(ci.Blocked, 'identity mismatch'):
            ci.parse_serial(guest.encode_report(report), expected['source_sha'], 'b' * 64, expected)

    def test_fixed_profile_network_only_for_vm_and_actual_namespace_no_port_checks(self):
        probe = ci.Probe('a' * 40, self.root)
        self.assertEqual((ci.VIRTUAL_BYTES, ci.OVERLAY_LIMIT, ci.OVERHEAD_LIMIT, ci.HOST_RESERVE),
                         (32 * ci.GIB, 16 * ci.GIB, 4 * ci.GIB, 3 * ci.GIB))
        self.assertEqual(qemu.OVERLAY_MAX_BYTES, ci.OVERLAY_LIMIT)
        self.assertEqual(ci.PUBLIC_SECONDS + ci.VM_SECONDS + ci.CLEANUP_SECONDS, ci.CONTROLLER_SECONDS)
        self.assertLessEqual(180 + guest.GUEST_ADMISSION_SECONDS + guest.INITIALIZE_SECONDS + guest.INITIALIZE_CLEANUP_SECONDS + guest.GUEST_FINAL_SECONDS, ci.VM_SECONDS)
        ordinary = probe.run_args('/usr/bin/true')
        vm = probe.run_args('/usr/bin/python3', vm=True)
        self.assertIn('--network=none', ordinary)
        self.assertIn('--network=slirp4netns:allow_host_loopback=false', vm)
        self.assertIn('--timeout=' + str(ci.VM_CONTAINER_SECONDS), vm)
        for forbidden in ('--privileged', '--network=host', 'hostfwd', 'guestfwd', '/var/run/docker.sock'):
            self.assertNotIn(forbidden, ' '.join(vm))
        row = {'HostConfig': {'NetworkMode': 'slirp4netns', 'PortBindings': {}, 'Privileged': False},
               'NetworkSettings': {'Ports': {}}, 'State': {'Pid': 12345}}
        def observed(args, **kwargs):
            if 'inspect' in args:
                return json.dumps([row]).encode()
            self.assertEqual(args, ['sudo', '-n', '/usr/bin/readlink', '/proc/12345/ns/net'])
            return b'net:[123456789]\n'
        with mock.patch.object(ci, 'run_small', side_effect=observed):
            probe.observe_vm_network()
            self.assertFalse(probe.report['network']['destination_acl'])
            row['HostConfig']['PortBindings'] = {'8080/tcp': [{'HostPort': '8080'}]}
            with self.assertRaisesRegex(ci.Blocked, 'isolation mismatch'):
                probe.observe_vm_network()
            row['HostConfig']['PortBindings'] = {}
            row['HostConfig']['NetworkMode'] = 'host'
            with self.assertRaises(ci.Blocked):
                probe.observe_vm_network()

    def test_guest_capture_kills_exited_parent_held_pipe_descendant_and_clips_phase(self):
        marker = self.root / 'escape'
        code = ('import os,time,pathlib,sys; pid=os.fork(); os._exit(0) if pid else None; '
                'time.sleep(.3); pathlib.Path(sys.argv[1]).write_text("escaped")')
        with self.assertRaisesRegex(ValueError, 'deadline'):
            guest.capture([sys.executable, '-c', code, str(marker)], timeout=.05)
        time.sleep(.35)
        self.assertFalse(marker.exists())
        probe = ci.Probe('a' * 40, self.root)
        probe.phase_end = time.monotonic() + .05
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ci.Blocked, 'deadline'):
            probe.bounded([sys.executable, '-c', 'import time;time.sleep(1)'], 10, 'remaining phase', disk_check=False)
        with self.assertRaisesRegex(ci.Blocked, 'wall-time budget'):
            with ci.deadline(.03):
                with ci.deadline(.2):
                    time.sleep(.1)

    def test_generated_password_and_failure_finalization_never_export_value(self):
        expected = identities()
        state_root = self.root / 'state'
        state_root.mkdir()
        source = self.root / 'source'
        source.mkdir()
        destination = self.root / 'inputs'
        secret_dir = self.root / 'secret'
        captured = []
        sentinel = 'synthetic-password-sentinel'
        def capture(args, *extra, **kwargs):
            if 'initialize' in args:
                password = Path(args[args.index('--password-file') + 1])
                self.assertEqual(password.stat().st_mode & 0o777, 0o600)
                self.assertEqual(password.read_text(), sentinel + '\n')
                self.assertNotIn(sentinel, json.dumps(args))
                self.assertNotIn(sentinel, json.dumps(guest.SAFE_ENV))
                failed = state(prepare='blocked')
                failed['phase'] = 'prepare'
                (state_root / 'initialize.json').write_text(json.dumps(failed))
                return 2, b'fixed public initialization failure'
            return 0, b'{"enrollment_recorded": false}'
        argv = ['guest.py', '--native-service', '--source', expected['source_sha'], '--inputs-json', json.dumps(expected),
                '--guest-sha256', guest.digest(Path(guest.__file__))]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(guest, 'STATE_ROOT', state_root), \
                mock.patch.object(guest, 'INPUT_DESTINATION', destination), mock.patch.object(guest, 'SECRET_DIRECTORY', secret_dir), \
                mock.patch.object(guest, 'native_executor_identity', return_value={'admission_deadline': time.monotonic() + 60}), \
                mock.patch.object(guest, 'baseline', return_value={'root_free_bytes': 9 * ci.GIB, 'fixture': 'no Fedora evidence'}), \
                mock.patch.object(guest, 'admit_inputs', return_value=source), \
                mock.patch.object(guest, 'capture', side_effect=capture), \
                mock.patch.object(guest.secrets, 'token_urlsafe', return_value=sentinel), \
                mock.patch.object(guest, 'diagnostics', return_value={'fixture': 'no runtime evidence'}), \
                mock.patch.object(guest, 'write_report', side_effect=lambda value, **kw: captured.append(copy.deepcopy(value))), \
                mock.patch.object(guest.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            guest.main()
        self.assertFalse((secret_dir / 'core-password').exists())
        self.assertNotIn(sentinel, json.dumps(captured))
        self.assertNotIn(sentinel, ci.seed_data(expected['source_sha'], expected, 'b' * 64))
        self.assertEqual(captured[0]['phases']['fedora-preflight']['status'], 'pass')
        self.assertEqual(captured[0]['phases']['bootstrap-prepare']['status'], 'blocked')
        self.assertEqual(captured[0]['phases']['maintenance-gptbox']['status'], 'blocked')
        self.assertEqual(captured[0]['initialization']['exit_status'], 2)

    def test_password_removed_at_matching_prepare_boundary_before_frame(self):
        state_root = self.root / 'phase-records'
        state_root.mkdir()
        with guest.make_password(self.root / 'phase-secret') as password:
            record = state()
            record['target']['context_sha256'] = 'f' * 64
            (state_root / 'initialize.json').write_text(json.dumps(record))
            guest.remove_password_after_prepare(password, state_root, identities())
            self.assertTrue(password.exists())
            record = state()
            (state_root / 'initialize.json').write_text(json.dumps(record))
            guest.remove_password_after_prepare(password, state_root, identities())
            self.assertFalse(password.exists())

    def test_password_write_failure_cleans_before_yield_and_native_run_deadline_is_real(self):
        secret_dir = self.root / 'failed-secret'
        with mock.patch.object(guest.os, 'fsync', side_effect=OSError('injected durability failure')):
            with self.assertRaises(OSError):
                with guest.make_password(secret_dir):
                    self.fail('secret yielded after failed fsync')
        self.assertFalse((secret_dir / 'core-password').exists())
        marker = self.root / 'native-timeout-escape'
        script = 'trap "" TERM; sleep .4; echo escaped > "' + str(marker) + '"'
        result = subprocess.run(['/usr/bin/timeout', '--signal=TERM', '--kill-after=.05s', '.05s', '/bin/sh', '-c', script],
                                capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        time.sleep(.45)
        self.assertFalse(marker.exists())

    def test_post_password_diagnostics_exclude_journal_and_unrelated_audit_bodies(self):
        calls = []
        def capture(args, *extra, **kwargs):
            calls.append(args)
            if 'ausearch' in args[0]:
                return 0, (b'type=AVC msg=audit(1794.5:12): avc: denied { write } for comm="crun" scontext=system_u:system_r:container_t:s0 tcontext=system_u:object_r:tmp_t:s0 tclass=fifo_file permissive=0\n'
                           b'type=PROCTITLE proctitle=synthetic-password-sentinel\n'
                           b'type=AVC comm="unrelated" name=synthetic-password-sentinel\n')
            return 0, b'fixed public status'
        with mock.patch.object(guest, 'capture', side_effect=capture):
            observed = guest.diagnostics(time.monotonic() + 10)
        self.assertFalse(any('journalctl' in command[0] for command in calls))
        self.assertNotIn('synthetic-password-sentinel', json.dumps(observed))
        self.assertEqual(observed['selinux_avcs']['records'][0]['comm'], 'crun')
        self.assertEqual(observed['selinux_avcs']['typed_seen'], 2)
        self.assertEqual(observed['selinux_avcs']['malformed'], 1)


if __name__ == '__main__':
    unittest.main()
