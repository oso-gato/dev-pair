"""Local development guest protocol tests with protected files and a synthetic engine."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_fedora_prepare import ci, guest, identities, executor_fixture
import test_development_image as image_fixture
import test_public_inputs as public_fixture

EXPECTED, SOURCE, g = image_fixture.EXPECTED, image_fixture.SOURCE, image_fixture.g


class DevelopmentSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = 'a' * 40

    def event(self, action='labeled', label=None, repo='oso-gato/dev-pair'):
        return {'action': action, 'label': {'name': label if label is not None else 'fedora-d-' + self.source},
                'repository': {'full_name': 'oso-gato/dev-pair'}, 'sender': {'login': 'example-owner'},
                'pull_request': {'head': {'sha': self.source, 'repo': {'full_name': repo}}}}

    def run_cli(self, event, scenario='development', *, env=None, supplied=None):
        event_file = self.root / 'event.json'
        event_file.write_text(json.dumps(event))
        expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REPOSITORY': 'oso-gato/dev-pair',
                    'GITHUB_EVENT_PATH': str(event_file), 'GITHUB_RUN_ID': '123456789', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_ACTOR': 'example-owner'}
        if env:
            expected.update(env)
        args = ['fedora_ci.py', '--expected-source', self.source, '--scenario', scenario]
        if supplied:
            args.extend(('--github-event', str(supplied)))
        with mock.patch.dict(os.environ, expected, clear=True), mock.patch.object(sys, 'argv', args), \
                mock.patch.object(ci, 'scratch_root') as scratch, \
                mock.patch.object(ci, 'run_in_private_mount_namespace', return_value=0) as native:
            try:
                self.assertEqual(ci.main(), 0)
            except (OSError, ci.Blocked):
                native.assert_not_called()
                raise
            finally:
                scratch.assert_not_called()
            return native.call_args.args

    def test_both_native_roles_require_exact_head_label_sender_and_first_run(self):
        for scenario, prefix in ci.NATIVE_LABEL_PREFIX.items():
            selected = self.event(label=prefix + self.source)
            self.assertEqual(self.run_cli(selected, scenario), (self.source, scenario))
            for action in ('opened', 'synchronize', 'reopened', 'unlabeled'):
                with self.assertRaisesRegex(ci.Blocked, 'outside the exact'):
                    self.run_cli(self.event(action, prefix + self.source), scenario)
            for label in ('other', 'fedora-development-producer', prefix + 'b' * 40, prefix.upper() + self.source):
                with self.assertRaisesRegex(ci.Blocked, 'outside the exact'):
                    self.run_cli(self.event(label=label), scenario)
            with self.assertRaisesRegex(ci.Blocked, 'outside the exact'):
                self.run_cli(self.event(label=prefix + self.source, repo='fork/project'), scenario)
            for env, failure in (({'GITHUB_ACTIONS': ''}, 'requires the Actions'),
                                 ({'GITHUB_EVENT_NAME': 'workflow_dispatch'}, 'requires the Actions'),
                                 ({'GITHUB_RUN_ATTEMPT': '2'}, 'first attempt'),
                                 ({'GITHUB_RUN_ID': 'missing'}, 'exact Actions run'),
                                 ({'GITHUB_ACTOR': 'another-actor'}, 'label actor')):
                with self.assertRaisesRegex(ci.Blocked, failure):
                    self.run_cli(selected, scenario, env=env)
        decoy = self.root / 'other.json'
        decoy.write_text('{}')
        with self.assertRaisesRegex(ci.Blocked, 'differs from the Actions event'):
            self.run_cli(self.event(), supplied=decoy)
        with self.assertRaisesRegex(ci.Blocked, 'outside the exact'):
            self.run_cli(self.event(), 'maintenance')
        stale = self.event()
        stale['pull_request']['head']['sha'] = 'b' * 40
        with self.assertRaisesRegex(ci.Blocked, 'event head differs'):
            self.run_cli(stale)

    def test_workflow_only_invokes_native_controller_for_exact_label_event(self):
        workflow = Path(ci.__file__).parents[1] / '.github/workflows/fedora-vm.yml'
        text = workflow.read_text()
        self.assertIn('contents: read', text)
        self.assertIn('group: fedora-vm-${{ github.event.pull_request.number }}-', text)
        self.assertIn("if: github.event.action == 'labeled'", text)
        self.assertIn('github.run_attempt == 1', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha }}', text)
        self.assertIn('python3 -B -m unittest discover', text)
        self.assertNotIn('workflow_dispatch', text)
        script = re.search(r'        run: \|\n((?:          .*\n)+)', text)[1]
        for label, scenario in (('fedora-m-' + self.source, 'maintenance'),
                                ('fedora-d-' + self.source, 'development'),
                                ('fedora-m-' + 'b' * 40, None), ('fedora-development-producer', None)):
            env = {'DP_EVENT_LABEL': label, 'DP_EXPECTED_SOURCE': self.source, 'GITHUB_EVENT_PATH': '/event.json'}
            result = subprocess.run(['/bin/sh', '-ec', 'python3() { printf "%s\\n" "$@"; }\n' + script],
                                    capture_output=True, text=True, env=env)
            if scenario:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ['-B', 'tools/fedora_ci.py', '--expected-source',
                                                              self.source, '--scenario', scenario, '--github-event', '/event.json'])
            else:
                self.assertEqual((result.returncode, result.stdout), (2, ''))

    def test_role_bound_bundle_admission_and_systemd_identity(self):
        fixture = public_fixture.PublicInputsTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        tree, bundle, _, record = fixture.fixture_payload()
        proof = b'synthetic strict verification output\n'
        (tree / 'evidence/cosign-verification.txt').write_bytes(proof)
        (tree / 'evidence/verification-receipt.json').write_text(json.dumps({
            'helper_source_sha': self.source, 'exit_status': 0, 'result': 'Verified OK', 'codex_binary_sha256': ci.public.CODEX_SHA,
            'codex_source_sha': ci.public.CODEX_SOURCE, 'verification_output_sha256': ci.sha256(proof)}))
        record['files'] = ci.public.inventory(tree)
        bundle.unlink()
        ci.public.write_payload(tree, record['files'], bundle)
        record['kind'] = 'verified-public-development-inputs'
        record['payload'] = {'sha256': ci.file_hash(bundle), 'bytes': bundle.stat().st_size}
        payload = self.root / 'payload'
        payload.mkdir()
        shutil.copyfile(bundle, payload / 'development-inputs.tar.gz')
        for name in ('public_inputs.py', 'fedora_oci.py'):
            shutil.copyfile(Path(ci.__file__).parent / name, payload / name)
        (payload / 'manifest.json').write_bytes(ci.public.canonical(record))
        expected = {**identities(), 'scenario': 'development', 'run_nonce': 'f' * 32,
                    'context_sha256': record['context_sha256'], 'distrobox_sha': record['distrobox_sha'],
                    'standards_sha': record['standards_sha'], 'payload_sha256': record['payload']['sha256'],
                    'payload_bytes': record['payload']['bytes'], 'manifest_sha256': ci.file_hash(payload / 'manifest.json'),
                    'helper_sha256': ci.file_hash(payload / 'public_inputs.py'), 'fedora_helper_sha256': ci.file_hash(payload / 'fedora_oci.py'),
                    'codex_sha256': ci.public.CODEX_SHA, 'codex_source_sha': ci.public.CODEX_SOURCE}
        destination = self.root / 'extracted'
        self.assertEqual(guest.admit_inputs(payload, expected, destination), destination / 'dev-pair')
        self.assertTrue((destination / 'context/inputs.json').is_file())
        self.assertIn('run_nonce', ci.seed_data(self.source, expected, 'b' * 64))
        self.assertNotEqual(guest.service_unit(expected, 'b' * 64), guest.service_unit({**expected, 'run_nonce': 'e' * 32}, 'b' * 64))

        record['kind'] = 'verified-public-maintenance-inputs'
        (payload / 'manifest.json').write_bytes(ci.public.canonical(record))
        with mock.patch.object(guest, 'command') as command, self.assertRaisesRegex(ValueError, 'handoff'):
            guest.admit_inputs(payload, {**expected, 'manifest_sha256': ci.file_hash(payload / 'manifest.json')}, self.root / 'wrong')
        command.assert_not_called()

    def test_controller_builds_and_transports_only_selected_development_bundle(self):
        fixture = public_fixture.PublicInputsTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        _, bundle, _, record = fixture.fixture_payload()
        probe = ci.Probe(self.source, self.root, 'development')
        probe.image = 'sha256:' + 'a' * 64
        probe.report['cloud_image'] = {}
        (probe.root / 'payload').mkdir(parents=True)
        commands = []

        def public_command(argv, *args):
            commands.append(argv)
            if 'fetch' in argv:
                return b'{}'
            self.assertEqual(argv[argv.index('--role') + 1], 'development')
            self.assertIn('build', argv)
            handoff = Path(argv[argv.index('--output') + 1])
            (handoff / 'verification').mkdir(parents=True, exist_ok=True)
            shutil.copyfile(bundle, handoff / 'development-inputs.tar.gz')
            manifest = handoff / 'manifest.json'
            manifest.write_bytes(ci.public.canonical(record))
            (handoff / 'verification/receipt.json').write_text('{}')
            return json.dumps({'source_sha': self.source, 'manifest_sha256': ci.file_hash(manifest),
                               'context_sha256': record['context_sha256'], 'payload_sha256': record['payload']['sha256']}).encode()

        def iso(argv, **kwargs):
            commands.append(argv)
            if 'info' in argv:
                return b'{"format":"qcow2","virtual-size":34359738368}'
            return b''

        with mock.patch.object(probe, 'bounded', side_effect=public_command), mock.patch.object(probe, 'helper', side_effect=iso), \
                mock.patch.object(ci, 'verification_evidence', return_value={'receipt': {}, 'output_base64': 'raw-canary'}), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ci.Blocked, 'producer target'):
                probe.payload()  # Maintenance-kind manifest from the same pinned source.
            record['kind'] = 'verified-public-development-inputs'
            commands.clear()
            probe.payload()
        self.assertEqual(sum('build' in command for command in commands), 1)
        self.assertEqual(sorted(node.name for node in (probe.root / 'payload').glob('*inputs.tar.gz')), ['development-inputs.tar.gz'])
        graft = next(command for command in commands if '-graft-points' in command)
        self.assertIn('development-inputs.tar.gz=/payload/development-inputs.tar.gz', graft)
        self.assertNotIn('native35', ' '.join(graft))
        self.assertNotIn('raw-canary', json.dumps(probe.report))
        self.assertEqual(probe.handoff['scenario'], 'development')
        self.assertIn(probe.handoff['run_nonce'], (probe.root / 'seed/user-data').read_text())

    def test_development_controller_withholds_failed_console_and_unvalidated_serial_bytes(self):
        probe = ci.Probe(self.source, self.root, 'development')
        console_capture = io.StringIO()
        with ci.ReportPipe(self.root) as pipe, contextlib.redirect_stdout(console_capture):
            script = ('import os,sys; f=os.open(sys.argv[1],os.O_WRONLY); '
                      'os.write(f,b"private-malformed-serial"); os.close(f); '
                      'print("private-console",flush=True); raise SystemExit(7)')
            with self.assertRaisesRegex(ci.Blocked, 'exit 7'):
                probe.bounded([sys.executable, '-c', script, str(pipe.base) + '.out'], 3,
                              'fixture', disk_check=False, report_pipe=pipe)
        witness = probe.report['dedicated_report_witness']
        self.assertEqual(witness['retained_bytes'], len(b'private-malformed-serial'))
        self.assertEqual(witness['sha256'], ci.sha256(b'private-malformed-serial'))
        self.assertFalse(witness['framing_complete'])
        self.assertNotIn('private-console', console_capture.getvalue())
        for key in ('head_hex', 'tail_hex', 'retained_base64'):
            self.assertNotIn(key, witness)


class DevelopmentGuestTests(unittest.TestCase):
    def setUp(self):
        fixture = self.fixture = image_fixture.DevelopmentImageTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.app = fixture.app
        self.root = fixture.root
        self.secret_dir = self.root / 'disposable-secret'
        self.expected = {**identities(), 'source_sha': SOURCE, 'context_sha256': EXPECTED, 'distrobox_sha': g.DBX_SHA,
                         'scenario': 'development', 'run_nonce': 'd' * 32}
        self.guest_sha = guest.digest(Path(guest.__file__))
        self.argv = ['guest.py', '--native-service', '--source', SOURCE, '--guest-sha256', self.guest_sha,
                     '--inputs-json', json.dumps(self.expected)]
        self.calls = []
        self.result = None

    def seed_development_ready(self):
        target = {'source_sha': SOURCE, 'context_sha256': EXPECTED, 'distrobox_sha': g.DBX_SHA,
                  'bootstrap_sources': [guest.DEVELOPMENT_BOOTSTRAP_SOURCE]}
        phase = g.PREPARE_NATIVE + '-12345678'
        intent = g.image_inputs_bytes({'schema': 1, 'target': target, 'phase_prefixes': [phase],
                                      'native_units': [phase + '-abcdef01']})
        self.app.atomic(g.DEVELOPMENT_HOST_INTENT, intent.decode())
        path = g.STATE + '/desired.json'
        desired = self.app._host_desired('core', target['bootstrap_sources'], EXPECTED)
        self.app.atomic(path, desired, expected=self.app.text(path))
        ready = {'schema': 1, 'kind': g.DEVELOPMENT_HOST_READY_KIND, 'source_sha': SOURCE, 'context_sha256': EXPECTED,
                 'standards_sha': g.candidate.STANDARDS, 'bootstrap_sha256': json.loads(desired)['bootstrap_sha256'],
                 'desired_sha256': g.sha(desired.encode()), 'packages_sha256': g.sha(self.fixture.engine.packages.encode()),
                 'intent_sha256': g.sha(intent)}
        path = g.STATE + '/host-ready.json'
        self.app.atomic(path, g.image_inputs_bytes(ready).decode(), expected=self.app.text(path))

    def capture(self, args, *, fail_prepare=False, prepare_effect=None, **kwargs):
        self.calls.append((args, kwargs))
        self.assertIn('--apply', args)
        self.assertNotIn('--retry', args)
        if 'prepare-development-host' in args:
            password = Path(args[args.index('--password-file') + 1])
            self.assertEqual(password.stat().st_mode & 0o777, 0o600)
            self.assertEqual(password.read_text(), 'disposable-fixture-sentinel\n')
            if prepare_effect is not None:
                prepare_effect()
            if fail_prepare:
                return 2, b'private command log /root/not-public disposable-fixture-sentinel'
            self.seed_development_ready()
            return 0, g.image_inputs_bytes({'kind': g.DEVELOPMENT_HOST_READY_KIND, 'source_sha': SOURCE,
                'context_sha256': EXPECTED, 'host_prerequisites': 'complete', 'reused': False, 'job_admission': False})
        self.assertIn('build-development', args)
        self.assertNotIn('--password-file', args)
        self.assertFalse(os.path.lexists(self.secret_dir / 'core-password'))
        self.result = self.fixture.assemble()
        return 0, g.image_inputs_bytes(self.result)

    def readback(self, source, expected, built, end):
        engine = self.fixture.engine

        class ReceiptCommands(g.Commands):
            def __call__(self, *args, **kwargs):
                return engine(*args, **kwargs)

        with mock.patch.object(self.app, 'run', ReceiptCommands()):
            return guest.development_release_evidence(g, self.app, expected, built, end)

    def run_guest(self, fail_prepare=False, prepare_effect=None, expect_removed=True):
        reports = []
        executor = executor_fixture(self.expected, self.guest_sha)
        executor['admission_deadline'] = time.monotonic() + 60
        baseline = {'os': 'Fedora 44', 'architecture': 'x86_64', 'pid1': 'systemd', 'selinux': 'Enforcing',
                    'cgroup': 'v2', 'root_free_bytes': 14 * ci.GIB}
        with mock.patch.object(sys, 'argv', self.argv), mock.patch.object(guest, 'SECRET_DIRECTORY', self.secret_dir), \
                mock.patch.object(guest, 'native_executor_identity', return_value=executor), \
                mock.patch.object(guest, 'baseline', return_value=baseline), \
                mock.patch.object(guest, 'admit_inputs', return_value=self.root), \
                mock.patch.object(guest, 'capture', side_effect=lambda *a, **kw: self.capture(
                    *a, fail_prepare=fail_prepare, prepare_effect=prepare_effect, **kw)), \
                mock.patch.object(guest, 'development_readback', side_effect=self.readback), \
                mock.patch.object(guest.secrets, 'token_urlsafe', return_value='disposable-fixture-sentinel'), \
                mock.patch.object(guest, 'write_report', side_effect=lambda report, **kw: reports.append(copy.deepcopy(report))), \
                mock.patch.object(guest.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as system:
            guest.main()
        self.assertEqual(system.call_args.args[0], ['/usr/bin/systemctl', 'poweroff', '--no-block'])
        if expect_removed:
            self.assertFalse(os.path.lexists(self.secret_dir / 'core-password'))
        self.assertEqual(len(reports), 1)
        frame = guest.encode_report(reports[0])
        for sensitive in (b'disposable-fixture-sentinel', b'/root/not-public', os.fsencode(self.root), os.fsencode(guest.SERVICE_MASK)):
            self.assertNotIn(sensitive, frame)
        return ci.parse_serial(frame, SOURCE, self.guest_sha, self.expected)

    def test_guest_progression_emits_real_fixture_release_receipt_for_exact_target(self):
        report = self.run_guest()
        self.assertEqual(report['development']['stage'], 'complete')
        self.assertFalse(report['development']['nested_placement_exercised'])
        self.assertFalse(report['development']['job_admission'])
        args = [argv for argv, _ in self.calls]
        times = [float(argv[argv.index('--work-deadline-monotonic') + 1]) for argv in args]
        self.assertLess(times[0], times[1])
        self.assertGreater(times[0], time.monotonic())
        self.assertLessEqual(times[0] - time.monotonic(), guest.INITIALIZE_SECONDS)
        self.assertLessEqual(times[1] - time.monotonic(), guest.INITIALIZE_SECONDS)
        self.assertLessEqual(self.calls[0][1]['timeout'], 600 + guest.INITIALIZE_CLEANUP_SECONDS)
        self.assertLessEqual(self.calls[1][1]['timeout'], 2160 + guest.INITIALIZE_CLEANUP_SECONDS)
        receipt = report['development']['receipt']
        self.assertEqual(receipt['inner'], self.result['inner'])
        self.assertEqual(receipt['inner']['archive_sha256'], ci.file_hash(Path(self.result['archive'])))
        self.assertEqual(receipt['intent_sha256'], ci.file_hash(self.app.path(g.DEVELOPMENT_HOST_INTENT)))
        self.assertEqual(receipt['inner_sha256'], ci.file_hash(Path(self.result['inner_record'])))

        stale = {**self.expected, 'run_nonce': 'e' * 32}
        bad_reports = []
        forged = copy.deepcopy(report)
        forged['inputs'] = stale
        forged['development']['receipt']['target']['run_nonce'] = stale['run_nonce']
        bad_reports.append((forged, stale))  # Native unit still belongs to the prior nonce.
        for field, value in (('receipt', None), ('stage', 'development-image'), ('job_admission', True),
                             ('nested_placement_exercised', True)):
            forged = copy.deepcopy(report)
            forged['development'][field] = value
            bad_reports.append((forged, self.expected))
        forged = copy.deepcopy(report)
        forged['development']['receipt']['inner']['image_id'] = '9' * 64
        bad_reports.append((forged, self.expected))
        forged = copy.deepcopy(report)
        forged['cleanup']['password_absent'] = False
        bad_reports.append((forged, self.expected))
        for bad, expected in bad_reports:
            with self.assertRaises((ci.Blocked, ValueError)):
                ci.parse_serial(guest.encode_report(bad), SOURCE, self.guest_sha, expected)
        with self.assertRaises((ci.Blocked, ValueError)):
            ci.parse_serial(guest.encode_report(report), SOURCE, self.guest_sha, stale)
        publication = self.fixture.publication
        publication_raw = publication.read_bytes()
        publication.write_bytes(g.image_inputs_bytes({**json.loads(publication_raw), 'phase': 'verified'}))
        with self.assertRaisesRegex(ValueError, 'publication is incomplete'):
            self.readback(self.root, self.expected, self.result, time.monotonic() + 4)
        publication.write_bytes(publication_raw)
        archive = Path(self.result['archive'])
        archive.chmod(0o644)
        data = archive.read_bytes()
        archive.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        archive.chmod(0o444)
        with self.assertRaisesRegex(ValueError, 'protected readback blocked'):
            self.readback(self.root, self.expected, self.result, time.monotonic() + 4)

    def test_prepare_failure_cleans_password_and_never_launches_build(self):
        report = self.run_guest(fail_prepare=True)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(report['development']['stage'], 'development-host-prepare')
        self.assertIsNone(report['development']['receipt'])
        self.assertEqual(report['phases']['development-image']['status'], 'blocked')
        self.assertTrue(report['cleanup']['password_absent'])
        witness = ci.report_witness(guest.encode_report(report), include_bytes=False)
        self.assertNotIn('retained_base64', witness)
        self.assertTrue(witness['framing_complete'])

    def test_late_success_during_cleanup_grace_never_starts_build(self):
        with mock.patch.object(guest, 'DEVELOPMENT_PREPARE_SECONDS', .04):
            report = self.run_guest(prepare_effect=lambda: time.sleep(.06))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(report['development']['stage'], 'development-host-prepare')
        self.assertIsNone(report['development']['receipt'])
        self.assertTrue(report['cleanup']['password_absent'])
        capture = guest.capture

        def delayed_child(*args, **kwargs):
            return capture([sys.executable, '-c', 'import time; time.sleep(.08); print("{}")'], **kwargs)

        with mock.patch.object(guest, 'capture', side_effect=delayed_child), self.assertRaisesRegex(ValueError, 'budget exhausted'):
            guest.development_command(self.root, 'prepare-development-host', [], time.monotonic() + 2, .04)

    def test_inaccessible_password_parent_is_unresolved_after_failed_prepare(self):
        report = self.run_guest(fail_prepare=True, prepare_effect=lambda: self.secret_dir.chmod(0), expect_removed=False)
        self.secret_dir.chmod(0o700)
        self.assertTrue((self.secret_dir / 'core-password').is_file())
        self.assertFalse(report['cleanup']['password_absent'])
        self.assertEqual(report['development']['stage'], 'development-host-prepare')
        self.assertEqual(len(self.calls), 1)

    def test_failed_unlink_or_final_metadata_observation_never_blesses_cleanup(self):
        unlink = os.unlink

        def denied_unlink(name, *, dir_fd=None):
            if dir_fd is not None and name == 'core-password':
                raise PermissionError('fixture denied exact unlink')
            return unlink(name, dir_fd=dir_fd)

        with mock.patch.object(guest.os, 'unlink', side_effect=denied_unlink):
            report = self.run_guest(fail_prepare=True, expect_removed=False)
        self.assertFalse(report['cleanup']['password_absent'])
        self.assertTrue((self.secret_dir / 'core-password').is_file())
        shutil.rmtree(self.secret_dir)
        self.calls.clear()
        leaf = guest.DevelopmentPassword.leaf
        observations = []

        def deny_final_observation(owner):
            if owner.removed:
                observations.append(owner.removed)
                if len(observations) == 2:
                    raise OSError('fixture final lstat failure')
            return leaf(owner)

        with mock.patch.object(guest.DevelopmentPassword, 'leaf', new=deny_final_observation):
            report = self.run_guest()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(observations), 2)
        self.assertFalse(report['cleanup']['password_absent'])
        self.assertEqual(report['development']['stage'], 'development-readback')
        self.assertIsNone(report['development']['receipt'])

    def test_password_parent_replacement_and_dangling_leaf_withhold_absence(self):
        password = guest.DevelopmentPassword(self.secret_dir)
        self.addCleanup(password.close)
        with password.create():
            pass
        self.assertTrue(password.absent())
        password.path.symlink_to(self.root / 'missing')
        self.assertFalse(password.absent())
        password.path.unlink()
        self.secret_dir.rename(self.root / 'original-secret')
        self.secret_dir.mkdir(mode=0o700)
        self.assertFalse(password.absent())

    def test_exact_password_leaf_is_held_through_removal_and_closed(self):
        password = guest.DevelopmentPassword(self.secret_dir)
        self.addCleanup(password.close)
        with password.create() as path:
            file_fd, parent_fd = password.file_fd, password.fd
            opened, named = os.fstat(file_fd), path.lstat()
            self.assertEqual((opened.st_dev, opened.st_ino, opened.st_nlink),
                             (named.st_dev, named.st_ino, 1))
            self.assertFalse(os.get_inheritable(file_fd))
        self.assertEqual(os.fstat(file_fd).st_nlink, 0)
        self.assertTrue(password.absent())
        password.close()
        for descriptor in (file_fd, parent_fd):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_replaced_or_multiply_linked_password_is_preserved(self):
        for replacement in (False, True):
            directory = self.root / str(replacement)
            password = guest.DevelopmentPassword(directory)
            self.addCleanup(password.close)
            saved = directory / 'still-linked'
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, 'password (file|path)'):
                with password.create() as path:
                    if replacement:
                        path.rename(saved)
                        path.write_text('unrelated fixture\n')
                        path.chmod(0o600)
                    else:
                        os.link(path, saved)
            self.assertFalse(password.absent())
            self.assertTrue(saved.is_file())
            if replacement:
                self.assertEqual(password.path.read_text(), 'unrelated fixture\n')
            else:
                self.assertEqual(password.path.lstat().st_nlink, 2)

    def test_named_enoent_without_original_unlink_withholds_build(self):
        unlink = os.unlink

        def move_away(name, *, dir_fd=None):
            if dir_fd is not None and name == 'core-password':
                os.rename(name, 'still-linked', src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                return
            return unlink(name, dir_fd=dir_fd)

        with mock.patch.object(guest.os, 'unlink', side_effect=move_away):
            report = self.run_guest()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(report['cleanup']['password_absent'])
        self.assertEqual(report['development']['stage'], 'development-host-prepare')
        self.assertTrue((self.secret_dir / 'still-linked').is_file())

    def test_descriptor_close_error_withholds_final_receipt(self):
        close = guest.DevelopmentPassword.close

        def fail_after_close(owner):
            close(owner)
            raise OSError('fixture password descriptor close failure')

        with mock.patch.object(guest.DevelopmentPassword, 'close', new=fail_after_close):
            result = self.run_guest()
        self.assertFalse(result['cleanup']['password_absent'])
        self.assertEqual(result['development']['stage'], 'development-readback')
        self.assertIsNone(result['development']['receipt'])

    def test_development_cli_deadline_clips_both_existing_native_ceilings(self):
        options = ['gptbox.py', 'prepare-development-host', '--apply', '--context', '/fixture-context',
                   '--source-sha', SOURCE, '--expected-context-sha256', EXPECTED, '--distrobox-source', '/fixture-upstream',
                   '--bootstrap-source', guest.DEVELOPMENT_BOOTSTRAP_SOURCE]
        app = g.DevelopmentGptbox(self.root)
        observed = []

        def stage(*args):
            with app.run.phase(600, 'dev-pair-initialize-prepare'):
                other = g.Commands()
                observed.append(other.execution_deadline())
                args = other.native_args(('--property=RuntimeMaxSec=1800',), other.limit_timeout(1800))
                observed.append(float(args[0].split('=')[-1].removesuffix('s')))
            return {'fixture': True}

        with mock.patch.object(g, 'DevelopmentGptbox', return_value=app), \
                mock.patch.object(app, 'prepare_development_host', side_effect=stage) as prepare, \
                mock.patch.object(app, 'assemble', side_effect=stage) as build, \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            deadline = time.monotonic() + 2
            cli = [*options, '--work-deadline-monotonic', repr(deadline)]
            with mock.patch.object(sys, 'argv', cli):
                self.assertEqual(g.main(), 0)
            cli[1] = 'build-development'
            with mock.patch.object(sys, 'argv', cli):
                self.assertEqual(g.main(), 0)
            cli[-1] = 'nan'
            with mock.patch.object(sys, 'argv', cli):
                self.assertEqual(g.main(), 2)
            prepare.assert_called_once()
            build.assert_called_once()
        self.assertEqual(observed[::2], [deadline, deadline])
        self.assertTrue(all(0 < duration <= 2 for duration in observed[1::2]))

        with mock.patch.object(guest, 'capture', return_value=(0, b'{}')) as capture:
            end = time.monotonic() + 2
            guest.development_command(self.root, 'build-development', [], end, guest.DEVELOPMENT_BUILD_SECONDS)
            self.assertIn(repr(end), capture.call_args.args[0])
            self.assertLessEqual(capture.call_args.kwargs['timeout'], 2 + guest.INITIALIZE_CLEANUP_SECONDS)
        with mock.patch.object(guest, 'capture') as capture, self.assertRaisesRegex(ValueError, 'budget exhausted'):
            guest.development_command(self.root, 'build-development', [], time.monotonic() - 1, guest.DEVELOPMENT_BUILD_SECONDS)
        capture.assert_not_called()
