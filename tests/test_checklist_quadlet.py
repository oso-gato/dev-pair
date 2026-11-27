import contextlib
import configparser
import copy
import os
import pathlib
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import host_handoff as h
import job_protocol as p

RUNTIME = h.host_runtime()
APP = ROOT / 'examples/checklist/checklist.py'
PYTHON = '/usr/bin/python3'


class FixtureService:
    """Use real checklist subprocesses over loopback, with a fixture service manager."""

    def __init__(self, directory, *, forget=False, cleanup_lost=False):
        self.path = directory
        self.forget = forget
        self.cleanup_lost = cleanup_lost
        self.path_created = False
        self.child = None
        self.logs = []
        self.actions = []

    def prepare(self, deadline, request_sha):
        self.path.mkdir()
        self.path_created = True
        return ['fixture-request-sha256:' + request_sha]

    def stop(self):
        if self.child is not None:
            self.child.terminate()
            try:
                self.child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=2)
            self.child.stdout.close()
            self.child.stderr.close()
            self.child = None

    def service(self, action, deadline):
        self.actions.append(action)
        self.stop()
        db = 'wrong.sqlite3' if action == 'restart' and self.forget else 'checklist.sqlite3'
        self.child = subprocess.Popen([PYTHON, '-IB', str(APP), 'serve', '--port', '0',
                                       '--database', str(self.path / db)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not select.select([self.child.stdout], [], [], 2)[0]:
            raise TimeoutError('fixture service startup')
        origin = self.child.stdout.readline().decode().strip()
        self.logs.append(action + ':exit-0')
        phase = str(len(self.actions))
        return int(origin.rsplit(':', 1)[1]), phase * 32, phase * 64

    def cleanup(self, deadline):
        self.stop()
        if self.cleanup_lost:
            raise OSError('fixture cleanup lost')
        shutil.rmtree(self.path)
        self.logs.append('cleanup:exit-0')


class QuadletHandoffTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.path = pathlib.Path(workspace.name)
        self.ledger = p.Ledger(self.path / 'ledger')
        self.addCleanup(self.ledger.close)
        self.id = self.ledger.controller_id
        self.principals = ('d' * 64, 'e' * 64)
        self.budget = {'seconds': 30, 'artifact_bytes': 8192, 'spend_usd': 0}
        self.candidates = [{'source_revision': code * 40, 'artifact_sha256': code * 64} for code in ('a', 'b')]
        self.job = p.envelope('job', job_id='checklist', standards_sha=p.STANDARDS,
                              agreement_sha256='1' * 64, budgets=self.budget, max_requests=4,
                              selection={'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
                                         'runtime_sha256': '2' * 64, 'verification': 'unverified-record-only'})
        self.ledger.create_job(self.job)
        self.services = []
        self.allowed = None
        self.frozen = False

    def request(self, series):
        checkpoint = p.envelope('checkpoint', job_id=self.job['job_id'], checkpoint_id='candidate-' + str(series),
                                candidate=self.candidates[series], test=h.recipe_identity(host=True),
                                summary='Fixture candidate checkpoint', evidence=[])
        self.ledger.checkpoint(checkpoint)
        return h.produce_request(checkpoint, 'restart-' + str(series), self.id, self.principals, self.budget, host=True)

    def approval(self, path, request):
        p.require(p.identity(request) == self.allowed, 'fixture approval does not match exact request')
        return 'localhost/checklist@sha256:' + request['candidate']['artifact_sha256'], ['fixture-approval']

    @contextlib.contextmanager
    def gate(self):
        p.require(not self.frozen, 'fixture renewal has frozen mutation')
        yield

    def dispatch(self, action, request, *, forget=False, cleanup_lost=False):
        def factory(runtime, env, attempt, image, candidate, budget):
            service = FixtureService(self.path / attempt, forget=forget, cleanup_lost=cleanup_lost)
            self.services.append(service)
            self.addCleanup(service.stop)
            return service

        with mock.patch.multiple(RUNTIME, Quadlet=factory, approval=self.approval, dispatch_gate=self.gate,
                                 APP_AUTHORITY=None):
            data = h.dispatch_host(self.ledger, RUNTIME, {}, self.path, self.path / 'approval', self.principals,
                                   {'operation': action, 'request': request})
        h.check_reply(action, data, request, self.id)
        return data

    def test_restart_failure_repair_and_exact_replay(self):
        failing = self.request(0)
        self.allowed = p.identity(failing)
        self.assertEqual(self.dispatch('submit', failing)['state'], 'pending')
        failed = self.dispatch('execute', failing, forget=True)
        self.assertEqual(failed['status'], 'fail')
        self.assertIn('/data/checklist.sqlite3', failed['diagnostics'])
        self.assertIn('missing', failed['diagnostics'])
        self.assertEqual(failed['cleanup']['status'], 'complete')
        self.assertEqual(self.dispatch('consume', failing)['progress'], 'repair-required')
        self.assertEqual(self.dispatch('execute', failing), failed)
        self.assertEqual(self.services[0].actions, ['start', 'restart'])

        repaired = self.request(1)
        self.allowed = p.identity(repaired)
        self.dispatch('submit', repaired)
        passed = self.dispatch('execute', repaired)
        self.assertEqual(passed['status'], 'pass')
        self.assertEqual(passed['executor']['boundary'], p.APP_QUADLET_BOUNDARY)
        self.assertEqual(passed['request_sha256'], p.identity(repaired))
        self.assertNotEqual(passed['attempt_id'], failed['attempt_id'])
        self.assertEqual(self.dispatch('consume', repaired)['progress'], 'host-checks-passed')
        self.assertEqual(self.dispatch('status', failing)['result'], failed)
        with self.assertRaisesRegex(ValueError, 'stale checkpoint'):
            self.dispatch('execute', failing)
        self.allowed = None
        self.assertEqual(self.dispatch('execute', repaired), passed)
        self.assertEqual([entry.actions for entry in self.services], [['start', 'restart'], ['start', 'restart']])
        self.assertFalse(any(service.path.exists() for service in self.services))

        self.ledger.close()
        self.ledger = p.Ledger(self.path / 'ledger')
        self.addCleanup(self.ledger.close)
        self.assertEqual(self.dispatch('status', repaired)['result'], passed)

    def test_permission_and_renewal_scope_and_status(self):
        request = self.request(0)
        with self.assertRaisesRegex(ValueError, 'authenticated'):
            self.ledger.submit(request)
        with self.assertRaisesRegex(ValueError, 'approval'):
            self.dispatch('submit', request)
        self.allowed = p.identity(request)
        changed = copy.deepcopy(request)
        changed['permitted_effects'].append('restart-another-service')
        with self.assertRaisesRegex(ValueError, 'fixed recipe'):
            self.dispatch('submit', changed)
        self.dispatch('submit', request)
        self.allowed = None
        with self.assertRaisesRegex(ValueError, 'approval'):
            self.dispatch('execute', request)
        self.frozen = True
        self.assertEqual(self.dispatch('status', request)['state'], 'pending')
        with self.assertRaisesRegex(ValueError, 'frozen'):
            self.dispatch('execute', request)
        with self.assertRaisesRegex(ValueError, 'authenticated'):
            self.ledger.begin(request['request_id'])
        self.assertFalse(self.services)

    def test_uncertain_cleanup_is_durable_and_never_restarts_again(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        with self.assertRaisesRegex(ValueError, 'unresolved Quadlet cleanup'):
            self.dispatch('execute', request, cleanup_lost=True)
        state = self.dispatch('status', request)
        self.assertEqual(state['state'], 'in-flight')
        self.assertTrue(state['reconciliation_required'])
        self.assertIsNone(state['result'])
        self.assertEqual(self.services[0].path.name, state['attempt_id'])
        self.assertTrue((self.services[0].path / 'checklist.sqlite3').is_file())
        with self.assertRaisesRegex(ValueError, 'execution refused'):
            self.dispatch('execute', request)
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.ledger.reconcile(request['request_id'], 'Synthetic local probe', ['fixture'])
        self.assertEqual(self.services[0].actions, ['start', 'restart'])
        self.assertEqual(len(self.services), 1)

    def test_generated_service_refuses_wrong_container_and_keeps_cleanup_owned(self):
        attempt = '24446e50-09f0-4065-8c46-784cc29313a4'
        runtime = self.path / 'runtime'
        storage = self.path / 'storage'
        runtime.mkdir(mode=0o700)
        storage.mkdir(mode=0o700)
        for leaf in ('attempts', 'graph'):
            (storage / leaf).mkdir(mode=0o700)
        candidate = self.candidates[0]
        image = 'localhost/checklist@sha256:' + candidate['artifact_sha256']
        observed = []
        image_id = '3' * 64

        def capture(argv, deadline, env):
            observed.append(argv)
            if argv[0] == '/usr/sbin/getenforce':
                return 0, b'Enforcing'
            if argv[0] == '/usr/bin/rm':
                shutil.rmtree(unit.path)
                return 0, b''
            if argv[0] == '/usr/bin/systemctl':
                if 'show' in argv:
                    return 0, ('SourcePath=' + str(unit.unit_path) + '\nFragmentPath=' +
                               str(runtime / 'systemd/generator' / unit.unit) + '\nDropInPaths=\nActiveState=' +
                               ('active' if 'start' in observed[-2] else 'inactive') +
                               '\nInvocationID=' + 'f' * 32).encode()
                return 0, b''
            args = argv[5:]
            if args[:2] == ['network', 'inspect']:
                return 0, (RUNTIME.NETWORK + ' bridge true').encode()
            if args[0] == 'info':
                return 0, f'true true v2 systemd {unit.graph} {unit.runroot}'.encode()
            if args[:2] == ['image', 'inspect']:
                return 0, ('\n'.join([image_id, image.split('@')[1], p.canonical([image]),
                                     candidate['source_revision']])).encode()
            if args[:2] == ['container', 'exists']:
                return 1, b''
            if args[:2] == ['container', 'inspect']:
                return 0, ('\n'.join(['4' * 64, '5' * 64, 'true', '101', 'user:role:container_t:s0:c1,c2',
                                     'user:role:container_file_t:s0:c1,c2', 'true false 32 65532:65532'])).encode()
            raise AssertionError(argv)

        with mock.patch.multiple(RUNTIME, STORAGE=storage, capture=capture,
                                 storage_identity=lambda path: ['fixture-bounded-storage']):
            unit = RUNTIME.Quadlet(runtime, {}, attempt, image, candidate, 30)
            unit.prepare(0, '6' * 64)
            receipt = p.loads((unit.path / 'operation.json').read_bytes())
            self.assertEqual(receipt['image_id'], image_id)
            self.assertEqual(receipt['unit'], unit.unit)
            self.assertEqual(receipt['attempt_id'], attempt)
            with self.assertRaisesRegex(ValueError, 'image or process'):
                unit.service('start', 0)
            unit.cleanup(0)
        self.assertFalse(unit.unit_path.exists())
        self.assertFalse(unit.path.exists())
        self.assertTrue(any('stop' in argv and unit.unit in argv for argv in observed))
        self.assertFalse(any('restart' in argv for argv in observed))

    def test_capture_limits_process_output_and_runtime(self):
        environment = {'PATH': '/usr/bin', 'LC_ALL': 'C.UTF-8'}
        with self.assertRaisesRegex(ValueError, 'output limit'):
            RUNTIME.capture([PYTHON, '-c', "print('a' * 65536)"], time.monotonic() + 2, environment)
        with self.assertRaises(TimeoutError):
            RUNTIME.capture([PYTHON, '-c', 'import time; time.sleep(30)'], time.monotonic() + 0.1, environment)

    def test_protected_receipt_binds_exact_candidate_request_and_machine(self):
        request = self.request(0)
        receipt = self.path / 'candidate.json'
        image = 'localhost/checklist@sha256:' + request['candidate']['artifact_sha256']
        document = {'version': 1, 'job_id': request['job_id'], 'candidate': request['candidate'], 'image': image}
        receipt.write_text(p.canonical(document))
        grant_file = self.path / 'approval.json'
        with mock.patch.object(RUNTIME, 'protected', side_effect=lambda path, **kwargs: path), \
                mock.patch.object(RUNTIME.os, 'geteuid', return_value=0), mock.patch.object(RUNTIME, 'APPROVAL', grant_file):
            grant = RUNTIME.issue_approval(receipt, request, 300)
            RUNTIME.publish_approval(grant)
            approved, evidence = RUNTIME.approval(grant_file, request)
            self.assertEqual(approved, image)
            self.assertIn('candidate-receipt-sha256:' + p.sha256(receipt.read_bytes()), evidence)
            different = dict(request, request_id='another-request')
            with self.assertRaisesRegex(ValueError, 'exact host approval'):
                RUNTIME.approval(grant_file, different)
            mismatched = dict(grant, machine_id='0' * 32)
            RUNTIME.publish_approval(mismatched)
            with self.assertRaisesRegex(ValueError, 'different executor'):
                RUNTIME.approval(grant_file, request)
            receipt.write_text(p.canonical(dict(document, candidate=self.candidates[1])))
            with self.assertRaisesRegex(ValueError, 'differs from'):
                RUNTIME.issue_approval(receipt, request, 300)

    def test_release_renderer_accepts_only_exact_internal_route_and_image(self):
        image = 'localhost/checklist@sha256:' + 'a' * 64
        hostname = 'erebus.example-tail.ts.net'
        content = RUNTIME.deployment_unit(image, hostname, 18279, 1200).decode()
        settings = configparser.ConfigParser(strict=False)
        settings.read_string(content)
        self.assertEqual(settings['Container']['PublishPort'], '127.0.0.1:18279:8000')
        self.assertEqual(settings['Container']['Network'], 'dev-pair-checklist-release')
        self.assertIn('--tailnet-host=' + hostname, settings['Container']['Exec'])
        self.assertEqual(settings['Container']['Image'], image)
        self.assertIn('/var/lib/dev-pair/checklist-live/data:/data:Z', settings['Container']['Volume'])
        self.assertEqual(settings['Install']['WantedBy'], 'default.target')
        for args in ((image, 'example.net', 18279, 1200), ('localhost/checklist:latest', hostname, 18279, 1200),
                     (image, hostname, 0, 1200), (image, hostname + '\n', 18279, 1200)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                RUNTIME.deployment_unit(*args)


if __name__ == '__main__':
    unittest.main()
