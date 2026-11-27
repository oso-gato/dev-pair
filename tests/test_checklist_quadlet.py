import contextlib
import configparser
import copy
import json
import os
import pathlib
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import host_handoff as h
import job_protocol as p
import ledger_recovery as recovery

RUNTIME = h.host_runtime()
CHECK_WORKLOAD_ACCESS = p.require_workload_access
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
        self.storage_evidence = ['storage-fsid:123']
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

    def verify_absent(self, deadline, staged):
        p.require(not self.path.exists(), 'fixture matching workspace is still present')


class DelayedFixtureService(FixtureService):
    """Publish a bound address before its ordinary checklist process accepts HTTP."""

    listener = None

    def service(self, action, deadline):
        self.stop()
        self.actions.append(action)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.logs.append(action + ':exit-0')
        phase = str(len(self.actions))
        return self.listener.getsockname()[1], phase * 32, phase * 64

    def accept_http(self):
        self.listener.listen(4)
        descriptor = self.listener.fileno()
        self.child = subprocess.Popen([PYTHON, '-IB', str(APP), 'serve', '--listen-fd', str(descriptor),
                                       '--database', str(self.path / 'checklist.sqlite3')],
                                      pass_fds=(descriptor,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stop(self):
        try:
            super().stop()
        finally:
            if self.listener is not None:
                self.listener.close()
                self.listener = None


class QuadletHandoffTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(p, 'require_workload_access'))
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.path = pathlib.Path(workspace.name)
        self.ledger = p.Ledger(self.path / 'ledger')
        self.addCleanup(self.ledger.close)
        self.id = self.ledger.controller_id
        self.environment = {'machine_sha256': 'a' * 64, 'storage_fsid': 123}
        self.history_path = self.path / 'execution-history'
        self.history = recovery.HostHistory(self.history_path, self.id, self.environment, initialize=True)
        self.addCleanup(self.history.close)
        self.ledger.host_history = self.history
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
        return ('localhost/checklist@sha256:' + request['candidate']['artifact_sha256'],
                ['fixture-approval', 'executor-machine-sha256:' + self.environment['machine_sha256']])

    @contextlib.contextmanager
    def gate(self):
        p.require(not self.frozen, 'fixture renewal has frozen mutation')
        yield

    def dispatch(self, action, request, *, forget=False, cleanup_lost=False, service_type=FixtureService):
        def factory(runtime, env, attempt, image, candidate, budget, *, storage_fsid):
            self.assertEqual(storage_fsid, 123)
            service = service_type(self.path / attempt, forget=forget, cleanup_lost=cleanup_lost)
            self.services.append(service)
            self.addCleanup(service.stop)
            return service

        with mock.patch.multiple(RUNTIME, Quadlet=factory, approval=self.approval, dispatch_gate=self.gate,
                                 APP_AUTHORITY=None, execution_identity=lambda: self.environment):
            data = h.dispatch_host(self.ledger, RUNTIME, {}, self.path, self.path / 'approval', self.principals,
                                   {'operation': action, 'request': request})
        h.check_reply(action, data, request, self.id)
        return data

    def test_managed_access_gate_preserves_readback_and_blocks_real_effect_until_admitted(self):
        flag = self.path / p.WORKLOAD_ACCESS
        fence = self.path / 'renewal-fence'
        original_check = CHECK_WORKLOAD_ACCESS
        real_lstat, real_fstat = pathlib.Path.lstat, os.fstat
        ancestry = {self.path, *self.path.parents}

        def projected_lstat(path):
            node = real_lstat(path)
            return SimpleNamespace(st_uid=0, st_mode=node.st_mode & ~0o022) if path in ancestry else node

        def projected_fstat(fd):
            node = real_fstat(fd)
            if flag.exists() and node.st_ino == flag.stat().st_ino and node.st_dev == flag.stat().st_dev:
                return SimpleNamespace(st_uid=0, st_mode=node.st_mode, st_nlink=node.st_nlink, st_size=node.st_size,
                                       st_ino=node.st_ino, st_dev=node.st_dev)
            return node

        def write_gate(phase):
            admitted = phase == 'admitted'
            scope = {'schema': 1, 'phase': phase, 'release_sha256': 'd' * 64 if admitted else None,
                     'images': {role: 'e' * 64 for role in ('maintenance', 'development', 'devbox')} if admitted else None}
            flag.write_text(json.dumps(scope))
            flag.chmod(0o644)

        request = self.request(0)
        self.allowed = p.identity(request)
        with (mock.patch.object(p, 'require_workload_access', side_effect=lambda: original_check(self.path)),
              mock.patch.object(pathlib.Path, 'lstat', projected_lstat), mock.patch.object(os, 'fstat', projected_fstat)):
            with self.assertRaisesRegex(ValueError, 'managed workload access observation is unavailable'):
                self.dispatch('submit', request)
            write_gate('legacy')
            original_check(self.path)
            fence.mkdir(exist_ok=True)
            (fence / 'selected-host.json').touch()
            with self.assertRaisesRegex(ValueError, 'standalone access review has no verified managed workload selection'):
                self.dispatch('submit', request)
            flag.unlink()
            with self.assertRaisesRegex(ValueError, 'managed workload access observation is unavailable'):
                self.dispatch('submit', request)
            write_gate('held')
            with self.assertRaisesRegex(ValueError, 'review is pending'):
                self.dispatch('submit', request)
            self.assertEqual(self.services, [])
            write_gate('admitted')
            original_check(self.path, release='d' * 64, images={'development': 'e' * 64})
            with self.assertRaisesRegex(ValueError, 'selected role image'):
                original_check(self.path, images={'development': '9' * 64})
            self.assertEqual(self.dispatch('submit', request)['state'], 'pending')
            write_gate('held')
            self.assertEqual(self.dispatch('status', request)['state'], 'pending')
            with self.assertRaisesRegex(ValueError, 'review is pending'):
                self.dispatch('execute', request)
            self.assertEqual(self.services, [])
            write_gate('admitted')
            self.assertEqual(self.dispatch('execute', request)['status'], 'pass')
            self.assertEqual(len(self.services), 1)
            replacement = self.path / 'replacement-workload-access'
            replacement.write_text(json.dumps({'schema': 1, 'phase': 'held', 'release_sha256': None, 'images': None}))
            replacement.chmod(0o644)

            def stale_reader(fd):
                node = projected_fstat(fd)
                if replacement.exists() and (node.st_dev, node.st_ino) == (flag.stat().st_dev, flag.stat().st_ino):
                    os.replace(replacement, flag)
                return node

            with mock.patch.object(os, 'fstat', stale_reader):
                with self.assertRaisesRegex(ValueError, 'workload access observation changed'):
                    original_check(self.path)

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
        self.ledger = p.Ledger(self.path / 'ledger', host_history=self.history)
        self.addCleanup(self.ledger.close)
        self.assertEqual(self.dispatch('status', repaired)['result'], passed)

    def test_http_waits_for_real_delayed_listeners_at_start_and_restart(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        original = h.app_http
        delays = []

        def start_listener_after_refusal(port, deadline, method, path, expected, body=None, *, authority):
            try:
                return original(port, deadline, method, path, expected, body, authority=authority)
            except ConnectionRefusedError:
                self.assertEqual((method, path), ('GET', '/items'))
                unit = self.services[-1]
                delays.append(unit.actions[-1])
                unit.accept_http()
                raise

        with mock.patch.object(h, 'app_http', side_effect=start_listener_after_refusal):
            result = self.dispatch('execute', request, service_type=DelayedFixtureService)
        self.assertEqual(delays, ['start', 'restart'])
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['cleanup']['status'], 'complete')
        self.assertEqual(self.dispatch('consume', request)['progress'], 'host-checks-passed')
        self.assertEqual(self.dispatch('execute', request), result)
        self.assertEqual([unit.actions for unit in self.services], [['start', 'restart']])

    def test_http_that_never_becomes_ready_records_blocked_result_and_cleans_up(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        # Keep the real monotonic deadline and project a short work allowance.
        with mock.patch.object(RUNTIME, 'CLEANUP_SECONDS', self.budget['seconds'] - 0.5):
            result = self.dispatch('execute', request, service_type=DelayedFixtureService)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['diagnostics'], 'wait for checklist HTTP readiness: TimeoutError')
        self.assertEqual(result['cleanup']['status'], 'complete')
        self.assertEqual(result['effects'], [])
        self.assertEqual(self.dispatch('status', request)['result'], result)
        self.assertEqual(self.dispatch('consume', request)['progress'], 'blocked')
        self.assertEqual(self.dispatch('execute', request), result)
        self.assertEqual([unit.actions for unit in self.services], [['start']])
        self.assertFalse(self.services[0].path.exists())

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
        with self.assertRaisesRegex(ValueError, 'matching workspace'):
            self.dispatch('reconcile', request)
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.ledger.reconcile(request['request_id'], 'Synthetic local probe', ['fixture'])
        self.assertEqual(self.services[0].actions, ['start', 'restart'])
        self.assertEqual([service.actions for service in self.services], [['start', 'restart'], []])

    def round_trip(self, name):
        end = time.monotonic() + 5
        backup, restored = (self.path / (part + '-' + name) for part in ('backup', 'restore'))
        recovery.backup(self.path / 'ledger', backup, end)
        recovery.restore(backup, restored, end)
        return contextlib.closing(p.Ledger(restored, host_history=self.history))

    def test_controller_exit_before_arming_closes_original_zero_effect(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        with self.round_trip('pending') as restored:
            self.assertEqual(restored.status(request['request_id'])['state'], 'pending')
        code = '''
import os, signal, sys
sys.path.insert(0, sys.argv[1])
import job_protocol as p
import ledger_recovery as recovery
request = p.loads(sys.stdin.buffer.read())
ledger = p.Ledger(sys.argv[2])
ledger.host_history = recovery.HostHistory(sys.argv[3], ledger.controller_id, p.loads(sys.argv[4]))
ledger.begin(request['request_id'], authenticated_request=request)
os.kill(os.getpid(), signal.SIGKILL)
'''
        exited = subprocess.run([PYTHON, '-IB', '-c', code, str(ROOT / 'tools'), str(self.path / 'ledger'),
                                 str(self.history_path), p.canonical(self.environment)],
                                input=p.canonical(request).encode(), timeout=4)
        self.assertEqual(exited.returncode, -signal.SIGKILL)
        before = self.dispatch('status', request)
        self.assertEqual(before['state'], 'in-flight')
        with self.round_trip('in-flight') as restored:
            self.assertEqual(restored.status(request['request_id']), before)
            self.assertEqual(restored.host_effect_state(request, before['attempt_id']), (False, None))
        closed = self.dispatch('reconcile', request)
        self.assertEqual(closed['attempt_id'], before['attempt_id'])
        self.assertEqual(closed['status'], 'blocked')
        self.assertEqual(closed['effects'], [])
        self.assertEqual(self.dispatch('execute', request), closed)
        self.assertEqual(self.dispatch('consume', request)['progress'], 'blocked')
        self.assertEqual([service.actions for service in self.services], [[]])
        self.request(1)
        with self.round_trip('closed') as restored:
            self.assertEqual(restored.status(request['request_id'])['result'], closed)

    def test_cleaned_staged_observation_can_publish_after_executor_loss(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        with mock.patch.object(self.ledger, 'close_host_effect', side_effect=OSError('controller lost before commit')):
            with self.assertRaisesRegex(OSError, 'before commit'):
                self.dispatch('execute', request)
        before = self.dispatch('status', request)
        self.assertEqual(before['state'], 'in-flight')
        self.ledger.close()
        self.ledger = p.Ledger(self.path / 'ledger', host_history=self.history)
        self.addCleanup(self.ledger.close)
        armed, stored = self.ledger.host_effect_state(request, before['attempt_id'])
        self.assertTrue(armed)
        self.assertEqual(stored['status'], 'pass')
        with self.round_trip('staged') as restored:
            self.assertEqual(restored.host_effect_state(request, before['attempt_id']), (True, stored))
        self.assertEqual(self.dispatch('reconcile', request), stored)
        self.assertEqual(self.dispatch('consume', request), {'progress': 'host-checks-passed', 'result': stored})
        self.assertEqual([service.actions for service in self.services], [['start', 'restart'], []])
        with self.round_trip('recovered') as restored:
            self.assertEqual(restored.status(request['request_id'])['result'], stored)

    def test_completed_attempt_survives_restore_of_job_snapshot(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        with self.round_trip('before-submit') as before_submit:
            self.assertEqual(self.dispatch('submit', request)['state'], 'pending')
            with self.round_trip('pending') as pending:
                completed = self.dispatch('execute', request)
                self.assertEqual(completed['status'], 'pass')
                original = self.ledger
                for recovered in (before_submit, pending):
                    with self.subTest(snapshot=recovered.root.name):
                        self.ledger = recovered
                        self.assertEqual(self.dispatch('status', request)['result'], completed)
                        self.assertEqual(self.dispatch('reconcile', request), completed)
                        self.assertEqual(self.dispatch('execute', request), completed)
                        self.assertEqual(self.dispatch('consume', request)['progress'], 'host-checks-passed')
                        reserved = [entry['body'] for entry in recovered.events()
                                    if entry['event'] == 'execution-reserved']
                        self.assertEqual(reserved, [p.effect_identity(request, completed['attempt_id'])])
                        recovery.validate_database(recovered.path, time.monotonic() + 5)
                self.ledger = original
        self.assertEqual([service.actions for service in self.services], [['start', 'restart']])

    def test_completed_authority_survives_loss_of_the_job_ledger_commit(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        with mock.patch.object(self.ledger, '_store_result', side_effect=OSError('job ledger write interrupted')):
            with self.assertRaisesRegex(OSError, 'job ledger write interrupted'):
                self.dispatch('execute', request)
        self.assertEqual(self.ledger.status(request['request_id'])['state'], 'in-flight')
        projected = self.dispatch('status', request)['result']
        self.assertEqual(projected['status'], 'pass')
        self.assertEqual(self.dispatch('reconcile', request), projected)
        self.assertEqual(self.ledger.status(request['request_id'])['result'], projected)
        self.assertEqual([service.actions for service in self.services], [['start', 'restart']])

    def test_restore_from_an_earlier_checkpoint_fences_the_job(self):
        previous = self.request(0)
        self.allowed = p.identity(previous)
        self.dispatch('submit', previous)
        with self.round_trip('earlier-checkpoint') as old:
            request = self.request(1)
            self.allowed = p.identity(request)
            self.dispatch('submit', request)
            self.assertEqual(self.dispatch('execute', request)['status'], 'pass')
            self.ledger = old
            self.allowed = p.identity(previous)
            with self.assertRaisesRegex(ValueError, 'unknown checkpoint'):
                self.dispatch('execute', previous)
        self.assertEqual([service.actions for service in self.services], [['start', 'restart']])

    def test_clean_host_restore_keeps_history_without_claiming_the_old_machine_effect(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        completed = self.dispatch('execute', request)
        with self.round_trip('clean-host') as restored:
            self.assertEqual(restored.status(request['request_id'])['result'], completed)
            self.ledger = restored
            for changes in ({'machine_sha256': 'b' * 64}, {'storage_fsid': 456}):
                with self.subTest(changes=changes):
                    old = self.environment
                    self.environment = dict(old, **changes)
                    try:
                        with self.assertRaisesRegex(ValueError, 'original executor machine and validation filesystem'):
                            self.dispatch('reconcile', request)
                        with self.assertRaisesRegex(ValueError, 'original controller, executor machine and validation filesystem'):
                            recovery.HostHistory(self.history_path, self.id, self.environment)
                    finally:
                        self.environment = old
            restored.host_history = None
            with self.assertRaisesRegex(ValueError, 'history is unavailable'):
                self.dispatch('execute', request)
        self.assertEqual([service.actions for service in self.services], [['start', 'restart']])

    def test_initializer_requires_pristine_history_and_supports_a_new_controller(self):
        fresh, migrated = (self.path / leaf for leaf in ('fresh', 'migrated'))
        for home in (fresh, migrated):
            home.mkdir(mode=0o700)
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        self.dispatch('execute', request)
        backup = self.path / 'migration-backup'
        end = time.monotonic() + 5
        recovery.backup(self.ledger.root, backup, end)
        recovery.restore(backup, migrated / 'ledger', end)
        new_environment = {'machine_sha256': 'b' * 64, 'storage_fsid': 456}
        with mock.patch.object(h, 'host_runtime', return_value=RUNTIME), \
                mock.patch.object(h, 'protected_host_code'), \
                mock.patch.multiple(RUNTIME, rootless_environment=lambda: (self.path, {}),
                                    execution_identity=lambda: new_environment, dispatch_gate=self.gate):
            with mock.patch.multiple(RUNTIME, HOME=migrated, HISTORY=migrated / 'execution-history'):
                with self.assertRaisesRegex(ValueError, 'fresh host execution history requires a local ledger'):
                    h.initialize_host_history()
            self.assertFalse((migrated / 'execution-history').exists())
            with mock.patch.multiple(RUNTIME, HOME=fresh, HISTORY=fresh / 'execution-history'):
                initial = h.initialize_host_history()
                self.assertNotEqual(initial['controller_id'], self.id)
                self.assertEqual(h.initialize_host_history(), initial)

    def test_arming_without_a_verdict_remains_unresolved_even_when_paths_are_empty(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        attempt, _ = self.ledger.begin(request['request_id'], authenticated_request=request)
        self.ledger.arm_host_effect(request, attempt)
        with self.assertRaisesRegex(ValueError, 'lacks a durable observation'):
            self.dispatch('reconcile', request)
        self.assertEqual(self.dispatch('status', request)['attempt_id'], attempt)
        self.assertEqual(self.services, [])

    def test_backup_rejects_generic_reconciliation_on_legacy_quadlet_request(self):
        request = self.request(0)
        request['capabilities'] = [capability for capability in request['capabilities'] if capability != p.HOST_EFFECT_RECEIPT]
        self.ledger.submit(request, authenticated=True)
        attempt, _ = self.ledger.begin(request['request_id'], authenticated_request=request)
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.ledger.reconcile(request['request_id'], 'Generic reconciliation', ['fixture'])
        closure = dict(p.effect_identity(request, attempt), mode='zero-effect', evidence=p.HOST_ABSENCE_EVIDENCE)
        result = p.closed_host_result(request, attempt, self.id, False, None, closure)
        with self.ledger.transaction():
            self.ledger.event('reconciliation', {'request_id': request['request_id'], 'attempt_id': attempt,
                                                 'diagnostics': result['diagnostics'], 'evidence': result['evidence']})
            self.ledger._store_result(result)
        with self.assertRaisesRegex(ValueError, 'unexpected application reconciliation'):
            self.round_trip('impossible-legacy')

    def test_backup_rejects_missing_host_closure_transaction(self):
        request = self.request(0)
        self.allowed = p.identity(request)
        self.dispatch('submit', request)
        self.dispatch('execute', request)
        # Remove the closure and retain a contiguous event sequence, so the missing transition is the rejection.
        with self.ledger.transaction():
            close = self.ledger.db.execute('SELECT sequence FROM events WHERE event=?', (p.HOST_EFFECT_CLOSED,)).fetchone()[0]
            self.ledger.db.execute('DELETE FROM events WHERE sequence=?', (close,))
            self.ledger.db.execute('UPDATE events SET sequence=? WHERE sequence=?', (close, close + 1))
        with self.assertRaisesRegex(ValueError, 'matching verified closure'):
            self.round_trip('forged-closure')

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
            if argv[0] == RUNTIME.GETENFORCE:
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
            end = time.monotonic() + 5
            unit.prepare(end, '6' * 64)
            receipt = p.loads((unit.path / 'operation.json').read_bytes())
            self.assertEqual(receipt['image_id'], image_id)
            self.assertEqual(receipt['unit'], unit.unit)
            self.assertEqual(receipt['attempt_id'], attempt)
            with self.assertRaisesRegex(ValueError, 'image or process'):
                unit.service('start', end)
            unit.cleanup(end)
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

    def test_expired_work_and_cleanup_start_no_commands_or_intents(self):
        deadline = time.monotonic() - 1
        with mock.patch.object(RUNTIME, 'STORAGE', self.path), \
                mock.patch.object(RUNTIME.subprocess, 'Popen', wraps=subprocess.Popen) as popen:
            unit = RUNTIME.Quadlet(self.path, {}, '24446e50-09f0-4065-8c46-784cc29313a4', None, self.candidates[0], 30)
            unit.path.mkdir(parents=True)
            unit.unit_stage.parent.mkdir(parents=True)
            unit.unit_stage.write_bytes(b'owned temporary unit')
            unit.unit_stage_owned = True
            unit.path_created = True
            with self.assertRaises(TimeoutError):
                RUNTIME.capture(['/usr/bin/true'], deadline, {})
            with self.assertRaises(TimeoutError):
                unit.service('restart', deadline)
            with self.assertRaises(TimeoutError):
                unit.cleanup(deadline)
            self.assertFalse((unit.path / 'restart-requested').exists())
            self.assertTrue(unit.unit_stage.is_file())
            popen.assert_not_called()

    def test_fedora_merged_usr_uses_the_same_canonical_checked_executable(self):
        usr = self.path / 'usr'
        (usr / 'bin').mkdir(parents=True)
        (usr / 'sbin').symlink_to('bin', target_is_directory=True)
        target = usr / 'bin/getenforce'
        target.write_text('#!/bin/sh\nprintf Enforcing')
        target.chmod(0o755)
        selected = self.path / pathlib.Path(RUNTIME.GETENFORCE).relative_to('/')
        original = pathlib.Path.lstat

        def trusted_owner(path):
            info = list(original(path))
            if path in (target, *target.parents):
                info[0] &= ~0o022
                info[4] = 0  # Project root ownership onto the real merged-/usr fixture.
            return os.stat_result(info)

        with mock.patch.object(pathlib.Path, 'lstat', trusted_owner):
            with self.assertRaisesRegex(ValueError, 'canonical paths'):
                RUNTIME.verify_executable(usr / 'sbin/getenforce')
            self.assertEqual(RUNTIME.verify_executable(selected), target)
        with mock.patch.object(RUNTIME, 'GETENFORCE', str(selected)):
            unit = RUNTIME.Quadlet(self.path, {}, '24446e50-09f0-4065-8c46-784cc29313a4', None, self.candidates[0], 30)
            unit.enforcing(time.monotonic() + 2)
        self.assertEqual(unit.logs, ['selinux:exit-0'])

    def test_reconciliation_checks_the_same_store_and_real_paths_before_manager_absence(self):
        with mock.patch.object(RUNTIME, 'STORAGE', self.path):
            unit = RUNTIME.Quadlet(self.path, {}, '24446e50-09f0-4065-8c46-784cc29313a4', None, self.candidates[0], 30)
        observed = {'cleanup': {'status': 'complete'}, 'evidence': ['storage-fsid:42']}
        end = time.monotonic() + 2
        manager = 'LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0'
        with mock.patch.object(unit, 'enforcing'), mock.patch.object(unit, 'systemd', return_value=manager) as systemd, \
                mock.patch.object(unit, 'podman', return_value=(1, '')) as podman, \
                mock.patch.object(RUNTIME, 'storage_identity', return_value=['storage-fsid:71']) as storage:
            with self.assertRaisesRegex(ValueError, 'filesystem identity changed'):
                unit.verify_absent(end, observed)
            systemd.assert_not_called()
            storage.return_value = ['storage-fsid:42']
            unit.path.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, 'workspace.*still present'):
                unit.verify_absent(end, observed)
            systemd.assert_not_called()
            unit.path.rmdir()
            systemd.return_value = manager.replace('not-found', 'loaded')
            with self.assertRaisesRegex(ValueError, 'systemd unit is present'):
                unit.verify_absent(end, observed)
            podman.assert_not_called()
            systemd.return_value = manager
            podman.return_value = (0, '')
            with self.assertRaisesRegex(ValueError, 'container is still present'):
                unit.verify_absent(end, observed)
            podman.return_value = (1, '')
            unit.verify_absent(end, observed)
            self.assertIn(unit.name, podman.call_args.args)

    def test_installed_recovery_helper_bytes_change_the_cli_recipe_and_grant(self):
        sources = (h.SELF, h.JOB_PROTOCOL, h.LEDGER_RECOVERY, h.HOST_RUNTIME, RUNTIME.TEMPLATE)
        for source in sources:
            staged = self.path / source.relative_to(ROOT)
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, staged)
        command = [PYTHON, '-EBs', str(self.path / h.SELF.relative_to(ROOT)), 'recipe', '--host']
        before = p.loads(subprocess.check_output(command, timeout=4))
        self.assertEqual(before, h.recipe_identity(host=True))
        helper = self.path / h.LEDGER_RECOVERY.relative_to(ROOT)
        with helper.open('ab') as stream:
            stream.write(b'\n# Changed installed helper bytes.\n')
        after = p.loads(subprocess.check_output(command, timeout=4))
        self.assertNotEqual(before['recipe_sha256'], after['recipe_sha256'])
        self.assertNotEqual(before['revision'], after['revision'])
        request = self.request(0)
        original = p.identity(request)
        self.allowed = original
        self.dispatch('submit', request)
        with mock.patch.object(h, 'LEDGER_RECOVERY', helper):
            with self.assertRaisesRegex(ValueError, 'different recipe'):
                h.check_request(request, self.id, self.principals, host=True)
            self.assertEqual(self.dispatch('status', request)['request'], request)
        self.assertNotEqual(original, p.identity(dict(request, test=after)))

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
