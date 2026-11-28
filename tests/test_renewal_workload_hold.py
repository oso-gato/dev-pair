"""Exercise product recovery while the stable controller changes workload access."""
import contextlib
import io
import os
from pathlib import Path
import unittest
from unittest import mock

import test_owner_intake as fixtures
from test_checklist_quadlet import RUNTIME
from bootstrap import Bootstrap
import job_protocol as p
import owner_intake as intake
import product_job as product
import renewal


ACCESS_CHECK = p.require_workload_access


@unittest.skipUnless(os.getuid() == 0, 'workload access and checklist leases require mapped root')
class WorkloadHoldTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.addCleanup(os.umask, os.umask(0o077))
        fixture = fixtures.OwnerIntakeTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.root, self.intake = fixture.root, fixture.intake
        draft = self.intake.draft(fixture.request())
        self.job, self.plan = draft['job_id'], draft['preview']['plan']
        self.boot = intake.boot_id()
        self.recovery = dict(boot=self.boot, after=0, queue_attempts=1, prepare_attempts=1)
        self.intake.save(self.job, dict(self.intake.record(self.job), phase='submitted',
                                       scheduled_boot=self.boot, recovery=self.recovery))
        folder = product.job_path(self.job)
        folder.mkdir(mode=0o700)
        self.initial = {'candidate': {'source_revision': self.plan['agreement']['initial_commit']}}
        self.state = dict.fromkeys(('maintenance', 'development', 'first', 'repair', 'final'))
        self.state.update(job_id=self.job, phase='maintenance-turn', initial=self.initial,
                          agreement_sha256=product.agreement_sha(self.plan), startup_sha256=self.plan['startup_sha256'],
                          repository=self.plan['agreement']['repository'])
        self.state_path = folder / 'state.json'
        product.durable_json(self.state_path, self.state)
        product.durable_json(folder / 'plan.json', self.plan)
        self.staged = self.intake.queue / (self.job + '.plan')
        product.durable_json(self.staged, self.plan)
        product.write_private(self.intake.catalogue / 'owner.lock', b'')

        (self.root / 'renewal').mkdir(mode=0o700)
        self.controller = renewal.Renewal(self.root, None)
        fence = self.root / 'renewal-fence'
        fence.mkdir()
        fence.chmod(0o755)
        lease = fence / 'owner.lock'
        lease.touch()
        lease.chmod(0o644)
        host = self.root / 'bootstrap'
        host.mkdir(mode=0o700)
        self.bootstrap = Bootstrap(host)
        old_path = self.bootstrap.path

        def stage_path(name):
            path = Path(name)
            if path.is_relative_to('/var/lib/dev-pair'):
                return self.root / path.relative_to('/var/lib/dev-pair')
            return old_path(str(path))

        self.enterContext(mock.patch.object(self.bootstrap, 'path', side_effect=stage_path))
        self.publish('a' * 64)
        self.enterContext(mock.patch.object(p, 'require_workload_access', new=ACCESS_CHECK))
        self.enterContext(mock.patch.object(RUNTIME, 'FENCE', fence))
        self.enterContext(mock.patch.multiple(product, ROOT=self.root, CATALOGUE=self.intake.catalogue,
                                              registered_contract=lambda value: value))
        self.enterContext(mock.patch.object(renewal.Renewal, 'live_release', side_effect=lambda: self.selected))
        self.enterContext(mock.patch.object(product, 'source_approval', side_effect=lambda value: self.assertEqual(value, self.plan)))
        self.worker = mock.Mock()
        self.worker.ledger.side_effect = self.ledger
        self.worker.turn.return_value = {'candidate_sha': self.initial['candidate']['source_revision']}
        self.worker.host_test.return_value = {'progress': 'host-checks-passed', 'result': {'attempt_id': 'stored'}}
        self.backend = self.enterContext(mock.patch.object(product, 'FedoraJob', return_value=self.worker))
        self.scheduled = self.enterContext(mock.patch.object(product.candidate, 'invoke', return_value=b''))
        self.clock = self.enterContext(mock.patch.object(product.time, 'time', return_value=1000))
        self.enterContext(mock.patch.object(product.time, 'sleep', side_effect=AssertionError('unexpected product poll')))
        self.enterContext(mock.patch.object(product.candidate, 'protected_file',
                                            side_effect=lambda path, limit=p.MAX_MESSAGE: p.read_data(path, limit)))

    @staticmethod
    def ledger(*_):
        with RUNTIME.dispatch_gate():
            pass

    def publish(self, reference):
        self.selected = reference
        self.bootstrap.publish_workload_gate('admitted', dict(release_sha256=reference, maintenance_image='c' * 64,
                                                               development_image='d' * 64, devbox_image='e' * 64))
        ACCESS_CHECK(self.root, release=reference)

    def start_fence(self, operation):
        attempt = self.controller.control / 'attempts' / operation
        attempt.mkdir(parents=True, mode=0o700)
        transition = {'phase': 'applying', 'freezes': {}}
        renewal.replace_json(self.controller.pointer, operation)
        renewal.replace_json(attempt / 'journal.json', transition)
        self.controller.mark_host_fence(operation, frozen=True)
        return attempt, transition

    def assert_resumed_once(self):
        self.assertEqual(intake.boot_id(), self.boot)
        self.assertEqual(self.intake.reconcile(), 0)
        self.scheduled.assert_called_once()
        self.assertEqual(self.scheduled.call_args.args[0][-1], 'dev-pair-product@' + self.job + '.service')
        self.assertEqual(product.main(['work', self.job]), 0)
        self.assertEqual(product.main(['work', self.job]), 0)
        self.assertEqual(self.intake.reconcile(), 0)
        self.scheduled.assert_called_once()
        self.worker.host_test.assert_called_once_with(1, self.initial)
        self.assertEqual(self.worker.turn.call_count, 2)
        self.worker.build.assert_not_called()

    def test_first_work_can_park_under_closed_workload_access(self):
        with self.controller.lock(), self.controller.host_fence():
            attempt, transition = self.start_fence('stable-update')
            self.bootstrap.hold_changed_workload_access('b' * 64)
            self.assertEqual(product.main(['work', self.job]), 76)
            self.assertEqual(p.loads(self.state_path.read_bytes())['phase'], product.RENEWAL_WAIT)
            self.backend.assert_not_called()
            self.scheduled.assert_not_called()
            self.clock.return_value += 45 * 60
            self.publish('b' * 64)
            self.controller.thaw(attempt, transition, 'completed', registries={})
        self.assert_resumed_once()

    def test_retry_and_timer_survive_activation_between_their_access_checks(self):
        with self.controller.lock(), self.controller.host_fence():
            self.assertEqual(product.work(self.job)['phase'], 'waiting')
            attempt, transition = self.start_fence('stable-update')
            self.bootstrap.hold_changed_workload_access('b' * 64)
            self.assertEqual(product.main(['work', self.job]), 76)
            parked = p.loads(self.state_path.read_bytes())
            self.assertEqual(parked['phase'], product.RENEWAL_WAIT)
            self.assertNotIn('retry', parked)
            self.publish('a' * 64)
            original_lock = self.intake.lock

            @contextlib.contextmanager
            def begin_activation():
                self.bootstrap.hold_changed_workload_access('b' * 64)
                with original_lock():
                    yield

            with mock.patch.object(self.intake, 'lock', new=begin_activation):
                self.assertEqual(self.intake.reconcile(), 0)
            self.assertEqual(self.intake.record(self.job)['phase'], 'submitted')
            self.assertEqual(self.intake.record(self.job)['recovery'], self.recovery)
            self.worker.turn.assert_not_called()
            self.clock.return_value += 45 * 60
            self.publish('b' * 64)
            self.controller.thaw(attempt, transition, 'completed', registries={})
        self.assert_resumed_once()

    def test_timer_records_an_acknowledged_job_which_never_observed_the_hold(self):
        with self.controller.lock(), self.controller.host_fence():
            attempt, transition = self.start_fence('stable-update')
            self.bootstrap.hold_changed_workload_access('b' * 64)
            self.assertEqual(self.intake.reconcile(), 0)
            parked = p.loads(self.state_path.read_bytes())
            self.assertEqual(parked['renewal_wait'], {'phase': 'maintenance-turn', 'fence': attempt.name})
            self.assertEqual(self.intake.record(self.job)['recovery'], self.recovery)
            self.backend.assert_not_called()
            self.scheduled.assert_not_called()
            self.clock.return_value += 45 * 60
            self.publish('b' * 64)
            self.controller.thaw(attempt, transition, 'completed', registries={})
        self.assert_resumed_once()

    def test_hold_after_submit_reads_plan_preserves_the_schedule_allowance(self):
        parked = dict(self.state, phase=product.RENEWAL_WAIT,
                      renewal_wait={'phase': 'maintenance-turn', 'fence': 'completed-update'})
        product.durable_json(self.state_path, parked)
        with contextlib.ExitStack() as activation:
            def start_after_read(path, limit=p.MAX_MESSAGE):
                raw = p.read_data(path, limit)
                if path == self.staged:
                    activation.enter_context(self.controller.lock())
                    activation.enter_context(self.controller.host_fence())
                    self.start_fence('stable-update')
                    self.bootstrap.hold_changed_workload_access('b' * 64)
                return raw

            with mock.patch.object(product.candidate, 'protected_file', side_effect=start_after_read):
                self.assertEqual(self.intake.reconcile(), 0)
            self.assertEqual(self.intake.record(self.job)['phase'], 'submitted')
            self.assertEqual(self.intake.record(self.job)['recovery'], self.recovery)
            self.assertEqual(self.intake.record(self.job)['renewal_wake']['epochs']['boot']['attempts'], 0)
            self.assertEqual(p.loads(self.state_path.read_bytes()), parked)
            self.backend.assert_not_called()
            self.scheduled.assert_not_called()

    def test_unrelated_denial_terminal_and_exhausted_work_stay_unchanged(self):
        self.bootstrap.hold_changed_workload_access('b' * 64)
        with self.assertRaisesRegex(ValueError, 'independent workload access review is pending'):
            product.work(self.job)
        with self.assertRaisesRegex(ValueError, 'independent workload access review is pending'):
            self.intake.reconcile()
        self.assertEqual(p.loads(self.state_path.read_bytes()), self.state)
        with self.controller.lock(), self.controller.host_fence():
            self.start_fence('stable-update')
            exhausted = dict(self.state, phase='waiting', retry={'phase': 'maintenance-turn',
                'reason': 'host-reply-interrupted', 'until_unix': 999, 'observations': 18, 'automatic': False})
            for state in (dict(self.state, phase='passed'), exhausted):
                product.durable_json(self.state_path, state)
                self.assertEqual(self.intake.reconcile(), 0)
                self.assertEqual(product.work(self.job), state)
                self.assertEqual(p.loads(self.state_path.read_bytes()), state)
            expired = dict(exhausted, retry=dict(exhausted['retry'], automatic=True, observations=1))
            product.durable_json(self.state_path, expired)
            self.assertEqual(product.main(['work', self.job]), 76)
            self.assertEqual(p.loads(self.state_path.read_bytes()),
                             dict(expired, retry=dict(expired['retry'], automatic=False)))
        self.assertEqual(self.intake.record(self.job)['recovery'], self.recovery)
        self.backend.assert_not_called()
        self.scheduled.assert_not_called()

    def test_accepted_wake_racing_later_renewals_does_not_exhaust_preparation_budget(self):
        self.recovery['queue_attempts'] = intake.QUEUE_ATTEMPTS - 1
        self.intake.save(self.job, dict(self.intake.record(self.job), recovery=self.recovery))
        with self.controller.lock(), self.controller.host_fence():
            attempt, transition = self.start_fence('first-update')
            self.bootstrap.hold_changed_workload_access('b' * 64)
            self.assertEqual(self.intake.reconcile(), 0)
            self.publish('b' * 64)
            self.controller.thaw(attempt, transition, 'completed', registries={})

        with mock.patch.object(intake.time, 'monotonic', return_value=2000) as monotonic:
            for operation, reference in (('second-update', 'c' * 64), ('third-update', 'd' * 64)):
                with self.subTest(operation=operation), contextlib.ExitStack() as activation:
                    transitions = []

                    def late_worker(*_):
                        activation.enter_context(self.controller.lock())
                        activation.enter_context(self.controller.host_fence())
                        transitions.append(self.start_fence(operation))
                        self.bootstrap.hold_changed_workload_access(reference)
                        self.assertEqual(product.main(['work', self.job]), 76)
                        self.backend.assert_not_called()
                        return b''

                    self.scheduled.side_effect = late_worker
                    self.scheduled.reset_mock()
                    self.assertEqual(self.intake.reconcile(), 0)
                    self.scheduled.assert_called_once()
                    self.assertEqual(p.loads(self.state_path.read_bytes())['renewal_wait']['fence'], operation)
                    self.assertEqual(self.intake.record(self.job)['recovery'], self.recovery)
                    attempt, transition = transitions[0]
                    monotonic.return_value += 45 * 60
                    self.clock.return_value += 45 * 60
                    self.publish(reference)
                    self.controller.thaw(attempt, transition, 'completed', registries={})
            self.scheduled.side_effect = None
            self.scheduled.reset_mock()
            self.assert_resumed_once()
        self.assertEqual(self.intake.record(self.job)['recovery'], self.recovery)

    def test_real_wake_failures_are_bounded_and_saved_fence_text_cannot_reset_them(self):
        with self.controller.lock(), self.controller.host_fence():
            attempt, transition = self.start_fence('first-update')
            self.bootstrap.hold_changed_workload_access('b' * 64)
            self.assertEqual(self.intake.reconcile(), 0)
            self.publish('b' * 64)
            self.controller.thaw(attempt, transition, 'completed', registries={})
        with (mock.patch.object(intake, 'WAKE_ATTEMPTS', 2, create=True),
              mock.patch.object(intake.time, 'monotonic', return_value=2000) as monotonic):
            self.scheduled.side_effect = OSError('fixed service manager was unavailable')
            for _ in range(2):
                self.assertEqual(self.intake.reconcile(), 0)
                monotonic.return_value += intake.RETRY_SECONDS
            self.assertEqual(self.scheduled.call_count, 2)
            initial = p.loads(self.state_path.read_bytes())
            for name in ('forged-hold', 'boot', 'first-update'):
                product.durable_json(self.state_path, dict(initial, renewal_wait=dict(initial['renewal_wait'], fence=name)))
                self.assertEqual(self.intake.reconcile(), 0)
                monotonic.return_value += intake.RETRY_SECONDS
                self.assertEqual(self.scheduled.call_count, 2)
            row = self.intake.record(self.job)
            self.assertEqual(row['phase'], 'submitted')
            self.assertIn('scheduling after renewal reached its limit', row['diagnostics'])
            self.assertEqual(row['recovery'], self.recovery)

            with self.controller.lock(), self.controller.host_fence():
                attempt, transition = self.start_fence('second-update')
                self.bootstrap.hold_changed_workload_access('c' * 64)
                self.assertEqual(self.intake.reconcile(), 0)
                self.assertEqual(p.loads(self.state_path.read_bytes())['renewal_wait']['fence'], attempt.name)
                self.publish('c' * 64)
                self.controller.thaw(attempt, transition, 'completed', registries={})
            with self.controller.lock():
                renewal.replace_json(self.controller.pointer, 'first-update')
            self.assertEqual(self.intake.reconcile(), 0)
            self.assertEqual(self.scheduled.call_count, 2)
            with self.controller.lock():
                renewal.replace_json(self.controller.pointer, 'second-update')
            self.scheduled.side_effect = None
            self.scheduled.reset_mock()
            self.assert_resumed_once()
            self.assertIsNone(self.intake.record(self.job)['diagnostics'])

    def expired_retry(self, *, phase='waiting'):
        retry = {'phase': 'maintenance-turn', 'reason': 'host-reply-interrupted', 'until_unix': 1180,
                 'observations': 1, 'automatic': True}
        product.durable_json(self.state_path, dict(self.state, phase=phase, retry=retry))
        return retry

    def test_next_boot_timer_does_not_schedule_a_legacy_retry_after_its_deadline(self):
        self.expired_retry()
        self.clock.return_value = 3400
        with mock.patch.object(intake, 'boot_id', return_value='00000000-0000-4000-8000-000000000005'):
            self.assertEqual(self.intake.reconcile(), 0)
        self.scheduled.assert_not_called()
        self.backend.assert_not_called()

    def test_delayed_or_interrupted_automatic_worker_rechecks_the_old_retry_deadline(self):
        retry = self.expired_retry()
        self.clock.return_value = 1179
        with mock.patch.object(intake, 'boot_id', return_value='00000000-0000-4000-8000-000000000005'):
            self.assertEqual(self.intake.reconcile(), 0)
        self.scheduled.assert_called_once()
        unit = Path(__file__).resolve().parents[1] / 'runtime/product-job/dev-pair-product@.service'
        self.assertIn('product_job.py work %i\n', unit.read_text())
        self.clock.return_value = 3400
        for phase in ('waiting', 'maintenance-turn'):
            with self.subTest(phase=phase):
                self.expired_retry(phase=phase)
                self.assertEqual(product.main(['work', self.job]), 76)
                self.backend.assert_not_called()
                retained = p.loads(self.state_path.read_bytes())
                self.assertEqual(retained['phase'], 'waiting')
                self.assertEqual(retained['retry'], dict(retry, automatic=False))

    def test_exact_owner_retry_authorizes_one_attempt_without_extending_the_earlier_budget(self):
        retry = self.expired_retry()
        self.clock.return_value = 3400
        saved = self.intake.record(self.job)
        with self.assertRaisesRegex(ValueError, 'draft has changed'):
            self.intake.confirm(self.job, 'f' * 64)
        self.scheduled.assert_not_called()
        self.intake.confirm(self.job, saved['agreement_token'])
        self.scheduled.assert_called_once()
        self.worker.turn.side_effect = product.HostReplyLost('execute')
        self.assertEqual(product.main(['work', self.job]), 76)
        self.worker.turn.assert_called_once_with('maintenance', self.initial)
        self.worker.host_test.assert_not_called()
        self.assertEqual(product.main(['work', self.job]), 76)
        self.worker.turn.assert_called_once()
        retained = p.loads(self.state_path.read_bytes())
        self.assertEqual(retained['retry'], dict(retry, observations=2, automatic=False))

    def test_explicit_root_retry_expires_if_the_worker_never_admits_it(self):
        self.expired_retry()
        self.clock.return_value = 3400
        self.assertEqual(product.main(['submit', str(self.staged)]), 0)
        self.scheduled.assert_called_once()
        self.clock.return_value += product.RETRY_SECONDS
        self.assertEqual(product.main(['work', self.job]), 76)
        self.backend.assert_not_called()

        self.clock.return_value += 1
        self.assertEqual(product.main(['submit', str(self.staged)]), 0)
        self.assertEqual(product.main(['work', self.job]), 0)
        self.assertEqual(product.main(['work', self.job]), 0)
        self.worker.host_test.assert_called_once_with(1, self.initial)
