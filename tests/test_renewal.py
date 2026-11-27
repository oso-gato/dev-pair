import copy
import fcntl
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import job_protocol as p
import renewal as r
from session_controller import Registry

FILE = Path(__file__).with_name('renewal_driver_fixture.py')


class RenewalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.control = self.root / 'renewal'
        for relative in ('renewal', 'renewal/attempts', 'renewal/registries', 'renewal/requests', 'renewal/releases', 'renewal/offers',
                         'renewal/registry-staging'):
            (self.root / relative).mkdir(mode=0o700)
        fence = self.root / 'renewal-fence'
        fence.mkdir(mode=0o755)
        fence.chmod(0o755)
        self.effect_lock = fence / 'owner.lock'
        self.effect_lock.touch(mode=0o644)
        self.effect_lock.chmod(0o644)
        self.driver = self.root / 'driver'
        self.driver.write_text('#!/usr/bin/python3\nimport os, sys\n'
                               f'os.execv(sys.executable, [sys.executable, {str(FILE)!r}, {str(self.root)!r}, sys.argv[1]])\n')
        self.driver.chmod(0o700)
        self.renewal = r.Renewal(self.root, r.SiteDriver(self.driver, 8), byte_limit=1024 * 1024, seconds=10)
        self.prior = self.release('a')
        baseline = self.renewal.release(self.prior)
        (self.root / 'site-live.json').write_text(json.dumps({'release_sha256': self.prior, 'components': baseline['components']}))
        r.replace_json(self.control / 'current.json', self.prior)
        ledger = p.Ledger(self.root / 'ledger')
        try:
            job = p.envelope('job', job_id='product', standards_sha=r.STANDARDS, agreement_sha256='a' * 64,
                             selection={'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
                                        'runtime_sha256': 'b' * 64, 'verification': 'unverified-record-only'},
                             budgets={'seconds': 5, 'artifact_bytes': 4096, 'spend_usd': 0}, max_requests=4)
            ledger.create_job(job)
            cp = p.envelope('checkpoint', job_id='product', checkpoint_id='repair-current',
                            candidate={'source_revision': 'c' * 40, 'artifact_sha256': 'e' * 64},
                            test=p.recipe_identity(), summary='Saved product repair', evidence=['local'])
            ledger.checkpoint(cp)
            artifact = self.root / 'payload.json'
            artifact.write_text('{"message":"ready"}')
            cp['candidate']['artifact_sha256'] = p.sha256(artifact.read_bytes())
            cp['checkpoint_id'] = 'repair-ready'
            ledger.checkpoint(cp)
            ledger.produce_request('product', 'recorded-effect', 'ready', 'local-protocol', 'Exercise real local ledger')
            self.effect = ledger.execute('recorded-effect', artifact)['attempt_id']
            ledger.produce_request('product', 'still-pending', 'ready', 'local-protocol', 'Keep pending during renewal')
            binding = {key: 'f' * 64 for key in ('source_sha256', 'binary_sha256', 'policy_sha256',
                                                'layout_sha256', 'startup_sha256')}
            binding.update(controller_id=ledger.controller_id, job_id='product', checkpoint_id=cp['checkpoint_id'],
                           checkpoint_sha256=p.identity(cp), runtime_sha256='b' * 64, standards_sha=r.STANDARDS,
                           agreement_sha256=job['agreement_sha256'], job_sha256=p.identity(job), source_revision='f' * 40,
                           provider='gptbox', model='gpt-6.2-sol', effort='high', credential_ref='scoped-ref')
        finally:
            ledger.close()
        self.sessions = {}
        for role in r.ROLES:
            (self.control / 'registries' / role).mkdir(mode=0o700)
            for path in self.renewal.trees(role, 'product').values():
                path.mkdir(parents=True, mode=0o700)
            workspace = self.renewal.trees(role, 'product')['workspaces']
            subprocess.run(['git', '-C', str(workspace), 'init', '-q'], check=True, timeout=5)
            (workspace / 'tracked.txt').write_text('committed source\n')
            subprocess.run(['git', '-C', str(workspace), 'add', 'tracked.txt'], check=True, timeout=5)
            subprocess.run(['git', '-C', str(workspace), '-c', 'user.name=Local fixture', '-c',
                            'user.email=local@example.invalid', 'commit', '-qm', 'start'], check=True, timeout=5)
            (workspace / 'tracked.txt').write_text('unfinished tracked edit\n')
            (workspace / 'untracked.txt').write_text('uncommitted ' + role)
            (workspace / 'source-link').symlink_to('untracked.txt')
            role_model = 'gpt-6.2-astra' if role == 'maintenance' else 'gpt-6.2-sol'
            self.renewal.register({**binding, 'role': role, 'model': role_model})
            for logical in ('one', 'two') if role == 'development' else ('one',):
                name = f'{role}-{logical}-start'
                spec = {'operation': name, 'role': role, 'job': 'product', 'logical_session': logical,
                        'session_uuid': None, 'request_sha256': r.sha(name.encode())}
                result = self.renewal.role_turn(spec, 'Initial work')
                self.sessions[(role, logical)] = result['uuid']
                self.assertEqual(result, self.renewal.role_turn(spec, 'Initial work'))

    def release(self, value, previous=None, scope='agent'):
        stub = {'source_revision': value * 40, 'config_sha256': value * 64, 'artifact_sha256': value * 64}
        if previous is None:
            release = {'schema': 1, 'source_revision': value * 40, 'config_sha256': value * 64,
                       'plan_sha256': value * 64,
                       'ledger_contract': 1, 'state_contract': 1,
                       'components': {name: dict(stub) for name in r.COMPONENTS}}
        else:
            release = copy.deepcopy(self.renewal.release(previous))
            release['source_revision'] = value * 40
            release['plan_sha256'] = value * 64
            if scope == 'host':
                release['config_sha256'] = value * 64
            for name in r.SCOPE_COMPONENTS[scope]:
                release['components'][name] = dict(stub)
        for name in r.SCOPE_COMPONENTS['agent']:
            release['components'][name].setdefault('codex_version', '0.169.0')
        ref = r.identity(release)
        r.replace_json(self.control / 'releases' / (ref + '.json'), release)
        return ref

    def request(self, until, *, previous=None, scope='agent', operation='run-one'):
        value = {'schema': 1, 'operation': operation, 'scope': scope,
                 'previous_sha256': previous or self.prior, 'target_sha256': until,
                 'affected_jobs': ['product'], 'reason': 'Platform repair found in product job'}
        if scope == 'agent':
            offer = {'schema': 1, 'request': value, 'run_ids': {'maintenance': 1, 'development': 2}}
            r.replace_json(self.control / 'offers' / 'agent.json', offer)
            value = {'schema': 1, 'request': value, 'offer_sha256': r.identity(offer)}
        r.replace_json(self.control / 'requests' / (scope + '.json'), value)

    def assert_sessions_preserved(self, state, active):
        self.assertEqual(self.renewal.live_release(), active)
        self.assertFalse((self.effect_lock.parent / 'frozen').exists())
        proofs = {(proof['role'], proof['logical_session']): proof for proof in state['proofs'].values()
                  if proof['release_sha256'] == active}
        self.assertEqual(self.sessions, {identity: proof['session_uuid'] for identity, proof in proofs.items()})
        for (role, logical), proof in proofs.items():
            paths = self.renewal.trees(role, 'product')
            history = (paths['state'] / (logical + '.txt')).read_text().splitlines()
            self.assertEqual(history.count(proof['operation']), 1)
            self.assertEqual(history[0], self.sessions[(role, logical)])
            self.assertEqual((paths['workspaces'] / 'source-link').read_text(), 'uncommitted ' + role)
            self.assertEqual((paths['workspaces'] / 'tracked.txt').read_text(), 'unfinished tracked edit\n')
            registry = Registry(self.renewal.registry_path(role, 'product'))
            try:
                self.assertEqual(registry.inventory()['dispatch']['state'], 'open')
            finally:
                registry.close()
        requests = self.renewal.ledger.inventory()['requests']
        self.assertEqual(requests['recorded-effect']['attempt_id'], self.effect)
        self.assertEqual(requests['still-pending']['state'], 'pending')

    def test_all_both_role_sessions_resume_over_three_distinct_scopes(self):
        previous = self.prior
        for value, scope in zip('bcd', ('agent', 'devbox', 'host')):
            target = self.release(value, previous, scope)
            self.request(target, previous=previous, scope=scope, operation='run-' + scope)
            result = self.renewal.apply(scope)
            self.assertEqual(result['phase'], 'completed', result)
            self.assertEqual(self.renewal.apply(scope), result)
            self.assert_sessions_preserved(result, target)
            attempt, state = self.renewal.transition()
            inventory = self.renewal.checked_inventory(attempt, state)
            self.assertEqual(len(inventory['sessions']), 3)
            for row in inventory['sessions']:
                self.assertEqual(row['target_sha256'], target)
                self.assertEqual(row['pending_host'], ['still-pending'])
            self.assertEqual(self.renewal.ledger.inventory(attempt / 'verified-restore' / 'ledger'), inventory['host'])
            previous = target
        calls = [json.loads(line) for line in (self.root / 'site-events.jsonl').read_text().splitlines()]
        self.assertEqual([call[1] for call in calls if call[0] == 'activate'], ['run-agent', 'run-devbox', 'run-host'])

    def test_failed_replacement_rolls_back_both_trees_and_durable_requests(self):
        target = self.release('b', self.prior)
        self.request(target)
        (self.root / 'disrupt-release').write_text(target)
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'rolled-back', result)
        self.assert_sessions_preserved(result, self.prior)
        self.assertEqual(self.renewal.apply('agent'), result)
        self.assertTrue((self.root / 'maintenance' / 'workspaces' / '.replaced-run-one-product').exists())

    def test_missing_both_registries_are_restored_with_identical_ids_and_uuid_history(self):
        before = {}
        for role in r.ROLES:
            registry = Registry(self.renewal.registry_path(role, 'product'))
            try:
                before[role] = registry.meta['registry_id'], registry.inventory()['operations']
            finally:
                registry.close()

        target = self.release('b', self.prior)
        self.request(target)
        (self.root / 'remove-registries').write_text(target)
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'completed', result)
        self.assert_sessions_preserved(result, target)
        for role in r.ROLES:
            registry = Registry(self.renewal.registry_path(role, 'product'))
            try:
                self.assertEqual((registry.meta['registry_id'], registry.inventory()['operations']), before[role])
            finally:
                registry.close()

    def test_previous_completed_release_gets_a_fresh_verified_return_generation(self):
        first = self.release('b', self.prior, scope='devbox')
        second = self.release('c', first, scope='devbox')
        for previous, target, name in ((self.prior, first, 'into-b'), (first, second, 'into-c')):
            self.request(target, previous=previous, scope='devbox', operation=name)
            result = self.renewal.apply('devbox')
            self.assertEqual((result['phase'], result['request']['operation']), ('completed', name), result)
            self.assertEqual(self.renewal.live_release(), target)
        self.request(first, previous=self.prior, scope='devbox', operation='into-b')
        with self.assertRaisesRegex(ValueError, 'no longer names the live release'):
            self.renewal.apply('devbox')
        self.request(first, previous=second, scope='devbox', operation='return-b')
        result = self.renewal.apply('devbox')
        self.assertEqual((result['phase'], result['request']['operation']), ('completed', 'return-b'), result)
        self.assertEqual(result['activation_generation'], 2)
        self.assertEqual(self.renewal.live_release(), first)
        self.assertEqual(self.renewal.apply('devbox'), result)

    def test_unregistered_durable_session_prevents_any_activation(self):
        target = self.release('b', self.prior)
        self.request(target)
        state = self.renewal.trees('development', 'product')['state']
        (state / 'stray.txt').write_text('11111111-1111-7111-8111-111111111111')
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertEqual(self.renewal.live_release(), self.prior)
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())

    def test_unregistered_durable_job_prevents_disruption_even_with_valid_registry_catalogue(self):
        target = self.release('b', self.prior)
        self.request(target)
        missing = self.root / 'development' / 'state' / 'unregistered'
        missing.mkdir()
        (missing / 'pending-context').write_text('must survive')
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertIn('durable job catalogue', result['failure']['reason'])
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())

    def test_managed_assembly_probe_empty_artifacts_can_coexist_with_real_jobs(self):
        target = self.release('b', self.prior)
        self.request(target)
        for name in ('workspaces', 'state', 'cache'):
            (self.root / 'maintenance' / name / 'gptbox-probe').mkdir(mode=0o700, parents=True)
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'completed', result)
        self.assert_sessions_preserved(result, target)

    def test_transient_deferral_retries_same_approval_and_rejected_target_cannot_be_renamed(self):
        target = self.release('b', self.prior)
        self.request(target)
        unavailable = self.root / 'missing-release-artifact'
        unavailable.write_text(self.prior)
        first = self.renewal.apply('agent')
        self.assertEqual(first['phase'], 'deferred', first)
        self.assertEqual(self.renewal.apply('agent'), first)
        attempt, _ = self.renewal.transition()
        r.replace_json(attempt / 'journal.json', {**first, 'retry_after': 0})
        unavailable.unlink()
        (self.root / 'disrupt-release').write_text(target)
        next_result = self.renewal.apply('agent')
        self.assertEqual((next_result['phase'], next_result['target_attempt']), ('rolled-back', 2), next_result)
        self.assertNotEqual(first['attempt_id'], next_result['attempt_id'])
        self.request(target, operation='other-id')
        self.assertEqual(self.renewal.apply('agent'), next_result)

    def test_idle_startup_fence_survives_failed_observation(self):
        lost = self.root / 'failed-host-observation'
        lost.touch()
        self.renewal.boot_fence()
        with self.renewal.lock(), self.assertRaisesRegex(ValueError, 'observe'):
            self.renewal.observe_then_clear_fence(None, None)
        self.assertTrue((self.effect_lock.parent / 'frozen').is_file())
        lost.unlink()
        with self.renewal.lock():
            self.renewal.observe_then_clear_fence(None, None)
        self.assertFalse((self.effect_lock.parent / 'frozen').exists())

    def test_terminal_recovery_cannot_clear_boot_fence_without_live_observation(self):
        target = self.release('b', self.prior)
        self.request(target)
        self.assertEqual(self.renewal.apply('agent')['phase'], 'completed')
        self.renewal.boot_fence()
        lost = self.root / 'failed-host-observation'
        lost.touch()
        with self.assertRaisesRegex(ValueError, 'observe'):
            self.renewal.apply('agent')
        self.assertTrue((self.effect_lock.parent / 'frozen').exists())
        lost.unlink()
        self.assertEqual(self.renewal.apply('agent')['phase'], 'completed')
        self.assertFalse((self.effect_lock.parent / 'frozen').exists())

    def test_current_intake_clears_older_pending_request(self):
        target = self.release('b', self.prior)
        self.request(target)
        candidate = runpy.run_path(str(TOOLS.parent / 'runtime' / 'renewal' / 'agent-candidate'))
        offer = {'request': {'target_sha256': self.prior}}
        r.replace_json(self.control / 'offers' / 'agent.json', offer)
        candidate['publish_request'](self.renewal, 'agent', offer['request'], self.prior, r.identity(offer))
        fresh = self.renewal.apply('agent')
        self.assertEqual(fresh['phase'], 'no-approved-target')
        self.assertEqual(self.renewal.live_release(), self.prior)

    def test_withdrawn_and_changed_offers_invalidate_protected_pending_approval(self):
        self.request(self.release('b', self.prior))
        offer = self.control / 'offers' / 'agent.json'
        raw = r.read_json(offer)
        r.replace_json(offer, {**raw, 'run_ids': {'development': 3, 'maintenance': 4}})
        with self.assertRaisesRegex(ValueError, 'changed or revoked'):
            self.renewal.apply('agent')
        offer.unlink()
        self.assertEqual(self.renewal.apply('agent')['phase'], 'no-approved-target')

    def test_missing_rollback_allowance_defers_before_replacement(self):
        target = self.release('b', self.prior)
        self.request(target)
        (self.root / 'deny-recovery-grant').write_text(self.prior)
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertEqual(self.renewal.live_release(), self.prior)
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())

    def test_failed_saved_product_baseline_defers_and_opens_original_dispatch(self):
        self.request(self.release('b', self.prior))
        (self.root / 'failed-product-baseline').touch()
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())
        with self.renewal.dispatch_gate() as live:
            self.assertEqual(live, self.prior)
        self.assertFalse(result['proofs'])
        for role in r.ROLES:
            with r.contextlib.closing(Registry(self.renewal.registry_path(role, 'product'))) as registry:
                self.assertEqual(registry.inventory()['dispatch']['state'], 'open')
        self.assertEqual(self.renewal.ledger.inventory()['requests']['recorded-effect']['attempt_id'], self.effect)

    def test_unsettled_general_checkpoint_defers_and_original_uuid_can_continue(self):
        self.request(self.release('b', self.prior))
        (self.root / 'unsettled-general-product-checkpoint').touch()
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertEqual(result['failure']['reason'], 'product continuation deferred: unsettled-general-checkpoint')
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())
        role, logical, operation = 'development', 'one', 'continue-original'
        uuid = self.sessions[role, logical]
        evidence = self.renewal.role_turn({'operation': operation, 'role': role, 'job': 'product', 'logical_session': logical,
                                           'session_uuid': uuid, 'request_sha256': r.sha(operation.encode())}, 'Continue original work')
        self.assertEqual((evidence['state'], evidence['uuid']), ('completed-turn', uuid))
        self.assertEqual(self.renewal.live_release(), self.prior)

    def test_authoritative_provider_escrow_must_cover_every_resume_and_rollback(self):
        target = self.release('b', self.prior)
        self.request(target)
        (self.root / 'insufficient-escrow').touch()
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertEqual(result['failure']['reason'], 'authoritative continuity budget cannot cover recovery')
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())

    def test_prepared_unpublished_attempt_adopts_exact_request_without_duplicate_activation(self):
        target = self.release('b', self.prior)
        self.request(target)
        request = self.renewal.active_request('agent')
        attempt = r.create_directory(self.control / 'attempts' / request['operation'])
        self.renewal.phase(attempt, {'schema': 1, 'request': request, 'freezes': {}, 'proofs': {}}, 'prepared')
        self.assertIsNone(self.renewal.transition()[0])
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'completed', result)
        self.assertEqual(self.renewal.apply('agent'), result)
        self.assertEqual((self.root / 'site-events.jsonl').read_text().count('activate'), 1)

    def test_real_interruption_and_failed_target_host_observation_recover_prior(self):
        target = self.release('b', self.prior, scope='host')
        self.request(target, scope='host')
        (self.root / 'interrupt-release').write_text(target)
        program = ('import pathlib, sys;sys.path.insert(0,sys.argv[1]);import renewal as r;'
                   'root=pathlib.Path(sys.argv[2]);r.Renewal(root,r.SiteDriver(root/"driver",8)).apply("host")')
        child = subprocess.Popen([sys.executable, '-c', program, str(TOOLS), str(self.root)], stdout=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 8
            while not (self.root / 'activation-held').exists():
                self.assertIsNone(child.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
            child.kill()
            child.wait(timeout=4)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=4)
        self.assertTrue((self.effect_lock.parent / 'frozen').exists())
        with self.assertRaisesRegex(ValueError, 'frozen'), self.renewal.dispatch_gate():
            self.fail('interrupted activation admitted new role dispatch')
        deadline = time.monotonic() + 5
        while not (self.root / 'activation-child-finished').exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)
        (self.root / 'failed-host-observation').write_text(target)
        self.renewal.boot_fence()
        unit = (TOOLS.parent / 'runtime/renewal/dev-pair-renewal-recovery.service').read_text()
        self.assertIn('Requires=dev-pair-renewal-boot-fence.service', unit)
        self.assertIn('Wants=network-online.target dev-pair-renewal-host-observe.service', unit)
        result = self.renewal.apply('host')
        self.assertEqual(result['phase'], 'rolled-back', result)
        self.assert_sessions_preserved(result, self.prior)

    def interrupt_at_cutover(self, checkpoint):
        program = '''import pathlib, sys, time
sys.path.insert(0, sys.argv[1])
import renewal as r
root = pathlib.Path(sys.argv[2])
checkpoint = sys.argv[3]
def interrupt():
    (root / 'cutover-point').touch()
    time.sleep(60)
def phase(self, attempt, state, value, **fields):
    original_phase(self, attempt, state, value, **fields)
    if value == checkpoint:
        interrupt()
def abort(self, receipt, binding):
    result = original_abort(self, receipt, binding)
    if checkpoint == 'partial-thaw':
        interrupt()
    return result
original_phase, original_abort = r.Renewal.phase, r.Registry.abort_freeze
r.Renewal.phase, r.Registry.abort_freeze = phase, abort
r.Renewal(root, r.SiteDriver(root/'driver', 8)).apply('host')
'''
        child = subprocess.Popen([sys.executable, '-c', program, str(TOOLS), str(self.root), checkpoint])
        try:
            deadline = time.monotonic() + 15
            while not (self.root / 'cutover-point').exists():
                self.assertIsNone(child.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
        finally:
            child.kill()
            child.wait(timeout=4)
        self.assertTrue((self.effect_lock.parent / 'frozen').exists())
        with self.assertRaisesRegex(ValueError, 'frozen'), self.renewal.dispatch_gate():
            self.fail('an interrupted thaw admitted dispatch')
        self.renewal.boot_fence()

    def test_accepted_cutover_reobserves_and_commits_without_repeating_target_turn(self):
        target = self.release('b', self.prior, scope='host')
        self.request(target, scope='host')
        self.interrupt_at_cutover('accepted')
        self.assertEqual(self.renewal.live_release(), self.prior)
        result = self.renewal.apply('host')
        self.assertEqual(result['phase'], 'completed', result)
        self.assertEqual((self.root / 'site-events.jsonl').read_text().count('activate'), 1)
        self.assert_sessions_preserved(result, target)

    def test_failed_accepted_cutover_refences_partially_open_registries_and_restores_prior(self):
        target = self.release('b', self.prior, scope='host')
        self.request(target, scope='host')
        self.interrupt_at_cutover('partial-thaw')
        self.assertEqual(self.renewal.live_release(), target)
        opened = 0
        for role in r.ROLES:
            with r.contextlib.closing(Registry(self.renewal.registry_path(role, 'product'))) as registry:
                opened += registry.inventory()['dispatch']['state'] == 'open'
        self.assertEqual(opened, 1)
        (self.root / 'failed-host-observation').write_text(target)
        result = self.renewal.apply('host')
        self.assertEqual(result['phase'], 'rolled-back', result)
        self.assertEqual(result['rollback_attempts'], 1)
        self.assert_sessions_preserved(result, self.prior)

    def test_accepted_cutover_without_retained_target_progress_rolls_back(self):
        target = self.release('b', self.prior, scope='host')
        self.request(target, scope='host')
        self.interrupt_at_cutover('accepted')
        history = self.renewal.trees('development', 'product')['state'] / 'one.txt'
        history.write_text(history.read_text().splitlines()[0] + '\n')
        result = self.renewal.apply('host')
        self.assertEqual(result['phase'], 'rolled-back', result)
        self.assert_sessions_preserved(result, self.prior)

    def test_terminal_journal_with_uncleared_cutover_marker_can_still_restore_prior(self):
        target = self.release('b', self.prior, scope='host')
        self.request(target, scope='host')
        self.interrupt_at_cutover('completed')
        self.assertEqual(self.renewal.transition()[1]['phase'], 'completed')
        (self.root / 'failed-host-observation').write_text(target)
        result = self.renewal.apply('host')
        self.assertEqual(result['phase'], 'rolled-back', result)
        self.assert_sessions_preserved(result, self.prior)

    def test_inflight_effect_and_foreign_scope_defer_or_reject_before_replacement(self):
        target = self.release('b', self.prior)
        self.request(target, scope='devbox')
        with self.assertRaisesRegex(ValueError, 'outside approved scope'):
            self.renewal.apply('devbox')
        self.request(target)
        ledger = p.Ledger(self.root / 'ledger')
        try:
            before, existing = ledger.begin('still-pending')
            self.assertIsNone(existing)
        finally:
            ledger.close()
        result = self.renewal.apply('agent')
        self.assertEqual(result['phase'], 'deferred', result)
        self.assertEqual(self.renewal.live_release(), self.prior)
        self.assertEqual(self.renewal.ledger.inventory()['requests']['still-pending']['attempt_id'], before)
        self.assertNotIn('activate', (self.root / 'site-events.jsonl').read_text())
        self.assertFalse((self.effect_lock.parent / 'frozen').exists())

    def test_protected_effect_lock_blocks_new_transition_until_real_owner_leaves(self):
        target = self.release('b', self.prior)
        self.request(target)
        with self.effect_lock.open('rb') as effect:
            fcntl.flock(effect, fcntl.LOCK_SH)
            with self.assertRaises(BlockingIOError):
                self.renewal.apply('agent')
        self.assertEqual(self.renewal.apply('agent')['phase'], 'completed')


class ProgressTests(unittest.TestCase):
    def test_fixed_driver_requires_real_task_specific_work_and_original_next_effect(self):
        driver = runpy.run_path(str(TOOLS.parent / 'runtime' / 'renewal' / 'driver'))
        check = driver['verify_progress']
        def tool(command, body):
            return {'type': 'item.completed', 'item': {'type': 'command_execution', 'command': shlex.join(command),
                    'exit_code': 0, 'aggregated_output': body}}
        file = TOOLS.parent / 'examples' / 'checklist' / 'checklist.py'
        for role in r.ROLES:
            expectation = driver['product_result'](role, r.sha(file.read_bytes()))
            recipe = expectation['recipe']
            planned = driver['product_command'](role, recipe)
            actual = subprocess.check_output(planned, cwd=TOOLS.parent, timeout=18, text=True)
            self.assertEqual(json.loads(actual), expectation)
            reply = {'operation': 'renew-next', 'checkpoint': 'saved-checkpoint', 'recipe': recipe,
                     'next_state': 'retain-pending-host-check'}
            event = {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': json.dumps(reply)}}
            work = {'head': 'a' * 40, 'product_plan_sha256': r.sha(b'approved plan'), 'product_result': expectation}
            spec = {'role': role, 'operation': 'renew-next', 'checkpoint': {'checkpoint_id': 'saved-checkpoint'},
                    'work': work, 'pending_host': ['pending-check']}
            events = b'\n'.join(r.json_bytes(row) for row in (tool(planned, actual), event))
            self.assertEqual(check(events, spec)['result'], expectation)
            with self.assertRaisesRegex(ValueError, 'task-specific product result'):
                check(r.json_bytes(event), spec)
            with self.assertRaisesRegex(ValueError, 'outside the approved product action'):
                check(b'\n'.join(r.json_bytes(row) for row in (tool(driver['STATUS'], ' M file'), event)), spec)
            with self.assertRaisesRegex(ValueError, 'stale'):
                check(events, {**spec, 'operation': 'renew-later'})


if __name__ == '__main__':
    unittest.main()
