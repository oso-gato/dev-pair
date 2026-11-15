import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import job_protocol as protocol

CLI = ROOT / 'tools/jobs.py'


class DurableJobsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.state = self.root / 'state'
        self.job = protocol.envelope('job', job_id='job-one', standards_sha=protocol.STANDARDS,
                                    agreement_sha256='a' * 64,
                                    selection={'provider': 'gptbox', 'model': 'gpt-6.1-sol', 'effort': 'high',
                                               'runtime_sha256': 'b' * 64, 'verification': 'unverified-record-only'},
                                    budgets={'seconds': 5, 'artifact_bytes': 4096, 'spend_usd': 0}, max_requests=4)

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(CLI), '--state', str(self.state), *map(str, args)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0 if ok else 2, result.stderr)
        return json.loads(result.stdout) if ok else result.stderr

    def send(self, command, message, ok=True):
        path = self.root / (command + '.json')
        path.write_text(json.dumps(message))
        return self.cli(command, path, ok=ok)

    def inputs(self, suffix='one', message='broken'):
        artifact = self.root / (suffix + '.json')
        artifact.write_text(json.dumps({'message': message}))
        cp = protocol.envelope('checkpoint', job_id='job-one', checkpoint_id='cp-' + suffix,
                               candidate={'source_revision': protocol.sha256(suffix.encode())[:40],
                                          'artifact_sha256': protocol.sha256(artifact.read_bytes())},
                               test=protocol.recipe_identity(), summary='Durable local checkpoint ' + suffix,
                               evidence=['local-source:' + suffix])
        request = protocol.envelope('request', job_id='job-one', request_id='request-' + suffix,
                                    checkpoint_id=cp['checkpoint_id'], candidate=cp['candidate'], test=cp['test'],
                                    boundary='local-protocol', reason='Exercise local protocol, no host claim',
                                    capabilities=['local-json-read'], permitted_effects=['read-artifact', 'write-ledger'],
                                    workspace='workspace-one', fixtures=[], budgets=self.job['budgets'],
                                    checks=[{'id': 'json-object', 'expected': 'object containing only a message string'},
                                            {'id': 'message-equals', 'expected': 'ready'}],
                                    cleanup={'plan': 'No disposable resources; retain all durable records',
                                             'preserve': ['source', 'checkpoints', 'evidence', 'deliverables']})
        return artifact, cp, request

    def prepared(self, suffix='one', message='broken'):
        artifact, cp, request = self.inputs(suffix, message)
        self.send('job', self.job)
        self.send('checkpoint', cp)
        self.send('submit', request)
        return artifact, cp, request

    def test_real_cli_failure_repair_and_matching_success_survive_restarts(self):
        artifact, cp, request = self.prepared()
        failure = self.cli('execute-local', request['request_id'], '--artifact', artifact)
        self.assertEqual([c['status'] for c in failure['checks']], ['pass', 'fail'])
        self.assertEqual(self.cli('consume', request['request_id'])['progress'], 'repair-required')
        repaired, fresh_cp, fresh_request = self.inputs('two', 'ready')
        self.send('checkpoint', fresh_cp)
        self.send('submit', fresh_request)
        passing = self.cli('execute-local', fresh_request['request_id'], '--artifact', repaired)
        self.assertEqual(passing['status'], 'pass')
        self.assertEqual(self.cli('consume', fresh_request['request_id'])['progress'], 'local-checks-passed')
        self.assertIn('stale', self.cli('consume', request['request_id'], ok=False))
        # A replayed old checkpoint cannot roll back repaired progress either.
        self.send('checkpoint', cp)
        state = self.cli('inspect', 'job-one')
        self.assertEqual(state['checkpoint_id'], fresh_cp['checkpoint_id'])
        self.assertEqual(state['progress'], 'local-checks-passed')
        self.assertEqual([r['result']['status'] for r in state['requests']], ['fail', 'pass'])
        self.assertEqual(self.cli('execute-local', fresh_request['request_id'], '--artifact', '/missing'), passing)
        events = self.cli('events')
        self.assertEqual(sum(e['event'] == 'execution-reserved' for e in events), 2)
        self.assertEqual(sum(e['event'] == 'checkpoint' for e in events), 2)
        self.assertTrue(artifact.exists() and repaired.exists())

    def test_killed_real_process_requires_reconciliation_and_never_replays(self):
        artifact, cp, request = self.prepared(message='ready')
        code = ('import sys,time; sys.path.insert(0,sys.argv[1]); from job_protocol import Ledger; '
                'db=Ledger(sys.argv[2]); db.begin(sys.argv[3]); print("reserved",flush=True); time.sleep(60)')
        process = subprocess.Popen([sys.executable, '-c', code, str(ROOT / 'tools'), str(self.state), request['request_id']],
                                   stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'reserved')
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
        status = self.cli('status', request['request_id'])
        self.assertTrue(status['reconciliation_required'])
        self.assertEqual(self.send('submit', request)['attempt_id'], status['attempt_id'])
        self.assertIn('reconciliation', self.cli('execute-local', request['request_id'], '--artifact', artifact, ok=False))
        _, new_cp, new_request = self.inputs('two', 'ready')
        self.assertIn('reconciliation', self.send('checkpoint', new_cp, ok=False))
        closed = self.cli('reconcile', request['request_id'], '--diagnostic', 'Inspected fixed read-only recipe and durable reservation',
                          '--evidence', 'local-inspection:one')
        self.assertEqual(closed['status'], 'blocked')
        self.assertEqual(closed['attempt_id'], status['attempt_id'])
        self.assertEqual(self.cli('execute-local', request['request_id'], '--artifact', artifact), closed)
        self.send('checkpoint', new_cp)
        self.send('submit', new_request)
        self.assertEqual(len([e for e in self.cli('events') if e['event'] == 'execution-reserved']), 1)

    def test_two_real_controllers_reserve_one_attempt(self):
        artifact, cp, request = self.prepared(message='ready')
        command = [sys.executable, str(CLI), '--state', str(self.state), 'execute-local', request['request_id'], '--artifact', str(artifact)]
        processes = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        results = [(*p.communicate(timeout=15), p.returncode) for p in processes]
        self.assertTrue(any(rc == 0 for out, err, rc in results), results)
        for out, err, rc in results:
            self.assertIn(rc, (0, 2), err)
            if rc == 2:
                self.assertIn('reconciliation', err)
        final = self.cli('status', request['request_id'])
        self.assertEqual(final['result']['status'], 'pass')
        self.assertEqual(len([e for e in self.cli('events') if e['event'] == 'execution-reserved']), 1)

    def test_collision_unknown_version_and_unknown_fields_have_no_effect(self):
        artifact, cp, request = self.prepared()
        before = self.cli('events')
        variants = []
        for path, value in [('version', 2), ('version', True), ('unknown', 'authority'), ('reason', 'different')]:
            item = copy.deepcopy(request)
            item[path] = value
            variants.append(item)
        nested = copy.deepcopy(request)
        nested['candidate']['executor'] = 'root'
        variants.append(nested)
        for item in variants:
            self.send('submit', item, ok=False)
        self.assertEqual(self.cli('events'), before)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            protocol.loads('{"version":1,"version":2}')

    def test_host_boundary_and_unsupported_capabilities_are_blocked(self):
        artifact, cp, request = self.inputs()
        request['boundary'] = 'fedora-host'
        request['capabilities'] = ['systemd', 'selinux']
        self.send('job', self.job)
        self.send('checkpoint', cp)
        self.send('submit', request)
        result = self.cli('execute-local', request['request_id'], '--artifact', '/missing')
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(all(c['status'] == 'blocked' for c in result['checks']))
        self.assertIn('No verified Fedora', result['diagnostics'])
        self.assertEqual(self.cli('consume', request['request_id'])['progress'], 'blocked')

    def test_cli_request_producer_uses_consumer_schema_and_actual_recipe_revision(self):
        artifact, cp, _ = self.inputs(message='ready')
        self.send('job', self.job)
        self.send('checkpoint', cp)
        produced = self.cli('request', 'job-one', 'produced-one', '--expected-message', 'ready', '--reason', 'Local protocol check')
        self.assertEqual(protocol.validate(produced['request'], 'request')['test'], protocol.recipe_identity())
        self.assertEqual(self.send('submit', produced['request']), produced)
        self.assertEqual(self.cli('execute-local', 'produced-one', '--artifact', artifact)['status'], 'pass')
        cp['checkpoint_id'] = 'cp-wrong-recipe'
        cp['test']['revision'] = 'f' * 64
        self.send('checkpoint', cp)
        self.cli('request', 'job-one', 'produced-two', '--expected-message', 'ready', '--reason', 'Stale test implementation')
        result = self.cli('execute-local', 'produced-two', '--artifact', artifact)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('changed trusted local recipe', result['diagnostics'])

    def test_identity_mismatch_budget_and_artifact_mutation_do_not_pass(self):
        artifact, cp, request = self.inputs(message='ready')
        self.send('job', self.job)
        self.send('checkpoint', cp)
        changed = copy.deepcopy(request)
        changed['candidate']['artifact_sha256'] = 'f' * 64
        self.assertIn('mismatch', self.send('submit', changed, ok=False))
        changed = copy.deepcopy(request)
        changed['budgets']['artifact_bytes'] = 8192
        self.assertIn('budget', self.send('submit', changed, ok=False))
        self.send('submit', request)
        artifact.write_text('{"message":"mutated"}')
        result = self.cli('execute-local', request['request_id'], '--artifact', artifact)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('digest mismatch', result['diagnostics'])

    def test_rollback_and_unsupported_database_version(self):
        db = protocol.Ledger(self.state)
        try:
            with self.assertRaises(RuntimeError):
                with db.transaction():
                    db.put(self.job, self.job['job_id'])
                    raise RuntimeError('simulated controller failure before commit')
            self.assertEqual(db.events(), [])
            with self.assertRaisesRegex(ValueError, 'unknown job'):
                db.record('job', self.job['job_id'])
            db.db.execute('PRAGMA user_version=42')
        finally:
            db.close()
        self.assertIn('unsupported ledger version', self.cli('events', ok=False))

    def test_distinct_request_budget_is_durable_and_duplicate_does_not_spend_it(self):
        self.job['max_requests'] = 1
        artifact, cp, request = self.prepared()
        self.assertEqual(self.send('submit', request)['state'], 'pending')
        request['request_id'] = 'request-extra'
        self.assertIn('budget exhausted', self.send('submit', request, ok=False))
        self.assertEqual(len(self.cli('inspect', 'job-one')['requests']), 1)

    def test_private_filesystem_boundary_and_fifo_rejection(self):
        self.state.mkdir(mode=0o755)
        self.state.chmod(0o755)
        self.assertIn('0700', self.cli('events', ok=False))
        self.state.rmdir()
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        self.state.symlink_to(target)
        self.assertIn('symlink', self.cli('events', ok=False))
        self.state.unlink()
        artifact, cp, request = self.prepared(message='ready')
        artifact.unlink()
        os.mkfifo(artifact)
        result = self.cli('execute-local', request['request_id'], '--artifact', artifact)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('regular data file', result['diagnostics'])
        self.assertEqual(oct((self.state / 'ledger.sqlite3').stat().st_mode & 0o777), '0o600')

    def test_result_binding_rejects_forgery_and_stale_test(self):
        artifact, cp, request = self.prepared(message='ready')
        db = protocol.Ledger(self.state)
        try:
            attempt, _ = db.begin(request['request_id'])
            result = db.make_result(request, attempt, db.blocked_checks(request, 'not run'), 'not run')
            for key in ('request_sha256',):
                forged = copy.deepcopy(result)
                forged[key] = 'f' * 64
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    db.finish(forged)
            forged = copy.deepcopy(result)
            forged['executor']['controller_id'] = 'other-controller'
            with self.assertRaisesRegex(ValueError, 'controller identity'):
                db.finish(forged)
            db.finish(result)
            altered_cp = copy.deepcopy(cp)
            altered_cp['checkpoint_id'] = 'cp-new-test'
            altered_cp['test']['revision'] = 'd' * 64
            db.checkpoint(altered_cp)
            with self.assertRaisesRegex(ValueError, 'stale'):
                db.consume(request['request_id'])
        finally:
            db.close()


if __name__ == '__main__':
    unittest.main()
