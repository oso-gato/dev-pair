import copy
import json
import os
import pathlib
import sqlite3
import time
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

    def test_utf8_near_limit_requests_always_fit_blocked_and_reconciled_results(self):
        artifact, cp, request = self.inputs(message='ready')
        self.send('job', self.job)
        self.send('checkpoint', cp)
        # Reproduce the old 65KB request dead-end: non-ASCII expectations expand
        # under canonical JSON escaping before per-check result fields are added.
        request['checks'] = [{'id': 'check-' + str(i), 'expected': 'é' * 668} for i in range(16)]
        before = self.cli('events')
        oversized = self.root / 'oversized-request.json'
        oversized.write_text(protocol.canonical(request))
        self.assertIn('response-reserving', self.cli('submit', oversized, ok=False))
        self.assertEqual(self.cli('events'), before)
        # Find the actual accepted byte boundary, not an implementation-shaped
        # fixed expected count, then exercise independent CLI executor/consumer.
        last = None
        for length in range(1, 669):
            probe = copy.deepcopy(request)
            for check in probe['checks']:
                check['expected'] = 'é' * length
            try:
                protocol.validate(probe, 'request')
            except ValueError:
                break
            last = probe
        self.assertIsNotNone(last)
        self.assertGreater(len(protocol.canonical(last).encode()), protocol.MAX_REQUEST_BYTES - 100)
        self.send('submit', last)
        blocked = self.cli('execute-local', last['request_id'], '--artifact', artifact)
        self.assertEqual(blocked['status'], 'blocked')
        self.assertEqual(len(blocked['checks']), 16)
        self.assertEqual([c['expected'] for c in blocked['checks']], [c['expected'] for c in last['checks']])
        self.assertLessEqual(len(protocol.canonical(blocked).encode()), protocol.MAX_MESSAGE)
        self.assertEqual(self.cli('consume', last['request_id'])['progress'], 'blocked')
        # A second near-limit request is durably reserved then opened by a
        # separate reconciliation process, as after a controller interruption.
        last['request_id'] = 'request-interrupted-large'
        self.send('submit', last)
        db = protocol.Ledger(self.state)
        try:
            attempt, _ = db.begin(last['request_id'])
        finally:
            db.close()
        diagnostic, evidence = 'é' * 500, ['inspection:' + 'é' * 500]
        self.assertIn('reserved byte budget', self.cli('reconcile', last['request_id'],
                      '--diagnostic', 'é' * 2000, '--evidence', evidence[0], ok=False))
        self.assertEqual(self.cli('status', last['request_id'])['state'], 'in-flight')
        reconciled = self.cli('reconcile', last['request_id'], '--diagnostic', diagnostic, '--evidence', evidence[0])
        self.assertEqual(reconciled['status'], 'blocked')
        self.assertEqual(reconciled['attempt_id'], attempt)
        self.assertEqual(reconciled['diagnostics'], diagnostic)
        self.assertEqual(reconciled['evidence'], evidence)
        self.assertEqual(len(reconciled['checks']), 16)
        self.assertLessEqual(len(protocol.canonical(reconciled).encode()), protocol.MAX_MESSAGE)
        _, fresh_cp, _ = self.inputs('after-large-reconciliation', 'ready')
        self.send('checkpoint', fresh_cp)
        self.assertEqual(self.cli('inspect', 'job-one')['checkpoint_id'], fresh_cp['checkpoint_id'])

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


    def recovery_pair(self):
        backup = self.root / 'backup'
        manifest = self.cli('backup', backup)
        restored = self.root / 'restored'
        output = subprocess.run([sys.executable, str(CLI), '--state', str(restored), 'restore', str(backup)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertEqual(json.loads(output.stdout)['backup_id'], manifest['backup_id'])
        return backup, restored

    def test_recovery_completed_journey_exact_history_and_fresh_continuation(self):
        artifact, cp, request = self.prepared()
        failed = self.cli('execute-local', request['request_id'], '--artifact', artifact)
        self.cli('consume', request['request_id'])
        repaired, cp2, req2 = self.inputs('repaired', 'ready')
        self.send('checkpoint', cp2); self.send('submit', req2)
        passed = self.cli('execute-local', req2['request_id'], '--artifact', repaired)
        self.cli('consume', req2['request_id'])
        before = self.cli('inspect', 'job-one'); events = self.cli('events')
        backup, restored = self.recovery_pair()
        old_state = self.state; self.state = restored
        try:
            self.assertEqual(self.cli('inspect', 'job-one'), before)
            self.assertEqual(self.cli('events'), events)
            artifact.unlink(); repaired.unlink()
            self.assertEqual(self.cli('execute-local', req2['request_id'], '--artifact', repaired), passed)
            self.assertEqual(self.cli('execute-local', request['request_id'], '--artifact', artifact), failed)
            self.assertIn('stale', self.cli('consume', request['request_id'], ok=False))
            fresh, cp3, req3 = self.inputs('continued', 'ready')
            self.send('checkpoint', cp3); self.send('submit', req3)
            self.assertEqual(self.cli('execute-local', req3['request_id'], '--artifact', fresh)['status'], 'pass')
            self.assertEqual(self.cli('consume', req3['request_id'])['progress'], 'local-checks-passed')
        finally:
            self.state = old_state
        self.assertEqual(self.cli('events'), events)
        self.assertEqual(before['requests'][1]['result']['executor']['controller_id'],
                         json.loads((backup / 'manifest.json').read_text())['summary']['controller_id'])
        for root in (backup, restored):
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(f.stat().st_mode & 0o777 == 0o600 for f in root.iterdir()))

    def test_recovery_killed_reservation_keeps_exact_attempt_and_blocks_replay(self):
        artifact, cp, request = self.prepared(message='ready')
        code = ('import sys,time;sys.path.insert(0,sys.argv[1]);from job_protocol import Ledger;'
                'd=Ledger(sys.argv[2]);d.begin(sys.argv[3]);print("reserved",flush=True);time.sleep(60)')
        process = subprocess.Popen([sys.executable, '-c', code, str(ROOT/'tools'), str(self.state), request['request_id']],
                                   stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'reserved')
            process.kill(); process.wait(timeout=5)
        finally:
            if process.poll() is None: process.kill(); process.wait()
            process.stdout.close()
        original = self.cli('status', request['request_id'])
        backup, restored = self.recovery_pair()
        self.state = restored
        self.assertEqual(self.cli('status', request['request_id']), original)
        self.assertIn('reconciliation', self.cli('execute-local', request['request_id'], '--artifact', artifact, ok=False))
        _, cp2, req2 = self.inputs('after-interruption', 'ready')
        self.assertIn('reconciliation', self.send('checkpoint', cp2, ok=False))
        closed = self.cli('reconcile', request['request_id'], '--diagnostic', 'Inspected restored read-only reservation',
                          '--evidence', 'inspection:restored')
        self.assertEqual(closed['attempt_id'], original['attempt_id'])
        self.assertEqual(closed['status'], 'blocked')
        self.send('checkpoint', cp2); self.send('submit', req2)
        self.assertEqual(sum(e['event'] == 'execution-reserved' for e in self.cli('events')), 1)
        # A reconciled history remains valid in another snapshot; no old attempt
        # becomes pending merely because its database is restored again.
        second = self.root/'after-reconciliation'
        self.cli('backup', second)
        again = self.root/'again'
        import ledger_recovery as recovery
        recovery.run('restore', second, again)
        ledger = protocol.Ledger(again)
        try:
            self.assertEqual(ledger.status(request['request_id'])['result'], closed)
            self.assertEqual(ledger.status(req2['request_id'])['state'], 'pending')
        finally:
            ledger.close()

    def rewrite_backup(self, backup, mutate):
        path = backup / 'snapshot.sqlite3'
        with sqlite3.connect(path) as db:
            mutate(db)
        manifest_path = backup / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        data = path.read_bytes()
        manifest.update(snapshot_bytes=len(data), snapshot_sha256=protocol.sha256(data))
        manifest_path.write_text(protocol.canonical(manifest))
        complete = json.loads((backup/'COMPLETE').read_text())
        complete['manifest_sha256'] = protocol.identity(manifest)
        (backup/'COMPLETE').write_text(protocol.canonical(complete))

    def test_recovery_rejects_schema_versions_corruption_and_forged_references(self):
        artifact, cp, req = self.prepared(message='ready')
        self.cli('execute-local', req['request_id'], '--artifact', artifact)
        variants = [
            lambda db: db.execute('PRAGMA user_version=0'),
            lambda db: db.execute('PRAGMA user_version=42'),
            lambda db: db.execute('CREATE TABLE unexpected (body TEXT)'),
            lambda db: db.execute('CREATE VIEW unexpected AS SELECT * FROM records'),
            lambda db: db.execute('CREATE TRIGGER unexpected AFTER INSERT ON jobs BEGIN DELETE FROM records; END'),
            lambda db: db.execute("UPDATE jobs SET checkpoint='missing'"),
            lambda db: db.execute("DELETE FROM events WHERE event='execution-reserved'"),
            lambda db: db.execute("UPDATE requests SET result=replace(result, 'request_sha256', 'forged_hash')"),
            lambda db: db.execute("UPDATE events SET body=replace(body, 'request_sha256', 'forged_hash') WHERE event='result'"),
            lambda db: db.execute("DELETE FROM records WHERE kind='request'"),
        ]
        before = self.cli('events')
        for i, mutate in enumerate(variants):
            backup = self.root / ('bad-backup-' + str(i));self.cli('backup', backup)
            self.rewrite_backup(backup, mutate)
            destination = self.root / ('bad-restore-' + str(i))
            output = subprocess.run([sys.executable, str(CLI), '--state', str(destination), 'restore', str(backup)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(output.returncode, 2, output.stdout)
            self.assertFalse((destination/'COMPLETE').exists())
            # Even a copied database with a failed semantic check is unadmitted.
            output = subprocess.run([sys.executable, str(CLI), '--state', str(destination), 'events'],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(output.returncode, 2)
        self.assertEqual(self.cli('events'), before)

    def test_recovery_hash_truncation_oversize_manifest_and_path_boundaries(self):
        import ledger_recovery as recovery
        self.prepared()
        for name, mutation in [
            ('hash', lambda b: (b/'snapshot.sqlite3').write_bytes(b'corrupt')),
            ('truncated', lambda b: (b/'snapshot.sqlite3').write_bytes((b/'snapshot.sqlite3').read_bytes()[:100])),
            ('oversize', lambda b: os.truncate(b/'snapshot.sqlite3', recovery.MAX_SNAPSHOT + 1)),
            ('manifest', lambda b: (b/'manifest.json').write_text('{"version":99}')),
            ('incomplete', lambda b: (b/'COMPLETE').unlink()),
            ('symlink', lambda b: ((b/'snapshot.sqlite3').rename(b/'original'), (b/'snapshot.sqlite3').symlink_to(b/'original'))),
            ('hardlink', lambda b: os.link(b/'snapshot.sqlite3', b/'alias')),
        ]:
            backup = self.root / ('backup-' + name); self.cli('backup', backup); mutation(backup)
            dest = self.root / ('restore-' + name)
            with self.assertRaises(ValueError): recovery.run('restore', backup, dest)
            self.assertFalse((dest/'COMPLETE').exists())
        backup = self.root / 'private-backup';self.cli('backup', backup)
        canary = self.root/'existing';canary.mkdir(mode=0o700);(canary/'canary').write_text('foreign')
        with self.assertRaises(ValueError): recovery.run('restore', backup, canary)
        self.assertEqual((canary/'canary').read_text(), 'foreign')
        link = self.root/'link';link.symlink_to(canary, target_is_directory=True)
        with self.assertRaises(ValueError): recovery.run('restore', backup, link)
        with self.assertRaises(ValueError): recovery.run('backup', link, self.root/'no-backup')
        if os.getuid() == 0:
            foreign = self.root/'foreign';foreign.mkdir(mode=0o700);os.chown(foreign, 12345, 12345)
            with self.assertRaises(ValueError): recovery.run('restore', backup, foreign)
        # An interrupted mkdir-only reservation must not initialize a fresh DB.
        empty = self.root/'empty-reservation';empty.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'incomplete'): protocol.Ledger(empty)
        self.assertFalse((empty/'ledger.sqlite3').exists())

    def test_recovery_normal_initializer_cannot_admit_concurrent_restore_reservation(self):
        from unittest import mock
        import ledger_recovery as recovery
        self.prepared()
        backup = self.root/'race-backup'
        self.cli('backup',backup)
        destination = self.root/'race-destination'
        original_mkdir = pathlib.Path.mkdir
        process = None
        # Schedule a real restore after Ledger has checked ancestors but before
        # its mkdir. Pause the restore after exclusive reservation, before its
        # first marker. This is ordinary entry-point concurrency, not mutation.
        def reserve_before_mkdir(path,*args,**kwargs):
            nonlocal process
            if path == destination and process is None:
                code = ('import sys,time;sys.path.insert(0,sys.argv[1]);import ledger_recovery as r;'
                        'original=r.trusted_directory\n'
                        'def reserve(path,**kwargs):\n'
                        ' result=original(path,**kwargs)\n'
                        ' if kwargs.get("create"):print("reserved",flush=True);sys.stdin.read(1)\n'
                        ' return result\n'
                        'r.trusted_directory=reserve\n'
                        'print(r.p.canonical(r.restore(sys.argv[2],sys.argv[3],time.monotonic()+10)),flush=True)')
                process = subprocess.Popen([sys.executable,'-c',code,str(ROOT/'tools'),str(backup),str(destination)],
                                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                self.assertEqual(process.stdout.readline().strip(),'reserved')
            return original_mkdir(path,*args,**kwargs)
        before = self.cli('events')
        try:
            with mock.patch.object(pathlib.Path,'mkdir',reserve_before_mkdir):
                with self.assertRaisesRegex(ValueError,'incomplete existing ledger directory'):
                    protocol.Ledger(destination)
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(destination.iterdir()),[])
            self.assertEqual(self.cli('events'),before)
            # The blocked opener did not poison or overwrite the winner. Let
            # the same restore complete and open its validated existing ledger.
            output,error = process.communicate(input='x',timeout=5)
            self.assertEqual(process.returncode,0,error)
            restored = json.loads(output)
            ledger = protocol.Ledger(destination)
            try:
                self.assertEqual(ledger.controller_id,restored['controller_id'])
                self.assertEqual(ledger.events(),before)
            finally:
                ledger.close()
        finally:
            if process is not None:
                if process.poll() is None:process.kill();process.communicate(timeout=2)
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream is not None:stream.close()

    def test_recovery_initializer_reuses_completed_concurrent_normal_ledger(self):
        from unittest import mock
        destination = self.root/'normal-initialization-race'
        original_mkdir = pathlib.Path.mkdir
        winner = None
        def initialize_before_mkdir(path,*args,**kwargs):
            nonlocal winner
            if path == destination and winner is None:
                code = ('import sys;sys.path.insert(0,sys.argv[1]);from job_protocol import Ledger;'
                        'd=Ledger(sys.argv[2]);print(d.controller_id);d.close()')
                result = subprocess.run([sys.executable,'-c',code,str(ROOT/'tools'),str(destination)],
                                        capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                winner = result.stdout.strip()
            return original_mkdir(path,*args,**kwargs)
        with mock.patch.object(pathlib.Path,'mkdir',initialize_before_mkdir):
            ledger = protocol.Ledger(destination)
        try:
            self.assertEqual(ledger.controller_id,winner)
            self.assertEqual(ledger.events(),[])
            self.assertFalse((destination/'RECOVERY').exists())
            self.assertEqual((destination/'ledger.sqlite3').stat().st_mode & 0o777,0o600)
        finally:
            ledger.close()

    def test_recovery_two_real_restores_cannot_replace_destination(self):
        self.prepared()
        backup = self.root/'backup';self.cli('backup', backup)
        dest = self.root/'destination'
        command = [sys.executable,str(CLI),'--state',str(dest),'restore',str(backup)]
        processes = [subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
        outcomes = [(*q.communicate(timeout=15),q.returncode) for q in processes]
        self.assertEqual(sorted(rc for out,err,rc in outcomes), [0,2], outcomes)
        manifest = (dest/'manifest.json').read_bytes();complete = (dest/'COMPLETE').read_bytes()
        self.assertEqual(subprocess.run(command,capture_output=True,timeout=15).returncode, 2)
        self.assertEqual((dest/'manifest.json').read_bytes(),manifest)
        self.assertEqual((dest/'COMPLETE').read_bytes(),complete)

    def test_recovery_real_sqlite_concurrency_busy_deadline_and_killed_staging(self):
        import ledger_recovery as recovery
        self.prepared()
        # Uncommitted source changes are never copied as a partial logical state.
        source = sqlite3.connect(self.state/'ledger.sqlite3',isolation_level=None)
        source.execute('BEGIN IMMEDIATE')
        source.execute("UPDATE jobs SET state='would-be-corrupt'")
        backup = self.root/'concurrent-backup'
        try:
            recovery.run('backup',self.state,backup)
        finally:
            source.execute('ROLLBACK');source.close()
        restored = self.root/'consistent'
        recovery.run('restore',backup,restored)
        d = protocol.Ledger(restored)
        try: self.assertEqual(d.inspect('job-one')['progress'],'awaiting-result')
        finally: d.close()
        second = dict(self.job, job_id='job-two')
        code = ('import sys,time,json;sys.path.insert(0,sys.argv[1]);from job_protocol import Ledger;'
                'd=Ledger(sys.argv[2]);d.db.execute("BEGIN IMMEDIATE");'
                'j=json.loads(sys.argv[3]);d.put(j,j["job_id"]);'
                'd.db.execute("INSERT INTO jobs VALUES (?,NULL,?)",(j["job_id"],"awaiting-checkpoint"));'
                'print("uncommitted",flush=True);time.sleep(.1);d.db.execute("COMMIT");d.close()')
        writer=subprocess.Popen([sys.executable,'-c',code,str(ROOT/'tools'),str(self.state),protocol.canonical(second)],
                                stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(writer.stdout.readline().strip(),'uncommitted')
            committed=self.root/'commit-race';recovery.run('backup',self.state,committed)
            writer.wait(timeout=5)
            self.assertEqual(writer.returncode,0)
        finally:
            if writer.poll() is None:writer.kill();writer.wait()
            writer.stdout.close()
        restored_commit=self.root/'commit-restored';recovery.run('restore',committed,restored_commit)
        d=protocol.Ledger(restored_commit)
        try:
            count=d.db.execute('SELECT count(*) FROM jobs').fetchone()[0]
            self.assertIn(count,(1,2))
            self.assertEqual(sum(e['event']=='job' for e in d.events()),count)
        finally:d.close()
        # An exclusive lock causes a bounded busy blocker, no completion marker.
        lock = sqlite3.connect(self.state/'ledger.sqlite3',isolation_level=None)
        lock.execute('BEGIN EXCLUSIVE')
        started = time.monotonic()
        try:
            with self.assertRaises(ValueError): recovery.backup(self.state,self.root/'busy',time.monotonic()+0.15)
        finally:
            lock.execute('ROLLBACK');lock.close()
        self.assertLess(time.monotonic()-started,2)
        self.assertFalse((self.root/'busy'/'COMPLETE').exists())
        # Kill a real writer exactly before its atomic completion publication.
        for operation, source_root in [('backup',self.state),('restore',backup)]:
            dest = self.root/('killed-'+operation)
            code = ('import sys,time;sys.path.insert(0,sys.argv[1]);import ledger_recovery as r;'
                    'r.publish=lambda *a:(print("staged",flush=True),time.sleep(60));'
                    'getattr(r,sys.argv[2])(sys.argv[3],sys.argv[4],time.monotonic()+10)')
            q = subprocess.Popen([sys.executable,'-c',code,str(ROOT/'tools'),operation,str(source_root),str(dest)],
                                 stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(q.stdout.readline().strip(),'staged')
                q.kill();q.wait(timeout=5)
            finally:
                if q.poll() is None:q.kill();q.wait()
                q.stdout.close()
            self.assertTrue((dest/'RECOVERY').exists())
            self.assertFalse((dest/'COMPLETE').exists())
            with self.assertRaises((ValueError,OSError)):protocol.Ledger(dest)
        self.assertEqual(self.cli('inspect','job-one')['progress'],'awaiting-result')

    def test_recovery_manifest_versions_and_strict_identity_summary(self):
        import ledger_recovery as recovery
        self.prepared()
        for index, mutation in enumerate([
            lambda m: m.update(version=0),
            lambda m: m.update(version=2),
            lambda m: m.update(version=True),
            lambda m: m.update(protocol_version=0),
            lambda m: m.update(unknown='extra'),
            lambda m: m['summary']['counts'].update(requests=0),
            lambda m: m.update(backup_id='f'*32),
        ]):
            backup=self.root/('manifest-backup-'+str(index));self.cli('backup',backup)
            path=backup/'manifest.json';value=json.loads(path.read_text());mutation(value)
            path.write_text(protocol.canonical(value))
            complete=json.loads((backup/'COMPLETE').read_text());complete['manifest_sha256']=protocol.identity(value)
            (backup/'COMPLETE').write_text(protocol.canonical(complete))
            destination=self.root/('manifest-destination-'+str(index))
            with self.assertRaises(ValueError):recovery.run('restore',backup,destination)
            self.assertFalse((destination/'COMPLETE').exists())

    def test_recovery_hard_timeout_reaps_fixed_real_child(self):
        import ledger_recovery as recovery
        from unittest import mock
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            with mock.patch.object(recovery,'SECONDS',0.75), mock.patch.object(recovery.subprocess,'Popen',return_value=child):
                with self.assertRaisesRegex(ValueError,'deadline'):
                    recovery.run('backup',self.root/'unused',self.root/'unused-destination')
            self.assertIsNotNone(child.poll())
            self.assertLess(child.returncode,0)
        finally:
            if child.poll() is None:child.kill();child.communicate(timeout=2)

    def test_recovery_preserves_historical_recipe_and_blocks_old_pending_identity(self):
        artifact, cp, request = self.inputs(message='ready')
        cp['test']['revision'] = cp['test']['recipe_sha256'] = 'f'*64
        request['test'] = cp['test']
        self.send('job',self.job);self.send('checkpoint',cp);self.send('submit',request)
        backup,restored = self.recovery_pair();self.state=restored
        self.assertEqual(self.cli('status',request['request_id'])['request'],request)
        result=self.cli('execute-local',request['request_id'],'--artifact',artifact)
        self.assertEqual(result['status'],'blocked')
        self.assertIn('changed trusted local recipe',result['diagnostics'])


if __name__ == '__main__':
    unittest.main()
