import contextlib
import io
import os
from pathlib import Path
import pwd
import shlex
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checklist_candidate as candidate
import candidate_git
import candidate_snapshot
import host_handoff as handoff
import job_protocol as p
import ledger_recovery as recovery
import product_job as job
from test_checklist_quadlet import FixtureService


class ProductJobTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = 'owner/approved-checklist'
        self.value = {'schema': 1, 'job_id': 'demo', 'adapter': 'checklist-quadlet',
                      'agreement': {'repository': self.repo, 'initial_commit': 'a' * 40,
                                    'brief': 'Repair persistence after a service restart.\nKeep the same item.',
                                    'host_seconds': 45, 'build_seconds': 120, 'turn_seconds': 90},
                      'startup_sha256': 'b' * 64}

    def git(self, work, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(work), *args], check=True,
                              capture_output=True, timeout=4).stdout.decode().strip()

    def source_workspace(self):
        path = self.root / 'development/workspaces/demo'
        path.mkdir(parents=True)
        self.git(path, 'init', '-b', 'main')
        self.git(path, 'config', 'user.name', 'Local fixture')
        self.git(path, 'config', 'user.email', 'fixture@example.com')
        self.git(path, 'remote', 'add', 'origin', 'https://github.com/' + self.repo)
        source = path / candidate.APP
        source.parent.mkdir(parents=True)
        source.write_text('# baseline\n')
        self.git(path, 'add', candidate.APP)
        self.git(path, 'commit', '-m', 'Baseline')
        approved = {'repository': self.repo, 'acquired_commit': self.git(path, 'rev-parse', 'HEAD'),
                    'acquired_tree': self.git(path, 'rev-parse', 'HEAD^{tree}')}
        return path, source, approved

    @contextlib.contextmanager
    def local_git(self):
        user = pwd.getpwuid(os.getuid())
        with mock.patch.multiple(candidate, ROOT=self.root, as_role=lambda role, *argv, **kw: list(map(str, argv))), \
                mock.patch.object(candidate.pwd, 'getpwnam', return_value=user):
            yield

    def test_exact_committed_blob_ignores_dirty_workspace_and_rejects_foreign_or_symlink(self):
        path, source, approved = self.source_workspace()
        base = approved['acquired_commit']
        source.write_text('# dirty work preserved\n')
        with self.local_git():
            git = candidate.git_runner(path, 'dp-dev', time.monotonic() + 10)
            self.assertEqual(candidate.approved_source(git, path, approved, base), b'# baseline\n')
            self.assertEqual(source.read_text(), '# dirty work preserved\n')
            with self.assertRaisesRegex(ValueError, 'authorized repository'):
                candidate.approved_source(git, path, dict(approved, repository='foreign/checkout'), base)
            source.unlink()
            source.symlink_to('/dev/null')
            self.git(path, 'add', candidate.APP)
            self.git(path, 'commit', '-m', 'Wrong source type')
            with self.assertRaisesRegex(ValueError, 'regular blob'):
                candidate.approved_source(git, path, approved, self.git(path, 'rev-parse', 'HEAD'))

    def test_maintenance_mirror_preserves_dirty_state_and_imports_exact_clean_successor(self):
        path, source, approval = self.source_workspace()
        maintenance = self.root / 'maintenance/workspaces/demo'
        maintenance.parent.mkdir(parents=True)
        (self.root / 'maintenance/conductor-inputs').mkdir(mode=0o700)
        subprocess.run(['/usr/bin/git', 'clone', '--no-local', str(path), str(maintenance)], check=True,
                       capture_output=True, timeout=4)
        self.git(maintenance, 'remote', 'set-url', 'origin', 'https://github.com/' + self.repo)
        source.write_text('# repaired\n')
        self.git(path, 'add', candidate.APP)
        self.git(path, 'commit', '-m', 'Repair')
        revision = self.git(path, 'rev-parse', 'HEAD')
        maintained = maintenance / candidate.APP
        maintained.write_text('# uncommitted maintenance data\n')
        with self.local_git():
            with self.assertRaisesRegex(ValueError, 'retained'):
                candidate.mirror_maintenance('demo', approval, revision, time.monotonic() + 10)
            self.assertEqual(maintained.read_text(), '# uncommitted maintenance data\n')
            self.git(maintenance, 'checkout', '--', candidate.APP)
            candidate.mirror_maintenance('demo', approval, revision, time.monotonic() + 10)
            candidate.mirror_maintenance('demo', approval, revision, time.monotonic() + 10)
        self.assertEqual(self.git(maintenance, 'rev-parse', 'HEAD'), revision)
        self.assertEqual(maintained.read_text(), '# repaired\n')
        self.assertEqual(list((self.root / 'maintenance/conductor-inputs').iterdir()), [])

    def test_archive_transport_matches_exact_manifest_and_config(self):
        config = b'{"architecture":"amd64","os":"linux"}'
        ident = p.sha256(config)
        manifest = p.canonical({'schemaVersion': 2, 'config': {'digest': 'sha256:' + ident, 'size': len(config)},
                               'layers': []}).encode()
        digest = p.sha256(manifest)
        descriptor = {'digest': 'sha256:' + digest, 'size': len(manifest),
                      'mediaType': 'application/vnd.oci.image.manifest.v1+json'}
        index = p.canonical({'schemaVersion': 2, 'manifests': [descriptor]}).encode()
        path = self.root / 'candidate.oci'
        for data in (manifest, manifest + b' '):
            with tarfile.open(path, 'w:') as out:
                for name, raw in (('index.json', index), ('blobs/sha256/' + digest, data), ('blobs/sha256/' + ident, config)):
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    out.addfile(member, io.BytesIO(raw))
            with mock.patch.object(candidate.pwd, 'getpwnam', return_value=pwd.getpwuid(os.getuid())):
                if data == manifest:
                    candidate.archive_manifest(path, ident, digest, time.monotonic() + 2)
                else:
                    with self.assertRaisesRegex(ValueError, 'descriptor digest changed'):
                        candidate.archive_manifest(path, ident, digest, time.monotonic() + 2)

    def test_detached_submit_idempotently_records_one_approved_agreement(self):
        catalogue = self.root / 'jobs'
        catalogue.mkdir(mode=0o700)
        plan = self.root / 'approved.json'
        plan.write_text(p.canonical(self.value))
        with mock.patch.object(job, 'JOBS', catalogue), mock.patch.object(candidate, 'protected_file',
                side_effect=lambda path, *args: path.read_bytes()), mock.patch.object(job, 'source_approval'), \
                mock.patch.object(candidate, 'invoke', return_value=b'') as start:
            first = job.submit(plan)
            self.assertEqual(first['phase'], 'submitted')
            self.assertEqual(first, job.submit(plan))
            self.assertEqual(start.call_args.args[0][-2:], ['--no-block', 'dev-pair-product@demo.service'])
            updated = {**self.value, 'agreement': {**self.value['agreement'], 'brief': 'Different agreement'}}
            plan.write_text(p.canonical(updated))
            with self.assertRaisesRegex(ValueError, 'another brief'):
                job.submit(plan)
            self.assertEqual(start.call_count, 2)

    def test_retained_host_failure_drives_changed_dev_candidate_and_fresh_retest(self):
        source = self.value['agreement']['initial_commit']
        repaired = 'c' * 40
        state = dict.fromkeys(('initial', 'maintenance', 'first', 'development', 'repair', 'final'))
        path = self.root / 'state.json'
        effects = []
        failure = {'progress': 'repair-required', 'result': {'attempt_id': 'effect-1', 'status': 'fail',
                                                           'diagnostics': 'Completed ID disappeared after restart'}}
        success = {'progress': 'host-checks-passed', 'result': {'attempt_id': 'effect-2', 'status': 'pass'}}
        case = self

        class Workflow:
            def build(self, ordinal, revision):
                effects.append(('build', ordinal, revision))
                return {'candidate': {'source_revision': revision}}

            def turn(self, role, checkpoint, result=None):
                if role == 'maintenance':
                    effects.append(('maintenance', checkpoint['candidate']['source_revision']))
                    return {'session_uuid': 'fixture-maintenance'}
                if effects[-1] == ('host', 1, source):
                    effects.append(('interrupted',))
                    raise BlockingIOError('fixture disconnected after durable host failure')
                case.assertEqual(result, failure)
                effects.append(('development', result['result']['attempt_id']))
                return {'session_uuid': 'fixture-development', 'base_sha': source,
                        'local_validation': {'exit_status': 0, 'snapshot_sha256': 'd' * 64}}

            def materialize(self, checkpoint, development):
                case.assertEqual(checkpoint['candidate']['source_revision'], source)
                effects.append(('materialized', development['local_validation']['snapshot_sha256']))
                return {'candidate_sha': repaired, 'binding': {'base_sha': source, 'snapshot_sha256': 'd' * 64}}

            def host_test(self, ordinal, checkpoint):
                effects.append(('host', ordinal, checkpoint['candidate']['source_revision']))
                return failure if ordinal == 1 else success

        backend = Workflow()
        with self.assertRaises(BlockingIOError):
            job.execute(self.value, state, backend, lambda row: job.durable_json(path, row))
        state = p.loads(path.read_bytes())
        self.assertEqual(state['first'], failure)
        job.execute(self.value, state, backend, lambda row: job.durable_json(path, row))
        self.assertEqual(state['phase'], 'passed')
        self.assertEqual(state['final'], success)
        self.assertEqual(effects, [('build', 1, source), ('maintenance', source), ('host', 1, source),
                                   ('interrupted',), ('development', 'effect-1'), ('materialized', 'd' * 64), ('build', 2, repaired),
                                   ('host', 2, repaired)])

    def test_general_repository_records_actual_local_test_and_holds_only_external_boundary(self):
        workspace, _, _ = self.source_workspace()
        self.git(workspace, 'rm', candidate.APP)
        (workspace / 'product.txt').write_text('Old product result\n')
        (workspace / 'test_product.py').write_text(
            'import pathlib\nimport unittest\n'
            'class ProductTest(unittest.TestCase):\n'
            '    def test_agreed_result(self):\n'
            '        self.assertEqual(pathlib.Path("product.txt").read_text().strip(), "Approved change")\n')
        self.git(workspace, 'add', '--all')
        self.git(workspace, 'commit', '-m', 'General product, no checklist source')
        initial = self.git(workspace, 'rev-parse', 'HEAD')
        approval = dict(repository=self.repo, acquired_commit=initial,
                        acquired_tree=self.git(workspace, 'rev-parse', 'HEAD^{tree}'))
        maintenance = self.root / 'maintenance/workspaces/demo'
        maintenance.parent.mkdir(parents=True)
        (self.root / 'maintenance/conductor-inputs').mkdir(mode=0o700)
        (self.root / 'development/conductor-inputs').mkdir(mode=0o700)
        subprocess.run(['/usr/bin/git', 'clone', '--no-local', str(workspace), str(maintenance)], check=True,
                       capture_output=True, timeout=4)
        self.git(maintenance, 'remote', 'set-url', 'origin', 'https://github.com/' + self.repo)
        value = job.plan(p.canonical(dict(self.value, adapter=job.EXTERNAL_ADAPTER,
            agreement=dict(self.value['agreement'], initial_commit=initial,
                           brief='Change the document result and record the deployment observation as pending.'))))
        backend = object.__new__(job.FedoraJob)
        backend.runtime = mock.Mock(dispatch_gate=contextlib.nullcontext)
        backend.plan, backend.agreement, backend.approval, backend.job = value, value['agreement'], approval, 'demo'
        backend.ledger = mock.Mock()
        backend.host_test = mock.Mock(side_effect=AssertionError('general mode cannot use the host recipe'))
        role_effects = []
        root = self.root / 'candidate-job'
        root.mkdir(mode=0o700)

        def turn(role, checkpoint):
            role_effects.append((role, checkpoint['candidate']['source_revision']))
            if role == 'maintenance':
                return {'session_uuid': 'unchanged-maintenance-uuid'}
            (workspace / 'product.txt').write_text('Approved change\n')
            prefix, suffix = candidate_git.witness()
            script = prefix + '/usr/bin/python3 -B -m unittest test_product.py' + suffix
            actual = subprocess.run(['/bin/sh', '-c', script.replace('/work/job', shlex.quote(str(workspace)))],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, timeout=5)
            command = shlex.join(['/bin/bash', '-lc', script])
            item = {'type': 'command_execution', 'id': 'item_7', 'command': command}
            rows = [
                {'type': 'item.started', 'item': dict(item, status='in_progress', exit_code=None, aggregated_output='')},
                {'type': 'item.completed', 'item': dict(item, status='completed', exit_code=actual.returncode,
                                                        aggregated_output=actual.stdout.decode())},
                {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': p.canonical(
                    {'base_sha': initial, 'summary': 'The agreed local product test passed.'})}},
            ]
            events = '\n'.join(map(p.canonical, rows)).encode()
            developed = job.proposal(events, source=True)
            return dict(developed, session_uuid='unchanged-development-uuid', events_sha256=p.sha256(events))

        backend.turn = turn
        def materialize(checkpoint, development):
            self.assertEqual(checkpoint['candidate']['source_revision'], initial)
            binding = {'job_id': 'demo', 'operation': 'demo-development', 'base_sha': initial,
                       'snapshot_sha256': development['local_validation']['snapshot_sha256'],
                       'session_uuid': development['session_uuid']}
            return candidate_git.materialize(self.root, root, approval, binding, time.monotonic() + 20)

        backend.materialize = mock.Mock(side_effect=materialize)
        state = dict.fromkeys(('initial', 'maintenance', 'first', 'development', 'repair', 'final'))
        persisted = self.root / 'general.json'
        with self.local_git(), mock.patch.object(job, 'ROOT', self.root):
            job.execute(value, state, backend, lambda row: job.durable_json(persisted, row))
            restored = p.loads(persisted.read_bytes())
            job.execute(value, restored, backend, lambda row: job.durable_json(persisted, row))
            local = job.plan(p.canonical(dict(value, adapter=job.LOCAL_ADAPTER)))
            self.assertNotEqual(job.agreement_sha(local), job.agreement_sha(value))
        self.assertEqual(restored['phase'], 'awaiting-external-validation')
        self.assertEqual(p.loads(persisted.read_bytes())['phase'], 'awaiting-external-validation')
        outcome = restored['local_validation']
        self.assertEqual(outcome['session_uuid'], 'unchanged-development-uuid')
        self.assertTrue(outcome['source_changed'])
        revision = self.git(workspace, 'rev-parse', 'HEAD')
        self.assertEqual((outcome['candidate_sha'], self.git(maintenance, 'rev-parse', 'HEAD')), (revision, revision))
        self.assertEqual(role_effects, [('maintenance', initial), ('development', initial)])
        backend.materialize.assert_called_once()
        backend.host_test.assert_not_called()

    def test_general_validation_requires_a_successful_witness_of_the_final_revision(self):
        revision = 'a' * 40
        marker = job.LOCAL_HEAD_MARKER + revision
        command = job.LOCAL_TEST_PREFIX + '/usr/bin/python3 -B -m unittest' + job.LOCAL_TEST_SUFFIX
        item = {'id': 'item_1', 'type': 'command_execution', 'command': command}
        rows = [{'type': 'item.started', 'item': item},
                {'type': 'item.completed', 'item': dict(item, status='completed', exit_code=0,
                                                       aggregated_output=marker + '\nOK\n' + marker)}]
        read = lambda entries: job.observed_validation('\n'.join(map(p.canonical, entries)).encode(), revision)
        self.assertEqual(read(rows)['exit_status'], 0)
        renamed = dict(item, id='item_2')
        later_failure = rows + [{'type': 'item.started', 'item': renamed},
            {'type': 'item.completed', 'item': dict(renamed, status='failed', exit_code=1,
                                                   aggregated_output=marker + '\nTest failed\n')}]
        for events in (rows[1:], later_failure,
                       rows[:1] + [{'type': 'item.completed', 'item': dict(rows[1]['item'],
                           aggregated_output=marker + '\nOK\n' + job.LOCAL_HEAD_MARKER + 'b' * 40)}]):
            with self.assertRaisesRegex(ValueError, 'no successful stock test'):
                read(events)

    def test_dirty_tested_bytes_materialize_once_and_recover_after_ref_publication(self):
        workspace, source, approval = self.source_workspace()
        old = workspace / 'obsolete.txt'
        old.write_text('Old file\n')
        self.git(workspace, 'add', 'obsolete.txt')
        self.git(workspace, 'commit', '-m', 'Add obsolete file')
        base = self.git(workspace, 'rev-parse', 'HEAD')
        approval.update(acquired_commit=base, acquired_tree=self.git(workspace, 'rev-parse', 'HEAD^{tree}'))
        job_root = self.root / 'job'
        job_root.mkdir(mode=0o700)
        (self.root / 'development/conductor-inputs').mkdir(mode=0o700)
        source.write_text('# repaired source\n')
        old.unlink()
        newcomer = workspace / 'added source.txt'
        newcomer.write_text('New relevant source\n')
        prefix, suffix = candidate_git.witness()
        script = prefix + '/usr/bin/python3 -IB -c "from pathlib import Path; assert Path(\'added source.txt\').is_file()"' + suffix
        actual = subprocess.run(['/bin/sh', '-c', script.replace('/work/job', shlex.quote(str(workspace)))],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        command = shlex.join(['/bin/bash', '-c', script])
        item = {'id': 'item_5', 'type': 'command_execution', 'command': command}
        witness = [{'type': 'item.started', 'item': item},
                   {'type': 'item.completed', 'item': dict(item, exit_code=0, status='completed',
                                                          aggregated_output=actual.stdout.decode())},
                   {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': p.canonical(
                       {'base_sha': base, 'summary': 'The local test observed the added source.'})}}]
        proposed = job.proposal('\n'.join(map(p.canonical, witness)).encode(), source=True)
        digest = candidate_snapshot.scan(workspace)[0]
        self.assertEqual(proposed['local_validation']['snapshot_sha256'], digest)
        binding = {'job_id': 'demo', 'operation': 'demo-development', 'base_sha': base, 'snapshot_sha256': digest,
                   'session_uuid': '01a21ce9-a96d-7a13-85e7-fa8bbbcf6ba4'}
        git_runner = candidate.git_runner

        def pause_live_index(*args, **kwargs):
            invoke = git_runner(*args, **kwargs)

            def run(*command, **options):
                if command[0] == 'read-tree':
                    raise BlockingIOError('fixture worker interrupted before index update')
                return invoke(*command, **options)

            return run

        with self.local_git():
            with mock.patch.object(candidate, 'git_runner', side_effect=pause_live_index), \
                    self.assertRaisesRegex(BlockingIOError, 'before index update'):
                candidate_git.materialize(self.root, job_root, approval, binding, time.monotonic() + 20)
            retained = p.loads((job_root / 'candidate' / 'receipt.json').read_bytes())
            self.assertEqual(self.git(workspace, 'rev-parse', 'HEAD'), retained['candidate_sha'])
            self.assertEqual(source.read_text(), '# repaired source\n')
            self.assertFalse(old.exists())
            self.assertEqual(newcomer.read_text(), 'New relevant source\n')
            self.assertEqual(candidate_git.materialize(self.root, job_root, approval, binding, time.monotonic() + 20), retained)
            self.assertEqual(candidate_git.materialize(self.root, job_root, approval, binding, time.monotonic() + 20), retained)
            dirty = workspace / 'new-uncommitted-change.txt'
            dirty.write_text('Keep post-test changes visible.\n')
            with self.assertRaisesRegex(ValueError, 'files changed after'):
                candidate_git.materialize(self.root, job_root, approval, binding, time.monotonic() + 20)
            self.assertEqual(dirty.read_text(), 'Keep post-test changes visible.\n')
            dirty.unlink()
        self.assertEqual(self.git(workspace, 'rev-list', '--count', base + '..HEAD'), '1')
        self.assertEqual(self.git(workspace, 'rev-parse', 'HEAD^'), base)
        self.assertEqual(self.git(workspace, 'show', 'HEAD:added source.txt'), 'New relevant source')
        self.assertEqual(self.git(workspace, 'status', '--porcelain=v1', '--untracked-files=all'), '')

    def test_invalid_or_unapproved_product_inputs_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'authorized validation adapter'):
            job.plan(p.canonical(dict(self.value, adapter='arbitrary-shell')).encode())
        with self.assertRaisesRegex(ValueError, 'numeric budget'):
            job.plan(p.canonical(dict(self.value, schema=True)).encode())
        with self.assertRaises(ValueError):
            job.proposal(b'{"type":"item.completed","item":{"type":"agent_message","text":"run sudo"}}')

    def test_lost_host_reply_retrieves_matching_effect_without_second_execution(self):
        adapter = object.__new__(job.FedoraJob)
        adapter.job = 'demo'
        adapter.runtime = mock.Mock(dispatch_gate=contextlib.nullcontext)
        budgets = {'seconds': 35, 'artifact_bytes': 8192, 'spend_usd': 0}
        checkpoint = p.envelope('checkpoint', job_id='demo', checkpoint_id='demo-c1',
                                candidate={'source_revision': 'a' * 40, 'artifact_sha256': 'b' * 64},
                                test=handoff.recipe_identity(host=True), summary='Approved first candidate', evidence=[])
        adapter.controller = mock.Mock()
        adapter.controller.ledger.checkpoint.return_value = ['controller', {'budgets': budgets}, checkpoint]
        operations = []
        result = None

        def transport(port, context, peer, operation, request):
            nonlocal result
            operations.append(operation)
            if operation == 'status' and result is None:
                raise ValueError('unknown request')
            state = {'request': request, 'state': 'pending' if result is None else 'completed',
                     'attempt_id': None if result is None else result['attempt_id'], 'result': result,
                     'reconciliation_required': False}
            if operation in ('status', 'submit'):
                return state
            if operation == 'execute':
                self.assertIsNone(result)
                identities = {key: request[key] for key in ('job_id', 'checkpoint_id', 'request_id', 'candidate', 'test')}
                check = dict(request['checks'][0], status='fail', actual='Missing completed item',
                             diagnostics='Retain the declared checklist database', evidence=[], exit_status=None)
                result = p.envelope('result', **identities, request_sha256=p.identity(request),
                                    executor={'controller_id': 'controller', 'environment': p.app_environment(request),
                                              'boundary': request['boundary'],
                                              'implementation_sha256': request['test']['recipe_sha256']},
                                    attempt_id='c0ba5af3-5ca3-417a-a53d-880ffaad35f2', status='fail', checks=[check],
                                    diagnostics=check['diagnostics'], evidence=[], effects=[],
                                    cleanup={'status': 'complete', 'diagnostics': 'Fixture resources cleared'})
                raise ConnectionResetError('lost the final packet')
            self.assertEqual(operation, 'consume')
            return {'progress': p.result_progress(result), 'result': result}

        with mock.patch.object(handoff, 'tls_principal', return_value=(None, None, ('a' * 64, 'b' * 64))), \
                mock.patch.object(handoff, 'exchange', side_effect=transport):
            self.assertEqual(adapter.host_test(1, checkpoint), {'progress': 'repair-required', 'result': result})
        self.assertEqual(operations, ['status', 'submit', 'execute', 'status', 'consume'])
        adapter.runtime.publish_approval.assert_called_once()

    def test_post_commit_truncated_frame_recovers_real_checklist_attempt(self):
        runtime = handoff.host_runtime()
        ledger_dir = self.root / 'ledger'
        ledger = p.Ledger(ledger_dir)
        self.addCleanup(ledger.close)
        controller = ledger.controller_id
        environment = {'machine_sha256': 'c' * 64, 'storage_fsid': 123}
        # The separately integrated Q history uses this ordinary fixture setup too.
        history_type = getattr(recovery, 'HostHistory', None)
        if history_type is not None:
            history = history_type(self.root / 'execution-history', controller, environment, initialize=True)
            self.addCleanup(history.close)
            ledger.host_history = history
        budgets = {'seconds': 35, 'artifact_bytes': 8192, 'spend_usd': 0}
        registered = p.envelope('job', job_id='demo', standards_sha=p.STANDARDS, agreement_sha256='1' * 64,
                                selection={'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
                                           'runtime_sha256': '2' * 64, 'verification': 'unverified-record-only'},
                                budgets=budgets, max_requests=2)
        checkpoint = p.envelope('checkpoint', job_id='demo', checkpoint_id='demo-c1',
                                candidate={'source_revision': 'a' * 40, 'artifact_sha256': 'b' * 64},
                                test=handoff.recipe_identity(host=True), summary='Approved first candidate', evidence=[])
        ledger.create_job(registered)
        ledger.checkpoint(checkpoint)
        adapter = object.__new__(job.FedoraJob)
        adapter.job = 'demo'
        adapter.runtime = mock.Mock(dispatch_gate=contextlib.nullcontext)
        adapter.controller = mock.Mock()
        adapter.controller.ledger.checkpoint.return_value = [controller, registered, checkpoint]
        principals = ('d' * 64, 'e' * 64)
        operations, services = [], []
        committed = None

        def fixture(*args, **kwargs):
            unit = FixtureService(self.root / args[2])
            self.addCleanup(unit.stop)
            services.append(unit)
            return unit

        def authorize(path, request):
            p.require(adapter.runtime.publish_approval.called, 'fixture approval has not been published')
            return 'localhost/checklist@sha256:' + 'b' * 64, ['executor-machine-sha256:' + environment['machine_sha256']]

        def transport(port, context, peer, operation, request):
            nonlocal ledger, committed
            operations.append(operation)
            packet = {'operation': operation, 'request': request}
            result = handoff.dispatch_host(ledger, runtime, {}, self.root, self.root / 'approval', principals, packet)
            if operation == 'execute':
                committed = result
                ledger.close()
                ledger = p.Ledger(ledger_dir)
                self.addCleanup(ledger.close)
                if history_type is not None:
                    ledger.host_history = history
                with contextlib.ExitStack() as sockets:
                    reader, writer = (sockets.enter_context(channel) for channel in socket.socketpair())
                    writer.sendall(struct.pack('!I', 90) + b'{"ok":true,"data":')
                    writer.shutdown(socket.SHUT_WR)
                    handoff.receive(reader, time.monotonic() + 2)
                    self.fail('partial authenticated payload was not rejected')
            return result

        with mock.patch.multiple(runtime, Quadlet=fixture, dispatch_gate=contextlib.nullcontext,
                                 APP_AUTHORITY=None, approval=authorize), \
                mock.patch.object(runtime, 'execution_identity', return_value=environment, create=True), \
                mock.patch.object(handoff, 'tls_principal', return_value=(None, None, principals)), \
                mock.patch.object(handoff, 'exchange', side_effect=transport):
            outcome = adapter.host_test(1, checkpoint)
        self.assertEqual(outcome, {'progress': 'host-checks-passed', 'result': committed})
        self.assertEqual([unit.actions for unit in services], [['start', 'restart']])
        self.assertEqual(operations, ['status', 'submit', 'execute', 'status', 'consume'])
        self.assertEqual(ledger.status('demo-r1')['attempt_id'], committed['attempt_id'])

    def product_slot(self):
        catalogue = self.root / 'product-jobs'
        path = catalogue / 'jobs/demo'
        path.mkdir(parents=True, mode=0o700)
        catalogue.chmod(0o700)
        job.write_private(catalogue / 'owner.lock', b'')
        job.write_private(path / 'plan.json', p.canonical(self.value).encode())
        initial = {'candidate': {'source_revision': self.value['agreement']['initial_commit']}}
        state = dict.fromkeys(('maintenance', 'first', 'development', 'repair', 'final'))
        state.update(job_id='demo', phase='maintenance-turn', initial=initial)
        job.write_private(path / 'state.json', p.canonical(state).encode())
        return catalogue, path, initial

    def test_boot_observation_pause_retains_job_and_auto_continues_same_operation(self):
        catalogue, path, initial = self.product_slot()
        marker = self.root / 'frozen'
        marker.write_text('boot')
        worker = mock.Mock()
        effects = []

        def role_turn(role, checkpoint, result=None):
            p.require(not marker.exists(), 'role dispatch frozen pending host observation')
            effects.append(role)
            return {'candidate_sha': initial['candidate']['source_revision']}

        worker.turn.side_effect = role_turn
        worker.host_test.return_value = {'progress': 'host-checks-passed', 'result': {'attempt_id': 'stored'}}
        with mock.patch.multiple(job, CATALOGUE=catalogue, JOBS=catalogue / 'jobs', registered_contract=lambda v: v), \
                mock.patch.object(job, 'FedoraJob', return_value=worker):
            first = job.work('demo')
            self.assertEqual(first['phase'], 'waiting')
            self.assertEqual(first['retry']['reason'], 'renewal-observation')
            self.assertTrue(first['retry']['automatic'])
            self.assertEqual(job.read_state(path), first)
            self.assertEqual(effects, [])

            def clear_during_wait(seconds):
                paused = job.read_state(path)
                self.assertEqual(paused['retry']['observations'], 2)
                self.assertEqual(paused['retry']['until_unix'], first['retry']['until_unix'])
                self.assertEqual(effects, [])
                marker.unlink()

            with mock.patch.object(job.os, 'geteuid', return_value=0), mock.patch.object(job.os, 'umask'), \
                    mock.patch.object(job.time, 'sleep', side_effect=clear_during_wait) as wait, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(job.main(['work', 'demo']), 0)
            wait.assert_called_once_with(job.RETRY_INTERVAL)
            emitted = [p.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([record['phase'] for record in emitted], ['waiting', 'passed'])
            finished = job.read_state(path)
            self.assertEqual(finished['phase'], 'passed')
            self.assertNotIn('retry', finished)
            self.assertEqual(job.work('demo'), finished)
        self.assertEqual(effects, ['maintenance', 'development'])
        worker.build.assert_not_called()
        worker.host_test.assert_called_once()

    def test_pause_has_bounded_budget_and_malformed_reply_is_terminal(self):
        catalogue, path, _ = self.product_slot()
        worker = mock.Mock()
        worker.turn.side_effect = job.HostReplyLost('execute')
        with mock.patch.multiple(job, CATALOGUE=catalogue, JOBS=catalogue / 'jobs', registered_contract=lambda v: v), \
                mock.patch.object(job, 'FedoraJob', return_value=worker), mock.patch.object(job, 'RETRY_OBSERVATIONS', 2):
            first = job.work('demo')
            second = job.work('demo')
            self.assertTrue(first['retry']['automatic'])
            self.assertEqual(second['phase'], 'waiting')
            self.assertFalse(second['retry']['automatic'])
            self.assertEqual(first['retry']['until_unix'], second['retry']['until_unix'])
            worker.turn.side_effect = ValueError('invalid transport response')
            failed = job.work('demo')
        self.assertEqual(failed['phase'], 'blocked')
        self.assertEqual(failed['diagnostics'], 'invalid transport response')
        self.assertNotIn('retry', job.read_state(path))


if __name__ == '__main__':
    unittest.main()
