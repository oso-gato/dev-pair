import contextlib
import io
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checklist_candidate as candidate
import host_handoff as handoff
import job_protocol as p
import product_job as job


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
                return {'session_uuid': 'fixture-development', 'candidate_sha': repaired}

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
                                   ('interrupted',), ('development', 'effect-1'), ('build', 2, repaired),
                                   ('host', 2, repaired)])

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
            with self.assertRaises(BlockingIOError):
                adapter.host_test(1, checkpoint)
            self.assertEqual(adapter.host_test(1, checkpoint), {'progress': 'repair-required', 'result': result})
        self.assertEqual(operations, ['status', 'submit', 'execute', 'status', 'consume'])
        adapter.runtime.publish_approval.assert_called_once()


if __name__ == '__main__':
    unittest.main()
