"""Exercise general job continuity against actual source and the product runner's event format."""
from contextlib import contextmanager
from importlib.util import find_spec
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
import renewal as r
import renewal_product as product
from renewal import protocol as p


@unittest.skipUnless(find_spec('product_job'), 'combined J product job source required')
class GeneralContinuityTests(unittest.TestCase):
    def run_git(self, directory, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(directory), *args], timeout=10).decode().strip()

    @contextmanager
    def arranged(self, adapter, snapshot=False):
        import product_job as j

        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.root = root
            folder = root / 'product-jobs/jobs/product'
            folder.mkdir(parents=True, mode=0o700)
            dev = root / 'development/workspaces/product'
            dev.mkdir(parents=True)
            self.run_git(dev, 'init', '-q')
            (dev / 'feature.py').write_text('status = "ready"\n')
            (dev / 'test_feature.py').write_text('import unittest\nimport feature\nclass Feature(unittest.TestCase):\n'
                                                '    def test_ready(self):\n        self.assertEqual(feature.status, "ready")\n')
            self.run_git(dev, 'add', 'feature.py', 'test_feature.py')
            self.run_git(dev, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'product')
            maint = root / 'maintenance/workspaces/product'
            maint.parent.mkdir(parents=True)
            self.run_git(dev, 'clone', '-q', str(dev), str(maint))
            head = self.run_git(dev, 'rev-parse', 'HEAD')
            tree = self.run_git(dev, 'rev-parse', 'HEAD^{tree}')
            test = ['/usr/bin/python3', '-B', '-m', 'unittest', 'discover']
            output = subprocess.check_output(test, cwd=dev, stderr=subprocess.STDOUT, timeout=5).decode().strip()
            if snapshot:
                import candidate_snapshot
                checked = candidate_snapshot.scan(dev)[0]
                prefix, suffix = j.candidate_git.witness()
                marker = candidate_snapshot.MARKER + checked
            else:
                prefix, suffix = j.LOCAL_TEST_PREFIX, j.LOCAL_TEST_SUFFIX
                marker = j.LOCAL_HEAD_MARKER + head
            command = prefix + shlex.join(test) + suffix
            recipe = j.local_recipe()
            repo = 'fixture/product'
            plan = {'schema': 1, 'job_id': 'product', 'adapter': adapter, 'startup_sha256': '9'*64,
                    'agreement': {'repository': repo, 'initial_commit': head, 'brief': 'Record the feature readiness result.',
                                  'host_seconds': 60, 'build_seconds': 60, 'turn_seconds': 60}}
            r.replace_json(folder / 'plan.json', plan)
            agree = j.agreement_sha(plan)
            checkpoint = p.envelope('checkpoint', job_id='product', checkpoint_id='product-c2',
                                    candidate={'source_revision': head, 'artifact_sha256': p.identity({'repository': repo, 'revision': head, 'tree': tree})},
                                    test=recipe, summary='Saved actual feature test', evidence=['git-tree:' + tree])
            phase = 'awaiting-external-validation' if adapter == product.EXTERNAL else 'local-validation-recorded'
            initial = {**checkpoint, 'checkpoint_id': 'product-c1'}
            state = {'job_id': 'product', 'repository': repo, 'phase': phase, 'agreement_sha256': agree,
                     'startup_sha256': plan['startup_sha256'], 'initial': initial, 'repair': checkpoint}
            payloads = {}
            for role in r.ROLES:
                thread = str(uuid.uuid4())
                operation = 'product-' + role
                rows = [{'type': 'thread.started', 'thread_id': thread}, {'type': 'turn.started'}]
                if role == 'development':
                    item = {'type': 'command_execution', 'id': 'item_1', 'command': command}
                    rows.extend([{'type': 'item.started', 'item': item}, {'type': 'item.completed', 'item': {**item, 'status': 'completed',
                                 'exit_code': 0, 'aggregated_output': f'{marker}\n{output}\n{marker}'}}])
                rows.extend([{'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'Verified'}}, {'type': 'turn.completed'}])
                events = b'\n'.join(r.json_bytes(row) for row in rows)
                transfer = root / role / 'state/product/turns' / operation
                transfer.mkdir(parents=True, mode=0o700)
                receipt = {'schema': 2, 'role': role, 'job': 'product', 'logical_session': role, 'operation': operation,
                           'session_uuid': thread, 'events_sha256': r.sha(events), 'request_sha256': '6'*64}
                r.write_private(transfer / 'events.jsonl', events)
                r.replace_json(transfer / 'result.json', {**receipt, 'events_bytes': len(events), 'status': 'completed-turn',
                                                        'owned_cleanup': 'reaped', 'runtime_admitted': True})
                state[role] = receipt
                payloads[role] = {'role': role, 'job': 'product', 'binding': {'agreement_sha256': agree}, 'checkpoint': checkpoint,
                                  'sessions': [{'logical_session': role, 'uuid': thread}]}
                if role == 'development':
                    proof = j.observed_source_validation(events) if snapshot else j.observed_validation(events, head)
                    state['local_validation'] = {**proof, 'candidate_sha': head, 'base_sha': head, 'session_uuid': thread,
                                                 'events_sha256': r.sha(events), 'checkpoint_id': checkpoint['checkpoint_id']}
                    if snapshot:
                        bound = {'job_id': 'product', 'operation': operation, 'snapshot_sha256': checked, 'session_uuid': thread,
                                 'events_sha256': r.sha(events), 'request_sha256': receipt['request_sha256'], 'agreement_sha256': agree,
                                 'startup_sha256': plan['startup_sha256'], 'base_sha': head, 'checkpoint_sha256': p.identity(initial),
                                 'validation_sha256': p.identity(proof)}
                        materialized = {'binding': bound, 'candidate_sha': head, 'tree_sha': tree,
                                        'bundle_sha256': '7'*64, 'head_ref': 'refs/heads/main'}
                        (folder / 'candidate').mkdir(mode=0o700)
                        r.replace_json(folder / 'candidate/receipt.json', materialized)
                        state['materialized'] = materialized
            r.replace_json(folder / 'state.json', state)
            yield dev, payloads, phase

    def check(self, adapter, *, snapshot=False):
        driver = runpy.run_path(str(REPO / 'runtime/renewal/driver'))
        observe = driver['capture_work']
        run = subprocess.run

        def scoped(command, **options):
            if command[0] == driver['SYSTEMD_RUN']:
                self.assertIn('--property=PrivateNetwork=yes', command)
                self.assertIn('--property=ProtectSystem=strict', command)
                mounts = [word for word in command if word.startswith('--property=BindReadOnlyPaths=')]
                self.assertEqual(len(mounts), 1)
                self.assertTrue(mounts[0].endswith(':/work/job'))
                workspace = mounts[0].removeprefix('--property=BindReadOnlyPaths=').removesuffix(':/work/job')
                return run(command[command.index('--') + 1:], cwd=workspace, **options)
            self.assertEqual(command[:2], [driver['RUNUSER'], '--user'])
            self.assertIn(command[2], ('dp-dev', 'dp-maint'))
            return run(command[4:], **options)

        with self.arranged(adapter, snapshot) as (dev, payloads, phase), \
                patch.dict(observe.__globals__, {'ROOT': self.root, 'owned_file': lambda path, maximum, uid=0: path.read_bytes()}), \
                patch.object(r.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())), \
                patch.object(subprocess, 'run', side_effect=scoped):
            for role, payload in payloads.items():
                work = observe(payload)
                observed = work['product_result']
                self.assertEqual(observed['validation_phase'], phase)
                self.assertEqual(r.next_product_state(observed, []), phase)
                self.assertEqual(observed['test_count'], int(role == 'development'))
                command = driver['product_command'](role, product.RECIPE, observed)
                workspace = self.root / role / 'workspaces/product'
                actual = run(command, cwd=workspace, check=True, capture_output=True, timeout=20).stdout
                case = {'role': role, 'operation': 'renew', 'checkpoint': {'checkpoint_id': 'product-c2'},
                        'work': work, 'pending_host': []}
                message = r.canonical({'operation': 'renew', 'checkpoint': 'product-c2', 'recipe': product.RECIPE, 'next_state': phase})
                events = [{'type': 'item.completed', 'item': {'type': 'command_execution', 'command': shlex.join(command),
                                                             'exit_code': 0, 'aggregated_output': actual.decode()}},
                          {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': message}}]
                proof = driver['verify_progress'](b'\n'.join(r.json_bytes(row) for row in events), case)
                self.assertEqual(proof['next_state'], phase)
                self.assertEqual(proof['result'], observed)
                with self.assertRaisesRegex(ValueError, 'enrolled provider UUID'):
                    observe({**payload, 'sessions': []})
            saved = self.root / 'development/state/product/turns/product-development/events.jsonl'
            initial_events = saved.read_bytes()
            saved.write_bytes(initial_events + b' ')
            with self.assertRaisesRegex(ValueError, 'accepted stock job evidence changed'):
                observe(payloads['maintenance'])
            saved.write_bytes(initial_events)
            state_path = self.root / 'product-jobs/jobs/product/state.json'
            state = r.read_json(state_path)
            r.replace_json(state_path, {**state, 'local_validation': None, 'phase': 'development-turn'})
            with self.assertRaisesRegex(ValueError, 'no settled validation'):
                observe(payloads['development'])
            r.replace_json(state_path, state)
            clean = observe(payloads['development'])['product_result']
            dirty = 'status = "ready"  # uncommitted edit\n'
            (dev / 'feature.py').write_text(dirty)
            resumed = observe(payloads['development'])['product_result']
            self.assertTrue(resumed['dirty'])
            self.assertNotEqual(resumed['source_sha256'], clean['source_sha256'])
            self.assertEqual((resumed['test_count'], resumed['validation_phase']), (1, phase))
            self.assertEqual((dev / 'feature.py').read_text(), dirty)
            failing = 'status = "unfinished edit"\n'
            (dev / 'feature.py').write_text(failing)
            with self.assertRaisesRegex(ValueError, 'cannot complete the approved local continuation'):
                observe(payloads['development'])
            self.assertEqual((dev / 'feature.py').read_text(), failing)

    def test_records_the_original_verified_local_checkpoint(self):
        self.check(product.LOCAL)

    def test_preserves_external_validation_and_materialized_source(self):
        import product_job
        if not hasattr(product_job, 'observed_source_validation'):
            self.skipTest('materialized J source required')
        self.check(product.EXTERNAL, snapshot=True)

    def test_saved_shell_is_evidence_and_cannot_expand_the_fixed_test_adapter(self):
        import product_job as j
        for test in ('/usr/bin/true', 'python3 -m unittest discover -s /var/lib',
                     'python3 -m unittest discover -s../foreign', 'python3 -m unittest discover && /usr/bin/true'):
            command = j.LOCAL_TEST_PREFIX + test + j.LOCAL_TEST_SUFFIX
            events = r.json_bytes({'type': 'item.completed', 'item': {'id': 'item_1', 'command': command}})
            matched = {'item_id': 'item_1', 'command_sha256': r.sha(command.encode())}
            with self.assertRaisesRegex(ValueError, 'no bounded renewal test adapter'):
                product.approved_unittest(events, matched, j.LOCAL_TEST_PREFIX, j.LOCAL_TEST_SUFFIX)
