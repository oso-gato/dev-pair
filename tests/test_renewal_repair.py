"""Production parser and durable launch regressions on private local data."""
import json
import os
from pathlib import Path
import runpy
import select
import sqlite3
import subprocess
import sys
import tempfile
import shlex
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / 'tools'
SCRIPT = REPO / 'runtime' / 'renewal' / 'driver'
sys.path.insert(0, str(TOOLS))
import renewal as r


class NativeRecoveryTests(unittest.TestCase):
    def test_only_exact_empty_probe_leaves_are_eligible_for_infrastructure_exclusion(self):
        check = runpy.run_path(str(SCRIPT))['check_probe_trees']
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for kind in ('workspaces', 'state', 'cache'):
                (root / 'maintenance' / kind / 'gptbox-probe').mkdir(parents=True, mode=0o700)
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            check(root, account)
            (root / 'maintenance' / 'state' / 'gptbox-probe' / 'state.sqlite3').touch()
            with self.assertRaisesRegex(ValueError, 'contains durable work'):
                check(root, account)

    def test_grant_requires_enough_full_cost_requests_for_the_product_tool_and_result(self):
        verify = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'continuity-grant'))['check_request_capacity']
        verify({'max_requests': 3, 'spend_microusd': 3264}, 1088, r.CONTINUITY_REQUESTS)
        for bad in ({'max_requests': 3, 'spend_microusd': 1}, {'max_requests': 3, 'spend_microusd': 2176},
                    {'max_requests': 1, 'spend_microusd': 1088}):
            with self.assertRaisesRegex(ValueError, 'cannot fund'):
                verify(bad, 1088, r.CONTINUITY_REQUESTS)

    def test_normal_driver_and_same_uuid_resume_keep_disjoint_operation_records(self):
        driver = runpy.run_path(str(SCRIPT))
        turn = driver['turn']
        g = turn.__globals__
        uid, gid = os.getuid(), os.getgid()
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            control = root / 'renewal'
            control.mkdir(mode=0o700)
            for folder in ('broker-requests', 'owned-turns', 'turn-launches', 'turn-receipts', 'provider-grants'):
                (control / folder).mkdir(mode=0o700)
            current = 'a' * 64
            r.replace_json(control / 'site-current.json', current)
            source = 'b' * 40
            parts = {'maintenance-agent': {'artifact_sha256': 'c'*64, 'source_revision': source, 'codex_version': '1.2.3'},
                     'development-agent': {'artifact_sha256': 'd'*64, 'source_revision': source, 'codex_version': '1.2.3'},
                     'devbox': {'artifact_sha256': 'e'*64}, 'host': {'artifact_sha256': 'f'*64}}
            plan = {'maintenance_context_sha256': '5'*64, 'development_manifests': {'product': '6'*64}}
            started = []

            def broker(action, channel):
                if action == 'start':
                    owned = list((control / 'owned-turns').iterdir())
                    self.assertEqual(len(owned), 1)
                    record = r.read_json(owned[0])
                    if record['role'] == 'development':
                        self.assertEqual(record['development_owner'], '7'*64)
                    self.assertEqual(owned[0].name, r.role_operation_key(record['role'], record['job'], record['operation']))
                    started.append(channel)

            changes = {'ROOT': root, 'CONTROL': control,
                       'admit_release': lambda _: ({'components': parts}, plan),
                       'live_host': lambda _: (root, 100), 'unit': broker,
                       'owned_file': lambda path, limit, expected_uid=0: r.read_private(path, limit),
                       'require_provider_ready': lambda *_: None, 'reserve_development_owner': lambda *_: '7'*64,
                       'provider_receipt': lambda _, sha: r.sha(sha.encode()),
                       'stage_verification': lambda payload: payload['request_sha256'], 'continued_rollout': lambda *_: None,
                       'gptbox': SimpleNamespace(job_selection=lambda raw, *_: r.loads(raw),
                                                  completed_turn=lambda events: r.loads(events.splitlines()[0])['thread_id'])}
            for role in r.ROLES:
                self.assertNotEqual(r.role_operation_key(role, 'job--part', 'turn'),
                                    r.role_operation_key(role, 'job', 'part--turn'))
            session = {role: str(uuid.uuid4()) for role in r.ROLES}
            with patch.dict(g, changes), patch.object(r.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid, pw_gid=gid)):
                for role, action, operation in (('maintenance', 'turn', 'normal-m'), ('development', 'turn', 'normal-d'),
                                                ('development', 'resume-without-effects', 'rollback-d')):
                    active = session[role]
                    compound = role == 'development'
                    request = {'role': role, 'job': 'product', 'logical_session': role, 'operation': operation,
                               'session_uuid': active if action != 'turn' else None, 'provider': 'gptbox',
                               'model': 'gpt-6.2-sol', 'effort': 'high', 'standards_sha': r.STANDARDS,
                               'agreement_sha256': 'a'*64, 'startup_sha256': 'b'*64, 'config_sha256': 'c'*64,
                               'prompt_sha256': 'd'*64, 'candidate_sha': source}
                    request_sha = r.identity(request)
                    leaf = root / 'turn-inputs' / role / 'product' / operation / 'turn'
                    leaf.mkdir(mode=0o700, parents=True)
                    r.replace_json(leaf / 'request.json', request)
                    r.replace_json(control / 'provider-grants' / (request_sha + '.json'), {})
                    events = r.json_bytes({'thread_id': active})
                    proof = None
                    if action != 'turn':
                        expectation = driver['product_result'](role, 'f'*64)
                        command = shlex.join(driver['product_command'](role, expectation['recipe']))
                        reply = {'operation': operation, 'checkpoint': 'cp', 'recipe': expectation['recipe'],
                                 'next_state': 'retain-pending-host-check'}
                        proof = {'checkpoint': {'checkpoint_id': 'cp', 'checkpoint_sha256': '3'*64},
                                 'work': {'product_plan_sha256': 'a'*64, 'product_result': expectation},
                                 'pending_host': ['still-pending']}
                        events += b'\n' + r.json_bytes({'type': 'item.completed', 'item': {'type': 'command_execution',
                                                'command': command, 'exit_code': 0, 'aggregated_output': r.canonical(expectation)}})
                        events += b'\n' + r.json_bytes({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': r.canonical(reply)}})
                    event_hash = r.sha(events)
                    observed = {**request, 'session_uuid': active, 'request_sha256': request_sha, 'schema': 2,
                                'status': 'completed-turn', 'runtime_admitted': True, 'owned_cleanup': 'reaped',
                                'events_sha256': event_hash, 'events_bytes': len(events)}
                    stored = root / role / 'state' / 'product' / 'turns' / operation
                    stored.mkdir(mode=0o700, parents=True)
                    r.replace_json(stored / 'result.json', observed)
                    r.write_private(stored / 'events.jsonl', events)
                    common = {'turn': observed, 'codex_version': '1.2.3'}
                    report = common | ({'outer_removed': True, 'inner_removed': True, 'manifest_sha256': '6'*64,
                                        'outer_image_id': 'e'*64, 'inner_image_id': 'd'*64} if compound else
                                       {'runtime_container_removed': True, 'context_sha256': '5'*64, 'image_id': 'c'*64,
                                        'source_sha': source})
                    binding = {**request, 'policy_sha256': request['config_sha256'], 'job_id': 'product', 'credential_ref': 'mock'}
                    spec = {**request, 'release_sha256': current, 'binding': binding, 'request_sha256': request_sha, **(proof or {})}
                    with patch.object(subprocess, 'run', side_effect=lambda command, **kwargs:
                                      real_run([sys.executable, '-c', 'import sys; print(sys.argv[1])', r.canonical(report)], **kwargs)):
                        result = turn(action, spec)
                    self.assertEqual(result['session_uuid'], active)
                    self.assertFalse(list((control / 'owned-turns').iterdir()))
                    if proof:
                        self.assertEqual(turn(action, spec), result)
                        self.assertEqual(result['product']['pending_host'], ['still-pending'])
            self.assertEqual(len(started), 3)
            self.assertEqual(len(list((control / 'turn-launches').iterdir())), 3)

    def test_rollback_archive_must_exist_as_exact_protected_file(self):
        verify = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'role-preflight'))['development_inputs']
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            manifest = path / 'manifest.json'
            archive = path / 'development.oci.tar'
            manifest.write_text('approved')
            manifest.chmod(0o444)
            with self.assertRaises(FileNotFoundError):
                verify(path, path.stat().st_dev, 3, owner=os.getuid())
            archive.write_bytes(b'oci')
            archive.chmod(0o444)
            self.assertEqual(verify(path, path.stat().st_dev, 3, owner=os.getuid()), (manifest, archive))
            with self.assertRaisesRegex(ValueError, 'length changed'):
                verify(path, path.stat().st_dev, 4, owner=os.getuid())

    def test_handoff_observation_requires_a_live_listener_owned_by_the_exact_process(self):
        inspect = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'host-release'))['listen_inode']
        child_code = ('import socket, time; s=socket.socket(); s.bind(("127.0.0.1", 0));'
                      's.listen(); print(s.getsockname()[1],flush=True); time.sleep(30)')
        child = subprocess.Popen([sys.executable, '-c', child_code], stdout=subprocess.PIPE)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            port = int(child.stdout.readline())
            self.assertTrue(inspect(Path('/proc') / str(child.pid), port).isdigit())
            with self.assertRaisesRegex(ValueError, 'does not own'):
                inspect(Path('/proc/self'), port)
        finally:
            child.kill()
            child.wait(timeout=4)
            child.stdout.close()

    def test_native_database_and_rollouts_exist_without_sidecar_and_preserve_archives(self):
        module = runpy.run_path(str(SCRIPT))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'development' / 'state' / 'product'
            (base / 'sqlite').mkdir(parents=True)
            active, archived = (str(uuid.uuid4()) for _ in range(2))
            database = base / 'sqlite' / 'state_5.sqlite'
            with sqlite3.connect(database) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE threads (id TEXT, cwd TEXT, rollout_path TEXT, model_provider TEXT, archived INTEGER)')
                for index, ident in enumerate((active, archived)):
                    name = f'rollout-{ident}.jsonl'
                    relative = Path('codex') / ('archived_sessions' if index else 'sessions') / name
                    path = base / relative
                    path.parent.mkdir(parents=True)
                    path.write_bytes(r.json_bytes({'type': 'session_meta', 'payload': {'id': ident, 'cwd': '/work/job'}}) + b'\n')
                    db.execute('INSERT INTO threads VALUES (?,?,?,?,?)', (ident, '/work/job', '/state/' + str(relative), 'openai', index))
                db.commit()
                before = {p.name: p.read_bytes() for p in database.parent.iterdir()}
                rows, older = module['native_sessions'](base, os.getuid())
                self.assertEqual(set(rows), {active})
                self.assertEqual(set(older), {archived})
                self.assertEqual({p.name: p.read_bytes() for p in database.parent.iterdir()}, before)
            verify = module['verify_sessions']
            verify.__globals__['ROOT'] = root
            with patch.object(r.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())), \
                    self.assertRaisesRegex(ValueError, 'native Codex and registry'):
                verify({'role': 'development', 'job': 'product', 'sessions': [], 'binding': {}})

    def test_native_rollout_must_keep_original_bytes_and_advance(self):
        module = runpy.run_path(str(SCRIPT))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'development' / 'state' / 'product'
            ident = str(uuid.uuid4())
            relative = Path('codex/sessions') / f'rollout-{ident}.jsonl'
            path = base / relative
            path.parent.mkdir(parents=True)
            (base / 'sqlite').mkdir()
            original = r.json_bytes({'type': 'session_meta', 'payload': {'id': ident, 'cwd': '/work/job'}}) + b'\n'
            path.write_bytes(original)
            with sqlite3.connect(base / 'sqlite' / 'state_5.sqlite') as db:
                db.execute('CREATE TABLE threads (id TEXT, cwd TEXT, rollout_path TEXT, model_provider TEXT)')
                db.execute('INSERT INTO threads VALUES (?,?,?,?)', (ident, '/work/job', '/state/' + str(relative), 'openai'))
            verify = module['continued_rollout']
            verify.__globals__['ROOT'] = root
            payload = {'role': 'development', 'job': 'product', 'session_uuid': ident,
                       'native_rollout': {'bytes': len(original), 'sha256': r.sha(original), 'path': str(relative)}}
            with self.assertRaisesRegex(ValueError, 'did not advance'):
                verify(payload, os.getuid())
            with path.open('ab') as stream:
                stream.write(b'{"type":"response_item"}\n')
            verify(payload, os.getuid())
            path.write_bytes(original.replace(b'"session_meta"', b'"session_meta" ') + b'{"type":"response_item"}\n')
            with self.assertRaisesRegex(ValueError, 'replaced original'):
                verify(payload, os.getuid())

    def test_sigkill_between_rollback_operation_publications_and_launch_proof_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for folder in ('broker-requests', 'owned-turns', 'turn-launches'):
                (root / folder).mkdir(mode=0o700)
            operation = 'development--product--renew-rollback'
            owned = {'request_sha256': 'e' * 64, 'operation': 'renew-rollback'}
            broker = {'operation': 'renew-rollback'}
            common = ('import json,pathlib,runpy,subprocess,sys,time;'
                      'sys.path.insert(0, sys.argv[1]); import renewal as r;'
                      'driver=runpy.run_path(sys.argv[2]);root=pathlib.Path(sys.argv[3]);'
                      'key=sys.argv[4]; owned=json.loads(sys.argv[5]); broker=json.loads(sys.argv[6]);')
            first = (common + 'driver["install_exact"](root/"broker-requests"/(owned["request_sha256"]+".json"),broker);'
                     'print("broker-published",flush=True); time.sleep(30)')
            native = ('import json,pathlib,sys; path=pathlib.Path(sys.argv[1]);'
                      'path.open("a").write("one scoped effect\\n"); print(json.dumps({"completed":True}))')
            second = common + '\nnative = ' + repr(native) + '''
launches = driver['turn_root'](root,key,owned,broker)
def launch(output):
    with output.open('xb') as stream:
        subprocess.run([sys.executable, '-c', native, str(root/'effects')], stdout=stream, check=True)
    output.chmod(0o600)
report = driver['durable_launch'](launches,owned,launch,lambda:True)
assert report == {'completed': True}
print('wrapper-recorded',flush=True); time.sleep(30)
'''
            for code, token in ((first, b'broker-published'), (second, b'wrapper-recorded')):
                child = subprocess.Popen([sys.executable, '-c', code, str(TOOLS), str(SCRIPT), str(root),
                                          operation, json.dumps(owned), json.dumps(broker)], stdout=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 7)[0], 'child did not reach crash boundary')
                    self.assertEqual(child.stdout.readline().strip(), token)
                    child.kill()
                    self.assertEqual(child.wait(timeout=5), -9)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=4)
                    child.stdout.close()
            driver = runpy.run_path(str(SCRIPT))
            work = driver['turn_root'](root, operation, owned, broker)
            report = driver['durable_launch'](work, owned, lambda _: self.fail('paid replay'), lambda: False)
            self.assertEqual(report, {'completed': True})
            self.assertEqual((root / 'effects').read_text(), 'one scoped effect\n')
            (work / 'launcher.json').unlink()
            with self.assertRaisesRegex(ValueError, 'outcome is uncertain'):
                driver['durable_launch'](work, owned, lambda _: self.fail('uncertain replay'), lambda: False)


if __name__ == '__main__':
    unittest.main()
