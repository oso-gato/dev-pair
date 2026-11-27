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
