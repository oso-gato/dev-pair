"""Fixed role-entry admission and protected request regressions."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from role_entry_stock import digest, stage
import gptbox
import gptbox_runtime as runtime


class RoleRequestTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.fixture = stage(directory.name)
        paths = {
            runtime.TURN_INPUTS / 'request.json': self.fixture / 'turn/request.json',
            runtime.TURN_INPUTS / 'prompt.txt': self.fixture / 'turn/prompt.txt',
            runtime.CREDENTIAL: self.fixture / 'credentials/api-key',
            runtime.REQUIREMENTS: self.fixture / 'etc/codex/requirements.toml',
            runtime.CODEX_HOME / 'config.toml': self.fixture / 'state/codex/config.toml',
        }
        self.payloads = {name: path.read_bytes() for name, path in paths.items()}
        self.selection = json.loads(self.payloads[runtime.TURN_INPUTS / 'request.json'])

    def request(self, role='maintenance', readonly=True):
        self.payloads[runtime.TURN_INPUTS / 'request.json'] = json.dumps(self.selection).encode()
        with patch.object(runtime, 'fixed_read', side_effect=lambda path, *args, **kwargs: self.payloads[path]), \
                patch.object(runtime.os, 'statvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0)):
            return runtime.turn_request(role)

    def test_explicit_saved_model_and_effort_survive(self):
        for model, effort in [('gpt-6.1-sol', 'medium'), ('gpt-6.2-sol', 'high')]:
            self.selection.update(model=model, effort=effort)
            actual, prompt, key = self.request()
            self.assertEqual((actual['model'], actual['effort']), (model, effort))
            self.assertEqual(digest(prompt), self.selection['prompt_sha256'])
            self.assertEqual(key, runtime.OFFLINE_KEY.decode())

    def test_rejects_cross_role_external_transport_and_writable_configuration(self):
        with self.assertRaisesRegex(RuntimeError, 'role or standards'):
            self.request('development')
        with self.assertRaisesRegex(RuntimeError, 'read-only'):
            self.request(readonly=False)
        for url in ('https://api.openai.com/v1', 'http://localhost:39162/v1', 'http://127.0.0.1:65536/v1'):
            with self.subTest(url=url), self.assertRaisesRegex(RuntimeError, 'local endpoint'):
                self.selection['endpoint'] = url
                self.request()

    def test_rejects_nonfixture_credentials_hash_mismatch_and_changed_policy(self):
        self.payloads[runtime.CREDENTIAL] = b'synthetic-invalid-key'
        with self.assertRaisesRegex(RuntimeError, 'scoped synthetic credential'):
            self.request()
        config = runtime.CODEX_HOME / 'config.toml'
        self.payloads[config] = b'not-even-toml'
        with self.assertRaisesRegex(RuntimeError, 'bound role input changed'):
            self.request()
        self.payloads[config] = b'allow_login_shell = true\n'
        self.selection['config_sha256'] = digest(self.payloads[config])
        with self.assertRaisesRegex(RuntimeError, 'managed role configuration changed'):
            self.request()

    def test_reads_regular_files_only_and_requires_actual_readonly_mount(self):
        prompt = self.fixture / 'turn/prompt.txt'
        self.assertEqual(runtime.fixed_read(prompt, 16384), prompt.read_bytes())
        with self.assertRaisesRegex(RuntimeError, 'mount is writable'):
            runtime.fixed_read(prompt, 16384, readonly=True)
        alias = self.fixture / 'turn/alias'
        alias.symlink_to(prompt)
        with self.assertRaises(OSError):
            runtime.fixed_read(alias, 16384)
        fifo = self.fixture / 'turn/fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(RuntimeError, 'regular file'):
            runtime.fixed_read(fifo, 16384)

    def test_rejects_duplicate_unordered_or_missing_cli_completion(self):
        uuid = '01234567-1234-7678-9012-3456789abcde'
        rows = [{'type': 'thread.started', 'thread_id': uuid}, {'type': 'turn.started'},
                {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'reply'}},
                {'type': 'turn.completed'}]
        encode = lambda entries: b'\n'.join(json.dumps(row).encode() for row in entries)
        self.assertEqual(runtime.completed_turn(encode(rows)), uuid)
        startup_item = {'type': 'item.completed', 'item': {'type': 'startup'}}
        self.assertEqual(runtime.completed_turn(encode([rows[0], startup_item, *rows[1:]])), uuid)
        for invalid in (rows[:-1], rows[:2] + rows[3:], [rows[1], rows[0], *rows[2:]],
                        [rows[0], rows[2], rows[1], rows[3]], rows + rows[-1:]):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                runtime.completed_turn(encode(invalid))


class ControllerEntryTests(unittest.TestCase):
    def setUp(self):
        self.app = gptbox.Gptbox()
        self.mounts = [dict(Type='bind', Source=f'/fixed/{i}', Destination=str(dest), RW=False)
                       for i, dest in enumerate(runtime.TURN_READONLY_MOUNTS)]
        self.mounts.extend(dict(Type='bind', Source=f'/role/{i}', Destination=dest, RW=True)
                           for i, dest in enumerate(('/work/job', '/state', '/cache/job')))
        self.row = {'State': {'Status': 'running', 'StartedAt': '2026-11-22T22:00:00Z'}, 'Mounts': self.mounts}

    def test_uses_fixed_distrobox_entry_for_running_exact_mounts(self):
        with patch.object(self.app, 'inspect_container', return_value=self.row) as inspect, \
                patch.object(self.app, 'execute', return_value='bounded-result') as run:
            self.assertEqual(self.app.enter('a' * 64, 'b' * 64, 'turn'), 'bounded-result')
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(run.call_args.args[-5:], ('/usr/bin/python3', '-I', gptbox.RUNTIME, 'entry', 'turn'))
        self.assertIn('--no-tty', run.call_args.args)
        self.assertEqual(run.call_args.kwargs, {'timeout': 30})

    def test_blocks_probe_mounts_duplicate_mounts_and_writable_credentials(self):
        cases = [self.mounts[-3:], self.mounts + self.mounts[:1],
                 [{**mount, 'RW': True} if mount['Destination'] == '/credentials' else mount for mount in self.mounts]]
        for mounts in cases:
            row = {**self.row, 'Mounts': mounts}
            with self.subTest(count=len(mounts)), patch.object(self.app, 'inspect_container', return_value=row), \
                    patch.object(self.app, 'execute') as run, self.assertRaisesRegex(gptbox.Blocked, 'job mounts'):
                self.app.enter('a' * 64, 'b' * 64, 'turn')
            run.assert_not_called()

    def test_replaced_runtime_requires_observation_not_redispatch(self):
        after = copy.deepcopy(self.row)
        after['State']['StartedAt'] = '2026-11-22T22:00:01Z'
        with patch.object(self.app, 'inspect_container', side_effect=[self.row, after]), \
                patch.object(self.app, 'execute') as run, self.assertRaisesRegex(gptbox.Blocked, 'durable turn state'):
            self.app.enter('a' * 64, 'b' * 64, 'turn')
        run.assert_called_once()
