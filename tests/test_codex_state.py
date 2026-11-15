"""Local schema and real-process bounds; stock acceptance is an explicit CLI run."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import codex_state as state


class CodexStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def runner(self):
        runner = state.Harness.__new__(state.Harness)
        runner.root = self.root
        runner.end = time.monotonic() + 2
        runner.used = 0
        runner.records = []
        runner.rpc_buffers = {}
        return runner

    def process(self, code, *args):
        return subprocess.Popen([sys.executable, '-c', code, *map(str, args)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=state.ENV, start_new_session=True)

    def test_exact_policy_schema_types_and_toml_roundtrip(self):
        policy = state.generated_policy()
        state.validate_policy(policy)
        for name, value in policy.items():
            self.assertEqual(tomllib.loads(state.toml(value)), value)
        for mutate in (lambda p: p['requirements'].update(unknown=True),
                       lambda p: p['requirements']['features'].update(plugins=0),
                       lambda p: p['requirements']['permissions']['product-child']['filesystem'].update({'/': 'read'}),
                       lambda p: p['config']['shell_environment_policy'].update(inherit='all')):
            changed = copy.deepcopy(policy)
            mutate(changed)
            with self.assertRaises(ValueError):
                state.validate_policy(changed)

    def test_manifest_identity_layout_and_inventory_reject_unknown_tampered_or_redirected_inputs(self):
        skills = {'.system/.codex-system-skills.marker': {'bytes': 1, 'sha256': 'a' * 64}}
        manifest = state.make_manifest(skills)
        for mutate in (lambda p: p.update(unknown=True), lambda p: p.update(version=True),
                       lambda p: p.update(binary_sha256='f' * 64), lambda p: p.update(policy_sha256='f' * 64),
                       lambda p: p['layout']['immutable'].remove('/home/gpt'), lambda p: p['layout']['product'].append('/etc/codex')):
            changed = copy.deepcopy(manifest)
            mutate(changed)
            with self.assertRaises(ValueError):
                state.validate_manifest(changed, skills)
        with self.assertRaises(ValueError):
            state.make_manifest({'../escaped': {'bytes': 1, 'sha256': 'a' * 64}})

    def test_returned_requirements_must_match_values_not_merely_contain_profile_name(self):
        with self.assertRaises(ValueError):
            state.verify_returned_requirements({'result': {'requirements': {'defaultPermissions': 'product-child'}}})
        with self.assertRaises(ValueError):
            state.verify_returned_requirements({'error': {'message': 'product-child'}})

    def test_skill_listing_requires_successful_fixed_cwd_immutable_builtin_paths(self):
        response = {'result': {'data': [{'cwd': '/job', 'errors': [], 'skills': [{'name': 'builtin', 'path': '/state/codex/skills/.system/builtin/SKILL.md'}]}]}}
        state.verify_skills_response(response)
        for mutate in (lambda p: p['result']['data'][0].update(errors=['failed']),
                       lambda p: p['result']['data'][0].update(cwd='/job/src'),
                       lambda p: p['result']['data'][0].update(skills=[]),
                       lambda p: p['result']['data'][0]['skills'][0].update(path='/job/src/.agents/skills/evil/SKILL.md')):
            changed = copy.deepcopy(response)
            mutate(changed)
            with self.assertRaises(ValueError):
                state.verify_skills_response(changed)

    def test_binary_admission_rejects_fifo_device_symlink_oversize_and_wrong_digest(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        regular = self.root / 'wrong'
        regular.write_bytes(b'unverified')
        alias = self.root / 'alias'
        alias.symlink_to(regular)
        for index, source in enumerate((fifo, Path('/dev/zero'), alias, regular)):
            destination = self.root / ('case' + str(index))
            destination.mkdir()
            started = time.monotonic()
            with self.assertRaises((ValueError, OSError)):
                state.Harness(destination, source)
            self.assertLess(time.monotonic() - started, .5)
        # Test-only identities exercise the same snapshot mechanism, never stock evidence.
        with mock.patch.object(state, 'CODEX_BYTES', len(b'unverified')), mock.patch.object(state, 'CODEX_SHA', 'f' * 64):
            destination = self.root / 'digest-case'
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, 'digest'):
                state.Harness(destination, regular)

    def test_verified_private_binary_snapshot_survives_source_replacement(self):
        source = self.root / 'fixture-binary'
        source.write_bytes(b'fixture bytes')
        destination = self.root / 'snapshot'
        destination.mkdir()
        with mock.patch.object(state, 'CODEX_BYTES', len(b'fixture bytes')), \
                mock.patch.object(state, 'CODEX_SHA', hashlib.sha256(b'fixture bytes').hexdigest()), \
                mock.patch.object(state.Harness, 'command', return_value=b''):
            runner = state.Harness(destination, source)
        source.write_bytes(b'changed after verification')
        self.assertEqual(runner.binary.read_bytes(), b'fixture bytes')
        self.assertEqual(runner.binary.stat().st_mode & 0o777, 0o500)

    def test_real_fragmented_rpc_and_duplicate_or_mismatched_identity(self):
        runner = self.runner()
        process = self.process("import os,time;os.write(1,b'{\"id\":');time.sleep(.04);os.write(1,b'1,\"result\":{}}\\n')")
        try:
            value, output = runner.collect(process, 1)
            self.assertEqual(value, {'id': 1, 'result': {}})
        finally:
            runner.stop(process)
        for data in ('{"id":1,"id":1,"result":{}}\n', '{"id":2,"result":{}}\n'):
            process = self.process('import os,sys;os.write(1,sys.argv[1].encode())', data)
            try:
                with self.assertRaises(ValueError):
                    runner.collect(process, 1)
            finally:
                runner.stop(process)

    def test_real_output_limit_and_exited_launcher_held_pipe_cleanup(self):
        runner = self.runner()
        marker = self.root / 'late-effect'
        code = 'import os,time,pathlib,sys;pid=os.fork();os._exit(0) if pid else None;os.write(1,b"x"*4096);time.sleep(.3);pathlib.Path(sys.argv[1]).write_text("escaped")'
        process = self.process(code, marker)
        try:
            with mock.patch.object(state, 'OUTPUT_BYTES', 1024):
                with self.assertRaisesRegex(ValueError, 'output budget'):
                    runner.collect(process)
        finally:
            runner.stop(process)
        time.sleep(.35)
        self.assertFalse(marker.exists())
        self.assertTrue(process.stdout.closed)

    def test_native_file_ceiling_enforced_by_real_child(self):
        path = self.root / 'native-limit'
        process = subprocess.run([sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"x"*(17*1024**2))', str(path)],
                                 env=state.ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 preexec_fn=state.child_limits, timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertLessEqual(path.stat().st_size, state.FILE_BYTES)

    def test_real_absolute_timeout_and_live_storage_monitor_block_and_reap(self):
        runner = self.runner()
        runner.end = time.monotonic() + .08
        process = self.process('import time;time.sleep(2)')
        try:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                runner.collect(process)
        finally:
            runner.stop(process)
        runner = self.runner()
        file = self.root / 'oversize'
        process = self.process('import pathlib,time,sys;pathlib.Path(sys.argv[1]).write_bytes(b"x"*4096);time.sleep(2)', file)
        try:
            with mock.patch.object(state, 'CODEX_BYTES', 0), mock.patch.object(state, 'STATE_BYTES', 1024):
                with self.assertRaisesRegex(ValueError, 'storage budget'):
                    runner.collect(process)
        finally:
            runner.stop(process)


if __name__ == '__main__':
    unittest.main()
