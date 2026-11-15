"""Synthetic engine/command tests only: no Fedora, Podman or Distrobox runtime acceptance."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gptbox as g

EXPECTED = 'a' * 64
SOURCE = '1' * 40
BASE = 'b' * 64
STAGE = 'c' * 64
SEALED = 'd' * 64
RUNTIME = 'e' * 64

class Engine:
    def __init__(self):
        self.calls = []
        self.containers = {}
        self.fail = None
        self.bad_attestation = False
        self.active = False
        self.app = None

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and self.fail(args):
            raise g.Blocked('injected engine boundary failure')
        if args[:2] == ('/usr/bin/id', '-u') or args[:2] == ('/usr/bin/id', '-g'):
            return '1001\n'
        if args[:2] == ('/usr/bin/systemctl', 'show'):
            return 'User=dp-maint\nActiveState=' + ('active' if self.active else 'inactive') + '\n'
        if args[:2] == ('/usr/bin/systemctl', 'stop'):
            self.active = False
        if not args or args[0] != '/usr/bin/systemd-run':
            return ''
        position = next(index for index, value in enumerate(args) if value.endswith('/bin/podman') and '=' not in value)
        command = args[position + 1:]
        if not command:
            return ''
        if 'distrobox-enter' in ' '.join(args[:position]):
            return ''
        if command[:2] == ('image', 'inspect'):
            return json.dumps([{'Id': SEALED}])
        if command[0] == 'pull':
            return ''
        if command[0] == 'build':
            self.build = Path(command[-1])
            return BASE
        if command[0] == 'commit':
            return SEALED
        if command[0] == 'create':
            runtime = '--read-only' in command
            identity = RUNTIME if runtime else STAGE
            name = next(value.split('=', 1)[1] for value in command if value.startswith('--name='))
            config = {'User': '1000:1000' if runtime else '',
                      'Labels': {'manager': 'distrobox', 'distrobox.unshare_groups': '0', 'dev-pair.context': EXPECTED}}
            host = {'Privileged': False, 'ReadonlyRootfs': runtime, 'CapAdd': [] if runtime else ['CAP_SYS_ADMIN'],
                    'CapDrop': ['ALL'] if runtime else [], 'SecurityOpt': ['no-new-privileges'],
                    'PidMode': 'private', 'IpcMode': 'private', 'UTSMode': 'private', 'NetworkMode': 'none' if runtime else 'slirp4netns',
                    'UsernsMode': 'private', 'IDMappings': {'UidMap': ['1000:1001:1'], 'GidMap': ['1000:1001:1']},
                    'Memory': 2147483648, 'PidsLimit': 256 if runtime else 512, 'NanoCpus': 1000000000}
            self.containers[identity] = {'Id': identity, 'Name': name, 'Image': SEALED if runtime else BASE,
                'Config': config, 'HostConfig': host, 'State': {'Status': 'created', 'Running': False, 'ExitCode': 0},
                'EffectiveCaps': [], 'BoundingCaps': [],
                'ProcessLabel': 'system_u:system_r:' + ('container_t' if runtime else 'container_engine_t') + ':s0:c10,c20',
                'MountLabel': 'system_u:object_r:container_file_t:s0:c10,c20',
                'Mounts': [{'Type': 'bind', 'Destination': target, 'Source': source, 'RW': rw}
                           for target, (source, rw) in (self.app.mounts.items() if runtime else [])]}
            if runtime:
                self.saved_runtime = copy.deepcopy(self.containers[identity])
            return identity
        if command[0] == 'inspect':
            identity = command[-1]
            found = self.containers.get(identity)
            if found is None:
                found = next((value for value in self.containers.values() if value['Name'] == identity), None)
            return json.dumps([found] if found else [])
        if command[0] == 'start':
            identity = command[-1]
            if '--attach' in command:
                self.containers[identity]['State'].update(Status='exited', Running=False)
                record = {'kind': 'genuine-distrobox-assembled', 'source_sha': SOURCE, 'uid': 1000, 'gid': 1000,
                          'inputs_sha256': hashlib.sha256((self.build / 'inputs.json').read_bytes()).hexdigest()}
                if self.bad_attestation:
                    record['inputs_sha256'] = '0' * 64
                return 'Synthetic fixture upstream progress\n' + json.dumps(record)
            self.containers[identity]['State'].update(Status='running', Running=True)
        if command[0] == 'logs':
            return 'container_setup_done\n'
        if command[0] == 'stop':
            self.containers[command[-1]]['State'].update(Status='exited', Running=False)
        if command[0] == 'rm':
            self.containers.pop(command[-1], None)
        return ''

class Fixture(g.Gptbox):
    def preflight(self):
        return {'fixture': 'not Fedora evidence'}

    def inputs(self, context, expected, upstream, revision):
        # No production CLI fixture bypass exists. Tests inject the external provenance boundary.
        return {}, {'distrobox-init': b'upstream fixture NOT DISTROBOX\n', 'distrobox-enter': b'entry fixture NOT DISTROBOX\n'}

    def directory(self, name, mode=0o700, owner=None):
        return super().directory(name, mode, owner=None)

    def execute(self, *args, timeout=120, ok=(0,)):
        if args[0].endswith('/distrobox-enter'):
            self.entry_calls.append(args)
            self.assert_ready_identity = args[args.index('--name') + 1]
            return '{"boundary_probe":"passed"}\n' if args[-1] == 'probe' else 'codex-cli 0.169.0\n'
        return super().execute(*args, timeout=timeout, ok=ok)

class GptboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.engine = Engine()
        self.app = Fixture(self.root, self.engine)
        self.app.entry_calls = []
        self.engine.app = self.app
        self.app.directory('/var/lib/dev-pair', mode=0o755)
        path = self.app.path(g.STATE + '/prepared')
        path.parent.mkdir(parents=True)
        path.parent.chmod(0o700)
        path.write_text('fixture prepared state, not host evidence')
        self.context = self.root / 'input'
        self.context.mkdir()
        (self.context / 'codex').write_bytes(b'fixture NOT CODEX')
        self.disk = patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=16 * 1024 ** 3))
        self.disk.start()
        self.addCleanup(self.disk.stop)

    def assemble(self, retry=False):
        return self.app.assemble(self.context, EXPECTED, '/unused', SOURCE, apply=True, retry=retry)

    def test_real_command_path_assembles_seals_probes_restarts_cleans_and_never_admits_jobs(self):
        result = self.assemble()
        self.assertEqual(result['boundary_and_version_cycles'], 2)
        self.assertFalse(result['job_admission'])
        self.assertTrue(result['runtime_container_removed'])
        self.assertEqual(len(self.app.entry_calls), 4)
        self.assertFalse(self.engine.containers)
        self.assertEqual(self.app.assert_ready_identity, RUNTIME)
        command_lists = [call[0] for call in self.engine.calls]
        creates = [call for call in command_lists if 'create' in call]
        self.assertEqual(len(creates), 2)
        self.assertTrue(any('--network=slirp4netns:allow_host_loopback=false' in call for call in creates))
        self.assertTrue(any('--userns=keep-id:uid=1000,gid=1000' in call for call in creates))
        self.assertTrue(all('--privileged' not in call and '--security-opt=label=disable' not in call for call in creates))
        self.assertIn(g.FINAL_HOOK, creates[0])
        self.assertIn(g.FROZEN_HOOK, creates[1])
        for args, kwargs in self.engine.calls:
            if args[0] == '/usr/bin/systemd-run':
                runtime = next(value for value in args if value.startswith('--property=RuntimeMaxSec='))
                maximum = int(runtime.rsplit('=', 1)[1])
                self.assertGreater(kwargs['timeout'], maximum + 10)
                self.assertIn('--unit=dev-pair-gptbox-' + EXPECTED + '.service', args)
                self.assertIn('DBX_CONTAINER_MANAGER=podman', args)
        prior_builds = len([call for call in command_lists if 'build' in call])
        self.assertTrue(self.assemble()['reused_completed_evidence'])
        self.assertEqual(len([call for call, _ in self.engine.calls if 'build' in call]), prior_builds)

    def test_bad_finalizer_never_commits_or_records_success_and_explicit_retry_is_bounded(self):
        self.engine.bad_attestation = True
        with self.assertRaises(g.Blocked):
            self.assemble()
        self.assertFalse(any('commit' in call for call, _ in self.engine.calls))
        self.assertFalse(self.app.path(self.app.target + '/result.json').exists())
        with self.assertRaises(g.Blocked):
            self.assemble()
        self.engine.bad_attestation = False
        self.assertFalse(self.assemble(retry=True)['job_admission'])
        self.assertEqual(json.loads(self.app.text(self.app.target + '/attempt.json'))['count'], 2)

    def test_runtime_security_mutations_fail_before_any_entry(self):
        self.assemble()
        # Field names follow Podman's InspectContainerHostConfig/InspectIDMappings
        # at a6a942f2ae0fc8ea001af86c2fd6322299c5a66c, not a Docker-only schema.
        original = copy.deepcopy(self.engine.saved_runtime)
        original['State'].update(Status='running', Running=True)
        before = len(self.app.entry_calls)
        mutations = [
            lambda row: row['HostConfig'].update(ReadonlyRootfs=False),
            lambda row: row['Config'].update(User='0'),
            lambda row: row['HostConfig'].update(Privileged=True),
            lambda row: row['HostConfig'].update(PidMode='host'),
            lambda row: row['HostConfig'].update(IpcMode='host'),
            lambda row: row['HostConfig'].update(UsernsMode='host'),
            lambda row: row['HostConfig'].update(NetworkMode='bridge'),
            lambda row: row['HostConfig'].update(Memory=0),
            lambda row: row['HostConfig'].update(PidsLimit=-1),
            lambda row: row['HostConfig'].update(NanoCpus=0),
            lambda row: row['HostConfig'].update(IDMappings={'UidMap': ['0:100000:65536'], 'GidMap': []}),
            lambda row: row.update(EffectiveCaps=['CAP_SYS_ADMIN']),
            lambda row: row.update(ProcessLabel='unconfined_u:unconfined_r:unconfined_t:s0'),
            lambda row: row['Mounts'].append({'Type': 'bind', 'Source': '/', 'Destination': '/run/host', 'RW': True}),
        ]
        for mutate in mutations:
            row = copy.deepcopy(original)
            mutate(row)
            self.engine.containers[RUNTIME] = row
            with self.assertRaises(g.Blocked):
                self.app.enter(RUNTIME, SEALED, 'version')
        self.assertEqual(len(self.app.entry_calls), before)

    def test_busy_executor_is_not_duplicated_and_retry_stops_it_before_recovery(self):
        self.engine.bad_attestation = True
        with self.assertRaises(g.Blocked):
            self.assemble()
        self.engine.bad_attestation = False
        self.engine.active = True
        before = len(self.engine.calls)
        with self.assertRaisesRegex(g.Blocked, 'busy'):
            self.assemble()
        self.assertFalse(any(call[0][0] == '/usr/bin/systemd-run' for call in self.engine.calls[before:]))
        self.assertFalse(self.assemble(retry=True)['job_admission'])
        self.assertTrue(any(call[:2] == ('/usr/bin/systemctl', 'stop') for call, _ in self.engine.calls))

    def test_two_failed_attempts_exhaust_budget_and_preserve_evidence(self):
        self.engine.bad_attestation = True
        for retry in (False, True):
            with self.assertRaises(g.Blocked):
                self.assemble(retry)
        before = len([call for call, _ in self.engine.calls if 'build' in call])
        with self.assertRaisesRegex(g.Blocked, 'budget'):
            self.assemble(True)
        self.assertEqual(len([call for call, _ in self.engine.calls if 'build' in call]), before)
        self.assertTrue(self.app.path(self.app.target + '/failure.json').exists())

    def test_bounded_nonsecret_diagnostics_survive_real_child_failure_and_later_success(self):
        app = g.Gptbox(self.root)
        app.target = '/diagnostic-fixture'
        app.directory(app.target)
        app.executor = []
        secret = 'synthetic-secret-must-not-be-inherited'
        with patch.dict(os.environ, {'OPENAI_API_KEY': secret}):
            with self.assertRaises(g.Blocked):
                app.execute(sys.executable, '-c', 'import os,sys; print(os.getenv("OPENAI_API_KEY")); print("native failure diagnostic",file=sys.stderr); sys.exit(7)', timeout=3)
        for _ in range(6):
            self.assertEqual(app.execute(sys.executable, '-c', 'print("ok")', timeout=3).strip(), 'ok')
        path = app.path(app.target + '/diagnostics.json')
        record = json.loads(path.read_text())
        self.assertEqual(len(record['recent']), 4)
        self.assertEqual(len(record['failures']), 1)
        self.assertIn('native failure diagnostic', record['failures'][0]['stderr_tail'])
        self.assertNotIn(secret, path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_preview_and_low_storage_leave_engine_unchanged(self):
        before = len(self.engine.calls)
        result = self.app.assemble(self.context, EXPECTED, '/unused', SOURCE)
        self.assertTrue(result['preview'])
        self.assertEqual(len(self.engine.calls), before)
        with patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=7 * 1024 ** 3)):
            with self.assertRaisesRegex(g.Blocked, 'eight GiB'):
                self.assemble()
        self.assertFalse(any(call[0][0] == '/usr/bin/systemd-run' for call in self.engine.calls))

if __name__ == '__main__':
    unittest.main()
