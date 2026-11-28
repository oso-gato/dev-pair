"""Synthetic engine/command tests only: no Fedora, Podman or Distrobox runtime acceptance."""
import copy
import hashlib
import importlib.util
import subprocess
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

REAL_COPY_WORKSPACE = g.fedora_oci.copy_workspace
REAL_RECOVER_WORKSPACES = g.fedora_oci.recover_workspaces
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
        self.starts = 0
        self.stale_logs = False
        self.app = None
        self.images={}

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and self.fail(args):
            raise g.Blocked('injected engine boundary failure')
        if args[:2] == ('/usr/bin/id', '-u') or args[:2] == ('/usr/bin/id', '-g'):
            return '1001\n'
        if args[:2] == ('/usr/bin/systemctl', 'show'):
            return 'User=dp-maint\nDescription=dev-pair-owned-dev-pair-gptbox-' + EXPECTED + '.service\nActiveState=' + ('active' if self.active else 'inactive') + '\n'
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
            if command[-1] in self.images:return json.dumps([self.images[command[-1]]])
            return json.dumps([{'Id': SEALED, 'Labels': {'dev-pair.context': EXPECTED, 'dev-pair.distrobox': g.DBX_SHA, 'org.opencontainers.image.revision': SOURCE}}])
        if command[0] == 'pull':
            return ''
        if command[0] == 'build':
            self.build = Path(command[-1])
            import re
            line=next(v for v in (self.build/'Containerfile').read_text().splitlines() if v.startswith('LABEL '))
            labels=dict(v.split('=',1) for v in line[6:].split())
            self.images[BASE]={'Id':BASE,'Labels':labels,'Architecture':'amd64','Os':'linux'}
            return BASE
        if command[0] == 'commit':
            self.images['sha256:' + SEALED] = {**self.images[BASE], 'Id': SEALED}
            return SEALED
        if command[0] == 'create':
            runtime = '--read-only' in command
            identity = RUNTIME if runtime else STAGE
            name = next(value.split('=', 1)[1] for value in command if value.startswith('--name='))
            config = {'User': '1000:1000' if runtime else '',
                      'Timeout': int(next(value[10:] for value in command if value.startswith('--timeout='))),
                      'Labels': {'manager': 'distrobox', 'distrobox.unshare_groups': '0', 'dev-pair.context': EXPECTED}}
            host = {'Privileged': False, 'ReadonlyRootfs': runtime, 'CapAdd': [] if runtime else ['CAP_SYS_ADMIN'],
                    'CapDrop': ['ALL'] if runtime else [], 'SecurityOpt': ['no-new-privileges'],
                    'PidMode': 'private', 'IpcMode': 'private', 'UTSMode': 'private', 'NetworkMode': 'none' if runtime else 'slirp4netns',
                    'UsernsMode': 'private', 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                    'Tmpfs': ({'/run': 'rw,nosuid,nodev,uid=1000,gid=1000,mode=0700', '/tmp': 'rw,nosuid,nodev,uid=1000,gid=1000,mode=0700'}
                              if runtime else {'/run': 'rw,nosuid,nodev,mode=0755', '/tmp': 'rw,nosuid,nodev,mode=1777'}),
                    'IDMappings': {'UidMap': ['1000:1001:1'], 'GidMap': ['1000:1001:1']},
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
            else:
                self.saved_stage = copy.deepcopy(self.containers[identity])
            return identity
        if command[0] == 'inspect':
            identity = command[-1]
            found = self.containers.get(identity)
            if found is None:
                found = next((value for value in self.containers.values() if value['Name'] == identity), None)
            return json.dumps([found] if found else [])
        if command[:2] == ('container', 'exists'):
            identity = command[-1]
            present = identity in self.containers or any(item['Name'] == identity for item in self.containers.values())
            if (0 if present else 1) not in kwargs.get('ok', (0,)):
                raise g.Blocked('synthetic container existence status rejected')
            return ''
        if command[0] == 'start':
            identity = command[-1]
            if '--attach' in command:
                self.containers[identity]['State'].update(Status='exited', Running=False)
                record = {'kind': 'genuine-distrobox-assembled', 'source_sha': SOURCE, 'uid': 1000, 'gid': 1000,
                          'inputs_sha256': hashlib.sha256((self.build / 'inputs.json').read_bytes()).hexdigest(),
                          'packages_sha256': '1' * 64}
                if self.bad_attestation:
                    record['inputs_sha256'] = '0' * 64
                return 'Synthetic fixture upstream progress\n' + json.dumps(record)
            self.starts += 1
            self.containers[identity]['State'].update(Status='running', Running=True, StartedAt=f'2026-11-15T00:00:{self.starts:02d}.123456789Z')
        if command[0] == 'logs':
            return '' if self.stale_logs and any(value.startswith('--since=') for value in command) else 'container_setup_done\n'
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
        return {'codex':{'sha256':hashlib.sha256(Path(context,'codex').read_bytes()).hexdigest()}}, {'distrobox-init': b'upstream fixture NOT DISTROBOX\n', 'distrobox-enter': b'entry fixture NOT DISTROBOX\n'}

    def directory(self, name, mode=0o700, owner=None):
        return super().directory(name, mode, owner=None)

    def execute(self, *args, timeout=120, ok=(0,)):
        if any(value.endswith('/distrobox-enter') for value in args[:5]):
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
        self.app.atomic(g.STATE + '/prepared', 'fixture prepared state, not host evidence')
        # Completion is installed after the known synthetic Codex/proof inputs below.
        self.context = self.root / 'input'
        self.context.mkdir()
        import fedora_input_fixture
        fedora_input_fixture.install(self)
        (self.context / 'codex').write_bytes(b'fixture NOT CODEX')
        import fedora_input_fixture
        legacy={'kind':'host-maintenance-gptbox-oci-candidate','source_sha':SOURCE,'context_sha256':EXPECTED,'image_id':'f'*64,
            'base_image':g.FEDORA,'codex_sha256':hashlib.sha256((self.context/'codex').read_bytes()).hexdigest(),
            'local_tag':'localhost/dev-pair/maintenance-gptbox:'+EXPECTED,'runtime_user':'dp-maint','storage_driver':'vfs',
            'launch':'blocked: stock Distrobox 1.8.2.5 adds privileged, label=disable and host mounts','distrobox_assembled':False,'runtime_validated':False,
            'fedora_base':fedora_input_fixture.synthetic_import(lambda *a,**k:None,Path('/synthetic'))}
        self.app.atomic(g.STATE+'/gptbox-image.json',json.dumps(legacy)+'\n')
        self.engine.images['f'*64]={'Id':'f'*64,'Architecture':'amd64','Os':'linux','Labels':{'dev-pair.context':EXPECTED,'org.opencontainers.image.revision':SOURCE,'dev-pair.role':'maintenance','dev-pair.standards':g.candidate.STANDARDS,'dev-pair.codex.version':'0.169.0'}}
        self.disk = patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=16 * 1024 ** 3))
        self.disk.start()
        self.addCleanup(self.disk.stop)

    def assemble(self, retry=False):
        return self.app.assemble(self.context, EXPECTED, '/unused', SOURCE, apply=True, retry=retry)

    def test_exhausted_cleanup_only_reclaims_recorded_image_work(self):
        self.app.target=g.ROOT+'/'+EXPECTED
        self.app.directory(self.app.target,mode=0o755)
        self.app.record('attempt',{'source_sha':SOURCE,'context_sha256':EXPECTED,'distrobox_sha':g.DBX_SHA,'count':2})
        work=self.app.path('/var/lib/dev-pair/artifacts/gptbox-adapter/'+EXPECTED+'/image-work')
        work.mkdir(parents=True);work.chmod(0o755)
        for verification in (False,True):
            with self.assertRaises(RuntimeError):
                with REAL_COPY_WORKSPACE(work,reconcile=lambda:(_ for _ in ()).throw(RuntimeError()),verification=verification) as leaf:
                    (leaf/'residue').write_text('interrupted own work')
        original=self.app.run
        def run(*args,**kwargs):
            if args[:2]==('/usr/bin/id','-u'):return str(os.getuid())+'\n'
            return original(*args,**kwargs)
        self.app.run=run
        with patch.object(g.fedora_oci,'copy_workspace',REAL_COPY_WORKSPACE), \
             patch.object(g.fedora_oci,'recover_workspaces',REAL_RECOVER_WORKSPACES):
            with self.assertRaisesRegex(g.Blocked,'build budget exhausted'):self.assemble(retry=True)
        self.assertEqual(list(work.iterdir()),[])
        self.assertFalse(any('build' in args for args,kw in self.engine.calls))
        self.assertEqual(json.loads(self.app.text(self.app.target+'/cleanup-only.json'))['phase'],'complete')

    def test_real_command_path_assembles_seals_probes_restarts_cleans_and_never_admits_jobs(self):
        result = self.assemble()
        recipe = (self.engine.build / 'Containerfile').read_text()
        shell = next(line[4:] for line in recipe.splitlines() if line.startswith('RUN '))
        subprocess.run(['/bin/sh', '-n'], input=shell, text=True, check=True, capture_output=True)
        self.assertIn('/usr/bin/timeout --signal=TERM --kill-after=10s 540s /bin/sh -ec', shell)
        self.assertIn('glibc-all-langpacks', shell)
        self.assertIn('dnf-plugins-core', shell)
        self.assertIn('test -d /usr/share/i18n/charmaps', shell)
        self.assertIn('localpkg_gpgcheck=1', shell)
        self.assertIn('rpms.txt', shell)
        self.assertEqual(result['boundary_and_version_cycles'], 2)
        self.assertFalse(result['job_admission'])
        self.assertTrue(result['runtime_container_removed'])
        self.assertEqual(len(self.app.entry_calls), 4)
        self.assertFalse(self.engine.containers)
        self.assertEqual(self.app.assert_ready_identity, RUNTIME)
        command_lists = [call[0] for call in self.engine.calls]
        for call in command_lists:
            if call[0] == '/usr/bin/systemd-run' and any(operation in call for operation in ('load','save','build')):
                temp = [value for value in call if value.startswith('TMPDIR=')]
                self.assertEqual(len(temp),1)
                self.assertIn('/image-work/image-copy',temp[0])
                self.assertGreater(call.index(temp[0]),call.index('-i'))
        wrapper = Path(self.app.wrapper).read_text()
        self.assertIn(str(g.fedora_oci.SAVE_FILE_LIMIT),wrapper)
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

    def test_prepared_host_cli_lane_builds_and_executes_both_probes_without_core_setup(self):
        from contextlib import nullcontext

        self.app.path(g.STATE + '/gptbox-image.json').unlink()
        desired = self.app.text(g.STATE + '/prepared')
        self.app.atomic(g.STATE + '/desired.json', desired)
        self.app.atomic(g.STATE + '/packages.txt', 'fixture package readback\n')
        ready = {'schema': 1, 'kind': 'host-prerequisites', 'source_sha': SOURCE, 'context_sha256': EXPECTED,
                 'standards_sha': g.candidate.STANDARDS, 'bootstrap_sha256': g.sha((Path(g.__file__).with_name('bootstrap.py')).read_bytes()),
                 'desired_sha256': g.sha(desired.encode()), 'packages_sha256': g.sha(b'fixture package readback\n')}
        self.app.atomic(g.STATE + '/host-ready.json', json.dumps(ready) + '\n')
        argv = ['gptbox.py', 'assemble-prepared-maintenance', '--apply', '--context', str(self.context),
                '--expected-context-sha256', EXPECTED, '--distrobox-source', '/unused', '--source-sha', SOURCE]
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with (patch.object(g, 'Gptbox', return_value=self.app),
              patch.object(self.app, 'maintenance_host_readiness', return_value=ready),
              patch.object(self.app.run, 'phase', return_value=nullcontext(), create=True),
              patch.object(sys, 'argv', argv), redirect_stdout(output)):
            self.assertEqual(g.main(), 0)
        observed = json.loads(output.getvalue())
        self.assertEqual(observed['boundary_and_version_cycles'], 2)
        self.assertTrue(observed['runtime_container_removed'])
        self.assertFalse(observed['job_admission'])
        self.assertEqual([args[-1] for args in self.app.entry_calls], ['probe', 'version', 'probe', 'version'])
        self.assertFalse(any('chpasswd' in args[0] for args, _ in self.engine.calls))

    def test_prepared_host_cli_rejects_permissive_preparation_marker(self):
        from contextlib import nullcontext, redirect_stderr
        from io import StringIO

        self.app.atomic(g.STATE + '/desired.json', '{}\n')
        marker = self.app.path(g.STATE + '/prepared')
        original = marker.read_bytes()
        marker.chmod(0o644)
        with self.assertRaisesRegex(g.Blocked, 'permissions conflict'):
            self.app.maintenance_host_readiness(EXPECTED)
        argv = ['gptbox.py', 'assemble-prepared-maintenance', '--apply', '--context', str(self.context),
                '--expected-context-sha256', EXPECTED, '--distrobox-source', '/unused', '--source-sha', SOURCE]
        with (patch.object(g, 'Gptbox', return_value=self.app),
              patch.object(self.app.run, 'phase', return_value=nullcontext(), create=True),
              patch.object(sys, 'argv', argv), redirect_stderr(StringIO())):
            self.assertEqual(g.main(), 2)
        self.assertEqual(marker.read_bytes(), original)
        self.assertFalse(self.engine.calls)
        self.assertFalse(self.app.entry_calls)

    def test_combined_initialize_retry_reconciles_native_inventory_and_completes_receipt(self):
        from contextlib import nullcontext

        self.app.path(g.STATE + '/gptbox-image.json').unlink()
        desired = self.app.text(g.STATE + '/prepared')
        self.app.atomic(g.STATE + '/desired.json', desired)
        self.app.atomic(g.STATE + '/packages.txt', 'fixture package readback\n')
        ready = {'schema': 1, 'kind': 'host-prerequisites', 'source_sha': SOURCE, 'context_sha256': EXPECTED,
                 'standards_sha': g.candidate.STANDARDS, 'bootstrap_sha256': g.sha((Path(g.__file__).with_name('bootstrap.py')).read_bytes()),
                 'desired_sha256': g.sha(desired.encode()), 'packages_sha256': g.sha(b'fixture package readback\n')}
        self.app.atomic(g.STATE + '/host-ready.json', json.dumps(ready) + '\n')
        self.app.atomic(g.STATE + '/operator-password-set', 'password configured; value remains external\n')
        access = ['192.0.2.44/32']
        target = {'source_sha': SOURCE, 'context_sha256': EXPECTED, 'distrobox_sha': g.DBX_SHA,
                  'bootstrap_sources': access}
        unit = 'dev-pair-initialize-adapter-1234abcd-5678efab'
        stale = {'schema': 2, 'target': target, 'phase': 'maintenance-gptbox', 'prepare': 'complete',
                 'maintenance_gptbox': 'blocked', 'native_units': [unit]}
        self.app.atomic(g.STATE + '/initialize.json', json.dumps(stale) + '\n')
        self.app.run.metadata_diagnostic = None
        preparation = SimpleNamespace(run=self.app.run, _host_prerequisites=lambda *args, **kwargs: ready)
        argv = ['gptbox.py', 'initialize', '--apply', '--retry', '--context', str(self.context),
                '--expected-context-sha256', EXPECTED, '--distrobox-source', '/unused', '--source-sha', SOURCE,
                '--bootstrap-source', access[0]]
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with (patch.object(g, 'Gptbox', return_value=self.app), patch.object(g, 'github_keys', return_value='fixture'),
              patch.object(self.app, 'preparation', return_value=preparation),
              patch.object(self.app, 'protected', side_effect=lambda path: Path(path)),
              patch.object(self.app, 'check_gptbox_inputs', return_value=(None, None, {'source_sha': SOURCE})),
              patch.object(self.app.run, 'phase', return_value=nullcontext(), create=True),
              patch.object(self.app.run, 'reconcile_native', create=True) as reconcile,
              patch.object(sys, 'argv', argv), redirect_stdout(output)):
            self.assertEqual(g.main(), 0)
        observed = json.loads(output.getvalue())
        self.assertEqual(observed['phase'], 'complete')
        self.assertEqual(observed['result']['boundary_and_version_cycles'], 2)
        self.assertEqual(observed['native_units'], [unit])
        self.assertEqual(reconcile.call_args_list[0].args[0], ('--unit=' + unit, '--description=dev-pair-owned-' + unit))
        self.assertEqual(json.loads(self.app.text(g.STATE + '/initialize.json')), observed)
        self.assertEqual(len(self.app.entry_calls), 4)
        self.assertFalse(any('chpasswd' in args[0] for args, _ in self.engine.calls))

    def test_pre_change_local_completion_binds_the_actual_sealed_output(self):
        result = self.assemble()
        resources = self.app.target + '/resources.json'
        prepared = g.STATE + '/gptbox-image.json'
        with patch.object(self.app, 'maintenance_gateway'):
            # Standalone assemble retained the original minimal preparation.
            self.assertEqual(self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED), '0.169.0')
            # Normal initialize publishes this same full candidate as preparation.
            self.app.atomic(prepared, self.app.text(self.app.target + '/candidate-image.json'),
                            expected=self.app.text(prepared))
            self.assertEqual(self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED), '0.169.0')
            # A different image can carry the same labels and copy result fields.
            # It cannot replace the sealed ID recorded by the actual attempt.
            other = '0' * 64
            self.engine.images['sha256:' + other] = {**self.engine.images['sha256:' + SEALED], 'Id': other}
            self.app.record('result', {**result, 'assembled_image_id': other})
            with self.assertRaisesRegex(g.Blocked, 'assembly resources differ'):
                self.app.admitted_maintenance_image(EXPECTED, SOURCE, other)
            self.app.record('result', result)
            self.app.path(resources).unlink()
            with self.assertRaisesRegex(g.Blocked, 'resources.json'):
                self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED)

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

    def test_storage_stage_is_after_exact_removal_and_never_after_failure(self):
        observed=[]
        original=self.app.observe_storage
        def observe(*args):
            self.assertFalse(self.engine.containers)
            observed.append(args)
            return original(*args)
        with patch.object(self.app,'observe_storage',side_effect=observe):
            self.assemble()
        self.assertEqual(observed,[('assembled-postcleanup',SOURCE,EXPECTED,'f'*64,SEALED)])
        value=json.loads(self.app.text(self.app.target+'/storage-assembled-postcleanup.json'))
        self.assertTrue(value['cleanup_verified']);self.assertEqual(value['reason'],'bounded-runner-unavailable')
        self.app.path(self.app.target+'/result.json').unlink()
        self.engine.bad_attestation=True
        with patch.object(self.app,'observe_storage',side_effect=AssertionError('observation after failed assembly')):
            with self.assertRaisesRegex(g.Blocked,'attestation'):self.assemble(retry=True)

    def test_storage_stage_does_not_run_after_failed_owned_cleanup(self):
        self.engine.fail=lambda args:'rm' in args
        with patch.object(self.app,'observe_storage',side_effect=AssertionError('postcleanup stage invented')):
            with self.assertRaisesRegex(g.Blocked,'injected engine boundary failure'):self.assemble()
        self.assertFalse(self.app.path(self.app.target+'/storage-assembled-postcleanup.json').exists())

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
            lambda row: row['Config'].update(Timeout=0),
            lambda row: row['HostConfig']['Tmpfs'].update({'/usr/local/lib': 'rw,nosuid,nodev,mode=0700'}),
            lambda row: row['HostConfig']['Tmpfs'].update({'/run': 'rw,suid,dev,mode=0700'}),
            lambda row: row['HostConfig'].update(RestartPolicy={'Name': 'always'}),
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

    def test_exhausted_build_budget_still_cleans_orphan_after_second_cleanup_failure(self):
        self.engine.bad_attestation = True
        with self.assertRaises(g.Blocked):
            self.assemble()
        self.engine.bad_attestation = False
        self.engine.fail = lambda args: ('logs' in args or ('rm' in args and args[-1] == RUNTIME))
        with self.assertRaises(g.Blocked):
            self.assemble(True)
        self.assertTrue(self.engine.containers[RUNTIME]['State']['Running'])
        builds = len([call for call, _ in self.engine.calls if 'build' in call])
        self.engine.fail = None
        with patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=1024)):
            with self.assertRaisesRegex(g.Blocked, 'resources cleaned without another build'):
                self.assemble(True)
        self.assertFalse(self.engine.containers)
        self.assertEqual(len([call for call, _ in self.engine.calls if 'build' in call]), builds)
        self.assertEqual(json.loads(self.app.text(self.app.target + '/cleanup-only.json'))['phase'], 'complete')
        creates = [call for call, _ in self.engine.calls if 'create' in call]
        self.assertTrue(all('--restart=no' in call for call in creates))
        self.assertTrue(all(any(value in call for value in ('--timeout=900', '--timeout=180')) for call in creates))

    def test_restart_requires_new_start_identity_and_current_start_readiness_marker(self):
        self.assemble()
        row = copy.deepcopy(self.engine.saved_runtime)
        row['State'].update(Status='running', Running=True, StartedAt='2026-11-15T01:02:03.123456789Z')
        self.engine.containers[RUNTIME] = row
        with self.assertRaisesRegex(g.Blocked, 'stale'):
            self.app.ready(RUNTIME, SEALED, row['State']['StartedAt'])
        self.engine.stale_logs = True
        with patch.object(g.time, 'monotonic', side_effect=[0, 1, 31]), patch.object(g.time, 'sleep'):
            with self.assertRaisesRegex(g.Blocked, 'deadline'):
                self.app.ready(RUNTIME, SEALED)
        logs = [call for call, _ in self.engine.calls if 'logs' in call]
        self.assertIn('--since=' + row['State']['StartedAt'], logs[-1])
        self.assertTrue(all(any(value.startswith('--since=') for value in call) for call in logs))

    def test_explicit_no_copy_tmpfs_matches_actual_upstream_normalization(self):
        self.assemble()
        # Podman a6a942f... pkg/util/mount_opts.go:150-159 consumes
        # notmpcopyup (not passed to OCI), and :216-238 appends rprivate
        # while suppressing the default tmpcopyup. Inspector joins those OCI
        # options into HostConfig.Tmpfs. Exercise that exact normalized shape.
        creates = [call for call, _ in self.engine.calls if 'create' in call]
        for command in creates:
            options = [value for value in command if value.startswith('--tmpfs=')]
            self.assertEqual(len(options), 2)
            self.assertTrue(all(value.endswith(',notmpcopyup') for value in options))
        for runtime, identity, image, original in (
                (False, STAGE, BASE, self.engine.saved_stage),
                (True, RUNTIME, SEALED, self.engine.saved_runtime)):
            row = copy.deepcopy(original)
            row['HostConfig']['Tmpfs'] = {path: value + ',rprivate' for path, value in row['HostConfig']['Tmpfs'].items()}
            self.engine.containers[identity] = row
            self.app.inspect_container(identity, image, runtime=runtime)
            # Unexpected copying is outside the explicitly constructed policy;
            # extra destinations and unsafe options remain rejected as before.
            row['HostConfig']['Tmpfs']['/run'] += ',tmpcopyup'
            with self.assertRaisesRegex(g.Blocked, 'undeclared tmpfs option'):
                self.app.inspect_container(identity, image, runtime=runtime)

    def test_preview_and_low_storage_leave_engine_unchanged(self):
        before = len(self.engine.calls)
        result = self.app.assemble(self.context, EXPECTED, '/unused', SOURCE)
        self.assertTrue(result['preview'])
        self.assertEqual(len(self.engine.calls), before)
        with patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=7 * 1024 ** 3)):
            with self.assertRaisesRegex(g.Blocked, 'eight GiB'):
                self.assemble()
        self.assertFalse(any(call[0][0] == '/usr/bin/systemd-run' for call in self.engine.calls))

class ProductionInputContractTests(unittest.TestCase):
    def test_refresh_tooling_is_unavailable_outside_the_authenticated_native_guest(self):
        with self.assertRaisesRegex(g.Blocked, 'authenticated native CI producer'):
            g.Gptbox().use_ci_tooling('b' * 64)

    def test_production_inputs_accepts_real_helper_triple_and_checks_git_objects(self):
        # Actual production inputs()/check_gptbox_inputs()/candidate verification run.
        # The tiny ELF/upstream scripts are explicitly UNTRUSTED synthetic artifacts;
        # only their external trust pins are injected. No engine or binary is run.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'reviewed-adapter-source'
            tools = repo / 'tools'
            tools.mkdir(parents=True)
            for name in ('gptbox.py', 'gptbox_runtime.py', 'bootstrap.py', 'selinux_bootstrap.py', 'candidate.py', 'native_io.py', 'native_relay.py', 'fedora_oci.py', 'public_inputs.py', 'storage.py', 'storage_observation.py', 'selected_payload.py'):
                (tools / name).write_bytes((ROOT / 'tools' / name).read_bytes())
            upstream = root / 'synthetic-upstream-NOT-DISTROBOX'
            upstream.mkdir()
            for name in ('distrobox-init', 'distrobox-enter'):
                (upstream / name).write_text('#!/bin/sh\nexit 0\n')
            def commit(path):
                for args in (('init', '--quiet'), ('add', '.'),
                             ('-c', 'user.name=Offline fixture', '-c', 'user.email=fixture@example.invalid',
                              '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                              'commit', '--quiet', '-m', 'Untrusted test source')):
                    subprocess.run(['/usr/bin/git', '-C', str(path), *args], check=True, capture_output=True)
                return subprocess.run(['/usr/bin/git', '-C', str(path), 'rev-parse', 'HEAD'],
                                      check=True, text=True, capture_output=True).stdout.strip()
            source_sha, upstream_sha = commit(repo), commit(upstream)
            def module(name, file):
                spec = importlib.util.spec_from_file_location(name, file)
                value = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(value)
                return value
            adapter = module('production_adapter_contract_fixture', tools / 'gptbox.py')
            preparation = module('production_candidate_contract_fixture', tools / 'candidate.py')
            data = bytearray(64)
            data[:6] = b'\x7fELF\x02\x01'
            data[18:20] = b'\x3e\x00'
            binary = root / 'synthetic-ELF-NOT-CODEX'
            binary.write_bytes(data)
            manifest = {'kind': 'operator-verified-inputs', 'source_sha': source_sha,
                        'standards_sha': preparation.STANDARDS,
                        'fedora': dict(adapter.fedora_oci.PROVENANCE),
                        'codex': {'version': '0.169.0', 'sha256': hashlib.sha256(data).hexdigest(),
                                  'source': 'https://github.com/openai/codex/releases/download/rust-v0.169.0/codex-x86_64-unknown-linux-musl.tar.gz',
                                  'verification': 'SYNTHETIC OFFLINE CONTRACT TEST - not Codex provenance'},
                        'role': 'maintenance', 'provider': 'gptbox', 'model': 'gpt-6.1-sol', 'effort': 'high',
                        'mounts': {name: ('/var/lib/dev-pair/credentials/maintenance/contract-test' if name == 'credentials'
                                         else '/var/lib/dev-pair/maintenance/' + {'workspace': 'workspaces', 'state': 'state', 'cache': 'cache'}[name] + '/contract-test')
                                   for name in ('workspace', 'state', 'cache', 'credentials')}}
            context = root / 'actual-verified-context'
            import fedora_input_fixture
            fedora_input_fixture.install(self)
            prepared = preparation.prepare(manifest, binary, context, fedora_inputs=root)
            app = adapter.Gptbox(root)
            # Redirect only physical module location/external trust pins; preserve
            # production helper implementation and its actual three-value return.
            bootstrap_module = sys.modules[adapter.Bootstrap.__module__]
            public_dependency = module('production_public_dependency_fixture', tools / 'public_inputs.py')
            with patch.object(adapter.fedora_oci, '_public_inputs', return_value=public_dependency), \
                    patch.object(bootstrap_module, '__file__', str(tools / 'bootstrap.py')), \
                    patch.object(adapter, 'candidate', preparation), \
                    patch.object(adapter, 'CODEX_SHA', manifest['codex']['sha256']), \
                    patch.object(adapter, 'DBX_SHA', upstream_sha):
                observed, scripts = app.inputs(context, prepared['context_sha256'], upstream, source_sha)
                self.assertEqual(observed, manifest)
                self.assertEqual(scripts['distrobox-init'], (upstream / 'distrobox-init').read_bytes())
                self.assertFalse(app.state.exists())
                with self.assertRaisesRegex(adapter.Blocked, 'context source'):
                    app.inputs(context, prepared['context_sha256'], upstream, '0' * 40)
                (repo / 'extra-public-file').write_text('changed HEAD, unchanged executors\n')
                commit(repo)
                with self.assertRaisesRegex(adapter.Blocked, 'HEAD differs'):
                    app.inputs(context, prepared['context_sha256'], upstream, source_sha)
                subprocess.run(['/usr/bin/git', '-C', str(repo), 'reset', '--hard', source_sha], check=True, capture_output=True)
                (upstream / 'extra-public-file').write_text('changed HEAD, unchanged scripts\n')
                commit(upstream)
                with self.assertRaisesRegex(adapter.Blocked, 'HEAD differs'):
                    app.inputs(context, prepared['context_sha256'], upstream, source_sha)
                subprocess.run(['/usr/bin/git', '-C', str(upstream), 'reset', '--hard', upstream_sha], check=True, capture_output=True)
                (upstream / 'distrobox-enter').write_text('# mutated upstream source\n')
                with self.assertRaisesRegex(adapter.Blocked, 'exact Git object'):
                    app.inputs(context, prepared['context_sha256'], upstream, source_sha)

if __name__ == '__main__':
    unittest.main()
