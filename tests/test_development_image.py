"""Development producer component checks with a synthetic engine and real OCI bytes."""
import ctypes
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import time
from unittest.mock import patch

from test_gptbox import BASE, EXPECTED, RUNTIME, SOURCE, Engine, g
import fedora_input_fixture
from test_devbox import db


class ProducerEngine(Engine):
    def __init__(self):
        super().__init__()
        self.bad_seal = False
        self.bad_archive = False
        self.bad_index_media = False
        self.account_uid = max(os.getuid(), 1000)
        self.account_gid = os.getgid() if os.getgid() >= 1000 else self.account_uid
        self.groups = 'dp-maint\n'
        self.packages = 'synthetic Fedora host packages\n'
        self.sealed_id = None

    def __call__(self, *args, **kwargs):
        if args == ('/usr/bin/id', '-u', 'dp-maint'):
            return f'{self.account_uid}\n'
        if args == ('/usr/bin/id', '-g', 'dp-maint'):
            return f'{self.account_gid}\n'
        if args == ('/usr/bin/id', '-nG', 'dp-maint'):
            return self.groups
        if args == ('/usr/bin/getent', 'passwd', 'dp-maint'):
            return f'dp-maint:x:{self.account_uid}:{self.account_gid}::/home/dp-maint:/usr/sbin/nologin\n'
        if args == ('/usr/bin/passwd', '-S', 'dp-maint'):
            return 'dp-maint LK synthetic\n'
        if args == ('/usr/bin/hostnamectl', '--static'):
            return 'erebus\n'
        if args == g.SUDO_PACKAGE_QUERY:
            return {'fixture': 'synthetic sudo package'}
        if args == ('/usr/bin/sudo', '-l', '-U', 'dp-maint'):
            return {'outcome': 'denied'}
        if args[:2] == ('/usr/bin/rpm', '-q'):
            return self.packages
        if not args or args[0] != '/usr/bin/systemd-run':
            return super().__call__(*args, **kwargs)
        pos = args.index(self.app.wrapper)
        command = args[pos + 1:]
        operation = command[0]
        if operation == 'start' and '--attach' in command:
            log = super().__call__(*args, **kwargs)
            attestation = json.loads(log.splitlines()[-1])
            attestation['packages_sha256'] = g.sha(b'synthetic package list')
            self.seal = g.image_inputs_bytes(attestation)
            return log.splitlines()[0] + '\n' + json.dumps(attestation)
        if operation == 'commit':
            self.calls.append((args, kwargs))
            assert command[1:3] == ('--pause=false', '--format=oci')
            assert self.containers[command[-1]]['State']['Status'] == 'exited'
            self.make_oci()
            return self.sealed_id
        if operation == 'create' and '--entrypoint=/usr/bin/false' in command:
            self.calls.append((args, kwargs))
            assert command[-1] == 'sha256:' + self.sealed_id
            self.containers[RUNTIME] = {'Id': RUNTIME, 'Image': self.sealed_id,
                'Config': {'Labels': {'dev-pair.context': EXPECTED},
                           'Timeout': int(next(value[10:] for value in command if value.startswith('--timeout=')))},
                'HostConfig': {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}},
                'Name': next(part[7:] for part in command if part.startswith('--name=')),
                'State': {'Status': 'configured', 'Running': False}}
            return RUNTIME
        if operation == 'cp':
            self.calls.append((args, kwargs))
            assert command[2].startswith(RUNTIME + ':')
            path = Path(command[-1])
            data = (self.build / 'inputs.json').read_bytes() if path.name == 'inputs.json' else self.seal
            if path.name == 'sealed.json' and self.bad_seal:
                data = data.strip()
            path.write_bytes(data)
            self.own(path)
            return ''
        if operation == 'save' and Path(command[3]).name == g.RELEASE_ARCHIVE:
            self.calls.append((args, kwargs))
            assert command[1:3] == ('--format=oci-archive', '--output')
            assert command[-1] == 'sha256:' + self.sealed_id
            path = Path(command[3])
            with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
                for name, content in self.members.items():
                    if self.bad_archive and name == self.layer_name:
                        content = b'x' + content[1:]
                    entry = tarfile.TarInfo('./' + name)
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
            self.own(path)
            return ''
        return super().__call__(*args, **kwargs)

    def own(self, path):
        if os.getuid() != self.account_uid:
            os.chown(path, self.account_uid, -1)

    def make_oci(self):
        media = 'application/vnd.oci.image.'
        self.members = {'oci-layout': g.image_inputs_bytes({'imageLayoutVersion': '1.0.0'})}

        def blob(kind, data):
            digest = g.sha(data)
            self.members['blobs/sha256/' + digest] = data
            return {'mediaType': media + kind, 'digest': 'sha256:' + digest, 'size': len(data)}

        plain = b'synthetic base layer'
        self.diffs = ['sha256:' + g.sha(plain), 'sha256:' + g.sha(b'synthetic finalizer layer')]
        layers = [blob('layer.v1.tar', plain), blob('layer.v1.tar+gzip', gzip.compress(b'synthetic finalizer layer', mtime=0))]
        self.layer_name = 'blobs/sha256/' + layers[-1]['digest'][7:]
        labels = self.images[BASE]['Labels']
        config = blob('config.v1+json', g.image_inputs_bytes({'architecture': 'amd64', 'os': 'linux',
            'config': {'Labels': labels}, 'rootfs': {'type': 'layers', 'diff_ids': self.diffs}}))
        manifest = blob('manifest.v1+json', g.image_inputs_bytes({'schemaVersion': 2, 'config': config, 'layers': layers}))
        index = {'schemaVersion': 2, 'manifests': [manifest]}
        if self.bad_index_media:
            index['mediaType'] = 'application/json'
        self.members['index.json'] = g.image_inputs_bytes(index)
        self.sealed_id = config['digest'][7:]
        self.images[config['digest']] = {'Id': self.sealed_id, 'Labels': labels, 'Os': 'linux',
                                         'Architecture': 'amd64', 'RootFS': {'Layers': self.diffs}}


class ProducerFixture(g.DevelopmentGptbox):
    def preflight(self):
        return {'fixture': 'no Fedora runtime evidence'}

    def inputs(self, context, expected, upstream, revision):
        self.archive_verifier = db
        return {'role': 'development', 'codex': {'sha256': g.sha((context / 'codex').read_bytes())}}, {
            'distrobox-init': b'synthetic Distrobox init\n', 'distrobox-enter': b'synthetic Distrobox enter\n'}

    def directory(self, name, mode=0o700, owner=None):
        return super().directory(name, mode=mode)


class DevelopmentImageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o755)
        self.engine = ProducerEngine()
        self.app = self.engine.app = ProducerFixture(self.root, self.engine)
        self.context = self.root / 'context'
        self.context.mkdir()
        (self.context / 'codex').write_bytes(b'synthetic Codex')
        self.release = self.app.path(g.DEVELOPMENT_ARTIFACTS + '/' + EXPECTED + '/release')
        self.pending = self.release.with_name('release.pending')
        self.publication = self.app.path(g.DEVELOPMENT_ROOT + '/' + EXPECTED + '/publication.json')
        native_copy = g.fedora_oci.copy_workspace
        fedora_input_fixture.install(self)
        self.enterContext(patch.object(g.fedora_oci, 'copy_workspace', native_copy))
        self.enterContext(patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=20 * 1024 ** 3)))
        self.host_ready = self.seed_provisioned_host()

    def seed_provisioned_host(self):
        self.app.directory('/var/lib/dev-pair', mode=0o755)
        self.app._directory_as('/var/lib/dev-pair/maintenance', 0o700, self.engine.account_uid,
                               self.engine.account_gid, change_owner=True, check_gid=True)
        self.app.directory(g.STATE)
        desired = g.image_inputs_bytes({'schema': 1, 'standards_sha': g.candidate.STANDARDS,
            'source_baseline': g.SOURCE_BASELINE, 'bootstrap_sha256': '8' * 64,
            'gptbox_context_sha256': '9' * 64, 'operator': 'core', 'keys_source': g.KEYS_URL,
            'bootstrap_sources': ['192.0.2.10/32']})
        self.app.atomic(g.STATE + '/desired.json', desired.decode())
        self.app.atomic(g.STATE + '/packages.txt', self.engine.packages)
        self.app.atomic(g.STATE + '/identity-dp-maint.json', g.image_inputs_bytes({
            'name': 'dp-maint', 'shell': '/usr/sbin/nologin', 'substart': 1000000}).decode())
        ready = {'schema': 1, 'kind': 'host-prerequisites', 'source_sha': '7' * 40,
            'context_sha256': '9' * 64, 'standards_sha': g.candidate.STANDARDS,
            'bootstrap_sha256': '8' * 64, 'desired_sha256': g.sha(desired),
            'packages_sha256': g.sha(self.engine.packages.encode())}
        self.app.atomic(g.STATE + '/host-ready.json', g.image_inputs_bytes(ready).decode())
        for path in ('/etc/subuid', '/etc/subgid'):
            self.app.atomic(path, 'dp-maint:1000000:65536\ndp-dev:1065536:65536\n', mode=0o644)
        return self.app.path(g.STATE + '/host-ready.json')

    def assemble(self, retry=False, apply=True):
        return self.app.assemble(self.context, EXPECTED, '/', SOURCE, apply=apply, retry=retry)

    def bounded_engine(self, seconds):
        engine = self.engine

        class BoundedEngine(g.Commands):
            def __call__(self, *args, **kwargs):
                return engine(*args, **kwargs)

            def reconcile_native(self, args, env):
                engine.calls.append((args, {}))

        runner = BoundedEngine()
        runner.deadline = time.monotonic() + seconds
        self.enterContext(patch.object(self.app, 'run', runner))
        return runner

    def test_development_oci_effects_use_reduced_independent_lifetimes(self):
        runner = self.bounded_engine(160)
        started = time.monotonic()
        self.assertEqual(self.assemble()['inner']['image_id'], self.engine.sealed_id)
        build = next(args for args, _ in self.engine.calls if 'build' in args)
        end = int(next(arg.split('=', 2)[2] for arg in build if arg.startswith('--build-arg=DP_OCI_END=')))
        self.assertLessEqual(end, runner.deadline - g.CLEANUP_EXECUTION)
        self.assertIn('--pid=private', build)
        recipe = (self.engine.build / 'Containerfile').read_text()
        self.assertIn('ARG DP_OCI_END', recipe)
        create_stage = next(args for args, _ in self.engine.calls if 'create' in args and '--entrypoint=/bin/sh' in args)
        lifetime = int(next(arg[10:] for arg in create_stage if arg.startswith('--timeout=')))
        self.assertTrue(0 < lifetime < g.ASSEMBLY_LIFETIME)
        self.assertLessEqual(started + 2 * lifetime + g.CLEANUP_EXECUTION, runner.deadline)
        self.assertIn(g.DEVELOPMENT_TIMED_EXEC.replace('$', '$$'), create_stage)
        self.assertEqual(self.engine.saved_stage['Config']['Timeout'], lifetime)
        snapshot = next(args for args, _ in self.engine.calls if 'create' in args and '--entrypoint=/usr/bin/false' in args)
        snapshot_lifetime = int(next(arg[10:] for arg in snapshot if arg.startswith('--timeout=')))
        self.assertTrue(0 < snapshot_lifetime < g.RUNTIME_LIFETIME)
        self.assertNotIn(RUNTIME, next(args for args, _ in self.engine.calls if 'start' in args and '--attach' in args))
        self.assertFalse(self.engine.containers)

    def test_delayed_create_to_start_does_not_launch_past_oci_budget(self):
        runner = self.bounded_engine(160)
        original = self.app.inspect_container

        def delayed(*args, **kwargs):
            container = original(*args, **kwargs)
            runner.deadline = time.monotonic() + (g.CLEANUP_EXECUTION + g.OCI_KILL_GRACE + 5)
            return container

        with patch.object(self.app, 'inspect_container', side_effect=delayed), \
                self.assertRaisesRegex(g.Blocked, 'start no longer fits'):
            self.assemble()
        self.assertFalse(any('start' in args and '--attach' in args for args, _ in self.engine.calls))
        self.assertFalse(self.engine.containers)
        self.assertFalse(self.release.exists())

    def test_unobservable_development_container_removal_withholds_ready_release(self):
        self.bounded_engine(160)
        self.engine.fail = lambda argv: 'exists' in argv
        with self.assertRaisesRegex(g.Blocked, 'cleanup unresolved'):
            self.assemble()
        self.assertFalse(self.release.exists())
        self.assertEqual(json.loads(self.publication.read_bytes())['phase'], 'verified')
        state = json.loads(self.app.text(self.app.target + '/resource-cleanup.json'))
        self.assertEqual(state, {'context_sha256': EXPECTED, 'source_sha': SOURCE, 'status': 'unresolved; exact resources retained'})

    def test_oci_entry_guard_rejects_expired_or_zero_payload_before_dispatch(self):
        uptime = int(Path('/proc/uptime').read_text().split()[0].split('.')[0])
        command = ['/bin/sh', '-ec', g.DEVELOPMENT_TIMED_EXEC, 'fixture']
        for end, ceiling in ((uptime, 550), (uptime + 30, 0), (uptime + 30, 10)):
            result = subprocess.run([*command, str(end), str(ceiling), '/bin/sh', '-c', 'printf forbidden'],
                                    capture_output=True, check=False, timeout=3)
            self.assertEqual(result.returncode, 124)
            self.assertEqual(result.stdout, b'')
        result = subprocess.run([*command, str(uptime + 30), '15', '/bin/sh', '-c', 'printf allowed'],
                                capture_output=True, check=True, timeout=3)
        self.assertEqual(result.stdout, b'allowed')

    def test_assembly_guard_survives_the_installed_systemd_argv_expander(self):
        try:
            version = subprocess.check_output(['/usr/bin/systemd-run', '--version'], text=True).split()[1]
        except (OSError, subprocess.SubprocessError, IndexError):
            self.skipTest('systemd argument parser unavailable')
        name = 'libsystemd-shared-' + version + '.so'
        paths = [*Path('/usr/lib').glob('*/systemd/' + name), Path('/usr/lib/systemd') / name,
                 Path('/usr/lib64/systemd') / name]
        try:
            library = ctypes.CDLL(str(next(path for path in paths if path.is_file())))
            expand, free = library.replace_env_argv, library.strv_free
        except (StopIteration, OSError, AttributeError):
            self.skipTest('systemd shared argument parser unavailable')
        ptr = ctypes.POINTER(ctypes.c_char_p)
        expand.argtypes = (ptr, ptr, ctypes.POINTER(ptr), ctypes.POINTER(ptr), ctypes.POINTER(ptr))
        expand.restype = ctypes.c_int
        free.argtypes = (ptr,)
        free.restype = ptr

        self.bounded_engine(160)
        self.assemble()
        create = next(args for args, _ in self.engine.calls if 'create' in args and '--entrypoint=/bin/sh' in args)
        idx = create.index('-ec')
        for expired in (False, True):
            command = list(create)
            if expired:
                command[idx + 3] = '1'
            original = (ctypes.c_char_p * (len(command) + 1))(*[value.encode() for value in command], None)
            environment = (ctypes.c_char_p * 3)(b'left=poison', b'uptime=poison', None)
            expanded, unset, bad = ptr(), ptr(), ptr()
            try:
                self.assertEqual(expand(original, environment, ctypes.byref(expanded), ctypes.byref(unset), ctypes.byref(bad)), 0)
                delivered = [expanded[i].decode() for i in range(len(command))]
                self.assertFalse(expanded[len(command)])
            finally:
                for field in (expanded, unset, bad):
                    free(field)
            command[idx + 1] = g.DEVELOPMENT_TIMED_EXEC
            self.assertEqual(delivered, command)  # Only the fixed script differed in transit.
            result = subprocess.run(['/bin/sh', *delivered[idx:idx + 5],
                                     '/bin/sh', '-c', 'printf fixture-payload'],
                                    capture_output=True, check=False, timeout=3)
            self.assertEqual(result.returncode, 124 if expired else 0)
            self.assertEqual(result.stdout, b'' if expired else b'fixture-payload')

    def reject_float_timeout(self, identity, expected_error):
        original = self.app.engine

        def engine(*args, **kwargs):
            output = original(*args, **kwargs)
            if args == ('inspect', '--type=container', identity):
                rows = json.loads(output)
                if rows:
                    rows[0]['Config']['Timeout'] = float(rows[0]['Config']['Timeout'])
                return json.dumps(rows)
            return output

        self.bounded_engine(160)
        with patch.object(self.app, 'engine', side_effect=engine), self.assertRaisesRegex(g.Blocked, expected_error):
            self.assemble()
        self.assertFalse(self.release.exists())
        self.assertFalse(self.engine.containers)

    def test_assembly_rejects_numerically_equal_noninteger_timeout(self):
        from test_gptbox import STAGE
        self.reject_float_timeout(STAGE, 'native container lifetime')

    def test_snapshot_rejects_numerically_equal_noninteger_timeout(self):
        self.reject_float_timeout(RUNTIME, 'never-started image snapshot')
        self.assertFalse(g.exact_oci_timeout(True, 1, g.RUNTIME_LIFETIME))

    def test_committed_development_graph_exports_a_bound_inner_record_atomically(self):
        self.assertFalse(self.assemble(apply=False)['changes'])
        self.assertFalse(self.release.parent.exists())
        result = self.assemble()
        self.assertFalse(result['job_admission'])
        self.assertFalse(self.engine.containers)
        self.assertFalse(self.app.path(g.STATE + '/gptbox-image.json').exists())
        self.assertFalse(self.app.path('/var/lib/dev-pair/maintenance/images').exists())
        self.assertIn('/image-store', Path(self.app.wrapper).read_text())
        self.assertIn(g.FINAL_HOOK, next(args for args, _ in self.engine.calls if g.FINAL_HOOK in args))
        self.assertEqual(sum('start' in args and '--attach' in args for args, _ in self.engine.calls), 1)
        archive = self.release / g.RELEASE_ARCHIVE
        inner = json.loads((self.release / g.RELEASE_INNER).read_bytes())
        self.assertEqual(inner, {'source_sha': SOURCE, 'image_id': self.engine.sealed_id, 'context_sha256': EXPECTED,
            'inputs_sha256': g.sha((self.engine.build / 'inputs.json').read_bytes()),
            'sealed_sha256': g.sha(self.engine.seal), 'archive_sha256': g.sha(archive.read_bytes()),
            'archive_bytes': archive.stat().st_size, 'diff_ids': self.engine.diffs})
        image_inputs = json.loads((self.engine.build / 'inputs.json').read_bytes())
        self.assertEqual(image_inputs['role'], 'development')
        self.assertEqual(image_inputs['files'][g.RUNTIME], g.sha(Path(g.__file__).with_name('gptbox_runtime.py').read_bytes()))
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o444)
        self.assertTrue(self.assemble()['reused'])
        db.check_archive_image(archive, inner, g.DEVELOPMENT_EXPANSION_LIMIT, g.time.monotonic() + 5)
        self.assertEqual(json.loads(self.publication.read_bytes())['phase'], 'ready')
        archive.chmod(0o644)
        with archive.open('ab') as output:
            output.write(b'x')
        archive.chmod(0o444)
        with self.assertRaises(g.Blocked):
            self.assemble()

    def test_bad_raw_seal_and_corrupt_archive_withhold_publication(self):
        self.engine.bad_seal = True
        with self.assertRaisesRegex(g.Blocked, 'seal bytes differ'):
            self.assemble()
        self.assertFalse(self.release.exists())
        self.assertFalse(self.engine.containers)
        with self.assertRaisesRegex(g.Blocked, 'explicit --retry'):
            self.assemble()
        self.engine.bad_seal = False
        self.engine.bad_archive = True
        with self.assertRaisesRegex(g.Blocked, 'layer blob digest mismatch'):
            self.assemble(retry=True)
        self.assertFalse(self.release.exists())
        self.assertFalse(self.engine.containers)
        with self.assertRaisesRegex(g.Blocked, 'retry budget exhausted'):
            self.assemble(retry=True)
        self.assertFalse(self.release.with_name('release.pending').exists())

    def test_reuse_compares_the_complete_record_with_protected_evidence(self):
        inner = self.assemble()['inner']
        record = self.release / g.RELEASE_INNER
        for key, changed in (('image_id', 'f' * 64), ('inputs_sha256', 'f' * 64),
                             ('sealed_sha256', 'f' * 64), ('diff_ids', list(reversed(inner['diff_ids'])))):
            with self.subTest(key=key):
                record.chmod(0o644)
                record.write_bytes(g.image_inputs_bytes({**inner, key: changed}))
                record.chmod(0o444)
                with self.assertRaisesRegex(g.Blocked, 'differs from protected publication evidence'):
                    self.assemble()
        record.chmod(0o644)
        record.write_bytes(g.image_inputs_bytes(inner))
        record.chmod(0o444)
        self.publication.unlink()
        with self.assertRaisesRegex(g.Blocked, 'exact ready evidence'):
            self.assemble()

    def test_retry_recovers_second_attempt_after_cleanup_and_before_atomic_rename(self):
        self.engine.bad_seal = True
        with self.assertRaises(g.Blocked):
            self.assemble()
        self.engine.bad_seal = False
        record = self.app.record

        def cut_before_ready(name, value):
            if name == 'publication' and value['phase'] == 'ready':
                raise KeyboardInterrupt('synthetic interruption after container cleanup')
            record(name, value)

        with patch.object(self.app, 'record', side_effect=cut_before_ready), self.assertRaises(KeyboardInterrupt):
            self.assemble(retry=True)
        self.assertFalse(self.engine.containers)
        verified = json.loads(self.publication.read_bytes())
        self.assertEqual((verified['phase'], verified['attempt']['count']), ('verified', 2))
        self.assertFalse(self.release.exists())
        with patch.object(g.os, 'rename', side_effect=OSError('synthetic interruption before publication')):
            with self.assertRaisesRegex(OSError, 'interruption before publication'):
                self.assemble(retry=True)
        self.assertEqual(json.loads(self.publication.read_bytes())['phase'], 'ready')
        with patch.object(self.app, 'setup_executor', side_effect=AssertionError('rebuild or cleanup forbidden')):
            result = self.assemble(retry=True)
        self.assertEqual(result['inner'], verified['inner'])
        self.assertTrue(self.release.exists())
        self.assertFalse(self.pending.exists())
        self.assertEqual(sum('commit' in args for args, _ in self.engine.calls), 2)

    def test_foreign_pending_directory_is_preserved(self):
        self.engine.bad_archive = True
        with self.assertRaises(g.Blocked):
            self.assemble()
        self.pending.rename(self.pending.with_name('preserved-owned-copy'))
        self.pending.mkdir(mode=0o700)
        fake = self.pending / g.RELEASE_ARCHIVE
        fake.write_bytes(b'foreign')
        with patch.object(self.app, 'setup_executor', side_effect=AssertionError('foreign work must block before setup')):
            with self.assertRaisesRegex(g.Blocked, 'unowned pending development release'):
                self.assemble(retry=True)
        self.assertEqual(fake.read_bytes(), b'foreign')

    def test_requires_protected_host_readiness_and_live_restricted_identity(self):
        ready = self.host_ready.read_bytes()
        self.host_ready.unlink()
        with patch.object(self.app, 'setup_executor', side_effect=AssertionError('unverified builder must not start')):
            with self.assertRaisesRegex(g.Blocked, 'required protected development evidence is missing'):
                self.assemble()
            self.app.atomic(g.STATE + '/host-ready.json', ready.decode())
            self.engine.groups = 'dp-maint wheel\n'
            with self.assertRaisesRegex(g.Blocked, 'private group'):
                self.assemble()
            self.engine.groups = 'dp-maint\n'
            subordinate = self.app.path('/etc/subgid')
            subordinate.write_text('dp-maint:1000000:65535\n')
            with self.assertRaisesRegex(g.Blocked, 'conflicting subordinate ID'):
                self.assemble()
            subordinate.write_text('dp-maint:1000000:65536\n')
            storage = self.app.path('/var/lib/dev-pair/maintenance')
            storage.chmod(0o755)
            with self.assertRaisesRegex(g.Blocked, 'provisioned maintenance directory owner'):
                self.assemble()
            storage.chmod(0o700)
            self.engine.packages = 'unrecorded package inventory\n'
            with self.assertRaisesRegex(g.Blocked, 'live host package inventory differs'):
                self.assemble()
        self.assertFalse(self.release.parent.exists())

    def test_legacy_maintenance_readiness_and_prepared_marker_allow_different_development_target(self):
        record = json.loads(self.host_ready.read_bytes())
        self.assertNotEqual((record['source_sha'], record['context_sha256']), (SOURCE, EXPECTED))
        with patch.object(self.app, 'setup_executor', side_effect=AssertionError('reached image executor')):
            with self.assertRaisesRegex(AssertionError, 'reached image executor'):
                self.assemble()
            self.host_ready.unlink()
            self.app.atomic(g.STATE + '/prepared', self.app.text(g.STATE + '/desired.json'))
            with self.assertRaisesRegex(AssertionError, 'reached image executor'):
                self.assemble()

    def test_producer_rejects_index_media_type_rejected_by_nested_consumer(self):
        self.engine.bad_index_media = True
        with self.assertRaisesRegex(g.Blocked, 'must select one image'):
            self.assemble()
        self.assertFalse(self.release.exists())

    def test_maintenance_gate_and_development_gate_require_their_own_role(self):
        default = g.Bootstrap(self.root)
        with patch.object(default, 'candidate_tool') as tool:
            tool.return_value._verify_content.return_value = (None, {'role': 'development'})
            with self.assertRaisesRegex(g.Blocked, 'maintenance-role'):
                default.check_gptbox_inputs(self.context, EXPECTED)
            default.check_gptbox_inputs(self.context, EXPECTED, expected_role='development')
            tool.return_value._verify_content.return_value = (None, {'role': 'maintenance'})
            with self.assertRaisesRegex(g.Blocked, 'development-role'):
                default.check_gptbox_inputs(self.context, EXPECTED, expected_role='development')
