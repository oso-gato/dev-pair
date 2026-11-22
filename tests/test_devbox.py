"""Local DevBox contract tests. Fedora confinement needs the native runner."""

from copy import deepcopy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import time
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import devbox
from devbox import db


OUTER = '1' * 64
INNER = '2' * 64
SOURCE = '3' * 40
OWNER = '4' * 64
CHILD = '5' * 64
START = '2026-11-22T20:15:01.123Z'


def manifest():
    return {'kind': 'dev-pair-development-nested-v1', 'standards_sha': db.STANDARDS,
            'job': 'nested-check', 'storage_bytes': db.GIB,
            'outer': {'image_id': OUTER, 'source_sha': SOURCE},
            'inner': {'image_id': INNER, 'source_sha': SOURCE, 'context_sha256': '6' * 64,
                      'inputs_sha256': '7' * 64, 'sealed_sha256': '8' * 64, 'archive_sha256': '9' * 64,
                      'archive_bytes': 800, 'diff_ids': ['sha256:' + 'a' * 64]},
            'categories': {'outer': [10, 11, 12], 'inner': [10, 11]}}


def admission(content):
    return hashlib.sha256(content).hexdigest()


def oci_archive(path, *, variant=False, order=(0, 1), extra_member=None, gzip_layers=True,
                mutated_blob=False, relative_paths=False):
    blobs = {}
    media = db.OCI_MIME

    def add(content, kind):
        key = admission(content)
        blobs['blobs/sha256/' + key] = content
        return {'digest': 'sha256:' + key, 'size': len(content), 'mediaType': media + kind}

    layers, diff_ids = [], []
    for value in (b'first layer', b'second layer'):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo('fixture')
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
        plain = buffer.getvalue()
        diff_ids.append('sha256:' + admission(plain))
        content = gzip.compress(plain, mtime=0) if gzip_layers else plain
        layers.append(add(content, 'layer.v1.tar+gzip' if gzip_layers else 'layer.v1.tar'))
    config = add(json.dumps({'os': 'linux', 'architecture': 'amd64', 'config': {'Variant': variant},
                             'rootfs': {'type': 'layers', 'diff_ids': diff_ids}}).encode(), 'config.v1+json')
    image = add(json.dumps({'schemaVersion': 2, 'mediaType': media + 'manifest.v1+json',
                            'config': config, 'layers': [layers[index] for index in order]}).encode(),
                'manifest.v1+json')
    members = {
        'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
        'index.json': json.dumps({'schemaVersion': 2, 'manifests': [image]}).encode(),
        **blobs,
    }
    if extra_member is not None:
        members[extra_member] = b'unselected payload'
    if mutated_blob:
        name = 'blobs/sha256/' + layers[0]['digest'].removeprefix('sha256:')
        content = members[name]
        members[name] = b'x' + content[1:]
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
        if relative_paths:
            for directory in ('.', './blobs', './blobs/sha256'):
                member = tarfile.TarInfo(directory)
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
        for name, content in members.items():
            member = tarfile.TarInfo('./' + name if relative_paths else name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return {'image_id': config['digest'].removeprefix('sha256:'), 'diff_ids': diff_ids,
            'archive_sha256': admission(path.read_bytes()), 'archive_bytes': path.stat().st_size}


class TestManifest(unittest.TestCase):
    def load(self, content, expected=None):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'manifest.json'
            path.write_bytes(content)
            return db.read_manifest(path, expected or admission(content), time.monotonic() + 2)

    def test_closed_digest_bound_development_manifest(self):
        value = manifest()
        payload = json.dumps(value).encode()
        self.assertEqual(self.load(payload), value)
        with self.assertRaisesRegex(db.Blocked, 'manifest SHA-256 mismatch'):
            self.load(payload, '0' * 64)
        with self.assertRaisesRegex(db.Blocked, 'duplicate'):
            self.load(payload[:-1] + b', "job": "duplicate"}')

    def test_invalid_roles_aliases_fields_categories_and_storage(self):
        invalid = [
            ({'kind': 'maintenance-gptbox-probe-candidate'}, 'placement'),
            ({'job': '../../other'}, 'leaf'),
            ({'storage_bytes': True}, 'ceiling'),
            ({'storage_bytes': 500}, 'archive'),
            ({'outer': {'image_id': INNER, 'source_sha': SOURCE}}, 'differ'),
            ({'categories': {'outer': [10, 11, 12], 'inner': [10, 13]}}, 'subset'),
            ({'categories': {'outer': [10, 11, 12], 'inner': [11, 10]}}, 'SELinux categories'),
            ({'engine_socket': '/var/run/podman/podman.sock'}, 'fields mismatch'),
        ]
        for change, error in invalid:
            with self.subTest(change=change), self.assertRaisesRegex(db.Blocked, error):
                self.load(json.dumps(manifest() | change).encode())

    def test_file_read_rejects_symlinks_directories_and_oversize(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / 'data'
            regular.write_bytes(b'data')
            symlink = root / 'link'
            symlink.symlink_to(regular)
            with self.assertRaises(OSError):
                db.file_hash(symlink, 8, time.monotonic() + 1)
            for path in (regular, root):
                with self.subTest(path=path), self.assertRaisesRegex(db.Blocked, 'bounded regular file'):
                    db.file_hash(path, 3, time.monotonic() + 1)


class TestConfinementContract(unittest.TestCase):
    def test_launch_profiles_are_specific_to_each_layer(self):
        value = manifest()
        for side, lifetime in (('outer', db.OUTER_SECONDS), ('inner', db.INNER_SECONDS)):
            with self.subTest(side=side):
                argv = db.container_args('owned', OWNER, value, side, '/empty')
                self.assertIn('--read-only', argv)
                self.assertIn('--network=none', argv)
                self.assertIn('--pull=never', argv)
                self.assertIn('--timeout=' + str(lifetime), argv)
                self.assertFalse(any(bad in arg for arg in argv
                                     for bad in ('--cap-add', 'SYS_ADMIN', 'SETFCAP', 'label=disable', '--privileged')))
                self.assertFalse(any(arg.startswith('--volume') for arg in argv))
        config = tomllib.loads((devbox.RUNTIME / 'host-containers.conf').read_text())
        self.assertEqual(config['containers']['default_capabilities'], ['CAP_SETUID', 'CAP_SETGID'])
        outer = db.container_args('outer', OWNER, manifest(), 'outer', '/empty')
        self.assertNotIn('--cap-drop=ALL', outer)
        self.assertNotIn('--security-opt=no-new-privileges', outer)
        inner = db.container_args('inner', OWNER, manifest(), 'inner', '/empty')
        self.assertIn('--cap-drop=ALL', inner)
        self.assertIn('--security-opt=no-new-privileges', inner)
        self.assertIn('ro,nosuid,nodev,rprivate,noexec', db.bind('/source', '/admission/file', False))

    def test_actual_controller_observation_requires_bounding_only_capabilities(self):
        value = manifest()
        expected = db.process_label(value, 'outer')
        with TemporaryDirectory() as temporary:
            proc = Path(temporary)
            (proc / 'attr').mkdir()
            (proc / 'attr/current').write_text('system_u:system_r:container_engine_t:s0:c10.c12\n')
            (proc / 'ns').mkdir()
            for namespace in db.NS_NAMES:
                (proc / 'ns' / namespace).symlink_to(namespace + ':[123]')
            (proc / 'cgroup').write_text('0::/\n')
            status = proc / 'status'
            base = 'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t1000\nNoNewPrivs:\t0\nSeccomp:\t2\n'
            status.write_text(base + ''.join(f'{key}:\t{value:x}\n' for key, value in zip(db.CAP_KEYS, db.OUTER_CAPS)))
            self.assertEqual(db.proc_snapshot(proc, db.OUTER_CAPS, 0, expected, 1000, 1000)['label'],
                             'system_u:system_r:container_engine_t:s0:c10.c12')
            status.write_text(base + ''.join(f'{key}:\tc0\n' for key in db.CAP_KEYS))
            with self.assertRaisesRegex(db.Blocked, 'effective capability'):
                db.proc_snapshot(proc, db.OUTER_CAPS, 0, expected, 1000, 1000)

    def test_selinux_mcs_ranges_require_exact_subject_and_categories(self):
        value = manifest()
        outer = db.process_label(value, 'outer')
        self.assertTrue(db.same_label('system_u:system_r:container_engine_t:s0:c10.c12', outer))
        self.assertTrue(db.same_label('system_u:system_r:container_engine_t:s0:c10.c11,c12', outer))
        for label in (
                'unconfined_u:system_r:container_engine_t:s0:c10.c12',
                'system_u:object_r:container_engine_t:s0:c10.c12',
                'system_u:system_r:container_t:s0:c10.c12',
                'system_u:system_r:container_engine_t:s0:c10.c13',
                'system_u:system_r:container_engine_t:s0:c10,c12',
                'system_u:system_r:container_engine_t:s0:c10.c12,c11',
                'system_u:system_r:container_engine_t:s0:c12.c10',
                'system_u:system_r:container_engine_t:s0:c10x12',
                'system_u:system_r:container_engine_t:s0-s0:c10.c12'):
            with self.subTest(label=label):
                self.assertFalse(db.same_label(label, outer))
        with patch.object(devbox.os, 'getxattr', return_value=b'system_u:object_r:container_file_t:s0:c10.c12\0'):
            devbox.check_label(Path('/fixture'), db.file_label(value, 'outer'))

    def test_nested_engine_checks_effective_image_copy_directory(self):
        config = tomllib.loads((devbox.RUNTIME / 'containers.conf').read_text())
        self.assertEqual(config['engine']['image_copy_tmp_dir'], db.IMAGE_COPY_DIR)
        self.assertEqual(db.inner_environment()['TMPDIR'], db.IMAGE_COPY_DIR)
        info = {'host': {'security': {'rootless': True, 'selinuxEnabled': True}},
                'store': {'graphDriverName': 'vfs', 'graphRoot': db.GRAPHROOT, 'runRoot': db.RUNROOT,
                          'imageCopyTmpDir': db.IMAGE_COPY_DIR}}
        db.check_engine_info(info)
        info['store']['imageCopyTmpDir'] = '/var/tmp'
        with self.assertRaisesRegex(db.Blocked, 'image import temporary directory'):
            db.check_engine_info(info)

    def test_image_copy_directory_is_a_separate_approved_parent_mount(self):
        value = manifest()
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with TemporaryDirectory() as temporary, patch.object(devbox, 'ROOT', Path(temporary)):
            root = devbox.ROOT
            job = value['job']
            build = root / 'builds' / job
            for directory in (build, build / 'graph', build / 'image-copy', build / 'inputs',
                              *(root / area / job for area in db.JOB_TARGETS)):
                directory.mkdir(mode=0o700, parents=True)
            admission_path = build / 'inputs' / 'manifest.json'
            archive_path = build / 'inputs' / 'development.oci.tar'
            for path, payload in ((admission_path, b'fixture'), (archive_path, b'z' * value['inner']['archive_bytes'])):
                path.write_bytes(payload)
                path.chmod(0o444)
            with patch.object(devbox, 'storage_mount', return_value={'bytes': db.GIB}), patch.object(devbox, 'check_label'):
                mounts, _ = devbox.placement(account, value, admission_path)
                self.assertEqual(mounts[db.IMAGE_COPY_DIR], (str(build / 'image-copy'), True))
                self.assertNotIn(db.IMAGE_COPY_DIR, db.JOB_TARGETS.values())
                (build / 'image-copy').rmdir()
                (build / 'image-copy').symlink_to(build / 'graph')
                with self.assertRaisesRegex(db.Blocked, 'symlink in image-copy'):
                    devbox.placement(account, value, admission_path)

    def test_composed_uid_mapping_excludes_ancestor_root(self):
        outer = '0 1065536 1000\n1000 1450 1\n1001 1066536 64536\n'
        inner = '0 1 999\n999 1001 1\n1000 1000 1\n1001 1002 64535\n'
        self.assertEqual(db.ids(outer, devbox.DP_DEV_SUBORDINATES, 1450)[1], (1000, 1450, 1))
        self.assertEqual(db.ids(inner, [(1, 999), (1001, 64536)], 1000)[2], (1000, 1000, 1))
        with self.assertRaisesRegex(db.Blocked, 'ancestor root'):
            db.ids(inner.replace('0 1 999', '0 0 999'), [(1, 999), (1001, 64536)], 1000)
        with self.assertRaisesRegex(db.Blocked, 'overlap'):
            db.ids(inner.replace('1001 1002 64535', '1000 1002 64535'), [(1, 999), (1001, 64536)], 1000)
        with self.assertRaisesRegex(db.Blocked, 'composition'):
            db.ids(inner.replace('64535', '64534'), [(1, 999), (1001, 64536)], 1000)

    def test_inspection_rejects_unexpected_child_binds_or_confinement_exceptions(self):
        value = manifest()
        mounts = {'/work/job': ('/devbox/job/workspaces', True)}
        row = {'Id': CHILD, 'Image': INNER, 'EffectiveCaps': [], 'BoundingCaps': [],
               'ProcessLabel': 'system_u:system_r:container_t:s0:c10.c11',
               'MountLabel': 'system_u:object_r:container_file_t:s0:c10.c11',
               'Config': {'Labels': {'dev-pair.devbox-owner': OWNER, 'manager': 'distrobox'},
                          'Timeout': db.INNER_SECONDS, 'User': '1000:1000'},
               'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
                              'PidMode': 'private', 'IpcMode': 'private', 'UTSMode': 'private',
                              'UsernsMode': 'keep-id', 'Cgroups': 'disabled',
                              'Tmpfs': {'/run': 'test', '/tmp': 'test'}},
               'Mounts': [{'Type': 'bind', 'Source': '/devbox/job/workspaces', 'Destination': '/work/job',
                           'RW': True}]}
        db.inspect_policy(row, CHILD, OWNER, value, 'inner', mounts)
        altered = deepcopy(row)
        altered['Mounts'].append({'Type': 'bind', 'Source': '/var/run/podman/podman.sock',
                                  'Destination': '/run/host.sock', 'RW': True})
        with self.assertRaisesRegex(db.Blocked, 'bind allowlist'):
            db.inspect_policy(altered, CHILD, OWNER, value, 'inner', mounts)
        altered = deepcopy(row)
        altered['HostConfig']['SecurityOpt'] = ['label=disable']
        with self.assertRaisesRegex(db.Blocked, 'confinement exception'):
            db.inspect_policy(altered, CHILD, OWNER, value, 'inner', mounts)

    def test_effective_mount_flags_detect_writable_root_or_cgroup(self):
        content = '''28 1 0:11 / / ro,relatime - vfs root rw
49 28 0:12 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw
50 28 0:13 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw
51 28 0:9 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup rw
52 28 0:15 / /work/job rw,nosuid,nodev,noexec - ext4 tmp rw
'''
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'mountinfo'
            path.write_text(content)
            db.observed_mounts(root, {'/work/job': True})
            for original, replacement, failure in (
                    (' / ro,', ' / rw,', 'root filesystem'),
                    ('cgroup ro,', 'cgroup rw,', 'cgroup filesystem'),
                    ('job rw,nosuid,nodev,noexec', 'job rw,nosuid,nodev', 'effective mount flags')):
                with self.subTest(failure=failure):
                    path.write_text(content.replace(original, replacement))
                    with self.assertRaisesRegex(db.Blocked, failure):
                        db.observed_mounts(root, {'/work/job': True})

    def test_development_seal_cannot_reuse_maintenance_identity(self):
        for role in ('development', 'maintenance'):
            with self.subTest(role=role):
                inputs = json.dumps({'role': role, 'source_sha': SOURCE}).encode()
                sealed = json.dumps({'kind': 'genuine-distrobox-assembled', 'source_sha': SOURCE,
                                     'inputs_sha256': admission(inputs), 'uid': 1000, 'gid': 1000}).encode()
                release = manifest()['inner'] | {'inputs_sha256': admission(inputs), 'sealed_sha256': admission(sealed)}

                def engine(_stage, *_args):
                    return 0, inputs if _args[-1].endswith('/inputs.json') else sealed

                if role == 'development':
                    db.check_inner_inputs(engine, CHILD, release)
                else:
                    with self.assertRaisesRegex(db.Blocked, 'development-role'):
                        db.check_inner_inputs(engine, CHILD, release)


class FakeEngine:
    command = ()
    env = {}

    def __init__(self, row=None):
        self.deadline = time.monotonic() + 20
        self.row = row
        self.removals = []
        self.collision_after_create = False

    def __call__(self, stage, *args, **_options):
        if args[:2] == ('container', 'exists'):
            return (0 if self.row else 1), b''
        if args[0] == 'rm':
            self.removals.append(args[-1])
            self.row = None
            return 0, b''
        if args[0] == 'create':
            self.row = {'Name': 'dp-devbox-' + OWNER[:24], 'Image': OUTER, 'Id': CHILD,
                        'Config': {'Labels': {'dev-pair.devbox-owner': 'foreign' if self.collision_after_create else OWNER}}}
            raise db.Blocked(f'{stage}: partial create')
        raise AssertionError(args)

    def inspect(self, _kind, _name):
        return self.row


class TestOwnedLifecycle(unittest.TestCase):
    def test_failed_create_reconciles_only_exact_ID(self):
        engine = FakeEngine()
        with patch.object(db, 'Engine', return_value=engine):
            with self.assertRaisesRegex(db.Blocked, 'create confined DevBox: partial create'):
                devbox.launch(engine, manifest(), '2' * 64, None, OWNER, '/empty', {})
        self.assertEqual(engine.removals, [CHILD])

    def test_cleanup_reports_original_failure_and_preserves_foreign_id(self):
        engine = FakeEngine()
        engine.collision_after_create = True
        with patch.object(db, 'Engine', return_value=engine):
            with self.assertRaisesRegex(db.Blocked, 'partial create; owned container cleanup unresolved'):
                devbox.launch(engine, manifest(), '2' * 64, None, OWNER, '/empty', {})
        self.assertEqual(engine.removals, [])
        self.assertIsNotNone(engine.row)

    def test_real_lease_refuses_second_invocation_and_preserves_admission_binding(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with TemporaryDirectory() as temporary, patch.object(devbox, 'ROOT', Path(temporary)):
            (devbox.ROOT / 'evidence').mkdir(mode=0o700)
            with devbox.ownership(account, 'job', '2' * 64) as (original, _):
                with self.assertRaisesRegex(db.Blocked, 'in use'), devbox.ownership(account, 'job', '2' * 64):
                    self.fail('duplicate invocation got the lease')
            with devbox.ownership(account, 'job', '2' * 64) as (recovered, _):
                self.assertEqual(original, recovered)
            with self.assertRaisesRegex(db.Blocked, 'another admission'), devbox.ownership(account, 'job', '3' * 64):
                self.fail('lease unexpectedly rebound to new input')


class TestExecution(unittest.TestCase):
    def test_real_subprocess_output_deadline_bound_and_sanitized_failure(self):
        arguments = [sys.executable, '-I', '-c']
        now = time.monotonic() + 8
        env = db.local_env()
        self.assertEqual(db.bounded([*arguments, 'print("fixed")'], now, env=env), (0, b'fixed\n'))
        with self.assertRaisesRegex(db.Blocked, 'command exit 3.*detail'):
            db.bounded([*arguments, 'import sys; sys.stderr.write("detail\\n"); sys.exit(3)'], now, env=env)
        with self.assertRaisesRegex(db.Blocked, 'output limit'):
            db.bounded([*arguments, 'print("a" * 1200000)'], now, env=env)
        with self.assertRaisesRegex(db.Blocked, 'timed out'):
            db.bounded([*arguments, 'import time; time.sleep(10)'], now, env=env, seconds=0.1)

    def test_real_enter_wrapper_blocks_stock_autocreate_and_autostart(self):
        wrapper = devbox.RUNTIME / 'enter-podman'
        for action in ('create', 'start', '--remote=true'):
            with self.subTest(action=action):
                completed = subprocess.run(['/bin/sh', wrapper, action], capture_output=True, timeout=2, check=False)
                self.assertEqual(completed.returncode, 64)

    def test_readiness_rejects_preexisting_marker_after_restart(self):
        engine = FakeEngine({'State': {'Running': True, 'StartedAt': START}})
        with self.assertRaisesRegex(db.Blocked, 'changed identity before readiness'):
            db.ready(engine, CHILD, lambda _row: None, START)


class TestDevelopmentArchive(unittest.TestCase):
    def cached_engine(self, value):
        release = value['inner']
        row = {'Id': release['image_id'], 'Os': 'linux', 'Architecture': 'amd64',
               'RootFS': {'Layers': release['diff_ids']},
               'Labels': {'dev-pair.role': 'development', 'dev-pair.standards': db.STANDARDS,
                          'dev-pair.distrobox': db.DISTROBOX, 'org.opencontainers.image.revision': release['source_sha'],
                          'dev-pair.context': release['context_sha256'], 'dev-pair.inputs': release['inputs_sha256'],
                          'dev-pair.codex.version': db.CODEX_VERSION}}

        class ExistingStore:
            def __init__(self):
                self.deadline = time.monotonic() + 5
                self.loads = []
                self.inspections = []

            def inspect(self, kind, identity):
                self.inspections.append((kind, identity))
                return row

            def __call__(self, _stage, *args, **_kwargs):
                self.loads.append(args)
                return 0, b''

        return ExistingStore()

    def test_validated_oci_archive_reaches_import_and_exact_image_inspection(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.tar'
            for use_gzip in (True, False):
                with self.subTest(gzip=use_gzip):
                    value = manifest()
                    value['inner'].update(oci_archive(path, gzip_layers=use_gzip, relative_paths=use_gzip))
                    engine = self.cached_engine(value)
                    db.load_development_archive(engine, value, path)
                    self.assertEqual(engine.loads, [('load', '--input', str(path))])
                    self.assertEqual(engine.inspections, [('image', value['inner']['image_id'])])

    def test_cached_expected_image_cannot_mask_selected_archive_mismatch(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.tar'
            valid = oci_archive(path)
            for errors, message in (({'variant': True}, 'config identity mismatch'),
                                    ({'order': (1, 0)}, 'ordered layer DiffID mismatch'),
                                    ({'mutated_blob': True}, 'layer blob digest mismatch'),
                                    ({'extra_member': 'blobs/sha256/' + '0' * 64}, 'unselected blobs'),
                                    ({'extra_member': '/index.json'}, 'unsupported development archive member')):
                with self.subTest(errors=errors):
                    actual = oci_archive(path, **errors)
                    value = manifest()
                    value['inner'].update(valid | {'archive_sha256': actual['archive_sha256'],
                                                  'archive_bytes': actual['archive_bytes']})
                    engine = self.cached_engine(value)
                    self.assertEqual(engine.inspect('image', value['inner']['image_id'])['Id'], valid['image_id'])
                    engine.inspections.clear()
                    with self.assertRaisesRegex(db.Blocked, message):
                        db.load_development_archive(engine, value, path)
                    self.assertEqual(engine.loads, [])
                    self.assertEqual(engine.inspections, [])

    def test_expanded_layers_fit_the_same_dedicated_storage_bound(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.tar'
            value = manifest()
            value['inner'].update(oci_archive(path))
            value['storage_bytes'] = 13000
            engine = self.cached_engine(value)
            with self.assertRaisesRegex(db.Blocked, 'expanded layer budget'):
                db.load_development_archive(engine, value, path)
            self.assertEqual(engine.loads, [])


if __name__ == '__main__':
    unittest.main()
