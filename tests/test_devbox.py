"""Local DevBox contract tests. Fedora confinement needs the native runner."""

from copy import deepcopy
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
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
import job_protocol


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


def configured_command(side):
    if side == 'outer':
        return ['/usr/bin/sleep', '600']
    return ['/usr/bin/distrobox-init', '--name', 'gpt', '--user', '1000', '--group', '1000', '--home', '/home/gpt',
            '--init', '0', '--pre-init-hooks', 'exec /usr/bin/python3 -I /usr/lib/dev-pair/gptbox/runtime.py frozen']


def configured_container(side, mounts):
    value = manifest()
    path, *args = configured_command(side)
    outer = side == 'outer'
    labels = {'dev-pair.devbox-owner': OWNER}
    host = {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none', 'PidMode': 'private',
            'IpcMode': 'private', 'UTSMode': 'private', 'UsernsMode': 'keep-id'}
    if outer:
        host.update(CgroupMode='private', Memory=2 * db.GIB, PidsLimit=512, NanoCpus=1000000000)
    else:
        host['Cgroups'] = 'disabled'
        labels['manager'] = 'distrobox'
    host['Tmpfs'] = dict.fromkeys(('/run', '/tmp'), f'rw,nosuid,nodev,noexec,U,mode=0700,size={64 if outer else 16}m,rprivate')
    return {'Id': CHILD, 'Image': value[side]['image_id'], 'Name': ('dp-devbox-' if outer else 'dp-nested-') + OWNER[:24],
            'Path': path, 'Args': args, 'EffectiveCaps': [], 'BoundingCaps': sorted(db.OUTER_BOUNDING) if outer else [],
            'ProcessLabel': db.process_label(value, side), 'MountLabel': db.file_label(value, side),
            'Config': {'Labels': labels, 'Timeout': 600 if outer else 180, 'User': '1000:1000',
                       'Entrypoint': [path], 'Cmd': args.copy()}, 'HostConfig': host,
            'Mounts': [{'Type': 'bind', 'Destination': target, 'Source': source, 'RW': writable}
                       for target, (source, writable) in mounts.items()]}


def admission(content):
    return hashlib.sha256(content).hexdigest()


def oci_archive(path, *, variant=False, order=(0, 1), extra_member=None, gzip_layers=True,
                mutated_blob=False, relative_paths=False, transform=None):
    blobs = {}
    media = db.OCI_MIME

    def add(content, kind):
        key = admission(content)
        blobs['blobs/sha256/' + key] = content
        return {'digest': 'sha256:' + key, 'size': len(content), 'mediaType': media + kind}

    def checked_fixture(kind, value):
        if transform is not None:
            transform(kind, value)
        return value

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
    config_data = checked_fixture('image config', {
        'os': 'linux', 'architecture': 'amd64',
        'config': checked_fixture('runtime config', {'Labels': {'fixture.Variant': 'literal', 'fixture.variant': str(variant)}}),
        'rootfs': checked_fixture('rootfs', {'type': 'layers', 'diff_ids': diff_ids}),
        'history': [checked_fixture('history entry', {'created_by': 'fixture'})],
    })
    config = add(json.dumps(config_data).encode(), 'config.v1+json')
    image_data = checked_fixture('manifest', {'schemaVersion': 2, 'mediaType': media + 'manifest.v1+json',
                                             'config': config, 'layers': [layers[index] for index in order]})
    image = add(json.dumps(image_data).encode(), 'manifest.v1+json')
    image['platform'] = checked_fixture('descriptor platform', {'architecture': 'amd64', 'os': 'linux'})
    index = checked_fixture('index', {'schemaVersion': 2, 'manifests': [checked_fixture('descriptor', image)],
                                      'annotations': {'fixture.Name': 'first', 'fixture.name': 'second'}})
    members = {
        'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
        'index.json': json.dumps(index).encode(),
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

    def test_access_probe_cli_selects_actual_immutable_inputs_and_separate_data(self):
        value = manifest()
        raw = json.dumps(value).encode()
        reference = admission(raw)
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / 'development'
            build = root / 'builds' / value['job']
            inputs = build / 'inputs' / reference
            inputs.mkdir(parents=True)
            build.chmod(0o700)
            path = inputs / 'manifest.json'
            path.write_bytes(raw)
            archive = inputs / 'development.oci.tar'
            archive.write_bytes(b'x' * value['inner']['archive_bytes'])
            for leaf in (path, archive):
                leaf.chmod(0o444)
            probe = devbox.access_probe_root(build, reference)
            probe.mkdir(mode=0o755)
            for name in ('graph', 'image-copy', 'empty-hooks', *db.JOB_TARGETS):
                (probe / name).mkdir(mode=0o700)
            live = root / 'state' / value['job']
            live.mkdir(parents=True)
            (live / 'prior.json').write_text('retained live data')
            (probe / 'state' / 'interrupted').write_text('owned probe scratch')
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            args = ['devbox.py', 'run', '--manifest', str(path), '--sha256', reference,
                    '--access-probe', '--probe-codex-version', '0.170.0']

            def execute(_engine, selected, selected_digest, _account, owner, hooks, mounts, *, probe_version):
                self.assertEqual((selected, selected_digest, owner, hooks, probe_version),
                                 (value, reference, OWNER, probe / 'empty-hooks', '0.170.0'))
                self.assertEqual(mounts[db.MANIFEST], (str(path), False))
                self.assertEqual(mounts[db.ARCHIVE], (str(archive), False))
                self.assertEqual(mounts[db.GRAPHROOT], (str(probe / 'graph'), True))
                for name in db.JOB_TARGETS:
                    self.assertEqual(mounts[f'{db.PARENT_JOB}/{name}'], (str(probe / name), True))
                    self.assertEqual(list((probe / name).iterdir()), [])
                return {'job_admission': False}

            with (patch.object(sys, 'argv', args), patch.object(devbox, 'ROOT', root),
                  patch.object(devbox.signal, 'signal'), patch.object(devbox, 'host_account', return_value=account),
                  patch.object(devbox, 'enforcing'), patch.object(devbox, 'host_env'),
                  patch.object(devbox, 'check_label'), patch.object(devbox, 'probe_owner', return_value=OWNER),
                  patch.object(devbox, 'storage_mount', return_value={'device': 'fixture'}),
                  patch.object(db, 'immutable_image'), patch.object(db, 'remove_owned') as remove,
                  patch.object(devbox, 'launch', side_effect=execute),
                  redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as error):
                self.assertEqual(devbox.main(), 0, error.getvalue())
                remove.assert_called_once()
                self.assertIs(json.loads(output.getvalue())['job_admission'], False)
                args[args.index('--sha256') + 1] = '7' * 64
                self.assertEqual(devbox.main(), 2)
                self.assertIn('manifest SHA-256 mismatch', error.getvalue())
                args[args.index('--sha256') + 1] = reference
                args[-3:] = ['--operation', 'approved-turn', '--request-sha256', '8' * 64]
                with patch.object(job_protocol, 'require_workload_access', side_effect=ValueError('workload review is pending')):
                    self.assertEqual(devbox.main(), 2)
                self.assertIn('workload review is pending', error.getvalue())
                with (patch.object(job_protocol, 'require_workload_access', side_effect=[None, ValueError('access withdrawn')]),
                      patch.object(job_protocol, 'workload_access_lease', return_value=nullcontext()) as lease):
                    self.assertEqual(devbox.main(), 2)
                lease.assert_called_once_with(root.parent)
                self.assertIn('access withdrawn', error.getvalue())
                remove.assert_called_once()
            self.assertEqual((live / 'prior.json').read_text(), 'retained live data')

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
                self.assertIn('--no-hosts', argv)
                self.assertIn('--no-hostname', argv)
                self.assertFalse(any(option.startswith('--dns') for option in argv))
                self.assertIn('--pull=never', argv)
                self.assertIn('--timeout=' + str(lifetime), argv)
                self.assertFalse(any(bad in arg for arg in argv
                                     for bad in ('--cap-add', 'SYS_ADMIN', 'SETFCAP', 'label=disable', '--privileged')))
                self.assertFalse(any(arg.startswith('--volume') for arg in argv))
                size = 64 if side == 'outer' else 16
                self.assertEqual([arg for arg in argv if arg.startswith(('--mount=', '--tmpfs='))],
                                 [f'--mount=type=tmpfs,destination={path},rw,nosuid,nodev,noexec,U,'
                                  f'tmpfs-mode=0700,tmpfs-size={size}m,notmpcopyup' for path in ('/run', '/tmp')])
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
            label = 'system_u:system_r:container_engine_t:s0:c10.c12'
            (proc / 'attr/current').write_text(label + '\x00')
            (proc / 'ns').mkdir()
            for namespace in db.NS_NAMES:
                (proc / 'ns' / namespace).symlink_to(namespace + ':[123]')
            (proc / 'cgroup').write_text('0::/\n')
            status = proc / 'status'
            base = 'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t1000\nNoNewPrivs:\t0\nSeccomp:\t2\n'
            status.write_text(base + ''.join(f'{key}:\t{value:x}\n' for key, value in zip(db.CAP_KEYS, db.OUTER_CAPS)))
            self.assertEqual(db.proc_snapshot(proc, db.OUTER_CAPS, 0, expected, 1000, 1000)['label'], label + '\x00')
            (proc / 'attr/current').write_text(label + '\x00\x00')
            with self.assertRaisesRegex(db.Blocked, 'effective SELinux process label'):
                db.proc_snapshot(proc, db.OUTER_CAPS, 0, expected, 1000, 1000)
            (proc / 'attr/current').write_text(label + '\n')
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
        with patch.object(devbox.os, 'getxattr', return_value=b'system_u:object_r:container_file_t:s0:c10.c12\0\0'):
            with self.assertRaisesRegex(db.Blocked, 'SELinux volume label'):
                devbox.check_label(Path('/fixture'), db.file_label(value, 'outer'))

    def test_probe_receipt_accepts_one_terminal_nul_from_proc_attr(self):
        value = manifest()
        label = 'system_u:system_r:container_t:s0:c10.c11'
        cycle = {'version': f'codex-cli {db.CODEX_VERSION}', 'started_at': START,
                 'proc': {'label': label}, 'probe': {'boundary_probe': 'passed', 'selinux_label': label + '\x00'}}
        receipt = {'kind': 'dev-pair-devbox-probe-v1', 'manifest_sha256': OUTER, 'owner': OWNER,
                   'inner_container_id': CHILD, 'inner_image_id': INNER, 'job_admission': False,
                   'inner_removed': True, 'cycles': [cycle | {'started_at': 'later'}, cycle]}
        decoded = db.json_data(json.dumps(receipt).encode())
        devbox.validate_result(decoded, OUTER, OWNER, value)
        for invalid in (label + '\x00\x00', label.replace('container_t', 'container\x00_t'),
                        label.replace('c10.c11', 'c10.c12') + '\x00'):
            with self.subTest(invalid=invalid):
                decoded['cycles'][0]['probe']['selinux_label'] = invalid
                with self.assertRaisesRegex(db.Blocked, 'nested probe evidence mismatch'):
                    devbox.validate_result(decoded, OUTER, OWNER, value)

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
                              'Tmpfs': dict.fromkeys(('/run', '/tmp'), 'rw,nosuid,nodev,noexec,U,mode=0700,size=16m,rprivate')},
               'Mounts': [{'Type': 'bind', 'Source': '/devbox/job/workspaces', 'Destination': '/work/job',
                           'RW': True}]}
        path, *args = configured_command('inner')
        row.update(Path=path, Args=args)
        row['Config'].update(Entrypoint=[path], Cmd=args.copy())
        db.inspect_policy(row, CHILD, OWNER, value, 'inner', mounts)
        db.inspect_policy({**row, 'EffectiveCaps': None, 'BoundingCaps': None}, CHILD, OWNER, value, 'inner', mounts)
        running = deepcopy(row)
        running['State'] = {'Running': True}
        with self.assertRaisesRegex(db.Blocked, 'temporary mount options'):
            db.inspect_policy(running, CHILD, OWNER, value, 'inner', mounts)
        running['HostConfig']['Tmpfs'] = {path: spec.replace(',U,', ',uid=1000,gid=1000,')
                                          for path, spec in running['HostConfig']['Tmpfs'].items()}
        db.inspect_policy(running, CHILD, OWNER, value, 'inner', mounts)
        options = running['HostConfig']['Tmpfs']['/run']
        for old, new in (('16m', '64m'), ('0700', '0777'), ('noexec,', ''), ('gid=1000', 'gid=0')):
            with self.subTest(option=old), self.assertRaisesRegex(db.Blocked, 'temporary mount options'):
                running['HostConfig']['Tmpfs']['/run'] = options.replace(old, new)
                db.inspect_policy(running, CHILD, OWNER, value, 'inner', mounts)
        altered = deepcopy(row)
        altered['Mounts'].append({'Type': 'bind', 'Source': '/var/run/podman/podman.sock',
                                  'Destination': '/run/host.sock', 'RW': True})
        with self.assertRaisesRegex(db.Blocked, 'bind allowlist'):
            db.inspect_policy(altered, CHILD, OWNER, value, 'inner', mounts)
        altered = deepcopy(row)
        altered['HostConfig']['SecurityOpt'] = ['label=disable']
        with self.assertRaisesRegex(db.Blocked, 'confinement exception'):
            db.inspect_policy(altered, CHILD, OWNER, value, 'inner', mounts)
        for field in ('Dns', 'DnsOptions', 'DnsSearch'):
            altered = deepcopy(row)
            altered['HostConfig'][field] = ['unexpected']
            with self.subTest(field=field), self.assertRaisesRegex(db.Blocked, 'engine-managed resolver'):
                db.inspect_policy(altered, CHILD, OWNER, value, 'inner', mounts)
        with self.assertRaisesRegex(db.Blocked, 'engine-managed resolver'):
            db.inspect_policy({**row, 'ResolvConfPath': '/unexpected/resolver'}, CHILD, OWNER, value, 'inner', mounts)

    def test_configured_command_requires_all_four_exact_inspect_fields(self):
        for side in ('outer', 'inner'):
            row = configured_container(side, {})
            db.inspect_policy(row, CHILD, OWNER, manifest(), side, {})
            for field, wrong in (('Path', '/usr/bin/false'), ('Args', ['unexpected']),
                                 ('Entrypoint', ['/usr/bin/false']), ('Cmd', ['unexpected'])):
                for substitution in ('missing', 'value', 'type'):
                    with self.subTest(side=side, field=field, substitution=substitution):
                        altered = deepcopy(row)
                        parent = altered if field in ('Path', 'Args') else altered['Config']
                        if substitution == 'missing':
                            del parent[field]
                        else:
                            parent[field] = wrong if substitution == 'value' else {'unexpected': field}
                        with self.assertRaisesRegex(db.Blocked, side + ' configured command'):
                            db.inspect_policy(altered, CHILD, OWNER, manifest(), side, {})

            alternate = deepcopy(row)
            alternate.update(Path='/usr/bin/false', Args=[])
            alternate['Config'].update(Entrypoint=['/usr/bin/false'], Cmd=[])
            with self.assertRaisesRegex(db.Blocked, side + ' configured command'):
                db.inspect_policy(alternate, CHILD, OWNER, manifest(), side, {})

        outer = configured_container('outer', {})
        outer['Mounts'].append({'Type': 'bind', 'Source': '/sys/fs/selinux', 'Destination': '/sys/fs/selinux', 'RW': True})
        with self.assertRaisesRegex(db.Blocked, 'outer bind allowlist mismatch'):
            db.inspect_policy(outer, CHILD, OWNER, manifest(), 'outer', {})

    def test_effective_mount_flags_detect_writable_root_or_cgroup(self):
        content = '''28 1 0:11 / / ro,relatime - vfs root rw
49 28 0:12 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw
50 28 0:13 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw
51 28 0:9 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup rw
52 28 0:15 / /work/job rw,nosuid,nodev,noexec - ext4 tmp rw
'''
        space = SimpleNamespace(f_frsize=4096, f_blocks=4096)
        with TemporaryDirectory() as temporary, patch.object(db.os, 'statvfs', return_value=space):
            root = Path(temporary)
            path = root / 'mountinfo'
            (root / 'root/etc').mkdir(parents=True)
            for leaf in ('run', 'tmp'):
                (root / 'root' / leaf).mkdir(mode=0o700)
            path.write_text(content)
            owner = (os.getuid(), os.getgid())
            db.observed_mounts(root, {'/work/job': True}, scratch_owner=owner)
            with self.assertRaisesRegex(db.Blocked, 'byte ceiling'):
                db.observed_mounts(root, {'/work/job': True}, scratch_mib=64, scratch_owner=owner)
            (root / 'root/tmp').chmod(0o777)
            with self.assertRaisesRegex(db.Blocked, 'mode'):
                db.observed_mounts(root, {'/work/job': True}, scratch_owner=owner)
            (root / 'root/tmp').chmod(0o700)
            with self.assertRaisesRegex(db.Blocked, 'ownership'):
                db.observed_mounts(root, {'/work/job': True}, scratch_owner=(owner[0] + 1, owner[1]))
            for target in ('/etc/hostname', '/etc/hosts', '/etc/resolv.conf'):
                path.write_text(content + f'53 28 0:16 / {target} ro,nosuid,nodev,noexec - ext4 tmp rw\n')
                with self.subTest(target=target), self.assertRaisesRegex(db.Blocked, 'network configuration mount'):
                    db.observed_mounts(root, {'/work/job': True}, scratch_owner=owner)
            path.write_text(content)
            resolver = root / 'root/etc/resolv.conf'
            resolver.symlink_to('/run/writable-resolver')
            with self.assertRaisesRegex(db.Blocked, 'must be an image-owned read-only file'):
                db.observed_mounts(root, {'/work/job': True}, scratch_owner=owner)
            resolver.unlink()
            for original, replacement, failure in (
                    (' / ro,', ' / rw,', 'root filesystem'),
                    ('cgroup ro,', 'cgroup rw,', 'cgroup filesystem'),
                    ('/tmp rw,nosuid,nodev,noexec', '/tmp rw,nosuid,nodev', 'unsafe effective temporary mount'),
                    ('job rw,nosuid,nodev,noexec', 'job rw,nosuid,nodev', 'effective mount flags')):
                with self.subTest(failure=failure):
                    path.write_text(content.replace(original, replacement))
                    with self.assertRaisesRegex(db.Blocked, failure):
                        db.observed_mounts(root, {'/work/job': True}, scratch_owner=owner)

    def test_live_nested_interfaces_are_loopback_only(self):
        with TemporaryDirectory() as temporary:
            proc = Path(temporary)
            (proc / 'net').mkdir()
            interfaces = proc / 'net/dev'
            healthy = 'Inter-| Receive | Transmit\n face | bytes   | bytes\n    lo: 0 0\n'
            interfaces.write_text(healthy)
            db.offline_interfaces(proc)
            interfaces.write_text(healthy + '  eth0: 0 0\n')
            with self.assertRaisesRegex(db.Blocked, 'only loopback'):
                db.offline_interfaces(proc)

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


class ConfiguredEngine(FakeEngine):
    def __init__(self, configured):
        super().__init__()
        self.configured = configured
        self.created = None
        self.starts = []
        self.inspections = []

    def __call__(self, stage, *args, **options):
        if args[0] == 'info':
            return 0, b'{}'
        if args[0] == 'unshare':
            return 0, b'0 1000 1\n1 1 999\n1000 1001 64536\n' * 2
        if args[0] == 'create':
            self.created = args
            self.row = deepcopy(self.configured)
            return 0, CHILD.encode()
        if args[0] == 'start':
            self.starts.append(args[-1])
            raise db.Blocked('fixture reached the start boundary')
        return super().__call__(stage, *args, **options)

    def inspect(self, kind, identity):
        self.inspections.append((kind, identity))
        return super().inspect(kind, identity)


class TestOwnedLifecycle(unittest.TestCase):
    def project_inner_environment(self, context):
        context.enter_context(patch.multiple(db, read_manifest=lambda *_: manifest(),
            proc_snapshot=lambda *_: {}, offline_interfaces=lambda *_: None, observed_mounts=lambda *_, **__: None,
            probe_parent_writes=lambda: None, helper_caps=lambda: None, check_engine_info=lambda *_: None,
            load_development_archive=lambda *_, **__: '0.169.1',
            file_hash=lambda path, *_, **__: (db.ENTER_SHA256 if path.name == 'distrobox-enter' else INNER, 0, None)))
        context.enter_context(patch.multiple(db.os, getuid=lambda: 1000, getgid=lambda: 1000, getgroups=lambda: [1000]))
        context.enter_context(patch.object(Path, 'mkdir'))
        context.enter_context(patch.object(Path, 'exists', return_value=False))

    def assert_configured_launch(self, engine, side, invoke, *, accepted):
        with patch.object(db, 'Engine', return_value=engine):
            reason = 'fixture reached the start boundary' if accepted else side + ' configured command'
            with self.assertRaisesRegex(db.Blocked, reason):
                invoke()
        path, *arguments = configured_command(side)
        expected = (f'--entrypoint={path}', manifest()[side]['image_id'], *arguments)
        self.assertEqual(engine.created[-len(expected):], expected)
        self.assertEqual(engine.inspections[0], ('container', CHILD))
        self.assertEqual(engine.starts, [CHILD] if accepted else [])
        self.assertEqual(engine.removals, [CHILD])
        self.assertIsNone(engine.row)

    def test_outer_launcher_checks_realized_command_before_start_in_all_modes(self):
        for options in ({}, {'probe_version': '0.169.1'}, {'job_turn': (OWNER, 'operation', INNER)}):
            for accepted in (True, False):
                with self.subTest(options=options, accepted=accepted):
                    row = configured_container('outer', {})
                    if not accepted:
                        row['Args'] = ['599']
                    engine = ConfiguredEngine(row)
                    self.assert_configured_launch(engine, 'outer', lambda: devbox.launch(
                        engine, manifest(), INNER, None, OWNER, '/empty', {}, **options), accepted=accepted)

    def test_inner_launcher_checks_the_literal_hook_before_start_in_all_modes(self):
        for options in ({}, {'probe_version': '0.169.1'}, {'operation': 'operation', 'request_sha': INNER}):
            for accepted in (True, False):
                with self.subTest(options=options, accepted=accepted), ExitStack() as context:
                    mounts = {target: (f'{db.PARENT_JOB}/{key}', True) for key, target in db.JOB_TARGETS.items()}
                    if 'operation' in options:
                        mounts.update({db.JOB_BUILD: (db.PARENT_BUILD, True),
                                       **{target: (source, False) for target, source in db.ADMISSION_ROLE.items()}})
                    row = configured_container('inner', mounts)
                    if not accepted:
                        row['Config']['Cmd'][-1] = 'fixture hook'
                    engine = ConfiguredEngine(row)
                    self.project_inner_environment(context)
                    self.assert_configured_launch(engine, 'inner', lambda: db.controller(INNER, OWNER, 180, **options),
                                                  accepted=accepted)

    def test_second_nested_probe_start_checks_the_stopped_container_again(self):
        class ChangedAfterStop(ConfiguredEngine):
            def __call__(self, stage, *args, **options):
                if args[0] == 'start' and not self.starts:
                    self.starts.append(args[-1])
                    return 0, b''
                if args[0] == 'stop':
                    self.row['Args'][-1] = 'fixture change after stop'
                    return 0, b''
                return super().__call__(stage, *args, **options)

        mounts = {target: (f'{db.PARENT_JOB}/{key}', True) for key, target in db.JOB_TARGETS.items()}
        engine = ChangedAfterStop(configured_container('inner', mounts))
        label = db.process_label(manifest(), 'inner')

        def process(proc, *_):
            return {'cgroup': 'retained', 'namespaces': dict.fromkeys(db.NS_NAMES, proc.name), 'label': label}

        def entry(_engine, _identity, operation, *_):
            if operation == 'probe':
                return json.dumps({'uid': 1000, 'boundary_probe': 'passed', 'selinux_label': label}).encode()
            return f'codex-cli {db.CODEX_VERSION}'.encode()

        with ExitStack() as context:
            self.project_inner_environment(context)
            context.enter_context(patch.object(Path, 'read_text', return_value='0 1 999\n999 1001 1\n1000 1000 1\n1001 1002 64535\n'))
            context.enter_context(patch.multiple(db, proc_snapshot=process, check_inner_inputs=lambda *_: None,
                ready=lambda *_: {'State': {'StartedAt': START, 'Pid': 2}}, fixed_entry=entry, Engine=lambda *_: engine))
            with self.assertRaisesRegex(db.Blocked, 'inner configured command'):
                db.controller(INNER, OWNER, 180)
        self.assertEqual(engine.starts, [CHILD])
        self.assertEqual(engine.removals, [CHILD])

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

    def test_noncanonical_structural_aliases_block_before_podman_can_reinterpret_archive(self):
        aliases = (
            ('index', 'Manifests', lambda _value: []),
            ('manifest', 'Layers', lambda value: list(reversed(value['layers']))),
            ('manifest', 'Config', lambda value: value['layers'][0]),
            ('descriptor', 'Digest', lambda _value: 'sha256:' + '0' * 64),
            ('descriptor platform', 'Architecture', lambda _value: 'arm64'),
            ('image config', 'RootFS', lambda value: value['rootfs'] | {'diff_ids': []}),
            ('image config', 'OS', lambda _value: 'windows'),
            ('rootfs', 'Diff_Ids', lambda value: list(reversed(value['diff_ids']))),
            ('runtime config', 'labels', lambda _value: {'dev-pair.role': 'maintenance'}),
            ('history entry', 'Created_By', lambda _value: 'substitute'),
        )
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.tar'
            for level, alias, override in aliases:
                with self.subTest(level=level, alias=alias):
                    def transform(kind, value):
                        if level == kind:
                            value[alias] = override(value)

                    value = manifest()
                    value['inner'].update(oci_archive(path, transform=transform))
                    engine = self.cached_engine(value)
                    with self.assertRaisesRegex(db.Blocked, f'OCI {level} structural keys'):
                        db.load_development_archive(engine, value, path)
                    self.assertEqual(engine.loads, [])
                    self.assertEqual(engine.inspections, [])


if __name__ == '__main__':
    unittest.main()
