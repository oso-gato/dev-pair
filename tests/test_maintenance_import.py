"""Test exact local admission and command ordering with a mocked native engine."""

from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_gptbox import Engine, EXPECTED, SOURCE, SEALED, RUNTIME, g

MANIFEST = '1' * 64
PRODUCER = '2' * 64
ARCHIVE = '3' * 64
LAYER = 'sha256:' + '4' * 64
BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
REBOOT = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
PACKAGE_LIST = b'local fixture package list\n'
ENTRY = b'#!/bin/sh\n# fixture Distrobox entry\n'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


class Runner(Engine):
    native_register = None
    native_prefix = None
    cleanups = 0

    @contextmanager
    def phase(self, _seconds, prefix, native=True):
        self.native_prefix = prefix + '-12345678' if native else None
        yield

    def __call__(self, *args, **kwargs):
        if args[:2] in (('/usr/bin/id', '-u'), ('/usr/bin/id', '-g')):
            return str(os.getuid() if args[1] == '-u' else os.getgid()) + '\n'
        if args == ('/usr/sbin/getenforce',):
            return 'Enforcing\n'
        if args[:2] == ('/usr/bin/rpm', '-q'):
            return PACKAGE_LIST.decode()
        if args[-2:] == ('info', '--format=json'):
            return json.dumps(self.app.store)
        if args[-5:-4] == ('exec',):
            return self.app.seal_files[Path(args[-1]).name]
        output = super().__call__(*args, **kwargs)
        if '--label=dev-pair.imported-probe=' + SEALED in args:
            row = self.containers[output]
            row['Config']['Labels']['dev-pair.imported-probe'] = SEALED
            row['HostConfig']['IDMappings'] = {'UidMap': ['1000:0:1'], 'GidMap': ['1000:0:1']}
        if 'rm' in args and args[-1] == RUNTIME:
            self.cleanups += 1
        return output


class Fixture(g.Gptbox):
    def __init__(self, root):
        run = Runner()
        super().__init__(root, run)
        run.app = self
        self.calls = []
        self.boot = BOOT
        self.store = {'host': {'security': {'rootless': True, 'selinuxEnabled': True}},
                      'store': {'graphRoot': g.MAINTENANCE_STORE,
                                'runRoot': f'/run/user/{os.getuid()}/dev-pair-gptbox', 'graphDriverName': 'vfs'}}
        self.directory('/var/lib/dev-pair', mode=0o755)
        self.state.mkdir(mode=0o700)
        self.target = g.ROOT + '/' + EXPECTED
        files = {'/opt/dev-pair/bin/codex': g.CODEX_SHA, '/usr/bin/distrobox-init': 'f' * 64, g.RUNTIME: 'e' * 64}
        inputs = {'source_sha': SOURCE, 'context_sha256': EXPECTED, 'distrobox_sha': g.DBX_SHA,
                  'role': 'maintenance', 'files': files}
        inputs_raw = g.image_inputs_bytes(inputs)
        seal = {'kind': 'genuine-distrobox-assembled', 'inputs_sha256': g.sha(inputs_raw),
                'source_sha': SOURCE, 'uid': 1000, 'gid': 1000, 'packages_sha256': '7' * 64}
        self.seal_files = {'inputs.json': inputs_raw.decode(), 'sealed.json': g.image_inputs_bytes(seal).decode()}
        labels = {'dev-pair.role': 'maintenance', 'dev-pair.context': EXPECTED, 'dev-pair.distrobox': g.DBX_SHA,
                  'dev-pair.standards': g.candidate.STANDARDS, 'org.opencontainers.image.revision': SOURCE,
                  'dev-pair.codex.version': '0.169.0', 'dev-pair.codex.sha256': g.CODEX_SHA,
                  'dev-pair.inputs': seal['inputs_sha256'], 'dev-pair.init': files['/usr/bin/distrobox-init'],
                  'dev-pair.runtime': files[g.RUNTIME]}
        run.images['sha256:' + SEALED] = {'Id': SEALED, 'Digest': 'sha256:' + MANIFEST, 'Architecture': 'amd64',
                                          'Os': 'linux', 'Labels': labels, 'RootFS': {'Layers': [LAYER]}}

    def preflight(self):
        self.calls.append('host-preflight')

    def protect_host_sources(self, upstream, revision):
        self.calls.append('protected-source')

    def context_inputs(self, context, expected, revision):
        self.calls.append('maintenance-context')
        return {'source_sha': revision}

    def protected(self, path):
        if path == Path(g.__file__).with_name('devbox.py'):
            return path
        return super().protected(path)

    def inputs(self, context, expected, upstream, revision):
        self.calls.append('exact-source')
        return {'source_sha': revision}, {'distrobox-enter': ENTRY}

    def maintenance_storage(self):
        self.calls.append('managed-storage')
        dev = self.path('/var/lib/dev-pair').stat().st_dev
        return f'{os.major(dev)}:{os.minor(dev)}'

    def preparation(self):
        return SimpleNamespace(run=self.run, _host_prerequisites=self.host_prerequisites, _host_desired=self.desired)

    def desired(self, name='core', sources=None, context=EXPECTED):
        value = {'schema': 1, 'gptbox_context_sha256': context, 'operator': name,
                 'standards_sha': g.candidate.STANDARDS, 'source_baseline': g.SOURCE_BASELINE,
                 'keys_source': g.KEYS_URL, 'bootstrap_sources': ['192.0.2.1/32'] if sources is None else sources,
                 'bootstrap_sha256': g.sha(Path(g.__file__).with_name('bootstrap.py').read_bytes())}
        if sources == []:
            value['bootstrap_transport'] = 'verified-provider-console'
        return g.image_inputs_bytes(value).decode()

    def host_prerequisites(self, name, keys, sources, context, expected, *, password, source_check, **extra):
        self.calls.append(('host-prerequisites', name, keys, sources, extra))
        source_check()
        return self.host_ready(sources)

    def host_ready(self, sources):
        desired = self.desired(sources=sources).encode()
        self.atomic(g.STATE + '/desired.json', desired.decode())
        self.atomic(g.STATE + '/packages.txt', PACKAGE_LIST.decode())
        value = {'schema': 1, 'kind': 'host-prerequisites', 'source_sha': SOURCE, 'context_sha256': EXPECTED,
                 'standards_sha': g.candidate.STANDARDS, 'bootstrap_sha256': json.loads(desired)['bootstrap_sha256'],
                 'desired_sha256': g.sha(desired), 'packages_sha256': g.sha(PACKAGE_LIST)}
        self.atomic(g.STATE + '/host-ready.json', g.image_inputs_bytes(value).decode())
        return value

    def verify_builder(self):
        return g._RoleIdentity('dp-maint', os.getuid(), os.getgid())

    def validate_bootstrap_access(self, sources, console_receipt=None):
        self.calls.append(('access', sources, console_receipt))
        return [] if console_receipt else g.validate_sources(sources)

    def observed_ssh_peer(self):
        return None

    def directory(self, name, mode=0o700, owner=None):
        return super().directory(name, mode, owner=None)

    def live_boot_id(self):
        return self.boot

    def execute(self, *args, **kwargs):
        if any(token.endswith('/distrobox-enter') for token in args):
            self.calls.append(('entry', args))
            if args[-1] == 'probe':
                return json.dumps({'boundary_probe': 'passed', 'uid': 1000,
                                   'selinux_label': self.run.containers[RUNTIME]['ProcessLabel']})
            if args[-1] == 'version':
                return 'codex-cli 0.169.0\n'
            raise AssertionError('unapproved fixture Distrobox entry')
        return super().execute(*args, **kwargs)


class MaintenanceImportTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.app = Fixture(Path(temp.name))
        pinned_enter = patch.object(g, 'ENTER_SHA256', g.sha(ENTRY))
        pinned_enter.start()
        self.addCleanup(pinned_enter.stop)
        keys = patch.object(g, 'github_keys', return_value='public fixture key')
        keys.start()
        self.addCleanup(keys.stop)
        self.app.atomic(g.STATE + '/operator-password-set', 'already prepared\n')

    def setup_release(self):
        part = {'schema': 1, 'image': {'role': 'maintenance', 'source_sha': SOURCE, 'context_sha256': EXPECTED,
                                       'image_id': SEALED, 'archive_sha256': ARCHIVE, 'archive_bytes': 123, 'diff_ids': [LAYER]},
                'oci_manifest_sha256': MANIFEST, 'producer': {'result_sha256': PRODUCER}}
        row = {'source_sha': SOURCE, 'context_sha256': EXPECTED, 'oci_config_sha256': SEALED,
               'oci_manifest_sha256': MANIFEST, 'archive_sha256': ARCHIVE, 'archive_bytes': 123,
               'codex_version': '0.169.0', 'codex_source_sha': SOURCE, 'codex_sha256': g.CODEX_SHA}
        raw = canonical(part)
        index = {'schema': 2, 'source_sha': SOURCE, 'publisher_run': 123, 'kind': 'dev-pair-platform-release',
                 'components': {'maintenance-agent': row}, 'transports': {'maintenance': {'files': {
                     'part.json': {'bytes': len(raw), 'sha256': g.sha(raw)},
                     'maintenance.oci.tar': {'bytes': 123, 'sha256': ARCHIVE}}}}}
        self.platform = g.sha(canonical(index))
        self.release = g.PLATFORM_RELEASES + '/' + self.platform
        self.app.atomic(self.release + '/platform.json', canonical(index).decode())
        self.app.atomic(self.release + '/intake.json', canonical({'schema': 2, 'source_sha': SOURCE,
                        'publisher_run': 123, 'kind': index['kind'], 'platform_sha256': self.platform}).decode())
        self.app.atomic(self.release + '/maintenance/part.json', raw.decode())

        def fields(value, allowed):
            self.assertEqual(set(value), set(allowed.split()))
        # The release publisher validates the complete signed manifest in its
        # own suite. This fixture keeps exact on-disk P input and boundary checks.
        protocol = SimpleNamespace(canonical=canonical, portable_index=Mock(), fields=fields,
                                   image_record=lambda value: value)
        publisher = SimpleNamespace(publication_evidence=Mock())
        scope = patch.dict(sys.modules, {'platform_release_protocol': protocol, 'platform_release': publisher})
        scope.start()
        self.addCleanup(scope.stop)
        self.protocol, self.publisher = protocol, publisher

    def prepare_cli(self, *access):
        argv = ['gptbox.py', 'prepare-maintenance-host', '--context', '/candidate', '--expected-context-sha256', EXPECTED,
                '--distrobox-source', '/upstream', '--source-sha', SOURCE, *access]
        with patch.object(g, 'Gptbox', return_value=self.app), patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()) as output:
            code = g.main()
        return code, json.loads(output.getvalue()) if code == 0 else None

    def prepare(self):
        self.assertEqual(self.prepare_cli('--bootstrap-source', '192.0.2.1/32', '--apply')[0], 0)

    def verify(self, phase='verify'):
        argv = ['gptbox.py', 'verify-installed-maintenance', '--phase', phase, '--platform-sha256', self.platform,
                '--context-sha256', EXPECTED, '--source-sha', SOURCE, '--image', SEALED, '--oci-manifest-sha256', MANIFEST]
        with patch.object(g, 'Gptbox', return_value=self.app), patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()) as output:
            code = g.main()
        return code, json.loads(output.getvalue()) if code == 0 else None

    def import_witness(self, **changes):
        path = self.release + '/maintenance-import.json'
        record = {'schema': 1, 'kind': 'maintenance-native-oci-import', 'platform_sha256': self.platform,
                  'source_sha': SOURCE, 'context_sha256': EXPECTED, 'image_id': SEALED,
                  'oci_manifest_sha256': MANIFEST, 'boot_id': self.app.boot, 'archive_sha256': ARCHIVE,
                  'graphroot': g.MAINTENANCE_STORE, 'runroot': self.app.store['store']['runRoot'], **changes}
        self.app.atomic(path, canonical(record).decode(), expected=self.app.text(path) or None)

    def test_normal_host_preparation_reuses_gateway_without_building(self):
        status, preview = self.prepare_cli('--bootstrap-source', '192.0.2.1/32')
        self.assertEqual(status, 0)
        self.assertFalse(preview['changes'])
        self.assertFalse(self.app.path(g.STATE + '/prepared').exists())
        status, prepared = self.prepare_cli('--console-receipt', '/signed-console.json', '--apply')
        self.assertEqual(status, 0)
        self.assertFalse(prepared['job_admission'])
        self.assertIn(('host-prerequisites', 'core', 'public fixture key', [],
                       {'console_receipt': '/signed-console.json'}), self.app.calls)
        self.assertLess(self.app.calls.index('managed-storage'), next(i for i, row in enumerate(self.app.calls)
                        if isinstance(row, tuple) and row[:1] == ('host-prerequisites',)))
        self.assertFalse(self.app.path(g.STATE + '/gptbox-image.json').exists())
        self.assertFalse(self.app.path(self.app.target + '/result.json').exists())
        self.assertEqual(self.app.path(g.STATE + '/prepared').read_bytes(), self.app.path(g.STATE + '/desired.json').read_bytes())
        self.assertFalse(any('build' in args or 'load' in args for args, _ in self.app.run.calls))

    def test_preflight_uses_signed_scope_before_any_oci_effect(self):
        self.prepare()
        self.setup_release()
        status, result = self.verify('preflight')
        self.assertEqual(status, 0)
        self.assertEqual(result['boot_id'], BOOT)
        self.assertEqual(result['phase'], 'preflight')
        self.assertEqual(self.app.run.starts, 0)
        self.assertFalse(self.app.path(self.app.import_receipt_path(EXPECTED, SEALED)).exists())
        self.protocol.portable_index.assert_called_once()
        self.publisher.publication_evidence.assert_called_once()

    def test_setup_preserves_conflicting_host_state_before_fetching_or_mutating(self):
        self.app.atomic(g.STATE + '/desired.json', '{"other":"protected"}\n')
        status, _ = self.prepare_cli('--bootstrap-source', '192.0.2.1/32', '--apply')
        self.assertEqual(status, 2)
        self.assertFalse(self.app.path(g.MAINTENANCE_HOST_INTENT).exists())
        self.assertEqual(self.app.text(g.STATE + '/desired.json'), '{"other":"protected"}\n')
        self.assertFalse(any(isinstance(row, tuple) and row[0] == 'host-prerequisites' for row in self.app.calls))

    def test_verify_runs_confined_two_cycle_probe_and_preserves_legacy_result(self):
        self.prepare()
        self.setup_release()
        self.import_witness()
        legacy = self.app.target + '/result.json'
        self.app.atomic(legacy, 'legacy unrelated local evidence\n')
        code, evidence = self.verify()
        self.assertEqual(code, 0)
        self.assertEqual(evidence, self.app.import_admission(self.platform, EXPECTED, SOURCE, SEALED, MANIFEST, BOOT, PRODUCER))
        self.assertEqual(self.app.run.starts, 2)
        self.assertEqual(self.app.run.cleanups, 1)
        self.assertFalse(self.app.run.containers)
        commands = [row[1] for row in self.app.calls if isinstance(row, tuple) and row[0] == 'entry']
        self.assertEqual([command[-1] for command in commands], ['probe', 'version'] * 2)
        self.assertTrue(all('--no-tty' in command and '/credentials' not in command for command in commands))
        self.assertEqual(self.app.text(legacy), 'legacy unrelated local evidence\n')
        self.assertTrue(all(not path.exists() for path in self.app.import_probe_leaves))
        self.assertEqual(self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED), '0.169.0')
        self.app.boot = REBOOT
        with self.assertRaisesRegex(g.Blocked, 'release or boot'):
            self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED)
        self.import_witness()
        code, current = self.verify()
        self.assertEqual(code, 0)
        self.assertEqual(current['boot_id'], REBOOT)
        self.assertEqual(current['platform_sha256'], evidence['platform_sha256'])

    def test_guest_result_without_local_assembly_evidence_cannot_admit_job(self):
        self.prepare()
        result = {'kind': 'maintenance-gptbox-probe-candidate', 'assembled_image_id': SEALED,
                  'source_sha': SOURCE, 'context_sha256': EXPECTED, 'distrobox_sha': g.DBX_SHA,
                  'boundary_and_version_cycles': 2, 'runtime_container_removed': True}
        self.app.atomic(self.app.target + '/result.json', g.image_inputs_bytes(result).decode())
        with self.assertRaisesRegex(g.Blocked, 'gptbox-image.json'):
            self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED)
        self.app.atomic(g.STATE + '/gptbox-image.json', g.image_inputs_bytes({'source_sha': SOURCE,
                        'context_sha256': EXPECTED}).decode())
        self.app.atomic(self.app.target + '/assembly-attestation.json', self.app.seal_files['sealed.json'])
        self.assertEqual(self.app.admitted_maintenance_image(EXPECTED, SOURCE, SEALED), '0.169.0')

    def test_wrong_import_and_rootless_store_are_rejected_before_runtime(self):
        self.prepare()
        self.setup_release()
        self.import_witness(boot_id=REBOOT)
        with self.assertRaisesRegex(g.Blocked, 'receipt differs'):
            self.app.verify_installed_maintenance('verify', self.platform, EXPECTED, SOURCE, SEALED, MANIFEST)
        self.import_witness()
        self.app.store['host']['security']['rootless'] = False
        with self.assertRaisesRegex(g.Blocked, 'rootless store'):
            self.app.verify_installed_maintenance('verify', self.platform, EXPECTED, SOURCE, SEALED, MANIFEST)
        self.assertFalse(self.app.run.containers)
        self.assertFalse(self.app.path(self.app.import_receipt_path(EXPECTED, SEALED)).exists())

    def test_tampered_transport_is_rejected_before_engine(self):
        self.prepare()
        self.setup_release()
        proof = self.app.path(self.release + '/maintenance/part.json')
        raw = proof.read_text()
        self.app.atomic(self.release + '/maintenance/part.json', raw.replace(PRODUCER, '9' * 64), expected=raw)
        with self.assertRaisesRegex(g.Blocked, 'transport'):
            self.app.verify_installed_maintenance('preflight', self.platform, EXPECTED, SOURCE, SEALED, MANIFEST)
        self.assertEqual(self.app.run.starts, 0)
        self.assertFalse(self.publisher.publication_evidence.called)

    def test_failed_seal_or_cleanup_creates_no_import_admission(self):
        self.prepare()
        self.setup_release()
        self.import_witness()
        original = self.app.seal_files['sealed.json']
        self.app.seal_files['sealed.json'] = original.replace('"uid": 1000', '"uid": 0')
        receipt = self.app.path(self.app.import_receipt_path(EXPECTED, SEALED))
        with self.assertRaisesRegex(g.Blocked, 'Distrobox seal differs'):
            self.app.verify_installed_maintenance('verify', self.platform, EXPECTED, SOURCE, SEALED, MANIFEST)
        self.assertFalse(receipt.exists())
        self.assertFalse(self.app.run.containers)
        self.app.seal_files['sealed.json'] = original
        self.app.run.fail = lambda args: 'rm' in args and args[-1] == RUNTIME
        with self.assertRaisesRegex(g.Blocked, 'injected engine boundary failure'):
            self.app.verify_installed_maintenance('verify', self.platform, EXPECTED, SOURCE, SEALED, MANIFEST)
        self.assertFalse(receipt.exists())
        self.assertIn(RUNTIME, self.app.run.containers)

    def test_existing_incompatible_admission_remains_unchanged(self):
        self.prepare()
        self.setup_release()
        self.import_witness()
        path = self.app.import_receipt_path(EXPECTED, SEALED)
        conflicting = self.app.import_admission('a' * 64, EXPECTED, SOURCE, SEALED, MANIFEST, BOOT, PRODUCER)
        self.app.atomic(path, g.image_inputs_bytes(conflicting).decode())
        with self.assertRaisesRegex(g.Blocked, 'conflicting imported maintenance'):
            self.app.verify_installed_maintenance('verify', self.platform, EXPECTED, SOURCE, SEALED, MANIFEST)
        self.assertEqual(self.app.path(path).read_bytes(), g.image_inputs_bytes(conflicting))
        self.assertEqual(self.app.run.starts, 0)


if __name__ == '__main__':
    unittest.main()
