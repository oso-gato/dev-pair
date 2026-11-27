import os
from contextlib import ExitStack, contextmanager
import errno
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import platform_release as release
import platform_release_install as install
import platform_release_protocol as protocol
import test_platform_release as fixtures


class InstallerTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.platform = '1' * 64
        self.site = '2' * 64
        self.source = '3' * 40
        self.image = '4' * 64
        self.manifest = '5' * 64
        self.context = '6' * 64
        self.boot = '11111111-1111-1111-1111-111111111111'
        self.end = time.monotonic() + 20
        self.config = {'schema': 1, 'hostname': 'erebus', 'host_config_sha256': '7' * 64,
                       'jobs': {'checklist': {'storage_bytes': 8 * protocol.GIB,
                                              'categories': {'outer': [100, 101, 102], 'inner': [100, 101]}}}}

    def index(self):
        return {'kind': 'dev-pair-platform-release', 'source_sha': self.source,
                'base_platform_sha256': None, 'components': {
                    'maintenance-agent': {'context_sha256': self.context, 'oci_config_sha256': self.image,
                                          'oci_manifest_sha256': self.manifest},
                    'host': {'source_sha': self.source, 'bundle_manifest_sha256': '8' * 64},
                }}


class PlatformReleaseInstallerTests(InstallerTestCase):
    def test_site_categories_reject_cross_job_aliases_and_unbounded_capacity(self):
        path = self.root / 'site.json'
        with mock.patch.object(install, 'protected_json', return_value=(self.config, b'valid')):
            self.assertEqual(install.site_configuration(path, self.site), self.config)
            self.config['jobs']['different-job'] = {'storage_bytes': 8 * protocol.GIB,
                                                   'categories': {'outer': [5, 6, 102], 'inner': [5, 6]}}
            with self.assertRaisesRegex(protocol.Blocked, 'shared'):
                install.site_configuration(path, self.site)
            self.config['jobs']['different-job']['storage_bytes'] = 20 * protocol.GIB
            with self.assertRaisesRegex(protocol.Blocked, 'storage ceiling'):
                install.site_configuration(path, self.site)

    def test_real_host_bundle_installs_exact_root_package_and_preserves_reuse(self):
        source = fixtures.PlatformReleaseTests()
        source.setUp()
        self.addCleanup(source.doCleanups)
        checkout, revision = source.git_repo()
        stage = self.root / 'stage'
        stage.mkdir()
        identity = release.build_host(checkout, revision, stage / 'host')
        host_store = self.root / 'host-releases'
        host_store.mkdir()
        row = {'source_sha': revision, 'bundle_manifest_sha256': identity}
        protected_hash = install.file_hash
        with (
            mock.patch.object(install, 'HOST_RELEASES', host_store),
            mock.patch.object(install.intake, 'protected', side_effect=lambda path, **_: path),
            mock.patch.object(install, 'protected_json', side_effect=lambda path, expected=None:
                              (release.readonly_json(path)[1], path.read_bytes())),
            mock.patch.object(install, 'file_hash', side_effect=lambda path, maximum, end, **_:
                              protected_hash(path, maximum, end)),
        ):
            self.assertEqual(install.install_host(stage, row, self.end), {'manifest_sha256': identity})
            target = host_store / identity
            self.assertEqual(target.stat().st_mode & 0o777, 0o555)
            self.assertEqual((target / 'runtime/unit-command').stat().st_mode & 0o777, 0o555)
            self.assertEqual(install.install_host(stage, row, self.end, reuse_only=True), {'manifest_sha256': identity})
            with self.assertRaisesRegex(protocol.Blocked, 'retained installed host bundle'):
                install.install_host(stage, {**row, 'bundle_manifest_sha256': '9' * 64}, self.end, reuse_only=True)

    def test_real_verified_archive_peak_accounts_for_vfs_parent_replication(self):
        case = fixtures.PlatformReleaseTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        directory = self.root / 'outer'
        image, manifest, _ = case.oci_image(directory, 'devbox')
        row = {'archive_bytes': image['archive_bytes'], 'oci_manifest_sha256': manifest}
        result = install.rootless_import_peak(directory / 'devbox.oci.tar', row, self.end)
        self.assertEqual(result, 2 * image['archive_bytes'] + 256 * 1024**2 +
                         2 * len(b'test layer bytes') + len(b'exact second layer'))

    def test_boot_readback_can_refresh_only_the_same_immutable_installation(self):
        path = self.root / 'installed.json'
        prior = {'schema': 1, 'platform_sha256': self.platform, 'boot_id': self.boot,
                 'components': {'maintenance': {'result_sha256': 'a' * 64, 'oci_config_sha256': self.image}}}
        install.publish_observation(path, prior, installed=True)
        booted = {**prior, 'boot_id': '22222222-2222-2222-2222-222222222222',
                  'components': {'maintenance': {'result_sha256': 'b' * 64, 'oci_config_sha256': self.image}}}
        with mock.patch.object(install, 'protected_json', side_effect=lambda name:
                               (release.readonly_json(name)[1], name.read_bytes())):
            install.publish_observation(path, booted, installed=True)
            self.assertEqual(path.read_bytes(), protocol.canonical(booted))
            changed = {**booted, 'boot_id': self.boot,
                       'components': {'maintenance': {'result_sha256': 'c' * 64, 'oci_config_sha256': '9' * 64}}}
            with self.assertRaisesRegex(protocol.Blocked, 'immutable installation binding'):
                install.publish_observation(path, changed, installed=True)
            with self.assertRaisesRegex(protocol.Blocked, 'same-boot'):
                install.publish_observation(path, {**booted, 'platform_sha256': 'f' * 64}, installed=True)
        self.assertEqual(path.read_bytes(), protocol.canonical(booted))

    def test_missing_prebuilt_G_capability_stops_before_native_role_loading(self):
        stage = self.root / self.platform
        stage.mkdir()
        index = self.index()
        with (
            mock.patch.object(install, 'site_configuration', return_value=self.config),
            mock.patch.object(install, 'machine', return_value=self.boot),
            mock.patch.object(install, 'stage_identity', return_value=(stage, index)),
            mock.patch.object(install, 'exact_local_programs'),
            mock.patch.object(install, 'maintenance_identity', return_value=(None, None)),
            mock.patch.object(install, 'bounded_volume', return_value={}),
            mock.patch.object(install, 'stage_budget'),
            mock.patch.object(install, 'ImportLease'),
            mock.patch.object(install, 'maintenance_probe') as p,
            mock.patch.object(install, 'development_request', return_value={}),
            mock.patch.object(install, 'approved_placement', side_effect=subprocess.CalledProcessError(2, [])) as g,
            mock.patch.object(install, 'install_maintenance') as maintenance,
            mock.patch.object(install, 'install_host') as host,
        ):
            with self.assertRaisesRegex(protocol.Blocked, 'prebuilt G deployment entry'):
                install.install(self.platform, self.site, self.end)
        p.assert_called_once_with(stage, index, 'preflight', self.end)
        g.assert_called_once_with(self.platform, self.platform, self.site, self.config, 'preflight', self.end)
        maintenance.assert_not_called()
        host.assert_not_called()
        self.assertFalse((stage / 'installed.json').exists())

    def test_maintenance_admission_rejects_guest_completion_and_binds_typed_actual_probe(self):
        stage = self.root / self.platform
        stage.mkdir()
        original = 'e' * 64
        receipt = {'schema': 1, 'kind': 'maintenance-imported-release-admission', 'platform_sha256': self.platform,
                   'source_sha': self.source, 'context_sha256': self.context, 'image_id': self.image,
                   'oci_manifest_sha256': self.manifest, 'boot_id': self.boot,
                   'distrobox_sha': release.public_inputs.DBX_SOURCE, 'boundary_and_version_cycles': 2,
                   'runtime_container_removed': True, 'job_admission': False, 'producer_result_sha256': original}
        node = SimpleNamespace(st_mode=0o100600)
        with (
            mock.patch.object(install.intake, 'protected', side_effect=lambda path, **_: path),
            mock.patch.object(install, 'bounded', return_value=(0, b'')) as command,
            mock.patch.object(install, 'current_boot', return_value=self.boot),
            mock.patch.object(install.release, 'readonly_json', return_value=(b'', {'producer': {'result_sha256': original}})),
            mock.patch.object(Path, 'lstat', return_value=node),
            mock.patch.object(install, 'protected_json', side_effect=lambda path: (receipt, install.gptbox.image_inputs_bytes(receipt))) as observed,
        ):
            expected = install.maintenance_probe(stage, self.index(), 'verify', self.end)
            self.assertEqual(expected['result_sha256'], release.digest(install.gptbox.image_inputs_bytes(receipt)))
            self.assertTrue(str(observed.call_args.args[0]).endswith(f'/imported-releases/{self.platform}/{self.image}/{self.boot}.json'))
            self.assertIn('verify-installed-maintenance', command.call_args.args[0])
            receipt['kind'] = 'maintenance-gptbox-probe-candidate'
            with self.assertRaisesRegex(protocol.Blocked, 'actual restricted native maintenance probe'):
                install.maintenance_probe(stage, self.index(), 'verify', self.end)

    def test_actual_versioned_manifest_retains_stable_outer_and_original_inner_encoding(self):
        stage = self.root / self.platform
        (stage / 'development').mkdir(parents=True)
        disk = b'role-scoped archive bytes'
        inner = {'image_id': self.image, 'source_sha': self.source, 'context_sha256': self.context,
                 'inputs_sha256': '8' * 64, 'sealed_sha256': '9' * 64, 'archive_bytes': len(disk),
                 'archive_sha256': release.digest(disk), 'diff_ids': ['sha256:' + 'a' * 64]}
        (stage / 'development/part.json').write_bytes(protocol.canonical({'producer': inner}))
        stable_outer = {'source_sha': 'b' * 40, 'oci_config_sha256': 'c' * 64, 'oci_manifest_sha256': 'd' * 64}
        base = {'components': {'devbox': stable_outer}}
        index = {'source_sha': self.source, 'standards_sha': protocol.STANDARDS, 'components': {
            'development-agent': {'context_sha256': self.context, 'oci_config_sha256': self.image,
                                  'oci_manifest_sha256': self.manifest, 'archive_bytes': len(disk),
                                  'archive_sha256': release.digest(disk)}}}
        manifest = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': protocol.STANDARDS,
                    'job': 'checklist', 'storage_bytes': 8 * protocol.GIB, 'inner': inner,
                    'outer': {'source_sha': stable_outer['source_sha'], 'image_id': stable_outer['oci_config_sha256']},
                    'categories': self.config['jobs']['checklist']['categories']}

        def place(value):
            raw = protocol.canonical(value)
            identity = release.digest(raw)
            leaf = self.root / 'development/builds/checklist/inputs' / identity
            leaf.mkdir(parents=True)
            for name, data in (('manifest.json', raw), ('development.oci.tar', disk)):
                path = leaf / name
                path.write_bytes(data)
                path.chmod(0o444)
            return {'outer': {key: stable_outer[key] for key in ('oci_config_sha256', 'oci_manifest_sha256')},
                    'jobs': {'checklist': {'manifest_sha256': identity}}}

        ordinary_json = release.readonly_json
        ordinary_hash = install.file_hash
        with (
            mock.patch.object(install, 'ROOT', self.root),
            mock.patch.object(release, 'readonly_json', side_effect=lambda path, _owner=None: ordinary_json(path)),
            mock.patch.object(install, 'file_hash', side_effect=lambda path, maximum, end, **_kwargs:
                              ordinary_hash(path, maximum, end)),
            mock.patch.object(install.devbox, 'check_label', create=True) as label,
            mock.patch.object(install.devbox, 'storage_mount'),
        ):
            reported = place(manifest)
            _, proof = install.check_development(stage, index, base, self.config, reported, self.end)
            encoded = install.gptbox.image_inputs_bytes(inner)
            self.assertNotEqual(encoded, protocol.canonical(inner))
            self.assertEqual(proof['inner_sha256'], release.digest(encoded))
            self.assertEqual(proof['jobs'], reported['jobs'])
            self.assertEqual(label.call_count, 2)
            wrong = {**manifest, 'outer': {**manifest['outer'], 'source_sha': self.source}}
            with self.assertRaisesRegex(protocol.Blocked, 'stable outer'):
                install.check_development(stage, index, base, self.config, place(wrong), self.end)


class NativeImportRecoveryTests(InstallerTestCase):
    def recovery_fixture(self):
        self.managed = self.root / 'managed'
        self.graph = self.managed / 'maintenance/images'
        self.graph.mkdir(parents=True)
        self.cgroups = self.root / 'cgroups'
        self.cgroups.mkdir()
        self.stage = self.root / self.platform
        (self.stage / 'maintenance').mkdir(parents=True)
        self.source_archive = self.stage / 'maintenance/maintenance.oci.tar'
        self.source_archive.write_bytes(b'exact archive fixture')
        self.runtime = self.root / 'run'
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.index_value = self.index()
        self.index_value['components']['maintenance-agent'].update(archive_bytes=len(self.source_archive.read_bytes()),
                                                                 archive_sha256='9' * 64, codex_version='0.169.0')
        self.capacity = {'device': f'{os.major(self.graph.stat().st_dev)}:{os.minor(self.graph.stat().st_dev)}',
                         'backing_inode': 123, 'backing_bytes': 20 * protocol.GIB}
        self.units = {}
        self.launches = []
        self.stops = []
        self.load_error = None
        self.restorecon_error = None
        self.stop_releases_group = True
        self.has_image = False
        self.booted = self.boot

    def protected_json(self, path, expected=None):
        raw, decoded = release.readonly_json(path)
        if expected is not None:
            self.assertEqual(release.digest(raw), expected)
        return decoded, raw

    @contextmanager
    def native(self):
        self.recovery_fixture()
        with ExitStack() as stack:
            for key, value in {'ROOT': self.managed, 'MAINTENANCE': self.graph, 'CGROUP_ROOT': self.cgroups,
                               'ADAPTER': self.managed / 'bootstrap/gptbox-adapter'}.items():
                stack.enter_context(mock.patch.object(install, key, value))
            stack.enter_context(mock.patch.object(install.intake, 'protected', side_effect=lambda path, **_: path))
            stack.enter_context(mock.patch.object(install, 'protected_json', side_effect=self.protected_json))
            stack.enter_context(mock.patch.object(install, 'regular', side_effect=lambda path, limit, _owner: protocol.regular(path, limit)))
            stack.enter_context(mock.patch.object(install, 'current_boot', side_effect=lambda: self.booted))
            stack.enter_context(mock.patch.object(install, 'volume_identity', return_value=self.capacity))
            stack.enter_context(mock.patch.object(install, 'bounded_volume', return_value=self.capacity))
            stack.enter_context(mock.patch.object(install, 'rootless_import_peak', return_value=1024))
            stack.enter_context(mock.patch.object(install, 'bounded', side_effect=self.command))
            yield

    def command(self, argv, end, limit=protocol.CONTROL_LIMIT, allowed=(0,), *, data=None):
        if argv[0] == '/usr/sbin/restorecon':
            if self.restorecon_error:
                raise self.restorecon_error
            return 0, b''
        if argv[0] == install.SYSTEMCTL:
            name = argv[-1]
            if argv[1] == 'list-jobs':
                return 0, b''
            if argv[1] == 'stop':
                self.stops.append(name)
                if self.stop_releases_group:
                    (self.cgroups / name / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
                del self.units[name]
                return 0, b''
            properties = self.units.get(name, {'Id': name, 'LoadState': 'not-found', 'ActiveState': 'inactive'})
            output = ''.join(f'{key}={value}\n' for key, value in properties.items()).encode()
            return (0 if name in self.units else 4), output
        self.assertEqual(argv[0], '/usr/bin/systemd-run')
        unit = argv[1].removeprefix('--unit=')
        description = argv[2].removeprefix('--description=')
        lease = protocol.json_bytes((self.managed / install.LEASE_NAME).read_bytes())
        operation = lease['unit']['operation']
        self.assertEqual(lease['unit']['name'], unit)
        self.assertIn(lease['image_id'], (self.image, 'a' * 64))
        self.assertIn(lease['nonce'], description)
        self.assertIn(operation, argv)
        self.launches.append(operation)
        spool = self.managed / (install.SPOOL_PREFIX + lease['nonce'])
        if operation == 'info':
            result = {'host': {'security': {'rootless': True, 'selinuxEnabled': True}},
                      'store': {'graphRoot': str(self.graph), 'runRoot': str(self.runtime / 'dev-pair-gptbox'),
                                'imageCopyTmpDir': str(spool), 'graphDriverName': 'vfs'}}
            return 0, protocol.canonical(result)
        if operation == 'load':
            self.assertEqual(data.read(), self.source_archive.read_bytes())
            (spool / 'partial').write_bytes(b'bdd-owned copy')
            if self.load_error:
                self.load_error(unit, description)
            self.has_image = True
            return 0, b''
        if operation == 'inspect' and self.has_image:
            return 0, protocol.canonical([{'Id': 'sha256:' + lease['image_id'], 'Digest': 'sha256:' + self.manifest,
                                           'Os': 'linux', 'Architecture': 'amd64'}])
        if operation == 'exists':
            if self.has_image:
                return 0, b''
            self.failed_unit(unit, description)
            return 1, b''
        raise protocol.Blocked('fixture native command failed with status 125')

    def failed_unit(self, unit, description, *, active=False):
        self.units[unit] = {'Id': unit, 'Description': description, 'Transient': 'yes', 'User': 'dp-maint',
                            'LoadState': 'loaded', 'ActiveState': 'active' if active else 'failed',
                            'ControlGroup': f'/system.slice/{unit}', 'Result': 'exit-code',
                            'ExecMainCode': '1', 'ExecMainStatus': '1'}
        group = self.cgroups / unit
        group.mkdir()
        (group / 'cgroup.events').write_text(f'populated {1 if active else 0}\nfrozen 0\n')

    def observe(self, *, load=True):
        install.observe_maintenance_engine(self.stage, self.index_value, self.account, self.runtime, self.end, allow_load=load)

    def assert_clean(self):
        self.assertFalse((self.managed / install.LEASE_NAME).exists())
        self.assertEqual(list(self.managed.glob(install.SPOOL_PREFIX + '*')), [])

    def test_pre_native_restorecon_failure_removes_exact_spool_and_allows_retry(self):
        with self.native():
            self.restorecon_error = protocol.Blocked('fixture restorecon failed')
            for _attempt in range(2):
                with self.assertRaisesRegex(protocol.Blocked, 'restorecon failed'):
                    self.observe()
                self.assert_clean()
            self.assertEqual(self.launches, [])
            self.restorecon_error = None
            self.observe()
            self.assert_clean()
            self.assertEqual(self.launches, ['info', 'exists', 'load', 'inspect'])

    def test_interrupted_load_retains_lease_reaps_exact_unit_and_reuses_imported_image(self):
        def interrupted(unit, description):
            self.has_image = True  # Engine completed its store write before launch transport timed out.
            self.failed_unit(unit, description, active=True)
            raise subprocess.TimeoutExpired('fixture systemd-run', 1)

        with self.native():
            self.load_error = interrupted
            with self.assertRaises(subprocess.TimeoutExpired):
                self.observe()
            path = self.managed / install.LEASE_NAME
            first = protocol.json_bytes(path.read_bytes())
            owned = self.managed / (install.SPOOL_PREFIX + first['nonce'])
            self.assertTrue((owned / 'partial').is_file())
            self.assertEqual(first['unit']['operation'], 'load')
            foreign = self.managed / (install.SPOOL_PREFIX + 'foreign')
            foreign.mkdir()
            self.observe()
            self.assertEqual(self.stops[-1], first['unit']['name'])
            self.assertFalse(owned.exists())
            self.assertTrue(foreign.is_dir())
            self.assertFalse(path.exists())
            self.assertEqual(self.launches, ['info', 'exists', 'load', 'info', 'exists', 'inspect'])

    def test_known_failed_owned_load_is_cleaned_before_a_fresh_launch(self):
        def failed(unit, description):
            self.failed_unit(unit, description)
            raise protocol.Blocked('fixture native command failed with status 125')

        with self.native():
            self.load_error = failed
            with self.assertRaisesRegex(protocol.Blocked, '125'):
                self.observe()
            owned = protocol.json_bytes((self.managed / install.LEASE_NAME).read_bytes())['unit']['name']
            self.load_error = None
            self.observe()
            self.assertIn(owned, self.stops)
            self.assertEqual(self.launches.count('load'), 2)
            self.assert_clean()

    def test_uncertain_same_boot_or_foreign_unit_retains_exact_fence(self):
        with self.native():
            error = subprocess.TimeoutExpired('fixture transport', 1)
            self.load_error = mock.Mock(side_effect=error)
            with self.assertRaises(subprocess.TimeoutExpired):
                self.observe()
            path = self.managed / install.LEASE_NAME
            first = path.read_bytes()
            record = protocol.json_bytes(first)
            unit = record['unit']['name']
            with self.assertRaisesRegex(protocol.Blocked, 'launch is uncertain'):
                self.observe()
            self.failed_unit(unit, 'foreign manager metadata', active=True)
            with self.assertRaisesRegex(protocol.Blocked, 'ownership differs'):
                self.observe()
            self.assertEqual(path.read_bytes(), first)
            self.assertNotIn(unit, self.stops)
            self.assertEqual(self.launches.count('load'), 1)

    def test_changed_boot_reconciles_absent_old_unit_before_readonly_inspection(self):
        with self.native():
            self.load_error = mock.Mock(side_effect=subprocess.TimeoutExpired('fixture launch', 1))
            with self.assertRaises(subprocess.TimeoutExpired):
                self.observe()
            self.booted = '22222222-2222-2222-2222-222222222222'
            self.has_image = True
            self.observe(load=False)
            self.assertEqual(self.launches, ['info', 'exists', 'load', 'info', 'inspect'])
            self.assert_clean()

    def test_owned_unit_with_surviving_cgroup_keeps_fence_and_prohibits_second_native_run(self):
        def interrupted(unit, description):
            self.has_image = True
            self.failed_unit(unit, description, active=True)
            raise subprocess.TimeoutExpired('fixture launch', 1)

        with self.native():
            self.load_error = interrupted
            with self.assertRaises(subprocess.TimeoutExpired):
                self.observe()
            path = self.managed / install.LEASE_NAME
            first = path.read_bytes()
            record = protocol.json_bytes(first)
            self.stop_releases_group = False
            with self.assertRaisesRegex(protocol.Blocked, 'native process cleanup is unresolved'):
                self.observe()
            retired = protocol.json_bytes(path.read_bytes())
            self.assertEqual(retired, {**record, 'unit': {**record['unit'], 'quiesced': True}})
            self.assertEqual(self.launches, ['info', 'exists', 'load'])
            self.assertEqual(self.stops[-1], record['unit']['name'])
            (self.cgroups / record['unit']['name'] / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
            self.observe()
            self.assertEqual(self.launches, ['info', 'exists', 'load', 'info', 'exists', 'inspect'])
            self.assert_clean()

    def test_exhausted_retry_reclaims_only_owned_spool_before_fresh_capacity_check(self):
        def interrupted(unit, description):
            self.has_image = True
            self.failed_unit(unit, description, active=True)
            raise subprocess.TimeoutExpired('fixture launch', 1)

        with self.native():
            self.load_error = interrupted
            with self.assertRaises(subprocess.TimeoutExpired):
                self.observe()
            path = self.managed / install.LEASE_NAME
            record = protocol.json_bytes(path.read_bytes())
            spool = self.managed / (install.SPOOL_PREFIX + record['nonce'])
            unrelated = self.managed / 'unrelated'
            unrelated.write_bytes(b'preserve')
            volume_readback = []

            def exhausted(graph, *, for_recovery=False):
                volume_readback.append((for_recovery, spool.exists()))
                return {**self.capacity, 'available_inodes': 0 if spool.exists() else 3,
                        'available_bytes': 0 if spool.exists() else 3 * 4096}

            with (mock.patch.object(install, 'volume_identity', side_effect=exhausted),
                  mock.patch.object(install, 'bounded_volume', wraps=self.real_bounded_volume),
                  mock.patch.object(install, 'replace_observation', side_effect=OSError(errno.ENOSPC, 'fixture full'))):
                with self.assertRaisesRegex(protocol.Blocked, 'inode headroom'):
                    self.observe()
            self.assertEqual(volume_readback, [(True, True), (False, False)])
            self.assertEqual(self.stops[-1], record['unit']['name'])
            self.assertEqual(self.launches, ['info', 'exists', 'load'])
            self.assertEqual(unrelated.read_bytes(), b'preserve')
            self.assert_clean()
            self.observe()
            self.assertEqual(self.launches, ['info', 'exists', 'load', 'info', 'exists', 'inspect'])
            self.assert_clean()

    real_bounded_volume = staticmethod(install.bounded_volume)

    def test_reobserve_uses_approved_history_and_real_receipt_reader_without_loading_or_redeploying(self):
        with self.native(), ExitStack() as stack:
            producer = 'a' * 64
            part = self.stage / 'maintenance/part.json'
            part.write_bytes(protocol.canonical({'producer': {'result_sha256': producer}}))
            self.index_value['transports'] = {'maintenance': {'files': {'part.json': {
                'sha256': release.digest(part.read_bytes()), 'bytes': part.stat().st_size}}}}
            old_boot = self.boot
            self.booted = '22222222-2222-2222-2222-222222222222'
            self.has_image = True

            def write(path, raw):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(0o600)

            account_path = install.ADAPTER / self.context / 'imported-releases' / self.platform / self.image
            ordinary_json = release.readonly_json
            stack.enter_context(mock.patch.object(release, 'readonly_json', side_effect=lambda path, _owner=None:
                                ordinary_json(path)))
            historical = install.maintenance_admission(self.stage, self.index_value, old_boot)
            historical_raw = install.gptbox.image_inputs_bytes(historical)
            write(account_path / (old_boot + '.json'), historical_raw)
            old_import_path = self.stage / 'maintenance-import.json'
            expected_old = install.maintenance_import_record(self.stage, self.index_value, self.runtime, old_boot)
            write(old_import_path, protocol.canonical(expected_old))
            installed_path = self.stage / 'installed.json'
            bindings = install.maintenance_bindings(self.stage, self.index_value)
            installed = {'schema': 1, 'platform_sha256': self.platform, 'base_platform_sha256': self.platform,
                         'site_config_sha256': self.site, 'source_sha': self.source, 'boot_id': old_boot,
                         'components': {'development': {}, 'devbox': {}, 'host': {},
                                        'maintenance': install.maintenance_result(bindings, historical_raw)}}
            write(installed_path, protocol.canonical(installed))
            for name, value in {'site_configuration': self.config, 'machine': self.booted, 'exact_local_programs': None,
                                'maintenance_identity': (self.account, self.runtime), 'stage_budget': None}.items():
                stack.enter_context(mock.patch.object(install, name, return_value=value))
            stack.enter_context(mock.patch.object(install.intake, 'retained_index', return_value=(self.stage, self.index_value, 'b' * 64)))
            stack.enter_context(mock.patch.object(install, 'file_hash', side_effect=lambda path, limit, end, **_:
                                protocol.file_hash(path, limit, end)))
            authority = stack.enter_context(mock.patch.object(install, 'approved_maintenance_selection', return_value=('c' * 64,)))
            placement = stack.enter_context(mock.patch.object(install, 'approved_placement'))
            host = stack.enter_context(mock.patch.object(install, 'install_host'))

            probes = []

            def command(argv, end, *args, **kwargs):
                if argv[0] == '/usr/bin/python3':
                    phase = argv[argv.index('--phase') + 1]
                    self.assertIn('verify-installed-maintenance', argv)
                    probes.append(phase)
                    if phase == 'preflight':
                        return 0, protocol.canonical({'schema': 1, 'phase': phase, **bindings, 'boot_id': self.booted})
                    self.assertEqual(protocol.json_bytes(old_import_path.read_bytes())['boot_id'], self.booted)
                    live = install.maintenance_admission(self.stage, self.index_value, self.booted)
                    write(account_path / (self.booted + '.json'), install.gptbox.image_inputs_bytes(live))
                    return 0, b''
                return self.command(argv, end, *args, **kwargs)

            stack.enter_context(mock.patch.object(install, 'bounded', side_effect=command))
            authority.side_effect = protocol.Blocked('fixture unselected candidate')
            with self.assertRaisesRegex(protocol.Blocked, 'unselected candidate'):
                install.reobserve_maintenance(self.platform, self.site, self.end)
            self.assertEqual(self.launches, [])
            authority.side_effect = None
            live = install.reobserve_maintenance(self.platform, self.site, self.end)
            self.assertEqual(live['oci_config_sha256'], self.image)
            self.assertEqual(self.launches, ['info', 'inspect'])
            self.assertEqual(probes, ['preflight', 'verify'])
            self.assertEqual(installed_path.read_bytes(), protocol.canonical(installed))
            self.assertEqual((account_path / (old_boot + '.json')).read_bytes(), historical_raw)
            self.assertEqual(live['result_sha256'], release.digest((account_path / (self.booted + '.json')).read_bytes()))
            placement.assert_not_called()
            host.assert_not_called()
            self.assert_clean()

    def test_reobservation_authority_follows_selected_and_exact_rollback_release(self):
        with self.native():
            control = self.managed / 'renewal'
            for path in ('plans', 'platform-bindings', '../renewal-fence'):
                (control / path).mkdir(parents=True, exist_ok=True)
            current, target = 'b' * 64, 'c' * 64
            reference = 'd' * 64
            attempt = SimpleNamespace(name='attempt-digest')
            journal = {'schema': 1, 'attempt_id': attempt.name, 'phase': 'rolling-back',
                       'request': {'scope': 'agent', 'previous_sha256': current, 'target_sha256': target}}
            plan = protocol.canonical({'maintenance_context_sha256': self.context})
            plan_sha = release.digest(plan)
            (control / 'plans' / (plan_sha + '.json')).write_bytes(plan)
            maintenance = {'source_revision': self.source, 'artifact_sha256': self.image, 'codex_version': '0.169.0',
                           'platform_sha256': self.platform}
            retained = {'plan_sha256': plan_sha, 'config_sha256': self.config['host_config_sha256'],
                        'components': {'maintenance-agent': maintenance}}
            other = {**retained, 'components': {'maintenance-agent': {**maintenance, 'platform_sha256': reference}}}
            controller = SimpleNamespace(control=control, live_release=lambda: current,
                                         release={current: retained, target: other}.__getitem__,
                                         transition=lambda: (attempt, journal))
            renewal = SimpleNamespace(Renewal=lambda *_: controller,
                                      read_json=lambda path: protocol.json_bytes(path.read_bytes()),
                                      checked_request=lambda request, _scope: request)
            selected = control / 'site-current.json'
            marker = self.managed / 'renewal-fence/frozen'
            approved = lambda: install.approved_maintenance_selection(
                self.stage, self.index_value, self.platform, 'e' * 64, self.site, self.config)
            with mock.patch.dict(sys.modules, {'renewal': renewal}):
                selected.write_bytes(protocol.canonical(current))
                self.assertEqual(approved(), (current,))
                selected.write_bytes(protocol.canonical(target))
                with self.assertRaisesRegex(protocol.Blocked, 'current and live site selection differ'):
                    approved()
                marker.write_bytes(protocol.canonical(attempt.name))
                self.assertEqual(approved(), (current,))
                journal['phase'] = 'accepted'
                with self.assertRaisesRegex(protocol.Blocked, 'not selected by an exact approved local release'):
                    approved()
