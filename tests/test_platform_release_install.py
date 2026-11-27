import os
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


class PlatformReleaseInstallerTests(unittest.TestCase):
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
            mock.patch.object(install, 'protected_json', side_effect=lambda path: (receipt, protocol.canonical(receipt))) as observed,
        ):
            expected = install.maintenance_probe(stage, self.index(), 'verify', self.end)
            self.assertEqual(expected['result_sha256'], release.digest(protocol.canonical(receipt)))
            self.assertTrue(str(observed.call_args.args[0]).endswith(f'/imported-releases/{self.image}.json'))
            self.assertIn('verify-installed-maintenance', command.call_args.args[0])
            receipt['kind'] = 'maintenance-gptbox-probe-candidate'
            with self.assertRaisesRegex(protocol.Blocked, 'actual restricted native maintenance probe'):
                install.maintenance_probe(stage, self.index(), 'verify', self.end)
