"""Commissioning discovery against the ordinary protected F and U input schemas."""
from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest
from unittest.mock import patch

import commission_host as c
import platform_release as publication
import platform_release_install as installer
import platform_release_protocol as protocol
import test_platform_release as fixtures

BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
MACHINE = 'a' * 32


@unittest.skipUnless(os.geteuid() == 0, 'requires isolated mapped-root authority files')
class Authorities(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/run')))
        self.portable = self.root / 'platform-releases'
        self.site = self.root / 'site-configs'
        self.hosts = self.root / 'host-releases'
        for path in (self.site, self.hosts, self.portable):
            path.mkdir(mode=0o700)
        self.enterContext(patch.object(installer.intake, 'ROOT', self.portable))
        self.enterContext(patch.object(installer, 'SITE_CONFIGS', self.site))
        self.enterContext(patch.object(installer, 'HOST_CONFIGS', self.hosts))
        self.live = object.__new__(c.Live)
        self.live.installer = installer
        self.live.bootstrap = SimpleNamespace(destination_identity=lambda: {'machine_id': MACHINE, 'boot_id': BOOT})

    def approved_full(self):
        fixture = fixtures.PlatformReleaseTests()
        fixture.root = self.root
        source, revision = fixture.git_repo()
        host = self.root / 'host-package'
        host_sha = publication.build_host(source, revision, host)
        roles = ('maintenance', 'development', 'devbox', 'host')
        records = {}
        for role in roles:
            if role == 'host':
                continue
            records[protocol.COMPONENT[role]] = {'source_sha': revision, 'context_sha256': 'b' * 64,
                'oci_config_sha256': 'c' * 64, 'oci_manifest_sha256': 'd' * 64, 'archive_sha256': 'e' * 64,
                'archive_bytes': 123}
            if role != 'devbox':
                records[protocol.COMPONENT[role]].update(codex_version='0.169.0',
                    codex_source_sha='f' * 40, codex_sha256='f' * 64)
        records['host'] = {'bundle_manifest_sha256': host_sha, 'source_sha': revision}
        transfers = {}
        for role in roles:
            if role == 'host':
                files = {path.name: {'sha256': c.digest(path.read_bytes()), 'bytes': path.stat().st_size}
                         for path in host.iterdir()}
            else:
                files = {'part.json': {'sha256': 'a' * 64, 'bytes': 123},
                         role + '.oci.tar': {'sha256': 'e' * 64, 'bytes': 123}}
            transfers[role] = {'name': f'platform-{role}-{revision}', 'files': files}
        index = {'schema': 2, 'kind': 'dev-pair-platform-release', 'repository': 'oso-gato/dev-pair',
                 'source_sha': revision, 'publisher_run': 123, 'standards_sha': protocol.STANDARDS,
                 'contracts': {'ledger': 1, 'state': 1, 'release_policy': 1},
                 'previous_platform_sha256': None, 'base_platform_sha256': None,
                 'components': records, 'transports': transfers}
        platform = c.digest(protocol.canonical(index))
        stage = self.portable / platform
        stage.mkdir(mode=0o700)
        host.rename(stage / 'host')
        self.write(stage / 'platform.json', protocol.canonical(index))
        self.write(stage / 'intake.json', protocol.canonical({'schema': 2, 'platform_sha256': platform,
                   'source_sha': revision, 'publisher_run': 123, 'kind': index['kind']}))
        return platform, revision

    def write(self, path, contents):
        path.write_bytes(contents)
        path.chmod(0o600)

    def test_discover_authentic_protected_intake_and_site_then_read_exact_host_bundle(self):
        platform, revision = self.approved_full()
        self.assertEqual(self.live.initial_platform(revision), platform)
        with self.assertRaisesRegex(c.Pending, 'initial-site-config') as pending:
            self.live.initial_site('erebus')
        self.assertEqual(pending.exception.report['phase'], 'source-gap')
        profile = c.encoded({'schema': 1, 'hostname': 'erebus', 'platform': 'fedora-44', 'selinux': 'enforcing',
                             'launch_contract': 1, 'role_launch_seconds': 145})
        site = {'schema': 1, 'hostname': 'erebus', 'host_config_sha256': c.digest(profile),
                'jobs': {'checklist': {'storage_bytes': 8 * 1024**3, 'categories': {'inner': [12, 13], 'outer': [12, 13, 14]}}}}
        raw = protocol.canonical(site)
        site_sha = c.digest(raw)
        self.write(self.site / (site_sha + '.json'), raw)
        self.assertEqual(self.live.initial_site('erebus'), (site_sha, site))
        path, exact = self.live.initial_host_profile(site, {'host': 'erebus'})
        self.assertEqual((Path(path), exact), (self.hosts / (c.digest(profile) + '.json'), profile))
        self.assertFalse(Path(path).exists())
        self.write(Path(path), exact)
        policy = {'platform_sha256': platform, 'source_sha': revision, 'site_config_sha256': site_sha}
        with patch.object(installer, 'machine', return_value=BOOT):
            observed, files = self.live.authority(policy)
        self.assertEqual(observed, site)
        self.assertIn('tools/fixture.py', files)
        with self.assertRaisesRegex(c.Pending, 'initial-host-config'):
            self.live.initial_host_profile({**site, 'host_config_sha256': '0' * 64}, {'host': 'erebus'})

    def test_missing_release_policy_and_missing_initial_selection_are_distinct(self):
        import release_trust
        policy = self.root / 'release-trust.json'
        credential = self.root / 'hosts.yml'
        publisher = {'workflow': '.github/workflows/platform-release.yml', 'sha256': '1' * 64, 'registry': None}
        trust = {'version': 1, 'writer_app_id': 123, 'reviewer_ids': [456],
                 'check': {'context': 'release-source-check', 'app_id': 123,
                           'workflow': '.github/workflows/release-check.yml', 'sha256': '2' * 64},
                 'components': {role: publisher for role in ('host', 'devbox', 'maintenance', 'development')}}
        with patch.object(release_trust, 'POLICY', policy), \
                patch.object(installer.intake, 'native_env', return_value={'GH_CONFIG_DIR': str(self.root)}), \
                patch.object(installer.intake, 'GITHUB', '/usr/bin/true'):
            self.live.run = lambda *args, **kwargs: self.fail('read-only discovery tried to contact a remote')
            for expected, phase in [('release-trust', 'pending'), ('release-read-custody', 'pending'),
                                    ('initial-full-release-selection', 'source-gap')]:
                with self.assertRaisesRegex(c.Pending, expected) as pending:
                    self.live.initial_platform('a' * 40)
                self.assertEqual(pending.exception.report['phase'], phase)
                if expected == 'release-trust':
                    self.write(policy, c.encoded(trust))
                elif expected == 'release-read-custody':
                    self.write(credential, b'fixture custody\n')

    def test_missing_tls_custody_holds_checklist_before_topology(self):
        with patch.object(c, 'CHECKLIST_SERVER', str(self.root / 'checklist-server')):
            with self.assertRaisesRegex(c.Pending, 'checklist-peer-custody') as pending:
                self.live.initial_checklist({'machine_id': MACHINE}, {}, 'a' * 40)
        self.assertEqual(pending.exception.report['phase'], 'pending')

    def test_first_checklist_geometry_depends_on_managed_capacity_and_id_checks(self):
        import destination_release as destination
        import host_handoff

        tls = self.root / 'server-profile'
        tls.mkdir(mode=0o700)
        for name in c.TLS_FILES:
            self.write(tls / name, b'credential fixture only\n')
        intent, ready, provision = (self.root / name for name in ('mount-intent', 'mount-ready', 'provision'))
        record = {'machine_id': MACHINE, 'filesystem': {'scope': 'fixture'}}
        for path in (intent, ready):
            self.write(path, c.encoded(record))
        observed = SimpleNamespace(record=lambda path: record, mount_observation=lambda *args, **kwargs: None,
                                   subid=lambda *args: False)
        volume = SimpleNamespace(f_bavail=20 * 1024**3, f_frsize=1, f_favail=100000)
        site = {'jobs': {'checklist': {'storage_bytes': 8 * 1024**3}}}
        with patch.object(c, 'CHECKLIST_SERVER', str(tls)), \
                patch.object(destination, 'MANAGED_INTENT', str(intent)), patch.object(destination, 'MANAGED_READY', str(ready)), \
                patch.object(destination, 'PROVISION', str(provision)), patch.object(destination, 'Destination', return_value=observed), \
                patch.object(host_handoff, 'tls_principal'), patch.object(c.pwd, 'getpwall', return_value=[]), \
                patch.object(c.grp, 'getgrall', return_value=[]), patch.object(c.os, 'statvfs', return_value=volume):
            selected = self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)
            self.assertEqual(selected, {'tls_profile': str(tls), **c.DEFAULT_CHECKLIST})
            volume.f_bavail = 1024**3
            with self.assertRaisesRegex(c.Pending, 'checklist-storage-capacity'):
                self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)
            observed.subid = lambda *args: True
            with self.assertRaisesRegex(c.Pending, 'checklist-account-allocation'):
                self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)
