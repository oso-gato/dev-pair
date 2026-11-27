"""Commissioning discovery against the ordinary protected F and U input schemas."""
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace
import os
import shutil
import socket
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
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
        import renewal_site
        self.live.resolver = renewal_site
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
        with self.assertRaises(FileNotFoundError):
            self.live.verify_initial_parts(platform)
        with self.assertRaisesRegex(c.Pending, 'initial-host-config'):
            self.live.initial_host_profile({**site, 'host_config_sha256': '0' * 64}, {'host': 'erebus'})

    def test_missing_release_policy_and_missing_initial_selection_are_distinct(self):
        import release_trust
        policy = self.root / 'release-trust.json'
        credential = self.root / 'hosts.yml'
        gh = self.root / 'gh-fixture'
        self.write(gh, b'#!/bin/sh\nexit 1\n')
        gh.chmod(0o755)
        publisher = {'workflow': '.github/workflows/platform-release.yml', 'sha256': '1' * 64, 'registry': None}
        trust = {'version': 1, 'writer_app_id': 123, 'reviewer_ids': [456],
                 'check': {'context': 'release-source-check', 'app_id': 123,
                           'workflow': '.github/workflows/release-check.yml', 'sha256': '2' * 64},
                 'components': {role: publisher for role in ('host', 'devbox', 'maintenance', 'development')}}
        with patch.object(release_trust, 'POLICY', policy), \
                patch.object(installer.intake, 'native_env', return_value={'GH_CONFIG_DIR': str(self.root)}), \
                patch.object(installer.intake, 'GITHUB', str(gh)):
            self.live.run = lambda *args, **kwargs: self.fail('read-only discovery tried to contact a remote')
            selection_phase = 'pending' if hasattr(installer.intake, 'acquire_initial') else 'source-gap'
            for expected, phase in [('release-trust', 'pending'), ('release-read-custody', 'pending'),
                                    ('initial-full-release-selection', selection_phase)]:
                with self.assertRaisesRegex(c.Pending, expected) as pending:
                    self.live.initial_platform('a' * 40)
                self.assertEqual(pending.exception.report['phase'], phase)
                if expected == 'release-trust':
                    self.write(policy, c.encoded(trust))
                elif expected == 'release-read-custody':
                    self.write(credential, b'fixture custody\n')
            for content, mode in ((b'', 0o600), (b'mode fixture\n', 0o644), (b'x' * (128 * 1024 + 1), 0o600)):
                self.write(credential, content)
                credential.chmod(mode)
                with self.assertRaisesRegex(c.Pending, 'release-read-custody'):
                    self.live.initial_platform('a' * 40)
            self.write(credential, b'fixture credential custody\n')
            gh.chmod(0o644)
            with self.assertRaisesRegex(c.Pending, 'release-read-custody'):
                self.live.initial_platform('a' * 40)

    def test_missing_tls_custody_holds_checklist_before_topology(self):
        with patch.object(c, 'CHECKLIST_SERVER', str(self.root / 'checklist-server')):
            with self.assertRaisesRegex(c.Pending, 'checklist-peer-custody') as pending:
                self.live.initial_checklist({'machine_id': MACHINE}, {}, 'a' * 40)
        self.assertEqual(pending.exception.report['phase'], 'pending')

    def test_hardlinked_peer_is_never_a_private_tls_input(self):
        tls = self.root / 'profile'
        tls.mkdir(mode=0o700)
        self.write(tls / 'cert.pem', b'fixture cert\n')
        alternate = self.root / 'shared-peer'
        self.write(alternate, b'other data\n')
        os.link(alternate, tls / 'peer.pem')
        with patch.object(c, 'CHECKLIST_SERVER', str(tls)):
            with self.assertRaisesRegex(c.Blocked, 'ancestry or inode'):
                self.live.initial_checklist({'machine_id': MACHINE}, {}, 'a' * 40)

    def test_atomic_publication_recovers_process_death_and_preserves_concurrent_owner(self):
        app = c.Commission(self.root, Path('/'), None, 0, self.live)
        real_link = os.link
        raw = b'protected fixture\n'
        for after in (False, True):
            target = self.site / ('after.json' if after else 'before.json')
            child = os.fork()
            if child == 0:
                def interrupted_link(*args, **kwargs):
                    if after:
                        real_link(*args, **kwargs)
                    os._exit(71)

                with patch.object(c.os, 'link', side_effect=interrupted_link):
                    app.file(str(target), raw, 0o600)
                os._exit(72)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 71)
            self.assertEqual(list(self.site.iterdir()), [target] if after else [])
            if after:
                self.assertEqual(target.stat().st_nlink, 1)
                with patch.object(app, 'sync', wraps=app.sync) as sync:
                    app.file(str(target), raw, 0o600)
                sync.assert_called_once_with(self.site)
            else:
                app.file(str(target), raw, 0o600)
            self.assertEqual((target.read_bytes(), target.stat().st_nlink), (raw, 1))
            target.unlink()

        target = self.site / 'contested.json'
        different = b'other exact owner\n'

        def concurrent(*args, **kwargs):
            self.write(target, different)
            real_link(*args, **kwargs)

        with patch.object(c.os, 'link', side_effect=concurrent):
            with self.assertRaisesRegex(c.Blocked, 'installed commissioning bytes changed'):
                app.file(str(target), raw, 0o600)
        self.assertEqual((target.read_bytes(), target.stat().st_nlink), (different, 1))
        self.assertEqual(list(self.site.iterdir()), [target])

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
        volume = SimpleNamespace(f_bavail=20 * 1024**3, f_frsize=1, f_favail=9000)
        site = {'jobs': {'checklist': {'storage_bytes': 8 * 1024**3}}}
        with patch.object(c, 'CHECKLIST_SERVER', str(tls)), \
                patch.object(destination, 'MANAGED_INTENT', str(intent)), patch.object(destination, 'MANAGED_READY', str(ready)), \
                patch.object(destination, 'PROVISION', str(provision)), patch.object(destination, 'Destination', return_value=observed), \
                patch.object(host_handoff, 'tls_principal'), patch.object(c.pwd, 'getpwall', return_value=[]), \
                patch.object(c.grp, 'getgrall', return_value=[]), patch.object(c.os, 'statvfs', return_value=volume):
            selected = self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)
            self.assertEqual(selected, {'tls_profile': str(tls), **c.DEFAULT_CHECKLIST})
            volume.f_favail = 1024
            with self.assertRaisesRegex(c.Pending, 'checklist-storage-capacity'):
                self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)
            volume.f_favail = 9000
            volume.f_bavail = 4 * 1024**3
            self.assertEqual(self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40, placed=True), selected)
            volume.f_bavail = 1024**3
            with self.assertRaisesRegex(c.Pending, 'checklist-storage-capacity'):
                self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)
            observed.subid = lambda *args: True
            with self.assertRaisesRegex(c.Pending, 'checklist-account-allocation'):
                self.live.initial_checklist({'machine_id': MACHINE}, site, 'a' * 40)

    def test_first_day0_site_publishes_observed_exclusive_default_and_preserves_it_on_resume(self):
        import gptbox
        import native_placements as native

        source, origin, image, context = 'b' * 40, 'e' * 40, 'c' * 64, 'd' * 64
        observed = {'host': 'erebus', 'machine_id': MACHINE, 'boot_id': BOOT, 'arch': 'x86_64',
                    'pid1': 'systemd', 'selinux': '1', 'os_release': 'ID=fedora\nVERSION_ID=44\n'}
        day0 = self.root / 'day0-progress.json'
        self.write(day0, c.encoded({'schema': 1, 'source_sha': origin, 'machine_id': MACHINE,
                                  'phase': 'host-bootstrap-complete', 'next': 'fixture verified host'}))
        checked = []
        self.live.bootstrap.status = lambda: {'prepared': True, 'phase': 'tailnet-only'}
        self.live.bootstrap.verify_final_guard = lambda: checked.append('guard')
        self.live.bootstrap.verify_final_ssh = lambda: checked.append('ssh')
        self.live.identity = lambda: {key: observed[key] for key in ('boot_id', 'machine_id')}
        self.live.inventory = lambda revision: observed
        self.live.check_initial_capacity = lambda identity, site: checked.append('native-capacity')
        probe = SimpleNamespace(lock=nullcontext, maintenance_host_readiness=lambda candidate: checked.append(candidate)
                                or {'source_sha': origin, 'context_sha256': context},
                                read_config_record=lambda path: (b'', {'gptbox_context_sha256': context,
                                                                        'assembled_image_id': image}),
                                admitted_maintenance_image=lambda *ids: checked.append(ids))
        app = c.Commission(self.root, Path('/'), None, 0, self.live)
        path = str(self.root / 'initial')
        cache = str(self.root / 'auto.json')
        with patch.object(c, 'DAY0_PROGRESS', str(day0)), patch.object(c, 'PRIVATE', path), \
                patch.object(c, 'INITIAL_SITE', path + '/initial-site.json'), patch.object(c, 'AUTOMATIC_POLICY', cache), \
                patch.object(gptbox, 'Gptbox', return_value=probe), patch.object(native, 'role_account', return_value=None), \
                patch.object(native, 'used_categories', return_value={1021, 1023}), patch.object(native, 'ROOT', self.root / 'placement'), \
                patch.object(self.live, 'initial_platform', side_effect=c.Pending('release-trust', 'first external inlet')):
            with self.assertRaisesRegex(c.Pending, 'initial-site-config'):
                app.automatic('status', source)
            self.assertFalse(Path(path).exists())
            with self.assertRaisesRegex(c.Pending, 'release-trust'):
                app.automatic('apply', source)
            self.assertFalse(Path(cache).exists())
            site_sha, site = self.live.initial_site('erebus')
            self.assertEqual(site['jobs'], {c.DEFAULT_SITE_SLOT:
                {'storage_bytes': c.DEFAULT_SITE_BYTES, 'categories': {'outer': [1019, 1020, 1022], 'inner': [1019, 1020]}}})
            intent = Path(c.INITIAL_SITE)
            before = intent.read_bytes()
            self.assertEqual((c.parse(before)['source_sha'], c.parse(before)['bootstrap_source_sha']), (source, origin))
            expected = ('guard', 'ssh', context, (context, origin, image), 'native-capacity')
            self.assertEqual(tuple(checked), expected)
            (self.site / (site_sha + '.json')).unlink()
            substituted = {**site, 'jobs': {'job-2': site['jobs'][c.DEFAULT_SITE_SLOT]}}
            substitution = c.encoded(substituted)
            competing = self.site / (c.digest(substitution) + '.json')
            self.write(competing, substitution)
            self.assertEqual(self.live.initial_site('erebus')[1], substituted)
            for action in ('discover', 'prepare', 'apply'):
                with self.subTest(action=action):
                    with self.assertRaisesRegex(c.Blocked, 'selected site differs from the protected first-site intent'):
                        app.automatic(action, source)
            with self.assertRaisesRegex(c.Blocked, 'selected site differs from the protected first-site intent'):
                app.apply({'machine_id': MACHINE, 'site_config_sha256': competing.stem}, None, BOOT, substituted, {})
            self.assertEqual(competing.read_bytes(), substitution)
            competing.unlink()
            with self.assertRaisesRegex(c.Pending, 'release-trust'):
                app.automatic('apply', source)
            self.assertEqual(self.live.initial_site('erebus'), (site_sha, site))
            self.assertEqual(intent.read_bytes(), before)
            self.assertEqual(checked.count('native-capacity'), 1)
            host_path = self.hosts / (site['host_config_sha256'] + '.json')
            host_bytes = host_path.read_bytes()
            host_path.unlink()
            with self.assertRaisesRegex(c.Pending, 'initial-host-config'):
                app.automatic('discover', source)
            with self.assertRaisesRegex(c.Pending, 'release-trust'):
                app.automatic('prepare', source)
            self.assertEqual(host_path.read_bytes(), host_bytes)
            wrong_host = c.encoded({**c.parse(host_bytes), 'role_launch_seconds': 100})
            self.write(host_path, wrong_host)
            with self.assertRaisesRegex(c.Blocked, 'host profile differs from the protected first-site intent'):
                app.automatic('prepare', source)
            self.assertEqual(host_path.read_bytes(), wrong_host)

    def test_first_local_checklist_pair_joins_interrupted_publish_and_authenticates(self):
        from bootstrap import Blocked as BootstrapBlocked
        import destination_release as destination
        from host_handoff import tls_principal

        source = 'b' * 40
        observed = {'machine_id': MACHINE}
        openssl = self.root / 'openssl'
        shutil.copyfile('/usr/bin/openssl', openssl)
        openssl.chmod(0o700)
        private, server, client, stage = (self.root / name for name in ('commission', 'server', 'client', 'stage'))
        self.live.first_site_authority = lambda *args: 'e' * 40
        app = c.Commission(self.root, Path('/'), None, 0, self.live)

        def run(*args, timeout):
            result = subprocess.run(args, capture_output=True, timeout=timeout)
            if result.returncode:
                raise BootstrapBlocked(result.stderr.decode())
            return result.stdout

        self.live.run = run
        real_rename = os.rename

        def interrupt(source, target):
            if Path(target) == client:
                raise InterruptedError('paused publishing distinct client')
            real_rename(source, target)

        with patch.object(c, 'PRIVATE', str(private)), patch.object(c, 'CHECKLIST_SERVER', str(server)), \
                patch.object(c, 'CHECKLIST_CLIENT', str(client)), patch.object(c, 'OPENSSL', str(openssl)), \
                patch.object(c, 'LOCAL_CHECKLIST_TLS', str(stage)), patch.object(destination, 'PROVISION', self.root / 'provision'):
            client.mkdir(mode=0o700)
            with self.assertRaisesRegex(c.Pending, 'checklist-peer-custody'):
                self.live.prepare_checklist_pair(app, observed, source)
            self.assertFalse(stage.exists())
            client.rmdir()
            previous = os.umask(0o077)
            try:
                with patch.object(self.live, 'run', side_effect=BootstrapBlocked('local crypto configuration')):
                    with self.assertRaisesRegex(c.Pending, 'checklist-local-crypto'):
                        self.live.prepare_checklist_pair(app, observed, source)
                self.assertFalse(server.exists() or client.exists())
                with patch.object(c.os, 'rename', side_effect=interrupt):
                    with self.assertRaisesRegex(InterruptedError, 'paused publishing'):
                        self.live.prepare_checklist_pair(app, observed, source)
                saved_server = (server / 'cert.pem').read_bytes()
                self.assertFalse(client.exists())
                self.live.prepare_checklist_pair(app, observed, source)
                self.live.prepare_checklist_pair(app, observed, source, issue=False)
            finally:
                os.umask(previous)
            self.assertEqual((server / 'cert.pem').read_bytes(), saved_server)
            self.assertNotEqual((server / 'key.pem').read_bytes(), (client / 'key.pem').read_bytes())
            for path in (server, client):
                self.assertEqual({p.name for p in path.iterdir()}, set(c.TLS_FILES))
                self.assertEqual((path / 'key.pem').stat().st_mode & 0o777, 0o600)
            external_stage = self.root / 'external-stage'
            with patch.object(c, 'PRIVATE', str(self.root / 'external')), \
                    patch.object(c, 'LOCAL_CHECKLIST_TLS', str(external_stage)), \
                    patch.object(self.live, 'first_site_authority', side_effect=AssertionError('replaced external TLS')):
                self.live.prepare_checklist_pair(app, observed, source)
                self.assertFalse(external_stage.exists())
            left, _, pins = tls_principal(server, maintenance=True)
            right, _, _ = tls_principal(client, maintenance=False)
            server_socket, client_socket = socket.socketpair()

            def answer():
                with left.wrap_socket(server_socket, server_side=True) as stream:
                    self.assertEqual(stream.recv(4), b'ping')
                    stream.sendall(b'pong')
                    return c.digest(stream.getpeercert(binary_form=True))

            with server_socket, client_socket, ThreadPoolExecutor(max_workers=1) as worker:
                server_socket.settimeout(3)
                client_socket.settimeout(3)
                response = worker.submit(answer)
                with right.wrap_socket(client_socket) as stream:
                    self.assertEqual(c.digest(stream.getpeercert(binary_form=True)), pins[1])
                    stream.sendall(b'ping')
                    self.assertEqual(stream.recv(4), b'pong')
                self.assertEqual(response.result(timeout=3), pins[0])
            saved = (stage / 'pair.json').read_bytes()
            invalid = c.parse(saved)
            invalid['profiles']['server']['cert.pem'] = '0' * 64
            self.write(stage / 'pair.json', c.encoded(invalid))
            with self.assertRaisesRegex(c.Blocked, 'differ from the recorded local issuance'):
                self.live.prepare_checklist_pair(app, observed, source, issue=False)

    def test_approved_initial_release_acquisition_uses_existing_locked_f_entry(self):
        import native_placements as native

        platform, revision = self.approved_full()
        calls = []
        class Waiting(Exception):
            phase = 'initial-source-not-published'
        intake = SimpleNamespace(ROOT=self.portable, CONTROL_SECONDS=900,
            intake_lock=nullcontext, retained_index=installer.intake.retained_index,
            InitialReleaseUnavailable=Waiting,
            acquire_initial=lambda source, end: calls.append(source) or {'platform_sha256': platform})
        with patch.object(native, 'managed_snapshot', return_value={'device': 'fixture'}):
            self.assertEqual(self.live.acquire_initial_platform(intake, revision), platform)
            self.assertEqual(calls, [revision])
            with patch.object(intake, 'acquire_initial', side_effect=Waiting('reviewed source is unpublished')):
                with self.assertRaisesRegex(c.Pending, 'initial-source-not-published'):
                    self.live.acquire_initial_platform(intake, revision)
