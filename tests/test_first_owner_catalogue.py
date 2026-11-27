import contextlib
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import subprocess
import sys
import stat
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'tools'))
import gptbox
import gptbox_runtime
import owner_intake as owner
import platform_release_intake
import product_job as product
import provider_broker
import renewal
import commission_host
import startup_delivery
from job_protocol import STANDARDS, canonical, identity, loads, sha256

REPOSITORY = 'fixture/owner-checklist'
JOB = 'job-1'
DESTINATION = 'https://erebus.fixture.ts.net/'
SELECTED = 'a' * 64
SITE = 'b' * 64
BOOTSTRAP = 'c' * 40
CODEX = 'd' * 64


@unittest.skipUnless(os.getuid() == 0, 'first-site fixture needs user-namespace root for the protected-file contract')
class FirstCatalogueTests(unittest.TestCase):
    def setUp(self):
        local = tempfile.TemporaryDirectory(prefix='.owner-site-', dir=REPO_ROOT)
        self.addCleanup(local.cleanup)
        self.path = Path(local.name)
        self.site = self.path / 'site'
        self.root = self.path / 'runtime'
        self.credential = self.path / 'credentials' / 'approved-api'
        self.billing = self.path / 'billing' / self.credential.name
        for folder in (self.site / 'standards', self.root / 'renewal', self.root / 'product-jobs/intake',
                       self.root / 'product-jobs/jobs', self.root / 'product-jobs/profiles',
                       self.root / 'repository-approvals', self.root / 'provider-allowances',
                       self.credential.parent, self.billing):
            folder.mkdir(mode=0o700, parents=True)
            folder.chmod(0o700)
        self.intake = owner.Intake(self.site, self.root)
        self.first = owner.FirstCatalogue(self.intake)
        owner.write_private(self.intake.catalogue / 'intake.lock', b'')
        owner.write_private(self.credential, b'not-a-live-key')
        self.bill = {
            'context': {'model': owner.MODEL, 'max_context_tokens': 2000},
            'tariff': {'model': owner.MODEL, 'input_microusd_per_million': 500000,
                       'output_microusd_per_million': 2000000, 'observed_models': [owner.MODEL]},
        }
        for name, value in self.bill.items():
            owner.write_private(self.billing / (owner.MODEL + '.' + name), canonical(value).encode())
        self.source = self.site / 'repositories' / REPOSITORY / 'acquired'
        self.startup = self.site / 'repositories' / REPOSITORY / 'startup'
        for repository in (self.source, self.startup):
            repository.mkdir(mode=0o700, parents=True)
            self.git(repository, 'init', '--template=')
            self.git(repository, 'config', 'remote.origin.url', 'https://github.com/' + REPOSITORY)
            (repository / 'STANDARDS.md').write_text('\n'.join(
                f'https://github.com/oso-gato/standards/blob/{STANDARDS}/{name}'
                for name in ('GOVERNANCE.md', 'ENGINEERING-STANDARDS.md', 'REPOSITORY-SETUP.md')) + '\n')
            app = repository / 'examples/checklist/checklist.py'
            app.parent.mkdir(mode=0o700, parents=True)
            app.write_bytes(b'# root-protected fixture app\n')
            self.git(repository, 'add', '--all')
            self.git(repository, '-c', 'user.name=Fixture', '-c', 'user.email=f@example.test', 'commit', '-m', 'Approved fixture')
        self.commit = self.git(self.source, 'rev-parse', 'HEAD').strip().decode()
        self.documents = {name + '.txt': ('fixture startup ' + name + '\n').encode() for name in owner.IDS}
        manifest = {'version': 1, 'mode': 'private-runtime', 'project_revision': self.git(self.startup, 'rev-parse', 'HEAD').strip().decode(),
                    'standards_sha': STANDARDS, 'documents': [
                        {'id': name, 'sha256': sha256(self.documents[name + '.txt']),
                         'bytes': len(self.documents[name + '.txt'])} for name in owner.IDS]}
        self.documents['manifest.json'] = owner.manifest_bytes(manifest)
        self.use(mock.patch.object(owner, 'load_private', return_value=SimpleNamespace(manifest=manifest)))
        self.use(mock.patch.multiple(owner, CREDENTIALS=self.credential.parent, BILLING_EVIDENCE=self.billing.parent))
        self.use(mock.patch.object(owner, 'protect_directory',
                                   side_effect=lambda path: self.protected(path, directory=True)))
        self.use(mock.patch.object(commission_host, 'protected', side_effect=self.protected))
        self.use(mock.patch.object(owner.candidate, 'protected_file', side_effect=self.read))
        self.use(mock.patch.object(provider_broker, 'protected_file', side_effect=self.read))
        self.use(mock.patch.object(provider_broker, 'ALLOWANCES', self.root / 'provider-allowances'))
        self.use(mock.patch.object(owner, 'trusted_directory', side_effect=self.private))
        self.use(mock.patch.object(renewal, 'trusted_directory', side_effect=self.private))
        self.use(mock.patch.object(product, 'trusted_directory', side_effect=self.private))
        self.use(mock.patch.multiple(product, ROOT=self.root, JOBS=self.intake.catalogue / 'jobs',
                                     PROFILES=self.intake.catalogue / 'profiles'))
        self.use(mock.patch.object(owner.pwd, 'getpwnam', side_effect=lambda name:
                                   SimpleNamespace(pw_uid=1001 if name == 'dp-dev' else 1002,
                                                   pw_gid=1001 if name == 'dp-dev' else 1002)))
        self.options = SimpleNamespace(repository=REPOSITORY, workload=owner.CHECKLIST, destination=DESTINATION,
            profile='openai-api-key', credential_ref=self.credential.name, spend_microusd=90000,
            expires_unix=int(time.time()) + 4000, context_tokens=2000, input_rate=500000,
            output_rate=2000000, observed_model=[owner.MODEL], requests=3, request_bytes=65536,
            output_tokens=400, host_seconds=45, build_seconds=60, turn_seconds=90, confirm_sha256=None)
        self.role_fixture()
        self.use(mock.patch.object(owner.os, 'fchown', side_effect=self.namespace_chown))
        self.use(mock.patch.object(owner.os, 'setxattr', side_effect=self.namespace_xattr))

    def protected(self, path, owner_id=0, *, directory=False, mode=None):
        # Host ancestors above the test tree are unmapped in this local user namespace.
        self.assertTrue(path.is_relative_to(self.path))
        self.assertEqual(path.resolve(strict=True), path)
        for current in (path, *(part for part in path.parents if part.is_relative_to(self.path))):
            node = current.lstat()
            self.assertEqual(node.st_uid, owner_id)
            self.assertFalse(node.st_mode & 0o022)
            if current != path or directory:
                self.assertTrue(stat.S_ISDIR(node.st_mode))
            else:
                self.assertTrue(stat.S_ISREG(node.st_mode) and node.st_nlink == 1)
        if mode is not None:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        return path

    def private(self, path, *, create=False):
        if create:
            path.mkdir(mode=0o700)
        return self.protected(path, directory=True, mode=0o700)

    def read(self, path, maximum=owner.p.MAX_MESSAGE, *, secret=False):
        self.protected(path, mode=0o600 if secret else None)
        return owner.p.read_data(path, maximum)

    native_chown = os.fchown
    native_setxattr = os.setxattr

    @staticmethod
    def namespace_chown(path, uid, gid, **kwargs):
        # This fixture has only its root POSIX ID in the namespace map.
        return FirstCatalogueTests.native_chown(path, uid, 0, **kwargs)

    @staticmethod
    def namespace_xattr(path, name, value, **kwargs):
        # Exercise the real immutable tree and copied xattrs on a kernel without SELinux.
        key = 'user.dev_pair_fixture_label' if name == 'security.selinux' else name
        return FirstCatalogueTests.native_setxattr(path, key, value, **kwargs)

    def use(self, patch):
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def git(path, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(path), *args], stderr=subprocess.DEVNULL, timeout=5)

    def role_fixture(self):
        self.runtime = sha256(Path(gptbox_runtime.__file__).read_bytes())

        def labels(role):
            return {'dev-pair.role': role, 'dev-pair.runtime': self.runtime, 'dev-pair.standards': STANDARDS,
                    'dev-pair.codex.sha256': CODEX, 'dev-pair.codex.version': '1.2.3',
                    'org.opencontainers.image.revision': BOOTSTRAP, 'dev-pair.context': 'e' * 64}

        config = canonical({'config': {'Labels': labels('development')}}).encode()
        artifact = sha256(config)
        archive = self.path / 'development.oci.tar'
        with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as stream:
            entry = tarfile.TarInfo('blobs/sha256/' + artifact)
            entry.size = len(config)
            stream.addfile(entry, io.BytesIO(config))
        self.geometry = {'categories': {'outer': [34, 58, 67], 'inner': [34, 58]}, 'storage_bytes': 8 * 1024**3}
        manifest = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': STANDARDS, 'job': JOB,
                    'outer': {'source_sha': BOOTSTRAP, 'image_id': '2' * 64},
                    'inner': {'source_sha': BOOTSTRAP, 'image_id': artifact, 'context_sha256': 'e' * 64,
                              'inputs_sha256': '3' * 64, 'sealed_sha256': '4' * 64,
                              'archive_bytes': archive.stat().st_size, 'archive_sha256': sha256(archive.read_bytes()),
                              'diff_ids': ['sha256:' + '5' * 64]},
                    **self.geometry}
        self.manifest = identity(manifest)
        leaf = self.root / 'development/builds' / JOB / 'inputs' / self.manifest
        leaf.mkdir(mode=0o700, parents=True)
        owner.write_private(leaf / 'manifest.json', canonical(manifest).encode())
        (leaf / 'manifest.json').chmod(0o444)
        portable = self.path / 'portable'
        (portable / 'development').mkdir(mode=0o700, parents=True)
        payloads = {archive.name: archive.read_bytes(), 'part.json': b'{"fixture":true}\n'}
        shipping = io.BytesIO()
        with zipfile.ZipFile(shipping, 'w') as release_zip:
            for name, raw in payloads.items():
                release_zip.writestr(name, raw)
        old_umask = os.umask(0o077)
        try:
            platform_release_intake.extract_zip(shipping, portable / 'development',
                {name: (sha256(data), len(data)) for name, data in payloads.items()}, time.monotonic() + 10)
        finally:
            os.umask(old_umask)
        self.portable_archive = portable / 'development' / archive.name
        components = {role + '-agent': {'source_revision': BOOTSTRAP, 'config_sha256': 'e' * 64,
                                      'artifact_sha256': artifact if role == 'development' else '8' * 64}
                      for role in owner.ROLES}
        self.controller = SimpleNamespace(release=lambda _: {'components': components}, dispatch_gate=contextlib.nullcontext)
        self.admitted = {JOB: self.manifest}
        self.use(mock.patch.object(self.intake, 'release_slots', return_value=(self.controller, SELECTED, self.admitted)))
        self.use(mock.patch.object(owner, 'selected_site', side_effect=lambda _: (self.controller, SELECTED, self.admitted,
            {'jobs': {JOB: self.geometry}}, {'site_config_sha256': SITE, 'platform_sha256': '9' * 64}, DESTINATION)))
        self.engine = SimpleNamespace(preflight=mock.Mock(), admitted_maintenance_image=mock.Mock(),
                                      lock=contextlib.nullcontext, maintenance_labels=lambda *args: labels('maintenance'))
        self.use(mock.patch.object(gptbox, 'Gptbox', return_value=self.engine))
        self.portable_authority = {'components': {
            role + '-agent': {'codex_version': '1.2.3', 'codex_sha256': CODEX} for role in owner.ROLES}}
        self.portable_authority['components']['development-agent'].update(
            oci_config_sha256=artifact, source_sha=BOOTSTRAP, context_sha256='e' * 64,
            **{key: manifest['inner'][key] for key in ('archive_sha256', 'archive_bytes')})
        self.use(mock.patch.object(platform_release_intake, 'retained_index',
                                   return_value=(portable, self.portable_authority, '9' * 64)))

    def preview(self):
        plan, _ = self.first.preview(self.options)
        self.options.confirm_sha256 = identity(plan)
        return plan

    def test_first_publication_feeds_existing_owner_approval_and_product_submission(self):
        live = object.__new__(commission_host.Live)
        live.checklist_builder = mock.Mock()
        with mock.patch.object(owner, 'Intake', return_value=self.intake):
            with self.assertRaises(commission_host.Pending) as held:
                live.owner_feature_authority(SELECTED, None)
            self.assertEqual(held.exception.report['prerequisite'], 'owner-catalogue-selection')
        plan = self.preview()
        self.assertFalse((self.site / 'slots').exists())
        self.assertNotIn('not-a-live-key', canonical(plan))
        self.assertEqual(plan['roles']['development']['runtime_sha256'], self.runtime)
        self.assertEqual(plan['roles']['maintenance']['runtime_sha256'], self.runtime)
        self.assertNotEqual(plan['roles']['development']['layout']['selinux_label'],
                            plan['roles']['maintenance']['layout']['selinux_label'])
        self.assertEqual(self.first.initialize(self.options)['phase'], 'configured')
        with mock.patch.object(owner, 'Intake', return_value=self.intake):
            authority = live.owner_feature_authority(SELECTED, None)
        self.assertEqual((authority['subject'], authority['expires_unix']), (JOB, self.options.expires_unix))
        live.checklist_builder.assert_called_once_with(prepare=False)
        config_inode = self.first.catalogue.stat().st_ino
        self.assertEqual(self.first.initialize(self.options)['phase'], 'configured')
        self.assertEqual(self.first.catalogue.stat().st_ino, config_inode)
        self.assertFalse((self.root / 'provider-allowances' / JOB).exists())
        requested = dict(action='draft', repository=REPOSITORY, workload=owner.CHECKLIST,
                         brief='Repair restart persistence.', audience='Existing checklist owners.',
                         access='Retain private group access.', acceptance='A completed item survives restart.',
                         constraints='', external_validation='')
        draft = self.intake.draft(requested)
        self.assertEqual(draft['phase'], 'awaiting-confirmation')
        self.assertEqual(draft['preview']['product_agreement']['destination'], DESTINATION)
        self.assertEqual(draft['preview']['plan']['agreement']['initial_commit'], self.commit)
        self.assertEqual(draft['preview']['provider_microusd'], self.options.spend_microusd)
        checked = draft['preview']['plan']
        roles = []

        def approve(plan, checkout, startup, cache, revision, tree):
            approval = dict(schema=1, job=JOB, repository=REPOSITORY, standards_sha=STANDARDS,
                            acquired_commit=self.commit, acquired_tree=tree, agreement_sha256=product.agreement_sha(plan),
                            startup_project_revision=revision, startup_sha256=plan['startup_sha256'])
            owner.write_private(self.root / 'repository-approvals' / (JOB + '.json'), canonical(approval).encode())
            folder = owner.private_leaf(self.root / 'repository-approvals' / JOB)
            for name, data in self.documents.items():
                owner.write_private(folder / name, data)
            return canonical(approval).encode()

        def acquire(role, job, account, agreement, tree, bundle, *, checklist):
            self.assertEqual((job, checklist), (JOB, True))
            temp = self.path / (role + '.bundle')
            temp.write_bytes(bundle)
            self.assertIn(self.commit.encode(), self.git(self.source, 'bundle', 'list-heads', temp))
            roles.append(role)

        normal_command = owner.candidate.invoke
        def command(argv, end, **kwargs):
            if argv[0] == owner.SYSTEMCTL:
                self.assertIn(argv[-1], ('dev-pair-intake@job-1.service', 'dev-pair-product@job-1.service'))
                return b''
            return normal_command(argv, end, **kwargs)

        for role in owner.ROLES:
            (self.root / 'turn-inputs' / role).mkdir(mode=0o700, parents=True)
        with mock.patch.object(owner.p, 'require_workload_access'), \
                mock.patch.object(owner.candidate, 'invoke', side_effect=command), \
                mock.patch.object(self.intake, 'approve', side_effect=approve), \
                mock.patch.object(self.intake, 'acquire_role', side_effect=acquire), \
                mock.patch.object(product, 'source_approval', return_value=(b'fixture', {})):
            self.assertEqual(self.intake.confirm(JOB, draft['agreement_token'])['phase'], 'confirmed')
            self.assertEqual(self.intake.prepare(JOB), 0, self.intake.status(JOB)['diagnostics'])
        self.assertEqual(self.intake.status(JOB)['phase'], 'submitted')
        self.assertEqual(roles, list(owner.ROLES))
        allowance = loads((self.root / 'provider-allowances' / JOB / 'allowance.json').read_bytes())
        self.assertEqual(allowance['agreement_sha256'], product.agreement_sha(checked))
        self.assertEqual(allowance['models'][owner.MODEL]['observed_models'], [owner.MODEL])
        self.assertTrue(product.job_path(JOB).is_dir())
        self.assertEqual(self.first.initialize(self.options)['phase'], 'configured')
        # J stages the ordinary P request and peer-bound grant from each generated seed.
        grants = self.root / 'renewal/provider-grants'
        grants.mkdir(mode=0o700)
        runner = object.__new__(product.FedoraJob)
        runner.plan, runner.job, runner.agreement = checked, JOB, checked['agreement']
        runner.agreement_sha = product.agreement_sha(checked)
        runner.approval_raw = (self.root / 'repository-approvals' / (JOB + '.json')).read_bytes()
        runner.gptbox, runner.renewal = gptbox_runtime, renewal
        runner.runtime = SimpleNamespace(protected=lambda path, *, file: self.protected(path, directory=not file))
        checkpoint = {'candidate': {'source_revision': self.commit}}
        allowance_sha = sha256((self.root / 'provider-allowances' / JOB / 'allowance.json').read_bytes())
        for role in owner.ROLES:
            operation = f'{JOB}-{role}'
            request, digest, account = runner.stage_turn(role, operation, b'An example authorized turn.',
                                                         checkpoint, product.profile(JOB, role))
            staged_grant = provider_broker.grant_document((grants / (digest + '.json')).read_bytes())
            self.assertEqual((request['model'], request['effort']), (owner.MODEL, 'high'))
            self.assertEqual(staged_grant['peer_uid'], account.pw_uid)
            self.assertEqual(staged_grant['spend_microusd'], plan['roles'][role]['grant']['spend_microusd'])
            self.assertEqual(staged_grant['allowance_sha256'], allowance_sha)

    def test_interrupted_publication_readback_keeps_original_slot_and_occupied_history(self):
        self.preview()
        with mock.patch.object(platform_release_intake, 'durable_record', side_effect=OSError('fixture lost publication')):
            with self.assertRaisesRegex(OSError, 'lost publication'):
                self.first.initialize(self.options)
        slot = self.site / 'slots' / JOB
        inode = slot.stat().st_ino
        self.assertFalse(self.first.catalogue.exists())
        self.assertEqual(self.first.initialize(self.options)['phase'], 'configured')
        self.assertEqual(slot.stat().st_ino, inode)
        previous = self.first.catalogue.read_bytes()
        self.options.confirm_sha256 = '2' * 64
        with self.assertRaisesRegex(ValueError, 'another approval'):
            self.first.initialize(self.options)
        self.assertEqual(self.first.catalogue.read_bytes(), previous)

    def test_missing_unsupported_or_expired_authority_and_stale_scope_have_no_effect(self):
        def pending(expected, **changes):
            other = SimpleNamespace(**(vars(self.options) | changes))
            with self.assertRaises(owner.SitePending) as result:
                self.first.preview(other)
            self.assertEqual(result.exception.observation['prerequisite'], expected)

        pending('unsupported-provider-profile', profile='chatgpt-subscription')
        pending('provider-credential', credential_ref='no-key')
        pending('provider-allowance-expired', expires_unix=int(time.time()) - 1)
        pending('owner-repository-inputs', repository='wrong/project')
        with self.assertRaisesRegex(ValueError, 'both requested'):
            self.first.preview(SimpleNamespace(**(vars(self.options) | {'spend_microusd': 1})))
        self.preview()
        (self.billing / (owner.MODEL + '.tariff')).write_text(canonical(dict(self.bill['tariff'], review='changed receipt')))
        with self.assertRaisesRegex(ValueError, 'selection changed'):
            self.first.initialize(self.options)
        occupied = self.intake.queue / (JOB + '.json')
        owner.write_private(occupied, b'prior owned history')
        pending('owner-slot-capacity')
        self.assertEqual(occupied.read_bytes(), b'prior owned history')
        self.assertFalse(self.first.catalogue.exists())

    def test_command_line_billing_values_can_only_assert_the_protected_facts(self):
        self.preview()
        wrong = {'context_tokens': 1024, 'input_rate': 1, 'output_rate': 1, 'observed_model': ['gpt-unlisted']}
        for key, value in wrong.items():
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'independently reviewed evidence'):
                self.first.preview(SimpleNamespace(**(vars(self.options) | {key: value})))
        self.assertFalse(self.first.catalogue.exists())

    def test_attended_setup_derives_billing_and_commits_after_one_confirmation(self):
        expires = datetime.fromtimestamp(self.options.expires_unix, timezone.utc).strftime('%Y-%m-%d %H:%M')
        given = '\n'.join((REPOSITORY, '1', '0.09', expires, 'yes', ''))
        with mock.patch.object(owner.getpass, 'getpass', return_value=self.credential.name) as hidden:
            printed = io.StringIO()
            owner.setup_site(self.first, io.StringIO(given), printed)
        hidden.assert_called_once()
        self.assertEqual(printed.getvalue().count('Confirm this exact owner setup?'), 1)
        self.assertIn(DESTINATION, printed.getvalue())
        self.assertIn('USD 0.090000', printed.getvalue())
        self.assertNotIn(self.credential.name, printed.getvalue())
        self.assertNotIn('tariff (', printed.getvalue())
        self.assertEqual(self.first.configured()['phase'], 'configured')
        settings, _, _, _ = self.intake.slot(JOB, self.manifest)
        self.assertEqual(settings['pricing']['max_context_tokens'], self.bill['context']['max_context_tokens'])
        self.assertEqual(settings['pricing']['input_microusd_per_million'], self.bill['tariff']['input_microusd_per_million'])
        self.assertFalse((self.root / 'provider-allowances' / JOB).exists())

    def test_declined_or_opaque_attended_setup_stays_held(self):
        expires = datetime.fromtimestamp(self.options.expires_unix, timezone.utc).strftime('%Y-%m-%d %H:%M')
        given = '\n'.join((REPOSITORY, '1', '0.09', expires, 'no', ''))
        with mock.patch.object(owner.getpass, 'getpass', return_value=self.credential.name):
            printed = io.StringIO()
            owner.setup_site(self.first, io.StringIO(given), printed)
            self.assertIn('Setup remains pending.', printed.getvalue())
            (self.billing / (owner.MODEL + '.tariff')).write_text('Previously reviewed opaque notes')
            printed = io.StringIO()
            owner.setup_site(self.first, io.StringIO(REPOSITORY + '\n1\n'), printed)
        self.assertIn('provider custodian must supply', printed.getvalue())
        self.assertNotIn('Approved total job budget', printed.getvalue())
        self.assertNotIn('Confirm this exact owner setup?', printed.getvalue())
        self.assertFalse(self.first.catalogue.exists())
        self.assertFalse((self.site / 'slots').exists())

    def test_wrong_git_origin_and_mismatched_verified_seed_runtime_are_refused(self):
        self.git(self.source, 'config', 'remote.origin.url', 'https://github.com/foreign/source')
        with self.assertRaisesRegex(ValueError, 'authorized repository'):
            self.preview()
        self.git(self.source, 'config', 'remote.origin.url', 'https://github.com/' + REPOSITORY)
        observed = self.engine.maintenance_labels()
        self.engine.maintenance_labels = lambda *args: {**observed, 'dev-pair.runtime': 'c' * 64}
        with self.assertRaisesRegex(ValueError, 'matching verified host seed-policy'):
            self.preview()
        self.assertFalse(self.first.catalogue.exists())

    def test_portable_config_is_bound_to_the_selected_placement_under_dp_dev_ancestry(self):
        development = self.root / 'development'
        builds = development / 'builds'
        for folder in (development, builds):
            folder.chmod(0o700)
        try:
            os.chown(development, 1001, 1001)
        except OSError as exc:
            self.skipTest(f'The mapped fixture cannot assign the separate role UID ({exc.errno}).')
        os.chown(builds, 1001, 1001)
        for folder in (development, builds):
            self.assertEqual((folder.stat().st_uid, stat.S_IMODE(folder.stat().st_mode)), (1001, 0o700))
        plan = self.preview()
        self.assertEqual(plan['roles']['development']['binary_sha256'], CODEX)
        self.portable_authority['components']['development-agent']['archive_sha256'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'differs from its signed release'):
            self.preview()
        self.assertFalse(self.first.catalogue.exists())

    def test_consumes_f_private_extraction_and_checks_its_exact_bytes_and_custody(self):
        archive = self.portable_archive
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        self.preview()
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        archive.chmod(0o620)
        with self.assertRaisesRegex(ValueError, 'outside protected custody'):
            self.preview()
        archive.chmod(0o600)
        with archive.open('r+b') as stream:
            stream.seek(-1, os.SEEK_END)
            stream.write(b'x')
        with self.assertRaisesRegex(ValueError, 'archive digest differs'):
            self.preview()
        self.assertFalse(self.first.catalogue.exists())

    def test_root_cli_reports_preconditions_and_rejects_core_setup_invocation(self):
        with mock.patch.dict(os.environ, {'SUDO_USER': 'core'}):
            with self.assertRaisesRegex(ValueError, 'root commissioning terminal'):
                owner.catalogue_command(self.intake, ['--inspect-site'])
        with mock.patch.dict(os.environ, {'SUDO_USER': ''}), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(owner.catalogue_command(self.intake, ['--inspect-site']), 0)
        self.assertEqual(loads(output.getvalue().encode())['prerequisite'], 'owner-catalogue-selection')
        self.assertFalse((self.site / 'slots').exists())
        self.assertFalse((self.site / '.first-catalogue.lock').exists())

    @unittest.skipUnless(os.environ.get('DEV_PAIR_TEST_STANDARDS_CACHE'), 'optional actual private cache was not selected')
    def test_preview_reads_actual_pinned_cache_without_staging_its_contents(self):
        cache = Path(os.environ['DEV_PAIR_TEST_STANDARDS_CACHE'])
        for document in ('README.md', 'STANDARDS.md', 'REQUIREMENTS.md', 'ARCHITECTURE.md'):
            (self.startup / document).write_bytes((REPO_ROOT / document).read_bytes())
        self.git(self.startup, 'add', '--all')
        self.git(self.startup, '-c', 'user.name=Fixture', '-c', 'user.email=f@example.test', 'commit', '-m', 'Local startup proof')

        def location(path):
            return cache if path == self.site / 'standards' else self.protected(path, directory=True)

        with mock.patch.object(owner, 'load_private', wraps=startup_delivery.load_private) as loader, \
                mock.patch.object(owner, 'protect_directory', side_effect=location):
            plan = self.preview()
        loader.assert_called_once()
        self.assertEqual(loader.call_args.args[1], cache)
        self.assertEqual(plan['standards_sha'], STANDARDS)
        self.assertFalse((self.site / 'slots').exists())
        self.assertFalse((self.root / 'repository-approvals' / JOB).exists())


if __name__ == '__main__':
    unittest.main()
