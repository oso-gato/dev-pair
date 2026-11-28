import os
import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import host_fixed_migration as migration
import provider_billing as billing
import provider_transition as transition
from bootstrap import Bootstrap
from ledger_recovery import write_private
from test_provider_transition import BOOT, OTHER_BOOT, PREVIOUS, fixture_fence

AUTHORITY = {'operation': 'stable-fixture', 'machine_id': '0' * 32, 'previous_release_sha256': '1' * 64,
             'previous_base_platform_sha256': '2' * 64, 'previous_base_intake_sha256': '3' * 64,
             'target_release_sha256': '4' * 64, 'platform_sha256': '5' * 64, 'intake_sha256': '6' * 64,
             'site_config_sha256': '7' * 64}


@unittest.skipUnless(os.getuid() == 0, 'protected fixed migration fixture needs mapped root')
class FixedMigrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.fence, self.manager = fixture_fence(self.root)
        self.enterContext(mock.patch.object(billing, 'protected', side_effect=self.protected))
        self.app = Bootstrap(self.root, self.manager)
        self.new = {name: b'# successor fixed bytes ' + name.encode() + b'\n' for name in migration.CHAIN}
        for name in (transition.TEMPLATE, transition.DROP_IN, transition.LAUNCHER, transition.GATE, *transition.BILLING_TOOLS):
            self.new[name] = self.fence.path(name).read_bytes()
        self.old = {key: None if key in migration.OLD_OPTIONAL else b'# predecessor fixed bytes ' + key.encode() + b'\n'
                    for key in migration.CHAIN}
        self.old[transition.TEMPLATE] = self.new[transition.TEMPLATE]
        for name, raw in self.old.items():
            leaf = self.fence.path(name)
            leaf.parent.mkdir(parents=True, exist_ok=True)
            if raw is None:
                if leaf.exists():
                    leaf.unlink()
            else:
                leaf.write_bytes(raw)
                leaf.chmod(migration.CHAIN[name][1])
        self.upgrade = migration.Migration(self.app, AUTHORITY, self.old, self.new)
        self.history = self.root / 'var/lib/dev-pair/prior-provider-accounting'
        write_private(self.history, b'fixture existing charge receipt\n')

    def protected(self, path, *, directory=False, private=False):
        self.assertTrue(path.is_relative_to(self.root))
        self.assertEqual(path.resolve(strict=True), path)
        stat = path.lstat()
        self.assertEqual((stat.st_uid, stat.st_gid), (0, 0))
        self.assertFalse(stat.st_mode & 0o022)
        if directory:
            self.assertTrue(path.is_dir())
        else:
            self.assertTrue(path.is_file())
            self.assertEqual(stat.st_nlink, 1)
        if private:
            self.assertEqual(stat.st_mode & 0o777, 0o700 if directory else 0o600)
        return path

    def test_fixed_old_runner_is_preserved_until_loaded_fence_and_idle_readback(self):
        self.manager.active.add(PREVIOUS)
        actual_manager = self.manager
        traces = []

        def show(*args, **kwargs):
            result = actual_manager(*args, **kwargs)
            if args[1] == 'list-units' and PREVIOUS in result:
                traces.append(result)
                self.assertEqual(self.fence.path(transition.LAUNCHER).read_bytes(), self.old[transition.LAUNCHER])
                self.assertEqual(self.fence.path(migration.TEMPORARY).read_bytes(), migration.TEMP_BYTES)
                self.assertFalse(self.fence.ready.exists())
                if len(traces) == 2:
                    self.manager.active.remove(PREVIOUS)
            return result

        self.upgrade.fence.run = show
        self.upgrade.prepare(end=time.monotonic() + 8)
        self.assertEqual(len(traces), 2)
        self.assertEqual(self.fence.path(transition.LAUNCHER).read_bytes(), self.new[transition.LAUNCHER])
        self.assertEqual(self.upgrade.record(self.upgrade.pending)['phase'], 'installed')
        with self.assertRaisesRegex(ValueError, 'fixed billing release migration remains held'):
            self.fence.require_ready()
        self.upgrade.finish(end=time.monotonic() + 8)
        self.fence.require_ready()
        self.assertEqual(self.upgrade.record(self.upgrade.evidence)['phase'], 'complete')
        self.assertEqual(self.history.read_bytes(), b'fixture existing charge receipt\n')
        with self.assertRaisesRegex(ValueError, 'predecessor is incompatible'):
            migration.refuse_incompatible_rollback(self.app, AUTHORITY)
        self.fence.path('/proc/sys/kernel/random/boot_id').write_text(OTHER_BOOT + '\n')
        with self.assertRaises(transition.Deferred):
            self.fence.converge(resume_custody=False)
        self.assertEqual(self.fence.path(transition.LAUNCHER).read_bytes(), self.new[transition.LAUNCHER])

    def test_interrupted_file_replacement_resumes_exact_fixed_authority(self):
        atomic = self.app.atomic

        def crash_after_write(path, *args, **kwargs):
            atomic(path, *args, **kwargs)
            if path == transition.LAUNCHER:
                raise OSError('interrupted after exact runner publication')

        with mock.patch.object(self.app, 'atomic', side_effect=crash_after_write):
            with self.assertRaisesRegex(OSError, 'interrupted'):
                self.upgrade.prepare(end=time.monotonic() + 6)
        self.assertEqual(self.fence.path(transition.LAUNCHER).read_bytes(), self.new[transition.LAUNCHER])
        self.assertTrue(self.fence.path(migration.TEMPORARY).exists())
        request = {'scope': 'stable', 'operation': AUTHORITY['operation'], 'previous_sha256': AUTHORITY['previous_release_sha256'],
                   'target_sha256': AUTHORITY['target_release_sha256']}
        owner = SimpleNamespace(root=self.root / 'var/lib/dev-pair')
        self.assertTrue(migration.forward_started(owner, request))
        with self.assertRaisesRegex(ValueError, 'different stable transition'):
            migration.forward_started(owner, {**request, 'operation': 'foreign-window'})
        self.fence.path('/proc/sys/kernel/random/boot_id').write_text(OTHER_BOOT + '\n')
        reopened = migration.Migration(self.app, AUTHORITY, self.old, self.new)
        reopened.prepare(end=time.monotonic() + 6)
        reopened.finish(end=time.monotonic() + 6)
        self.assertTrue(migration.forward_started(owner, request))
        self.assertEqual(billing.json_bundle(self.fence.ready.read_bytes())['boot'], OTHER_BOOT)
        self.assertEqual(self.history.read_bytes(), b'fixture existing charge receipt\n')

    def test_unknown_fixed_bytes_and_unowned_overlay_are_preserved(self):
        runner = self.fence.path(transition.LAUNCHER)
        unknown = b'# unrelated fixed customization\n'
        runner.write_bytes(unknown)
        with self.assertRaisesRegex(ValueError, 'differ from the signed migration'):
            self.upgrade.prepare(end=time.monotonic() + 6)
        self.assertEqual(runner.read_bytes(), unknown)
        self.assertFalse(self.upgrade.pending.exists())
        runner.write_bytes(self.old[transition.LAUNCHER])
        unowned = self.fence.path(migration.TEMPORARY)
        unowned.write_bytes(migration.TEMP_BYTES)
        with self.assertRaisesRegex(ValueError, 'unowned temporary provider guard'):
            self.upgrade.prepare(end=time.monotonic() + 6)
        self.assertEqual(unowned.read_bytes(), migration.TEMP_BYTES)
        self.assertEqual(runner.read_bytes(), self.old[transition.LAUNCHER])

    def signed_host(self, *, redirect=False, skip=()):
        # Retained native host archive surrogate. File hashes and the bundle
        # traversal are production checks. Portable signing happened in F.
        home = self.root / 'signed-bundle'
        home.mkdir()
        files, rows = {}, []
        for target, (source, mode) in migration.CHAIN.items():
            if target in skip:
                continue
            path = home / source
            path.parent.mkdir(parents=True, exist_ok=True)
            body = self.new[target]
            path.write_bytes(body)
            files[source] = hashlib.sha256(body).hexdigest()
            path.chmod(0o555 if mode == 0o755 else 0o444)
            rows.append({'source': source, 'target': target, 'mode': f'{mode:04o}', 'feature': 'base'})
        if redirect:
            next(row for row in rows if row['target'] == transition.LAUNCHER)['source'] = 'tools/renewal.py'
        manifest = home / migration.MANIFEST
        manifest.parent.mkdir(parents=True, exist_ok=True)
        body = billing.canonical({'schema': 1, 'files': rows})
        manifest.write_bytes(body)
        manifest.chmod(0o444)
        files[migration.MANIFEST] = hashlib.sha256(body).hexdigest()
        source = 'a' * 40
        host_bytes = billing.canonical({'schema': 1, 'source_revision': source, 'state_contract': 1, 'files': files})
        (home / 'manifest.json').write_bytes(host_bytes)
        (home / 'manifest.json').chmod(0o444)
        for parent, _, _ in os.walk(home, topdown=False):
            Path(parent).chmod(0o555)
        self.addCleanup(lambda: [Path(parent).chmod(0o700) for parent, _, _ in os.walk(home)])
        return home, {'source_sha': source, 'bundle_manifest_sha256': hashlib.sha256(host_bytes).hexdigest()}

    def test_signed_manifests_pin_exact_fixed_sources_and_modes(self):
        home, host = self.signed_host()
        with mock.patch.object(migration.installer.intake, 'protected', side_effect=self.protected):
            self.assertEqual(migration.fixed_inputs(home, host), self.new)

    def test_signed_archive_cannot_redirect_a_fixed_activation_path(self):
        home, host = self.signed_host(redirect=True)
        with mock.patch.object(migration.installer.intake, 'protected', side_effect=self.protected):
            with self.assertRaisesRegex(ValueError, 'changes a fixed activation path'):
                migration.fixed_inputs(home, host)

    def test_historical_omissions_are_allowed_only_for_the_signed_predecessor(self):
        home, host = self.signed_host(skip=migration.OLD_OPTIONAL)
        with mock.patch.object(migration.installer.intake, 'protected', side_effect=self.protected):
            accepted = migration.fixed_inputs(home, host, previous=True)
            expected = {'owner_source': 0o644, 'day0_access_exchange': 0o755, 'destination_observation': 0o644,
                        'managed_backing': 0o644}
            for name, mode in expected.items():
                path = f'{migration.INSTALL}/tools/{name}.py'
                self.assertIsNone(accepted[path])
                self.assertEqual(migration.CHAIN[path], (f'tools/{name}.py', mode))
            with self.assertRaisesRegex(ValueError, 'missing a required fixed billing path'):
                migration.fixed_inputs(home, host)

    def test_successor_follows_the_signed_optional_billing_courier(self):
        self.assertIsNone(self.old[migration.COURIER])
        self.upgrade.prepare(end=time.monotonic() + 6)
        current = self.fence.path(migration.COURIER)
        self.assertEqual(current.read_bytes(), self.new[migration.COURIER])
        self.assertEqual(current.stat().st_mode & 0o777, 0o755)

    def test_pre_courier_package_is_supported_and_cannot_remove_an_installed_courier(self):
        home, host = self.signed_host(skip=(migration.COURIER,))
        with mock.patch.object(migration.installer.intake, 'protected', side_effect=self.protected):
            historical = migration.fixed_inputs(home, host)
        self.assertIsNone(historical[migration.COURIER])
        prior_window = migration.Migration(self.app, AUTHORITY, self.old, historical)
        prior_window.prepare(end=time.monotonic() + 6)
        prior_window.finish(end=time.monotonic() + 6)
        self.assertFalse(self.fence.path(migration.COURIER).exists())
        with self.assertRaisesRegex(ValueError, 'remove or omit the billing courier'):
            migration.Migration(self.app, AUTHORITY, self.new, historical)
        dependent = {**historical, f'{migration.INSTALL}/tools/owner_intake.py':
                     b'from billing_courier import setup_route\n'}
        with self.assertRaisesRegex(ValueError, 'remove or omit the billing courier'):
            migration.Migration(self.app, AUTHORITY, self.old, dependent)

    def test_versioned_host_apply_closes_fence_before_target_selection(self):
        script = ROOT / 'runtime/renewal/host-release'
        loader = importlib.machinery.SourceFileLoader('fixed_host_release_fixture', str(script))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        entry = importlib.util.module_from_spec(spec)
        loader.exec_module(entry)
        control = self.root / 'var/lib/dev-pair/renewal'
        control.mkdir(mode=0o700)
        target = AUTHORITY['target_release_sha256']
        host = {'artifact_sha256': 'd' * 64, 'source_revision': 'a' * 40, 'config_sha256': 'c' * 64}
        store = self.fence.path(entry.STORE.as_posix())
        selected = store / host['artifact_sha256']
        desired = {'operation': AUTHORITY['operation'], 'release_sha256': target, 'component': host}
        migration.r.replace_json(control / 'host-desired.json', desired)
        request = {'scope': 'stable', 'operation': AUTHORITY['operation'], 'previous_sha256': AUTHORITY['previous_release_sha256'],
                   'target_sha256': target}
        journal = {'phase': 'applying', 'request': request}
        owner = SimpleNamespace(transition=lambda: (None, journal), release=lambda _: {'components': {'host': host}})

        def read_handoff(directory, *, restart):
            self.assertTrue(restart)
            self.assertEqual(directory, selected)
            self.assertEqual(self.upgrade.record(self.upgrade.pending)['phase'], 'installed')
            self.assertFalse(self.fence.ready.exists())
            return {'pid': 234}

        def publish(component):
            self.assertEqual(component, host)
            self.assertEqual(self.upgrade.files(final=True), set(migration.CHAIN))
            self.assertFalse(self.fence.ready.exists())

        stable = SimpleNamespace(verify_transition=mock.Mock(return_value=AUTHORITY))
        self.app.hold_changed_workload_access = mock.Mock()
        with (mock.patch.multiple(entry, CONTROL=control, STORE=store, VERSIONED=selected,
                                  EXECUTED=selected / 'runtime/renewal/host-release'),
              mock.patch.object(sys, 'argv', [str(script), 'apply']),
              mock.patch.dict(sys.modules, stable_renewal=stable),
              mock.patch.object(entry.r, 'Renewal', return_value=owner),
              mock.patch('bootstrap.Bootstrap', return_value=self.app),
              mock.patch.object(migration, 'authorized', return_value=self.upgrade),
              mock.patch.object(entry, 'release_dirs', return_value=(selected, {})),
              mock.patch.object(entry, 'host_measurement', return_value={}),
              mock.patch.object(entry, 'measure_release', return_value={'boot_id': BOOT}),
              mock.patch.object(entry, 'publish_selector', side_effect=publish),
              mock.patch.object(entry, 'handoff_runtime', side_effect=read_handoff),
              mock.patch('builtins.print') as output):
            entry.main()
        self.fence.require_ready()
        self.assertEqual(migration.r.read_json(control / 'host-selection.json'), host)
        self.assertEqual(self.upgrade.record(self.upgrade.evidence)['phase'], 'complete')
        self.app.hold_changed_workload_access.assert_called_once_with(target, acquire_lease=True)
        self.assertEqual(stable.verify_transition.call_count, 3)
        output.assert_called_once()
