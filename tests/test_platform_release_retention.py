import contextlib
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import platform_release_intake as intake
from platform_release_protocol import Blocked, canonical, file_hash, json_bytes


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.portable = self.root / 'platform-releases'
        self.portable.mkdir()
        self.control = self.root / 'renewal'
        for name in ('platform-bindings', 'attempts', 'offers', 'requests'):
            (self.control / name).mkdir(parents=True)
        self.catalog, self.locals, self.references = {}, {}, {}
        self.base = self.package(1)
        self.old = self.package(2, self.base)
        self.previous = self.package(3, self.old)
        self.active = self.package(4, self.previous)
        self.abandoned = self.package(5, self.previous)
        self.pending = self.package(6, self.active)
        self.deferred = self.package(7, self.previous)
        self.current = self.references[self.active]
        self.transition = None
        (self.control / 'site-current.json').write_bytes(canonical(self.current))
        self.end = time.monotonic() + 20
        self.owner = os.getuid()
        self.gate = SimpleNamespace(control=self.control, root=self.root, live_release=lambda: self.current,
                                    release=self.locals.__getitem__, transition=lambda: (None, self.transition),
                                    lock=contextlib.nullcontext)
        renewal = SimpleNamespace(Renewal=lambda _root, _driver: self.gate, read_json=self.read,
                                  checked_request=lambda value, _scope: value,
                                  trusted_directory=lambda path: path, MAX_ATTEMPTS=32,
                                  SCOPE_COMPONENTS=('agent', 'devbox', 'host'),
                                  TERMINAL={'completed', 'deferred', 'rolled-back', 'rejected'})
        resolver = SimpleNamespace(offer_record=lambda offer, _scope: offer)
        self.enterContext(mock.patch.dict(sys.modules, {'renewal': renewal, 'renewal_site': resolver}))
        self.enterContext(mock.patch.object(intake, 'ROOT', self.portable))
        self.enterContext(mock.patch.object(intake, 'protected', side_effect=lambda path, **_: path))
        self.enterContext(mock.patch.object(intake, 'retained_index', side_effect=self.catalog.__getitem__))
        self.verify_rollback = self.enterContext(mock.patch.object(intake, 'previous_release'))
        self.enterContext(mock.patch.object(intake, 'file_hash', side_effect=lambda path, maximum, end, **_:
                              file_hash(path, maximum, end, owner=self.owner)))
        real_read = intake.release.readonly_json
        self.enterContext(mock.patch.object(intake.release, 'readonly_json', side_effect=lambda path, _owner=None:
                              real_read(path, self.owner)))

    @staticmethod
    def read(path):
        return json_bytes(path.read_bytes())

    def package(self, run, predecessor=None):
        identity, reference = f'{run:064x}', f'{run + 100:064x}'
        directory = self.portable / identity
        directory.mkdir()
        evidence = {}
        for role in ('maintenance', 'development'):
            leaf = directory / role
            leaf.mkdir()
            files = {}
            for name in ('part.json', f'{role}.oci.tar'):
                raw = f'{identity} {role} {name}\n'.encode()
                (leaf / name).write_bytes(raw)
                files[name] = {'bytes': len(raw), 'sha256': intake.release.digest(raw)}
            evidence[role] = {'files': files}
        kind = 'dev-pair-platform-release' if predecessor is None else 'dev-pair-agent-release'
        component = {'oci_config_sha256': 'a' * 64}
        index = {'kind': kind, 'base_platform_sha256': None if predecessor is None else self.base,
                 'schema': 2 if predecessor is None else 3, 'previous_platform_sha256': None,
                 'publisher_run': run, 'source_sha': 'b' * 40, 'transports': evidence,
                 'components': {'maintenance-agent': component}}
        if predecessor:
            (directory / 'site-predecessor.json').write_bytes(canonical({'schema': 1, 'platform_sha256': identity,
                'base_platform_sha256': self.base, 'previous_platform_sha256': predecessor}))
        proof = f'{run + 200:064x}'
        self.catalog[identity] = (directory, index, proof)
        self.locals[reference] = {'plan_sha256': 'c' * 64, 'components': {'maintenance-agent': {
            'artifact_sha256': component['oci_config_sha256'], 'source_revision': index['source_sha'],
            'platform_sha256': identity}}}
        binding = {'schema': 1, 'release_sha256': reference, 'platform_sha256': identity,
                   'base_platform_sha256': index['base_platform_sha256'] or identity, 'site_config_sha256': 'd' * 64,
                   'plan_sha256': self.locals[reference]['plan_sha256'], 'intake_sha256': proof}
        (self.control / 'platform-bindings' / (reference + '.json')).write_bytes(canonical(binding))
        self.references[identity] = reference
        return identity

    def scope(self):
        return intake.retirement_scope(self.gate, self.catalog, self.active, self.base, self.end)

    def retire(self):
        old = self.catalog[self.old][0]
        old_archives = [old / role / f'{role}.oci.tar' for role in ('maintenance', 'development')]

        def physical(path):
            released = sum(not file.exists() for file in old_archives)
            return SimpleNamespace(f_favail=1000, f_frsize=1, f_bavail=intake.GUEST_RESERVE + (1000 if released == 2 else 0))

        node = self.portable.stat()
        with (mock.patch.object(intake, 'retirement_device', return_value=(node.st_dev, 42, 17, ('99',))),
              mock.patch.object(intake.os, 'statvfs', side_effect=physical)):
            intake.retain_for_transfer([row[0] for row in self.catalog.values()], self.active, self.base, 100, self.end)

    def test_pressure_reclaims_only_old_archives_and_keeps_compact_evidence(self):
        expected = self.catalog[self.old][2]
        old = self.catalog[self.old][0]
        self.retire()
        self.assertEqual(self.read(old / intake.RETIREMENT)['intake_sha256'], expected)
        self.assertEqual(list(old.glob('*/*.oci.tar')), [])
        for identity in (self.base, self.previous, self.active, self.pending, self.abandoned):
            self.assertEqual(len(list(self.catalog[identity][0].glob('*/*.oci.tar'))), 2)
        self.assertEqual(len(list(old.glob('*/part.json'))), 2)
        self.assertTrue((old / 'site-predecessor.json').is_file())
        self.verify_rollback.assert_called_once_with(self.previous, self.end)

    def test_publish_and_poll_pins_offer_and_incomplete_renewal(self):
        offer = {'platform_sha256': self.abandoned, 'previous_release_sha256': self.references[self.previous]}
        (self.control / 'offers/agent.json').write_bytes(canonical(offer))
        self.assertIn(self.abandoned, self.scope()[1])
        self.transition = {'phase': 'rolling-back'}
        with self.assertRaisesRegex(Blocked, 'pending renewal'):
            self.retire()
        self.assertEqual(len(list(self.catalog[self.old][0].glob('*/*.oci.tar'))), 2)

    def test_irreconcilable_mixed_scope_or_changed_file_keeps_old_archive(self):
        path = self.control / 'platform-bindings' / (self.current + '.json')
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(Blocked, 'exact portable binding'):
            self.retire()
        path.write_bytes(raw)
        old = self.catalog[self.old][0]
        (old / 'maintenance/maintenance.oci.tar').write_bytes(b'changed')
        with self.assertRaisesRegex(Blocked, 'transport changed'):
            self.retire()
        self.assertFalse((old / intake.RETIREMENT).exists())
        self.assertTrue((old / 'development/development.oci.tar').exists())

    def test_retirement_replays_its_exact_journal_after_partial_unlink(self):
        old = self.catalog[self.old][0]
        ordinary_unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path == old / 'development/development.oci.tar':
                raise OSError('fixture interruption after retiring maintenance archive')
            return ordinary_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, 'unlink', interrupt):
            with self.assertRaisesRegex(OSError, 'fixture interruption'):
                self.retire()
        journal = (old / intake.RETIREMENT).read_bytes()
        self.assertFalse((old / 'maintenance/maintenance.oci.tar').exists())
        self.assertTrue((old / 'development/development.oci.tar').exists())
        self.retire()
        self.assertEqual((old / intake.RETIREMENT).read_bytes(), journal)
        self.assertFalse((old / 'development/development.oci.tar').exists())
