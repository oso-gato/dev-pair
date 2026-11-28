"""Local fixtures for the prebuilt release installer boundary."""

from contextlib import contextmanager
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_placement_release as g
import native_placements as n

db = n.db
OUTER_SOURCE = '1' * 40
DEVELOPMENT = '2' * 40
PLATFORM = '3' * 64
BASE = '4' * 64
SITE = '5' * 64
OUTER = '6' * 64
OUTER_MANIFEST = '7' * 64
INNER_MANIFEST = '8' * 64
INNER = 'a' * 64
CATEGORIES = {'outer': [10, 11, 12], 'inner': [10, 11]}


def header(name, content=None, *, directory=False, link=None):
    item = tarfile.TarInfo(name)
    item.mode = 0o755 if directory else 0o444
    if directory:
        item.type = tarfile.DIRTYPE
    if link is not None:
        item.type = tarfile.SYMTYPE
        item.linkname = link
    if content is not None:
        item.size = len(content)
    return item, content


def layer(rows):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for entry, content in rows:
            archive.addfile(entry, None if content is None else io.BytesIO(content))
    return result.getvalue()


def image_layers(layers):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for content in layers:
            row, data = header('./blobs/sha256/' + g.digest(content), content)
            archive.addfile(row, io.BytesIO(data))
    result.seek(0)
    return result


class TestSeal(unittest.TestCase):
    def setUp(self):
        self.inputs = g.INNER_FILES[0]
        self.seal = g.INNER_FILES[1]
        self.packages = g.INNER_FILES[2]
        parents = ('usr', 'usr/lib', 'usr/lib/dev-pair', 'usr/lib/dev-pair/gptbox')
        self.parents = [header(name + '/', directory=True) for name in parents]
        self.files = [header(name, content) for name, content in zip(g.INNER_FILES, (b'inputs', b'seal', b'packages'))]

    def observe(self, layers):
        with tarfile.open(fileobj=image_layers(layers), mode='r:') as archive:
            blobs = {db.archive_path(row.name): row for row in archive}
            return g.rootfs_evidence(archive, blobs, [{'digest': 'sha256:' + g.digest(raw)} for raw in layers],
                                     time.monotonic() + 5)

    def test_exact_effective_files_are_read_in_order_without_extraction(self):
        lower = layer([*self.parents, *self.files])
        upper = layer([header('./' + self.inputs, b'current')])
        self.assertEqual(self.observe((lower, upper)), (b'current', b'seal', b'packages'))

    def test_whiteout_and_opaque_directory_hide_predecessor_file(self):
        lower = layer([*self.parents, *self.files])
        for marker in ('.wh.sealed.json', '.wh..wh..opq'):
            upper = layer([header('usr/lib/dev-pair/gptbox/' + marker, b'')])
            with self.subTest(marker=marker), self.assertRaisesRegex(db.Blocked, 'effective'):
                self.observe((lower, upper))
        upper = layer([header('usr/lib/dev-pair/gptbox/.wh.sealed.json', b''),
                       header(self.seal, b'replaced')])
        self.assertEqual(self.observe((lower, upper)), (b'inputs', b'replaced', b'packages'))

    def test_link_or_conflicting_ancestor_cannot_replace_the_observed_path(self):
        lower = layer([*self.parents, *self.files])
        for changed in ([header(self.seal, link='other')], [header('usr/lib/dev-pair', link='elsewhere')],
                        [header('usr/lib/dev-pair', link='elsewhere'), header(self.inputs, b'other')]):
            with self.subTest(changed=changed), self.assertRaises(db.Blocked):
                self.observe((lower, layer(changed)))


class PlacementFixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.release = g.ReleasePlacement.__new__(g.ReleasePlacement)
        self.release.job = 'checklist'
        self.release.boot = 'f' * 8 + '-1111-2222-3333-' + 'd' * 12
        self.release.previous = None
        self.release.establish = Mock()
        self.release.admission_binding = Mock(return_value={'fixture': True})
        self.release.preflight = Mock()
        self.release.load_outer = Mock()
        self.release.save = Mock()
        self.release.job_state = {'categories': CATEGORIES, 'manifests': {}, 'preflight': {'fixture': True}}
        self.release.outer_label = 'fixture-label'
        self.release.build_volume = SimpleNamespace(capacity=8 * db.GIB)
        self.release.build_inputs = self.inputs
        self.input_root = self.root / 'inputs'
        self.input_root.mkdir()
        self.stage_item(DEVELOPMENT, b'independent inner artifact')

    def stage_item(self, source, data):
        source_path = self.root / (source + '.oci.tar')
        source_path.write_bytes(data)
        inner = {'source_sha': source, 'context_sha256': '9' * 64, 'image_id': INNER,
                 'archive_bytes': len(data), 'archive_sha256': g.digest(data),
                 'inputs_sha256': 'c' * 64, 'sealed_sha256': 'd' * 64,
                 'diff_ids': ['sha256:' + 'e' * 64]}
        self.release.item = SimpleNamespace(
            identity=PLATFORM, base=BASE, site=SITE, source=source, job='checklist',
            outer={'image': {'source_sha': OUTER_SOURCE, 'image_id': OUTER},
                   'oci_manifest_sha256': OUTER_MANIFEST},
            inner=inner, inner_path=source_path, inner_record_sha=g.digest(n.image_inputs_bytes(inner)))
        self.release.copy_verified = self.fixture_copy

    @contextmanager
    def inputs(self):
        with n.directory_fd(self.input_root) as fd:
            yield fd

    @contextmanager
    def child(self, parent, name, uid, gid, *, mode, label, create):
        created = False
        if create:
            try:
                os.mkdir(name, mode, dir_fd=parent)
            except FileExistsError:
                pass
            else:
                created = True
        fd = os.open(name, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            yield fd, created
        finally:
            os.close(fd)

    def write(self, parent, name, writer, label):
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=parent)
        except FileExistsError:
            return
        with os.fdopen(fd, 'wb') as output:
            writer(output)

    def fixture_copy(self, source, expected, size, output):
        data = source.read_bytes()
        n.require(len(data) == size and g.digest(data) == expected, 'fixture source digest changed')
        output.write(data)

    def stage(self):
        with patch.object(n, 'private_child', self.child), patch.object(n, 'stable_file', self.write), \
                patch.object(n, 'current_boot', return_value=self.release.boot):
            return self.release.install('stage')

    def test_preflight_keeps_fixed_cli_response_and_never_loads(self):
        with patch.object(n, 'current_boot', return_value=self.release.boot):
            receipt = self.release.install('preflight')
        self.assertEqual(receipt, {'schema': 1, 'phase': 'preflight', 'platform_sha256': PLATFORM,
            'base_platform_sha256': BASE, 'site_config_sha256': SITE, 'boot_id': self.release.boot,
            'job': 'checklist', 'outer': {'oci_config_sha256': OUTER, 'oci_manifest_sha256': OUTER_MANIFEST},
            'manifest_sha256': None})
        self.assertFalse(list(self.input_root.iterdir()))
        self.release.load_outer.assert_not_called()

    def test_refresh_uses_independent_sources_and_preserves_previous_artifacts(self):
        first = self.stage()
        first_manifest = self.input_root / first['manifest_sha256'] / 'manifest.json'
        old = first_manifest.read_bytes()
        old_archive = first_manifest.with_name(n.RELEASE_ARCHIVE).read_bytes()
        self.stage_item('a' * 40, b'new authenticated image bytes')
        second = self.stage()
        current = self.input_root / second['manifest_sha256'] / 'manifest.json'
        observation = db.read_manifest(current, second['manifest_sha256'], time.monotonic() + 5)
        self.assertEqual(observation['outer']['source_sha'], OUTER_SOURCE)
        self.assertEqual(observation['inner']['source_sha'], 'a' * 40)
        self.assertNotEqual(first, second)
        self.assertEqual(first_manifest.read_bytes(), old)
        self.assertEqual(first_manifest.with_name(n.RELEASE_ARCHIVE).read_bytes(), old_archive)
        self.assertEqual(self.stage(), second)

    def test_changed_boot_preflight_fails_before_load_or_publication(self):
        self.release.admission_binding.return_value = {'fixture': 'changed boot'}
        with self.assertRaisesRegex(db.Blocked, 'current-boot preflight'):
            self.stage()
        self.release.load_outer.assert_not_called()
        self.release.establish.assert_not_called()
        self.assertFalse(list(self.input_root.iterdir()))

    def test_corrupt_new_input_cannot_replace_previous_manifest(self):
        first = self.stage()
        directory = self.input_root / first['manifest_sha256']
        old = (directory / 'manifest.json').read_bytes()
        self.stage_item('c' * 40, b'candidate')
        self.release.item.inner_path.write_bytes(b'corrupted')
        with self.assertRaisesRegex(db.Blocked, 'fixture source digest'):
            self.stage()
        self.assertEqual((directory / 'manifest.json').read_bytes(), old)
        self.assertEqual([path.parent for path in self.input_root.glob('*/manifest.json')], [directory])

    def test_stage_reconciles_interrupted_archive_before_budgeting_replay(self):
        first = self.stage()
        old = self.input_root / first['manifest_sha256']
        old_manifest = (old / 'manifest.json').read_bytes()
        old_archive = (old / n.RELEASE_ARCHIVE).read_bytes()
        self.stage_item('a' * 40, b'new authenticated image bytes')

        def interrupt(source, expected, size, output):
            output.write(source.read_bytes()[:-1])
            raise InterruptedError('after partial copy')

        def stage_writer(parent, name, writer, label):
            temporary = Path(os.readlink(f'/proc/self/fd/{parent}')) / (name + '.new')
            with temporary.open('xb') as output:
                os.fchmod(output.fileno(), 0o600)
                writer(output)

        self.release.copy_verified = interrupt
        with patch.object(self, 'write', stage_writer), self.assertRaises(InterruptedError):
            self.stage()
        pending, = self.input_root.glob(f'*/{n.RELEASE_ARCHIVE}.new')
        free = g.STAGE_HEADROOM + self.release.item.inner['archive_bytes']
        real_stat = os.stat

        def local_stat(path, *args, **kwargs):
            node = real_stat(path, *args, **kwargs)
            if path == n.RELEASE_ARCHIVE + '.new':
                return SimpleNamespace(st_uid=0, st_gid=0, st_mode=node.st_mode,
                                       st_nlink=node.st_nlink, st_size=node.st_size)
            return node

        def capacity(fd):
            return SimpleNamespace(f_bavail=free - pending.exists(), f_frsize=1, f_favail=4 - pending.exists())

        self.release.copy_verified = Mock(wraps=self.fixture_copy)
        with patch.object(os, 'stat', side_effect=local_stat), patch.object(os, 'fstatvfs', side_effect=capacity):
            current = self.stage()
            self.assertEqual(self.stage(), current)
        self.release.copy_verified.assert_called_once()
        self.assertFalse(pending.exists())
        self.assertEqual((old / 'manifest.json').read_bytes(), old_manifest)
        self.assertEqual((old / n.RELEASE_ARCHIVE).read_bytes(), old_archive)

    def test_reconcile_preserves_ambiguous_stage_links(self):
        source = self.release.item.inner_path
        pending = self.input_root / (n.RELEASE_ARCHIVE + '.new')
        pending.symlink_to(source)
        with n.directory_fd(self.input_root) as fd, self.assertRaisesRegex(db.Blocked, 'ambiguous released'):
            self.release.reconcile_inner_copy(fd, self.input_root)
        self.assertTrue(pending.is_symlink())
        self.assertEqual(source.read_bytes(), b'independent inner artifact')


class TestCurrentSelection(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.producer = n.DevelopmentGptbox(self.root)
        self.current = self.root / 'current.json'
        self.site = self.root / 'site-current.json'
        self.bindings = self.root / 'platform-bindings'
        self.bindings.mkdir()
        self.item = SimpleNamespace(previous='d' * 64, identity=PLATFORM, site=SITE, base=BASE, schema=2)
        self.ref = 'c' * 64
        self.enterContext(patch.object(g, 'RENEWAL', self.root))

    def select(self, platform, site=SITE):
        self.current.write_bytes(n.json_bytes(self.ref))
        self.site.write_bytes(n.json_bytes(self.ref))
        (self.bindings / (self.ref + '.json')).write_bytes(n.json_bytes(
            {'schema': 1, 'release_sha256': self.ref, 'site_config_sha256': site, 'platform_sha256': platform,
             'base_platform_sha256': BASE, 'plan_sha256': 'e' * 64, 'intake_sha256': 'f' * 64}))

    def test_release_install_requires_actual_current_previous_or_exact_reapply(self):
        with self.assertRaisesRegex(db.Blocked, 'previous platform'):
            g.current_selection(self.producer, self.item)
        self.item.previous = None
        self.assertIsNone(g.current_selection(self.producer, self.item))
        self.item.previous = 'd' * 64
        for platform in (self.item.previous, self.item.identity):
            self.select(platform)
            self.assertEqual(g.current_selection(self.producer, self.item), self.ref)
        self.site.write_bytes(n.json_bytes('1' * 64))
        with self.assertRaisesRegex(db.Blocked, 'selectors disagree'):
            g.current_selection(self.producer, self.item)
        self.select(self.item.previous, site='9' * 64)
        with self.assertRaisesRegex(db.Blocked, 'approved install'):
            g.current_selection(self.producer, self.item)


class TestRetainedProof(unittest.TestCase):
    def test_previous_installed_record_must_match_original_producer_serialization(self):
        prior = 'a' * 64
        boot = 'aabbccdd-1122-3344-5566-abcd0123abcd'
        producer_record = {'source_sha': OUTER_SOURCE, 'archive_bytes': 10}
        original = g.digest(n.image_inputs_bytes(producer_record))
        inner = {'context_sha256': 'd' * 64, 'oci_config_sha256': INNER,
                 'oci_manifest_sha256': INNER_MANIFEST}
        outer = {'oci_config_sha256': OUTER, 'oci_manifest_sha256': OUTER_MANIFEST}
        index = {'kind': 'dev-pair-platform-release', 'source_sha': OUTER_SOURCE, 'base_platform_sha256': None,
                 'components': {'devbox': {**outer, 'source_sha': OUTER_SOURCE}, 'development-agent': inner}}
        stored = {'schema': 1, 'platform_sha256': prior, 'base_platform_sha256': prior,
                  'site_config_sha256': SITE, 'boot_id': boot, 'source_sha': OUTER_SOURCE,
                  'components': {'host': {}, 'maintenance': {}, 'devbox': outer,
                                 'development': {**inner, 'inner_sha256': original,
                                                 'jobs': {'checklist': {'manifest_sha256': '9' * 64}}}}}
        item = SimpleNamespace(previous=prior, base=prior, identity=PLATFORM, site=SITE, job='checklist',
                               outer={'image': {'image_id': OUTER, 'source_sha': OUTER_SOURCE},
                                      'oci_manifest_sha256': OUTER_MANIFEST})
        with (patch.object(g, 'read_index', return_value=(Path('/protected/previous'), index)),
              patch.object(g, 'metadata', return_value=stored),
              patch.object(g, 'read_part', return_value={'producer': producer_record})):
            self.assertIs(g.previous_installed(None, item), stored)
            stored['components']['development']['inner_sha256'] = g.digest(n.json_bytes(producer_record))
            with self.assertRaisesRegex(db.Blocked, 'exact protected producer'):
                g.previous_installed(None, item)


class TestOuterReadback(unittest.TestCase):
    def setUp(self):
        self.placement = g.ReleasePlacement.__new__(g.ReleasePlacement)
        image = {'image_id': OUTER, 'source_sha': OUTER_SOURCE, 'diff_ids': ['sha256:' + '4' * 64]}
        self.placement.item = SimpleNamespace(outer={'image': image, 'oci_manifest_sha256': OUTER_MANIFEST})
        self.placement.previous = None
        self.placement.managed = Mock(return_value=(0, b''))
        self.placement.engine = Mock()
        self.row = {'Id': 'sha256:' + OUTER, 'Digest': 'sha256:' + OUTER_MANIFEST, 'RootFS': {'Layers': image['diff_ids']},
                    'Os': 'linux', 'Architecture': 'amd64',
                    'Labels': {'dev-pair.role': 'devbox', 'dev-pair.standards': db.STANDARDS,
                               'dev-pair.distrobox': db.DISTROBOX,
                               'org.opencontainers.image.revision': OUTER_SOURCE}}
        self.placement.inspect = Mock(return_value=self.row)

    def test_existing_wrong_oci_digest_or_source_never_reloads(self):
        self.placement.load_outer()
        self.placement.engine.assert_not_called()
        self.row['Digest'] = 'sha256:' + '5' * 64
        with self.assertRaisesRegex(db.Blocked, 'live outer config'):
            self.placement.load_outer()
        self.row['Digest'] = 'sha256:' + OUTER_MANIFEST
        self.row['Labels']['org.opencontainers.image.revision'] = DEVELOPMENT
        with self.assertRaisesRegex(db.Blocked, 'provenance'):
            self.placement.load_outer()
        self.placement.engine.assert_not_called()


class CliTests(unittest.TestCase):
    def test_release_subcommand_has_fixed_phase_and_identity_arguments(self):
        source = Path(n.__file__).resolve()
        output = subprocess.run([sys.executable, '-B', str(source), 'install-release', '--help'],
                                check=True, capture_output=True, timeout=10)
        self.assertIn(b'--phase {preflight,stage}', output.stdout)
        self.assertIn(b'--platform-sha256', output.stdout)
        self.assertIn(b'--job', output.stdout)


if __name__ == '__main__':
    unittest.main()
