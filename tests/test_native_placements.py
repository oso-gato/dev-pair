"""Local storage ownership, release custody and managed-entry checks for the native bridge."""

from contextlib import contextmanager, ExitStack
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
import tomllib
from unittest.mock import Mock, patch

from test_devbox import manifest, oci_archive

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_placements as n
from gptbox import DevelopmentGptbox, RELEASE_INNER, image_inputs_bytes

db = n.db


class TestProtectedPublication(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(TemporaryDirectory())
        self.root = Path(scratch)
        self.producer = DevelopmentGptbox(self.root)
        self.inner = manifest()['inner']
        self.context = self.inner['context_sha256']
        self.revision = self.inner['source_sha']
        self.attempt = {'source_sha': self.revision, 'context_sha256': self.context,
                        'distrobox_sha': db.DISTROBOX, 'count': 1}
        self.target = self.root / n.DEVELOPMENT_ROOT.lstrip('/') / self.context
        self.target.mkdir(parents=True)
        self.artifacts = self.root / n.DEVELOPMENT_ARTIFACTS.lstrip('/')
        self.release = self.artifacts / self.context / 'release'
        self.release.mkdir(parents=True, mode=0o700)
        self.archive = self.release / n.RELEASE_ARCHIVE
        self.inner.update(oci_archive(self.archive))
        self.archive.chmod(0o444)
        self.write(self.release / RELEASE_INNER, self.inner, 0o444)
        self.write(self.target / 'attempt.json', self.attempt, 0o600)
        self.receipt = {'schema': 1, 'attempt': self.attempt, 'phase': 'ready',
                        'directory': n.identity(self.release.stat()), 'inner': self.inner,
                        'inner_sha256': hashlib.sha256(image_inputs_bytes(self.inner)).hexdigest()}
        self.write(self.target / 'publication.json', self.receipt, 0o600)
        self.enterContext(patch.object(n, 'DEVELOPMENT_ARTIFACTS', str(self.artifacts)))

    def write(self, destination, value, mode):
        if destination.exists():
            destination.chmod(0o600)
        destination.write_bytes(image_inputs_bytes(value))
        destination.chmod(mode)

    def read(self, revision=None):
        return n.protected_publication(self.producer, revision or self.revision, self.context)

    def test_uses_exact_producer_receipt_and_archive(self):
        inner, archive = self.read()
        self.assertEqual((inner, archive), (self.inner, self.archive))
        db.check_archive_image(archive, inner, db.GIB, n.time.monotonic() + 1)
        self.archive.chmod(0o600)
        original = self.archive.read_bytes()
        self.archive.write_bytes(b'X' + original[1:])
        self.archive.chmod(0o444)
        with self.assertRaisesRegex(n.BootstrapBlocked, 'no longer matches'):
            self.read()

    def test_pending_or_wrong_source_blocks_the_published_directory(self):
        with self.assertRaisesRegex(n.BootstrapBlocked, 'attempt record'):
            self.read('a' * 40)
        self.write(self.target / 'publication.json', {**self.receipt, 'phase': 'verified'}, 0o600)
        with self.assertRaisesRegex(db.Blocked, 'protected ready'):
            self.read()
        self.write(self.target / 'publication.json', self.receipt, 0o600)
        self.release.with_name('release.pending').mkdir()
        with self.assertRaisesRegex(db.Blocked, 'protected ready'):
            self.read()


class TestKernelOwnership(unittest.TestCase):
    def test_anchors_directories_and_rejects_a_symlink_parent(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            real = root / 'real'
            real.mkdir()
            alias = root / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            with n.directory_fd(real) as fd:
                self.assertEqual(os.fstat(fd).st_ino, real.stat().st_ino)
                renamed = root / 'renamed'
                real.rename(renamed)
                real.mkdir()
                self.assertEqual(os.fstat(fd).st_ino, renamed.stat().st_ino)
                self.assertNotEqual(os.fstat(fd).st_ino, real.stat().st_ino)
            with self.assertRaises(OSError), n.directory_fd(alias):
                self.fail('followed untrusted parent')

    def test_loop_lookup_rejects_aliases_offsets_and_multiple_results(self):
        image = Path('/protected/backing.ext4')
        row = {'name': '/dev/loop5', 'back-file': str(image), 'offset': 0, 'sizelimit': 0,
               'ro': False, 'autoclear': False}
        for rows, answer in (([], None), ([row], Path('/dev/loop5'))):
            with patch.object(n, 'command', return_value=(0, n.json_bytes({'loopdevices': rows}))):
                self.assertEqual(n.associated(image), answer)
        for rows in ([row, row], [{**row, 'offset': 4096}], [{**row, 'back-file': str(image) + ' (deleted)'}]):
            with self.subTest(rows=rows), patch.object(n, 'command',
                    return_value=(0, n.json_bytes({'loopdevices': rows}))), self.assertRaises(db.Blocked):
                n.associated(image)

    def test_mount_reports_finite_space_and_inodes_and_rejects_alias(self):
        target = Path(self.enterContext(TemporaryDirectory()))
        device = Path('/dev/loop5')
        number = f'{os.major(target.stat().st_dev)}:{os.minor(target.stat().st_dev)}'
        row = f'34 21 {number} / {target} rw,nosuid,nodev,noatime - ext4 /dev/loop5 rw'.split()
        fs = SimpleNamespace(f_blocks=10000, f_bavail=8000, f_frsize=4096, f_files=400, f_favail=391)
        with patch.object(n, 'block_id', return_value=number), patch.object(n.os, 'statvfs', return_value=fs):
            with patch.object(n, 'mount_rows', return_value=[row]):
                proof = n.validate_mount(device, target, 50000000)
                self.assertEqual(proof['bytes'], 40960000)
                self.assertEqual(proof['inodes'], 400)
                self.assertEqual(proof['available_inodes'], 391)
                fs.f_files = n.INODE_CEILING + 1
                with self.assertRaisesRegex(db.Blocked, 'storage/inode'):
                    n.validate_mount(device, target, 50000000)
            alias = f'35 21 {number} / {target}-alias rw,nosuid,nodev - ext4 /dev/loop5 rw'.split()
            with patch.object(n, 'mount_rows', return_value=[row, alias]), self.assertRaisesRegex(db.Blocked, 'unique'):
                n.validate_mount(device, target, 50000000)
            child = f'36 34 0:2 / {target}/graph rw,nosuid,nodev - tmpfs tmpfs rw'.split()
            with patch.object(n, 'mount_rows', return_value=[row, child]), self.assertRaisesRegex(db.Blocked, 'descendant'):
                n.validate_mount(device, target, 50000000)

    def test_reserve_is_charged_before_allocating_a_new_volume(self):
        with TemporaryDirectory() as scratch:
            placement = SimpleNamespace(record=Path(scratch) / 'lease.json', backings=Path(scratch),
                                        state={'volumes': {}}, save=Mock())
            volume = n.Volume(placement, 'build', Path('/native/build'), 16 * db.GIB)
            stats = SimpleNamespace(f_bavail=16 * db.GIB, f_frsize=1, f_files=100000, f_favail=80000)
            with patch.object(n.os, 'statvfs', return_value=stats), self.assertRaisesRegex(db.Blocked, 'headroom'):
                volume.backing_file()
            self.assertFalse(volume.backing.exists())
            placement.save.assert_not_called()

    def test_reserved_categories_are_disjoint_from_live_and_durable_roles(self):
        used = {1023, 1020, 1018}
        assigned = n.allocate_categories(used)
        self.assertEqual(assigned, {'outer': [1019, 1021, 1022], 'inner': [1019, 1021]})
        self.assertTrue(used.isdisjoint(assigned['outer']))
        with self.assertRaisesRegex(db.Blocked, 'three exclusive'):
            n.allocate_categories(set(range(1022)))

    def test_exact_kernel_free_space_preserves_remaining_metadata_and_inodes(self):
        requested = 13 * db.GIB
        sample = SimpleNamespace(f_bavail=requested + n.HOST_METADATA_BYTES, f_frsize=1,
                                 f_files=100000, f_favail=n.HOST_INODE_HEADROOM)
        with patch.object(n.os, 'statvfs', return_value=sample):
            self.assertEqual(n.reserve_managed(Path('/managed'), requested), sample.f_bavail)
            sample.f_bavail -= 1
            with self.assertRaisesRegex(db.Blocked, 'headroom'):
                n.reserve_managed(Path('/managed'), requested)
            sample.f_bavail += 1
            sample.f_files = sample.f_favail = 0
            with self.assertRaisesRegex(db.Blocked, 'inode'):
                n.reserve_managed(Path('/managed'), requested)

    def test_unregistered_mount_cannot_create_unbounded_write_class(self):
        root = Path('/var/lib/dev-pair')
        graph = root / 'development/builds/fixture'
        row = '50 32 7:4 / /var/lib/dev-pair/development/builds/fixture rw - ext4 /dev/loop4 rw'.split()
        n.verify_enrollment([row], {graph}, (root,))
        with self.assertRaisesRegex(db.Blocked, 'unregistered mount'):
            n.verify_enrollment([row], set(), (root,))

    def test_normal_consumer_proves_external_reserve_for_exact_nested_parent(self):
        host = Path(self.enterContext(TemporaryDirectory()))
        enclosing = host / 'dev-pair'
        role = enclosing / 'development'
        build = role / 'builds' / 'fixture'
        inner_backing = enclosing / 'native-placements/backings/fixture/build.ext4'
        parent_backing = host / 'dev-pair-managed.ext4'
        build.mkdir(parents=True)
        inner_backing.parent.mkdir(parents=True)
        for file in (inner_backing, parent_backing):
            file.write_bytes(b'trusted fixture')
        host_dev, managed_dev, build_dev = os.makedev(8, 1), os.makedev(7, 3), os.makedev(7, 5)
        framed = {
            host: SimpleNamespace(st_dev=host_dev),
            enclosing: SimpleNamespace(st_dev=managed_dev, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755),
            build.parent: SimpleNamespace(st_dev=managed_dev),
            build: SimpleNamespace(st_dev=build_dev),
            inner_backing: SimpleNamespace(st_dev=managed_dev, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600,
                                           st_nlink=1, st_size=8 * db.GIB, st_blocks=8 * db.GIB // 512),
            parent_backing: SimpleNamespace(st_dev=host_dev, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600,
                                            st_nlink=1, st_size=20 * db.GIB, st_ino=19, st_blocks=20 * db.GIB // 512),
        }
        info = (f'4 1 8:1 / {host} rw - ext4 /dev/sda1 rw\n'
                f'5 4 7:3 / {enclosing} rw,nosuid,nodev - ext4 /dev/loop3 rw\n'
                f'6 5 7:5 / {build} rw,nosuid,nodev - ext4 /dev/loop5 rw\n')
        stats = {
            host: SimpleNamespace(f_bavail=8 * db.GIB, f_frsize=1, f_files=100000, f_favail=4096),
            enclosing: SimpleNamespace(f_blocks=19 * db.GIB, f_bavail=db.GIB, f_frsize=1,
                                       f_files=100000, f_favail=10000),
            build: SimpleNamespace(f_blocks=7 * db.GIB, f_frsize=1),
            build.parent: SimpleNamespace(f_bavail=db.GIB, f_frsize=1),
        }
        sysfs = Path('/sys/dev/block')
        paths = {sysfs / '7:3/loop/backing_file': str(parent_backing), sysfs / '7:3/loop/offset': '0',
                 sysfs / '7:3/loop/sizelimit': '0', sysfs / '7:5/loop/backing_file': str(inner_backing)}
        actual_stat, actual_lstat = Path.stat, Path.lstat
        with ExitStack() as patched:
            patched.enter_context(patch.object(n.devbox, 'ROOT', role))
            patched.enter_context(patch.object(n.devbox, 'MANAGED_BACKING', parent_backing))
            patched.enter_context(patch.object(Path, 'stat',
                lambda path, **kwargs: framed[path] if path in framed else actual_stat(path, **kwargs)))
            patched.enter_context(patch.object(Path, 'lstat',
                lambda path: framed[path] if path in framed else actual_lstat(path)))
            patched.enter_context(patch.object(Path, 'exists', lambda path: path in paths or path in framed))
            patched.enter_context(patch.object(Path, 'read_text', lambda path: paths[path]))
            patched.enter_context(patch.object(n.os, 'statvfs', lambda path: stats[path]))
            proof = n.devbox.storage_mount(build, 8 * db.GIB, info)
            self.assertEqual(proof['managed_storage']['host_available_bytes'], 8 * db.GIB)
            self.assertEqual(proof['managed_storage']['available_bytes'], db.GIB)
            stats[host].f_files = stats[host].f_favail = 0
            with self.assertRaisesRegex(db.Blocked, 'finite inode'):
                n.devbox.storage_mount(build, 8 * db.GIB, info)
            stats[enclosing].f_favail = stats[enclosing].f_bavail = stats[host].f_bavail = 0
            recovery = n.devbox.managed_storage(info, for_recovery=True)
            self.assertEqual((recovery['backing_inode'], recovery['available_inodes'], recovery['available_bytes']), (19, 0, 0))
            with self.assertRaisesRegex(db.Blocked, 'inode ceiling'):
                n.devbox.managed_storage(info)
            stats[enclosing].f_favail = 10000
            stats[host].f_files, stats[host].f_favail = 100000, 4096
            framed[parent_backing].st_blocks -= 1
            with self.assertRaisesRegex(db.Blocked, 'sparse'):
                n.devbox.storage_mount(build, 8 * db.GIB, info)
            with self.assertRaisesRegex(db.Blocked, 'sparse'):
                n.devbox.managed_storage(info, for_recovery=True)

    def test_inode_is_rebound_to_verified_new_minor_and_exchanged_leaf_is_rejected(self):
        scratch = Path(self.enterContext(TemporaryDirectory()))
        path = scratch / 'inputs'
        path.mkdir()
        node = path.stat()
        earlier_loop = SimpleNamespace(**{field: getattr(node, field) for field in
                                          ('st_ino', 'st_uid', 'st_gid', 'st_mode')}, st_dev=node.st_dev + 1)
        self.assertNotEqual(n.identity(earlier_loop), n.identity(node))
        volume = SimpleNamespace(info={'inputs': n.volume_inode(earlier_loop)},
                                 device=SimpleNamespace(stat=lambda: SimpleNamespace(st_rdev=node.st_dev)))
        placement = n.Placement.__new__(n.Placement)
        placement.build_path = scratch
        placement.outer_label = 'fixture'
        placement.existing_volume = Mock(return_value=volume)

        @contextmanager
        def opened(parent, name, *owners, **options):
            fd = os.open(name, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                yield fd, False
            finally:
                os.close(fd)

        with patch.object(n, 'private_child', opened):
            with placement.build_inputs() as fd:
                self.assertEqual(os.fstat(fd).st_ino, node.st_ino)
            path.rename(scratch / 'preserved')
            path.mkdir()
            with self.assertRaisesRegex(db.Blocked, 'input directory was exchanged'), placement.build_inputs():
                self.fail('accepted a replacement inode')


class TestStagedAccess(unittest.TestCase):
    def test_ordinary_storage_check_stats_backing_with_execute_only_ancestors(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        backings = root / 'backings'
        job = backings / 'fixture'
        for directory in (backings, job):
            directory.mkdir(mode=0o711)
            directory.chmod(0o711)
        image = job / 'build.ext4'
        image.write_bytes(os.urandom(8192))
        image.chmod(0o000)  # Simulate the role's lack of access to root's mode-0600 bytes.
        payload = f"""import os, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, {str(n.SOURCE / 'tools')!r})
import devbox
volume = Path('/dev/shm')
node = volume.stat()
device = f'{{os.major(node.st_dev)}}:{{os.minor(node.st_dev)}}'
sysfs = Path('/sys/dev/block') / device / 'loop/backing_file'
real_exists, real_read, real_statvfs = Path.exists, Path.read_text, os.statvfs
def mount_space(path):
    if path == volume.parent:
        return SimpleNamespace(f_bavail=8 * devbox.db.GIB, f_frsize=1)
    return real_statvfs(path)
with patch.object(Path, 'exists', lambda path: path == sysfs or real_exists(path)), \
     patch.object(Path, 'read_text', lambda path: {str(image)!r} if path == sysfs else real_read(path)), \
     patch.object(os, 'statvfs', mount_space):
    info = f'10 1 {{device}} / /dev/shm rw - ext4 /dev/loop5 rw'
    capacity = real_statvfs(volume)
    assert devbox.storage_mount(volume, capacity.f_blocks * capacity.f_frsize, info)['device'] == device
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', payload], check=False, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        if os.geteuid() != 0:
            backings.chmod(0)
            denied = subprocess.run([sys.executable, '-I', '-B', '-c', payload],
                                    check=False, capture_output=True, timeout=5)
            backings.chmod(0o711)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn(b'PermissionError', denied.stderr)

    def test_real_launcher_stage_is_traversable_under_private_umask(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        root.chmod(0o755)

        class Relocated(DevelopmentGptbox):
            def directory(self, name, mode=0o700, owner=None):
                return super().directory('/' + str(Path(name).relative_to(self.root)), mode, owner)

        placement = n.Placement.__new__(n.Placement)
        placement.producer = Relocated(root)
        placement.recipes = root / 'recipes'
        placement.entry = placement.recipes / 'entry'
        placement.entry_files = {name: (n.SOURCE / name).read_bytes() for name in n.ENTRY_FILES}
        previous = os.umask(0o077)
        try:
            n.protected_directories(placement.producer, placement.recipes)
            placement.stage_entry()
        finally:
            os.umask(previous)
        for leaf in (*n.ENTRY_FILES, 'tools/placement_check.py'):
            path = placement.entry / leaf
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            for ancestor in path.parents:
                if ancestor == root:
                    break
                self.assertEqual(stat.S_IMODE(ancestor.stat().st_mode), 0o755)
        probe = """import sys, tomllib
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import devbox
with (devbox.RUNTIME / 'host-containers.conf').open('rb') as stream:
    assert tomllib.load(stream)['containers']['default_capabilities'] == ['CAP_SETUID', 'CAP_SETGID']
print(devbox.__file__)
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', probe, str(placement.entry / 'tools')],
                                check=True, capture_output=True, timeout=5)
        self.assertEqual(Path(result.stdout.decode().strip()), placement.entry / 'tools/devbox.py')

    def test_build_profile_has_filecap_without_runtime_sysadmin_and_removes_inherited_sudo(self):
        caps = tomllib.loads(n.BUILD_CONF.decode())['containers']['default_capabilities']
        self.assertIn('CAP_SETFCAP', caps)
        self.assertIn('CAP_CHOWN', caps)
        self.assertNotIn('CAP_SYS_ADMIN', caps)
        self.assertIn('rpm --test -e sudo && rpm -e sudo', n.TOOLING_RECIPE.decode())
        self.assertIn('test ! -e /usr/bin/sudo', n.TOOLING_RECIPE.decode())


class TestManagedEntry(unittest.TestCase):
    def placement(self):
        candidate = n.Placement.__new__(n.Placement)
        candidate.boot = 'fixture-boot'
        candidate.state = n.new_record({'source_sha': manifest()['outer']['source_sha']}, set())
        candidate.account = SimpleNamespace(pw_uid=1234, pw_dir='/home/dp-dev')
        candidate.entry = Path('/protected/entry')
        candidate.recipes = candidate.entry.parent
        candidate.copy_path = Path('/bounded/host-copy')
        candidate.save = Mock()
        return candidate

    def test_fixed_dp_dev_service_preserves_the_consumer_failure(self):
        candidate = self.placement()
        failure = db.Blocked('timeout: command exit 2 — DevBox blocked: exact entry failure')
        missing = (4, b'LoadState=not-found\nActiveState=inactive\n')
        with patch.object(n, 'command', side_effect=[missing, failure, missing]) as control, \
                patch.object(n, 'verify_inactive_cgroup') as proof:
            with self.assertRaisesRegex(db.Blocked, 'exact entry failure'):
                candidate.managed('/usr/bin/python3', '-I', '/protected/entry/tools/devbox.py', 'run', seconds=610)
        launch = control.call_args_list[1].args
        for option in ('--uid=dp-dev', '--property=RuntimeMaxSec=610s', '--property=MemoryMax=2G',
                       '--property=MemorySwapMax=0', '--property=TasksMax=512', '--property=CPUQuota=100%',
                       'CONTAINERS_CONF=/protected/entry/runtime/devbox/host-containers.conf'):
            self.assertIn(option, launch)
        self.assertIn(('-i', 'PATH=/usr/bin:/usr/sbin:/bin'), tuple(zip(launch, launch[1:])))
        self.assertNotIn('TMPDIR=/bounded/host-copy', launch)
        proof.assert_called_once()
        self.assertIsNone(candidate.state['activity'])

    def test_disappeared_uncertain_launch_retains_recovery_record(self):
        candidate = self.placement()
        unit = 'dev-pair-gptbox-' + 'a' * 64 + '.service'
        record = {'unit': unit, 'boot': candidate.boot, 'deadline': n.time.monotonic() + 60}
        candidate.state['activity'] = record
        missing = (4, b'LoadState=not-found\nActiveState=inactive\n')
        with patch.object(n, 'command', return_value=missing), patch.object(n, 'verify_inactive_cgroup') as proof:
            with self.assertRaisesRegex(db.Blocked, 'ambiguous'):
                candidate.reconcile(interrupted=True)
            self.assertEqual(candidate.state['activity'], record)
            proof.assert_not_called()
            candidate.boot = 'new-boot'
            candidate.reconcile(interrupted=True)
            proof.assert_called_once_with(unit)
            self.assertIsNone(candidate.state['activity'])

    def test_untyped_systemd_failure_preserves_uncertainty_and_primary(self):
        candidate = self.placement()
        missing = (4, b'LoadState=not-found\nActiveState=inactive\n')
        manager_failure = db.Blocked('timeout: command exit 2 — systemd launcher failed')
        with patch.object(n, 'command', side_effect=[missing, manager_failure, missing]), \
                patch.object(n, 'verify_inactive_cgroup') as proof:
            with self.assertRaisesRegex(db.Blocked, 'systemd launcher failed.*cleanup unresolved'):
                candidate.managed('/usr/bin/podman', 'load', seconds=30)
        self.assertIsNotNone(candidate.state['activity'])
        proof.assert_not_called()

    def test_idle_broker_and_launcher_are_tied_to_verified_user_bus_scope(self):
        scope = '/user.slice/user-1234.slice/user@1234.service'
        names = (('/usr/bin/dbus-broker','dbus-broker'), ('/usr/bin/dbus-broker-launch','dbus-broker-lau'))
        for program, name in names:
            with self.subTest(program=program), patch.object(n.os, 'readlink', return_value=program):
                with patch.object(Path, 'read_text', return_value='0::' + scope + '/session.slice/dbus-broker.service\n'):
                    self.assertTrue(n.idle_process(105, name, 101, scope, None))
                with patch.object(Path, 'read_text', return_value='0::' + scope + '/app.slice/unrelated.service\n'):
                    self.assertFalse(n.idle_process(105, name, 101, scope, None))
        with patch.object(n.os, 'readlink', return_value='/usr/bin/python3'), \
                patch.object(Path, 'read_text', return_value='0::' + scope + '/session.slice/dbus-broker.service'):
            self.assertFalse(n.idle_process(105, 'dbus-broker', 101, scope, 105))

    def test_uncertain_signed_base_import_keeps_its_spool_on_bounded_storage(self):
        candidate = self.placement()
        candidate.cache = Path('/protected/cache')
        candidate.scratch_path = Path(self.enterContext(TemporaryDirectory()))
        candidate.validate_scratch = Mock()
        failure = db.Blocked('owned systemd cleanup unresolved')

        @contextmanager
        def verified(cache, *, temporary_parent, leased):
            self.assertEqual(cache, candidate.cache)
            with n.fedora_oci._verification_tree(temporary_parent, leased) as scratch:
                archive = Path(scratch) / 'base.oci.tar'
                archive.write_bytes(b'signed archive fixture')
                yield archive, {'verified': True}

        def import_image(engine, archive, *, uid):
            self.assertEqual(uid, candidate.account.pw_uid)
            return engine('load', str(archive), timeout=5)

        def interrupted(*argv, **options):
            candidate.state['activity'] = {'unit': 'fixture-pending'}
            raise failure

        with patch.object(n.fedora_oci, 'verified', verified), \
                patch.object(n.fedora_oci, 'import_image', import_image), \
                patch.object(n, 'private_child', side_effect=self.local_child), \
                patch.object(candidate, 'managed', side_effect=interrupted):
            with self.assertRaisesRegex(db.Blocked, 'cleanup unresolved'):
                candidate.import_fedora_base()
        records = list(candidate.scratch_path.glob('verification/dev-pair-fedora-*/base.oci.tar'))
        self.assertEqual([record.read_bytes() for record in records], [b'signed archive fixture'])
        self.assertIsNotNone(candidate.state['verification'])
        candidate.state['activity'] = None
        candidate.cleanup_verification()
        self.assertFalse(records[0].exists())

    @contextmanager
    def local_child(self, parent, name, uid, gid, **options):
        os.mkdir(name, 0o755, dir_fd=parent)
        fd = os.open(name, os.O_DIRECTORY, dir_fd=parent)
        try:
            yield fd, True
        finally:
            os.close(fd)

    def test_signed_base_save_limits_file_size_within_bounded_copy_path(self):
        candidate = self.placement()
        candidate.managed = Mock(return_value=(0, b''))
        candidate.validate_scratch = Mock()
        candidate.engine('save', '--output', '/bounded/archive.oci.tar', timeout=5)
        argv = candidate.managed.call_args.args
        limit = n.fedora_oci.SAVE_FILE_LIMIT
        self.assertEqual(argv[:3], ('/usr/bin/prlimit', f'--fsize={limit}:{limit}', '--'))
        self.assertEqual(candidate.managed.call_args.kwargs, {'copy': True, 'build': False, 'seconds': 5})

    def test_build_uses_separate_capability_profile_and_exact_copy_root(self):
        candidate = self.placement()
        missing = (4, b'LoadState=not-found\nActiveState=inactive\n')
        with patch.object(n, 'command', side_effect=[missing, (0, b'image-id'), missing]) as calls, \
                patch.object(candidate, 'validate_scratch') as scratch, patch.object(n, 'verify_inactive_cgroup'):
            self.assertEqual(candidate.engine('build', '--network=none'), b'image-id')
        scratch.assert_called_once()
        launch = calls.call_args_list[1].args
        self.assertIn('CONTAINERS_CONF=/protected/build-containers.conf', launch)
        self.assertIn('TMPDIR=/bounded/host-copy', launch)
        self.assertNotIn('CONTAINERS_CONF=/protected/entry/runtime/devbox/host-containers.conf', launch)

    def test_foreign_unit_is_never_stopped(self):
        candidate = self.placement()
        unit = 'dev-pair-gptbox-' + 'a' * 64 + '.service'
        record = {'unit': unit, 'boot': candidate.boot, 'deadline': n.time.monotonic() + 60}
        candidate.state['activity'] = record
        foreign = (0, b'LoadState=loaded\nActiveState=active\nDescription=unowned\nUser=dp-dev\n')
        with patch.object(n, 'command', return_value=foreign) as control:
            with self.assertRaisesRegex(db.Blocked, 'foreign systemd unit preserved'):
                candidate.reconcile(interrupted=True)
            control.assert_called_once()
        self.assertEqual(candidate.state['activity'], record)

    def test_image_record_keeps_config_id_and_manifest_digest_distinct(self):
        row = {'Architecture': 'amd64', 'Os': 'linux', 'Id': 'sha256:' + 'a' * 64,
               'Digest': 'sha256:' + 'b' * 64, 'RootFS': {'Layers': ['sha256:' + 'c' * 64]}}
        record = n.image_shape(row)
        self.assertEqual(record, {'config_id': 'a' * 64, 'oci_manifest_digest': 'sha256:' + 'b' * 64,
                                  'diff_ids': ['sha256:' + 'c' * 64]})
        row['Digest'] = 'latest'
        with self.assertRaisesRegex(db.Blocked, 'manifest digest'):
            n.image_shape(row)

    def completion_fixture(self, candidate):
        candidate.job = 'test-entry'
        candidate.reconcile = Mock()
        candidate.reconcile_verification = Mock()
        candidate.check_categories = Mock()
        candidate.establish_storage = Mock(return_value={'build': {'inodes': 8}})
        candidate.verify_archive = Mock()
        candidate.stage_entry = Mock()
        candidate.verify_role_access = Mock()
        candidate.prepare_images = Mock(return_value={'graphroot': '/bounded/outer'})
        digest = 'd' * 64
        candidate.write_manifest = Mock(return_value=(Path('/bounded/manifest.json'), digest))
        candidate.record = Path('/protected/job/placement.json')
        candidate.inner = manifest()['inner']
        candidate.state['images'] = {'outer': {'config_id': 'e' * 64}}
        receipt = {'manifest_sha256': digest, 'job_admission': False, 'inner_removed': True, 'outer_removed': True,
                   'outer_image_id': 'e' * 64, 'archive_sha256': candidate.inner['archive_sha256']}
        candidate.managed = Mock(return_value=(0, n.json_bytes(receipt)))
        return receipt

    def test_known_spool_is_reclaimed_before_exhausted_image_retry(self):
        candidate = self.placement()
        self.completion_fixture(candidate)
        candidate.scratch_path = Path(self.enterContext(TemporaryDirectory()))
        spool = candidate.scratch_path / 'verification'
        spool.mkdir()
        (spool / 'captured-signed-layer').write_bytes(b'candidate-owned content')
        candidate.state['verification'] = n.volume_inode(spool.stat())
        candidate.validate_scratch = Mock()
        candidate.reconcile_verification = n.Placement.reconcile_verification.__get__(candidate)
        candidate.state['assembly_attempts'] = 2
        candidate.state['images'] = None
        candidate.initialize_scratch = Mock()
        candidate.engine_store = Mock(return_value={})
        candidate.prepare_images = n.Placement.prepare_images.__get__(candidate)
        volume = SimpleNamespace(info={'prepared': True}, allocated=lambda: n.SCRATCH_BYTES, mount=Mock())
        with patch.object(n, 'Volume', return_value=volume), self.assertRaisesRegex(db.Blocked, 'two-attempt'):
            candidate.run(retry=True)
        volume.mount.assert_called_once()
        self.assertFalse(spool.exists())
        self.assertIsNone(candidate.state['verification'])

    def test_same_boot_reapply_reuses_exact_result_and_new_boot_reproves(self):
        candidate = self.placement()
        self.completion_fixture(candidate)
        first = candidate.run(retry=False)
        self.assertFalse(first['reused'])
        self.assertFalse(first['job_admission'])
        replay = candidate.run(retry=False)
        self.assertTrue(replay['reused'])
        candidate.managed.assert_called_once()
        candidate.boot = 'different-boot'
        reboot = candidate.run(retry=False)
        self.assertFalse(reboot['reused'])
        self.assertEqual(reboot['boot_id'], 'different-boot')
        self.assertEqual(candidate.managed.call_count, 2)

    def test_failed_devbox_proof_stays_unpublished_and_retry_is_bounded(self):
        candidate = self.placement()
        receipt = self.completion_fixture(candidate)
        candidate.managed.return_value = (0, n.json_bytes({**receipt, 'job_admission': True}))
        with self.assertRaisesRegex(db.Blocked, 'does not prove'):
            candidate.run(retry=False)
        self.assertIsNone(candidate.state['report'])
        with self.assertRaisesRegex(db.Blocked, 'explicit --retry'):
            candidate.run(retry=False)
        with self.assertRaisesRegex(db.Blocked, 'does not prove'):
            candidate.run(retry=True)
        with self.assertRaisesRegex(db.Blocked, 'two-attempt'):
            candidate.run(retry=True)
        self.assertEqual(candidate.managed.call_count, 2)


if __name__ == '__main__':
    unittest.main()
