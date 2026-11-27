"""Exercise the interactive owner control flow with local physical boundaries projected."""
from contextlib import contextmanager, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import owner_day0 as day
import bootstrap as bootstrap
import gptbox
import public_inputs

SOURCE = 'a' * 40
MACHINE = 'b' * 32
BOOT = '11111111-2222-3333-4444-555555555555'


def safe_local(path):
    node = path.lstat()
    if not stat.S_ISREG(node.st_mode) or node.st_nlink != 1 or node.st_mode & 0o022:
        raise bootstrap.Blocked('protected test file required')
    return path


class DayZeroTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(patch.object(day, 'local_file', side_effect=safe_local))
        self.entry = day.DayZero(self.directory / 'dev-pair', Mock())
        self.identity = {'machine_id': MACHINE, 'boot_id': BOOT, 'host': 'erebus', 'selinux': '1'}

    def test_gitless_kit_verification_and_signed_prerequisite(self):
        repo = self.entry.repo
        for name in ('day0.sh', 'tools/owner_day0.py', '.git/HEAD', '.git/index'):
            leaf = repo / name
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.write_bytes(name.encode())
        marker = self.directory / 'SOURCE'
        marker.write_text(SOURCE + '\n')
        manifest = self.directory / 'MANIFEST.sha256'
        files = [marker, *[path for path in repo.rglob('*') if path.is_file()]]
        manifest.write_text(''.join(f'{sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.directory)}\n' for path in files))
        git = self.directory / 'git'
        with patch.object(day, 'GIT', git):
            self.assertEqual(day.kit_source(repo), (SOURCE, True))
            self.entry.app.destination_source.return_value = SOURCE
            with patch.object(day.subprocess, 'run') as command:
                self.assertEqual(self.entry.ensure_git(SOURCE, True), SOURCE)
            self.assertEqual(command.call_args.args[0][-3:], ['--enablerepo=updates', 'install', 'git-core'])
            self.assertIn('--setopt=gpgcheck=1', command.call_args.args[0])
            self.entry.app.destination_source.assert_called_once_with(SOURCE)
            (repo / 'day0.sh').write_bytes(b'changed')
            with self.assertRaisesRegex(bootstrap.Blocked, 'bytes differ'):
                day.kit_source(repo)

    def test_public_checkout_uses_owner_supplied_pin_without_fabricated_manifest(self):
        path = self.directory / 'SOURCE'
        path.write_text(SOURCE + '\n')
        self.assertEqual(day.kit_source(self.entry.repo), (SOURCE, False))
        with self.assertRaisesRegex(bootstrap.Blocked, 'differs'):
            day.kit_source(self.entry.repo, 'c' * 40)

    def test_distinct_local_recovery_session_confirms_same_boot_and_source(self):
        path = self.directory / 'recovery.json'
        pending = path.with_name('challenge.json')
        pending.write_text(json.dumps({'schema': 1, 'machine_id': MACHINE, 'boot_id': BOOT, 'source_sha': SOURCE,
                                       'owner_checkout': str(self.entry.repo), 'created_at': int(time.time()), 'origin_session': 1001, 'code': 'test-code'}))
        pending.chmod(0o600)
        self.entry.original = Mock(return_value=self.identity)
        self.entry.app.ssh_ancestors.return_value = []
        records = []
        with (patch.object(day, 'ATTENDED_RECEIPT', str(path)), patch.object(day, 'kit_source', return_value=(SOURCE, False)),
              patch.object(day, 'secret_answer', return_value='test-code'), patch.dict(os.environ, {}, clear=True),
              patch.object(day, 'save', side_effect=lambda app, path, value: records.append(value)),
              patch.object(day.os, 'getsid', return_value=1001) as session):
            with self.assertRaisesRegex(bootstrap.Blocked, 'different current hPanel session'):
                self.entry.confirm_recovery(None, SOURCE)
            session.return_value = 1002
            self.entry.confirm_recovery(None, SOURCE)
        self.assertEqual(records[0]['kind'], bootstrap.ATTENDED_ACCESS)
        self.assertNotIn('code', records[0])
        self.assertEqual((records[0]['origin_session'], records[0]['confirmed_session']), (1001, 1002))
        self.assertNotIn('public_ssh_denied', records[0])

    def test_reboot_pause_resumes_same_source_without_second_host_or_core_setup(self):
        state = self.directory / 'state'
        boot = self.directory / 'bootstrap'
        boot.mkdir()
        desired = boot / 'desired.json'
        desired.write_text(json.dumps({'gptbox_context_sha256': 'a' * 64}))
        desired.chmod(0o600)
        self.entry.progress = state / 'progress.json'
        self.entry.original = Mock(return_value=self.identity)
        self.entry.ensure_git = Mock(return_value=SOURCE)
        self.entry.selinux = Mock(side_effect=[False, True, True])
        self.entry.transport = Mock(side_effect=[None, ['--bootstrap-source', '192.0.2.44/32'],
                                                   ['--bootstrap-source', '192.0.2.44/32']])
        self.entry.storage_geometry = Mock(return_value=(20480, 262144, 4096))
        self.entry.managed_storage = Mock()
        self.entry.inputs = Mock(return_value=('context', 'upstream', 'a' * 64))
        self.entry.prepare = Mock(return_value='b' * 64)
        self.entry.maintenance_receipt = Mock(return_value='b' * 64)
        self.entry.enroll = Mock(return_value=False)
        self.entry.app.status.side_effect = [{'prepared': False}, {'prepared': False}, {'prepared': False}, {'prepared': True}]

        def write(path, contents, **kwargs):
            target = Path(path)
            target.write_text(contents)
            target.chmod(0o600)

        original_stat = os.fstat

        def projected_stat(descriptor):
            node = original_stat(descriptor)
            return SimpleNamespace(st_uid=0, st_nlink=node.st_nlink, st_mode=node.st_mode)

        self.entry.app.atomic.side_effect = write
        with (patch.object(day, 'STATE', state), patch.object(day, 'BOOTSTRAP', str(boot)),
              patch.object(day, 'kit_source', return_value=(SOURCE, True)),
              patch.object(day, 'secure_directory', side_effect=lambda path: path.mkdir(exist_ok=True) or path),
              patch.object(day.os, 'fstat', side_effect=projected_stat),
              patch.object(day, 'answer', return_value='yes') as prompt,
              redirect_stdout(io.StringIO())):
            self.entry.start(None, None)
            self.entry.selinux.assert_not_called()
            self.entry.start(None, None)
            self.entry.prepare.assert_not_called()
            self.identity['boot_id'] = '11111111-2222-3333-4444-000000000000'
            self.entry.start(None, None)
            self.entry.start(None, None)
            prompt.assert_called_once()
            self.entry.prepare.assert_called_once()
            self.assertEqual(self.entry.maintenance_receipt.call_count, 2)
        record = json.loads(self.entry.progress.read_bytes())
        self.assertEqual(record['machine_id'], MACHINE)
        self.assertEqual(record['phase'], 'host-bootstrap-complete')
        self.assertNotIn('password', self.entry.progress.read_text())

    def test_normal_initializer_uses_the_verified_sanitized_checkout_and_ephemeral_core_password(self):
        boot = self.directory / 'bootstrap'
        boot.mkdir()
        password = 'fixture-private-core-input'
        ephemeral = self.directory / 'ephemeral'
        context = self.directory / 'extracted' / 'context'
        upstream = context.parent / 'distrobox'
        sanitized = context.parent / 'dev-pair'
        for checkout in (self.entry.repo, sanitized):
            (checkout / 'tools').mkdir(parents=True)
            for entry in ('bootstrap.py', 'gptbox.py'):
                (checkout / 'tools' / entry).write_text('exact ' + entry)
        seen = []
        probes = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': SOURCE, 'context_sha256': 'a' * 64,
                  'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False,
                  'assembled_image_id': 'b' * 64}

        @contextmanager
        def file(value):
            self.assertEqual(value, password)
            ephemeral.write_text(value)
            try:
                yield ephemeral
            finally:
                ephemeral.unlink()

        def call(name, *arguments, checkout, **kwargs):
            self.assertEqual(checkout, sanitized)
            if '--password-file' in arguments:
                self.assertTrue(ephemeral.exists())
            seen.append((name, *map(str, arguments)))
            return ({'phase': 'complete', 'maintenance_gptbox': 'complete', 'result': probes}
                    if name == 'bootstrap.py' else probes)

        self.entry.call = call
        with (patch.object(day, 'BOOTSTRAP', str(boot)), patch.object(day, 'secret_file', side_effect=file),
              patch.object(day, 'secret_answer', return_value=password) as prompt):
            input_paths = (context, upstream, 'a' * 64)
            initial = self.entry.prepare(SOURCE, ['--bootstrap-source', '192.0.2.44/32'], input_paths, None)
            self.assertEqual(initial, 'b' * 64)
            self.assertFalse(ephemeral.exists())
            prepared = self.entry.prepare(SOURCE, (), input_paths, None, already_prepared=True)
            self.assertEqual(prepared, initial)
            self.assertEqual(prompt.call_count, 2)
        self.assertEqual(seen[0][:2], ('bootstrap.py', 'initialize'))
        self.assertEqual(seen[1][:2], ('gptbox.py', 'assemble-prepared-maintenance'))
        self.assertNotIn(password, ' '.join(map(str, seen)))
        self.assertNotIn('--password-file', seen[1])
        with self.assertRaisesRegex(bootstrap.Blocked, 'both offline'):
            self.entry.probes({**probes, 'boundary_and_version_cycles': 1}, SOURCE, 'a' * 64)

    def test_enforcing_host_does_not_arm_relabel_or_reboot(self):
        self.entry.call = Mock(return_value={'live': 'Enforcing', 'persistent': 'enforcing', 'policy_present': True})
        with patch.object(day, 'ROOT', self.directory), patch.object(day, 'answer') as prompt:
            self.assertTrue(self.entry.selinux(self.identity, SOURCE, None))
        self.entry.call.assert_called_once_with('selinux_bootstrap.py', 'inspect')
        prompt.assert_not_called()

    def test_attended_guard_retains_existing_ssh_only_until_checked_cutover(self):
        temporary = bootstrap.Bootstrap.guard_rules([], retain_ssh=True)
        final = bootstrap.Bootstrap.guard_rules([], tailnet_only=True)
        self.assertIn('\nadd rule inet dev_pair_bootstrap input tcp dport 22 accept\n', temporary)
        self.assertNotIn('\nadd rule inet dev_pair_bootstrap input tcp dport 22 accept\n', final)
        self.assertIn('tcp dport { 22, 443 } drop', final)
        with self.assertRaises(bootstrap.Blocked):
            bootstrap.Bootstrap.guard_rules([], retain_ssh=True, tailnet_only=True)


    def test_admitted_sanitized_git_layout_from_normal_checkout(self):
        def commit(repo):
            for args in (('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                                        'commit', '-qm', 'owner source fixture')):
                subprocess.run(['/usr/bin/git', '-C', str(repo), *args], check=True)
            return subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()

        tree = Path(gptbox.__file__).resolve().parents[1]
        source = self.entry.repo
        (source / 'tools').mkdir(parents=True)
        for name in (*gptbox.ADAPTER_SOURCE_FILES, 'public_inputs.py'):
            (source / 'tools' / name).write_bytes((tree / 'tools' / name).read_bytes())
        runtime = source / 'runtime/devbox'
        runtime.mkdir(parents=True)
        (runtime / 'controller.py').write_bytes((tree / 'runtime/devbox/controller.py').read_bytes())
        revision = commit(source)
        upstream = self.directory / 'upstream'
        upstream.mkdir()
        for name in ('distrobox-init', 'distrobox-enter'):
            (upstream / name).write_text('fixture script\n')
        upstream_revision = commit(upstream)
        work = self.directory / 'work'
        (work / 'home').mkdir(parents=True)
        selected, distrobox = work / 'extracted/dev-pair', work / 'extracted/distrobox'
        for original, revision_pin, name, target in ((source, revision, 'dev-pair', selected),
                                                     (upstream, upstream_revision, 'distrobox', distrobox)):
            packed = work / name
            public_inputs.clean_checkout(original, revision_pin, packed, work)
            # The actual public-input handoff inventories files and recreates
            # the required ancestry. Stock Git's empty directories are omitted.
            for leaf in packed.rglob('*'):
                if leaf.is_file():
                    copy = target / leaf.relative_to(packed)
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    copy.write_bytes(leaf.read_bytes())
        app = gptbox.Gptbox(self.directory, lambda *args, **kwargs: subprocess.check_output(args, text=True))
        with (patch.object(gptbox, '__file__', str(selected / 'tools/gptbox.py')),
              patch.object(public_inputs, '__file__', str(selected / 'tools/public_inputs.py')),
              patch.object(gptbox, 'DBX_SHA', upstream_revision)):
            app.protect_host_sources(distrobox, revision)
            app.source(revision)
            self.assertFalse((selected / '.git/index').exists())
        self.assertEqual(subprocess.check_output(['/usr/bin/git', '-C', str(source), 'status', '--porcelain'], text=True), '')

    def test_physical_free_inodes_are_distinct_from_future_inner_capacity(self):
        with (patch.object(day, 'record', return_value=None), patch.object(day.os, 'statvfs') as volume,
              redirect_stdout(io.StringIO())):
            volume.return_value = SimpleNamespace(f_bavail=30 * 1024, f_frsize=day.MIB, f_favail=6000)
            self.assertEqual(self.entry.storage_geometry(), (20480, 262144, 4096))
            volume.return_value.f_bavail = 20 * 1024
            with self.assertRaisesRegex(bootstrap.Blocked, 'physical reserve'):
                self.entry.storage_geometry()

    def test_existing_relabel_marker_runs_the_lower_enforcing_gate(self):
        self.entry.call = Mock(side_effect=[{'live': 'Enforcing', 'persistent': 'enforcing', 'policy_present': True},
                                           bootstrap.Blocked('foreign relabel is pending')])
        self.entry.stage = Mock()
        with patch.object(day.os.path, 'lexists', side_effect=lambda path: str(path) == '/.autorelabel'):
            with self.assertRaisesRegex(bootstrap.Blocked, 'foreign relabel'):
                self.entry.selinux(self.identity, SOURCE, None)
        self.assertEqual(self.entry.call.call_args.args[1], 'converge')
