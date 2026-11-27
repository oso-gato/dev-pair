"""Exercise the interactive owner control flow with local physical boundaries projected."""
from contextlib import contextmanager, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
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
        self.identity = {'machine_id': MACHINE, 'boot_id': BOOT, 'host': 'erebus'}

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
                                       'created_at': int(time.time()), 'origin_session': 1001, 'code': 'test-code'}))
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
        self.entry.transport = Mock(return_value=['--bootstrap-source', '192.0.2.44/32'])
        self.entry.managed_storage = Mock()
        self.entry.inputs = Mock(return_value=('context', 'upstream', 'a' * 64))
        self.entry.prepare = Mock()
        self.entry.enroll = Mock(return_value=False)
        self.entry.app.status.side_effect = [{'prepared': False}, {'prepared': True}]

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
              patch.object(gptbox.Gptbox, 'maintenance_host_readiness') as readiness, redirect_stdout(io.StringIO())):
            self.entry.start(None, None, None)
            self.entry.prepare.assert_not_called()
            self.identity['boot_id'] = '11111111-2222-3333-4444-000000000000'
            self.entry.start(None, None, None)
            self.entry.start(None, None, None)
            prompt.assert_called_once()
            self.entry.prepare.assert_called_once()
            readiness.assert_called_once_with('a' * 64)
        record = json.loads(self.entry.progress.read_bytes())
        self.assertEqual(record['machine_id'], MACHINE)
        self.assertEqual(record['phase'], 'host-bootstrap-complete')
        self.assertNotIn('password', self.entry.progress.read_text())

    def test_named_core_secret_uses_only_an_ephemeral_file(self):
        boot = self.directory / 'bootstrap'
        boot.mkdir()
        password = 'fixture-private-core-input'
        ephemeral = self.directory / 'ephemeral'
        seen = []

        @contextmanager
        def file(value):
            self.assertEqual(value, password)
            ephemeral.write_text(value)
            try:
                yield ephemeral
            finally:
                ephemeral.unlink()

        def call(name, *arguments, **kwargs):
            if '--password-file' in arguments:
                self.assertTrue(ephemeral.exists())
            seen.extend(map(str, arguments))

        self.entry.call = call
        with (patch.object(day, 'BOOTSTRAP', str(boot)), patch.object(day, 'secret_file', side_effect=file),
              patch.object(day, 'secret_answer', return_value=password) as prompt):
            self.entry.prepare(SOURCE, ['--bootstrap-source', '192.0.2.44/32'], ('context', 'upstream', 'a' * 64), None)
            self.assertFalse(ephemeral.exists())
            (boot / 'operator-password-set').touch()
            self.entry.prepare(SOURCE, ['--bootstrap-source', '192.0.2.44/32'], ('context', 'upstream', 'a' * 64), None)
            self.assertEqual(prompt.call_count, 2)
        self.assertNotIn(password, seen)

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
