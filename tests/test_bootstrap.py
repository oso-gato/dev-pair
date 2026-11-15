"""Synthetic tempfile/command tests. These do NOT establish Fedora/runtime behavior."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bootstrap', ROOT / 'tools/bootstrap.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKsyntheticfixtureonly\n'

class Fake:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.accounts = {}
        self.fail = None
        self.node = {'BackendState': 'NeedsLogin'}

    def __call__(self, *args, ok=(0,)):
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise b.Blocked('injected command failure (output withheld)')
        exe = Path(args[0]).name
        if exe == 'getenforce':
            return 'Enforcing\n'
        if exe == 'systemctl' and args[1] == 'is-active':
            return 'inactive\n'
        if exe == 'ss':
            return 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'
        if exe == 'sshd' and args[1] == '-T':
            if '-C' in args:
                name = args[-1].split(',')[0].split('=')[1]
                return ('authenticationmethods publickey\npasswordauthentication no\n'
                        'kbdinteractiveauthentication no\npubkeyauthentication yes\n'
                        f'authorizedkeysfile /etc/ssh/dev-pair-keys/{name}\n')
            return 'port 22\n'
        if exe == 'getent':
            return self.accounts.get(args[-1], '')
        if exe == 'useradd':
            name = args[-1]
            shell = args[args.index('--shell') + 1]
            self.accounts[name] = f'{name}:x:1001:1001::/home/{name}:{shell}\n'
        if exe == 'id':
            return args[-1] + '\n' if args[1] == '-nG' else '1001\n'
        if exe == 'tailscale':
            if args[1] == 'down':
                self.node['BackendState'] = 'Stopped'
            if args[1] == 'up':
                self.node = {'BackendState': 'Running', 'CurrentTailnet': {'Name': 'example.ts.net'}, 'Self': {'ID': 'node-fixture'}}
            return json.dumps(self.node)
        if exe == 'rpm':
            return 'synthetic-package-versions-not-fedora-evidence\n'
        return ''

class FixtureBootstrap(b.Bootstrap):
    def directory(self, name, mode=0o700, owner=None):
        # Real filesystem safety/mode checks; account/chown are command fixtures only.
        return super().directory(name, mode, owner=None)

class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fake = Fake(self.root)
        self.app = FixtureBootstrap(self.root, self.fake)
        for path, data in [('/etc/os-release', 'ID=fedora\nVERSION_ID=44\n'), ('/proc/1/comm', 'systemd\n')]:
            p = self.app.path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(data)
        self.rootpatch = patch.object(b.os, 'geteuid', return_value=0)
        self.rootpatch.start()
        self.addCleanup(self.rootpatch.stop)
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def prepare(self):
        return self.app.prepare('operator', KEY, ['192.0.2.9/32'])

    def secret(self):
        p = self.root / 'secret'
        p.write_text('tskey-secret-MUST-NOT-APPEAR')
        p.chmod(0o600)
        return p

    def test_nonfedora_and_selinux_denied_before_any_mutation(self):
        self.app.path('/etc/os-release').write_text('ID=debian\nVERSION_ID=12\n')
        with self.assertRaisesRegex(b.Blocked, 'Fedora'):
            self.prepare()
        self.assertFalse(self.app.state.exists())
        self.assertFalse(self.fake.calls)

    def test_reapply_preserves_data_and_never_recreates_users(self):
        self.prepare()
        durable = self.app.path('/var/lib/dev-pair/development/workspaces/work')
        durable.write_text('uncommitted work')
        before = [x for x in self.fake.calls if Path(x[0]).name == 'useradd']
        self.prepare()
        self.assertEqual(len(before), 3)
        self.assertEqual(len([x for x in self.fake.calls if Path(x[0]).name == 'useradd']), 3)
        self.assertEqual(durable.read_text(), 'uncommitted work')
        self.assertEqual(len(self.app.text('/etc/subuid').splitlines()), 2)
        self.assertFalse(any('podman' == Path(c[0]).name for c in self.fake.calls))
        self.assertFalse(self.app.path('/etc/ssh/sshd_config').exists())
        self.assertEqual(self.app.path('/etc/ssh/dev-pair-keys/operator').stat().st_mode & 0o777, 0o644)
        self.assertIn('Match User operator', self.app.text('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'))

    def test_interrupted_prepare_resumes_without_duplicate_accounts(self):
        self.fake.fail = lambda a: Path(a[0]).name == 'nft' and '-f' in a
        with self.assertRaises(b.Blocked):
            self.prepare()
        self.assertFalse(self.app.path(b.STATE + '/prepared').exists())
        self.assertIn('interrupted-or-failed', self.app.text(b.STATE + '/journal.jsonl'))
        self.fake.fail = None
        self.prepare()
        self.assertEqual(len([x for x in self.fake.calls if Path(x[0]).name == 'useradd']), 3)
        self.assertTrue(self.app.status()['prepared'])

    def test_conflicting_key_source_user_and_subids_fail_closed(self):
        self.fake.accounts['operator'] = 'operator:x:1001:1001::/home/operator:/bin/bash\n'
        with self.assertRaisesRegex(b.Blocked, 'existing account'):
            self.prepare()
        self.assertFalse(any(Path(a[0]).name == 'useradd' for a in self.fake.calls))
        self.fake.accounts.clear()
        self.app.path('/etc/subuid').write_text('other:1000000:65536\n')
        with self.assertRaisesRegex(b.Blocked, 'overlap'):
            self.prepare()
        self.assertEqual(self.app.text('/etc/subuid'), 'other:1000000:65536\n')

    def test_changed_inputs_fail_before_commands_after_preflight(self):
        self.prepare()
        with self.assertRaisesRegex(b.Blocked, 'conflicting managed file'):
            self.app.prepare('operator', KEY + 'different', ['192.0.2.9/32'])

    def test_current_ssh_source_must_be_allowed(self):
        with patch.dict(os.environ, {'SSH_CONNECTION': '192.0.2.10 30000 192.0.2.2 22'}):
            with self.assertRaisesRegex(b.Blocked, 'outside'):
                self.prepare()
        self.assertFalse(self.fake.calls)
        self.assertFalse(self.app.state.exists())

    def test_ssh_effective_conflict_removes_fragment_without_reloading(self):
        original = self.fake.__call__
        def run(*args, **kwargs):
            if Path(args[0]).name == 'sshd' and '-C' in args:
                return 'passwordauthentication yes\n'
            return original(*args, **kwargs)
        self.app.run = run
        with self.assertRaisesRegex(b.Blocked, 'effective'):
            self.prepare()
        self.assertFalse(self.app.path('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf').exists())
        self.assertFalse(any(a[1:3] == ('reload', 'sshd.service') for a in self.fake.calls))

    def test_guard_scopes_sources_and_never_flushes_other_tables(self):
        self.prepare()
        rules = self.app.text('/etc/dev-pair/bootstrap.nft')
        self.assertIn('ip saddr 192.0.2.9/32 tcp dport 22 accept', rules)
        self.assertIn('iifname "tailscale0" tcp dport 22', rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('input tcp dport 22 accept', rules)
        self.assertEqual(rules.count('policy drop'), 2)
        for source in ['0.0.0.0/0', '::/0', '192.0.2.9/24', 'x; reboot']:
            with self.assertRaises(b.Blocked):
                b.validate_sources([source])

    def test_lock_and_symlink_conflicts(self):
        self.app.state.parent.mkdir(parents=True)
        target = self.root / 'elsewhere'
        target.mkdir()
        self.app.state.symlink_to(target)
        with self.assertRaisesRegex(b.Blocked, 'symlink'):
            with self.app.lock():
                self.fail('acquired lock through symlink')
        self.app.state.unlink()
        with self.app.lock():
            with self.assertRaisesRegex(b.Blocked, 'another'):
                with self.app.lock():
                    self.fail('parallel operation')

    def test_enroll_secret_reference_redaction_and_idempotence(self):
        self.prepare()
        secret = self.secret()
        with patch.object(b, 'checked_file', return_value=secret):
            self.app.enroll(str(secret), 'example.ts.net')
            self.app.enroll(str(secret), 'example.ts.net')
        up = [a for a in self.fake.calls if a[0:2] == ('/usr/bin/tailscale', 'up')]
        self.assertEqual(len(up), 1)
        self.assertIn('--auth-key=file:' + str(secret), up[0])
        self.assertIn('--ssh=false', up[0])
        self.assertIn('--netfilter-mode=off', up[0])
        for f in self.app.state.iterdir():
            if f.is_file():
                self.assertNotIn('tskey-secret', f.read_text())

    def test_enrollment_failure_keeps_bootstrap_route_and_reports_no_secret(self):
        self.prepare()
        before = self.app.text('/etc/dev-pair/bootstrap.nft')
        self.fake.fail = lambda a: a[:2] == ('/usr/bin/tailscale', 'up')
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaisesRegex(b.Blocked, 'withheld'):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(before, self.app.text('/etc/dev-pair/bootstrap.nft'))
        self.assertTrue(self.app.status()['root_and_initial_ssh_retained'])

    def test_command_errors_and_timeouts_never_echo_secret_output(self):
        result = subprocess.CompletedProcess([], 1, 'tskey-secret', 'tskey-secret')
        with patch.object(b.subprocess, 'run', return_value=result):
            with self.assertRaises(b.Blocked) as ctx:
                b.Commands()('/usr/bin/tailscale', 'up', '--auth-key=file:/secret')
            self.assertNotIn('tskey-secret', str(ctx.exception))
            self.assertNotIn('/secret', str(ctx.exception))
        with patch.object(b.subprocess, 'run', side_effect=subprocess.TimeoutExpired('tskey-secret', 1)):
            with self.assertRaises(b.Blocked) as ctx:
                b.Commands()('/usr/bin/tailscale', 'up')
            self.assertNotIn('tskey-secret', str(ctx.exception))

    def test_existing_or_mismatched_tailnet_never_adopted(self):
        self.prepare()
        self.fake.node = {'BackendState': 'Running', 'CurrentTailnet': {'Name': 'other'}, 'Self': {'ID': 'other'}}
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaisesRegex(b.Blocked, 'already enrolled'):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertFalse(any(a[:2] == ('/usr/bin/tailscale', 'up') for a in self.fake.calls))

    def test_wrong_new_tailnet_is_disconnected(self):
        self.prepare()
        original = self.fake.__call__
        def run(*args, **kwargs):
            out = original(*args, **kwargs)
            if args[:2] == ('/usr/bin/tailscale', 'up'):
                self.fake.node['CurrentTailnet']['Name'] = 'wrong.ts.net'
            return out
        self.app.run = run
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaisesRegex(b.Blocked, 'taken down'):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Stopped')
        self.assertFalse(self.app.path(b.STATE + '/node.json').exists())

    def test_readonly_inspect_rejects_firewall_and_allows_resolved(self):
        original = self.fake.__call__
        def resolved(*args, **kwargs):
            if Path(args[0]).name == 'ss':
                return 'tcp LISTEN 0 128 127.0.0.53:53 0.0.0.0:*\n'
            return original(*args, **kwargs)
        self.app.run = resolved
        self.app.preflight()
        self.assertFalse(self.app.state.exists())
        def competing(*args, **kwargs):
            if args[1:3] == ('is-active', 'firewalld.service'):
                return 'active\n'
            return original(*args, **kwargs)
        self.app.run = competing
        with self.assertRaisesRegex(b.Blocked, 'competing'):
            self.app.preflight()

    def test_existing_valid_fragment_survives_later_validation_failure(self):
        self.prepare()
        original = self.fake.__call__
        def broken(*args, **kwargs):
            if Path(args[0]).name == 'sshd' and '-C' in args:
                return 'passwordauthentication yes\n'
            return original(*args, **kwargs)
        self.app.run = broken
        with self.assertRaises(b.Blocked):
            self.prepare()
        self.assertTrue(self.app.path('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf').exists())

    def test_finalize_always_blocks_without_reading_fake_evidence(self):
        proc = subprocess.run([sys.executable, str(ROOT / 'tools/bootstrap.py'), 'finalize'], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('not implemented', proc.stderr)

if __name__ == '__main__':
    unittest.main()
