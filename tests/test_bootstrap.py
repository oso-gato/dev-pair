"""Synthetic tempfile/command tests. These do NOT establish Fedora/runtime behavior."""
import importlib.util
import hashlib
from types import SimpleNamespace
import json
import io
import pty
import urllib.error
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
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
        self.image = None
        self.password_inputs = []
        self.password_set = False

    def __call__(self, *args, ok=(0,), input_text=None):
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise b.Blocked('injected command failure (output withheld)')
        exe = Path(args[0]).name
        if exe == 'chpasswd':
            self.password_inputs.append(input_text)
            self.password_set = True
        if exe == 'passwd':
            return 'core P 2026-11-15 0 99999 7 -1\n' if self.password_set else 'core L 2026-11-15 0 99999 7 -1\n'
        if exe == 'hostnamectl' and args[1] == '--static':
            return 'erebus\n'
        if exe == 'sudo':
            if args[-1] in ('dp-maint', 'dp-dev'):
                self.assert_no_sudo_expected = ok == (1,)
                return ''
            return 'Matching Defaults entries for core: authenticate\n    (ALL) PASSWD: ALL\n'
        if exe == 'systemd-run':
            operation = args[args.index('--storage-driver=vfs') + 1:]
            if operation[:2] == ('image', 'inspect'):
                return json.dumps([self.image]) if self.image else ''
            if operation[0] == 'build':
                context = Path(operation[-1])
                m = json.loads((context / 'inputs.json').read_text())
                expected = operation[operation.index('--label') + 1].split('=', 1)[1]
                self.image = {'Id': 'sha256:' + 'a' * 64, 'Architecture': 'amd64', 'Os': 'linux',
                              'Labels': {'dev-pair.context': expected, 'dev-pair.role': 'maintenance',
                                         'dev-pair.standards': b.STANDARDS,
                                         'org.opencontainers.image.revision': m['source_sha'],
                                         'dev-pair.codex.version': m['codex']['version']}}
                return self.image['Id'] + '\n'
            return ''
        if exe == 'getenforce':
            return 'Enforcing\n'
        if exe == 'systemd-analyze':
            return '[Resolve]\nLLMNR=no\nMulticastDNS=no\n'
        if exe == 'systemctl' and args[1] == 'show' and args[-1] == 'systemd-resolved.service':
            return 'LoadState=not-found\nActiveState=inactive\n'
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
        return self.app.prepare('core', KEY, ['192.0.2.9/32'], password='fixture-password-not-a-secret')

    def secret(self):
        p = self.root / 'secret'
        p.write_text('tskey-secret-MUST-NOT-APPEAR')
        p.chmod(0o600)
        return p

    def stock_resolved(self):
        # Public ss output captured from the disposable run7 guest; identity
        # observations below remain synthetic, not new Fedora evidence.
        self.inventory = (ROOT / 'tests/data/fedora44/listeners-run7.txt').read_text()
        self.resolved_state = 'LoadState=loaded\nActiveState=active\nUser=systemd-resolve\nMainPID=767\n'
        for path, value in [('/proc/767/status', 'Uid:\t193\t193\t193\t193\n'),
                            ('/proc/767/cgroup', '0::/system.slice/systemd-resolved.service\n'),
                            ('/usr/lib/systemd/systemd-resolved', 'synthetic executable identity only\n')]:
            target = self.app.path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value)
        self.app.path('/proc/767/exe').symlink_to('/usr/lib/systemd/systemd-resolved')
        self.fake.accounts['systemd-resolve'] = 'systemd-resolve:x:193:193:Resolver:/:/usr/sbin/nologin\n'
        original = self.fake
        def run(*args, **kwargs):
            if args[:2] == ('/usr/bin/ss', '-H'):
                original.calls.append(args)
                return self.inventory
            if args[:2] == ('/usr/bin/systemctl', 'show') and args[-1] == 'systemd-resolved.service':
                original.calls.append(args)
                return self.resolved_state
            result = original(*args, **kwargs)
            if args[:2] == ('/usr/bin/systemctl', 'restart') and args[-1] == 'systemd-resolved.service':
                self.inventory = '\n'.join(line for line in self.inventory.splitlines() if ':5355' not in line) + '\n'
            return result
        self.app.run = run

    def test_stock_resolved_discovery_is_temporarily_identity_bound_then_persistently_disabled(self):
        self.stock_resolved()
        self.app.preflight()
        self.prepare()
        expected = '[Resolve]\nLLMNR=no\nMulticastDNS=no\n'
        self.assertEqual(self.app.text('/etc/systemd/resolved.conf.d/90-dev-pair-discovery.conf'), expected)
        self.assertNotIn(':5355', self.inventory)
        self.assertIn('127.0.0.53%lo:53', self.inventory)
        self.assertIn('0.0.0.0:22', self.inventory)
        self.prepare()
        self.assertEqual(self.app.text('/etc/systemd/resolved.conf.d/90-dev-pair-discovery.conf'), expected)
        self.inventory += 'udp UNCONN 0 0 0.0.0.0:5355 0.0.0.0:* users:(("systemd-resolve",pid=767,fd=12))\n'
        with self.assertRaisesRegex(b.Blocked, 'unexpected listener'):
            self.app.preflight()

    def test_resolved_discovery_impostor_service_and_process_mismatches_are_rejected(self):
        self.stock_resolved()
        original_inventory, original_state = self.inventory, self.resolved_state
        for change in (lambda: setattr(self, 'inventory', original_inventory.replace('"systemd-resolve"', '"impostor"')),
                       lambda: setattr(self, 'resolved_state', original_state.replace('MainPID=767', 'MainPID=999')),
                       lambda: setattr(self, 'resolved_state', original_state.replace('User=systemd-resolve', 'User=root'))):
            self.inventory, self.resolved_state = original_inventory, original_state
            change()
            with self.assertRaisesRegex(b.Blocked, 'unexpected listener'):
                self.app.preflight()
        self.inventory, self.resolved_state = original_inventory, original_state
        self.app.path('/proc/767/cgroup').write_text('0::/system.slice/unrelated.service\n')
        with self.assertRaisesRegex(b.Blocked, 'unexpected listener'):
            self.app.preflight()
        self.app.path('/proc/767/cgroup').write_text('0::/system.slice/systemd-resolved.service\n')
        self.app.path('/proc/767/status').write_text('Uid:\t0\t0\t0\t0\n')
        with self.assertRaisesRegex(b.Blocked, 'unexpected listener'):
            self.app.preflight()

    def test_resolved_failed_restart_and_effective_override_never_complete_prepare(self):
        self.stock_resolved()
        self.fake.fail = lambda args: args[:2] == ('/usr/bin/systemctl', 'restart')
        with self.assertRaises(b.Blocked):
            self.prepare()
        self.assertFalse(self.app.path(b.STATE + '/prepared').exists())
        self.assertFalse(any(Path(args[0]).name == 'useradd' for args in self.fake.calls))
        self.fake.fail = None
        old = self.app.run
        def run(*args, **kwargs):
            if args[0] == '/usr/bin/systemd-analyze':
                return '[Resolve]\nLLMNR=no\nMulticastDNS=no\nLLMNR=yes\n'
            return old(*args, **kwargs)
        self.app.run = run
        with self.assertRaisesRegex(b.Blocked, 'configuration conflicts'):
            self.prepare()
        self.assertFalse(self.app.path(b.STATE + '/prepared').exists())

    def test_resolved_successful_restart_with_remaining_discovery_is_blocked(self):
        self.stock_resolved()
        inventory = self.inventory
        old = self.app.run
        def run(*args, **kwargs):
            result = old(*args, **kwargs)
            if args[:2] == ('/usr/bin/systemctl', 'restart'):
                self.inventory = inventory
            return result
        self.app.run = run
        with self.assertRaisesRegex(b.Blocked, 'discovery listener remains'):
            self.prepare()
        self.assertFalse(self.app.path(b.STATE + '/prepared').exists())

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
        self.assertEqual(self.app.path('/etc/ssh/dev-pair-keys/core').stat().st_mode & 0o777, 0o644)
        self.assertIn('Match User core', self.app.text('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'))

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
        self.fake.accounts['core'] = 'core:x:1001:1001::/home/core:/bin/bash\n'
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
            self.app.prepare('core', KEY, ['192.0.2.10/32'])

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
        self.app.state.parent.chmod(0o755)
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
        for code, timeout in [('import sys;print("tskey-secret");sys.exit(1)', 3),
                              ('import time;time.sleep(3)', .05)]:
            with self.assertRaises(b.Blocked) as ctx:
                b.Commands()(sys.executable, '-c', code, 'secret-argv', timeout=timeout)
            self.assertNotIn('tskey-secret', str(ctx.exception))
            self.assertNotIn('secret-argv', str(ctx.exception))

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

    def context(self, role='maintenance', fixture=False):
        repo = self.root / 'isolated-candidate-source'
        (repo / 'tools').mkdir(parents=True, exist_ok=True)
        source = repo / 'tools/candidate.py'
        source.write_bytes((ROOT / 'tools/candidate.py').read_bytes())
        for arguments in [('init', '--quiet'), ('add', 'tools/candidate.py'),
                          ('-c', 'user.name=Offline fixture', '-c', 'user.email=fixture@example.invalid',
                           '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                           'commit', '--allow-empty', '--quiet', '-m', 'Synthetic verifier source')]:
            subprocess.run(['/usr/bin/git', '-C', str(repo), *arguments], check=True, capture_output=True)
        tool_spec = importlib.util.spec_from_file_location('isolated_build_candidate', source)
        tool = importlib.util.module_from_spec(tool_spec)
        tool_spec.loader.exec_module(tool)
        self.app.candidate_tool = lambda: tool
        binary = self.root / 'synthetic-ELF-NOT-CODEX'
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        data[18:20] = b'\x3e\x00'
        binary.write_bytes(data)
        sha = subprocess.run(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD'], check=True, text=True, capture_output=True).stdout.strip()
        m = {'kind': 'fixture' if fixture else 'operator-verified-inputs', 'source_sha': sha,
             'standards_sha': b.STANDARDS,
             'fedora': {'image': 'registry.fedoraproject.org/fedora:44@sha256:' + hashlib.sha256(b'SYNTHETIC NOT FEDORA').hexdigest(),
                        'verification': 'SYNTHETIC OFFLINE TEST - no upstream acceptance'},
             'codex': {'version': '9876.5.4',
                       'source': 'https://github.com/openai/codex/releases/download/rust-v9876.5.4/codex-x86_64-unknown-linux-musl.tar.gz',
                       'sha256': hashlib.sha256(data).hexdigest(), 'verification': 'SYNTHETIC OFFLINE TEST - no upstream acceptance'},
             'role': role, 'provider': 'gptbox', 'model': 'gpt-6.1-sol', 'effort': 'high',
             'mounts': {key: (f'/var/lib/dev-pair/credentials/{role}/offline-test' if key == 'credentials' else f'/var/lib/dev-pair/{role}/' + {'workspace': 'workspaces', 'state': 'state', 'cache': 'cache'}[key] + '/offline-test') for key in ('workspace', 'state', 'cache', 'credentials')}}
        out = self.root / 'context'
        result = tool.prepare(m, binary, out, fixture=fixture)
        return out, result['context_sha256']

    def test_real_verifier_build_handoff_and_artifact_replay(self):
        self.prepare()
        context, digest = self.context()
        with patch.object(b.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024 ** 3)):
            result = self.app.build_gptbox(context, digest)
            self.app.build_gptbox(context, digest)
            # An unrecorded prior engine success is rebuilt; public labels are insufficient.
            self.app.path(b.STATE + '/gptbox-image.json').unlink()
            self.app.build_gptbox(context, digest)
        engine = [a for a in self.fake.calls if Path(a[0]).name == 'systemd-run']
        self.assertEqual(len([a for a in engine if 'build' in a]), 2)
        self.assertTrue(all('--uid=dp-maint' in a for a in engine))
        self.assertTrue(all('--property=KillMode=control-group' in a for a in engine))
        build = next(a for a in engine if 'build' in a)
        self.assertIn('--network=none', build)
        self.assertIn('--pull=never', build)
        self.assertEqual(result['image_id'], 'sha256:' + 'a' * 64)
        self.assertFalse(result['distrobox_assembled'])
        self.assertFalse(result['runtime_validated'])
        stage = self.app.path('/var/lib/dev-pair/artifacts/gptbox/' + digest)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o444 for p in stage.iterdir()))

    def test_gptbox_tamper_fixture_role_denied_before_engine(self):
        self.prepare()
        context, digest = self.context(role='development')
        with self.assertRaisesRegex(b.Blocked, 'maintenance-role'):
            self.app.build_gptbox(context, digest)
        (context / 'Containerfile').write_text('FROM bad\nRUN arbitrary-command\n')
        with self.assertRaisesRegex(b.Blocked, 'verification failed'):
            self.app.build_gptbox(context, digest)
        self.assertFalse(any(Path(a[0]).name == 'systemd-run' for a in self.fake.calls))
        for file in context.iterdir():
            file.unlink()
        context.rmdir()
        context, digest = self.context(fixture=True)
        with self.assertRaisesRegex(b.Blocked, 'verification failed'):
            self.app.build_gptbox(context, digest)
        self.assertFalse(any(Path(a[0]).name == 'systemd-run' for a in self.fake.calls))

    def test_gptbox_missing_identity_and_engine_failure_record_no_success(self):
        self.prepare()
        context, digest = self.context()
        with self.assertRaisesRegex(b.Blocked, 'trusted context'):
            self.app.build_gptbox(context, None)
        self.fake.fail = lambda a: Path(a[0]).name == 'systemd-run' and 'build' in a
        with patch.object(b.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024 ** 3)):
            with self.assertRaises(b.Blocked):
                self.app.build_gptbox(context, digest)
        self.assertFalse(self.app.path(b.STATE + '/gptbox-image.json').exists())
        self.assertTrue(self.app.path(b.STATE + '/gptbox-build-intent.json').exists())
        self.fake.fail = None
        manifest = json.loads((context / 'inputs.json').read_text())
        record = {'image_id': 'sha256:' + 'b' * 64, 'context_sha256': digest, 'source_sha': manifest['source_sha'],
                  'base_image': manifest['fedora']['image'], 'codex_sha256': manifest['codex']['sha256']}
        self.app.atomic(b.STATE + '/gptbox-image.json', json.dumps(record) + '\n')
        self.fake.image = {'Id': 'sha256:' + 'a' * 64}
        with self.assertRaisesRegex(b.Blocked, 'identity mismatch'):
            self.app.build_gptbox(context, digest)

    def test_failed_enroll_after_daemon_side_effect_disconnects(self):
        self.prepare()
        original = self.fake.__call__
        def committed_but_failed(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[:2] == ('/usr/bin/tailscale', 'up'):
                self.fake.node['CurrentTailnet']['Name'] = 'wrong.ts.net'
                raise b.Blocked('CLI timeout after daemon committed')
            return result
        self.app.run = committed_but_failed
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaises(b.Blocked):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Stopped')
        self.assertFalse(self.app.path(b.STATE + '/node.json').exists())

    def test_peerapi_allowed_only_for_actual_root_tailscaled_node_address(self):
        exe = self.app.path('/usr/bin/tailscale')
        exe.parent.mkdir(parents=True)
        exe.touch()
        proc = self.app.path('/proc/99')
        proc.mkdir()
        (proc / 'exe').symlink_to('/usr/sbin/tailscaled')
        (proc / 'status').write_text('Uid:\t0\t0\t0\t0\n')
        self.fake.node = {'BackendState': 'Running', 'TailscaleIPs': ['100.64.0.2']}
        line = 'tcp LISTEN 0 4096 100.64.0.2:45879 0.0.0.0:* users:(("tailscaled",pid=99,fd=20))'
        self.assertTrue(self.app.peerapi_listener(line, '100.64.0.2'))
        self.assertFalse(self.app.peerapi_listener(line, '0.0.0.0'))
        self.fake.node = {'BackendState': 'NeedsLogin'}
        self.prepare()
        with patch.object(b, 'checked_file', return_value=self.secret()):
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
            self.fake.node['TailscaleIPs'] = ['100.64.0.2']
            original = self.fake.__call__
            def peerapi(*args, **kwargs):
                if Path(args[0]).name == 'ss':
                    return line + '\n'
                return original(*args, **kwargs)
            self.app.run = peerapi
            self.prepare()
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        (proc / 'status').write_text('Uid:\t1001\t1001\t1001\t1001\n')
        self.assertFalse(self.app.peerapi_listener(line, '100.64.0.2'))

    def test_directory_symlink_swap_never_chmods_or_chowns_victim(self):
        victim = self.root / 'victim'
        victim.mkdir(mode=0o755)
        victim.chmod(0o755)
        parent = self.app.path('/var/lib/dev-pair/development')
        parent.mkdir(parents=True)
        actual_mkdir = b.os.mkdir
        def swap(path, mode=0o777, *, dir_fd=None):
            actual_mkdir(path, mode, dir_fd=dir_fd)
            if path == 'cache' and dir_fd is not None:
                b.os.rmdir(path, dir_fd=dir_fd)
                b.os.symlink(str(victim), path, dir_fd=dir_fd)
        with patch.object(b.os, 'mkdir', side_effect=swap), patch.object(b.os, 'fchown') as chown:
            with self.assertRaisesRegex(b.Blocked, 'traversal'):
                b.Bootstrap.directory(self.app, '/var/lib/dev-pair/development/cache', owner='dp-dev')
            chown.assert_not_called()
        self.assertEqual(victim.stat().st_mode & 0o777, 0o755)

    def assert_no_host_mutation(self):
        mutations = {'dnf', 'useradd', 'usermod', 'loginctl', 'nft', 'systemd-run'}
        self.assertFalse(any(Path(call[0]).name in mutations for call in self.fake.calls))
        self.assertFalse(self.app.state.exists())
        self.assertFalse(self.app.path('/etc/dev-pair').exists())

    def test_upfront_context_hash_role_fixture_and_arch_rejections_leave_no_state(self):
        context, digest = self.context(role='development')
        for expected in (digest, '1' * 64):
            with self.subTest(expected=expected):
                with self.assertRaises(b.Blocked):
                    self.app.prepare('core', KEY, ['192.0.2.9/32'], context, expected, password='fixture-password-not-a-secret')
                self.assert_no_host_mutation()
        with patch.object(b.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(b.Blocked, 'x86_64'):
                self.app.prepare('core', KEY, ['192.0.2.9/32'], context, digest, password='fixture-password-not-a-secret')
        self.assert_no_host_mutation()
        for file in context.iterdir():
            file.unlink()
        context.rmdir()
        context, digest = self.context(fixture=True)
        with self.assertRaises(b.Blocked):
            self.app.prepare('core', KEY, ['192.0.2.9/32'], context, digest, password='fixture-password-not-a-secret')
        self.assert_no_host_mutation()

    def test_corrected_hash_retry_and_minimal_git_prerequisite_before_binding(self):
        context, digest = self.context()
        with self.assertRaises(b.Blocked):
            self.app.prepare('core', KEY, ['192.0.2.9/32'], context, '1' * 64, password='fixture-password-not-a-secret')
        self.assert_no_host_mutation()
        original = self.fake.__call__
        def prerequisite(*args, **kwargs):
            if Path(args[0]).name == 'dnf' and args[-1] == 'git-core':
                self.assertFalse(self.app.path(b.STATE + '/desired.json').exists())
                self.assertFalse(any(Path(call[0]).name == 'useradd' for call in self.fake.calls))
            return original(*args, **kwargs)
        self.app.run = prerequisite
        with patch.object(b.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024 ** 3)):
            self.app.prepare('core', KEY, ['192.0.2.9/32'], context, digest, password='fixture-password-not-a-secret')
        dnf = [call for call in self.fake.calls if Path(call[0]).name == 'dnf']
        self.assertEqual(dnf[0][-2:], ('install', 'git-core'))
        self.assertTrue(self.app.path(b.STATE + '/prepared').exists())

    def test_source_failure_after_git_prerequisite_does_not_bind_desired(self):
        context, digest = self.context()
        tool = self.app.candidate_tool()
        with patch.object(tool, 'check_source', side_effect=ValueError('source mismatch')):
            with self.assertRaisesRegex(b.Blocked, 'source verification'):
                self.app.prepare('core', KEY, ['192.0.2.9/32'], context, digest, password='fixture-password-not-a-secret')
        self.assertFalse(self.app.path(b.STATE + '/desired.json').exists())
        dnf = [call for call in self.fake.calls if Path(call[0]).name == 'dnf']
        self.assertEqual(len(dnf), 1)
        self.assertEqual(dnf[0][-2:], ('install', 'git-core'))
        self.assertFalse(any(Path(call[0]).name == 'useradd' for call in self.fake.calls))

    def test_post_up_status_json_and_persistence_failures_disconnect(self):
        self.prepare()
        guard = self.app.text('/etc/dev-pair/bootstrap.nft')
        original_run, original_atomic = self.fake.__call__, self.app.atomic
        for failure in ('status', 'json', 'persist', 'persist_after_write'):
            with self.subTest(failure=failure):
                self.fake.node = {'BackendState': 'NeedsLogin'}
                after_up = False
                def run(*args, **kwargs):
                    nonlocal after_up
                    if after_up and args[:2] == ('/usr/bin/tailscale', 'status'):
                        if failure == 'status':
                            raise b.Blocked('post-up status failed (output withheld)')
                        if failure == 'json':
                            return 'malformed tskey-SECRET payload'
                    result = original_run(*args, **kwargs)
                    if args[:2] == ('/usr/bin/tailscale', 'up'):
                        after_up = True
                    return result
                def atomic(path, *args, **kwargs):
                    if path == b.STATE + '/node.json':
                        if failure == 'persist_after_write':
                            original_atomic(path, *args, **kwargs)
                            raise OSError('synthetic failure after visible write')
                        if failure == 'persist':
                            raise OSError('synthetic persistence failure')
                    return original_atomic(path, *args, **kwargs)
                self.app.run, self.app.atomic = run, atomic
                with patch.object(b, 'checked_file', return_value=self.secret()):
                    with self.assertRaises((b.Blocked, ValueError, OSError)):
                        self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
                self.assertEqual(self.fake.node['BackendState'], 'Stopped')
                self.assertFalse(self.app.path(b.STATE + '/node.json').exists())
                self.assertEqual(self.app.text('/etc/dev-pair/bootstrap.nft'), guard)
        self.app.run, self.app.atomic = original_run, original_atomic

    def test_accepted_node_status_failure_does_not_disconnect(self):
        self.prepare()
        with patch.object(b, 'checked_file', return_value=self.secret()):
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
            original = self.fake.__call__
            def failed_status(*args, **kwargs):
                if args[:2] == ('/usr/bin/tailscale', 'status'):
                    raise b.Blocked('temporary status error')
                return original(*args, **kwargs)
            self.app.run = failed_status
            with self.assertRaises(b.Blocked):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Running')
        self.assertTrue(self.app.path(b.STATE + '/node.json').exists())
        self.assertFalse(any(call[:2] == ('/usr/bin/tailscale', 'down') for call in self.fake.calls))

    def test_resumed_unverified_running_persistence_failure_disconnects_without_up(self):
        self.prepare()
        self.app.atomic(b.STATE + '/enrollment-intent.json', json.dumps({'tailnet': 'example.ts.net'}, sort_keys=True) + '\n')
        self.fake.node = {'BackendState': 'Running', 'CurrentTailnet': {'Name': 'example.ts.net'},
                          'Self': {'ID': 'interrupted-unverified-node'}}
        original = self.app.atomic
        def failed_persistence(path, *args, **kwargs):
            if path == b.STATE + '/node.json':
                raise OSError('resumed persistence failure')
            return original(path, *args, **kwargs)
        self.app.atomic = failed_persistence
        guard = self.app.text('/etc/dev-pair/bootstrap.nft')
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaises(OSError):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Stopped')
        self.assertFalse(self.app.path(b.STATE + '/node.json').exists())
        self.assertFalse(any(call[:2] == ('/usr/bin/tailscale', 'up') for call in self.fake.calls))
        self.assertEqual(self.app.text('/etc/dev-pair/bootstrap.nft'), guard)

    def test_same_intent_unverified_stopped_retry_succeeds_with_explicit_enroll(self):
        self.prepare()
        self.app.atomic(b.STATE + '/enrollment-intent.json', json.dumps({'tailnet': 'example.ts.net'}, sort_keys=True) + '\n')
        # This is the daemon state left by cleanup after an observation/persistence failure.
        self.fake.node = {'BackendState': 'Stopped', 'CurrentTailnet': {'Name': 'example.ts.net'},
                          'Self': {'ID': 'unverified-node'}}
        with patch.object(b, 'checked_file', return_value=self.secret()):
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Running')
        self.assertTrue(self.app.path(b.STATE + '/node.json').exists())
        up = [call for call in self.fake.calls if call[:2] == ('/usr/bin/tailscale', 'up')]
        self.assertEqual(len(up), 1)
        self.assertFalse(any('force-reauth' in argument or 'reset' in argument for argument in up[0]))

    def test_accepted_stopped_node_is_never_automatically_reactivated(self):
        self.prepare()
        with patch.object(b, 'checked_file', return_value=self.secret()):
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
            self.fake.node['BackendState'] = 'Stopped'
            count = len(self.fake.calls)
            with self.assertRaisesRegex(b.Blocked, 'explicit recovery'):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Stopped')
        self.assertTrue(self.app.path(b.STATE + '/node.json').exists())
        self.assertFalse(any(call[:2] == ('/usr/bin/tailscale', 'up') for call in self.fake.calls[count:]))

    def test_wrong_tailnet_stopped_retry_is_latched_for_explicit_recovery(self):
        self.prepare()
        self.app.atomic(b.STATE + '/enrollment-intent.json', json.dumps({'tailnet': 'example.ts.net'}, sort_keys=True) + '\n')
        self.fake.node = {'BackendState': 'Stopped', 'CurrentTailnet': {'Name': 'wrong.ts.net'},
                          'Self': {'ID': 'unverified-wrong-node'}}
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaisesRegex(b.Blocked, 'tailnet mismatch'):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
            self.assertTrue(self.app.path(b.STATE + '/enrollment-recovery-required.json').exists())
            # Later daemon omission of CurrentTailnet cannot erase the observed mismatch.
            self.fake.node = {'BackendState': 'Stopped'}
            with self.assertRaisesRegex(b.Blocked, 'explicit recovery'):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Stopped')
        self.assertFalse(self.app.path(b.STATE + '/node.json').exists())
        self.assertFalse(any(call[:2] == ('/usr/bin/tailscale', 'up') for call in self.fake.calls))

    def test_nullable_fresh_needslogin_and_same_intent_stopped_enroll(self):
        self.prepare()
        self.fake.node = {'BackendState': 'NeedsLogin', 'CurrentTailnet': None, 'Self': None}
        with patch.object(b, 'checked_file', return_value=self.secret()):
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
            self.assertTrue(self.app.path(b.STATE + '/node.json').exists())
            # Independent synthetic stopped-unverified attempt with the same recorded intent.
            self.app.path(b.STATE + '/node.json').unlink()
            self.fake.node = {'BackendState': 'Stopped', 'CurrentTailnet': None, 'Self': None}
            self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertEqual(self.fake.node['BackendState'], 'Running')
        self.assertTrue(self.app.path(b.STATE + '/node.json').exists())
        self.assertEqual(len([call for call in self.fake.calls if call[:2] == ('/usr/bin/tailscale', 'up')]), 2)

    def test_nullable_running_identity_is_unverified_and_disconnected(self):
        self.prepare()
        self.app.atomic(b.STATE + '/enrollment-intent.json', json.dumps({'tailnet': 'example.ts.net'}, sort_keys=True) + '\n')
        for field in ('CurrentTailnet', 'Self'):
            with self.subTest(field=field):
                self.fake.node = {'BackendState': 'Running', 'CurrentTailnet': {'Name': 'example.ts.net'},
                                  'Self': {'ID': 'interrupted-node'}}
                self.fake.node[field] = None
                # Reset only synthetic fixture between independent schema cases.
                self.app.path(b.STATE + '/enrollment-recovery-required.json').unlink(missing_ok=True)
                with patch.object(b, 'checked_file', return_value=self.secret()):
                    with self.assertRaisesRegex(b.Blocked, 'identity mismatch'):
                        self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
                self.assertEqual(self.fake.node['BackendState'], 'Stopped')
                self.assertFalse(self.app.path(b.STATE + '/node.json').exists())
        self.assertFalse(any(call[:2] == ('/usr/bin/tailscale', 'up') for call in self.fake.calls))

    def test_resumed_running_actual_intent_write_failure_disconnects(self):
        self.prepare()
        intent = b.STATE + '/enrollment-intent.json'
        self.app.atomic(intent, json.dumps({'tailnet': 'example.ts.net'}, sort_keys=True) + '\n')
        self.fake.node = {'BackendState': 'Running', 'CurrentTailnet': {'Name': 'example.ts.net'},
                          'Self': {'ID': 'interrupted-node'}}
        original_run, original_atomic = self.fake.__call__, self.app.atomic
        wrote_intent = False
        def status_loses_intent(*args, **kwargs):
            result = original_run(*args, **kwargs)
            if args[:2] == ('/usr/bin/tailscale', 'status'):
                # Simulate loss after the protected same-intent read, so reconciliation must write.
                self.app.path(intent).unlink(missing_ok=True)
            return result
        def failed_intent_write(path, *args, **kwargs):
            nonlocal wrote_intent
            if path == intent:
                self.assertFalse(self.app.path(path).exists())
                original_atomic(path, *args, **kwargs)
                wrote_intent = True
                raise OSError('synthetic fsync failure after actual intent write')
            return original_atomic(path, *args, **kwargs)
        self.app.run, self.app.atomic = status_loses_intent, failed_intent_write
        with patch.object(b, 'checked_file', return_value=self.secret()):
            with self.assertRaises(OSError):
                self.app.enroll(str(self.root / 'secret'), 'example.ts.net')
        self.assertTrue(wrote_intent)
        self.assertEqual(self.fake.node['BackendState'], 'Stopped')
        self.assertFalse(self.app.path(b.STATE + '/node.json').exists())
        self.assertFalse(any(call[:2] == ('/usr/bin/tailscale', 'up') for call in self.fake.calls))

    def test_core_password_stdin_and_completed_retry_never_relocks_or_resets(self):
        self.prepare()
        self.assertEqual(self.fake.password_inputs, ['core:fixture-password-not-a-secret\n'])
        self.app.prepare('core', KEY, ['192.0.2.9/32'])
        self.app.prepare('core', KEY, ['192.0.2.9/32'], password='different-ignored-on-completed-retry')
        self.assertEqual(len(self.fake.password_inputs), 1)
        locks = [call[-1] for call in self.fake.calls if call[:2] == ('/usr/sbin/usermod', '--lock')]
        self.assertNotIn('core', locks)
        self.assertEqual(set(locks), {'dp-maint', 'dp-dev'})
        for call in self.fake.calls:
            self.assertFalse(any('fixture-password' in arg for arg in call))
        for path in self.app.state.iterdir():
            if path.is_file():
                self.assertNotIn('fixture-password', path.read_text())
        sudo = self.app.text('/etc/sudoers.d/dev-pair-operator')
        self.assertIn('core ALL=(ALL) PASSWD: ALL', sudo)
        self.assertNotIn('NOPASSWD', sudo)
        self.assertNotIn('dp-maint', sudo)
        self.assertNotIn('dp-dev', sudo)
        self.assertTrue(self.fake.assert_no_sudo_expected)
        self.fake.password_set = False
        with self.assertRaisesRegex(b.Blocked, 'not usable'):
            self.app.prepare('core', KEY, ['192.0.2.9/32'])
        self.assertEqual(len(self.fake.password_inputs), 1)

    def test_fedora_historical_ps_password_status_is_usable_but_np_lk_are_not(self):
        self.prepare()
        original = self.fake.__call__
        status = 'PS'
        def run(*args, **kwargs):
            if args[:2] == ('/usr/bin/passwd', '-S'):
                return f'core {status} 2026-11-15 0 99999 7 -1\n'
            return original(*args, **kwargs)
        self.app.run = run
        self.app.prepare('core', KEY, ['192.0.2.9/32'])
        for status in ('NP', 'LK', 'L', ''):
            with self.assertRaisesRegex(b.Blocked, 'not usable'):
                self.app.prepare('core', KEY, ['192.0.2.9/32'])

    def test_ssh_key_only_policy_is_reloaded_before_password_unlock_and_survives_marker_failure(self):
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path.endswith('/operator-password-set'):
                raise OSError('injected completion failure')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.prepare()
        self.assertTrue(self.fake.password_set)
        self.assertIn('PasswordAuthentication no', self.app.text('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'))
        reload_index = self.fake.calls.index(('/usr/bin/systemctl', 'reload', 'sshd.service'))
        unlock_index = self.fake.calls.index(('/usr/sbin/chpasswd',))
        self.assertLess(reload_index, unlock_index)
        self.assertFalse(self.app.path(b.STATE + '/operator-password-set').exists())

    def test_each_initial_policy_failure_window_prevents_password_unlock(self):
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path.endswith('/operator-keys.json'):
                raise OSError('injected key intent failure')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse(self.fake.password_set)
        self.app.atomic = original
        for command in ('restorecon', 'visudo', 'sudo', 'sshd'):
            self.fake.fail = lambda args, command=command: Path(args[0]).name == command
            with self.assertRaises(b.Blocked):
                self.prepare()
            self.assertFalse(self.fake.password_set)
        self.fake.fail = lambda args: args[:2] == ('/usr/bin/systemctl', 'reload')
        with self.assertRaises(b.Blocked):
            self.prepare()
        self.assertFalse(self.fake.password_set)
        self.assertFalse(self.fake.password_inputs)

    def test_blocked_dns_child_is_killed_by_deadline_and_existing_keys_are_preserved(self):
        self.prepare()
        before = self.app.text('/etc/ssh/dev-pair-keys/core')
        self.fake.calls.clear()
        original = subprocess.run
        attempts = []
        def blocking_dns(command, **kwargs):
            attempts.append(command)
            script = ('import runpy,socket,sys,time\n'
                      'target,marker=sys.argv[1:3]\n'
                      'def blocked_dns(*a,**k):\n'
                      '    with open(marker,"a") as output: output.write("DNS entered\\n")\n'
                      '    time.sleep(120)\n'
                      'socket.getaddrinfo=blocked_dns\n'
                      'sys.argv=[target,"_fetch-github-keys"]\n'
                      'runpy.run_path(target,run_name="__main__")')
            return original([sys.executable, '-I', '-c', script, str(ROOT / 'tools/bootstrap.py'),
                             str(self.root / 'dns-handshake')], **kwargs)
        argv = ['bootstrap.py', 'prepare', '--apply', '--gptbox-context', '/unused',
                '--expected-context-sha256', 'a' * 64, '--bootstrap-source', '192.0.2.9/32']
        start = time.monotonic()
        with patch.object(sys, 'argv', argv), patch.object(b, 'Bootstrap', return_value=self.app), \
                patch.object(b.subprocess, 'run', side_effect=blocking_dns), \
                patch.object(b, 'KEYS_FETCH_TIMEOUT', 0.4), patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(b.main(), 2)
        self.assertLess(time.monotonic() - start, 4)
        self.assertEqual((self.root / 'dns-handshake').read_text().splitlines(), ['DNS entered'] * 3)
        self.assertEqual(len(attempts), 3)
        self.assertTrue(all(command[-1] == '_fetch-github-keys' for command in attempts))
        self.assertEqual(self.app.text('/etc/ssh/dev-pair-keys/core'), before)
        self.assertFalse(self.fake.calls)

    @unittest.skipUnless(Path('/usr/sbin/sshd').exists(), 'sshd parser unavailable')
    def test_real_sshd_effective_policy_rejects_password_after_unlocked_marker_failure(self):
        host = self.root / 'test-host-key'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(host)], check=True)
        config = self.root / 'test-sshd.conf'
        base = ('HostKey ' + str(host) + '\nPasswordAuthentication yes\n'
                'KbdInteractiveAuthentication yes\nPubkeyAuthentication yes\n')
        config.write_text(base)
        command = ['/usr/sbin/sshd', '-T', '-f', str(config), '-C', 'user=core,host=bootstrap,addr=192.0.2.2']
        baseline = subprocess.run(command, text=True, capture_output=True, check=True).stdout
        self.assertIn('passwordauthentication yes', baseline.splitlines())
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path.endswith('/operator-password-set'):
                raise OSError('injected completion failure')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.prepare()
        self.assertTrue(self.fake.password_set)
        config.write_text(base + 'Include ' + str(self.app.path('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf')) + '\n')
        effective = subprocess.run(command, text=True, capture_output=True, check=True).stdout.splitlines()
        self.assertIn('authenticationmethods publickey', effective)
        self.assertIn('passwordauthentication no', effective)
        self.assertIn('kbdinteractiveauthentication no', effective)

    def test_password_marker_write_failure_retries_without_locking_core(self):
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path.endswith('/operator-password-set'):
                raise OSError('injected disk error')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.prepare()
        self.assertTrue(self.fake.password_set)
        self.assertFalse(self.app.path(b.STATE + '/operator-password-set').exists())
        self.app.atomic = original
        self.prepare()
        self.assertEqual(len(self.fake.password_inputs), 2)
        self.assertEqual(len([call for call in self.fake.calls if Path(call[0]).name == 'useradd']), 3)
        self.assertFalse(any(call[:2] == ('/usr/sbin/usermod', '--lock') and call[-1] == 'core'
                             for call in self.fake.calls))

    def test_chpasswd_failure_has_no_completion_and_corrected_retry_works(self):
        self.fake.fail = lambda args: Path(args[0]).name == 'chpasswd'
        with self.assertRaises(b.Blocked):
            self.prepare()
        self.assertFalse(self.app.path(b.STATE + '/operator-password-set').exists())
        self.assertTrue(self.app.path('/etc/sudoers.d/dev-pair-operator').exists())
        self.assertIn('PasswordAuthentication no', self.app.text('/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'))
        self.assertFalse(self.fake.password_set)
        self.fake.fail = None
        self.prepare()
        self.assertTrue(self.app.status()['prepared'])

    def test_operator_keys_atomic_rotation_and_interruption_preserve_previous_keys(self):
        self.prepare()
        target = '/etc/ssh/dev-pair-keys/core'
        changed = KEY.replace('fixtureonly', 'fixturechanged')
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path == target:
                raise OSError('injected rename failure')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.app.prepare('core', changed, ['192.0.2.9/32'])
        self.assertEqual(self.app.text(target), KEY)
        self.app.atomic = original
        self.app.prepare('core', changed, ['192.0.2.9/32'])
        self.assertEqual(self.app.text(target), changed)
        self.assertEqual(len(self.fake.password_inputs), 1)
        self.app.path(target).write_text('unauthorized root-side drift')
        with self.assertRaisesRegex(b.Blocked, 'conflicts'):
            self.app.prepare('core', KEY, ['192.0.2.9/32'])
        self.assertEqual(self.app.text(target), 'unauthorized root-side drift')

    def test_hostname_time_and_mosh_are_prepared_without_claiming_acceptance(self):
        self.prepare()
        self.assertIn('preserve_hostname: true', self.app.text('/etc/cloud/cloud.cfg.d/99-dev-pair-hostname.cfg'))
        self.assertIn(('/usr/bin/hostnamectl', 'set-hostname', 'erebus'), self.fake.calls)
        self.assertIn(('/usr/bin/systemctl', 'enable', '--now', 'chronyd.service'), self.fake.calls)
        rules = self.app.text('/etc/dev-pair/bootstrap.nft').splitlines()
        self.assertIn('add rule inet dev_pair_bootstrap input iifname "tailscale0" udp dport 60000-61000 accept', rules)
        self.assertLess(rules.index('add rule inet dev_pair_bootstrap input iifname != "tailscale0" udp dport 60000-61000 drop'),
                        rules.index('add rule inet dev_pair_bootstrap input ct state established,related accept'))
        self.assertEqual(self.app.status()['runtime_acceptance'], 'not verified')

    def test_mosh_reservation_preserves_existing_ranges_and_handles_reapply(self):
        proc = self.app.path('/proc/sys/net/ipv4/ip_local_reserved_ports')
        proc.parent.mkdir(parents=True)
        proc.write_text('1024,58000-60001,62000-62002\n')
        self.prepare()
        expected = 'net.ipv4.ip_local_reserved_ports = 1024,58000-61000,62000-62002\n'
        self.assertEqual(self.app.text('/etc/sysctl.d/90-dev-pair-mosh.conf'), expected)
        proc.write_text('1024,58000-61000,62000-62002\n')
        self.prepare()
        self.assertEqual(self.app.text('/etc/sysctl.d/90-dev-pair-mosh.conf'), expected)

    def test_failed_fetch_does_not_touch_existing_keys_or_execute_prepare(self):
        self.prepare()
        before = self.app.text('/etc/ssh/dev-pair-keys/core')
        self.fake.calls.clear()
        argv = ['bootstrap.py', 'prepare', '--apply', '--gptbox-context', '/unused',
                '--expected-context-sha256', 'a' * 64, '--bootstrap-source', '192.0.2.9/32']
        with patch.object(sys, 'argv', argv), patch.object(b, 'Bootstrap', return_value=self.app), \
                patch.object(b, 'github_keys', side_effect=b.Blocked('fetch failed')), \
                patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(b.main(), 2)
        self.assertEqual(self.app.text('/etc/ssh/dev-pair-keys/core'), before)
        self.assertFalse(self.fake.calls)

    def test_active_mosh_listener_is_only_accepted_for_managed_core_executable(self):
        self.prepare()
        process = self.app.path('/proc/72')
        process.mkdir()
        (process / 'exe').symlink_to('/usr/bin/mosh-server')
        (process / 'status').write_text('Uid: 1001 1001 1001 1001\n')
        line = 'udp UNCONN 0 0 0.0.0.0:60001 0.0.0.0:* users:(("mosh-server",pid=72,fd=3))'
        original = self.fake.__call__
        def run(*args, **kwargs):
            return line if args[:2] == ('/usr/bin/ss', '-H') else original(*args, **kwargs)
        self.app.run = run
        self.app.preflight()
        (process / 'status').write_text('Uid: 0 0 0 0\n')
        with self.assertRaisesRegex(b.Blocked, 'unexpected listener'):
            self.app.preflight()

    def test_finalize_always_blocks_without_reading_fake_evidence(self):
        proc = subprocess.run([sys.executable, str(ROOT / 'tools/bootstrap.py'), 'finalize'], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('not implemented', proc.stderr)

class OperatorInputTests(unittest.TestCase):
    def test_password_input_constraints_and_real_command_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'password'
            with patch.object(b, 'checked_file', return_value=file):
                for invalid in ('', 'two\nlines', 'colon:break', 'carriage\r', 'a' * 1025):
                    file.write_text(invalid)
                    with self.assertRaises(b.Blocked):
                        b.operator_password(str(file))
                file.write_text('synthetic-stdin-value\n')
                self.assertEqual(b.operator_password(str(file)), 'synthetic-stdin-value')
        # Execute a harmless real child reading stdin, rather than only asserting a mock call.
        result = b.Commands()(sys.executable, '-c', 'import sys; print(len(sys.stdin.read()))',
                              input_text='synthetic-stdin-value')
        self.assertEqual(result, '')
        records = []
        run = b.Commands()
        run.diagnostic = records.append
        with self.assertRaises(b.Blocked) as error:
            run(sys.executable, '-c', 'import sys;print(sys.stdin.read());sys.exit(1)',
                input_text='core:synthetic-stdin-value\n')
        self.assertNotIn('synthetic-stdin-value', str(error.exception))
        self.assertNotIn('synthetic-stdin-value', json.dumps(records))
        self.assertTrue(records[0]['sensitive_stdin'])

    def test_profile_interactive_tty_reconnect_and_noninteractive_protocols(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            identity = directory / 'identity'
            identity.write_text('#!/bin/sh\necho core\n')
            identity.chmod(0o700)
            tmux = directory / 'tmux'
            tmux.write_text('#!/bin/sh\nprintf "ATTACHED:%s\\n" "$*"\n')
            tmux.chmod(0o700)
            profile = directory / 'profile'
            profile.write_text(b.OPERATOR_PROFILE.replace('/usr/bin/id', str(identity)).replace('/usr/bin/tmux', str(tmux)))
            command = '. ' + str(profile) + '; printf PROTOCOL-UNCHANGED'
            for interactive in (False, True):
                args = ['/bin/bash', '--noprofile', '--norc', '-ic' if interactive else '-c', command]
                plain = subprocess.run(args, capture_output=True, text=True, env={'PATH': '/usr/bin'})
                self.assertEqual(plain.stdout, 'PROTOCOL-UNCHANGED')
            master, slave = pty.openpty()
            try:
                proc = subprocess.Popen(['/bin/bash', '--noprofile', '--norc', '-ic', command],
                                        stdin=slave, stdout=slave, stderr=slave, env={'PATH': '/usr/bin'})
                proc.wait(timeout=5)
                os.close(slave)
                slave = None
                output = b''
                while True:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                self.assertIn(b'ATTACHED:new-session -A -s dev-pair-core', output)
                self.assertNotIn(b'PROTOCOL-UNCHANGED', output)
            finally:
                os.close(master)
                if slave is not None:
                    os.close(slave)


class GitHubKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys = []
        for kind in ('ed25519', 'rsa'):
            key = Path(cls.tmp.name) / kind
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', kind, '-N', '', '-f', str(key)], check=True)
            cls.keys.append(key.with_suffix('.pub').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_valid_key_types_imported_and_invalid_payloads_fail_as_a_whole(self):
        combined = ''.join(self.keys + self.keys[:1]).encode()
        accepted = b.validate_public_keys(combined)
        self.assertEqual(len(accepted.splitlines()), 2)
        self.assertTrue(accepted.startswith('ssh-ed25519 '))
        self.assertIn('\nssh-rsa ', accepted)
        for invalid in (b'', b'x' * (b.KEYS_MAX_BYTES + 1), b'<html>oops</html>',
                        b'command="touch /tmp/no" ' + self.keys[0].encode(),
                        self.keys[0].encode() + b'ssh-ed25519 AAAA\n',
                        self.keys[0].encode().replace(b'ssh-ed25519', b'ssh-rsa', 1)):
            with self.assertRaises(b.Blocked):
                b.validate_public_keys(invalid)

    def test_https_fetch_retries_size_redirect_bounds_and_preserves_existing_keyfile(self):
        class Response(io.BytesIO):
            status = 200
            def geturl(self):
                return b.KEYS_URL
        payload = ''.join(self.keys).encode()
        opener = SimpleNamespace(open=lambda *args, **kwargs: Response(payload))
        with patch.object(b.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(len(b.validate_public_keys(b.fetch_github_response()).splitlines()), 2)
        with patch.object(b.urllib.request, 'build_opener', return_value=opener):
            with patch.object(opener, 'open', side_effect=urllib.error.URLError('secret external detail')) as fetch:
                with self.assertRaises(b.Blocked) as error:
                    b.fetch_github_response()
                self.assertEqual(fetch.call_count, 1)
                self.assertNotIn('secret external', str(error.exception))
                for args in fetch.call_args_list:
                    self.assertEqual(args.kwargs['timeout'], 5)
                    self.assertEqual(args.args[0].full_url, b.KEYS_URL)
            with patch.object(opener, 'open', return_value=Response(b'x' * (b.KEYS_MAX_BYTES + 1))):
                with self.assertRaises(b.Blocked):
                    b.fetch_github_response()
        self.assertIsNone(b.NoRedirect().redirect_request(None, None, 302, 'redirect', {}, 'https://other.example/keys'))

if __name__ == '__main__':
    unittest.main()
