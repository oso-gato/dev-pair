"""Synthetic tempfile/command tests. These do NOT establish Fedora/runtime behavior."""
import importlib.util
import hashlib
from types import SimpleNamespace
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
        self.image = None

    def __call__(self, *args, ok=(0,)):
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise b.Blocked('injected command failure (output withheld)')
        exe = Path(args[0]).name
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
             'mounts': {key: '/var/lib/dev-pair/jobs/offline-test/' + key for key in ('workspace', 'state', 'cache', 'credentials')}}
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
        record = {'image_id': 'sha256:' + 'b' * 64, 'context_sha256': digest}
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
                    self.app.prepare('operator', KEY, ['192.0.2.9/32'], context, expected)
                self.assert_no_host_mutation()
        with patch.object(b.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(b.Blocked, 'x86_64'):
                self.app.prepare('operator', KEY, ['192.0.2.9/32'], context, digest)
        self.assert_no_host_mutation()
        for file in context.iterdir():
            file.unlink()
        context.rmdir()
        context, digest = self.context(fixture=True)
        with self.assertRaises(b.Blocked):
            self.app.prepare('operator', KEY, ['192.0.2.9/32'], context, digest)
        self.assert_no_host_mutation()

    def test_corrected_hash_retry_and_minimal_git_prerequisite_before_binding(self):
        context, digest = self.context()
        with self.assertRaises(b.Blocked):
            self.app.prepare('operator', KEY, ['192.0.2.9/32'], context, '1' * 64)
        self.assert_no_host_mutation()
        original = self.fake.__call__
        def prerequisite(*args, **kwargs):
            if Path(args[0]).name == 'dnf' and args[-1] == 'git-core':
                self.assertFalse(self.app.path(b.STATE + '/desired.json').exists())
                self.assertFalse(any(Path(call[0]).name == 'useradd' for call in self.fake.calls))
            return original(*args, **kwargs)
        self.app.run = prerequisite
        with patch.object(b.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024 ** 3)):
            self.app.prepare('operator', KEY, ['192.0.2.9/32'], context, digest)
        dnf = [call for call in self.fake.calls if Path(call[0]).name == 'dnf']
        self.assertEqual(dnf[0][-2:], ('install', 'git-core'))
        self.assertTrue(self.app.path(b.STATE + '/prepared').exists())

    def test_source_failure_after_git_prerequisite_does_not_bind_desired(self):
        context, digest = self.context()
        tool = self.app.candidate_tool()
        with patch.object(tool, 'check_source', side_effect=ValueError('source mismatch')):
            with self.assertRaisesRegex(b.Blocked, 'source verification'):
                self.app.prepare('operator', KEY, ['192.0.2.9/32'], context, digest)
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

    def test_finalize_always_blocks_without_reading_fake_evidence(self):
        proc = subprocess.run([sys.executable, str(ROOT / 'tools/bootstrap.py'), 'finalize'], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('not implemented', proc.stderr)

if __name__ == '__main__':
    unittest.main()
