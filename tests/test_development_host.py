"""Development host dispatcher and convergence with isolated Git and host fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_bootstrap as host
from test_gptbox import g
import bootstrap as b
import fedora_input_fixture


class HostFixture(b.Bootstrap):
    def _directory_as(self, name, mode, uid, gid, *, change_owner, check_gid=False):
        # Keep the real directory checks while modeling account ownership locally.
        return super()._directory_as(name, mode, os.getuid(), os.getgid(), change_owner=False, check_gid=check_gid)


class HostCommands(b.Commands):
    def __init__(self, fixture):
        self.fixture = fixture

    def __call__(self, *args, **kwargs):
        fixture = self.fixture
        if args[0] == '/usr/bin/git':
            fixture.events.append(('proof', args[-1]))
            return super().__call__(*args, **kwargs)
        if args[0] == '/usr/bin/dnf':
            self.assert_native_scope()
            self.native_register(self.native_prefix + f'-{len(fixture.events):08x}')
            fixture.events.append(('dnf', args[-1]))
            if args[-1] == 'git-core':
                fixture.git.parent.mkdir(parents=True, exist_ok=True)
                fixture.git.touch()
            if fixture.fail_packages and args[-1] != 'git-core':
                raise b.Blocked('interrupted fixture host package command')
        return fixture.host.fake(*args, **kwargs)

    def assert_native_scope(self):
        if self.deadline is None or self.native_prefix is None or self.native_register is None:
            raise AssertionError('host effects escaped the registered bounded native phase')

    def reconcile_native(self, args, env):
        self.fixture.events.append(('reconcile', args))
        if self.fixture.fail_reconcile:
            raise b.Blocked('fixture owner reconciliation blocked')


class DevelopmentHostTests(unittest.TestCase):
    def setUp(self):
        self.host = host.BootstrapTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.root = self.host.root
        self.git = self.host.app.path('/usr/bin/git')
        self.events = []
        self.fail_packages = False
        self.fail_reconcile = False
        self.password = self.root / 'disposable-password'
        self.password.write_text('synthetic-disposable-password\n')
        self.password.chmod(0o600)
        self.entry = g.DevelopmentGptbox(self.root, HostCommands(self))
        self.preparation = HostFixture(self.root, HostCommands(self))
        self.enterContext(patch.object(self.entry, 'preparation', return_value=self.preparation))
        self.enterContext(patch.object(b, 'checked_file', return_value=self.password))
        self.enterContext(patch.object(g, 'github_keys', side_effect=self.public_keys))
        self.enterContext(patch.object(b.Bootstrap, 'build_gptbox', side_effect=AssertionError('maintenance build invoked')))
        self.enterContext(patch.object(self.entry, 'setup_executor', side_effect=AssertionError('image executor invoked')))

        source = Path(g.__file__).resolve().parent.parent
        files = {f'tools/{name}': (source / 'tools' / name).read_bytes() for name in g.ADAPTER_SOURCE_FILES}
        files['runtime/devbox/controller.py'] = (source / 'runtime/devbox/controller.py').read_bytes()
        self.source, self.revision = self.checkout('dev-pair', files)
        self.upstream, upstream_head = self.checkout('distrobox', {
            'distrobox-init': b'synthetic distrobox init script\n', 'distrobox-enter': b'synthetic distrobox enter script\n'})
        self.enterContext(patch.object(g, 'DBX_SHA', upstream_head))
        for module in (g, b, g.candidate, g.fedora_oci, g.fedora_oci._public_inputs()):
            self.enterContext(patch.object(module, '__file__', str(self.source / 'tools' / Path(module.__file__).name)))
        fedora_input_fixture.install(self)
        codex = bytearray(64)
        codex[:6] = b'\x7fELF\x02\x01'
        codex[18:20] = b'\x3e\x00'
        self.binary = self.root / 'synthetic-codex'
        self.binary.write_bytes(codex)
        self.enterContext(patch.object(g, 'CODEX_SHA', g.sha(codex)))
        self.context, self.digest = self.make_context('development')

    def checkout(self, name, files):
        raw = self.root / ('raw-' + name)
        raw.mkdir()
        for relative, data in files.items():
            path = raw / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

        def git(*arguments):
            return subprocess.run(['/usr/bin/git', '-C', str(raw), *arguments], check=True, capture_output=True).stdout.decode().strip()

        git('init', '--quiet', '--template=')
        git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
            '-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'Isolated host-entry component fixture')
        revision = git('rev-parse', 'HEAD')
        public = g.fedora_oci._public_inputs()
        exported = public.clean_checkout(raw, revision, self.root / ('export-' + name), self.root)
        staged = self.root / name
        for path in exported.rglob('*'):
            if path.is_file():
                target = staged / path.relative_to(exported)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                target.chmod(0o444)
        return staged, revision

    def make_context(self, role):
        output = self.root / (role + '-context')
        manifest = {'kind': 'operator-verified-inputs', 'source_sha': self.revision,
            'standards_sha': g.candidate.STANDARDS, 'fedora': dict(g.fedora_oci.PROVENANCE),
            'codex': {'version': '0.169.0', 'source': 'https://github.com/openai/codex/releases/download/rust-v0.169.0/codex-x86_64-unknown-linux-musl.tar.gz',
                      'sha256': g.CODEX_SHA, 'verification': 'SYNTHETIC fixture only'},
            'role': role, 'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
            'mounts': {name: f'/var/lib/dev-pair/{role}/{directory}/offline-fixture'
                       for name, directory in (('workspace', 'workspaces'), ('state', 'state'), ('cache', 'cache'))}}
        manifest['mounts']['credentials'] = f'/var/lib/dev-pair/credentials/{role}/offline-fixture'
        record = g.candidate.prepare(manifest, self.binary, output, fedora_inputs=self.root / 'fake-fedora')
        return output, record['context_sha256']

    def public_keys(self):
        self.events.append(('keys', 'synthetic'))
        return host.KEY

    def cli(self, *options, stage='prepare-development-host', context=None, digest=None, source='192.0.2.9/32'):
        argv = ['gptbox.py', stage, '--context', str(context or self.context), '--expected-context-sha256', digest or self.digest,
                '--distrobox-source', str(self.upstream), '--source-sha', self.revision,
                '--bootstrap-source', source, '--password-file', str(self.password), *options]
        stdout = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(g, 'DevelopmentGptbox', return_value=self.entry), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            result = g.main()
        return result, json.loads(stdout.getvalue()) if stdout.getvalue() else None

    def test_dispatcher_converges_real_host_primitive_and_producer_consumes_readiness(self):
        self.assertEqual(self.cli()[1]['source_verification'], 'pending signed Git prerequisite')
        self.assertFalse(self.entry.state.exists())
        status, result = self.cli('--apply')
        self.assertEqual(status, 0)
        self.assertEqual(result['host_prerequisites'], 'complete')
        self.assertFalse(result['job_admission'])
        first, second, *_ = [i for i, event in enumerate(self.events) if event[0] == 'dnf']
        self.assertEqual(self.events[first], ('dnf', 'git-core'))
        self.assertTrue(any(event[0] == 'proof' for event in self.events[first + 1:second]))
        self.assertIn(('keys', 'synthetic'), self.events[first + 1:second])
        signed_git = next(args for args in self.host.fake.calls if args[-1] == 'git-core')
        self.assertEqual(signed_git[1:], ('-y', '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1',
                                         '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'))
        self.assertEqual(self.host.fake.password_inputs, ['core:synthetic-disposable-password\n'])
        self.assertTrue({'core', 'dp-maint', 'dp-dev'} <= self.host.fake.accounts.keys())
        for name in ('prepared', 'initialize.json', 'gptbox-image.json', 'gptbox-adapter', 'gptbox-development'):
            self.assertFalse((self.entry.state / name).exists())
        self.assertEqual(self.preparation.run.phase_budget_witness['configured_seconds'], 600)
        with patch.object(self.entry, 'verify_builder', side_effect=AssertionError('producer reached live builder guard')):
            with self.assertRaisesRegex(AssertionError, 'producer reached live builder guard'):
                self.cli('--apply', stage='build-development')
        self.entry.verify_host_readiness(self.revision, self.digest)
        with self.assertRaisesRegex(b.Blocked, 'differs from the prepared development host'):
            self.entry.verify_host_readiness(self.revision, 'f' * 64)

    def test_wrong_role_dirty_source_and_prior_host_do_not_converge(self):
        maintenance, digest = self.make_context('maintenance')
        self.assertEqual(self.cli('--apply', context=maintenance, digest=digest)[0], 2)
        self.assertFalse(self.entry.state.exists())
        with self.assertRaisesRegex(b.Blocked, 'only maintenance-role'):
            g.Gptbox(self.root, HostCommands(self)).initialize(self.context, self.digest, self.upstream, self.revision,
                                                               ['192.0.2.9/32'], str(self.password), apply=True)
        self.entry.directory('/var/lib/dev-pair', mode=0o755)
        self.entry.directory(b.STATE)
        prior = self.entry.state / 'prepared'
        prior.write_text('unrelated existing host state\n')
        self.assertEqual(self.cli('--apply')[0], 2)
        self.assertEqual(prior.read_text(), 'unrelated existing host state\n')
        prior.unlink()
        operator = self.entry.path('/etc/sudoers.d/dev-pair-operator')
        operator.parent.mkdir()
        operator.write_text('unowned fixture\n')
        self.assertEqual(self.cli('--apply')[0], 2)
        self.assertFalse(any(event[0] == 'dnf' for event in self.events))
        self.assertEqual(operator.read_text(), 'unowned fixture\n')
        operator.unlink()
        script = self.upstream / 'distrobox-init'
        script.chmod(0o644)
        script.write_text('dirty upstream worktree\n')
        self.assertEqual(self.cli('--apply')[0], 2)
        self.assertEqual([event for event in self.events if event[0] == 'dnf'], [('dnf', 'git-core')])
        self.assertFalse((self.entry.state / 'desired.json').exists())
        self.assertFalse((self.entry.state / 'host-ready.json').exists())

    def test_interrupt_requires_exact_retry_and_owned_native_reconciliation(self):
        self.fail_packages = True
        self.assertEqual(self.cli('--apply')[0], 2)
        self.assertTrue((self.entry.state / 'desired.json').exists())
        self.assertFalse((self.entry.state / 'host-ready.json').exists())
        self.assertEqual(self.cli('--apply', stage='build-development')[0], 2)
        intent = json.loads(self.entry.path(b.DEVELOPMENT_HOST_INTENT).read_bytes())
        self.assertEqual(len(intent['native_units']), 2)
        self.assertEqual(self.cli('--apply')[0], 2)
        self.assertEqual(self.cli('--apply', '--retry', source='192.0.2.10/32')[0], 2)
        self.assertFalse(any(event[0] == 'reconcile' for event in self.events))
        intent_path = self.entry.path(b.DEVELOPMENT_HOST_INTENT)
        original_intent = intent_path.read_bytes()
        intent_path.write_bytes(g.image_inputs_bytes({**intent, 'native_units': ['dev-pair-initialize-prepare-12345678-12345678']}))
        self.assertEqual(self.cli('--apply', '--retry')[0], 2)
        self.assertFalse(any(event[0] == 'reconcile' for event in self.events))
        intent_path.write_bytes(original_intent)
        self.fail_reconcile = True
        self.fail_packages = False
        self.assertEqual(self.cli('--apply', '--retry')[0], 2)
        self.assertFalse((self.entry.state / 'host-ready.json').exists())
        self.fail_reconcile = False
        self.events.clear()
        self.assertEqual(self.cli('--apply', '--retry')[0], 0)
        self.assertEqual([event[1] for event in self.events if event[0] == 'reconcile'], [
            ('--unit=' + unit, '--description=dev-pair-owned-' + unit) for unit in intent['native_units']])
        self.assertFalse(any(event == ('dnf', 'git-core') for event in self.events))
        with patch.object(self.entry, 'verify_builder', return_value=None):
            self.assertTrue(self.cli('--apply')[1]['reused'])

    def test_phase_exit_failure_withholds_readiness_and_maintenance_prepare(self):
        original = self.preparation.run.phase

        @contextlib.contextmanager
        def expired(*args, **kwargs):
            with original(*args, **kwargs):
                yield
            raise b.Blocked('fixture native phase expiry at exit')

        with patch.object(self.preparation.run, 'phase', side_effect=expired):
            self.assertEqual(self.cli('--apply')[0], 2)
        self.assertTrue((self.entry.state / 'packages.txt').exists())
        self.assertFalse((self.entry.state / 'host-ready.json').exists())
        self.assertEqual(self.cli('--apply', stage='build-development')[0], 2)
        maintenance, digest = self.make_context('maintenance')
        with self.assertRaisesRegex(b.Blocked, 'belongs to the development host preparation'):
            self.preparation.prepare('core', host.KEY, ['192.0.2.9/32'], maintenance, digest, password='fixture')
