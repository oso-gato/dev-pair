"""The producer CLIs admit newer tooling before signed Git, then verify exact source."""
from contextlib import ExitStack, nullcontext, redirect_stderr
from hashlib import sha256
import io
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import gptbox as g
import public_inputs as public


def commit(path):
    for arguments in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                       'commit', '-qm', 'protected source fixture']):
        subprocess.run(['/usr/bin/git', '-C', str(path), *arguments], check=True, stdin=subprocess.DEVNULL)
    return subprocess.check_output(['/usr/bin/git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()


def evidence(directory, revision, role):
    proof, bundle = b'Verified OK', b'fixture bundle'
    binary = sha256(b'new stable executable').hexdigest()
    tooling = {'schema': 1, 'kind': 'dev-pair-verified-codex-pin-proposal', 'reviewed_source_sha': revision,
               'source_sha': 'f'*40, 'tag': 'rust-v0.170.0', 'version': '0.170.0', 'release_id': 123,
               'assets': {'archive': {'sha256': 'd'*64, 'bytes': 20},
                          'bundle': {'sha256': sha256(bundle).hexdigest(), 'bytes': len(bundle)}},
               'binary': {'sha256': binary, 'bytes': 23}, 'verification_sha256': 'e'*64,
               'approved_pins_match': False, 'cached_assets': []}
    raw = public.canonical(tooling)
    expected = sha256(raw).hexdigest()
    artifacts, *_ = public.selected_tooling(tooling)
    receipt = {'helper_source_sha': revision, 'exit_status': 0, 'result': 'Verified OK',
               'verification_output_sha256': sha256(proof).hexdigest(), 'artifacts': public.artifact_receipt(artifacts),
               'codex_source_sha': tooling['source_sha'], 'codex_binary_sha256': binary, 'codex_binary_bytes': 23}
    for name, payload in [('tooling.json', raw), ('verification-receipt.json', public.canonical(receipt)),
                          ('cosign-verification.txt', proof), ('codex.sigstore', bundle)]:
        file = directory / name
        file.write_bytes(payload)
        file.chmod(0o444)
    context = '9'*64
    incoming = {'source_sha': revision, 'scenario': role, 'refresh_tooling_sha256': expected,
                'codex_sha256': binary, 'codex_version': '0.170.0', 'codex_source_sha': tooling['source_sha'],
                'context_sha256': context, 'platform_export': {}}
    return expected, context, binary, public.canonical({'version': 2, 'source_sha': revision, 'inputs': incoming})


class RefreshGitTests(unittest.TestCase):
    def test_both_cli_roles_install_signed_git_then_verify_actual_git_objects(self):
        for role in ('maintenance', 'development'):
            with self.subTest(role=role), TemporaryDirectory() as temporary:
                self.producer(role, Path(temporary))

    def producer(self, role, root):
        source, upstream, context, proof = (root / 'input' / item for item in ('dev-pair', 'distrobox', 'context', 'evidence'))
        for path in (source / 'tools', upstream, context, proof):
            path.mkdir(parents=True)
        for name in (*g.ADAPTER_SOURCE_FILES, 'public_inputs.py'):
            (source / 'tools' / name).write_bytes((TOOLS / name).read_bytes())
        runtime = source / 'runtime/devbox'
        runtime.mkdir(parents=True)
        (runtime / 'controller.py').write_bytes((TOOLS.parent / 'runtime/devbox/controller.py').read_bytes())
        revision = commit(source)
        for name in ('distrobox-init', 'distrobox-enter'):
            (upstream / name).write_text('#!/bin/sh\nexit 0\n')
        upstream_revision = commit(upstream)
        (root / 'var/lib/dev-pair/bootstrap').mkdir(parents=True, mode=0o700)
        git = root / 'usr/bin/git'
        trace = []
        test = self

        class Runner:
            metadata_diagnostic = native_register = None
            native_prefix = g.PREPARE_NATIVE + '-f00d1234'

            def phase(self, *args, **kwargs):
                return nullcontext()

            def __call__(self, *args, **kwargs):
                if args[0] == '/usr/bin/dnf':
                    test.assertEqual(args, ('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1',
                                            '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'))
                    test.assertFalse(git.exists())
                    trace.append('signed-git')
                    git.parent.mkdir(parents=True)
                    git.touch()
                    return ''
                if args[0] == '/usr/bin/git':
                    test.assertTrue(git.exists(), 'Git invoked before the signed prerequisite')
                    trace.append(args[2:])
                    return subprocess.check_output(args, text=True)
                if args[:2] == ('/usr/bin/getent', 'passwd'):
                    return ''
                raise AssertionError(f'unprojected command {args[0]}')

        app = (g.DevelopmentGptbox if role == 'development' else g.Gptbox)(root, Runner())
        prep = g.Bootstrap(root, Runner())
        expected, context_digest, binary, request = evidence(proof, revision, role)
        manifest = {'source_sha': revision, 'role': role, 'fedora': {'image': g.FEDORA},
                    'codex': {'version': '0.170.0', 'sha256': binary}}
        protected = app.protected_bytes

        def read(path, *args):
            return request if path == Path('/var/lib/dev-pair/ci-executor/request.json') else protected(path, *args)

        def stop(path, contents, **kwargs):
            self.assertEqual(path, g.STATE + '/desired.json')
            self.assertEqual((app.codex_version, app.codex_sha), ('0.170.0', binary))
            for repo, leaf in ((source, revision + ':tools/gptbox.py'), (source, revision + ':tools/public_inputs.py'),
                               (upstream, upstream_revision + ':distrobox-enter')):
                self.assertIn((str(repo), 'show', leaf), trace)
            trace.append('normal-effects-gate')
            raise g.Blocked('local fixture stops before normal bootstrap effects')

        cli = 'initialize' if role == 'maintenance' else 'prepare-development-host'
        argv = ['gptbox.py', cli, '--apply', '--context', str(context), '--expected-context-sha256', context_digest,
                '--source-sha', revision, '--distrobox-source', str(upstream), '--bootstrap-source', '192.0.2.9/32',
                '--password-file', str(root / 'fixture-password'), '--ci-tooling-sha256', expected]
        check = lambda *args, **kwargs: (None, None, manifest)
        with ExitStack() as stack:
            for obj, name, value in ((g, '__file__', str(source / 'tools/gptbox.py')), (g, 'DBX_SHA', upstream_revision),
                                     (public, '__file__', str(source / 'tools/public_inputs.py')),
                                     (g, 'operator_password', lambda _: 'local fixture only'), (g, 'github_keys', lambda: 'fixture'),
                                     (app, 'ci_producer_source', lambda: source), (app, 'protected_bytes', read),
                                     (app, 'check_gptbox_inputs', check), (g.candidate, 'verify', lambda *args: None),
                                     (app, 'preparation', lambda: prep), (app, 'preflight', lambda: None),
                                     (app, 'lock', lambda *args: nullcontext()), (prep, 'check_gptbox_inputs', check),
                                     (prep, 'validate_gptbox_context', check), (prep, 'preflight', lambda: None),
                                     (prep, 'atomic', stop), (prep, 'step', lambda name, operation: operation()), (sys, 'argv', argv)):
                stack.enter_context(patch.object(obj, name, value))
            if role == 'development':
                stack.enter_context(patch.object(g, 'DevelopmentGptbox', return_value=app))
                stack.enter_context(patch.object(app, 'protect_host_sources'))
            else:
                stack.enter_context(patch.object(g, 'Gptbox', return_value=app))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(g.main(), 2)
        self.assertEqual(trace[0], 'signed-git')
        self.assertEqual(trace[-1], 'normal-effects-gate')
