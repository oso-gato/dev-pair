"""Exercise attended source provisioning with real disposable Git repositories."""

import contextlib
import errno
import io
import os
from pathlib import Path
import pty
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'tools'))
import owner_intake as owner
import owner_source as source
import session_controller as controller

REPOSITORY = 'fixture/project'


@unittest.skipUnless(os.getuid() == 0, 'source fixture needs mapped root for protected input ownership')
class OwnerSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.owner-source-', dir=REPO_ROOT)
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.site = self.path / 'site'
        self.intake = owner.Intake(self.site, self.path / 'runtime')
        self.first = owner.FirstCatalogue(self.intake)
        self.standards = self.repository('standards')
        self.project = self.repository('project')
        bodies = {name: ('Synthetic shared input ' + name + '\n').encode() for name in controller.SHARED}
        for name, body in bodies.items():
            (self.standards / name).write_bytes(body)
        self.standard_pin = self.commit(self.standards, 'Fixture standards')
        self.use(mock.patch.dict(controller.SHARED, {name: owner.p.sha256(body) for name, body in bodies.items()}))
        self.use(mock.patch.object(owner.p, 'STANDARDS', self.standard_pin))
        self.use(mock.patch.object(controller, 'STANDARDS', self.standard_pin))
        for name in controller.PUBLIC:
            (self.project / name).write_text('Synthetic project document ' + name + '\n')
        (self.project / 'STANDARDS.md').write_text('\n'.join(
            f'https://github.com/{source.STANDARD_REPOSITORY}/blob/{self.standard_pin}/{name}' for name in bodies))
        app = self.project / owner.candidate.APP
        app.parent.mkdir(parents=True)
        app.write_text('# Synthetic checklist body\n')
        self.parent = self.commit(self.project, 'Approved project parent')
        app.write_text('# Exact acquired checklist body\n')
        self.acquired = self.commit(self.project, 'Approved acquired commit')
        (self.project / 'README.md').write_text('Approved project startup document.\n')
        self.startup = self.commit(self.project, 'Approved startup commit')
        self.config = {'commit': self.acquired, 'startup_revision': self.startup,
                       'destination': 'https://fixture.ts.net', 'workloads': [owner.CHECKLIST]}
        self.selections = []
        self.use(mock.patch.object(owner, 'protect_directory', side_effect=lambda path: self.protect(path, directory=True)))
        self.use(mock.patch.object(owner.candidate, 'protected_file', side_effect=self.protected_file))
        self.use(mock.patch.object(source, 'trusted_directory', side_effect=lambda path: self.protect(path, directory=True, mode=0o700)))
        self.use(mock.patch.object(source, 'CREDENTIALS', self.path / 'credentials'))
        self.credential = source.CREDENTIALS / source.STANDARD_REPOSITORY
        self.credential.parent.mkdir(mode=0o700, parents=True)
        owner.write_private(self.credential, b'fixture_github_contents_read\n')
        self.invoke = owner.candidate.invoke
        self.use(mock.patch.object(owner.candidate, 'invoke', side_effect=self.fixture_transport))

    def use(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def protect(self, path, *, directory, mode=None):
        # Host ancestors above this tree are unmapped in the user namespace.
        self.assertTrue(path.is_relative_to(self.path))
        self.assertEqual(path.resolve(strict=True), path)
        for component in (path, *(parent for parent in path.parents if parent.is_relative_to(self.path))):
            node = component.lstat()
            self.assertEqual(node.st_uid, 0)
            self.assertFalse(node.st_mode & 0o022)
            if directory or component != path:
                self.assertTrue(stat.S_ISDIR(node.st_mode))
            else:
                self.assertTrue(stat.S_ISREG(node.st_mode) and node.st_nlink == 1)
        if mode is not None:
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), mode)
        return path

    def protected_file(self, path, limit):
        self.protect(path, directory=False)
        return owner.p.read_data(path, limit)

    def fixture_transport(self, argv, end, **kwargs):
        if 'fetch' in argv and argv[-2].startswith('https://github.com/'):
            url = argv[-2]
            remotes = {source.https_origin(REPOSITORY): self.project,
                       source.https_origin(source.STANDARD_REPOSITORY): self.standards}
            self.assertIn(url, remotes)
            self.assertIn('http.followRedirects=false', argv)
            self.assertIn('credential.useHttpPath=true', argv)
            self.assertNotIn('fixture_github_contents_read', ' '.join(argv))
            self.selections.append((url, argv[-1], '--depth=1' in argv))
            argv = list(argv)
            argv[argv.index('protocol.https.allow=always')] = 'protocol.file.allow=always'
            argv[-2] = str(remotes[url])
        return self.invoke(argv, end, **kwargs)

    def git(self, checkout, *arguments):
        return subprocess.check_output(['/usr/bin/git', '-C', str(checkout), *arguments], stderr=subprocess.DEVNULL)

    def repository(self, name):
        path = self.path / name
        path.mkdir(mode=0o700)
        self.git(path, 'init', '--template=')
        return path

    def commit(self, checkout, message):
        self.git(checkout, 'add', '--all')
        self.git(checkout, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-m', message)
        return self.git(checkout, 'rev-parse', 'HEAD').strip().decode()

    def provision(self, *answers):
        responses = iter(answers)
        return source.provision(self.intake, REPOSITORY, owner.CHECKLIST, lambda _: next(responses), lambda _: None)

    def test_attended_source_provisions_exact_commits_and_real_role_bundle(self):
        answers = io.StringIO('\n'.join((REPOSITORY, '1', self.acquired, self.startup, 'yes', '')))
        output = io.StringIO()
        with mock.patch.object(owner.getpass, 'getpass', return_value='fixture'), mock.patch.object(
                owner, 'provider_custody', side_effect=owner.SitePending('provider', 'Billing custody still pending.')):
            owner.setup_site(self.first, answers, output)
        transcript = output.getvalue()
        self.assertIn(self.acquired, transcript)
        self.assertIn(self.startup, transcript)
        self.assertIn(self.standard_pin, transcript)
        self.assertIn('Billing custody still pending.', transcript)
        self.assertNotIn('Synthetic shared input', transcript)
        self.assertEqual(self.selections, [(source.https_origin(REPOSITORY), self.acquired, False),
            (source.https_origin(REPOSITORY), self.startup, True),
            (source.https_origin(source.STANDARD_REPOSITORY), self.standard_pin, True)])
        config, tree, startup_hash = owner.first_source(self.intake, REPOSITORY, owner.CHECKLIST)
        self.assertEqual(config, {key: self.config[key] for key in source.CHECKOUTS.values()})
        self.assertRegex(tree, '^[0-9a-f]{40}$')
        self.assertRegex(startup_hash, '^[0-9a-f]{64}$')
        checkout = self.site / 'repositories' / REPOSITORY / 'acquired'
        bundle = self.path / 'role-input.bundle'
        bundle.write_bytes(owner.fixed_git(checkout, 'bundle', 'create', '-', 'HEAD', cap=owner.candidate.MAX_BUNDLE))
        role = self.repository('role')
        self.git(role, 'fetch', '--no-tags', '--no-recurse-submodules', str(bundle), 'HEAD')
        self.git(role, 'checkout', '--detach', self.acquired)
        self.assertEqual(self.git(role, 'rev-parse', 'HEAD^').strip().decode(), self.parent)
        self.assertEqual(tuple(sorted(path.name for path in (self.site / 'standards').iterdir())), tuple(sorted(controller.SHARED)))
        self.assertTrue(all(stat.S_IMODE((self.site / 'standards' / name).stat().st_mode) == 0o600 for name in controller.SHARED))
        self.assertFalse(self.first.catalogue.exists())
        self.assertTrue(self.provision())
        self.assertEqual(len(self.selections), 3)

    def test_declined_nonexact_or_unavailable_private_source_leaves_no_inputs(self):
        self.assertFalse(self.provision(self.acquired, self.startup, 'no'))
        self.assertFalse(self.site.exists())
        self.assertEqual(self.selections, [])
        with self.assertRaisesRegex(ValueError, 'full 40-character'):
            self.provision('main')
        self.credential.unlink()
        with self.assertRaises(owner.SitePending) as failure:
            self.provision(self.acquired, self.startup, 'yes')
        self.assertIn('standards read credential', failure.exception.observation['message'])
        self.assertFalse((self.site / 'repositories').exists())
        self.assertFalse((self.site / 'standards').exists())
        self.assertEqual(list(self.site.glob(source.STAGE_PREFIX + '*')), [])

    def test_installed_cli_command_accepts_source_in_controlling_terminal(self):
        child, terminal = pty.fork()
        if child == 0:
            try:
                os.environ.pop('SUDO_USER', None)
                sys.argv = ['owner_intake.py', '--setup-site']
                with mock.patch.object(owner, 'Intake', return_value=self.intake), mock.patch.object(
                        owner.getpass, 'getpass', return_value='fixture'), mock.patch.object(
                        owner, 'provider_custody', side_effect=owner.SitePending('provider', 'Billing custody still pending.')):
                    os._exit(owner.main())
            except BaseException:
                traceback.print_exc()
                sys.stderr.flush()
                os._exit(1)
        output = bytearray()
        deadline = time.monotonic() + 10
        finished = False
        try:
            os.write(terminal, '\n'.join((REPOSITORY, '1', self.acquired, '', 'yes', '')).encode())
            while select.select([terminal], [], [], max(0, deadline - time.monotonic()))[0]:
                try:
                    chunk = os.read(terminal, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
                self.assertLess(len(output), 8192)
            else:
                self.fail('Attended source setup exceeded the terminal deadline.')
            finished = True
        finally:
            if not finished:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(child, signal.SIGKILL)
            os.close(terminal)
            _, status = os.waitpid(child, 0)
        transcript = output.decode()
        self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, transcript)
        self.assertIn('Billing custody still pending.', transcript)
        config, _, _ = owner.first_source(self.intake, REPOSITORY, owner.CHECKLIST)
        self.assertEqual(config, {'commit': self.acquired, 'startup_revision': self.acquired})

    def test_exact_approved_retry_repairs_only_missing_leaves(self):
        original_rename = Path.rename

        def interrupted(path, target):
            if Path(target).name == 'startup':
                raise OSError('fixture interrupted before publishing startup')
            return original_rename(path, target)

        with mock.patch.object(Path, 'rename', interrupted), self.assertRaisesRegex(OSError, 'interrupted'):
            self.provision(self.acquired, self.startup, 'yes')
        checkout = self.site / 'repositories' / REPOSITORY / 'acquired'
        original_inode = checkout.lstat().st_ino
        cache = self.site / 'standards'
        lost = next(iter(source.SHARED))
        (cache / lost).unlink()
        retained = next(path for path in cache.iterdir() if path.name != lost)
        retained_inode = retained.lstat().st_ino
        owner.write_private(self.first.catalogue, owner.p.canonical({'schema': 1, 'repositories': {
            REPOSITORY: self.config}, 'slots': ['job-1']}).encode())
        output = io.StringIO()
        source.restore(self.first, io.StringIO('yes\n'), output)
        self.assertIn('exact approved revisions', output.getvalue())
        self.assertEqual(checkout.lstat().st_ino, original_inode)
        self.assertEqual(retained.lstat().st_ino, retained_inode)
        self.assertEqual(self.selections[-2:], [(source.https_origin(REPOSITORY), self.startup, True),
            (source.https_origin(source.STANDARD_REPOSITORY), self.standard_pin, True)])
        (cache / lost).write_bytes(b'altered record for review\n')
        with self.assertRaisesRegex(ValueError, 'Preserve it for review'):
            source.restore(self.first, io.StringIO('yes\n'), io.StringIO())
        self.assertEqual((cache / lost).read_bytes(), b'altered record for review\n')
        self.assertEqual(len(self.selections), 5)

    def test_git_credential_exchange_is_scoped_and_does_not_store(self):
        repository = source.STANDARD_REPOSITORY
        request = f'protocol=https\nhost=github.com\npath={repository}.git\n'.encode()
        output = io.BytesIO()
        source.credential_exchange(repository, 'get', io.BytesIO(request), output)
        self.assertIn(b'username=x-access-token\npassword=', output.getvalue())
        for wrong in (request.replace(b'github.com', b'elsewhere.test'), request.replace(b'https', b'http'),
                      request.replace(b'standards.git', b'other.git'), request + b'host=github.com\n'):
            with self.subTest(scope=wrong), self.assertRaisesRegex(ValueError, 'scope mismatch'):
                source.credential_exchange(repository, 'get', io.BytesIO(wrong), io.BytesIO())
        before = self.credential.read_bytes()
        source.credential_exchange(repository, 'store', io.BytesIO(request + b'password=replacement\n'), io.BytesIO())
        self.assertEqual(self.credential.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
