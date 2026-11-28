"""Exercise production source selection with real Git and protected files."""
from contextlib import nullcontext, redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase, main, skipUnless
from unittest.mock import Mock, patch

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import bootstrap
import day0_source as source
import owner_day0 as day
import release_setup
from test_destination_release import HEAD, SOURCE, TESTED, TREE
from test_release_setup import BASE, GitHubFixture, MACHINE, PRINCIPAL, REVIEWER, TOKEN


@skipUnless(os.getuid() == 0, 'production source custody needs mapped root')
class ProductionSourceTests(TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/root')))
        self.state, self.native = root / 'state', root / 'bootstrap'
        self.kits = root / 'kits'
        self.kits.mkdir(mode=0o700)
        self.enterContext(patch.multiple(day, STATE=self.state, BOOTSTRAP=str(self.native), OWNER_KITS=self.kits))
        self.repository = root / 'custodian-repo'
        self.git(None, 'init', '-q', '-b', 'main', self.repository)
        (self.repository / 'README.md').write_text('base\n')
        self.git(self.repository, 'add', '.')
        self.git(self.repository, 'commit', '-qm', 'base')
        base = self.git(self.repository, 'rev-parse', 'HEAD').strip().decode()
        self.git(self.repository, 'checkout', '-q', '-b', 'reviewed')
        script = self.repository / 'tools' / 'owner_day0.py'
        script.parent.mkdir()
        script.write_text('# reviewed entry\n')
        launcher = self.repository / 'day0.sh'
        launcher.write_text('#!/bin/sh\n')
        launcher.chmod(0o700)
        self.git(self.repository, 'add', '.')
        self.git(self.repository, 'commit', '-qm', 'reviewed head')
        self.head = self.git(self.repository, 'rev-parse', 'HEAD').strip().decode()
        self.tree = self.git(self.repository, 'rev-parse', 'HEAD^{tree}').strip().decode()
        self.tested = self.git(self.repository, 'commit-tree', self.tree, '-p', base, '-p', self.head,
                               '-m', 'tested synthetic merge').strip().decode()
        self.merge = self.git(self.repository, 'commit-tree', self.tree, '-p', base, '-p', self.head,
                              '-m', 'protected production merge').strip().decode()
        self.git(self.repository, 'update-ref', 'refs/heads/main', self.merge)
        self.seed = self.make_checkout(self.head)
        self.entry = day.DayZero(self.seed, bootstrap.Bootstrap())
        self.entry.original = Mock(return_value={'host': 'fixture', 'machine_id': MACHINE})
        self.entry.ensure_git = Mock()
        self.entry.app.destination_identity = Mock(return_value={'machine_id': MACHINE})
        self.custody = root / 'custody.json'
        self.raw = self.custodian_handoff()
        self.write_grant(self.raw)
        self.authority = self.state / source.SOURCE_NAME
        self.target = source.production_checkout(self.kits, self.merge)
        self.remote_reads = []
        original = source.git

        def boundary(repo, *args, timeout=15):
            if source.REMOTE in args:
                self.remote_reads.append(args)
                args = tuple(str(self.repository) if arg == source.REMOTE else arg for arg in args)
                return self.git(repo, *args)
            return original(repo, *args, timeout=timeout)

        self.enterContext(patch.object(source, 'git', side_effect=boundary))

    @staticmethod
    def git(repo, *argv):
        prefix = ('-C', str(repo)) if repo is not None else ()
        return subprocess.check_output(['/usr/bin/git', '-c', 'user.name=Scoped fixture',
                                        '-c', 'user.email=fixture@example.invalid', *prefix, *argv],
                                       env=source.GIT_ENV, cwd='/', stderr=subprocess.DEVNULL, timeout=30)

    def make_checkout(self, revision):
        repo = source.production_checkout(self.kits, revision)
        repo.parent.mkdir(mode=0o700)
        self.git(None, 'clone', '-q', '--no-hardlinks', self.repository, repo)
        self.git(repo, 'checkout', '-q', '--detach', revision)
        (repo.parent / 'SOURCE').write_text(revision + '\n')
        return repo

    def custodian_handoff(self):
        service = GitHubFixture()
        replacements = {SOURCE: self.merge, HEAD: self.head, TREE: self.tree, TESTED: self.tested}

        def change(value):
            if isinstance(value, str):
                for original, replacement in replacements.items():
                    value = value.replace(original, replacement)
                return value
            if isinstance(value, list):
                return [change(item) for item in value]
            if isinstance(value, dict):
                return {change(key): change(item) for key, item in value.items()}
            return value

        service.values = change(service.values)
        with patch.object(release_setup, 'Commands', return_value=service):
            return release_setup.prepare(self.merge, MACHINE, [REVIEWER['login']], 123, 77, BASE,
                                         PRINCIPAL['login'], TOKEN)

    def write_grant(self, raw):
        self.custody.write_bytes(raw)
        self.custody.chmod(0o600)

    def choose(self, *, digest=None, entry=None):
        signed = release_setup.fingerprint(self.custody.read_bytes()) if digest is None else digest
        with patch.object(day, 'answer', side_effect=[str(self.custody), signed]), redirect_stdout(io.StringIO()):
            return (entry or self.entry).production_entry(None, object())

    def test_unreviewed_seed_waits_without_starting_managed_setup(self):
        with (patch.object(day, 'DayZero', return_value=self.entry),
              patch.object(sys, 'argv', ['day0.sh', 'start']), patch.object(day, 'answer', return_value=''),
              patch.object(day, 'tty_open', return_value=nullcontext(object())),
              patch.object(self.entry, 'start') as start, redirect_stdout(io.StringIO()) as console):
            self.assertEqual(day.main(), 0)
        self.assertIn('waiting for the independently approved release handoff', console.getvalue())
        start.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertFalse(self.target.exists())
        self.entry.ensure_git.assert_not_called()
        self.assertEqual(self.remote_reads, [])

    def test_reviewed_seed_selects_one_distinct_exact_merge_and_routes_all_commands(self):
        self.assertNotEqual(self.merge, self.head)
        self.assertEqual(self.choose(), (self.target, self.merge))
        self.assertEqual(self.authority.read_bytes(), self.raw)
        self.assertEqual(self.git(self.target, 'rev-parse', 'HEAD'), (self.merge + '\n').encode())
        self.assertEqual(self.git(self.seed, 'rev-parse', 'HEAD'), (self.head + '\n').encode())
        fetches = [args for args in self.remote_reads if args[0] == 'fetch']
        self.assertEqual(len(fetches), 1)
        self.assertEqual(fetches[0][-2:], (source.REMOTE, self.merge))
        self.git(self.repository, 'update-ref', 'refs/heads/main', self.head)
        self.custody.unlink()
        self.assertEqual(self.entry.production_entry(None), (self.target, self.merge))
        for stage, option in (('status', None), ('resume', '--confirm-recovery'), ('access-request', '--workloads')):
            suffix = [option] if option else []
            with (patch.object(day, 'DayZero', return_value=self.entry),
                  patch.object(sys, 'argv', ['day0.sh', stage, '--source-sha', self.head, *suffix]),
                  patch.object(day, 'tty_open', return_value=nullcontext(object())),
                  patch.object(day.os, 'chdir') as cd,
                  patch.object(day.os, 'execv', side_effect=SystemExit) as route, self.assertRaises(SystemExit)):
                day.main()
            cd.assert_called_once_with(self.target)
            self.assertEqual(route.call_args.args[1], ['/usr/bin/python3', '-EBs', str(self.target / 'tools/owner_day0.py'),
                                                       stage, '--source-sha', self.merge, *suffix])
        self.assertEqual(len(self.remote_reads), 3)

    def test_machine_digest_review_head_modes_and_tree_hold_before_selection(self):
        with self.assertRaisesRegex(bootstrap.Blocked, 'fingerprint'):
            self.choose(digest='0' * 64)
        self.entry.original.return_value['machine_id'] = 'f' * 32
        with self.assertRaisesRegex(bootstrap.Blocked, 'machine or source'):
            self.choose()
        self.entry.original.return_value['machine_id'] = MACHINE
        same_tree = day.DayZero(self.make_checkout(self.tested), self.entry.app)
        same_tree.original = self.entry.original
        with self.assertRaisesRegex(bootstrap.Blocked, 'neither the independently reviewed head'):
            self.choose(entry=same_tree)
        for field, value in (('repository', 'elsewhere/other'), ('review', {'source_tree': 'f' * 40})):
            grant = release_setup.decode(self.raw, self.merge, MACHINE)
            grant[field] = {**grant[field], **value} if isinstance(value, dict) else value
            self.write_grant(release_setup.encode(grant))
            with self.assertRaises(bootstrap.Blocked):
                self.choose()
        self.write_grant(self.raw)
        (self.seed / 'day0.sh').chmod(0o600)
        with self.assertRaisesRegex(bootstrap.Blocked, 'local changes|executable mode'):
            self.choose()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.authority.exists())
        self.assertEqual(self.remote_reads, [])

    def test_moved_main_or_interrupted_authority_publish_cannot_rebind(self):
        self.git(self.repository, 'update-ref', 'refs/heads/main', self.head)
        with self.assertRaisesRegex(bootstrap.Blocked, 'main has moved'):
            self.choose()
        self.assertFalse(self.target.exists())
        self.git(self.repository, 'update-ref', 'refs/heads/main', self.merge)
        with self.entry.owner_lock(), self.assertRaises(BlockingIOError):
            self.choose()
        self.assertFalse(self.authority.exists())
        with patch.object(release_setup, 'private_publish', side_effect=OSError('durability interruption')):
            with self.assertRaisesRegex(OSError, 'durability interruption'):
                self.choose()
        self.assertTrue(self.target.is_dir())
        self.assertFalse(self.authority.exists())
        self.assertEqual(self.choose(), (self.target, self.merge))
        self.assertEqual(len([args for args in self.remote_reads if args[0] == 'fetch']), 1)

    def test_preexisting_divergent_target_is_preserved_and_post_selection_changes_hold(self):
        checkout = self.make_checkout(self.merge)
        file = checkout / 'README.md'
        file.write_text('operator data stays here\n')
        with self.assertRaisesRegex(bootstrap.Blocked, 'local changes'):
            self.choose()
        self.assertEqual(file.read_text(), 'operator data stays here\n')
        self.assertFalse(self.authority.exists())
        self.git(checkout, 'checkout', '--', file.name)
        self.assertEqual(self.choose(), (checkout, self.merge))
        file.write_text('unexpected change\n')
        with self.assertRaisesRegex(bootstrap.Blocked, 'local changes'):
            self.entry.production_entry(None)
        self.assertEqual(self.authority.read_bytes(), self.raw)

    def test_exact_merge_can_enter_directly_and_retained_trust_is_reused(self):
        checkout = self.make_checkout(self.merge)
        direct = day.DayZero(checkout, self.entry.app)
        direct.ensure_git, direct.original = self.entry.ensure_git, self.entry.original
        self.assertEqual(self.choose(entry=direct), (checkout, self.merge))
        self.assertFalse(any(args[0] == 'fetch' for args in self.remote_reads))
        direct.call = Mock(side_effect=[{'phase': 'pending', 'prerequisite': 'release-trust'}, {}, {'phase': 'ready'}])
        with patch.object(day, 'answer', side_effect=AssertionError('the handoff was requested again')):
            self.assertEqual(direct.commission_apply(self.merge, object()), {'phase': 'ready'})
        self.assertEqual(direct.call.call_args_list[1].args,
                         ('release_setup.py', 'install', '--source-sha', self.merge, '--handoff', self.authority,
                          '--sha256', release_setup.fingerprint(self.raw)))

    def test_historical_progress_stays_on_its_original_source_and_draft_is_explicit(self):
        self.assertEqual(self.entry.production_entry(self.head, draft=True), (self.seed, self.head))
        self.native.mkdir(mode=0o700)
        (self.native / 'initialize.json').touch()
        with self.assertRaisesRegex(bootstrap.Blocked, 'original pinned checkout'):
            self.choose()
        with self.entry.owner_lock():
            day.save(self.entry.app, self.state / 'progress.json',
                     {'schema': 1, 'source_sha': '11fbe9e0e0ff911fce13e33527c55020958a50a7', 'machine_id': MACHINE})
        previous = (self.state / 'progress.json').read_bytes()
        with patch.object(day, 'answer', side_effect=AssertionError('historical progress prompted for a new source')):
            self.assertEqual(self.entry.production_entry(self.head, object()), (self.seed, self.head))
        self.assertEqual((self.state / 'progress.json').read_bytes(), previous)
        self.assertFalse(self.authority.exists())
        self.assertEqual(self.remote_reads, [])


if __name__ == '__main__':
    main()
