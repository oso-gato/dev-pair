"""Exercise the checklist builder's protected transfer and input reuse."""

from contextlib import ExitStack
import fcntl
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checklist_build_storage as storage
import checklist_candidate as candidate
import job_protocol as p

MIB = 1024 ** 2
REVISION = 'a' * 40
UNIX_ROOT = os.getuid() == os.getgid() == 0


class StreamingTests(unittest.TestCase):
    def test_bounded_output_and_read_only_input_use_the_real_process_runner(self):
        code = 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'
        payload = b'archive-stream' * 800
        end = time.monotonic() + 10
        with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as outgoing:
            incoming.write(payload)
            incoming.seek(0)
            self.assertEqual(candidate.invoke([sys.executable, '-c', code], end, stdin=incoming,
                                              stdout=outgoing, cap=len(payload)), b'')
            outgoing.seek(0)
            self.assertEqual(outgoing.read(), payload)
            incoming.seek(0)
            outgoing.seek(0)
            with self.assertRaisesRegex(ValueError, 'output exceeds its limit'):
                candidate.invoke([sys.executable, '-c', code], end, stdin=incoming, stdout=outgoing, cap=1)


@unittest.skipUnless(UNIX_ROOT, 'root custody fixture requires a mapped root namespace')
class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/tmp')))
        self.control = self.root / 'control'
        self.volume = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.control.mkdir(mode=0o700)
        self.spool = storage.Spool(self.control, self.volume, self.volume.stat().st_dev, MIB)
        self.archive = self.spool.path / storage.ARCHIVE
        self.source = self.volume / 'durable-source'
        self.source.write_bytes(b'user edit')
        self.rollback = self.volume / 'rollback-proof'
        self.rollback.write_bytes(b'prior artifact')

    def leave_interrupted(self):
        pid = os.fork()
        if pid == 0:
            try:
                with self.spool.locked(create=True) as fd, self.spool.transfer(fd, 'job-a', REVISION) as staged:
                    staged[1].write(b'x' * (512 * 1024))
                    staged[1].flush()
                    os.fsync(staged[1].fileno())
                    os._exit(73)
            except BaseException:
                os._exit(74)
        self.assertEqual(os.waitpid(pid, 0)[1], 73 << 8)
        self.assertTrue(self.archive.exists())

    def test_completed_and_interrupted_transfer_keep_work_and_previous_artifact(self):
        self.leave_interrupted()
        with self.spool.locked(create=False) as fd:
            before = storage.free_space(fd)
            reserved_at = self.spool.record(fd)['reserved_at']
            self.assertEqual(self.spool.reclaim(fd, now=reserved_at + storage.IDLE_SECONDS - 1)['event'],
                             'retained')
            with self.assertRaises(BlockingIOError), self.spool.locked(create=False):
                self.fail('concurrent cleanup obtained the active lock')
            with self.spool.transfer(fd, 'job-b', 'b' * 40) as (archive, stream, observed):
                recovery = observed['before_build']
                self.assertEqual(recovery['job'], 'job-a')
                self.assertGreaterEqual(recovery['after']['bytes'] - before['bytes'], 512 * 1024)
                self.assertEqual(recovery['after']['inodes'], before['inodes'] + 1)
                stream.write(b'new verified transfer')
                stream.flush()
                self.assertEqual(archive.read_bytes(), b'new verified transfer')
            self.assertEqual(observed['completion']['event'], 'reclaimed')
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.spool.lease.exists())
        self.assertEqual(self.source.read_bytes(), b'user edit')
        self.assertEqual(self.rollback.read_bytes(), b'prior artifact')

    def test_idle_cleanup_rejects_ambiguous_file_then_reclaims_exact_archive(self):
        self.leave_interrupted()
        foreign = self.spool.path / 'foreign'
        foreign.symlink_to(self.source)
        with self.spool.locked(create=False) as fd:
            when = self.spool.record(fd)['reserved_at'] + storage.IDLE_SECONDS
            with self.assertRaisesRegex(ValueError, 'foreign'):
                self.spool.reclaim(fd, now=when)
            self.assertTrue(self.archive.exists())
            self.assertTrue(foreign.is_symlink())
            foreign.unlink()
            self.assertEqual(self.spool.reclaim(fd, now=when)['event'], 'reclaimed')
            self.assertEqual(self.spool.reclaim(fd, now=when)['event'], 'empty')
        self.assertEqual(self.source.read_bytes(), b'user edit')

    def test_insufficient_bytes_or_inodes_create_no_transfer(self):
        with self.spool.locked(create=True) as fd:
            before = storage.free_space(fd)
            with patch.object(storage, 'INODE_HEADROOM', before['inodes'] + 1):
                with self.assertRaises(storage.StoragePressure), self.spool.transfer(fd, 'job-a', REVISION):
                    self.fail('transfer started with insufficient available inodes')
            with patch.object(storage, 'IMAGE_HEADROOM', before['bytes'] + 1):
                with self.assertRaises(storage.StoragePressure), self.spool.transfer(fd, 'job-a', REVISION):
                    self.fail('transfer started with insufficient available bytes')
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.spool.lease.exists())


@unittest.skipUnless(UNIX_ROOT, 'root custody fixture requires a mapped root namespace')
class NormalBuildTests(unittest.TestCase):
    def test_compatible_base_reuse_changed_source_clean_output_and_preserved_receipt(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as mocks:
            root = Path(temporary)
            volume, receipts, context = (root / part for part in ('validation', 'receipts', 'context'))
            for directory in (volume, receipts, context, volume / 'builder', volume / 'builder/graph',
                              volume / 'builder/tmp', volume / 'image-copy', volume / 'graph'):
                directory.mkdir(mode=0o700)
            context.chmod(0o750)
            source_dir = root / 'development/workspaces/job'
            source_dir.mkdir(parents=True)
            (source_dir / 'uncommitted').write_bytes(b'working tree must survive')
            base, recipe, config = (root / part for part in ('base', 'Containerfile', 'containers.conf'))
            base_digest = 'e' * 64
            base_image = 'localhost/verified/base@sha256:' + base_digest
            base.write_text(p.canonical({'version': 1, 'image': base_image, 'verification_sha256': 'f' * 64}))
            recipe.write_bytes(b'protected recipe')
            config.write_text(f'[engine]\nimage_copy_tmp_dir="{volume / "image-copy"}"\n')
            matcher = r'localhost/[a-z0-9/.-]+@sha256:[0-9a-f]{64}'
            runtime = SimpleNamespace(STORAGE=volume, ACCOUNT='dp-checklist', IMAGE=matcher,
                                      protected=lambda path, file: path)
            account = SimpleNamespace(pw_uid=0, pw_gid=0, pw_dir=str(root))
            active = {}
            calls = []
            base_hits = []
            imported = []

            def image_row(ident, digest, repository, source):
                return p.canonical([{'Architecture': 'amd64', 'Os': 'linux', 'Id': 'sha256:' + ident,
                                     'Digest': 'sha256:' + digest,
                                     'RepoDigests': [repository + '@sha256:' + digest],
                                     'Labels': {'org.opencontainers.image.revision': source}}]).encode()

            def run(argv, end, *, cap, stdin=None, stdout=None):
                # The fake actor receives the exact normal Podman arguments.
                graph, runroot = argv[2], argv[4]
                action, *args = argv[5:]
                calls.append(action)
                if action == 'info':
                    return f'true true {graph} {runroot} {volume / "image-copy"}'.encode()
                if action == 'build':
                    self.assertIn('--pull=never', args)
                    self.assertIn('--network=none', args)
                    self.assertIn('--no-cache', args)
                    source = next(part.split('=', 1)[1] for part in args
                                  if isinstance(part, str) and part.startswith('CHECKLIST_SOURCE='))
                    self.assertEqual((Path(args[-1]) / 'checklist.py').read_bytes(), source.encode())
                    cfg = ('config ' + source).encode()
                    cid = p.sha256(cfg)
                    manifest = p.canonical({'config': {'digest': 'sha256:' + cid, 'size': len(cfg)}}).encode()
                    dig = p.sha256(manifest)
                    index = p.canonical({'schemaVersion': 2, 'manifests': [{
                        'digest': 'sha256:' + dig, 'size': len(manifest),
                        'mediaType': 'application/vnd.oci.image.manifest.v1+json'}]}).encode()
                    destination = io.BytesIO()
                    with tarfile.open(fileobj=destination, mode='w') as archive:
                        for name, raw in (('index.json', index), ('blobs/sha256/' + dig, manifest),
                                          ('blobs/sha256/' + cid, cfg)):
                            entry = tarfile.TarInfo(name)
                            entry.size = len(raw)
                            archive.addfile(entry, io.BytesIO(raw))
                    active.update(archive=destination.getvalue(), row=image_row(cid, dig, 'localhost/dev-pair-checklist', source))
                    return b''
                if action == 'image' and args[-1] == base_image:
                    base_hits.append(base_digest)
                    return image_row('d' * 64, base_digest, 'localhost/verified/base', 'fixed-base')
                if action == 'image':
                    return active['row']
                if action == 'save':
                    self.assertEqual(cap, 4 * MIB)
                    self.assertEqual(os.fstat(stdout.fileno()).st_uid, 0)
                    stdout.write(active['archive'])
                    return b''
                self.assertEqual(action, 'load')
                self.assertEqual(fcntl.fcntl(stdin, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                self.assertEqual(stdin.read(), active['archive'])
                imported.append(p.sha256(active['archive']))
                return b''

            mocks.enter_context(patch.multiple(candidate, ROOT=root, RECEIPTS=receipts, BUILD_INPUTS=context,
                                               BASE=base, RECIPE=recipe, CONTAINERS=config, MAX_ARCHIVE=4 * MIB))
            mocks.enter_context(patch.object(candidate.h, 'host_runtime', return_value=runtime))
            mocks.enter_context(patch.object(candidate, 'checked_storage', return_value=volume.stat().st_dev))
            mocks.enter_context(patch.object(candidate.pwd, 'getpwnam', return_value=account))
            mocks.enter_context(patch.object(candidate, 'checkout_approval', return_value=(b'', {})))
            mocks.enter_context(patch.object(candidate, 'git_runner'))
            mocks.enter_context(patch.object(candidate, 'approved_source',
                                             side_effect=lambda git, work, approval, revision: revision.encode()))
            mocks.enter_context(patch.object(candidate, 'as_role', side_effect=lambda role, *cmd, **kwargs: cmd))
            mocks.enter_context(patch.object(candidate, 'invoke', side_effect=run))
            mocks.enter_context(patch.object(candidate, 'preload', side_effect=lambda path, receipt, *a, **kw: (path, receipt)))
            mocks.enter_context(patch.object(sys, 'stderr', io.StringIO()))
            end = time.monotonic() + 15
            previous, initial = candidate.build('job', 'repo/one', 'b' * 64, REVISION, end)
            current, second = candidate.build('job', 'repo/one', 'b' * 64, 'c' * 40, end)
            self.assertNotEqual(initial['candidate'], second['candidate'])
            self.assertEqual(base_hits, [base_digest, base_digest])
            self.assertEqual(len(set(imported)), 2)
            self.assertEqual(candidate.build('job', 'repo/one', 'b' * 64, 'c' * 40, end), (current, second))
            recipe.write_bytes(b'changed recipe')
            with self.assertRaisesRegex(ValueError, 'checklist build inputs changed'):
                candidate.build('job', 'repo/one', 'b' * 64, REVISION, end)
            self.assertEqual(p.loads(previous.read_bytes()), initial)
            self.assertEqual((source_dir / 'uncommitted').read_bytes(), b'working tree must survive')
            self.assertEqual(calls.count('build'), 2)
            self.assertFalse((volume / '.build-transfer' / storage.ARCHIVE).exists())
            self.assertEqual(sys.stderr.getvalue().count('"input_downloads":0'), 2)


if __name__ == '__main__':
    unittest.main()
