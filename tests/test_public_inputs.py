import copy
import builtins
import contextlib
import hashlib
import gzip
import io
import json
import os
import shutil
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import public_inputs as inputs


class PublicInputsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        (self.work / 'home').mkdir()

    def git(self, repo, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    def source_repo(self):
        repo = self.root / 'repo'
        repo.mkdir()
        self.git(repo, 'init', '--template=')
        self.git(repo, 'config', 'user.name', 'Public test')
        self.git(repo, 'config', 'user.email', 'test@example.invalid')
        (repo / 'old-only').write_text('historical fixture must not enter payload')
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-m', 'old public test object')
        old = self.git(repo, 'rev-parse', 'HEAD')
        (repo / 'old-only').unlink()
        (repo / 'source.txt').write_text('exact current public source\n')
        self.git(repo, 'add', '-A')
        self.git(repo, 'commit', '-m', 'current public test object')
        self.git(repo, 'config', 'credential.helper', 'TEST-CONFIG-MUST-NOT-COPY')
        (repo / '.git/hooks').mkdir()
        (repo / '.git/hooks/fixture').write_text('TEST-HOOK-MUST-NOT-COPY')
        return repo, self.git(repo, 'rev-parse', 'HEAD'), old

    def test_real_git_transfer_has_exact_shallow_objects_without_config_hooks_or_history(self):
        repo, revision, old = self.source_repo()
        clean = inputs.clean_checkout(repo, revision, self.work / 'clean', self.work)
        self.assertEqual((clean / 'source.txt').read_text(), 'exact current public source\n')
        self.assertFalse((clean / 'old-only').exists())
        self.assertFalse((clean / '.git/hooks').exists())
        self.assertNotIn('TEST-CONFIG', (clean / '.git/config').read_text())
        self.assertEqual(self.git(clean, 'show', revision + ':source.txt'), 'exact current public source')
        self.git(clean, 'fsck', '--full', '--strict')
        missing = subprocess.run(['/usr/bin/git', '-C', str(clean), 'cat-file', '-e', old], capture_output=True)
        self.assertNotEqual(missing.returncode, 0)
        files = inputs.inventory(clean)
        self.assertTrue(any(item['path'].endswith('.pack') for item in files))

    def test_git_symlink_and_changed_head_reject_before_checkout(self):
        repo, revision, old = self.source_repo()
        with self.assertRaisesRegex(ValueError, 'HEAD mismatch'):
            inputs.clean_checkout(repo, old, self.work / 'wrong', self.work)
        (repo / 'link').symlink_to('/etc/passwd')
        self.git(repo, 'add', 'link')
        self.git(repo, 'commit', '-m', 'unsafe source fixture')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            inputs.clean_checkout(repo, self.git(repo, 'rev-parse', 'HEAD'), self.work / 'unsafe', self.work)

    def test_actual_snapshot_hash_length_and_symlink_rejection(self):
        source = self.root / 'public-data'
        source.write_bytes(b'actual bounded public fixture')
        sha = inputs.digest(source)
        inputs.snapshot(source, self.work / 'copy', source.stat().st_size, sha)
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            inputs.snapshot(source, self.work / 'wrong-digest', source.stat().st_size, 'f' * 64)
        with self.assertRaisesRegex(ValueError, 'length'):
            inputs.snapshot(source, self.work / 'wrong-length', 1, sha)
        link = self.root / 'link'
        link.symlink_to(source)
        with self.assertRaises(OSError):
            inputs.snapshot(link, self.work / 'link-copy', source.stat().st_size, sha)

    def test_codex_tar_rejects_extra_link_and_wrong_expansion_before_writing(self):
        for kind in ('extra', 'symlink', 'size'):
            archive = self.root / (kind + '.gz')
            with tarfile.open(archive, 'w:gz') as output:
                member = tarfile.TarInfo('codex-x86_64-unknown-linux-musl')
                member.size = 1
                if kind == 'symlink':
                    member.type, member.linkname = tarfile.SYMTYPE, '/etc/passwd'
                output.addfile(member, None if kind == 'symlink' else io.BytesIO(b'x'))
                if kind == 'extra':
                    output.addfile(tarfile.TarInfo('unexpected'))
            with self.assertRaises(ValueError):
                inputs.extract_codex(archive, self.work / ('binary-' + kind))
            self.assertFalse((self.work / ('binary-' + kind)).exists())
            # Explicit parser-level fixtures bypass only the outer test's pinned
            # transport identity. The production wrapper has no override switch.
            with self.assertRaises(ValueError):
                inputs._parse_codex_archive(archive, self.work / ('parsed-' + kind),
                                            2 if kind == 'size' else 1, hashlib.sha256(b'x').hexdigest())
        valid = self.root / 'valid-parser-fixture.gz'
        with tarfile.open(valid, 'w:gz') as output:
            member = tarfile.TarInfo('codex-x86_64-unknown-linux-musl')
            member.size = 1
            output.addfile(member, io.BytesIO(b'x'))
        inputs._parse_codex_archive(valid, self.work / 'parsed-valid', 1, hashlib.sha256(b'x').hexdigest())
        self.assertEqual((self.work / 'parsed-valid').read_bytes(), b'x')

    def fixture_payload(self):
        tree = self.work / 'tree'
        tree.mkdir()
        config = '[core]\nrepositoryformatversion=0\nbare=false\nfilemode=true\n'
        for repo, revision in (('dev-pair', 'a' * 40), ('distrobox', inputs.DBX_SOURCE)):
            for name, value in (('config', config), ('HEAD', 'ref: refs/heads/public-input\n'),
                                ('shallow', revision + '\n'), ('refs/heads/public-input', revision + '\n')):
                path = tree / repo / '.git' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
        for name in ('inputs.json', 'codex', 'candidate.json', 'Containerfile'):
            path = tree / 'context' / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b'explicit parser fixture, no admissible Codex binary')
        for name in ('codex.sigstore', 'cosign-verification.txt', 'verification-receipt.json'):
            path = tree / 'evidence' / name
            path.parent.mkdir(exist_ok=True)
            path.write_text('parser fixture, not signature evidence')
        files = inputs.inventory(tree)
        payload = self.root / 'payload.gz'
        inputs.write_payload(tree, files, payload)
        record = {'version': 1, 'kind': 'verified-public-maintenance-inputs', 'source_sha': 'a' * 40,
                  'standards_sha': inputs.STANDARDS, 'distrobox_sha': inputs.DBX_SOURCE, 'context_sha256': 'b' * 64,
                  'artifacts': {name: {'url': url, 'bytes': size, 'sha256': sha} for name, (url, size, sha) in inputs.ARTIFACTS.items()},
                  'payload': {'sha256': inputs.digest(payload), 'bytes': payload.stat().st_size}, 'files': files,
                  'verification': inputs.VERIFICATION}
        manifest = self.root / 'manifest.json'
        manifest.write_bytes(inputs.canonical(record))
        return tree, payload, manifest, record

    def test_compressed_transfer_roundtrip_requires_separately_trusted_manifest(self):
        tree, payload, manifest, record = self.fixture_payload()
        with self.assertRaisesRegex(ValueError, 'manifest integrity'):
            inputs.extract(payload, manifest, 'f' * 64, self.root / 'rejected')
        result = inputs.extract(payload, manifest, inputs.digest(manifest), self.root / 'extracted')
        self.assertIn('transport integrity', result['verification'])
        self.assertEqual(inputs.inventory(tree), inputs.inventory(self.root / 'extracted'))
        self.assertFalse((self.root / 'extracted/dev-pair/.git/hooks').exists())

    @contextlib.contextmanager
    def replace_after_open(self, target, replacement):
        real_os_open, real_open = inputs.os.open, builtins.open
        changed = []
        def swap(path):
            if not changed and isinstance(path, (str, os.PathLike)) and pathlib.Path(path) == target:
                os.replace(replacement, target)
                changed.append(True)
        def fd_open(path, *args, **kwargs):
            fd = real_os_open(path, *args, **kwargs)
            swap(path)
            return fd
        def file_open(path, *args, **kwargs):
            result = real_open(path, *args, **kwargs)
            swap(path)
            return result
        with mock.patch.object(inputs.os, 'open', side_effect=fd_open), mock.patch('builtins.open', side_effect=file_open):
            yield changed

    def test_actual_manifest_replacement_after_open_cannot_change_hashed_bytes(self):
        tree, payload, manifest, record = self.fixture_payload()
        trusted = inputs.digest(manifest)
        replacement = self.root / 'replacement.json'
        changed = copy.deepcopy(record)
        changed['source_sha'] = 'c' * 40
        replacement.write_bytes(inputs.canonical(changed))
        with self.replace_after_open(manifest, replacement) as swapped:
            accepted = inputs.read_manifest(manifest, trusted)
        self.assertTrue(swapped)
        self.assertEqual(accepted, record)
        self.assertEqual(json.loads(manifest.read_bytes()), changed)

    def test_actual_payload_replacement_cannot_change_decompressed_snapshot(self):
        tree, payload, manifest, record = self.fixture_payload()
        trusted = inputs.digest(manifest)
        replacement = self.root / 'replacement.gz'
        damaged = bytearray(payload.read_bytes())
        damaged[0] ^= 1
        replacement.write_bytes(damaged)
        with self.replace_after_open(payload, replacement) as swapped:
            inputs.extract(payload, manifest, trusted, self.root / 'captured-output')
        self.assertTrue(swapped)
        self.assertEqual(inputs.inventory(tree), inputs.inventory(self.root / 'captured-output'))
        self.assertEqual(payload.read_bytes(), damaged)

    def test_actual_fifo_device_and_oversize_admission_is_fast_and_bounded(self):
        tree, payload, manifest, record = self.fixture_payload()
        trusted = inputs.digest(manifest)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        oversize = self.root / 'oversize-manifest'
        with open(oversize, 'wb') as stream:
            stream.truncate(inputs.MANIFEST_LIMIT + 1)
        big_payload = self.root / 'oversize-payload'
        with open(big_payload, 'wb') as stream:
            stream.truncate(inputs.PAYLOAD_LIMIT + 1)
        manifest_link = self.root / 'manifest-link'
        manifest_link.symlink_to(manifest)
        payload_link = self.root / 'payload-link'
        payload_link.symlink_to(payload)
        for index, (manifest_input, payload_input) in enumerate(((fifo, payload), (pathlib.Path('/dev/zero'), payload),
                (oversize, payload), (manifest, fifo), (manifest, pathlib.Path('/dev/zero')), (manifest, big_payload),
                (manifest_link, payload), (manifest, payload_link))):
            destination = self.root / ('reject-' + str(index))
            result = subprocess.run([sys.executable, str(ROOT / 'tools/public_inputs.py'), 'extract', '--manifest', str(manifest_input),
                                     '--payload', str(payload_input), '--expected-manifest-sha256', trusted,
                                     '--output', str(destination)], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(destination.exists())
        with mock.patch.object(inputs.os, 'read', side_effect=AssertionError('oversize must reject before read')):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                inputs.capture_regular(oversize, inputs.MANIFEST_LIMIT)

    def test_admission_deadline_interrupts_actual_blocking_read_before_hash(self):
        tree, payload, manifest, record = self.fixture_payload()
        code = ('import sys,time;sys.path.insert(0,sys.argv[1]);import public_inputs as p;'
                'p.EXTRACTION_SECONDS=.1;original=p.os.read;'
                'p.os.read=lambda *a:(time.sleep(5),original(*a))[1]\n'
                'try:p.extract(p.pathlib.Path(sys.argv[2]),p.pathlib.Path(sys.argv[3]),sys.argv[4],p.pathlib.Path(sys.argv[5]))\n'
                'except ValueError as e:\n assert "wall-time" in str(e);print("bounded admission")\n'
                'else:raise AssertionError("deadline did not run during admission")\n')
        result = subprocess.run([sys.executable, '-c', code, str(ROOT / 'tools'), str(payload), str(manifest),
                                 inputs.digest(manifest), str(self.root / 'slow-output')], capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'bounded admission', result.stdout)
        self.assertFalse((self.root / 'slow-output').exists())

    def test_real_git_metadata_passes_shared_manifest_and_extracted_git_reads(self):
        tree, payload, manifest, record = self.fixture_payload()
        repo, revision, _ = self.source_repo()
        shutil.rmtree(tree / 'dev-pair')
        inputs.clean_checkout(repo, revision, tree / 'dev-pair', self.work)
        record['source_sha'] = revision
        record['files'] = inputs.inventory(tree)
        payload.unlink()
        inputs.write_payload(tree, record['files'], payload)
        record['payload'] = {'bytes': payload.stat().st_size, 'sha256': inputs.digest(payload)}
        inputs.validate_manifest(record)
        manifest.write_bytes(inputs.canonical(record))
        inputs.extract(payload, manifest, inputs.digest(manifest), self.root / 'git-roundtrip')
        restored = self.root / 'git-roundtrip/dev-pair'
        self.assertEqual(self.git(restored, 'show', revision + ':source.txt'), 'exact current public source')
        self.git(restored, 'fsck', '--full', '--strict')

    def test_consumer_rejects_unknown_schema_and_unexpected_git_metadata(self):
        tree, payload, manifest, record = self.fixture_payload()
        for key, value in (('version', True), ('version', 2), ('unknown', 'claim')):
            changed = copy.deepcopy(record)
            changed[key] = value
            with self.assertRaises(ValueError):
                inputs.validate_manifest(changed)
        changed = copy.deepcopy(record)
        changed['files'][0]['path'] = 'dev-pair/.git/hooks/post-checkout'
        with self.assertRaisesRegex(ValueError, 'Git metadata'):
            inputs.validate_manifest(changed)

    def test_consumer_rejects_archive_symlink_even_with_updated_transport_hash(self):
        tree, payload, manifest, record = self.fixture_payload()
        with tarfile.open(payload, 'w:gz') as output:
            member = tarfile.TarInfo(record['files'][0]['path'])
            member.type, member.linkname = tarfile.SYMTYPE, '/etc/passwd'
            output.addfile(member)
        record['payload'] = {'bytes': payload.stat().st_size, 'sha256': inputs.digest(payload)}
        manifest.write_bytes(inputs.canonical(record))
        with self.assertRaisesRegex(ValueError, 'nonregular'):
            inputs.extract(payload, manifest, inputs.digest(manifest), self.root / 'link-output')
        self.assertFalse((self.root / 'link-output').exists())

    def test_fixed_signature_identity_and_clean_environment(self):
        argv = inputs.signature_args(pathlib.Path('/verifier'), pathlib.Path('/bundle'), pathlib.Path('/blob'))
        self.assertIn(inputs.CODEX_SOURCE, argv)
        self.assertIn('https://token.actions.githubusercontent.com', argv)
        self.assertIn('openai/codex', argv)
        self.assertFalse(any('insecure' in flag or flag in ('--offline', '--key') for flag in argv))
        with mock.patch.dict(os.environ, {'OPENAI_API_KEY': 'synthetic-test-marker', 'PYTHONPATH': '/unsafe', 'HTTPS_PROXY': 'synthetic-approved-proxy'}):
            env = inputs.environment(self.work / 'home', network=True)
        self.assertNotIn('OPENAI_API_KEY', env)
        self.assertNotIn('PYTHONPATH', env)
        self.assertEqual(env['HTTPS_PROXY'], 'synthetic-approved-proxy')
        self.assertNotIn('HTTPS_PROXY', inputs.environment(self.work / 'home'))

    def test_failed_packaging_keeps_existing_public_receipt_but_not_unpublished_payload(self):
        output = self.root / 'failed'
        output.mkdir()
        retained = output / 'verification'
        retained.mkdir()
        (retained / 'receipt.json').write_text('explicit cleanup fixture, not verification evidence')
        (output / 'maintenance-inputs.tar.gz').write_text('unpublished fixture')
        inputs.cleanup_failed_build(output)
        self.assertTrue((retained / 'receipt.json').is_file())
        self.assertFalse((output / 'maintenance-inputs.tar.gz').exists())
        self.assertEqual(json.loads((output / 'failure.json').read_text())['status'], 'payload-not-published')

    def test_real_command_output_and_timeout_bounds(self):
        with self.assertRaisesRegex(ValueError, 'output limit'):
            inputs.command([sys.executable, '-c', 'import os;os.write(1,b"x"*(2*1024**2))'], self.work)
        marker = self.work / 'descendant'
        code = ('import os,time,pathlib,sys\n'
                'if os.fork()==0:\n time.sleep(1);pathlib.Path(sys.argv[1]).write_text("escaped");os._exit(0)\n'
                'time.sleep(5)\n')
        with self.assertRaisesRegex(ValueError, 'deadline'):
            inputs.command([sys.executable, '-c', code, str(marker)], self.work, timeout=.1)
        time.sleep(1.1)
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
