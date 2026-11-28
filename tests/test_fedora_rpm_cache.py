"""Construction cache identity, staging and image history checks."""
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from test_gptbox import g
import bootstrap


cache = g.fedora_rpm_cache


class CacheTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.wanted = cache.binding('1' * 40, g.candidate.STANDARDS, g.sha(g.PACKAGE_SCRIPT.encode()))
        self.inputs = self.root / 'input'
        self.inputs.mkdir()
        repo = next(iter(cache.REPOSITORIES))
        self.member = repo + '/packages/example-1-1.fc44.x86_64.rpm'
        self.source = self.inputs / self.member
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'synthetic RPM bytes')
        self.archive = self.root / 'cache.tar'

    def capture(self, expected, wanted=None):
        destination = self.root / 'verified'
        destination.mkdir(exist_ok=True)
        return cache.unpack(self.archive, expected, wanted or self.wanted, destination, self.root / 'fedora-key',
                            time.monotonic() + 5)

    def test_exact_manifest_and_file_bytes_then_separate_writable_build_copy(self):
        expected = cache.build_transport(self.inputs, self.archive, self.wanted)
        with patch.object(cache, 'validate_repositories') as verify:
            canonical = self.capture(expected)
        verify.assert_called_once()
        self.assertEqual((canonical / self.member).read_bytes(), self.source.read_bytes())
        self.assertEqual((canonical / self.member).stat().st_mode & 0o777, 0o444)
        work = self.root / 'work'
        work.mkdir()
        mounts = cache.build_mounts(work, canonical, os.getuid(), os.getgid())
        self.assertEqual(mounts, ('--volume', f'{work}/rpm-cache:{cache.ROOT}:rw,Z,nodev,nosuid,noexec',
                                  '--volume', f'{work}/{cache.DROPIN_NAME}:{cache.DROPIN_PATH}:ro,Z,nodev,nosuid,noexec'))
        self.assertNotEqual((work / 'rpm-cache' / self.member).stat().st_ino,
                            (canonical / self.member).stat().st_ino)

    def test_independent_digest_source_recipe_and_file_tamper_fail_before_use(self):
        expected = cache.build_transport(self.inputs, self.archive, self.wanted)
        for digest, binding, message in (('0' * 64, self.wanted, 'separately supplied digest'),
                                         (expected, {**self.wanted, 'source_sha': '2' * 40}, 'source, recipe'),
                                         (expected, {**self.wanted, 'recipe_sha256': '3' * 64}, 'source, recipe')):
            with self.assertRaisesRegex(ValueError, message):
                self.capture(digest, binding)
        data = self.archive.read_bytes().replace(self.source.read_bytes(), b'Z' * len(self.source.read_bytes()))
        self.archive.chmod(0o600)
        self.archive.write_bytes(data)
        with patch.object(cache, 'validate_repositories') as verify, self.assertRaisesRegex(ValueError, 'file digest'):
            self.capture(expected)
        verify.assert_not_called()

    def test_expected_digest_cannot_admit_missing_vendor_metadata(self):
        expected = cache.build_transport(self.inputs, self.archive, self.wanted)
        with patch.object(cache, 'verify_signatures') as verify, self.assertRaisesRegex(ValueError, 'metalink or repomd'):
            self.capture(expected)
        verify.assert_not_called()

    def test_cache_paths_and_symlinks_cannot_enter_oci_history(self):
        def layer(name, link=None):
            content = io.BytesIO()
            with tarfile.open(fileobj=content, mode='w') as stream:
                info = tarfile.TarInfo(name)
                if link is not None:
                    info.type, info.linkname = tarfile.SYMTYPE, link
                    stream.addfile(info)
                else:
                    info.size = 1
                    stream.addfile(info, io.BytesIO(b'a'))
            return content.getvalue()

        clean = layer('usr/lib/dev-pair/gptbox/rpms.txt')
        self.assertEqual(cache.audit_layer(io.BytesIO(clean), len(clean), time.monotonic() + 5),
                         ('sha256:' + hashlib.sha256(clean).hexdigest(), len(clean)))
        for name, link in (('./var/cache/libdnf5/repomd.xml', None), ('usr/share/hidden.rpm', None),
                           (cache.DROPIN_PATH.lstrip('/'), None), ('var/cache/saved', '../cache/libdnf5/repomd.xml')):
            polluted = layer(name, link)
            with self.assertRaisesRegex(ValueError, 'entered OCI history'):
                cache.audit_layer(io.BytesIO(polluted), len(polluted), time.monotonic() + 5)

    def test_initialize_forwards_the_independent_cache_reference(self):
        class ExecRequested(BaseException):
            pass

        digest = '1' * 64
        flags = ['--rpm-cache', str(self.archive), '--expected-rpm-cache-manifest-sha256', digest]
        argv = ['bootstrap.py', 'initialize', '--apply', '--gptbox-context', '/context',
                '--expected-context-sha256', '2' * 64, '--source-sha', '3' * 40,
                '--distrobox-source', '/distrobox', '--bootstrap-source', '192.0.2.0/24', *flags]
        with patch.object(bootstrap.sys, 'argv', argv), patch.object(bootstrap.os, 'execv', side_effect=ExecRequested) as launch:
            with self.assertRaises(ExecRequested):
                bootstrap.main()
        self.assertEqual(launch.call_args.args[1][-4:], flags)
