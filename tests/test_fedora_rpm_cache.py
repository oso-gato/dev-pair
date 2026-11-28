"""Construction cache identity, staging and image history checks."""
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_gptbox import g
import bootstrap
import native_placements
import platform_release_ci


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

    def test_combined_manifest_keeps_exact_inner_and_outer_recipe_identity(self):
        combined = native_placements.tooling_cache_binding('1' * 40)
        expected = cache.build_transport(self.inputs, self.archive, combined)
        with patch.object(cache, 'validate_repositories'):
            self.capture(expected)
        with self.assertRaisesRegex(ValueError, 'source, recipe'):
            self.capture(expected, {**combined, 'outer_recipe_sha256': '1' * 64})

    def test_primary_matches_selected_packages_and_checks_all_xml(self):
        location = '<c:location href="Packages/e/example-1-1.fc44.x86_64.rpm"/>'
        checksum = '<c:checksum type="sha256">' + 'a' * 64 + '</c:checksum>'
        size = '<c:size package="42"/>'
        entry = f'<c:package>{checksum}{size}{location}<r:format>ignored</r:format></c:package>'
        unselected = '<c:package><c:location href="Packages/o/other.rpm"/></c:package>'
        wanted = {'example-1-1.fc44.x86_64.rpm': {'bytes': 42, 'sha256': 'a' * 64}}

        def document(body):
            return ('<c:metadata xmlns:c="http://linux.duke.edu/metadata/common"'
                    ' xmlns:r="http://linux.duke.edu/metadata/rpm">' + body + '</c:metadata>')

        def check(raw):
            cache.primary_packages(io.BytesIO(raw.encode()), wanted, time.monotonic() + 5)

        check(document(unselected + entry))
        for description, raw in (
            ('duplicate selected RPM', document(entry + entry)),
            ('missing selected RPM', document(unselected)),
            ('inconsistent selected checksum', document(entry.replace('a' * 64, 'b' * 64))),
            ('inconsistent selected size', document(entry.replace('package="42"', 'package="41"'))),
            ('inconsistent selected location', document(entry.replace('Packages/e/', 'elsewhere/'))),
            ('duplicate location', document(entry.replace(location, location * 2))),
            ('duplicate selected checksum', document(entry.replace(checksum, checksum * 2))),
            ('missing unselected location', document('<c:package/>' + entry)),
            ('nested package', document(entry.replace('ignored', '<r:package/>'))),
            ('malformed unselected descendant', document(unselected.replace('</c:package>', '<a></c:package>') + entry)),
            ('unbound prefix in unselected descendant', document(unselected.replace('</c:package>', '<p:new/></c:package>') + entry)),
            ('malformed trailer', document(entry) + '<p/>'),
            ('DTD', '<!DOCTYPE c:metadata []>' + document(entry)),
        ):
            with self.subTest(description=description), self.assertRaises(ValueError):
                check(raw)

    def test_primary_refuses_expired_or_oversized_input(self):
        prefix = b'<metadata xmlns="' + cache.PRIMARY_NAMESPACE + b'"><package>'
        record = b'<location href="other.rpm"/><format>' + b'x' * 10000 + b'</format></package></metadata>'
        for end, limit, message in ((time.monotonic() - 1, cache.PRIMARY_WINDOW_LIMIT, 'deadline exceeded'),
                                    (time.monotonic() + 5, 4096, 'oversized Fedora primary metadata record')):
            with patch.object(cache, 'PRIMARY_WINDOW_LIMIT', limit), self.assertRaisesRegex(ValueError, message):
                cache.primary_packages(io.BytesIO(prefix + record), {}, end)

    def test_assembly_handoff_uses_readonly_role_group_modes_under_umask_077(self):
        previous = os.umask(0o077)
        try:
            handoff, dropin = cache.assembly_handoff(self.root / 'assembly', self.inputs, os.getgid())
        finally:
            os.umask(previous)
        for directory in (handoff.parent, handoff, (handoff / self.member).parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o750)
        for file in (handoff / self.member, dropin):
            self.assertEqual(file.stat().st_mode & 0o777, 0o440)
            self.assertEqual((file.stat().st_uid, file.stat().st_gid), (os.getuid(), os.getgid()))

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
        with self.assertRaisesRegex(ValueError, 'nonzero data trails'):
            cache.audit_layer(io.BytesIO(clean + b'concealed content'), len(clean) + 40, time.monotonic() + 5)

    def test_layer_audit_accepts_bounded_pax_paths_and_xattrs(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w', format=tarfile.PAX_FORMAT) as output:
            entry = tarfile.TarInfo('usr/share/' + 'a' * 120)
            entry.pax_headers = {'SCHILY.xattr.user.fixture': 'signed RPM installed file'}
            entry.size = 1
            output.addfile(entry, io.BytesIO(b'x'))
        data = archive.getvalue()
        self.assertEqual(cache.audit_layer(io.BytesIO(data), len(data), time.monotonic() + 5)[1], len(data))
        excessive = tarfile.TarInfo('pax')
        excessive.type, excessive.size = tarfile.XHDTYPE, 65537
        with self.assertRaisesRegex(ValueError, 'oversized OCI archive metadata'):
            cache.audit_layer(io.BytesIO(excessive.tobuf()), 1 << 20, time.monotonic() + 5)

    def test_exact_maintenance_history_save_keeps_generic_base_limit(self):
        app = g.Gptbox(self.root)
        app.uid = str(os.getuid())
        context, image = '4' * 64, '5' * 64
        app.target = g.ROOT + '/' + context
        app.rpm_cache = (self.archive, '6' * 64)
        leaf = app.path(f'{g.ARTIFACTS}/{context}/assembly-cache/image-copy/sealed.oci.tar')
        leaf.parent.mkdir(parents=True)
        emitter = self.root / 'emit.py'
        length = g.fedora_oci.SAVE_FILE_LIMIT + 4096
        emitter.write_text('import sys\nfrom pathlib import Path\n'
                           'with Path(sys.argv[sys.argv.index("--output") + 1]).open("xb") as output:\n'
                           f'    output.seek({length - 1})\n    output.write(b"x")\n')
        engine = (sys.executable, str(emitter))
        args = ('save', '--format=oci-archive', '--output', str(leaf), 'sha256:' + image)
        wrapper = self.root / 'podman'
        wrapper.write_text(g.podman_wrapper_script(g.podman_wrapper_tail(shlex.join(engine))))
        with patch.object(app, 'maintenance_engine', return_value=engine):
            ordinary = subprocess.run(['/bin/sh', str(wrapper), *args], capture_output=True, timeout=6)
            self.assertNotEqual(ordinary.returncode, 0)
            self.assertLessEqual(leaf.stat().st_size, g.fedora_oci.SAVE_FILE_LIMIT)
            leaf.unlink()
            command = app.maintenance_history_save_argv(image, leaf)
            subprocess.run(command, capture_output=True, check=True, timeout=6)
            self.assertEqual(leaf.stat().st_size, length)
            with leaf.open('rb') as output:
                self.assertEqual(output.read(1), b'\0')
            with self.assertRaisesRegex(g.Blocked, 'owned verification workspace'):
                app.maintenance_history_save_argv(image, self.root / 'alternate.tar')

    def test_native_outer_tooling_limits_the_cache_to_its_exact_build(self):
        from contextlib import nullcontext

        request = {'source_sha': '1' * 40, 'rpm_cache_manifest_sha256': '2' * 64}
        workspace = self.root / 'verification'
        workspace.mkdir()
        placement = SimpleNamespace(rpm_cache=self.archive, cache=self.inputs,
                                    verification_work=lambda: nullcontext(workspace),
                                    engine=Mock(return_value=b''), producer=SimpleNamespace(protected=lambda value: value),
                                    account=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
        prefix = ('build', '--quiet', '--pull=never', '--http-proxy=false', '--format=oci')
        with patch.object(cache, 'unpack') as open_cache:
            native_placements.Placement.build_tooling(placement, prefix, self.inputs, request)
        binding = open_cache.call_args.args[2]
        self.assertEqual(binding, native_placements.tooling_cache_binding(request['source_sha']))
        build = placement.engine.call_args.args
        self.assertEqual(build[:len(prefix) + 2], (*prefix, '--network=none', '--no-cache'))
        self.assertIn('--label=dev-pair.rpm-cache=' + request['rpm_cache_manifest_sha256'], build)
        self.assertEqual(placement.engine.call_args.kwargs, {'timeout': 600})

    def test_protected_ci_verifies_with_pinned_fedora_and_no_outbound(self):
        key = self.root / 'vendor-key'
        key.write_bytes(b'fixture material already checked by intake')
        package = '/run/dev-pair-rpm-verification/input/' + self.member
        stdout = (f'{cache.SIGNER} Fedora public key\n{package}:\n'
                  f'    Header OpenPGP signature, key fingerprint: {cache.SIGNER}: OK\n').encode()
        with patch.object(platform_release_ci, 'engine_copy', return_value=stdout) as run:
            platform_release_ci.verify_cache_signatures(object(), self.root, self.inputs, key, [self.source],
                                                       time.monotonic() + 5)
        args = run.call_args.args[2:]
        self.assertEqual(args[:5], ('run', '--rm', '--pull=never', '--network=none', '--http-proxy=false'))
        self.assertIn(g.FEDORA, args)
        self.assertIn('--cap-drop=ALL', args)
        self.assertIn(f'--user={self.root.stat().st_uid}:{self.root.stat().st_gid}', args)
        self.assertIn('--tmpfs=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=16m', args)
        self.assertIn(f'{self.root}:/run/dev-pair-rpm-verification:ro,nosuid,nodev,noexec', args)

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
