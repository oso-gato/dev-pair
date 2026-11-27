from contextlib import redirect_stdout
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from textwrap import dedent
import tempfile
import time
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import fedora_ci as ci
import fedora_ci_guest as guest
import fedora_oci
import platform_release as publisher
import platform_release_ci as builder
import platform_release_intake as intake
import platform_release_protocol as protocol
import platform_tooling_refresh as refresh


class PlatformReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = 'a' * 40
        self.context = 'b' * 64
        self.nonce = 'c' * 32
        self.end = time.monotonic() + 30

    def for_push(self, **updates):
        path = self.root / 'event.json'
        path.write_bytes(protocol.canonical({'ref': 'refs/heads/main', 'after': self.source, 'deleted': False,
                                             'repository': {'full_name': publisher.REPOSITORY}}))
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': publisher.REPOSITORY, 'GITHUB_EVENT_NAME': 'push',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_SHA': self.source, 'GITHUB_RUN_ID': '12345', 'GITHUB_EVENT_PATH': str(path),
                'GITHUB_WORKFLOW_REF': publisher.REPOSITORY + '/' + builder.PLATFORM_WORKFLOW + '@refs/heads/main',
                **updates}

    def test_native_entry_requires_same_protected_main_push_before_privilege(self):
        env = self.for_push()
        builder.admitted_push(self.source, env)
        for update in ({'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_REF_PROTECTED': 'false'},
                       {'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_REF': 'refs/heads/unreviewed'}):
            with self.assertRaisesRegex(protocol.Blocked, 'exact protected main push'):
                builder.admitted_push(self.source, {**env, **update})
        path = Path(env['GITHUB_EVENT_PATH'])
        value = json.loads(path.read_bytes())
        value['after'] = 'b' * 40
        path.write_bytes(protocol.canonical(value))
        with self.assertRaisesRegex(protocol.Blocked, 'source mismatch'):
            builder.admitted_push(self.source, env)

    def test_ordinary_guest_inputs_stay_closed_and_release_scope_is_nonce_bound(self):
        inputs = {**{key: 'e' * length for key, length in guest.INPUT_LENGTHS.items()}, 'payload_bytes': 1}
        self.assertEqual(guest.validate_inputs(inputs), inputs)
        export = {'nonce': self.nonce, 'writer_sha256': 'a' * 64}
        protected = {**inputs, 'platform_export': export}
        self.assertEqual(guest.validate_inputs(protected), protected)
        with self.assertRaises(ValueError):
            guest.validate_inputs({**inputs, 'platform_export': {**export, 'credentials': 'secret'}})
        budget = guest.INITIALIZE_SECONDS - guest.PLATFORM_EXPORT_SECONDS - guest.PLATFORM_VERIFY_SECONDS
        self.assertLessEqual(180 + guest.GUEST_ADMISSION_SECONDS + budget + guest.INITIALIZE_CLEANUP_SECONDS +
                             guest.GUEST_FINAL_SECONDS + guest.PLATFORM_EXPORT_SECONDS + guest.PLATFORM_VERIFY_SECONDS,
                             ci.VM_SECONDS)

    def test_guest_frame_terminator_digest_and_scope_are_independently_required(self):
        archive = self.root / 'input'
        data = b'public OCI transport fixture'
        archive.write_bytes(data)
        image = {'role': 'development', 'source_sha': self.source, 'context_sha256': self.context,
                 'image_id': 'd' * 64, 'archive_bytes': len(data), 'archive_sha256': publisher.digest(data),
                 'diff_ids': ['sha256:' + 'e' * 64]}
        wanted = {'source_sha': self.source, 'role': 'development', 'context_sha256': self.context,
                  'image_id': image['image_id'], 'nonce': self.nonce}
        frame = {'schema': 1, 'nonce': self.nonce, 'image': image, 'receipt': {}}
        wire = io.BytesIO()
        protocol.send_frame(wire, frame, archive, self.end)
        data_on_wire = wire.getvalue()
        spool = self.root / 'spool'
        spool.write_bytes(data_on_wire)
        out = self.root / 'output'
        self.assertEqual(protocol.receive_frame(spool, out, wanted, self.end), frame)
        self.assertEqual(out.read_bytes(), data)
        with self.assertRaisesRegex(protocol.Blocked, 'exact native result'):
            protocol.receive_frame(spool, self.root / 'wrong', {**wanted, 'nonce': 'f' * 32}, self.end)
        self.assertFalse((self.root / 'wrong').exists())
        for i, mutated in enumerate((data_on_wire + b'X', data_on_wire[:-1], data_on_wire.replace(data, b'X' * len(data)))):
            spool.write_bytes(mutated)
            with self.assertRaises(protocol.Blocked):
                protocol.receive_frame(spool, self.root / f'bad-{i}', wanted, self.end)

    def oci_image(self, directory, role, *, wrong_release_source=False):
        directory.mkdir(parents=True)
        layer = b'test layer bytes'
        diff = 'sha256:' + publisher.digest(layer)
        media = publisher.db.OCI_MIME
        labels = {'org.opencontainers.image.revision': ('f' * 40 if wrong_release_source else self.source),
                  'dev-pair.role': role, 'dev-pair.standards': protocol.STANDARDS,
                  'dev-pair.distrobox': publisher.public_inputs.DBX_SOURCE}
        if role != 'devbox':
            labels.update({'dev-pair.context': self.context, 'dev-pair.codex.version': publisher.CODEX_VERSION,
                           'dev-pair.codex.sha256': publisher.public_inputs.CODEX_SHA})
        layers = [layer, b'exact second layer'] if role == 'devbox' else [layer]
        diffs = ['sha256:' + publisher.digest(value) for value in layers]
        config = protocol.canonical({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': diffs},
                                     'config': {'Labels': labels}})
        desc = lambda value, kind: {'mediaType': media + kind, 'size': len(value), 'digest': 'sha256:' + publisher.digest(value)}
        manifest = protocol.canonical({'schemaVersion': 2, 'config': desc(config, 'config.v1+json'),
                                       'layers': [desc(value, 'layer.v1.tar') for value in layers]})
        index = protocol.canonical({'schemaVersion': 2, 'manifests': [desc(manifest, 'manifest.v1+json')]})
        path = directory / publisher.archive_name(role)
        members = {'index.json': index, 'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
                   **{'blobs/sha256/' + publisher.digest(value): value for value in (config, manifest, *layers)}}
        with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name, value in members.items():
                item = tarfile.TarInfo(name)
                item.size = len(value)
                archive.addfile(item, io.BytesIO(value))
        image = {'role': role, 'source_sha': self.source, 'context_sha256': self.context,
                 'image_id': publisher.digest(config), 'archive_bytes': path.stat().st_size,
                 'archive_sha256': publisher.digest(path.read_bytes()), 'diff_ids': diffs}
        return image, publisher.digest(manifest), diff[7:]

    def test_released_oci_bytes_bind_actual_config_manifest_base_layer_and_labels(self):
        for role in protocol.ROLES:
            directory = self.root / role
            image, expected, base_diff = self.oci_image(directory, role)
            with mock.patch.object(fedora_oci, 'DIFF', base_diff):
                self.assertEqual(publisher.image_archive(directory / publisher.archive_name(role), image, self.end), expected)
            with self.assertRaisesRegex(protocol.Blocked, 'signed Fedora root layer'):
                publisher.image_archive(directory / publisher.archive_name(role), image, self.end)
        directory = self.root / 'wrong'
        image, _, base_diff = self.oci_image(directory, 'development', wrong_release_source=True)
        with mock.patch.object(fedora_oci, 'DIFF', base_diff), self.assertRaisesRegex(protocol.Blocked, 'archived image labels'):
            publisher.image_archive(directory / publisher.archive_name('development'), image, self.end)

    def git_repo(self):
        source = self.root / 'repo'
        source.mkdir()
        command = ['/usr/bin/git', '-C', str(source)]
        env = {'PATH': '/usr/bin:/usr/sbin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        subprocess.run(command + ['init', '-q'], env=env, check=True)
        (source / 'tools').mkdir()
        (source / 'tools' / 'fixture.py').write_text('print("exact source")\n')
        (source / 'runtime').mkdir()
        native = source / 'runtime' / 'unit-command'
        native.write_text('#!/bin/sh\ntrue\n')
        native.chmod(0o755)
        subprocess.run(command + ['add', 'tools', 'runtime'], env=env, check=True)
        subprocess.run(command + ['-c', 'user.name=Test Fixture', '-c', 'user.email=test@example.invalid',
                                  'commit', '-q', '-m', 'isolated test fixture'], env=env, check=True)
        return source, publisher.source_git(source, 'rev-parse', 'HEAD').decode().strip()

    def test_host_bundle_uses_exact_git_bytes_and_preserves_executable_readonly_mode(self):
        source, revision = self.git_repo()
        result = self.root / 'host-output'
        identity = publisher.build_host(source, revision, result)
        unpacked = self.root / 'unpacked'
        unpacked.mkdir()
        self.assertEqual(publisher.validate_host(result, revision, self.end, unpacked), identity)
        self.assertEqual((unpacked / 'runtime/unit-command').stat().st_mode & 0o777, 0o555)
        self.assertEqual((unpacked / 'tools/fixture.py').stat().st_mode & 0o777, 0o444)
        (source / 'tools/fixture.py').write_text('not the committed source')
        with self.assertRaisesRegex(protocol.Blocked, 'exact clean commit'):
            publisher.build_host(source, revision, self.root / 'reject')
        self.assertFalse((self.root / 'reject').exists())

    def test_portable_index_binds_three_verified_oci_parts_and_exact_host(self):
        revision_path, self.source = self.git_repo()
        parts = self.root / 'platform-parts'
        parts.mkdir()
        host = parts / publisher.artifact_name('host', self.source)
        host_sha = publisher.build_host(revision_path, self.source, host)
        imports = {'source': fedora_oci.PROVENANCE, 'imported_config': 'sha256:' + fedora_oci.CONFIG,
                   'imported_manifest': 'sha256:' + fedora_oci.MANIFEST,
                   'conversion': 'source manifest/config retained on load; storage save gzip representation derived and fully rehashed',
                   'saveback': {'manifest_sha256': '3' * 64, 'config_sha256': fedora_oci.CONFIG,
                                'compressed_layer_sha256': '4' * 64, 'diff_id_sha256': fedora_oci.DIFF,
                                'derivation': 'storage export gzip recompression allowed; exact source config bytes and rootfs diff stream required'},
                   'verification': 'Source archive chain plus exported config-byte/rootfs-diff equality and full derived descriptor/blob graph',
                   'failure_recovery': 'Import is nontransactional; unreferenced store layers may remain, no broad prune/removal'}
        base = None
        images = {}
        for role in protocol.ROLES:
            directory = parts / publisher.artifact_name(role, self.source)
            image, _, base = self.oci_image(directory, role)
            images[role] = image
            if role == 'maintenance':
                result = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': self.source,
                          'context_sha256': self.context, 'distrobox_sha': publisher.public_inputs.DBX_SOURCE,
                          'assembled_image_id': image['image_id'], 'boundary_and_version_cycles': 2,
                          'runtime_container_removed': True, 'job_admission': False, 'fedora_base': imports,
                          'runtime_container_id': '4' * 64, 'authentication': 'not verified',
                          'model_access': 'not verified', 'nested_placement': 'not verified',
                          'note': 'Probe-only candidate; no Codex job, credential or model request is admitted.'}
                proof = {'result': result, 'result_sha256': publisher.digest(json.dumps(result, sort_keys=True).encode() + b'\n')}
            elif role == 'development':
                proof = {key: value for key, value in image.items() if key != 'role'}
                proof.update(inputs_sha256='d' * 64, sealed_sha256='e' * 64)
            else:
                proof = {'tooling_image_id': '9' * 64, 'tooling_diff_ids': image['diff_ids'][:1],
                         'tooling_recipe_sha256': '8' * 64, 'signed_base': imports}
            with mock.patch.object(fedora_oci, 'DIFF', base):
                proof_container = proof.get('result', proof)
                if role in ('maintenance', 'devbox'):
                    proof_container['fedora_base' if role == 'maintenance' else 'signed_base']['saveback']['diff_id_sha256'] = base
                    if role == 'maintenance':
                        proof['result_sha256'] = publisher.digest(json.dumps(result, sort_keys=True).encode() + b'\n')
                publisher.write_image_part(directory, image, proof, self.end)
        text = (ROOT / '.github/workflows/platform-release.yml').read_text()
        step = text.split('      - name: Verify all parts and assemble the portable release index\n', 1)[1]
        shell = dedent(step.split('        run: |\n', 1)[1].split('      - uses:', 1)[0])
        shim = self.root / 'fixture-python.py'
        shim.write_text(dedent("""\
            import os
            from pathlib import Path
            import runpy
            import sys

            assert sys.argv[1:3] == ['-B', 'tools/platform_release.py']
            script = Path(sys.argv[2]).resolve()
            sys.path.insert(0, str(script.parent))
            import fedora_oci
            fedora_oci.DIFF = os.environ['FIXTURE_LAYER_DIFF']
            sys.argv = sys.argv[2:]
            runpy.run_path(str(script), run_name='__main__')
        """))
        env = {**os.environ, 'RUNNER_TEMP': str(self.root), 'GITHUB_SHA': self.source, 'GITHUB_RUN_ID': '1234',
               'PREVIOUS': 'initial', 'ARTIFACT_BYTES': str(publisher.TRANSPORT_BUDGET),
               'FIXTURE_LAYER_DIFF': base, 'PYTHON_SHIM': str(shim), 'FIXTURE_PYTHON': sys.executable}
        command = 'python3() { "$FIXTURE_PYTHON" -B "$PYTHON_SHIM" "$@"; }\n' + shell
        published = subprocess.run(['/bin/bash', '-e', '-c', command], cwd=ROOT, env=env,
                                   capture_output=True, text=True, timeout=15)
        self.assertEqual(published.returncode, 0, published.stderr)
        platform_sha = published.stdout.strip()
        output = self.root / ('platform-subjects-' + self.source)
        with mock.patch.object(fedora_oci, 'DIFF', base):
            agent_sha = publisher.assemble(parts, self.root / 'agent', self.source, 5678, platform_sha,
                                           publisher.AGENT_BUDGET, agent=True, base=platform_sha)
        platform_raw, platform = publisher.readonly_json(output / 'platform.json')
        self.assertEqual(publisher.digest(platform_raw), platform_sha)
        protocol.portable_index(platform, self.source, 1234)
        self.assertEqual(platform['components']['host']['bundle_manifest_sha256'], host_sha)
        for role, image in images.items():
            name = protocol.COMPONENT[role]
            self.assertEqual(platform['components'][name]['oci_config_sha256'], image['image_id'])
            self.assertEqual(platform['transports'][role]['files'][publisher.archive_name(role)]['sha256'], image['archive_sha256'])
        agent_raw, agent = publisher.readonly_json(self.root / 'agent/platform.json')
        self.assertEqual(publisher.digest(agent_raw), agent_sha)
        protocol.portable_index(agent, self.source, 5678)
        self.assertEqual(set(agent['components']), {'maintenance-agent', 'development-agent'})
        self.assertEqual(agent['base_platform_sha256'], platform_sha)

        staged = self.root / 'staged'
        staged.mkdir()
        ordinary_json = publisher.readonly_json
        with (mock.patch.object(intake, 'ROOT', staged),
              mock.patch.object(intake, 'protected', side_effect=lambda path, **_: path),
              mock.patch.object(intake, 'file_hash', side_effect=lambda path, maximum, end, **_:
                                protocol.file_hash(path, maximum, end, owner=os.getuid())),
              mock.patch.object(publisher, 'readonly_json', side_effect=lambda path, _owner=None: ordinary_json(path)),
              mock.patch.object(fedora_oci, 'DIFF', base)):
            for identity, raw, value in ((platform_sha, platform_raw, platform), (agent_sha, agent_raw, agent)):
                destination = staged / identity
                destination.mkdir()
                (destination / 'platform.json').write_bytes(raw)
                receipt = {'schema': 2, 'platform_sha256': identity, 'source_sha': self.source,
                           'publisher_run': value['publisher_run'], 'kind': value['kind']}
                receipt_path = destination / 'intake.json'
                receipt_path.write_bytes(protocol.canonical(receipt))
                receipt_path.chmod(0o600)
                for role, transfer in value['transports'].items():
                    shutil.copytree(parts / transfer['name'], destination / role)
                self.assertEqual(intake.previous_release(identity, self.end), value)
                self.assertEqual(intake.retained_index(identity), (destination, value, publisher.digest(receipt_path.read_bytes())))
                receipt_path.write_bytes(protocol.canonical(receipt) + b'\n')
                with self.assertRaisesRegex(protocol.Blocked, 'exact prior trust receipt'):
                    intake.retained_index(identity)
                receipt_path.write_bytes(protocol.canonical(receipt))

        agent['components']['development-agent']['codex_sha256'] = '0' * 64
        with self.assertRaisesRegex(protocol.Blocked, 'different verified tooling'):
            protocol.portable_index(agent, self.source, 5678)
        with self.assertRaisesRegex(protocol.Blocked, 'quota approval'):
            publisher.assemble(parts, self.root / 'other', self.source, 1234, 'initial', publisher.TRANSPORT_BUDGET - 1)

    def test_exact_action_zip_extraction_rejects_paths_modes_and_bombs(self):
        path = self.root / 'artifact.zip'
        output = self.root / 'out'
        output.mkdir()
        name, data = 'platform.json', b'bounded public subject'
        wanted = {name: (publisher.digest(data), len(data))}
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(name, data)
        intake.extract_zip(path, output, wanted, self.end)
        self.assertEqual((output / name).read_bytes(), data)
        for i, (entry, payload) in enumerate(((name, b'a' * 10000), ('../' + name, data), (name + '.arbitrary', data))):
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(entry, payload)
            rejected = self.root / f'rejected-{i}'
            rejected.mkdir()
            with self.assertRaises(protocol.Blocked):
                intake.extract_zip(path, rejected, wanted, self.end)
            self.assertEqual(list(rejected.iterdir()), [])

    def test_transfer_workflow_separates_native_build_from_attestation_and_keeps_pr_path(self):
        text = (ROOT / '.github/workflows/platform-release.yml').read_text()
        publication = text.split('  publish:\n', 1)[1]
        self.assertIn('github.ref_protected', text)
        self.assertIn('branches: [main]', text)
        self.assertIn('id-token: write', publication)
        self.assertNotIn('id-token:', text.split('  publish:\n', 1)[0])
        self.assertNotIn('pull_request', text)
        self.assertNotIn('secrets.', text)
        self.assertEqual(text.count('retention-days: 1'), 3)
        self.assertNotIn('platform_release', (ROOT / '.github/workflows/fedora-vm.yml').read_text())

    def test_latest_stable_gate_checks_real_upstream_release_shape(self):
        raw = {'draft': False, 'prerelease': False, 'tag_name': 'rust-v0.169.0',
               'html_url': 'https://github.com/openai/codex/releases/tag/rust-v0.169.0'}
        self.assertEqual(publisher.stable_version(protocol.canonical(raw)), '0.169.0')
        for field, value in (('draft', 0), ('prerelease', True), ('tag_name', 'rust-v1.0.0-beta.1'), ('html_url', 'https://example.invalid')):
            with self.assertRaises(protocol.Blocked):
                publisher.stable_version(protocol.canonical({**raw, field: value}))

    def test_refresh_admits_only_exact_fixed_schedule_or_dispatch_for_both_agents(self):
        env = self.for_push(GITHUB_EVENT_NAME='schedule',
                            GITHUB_WORKFLOW_REF=publisher.REPOSITORY + '/' + builder.AGENT_WORKFLOW + '@refs/heads/main')
        path = Path(env['GITHUB_EVENT_PATH'])
        path.write_bytes(protocol.canonical({'schedule': builder.AGENT_SCHEDULE}))
        self.assertTrue(builder.admitted_source(self.source, 'maintenance', env))
        self.assertTrue(builder.admitted_source(self.source, 'development', env))
        with self.assertRaisesRegex(protocol.Blocked, 'only maintenance and development'):
            builder.admitted_source(self.source, 'devbox', env)
        path.write_bytes(protocol.canonical({'ref': 'refs/heads/main', 'inputs': {}}))
        env['GITHUB_EVENT_NAME'] = 'workflow_dispatch'
        self.assertTrue(builder.admitted_source(self.source, 'development', env))
        path.write_bytes(protocol.canonical({'ref': 'refs/heads/main', 'inputs': {'alternate': 'command'}}))
        with self.assertRaisesRegex(protocol.Blocked, 'fixed operation'):
            builder.admitted_source(self.source, 'development', env)

    def test_refresh_reuses_only_pinned_bytes_and_rejects_unverified_binary_members(self):
        cache = self.root / 'cache'
        cache.mkdir()
        data = b'checked public artifact bytes'
        digest = publisher.digest(data)
        blob = cache / (digest + '.blob')
        blob.write_bytes(data)
        path = self.root / 'copied'
        opener = mock.Mock()
        record = refresh.acquire(opener, path, ('https://github.com/unused', len(data), digest), self.end, cache)
        self.assertEqual(record, {'sha256': digest, 'bytes': len(data), 'reused': True})
        opener.open.assert_not_called()
        blob.write_bytes(b'x' * len(data))
        with self.assertRaisesRegex(protocol.Blocked, 'cache entry changed'):
            refresh.acquire(opener, self.root / 'bad-copy', ('https://github.com/unused', len(data), digest), self.end, cache)
        archive = self.root / 'tooling.tgz'
        with tarfile.open(archive, 'w:gz') as stream:
            member = tarfile.TarInfo('codex-x86_64-unknown-linux-musl')
            member.size = len(data)
            stream.addfile(member, io.BytesIO(data))
        self.assertEqual(refresh.extract_binary(archive, self.root / 'codex', self.end), (digest, len(data)))
        with tarfile.open(archive, 'w:gz') as stream:
            member = tarfile.TarInfo('../unexpected-file')
            member.size = len(data)
            stream.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(protocol.Blocked, 'unsupported archive member'):
            refresh.extract_binary(archive, self.root / 'no-code', self.end)

    def upstream_metadata(self):
        fixture = ROOT / 'tests/data/platform/codex-rust-v0.169.0-release.json.gz'
        raw = gzip.decompress(fixture.read_bytes())
        self.assertEqual(len(raw), 413671)
        self.assertEqual(publisher.digest(raw), 'b784f8cfb2ae3cad0051c1e4273473810be8ea7153e2659afbe1e8fbfdbd76ea')
        return raw

    def response(self, raw):
        response = io.BytesIO(raw)
        response.status = 200
        response.geturl = lambda: publisher.LATEST
        return response

    def test_real_multi_asset_metadata_is_admitted_by_both_production_readers(self):
        raw = self.upstream_metadata()
        with mock.patch.object(publisher.urllib.request, 'urlopen', return_value=self.response(raw)):
            self.assertEqual(publisher.official_version(), '0.169.0')
        opener = mock.Mock()
        opener.open.return_value = self.response(raw)
        result, tag, version = refresh.latest(opener, self.end)
        self.assertEqual((len(result['assets']), tag, version), (194, 'rust-v0.169.0', '0.169.0'))
        for kind, name in (('archive', 'codex.tar.gz'), ('bundle', 'codex.sigstore')):
            url, size, digest = refresh.selected_asset(result, tag, kind)
            approved = publisher.public_inputs.ARTIFACTS[name]
            self.assertEqual((url, size), approved[:2])
            self.assertIn(digest, (None, approved[2]))
        with self.assertRaisesRegex(protocol.Blocked, 'release metadata exceeds'):
            protocol.json_bytes(raw)
        with mock.patch.object(publisher.urllib.request, 'urlopen',
                               return_value=self.response(b'X' * (protocol.UPSTREAM_RELEASE_LIMIT + 1))):
            with self.assertRaisesRegex(protocol.Blocked, 'official release metadata exceeds'):
                publisher.official_version()

    def test_newer_large_stable_reply_proposes_pins_and_preserves_prior_selection(self):
        raw = self.upstream_metadata().replace(b'rust-v0.169.0', b'rust-v0.170.0')
        resolver = mock.Mock()
        resolver.open.side_effect = lambda *_args, **_kwargs: self.response(raw)
        prior = self.root / 'current-selection'
        prior.write_text('retained exact previous release')
        output = self.root / 'pin-proposal'
        with (
            mock.patch.object(refresh.urllib.request, 'build_opener', return_value=resolver),
            mock.patch.object(refresh.release, 'source_checkout'),
            mock.patch.object(refresh, 'commit_for_tag', return_value='a' * 40),
            mock.patch.object(refresh, 'acquire', return_value={'sha256': '3' * 64, 'bytes': 41, 'reused': False}),
            mock.patch.object(refresh, 'extract_binary', return_value=('4' * 64, 19)),
            mock.patch.object(Path, 'chmod'),
            mock.patch.object(refresh, 'verify_signature', return_value='5' * 64),
        ):
            self.assertFalse(refresh.resolve(output, self.source))
        _, proposal = publisher.readonly_json(output / 'tooling.json')
        self.assertEqual((proposal['tag'], proposal['version'], proposal['approved_pins_match']),
                         ('rust-v0.170.0', '0.170.0', False))
        self.assertEqual(set(item.name for item in output.iterdir()), {'tooling.json'})
        self.assertEqual(prior.read_text(), 'retained exact previous release')

    def test_reports_identify_actual_workflow_trigger_role_limits_and_transfer_policy(self):
        for event, role, workflow in (
            ('pull_request', 'maintenance', '.github/workflows/fedora-vm.yml'),
            ('push', 'maintenance', builder.PLATFORM_WORKFLOW),
            ('push', 'devbox', builder.PLATFORM_WORKFLOW),
            ('schedule', 'development', builder.AGENT_WORKFLOW),
            ('workflow_dispatch', 'development', builder.AGENT_WORKFLOW),
        ):
            with self.subTest(event=event, role=role):
                summary = self.root / 'step-summary'
                summary.unlink(missing_ok=True)
                env = self.for_push(GITHUB_EVENT_NAME=event, GITHUB_STEP_SUMMARY=str(summary),
                                    GITHUB_WORKFLOW_REF=publisher.REPOSITORY + '/' + workflow + '@refs/heads/main')
                export = None if event == 'pull_request' else builder.Export(role, self.root / 'artifact')
                with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(io.StringIO()) as log:
                    probe = ci.Probe(self.source, self.root, role if role != 'devbox' else 'maintenance', release=export)
                    probe.finish_report()
                output = json.loads(log.getvalue().split(' ', 1)[1])
                self.assertEqual((output['workflow'], output['workflow_sha256'], output['scenario']),
                                 (workflow, ci.file_hash(ROOT / workflow), role))
                self.assertEqual(output['trigger']['run_id'], '12345')
                if export is None:
                    self.assertIn('label', output['trigger'])
                    self.assertIn('No artifact/cache uploads', summary.read_text())
                    self.assertEqual(output['limits']['vm_seconds'], ci.VM_SECONDS)
                else:
                    self.assertNotIn('label', output['trigger'])
                    self.assertEqual(output['trigger']['event'], event)
                    self.assertEqual(output['limits']['release_storage_bytes'], builder.EXPORT_VOLUME)
                    self.assertIn('uploads a successful role export', summary.read_text())
                    if role == 'devbox':
                        self.assertNotIn('vm_seconds', output['limits'])
                        self.assertEqual(output['limits']['outer_build_seconds'], builder.OUTER_SECONDS)
                    else:
                        self.assertEqual(output['limits']['vm_seconds'], ci.VM_SECONDS - guest.PLATFORM_VERIFY_SECONDS)
                    if event == 'schedule':
                        self.assertEqual(output['trigger']['schedule'], builder.AGENT_SCHEDULE)

    def test_outer_role_reports_verified_output_but_withholds_success_after_cleanup_failure(self):
        with mock.patch.dict(os.environ, self.for_push(), clear=True):
            probe = ci.Probe(self.source, self.root, release=builder.Export('devbox', self.root / 'output'))
            with (
                mock.patch.object(Path, 'is_file', return_value=True),
                mock.patch.object(probe, 'preflight', side_effect=lambda:
                                  probe.phase('runner-preflight', 'pass', 'local preflight fixture')),
                mock.patch.object(builder, 'build_devbox'),
                mock.patch.object(probe, 'cleanup', side_effect=ci.Blocked('owned cleanup unresolved')),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(builder.execute_devbox(probe), 2)
        report = json.loads(next(line.removeprefix('DP_REPORT ') for line in output.getvalue().splitlines()
                                 if line.startswith('DP_REPORT ')))
        self.assertEqual(report['scenario'], 'devbox')
        self.assertEqual(report['phases']['outer-devbox']['status'], 'pass')
        self.assertEqual(report['phases']['cleanup']['status'], 'fail')
