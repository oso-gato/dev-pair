import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
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
                'GITHUB_SHA': self.source, 'GITHUB_RUN_ID': '12345', 'GITHUB_EVENT_PATH': str(path), **updates}

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

    def test_assembly_binds_three_verified_oci_parts_and_exact_host_to_both_subjects(self):
        revision_path, self.source = self.git_repo()
        parts = self.root / 'parts'
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
        output = self.root / 'subjects'
        with mock.patch.object(fedora_oci, 'DIFF', base):
            platform_sha, runtime_sha = publisher.assemble(parts, output, self.source, 1234, '1' * 64,
                                                            '2' * 64, 'initial', publisher.TRANSPORT_BUDGET)
        platform_raw, platform = publisher.readonly_json(output / 'platform.json')
        self.assertEqual(publisher.digest(platform_raw), platform_sha)
        intake.validate_subject(platform, self.source, 1234)
        _, runtime = publisher.readonly_json(output / 'release.json')
        self.assertEqual(platform['release_sha256'], runtime_sha)
        self.assertEqual(runtime['components']['host']['artifact_sha256'], host_sha)
        for role, image in images.items():
            name = protocol.COMPONENT[role]
            self.assertEqual(runtime['components'][name]['artifact_sha256'], image['image_id'])
            self.assertEqual(platform['transports'][role]['files'][publisher.archive_name(role)]['sha256'], image['archive_sha256'])
        with self.assertRaisesRegex(protocol.Blocked, 'quota approval'):
            publisher.assemble(parts, self.root / 'other', self.source, 1234, '1' * 64, '2' * 64, 'initial',
                               publisher.TRANSPORT_BUDGET - 1)

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
