"""Development producer component checks with a synthetic engine and real OCI bytes."""
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_gptbox import BASE, EXPECTED, RUNTIME, SOURCE, Engine, g
import fedora_input_fixture


class ProducerEngine(Engine):
    def __init__(self):
        super().__init__()
        self.bad_seal = False
        self.bad_archive = False
        self.account_uid = max(os.getuid(), 1000)
        self.sealed_id = None

    def __call__(self, *args, **kwargs):
        if args[:1] == ('/usr/bin/id',):
            return f'{self.account_uid}\n'
        if not args or args[0] != '/usr/bin/systemd-run':
            return super().__call__(*args, **kwargs)
        pos = args.index(self.app.wrapper)
        command = args[pos + 1:]
        operation = command[0]
        if operation == 'start' and '--attach' in command:
            log = super().__call__(*args, **kwargs)
            attestation = json.loads(log.splitlines()[-1])
            attestation['packages_sha256'] = g.sha(b'synthetic package list')
            self.seal = g.image_inputs_bytes(attestation)
            return log.splitlines()[0] + '\n' + json.dumps(attestation)
        if operation == 'commit':
            self.calls.append((args, kwargs))
            assert command[1:3] == ('--pause=false', '--format=oci')
            assert self.containers[command[-1]]['State']['Status'] == 'exited'
            self.make_oci()
            return self.sealed_id
        if operation == 'create' and '--entrypoint=/usr/bin/false' in command:
            self.calls.append((args, kwargs))
            assert command[-1] == 'sha256:' + self.sealed_id
            self.containers[RUNTIME] = {'Id': RUNTIME, 'Image': self.sealed_id,
                'Config': {'Labels': {'dev-pair.context': EXPECTED}},
                'Name': next(part[7:] for part in command if part.startswith('--name=')),
                'State': {'Status': 'configured', 'Running': False}}
            return RUNTIME
        if operation == 'cp':
            self.calls.append((args, kwargs))
            assert command[2].startswith(RUNTIME + ':')
            path = Path(command[-1])
            data = (self.build / 'inputs.json').read_bytes() if path.name == 'inputs.json' else self.seal
            if path.name == 'sealed.json' and self.bad_seal:
                data = data.strip()
            path.write_bytes(data)
            self.own(path)
            return ''
        if operation == 'save' and Path(command[3]).name == g.RELEASE_ARCHIVE:
            self.calls.append((args, kwargs))
            assert command[1:3] == ('--format=oci-archive', '--output')
            assert command[-1] == 'sha256:' + self.sealed_id
            path = Path(command[3])
            with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
                for name, content in self.members.items():
                    if self.bad_archive and name == self.layer_name:
                        content = b'x' + content[1:]
                    entry = tarfile.TarInfo('./' + name)
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
            self.own(path)
            return ''
        return super().__call__(*args, **kwargs)

    def own(self, path):
        if os.getuid() != self.account_uid:
            os.chown(path, self.account_uid, -1)

    def make_oci(self):
        media = 'application/vnd.oci.image.'
        self.members = {'oci-layout': g.image_inputs_bytes({'imageLayoutVersion': '1.0.0'})}

        def blob(kind, data):
            digest = g.sha(data)
            self.members['blobs/sha256/' + digest] = data
            return {'mediaType': media + kind, 'digest': 'sha256:' + digest, 'size': len(data)}

        plain = b'synthetic base layer'
        self.diffs = ['sha256:' + g.sha(plain), 'sha256:' + g.sha(b'synthetic finalizer layer')]
        layers = [blob('layer.v1.tar', plain), blob('layer.v1.tar+gzip', gzip.compress(b'synthetic finalizer layer', mtime=0))]
        self.layer_name = 'blobs/sha256/' + layers[-1]['digest'][7:]
        labels = self.images[BASE]['Labels']
        config = blob('config.v1+json', g.image_inputs_bytes({'architecture': 'amd64', 'os': 'linux',
            'config': {'Labels': labels}, 'rootfs': {'type': 'layers', 'diff_ids': self.diffs}}))
        manifest = blob('manifest.v1+json', g.image_inputs_bytes({'schemaVersion': 2, 'config': config, 'layers': layers}))
        self.members['index.json'] = g.image_inputs_bytes({'schemaVersion': 2, 'manifests': [manifest]})
        self.sealed_id = config['digest'][7:]
        self.images[config['digest']] = {'Id': self.sealed_id, 'Labels': labels, 'Os': 'linux',
                                         'Architecture': 'amd64', 'RootFS': {'Layers': self.diffs}}


class ProducerFixture(g.DevelopmentGptbox):
    def preflight(self):
        return {'fixture': 'no Fedora runtime evidence'}

    def inputs(self, context, expected, upstream, revision):
        return {'role': 'development', 'codex': {'sha256': g.sha((context / 'codex').read_bytes())}}, {
            'distrobox-init': b'synthetic Distrobox init\n', 'distrobox-enter': b'synthetic Distrobox enter\n'}

    def directory(self, name, mode=0o700, owner=None):
        return super().directory(name, mode=mode)


class DevelopmentImageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o755)
        self.engine = ProducerEngine()
        self.app = self.engine.app = ProducerFixture(self.root, self.engine)
        self.context = self.root / 'context'
        self.context.mkdir()
        (self.context / 'codex').write_bytes(b'synthetic Codex')
        self.release = self.app.path(g.DEVELOPMENT_ARTIFACTS + '/' + EXPECTED + '/release')
        native_copy = g.fedora_oci.copy_workspace
        fedora_input_fixture.install(self)
        self.enterContext(patch.object(g.fedora_oci, 'copy_workspace', native_copy))
        self.enterContext(patch.object(g.shutil, 'disk_usage', return_value=SimpleNamespace(free=20 * 1024 ** 3)))

    def assemble(self, retry=False, apply=True):
        return self.app.assemble(self.context, EXPECTED, '/', SOURCE, apply=apply, retry=retry)

    def test_committed_development_graph_exports_a_bound_inner_record_atomically(self):
        self.assertFalse(self.assemble(apply=False)['changes'])
        self.assertFalse(self.release.parent.exists())
        result = self.assemble()
        self.assertFalse(result['job_admission'])
        self.assertFalse(self.engine.containers)
        self.assertFalse(self.app.path(g.STATE + '/gptbox-image.json').exists())
        self.assertFalse(self.app.path('/var/lib/dev-pair/maintenance/images').exists())
        self.assertIn('/image-store', Path(self.app.wrapper).read_text())
        self.assertIn(g.FINAL_HOOK, next(args for args, _ in self.engine.calls if g.FINAL_HOOK in args))
        self.assertEqual(sum('start' in args and '--attach' in args for args, _ in self.engine.calls), 1)
        archive = self.release / g.RELEASE_ARCHIVE
        inner = json.loads((self.release / g.RELEASE_INNER).read_bytes())
        self.assertEqual(inner, {'source_sha': SOURCE, 'image_id': self.engine.sealed_id, 'context_sha256': EXPECTED,
            'inputs_sha256': g.sha((self.engine.build / 'inputs.json').read_bytes()),
            'sealed_sha256': g.sha(self.engine.seal), 'archive_sha256': g.sha(archive.read_bytes()),
            'archive_bytes': archive.stat().st_size, 'diff_ids': self.engine.diffs})
        self.assertEqual(json.loads((self.engine.build / 'inputs.json').read_bytes())['role'], 'development')
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o444)
        self.assertTrue(self.assemble()['reused'])
        archive.chmod(0o644)
        with archive.open('ab') as output:
            output.write(b'x')
        archive.chmod(0o444)
        with self.assertRaises(g.Blocked):
            self.assemble()

    def test_bad_raw_seal_and_corrupt_archive_withhold_publication(self):
        self.engine.bad_seal = True
        with self.assertRaisesRegex(g.Blocked, 'seal bytes differ'):
            self.assemble()
        self.assertFalse(self.release.exists())
        self.assertFalse(self.engine.containers)
        with self.assertRaisesRegex(g.Blocked, 'explicit --retry'):
            self.assemble()
        self.engine.bad_seal = False
        self.engine.bad_archive = True
        with self.assertRaisesRegex(g.Blocked, 'layer blob mismatch'):
            self.assemble(retry=True)
        self.assertFalse(self.release.exists())
        self.assertFalse(self.engine.containers)
        with self.assertRaisesRegex(g.Blocked, 'retry budget exhausted'):
            self.assemble(retry=True)
        self.assertFalse(self.release.with_name('release.pending').exists())

    def test_maintenance_gate_and_development_gate_require_their_own_role(self):
        default = g.Bootstrap(self.root)
        with patch.object(default, 'candidate_tool') as tool:
            tool.return_value._verify_content.return_value = (None, {'role': 'development'})
            with self.assertRaisesRegex(g.Blocked, 'maintenance-role'):
                default.check_gptbox_inputs(self.context, EXPECTED)
            default.check_gptbox_inputs(self.context, EXPECTED, expected_role='development')
            tool.return_value._verify_content.return_value = (None, {'role': 'maintenance'})
            with self.assertRaisesRegex(g.Blocked, 'development-role'):
                default.check_gptbox_inputs(self.context, EXPECTED, expected_role='development')
