import copy
import importlib.util
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('candidate', ROOT / 'tools/candidate.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        subprocess.run([sys.executable, str(ROOT / 'tests/make_fixture.py'),
                        str(self.root / 'fixture')], check=True)
        self.fixture = self.root / 'fixture'
        self.m = json.loads((self.fixture / 'inputs.fixture.json').read_text())
        self.binary = self.fixture / 'codex.fixture'

    def test_identical_inputs_produce_identical_contexts_and_preserve_input(self):
        a = candidate.prepare(self.m, self.binary, self.root / 'a', True)
        b = candidate.prepare(self.m, self.binary, self.root / 'b', True)
        self.assertEqual(a, b)
        self.assertEqual(a['kind'], 'fixture-not-admissible')
        for name in ('codex', 'Containerfile', 'inputs.json', 'candidate.json'):
            self.assertEqual((self.root / 'a' / name).read_bytes(),
                             (self.root / 'b' / name).read_bytes())
        self.assertEqual(self.binary.read_bytes(), (self.root / 'a/codex').read_bytes())

    def test_fixture_not_admitted_without_explicit_fixture_mode(self):
        with self.assertRaisesRegex(ValueError, 'fixture'):
            candidate.prepare(self.m, self.binary, self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_verify_cli_checks_handoff_identity_and_keeps_fixture_blocked(self):
        out = self.root / 'context'
        prepared = candidate.prepare(self.m, self.binary, out, True)
        result = subprocess.run(
            [sys.executable, str(ROOT / 'tools/candidate.py'), 'verify', '--fixture',
             '--context', str(out), '--expected-context-sha256', prepared['context_sha256']],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        verified = json.loads(result.stdout)
        self.assertEqual(verified['context_sha256'], prepared['context_sha256'])
        self.assertEqual(verified['kind'], 'fixture-not-admissible')
        self.assertEqual(verified['runtime'], 'blocked')
        with self.assertRaisesRegex(ValueError, 'record'):
            candidate.verify(out, prepared['context_sha256'])
        with self.assertRaisesRegex(ValueError, 'handoff'):
            candidate.verify(out, '1' * 64, True)

    def test_verify_rejects_each_changed_context_file(self):
        for name in ('codex', 'inputs.json', 'Containerfile', 'candidate.json'):
            with self.subTest(file=name):
                out = self.root / name
                prepared = candidate.prepare(self.m, self.binary, out, True)
                path = out / name
                path.chmod(0o600)
                path.write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    candidate.verify(out, prepared['context_sha256'], True)

    def test_verify_rejects_rehashed_tampering_against_original_handoff(self):
        out = self.root / 'context'
        prepared = candidate.prepare(self.m, self.binary, out, True)
        (out / 'Containerfile').write_bytes(b'FROM malicious\n')
        files = {name: (out / name).read_bytes() for name in prepared['files_sha256']}
        forged = candidate.context_record(files, True)
        (out / 'candidate.json').write_bytes(candidate.canonical(forged))
        with self.assertRaisesRegex(ValueError, 'handoff'):
            candidate.verify(out, prepared['context_sha256'], True)
        # Even a new identity cannot substitute an unsupported build recipe.
        with self.assertRaisesRegex(ValueError, 'recipe'):
            candidate.verify(out, forged['context_sha256'], True)

    def test_verify_rejects_missing_extra_symlink_and_directory_inputs(self):
        for kind in ('missing', 'extra', 'symlink', 'directory', 'root-symlink'):
            with self.subTest(kind=kind):
                out = self.root / kind
                prepared = candidate.prepare(self.m, self.binary, out, True)
                if kind == 'extra':
                    (out / 'unexpected-hook').write_text('untracked input')
                elif kind == 'root-symlink':
                    link = self.root / 'linked-context'
                    link.symlink_to(out, target_is_directory=True)
                    out = link
                else:
                    (out / 'codex').unlink()
                    if kind == 'symlink':
                        (out / 'codex').symlink_to(self.binary)
                    elif kind == 'directory':
                        (out / 'codex').mkdir()
                with self.assertRaises(ValueError):
                    candidate.verify(out, prepared['context_sha256'], True)

    def test_corrupt_binary_rejected_before_writes(self):
        self.binary.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            candidate.prepare(self.m, self.binary, self.root / 'out', True)
        self.assertFalse((self.root / 'out').exists())

    def test_refuses_overwrite_and_symlink_output(self):
        out = self.root / 'out'
        out.mkdir()
        (out / 'keep').write_text('durable')
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            candidate.prepare(self.m, self.binary, out, True)
        self.assertEqual((out / 'keep').read_text(), 'durable')
        link = self.root / 'link'
        link.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            candidate.prepare(self.m, self.binary, link, True)

    def test_missing_floating_unofficial_and_extra_inputs_rejected(self):
        mutations = [lambda m: m.pop('source_sha'),
                     lambda m: m.update(standards_sha='1' * 40),
                     lambda m: m['fedora'].update(image='fedora:latest'),
                     lambda m: m['fedora'].update(image=m['fedora']['image'].replace('fedora:44@', 'fedora:45@')),
                     lambda m: m['fedora'].pop('verification'),
                     lambda m: m['codex'].update(version='1.2.3-alpha.1'),
                     lambda m: m['codex'].update(source='https://example.com/codex'),
                     lambda m: m.update(provider='claudebox'),
                     lambda m: m.update(model='default'),
                     lambda m: m.update(effort=''),
                     lambda m: m.update(host_socket='/run/podman/podman.sock')]
        for mutate in mutations:
            m = copy.deepcopy(self.m)
            mutate(m)
            with self.subTest(m=m), self.assertRaises(ValueError):
                candidate.validate(m, True)

    def test_dangerous_paths_overlaps_and_code_shadowing_rejected(self):
        for path in ('/', '/usr', '/opt/dev-pair', '/run/podman/podman.sock',
                     '/var/lib/dev-pair/jobs/x/../etc',
                     '/var/lib/dev-pair/jobs/fixture/state',
                     '/var/lib/dev-pair/jobs/fixture/state/nested',
                     '/var/lib/dev-pair/jobs/fixture/workspace:rw',
                     '/var/lib/dev-pair/jobs/fixture//workspace'):
            m = copy.deepcopy(self.m)
            m['mounts']['workspace'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                candidate.validate(m, True)
        m = copy.deepcopy(self.m)
        m['mounts']['/usr'] = m['mounts'].pop('workspace')
        with self.assertRaises(ValueError):
            candidate.validate(m, True)

    def test_both_placements_and_exact_resume_identity(self):
        sid = '12345678-1234-1234-1234-123456789abc'
        for role, placement in [('maintenance', 'host -> maintenance gptbox'),
                                ('development', 'host -> DevBox -> development gptbox')]:
            self.m['role'] = role
            p = candidate.plan(self.m, 'agentbox', 'gpt-6.1-sol', 'high', sid, True)
            self.assertEqual(p['placement'], placement)
            self.assertEqual(p['runtime'], 'blocked')
            self.assertEqual(p['provider'], 'gptbox')
            self.assertEqual(p['codex_argv_proposal'][-2:], [sid, '-'])
            self.assertNotIn('--last', p['codex_argv_proposal'])
            self.assertIn('model_reasoning_effort="high"', p['codex_argv_proposal'])
        for selector, model, effort, resume in [('claudebox', 'gpt-6.1-sol', 'high', sid),
                                               ('agentbox', 'gpt-other', 'high', sid),
                                               ('agentbox', 'gpt-6.1-sol', 'medium', sid),
                                               ('agentbox', 'gpt-6.1-sol', 'high', '--last')]:
            with self.assertRaises(ValueError):
                candidate.plan(self.m, selector, model, effort, resume, True)

    def test_cli_launch_fails_closed_without_engines_or_network(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/candidate.py'), 'launch'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('execution denied', result.stderr)
        self.assertEqual(result.stdout, '')


class NonFixturePreparationTests(unittest.TestCase):
    """Exercise fixture=False with real Git and synthetic, UNTRUSTED metadata.

    These inputs test local validation only. The ELF header is not a working
    Codex binary, and no digest/version/evidence here has upstream acceptance.
    All generated objects and contexts remain inside the temporary test root.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='untrusted-offline-preparation-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.repo = self.root / 'synthetic-repo'
        (self.repo / 'tools').mkdir(parents=True)
        self.script = self.repo / 'tools/candidate.py'
        self.source = (ROOT / 'tools/candidate.py').read_bytes()
        self.script.write_bytes(self.source)
        self.git('init', '--quiet')
        self.git('add', 'tools/candidate.py')
        self.git('commit', '--quiet', '-m', 'Synthetic matching source for offline tests')
        matching_sha = self.git('rev-parse', 'HEAD')
        spec = importlib.util.spec_from_file_location('synthetic_candidate', self.script)
        self.subject = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.subject)

        # Only the header fields that prepare checks, not executable software.
        self.binary = self.root / 'UNTRUSTED-synthetic-ELF'
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        data[18:20] = b'\x3e\x00'
        self.binary.write_bytes(data + b'SYNTHETIC OFFLINE INPUT, NOT CODEX')
        digest = hashlib.sha256(b'SYNTHETIC OFFLINE IMAGE ID, NOT FEDORA').hexdigest()
        evidence = 'SYNTHETIC UNTRUSTED OFFLINE INPUT: no upstream acceptance'
        self.m = {
            'kind': 'operator-verified-inputs',
            'source_sha': matching_sha,
            'standards_sha': candidate.STANDARDS,
            'fedora': {'image': 'registry.fedoraproject.org/fedora:44@sha256:' + digest,
                       'verification': evidence},
            'codex': {
                'version': '9876.5.4',
                'source': 'https://github.com/openai/codex/releases/download/rust-v9876.5.4/codex-x86_64-unknown-linux-musl.tar.gz',
                'sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                'verification': evidence},
            'role': 'development', 'provider': 'gptbox',
            'model': 'gpt-6.1-sol', 'effort': 'high',
            'mounts': {name: '/var/lib/dev-pair/jobs/synthetic-offline-test/' + name
                       for name in ('workspace', 'state', 'cache', 'credentials')},
        }

    def git(self, *args):
        return subprocess.run(
            ['git', '-C', str(self.repo), '-c', 'user.name=Offline regression test',
             '-c', 'user.email=offline-test@example.invalid',
             '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', *args],
            check=True, capture_output=True, text=True).stdout.strip()

    def test_matching_real_git_source_prepares_but_never_admits_synthetic_inputs(self):
        out = self.root / 'context'
        result = self.subject.prepare(self.m, self.binary, out)
        self.assertEqual(result['kind'], 'prepared-not-runtime-validated')
        self.assertEqual(result['runtime'], 'blocked')
        self.assertIn('Operator supplies upstream verification', result['provenance'])
        recorded = json.loads((out / 'inputs.json').read_text())
        self.assertEqual(recorded, self.m)
        self.assertIn('SYNTHETIC UNTRUSTED', recorded['fedora']['verification'])
        self.assertEqual((out / 'codex').read_bytes(), self.binary.read_bytes())
        self.assertIn(self.m['source_sha'], (out / 'Containerfile').read_text())
        self.assertEqual(result['files_sha256']['codex'], self.m['codex']['sha256'])
        verified = self.subject.verify(out, result['context_sha256'])
        self.assertEqual(verified['verification'], 'local-context-integrity-only')
        self.assertEqual(verified['runtime'], 'blocked')

    def test_existing_git_source_with_different_implementation_is_rejected(self):
        self.script.write_bytes(self.source + b'\n# Different synthetic source revision\n')
        self.git('add', 'tools/candidate.py')
        self.git('commit', '--quiet', '-m', 'Synthetic mismatched source')
        self.m['source_sha'] = self.git('rev-parse', 'HEAD')
        self.script.write_bytes(self.source)
        out = self.root / 'mismatch-context'
        with self.assertRaisesRegex(ValueError, 'does not identify'):
            self.subject.prepare(self.m, self.binary, out)
        self.assertFalse(out.exists())

    def test_missing_git_object_and_missing_source_file_are_rejected(self):
        out = self.root / 'missing-context'
        self.m['source_sha'] = '0' * 40
        with self.assertRaises(subprocess.CalledProcessError):
            self.subject.prepare(self.m, self.binary, out)
        self.assertFalse(out.exists())
        self.git('rm', '--quiet', 'tools/candidate.py')
        self.git('commit', '--quiet', '-m', 'Synthetic revision without preparation source')
        self.m['source_sha'] = self.git('rev-parse', 'HEAD')
        # git rm may remove the empty tools directory when bytecode is disabled.
        self.script.parent.mkdir(parents=True, exist_ok=True)
        self.script.write_bytes(self.source)
        with self.assertRaises(subprocess.CalledProcessError):
            self.subject.prepare(self.m, self.binary, out)
        self.assertFalse(out.exists())

    def test_matching_hash_wrong_architecture_or_non_elf_is_rejected(self):
        good_header = self.binary.read_bytes()
        for name, data in [('non-ELF', b'UNTRUSTED matching hash, not an ELF'),
                           ('aarch64', good_header[:18] + b'\xb7\x00' + good_header[20:]),
                           ('32-bit', good_header[:4] + b'\x01' + good_header[5:])]:
            with self.subTest(binary=name):
                self.binary.write_bytes(data)
                self.m['codex']['sha256'] = hashlib.sha256(data).hexdigest()
                out = self.root / name
                with self.assertRaisesRegex(ValueError, 'x86_64 ELF'):
                    self.subject.prepare(self.m, self.binary, out)
                self.assertFalse(out.exists())

    def test_non_fixture_placeholder_image_digest_and_version_are_rejected(self):
        for name in ('digest', 'version'):
            m = copy.deepcopy(self.m)
            if name == 'digest':
                m['fedora']['image'] = 'registry.fedoraproject.org/fedora:44@sha256:' + '0' * 64
                error = 'placeholder image digest'
            else:
                m['codex']['version'] = '0.0.0'
                m['codex']['source'] = m['codex']['source'].replace('9876.5.4', '0.0.0')
                error = 'fixture version'
            out = self.root / name
            with self.subTest(placeholder=name), self.assertRaisesRegex(ValueError, error):
                self.subject.prepare(m, self.binary, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
