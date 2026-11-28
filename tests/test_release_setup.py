"""Exercise custody transfer, live release decisions and the initial builder cache."""
from contextlib import nullcontext
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checklist_build_storage as storage
import checklist_candidate as candidate
import commission_host as commission
import release_setup as setup
import release_trust
from bootstrap import Blocked
from test_destination_release import BASE, BASE_INVOCATION, HEAD, SOURCE, PublicationFixture, workflow_content

MACHINE = 'a' * 32
TOKEN = b'github_pat_' + b'x' * 45
PRINCIPAL = {'id': 110, 'login': 'release-read'}
REVIEWER = {'id': 111, 'login': 'independent-reviewer'}


class GitHubFixture:
    def __init__(self):
        fixture = PublicationFixture()
        self.values, self.calls = fixture.values, []
        self.values.update({'actions/artifacts?per_page=1': {'artifacts': []},
                            'user': {**PRINCIPAL, 'type': 'User'},
                            'users/' + REVIEWER['login']: {**REVIEWER, 'type': 'User'}})
        for i, workflow in enumerate(setup.WORKFLOWS, 71):
            self.values['actions/workflows/' + Path(workflow).name] = {'path': workflow, 'state': 'active', 'id': i}
            if workflow == setup.GATE:
                gate_path = next(path for path in self.values if path.startswith('contents/' + workflow))
                self.values[f'contents/{workflow}?ref={SOURCE}'] = self.values[gate_path]
            else:
                self.values[f'contents/{workflow}?ref={SOURCE}'] = workflow_content(workflow, workflow.encode())

    def __call__(self, *argv, timeout):
        self.calls.append(argv)
        self.assert_safe(argv, timeout)
        helper = argv.index(setup.GITHUB)
        args = argv[helper + 1:]
        if args[:2] == ('attestation', 'verify'):
            if args[2] != 'oci://' + BASE['image'] or args[args.index('--source-digest') + 1] != BASE['source']:
                raise AssertionError('base subject or signer changed')
            return json.dumps([{'verificationResult': {'signature': {'certificate': {
                'extensions': {'runInvocationURI': BASE_INVOCATION}}}}}])
        if args[args.index('-X') + 1] != 'GET':
            raise AssertionError('write-capable GitHub request')
        endpoint = args[-1].removeprefix('repos/' + setup.REPOSITORY + '/')
        response = self.values[endpoint]
        return json.dumps([response] if '--slurp' in args else response)

    @staticmethod
    def assert_safe(argv, timeout):
        if argv[:2] != ('/usr/bin/env', '-i') or not 0 < timeout <= 60 or any(TOKEN.decode() in str(arg) for arg in argv):
            raise AssertionError('ambient environment, token argv or unbounded network request')
        config = next(arg.split('=', 1)[1] for arg in argv if arg.startswith('GH_CONFIG_DIR='))
        if (Path(config) / 'hosts.yml').read_bytes() != setup.hosts_document(PRINCIPAL, TOKEN):
            raise AssertionError('GitHub read used different credential bytes')

    def prepare(self):
        with patch.object(setup, 'Commands', return_value=self):
            return setup.prepare(SOURCE, MACHINE, [REVIEWER['login']], 123, 77, BASE, PRINCIPAL['login'], TOKEN)


class ReleaseAuthorityTests(unittest.TestCase):
    def test_derives_exact_independent_authority_from_existing_release_verifier(self):
        hub = GitHubFixture()
        raw = hub.prepare()
        handoff = setup.decode(raw, SOURCE, MACHINE)
        self.assertEqual(handoff['policy']['reviewer_ids'], [REVIEWER['id']])
        self.assertEqual(handoff['policy']['writer_app_id'], 77)
        self.assertEqual(handoff['review']['review_head'], HEAD)
        self.assertEqual(handoff['base_proof']['invocation'], BASE_INVOCATION)
        self.assertEqual(handoff['workflow_ids'][setup.PLATFORM], 72)
        self.assertEqual(handoff['read']['token_sha256'], setup.fingerprint(TOKEN))
        self.assertNotIn(TOKEN, raw)
        self.assertIn('branches/main/protection', ' '.join(' '.join(call) for call in hub.calls))
        self.assertIn('actions/artifacts?per_page=1', ' '.join(' '.join(call) for call in hub.calls))

    def test_rejects_author_review_stale_gate_or_divergent_machine(self):
        for field, value, message in (
                ('pulls/42/reviews?per_page=100', [], 'no eligible independent approval'),
                ('environments/checklist-release/deployment_protection_rules',
                 {'total_count': 1, 'custom_deployment_protection_rules': [{'app': {'id': 41}, 'enabled': True}]},
                 'registry writer gate'),
                ('branches/main', {'protected': True, 'commit': {'sha': '0' * 40}}, 'protected main')):
            with self.subTest(field=field):
                hub = GitHubFixture()
                hub.values[field] = value
                with self.assertRaisesRegex(Blocked, message):
                    hub.prepare()
        raw = GitHubFixture().prepare()
        with self.assertRaisesRegex(Blocked, 'selected machine or source'):
            setup.decode(raw, SOURCE, '0' * 32)


@unittest.skipUnless(os.getuid() == os.getgid() == 0 and Path('/run').stat().st_uid == 0,
                     'requires root-owned fixture ancestry, for example an isolated root container')
class ProtectedHostTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/run')))
        self.handoff, self.authority, self.policy = (self.root / leaf for leaf in ('source', 'authority', 'policy'))
        self.hub = GitHubFixture()
        self.raw = self.hub.prepare()
        self.digest = setup.fingerprint(self.raw)
        setup.write_private(self.handoff, self.raw)
        self.enterContext(patch.object(setup, 'FIRST_TRUST', self.authority))
        self.enterContext(patch.object(setup, 'POLICY', self.policy))
        self.enterContext(patch.object(release_trust, 'POLICY', self.policy))

    def install(self):
        setup.install_handoff(self.handoff, self.digest, SOURCE, MACHINE)

    def test_real_protected_paths_recover_after_handoff_only_and_refuse_changed_custody(self):
        with self.assertRaisesRegex(Blocked, 'fingerprint'):
            setup.install_handoff(self.handoff, '0' * 64, SOURCE, MACHINE)
        self.assertFalse(self.authority.exists() or self.policy.exists())
        child = os.fork()
        if child == 0:
            try:
                with patch.object(setup, 'installed', side_effect=lambda *args, **kwargs: os._exit(73)):
                    self.install()
            except BaseException:
                os._exit(74)
            os._exit(75)
        self.assertEqual(os.waitpid(child, 0)[1], 73 << 8)
        self.assertEqual(self.authority.read_bytes(), self.raw)
        self.assertFalse(self.policy.exists())
        self.handoff.unlink()
        setup.installed(SOURCE, MACHINE, finish=True)
        with patch.object(release_trust.ReleaseTrust, 'api', side_effect=AssertionError('local install called GitHub')):
            trust = release_trust.ReleaseTrust().policy('host')
        self.assertEqual(trust['reviewer_ids'], [111])
        info = self.policy.stat()
        self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777, info.st_nlink), (0, 0, 0o600, 1))
        self.policy.write_bytes(b'conflicting existing authority')
        with self.assertRaisesRegex(Blocked, 'protected release custody differs'):
            setup.installed(SOURCE, MACHINE, finish=True)
        self.assertEqual(self.policy.read_bytes(), b'conflicting existing authority')

    def test_only_custodian_bound_token_is_registered_and_reused(self):
        self.install()
        secret, config = self.root / 'token', self.root / '.config/gh'
        setup.write_private(secret, TOKEN[:-1] + b'z\n')
        with patch.object(setup, 'github_prerequisite', side_effect=AssertionError('unapproved token reached GitHub')):
            with self.assertRaisesRegex(Blocked, 'independently authorized read token'):
                setup.register_read(SOURCE, MACHINE, secret, config=config)
        self.assertFalse(config.exists())
        secret.write_bytes(TOKEN + b'\n')
        with patch.object(setup, 'github_prerequisite'), patch.object(setup, 'Commands', return_value=self.hub):
            setup.register_read(SOURCE, MACHINE, secret, config=config)
        approved = setup.installed(SOURCE, MACHINE)
        custodied = config / 'hosts.yml'
        setup.registered_read(approved, custodied)
        self.assertEqual((custodied.stat().st_mode & 0o777, config.stat().st_mode & 0o777), (0o600, 0o700))
        saved = custodied.stat().st_ino
        with patch.object(setup, 'github_prerequisite'), patch.object(setup, 'Commands', side_effect=AssertionError('repeat registration contacted GitHub')):
            setup.register_read(SOURCE, MACHINE, secret, config=config)
        self.assertEqual(custodied.stat().st_ino, saved)
        custodied.write_bytes(setup.hosts_document(PRINCIPAL, TOKEN[:-1] + b'1'))
        with self.assertRaisesRegex(Blocked, 'authorized read credential'):
            setup.registered_read(approved, custodied)

    def test_genuine_commissioning_pending_reasons_and_normal_retry_from_accepted_handoff(self):
        self.install()
        self.policy.unlink()
        live = object.__new__(commission.Live)
        live.run = lambda *args, **kwargs: self.fail('commissioning pending check touched GitHub')
        live.identity = lambda: {'machine_id': MACHINE}
        config = self.root / 'gh'
        intake = SimpleNamespace(ROOT=self.root / 'intake', GITHUB=str(self.root / 'gh-bin'),
                                 native_env=lambda: {'GH_CONFIG_DIR': str(config)}, TRANSFER_LEASE='lease',
                                 TRANSFER_PREFIX='transfer-', protected=lambda path: path)
        live.installer = SimpleNamespace(intake=intake)
        with self.assertRaisesRegex(commission.Pending, 'release-trust'):
            live.initial_platform(SOURCE)
        self.assertFalse(self.policy.exists())
        with self.assertRaisesRegex(commission.Pending, 'release-read-custody'):
            live.initial_platform(SOURCE, acquire=True)
        self.assertTrue(self.policy.exists())
        config.mkdir(mode=0o700)
        setup.write_private(config / 'hosts.yml', setup.hosts_document(PRINCIPAL, TOKEN))
        gh = Path(intake.GITHUB)
        gh.write_bytes(b'dummy GitHub CLI')
        gh.chmod(0o755)
        intake.acquire_initial = lambda *args: self.fail('status tried to acquire initial publication')
        with patch.object(commission, 'GITHUB_CONFIG', config):
            with self.assertRaisesRegex(commission.Pending, 'initial-full-release-selection'):
                live.initial_platform(SOURCE)

    def builder(self):
        self.install()
        root = self.root / 'validation'
        config = self.root / 'checklist'
        receipts = self.root / 'receipts'
        for path in (root, config, receipts, root / 'image-copy', root / 'graph', root / 'builder',
                     root / 'builder/graph', root / 'builder/tmp'):
            path.mkdir(mode=0o700)
        base = config / 'build-base.json'
        containers = config / 'validation-containers.conf'
        containers.write_text(f'[engine]\nimage_copy_tmp_dir="{root / "image-copy"}"\n')
        runtime = SimpleNamespace(STORAGE=root, ACCOUNT='dp-checklist', dispatch_gate=nullcontext,
                                  IMAGE=re.escape(BASE['image']), protected=lambda path, *, file: release_trust.protect(path, directory=not file))
        loaded = {'image': False, 'fail': False, 'pressure': False, 'calls': [], 'attest': 0}

        def actor(name, *argv, environment):
            self.assertEqual(name, 'dp-checklist')
            self.assertEqual(environment['TMPDIR'], str(root / 'builder/tmp'))
            self.assertEqual(environment['CONTAINERS_CONF'], str(containers))
            return argv

        def invoke(argv, end, *, cap, stdin=None, stdout=None, status=False):
            self.assertGreater(end, time.monotonic())
            graph = root / 'builder/graph'
            runroot = Path('/run/user/0/dev-pair-checklist-builder')
            if argv[0] == '/usr/bin/timeout':
                self.assertEqual(argv[:3], ('/usr/bin/timeout', '--kill-after=5s', '100s'))
                argv = argv[3:]
            self.assertEqual(argv[:5], ('/usr/bin/podman', '--root', graph, '--runroot', runroot))
            action, *args = argv[5:]
            loaded['calls'].append((action, tuple(args)))
            if action == 'info':
                return f'true true {graph} {runroot} {root / "image-copy"}'.encode()
            if action == 'pull':
                self.assertIn('--retry=0', args)
                self.assertIn('--tls-verify=true', args)
                self.assertEqual(args[-1], 'docker://' + BASE['image'])
                self.assertEqual(Path(args[args.index('--authfile') + 1]).read_bytes(), b'{"auths":{}}\n')
                with (receipts / '.build-lifecycle/owner.lock').open('rb') as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(fcntl.fcntl(stdin, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                loaded['image'] = True
                if loaded['fail']:
                    raise InterruptedError('paused after rootless image publication')
                return b''
            if action == 'image' and args[:1] == ['exists']:
                self.assertTrue(status)
                return (0 if loaded['image'] else 1), b''
            if action == 'image' and args[:2] == ['rm', '--no-prune']:
                self.assertEqual(args[-1], BASE['image'])
                loaded['image'] = False
                return b''
            self.assertEqual((action, args), ('image', ['inspect', BASE['image']]))
            if not loaded['image']:
                raise ValueError('image is absent')
            return json.dumps([{'Architecture': 'amd64', 'Os': 'linux', 'Id': 'a' * 64,
                                'Digest': BASE['image'].split('@')[1], 'RepoDigests': [BASE['image']]}]).encode()

        def verified(policy):
            self.assertEqual(policy, BASE)
            loaded['attest'] += 1
            return {'version': 1, 'policy': BASE, 'invocation': BASE_INVOCATION}

        self.enterContext(patch.multiple(candidate, BASE=base, CONTAINERS=containers, RECEIPTS=receipts,
                                         invoke=invoke, as_role=actor))
        self.enterContext(patch.object(candidate.h, 'host_runtime', return_value=runtime))
        self.enterContext(patch.object(candidate, 'checked_storage', return_value=root.stat().st_dev))
        self.enterContext(patch.object(candidate.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=0, pw_gid=0)))
        self.enterContext(patch.object(storage, 'free_space', side_effect=lambda fd: {
            'bytes': 256 if loaded['pressure'] and loaded['image'] else 2 * 1024**3, 'inodes': 65536}))
        trust = release_trust.ReleaseTrust()
        self.enterContext(patch.object(trust, 'verify_base', side_effect=verified))

        def preload(prepare=True):
            return candidate.preloaded_base(runtime, trust, time.monotonic() + 45, prepare=prepare, require_proof=True)
        return base, loaded, preload

    def test_initial_pull_reuses_verified_proof_and_resident_image_after_interruption(self):
        base, loaded, preload = self.builder()
        loaded['fail'] = True
        with self.assertRaises(InterruptedError):
            preload()
        self.assertFalse(base.exists())
        self.assertTrue(base.with_name('build-base-proof.json').exists())
        loaded['fail'] = False
        first = preload()
        self.assertEqual(preload(prepare=False), first)
        self.assertEqual(setup.fingerprint(base.with_name('build-base-proof.json').read_bytes()), first['verification_sha256'])
        self.assertEqual(loaded['attest'], 1)
        self.assertEqual(sum(action == 'pull' for action, _ in loaded['calls']), 1)
        loaded['image'] = False
        with self.assertRaisesRegex(ValueError, 'image is absent'):
            preload(prepare=False)
        self.assertEqual(preload(), first)
        self.assertEqual(sum(action == 'pull' for action, _ in loaded['calls']), 2)

    def test_post_pull_pressure_retires_only_the_exact_owned_image(self):
        base, loaded, preload = self.builder()
        loaded['pressure'] = True
        with self.assertRaises(storage.StoragePressure):
            preload()
        self.assertFalse(base.exists() or loaded['image'])
        self.assertEqual([args[-1] for action, args in loaded['calls'] if action == 'image' and args[0] == 'rm'], [BASE['image']])
        loaded['pressure'] = False
        self.assertEqual(preload()['image'], BASE['image'])
        self.assertEqual(loaded['attest'], 1)

    def test_pressure_preserves_an_exact_image_without_a_pull_intent(self):
        base, loaded, preload = self.builder()
        loaded.update(image=True, pressure=True)
        with self.assertRaises(storage.StoragePressure):
            preload()
        self.assertTrue(loaded['image'])
        self.assertFalse(base.exists() or base.with_name('build-base-pull.json').exists())
        self.assertFalse(any(args[0] == 'rm' for action, args in loaded['calls'] if action == 'image'))


if __name__ == '__main__':
    unittest.main()
