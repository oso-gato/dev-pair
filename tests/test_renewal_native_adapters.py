"""Exercise protected file and accounting contracts without provider or systemd effects."""
import os
import importlib.util
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
import renewal as r


def adapter(name):
    return runpy.run_path(str(REPO / 'runtime' / 'renewal' / name))


class NativeAdapterTests(unittest.TestCase):
    def test_host_release_requires_immutable_complete_artifact_and_matching_live_config(self):
        source = adapter('host-release')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = r.create_directory(root / 'releases')
            configs = r.create_directory(root / 'configs')
            files = {name: name.encode() for name in source['REQUIRED']}
            manifest = {'schema': 1, 'state_contract': 1, 'source_revision': '1' * 40,
                        'files': {name: r.sha(data) for name, data in files.items()}}
            reference = r.identity(manifest)
            bundle = r.create_directory(store / reference)
            config = {'schema': 1, 'hostname': 'erebus', 'platform': 'fedora-44', 'selinux': 'enforcing',
                      'launch_contract': 1, 'role_launch_seconds': 130}
            cp = configs / (r.identity(config) + '.json')
            cp.write_bytes(r.json_bytes(config))
            cp.chmod(0o444)
            for name, data in {**files, 'manifest.json': r.json_bytes(manifest)}.items():
                node = bundle / name
                node.parent.mkdir(parents=True, exist_ok=True)
                node.write_bytes(data)
                node.chmod(0o444)
            directories = [bundle, *(node for node in bundle.rglob('*') if node.is_dir())]
            try:
                for node in directories:
                    node.chmod(0o555)
                component = {'artifact_sha256': reference, 'config_sha256': r.identity(config),
                             'source_revision': manifest['source_revision']}
                path, loaded = source['release_dirs'](store, component, configs, uid=os.getuid())
                self.assertEqual((path, loaded), (bundle, config))
                observed = {'hostname': 'erebus', 'platform': 'fedora-44', 'selinux': 'enforcing', 'boot_id': str(uuid.uuid4())}
                self.assertEqual(source['measure_release'](component, path, loaded, observed)['launch_root'], str(bundle))
                with self.assertRaisesRegex(ValueError, 'live host profile changed'):
                    source['measure_release'](component, path, loaded, {**observed, 'selinux': 'permissive'})
                member = bundle / sorted(files)[0]
                member.chmod(0o600)
                member.write_bytes(b'changed')
                member.chmod(0o444)
                with self.assertRaisesRegex(ValueError, 'member digest mismatch'):
                    source['release_dirs'](store, component, configs, uid=os.getuid())
            finally:
                for node in directories:
                    node.chmod(0o700)

    def test_continuity_budget_reserves_before_issuance_and_replay_cannot_mint_authority(self):
        module = adapter('continuity-grant')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in ('allowance-journals', 'provider-grants'):
                r.create_directory(root / directory)
            role = {'role': 'maintenance', 'job': 'product', 'model': 'gpt-6.2-astra', 'effort': 'high'}
            turn = {**role, 'scope': 'agent', 'operation': 'turn', 'activation_operation': 'activation',
                    'session_uuid': str(uuid.uuid4()), 'release_sha256': 'a' * 64}
            profile = {'schema': 1, 'authorization_id': 'allowance', 'approved_until': 1000,
                       'total_microusd': 20, 'max_operations': 2, 'permitted': [role], 'scopes': ['agent'],
                       'grant': {'allowance_ref': 'test-allowance', 'allowance_sha256': 'a' * 64,
                                 'spend_microusd': 20, 'seconds': 60,
                                 'max_requests': 1, 'max_request_bytes': 4096, 'max_context_tokens': 1024,
                                 'max_output_tokens': 128, 'input_microusd_per_million': 1,
                                 'output_microusd_per_million': 1, 'observed_models': [role['model']]}}
            account = SimpleNamespace(pw_uid=2300, pw_gid=2300)

            def validate(raw):
                data = r.loads(raw)
                self.assertEqual((data['schema'], data['auth_profile'], data['peer_uid'], data['peer_gid']),
                                 (1, 'openai-api-key', 2300, 2300))

            claim = module['claim']
            path = claim(root, profile, 'b' * 64, turn, account, validate, 1)
            journal = root / 'allowance-journals' / 'allowance.json'
            before = journal.read_bytes()
            grant = path.read_bytes()
            path.unlink()
            self.assertEqual(claim(root, profile, 'b' * 64, turn, account, validate, 1).read_bytes(), grant)
            self.assertEqual(journal.read_bytes(), before)
            with self.assertRaisesRegex(ValueError, 'aggregate continuity allowance exhausted'):
                claim(root, profile, 'c' * 64, {**turn, 'operation': 'second'}, account, validate, 1)
            with self.assertRaisesRegex(ValueError, 'claim identity changed'):
                claim(root, profile, 'b' * 64, {**turn, 'session_uuid': str(uuid.uuid4())}, account, validate, 1)
            modified = {**profile, 'total_microusd': 100}
            with self.assertRaisesRegex(ValueError, 'allowance was changed'):
                claim(root, modified, 'c' * 64, turn, account, validate, 1)

    def test_governed_stable_release_requires_canonical_official_url_and_non_prerelease(self):
        if importlib.util.find_spec('platform_release_protocol') is None:
            protocol = SimpleNamespace(UPSTREAM_RELEASE_LIMIT=1024**2, upstream_release_json=r.loads)
            self.enterContext(patch.dict(sys.modules, {'platform_release_protocol': protocol}))
        check = adapter('agent-candidate')['stable_version']
        release = {'tag_name': 'rust-v0.169.0', 'draft': False, 'prerelease': False,
                   'html_url': 'https://github.com/openai/codex/releases/tag/rust-v0.169.0'}
        self.assertEqual(check(r.json_bytes(release)), '0.169.0')
        for change in ({'prerelease': True}, {'draft': True}, {'tag_name': 'rust-v0.170.0-pre'},
                       {'html_url': 'https://example.invalid/rust-v0.169.0'}):
            with self.assertRaisesRegex(ValueError, 'latest official stable'):
                check(r.json_bytes({**release, **change}))


if __name__ == '__main__':
    unittest.main()
