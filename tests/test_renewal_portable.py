"""Resolve protected local fixture records without a native import or remote API."""
import copy
import importlib.util
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import renewal as r
import renewal_site as site


class PortableSiteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for relative in ('renewal', 'renewal/plans', 'renewal/releases', 'renewal/platform-bindings',
                         'renewal/platform-observations', 'renewal/offers', 'renewal/requests',
                         'platform-releases', 'site-configs', 'host-releases', 'host-configs'):
            (self.root / relative).mkdir(mode=0o700)
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.controller = r.Renewal(self.root, None)
        self.resolve = site.Resolver(self.controller, self.root / 'platform-releases', self.root / 'site-configs',
                                     self.root / 'host-releases', self.root / 'host-configs')
        if importlib.util.find_spec('platform_release_protocol') is None:
            # The exact portable parser is supplied by F in combined validation.
            dependency = SimpleNamespace(canonical=self.canonical, portable_index=lambda value, source, run: value)
            self.enterContext(patch.dict(sys.modules, {'platform_release_protocol': dependency}))
        self.config = self.canonical({'verified': 'immutable fixture host profile'})
        self.host_config_sha = r.sha(self.config)
        (self.root / 'host-configs' / (self.host_config_sha + '.json')).write_bytes(self.config)
        self.host = self.canonical({'schema': 1, 'source_revision': 'a'*40, 'state_contract': 1, 'files': {}})
        self.host_sha = r.sha(self.host)
        (self.root / 'host-releases' / self.host_sha).mkdir(mode=0o700)
        (self.root / 'host-releases' / self.host_sha / 'manifest.json').write_bytes(self.host)
        self.geometry = {'schema': 1, 'hostname': 'erebus', 'host_config_sha256': self.host_config_sha,
                         'jobs': {'job-one': {'storage_bytes': 2**30, 'categories': {'outer': [1, 2, 3], 'inner': [1, 2]}}}}
        data = self.canonical(self.geometry)
        self.config_sha = r.sha(data)
        (self.root / 'site-configs' / (self.config_sha + '.json')).write_bytes(data)

    def canonical(self, value):
        return r.json_bytes(value) + b'\n'

    def stage(self, source_code, *, agent=False, older=None, base=None):
        source = source_code * 40
        roles = ('maintenance', 'development') if agent else ('maintenance', 'development', 'devbox', 'host')
        index = {'schema': 2, 'kind': site.AGENT if agent else site.FULL, 'repository': 'oso-gato/dev-pair',
                 'source_sha': source, 'publisher_run': 22 if agent else 11, 'standards_sha': r.STANDARDS,
                 'contracts': {'ledger': 1, 'state': 1, 'release_policy': 1},
                 'previous_platform_sha256': older, 'base_platform_sha256': base, 'components': {}, 'transports': {}}
        files, role_evidence = {}, {}
        inner = None
        for role in roles:
            archive = ('fixture archive ' + role + source).encode()
            if role == 'host':
                filenames = {'host.tar': archive, 'host-manifest.json': self.host}
                index['components']['host'] = {'source_sha': source, 'bundle_manifest_sha256': self.host_sha}
                role_evidence['host'] = {'manifest_sha256': self.host_sha}
            else:
                context = r.sha((role + source).encode())
                config = r.sha((context + 'config').encode())
                oci = r.sha((context + 'oci').encode())
                row = {'source_sha': source, 'context_sha256': context, 'oci_config_sha256': config,
                       'oci_manifest_sha256': oci, 'archive_sha256': r.sha(archive), 'archive_bytes': len(archive)}
                role_evidence[role] = {'oci_config_sha256': config, 'oci_manifest_sha256': oci}
                if role != 'devbox':
                    row.update(codex_version='2.0.0' if agent else '1.0.0', codex_source_sha=source, codex_sha256='f'*64)
                    role_evidence[role]['context_sha256'] = context
                index['components'][role if role == 'devbox' else role + '-agent'] = row
                image = {'role': role, 'source_sha': source, 'context_sha256': context, 'image_id': config,
                         'archive_sha256': r.sha(archive), 'archive_bytes': len(archive), 'diff_ids': ['sha256:' + '7'*64]}
                if role == 'development':
                    inner = {**{key: value for key, value in image.items() if key != 'role'},
                             'inputs_sha256': '5'*64, 'sealed_sha256': '6'*64}
                filenames = {role + '.oci.tar': archive, 'part.json': self.canonical({'schema': 1, 'image': image,
                              'oci_manifest_sha256': oci, 'producer': inner if role == 'development' else {}})}
                if role == 'maintenance':
                    result = {'source_sha': source, 'context_sha256': context, 'assembled_image_id': config,
                              'runtime_container_removed': True, 'boundary_and_version_cycles': 2, 'job_admission': False}
                    leaf = self.root / 'bootstrap' / 'gptbox-adapter' / context / 'result.json'
                    leaf.parent.mkdir(mode=0o700, parents=True)
                    content = self.canonical(result)
                    leaf.write_bytes(content)
                    role_evidence[role]['result_sha256'] = r.sha(content)
            files[role] = filenames
            index['transports'][role] = {'name': f'platform-{role}-{source}',
                                         'files': {name: {'bytes': len(data), 'sha256': r.sha(data)} for name, data in filenames.items()}}
        raw = self.canonical(index)
        portable = r.sha(raw)
        directory = self.root / 'platform-releases' / portable
        directory.mkdir(mode=0o700)
        (directory / 'platform.json').write_bytes(raw)
        intake = {key: index[key] for key in ('source_sha', 'publisher_run', 'kind')}
        r.replace_json(directory / 'intake.json', {'schema': 2, 'platform_sha256': portable, **intake})
        for role, contents in files.items():
            (directory / role).mkdir(mode=0o700)
            for filename, data in contents.items():
                (directory / role / filename).write_bytes(data)
        if agent:
            _, retained, retained_evidence = self.initial_record
            for role in ('host', 'devbox'):
                role_evidence[role] = retained_evidence[role]
            outer = retained['components']['devbox']
        else:
            outer = index['components']['devbox']
        job = 'job-one'
        body = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': r.STANDARDS, 'job': job,
                'outer': {'image_id': outer['oci_config_sha256'], 'source_sha': outer['source_sha']}, 'inner': inner,
                **self.geometry['jobs'][job]}
        manifest = self.canonical(body)
        checksum = r.sha(manifest)
        parent = self.root / 'development' / 'builds' / job / 'inputs' / checksum
        parent.mkdir(mode=0o700, parents=True)
        (parent / 'manifest.json').write_bytes(manifest)
        archive = parent / 'development.oci.tar'
        archive.write_bytes(files['development']['development.oci.tar'])
        archive.chmod(0o444)
        role_evidence['development'].update(inner_sha256=r.sha(self.canonical(inner)), jobs={job: {'manifest_sha256': checksum}})
        installed = {'schema': 1, 'platform_sha256': portable, 'base_platform_sha256': base if agent else portable,
                     'site_config_sha256': self.config_sha, 'boot_id': self.boot, 'source_sha': source, 'components': role_evidence}
        r.replace_json(directory / 'installed.json', installed)
        if not agent:
            self.initial_record = portable, index, role_evidence
        return portable, parent

    def offer(self, portable, previous=None):
        return {'schema': 2, 'scope': 'agent' if previous else 'initial', 'operation': 'renew-agents' if previous else 'commission',
                'platform_sha256': portable, 'previous_release_sha256': previous, 'site_config_sha256': self.config_sha,
                'affected_jobs': ['job-one'], 'reason': 'Exact approved portable release'}

    def resolve_site(self, offer):
        return self.resolve.resolve(offer, boot=self.boot, hostname='erebus')

    def test_full_bootstrap_and_agent_resolution_keep_base_and_bind_approval_to_installed_boot(self):
        platform, _ = self.stage('a')
        initial = self.resolve_site(self.offer(platform))
        current = initial['release_sha256']
        self.assertFalse((self.controller.control / 'current.json').exists())
        r.replace_json(self.controller.control / 'current.json', current)
        r.replace_json(self.controller.control / 'site-current.json', current)
        authored, _ = self.stage('b', agent=True, older=platform, base=platform)
        offer = self.offer(authored, current)
        selected = self.resolve_site(offer)
        released = selected['release_sha256']
        previous, next_release = (self.controller.release(path) for path in (current, released))
        for name in ('host', 'devbox'):
            self.assertEqual(previous['components'][name], next_release['components'][name])
        self.assertNotEqual(previous['components']['development-agent'], next_release['components']['development-agent'])
        self.assertEqual(self.resolve_site(offer), selected)
        scope = self.controller.control
        r.replace_json(scope / 'offers' / 'agent.json', offer)
        request = {'schema': 1, 'scope': 'agent', 'operation': offer['operation'], 'previous_sha256': current,
                   'target_sha256': released, 'affected_jobs': offer['affected_jobs'], 'reason': offer['reason']}
        r.replace_json(scope / 'requests' / 'agent.json', {'schema': 1, 'offer_sha256': r.identity(offer), 'request': request})
        self.assertEqual(self.controller.active_request('agent'), request)
        admission = self.root / 'platform-releases' / authored / 'intake.json'
        admission_bytes = admission.read_bytes()
        r.replace_json(admission, {**r.read_json(admission), 'publisher_run': 333})
        with self.assertRaisesRegex(ValueError, 'intake result'):
            self.controller.active_request('agent')
        admission.write_bytes(admission_bytes)
        legacy = {'schema': 1, 'request': request, 'run_ids': {'maintenance': 1, 'development': 2}}
        r.replace_json(scope / 'offers' / 'agent.json', legacy)
        r.replace_json(scope / 'requests' / 'agent.json', {'schema': 1, 'offer_sha256': r.identity(legacy), 'request': request})
        with self.assertRaisesRegex(ValueError, 'changed or revoked'):
            self.controller.active_request('agent')
        r.replace_json(scope / 'offers' / 'agent.json', offer)
        r.replace_json(scope / 'requests' / 'agent.json', {'schema': 1, 'offer_sha256': r.identity(offer), 'request': request})
        receipt = self.root / 'platform-releases' / authored / 'installed.json'
        current_receipt = r.read_json(receipt)
        r.replace_json(receipt, {**current_receipt, 'boot_id': '11111111-1111-1111-1111-111111111111'})
        with self.assertRaisesRegex(ValueError, 'installed boot readback'):
            self.controller.active_request('agent')
        with self.assertRaisesRegex(ValueError, 'site or boot'):
            self.resolve_site(offer)

    def test_uninstalled_manifest_change_and_foreign_site_geometry_fail_before_admission(self):
        platform, parent = self.stage('a')
        expected = (parent / 'manifest.json').read_bytes()
        (parent / 'manifest.json').write_bytes(expected + b' ')
        with self.assertRaisesRegex(ValueError, 'DevBox manifest bytes differ'):
            self.resolve_site(self.offer(platform))
        self.assertFalse(list((self.controller.control / 'releases').iterdir()))
        (parent / 'manifest.json').write_bytes(expected)
        with self.assertRaisesRegex(ValueError, 'another host'):
            self.resolve.resolve(self.offer(platform), boot=self.boot, hostname='foreign')
        overlap = copy.deepcopy(self.geometry)
        overlap['jobs']['job-two'] = overlap['jobs']['job-one']
        with self.assertRaisesRegex(ValueError, 'incompatible SELinux categories'):
            site.closed_site(self.canonical(overlap))

    def test_nightly_entry_derives_local_request_only_for_current_official_release(self):
        platform, _ = self.stage('a')
        current = self.resolve_site(self.offer(platform))['release_sha256']
        r.replace_json(self.controller.control / 'current.json', current)
        r.replace_json(self.controller.control / 'site-current.json', current)
        authored, _ = self.stage('b', agent=True, older=platform, base=platform)
        offer = self.offer(authored, current)
        r.replace_json(self.controller.control / 'offers' / 'agent.json', offer)
        qualify = runpy.run_path(str(TOOLS.parent / 'runtime/renewal/agent-candidate'))['controller_offer']
        adapter = SimpleNamespace(index=self.resolve.index, resolve=self.resolve_site)
        changes = {'CONTROL': self.controller.control, 'Resolver': lambda controller: adapter,
                   'official_version': lambda: '3.0.0'}
        with patch.dict(qualify.__globals__, changes):
            with self.assertRaisesRegex(ValueError, 'not the current official stable CLI'):
                qualify(self.controller)
        self.assertIsNone(self.controller.active_request('agent'))
        with patch.dict(qualify.__globals__, {**changes, 'official_version': lambda: '2.0.0'}):
            result = qualify(self.controller)
            self.assertEqual(result['status'], 'verified')
            bound = self.controller.active_request('agent')
            self.assertEqual(bound['target_sha256'], result['release_sha256'])
            self.assertNotEqual(bound['target_sha256'], authored)
            r.replace_json(self.controller.control / 'current.json', result['release_sha256'])
            self.assertEqual(qualify(self.controller)['status'], 'current')
            self.assertIsNone(self.controller.active_request('agent'))


if __name__ == '__main__':
    unittest.main()
