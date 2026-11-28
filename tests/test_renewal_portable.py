"""Resolve protected local fixture records without a native import or remote API."""
import copy
from contextlib import contextmanager
import gzip
import importlib.util
from io import BytesIO
import os
from pathlib import Path
import runpy
import stat
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
                                     self.root / 'host-releases', self.root / 'host-configs', self.read_manifest)
        if importlib.util.find_spec('platform_release_protocol') is None:
            # The exact portable parser is supplied by F in combined validation.
            dependency = SimpleNamespace(canonical=self.canonical, portable_index=lambda value, source, run: value,
                                         UPSTREAM_RELEASE_LIMIT=1024**2, upstream_release_json=r.loads)
            self.enterContext(patch.dict(sys.modules, {'platform_release_protocol': dependency}))
        self.config = self.canonical({'verified': 'immutable fixture host profile'})
        self.host_config_sha = r.sha(self.config)
        (self.root / 'host-configs' / (self.host_config_sha + '.json')).write_bytes(self.config)
        self.host = self.canonical({'schema': 1, 'source_revision': 'a'*40, 'state_contract': 1, 'files': {}})
        self.host_sha = r.sha(self.host)
        (self.root / 'host-releases' / self.host_sha).mkdir(mode=0o700)
        (self.root / 'host-releases' / self.host_sha / 'manifest.json').write_bytes(self.host)
        self.geometry = {'schema': 1, 'hostname': 'erebus', 'host_config_sha256': self.host_config_sha,
                         'jobs': {'job-one': {'storage_bytes': 8 * 2**30, 'categories': {'outer': [1, 2, 3], 'inner': [1, 2]}}}}
        data = self.canonical(self.geometry)
        self.config_sha = r.sha(data)
        (self.root / 'site-configs' / (self.config_sha + '.json')).write_bytes(data)

    def canonical(self, value):
        return r.json_bytes(value) + b'\n'

    def read_manifest(self, root, manifests, config):
        def inode(node):
            return [node.st_ino, node.st_uid, node.st_gid, node.st_mode]

        @contextmanager
        def private_child(parent, name, uid, gid, *, mode, create, label):
            self.assertFalse(create)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                node = os.fstat(fd)
                self.assertEqual((node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode)), (uid, gid, mode))
                yield fd, False
            finally:
                os.close(fd)

        try:
            from native_placements import private_child, volume_inode as inode
        except ImportError:
            pass  # The isolated U branch uses the exact G adapter during the combined check.
        label = 'system_u:object_r:container_file_t:s0:c1,c2,c3'
        db = SimpleNamespace(file_label=lambda manifest, scope: label, same_label=lambda seen, expected: seen == expected)
        native = SimpleNamespace(volume_inode=inode, private_child=private_child, db=db)
        for job, (reference, manifest) in manifests.items():
            build = root / 'development/builds' / job
            self.assertEqual(stat.S_IMODE(build.stat().st_mode), 0o700)
            leaf = build / 'inputs' / reference
            parsed = r.loads(manifest)
            self.assertEqual(parsed['categories'], config['jobs'][job]['categories'])
            claim = {'directory': inode(leaf.stat()), 'inner_sha256': r.sha(site.image_inputs_bytes(parsed['inner']))}
            lease = {'manifests': {reference: claim}, 'volumes': {'build': {'inputs': inode(leaf.parent.stat())}}}
            descriptor = os.open(build, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with patch.object(os, 'getxattr', return_value=label.encode()):
                    site.observe_development_files(native, descriptor, lease, reference, manifest, parsed,
                                                   owner=(os.getuid(), os.getgid()))
            finally:
                os.close(descriptor)

    def stage(self, source_code, *, agent=False, older=None, base=None, stable=None, local_prior=None, run=None, native=False):
        source = source_code * 40
        roles = ('maintenance', 'development') if agent else ('maintenance', 'development', 'devbox', 'host')
        index = {'schema': 3 if local_prior is not None else 2, 'kind': site.AGENT if agent else site.FULL, 'repository': 'oso-gato/dev-pair',
                 'source_sha': source, 'publisher_run': run if run is not None else (22 if agent else 11), 'standards_sha': r.STANDARDS,
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
                    row.update(codex_version=stable or ('2.0.0' if agent else '1.0.0'), codex_source_sha=source, codex_sha256='f'*64)
                    role_evidence[role]['context_sha256'] = context
                index['components'][role if role == 'devbox' else role + '-agent'] = row
                image = {'role': role, 'source_sha': source, 'context_sha256': context, 'image_id': config,
                         'archive_sha256': r.sha(archive), 'archive_bytes': len(archive), 'diff_ids': ['sha256:' + '7'*64]}
                if role == 'development':
                    inner = {**{key: value for key, value in image.items() if key != 'role'},
                             'inputs_sha256': '5'*64, 'sealed_sha256': '6'*64}
                capabilities = {'maintenance': {'result_sha256': '9'*64}, 'development': inner, 'devbox': {}}
                if native:
                    import fedora_oci
                    base_proof = {'source': fedora_oci.PROVENANCE, 'imported_config': 'sha256:' + fedora_oci.CONFIG,
                                  'imported_manifest': 'sha256:' + fedora_oci.MANIFEST,
                                  'conversion': 'source manifest/config retained on load; storage save gzip representation derived and fully rehashed',
                                  'saveback': {'manifest_sha256': '3'*64, 'config_sha256': fedora_oci.CONFIG,
                                               'compressed_layer_sha256': '4'*64, 'diff_id_sha256': fedora_oci.DIFF,
                                               'derivation': 'storage export gzip recompression allowed; exact source config bytes and rootfs diff stream required'},
                                  'verification': 'Source archive chain plus exported config-byte/rootfs-diff equality and full derived descriptor/blob graph',
                                  'failure_recovery': 'Import is nontransactional; unreferenced store layers may remain, no broad prune/removal'}
                    if role == 'maintenance':
                        result = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': source, 'context_sha256': context,
                                  'distrobox_sha': site.DBX_SOURCE, 'assembled_image_id': image['image_id'], 'boundary_and_version_cycles': 2,
                                  'runtime_container_removed': True, 'job_admission': False, 'fedora_base': base_proof,
                                  'runtime_container_id': '4'*64, 'authentication': 'not verified', 'model_access': 'not verified',
                                  'nested_placement': 'not verified',
                                  'note': 'Probe-only candidate; no Codex job, credential or model request is admitted.'}
                        capabilities[role] = {'result': result, 'result_sha256': r.sha(site.image_inputs_bytes(result))}
                    elif role == 'devbox':
                        image['diff_ids'].append('sha256:' + '8'*64)
                        capabilities[role] = {'tooling_image_id': '9'*64, 'tooling_diff_ids': image['diff_ids'][:1],
                                              'tooling_recipe_sha256': '8'*64, 'signed_base': base_proof}
                filenames = {role + '.oci.tar': archive, 'part.json': self.canonical({'schema': 1, 'image': image,
                              'oci_manifest_sha256': oci, 'producer': capabilities[role]})}
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
        if local_prior is not None:
            binding = {'schema': 1, 'platform_sha256': portable, 'base_platform_sha256': base,
                       'previous_platform_sha256': local_prior}
            (directory / 'site-predecessor.json').write_bytes(self.canonical(binding))
        for role, contents in files.items():
            (directory / role).mkdir(mode=0o700)
            for filename, data in contents.items():
                (directory / role / filename).write_bytes(data)
        claim = site.maintenance_claim(directory, index)
        from gptbox import Gptbox
        if hasattr(Gptbox, 'import_admission'):
            observed = Gptbox.import_admission(portable, claim['context_sha256'], source, claim['image_id'],
                                               claim['oci_manifest_sha256'], self.boot, claim['producer_result_sha256'])
            self.assertEqual(observed, {**claim, 'boot_id': self.boot})
        else:
            observed = {**claim, 'boot_id': self.boot}
        evidence = site.image_inputs_bytes(observed)
        leaf = site.maintenance_path(self.root, claim, self.boot)
        leaf.parent.mkdir(mode=0o700, parents=True)
        leaf.write_bytes(evidence)
        leaf.chmod(0o600)
        role_evidence['maintenance']['result_sha256'] = r.sha(evidence)
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
        parent.mkdir(mode=0o755, parents=True)
        parent.chmod(0o755)
        parent.parent.chmod(0o755)
        parent.parent.parent.chmod(0o700)
        path = parent / 'manifest.json'
        path.write_bytes(manifest)
        path.chmod(0o444)
        archive = parent / 'development.oci.tar'
        archive.write_bytes(files['development']['development.oci.tar'])
        archive.chmod(0o444)
        role_evidence['development'].update(inner_sha256=r.sha(site.image_inputs_bytes(inner)), jobs={job: {'manifest_sha256': checksum}})
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
        initial_release = self.controller.release(current)
        component = initial_release['components']['maintenance-agent']
        claim, boot, config = site.retained_maintenance(self.controller, component, component['config_sha256'])
        self.assertEqual((claim['platform_sha256'], boot, config), (platform, self.boot, self.config_sha))
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

    def test_two_site_chained_offers_bind_each_exact_active_predecessor_and_keep_base(self):
        import platform_release_protocol as protocol
        if not hasattr(protocol, 'site_predecessor'):
            self.skipTest('combined schema 3 release protocol is required')
        platform, _ = self.stage('a')
        initial = self.resolve_site(self.offer(platform))
        current = initial['release_sha256']
        control = self.controller.control
        for name in ('current.json', 'site-current.json'):
            r.replace_json(control / name, current)
        first, _ = self.stage('b', agent=True, base=platform, local_prior=platform)
        first_offer = self.offer(first, current)
        first_selected = self.resolve_site(first_offer)
        for name in ('current.json', 'site-current.json'):
            r.replace_json(control / name, first_selected['release_sha256'])
        self.assertEqual(self.resolve_site(first_offer), first_selected)
        second, _ = self.stage('c', agent=True, base=platform, stable='3.0.0', local_prior=first)
        second_offer = self.offer(second, first_selected['release_sha256'])
        second_selected = self.resolve_site(second_offer)
        self.assertEqual(second_selected['base_platform_sha256'], platform)
        self.assertEqual(second_selected['platform_sha256'], second)
        first_image = self.controller.release(first_selected['release_sha256'])['components']
        second_image = self.controller.release(second_selected['release_sha256'])['components']
        self.assertEqual(first_image['host'], second_image['host'])
        self.assertEqual(first_image['devbox'], second_image['devbox'])
        self.assertNotEqual(first_image['maintenance-agent'], second_image['maintenance-agent'])
        with self.assertRaisesRegex(ValueError, 'stale local predecessor'):
            self.resolve_site(self.offer(second, current))
        proof = self.root / 'platform-releases' / second / 'site-predecessor.json'
        binding = r.read_json(proof)
        proof.write_bytes(self.canonical({**binding, 'previous_platform_sha256': platform}))
        with self.assertRaisesRegex(ValueError, 'changes independently staged predecessor'):
            self.resolve_site(second_offer)

    def test_uninstalled_manifest_change_and_foreign_site_geometry_fail_before_admission(self):
        platform, parent = self.stage('a')
        expected = (parent / 'manifest.json').read_bytes()
        (parent / 'manifest.json').chmod(0o600)
        (parent / 'manifest.json').write_bytes(expected + b' ')
        (parent / 'manifest.json').chmod(0o444)
        with self.assertRaisesRegex(ValueError, 'input ownership, label or length differs'):
            self.resolve_site(self.offer(platform))
        self.assertFalse(list((self.controller.control / 'releases').iterdir()))
        (parent / 'manifest.json').chmod(0o600)
        (parent / 'manifest.json').write_bytes(expected)
        (parent / 'manifest.json').chmod(0o444)
        with self.assertRaisesRegex(ValueError, 'another host'):
            self.resolve.resolve(self.offer(platform), boot=self.boot, hostname='foreign')
        overlap = copy.deepcopy(self.geometry)
        overlap['jobs']['job-two'] = overlap['jobs']['job-one']
        with self.assertRaisesRegex(ValueError, 'incompatible SELinux categories'):
            site.closed_site(self.canonical(overlap))

    def test_exact_platform_and_boot_maintain_separate_immutable_import_proofs(self):
        current_boot = self.boot
        initial_boot = '11111111-1111-1111-1111-111111111111'
        self.boot = initial_boot
        platform, _ = self.stage('a')
        release = self.controller.release(self.resolve_site(self.offer(platform))['release_sha256'])
        component = release['components']['maintenance-agent']
        context = component['config_sha256']
        claim, observed, _ = site.retained_maintenance(self.controller, component, context)
        self.assertEqual((component['platform_sha256'], observed), (platform, initial_boot))
        old_file = site.maintenance_path(self.root, claim, initial_boot)
        old_raw = old_file.read_bytes()
        new_file = site.maintenance_path(self.root, claim, current_boot)
        self.assertNotEqual(old_file, new_file)
        new_file.write_bytes(site.image_inputs_bytes({**claim, 'boot_id': current_boot, 'platform_sha256': 'f'*64}))
        new_file.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'exact typed local import'):
            site.retained_maintenance(self.controller, component, context)
        new_file.write_bytes(site.image_inputs_bytes({**claim, 'boot_id': current_boot}))
        self.assertEqual(site.retained_maintenance(self.controller, component, context)[1], current_boot)
        self.assertEqual(old_file.read_bytes(), old_raw)

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

    def test_actual_sized_upstream_release_passes_normal_candidate_entry(self):
        import platform_release_protocol as protocol

        source = getattr(protocol, '__file__', None)
        fixture = Path(source).resolve().parents[1] / 'tests/data/platform/codex-rust-v0.169.0-release.json.gz' if source else None
        if fixture is not None and fixture.is_file():
            upstream = gzip.decompress(fixture.read_bytes())
            self.assertEqual(len(upstream), 413671)
        else:
            upstream = r.json_bytes({'tag_name': 'rust-v0.169.0', 'draft': False, 'prerelease': False,
                                     'html_url': 'https://github.com/openai/codex/releases/tag/rust-v0.169.0',
                                     'assets': [{'name': 'example', 'text': 'a'*2048} for _ in range(194)]})
            self.assertGreater(len(upstream), 262144)
        platform, _ = self.stage('a')
        current = self.resolve_site(self.offer(platform))['release_sha256']
        r.replace_json(self.controller.control / 'current.json', current)
        r.replace_json(self.controller.control / 'site-current.json', current)
        candidate, _ = self.stage('b', agent=True, older=platform, base=platform, stable='0.169.0')
        r.replace_json(self.controller.control / 'offers' / 'agent.json', self.offer(candidate, current))
        path = TOOLS.parent / 'runtime/renewal/agent-candidate'
        qualify = runpy.run_path(str(path))['controller_offer']
        adapter = SimpleNamespace(index=self.resolve.index, resolve=self.resolve_site)

        class Response(BytesIO):
            status = 200

            def geturl(self):
                return qualify.__globals__['LATEST']

        with patch.dict(qualify.__globals__, {'CONTROL': self.controller.control, 'Resolver': lambda controller: adapter}), \
                patch('urllib.request.urlopen', return_value=Response(upstream)) as transport:
            result = qualify(self.controller)
        self.assertEqual(result['version'], '0.169.0')
        self.assertEqual(self.controller.active_request('agent')['target_sha256'], result['release_sha256'])
        self.assertEqual(transport.call_args.args[0].full_url, 'https://api.github.com/repos/openai/codex/releases/latest')


if __name__ == '__main__':
    unittest.main()
