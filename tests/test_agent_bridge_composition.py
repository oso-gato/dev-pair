"""Combine normal publisher, transport, discovery and approval with local boundary fixtures."""
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
import zipfile

import test_renewal_portable as local
import test_agent_release_bridge as scheduled
import agent_release_bridge as bridge
import platform_release as publish
import platform_release_intake as intake
import platform_release_install as installer
import native_placement_release as placement
import native_placements as native_host
import gptbox as roles
import test_native_placement_release as native_fixture
import platform_release_protocol as protocol
import renewal as renewal
import renewal_site as site


class FixtureOwner:
    """Project the local test UID into the production root-only call sites."""
    def __init__(self, effective_uid=0):
        self.effective_uid = effective_uid

    def __getattr__(self, name):
        return getattr(os, name)

    def getuid(self):
        return 0

    def geteuid(self):
        return self.effective_uid

    def uname(self):
        return SimpleNamespace(nodename='erebus', machine='x86_64')

    def fstat(self, fd):
        info = os.fstat(fd)
        class FileIdentity:
            st_uid = 0

            def __getattr__(self, key):
                return getattr(info, key)

        return FileIdentity()


class NightlyComposition(TestCase):
    def test_two_scheduled_packages_through_production_cli_transport_and_local_approval(self):
        self.run_composition(('schedule', 'schedule'))

    def test_fixed_manual_dispatch_uses_the_same_signed_intake_and_approval(self):
        self.run_composition(('schedule', 'workflow_dispatch'))

    def run_composition(self, events):
        destination = local.PortableSiteTests()
        destination.setUp()
        self.addCleanup(destination.doCleanups)
        store = destination.root / 'platform-releases'
        control = destination.controller.control
        checkout = native_host.SOURCE
        names = ('tools/native_placements.py', 'tools/native_placement_release.py', 'tools/platform_release.py',
                 'tools/platform_release_protocol.py', 'tools/platform_release_install.py', 'tools/bootstrap.py',
                 'tools/gptbox.py', 'tools/fedora_oci.py', 'tools/native_io.py', 'tools/storage.py', *native_host.ENTRY_FILES)
        source_files = {name: (checkout / name).read_bytes() for name in names}
        destination.host = protocol.canonical({'schema': 1, 'source_revision': 'a'*40, 'state_contract': 1,
                                               'files': {name: publish.digest(raw) for name, raw in source_files.items()}})
        destination.host_sha = publish.digest(destination.host)
        first, initial_inputs = destination.stage('a', native=True)
        path = store / first / 'intake.json'
        path.write_bytes(protocol.canonical(renewal.read_json(path)))
        path.chmod(0o600)
        (store / first / 'installed.json').unlink()
        shutil.rmtree(initial_inputs)
        stage_index = publish.readonly_json(store / first / 'platform.json')[1]
        initial_claim = site.maintenance_claim(store / first, stage_index)
        site.maintenance_path(destination.root, initial_claim, destination.boot).unlink()
        selector = runpy.run_path(str(local.TOOLS.parent / 'runtime/renewal/agent-candidate'))['controller_offer']
        native = {'calls': [], 'stage': {}, 'signed': {}, 'blobs': {}, 'artifacts': {}, 'run': None,
                  'occupied': False, 'placement': {}}
        input_helper = publish.public_inputs

        def part(directory, role, source, end, tooling=None):
            raw, value = publish.readonly_json(directory / 'part.json')
            self.assertEqual(value['image']['source_sha'], source)
            self.assertEqual(value['image']['role'], role)
            return value, publish.digest(raw)

        def stamp(day, hour, minute=0):
            return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)

        def query(endpoint, end, *, limit=intake.META_LIMIT, output=None):
            run = native['run']
            if endpoint == 'branches/main':
                return {'protected': True, 'commit': {'sha': run['head_sha']}}
            if endpoint.startswith('actions/workflows/'):
                self.assertIn('event=' + run['event'], endpoint)
                return {'workflow_runs': [run] if native['occupied'] else []}
            if endpoint == f"actions/runs/{run['id']}":
                return run
            if endpoint == f"actions/runs/{run['id']}/artifacts?per_page=100":
                return native['artifacts'][run['id']]
            if endpoint.startswith('actions/artifacts/') and endpoint.endswith('/zip'):
                blob = native['blobs'][int(endpoint.split('/')[2])]
                self.assertLessEqual(len(blob), limit)
                output.write(blob)
                output.flush()
                return None
            raise AssertionError(f'Unexpected endpoint {endpoint}')

        def attestation(path, digest, source, run, role, end):
            self.assertEqual((source, digest, path.read_bytes()), native['signed'][run])
            self.assertIn(role, ('maintenance', 'development'))
            native['calls'].append(('attested', run, role))

        maint = roles.Gptbox(destination.root)
        developer = roles.DevelopmentGptbox(destination.root)
        developer.lock = nullcontext
        developer_protected = developer.protected
        developer.protected = lambda path: path if Path(path).is_relative_to(checkout) else developer_protected(path)
        maint.preflight = lambda: None
        maint.maintenance_host_readiness = lambda context: None
        maint.live_boot_id = lambda: destination.boot
        maint.lock = nullcontext
        maint.run = SimpleNamespace(phase=lambda *args, **kwargs: nullcontext())
        projection = native_fixture.PlacementFixture()

        def observe_maintenance(root, binding, part, diffs, producer, receipt):
            _, import_record = maint.read_config_record(root + '/maintenance-import.json')
            self.assertEqual(import_record['oci_manifest_sha256'], binding['oci_manifest_sha256'])
            self.assertEqual(import_record['archive_sha256'], part['archive_sha256'])
            native['calls'].append(('maintenance-observed', binding['platform_sha256'], part['codex_version']))
            return maint.import_admission(binding['platform_sha256'], binding['context_sha256'], binding['source_sha'],
                                         binding['image_id'], binding['oci_manifest_sha256'], binding['boot_id'], producer)

        def placement_mounts(active, producer, account, candidate, previous):
            active.item, active.previous = candidate, previous
            active.job, active.boot = candidate.job, destination.boot
            active.establish = lambda: None
            active.load_outer = lambda: None
            active.save = lambda: None
            active.outer_label = 'fixture-label'
            active.build_volume = SimpleNamespace(capacity=candidate.geometry['storage_bytes'])
            active.job_state = native['placement'].setdefault(candidate.job, {'categories': candidate.geometry['categories'],
                                                                            'manifests': {}, 'preflight': None})
            active.input_root = destination.root / 'development/builds' / candidate.job / 'inputs'
            active.input_root.mkdir(mode=0o755, parents=True, exist_ok=True)
            active.build_inputs = lambda: native_host.directory_fd(active.input_root)
            active.copy_verified = projection.fixture_copy

            def shape():
                return {'identity': candidate.identity, 'prior': candidate.previous, 'boot': destination.boot,
                        'archive': publish.digest(candidate.inner_path.read_bytes())}

            active.admission_binding = shape
            active.preflight = lambda binding: self.assertEqual(binding['archive'], candidate.inner['archive_sha256'])

        @contextmanager
        def projected_label_directory(parent, name, uid, gid, *, mode, label, create):
            with projection.child(parent, name, uid, gid, mode=mode, label=label, create=create) as (fd, created):
                if created:
                    os.fchmod(fd, mode)
                yield fd, created

        def projected_label_file(parent, name, writer, label):
            projection.write(parent, name, writer, label)
            os.chmod(name, 0o444, dir_fd=parent)

        def host_archive(directory, source, end, unpack=None):
            self.assertEqual(source, 'a'*40)
            self.assertEqual((directory / 'host-manifest.json').read_bytes(), destination.host)
            if unpack is not None:
                (unpack / 'manifest.json').write_bytes(destination.host)
                (unpack / 'manifest.json').chmod(0o444)
                for name, raw in source_files.items():
                    path = unpack / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                    path.chmod(0o444)
            return destination.host_sha

        def execute_native(argv, end, **kwargs):
            output = io.StringIO()
            if argv[2] == str(installer.G_ENTRY):
                with redirect_stdout(output):
                    self.assertEqual(placement.install_cli(argv[4:]), 0)
                native['calls'].append(('placement', argv[5], argv[7]))
            elif argv[2] == str(installer.P_ENTRY):
                with redirect_stdout(output):
                    self.assertEqual(roles.maintenance_install_cli(argv[3], argv[4:]), 0)
            else:
                raise AssertionError(f'Unexpected native command {argv}')
            return 0, output.getvalue().encode()

        def native_runner(name, *args, timeout):
            fields = dict(zip(args, args[1:]))
            identity = fields['--platform-sha256']
            if name == 'platform_release_intake.py':
                self.assertIn('--agent-only', args)
                with intake.intake_lock():
                    intake.acquire(fields['--source'], int(fields['--run-id']), identity, fields['--previous'],
                                   time.monotonic() + timeout, agent=True)
                native['calls'].append(('retained-predecessor', identity, fields['--previous']))
            else:
                self.assertEqual(name, 'platform_release_install.py')
                self.assertEqual(fields['--site-config-sha256'], destination.config_sha)
                with intake.intake_lock():
                    installer.install(identity, fields['--site-config-sha256'], time.monotonic() + timeout)
                native['calls'].append(('observed-install', identity))

        def resolve(offer):
            resolver = adapter['resolver']
            return resolver(offer, boot=destination.boot, hostname='erebus')

        adapter = {'resolver': destination.resolve.resolve}
        fixture_resolver = destination.resolve
        ordinary_json = publish.readonly_json
        with ExitStack() as stack:
            stack.enter_context(patch.object(bridge, 'os', FixtureOwner(os.geteuid())))
            stack.enter_context(patch.object(intake, 'os', FixtureOwner()))
            stack.enter_context(patch.object(intake, 'file_hash', side_effect=lambda path, maximum, end, **kwargs:
                                            protocol.file_hash(path, maximum, end, owner=os.getuid())))
            stack.enter_context(patch.object(publish, 'readonly_json', side_effect=lambda path, owner=None: ordinary_json(path)))
            stack.enter_context(patch.object(renewal, 'DEFAULT_ROOT', destination.root))
            stack.enter_context(patch.object(site, 'Resolver', return_value=fixture_resolver))
            stack.enter_context(patch.object(fixture_resolver, 'resolve', side_effect=resolve))
            stack.enter_context(patch.object(intake, 'ROOT', store))
            stack.enter_context(patch.object(intake, 'portable_volume', return_value=(store.stat().st_dev, 42, 17, ('99',))))
            stack.enter_context(patch.object(intake, 'GITHUB', '/usr/bin/python3'))
            stack.enter_context(patch.object(intake, 'protected', side_effect=lambda path, **kwargs: path))
            stack.enter_context(patch.object(intake, 'read_api', side_effect=query))
            stack.enter_context(patch.object(intake, 'verify_subject', side_effect=attestation))
            stack.enter_context(patch.object(publish, 'validate_image_part', side_effect=part))
            stack.enter_context(patch.object(publish, 'validate_host', side_effect=host_archive))
            stack.enter_context(patch.object(publish, 'publication_evidence', wraps=publish.publication_evidence))
            stack.enter_context(patch.object(installer, 'ROOT', destination.root))
            stack.enter_context(patch.object(installer, 'ADAPTER', destination.root / 'bootstrap/gptbox-adapter'))
            stack.enter_context(patch.object(installer, 'HOST_RELEASES', destination.root / 'host-releases'))
            stack.enter_context(patch.object(installer, 'SITE_CONFIGS', destination.root / 'site-configs'))
            stack.enter_context(patch.object(installer, 'G_ENTRY', checkout / 'tools/native_placements.py'))
            stack.enter_context(patch.object(installer, 'P_ENTRY', checkout / 'tools/gptbox.py'))
            stack.enter_context(patch.object(installer, 'file_hash', side_effect=lambda path, maximum, end, **kwargs:
                                            protocol.file_hash(path, maximum, end, owner=os.getuid())))
            stack.enter_context(patch.object(installer, 'regular', side_effect=lambda path, maximum, owner=None:
                                            protocol.regular(path, maximum, os.getuid())))
            stack.enter_context(patch.object(installer, 'machine', return_value=destination.boot))
            stack.enter_context(patch.object(installer, 'maintenance_identity', return_value=(None, Path('/run/user/1000'))))
            stack.enter_context(patch.object(installer, 'bounded_volume', return_value={'device': f'{os.major(store.stat().st_dev)}:{os.minor(store.stat().st_dev)}'}))
            stack.enter_context(patch.object(installer, 'recover_maintenance'))
            stack.enter_context(patch.object(installer, 'observe_maintenance_engine'))
            stack.enter_context(patch.object(installer, 'bounded', side_effect=execute_native))
            stack.enter_context(patch.object(installer.devbox, 'storage_mount'))
            stack.enter_context(patch.object(installer.devbox, 'check_label'))
            stack.enter_context(patch.object(placement, 'os', FixtureOwner()))
            stack.enter_context(patch.object(placement, 'RELEASES', store))
            stack.enter_context(patch.object(placement, 'RENEWAL', control))
            stack.enter_context(patch.object(placement, 'SITE_CONFIGS', destination.root / 'site-configs'))
            stack.enter_context(patch.object(placement.ReleasePlacement, '__init__', placement_mounts))
            stack.enter_context(patch.object(native_host, 'DevelopmentGptbox', return_value=developer))
            stack.enter_context(patch.object(native_host, 'managed_snapshot'))
            stack.enter_context(patch.object(native_host, 'role_account'))
            stack.enter_context(patch.object(native_host, 'private_child', projected_label_directory))
            stack.enter_context(patch.object(native_host, 'stable_file', projected_label_file))
            stack.enter_context(patch.object(roles, 'PLATFORM_RELEASES', '/platform-releases'))
            stack.enter_context(patch.object(roles, 'ROOT', '/bootstrap/gptbox-adapter'))
            factory = stack.enter_context(patch.object(roles, 'Gptbox', return_value=maint))
            factory.import_admission.side_effect = maint.import_admission
            stack.enter_context(patch.object(maint, 'prove_installed_maintenance', side_effect=observe_maintenance))
            stack.enter_context(patch.object(publish, 'source_checkout'))
            controller = bridge.Site(renewal, site, intake, protocol)
            stack.enter_context(patch.object(controller, 'run_tool', side_effect=native_runner))
            stack.enter_context(patch.object(controller, 'dispatch', side_effect=lambda: native['calls'].append(('dispatched',))))
            installer.install(first, destination.config_sha, time.monotonic() + 30)
            initial = resolve(destination.offer(first))
            for name in ('current.json', 'site-current.json'):
                renewal.replace_json(control / name, initial['release_sha256'])
            prior = first
            for (day, run_id, letter, version), event_name in zip(((26, 22, 'b', '2.0.0'), (27, 23, 'c', '3.0.0')), events):
                source = letter * 40
                on_demand = event_name == 'workflow_dispatch'
                run = scheduled.run_row(run_id, stamp(day, 19, 6), head_sha=source, event=event_name)
                native['run'] = run
                native['occupied'] = False
                self.assertEqual(controller.cycle(bridge.selection_window(stamp(day, 19), on_demand)),
                                 {'status': 'awaiting-publication'})
                staged, input_directory = destination.stage(letter, agent=True, base=first, stable=version,
                                                             local_prior=prior, run=run_id, native=True)
                shutil.rmtree(input_directory)
                interim = publish.readonly_json(store / staged / 'platform.json')[1]
                claim = site.maintenance_claim(store / staged, interim)
                site.maintenance_path(destination.root, claim, destination.boot).unlink()
                remote = destination.root / ('publisher-' + str(run_id))
                (remote / 'parts').mkdir(parents=True)
                for role in ('maintenance', 'development'):
                    shutil.copytree(store / staged / role, remote / 'parts' / publish.artifact_name(role, source))
                event = remote / 'event.json'
                observed_event = {'ref': 'main', 'inputs': {}} if on_demand else {'schedule': '0 19 * * *'}
                event.write_bytes(protocol.canonical(observed_event))
                tooling = {'schema': 1, 'kind': 'dev-pair-verified-codex-pin-proposal', 'reviewed_source_sha': source,
                           'source_sha': source, 'tag': 'rust-v' + version, 'version': version, 'release_id': run_id,
                           'assets': {'archive': {'sha256': '9' * 64, 'bytes': 1}, 'bundle': {'sha256': '8' * 64, 'bytes': 1}},
                           'binary': {'sha256': 'f' * 64, 'bytes': 1}, 'verification_sha256': '7' * 64,
                           'approved_pins_match': False, 'cached_assets': []}
                tooling_file = remote / 'tooling.json'
                tooling_file.write_bytes(input_helper.canonical(tooling))
                env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': publish.REPOSITORY, 'GITHUB_EVENT_NAME': event_name,
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
                       'GITHUB_SHA': source, 'GITHUB_RUN_ID': str(run_id), 'GITHUB_EVENT_PATH': str(event),
                       'GITHUB_WORKFLOW_REF': publish.REPOSITORY + '/.github/workflows/agent-refresh.yml@refs/heads/main'}
                arguments = ['platform_release.py', 'assemble', '--agent-only', '--site-chain', '--source', source,
                             '--input', str(remote / 'parts'), '--output', str(remote / 'subjects'),
                             '--run-id', str(run_id), '--base-platform', first, '--refresh-tooling', str(tooling_file),
                             '--approved-artifact-bytes', str(publish.AGENT_BUDGET)]
                stdout = io.StringIO()
                with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', arguments), redirect_stdout(stdout):
                    self.assertEqual(publish.main(), 0)
                self.assertEqual(stdout.getvalue().strip(), staged)
                signed = (remote / 'subjects/platform.json').read_bytes()
                native['signed'][run_id] = (source, staged, signed)
                leaves = {publish.artifact_name('subjects', source): {'platform.json': signed},
                          f'agent-tooling-{source}': {'tooling.json': tooling_file.read_bytes()}}
                for role in ('maintenance', 'development'):
                    name = publish.artifact_name(role, source)
                    leaves[name] = {path.name: path.read_bytes() for path in (remote / 'parts' / name).iterdir()}
                rows = []
                for offset, (name, items) in enumerate(leaves.items(), start=1):
                    artifact = io.BytesIO()
                    with zipfile.ZipFile(artifact, 'w') as archive:
                        for leaf, raw in items.items():
                            archive.writestr(leaf, raw)
                    data = artifact.getvalue()
                    identifier = run_id * 10 + offset
                    native['blobs'][identifier] = data
                    rows.append({'name': name, 'id': identifier, 'expired': False,
                                 'size_in_bytes': len(data), 'digest': 'sha256:' + publish.digest(data)})
                native['artifacts'][run_id] = {'artifacts': rows, 'total_count': len(rows)}
                shutil.rmtree(store / staged)
                native['occupied'] = True
                self.assertEqual(controller.cycle(bridge.selection_window(stamp(day, 22, 30), on_demand))['status'], 'queued')
                self.assertIn(('retained-predecessor', staged, prior), native['calls'])
                self.assertIn(('observed-install', staged), native['calls'])
                self.assertIn(('placement', 'preflight', staged), native['calls'])
                self.assertIn(('placement', 'stage', staged), native['calls'])
                self.assertIn(('maintenance-observed', staged, version), native['calls'])
                self.assertIn(('attested', run_id, 'maintenance'), native['calls'])
                self.assertIn(('attested', run_id, 'development'), native['calls'])
                self.assertEqual(native['calls'][-1], ('dispatched',))
                with patch.dict(selector.__globals__, {'CONTROL': control, 'Resolver': lambda _: fixture_resolver,
                                                      'official_version': lambda: version}):
                    result = selector(destination.controller)
                self.assertEqual(result['status'], 'verified')
                proof = store / staged / 'site-predecessor.json'
                prior_proof = proof.read_bytes()
                observed_install = store / staged / 'installed.json'
                retained_install = observed_install.read_bytes()
                with intake.intake_lock():
                    installer.install(staged, destination.config_sha, time.monotonic() + 30)
                self.assertEqual(observed_install.read_bytes(), retained_install)
                proof.unlink()
                with self.assertRaises((OSError, ValueError)):
                    installer.install(staged, destination.config_sha, time.monotonic() + 30)
                proof.write_bytes(prior_proof)
                proof.chmod(0o600)
                request = destination.controller.active_request('agent')
                self.assertEqual(request['target_sha256'], result['release_sha256'])
                self.assertEqual(request['previous_sha256'], renewal.read_json(control / 'current.json'))
                for selector_name in ('current.json', 'site-current.json'):
                    renewal.replace_json(control / selector_name, result['release_sha256'])
                prior = staged
        self.assertEqual(len([leaf for leaf in store.iterdir() if len(leaf.name) == 64]), 3)
