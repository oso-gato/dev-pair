"""Combine normal publisher, transport, discovery and approval with local boundary fixtures."""
from contextlib import ExitStack, redirect_stdout
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
import platform_release_protocol as protocol
import renewal as renewal
import renewal_site as site


class FixtureOwner:
    """Project the local test UID into the production root-only call sites."""
    def __getattr__(self, name):
        return getattr(os, name)

    def getuid(self):
        return 0

    def geteuid(self):
        return 0

    def fstat(self, fd):
        info = os.fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_uid=0)


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
        first, _ = destination.stage('a')
        path = store / first / 'intake.json'
        path.write_bytes(protocol.canonical(renewal.read_json(path)))
        initial = destination.resolve_site(destination.offer(first))
        for selector in ('current.json', 'site-current.json'):
            renewal.replace_json(control / selector, initial['release_sha256'])
        selector = runpy.run_path(str(local.TOOLS.parent / 'runtime/renewal/agent-candidate'))['controller_offer']
        native = {'calls': [], 'stage': {}, 'signed': {}, 'blobs': {}, 'artifacts': {}, 'run': None,
                  'occupied': False, 'installed': {}}
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
                with output.open('xb') as target:
                    target.write(blob)
                return None
            raise AssertionError(f'Unexpected endpoint {endpoint}')

        def attestation(path, digest, source, run, role, end):
            self.assertEqual((source, digest, path.read_bytes()), native['signed'][run])
            self.assertIn(role, ('maintenance', 'development'))
            native['calls'].append(('attested', run, role))

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
                (store / identity / 'installed.json').write_bytes(native['installed'][identity])
                native['calls'].append(('observed-install', identity))

        def resolve(offer):
            resolver = adapter['resolver']
            return resolver(offer, boot=destination.boot, hostname='erebus')

        adapter = {'resolver': destination.resolve.resolve}
        fixture_resolver = destination.resolve
        ordinary_json = publish.readonly_json
        with ExitStack() as stack:
            stack.enter_context(patch.object(bridge, 'os', FixtureOwner()))
            stack.enter_context(patch.object(intake, 'os', FixtureOwner()))
            stack.enter_context(patch.object(intake, 'file_hash', side_effect=lambda path, maximum, end, **kwargs:
                                            protocol.file_hash(path, maximum, end, owner=os.getuid())))
            stack.enter_context(patch.object(publish, 'readonly_json', side_effect=lambda path, owner=None: ordinary_json(path)))
            stack.enter_context(patch.object(renewal, 'DEFAULT_ROOT', destination.root))
            stack.enter_context(patch.object(site, 'Resolver', return_value=fixture_resolver))
            stack.enter_context(patch.object(fixture_resolver, 'resolve', side_effect=resolve))
            stack.enter_context(patch.object(intake, 'ROOT', store))
            stack.enter_context(patch.object(intake, 'GITHUB', '/usr/bin/python3'))
            stack.enter_context(patch.object(intake, 'protected', side_effect=lambda path, **kwargs: path))
            stack.enter_context(patch.object(intake, 'read_api', side_effect=query))
            stack.enter_context(patch.object(intake, 'verify_subject', side_effect=attestation))
            stack.enter_context(patch.object(publish, 'validate_image_part', side_effect=part))
            stack.enter_context(patch.object(publish, 'validate_host', return_value=destination.host_sha))
            stack.enter_context(patch.object(publish, 'source_checkout'))
            controller = bridge.Site(renewal, site, intake, protocol)
            stack.enter_context(patch.object(controller, 'run_tool', side_effect=native_runner))
            stack.enter_context(patch.object(controller, 'dispatch', side_effect=lambda: native['calls'].append(('dispatched',))))
            prior = first
            for (day, run_id, letter, version), event_name in zip(((26, 22, 'b', '2.0.0'), (27, 23, 'c', '3.0.0')), events):
                source = letter * 40
                on_demand = event_name == 'workflow_dispatch'
                run = scheduled.run_row(run_id, stamp(day, 19, 6), head_sha=source, event=event_name)
                native['run'] = run
                native['occupied'] = False
                self.assertEqual(controller.cycle(bridge.selection_window(stamp(day, 19), on_demand)),
                                 {'status': 'awaiting-publication'})
                staged, _ = destination.stage(letter, agent=True, base=first, stable=version, local_prior=prior, run=run_id)
                native['installed'][staged] = (store / staged / 'installed.json').read_bytes()
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
                self.assertIn(('attested', run_id, 'maintenance'), native['calls'])
                self.assertIn(('attested', run_id, 'development'), native['calls'])
                self.assertEqual(native['calls'][-1], ('dispatched',))
                with patch.dict(selector.__globals__, {'CONTROL': control, 'Resolver': lambda _: fixture_resolver,
                                                      'official_version': lambda: version}):
                    result = selector(destination.controller)
                self.assertEqual(result['status'], 'verified')
                request = destination.controller.active_request('agent')
                self.assertEqual(request['target_sha256'], result['release_sha256'])
                self.assertEqual(request['previous_sha256'], renewal.read_json(control / 'current.json'))
                for selector_name in ('current.json', 'site-current.json'):
                    renewal.replace_json(control / selector_name, result['release_sha256'])
                prior = staged
        self.assertEqual(len([leaf for leaf in store.iterdir() if len(leaf.name) == 64]), 3)
