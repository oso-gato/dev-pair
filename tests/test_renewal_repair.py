"""Production parser and durable launch regressions on private local data."""
from contextlib import nullcontext
import fcntl
import json
import os
from pathlib import Path
import runpy
import select
import sqlite3
import subprocess
import sys
import tempfile
import shlex
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / 'tools'
SCRIPT = REPO / 'runtime' / 'renewal' / 'driver'
sys.path.insert(0, str(TOOLS))
import renewal as r
import bootstrap as b
import gptbox


class NativeRecoveryTests(unittest.TestCase):
    def test_direct_job_uses_the_existing_driver_inode_and_rechecks_after_revocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            host = gptbox.Gptbox(scratch)
            root = host.path('/var/lib/dev-pair')
            old = root / 'renewal' / 'driver.lock'
            current = root / r.protocol.WORKLOAD_LEASE
            flag = root / r.protocol.WORKLOAD_ACCESS
            host.directory('/var/lib/dev-pair/renewal', mode=0o700)
            host.atomic('/var/lib/dev-pair/renewal/driver.lock', '')
            host.atomic(b.STATE + '/prepared', 'fixture')
            roles = {'release_sha256': '1' * 64, 'maintenance_image': '2' * 64,
                     'development_image': '3' * 64, 'devbox_image': '4' * 64}
            with patch.object(b, 'checked_file', side_effect=Path):
                with old.open('rb') as legacy:
                    fcntl.flock(legacy, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    host.publish_workload_gate('admitted', roles)
                    self.assertEqual((old.stat().st_dev, old.stat().st_ino), (current.stat().st_dev, current.stat().st_ino))
                    with current.open('rb') as reader, self.assertRaises(BlockingIOError):
                        fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
            original_check = r.protocol.require_workload_access
            real_lstat, real_fstat = Path.lstat, os.fstat
            ancestry = {current.parent, *current.parents}

            def mapped_lstat(path):
                node = real_lstat(path)
                return SimpleNamespace(st_uid=0, st_mode=node.st_mode & ~0o022) if path in ancestry else node

            def mapped_fstat(fd):
                node = real_fstat(fd)
                if any((node.st_dev, node.st_ino) == (path.stat().st_dev, path.stat().st_ino) for path in (flag, current)):
                    return SimpleNamespace(st_uid=0, st_mode=node.st_mode, st_nlink=node.st_nlink,
                                           st_size=node.st_size, st_ino=node.st_ino, st_dev=node.st_dev)
                return node

            approved = flag.read_bytes()
            replacement = flag.with_suffix('.held')
            replacement.write_text(json.dumps({'schema': 1, 'phase': 'held', 'release_sha256': None, 'images': None}))
            replacement.chmod(0o644)

            def revoke_after_initial_check(*args, **kwargs):
                original_check(*args, **kwargs)
                if replacement.exists():
                    with r.protocol.workload_access_lease(root, exclusive=True):
                        os.replace(replacement, flag)

            options = ['--job', 'demo', '--operation', 'approved-turn', '--request-sha256', '5' * 64,
                       '--image', roles['maintenance_image'], '--context-sha256', '6' * 64, '--source-sha', '7' * 40]

            def during_preflight(*, managed_runtime):
                self.assertTrue(managed_runtime)
                with self.assertRaises(BlockingIOError), r.protocol.workload_access_lease(root, exclusive=True):
                    self.fail('activation entered before the admitted job released its lease')

            with (patch.object(gptbox, 'Gptbox', return_value=host), patch.object(Path, 'lstat', mapped_lstat),
                  patch.object(os, 'fstat', mapped_fstat), patch.object(host, 'lock', return_value=nullcontext()),
                  patch.object(host, 'preflight', side_effect=during_preflight) as prepare,
                  patch.object(host, 'run_job_locked', return_value={'turn': {'status': 'completed-turn'}}) as run):
                with patch.object(r.protocol, 'require_workload_access', side_effect=revoke_after_initial_check):
                    self.assertEqual(gptbox.run_job_cli(options), 2)
                    prepare.assert_not_called()
                    run.assert_not_called()
                flag.write_bytes(approved)
                with r.protocol.workload_access_lease(root):
                    self.assertEqual(gptbox.run_job_cli(options), 0)
                prepare.assert_called_once()
                run.assert_called_once()
                with r.protocol.workload_access_lease(root, exclusive=True):
                    pass

    def test_activation_holds_prior_public_grant_before_host_selector_or_service(self):
        activate = runpy.run_path(str(SCRIPT))['release_action']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control = root / 'renewal'
            (control / 'owned-turns').mkdir(parents=True, mode=0o700)
            host = b.Bootstrap(root)
            roles = {'release_sha256': '1' * 64, 'maintenance_image': '2' * 64,
                     'development_image': '3' * 64, 'devbox_image': '4' * 64}
            host.atomic(b.CUTOVER, json.dumps({'phase': 'complete', 'role_artifacts': roles}))
            host.publish_workload_gate('admitted', roles)
            marker = host.path('/var/lib/dev-pair/' + r.protocol.WORKLOAD_ACCESS)
            release = {'components': {'host': {'artifact_sha256': '5' * 64}}}
            target = '6' * 64
            payload = {'operation': 'approved-change', 'scope': 'host', 'release_sha256': target, 'release': release}

            def interrupted(_action, _name, **_):
                self.assertEqual(r.read_json(control / 'host-desired.json')['release_sha256'], target)
                self.assertEqual(json.loads(marker.read_text())['phase'], 'held')
                raise RuntimeError('interrupted during native host activation')

            with (patch.dict(activate.__globals__, {'CONTROL': control, 'ROOT': root,
                                                        'admit_release': lambda _: (release, {}), 'unit': interrupted,
                                                        'observe_host': Mock(side_effect=ValueError('new host'))}),
                  patch.object(b, 'Bootstrap', return_value=host),
                  patch.object(b, 'checked_file', side_effect=Path),
                  patch.object(r, 'Renewal', return_value=SimpleNamespace(transition=lambda: (None, None)))):
                with self.assertRaisesRegex(RuntimeError, 'interrupted during native host activation'):
                    activate('activate', payload)
            self.assertEqual(json.loads(marker.read_text())['phase'], 'held')
            self.assertFalse((control / 'site-current.json').exists())

    def test_private_role_probe_checks_real_named_route_then_dispatches_exact_offline_adapters(self):
        probe = runpy.run_path(str(SCRIPT))['access_probe']
        source = 'a' * 40
        identity = {'machine_id': 'b' * 32, 'boot_id': '5edb2370-cd2e-4f63-b180-b84db50f524b'}
        selection = {'release_sha256': '0' * 64, 'job': 'checklist', 'development_manifest': '1' * 64,
                     'maintenance_image': '2' * 64, 'development_image': '3' * 64, 'devbox_image': '4' * 64}
        claim = {'platform_sha256': '5' * 64, 'source_sha': source, 'oci_manifest_sha256': '6' * 64,
                 'boundary_and_version_cycles': 2, 'job_admission': False}
        peer = {'local': '100.64.0.10', 'device': 'tailscale0', 'core': True}
        live = {'TailscaleIPs': [peer['local']]}
        host = Mock()
        host.named_tailnet_peer.side_effect = b.Bootstrap().named_tailnet_peer
        host.observed_ssh_peer.return_value = peer
        host.tailscale_state.return_value = (live, 'erebus.fixture.ts.net')
        host.verify_final_guard.return_value = {'target': {'source_sha': source}, 'scope': 'core'}
        host.destination_identity.return_value = identity
        host.access_workload_selection.return_value = selection
        host.access_control_source.side_effect = lambda revision, guard: (
            self.assertEqual(revision, guard['target']['source_sha']))
        release = {'components': {'host': {}, 'maintenance-agent': {}, 'development-agent': {'codex_version': '0.170.0'}}}
        plan = {'maintenance_context_sha256': '7' * 64}
        development = {'kind': 'dev-pair-devbox-probe-v1', 'manifest_sha256': selection['development_manifest'],
                       'inner_image_id': selection['development_image'], 'outer_image_id': selection['devbox_image'],
                       'inner_removed': True, 'outer_removed': True, 'cycles': [{}, {}], 'job_admission': False}
        run = Mock(side_effect=[r.json_bytes({**claim, 'boot_id': identity['boot_id']}), r.json_bytes(development)])
        config = {'run': run, 'admit_release': lambda _: (release, plan), 'live_host': lambda _: (Path('/protected'), 100),
                  'retained_maintenance': lambda *_: (claim, identity['boot_id'], 'site'),
                  'private_devbox_probe': lambda *_: nullcontext()}
        with (patch.dict(probe.__globals__, config), patch.object(b, 'Bootstrap', return_value=host),
              patch.object(r, 'Renewal', return_value=SimpleNamespace(lock=nullcontext))):
            for role in ('maintenance', 'development'):
                actual = probe({'role': role, 'source_sha': source})
                self.assertEqual(actual, {'role': role, 'source_sha': source, **identity, 'role_artifacts': selection,
                                          'probe_cycles': 2, 'job_admission': False, 'address': peer['local']})
            maintain, develop = (call.args[0] for call in run.call_args_list)
            self.assertIn('verify-installed-maintenance', maintain)
            self.assertEqual(maintain[maintain.index('--image') + 1], selection['maintenance_image'])
            self.assertEqual(develop[:4], ['/usr/sbin/runuser', '--user', 'dp-dev', '--'])
            self.assertEqual(develop[-5:], ['--sha256', selection['development_manifest'], '--access-probe',
                                           '--probe-codex-version', '0.170.0'])
            self.assertNotIn('--operation', develop)
            host.observed_ssh_peer.return_value = {**peer, 'device': 'eth0'}
            with self.assertRaisesRegex(b.Blocked, 'named core tailnet'):
                probe({'role': 'maintenance', 'source_sha': source})
            self.assertEqual(run.call_count, 2)
        turn = probe.__globals__['turn']
        with (patch.object(b, 'Bootstrap', return_value=host),
              patch.object(host, 'verify_workload_access', side_effect=b.Blocked('independent workload access checks pending'))):
            with self.assertRaisesRegex(ValueError, 'independent workload access'):
                turn('turn', {})

    def test_only_exact_empty_probe_leaves_are_eligible_for_infrastructure_exclusion(self):
        check = runpy.run_path(str(SCRIPT))['check_probe_trees']
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for kind in ('workspaces', 'state', 'cache'):
                (root / 'maintenance' / kind / 'gptbox-probe').mkdir(parents=True, mode=0o700)
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            check(root, account)
            (root / 'maintenance' / 'state' / 'gptbox-probe' / 'state.sqlite3').touch()
            with self.assertRaisesRegex(ValueError, 'contains durable work'):
                check(root, account)

    def test_grant_requires_enough_full_cost_requests_for_the_product_tool_and_result(self):
        verify = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'continuity-grant'))['check_request_capacity']
        verify({'max_requests': 3, 'spend_microusd': 3264, 'max_request_bytes': 524288},
               1088, r.CONTINUITY_REQUESTS, 200000, 524288)
        for bad in ({'max_requests': 3, 'spend_microusd': 1}, {'max_requests': 3, 'spend_microusd': 2176},
                    {'max_requests': 1, 'spend_microusd': 1088}):
            with self.assertRaisesRegex(ValueError, 'cannot fund'):
                verify(bad, 1088, r.CONTINUITY_REQUESTS, 200000, 524288)

    def test_fully_funded_small_grant_cannot_carry_both_roles_saved_context(self):
        module = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'continuity-grant'))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(r, 'DEFAULT_ROOT', root):
                for role in r.ROLES:
                    ident = str(uuid.uuid4())
                    leaf = root / 'turn-inputs' / role / 'product' / 'resume'
                    startup = leaf / 'turn/startup'
                    for parent in (startup, leaf / 'requirements', leaf / 'loaders'):
                        parent.mkdir(parents=True)
                    doc = b'Approved deployment startup.\n' * 1024
                    (startup / 'project.txt').write_bytes(doc)
                    manifest = r.json_bytes({'documents': [{'id': 'project', 'bytes': len(doc), 'sha256': r.sha(doc)}]})
                    (startup / 'manifest.json').write_bytes(manifest)
                    data = {'requirements': (leaf / 'requirements/requirements.toml', b'policy requirements'),
                            'config': (leaf / 'loaders/config.toml', b'role policy'),
                            'prompt': (leaf / 'turn/prompt.txt', b'bounded continuation and observed tool result')}
                    for path, contents in data.values():
                        path.write_bytes(contents)
                    relative = Path('codex/sessions') / f'rollout-{ident}.jsonl'
                    rollout = root / role / 'state/product' / relative
                    rollout.parent.mkdir(parents=True)
                    raw = r.json_bytes({'type': 'response_item', 'payload': {'type': 'message', 'content': doc.decode()}}) + b'\n'
                    rollout.write_bytes(raw)
                    request = {'role': role, 'job': 'product', 'session_uuid': ident, 'startup_sha256': r.sha(manifest),
                               **{key + '_sha256': r.sha(contents) for key, (_, contents) in data.items()}}
                    retained = {'native_rollout': {'path': str(relative), 'bytes': len(raw), 'sha256': r.sha(raw)}}
                    inputs = module['capacity_inputs'](request, retained, SimpleNamespace(pw_uid=os.getuid()), leaf,
                                                       ('project',), 262144)
                    floor = module['request_body_floor'](*inputs, 128)
                    self.assertGreater(floor, len(raw))
                    grant = {'max_requests': 3, 'spend_microusd': 3264, 'max_request_bytes': 4096}
                    verify = module['check_request_capacity']
                    with self.assertRaisesRegex(ValueError, 'cannot carry the saved startup'):
                        verify(grant, 1088, r.CONTINUITY_REQUESTS, floor, 524288)
                    verify({**grant, 'max_request_bytes': floor}, 1088, r.CONTINUITY_REQUESTS, floor, 524288)
                    rollout.write_bytes(raw + b' ')
                    with self.assertRaisesRegex(ValueError, 'saved continuity transcript differs'):
                        module['capacity_inputs'](request, retained, SimpleNamespace(pw_uid=os.getuid()), leaf,
                                                  ('project',), 262144)

    def test_saved_checkpoint_baseline_executes_actual_healthy_and_failing_source(self):
        module = runpy.run_path(str(SCRIPT))
        source = (REPO / 'examples/checklist/checklist.py').read_bytes()
        baseline = module['product_baseline']
        original = subprocess.run

        def fixture_run(command, **kwargs):
            self.assertTrue({'--uid=dp-dev', '--property=PrivateNetwork=yes', '--property=ProtectSystem=strict',
                             '--property=SystemCallFilter=~@network-io'} <= set(command))
            return original(command[command.index('--') + 1:], **kwargs)

        action = module['product_command']('development', 'checklist-backup-restore')
        with patch.object(subprocess, 'run', side_effect=fixture_run):
            self.assertEqual(baseline('dp-dev', action, source), module['product_result']('development', r.sha(source)))
            failing = source.replace(b'"done": bool(done)', b'"done": not bool(done)')
            self.assertNotEqual(failing, source)
            result = baseline('dp-dev', action, failing)
            self.assertFalse(result['restored']['done'])
            self.assertNotEqual(result, module['product_result']('development', r.sha(failing)))

    def test_normal_driver_and_same_uuid_resume_keep_disjoint_operation_records(self):
        driver = runpy.run_path(str(SCRIPT))
        turn = driver['turn']
        g = turn.__globals__
        uid, gid = os.getuid(), os.getgid()
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            control = root / 'renewal'
            control.mkdir(mode=0o700)
            for folder in ('broker-requests', 'owned-turns', 'turn-launches', 'turn-receipts', 'provider-grants'):
                (control / folder).mkdir(mode=0o700)
            current = 'a' * 64
            r.replace_json(control / 'site-current.json', current)
            source = 'b' * 40
            parts = {'maintenance-agent': {'artifact_sha256': 'c'*64, 'source_revision': source, 'codex_version': '1.2.3',
                                           'platform_sha256': '0'*64},
                     'development-agent': {'artifact_sha256': 'd'*64, 'source_revision': source, 'codex_version': '1.2.3'},
                     'devbox': {'artifact_sha256': 'e'*64}, 'host': {'artifact_sha256': 'f'*64}}
            plan = {'maintenance_context_sha256': '5'*64, 'development_manifests': {'product': '6'*64}}
            started = []

            def broker(action, channel):
                if action == 'start':
                    owned = list((control / 'owned-turns').iterdir())
                    self.assertEqual(len(owned), 1)
                    record = r.read_json(owned[0])
                    if record['role'] == 'development':
                        self.assertEqual(record['development_owner'], '7'*64)
                    self.assertEqual(owned[0].name, r.role_operation_key(record['role'], record['job'], record['operation']))
                    started.append(channel)

            changes = {'ROOT': root, 'CONTROL': control,
                       'verify_workload_access': lambda *_: None,
                       'admit_release': lambda _: ({'components': parts}, plan),
                       'live_host': lambda _: (root, 100), 'unit': broker,
                       'owned_file': lambda path, limit, expected_uid=0: r.read_private(path, limit),
                       'require_provider_ready': lambda *_: None, 'reserve_development_owner': lambda *_: '7'*64,
                       'provider_receipt': lambda _, sha: r.sha(sha.encode()),
                       'stage_verification': lambda payload: payload['request_sha256'], 'continued_rollout': lambda *_: None,
                       'gptbox': SimpleNamespace(job_selection=lambda raw, *_: r.loads(raw),
                                                  completed_turn=lambda events: r.loads(events.splitlines()[0])['thread_id'])}
            for role in r.ROLES:
                self.assertNotEqual(r.role_operation_key(role, 'job--part', 'turn'),
                                    r.role_operation_key(role, 'job', 'part--turn'))
            session = {role: str(uuid.uuid4()) for role in r.ROLES}
            with patch.dict(g, changes), patch.object(r.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid, pw_gid=gid)):
                for role, action, operation in (('maintenance', 'turn', 'normal-m'), ('development', 'turn', 'normal-d'),
                                                ('development', 'resume-without-effects', 'rollback-d')):
                    active = session[role]
                    compound = role == 'development'
                    request = {'role': role, 'job': 'product', 'logical_session': role, 'operation': operation,
                               'session_uuid': active if action != 'turn' else None, 'provider': 'gptbox',
                               'model': 'gpt-6.2-sol', 'effort': 'high', 'standards_sha': r.STANDARDS,
                               'agreement_sha256': 'a'*64, 'startup_sha256': 'b'*64, 'config_sha256': 'c'*64,
                               'prompt_sha256': 'd'*64, 'candidate_sha': source}
                    request_sha = r.identity(request)
                    leaf = root / 'turn-inputs' / role / 'product' / operation / 'turn'
                    leaf.mkdir(mode=0o700, parents=True)
                    r.replace_json(leaf / 'request.json', request)
                    r.replace_json(control / 'provider-grants' / (request_sha + '.json'), {})
                    events = r.json_bytes({'thread_id': active})
                    proof = None
                    if action != 'turn':
                        expectation = driver['product_result'](role, 'f'*64)
                        command = shlex.join(driver['product_command'](role, expectation['recipe']))
                        reply = {'operation': operation, 'checkpoint': 'cp', 'recipe': expectation['recipe'],
                                 'next_state': 'retain-pending-host-check'}
                        proof = {'checkpoint': {'checkpoint_id': 'cp', 'checkpoint_sha256': '3'*64},
                                 'work': {'product_plan_sha256': 'a'*64, 'product_result': expectation},
                                 'pending_host': ['still-pending']}
                        events += b'\n' + r.json_bytes({'type': 'item.completed', 'item': {'type': 'command_execution',
                                                'command': command, 'exit_code': 0, 'aggregated_output': r.canonical(expectation)}})
                        events += b'\n' + r.json_bytes({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': r.canonical(reply)}})
                    event_hash = r.sha(events)
                    observed = {**request, 'session_uuid': active, 'request_sha256': request_sha, 'schema': 2,
                                'status': 'completed-turn', 'runtime_admitted': True, 'owned_cleanup': 'reaped',
                                'events_sha256': event_hash, 'events_bytes': len(events)}
                    stored = root / role / 'state' / 'product' / 'turns' / operation
                    stored.mkdir(mode=0o700, parents=True)
                    r.replace_json(stored / 'result.json', observed)
                    r.write_private(stored / 'events.jsonl', events)
                    common = {'turn': observed, 'codex_version': '1.2.3'}
                    report = common | ({'outer_removed': True, 'inner_removed': True, 'manifest_sha256': '6'*64,
                                        'outer_image_id': 'e'*64, 'inner_image_id': 'd'*64} if compound else
                                       {'runtime_container_removed': True, 'context_sha256': '5'*64, 'image_id': 'c'*64,
                                        'source_sha': source})
                    binding = {**request, 'policy_sha256': request['config_sha256'], 'job_id': 'product', 'credential_ref': 'mock'}
                    spec = {**request, 'release_sha256': current, 'binding': binding, 'request_sha256': request_sha, **(proof or {})}
                    def launch(command, **kwargs):
                        if role == 'maintenance':
                            self.assertEqual(command[command.index('--platform-sha256') + 1], '0'*64)
                        else:
                            self.assertNotIn('--platform-sha256', command)
                        return real_run([sys.executable, '-c', 'import sys; print(sys.argv[1])', r.canonical(report)], **kwargs)

                    with patch.object(subprocess, 'run', side_effect=launch):
                        result = turn(action, spec)
                    self.assertEqual(result['session_uuid'], active)
                    self.assertFalse(list((control / 'owned-turns').iterdir()))
                    if proof:
                        self.assertEqual(turn(action, spec), result)
                        self.assertEqual(result['product']['pending_host'], ['still-pending'])
            self.assertEqual(len(started), 3)
            self.assertEqual(len(list((control / 'turn-launches').iterdir())), 3)

    def test_rollback_archive_must_exist_as_exact_protected_file(self):
        verify = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'role-preflight'))['development_inputs']
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            manifest = path / 'manifest.json'
            archive = path / 'development.oci.tar'
            manifest.write_text('approved')
            manifest.chmod(0o444)
            with self.assertRaises(FileNotFoundError):
                verify(path, path.stat().st_dev, 3, owner=os.getuid())
            archive.write_bytes(b'oci')
            archive.chmod(0o444)
            self.assertEqual(verify(path, path.stat().st_dev, 3, owner=os.getuid()), (manifest, archive))
            with self.assertRaisesRegex(ValueError, 'length changed'):
                verify(path, path.stat().st_dev, 4, owner=os.getuid())

    def test_legacy_preflight_uses_normal_p_and_requires_actual_resource_record(self):
        import gptbox
        if not hasattr(gptbox.Gptbox, 'local_maintenance_completion'):
            self.skipTest('complete P legacy admission required')
        verify = runpy.run_path(str(REPO / 'runtime/renewal/role-preflight'))['maintenance']
        with tempfile.TemporaryDirectory() as temp:
            app = gptbox.Gptbox(root=Path(temp))
            context, revision, image = 'a'*64, 'b'*40, 'c'*64
            target = gptbox.ROOT + '/' + context
            scope = {'source_sha': revision, 'context_sha256': context, 'distrobox_sha': gptbox.DBX_SHA}
            labels = {'dev-pair.inputs': 'd'*64, 'dev-pair.runtime': 'e'*64, 'dev-pair.init': 'f'*64,
                      'dev-pair.codex.sha256': '0'*64, 'dev-pair.codex.version': '0.169.0'}
            build = {'kind': 'full-adapter-candidate', 'fedora_base': '1'*64, 'image_id': '2'*64,
                     **{key: labels[label] for key, label in (('inputs_sha256', 'dev-pair.inputs'),
                        ('runtime_sha256', 'dev-pair.runtime'), ('init_sha256', 'dev-pair.init'),
                        ('codex_sha256', 'dev-pair.codex.sha256'))}}
            names = {f'dp-gptbox-a-{context[:16]}-1': build['image_id'], f'dp-gptbox-r-{context[:16]}-1': image}
            records = {gptbox.STATE + '/prepared': {}, gptbox.STATE + '/gptbox-image.json': build,
                       target + '/candidate-image.json': build, target + '/attempt.json': {**scope, 'count': 1},
                       target + '/resources.json': names,
                       target + '/assembly-attestation.json': {'kind': 'genuine-distrobox-assembled', 'source_sha': revision,
                           'uid': 1000, 'gid': 1000, 'inputs_sha256': build['inputs_sha256'], 'packages_sha256': '3'*64},
                       target + '/result.json': {**scope, 'kind': 'maintenance-gptbox-probe-candidate',
                           'assembled_image_id': image, 'fedora_base': build['fedora_base'], 'runtime_container_id': '4'*64,
                           'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False,
                           'authentication': 'not verified', 'model_access': 'not verified', 'nested_placement': 'not verified',
                           'note': 'Probe-only candidate; no Codex job, credential or model request is admitted.'}}
            for path, row in records.items():
                file = app.path(path)
                file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                r.write_private(file, gptbox.image_inputs_bytes(row))
            app.path('/var/lib/dev-pair').chmod(0o755)
            engine = []
            preflights = []
            def observe_engine(*args, **options):
                self.assertEqual((args[:2], options['ok']), (('container', 'exists'), (1,)))
                engine.append(args[2])
            calls = {'preflight': lambda *, managed_runtime: preflights.append(managed_runtime), 'maintenance_gateway': lambda *_: None,
                     'check_prepared_record': lambda *_: None, 'prepared_build_files': lambda *_: None,
                     'maintenance_labels': lambda *_: labels, 'engine': observe_engine}
            spec = {'context_sha256': context, 'component': {'artifact_sha256': image, 'source_revision': revision,
                                                           'codex_version': '0.169.0'}}
            with patch.multiple(app, **calls), patch.object(gptbox, 'Gptbox', return_value=app):
                verify(spec)
                self.assertEqual(len(engine), 3)
                self.assertEqual(preflights, [True])
                resources = app.path(target + '/resources.json')
                resources.unlink()
                with self.assertRaises((FileNotFoundError, gptbox.Blocked)):
                    verify(spec)
                self.assertEqual(len(engine), 3)

    def test_handoff_observation_requires_a_live_listener_owned_by_the_exact_process(self):
        inspect = runpy.run_path(str(REPO / 'runtime' / 'renewal' / 'host-release'))['listen_inode']
        child_code = ('import socket, time; s=socket.socket(); s.bind(("127.0.0.1", 0));'
                      's.listen(); print(s.getsockname()[1],flush=True); time.sleep(30)')
        child = subprocess.Popen([sys.executable, '-c', child_code], stdout=subprocess.PIPE)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            port = int(child.stdout.readline())
            self.assertTrue(inspect(Path('/proc') / str(child.pid), port).isdigit())
            with self.assertRaisesRegex(ValueError, 'does not own'):
                inspect(Path('/proc/self'), port)
        finally:
            child.kill()
            child.wait(timeout=4)
            child.stdout.close()

    def test_native_database_and_rollouts_exist_without_sidecar_and_preserve_archives(self):
        module = runpy.run_path(str(SCRIPT))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'development' / 'state' / 'product'
            (base / 'sqlite').mkdir(parents=True)
            active, archived = (str(uuid.uuid4()) for _ in range(2))
            database = base / 'sqlite' / 'state_5.sqlite'
            with sqlite3.connect(database) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE threads (id TEXT, cwd TEXT, rollout_path TEXT, model_provider TEXT, archived INTEGER)')
                for index, ident in enumerate((active, archived)):
                    name = f'rollout-{ident}.jsonl'
                    relative = Path('codex') / ('archived_sessions' if index else 'sessions') / name
                    path = base / relative
                    path.parent.mkdir(parents=True)
                    path.write_bytes(r.json_bytes({'type': 'session_meta', 'payload': {'id': ident, 'cwd': '/work/job'}}) + b'\n')
                    db.execute('INSERT INTO threads VALUES (?,?,?,?,?)', (ident, '/work/job', '/state/' + str(relative), 'openai', index))
                db.commit()
                before = {p.name: p.read_bytes() for p in database.parent.iterdir()}
                rows, older = module['native_sessions'](base, os.getuid())
                self.assertEqual(set(rows), {active})
                self.assertEqual(set(older), {archived})
                self.assertEqual({p.name: p.read_bytes() for p in database.parent.iterdir()}, before)
            verify = module['verify_sessions']
            verify.__globals__['ROOT'] = root
            with patch.object(r.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())), \
                    self.assertRaisesRegex(ValueError, 'native Codex and registry'):
                verify({'role': 'development', 'job': 'product', 'sessions': [], 'binding': {}})

    def test_native_rollout_must_keep_original_bytes_and_advance(self):
        module = runpy.run_path(str(SCRIPT))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'development' / 'state' / 'product'
            ident = str(uuid.uuid4())
            relative = Path('codex/sessions') / f'rollout-{ident}.jsonl'
            path = base / relative
            path.parent.mkdir(parents=True)
            (base / 'sqlite').mkdir()
            original = r.json_bytes({'type': 'session_meta', 'payload': {'id': ident, 'cwd': '/work/job'}}) + b'\n'
            path.write_bytes(original)
            with sqlite3.connect(base / 'sqlite' / 'state_5.sqlite') as db:
                db.execute('CREATE TABLE threads (id TEXT, cwd TEXT, rollout_path TEXT, model_provider TEXT)')
                db.execute('INSERT INTO threads VALUES (?,?,?,?)', (ident, '/work/job', '/state/' + str(relative), 'openai'))
            verify = module['continued_rollout']
            verify.__globals__['ROOT'] = root
            payload = {'role': 'development', 'job': 'product', 'session_uuid': ident,
                       'native_rollout': {'bytes': len(original), 'sha256': r.sha(original), 'path': str(relative)}}
            with self.assertRaisesRegex(ValueError, 'did not advance'):
                verify(payload, os.getuid())
            with path.open('ab') as stream:
                stream.write(b'{"type":"response_item"}\n')
            verify(payload, os.getuid())
            path.write_bytes(original.replace(b'"session_meta"', b'"session_meta" ') + b'{"type":"response_item"}\n')
            with self.assertRaisesRegex(ValueError, 'replaced original'):
                verify(payload, os.getuid())

    def test_sigkill_between_rollback_operation_publications_and_launch_proof_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for folder in ('broker-requests', 'owned-turns', 'turn-launches'):
                (root / folder).mkdir(mode=0o700)
            operation = 'development--product--renew-rollback'
            owned = {'request_sha256': 'e' * 64, 'operation': 'renew-rollback'}
            broker = {'operation': 'renew-rollback'}
            common = ('import json,pathlib,runpy,subprocess,sys,time;'
                      'sys.path.insert(0, sys.argv[1]); import renewal as r;'
                      'driver=runpy.run_path(sys.argv[2]);root=pathlib.Path(sys.argv[3]);'
                      'key=sys.argv[4]; owned=json.loads(sys.argv[5]); broker=json.loads(sys.argv[6]);')
            first = (common + 'driver["install_exact"](root/"broker-requests"/(owned["request_sha256"]+".json"),broker);'
                     'print("broker-published",flush=True); time.sleep(30)')
            native = ('import json,pathlib,sys; path=pathlib.Path(sys.argv[1]);'
                      'path.open("a").write("one scoped effect\\n"); print(json.dumps({"completed":True}))')
            second = common + '\nnative = ' + repr(native) + '''
launches = driver['turn_root'](root,key,owned,broker)
def launch(output):
    with output.open('xb') as stream:
        subprocess.run([sys.executable, '-c', native, str(root/'effects')], stdout=stream, check=True)
    output.chmod(0o600)
report = driver['durable_launch'](launches,owned,launch,lambda:True)
assert report == {'completed': True}
print('wrapper-recorded',flush=True); time.sleep(30)
'''
            for code, token in ((first, b'broker-published'), (second, b'wrapper-recorded')):
                child = subprocess.Popen([sys.executable, '-c', code, str(TOOLS), str(SCRIPT), str(root),
                                          operation, json.dumps(owned), json.dumps(broker)], stdout=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 7)[0], 'child did not reach crash boundary')
                    self.assertEqual(child.stdout.readline().strip(), token)
                    child.kill()
                    self.assertEqual(child.wait(timeout=5), -9)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=4)
                    child.stdout.close()
            driver = runpy.run_path(str(SCRIPT))
            work = driver['turn_root'](root, operation, owned, broker)
            report = driver['durable_launch'](work, owned, lambda _: self.fail('paid replay'), lambda: False)
            self.assertEqual(report, {'completed': True})
            self.assertEqual((root / 'effects').read_text(), 'one scoped effect\n')
            (work / 'launcher.json').unlink()
            with self.assertRaisesRegex(ValueError, 'outcome is uncertain'):
                driver['durable_launch'](work, owned, lambda _: self.fail('uncertain replay'), lambda: False)


if __name__ == '__main__':
    unittest.main()
