"""Local destination boundary fixtures. No provider, firewall or registry mutations."""
import contextlib
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap as b
import commission_host as commission
import destination_release as d
from destination_observation import access_envelope
import job_protocol as jobs
import owner_day0
import release_trust as t
import renewal

SOURCE = 'a' * 40
HEAD = 'b' * 40
DIGEST = 'c' * 64
IMAGE = f'ghcr.io/oso-gato/dev-pair/checklist@sha256:{DIGEST}'
WORKFLOW = '.github/workflows/checklist-release.yml'
DNS = 'erebus.tail123.ts.net'
TESTED = 'd' * 40
TREE = 'e' * 40
GATE_WORKFLOW = '.github/workflows/release-check.yml'
BASE = {'image': 'ghcr.io/independent/checklist-base@sha256:' + '8' * 64, 'repo': 'independent/base-source',
        'workflow': '.github/workflows/base.yml', 'source': '9' * 40, 'ref': 'refs/heads/main'}
BASE_INVOCATION = 'https://github.com/independent/base-source/actions/runs/34/attempts/2'


def workflow_content(path, data):
    return {'path': path, 'type': 'file', 'encoding': 'base64', 'size': len(data),
            'content': base64.b64encode(data).decode()}


class BootstrapAccessTests(unittest.TestCase):
    def test_signed_core_cutover_preserves_workload_hold_then_admits_exact_full_proof(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temporary:
            root = Path(temporary)
            key, signers, receipt = (root / name for name in ('key', 'allowed_signers', 'receipt.json'))
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            signers.write_text('dev-pair-access-review ' + key.with_suffix('.pub').read_text())
            nft_commands = []
            fail_check = False

            def run(*args, input_text=None, **_):
                if args[0] == '/usr/bin/ssh-keygen':
                    return subprocess.run(args, input=input_text, capture_output=True, text=True, check=True).stdout
                if args[0] == '/usr/sbin/nft':
                    if fail_check and '--check' in args:
                        raise b.Blocked('fixture guard preflight failure')
                    nft_commands.append(args)
                return 'active'

            app = b.Bootstrap(root, run)
            access = ['192.0.2.44/32']
            historical = owner_day0.INITIAL_MAINTENANCE_SOURCE
            data = {'version': 1, 'source_sha': historical, 'machine_id': 'd' * 32, 'boot_id': '01234567-1234-5678-abcd-0123456789ab',
                    'issued_at': int(time.time()) - 5, 'expires_at': int(time.time()) + 600, 'node_id': 'node',
                    'tailnet': 'tail', 'dns_name': DNS, 'keys_sha256': '3' * 64, 'acl_sha256': '4' * 64,
                    'execution_route': 'provider-recovery', 'provider_recovery': 'hostinger://test-vps/recovery',
                    'public_addresses': {'ipv4': '8.8.4.4', 'ipv6': None},
                    'tailnet_addresses': {'ipv4': '100.64.0.5', 'ipv6': 'fd7a:115c:a1e0::5'}}
            role_selection = {'release_sha256': '5' * 64, 'maintenance_image': 'a' * 64, 'development_image': 'b' * 64,
                              'devbox_image': 'c' * 64, 'development_manifest': 'd' * 64, 'job': 'checklist'}

            def sign(core, *, legacy=False, **overrides):
                scope = b.CORE_ACCESS_CUTOVER if core else b.WORKLOAD_ACCESS_CUTOVER
                expected = app.access_probe_plan(DNS, data['provider_recovery'], data['public_addresses'], core_only=core)
                rows = [{'test': test, 'family': family, 'endpoint': endpoint, 'vantage': principal,
                         'client_id': 'fixture-' + principal, 'outcome': outcome, 'observed_at': data['issued_at'],
                         'evidence_sha256': 'a' * 64} for (test, family), (endpoint, principal, outcome) in expected.items()]
                payload = {**data, 'kind': scope, 'probes': rows, **overrides}
                if not core:
                    payload.setdefault('role_artifacts', role_selection)
                if legacy:
                    for field in ('kind', 'tailnet_addresses', 'role_artifacts'):
                        del payload[field]
                receipt.write_text(json.dumps(payload))
                signature = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'dev-pair-destination'],
                                           input=receipt.read_bytes(), capture_output=True, check=True).stdout
                receipt.with_suffix('.json.sig').write_bytes(signature)

            desired = json.dumps({'bootstrap_sources': access})
            app.directory('/var/lib/dev-pair', mode=0o755)
            app.directory(b.STATE, mode=0o700)
            app.directory('/var/lib/dev-pair/renewal', mode=0o700)
            app.atomic(b.STATE + '/prepared', desired)
            app.atomic(b.STATE + '/desired.json', desired)
            temporary_guard = app.guard_rules(access)
            app.atomic(b.GUARD_PATH, temporary_guard)
            read_selection = app.access_workload_selection
            with (patch.object(b, 'checked_file', side_effect=lambda path, **_: Path(path)),
                  patch.object(b, 'TRUST_SIGNERS', '/' + signers.name),
                  patch.object(b.os, 'geteuid', return_value=0),
                  patch.object(app, 'destination_source'),
                  patch.object(app, 'destination_identity', return_value={key: data[key] for key in ('machine_id', 'boot_id')}) as identity,
                  patch.object(app, 'tailscale_state', return_value=({'TailscaleIPs': list(data['tailnet_addresses'].values())}, DNS)),
                  patch.object(app, 'identity_fields', return_value=(data['tailnet'], data['node_id'])),
                  patch.object(app, 'access_keys_digest', return_value=data['keys_sha256']),
                  patch.object(app, 'observed_ssh_peer', return_value=None), patch.object(app, 'verify_final_ssh'),
                  patch.object(jobs, 'require_workload_access'),
                  patch.object(app, 'guard_hash', return_value='6' * 64),
                  patch.object(app, 'access_workload_selection', return_value=role_selection) as current):
                fail_check = True
                sign(True)
                with self.assertRaisesRegex(b.Blocked, 'fixture guard preflight'):
                    app.finalize(str(receipt))
                self.assertEqual(app.text(b.GUARD_PATH), temporary_guard)
                self.assertFalse(app.path(b.SSH_CUTOVER).exists())
                fail_check = False
                write = app.atomic

                def interrupt_after_guard(path, content, *args, **kwargs):
                    if path == b.CUTOVER and json.loads(content)['phase'] == 'complete':
                        raise RuntimeError('simulated interruption after applying guard')
                    return write(path, content, *args, **kwargs)

                with patch.object(app, 'atomic', side_effect=interrupt_after_guard):
                    with self.assertRaisesRegex(RuntimeError, 'after applying guard'):
                        app.finalize(str(receipt))
                pending = app.path(b.CUTOVER)
                original = pending.read_bytes()
                intent = json.loads(original)['intent']
                self.assertEqual(intent['kind'], b.CORE_ACCESS_CUTOVER)
                self.assertEqual(intent['claims']['boot_id'], data['boot_id'])
                self.assertEqual(app.text(b.GUARD_PATH), app.guard_rules([], tailnet_only=True))
                sign(False, legacy=True)
                with self.assertRaisesRegex(b.Blocked, 'requires matching scoped evidence'):
                    app.finalize(str(receipt))
                self.assertEqual(pending.read_bytes(), original)
                previous_boot = data['boot_id']
                data['boot_id'] = '01234567-1234-5678-abcd-0123456789ac'
                identity.return_value = {key: data[key] for key in ('machine_id', 'boot_id')}
                sign(True)
                with self.assertRaisesRegex(b.Blocked, 'requires matching scoped evidence'):
                    app.finalize(str(receipt))
                self.assertEqual(pending.read_bytes(), original)
                self.assertEqual(app.finalize(str(receipt), recover=True)['access_scope'], 'core')
                archived = json.loads(pending.read_bytes())['recovery_predecessor_sha256']
                self.assertEqual(app.path(b.STATE + '/cutover-recovery/' + archived + '.json').read_bytes(), original)
                app.atomic(b.CUTOVER, original.decode(), expected=pending.read_text())
                data['boot_id'] = previous_boot
                data['source_sha'] = SOURCE
                identity.return_value = {key: data[key] for key in ('machine_id', 'boot_id')}
                continuation = {'schema': 1, 'machine_id': data['machine_id'], 'controller_source_sha': SOURCE,
                                'maintenance_source_sha': historical, 'image_id': 'a' * 64, 'context_sha256': 'b' * 64,
                                'initializer_sha256': 'c' * 64, 'desired_sha256': 'd' * 64}
                day0_state = app.path('/var/lib/dev-pair-day0')
                day0_state.mkdir(mode=0o700)
                entry = owner_day0.DayZero(app=app)

                def response():
                    return io.BytesIO(access_envelope(receipt.read_bytes(), receipt.with_suffix('.json.sig').read_bytes()))

                with (patch.object(owner_day0, 'STATE', day0_state), patch.object(owner_day0, 'CUTOVER', str(pending)),
                      patch.object(owner_day0, 'local_file', side_effect=lambda path: path)):
                    sign(True)
                    with self.assertRaisesRegex(b.Blocked, 'access review source differs'):
                        entry.apply_access(SOURCE, historical, response(), workload=False)
                    self.assertEqual(pending.read_bytes(), original)
                    app.atomic('/var/lib/dev-pair-day0/continuation.json', json.dumps(continuation))
                    sign(True, acl_sha256='1' * 64)
                    with self.assertRaisesRegex(b.Blocked, 'requires matching scoped evidence'):
                        entry.apply_access(SOURCE, historical, response(), workload=False)
                    self.assertEqual(pending.read_bytes(), original)
                    sign(True, issued_at=data['issued_at'] + 1)
                    self.assertEqual(entry.apply_access(SOURCE, historical, response(), workload=False)['access_scope'], 'core')
                restored = json.loads(pending.read_bytes())
                self.assertEqual(restored['target']['source_sha'], SOURCE)
                self.assertEqual(restored['recovery_predecessor_sha256'], hashlib.sha256(original).hexdigest())
                self.assertEqual(app.path(b.STATE + '/cutover-recovery/' + restored['recovery_predecessor_sha256'] + '.json').read_bytes(), original)
                with self.assertRaisesRegex(b.Blocked, 'workload access'):
                    app.verify_workload_access()
                sign(False, legacy=True)
                with self.assertRaisesRegex(b.Blocked, 'separate exact signed workload'):
                    app.finalize(str(receipt))
                sign(False, role_artifacts={'release_sha256': '7' * 64})
                with self.assertRaisesRegex(b.Blocked, 'selected installed role'):
                    app.finalize(str(receipt))
                self.assertEqual(app.status()['access_scope'], 'core')
                sign(False)
                self.assertEqual(app.finalize(str(receipt))['access_scope'], 'full')
                self.assertEqual(app.verify_workload_access()['role_artifacts'], role_selection)
                marker = app.path('/var/lib/dev-pair/' + jobs.WORKLOAD_ACCESS)
                self.assertEqual(json.loads(marker.read_text())['release_sha256'], role_selection['release_sha256'])
                app.atomic('/var/lib/dev-pair/renewal/current.json', json.dumps(role_selection['release_sha256']))
                app.atomic('/var/lib/dev-pair/renewal/site-current.json', json.dumps('1' * 64))
                current.side_effect = read_selection
                with self.assertRaisesRegex(b.Blocked, 'not settled'):
                    app.refresh_workload_gate()
                self.assertEqual(json.loads(marker.read_text())['phase'], 'held')
                current.side_effect = None
                updated = {**role_selection, 'release_sha256': '7' * 64, 'development_image': '8' * 64}
                current.return_value = updated
                with self.assertRaisesRegex(b.Blocked, 'required for the current role placement'):
                    app.verify_workload_access()
                with self.assertRaisesRegex(b.Blocked, 'selected installed role'):
                    app.finalize(str(receipt))
                app.hold_changed_workload_access(updated['release_sha256'])
                self.assertEqual(json.loads(marker.read_text())['phase'], 'held')
                sign(False, role_artifacts=updated)
                self.assertEqual(app.finalize(str(receipt))['access_scope'], 'full')
                self.assertEqual(app.verify_workload_access()['role_artifacts'], updated)
                self.assertEqual(json.loads(marker.read_text())['images']['development'], updated['development_image'])
                app.hold_changed_workload_access('9' * 64)
                with patch.object(app, 'own_workload_rollback', return_value=False) as rollback:
                    app.restore_retained_workload_gate(updated['release_sha256'])
                    self.assertEqual(json.loads(marker.read_text())['phase'], 'held')
                    rollback.return_value = True
                    app.restore_retained_workload_gate(updated['release_sha256'])
                    self.assertEqual(json.loads(marker.read_text())['phase'], 'admitted')
                self.assertEqual(len([call for call in nft_commands if '--check' not in call]), 3)

                # The historical full first ceremony still works. Its known
                # managed baseline is retained and cannot follow a later selector.
                app.path(b.CUTOVER).unlink()
                app.path(b.SSH_CUTOVER).unlink()
                app.atomic(b.GUARD_PATH, temporary_guard, expected=app.text(b.GUARD_PATH))
                current.return_value = role_selection
                sign(False, legacy=True)
                with (patch.object(app, 'selected_workload_placement', return_value=role_selection),
                      patch.object(app, 'runtime_selected_host', return_value=(role_selection['release_sha256'], {}, {}))):
                    self.assertEqual(app.finalize(str(receipt))['access_scope'], 'full')
                self.assertEqual(json.loads(pending.read_bytes())['legacy_role_artifacts'], role_selection)
                self.assertEqual(json.loads(marker.read_text())['phase'], 'legacy')
                app.hold_changed_workload_access(updated['release_sha256'])
                current.return_value = updated
                app.refresh_workload_gate()
                self.assertEqual(json.loads(marker.read_text())['phase'], 'held')

                app.path(b.CUTOVER).unlink()
                app.path(b.SSH_CUTOVER).unlink()
                app.atomic(b.GUARD_PATH, temporary_guard, expected=app.text(b.GUARD_PATH))
                shutil.rmtree(app.path('/var/lib/dev-pair/renewal'))
                data['source_sha'] = historical
                sign(False, legacy=True)
                self.assertEqual(app.finalize(str(receipt))['access_scope'], 'full')
                recorded = json.loads(pending.read_bytes())
                self.assertEqual(recorded['legacy_origin'], 'standalone')
                # Project the original 11f persistence format after the real
                # signed legacy receipt has passed the complete cutover path.
                historical_fields = ('phase', 'target', 'guard_sha256', 'core_keys_sha256', 'acl_sha256',
                                     'provider_recovery', 'public_addresses', 'access_receipt_sha256')
                original = json.dumps({key: recorded[key] for key in historical_fields}, sort_keys=True) + '\n'
                app.atomic(b.CUTOVER, original, expected=pending.read_text())
                original_standalone = pending.read_bytes()
                approved = owner_day0.DayZero(app=app)
                self.assertTrue(approved.finalize())
                self.assertEqual(pending.read_bytes(), original_standalone)
                self.assertIsNone(json.loads(marker.read_text())['release_sha256'])

                app.directory(commission.CONTROL, mode=0o700)
                controller = renewal.Renewal(app.path('/var/lib/dev-pair'), None)
                first = commission.Commission(root, root, None, os.getuid(), SimpleNamespace(
                    renewal=lambda: controller, resolve_initial=lambda *_: role_selection['release_sha256'],
                    verify_selection=lambda *_: None))
                self.assertEqual(first.selectors({}, data['boot_id'], {}, None), role_selection['release_sha256'])
                self.assertEqual(controller.transition(), (None, None))
                self.assertTrue(approved.finalize())
                self.assertEqual(pending.read_bytes(), original_standalone)
                self.assertEqual(json.loads(marker.read_text())['phase'], 'held')

                current.return_value = role_selection
                data['source_sha'] = SOURCE
                sign(False)
                with self.assertRaisesRegex(b.Blocked, 'target conflict'):
                    app.finalize(str(receipt), previous_source='4' * 40)
                self.assertEqual(pending.read_bytes(), original_standalone)
                app.access_control_source(SOURCE, json.loads(original_standalone))
                archive_name = hashlib.sha256(original_standalone).hexdigest() + '.json'
                history = app.path(b.STATE + '/cutover-history/' + archive_name)

                def interrupt_after_history(path, content, *args, **kwargs):
                    if path == b.CUTOVER and 'role_artifacts' in json.loads(content):
                        self.assertEqual(history.read_bytes(), original_standalone)
                        raise RuntimeError('simulated interruption after archiving original cutover')
                    return write(path, content, *args, **kwargs)

                with patch.object(app, 'atomic', side_effect=interrupt_after_history):
                    with self.assertRaisesRegex(RuntimeError, 'after archiving original cutover'):
                        app.finalize(str(receipt), previous_source=historical)
                self.assertTrue(approved.finalize())
                self.assertEqual(pending.read_bytes(), original_standalone)
                self.assertEqual(json.loads(marker.read_text())['phase'], 'held')
                self.assertEqual(app.finalize(str(receipt), previous_source=historical)['access_scope'], 'full')
                accepted = json.loads(pending.read_bytes())
                self.assertEqual(accepted['target']['source_sha'], SOURCE)
                self.assertNotIn('legacy_origin', accepted)
                archived = b.STATE + '/cutover-history/' + accepted['predecessor_cutover_sha256'] + '.json'
                self.assertEqual(app.path(archived).read_bytes(), original_standalone)

    def test_stripped_ssh_binding_denies_existing_scoped_path(self):
        app = b.Bootstrap()
        with patch.dict(os.environ, {}, clear=True), patch.object(app, 'ssh_ancestors', return_value=[424]):
            with self.assertRaisesRegex(b.Blocked, 'preserve full SSH_CONNECTION'):
                app.validate_bootstrap_access(['192.0.2.1/32'])
        with patch.dict(os.environ, {'SSH_CLIENT': '192.0.2.1 42000 22'}, clear=True), patch.object(app, 'ssh_ancestors', return_value=[]):
            with self.assertRaisesRegex(b.Blocked, 'preserve full SSH_CONNECTION'):
                app.validate_bootstrap_access(['192.0.2.1/32'])

    def test_access_evidence_binds_distinct_roles_vantages_and_endpoint(self):
        app = b.Bootstrap()
        expected = app.access_probe_plan(DNS, 'hostinger://test-vps/recovery', {'ipv4': '8.8.4.4', 'ipv6': None})
        rows = [{'test': test, 'family': family, 'endpoint': endpoint, 'vantage': vantage, 'client_id': 'fixture-' + vantage,
                 'outcome': outcome, 'observed_at': 100, 'evidence_sha256': 'f' * 64}
                for (test, family), (endpoint, vantage, outcome) in expected.items()]
        app.verify_access_probes({'issued_at': 120, 'probes': rows}, expected)
        next(row for row in rows if row['vantage'] == 'denied')['client_id'] = 'fixture-authorized'
        with self.assertRaisesRegex(b.Blocked, 'reused client'):
            app.verify_access_probes({'issued_at': 120, 'probes': rows}, expected)

    def test_zero_public_ssh_requires_independent_provider_observation(self):
        app = b.Bootstrap()
        receipt = {'provider': 'hostinger', 'provider_vps_id': '42', 'transport': 'out-of-band',
                   'reopened_root': True, 'public_ssh_denied': True}
        with patch.dict(os.environ, {}, clear=True), patch.object(app, 'ssh_ancestor', return_value=False), \
                patch.object(app, 'recent_destination_evidence', return_value=receipt) as check:
            self.assertEqual(app.validate_bootstrap_access(None, '/root/receipt.json'), [])
            self.assertEqual(check.call_args.args[:2], ('/root/receipt.json', 'dev-pair-provider-console'))
            with self.assertRaises(b.Blocked):
                app.validate_bootstrap_access([])
            receipt['public_ssh_denied'] = False
            with self.assertRaises(b.Blocked):
                app.validate_bootstrap_access(None, '/root/receipt.json')
            with patch.dict(os.environ, {'SSH_CONNECTION': '192.0.2.1 65530 192.0.2.2 22'}):
                with self.assertRaises(b.Blocked):
                    app.validate_bootstrap_access(None, '/root/receipt.json')
            self.assertEqual(app.validate_bootstrap_access(['192.0.2.1/32']), ['192.0.2.1/32'])
        guard = app.guard_rules([], tailnet_only=True)
        self.assertLess(guard.index('tcp dport { 22, 443 } drop'), guard.index('ct state established'))
        self.assertIn('iifname "tailscale0" tcp dport { 22, 443 } accept', guard)
        self.assertIn('ip saddr 192.0.2.1/32 tcp dport 22 accept', app.guard_rules(['192.0.2.1/32']))
        self.assertNotIn('saddr', app.guard_rules([]))

    def test_actual_ssh_signature_binds_unchanged_evidence_and_role(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, signers, receipt = (root / leaf for leaf in ('key', 'allowed_signers', 'receipt.json'))
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            signers.write_text('dev-pair-provider-console ' + key.with_suffix('.pub').read_text())
            receipt.write_text('{"version":1,"provider":"hostinger"}\n')
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-Y', 'sign', '-f', str(key), '-n', 'dev-pair-destination',
                            str(receipt)], check=True, capture_output=True)
            app = b.Bootstrap()
            with patch.object(b, 'checked_file', side_effect=lambda path: Path(path)), patch.object(b, 'TRUST_SIGNERS', str(signers)):
                self.assertEqual(app.signed_evidence(str(receipt), 'dev-pair-provider-console', 'dev-pair-destination')['provider'], 'hostinger')
                with self.assertRaises(b.Blocked):
                    app.signed_evidence(str(receipt), 'dev-pair-access-review', 'dev-pair-destination')
                receipt.write_text('{"version":1,"provider":"changed"}\n')
                with self.assertRaises(b.Blocked):
                    app.signed_evidence(str(receipt), 'dev-pair-provider-console', 'dev-pair-destination')


class PublicationFixture(t.ReleaseTrust):
    def __init__(self):
        required = GATE_WORKFLOW
        check_bytes, publisher_bytes = b'name: independently pinned check\n', b'name: independently pinned publisher\n'
        check = {'context': 'release-source-check', 'app_id': 123, 'workflow': required, 'sha256': hashlib.sha256(check_bytes).hexdigest()}
        self.publisher_hash = hashlib.sha256(publisher_bytes).hexdigest()
        self.values = {
            'branches/main': {'protected': True, 'commit': {'sha': SOURCE}},
            'branches/main/protection': {
                'enforce_admins': {'enabled': True}, 'allow_force_pushes': {'enabled': False},
                'allow_deletions': {'enabled': False}, 'required_status_checks': {'strict': True, 'checks': [{'context': 'release-source-check', 'app_id': 123}]},
                'required_pull_request_reviews': {'dismiss_stale_reviews': True, 'require_last_push_approval': True,
                                                 'required_approving_review_count': 1}},
            f'commits/{SOURCE}/pulls?per_page=100': [
                {'number': 42, 'merge_commit_sha': SOURCE, 'base': {'ref': 'main', 'repo': {'full_name': t.REPOSITORY}},
                 'merged_at': '2026-11-27T12:00:00Z'}],
            'pulls/42': {'merged': True, 'merge_commit_sha': SOURCE, 'head': {'sha': HEAD},
                         'base': {'ref': 'main', 'repo': {'full_name': t.REPOSITORY}}, 'user': {'id': 100}, 'merged_by': {'id': 101}},
            'pulls/42/reviews?per_page=100': [{'id': 12, 'user': {'id': 111}, 'state': 'APPROVED', 'commit_id': HEAD}],
            f'contents/{required}?ref={TESTED}': workflow_content(required, check_bytes),
            f'contents/{WORKFLOW}?ref={SOURCE}': workflow_content(WORKFLOW, publisher_bytes),
            f'commits/{HEAD}/check-runs?filter=latest&per_page=100': {'check_runs': [
                {'id': 987, 'head_sha': HEAD, 'conclusion': 'success', 'name': 'release-source-check', 'app': {'id': 123},
                 'details_url': f'https://github.com/{t.REPOSITORY}/actions/runs/456/job/987'}]},
            'actions/runs/456': {'path': required, 'head_sha': HEAD, 'event': 'pull_request', 'conclusion': 'success',
                                 'repository': {'full_name': t.REPOSITORY}},
            'check-runs/987/annotations?per_page=100': [{'title': 'dev-pair-release-tree', 'annotation_level': 'notice',
                                                         'path': required, 'message': f'{HEAD}:{TESTED}:{TREE}:{TESTED}'}],
            f'git/commits/{TESTED}': {'sha': TESTED, 'tree': {'sha': TREE}, 'parents': [{'sha': 'f'*40}, {'sha': HEAD}]},
            f'git/commits/{HEAD}': {'sha': HEAD, 'tree': {'sha': TREE}},
            f'git/commits/{SOURCE}': {'sha': SOURCE, 'tree': {'sha': TREE}},
            'environments/checklist-release': {'name': 'checklist-release', 'deployment_branch_policy': {
                'protected_branches': False, 'custom_branch_policies': True}},
            'environments/checklist-release/deployment-branch-policies?per_page=100': {'total_count': 1,
                'branch_policies': [{'name': 'main', 'type': 'branch'}]},
            'environments/checklist-release/deployment_protection_rules': {'total_count': 1,
                'custom_deployment_protection_rules': [{'app': {'id': 77}, 'enabled': True}]},
            'actions/runs/78': {'id': 78, 'run_attempt': 1, 'head_sha': SOURCE, 'head_branch': 'main', 'event': 'push',
                                'status': 'completed', 'conclusion': 'success', 'path': WORKFLOW,
                                'repository': {'full_name': t.REPOSITORY}, 'head_repository': {'full_name': t.REPOSITORY}}}
        self.check = check
        self.invocation = f'https://github.com/{t.REPOSITORY}/actions/runs/78/attempts/1'
        self.base_invocation = BASE_INVOCATION
        self.base = {'version': 1, 'policy': BASE.copy(), 'invocation': BASE_INVOCATION}
        self.event = 'push'
        self.calls = []

    def policy(self, component):
        return {'reviewer_ids': [111], 'writer_app_id': 77, 'check': self.check, 'components': {
            'checklist': {'registry': IMAGE.split('@')[0], 'workflow': WORKFLOW, 'sha256': self.publisher_hash, 'base': BASE}}}

    def api(self, endpoint, *, pages=False):
        return self.values[endpoint]

    def run(self, *args, **kwargs):
        self.calls.append(args)
        invocation = self.base_invocation if args[3] == 'oci://' + BASE['image'] else self.invocation
        result = {'signature': {'certificate': {'extensions': {'runInvocationURI': invocation, 'buildTrigger': self.event}}}}
        if '--predicate-type' in args:
            result['statement'] = {'predicate': {'proof': self.base,
                                                 'proof_sha256': hashlib.sha256((t.canonical(self.base) + '\n').encode()).hexdigest()}}
        return json.dumps([{'verificationResult': result}])


class PublicationTests(unittest.TestCase):
    def test_exact_trusted_run_and_source_bind_verified_oci_digest(self):
        fixture = PublicationFixture()
        result = fixture.verify('checklist', SOURCE, IMAGE, 78)
        self.assertEqual(result['artifact_sha256'], DIGEST)
        self.assertEqual(result['review_head'], HEAD)
        verification, base_record, upstream = fixture.calls
        self.assertIn('oci://' + IMAGE, verification)
        self.assertIn(t.REPOSITORY + '/' + WORKFLOW, verification)
        self.assertEqual(verification[verification.index('--source-digest') + 1], SOURCE)
        self.assertIn('--deny-self-hosted-runners', verification)
        self.assertIn(t.BASE_PREDICATE, base_record)
        self.assertIn('oci://' + BASE['image'], upstream)
        self.assertEqual(result['base']['upstream_attempt'], BASE_INVOCATION)
        fixture.invocation = fixture.invocation.replace('/attempts/1', '/attempts/2')
        with self.assertRaisesRegex(b.Blocked, 'exact trusted publication attempt'):
            fixture.verify('checklist', SOURCE, IMAGE, 78)

    def test_release_rejects_wrong_base_label_policy_and_signature_attempt(self):
        fixture = PublicationFixture()
        fixture.base['policy']['image'] = BASE['image'].replace('8' * 64, '7' * 64)
        with self.assertRaisesRegex(b.Blocked, 'approved base evidence'):
            fixture.verify('checklist', SOURCE, IMAGE, 78)
        fixture = PublicationFixture()
        fixture.base_invocation = BASE_INVOCATION.replace('/attempts/2', '/attempts/1')
        with self.assertRaisesRegex(b.Blocked, 'upstream base signature'):
            fixture.verify('checklist', SOURCE, IMAGE, 78)
        app = d.Destination()
        metadata = {'Id': '8' * 64, 'Digest': 'sha256:' + DIGEST, 'RepoDigests': [IMAGE], 'Architecture': 'amd64', 'Os': 'linux',
                    'Labels': {'org.opencontainers.image.revision': SOURCE, 'dev-pair.data-compatibility': d.COMPATIBILITY}}
        base = {'image': BASE['image'], 'proof_sha256': '7' * 64}
        with patch.object(app, 'podman', side_effect=lambda *args: json.dumps([metadata])):
            with self.assertRaisesRegex(b.Blocked, 'independently verified signed base'):
                app.image_identity(1234, 'live', IMAGE, SOURCE, production=True, base=base)
            metadata['Labels'].update({'dev-pair.checklist.base': base['image'], 'dev-pair.checklist.base-proof': base['proof_sha256']})
            self.assertEqual(app.image_identity(1234, 'live', IMAGE, SOURCE, production=True, base=base), '8' * 64)

    def test_nightly_and_on_demand_are_only_admitted_for_independently_pinned_agent_workflow(self):
        for event in ('schedule', 'workflow_dispatch'):
            fixture = PublicationFixture()
            refresh = '.github/workflows/agent-refresh.yml'
            workflow = b'name: exact independent refresh\n'
            publisher = {'registry': None, 'workflow': WORKFLOW, 'sha256': fixture.publisher_hash,
                         'agent_refresh': {'workflow': refresh, 'sha256': hashlib.sha256(workflow).hexdigest()}}
            fixture.values['actions/runs/78'].update(event=event, path=refresh)
            fixture.values[f'contents/{refresh}?ref={SOURCE}'] = workflow_content(refresh, workflow)
            fixture.event = event
            original_policy = fixture.policy('checklist')
            policy = {**original_policy, 'components': {**original_policy['components'], 'maintenance': publisher}}
            with patch.object(fixture, 'policy', return_value=policy), patch.object(t, 'file_digest', return_value=DIGEST), \
                    patch.object(fixture, 'platform_subject', return_value={'portable_kind': 'dev-pair-agent-release'}):
                result = fixture.verify('maintenance', SOURCE, '/approved/platform.json', 78, artifact_sha256=DIGEST)
                self.assertEqual(result['workflow'], refresh)
                with self.assertRaisesRegex(b.Blocked, 'event lacks independent component authorization'):
                    fixture.verify('checklist', SOURCE, IMAGE, 78)

    def test_absent_gate_stale_approval_and_untrusted_check_deny_before_attestation(self):
        for mutation in ('protected', 'review', 'check', 'bypass', 'workflow-content', 'renamed-check', 'environment',
                         'tested-workflow', 'merged-tree', 'writer-rule', 'duplicate-tree-evidence'):
            with self.subTest(mutation=mutation):
                fixture = PublicationFixture()
                if mutation == 'protected':
                    fixture.values['branches/main']['protected'] = False
                elif mutation == 'review':
                    fixture.values['pulls/42/reviews?per_page=100'][0]['commit_id'] = 'f' * 40
                elif mutation == 'check':
                    fixture.values[f'commits/{HEAD}/check-runs?filter=latest&per_page=100']['check_runs'][0]['app']['id'] = 999
                elif mutation == 'bypass':
                    fixture.values['branches/main/protection']['required_pull_request_reviews']['bypass_pull_request_allowances'] = {'users': [{'id': 100}]}
                elif mutation == 'workflow-content':
                    fixture.values[f'contents/{WORKFLOW}?ref={SOURCE}'] = workflow_content(WORKFLOW, b'name: changed publisher\n')
                elif mutation == 'renamed-check':
                    fixture.values['actions/runs/456']['path'] = '.github/workflows/other.yml'
                elif mutation == 'environment':
                    fixture.values['environments/checklist-release/deployment-branch-policies?per_page=100']['branch_policies'][0]['name'] = '*'
                elif mutation == 'tested-workflow':
                    fixture.values[f'contents/{GATE_WORKFLOW}?ref={TESTED}'] = workflow_content(GATE_WORKFLOW, b'name: different executed check\n')
                elif mutation == 'merged-tree':
                    fixture.values[f'git/commits/{SOURCE}']['tree']['sha'] = 'f' * 40
                elif mutation == 'writer-rule':
                    fixture.values['environments/checklist-release/deployment_protection_rules']['custom_deployment_protection_rules'][0]['enabled'] = False
                else:
                    rows = fixture.values['check-runs/987/annotations?per_page=100']
                    rows.append(rows[0].copy())
                with self.assertRaises(b.Blocked):
                    fixture.verify('checklist', SOURCE, IMAGE, 78)
                self.assertEqual(fixture.calls, [])


class RolloutTests(unittest.TestCase):
    def test_proxy_only_accepts_exact_private_route(self):
        app = d.Destination()
        serve = {'TCP': {'443': {'HTTPS': True}}, 'Web': {f'{DNS}:443': {'Handlers': {'/': {'Proxy': d.PROXY}}}}}
        with patch.object(app, 'run', return_value=json.dumps(serve)):
            self.assertTrue(app.serve_config(DNS))
        serve['AllowFunnel'] = {f'{DNS}:443': True}
        with patch.object(app, 'run', return_value=json.dumps(serve)):
            with self.assertRaisesRegex(b.Blocked, 'Funnel'):
                app.serve_config(DNS)

    def local_database(self, path, title=None):
        tool = Path(__file__).resolve().parents[1] / 'examples/checklist/checklist.py'
        script = ("import contextlib,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import checklist as c\n"
                  "with contextlib.closing(c.connect(Path(sys.argv[2]))) as db:\n"
                  " c.initialize(db)\n"
                  " if sys.argv[3]: db.execute('INSERT INTO items(title,done) VALUES (?,1)',(sys.argv[3],)); db.commit()")
        subprocess.run(['/usr/bin/python3', '-IB', '-c', script, str(tool.parent), str(path), title or ''], check=True)

    def fixture(self, root, *, initial):
        code = Path(__file__).resolve().parents[1]
        database = root / 'data' / 'checklist.sqlite3'
        unit = root / 'fixture.container'
        database.parent.mkdir()
        (root / 'backups').mkdir()
        app = d.Destination()
        old = {'version': 1, 'subject': IMAGE, 'source_sha': SOURCE, 'image_id': 'd' * 64, 'artifact_sha256': DIGEST,
               'compatibility': d.COMPATIBILITY, 'dns_name': DNS, 'verified_destination': True}
        state = {'version': 2, 'active': None if initial else old, 'previous': None, 'pending': None,
                 'confirmed': None if initial else DIGEST, 'route_pending': False}
        route = [not initial]
        if not initial:
            unit.write_text(old['subject'])
            self.local_database(database, 'Existing completed item')

        @contextlib.contextmanager
        def gate():
            yield {'platform_sha': '9' * 40}, 1234, DNS

        def trust(component, source, image, run_id):
            return {'version': 1, 'subject': image, 'source_sha': source, 'artifact_sha256': image.rsplit(':', 1)[-1]}

        def role(uid, *args, **kwargs):
            return subprocess.run(args, check=True, capture_output=True, text=True).stdout

        def persist(value):
            state.clear()
            state.update(value)

        def effect(uid, dns, release, allowed):
            unit.write_text(release['subject'])
            if not database.exists():
                self.local_database(database, 'Rejected candidate item' if release['source_sha'] == HEAD else None)
            if release['source_sha'] == HEAD and not initial:
                with contextlib.closing(sqlite3.connect(database)) as db:
                    db.execute('DELETE FROM items')
                    db.commit()

        def run(*args, **kwargs):
            if args[:3] == (d.TAILSCALE, 'serve', '--https=443'):
                route[:] = [False]
            return ''

        def route_effect(dns):
            self.assertIsNone(state['pending'])
            self.assertTrue(state['route_pending'])
            route[:] = [True]

        def health(uid, dns, release, expected=None):
            if expected is not None:
                d.require(app.data_snapshot(uid, str(database)) == expected, 'unhealthy candidate changed items')

        replacements = {
            'release_gate': gate, 'initial_activation': lambda: state.copy(), 'serve_config': lambda dns: route[0],
            'run': run, 'pull': lambda *args: None, 'image_identity': lambda *args, **kwargs: 'd' * 64,
            'render_unit': lambda uid, dns, release: release['subject'], 'unit_path': lambda uid: str(unit),
            'user_unit': lambda *args: '', 'subprocess_role': role, 'save_activation': persist,
            'install_unit': effect, 'publish_route': route_effect, 'health': health,
        }
        self.enterContext(patch.object(d, 'LIVE', str(root)))
        self.enterContext(patch.object(d, 'CODE', str(code)))
        self.enterContext(patch.object(d, 'protect', side_effect=lambda path: Path(path)))
        self.enterContext(patch.object(d.ReleaseTrust, 'verify', side_effect=trust))
        self.enterContext(patch.object(d.ReleaseTrust, 'main'))
        for method, function in replacements.items():
            self.enterContext(patch.object(app, method, side_effect=function))
        return app, state, database, unit, route

    def test_failed_activation_restores_actual_completed_item_and_retains_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            app, state, database, unit, route = self.fixture(Path(directory), initial=False)
            proposed = IMAGE.replace(DIGEST, 'e' * 64)
            with self.assertRaisesRegex(b.Blocked, 'unhealthy candidate changed items'):
                app.deploy(HEAD, proposed, 78, None)
            with contextlib.closing(sqlite3.connect(database)) as db:
                self.assertEqual(db.execute('SELECT title,done FROM items').fetchall(), [('Existing completed item', 1)])
            self.assertTrue(Path(state['last_failed']['baseline']['path']).is_file())
            self.assertEqual(unit.read_text(), IMAGE)
            self.assertFalse(state['route_pending'])
            self.assertIsNone(state['pending'])
            self.assertTrue(route[0])

    def test_failed_first_release_archives_owned_data_and_allows_corrected_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            app, state, database, unit, route = self.fixture(Path(directory), initial=True)
            proposed = IMAGE.replace(DIGEST, 'e' * 64)
            with self.assertRaisesRegex(b.Blocked, 'unhealthy candidate changed items'):
                app.deploy(HEAD, proposed, 78, None)
            self.assertIsNone(state['pending'])
            self.assertIsNone(state['active'])
            self.assertFalse(route[0])
            self.assertFalse(unit.exists())
            self.assertFalse(database.exists())
            archive = state['last_failed']['data_archive']
            with contextlib.closing(sqlite3.connect(archive)) as db:
                self.assertEqual(db.execute('SELECT title FROM items').fetchall(), [('Rejected candidate item',)])
            result = app.deploy(SOURCE, IMAGE, 79, None)
            self.assertEqual(result['active']['subject'], IMAGE)
            self.assertIsNone(result['pending'])
            self.assertTrue(route[0])
            self.assertTrue(Path(archive).is_file())

    def test_proxy_publication_failure_after_promotion_preserves_accepted_write(self):
        with tempfile.TemporaryDirectory() as directory:
            app, state, database, _, route = self.fixture(Path(directory), initial=True)
            publish = app.publish_route

            def accepted_then_unobserved(dns):
                publish(dns)
                with contextlib.closing(sqlite3.connect(database)) as db:
                    db.execute("INSERT INTO items(title,done) VALUES('Accepted after promotion',1)")
                    db.commit()
                raise b.Blocked('proxy observation interrupted')

            with patch.object(app, 'publish_route', side_effect=accepted_then_unobserved):
                with self.assertRaisesRegex(b.Blocked, 'proxy observation interrupted'):
                    app.deploy(SOURCE, IMAGE, 78, None)
            self.assertTrue(state['route_pending'])
            self.assertIsNone(state['pending'])
            self.assertEqual(state['active']['subject'], IMAGE)
            app.deploy(SOURCE, IMAGE, 78, None)
            with contextlib.closing(sqlite3.connect(database)) as db:
                self.assertEqual(db.execute('SELECT title FROM items').fetchall(), [('Accepted after promotion',)])
            self.assertTrue(route[0])

    def test_interrupted_then_failed_reinstall_archives_both_and_restores_verified_item(self):
        with tempfile.TemporaryDirectory() as directory:
            app, state, database, unit, route = self.fixture(Path(directory), initial=False)
            proposed = IMAGE.replace(DIGEST, 'e' * 64)
            install = app.install_unit

            def interrupted(*args):
                install(*args)
                raise KeyboardInterrupt()

            with patch.object(app, 'install_unit', side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    app.deploy(HEAD, proposed, 78, None)
            self.assertEqual(state['pending']['phase'], 'prepared')
            self.assertFalse(route[0])
            with self.assertRaisesRegex(b.Blocked, 'unhealthy candidate changed items'):
                app.deploy(HEAD, proposed, 78, None)
            self.assertIsNone(state['pending'])
            self.assertTrue(route[0])
            self.assertEqual(unit.read_text(), IMAGE)
            self.assertEqual(len(list((Path(directory) / 'backups').glob('*.failed-sqlite3.*'))), 2)
            with contextlib.closing(sqlite3.connect(database)) as db:
                self.assertEqual(db.execute('SELECT title,done FROM items').fetchall(), [('Existing completed item', 1)])

    def test_external_first_rejection_quiesces_owned_release_and_admits_data_preserving_correction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app, state, database, unit, route = self.fixture(root, initial=True)
            app.deploy(SOURCE, IMAGE, 78, None)
            with contextlib.closing(sqlite3.connect(database)) as db:
                db.execute("INSERT INTO items(title,done) VALUES('Accepted browser item',1)")
                db.commit()
            evidence = root / 'review.json'
            evidence.write_text('fixture signed rejection')
            rejected = {'source_sha': '9' * 40, 'release_source': SOURCE, 'image': IMAGE, 'dns_name': DNS,
                        'failed_check': 'tailnet-loss', 'observation_sha256': '7' * 64}
            with patch.object(app, 'recent_destination_evidence', return_value=rejected):
                app.reject(str(evidence))
            self.assertTrue(state['active']['quarantined'])
            self.assertIsNone(state['pending'])
            self.assertFalse(route[0])
            self.assertFalse(unit.exists())
            self.assertTrue(Path(state['last_rejected']['baseline']['path']).is_file())
            corrected = IMAGE.replace(DIGEST, 'f' * 64)
            result = app.deploy('7' * 40, corrected, 79, None)
            self.assertEqual(result['active']['subject'], corrected)
            self.assertIsNone(result['previous'])
            self.assertTrue(route[0])
            with contextlib.closing(sqlite3.connect(database)) as db:
                self.assertEqual(db.execute('SELECT title,done FROM items').fetchall(), [('Accepted browser item', 1)])

    def test_maximum_multilingual_inventory_uses_real_capture_http_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app, _, database, _, _ = self.fixture(root, initial=False)
            title = '📋' * 120
            with contextlib.closing(sqlite3.connect(database)) as db:
                db.execute('DELETE FROM items')
                db.executemany('INSERT INTO items(title,done) VALUES (?,1)', [(title,)] * 1000)
                db.commit()
            commands = b.Commands()
            with patch.object(app, 'subprocess_role', side_effect=lambda _uid, *args, **kwargs: commands(*args, **kwargs)):
                expected = app.data_snapshot(1234, str(database))
                backup = app.backup(1234, '2' * 32)
                self.assertEqual(backup['inventory_sha256'], expected)
                with contextlib.closing(sqlite3.connect(database)) as db:
                    db.execute('DELETE FROM items')
                    db.commit()
                app.restore_failed_data(1234, {'baseline': backup, 'attempt': '2' * 32})
                self.assertEqual(app.data_snapshot(1234, str(database)), expected)
            tool = Path(__file__).resolve().parents[1] / 'examples/checklist/checklist.py'
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                port = listener.getsockname()[1]
                command = ['/usr/bin/python3', '-IB', str(tool), 'serve', '--database', str(database),
                           '--listen-fd', str(listener.fileno())]
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      pass_fds=(listener.fileno(),)) as process:
                    try:
                        self.assertTrue(select.select([process.stdout], [], [], 5)[0])
                        self.assertEqual(process.stdout.readline().strip(), f'http://127.0.0.1:{port}')
                        with patch.object(d, 'PORT', port):
                            self.assertEqual(app.browser_inventory(f'127.0.0.1:{port}'), expected)
                    finally:
                        process.terminate()
                        process.communicate(timeout=5)


class ProvisioningTests(unittest.TestCase):
    def test_completed_transition_is_preserved_before_mounted_copy_and_unrelated_data_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            root = home / 'dev-pair'; root.mkdir()
            old = root / 'selinux-bootstrap'; old.mkdir()
            contents = {name: name + '\n' for name in ('intent.json', 'complete.json', 'relabel-done.json', 'config-original', 'lock')}
            for name, value in contents.items():
                (old / name).write_text(value)
            original = home / 'selinux-preserved'
            receipt = home / 'managed.json'
            ready = root / '.managed-storage-ready'
            digest = {name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in contents.items()}
            previous = (str(old), contents, digest)
            app = d.Destination()
            steps = []

            def mount(where, spec, **kwargs):
                self.assertTrue(original.is_dir())
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(json.loads(receipt.read_bytes())['transition'], digest)
                steps.append('mount')

            args = SimpleNamespace(managed_mib=2048, managed_inodes=8192, reserve_inodes=4096)
            with patch.object(d, 'ROOT', str(root)), patch.object(d, 'TRANSITION', str(old)), \
                    patch.object(d, 'PRESERVED_TRANSITION', str(original)), patch.object(d, 'MANAGED_INTENT', str(receipt)), \
                    patch.object(d, 'MANAGED_READY', str(ready)), patch.object(app, 'mount', side_effect=mount), \
                    patch.object(app, 'allocate', side_effect=lambda *args: steps.append('allocated')), \
                    patch.object(app, 'directory', side_effect=lambda path, mode=0o700: Path(path).mkdir(mode=mode, exist_ok=True)), \
                    patch.object(app, 'atomic', side_effect=lambda path, raw, **kwargs: Path(path).write_text(raw)), \
                    patch.object(app, 'run', side_effect=lambda *args, **kwargs: '/dev/loop7\n' if '--find' in args else 'Enforcing\n'), \
                    patch.object(app, 'transition_contents', side_effect=lambda where: {p.name: p.read_text() for p in Path(where).iterdir()}), \
                    patch.object(app, 'destination_identity', return_value={'machine_id': 'fixture-machine'}):
                unrelated = root / 'owner-file'
                unrelated.write_text('preserve unrelated')
                with self.assertRaisesRegex(b.Blocked, 'hide unrelated'):
                    app.enroll_managed_storage(args, None, False, previous)
                self.assertEqual(unrelated.read_text(), 'preserve unrelated')
                self.assertFalse(steps)
                unrelated.unlink()
                self.assertTrue(app.enroll_managed_storage(args, None, False, previous)['preserved_transition'])
            self.assertEqual(steps, ['allocated', 'mount'])
            self.assertEqual({p.name: p.read_text() for p in original.iterdir()}, contents)
            self.assertEqual({p.name: p.read_text() for p in old.iterdir()}, contents)
            self.assertEqual(ready.read_bytes(), receipt.read_bytes())

    def test_direct_to_managed_waits_for_observation_and_unfenced_recovery_without_reinitializing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / 'executor'; home.mkdir()
            (home / 'execution-history').mkdir(mode=0o700)
            fence = root / 'fence'; fence.mkdir()
            marker = fence / 'frozen'
            requested = root / 'managed-listener.json'
            current = root / 'site-current.json'
            current.write_text(json.dumps('a' * 64))
            app = d.Destination()
            effects = []
            jobs = {d.U_OBSERVE: (False, 'success'), d.U_RECOVERY: (False, 'success')}
            started = [100]
            enabled = [False]

            def systemctl(*args, **kwargs):
                self.assertEqual(args[0], d.SYSTEMCTL)
                effects.append(args[1:])
                if args[-1] == d.U_BOOT_FENCE and args[1] == 'restart':
                    marker.write_text(json.dumps('boot'))
                if args[-1] in jobs:
                    if args[-1] == d.U_OBSERVE:
                        self.assertEqual(json.loads(marker.read_text()), 'boot')
                    if args[-1] == d.U_RECOVERY and args[1] == 'enable':
                        self.assertEqual(json.loads(marker.read_text()), 'boot')
                        enabled[0] = True
                        started[0] = 110
                    if args[1] == 'is-enabled':
                        return 'enabled\n' if enabled[0] else 'disabled\n'
                    jobs[args[-1]] = (True, 'success')
                return ''

            with patch.object(d, 'HOME', str(home)), patch.object(d, 'FENCE', str(fence)), patch.object(d, 'RENEWAL', str(root)), \
                    patch.object(d, 'MANAGED_LISTENER', str(requested)), patch.object(app, 'run', side_effect=systemctl), \
                    patch.object(app, 'record', side_effect=lambda path: json.loads(Path(path).read_text())), \
                    patch.object(app, 'atomic', side_effect=lambda path, raw, **kwargs: Path(path).write_text(raw)), \
                    patch.object(app, 'subprocess_role') as initializer, \
                    patch.object(app, 'destination_identity', return_value={'boot_id': 'fixture-boot'}), \
                    patch.object(app, 'recovery_start', side_effect=lambda: started[0]), \
                    patch.object(app, 'manager_job', side_effect=lambda unit: jobs[unit]), \
                    patch.object(app, 'verify_managed_executor', side_effect=lambda *_args: effects.append(('observed',))):
                uid = os.getuid()
                unit, queued = app.start_executor(uid, True, True)
                self.assertEqual(queued, 'host-observation-queued')
                self.assertEqual(app.start_executor(uid, True, True)[1], 'host-observation-running')
                jobs[d.U_OBSERVE] = (False, 'success')
                marker.unlink()  # An older consumed marker must not bypass the recovery queue.
                self.assertEqual(app.start_executor(uid, True, True)[1], 'renewal-readback-queued')
                self.assertEqual(app.start_executor(uid, True, True)[1], 'renewal-readback-running')
                jobs[d.U_RECOVERY] = (False, 'success')
                self.assertEqual(app.start_executor(uid, True, True)[1], 'renewal-readback-fenced')
                marker.unlink()
                started[0] = 100
                with self.assertRaisesRegex(b.Blocked, 'fresh successful manager witness'):
                    app.start_executor(uid, True, True)
                started[0] = 110
                enabled[0] = False
                with self.assertRaisesRegex(b.Blocked, 'not enabled'):
                    app.start_executor(uid, True, True)
                enabled[0] = True
                self.assertEqual(app.start_executor(uid, True, True)[1], 'ready')
                initializer.assert_not_called()
            self.assertEqual(effects[:6], [('enable', unit), ('restart', d.U_BOOT_FENCE),
                                          ('start', '--no-block', d.U_OBSERVE), ('observed',),
                                          ('restart', d.U_BOOT_FENCE),
                                          ('enable', '--now', '--no-block', d.U_RECOVERY)])
            self.assertEqual(json.loads(requested.read_bytes())['phase'], 'ready')

    def test_existing_owned_fence_is_preserved_and_foreign_fence_is_rejected(self):
        app = d.Destination()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'frozen'
            marker.write_text('"boot"\n')
            with patch.object(d, 'FENCE', directory), patch.object(app, 'run') as runner, \
                    patch.object(app, 'record', side_effect=lambda path: json.loads(Path(path).read_text())):
                app.ensure_boot_fence()
                marker.write_text('"different active renewal"\n')
                with self.assertRaisesRegex(b.Blocked, 'owned boot dispatch fence'):
                    app.ensure_boot_fence()
                runner.assert_not_called()

    def test_restrictive_umask_preserves_traversable_code_and_quadlet_ancestors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = b.Bootstrap(root)
            original = os.umask(0o077)
            try:
                code = root / 'usr/libexec/dev-pair/checklist/tools/host_handoff.py'
                unit = root / 'etc/containers/systemd/users/1940/checklist.container'
                for path in (code, unit):
                    app.atomic('/' + str(path.relative_to(root)), 'test bytes\n', mode=0o644)
                private = root / 'var/lib/dev-pair/checklist-executor'
                app.directory('/' + str(private.relative_to(root)))
            finally:
                os.umask(original)
            for path in (code, unit):
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                for parent in path.parents:
                    if parent == root:
                        break
                    self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(private.parent.stat().st_mode & 0o777, 0o755)

    def test_populated_private_ancestor_grants_only_named_search_and_retains_signer_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            app = d.Destination(root)
            fixed = root / 'etc/dev-pair'
            original = os.umask(0o077)
            try:
                signer = fixed / 'trust/allowed_signers'
                signer.parent.mkdir(parents=True)
                signer.write_text('fixture signing material')
                path = fixed / 'checklist/validation-containers.conf'
                app.atomic('/etc/dev-pair/checklist/validation-containers.conf', 'fixture public config\n', mode=0o644)
            finally:
                os.umask(original)
            (root / 'etc').chmod(0o755)
            acl = ['user::rwx', 'group::---', 'other::---']
            calls = []

            def run(*args, **kwargs):
                calls.append(args)
                if args[0].endswith('getfacl'):
                    return '\n'.join(acl) + '\n'
                self.assertEqual(args[2], 'user:1940:--x')
                acl[:] = ['user::rwx', 'user:1940:--x', 'group::---', 'mask::--x', 'other::---']

            with patch.object(d, 'ROLE_ANCESTORS', (fixed,)), patch.object(app, 'role_path_info', side_effect=lambda p: p.lstat()), \
                    patch.object(app, 'run', side_effect=run):
                unrelated = fixed / 'unrelated-config'
                unrelated.write_text('must not be exposed')
                unrelated.chmod(0o644)
                with self.assertRaisesRegex(b.Blocked, 'expose an unrelated'):
                    app.role_search_plan([str(path)], [], 1940)
                self.assertFalse(any(command[0].endswith('setfacl') for command in calls))
                unrelated.chmod(0o600)
                grants, hidden = app.role_search_plan([str(path)], [], 1940)
                self.assertEqual([item[0] for item in grants], [fixed])
                self.assertEqual(set(hidden), {str(signer.parent), str(unrelated)})
                app.grant_role_search(grants, 1940)
                self.assertEqual(app.role_search_plan([str(path)], [], 1940)[0], [])
            self.assertEqual(signer.read_text(), 'fixture signing material')
            self.assertEqual(signer.stat().st_mode & 0o777, 0o600)
            self.assertEqual(signer.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_role_probe_opens_exact_bytes_and_rejects_digest_or_actor_mismatch(self):
        app = d.Destination()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / 'peer.pem'
            public.write_text('fixture certificate')
            digest = hashlib.sha256(public.read_bytes()).hexdigest()
            commands = b.Commands()
            with patch.object(app, 'subprocess_role', side_effect=lambda _uid, *args, **kwargs: commands(*args, **kwargs)):
                app.verify_role_paths(os.getuid(), {str(public): digest}, [directory], [str(root / 'unreachable')])
                with self.assertRaises(b.Blocked):
                    app.verify_role_paths(os.getuid(), {str(public): '0' * 64}, [directory], [])
                with self.assertRaises(b.Blocked):
                    app.verify_role_paths(os.getuid() + 1, {str(public): digest}, [directory], [])

    def test_primary_identity_cannot_overlap_earlier_subordinate_block(self):
        app = d.Destination()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'subids'
            source.write_text('other-identity:1400:800\n')
            with patch.object(d, 'protect', side_effect=lambda path: Path(path)):
                with self.assertRaisesRegex(b.Blocked, 'primary or subordinate'):
                    app.subid(source, None, 1500, 90000, [])

    def test_canonical_fedora_sudo_denial_has_success_exit_and_complete_text(self):
        package = b.sudo_package_projection(b'sudo\t1.9.17\t7.p2.fc44\tx86_64\n', b'', True, 0)
        args = {'native_status': None, 'relay_verified': False, 'host_verified': True,
                'package': package, 'execution_kind': 'direct', 'complete': True}
        expected = b'User dp-checklist is not allowed to run sudo on erebus.\n'
        self.assertEqual(b.sudo_denial_projection('dp-checklist', expected, b'', status=0, **args)['outcome'], 'denied')
        self.assertEqual(b.sudo_denial_projection('dp-checklist', b'', b'sudo: error', status=1, **args)['outcome'], 'blocked')

    def test_unrecorded_backing_bytes_never_reach_format(self):
        app = d.Destination()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'unowned.ext4'
            image.write_bytes(b'preserve me')
            spec = {'image': str(image), 'mib': 128, 'inodes': 1024, 'uuid': 'fixture'}
            with patch.object(app, 'run') as runner:
                with self.assertRaises(FileExistsError):
                    app.allocate(spec, str(image) + '.receipt', 1, 128)
                runner.assert_not_called()
            self.assertEqual(image.read_bytes(), b'preserve me')


if __name__ == '__main__':
    unittest.main()
