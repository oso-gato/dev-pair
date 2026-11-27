"""Local destination boundary fixtures. No provider, firewall or registry mutations."""
import contextlib
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap as b
import destination_release as d
import release_trust as t

SOURCE = 'a' * 40
HEAD = 'b' * 40
DIGEST = 'c' * 64
IMAGE = f'ghcr.io/oso-gato/dev-pair/checklist@sha256:{DIGEST}'
WORKFLOW = '.github/workflows/checklist-release.yml'
DNS = 'erebus.tail123.ts.net'


def workflow_content(path, data):
    return {'path': path, 'type': 'file', 'encoding': 'base64', 'size': len(data),
            'content': base64.b64encode(data).decode()}


class BootstrapAccessTests(unittest.TestCase):
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
        required = '.github/workflows/fedora-vm.yml'
        check_bytes, publisher_bytes = b'name: independently pinned check\n', b'name: independently pinned publisher\n'
        check = {'context': 'fedora-vm', 'app_id': 123, 'workflow': required, 'sha256': hashlib.sha256(check_bytes).hexdigest()}
        self.publisher_hash = hashlib.sha256(publisher_bytes).hexdigest()
        self.values = {
            'branches/main': {'protected': True, 'commit': {'sha': SOURCE}},
            'branches/main/protection': {
                'enforce_admins': {'enabled': True}, 'allow_force_pushes': {'enabled': False},
                'allow_deletions': {'enabled': False}, 'required_status_checks': {'strict': True, 'checks': [{'context': 'fedora-vm', 'app_id': 123}]},
                'required_pull_request_reviews': {'dismiss_stale_reviews': True, 'require_last_push_approval': True,
                                                 'required_approving_review_count': 1}},
            f'commits/{SOURCE}/pulls?per_page=100': [
                {'number': 42, 'merge_commit_sha': SOURCE, 'base': {'ref': 'main', 'repo': {'full_name': t.REPOSITORY}},
                 'merged_at': '2026-11-27T12:00:00Z'}],
            'pulls/42': {'merged': True, 'merge_commit_sha': SOURCE, 'head': {'sha': HEAD},
                         'base': {'ref': 'main', 'repo': {'full_name': t.REPOSITORY}}, 'user': {'id': 100}, 'merged_by': {'id': 101}},
            'pulls/42/reviews?per_page=100': [{'id': 12, 'user': {'id': 111}, 'state': 'APPROVED', 'commit_id': HEAD}],
            f'contents/{required}?ref={HEAD}': workflow_content(required, check_bytes),
            f'contents/{WORKFLOW}?ref={SOURCE}': workflow_content(WORKFLOW, publisher_bytes),
            f'commits/{HEAD}/check-runs?filter=latest&per_page=100': {'check_runs': [
                {'id': 987, 'head_sha': HEAD, 'conclusion': 'success', 'name': 'fedora-vm', 'app': {'id': 123},
                 'details_url': f'https://github.com/{t.REPOSITORY}/actions/runs/456/job/987'}]},
            'actions/runs/456': {'path': required, 'head_sha': HEAD, 'event': 'pull_request', 'conclusion': 'success',
                                 'repository': {'full_name': t.REPOSITORY}},
            'environments/checklist-release': {'name': 'checklist-release', 'deployment_branch_policy': {
                'protected_branches': False, 'custom_branch_policies': True}},
            'environments/checklist-release/deployment-branch-policies?per_page=100': {'total_count': 1,
                'branch_policies': [{'name': 'main', 'type': 'branch'}]},
            'actions/runs/78': {'id': 78, 'run_attempt': 1, 'head_sha': SOURCE, 'head_branch': 'main', 'event': 'push',
                                'status': 'completed', 'conclusion': 'success', 'path': WORKFLOW,
                                'repository': {'full_name': t.REPOSITORY}, 'head_repository': {'full_name': t.REPOSITORY}}}
        self.check = check
        self.invocation = f'https://github.com/{t.REPOSITORY}/actions/runs/78/attempts/1'
        self.calls = []

    def policy(self, component):
        return {'reviewer_ids': [111], 'check': self.check, 'components': {
            'checklist': {'registry': IMAGE.split('@')[0], 'workflow': WORKFLOW, 'sha256': self.publisher_hash}}}

    def api(self, endpoint, *, pages=False):
        return self.values[endpoint]

    def run(self, *args, **kwargs):
        self.calls.append(args)
        return json.dumps([{'verificationResult': {'signature': {'certificate': {'extensions': {
            'runInvocationURI': self.invocation, 'buildTrigger': 'push'}}}}}])


class PublicationTests(unittest.TestCase):
    def test_exact_trusted_run_and_source_bind_verified_oci_digest(self):
        fixture = PublicationFixture()
        result = fixture.verify('checklist', SOURCE, IMAGE, 78)
        self.assertEqual(result['artifact_sha256'], DIGEST)
        self.assertEqual(result['review_head'], HEAD)
        (verification,) = fixture.calls
        self.assertIn('oci://' + IMAGE, verification)
        self.assertIn(t.REPOSITORY + '/' + WORKFLOW, verification)
        self.assertEqual(verification[verification.index('--source-digest') + 1], SOURCE)
        self.assertIn('--deny-self-hosted-runners', verification)
        fixture.invocation = fixture.invocation.replace('/attempts/1', '/attempts/2')
        with self.assertRaisesRegex(b.Blocked, 'exact trusted publication attempt'):
            fixture.verify('checklist', SOURCE, IMAGE, 78)

    def test_absent_gate_stale_approval_and_untrusted_check_deny_before_attestation(self):
        for mutation in ('protected', 'review', 'check', 'bypass', 'workflow-content', 'renamed-check', 'environment'):
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
                else:
                    fixture.values['environments/checklist-release/deployment-branch-policies?per_page=100']['branch_policies'][0]['name'] = '*'
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

    def test_failed_activation_restores_known_digest_and_preserves_active_record(self):
        app = d.Destination()
        old = {'version': 1, 'subject': IMAGE, 'source_sha': SOURCE, 'image_id': 'd' * 64, 'artifact_sha256': DIGEST,
               'compatibility': d.COMPATIBILITY, 'dns_name': DNS, 'verified_destination': True}
        proposed = {'version': 1, 'subject': IMAGE.replace(DIGEST, 'e' * 64), 'source_sha': HEAD,
                    'artifact_sha256': 'e' * 64}
        state = {'version': 1, 'active': old, 'previous': None, 'pending': None, 'confirmed': DIGEST}
        calls = []

        @contextlib.contextmanager
        def gate():
            yield {}, 1234, DNS

        def health(uid, dns, release):
            calls.append(('health', release['subject']))
            if release['subject'] == proposed['subject']:
                raise b.Blocked('unhealthy candidate')

        with patch.object(app, 'release_gate', gate), patch.object(app, 'initial_activation', return_value=state), \
                patch.object(app, 'serve_config', return_value=True), patch.object(d.ReleaseTrust, 'verify', return_value=proposed.copy()), \
                patch.object(d.ReleaseTrust, 'main'), patch.object(app, 'pull'), patch.object(app, 'image_identity', return_value=old['image_id']), \
                patch.object(app, 'render_unit', side_effect=lambda uid, dns, release: release['subject']), \
                patch.object(app, 'current_unit'), patch.object(app, 'backup', return_value='/fixture/backup'), \
                patch.object(app, 'save_activation', side_effect=lambda value: calls.append(('state', value.copy()))), \
                patch.object(app, 'install_unit', side_effect=lambda uid, dns, release, allowed: calls.append(('install', release['subject']))), \
                patch.object(app, 'health', health), patch.object(app, 'publish_route'), patch.object(app, 'prune_backup'):
            with self.assertRaisesRegex(b.Blocked, 'unhealthy candidate'):
                app.deploy(HEAD, proposed['subject'], 78, None)
        self.assertEqual([value for event, value in calls if event == 'install'], [proposed['subject'], IMAGE])
        self.assertIsNotNone(calls[0][1]['pending'])
        self.assertIsNone(calls[-1][1]['pending'])
        self.assertEqual(calls[-1][1]['active'], old)


if __name__ == '__main__':
    unittest.main()
