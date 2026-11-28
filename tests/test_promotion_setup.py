"""Check attended promotion admission and independent receipt custody without remote writes."""
import base64
from contextlib import nullcontext
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checklist_proposal as proposer
import commission_host as commission
import destination_observation as station
import job_protocol as p
import product_release as release
import promotion_setup as setup
from release_trust import ReleaseTrust

REPOSITORY = 'oso-gato/dev-pair'
FORK = 'scoped-organization/dev-pair'
DNS = 'erebus.example.ts.net'
TOKENS = ['github_pat_' + letter * 36 for letter in 'FRO']
JOB = 'first-checklist'
BASE = 'a' * 40
CHECK = '.github/workflows/release-check.yml'
CHECK_BYTES, MERGE_BYTES, PUBLISH_BYTES = b'exact check', b'exact merge', b'exact publisher'


def approval():
    return {'developer_login': 'scoped-developer', 'observer_login': 'separate-observer', 'fork': FORK,
            'merge_actor_id': 30, 'merge_gate_app_id': 302, 'merge_workflow_sha256': p.sha256(MERGE_BYTES),
            'dns_name': DNS, 'expires_unix': int(time.time()) + 600}


def selected_site():
    site = approval()
    del site['observer_login']
    return {**site, 'version': 1, 'repository': REPOSITORY, 'developer_id': 10, 'observer_id': 20}


class UpstreamPreflight(unittest.TestCase):
    def setUp(self):
        self.rules = {'check': {'workflow': CHECK, 'sha256': p.sha256(CHECK_BYTES), 'context': 'release-source-check',
                                'app_id': 14}, 'components': {'checklist': {'workflow': release.PUBLISHER,
                            'registry': release.REGISTRY, 'sha256': p.sha256(PUBLISH_BYTES)}},
                      'writer_app_id': 303, 'reviewer_ids': [40]}
        self.calls = []
        self.actor = {TOKENS[0]: (10, 'scoped-developer'), TOKENS[1]: (10, 'scoped-developer'),
                      TOKENS[2]: (20, 'separate-observer')}
        self.main_protected = True
        self.push = {TOKENS[0]: True, TOKENS[1]: False, TOKENS[2]: False}
        self.enterContext(patch.object(proposer, 'capture', side_effect=self.github))
        self.enterContext(patch.object(ReleaseTrust, 'policy', return_value=self.rules))

    def github(self, argv, end, *, timeout, env, classify_http):
        self.assertEqual(argv[:4], (proposer.GH, 'api', '--hostname', 'github.com'))
        self.assertEqual(argv[-3:-1], ('-X', 'GET'))
        token, endpoint = env['GH_TOKEN'], argv[-1]
        self.calls.append((token, endpoint))
        prefix = 'repos/' + REPOSITORY
        if endpoint == 'user':
            actor, login = self.actor[token]
            value = {'id': actor, 'login': login}
        elif endpoint == 'user/30':
            value = {'id': 30}
        elif endpoint in ('repos/' + FORK, prefix):
            value = {'full_name': endpoint.removeprefix('repos/'), 'fork': endpoint.endswith(FORK),
                     'parent': {'full_name': REPOSITORY}, 'allow_merge_commit': True,
                     'permissions': {'pull': True, 'push': self.push[token], 'maintain': False, 'admin': False}}
        elif endpoint == prefix + '/branches/main':
            value = {'protected': self.main_protected, 'commit': {'sha': BASE}}
        elif endpoint == prefix + '/branches/main/protection':
            value = {'enforce_admins': {'enabled': True}, 'allow_force_pushes': {'enabled': False},
                     'allow_deletions': {'enabled': False}, 'required_pull_request_reviews': {
                         'dismiss_stale_reviews': True, 'require_last_push_approval': True, 'required_approving_review_count': 1},
                     'required_status_checks': {'strict': True, 'checks': [{'context': 'release-source-check', 'app_id': 14}]}}
        elif endpoint.startswith(prefix + '/contents/'):
            path = endpoint.removeprefix(prefix + '/contents/').removesuffix('?ref=' + BASE)
            content = {CHECK: CHECK_BYTES, release.MERGE_WORKFLOW: MERGE_BYTES, release.PUBLISHER: PUBLISH_BYTES}[path]
            value = {'path': path, 'type': 'file', 'encoding': 'base64', 'size': len(content),
                     'content': base64.b64encode(content).decode()}
        elif '/environments/' in endpoint:
            name, _, detail = endpoint.partition('/environments/')[2].partition('/')
            if not detail:
                value = {'name': name, 'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
            elif detail.startswith('deployment-branch-policies?'):
                value = {'total_count': 1, 'branch_policies': [{'name': 'main', 'type': 'branch'}]}
            else:
                app = 302 if name == 'checklist-merge' else 303
                value = {'total_count': 1, 'custom_deployment_protection_rules': [{'enabled': True, 'app': {'id': app}}]}
        else:
            self.fail('unexpected GitHub endpoint: ' + endpoint)
        return json.dumps(value).encode()

    def test_attended_preflight_binds_distinct_identities_and_exact_workflows_by_reads(self):
        grant = approval()
        end = time.monotonic() + 30
        observed = setup.observed_policy(grant, *TOKENS, end)
        self.assertEqual(observed, {**selected_site(), 'expires_unix': grant['expires_unix']})
        setup.remote_preflight(observed, TOKENS[-1], end)
        self.assertIn((TOKENS[0], 'repos/' + FORK), self.calls)
        self.assertIn((TOKENS[1], 'repos/' + REPOSITORY), self.calls)
        self.assertIn((TOKENS[2], 'repos/' + REPOSITORY + '/branches/main/protection'), self.calls)
        self.main_protected = False
        with self.assertRaisesRegex(release.Blocked, 'protected main'):
            setup.remote_preflight(observed, TOKENS[-1], end)

    def test_refuses_an_upstream_push_grant_or_shared_review_identity(self):
        end = time.monotonic() + 30
        self.push[TOKENS[1]] = True
        with self.assertRaisesRegex(ValueError, 'exceeds the scoped'):
            setup.observed_policy(approval(), *TOKENS, end)
        self.push[TOKENS[1]] = False
        self.rules['reviewer_ids'] = [20]
        with self.assertRaisesRegex(ValueError, 'separate authority'):
            setup.remote_preflight(setup.observed_policy(approval(), *TOKENS, end), TOKENS[-1], end)

    def test_expired_or_overlong_enrollment_grant_is_rejected(self):
        now = datetime(2026, 11, 28, tzinfo=timezone.utc).timestamp()
        with patch.object(setup.time, 'time', return_value=now):
            self.assertEqual(setup.expiry('2026-12-01T00:00Z') - now, 3 * 86400)
            for value in ('2026-11-28T00:00Z', '2027-01-01T00:00Z', 'tomorrow'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    setup.expiry(value)

    def test_owner_progress_reports_incomplete_expired_and_withdrawn_custody_without_losing_validation(self):
        state = {'phase': 'passed', 'materialized': {'bundle_sha256': 'd' * 64}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / 'policy.json'
            policy.write_bytes(b'previously staged')
            with (patch.object(release.product, 'read_state', return_value=state),
                  patch.object(release.product, 'PROMOTION_POLICY', policy),
                  patch.object(setup, 'enrollment') as custody):
                for phase, reason in (('staging', 'protected-promotion-enrollment-incomplete'),
                                      ('active', 'scoped-release-grant-expired'),
                                      ('withdrawn', 'protected-promotion-withdrawn')):
                    custody.return_value = {'state': phase, 'expires_unix': int(time.time()) - 1}
                    progress = release.product.read_progress(root)
                    self.assertEqual(progress['phase'], 'passed')
                    self.assertEqual(progress['promotion']['reason'], reason)
                    self.assertTrue(progress['promotion']['resume_required'])


class StationSite(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def key(self, name):
        path = self.root / name
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-N', '', '-t', 'ed25519', '-f', str(path)],
                       check=True, timeout=5)
        return path.with_suffix('.pub')

    def test_compiles_real_distinct_public_keys_and_approved_client_inputs(self):
        args = SimpleNamespace(dns_name=DNS, provider_recovery='hostinger://fixture/recovery',
            public_ipv4='8.8.8.8', public_ipv6='none', tailnet_ipv4='100.64.0.5', tailnet_ipv6='fd7a:115c:a1e0::5',
            denied_route_ipv4=['100.64.0.6', '9.9.9.9', 'control.example.com'],
            denied_route_ipv6=['fd7a:115c:a1e0::6', '2606:4700:4700::1111', 'control.example.com'],
            public_route_ipv4=['1.1.1.1', '9.9.9.9', 'control.example.com'], public_route_ipv6=None,
            **{role + '_client': role + '-client' for role in station.VANTAGES},
            **{role + '_key': self.key(role) for role in ('plan', *station.VANTAGES)})
        site, keys = station.prepare_release_site(args)
        self.assertEqual(site['clients']['authorized'], 'authorized-client')
        self.assertIsNone(site['public_addresses']['ipv6'])
        self.assertIsNone(site['negative_routes']['public']['ipv6'])
        self.assertEqual(len(keys.splitlines()), 6)
        args.provider_key = args.denied_key
        with self.assertRaisesRegex(release.Blocked, 'distinct Ed25519'):
            station.prepare_release_site(args)
        args.public_route_ipv4 = None
        with self.assertRaises(release.Blocked):
            station.prepare_release_site(args)

    def test_signed_proof_is_bound_to_exact_destination_and_replay_is_read_only(self):
        public = self.key('independent-access-review')
        private = public.with_suffix('')
        trusted = self.root / 'signers'
        trusted.write_text('dev-pair-access-review namespaces="dev-pair-destination" ' + public.read_text())
        job = self.root / JOB
        storage = self.root / 'proofs'
        job.mkdir(mode=0o700)
        storage.mkdir(mode=0o700)
        binding = {'source_sha': BASE, 'machine_id': '1' * 32, 'boot_id': '2' * 36, 'release_source': 'c' * 40,
                   'image': release.REGISTRY + '@sha256:' + 'd' * 64, 'dns_name': DNS, 'guard_sha256': 'e' * 64,
                   'job_id': JOB, 'publisher_run_id': 12, 'publisher_run_attempt': 2}
        receipt = self.root / 'independent.json'
        proof = {**binding, 'expires_at': int(time.time()) + 60, 'item_id': 1, 'item_title_sha256': 'a' * 64}
        receipt.write_bytes(station.encoding(proof))
        subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', 'dev-pair-destination', '-f', str(private), str(receipt)],
                       check=True, timeout=5, capture_output=True)
        signature = receipt.with_suffix('.json.sig').read_bytes()
        envelope = station.access_envelope(receipt.read_bytes(), signature)

        class IndependentPrimitives(setup.Destination):
            def recent_destination_evidence(self, path, principal, fields, *, lifetime):
                value, _ = station.verify_file(Path(path), principal, trusted, 'dev-pair-destination')
                return value

            def confirm(self, path, *, job_id):
                return self.release_proof(path, {**binding, 'job_id': job_id})

        with (patch.object(release, 'EVIDENCE', storage), patch.object(release.product, 'job_path', return_value=job),
              patch.object(station, 'export_release', return_value={**binding, 'image': 'another subject'}) as export,
              patch.object(setup, 'Destination', IndependentPrimitives),
              patch.object(release, 'record', return_value={'phase': 'awaiting-independent-destination'})):
            with self.assertRaisesRegex(release.Blocked, 'exact release, job or publisher attempt'):
                setup.import_evidence(JOB, io.BytesIO(envelope))
            target = setup.evidence_envelope(JOB)
            self.assertFalse(target.exists())
            export.return_value = binding
            with self.assertRaisesRegex(release.Blocked, 'invalid independent signature'):
                setup.import_evidence(JOB, io.BytesIO(station.access_envelope(receipt.read_bytes(), b'not a signature')))
            setup.import_evidence(JOB, io.BytesIO(envelope))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(setup.confirm_envelope(IndependentPrimitives(), target, job_id=JOB), proof)
            with patch.object(setup.time, 'time', return_value=proof['expires_at']):
                with self.assertRaisesRegex(release.Wait, 'signed-destination-evidence-expired'):
                    setup.stored_proof(target)
            before = target.stat().st_ino
            export.return_value = {**binding, 'publisher_run_attempt': 3}
            with self.assertRaisesRegex(release.Blocked, 'exact release, job or publisher attempt'):
                setup.import_evidence(JOB, io.BytesIO(envelope))
            export.return_value = binding
            setup.import_evidence(JOB, io.BytesIO(envelope))
            self.assertEqual(target.stat().st_ino, before)
            self.assertEqual(list(storage.iterdir()), [target])


@unittest.skipUnless(os.geteuid() == 0, 'requires a mapped-root private filesystem')
class EnrollmentCustody(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2])))
        base = self.root / 'proposer'
        self.enterContext(patch.object(release, 'SITE', self.root / 'site'))
        self.enterContext(patch.object(release, 'EVIDENCE', self.root / 'evidence'))
        for name, path in (('ROOT', base), ('INBOX', base / 'inbox'), ('CREDENTIALS', base / 'credentials')):
            self.enterContext(patch.object(proposer, name, path))
        self.enterContext(patch.object(setup, 'account_record', return_value=0))
        self.enterContext(patch.object(setup, 'account'))
        self.enterContext(patch.object(setup, 'catalogue_dns', return_value=DNS))
        self.enterContext(patch.object(setup, 'trust_identity', return_value='e' * 64))
        self.enterContext(patch.object(setup, 'provision_account', side_effect=self.fixture_account))
        self.enterContext(patch.object(setup, 'scratch', return_value=nullcontext()))
        # In mapped-root, / and some outer parents have an unmapped UID. Real mode and inode
        # checks still apply to every leaf in the isolated fixture.
        self.enterContext(patch.object(commission, 'protected', side_effect=self.project_ancestry))
        self.enterContext(patch.object(setup, 'trusted_directory', side_effect=self.project_private_directory))
        self.site = selected_site()
        self.run_command = Mock()

    def project_ancestry(self, path, owner, *, directory=False, mode=None):
        for member in (path, *path.parents):
            if not member.is_relative_to(self.root):
                break
            node = member.lstat()
            self.assertIn(node.st_uid, (0, owner))
            self.assertFalse(node.st_mode & 0o022)
            self.assertTrue(stat.S_ISDIR(node.st_mode))
        return path

    @staticmethod
    def project_private_directory(path):
        setup.exact_node(path, 0, 0, 0o700, directory=True)
        return path

    @staticmethod
    def fixture_account(run):
        setup.write_once(release.SITE / setup.ACCOUNT, commission.encoded({'version': 1, 'uid': 2500}))
        setup.directory(proposer.ROOT, mode=0o750)
        setup.directory(proposer.INBOX, mode=0o750)
        setup.directory(proposer.CREDENTIALS, mode=0o750)
        setup.directory(release.EVIDENCE)
        return 0

    def test_interrupted_first_enrollment_reuses_exact_custody_and_withdrawal_preserves_proof(self):
        real = setup.write_once

        def interrupted(path, data, *args):
            if path.name == 'upstream-pr.token':
                raise InterruptedError('local fixture interruption')
            real(path, data, *args)

        with patch.object(setup, 'write_once', side_effect=interrupted):
            with self.assertRaises(InterruptedError):
                setup.enroll(self.site, *TOKENS, None, self.run_command)
        self.assertEqual(setup.enrollment()['state'], 'staging')
        with self.assertRaisesRegex(ValueError, 'current attended'):
            setup.runtime_grant('selected')
        setup.enroll(self.site, *TOKENS, None, self.run_command)
        credential = proposer.CREDENTIALS / 'fork.token'
        self.assertEqual(stat.S_IMODE(credential.stat().st_mode), 0o440)
        selected = setup.runtime_grant('selected')
        setup.enroll(self.site, *TOKENS, None, self.run_command)
        self.assertEqual(setup.runtime_grant('selected'), selected)
        kept = release.EVIDENCE / 'independent-proof'
        kept.write_bytes(b'original proof')
        setup.withdraw()
        self.assertEqual(setup.enrollment()['state'], 'withdrawn')
        self.assertFalse(credential.exists())
        self.assertFalse((release.SITE / 'policy.json').exists())
        self.assertEqual(kept.read_bytes(), b'original proof')
        setup.withdraw()
        with self.assertRaisesRegex(ValueError, 'current attended'):
            setup.runtime_grant('selected')


if __name__ == '__main__':
    unittest.main()
