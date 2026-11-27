"""Local destination boundary fixtures. No provider, firewall or registry mutations."""
import contextlib
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
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
TESTED = 'd' * 40
TREE = 'e' * 40
GATE_WORKFLOW = '.github/workflows/release-check.yml'


def workflow_content(path, data):
    return {'path': path, 'type': 'file', 'encoding': 'base64', 'size': len(data),
            'content': base64.b64encode(data).decode()}


class BootstrapAccessTests(unittest.TestCase):
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
        self.calls = []

    def policy(self, component):
        return {'reviewer_ids': [111], 'writer_app_id': 77, 'check': self.check, 'components': {
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
            yield {}, 1234, DNS

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


class ProvisioningTests(unittest.TestCase):
    def test_managed_executor_observes_protected_selection_before_listener_admission(self):
        app = d.Destination()
        effects = []

        def systemctl(*args, **kwargs):
            self.assertEqual(args[0], d.SYSTEMCTL)
            effects.append(args[1:])
            return 'inactive\n' if args[1] == 'is-active' else ''

        with patch.object(app, 'run', side_effect=systemctl), \
                patch.object(app, 'subprocess_role', side_effect=lambda *args: effects.append(('prepare', args[-1]))), \
                patch.object(app, 'executor_ready', side_effect=lambda unit, uid: effects.append(('listener', unit, uid))), \
                patch.object(d, 'protect', side_effect=lambda path: effects.append(('protect', path))):
            unit, needs_readback = app.start_executor(1234, True, False)
        self.assertTrue(needs_readback)
        self.assertEqual(effects, [('is-active', unit), ('prepare', 'initialize-host-history'), ('enable', unit),
                                   ('start', 'dev-pair-renewal-boot-fence.service'), ('start', 'dev-pair-renewal-host-observe.service'),
                                   ('protect', d.FENCE + '/selected-host.json'), ('listener', unit, 1234)])

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
