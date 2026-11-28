"""Exercise normal commissioning against the signed destination access controller."""
from contextlib import nullcontext, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_host_commissioning as fixture
import bootstrap as b
import checklist_candidate
import commission_host as c
import destination_release as d
import host_handoff
import owner_intake
import platform_release_intake
import platform_release_install
import provider_billing
import release_trust
import renewal
import session_controller


@unittest.skipUnless(os.geteuid() == 0 and hasattr(b.Bootstrap, 'verify_workload_access'),
                     'requires mapped root and the current D proof companion')
class SignedWorkloadAuthority(unittest.TestCase):
    def test_normal_apply_holds_core_and_expired_proof_then_arms_verified_local_cleanup(self):
        self.exercise()

    @unittest.skipUnless(os.environ.get('DEV_PAIR_TEST_STANDARDS'), 'requires checked private standards for positive owner fixture')
    def test_pinned_owner_grant_and_read_only_agent_bridge_qualify_before_any_offer(self):
        self.exercise(with_grants=True)

    def exercise(self, *, with_grants=False):
        setup = fixture.HostCommissioning()
        setup.setUp()
        self.addCleanup(setup.doCleanups)
        setup.automatic_services()
        app, root, services = setup.app, setup.root, setup.services
        machine = services.identity()
        app.directory(c.CONTROL, 0o700)

        job = 'owner-' + 'x' * 42
        dev_manifest = c.encoded({'job': job, 'standards_sha': owner_intake.p.STANDARDS})
        dev_sha = c.digest(dev_manifest)
        plan = renewal.json_bytes({'schema': 1, 'maintenance_context_sha256': '1' * 64,
                                   'development_manifests': {job: dev_sha}})
        plan_sha = c.digest(plan)
        app.file(c.CONTROL + '/plans/' + plan_sha + '.json', plan, 0o600)
        components = {name: {'source_revision': fixture.SOURCE, 'config_sha256': 'c' * 64, 'artifact_sha256': 'd' * 64}
                      for name in renewal.COMPONENTS}
        kit = Path(__file__).resolve().parents[1]
        tool_paths = ('tools/checklist_candidate.py', 'tools/agent_release_bridge.py')
        host_bytes = c.encoded({'schema': 1, 'source_revision': fixture.SOURCE, 'state_contract': 1,
                                'files': {path: c.digest((kit / path).read_bytes()) for path in tool_paths}})
        bundle_sha = c.digest(host_bytes)
        host_bundles = app.directory(c.INSTALL + '/host-releases', 0o755)
        bundle = app.directory(c.INSTALL + '/host-releases/' + bundle_sha, 0o755)
        for path in tool_paths:
            app.file(c.INSTALL + '/host-releases/' + bundle_sha + '/' + path, (kit / path).read_bytes(), 0o444)
            app.file(c.INSTALL + '/' + path, (kit / path).read_bytes(), 0o644)
        app.file(c.INSTALL + '/host-releases/' + bundle_sha + '/manifest.json', host_bytes, 0o444)
        (bundle / 'tools').chmod(0o555)
        bundle.chmod(0o555)
        components['host']['artifact_sha256'] = bundle_sha
        for role in renewal.SCOPE_COMPONENTS['agent']:
            components[role]['codex_version'] = '0.169.0'
        release = renewal.json_bytes({'schema': 1, 'source_revision': fixture.SOURCE, 'config_sha256': 'c' * 64,
                                      'plan_sha256': plan_sha, 'ledger_contract': 1, 'state_contract': 1,
                                      'components': components})
        selected = c.digest(release)
        app.file(c.CONTROL + '/releases/' + selected + '.json', release, 0o600)
        app.file(c.CONTROL + '/platform-bindings/' + selected + '.json',
                 c.encoded({'release_sha256': selected, 'base_platform_sha256': fixture.PLATFORM}), 0o600)
        services.resolve_initial = lambda *args: selected
        services.allowed.add(selected)

        def checked_ssh(*args, input_text=None, **kwargs):
            if args[0] == '/usr/bin/ssh-keygen':
                return subprocess.run(args, input=input_text, capture_output=True, text=True, check=True).stdout
            return 'active'

        bootstrap = b.Bootstrap(root, checked_ssh)
        bootstrap.destination_source = lambda *args, **kwargs: None
        bootstrap.destination_identity = services.identity
        bootstrap.guard_hash = lambda: '7' * 64
        bootstrap.verify_final_ssh = lambda: None
        bootstrap.observed_ssh_peer = lambda: None
        bootstrap.access_keys_digest = lambda: '3' * 64
        addr = {'ipv4': '100.64.0.5', 'ipv6': 'fd7a:115c:a1e0::5'}
        dns = 'erebus.tail123.ts.net'
        bootstrap.tailscale_state = lambda: ({'TailscaleIPs': list(addr.values())}, dns)
        bootstrap.identity_fields = lambda _: ('tail', 'node')
        desired = json.dumps({'bootstrap_sources': ['192.0.2.44/32']})
        bootstrap.directory(b.STATE, mode=0o700)
        bootstrap.atomic(b.STATE + '/prepared', desired)
        bootstrap.atomic(b.STATE + '/desired.json', desired)
        bootstrap.atomic(b.GUARD_PATH, bootstrap.guard_rules(['192.0.2.44/32']))
        key, signers, receipt = (root / name for name in ('fixture-key', 'allowed_signers', 'access.json'))
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        signers.write_text('dev-pair-access-review ' + key.with_suffix('.pub').read_text())
        signers.chmod(0o600)

        def sign(*, core, expired=False):
            issued = int(time.time()) - 5
            recovery = 'hostinger://fixture-vps/recovery'
            addresses = {'ipv4': '8.8.4.4', 'ipv6': None}
            expected = bootstrap.access_probe_plan(dns, recovery, addresses, core_only=core)
            probes = [{'test': test, 'family': family, 'endpoint': endpoint, 'vantage': vantage,
                       'client_id': 'fixture-' + vantage, 'outcome': outcome, 'observed_at': issued,
                       'evidence_sha256': 'a' * 64}
                      for (test, family), (endpoint, vantage, outcome) in expected.items()]
            payload = {'version': 1, 'source_sha': fixture.SOURCE, **machine, 'issued_at': issued,
                       'expires_at': issued + (1 if expired else 600), 'node_id': 'node', 'tailnet': 'tail',
                       'dns_name': dns, 'keys_sha256': '3' * 64, 'acl_sha256': '4' * 64,
                       'execution_route': 'provider-recovery', 'provider_recovery': recovery,
                       'public_addresses': addresses, 'tailnet_addresses': addr, 'probes': probes,
                       'kind': b.CORE_ACCESS_CUTOVER if core else b.WORKLOAD_ACCESS_CUTOVER}
            if not core:
                payload['role_artifacts'] = bootstrap.access_workload_selection()
            receipt.write_text(json.dumps(payload))
            receipt.chmod(0o600)
            signature = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'dev-pair-destination'],
                                       input=receipt.read_bytes(), capture_output=True, check=True).stdout
            signed = receipt.with_suffix('.json.sig')
            signed.write_bytes(signature)
            signed.chmod(0o600)

        live = c.Live(root, bootstrap)
        live.renewal = lambda: renewal.Renewal(app.path(c.STATE), None)
        services.workload_scope = live.workload_scope
        services.feature_authority = live.feature_authority
        services.agent_publication_status = live.agent_publication_status
        storage = app.directory('/var/lib/dev-pair/checklist-validation', 0o700)
        cleanup = SimpleNamespace(STORAGE=storage, dispatch_gate=nullcontext,
                                  protected=lambda path, *, file: c.protected(path, 0, directory=not file))
        managed = d.Destination(root, checked_ssh)
        managed.destination_identity = services.identity
        managed.account = lambda: 1210
        managed.manager_job = lambda unit: (False, 'success') if unit == c.RECOVERY else (True, 'failed')
        managed.recovery_start = lambda: 1
        managed.require_recovery_enabled = lambda: self.assertIn(c.RECOVERY, setup.manager.enabled)
        managed.verify_managed_executor = lambda site, uid: self.assertEqual((site, uid), (selected, 1210))

        def cli():
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(c.main(['apply', '--source-sha', fixture.SOURCE]), 0)
            return json.loads(output.getvalue())

        archive = root / 'read-authority'
        gh = root / 'gh'
        gh.write_bytes(b'#!/bin/sh\nexit 97\n')
        gh.chmod(0o700)
        catalogue = app.directory('/etc/dev-pair/product-intake', 0o700)
        credentials = app.directory('/etc/dev-pair/provider-credentials', 0o700)
        billing_root = app.directory('/etc/dev-pair/provider-evidence', 0o700)
        app.file('/etc/machine-id', (machine['machine_id'] + '\n').encode(), 0o444)
        release_policy = root / 'release-trust.json'
        intake = owner_intake.Intake(root=app.path(c.STATE), site=catalogue)
        stable = {'components': {'host': {'bundle_manifest_sha256': bundle_sha, 'source_sha': fixture.SOURCE}}}
        expected_reads = ['branches/main', *(f'actions/workflows/agent-refresh.yml/runs?branch=main&event={event}'
                                            f'&head_sha={fixture.SOURCE}&per_page=1'
                                            for event in ('schedule', 'workflow_dispatch'))]
        reads, permission = [], {'allowed': False}

        def publication_read(endpoint, end):
            self.assertIn(endpoint, expected_reads)
            self.assertGreater(end, time.monotonic())
            reads.append(endpoint)
            if not permission['allowed']:
                raise subprocess.CalledProcessError(1, 'fixture gh read', output=b'local response must be withheld')
            if endpoint == 'branches/main':
                return {'name': 'main', 'protected': True, 'commit': {'sha': fixture.SOURCE}}
            return {'total_count': 0, 'workflow_runs': []}

        def storage_probe(runtime, end, *, witness):
            self.assertEqual(witness, bundle / 'tools/checklist_candidate.py')
            return storage.stat().st_dev

        with (patch.object(b, 'TRUST_SIGNERS', '/allowed_signers'), patch.object(c, 'verify_checkout'),
              patch.object(c, 'Commission', return_value=app), patch.object(c, 'Live', return_value=services),
              patch.object(d, 'Destination', return_value=managed),
              patch.object(owner_intake, 'Intake', return_value=intake), patch.object(owner_intake, 'CREDENTIALS', credentials),
              patch.multiple(provider_billing, CREDENTIALS=credentials, EVIDENCE=billing_root, SIGNERS=signers,
                             MACHINE_ID=app.path('/etc/machine-id')),
              patch.object(c, 'GITHUB_CONFIG', archive), patch.object(platform_release_intake, 'GITHUB', str(gh)),
              patch.object(platform_release_install, 'HOST_RELEASES', host_bundles),
              patch.object(platform_release_intake, 'retained_index', return_value=(root, stable, '1' * 64)),
              patch.object(platform_release_intake, 'ROOT', root), patch.object(platform_release_intake, 'portable_volume'),
              patch.object(platform_release_intake, 'read_api', side_effect=publication_read),
              patch.object(release_trust, 'POLICY', release_policy),
              patch.object(host_handoff, 'host_runtime', return_value=cleanup),
              patch.object(checklist_candidate, 'checked_storage', side_effect=storage_probe)):
            # Use the live methods instantiated above through the actual CLI.
            sign(core=True)
            self.assertEqual(bootstrap.finalize(str(receipt))['access_scope'], 'core')
            cli()
            provision = c.encoded({'machine_id': machine['machine_id'], 'uid': 1210})
            app.file(d.PROVISION, provision, 0o600)
            app.file(d.CONTROL + '/ready.json', provision, 0o600)
            app.file(d.MANAGED_LISTENER, c.encoded({'version': 2, 'phase': 'ready', 'site': selected,
                                                   'boot': machine['boot_id'], 'recovery_after': 0}), 0o600)
            self.assertEqual(cli()['pending_features'], dict.fromkeys(c.TIMERS, 'workload-access'))
            sign(core=False, expired=True)
            with self.assertRaisesRegex(b.Blocked, 'stale or belongs to another'):
                bootstrap.finalize(str(receipt))
            self.assertFalse(cli()['timers'])
            sign(core=False)
            self.assertEqual(bootstrap.finalize(str(receipt))['access_scope'], 'full')
            self.assertEqual(live.verified_workload_bundle(selected), bundle)
            result = cli()
            self.assertEqual(set(result['timers']), {c.TIMERS['checklist-spool'][0]}, result)
            self.assertEqual(result['pending_features'], {'agent-renewal': 'release-read-custody',
                                                         'checklist-promotion': 'promotion-enrollment',
                                                         'owner-intake': 'owner-catalogue-selection'})
            app.require_runtime_feature('checklist-spool')
            if with_grants:
                self.approved_owner(app, catalogue, credentials, job, dev_sha, dev_manifest, billing_root, signers)
                archive.mkdir(mode=0o700)
                (archive / 'hosts.yml').write_text('Fixture read-only authorization. No token.\n')
                (archive / 'hosts.yml').chmod(0o600)
                role_policy = {'workflow': '.github/workflows/platform-release.yml', 'sha256': '2' * 64, 'registry': None,
                               'agent_refresh': {'workflow': '.github/workflows/agent-refresh.yml', 'sha256': '3' * 64}}
                release_policy.write_bytes(c.encoded({'version': 1, 'reviewer_ids': [1], 'writer_app_id': 2,
                    'check': {'context': 'release-source-check', 'app_id': 2, 'workflow': '.github/workflows/release-check.yml', 'sha256': '4' * 64},
                    'components': {role: role_policy for role in ('maintenance', 'development')}}))
                release_policy.chmod(0o600)
                with patch.object(owner_intake.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=2200, pw_gid=2200)):
                    withheld = cli()
                    self.assertEqual(withheld['pending_features'], {'agent-renewal': 'agent-observer-key',
                                                                   'checklist-promotion': 'promotion-enrollment'})
                    self.assertNotIn(c.AGENT_BRIDGE[0], withheld['timers'])
                    self.assertFalse(reads)
                    collector = root / 'agent-collector'
                    subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(collector)], check=True)
                    public = bootstrap.observer_public_key(collector.with_suffix('.pub').read_text())
                    bootstrap.update_agent_observer(bootstrap.signer_fingerprint(public), public=public)
                    refused = cli()
                    self.assertEqual(refused['pending_features'], {'agent-renewal': 'agent-publication-read',
                                                                  'checklist-promotion': 'promotion-enrollment'})
                    self.assertNotIn(c.AGENT_BRIDGE[0], refused['timers'])
                    self.assertNotIn('agent_publication', refused)
                    self.assertEqual(reads, [expected_reads[0]])
                    permission['allowed'] = True
                    result = cli()
                self.assertEqual(reads, [expected_reads[0], *expected_reads])
                self.assertEqual(result['owner_terminal'], '/usr/local/bin/dev-pair')
                self.assertEqual(set(result['timers']), {c.AGENT_BRIDGE[0], c.TIMERS['owner-intake'][0], c.TIMERS['checklist-spool'][0]})
                self.assertEqual(result['agent_publication'], 'awaiting-signed-publication')
                self.assertFalse(app.path(c.CONTROL + '/offers/agent.json').exists())
                app.require_runtime_feature('agent-renewal')
                app.require_runtime_feature('owner-intake', owner_entry=True)
                self.assertEqual(reads, [expected_reads[0], *expected_reads])
                saved_custody = (archive / 'hosts.yml').stat()
                permission['allowed'] = False
                with patch.object(owner_intake.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=2200, pw_gid=2200)):
                    lost = cli()
                    self.assertEqual(lost['pending_features'], {'agent-renewal': 'agent-publication-read',
                                                               'checklist-promotion': 'promotion-enrollment'})
                    self.assertNotIn(c.AGENT_BRIDGE[0], lost['timers'])
                    self.assertNotIn(c.AGENT_BRIDGE[0], setup.manager.active)
                    self.assertEqual((archive / 'hosts.yml').stat().st_ino, saved_custody.st_ino)
                    permission['allowed'] = True
                    self.assertIn(c.AGENT_BRIDGE[0], cli()['timers'])
                self.assertEqual(reads, [expected_reads[0], *expected_reads, expected_reads[0], *expected_reads])
                self.assertFalse(app.path(c.STATE + '/provider-allowances/' + job).exists())
                (credentials / 'local-fixture').unlink()
                with self.assertRaisesRegex(c.Pending, 'provider-slot-authority'):
                    app.require_runtime_feature('owner-intake', owner_entry=True)
                result = cli()
                self.assertEqual(set(result['timers']), {c.AGENT_BRIDGE[0], c.TIMERS['checklist-spool'][0]})
                self.assertEqual(result['pending_features'], {'owner-intake': 'provider-slot-authority',
                                                             'checklist-promotion': 'promotion-enrollment'})
                self.assertFalse(app.path('/etc/sudoers.d/60-dev-pair-owner').exists())
                activation = app.path(c.ACTIVATION)
                before = activation.read_bytes()
                machine['boot_id'] = '11111111-2222-3333-4444-555555555555'

                def installed(name):
                    try:
                        app.require_runtime_feature(name)
                    except c.Pending as wait:
                        raise c.Blocked(str(wait)) from wait

                with patch.object(c, 'require_installed_workload', side_effect=installed):
                    with patch.object(managed, 'manager_job', return_value=(True, 'success')):
                        self.assertEqual(c.main(['guard', 'agent-renewal']), 1)
                        self.assertEqual(activation.read_bytes(), before)
                    self.assertEqual(c.main(['guard', 'agent-renewal']), 0)
                    self.assertEqual(c.parse(activation.read_bytes())['features']['agent-renewal']['runtime']['boot_id'], machine['boot_id'])
                    self.assertEqual(c.main(['guard', 'checklist-spool']), 0)
                    self.assertEqual(c.main(['guard', 'owner-intake']), 1)
                    self.assertEqual(c.main(['guard', 'checklist-promotion']), 1)
                    (archive / 'hosts.yml').write_bytes(b'Different publisher custody.\n')
                    self.assertEqual(c.main(['guard', 'agent-renewal']), 1)
                self.assertFalse(app.path(c.CONTROL + '/offers/agent.json').exists())
            access = app.path('/var/lib/dev-pair/workload-access.json')
            access.unlink()
            self.assertFalse(cli()['timers'])
            self.assertNotIn(c.TIMERS['checklist-spool'][0], setup.manager.active)

    @staticmethod
    def approved_owner(app, catalogue, credentials, job, dev_sha, dev_manifest, billing_root, signers):
        standards = Path(os.environ['DEV_PAIR_TEST_STANDARDS'])
        cache = catalogue / 'standards'
        cache.mkdir(mode=0o700)
        for name in session_controller.SHARED:
            (cache / name).write_bytes((standards / name).read_bytes())
            (cache / name).chmod(0o600)
        upstream = 'fixture-owner/private-project'
        base = catalogue / 'repositories' / upstream
        revisions = {}
        for purpose in ('acquired', 'startup'):
            repo = base / purpose
            repo.mkdir(parents=True, mode=0o700)
            def git(*args):
                return subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], stderr=subprocess.DEVNULL, timeout=5)
            git('init', '--template=')
            git('config', 'remote.origin.url', 'https://github.com/' + upstream)
            for name in session_controller.PUBLIC:
                (repo / name).write_text('Private local fixture project document.\n')
            git('add', '--all')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'Bind project documents')
            revisions[purpose] = git('rev-parse', 'HEAD').decode().strip()
        settings = {'schema': 1, 'slots': [job], 'repositories': {upstream: {'commit': revisions['acquired'],
                    'startup_revision': revisions['startup'], 'destination': 'private fixture delivery', 'workloads': ['general-development']}}}
        (catalogue / 'repositories.json').write_bytes(c.encoded(settings))
        slot = catalogue / 'slots' / job
        slot.mkdir(parents=True, mode=0o700)
        pricing = {'max_context_tokens': 2048, 'input_microusd_per_million': 1000, 'output_microusd_per_million': 2000,
                   'observed_models': ['gpt-6.2-sol']}
        key = signers.with_name('separate-provider-billing-custodian')
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, timeout=5)
        with signers.open('a') as trust:
            trust.write('provider-billing ' + key.with_suffix('.pub').read_text())
        ref = 'local-fixture'
        secret = 'sk-proj-historical-fixture-never-sent'
        owner_intake.write_private(credentials / ref, secret.encode())
        now = int(time.time())
        review = {**pricing, 'request': provider_billing.request_record(ref, secret),
                  'organization': 'org-fixture', 'project': 'proj_fixture', 'issued_unix': now,
                  'expires_unix': now + 1800, 'sources': {kind: {'source': 'record:fixture-authority',
                      'sha256': c.digest(b'separate custody fixture'), 'bytes': 24} for kind in provider_billing.SOURCE_KINDS}}
        signature = provider_billing.openssh('sign', '-f', str(key), '-n', provider_billing.NAMESPACE,
                                            data=provider_billing.canonical(review)).decode()
        reference_dir = billing_root / ref
        reference_dir.mkdir(mode=0o700)
        digest = provider_billing.review_digest(review)
        owner_intake.write_private(reference_dir / provider_billing.ACTIVE, (digest + '\n').encode())
        for kind, proof in provider_billing.normalized(review, signature).items():
            (slot / (owner_intake.MODEL + '.' + kind)).write_bytes(proof)
            pricing[kind + '_evidence_sha256'] = c.digest(proof)
        (slot / 'profile.json').write_bytes(c.encoded({'schema': 1, 'host_seconds': 25, 'build_seconds': 20, 'turn_seconds': 10,
                                                     'allowance_ref': ref, 'spend_microusd': 3000,
                                                     'expires_unix': now + 900, 'pricing': pricing,
                                                     'billing_scope': provider_billing.ALLOWANCE_KIND}))
        for role in owner_intake.ROLES:
            role_root = slot / role
            seed = role_root / 'seed'
            seed.mkdir(parents=True, mode=0o700)
            (seed / 'config.toml').write_text('model = "gpt-6.2-sol"\n')
            (role_root / 'profile.json').write_bytes(c.encoded({'runtime_sha256': '5' * 64, 'binary_sha256': '6' * 64,
                'layout_sha256': '7' * 64, 'credential_ref': ref, 'grant': {'spend_microusd': 1000, 'seconds': 30,
                    'max_requests': 1, 'max_request_bytes': 1024, 'max_output_tokens': 128}}))
        app.file(c.STATE + '/development/builds/' + job + '/inputs/' + dev_sha + '/manifest.json', dev_manifest, 0o444)
