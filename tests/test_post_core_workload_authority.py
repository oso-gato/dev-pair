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
import renewal


@unittest.skipUnless(os.geteuid() == 0 and hasattr(b.Bootstrap, 'verify_workload_access'),
                     'requires mapped root and the current D proof companion')
class SignedWorkloadAuthority(unittest.TestCase):
    def test_normal_apply_holds_core_and_expired_proof_then_arms_verified_local_cleanup(self):
        setup = fixture.HostCommissioning()
        setup.setUp()
        self.addCleanup(setup.doCleanups)
        setup.automatic_services()
        app, root, services = setup.app, setup.root, setup.services
        machine = services.identity()
        app.directory(c.CONTROL, 0o700)

        plan = renewal.json_bytes({'development_manifests': {'checklist': 'b' * 64}})
        plan_sha = c.digest(plan)
        app.file(c.CONTROL + '/plans/' + plan_sha + '.json', plan, 0o600)
        components = {name: {'source_revision': fixture.SOURCE, 'config_sha256': 'c' * 64, 'artifact_sha256': 'd' * 64}
                      for name in renewal.COMPONENTS}
        for role in renewal.SCOPE_COMPONENTS['agent']:
            components[role]['codex_version'] = '0.169.0'
        release = renewal.json_bytes({'schema': 1, 'source_revision': fixture.SOURCE, 'config_sha256': 'c' * 64,
                                      'plan_sha256': plan_sha, 'ledger_contract': 1, 'state_contract': 1,
                                      'components': components})
        selected = c.digest(release)
        app.file(c.CONTROL + '/releases/' + selected + '.json', release, 0o600)
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
        services.workload_scope = live.workload_scope
        services.feature_authority = live.feature_authority
        storage = app.directory('/var/lib/dev-pair/checklist-validation', 0o700)
        cleanup = SimpleNamespace(STORAGE=storage, dispatch_gate=nullcontext,
                                  protected=lambda path, *, file: c.protected(path, 0, directory=not file))
        managed = SimpleNamespace(require_recovery_enabled=lambda: self.assertIn(c.RECOVERY, setup.manager.enabled),
                                  verify_managed_executor=lambda site, uid: self.assertEqual((site, uid), (selected, 1210)))

        def cli():
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(c.main(['apply', '--source-sha', fixture.SOURCE]), 0)
            return json.loads(output.getvalue())

        archive = root / 'no-gh-home'
        with (patch.object(b, 'TRUST_SIGNERS', '/allowed_signers'), patch.object(c, 'verify_checkout'),
              patch.object(c, 'Commission', return_value=app), patch.object(c, 'Live', return_value=services),
              patch.object(d, 'Destination', return_value=managed),
              patch.object(owner_intake, 'Intake', return_value=owner_intake.Intake(root=storage, site=storage)),
              patch.object(platform_release_intake, 'native_env', return_value={'GH_CONFIG_DIR': str(archive)}),
              patch.object(host_handoff, 'host_runtime', return_value=cleanup),
              patch.object(checklist_candidate, 'checked_storage', return_value=storage.stat().st_dev)):
            # Use the live methods instantiated above through the actual CLI.
            sign(core=True)
            self.assertEqual(bootstrap.finalize(str(receipt))['access_scope'], 'core')
            cli()
            app.file(d.MANAGED_LISTENER, c.encoded({'version': 2, 'phase': 'ready', 'site': selected,
                                                   'boot': machine['boot_id']}), 0o600)
            self.assertEqual(cli()['pending_features'], dict.fromkeys(c.TIMERS, 'workload-access'))
            sign(core=False, expired=True)
            with self.assertRaisesRegex(b.Blocked, 'stale or belongs to another'):
                bootstrap.finalize(str(receipt))
            self.assertFalse(cli()['timers'])
            sign(core=False)
            self.assertEqual(bootstrap.finalize(str(receipt))['access_scope'], 'full')
            result = cli()
            self.assertEqual(set(result['timers']), {c.TIMERS['checklist-spool'][0]})
            self.assertEqual(result['pending_features'], {'agent-renewal': 'release-read-custody', 'owner-intake': 'owner-catalogue'})
            app.require_runtime_feature('checklist-spool')
            access = app.path('/var/lib/dev-pair/workload-access.json')
            access.unlink()
            self.assertFalse(cli()['timers'])
            self.assertNotIn(c.TIMERS['checklist-spool'][0], setup.manager.active)
