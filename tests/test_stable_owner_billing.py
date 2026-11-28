"""Exercise owner resume against the protected historical and selected-stable records."""
from contextlib import nullcontext, redirect_stdout
import io
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import commission_host as c
import owner_day0 as day
import renewal as r
import stable_renewal as stable
import test_stable_renewal as fixture


@unittest.skipUnless(os.getuid() == 0, 'automatic stable authority needs protected fixture ownership')
class StableOwnerBilling(unittest.TestCase):
    def test_day0_routes_expired_or_changed_historical_grant_and_records_only_new_owner_consent(self):
        site = fixture.NativeAuthority()
        self.addCleanup(site.doCleanups)
        site.setUp()
        successor = site.package('c', 43, previous=site.origin)
        selected = site.resolver.resolve(site.offer('stable', successor, site.initial), boot=fixture.BOOT)['release_sha256']
        for name in ('current', 'site-current'):
            r.replace_json(site.control / (name + '.json'), selected)
        identity = {'machine_id': fixture.MACHINE, 'boot_id': fixture.BOOT}
        services = Mock()
        services.renewal.return_value = site.controller
        services.identity.return_value = identity
        services.verify_selection.side_effect = lambda _, reference, policy: stable.local_binding(
            site.resolver, reference, policy['site_config_sha256'])
        services.workload_scope.return_value = '7' * 64
        commissioner = c.Commission(site.root, site.root, Mock(), 0, services)
        commissioner.run.return_value = ('LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'
                                         'Unit=dev-pair-intake-recovery.service\nNextElapseUSecRealtime=scheduled\n')
        commissioner.path = lambda name: site.root / name.removeprefix('/var/lib/dev-pair/').lstrip('/')
        commissioner.inspect = Mock(return_value=identity)
        commissioner.provider_fence = Mock()
        policy_path = commissioner.path(c.AUTOMATIC_POLICY)
        policy = r.read_json(policy_path)
        policy['checklist'] = {'tls_profile': c.CHECKLIST_SERVER, **c.DEFAULT_CHECKLIST}
        policy_path.write_bytes(c.encoded(policy))
        activation = commissioner.path(c.ACTIVATION)
        state = site.root / 'day0'
        state.mkdir(mode=0o700)
        r.replace_json(state / 'progress.json', {'machine_id': fixture.MACHINE, 'source_sha': 'a' * 40})
        phase = {'offer_consent': False, 'consented': False}
        reports = []
        checkout = Path(__file__).resolve().parents[1]
        entry = day.DayZero(checkout, Mock())
        entry.ensure_git = Mock()
        entry.original = Mock(return_value={**identity, 'host': 'erebus', 'selinux': '1'})
        entry.owner_lock = nullcontext
        entry.stable_site = Mock(return_value={'source_sha': 'c' * 40, 'original_source_sha': 'a' * 40})
        entry.stable_checkout = Mock(return_value=checkout)

        def setup(_terminal, *, billing_slot):
            self.assertEqual(billing_slot, 'job-1')
            phase['consented'] = phase['offer_consent']
            return phase['consented']

        entry.setup_owner = Mock(side_effect=setup)

        def dispatch(helper, action, argument, source, **kwargs):
            self.assertEqual((helper, action, argument, source), ('commission_host.py', 'apply', '--source-sha', 'c' * 40))
            self.assertEqual(kwargs['checkout'], checkout)
            report = commissioner.automatic(action, source)
            reports.append(report)
            return report

        entry.call = dispatch
        with (patch.object(site.controller, 'host_fence', return_value=nullcontext()),
              patch.object(day, 'STATE', state), patch.object(day, 'DayZero', return_value=entry),
              patch.object(day, 'kit_source', return_value=('c' * 40, False)),
              patch.object(day, 'tty_open', return_value=nullcontext(object())),
              patch.object(sys, 'argv', ['day0.sh', 'resume']), redirect_stdout(io.StringIO())):
            for scenario, expires in (('expired', -5), ('changed', 3600)):
                with self.subTest(scenario=scenario):
                    entry.setup_owner.reset_mock()
                    phase.update(offer_consent=False, consented=False)
                    previous = {'subject': 'job-1', 'expires_unix': int(time.time()) + expires, 'sha256': '3' * 64}
                    grant = {**previous, 'expires_unix': int(time.time()) + 7200, 'sha256': '4' * 64}
                    original = {'schema': 1, **identity, 'policy_sha256': c.digest(policy_path.read_bytes()),
                                'release_sha256': site.initial, 'proof_sha256': '5' * 64,
                                'features': {'owner-intake': {'phase': 'armed', 'grant': previous, 'next': ['fixture-timer']}}}
                    r.replace_json(activation, original)
                    services.feature_authority.return_value = grant

                    def renewed(reference, recorded):
                        self.assertEqual((reference, recorded), (selected, previous))
                        if not phase['consented']:
                            raise c.Pending('provider-slot-authority', 'New protected owner consent is required.')
                        return nullcontext((grant, '2' * 64))

                    services.owner_billing_reauthorization.side_effect = renewed
                    status = commissioner.automatic('status', 'c' * 40)
                    self.assertIn('owner-intake', status['held_features'])
                    entry.setup_owner.assert_not_called()
                    self.assertEqual(day.main(), 0)
                    self.assertIsNone(reports[-1]['owner_terminal'])
                    self.assertEqual(reports[-1]['owner_billing_slot'], 'job-1')
                    self.assertEqual(r.read_json(activation), original)
                    phase['offer_consent'] = True
                    self.assertEqual(day.main(), 0)
                    self.assertEqual(reports[-1]['owner_terminal'], '/usr/local/bin/dev-pair')
                    self.assertEqual(entry.setup_owner.call_count, 2)
                    active = r.read_json(activation)
                    self.assertEqual(set(active['features']), {'owner-intake'})
                    owner = active['features']['owner-intake']
                    self.assertEqual(owner['grant'], grant)
                    self.assertEqual(owner['runtime']['release_sha256'], selected)
                    self.assertEqual(reports[-1]['pending_features']['checklist-promotion'], 'protected-feature-activation')
                    archive = commissioner.path(c.PRIVATE + '/owner-billing-receipts')
                    self.assertIn(previous, [r.read_json(path)['previous_grant'] for path in archive.iterdir()])
