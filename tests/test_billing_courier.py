"""Check the dedicated signed billing transport and its owner-wizard boundary."""

import base64
import io
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import billing_courier as courier
import job_protocol as p
import owner_intake as owner
import provider_billing as billing


class BillingCourierTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.secret = 'sk-proj-compiled-test-not-a-live-credential'
        self.reference = 'fixture-approved-reference'
        self.epoch = 'e' * 32
        self.machine = 'a' * 64
        self.enterContext(patch.object(billing, 'reviewer_state', return_value={'key': 'test-key', 'epoch': self.epoch}))
        self.enterContext(patch.object(billing, 'machine_binding', return_value=self.machine))
        self.profile = {'machine_sha256': self.machine, 'reviewer_epoch': self.epoch,
                        'host': '100.64.0.3', 'account': 'dp-billing-wire', 'generation': 'c' * 32}
        self.request = billing.request_record(self.reference, self.secret)
        self.signing_key = self.directory / 'reviewer'
        courier.candidate.invoke([billing.SSH_KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', str(self.signing_key)],
                                 time.monotonic() + 5)
        self.profile['reviewer_key'] = billing.reviewer_key(self.signing_key.with_suffix('.pub').read_text())[0]

    def response(self, request=None, body=b'private fixture billing evidence'):
        now = int(time.time())
        review = {'request': request or self.request, 'organization': 'org-fixture', 'project': 'proj_fixture',
                  'issued_unix': now, 'expires_unix': now + 1800, 'max_context_tokens': 16000,
                  'input_microusd_per_million': 3000000, 'output_microusd_per_million': 5000000,
                  'observed_models': [billing.MODEL], 'sources': {kind: {'source': 'https://openai.com/api/pricing/',
                      'sha256': p.sha256(body), 'bytes': len(body)} for kind in billing.SOURCE_KINDS}}
        signature = billing.openssh('sign', '-f', str(self.signing_key), '-n', billing.NAMESPACE,
                                    data=billing.canonical(review)).decode()
        return billing.canonical({'review': review, 'signature': signature,
            'evidence': {kind: base64.b64encode(body).decode() for kind in billing.SOURCE_KINDS}})

    def test_wire_uses_only_canonical_reference_fingerprint_and_machine_binding(self):
        response = self.response()
        receiver = Mock(return_value=response)
        with (patch.object(courier, 'current_client', return_value=self.profile),
              patch.object(courier, 'local_station'), patch.object(courier, 'CLIENT', self.directory),
              patch.object(billing, 'credential_from', return_value=self.secret),
              patch.object(courier.candidate, 'invoke', receiver)):
            self.assertEqual(courier.exchange(self.reference, self.profile), response)
        argv, _ = receiver.call_args.args
        request = receiver.call_args.kwargs['data']
        self.assertEqual(request, billing.canonical(self.request))
        self.assertNotIn(self.secret.encode(), request)
        self.assertNotIn(self.secret, ' '.join(argv))
        self.assertEqual(argv[-3:], ['dp-billing-wire@100.64.0.3', courier.COMMAND, p.sha256(request)])
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn(f'UserKnownHostsFile={self.directory}/{self.profile["generation"]}.hosts', argv)
        self.assertIn('IdentityAgent=none', argv)
        self.assertEqual(receiver.call_args.kwargs['cap'], billing.BUNDLE_LIMIT)

    def test_rejects_other_reviewer_epoch_machine_or_credential_and_secret_evidence(self):
        for key, value in (('machine_sha256', 'b' * 64), ('reviewer_epoch', 'b' * 32)):
            with self.assertRaisesRegex(ValueError, 'admitted machine or reviewer enrollment'):
                courier.read_request(billing.canonical({**self.request, key: value}), self.profile)
        for key, value in (('credential_sha256', 'b' * 64), ('credential_ref', 'other')):
            with self.assertRaisesRegex(ValueError, 'differ from this exact request'):
                courier.read_response(self.response({**self.request, key: value}), self.request, time.time())
        with self.assertRaisesRegex(ValueError, 'must exclude API keys'):
            courier.read_response(self.response(body=self.secret.encode()), self.request, time.time())

    def test_owner_wizard_receives_existing_billing_gate_without_creating_offline_handoff(self):
        response = self.response()
        facts = ({}, {}, {'expires_unix': 2000})
        existing_key = self.directory / self.reference
        existing_key.write_bytes(b'exists in fixture')
        with (patch.object(owner, 'CREDENTIALS', self.directory),
              patch.object(owner, 'setup_secret', return_value=self.reference),
              patch.object(owner, 'provider_custody'),
              patch.object(owner, 'billing_authority', side_effect=[owner.SitePending('billing', 'Pending'), facts]),
              patch.object(billing, 'has_reviewer', return_value=True),
              patch.object(billing, 'setup_handoff') as offline,
              patch.object(billing, 'receive') as receive,
              patch.object(courier, 'current_client', return_value=self.profile),
              patch.object(courier, 'exchange', return_value=response)):
            self.assertEqual(owner.setup_provider(Mock(side_effect=AssertionError('unexpected question')),
                                                   Mock(), io.StringIO()), (self.reference, facts))
        receive.assert_called_once_with(self.reference, response)
        offline.assert_not_called()

    def test_no_station_means_explicit_offline_or_defer(self):
        with patch.object(courier, 'current_client', return_value=None):
            self.assertEqual(courier.setup_route(self.reference, lambda _: '', print), (False, None))
            self.assertEqual(courier.setup_route(self.reference, lambda _: 'offline', print), (True, None))
        with (patch.object(courier, 'current_client', return_value=self.profile),
              patch.object(courier, 'exchange', return_value=None),
              patch.object(courier, 'show_enrollment') as show):
            messages = []
            self.assertEqual(courier.setup_route(self.reference, lambda _: '', messages.append), (False, None))
            self.assertIn('exact request is at the independent billing station', messages[0])
            show.assert_not_called()


if __name__ == '__main__':
    unittest.main()
