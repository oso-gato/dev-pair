import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import provider_billing as billing
import provider_broker as broker
from ledger_recovery import write_private

REF = 'first-project'
SECRET = 'sk-proj-offline-fixture-never-sent'
ORG = 'org-example'
PROJECT = 'proj_example'


@unittest.skipUnless(os.getuid() == 0, 'provider issuance needs mapped root for protected credentials')
class ProviderBillingTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o077))
        directory = tempfile.TemporaryDirectory(prefix='.billing-test-', dir=ROOT)
        self.addCleanup(directory.cleanup)
        self.directory = root = Path(directory.name)
        self.credentials = root / 'credentials'
        self.evidence = root / 'evidence'
        self.signers = root / 'allowed_signers'
        self.key = root / 'reviewer'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)],
                       timeout=5, check=True)
        write_private(self.signers, b'provider-billing namespaces="dev-pair-provider-billing" ' +
                      self.key.with_suffix('.pub').read_bytes())
        self.secret = root / 'external-key'
        write_private(self.secret, SECRET.encode())
        self.enterContext(mock.patch.multiple(billing, CREDENTIALS=self.credentials, EVIDENCE=self.evidence,
                                              SIGNERS=self.signers))
        self.enterContext(mock.patch.object(billing, 'protected', side_effect=self.protected))
        self.enterContext(mock.patch.dict(os.environ, SUDO_USER=''))
        self.now = int(time.time())
        self.clock = self.enterContext(mock.patch.object(billing.time, 'time', return_value=self.now))
        self.connection = self.enterContext(mock.patch.object(broker.http.client, 'HTTPSConnection'))
        self.response = self.connection.return_value.getresponse.return_value
        self.response.status = 200
        self.response.read.return_value = billing.canonical({'id': billing.MODEL})
        self.assertEqual(self.cli('register', '--credential-ref', REF, '--secret-file', str(self.secret))[0], 0)
        code, raw, errors = self.cli('request', '--credential-ref', REF)
        self.assertEqual((code, errors), (0, ''))
        request = root / 'review-request.json'
        write_private(request, raw)
        self.review_arguments = ['review', '--request', str(request), '--signing-key', str(self.key),
                                 '--organization', ORG, '--project', PROJECT, '--expires-unix', str(self.now + 7200),
                                 '--context-tokens', '200000', '--input-usd-per-million', '2.123456',
                                 '--output-usd-per-million', '4', '--response-model', billing.MODEL,
                                 '--response-model', billing.MODEL + '-observed']
        for kind in billing.SOURCE_KINDS:
            evidence = root / kind
            write_private(evidence, ('Synthetic provider source: ' + kind).encode())
            self.review_arguments.extend(('--' + kind.replace('_', '-') + '-source', 'record:fixture-' + kind, str(evidence)))

    def protected(self, path, *, directory=False, private=False):
        # The mapped test UID owns this fixture tree, while the host's root is unmapped.
        self.assertTrue(path.is_relative_to(self.directory))
        self.assertEqual(path.resolve(strict=True), path)
        for item in (path, *(parent for parent in path.parents if parent.is_relative_to(self.directory))):
            node = item.lstat()
            self.assertEqual((node.st_uid, node.st_gid), (0, 0))
            self.assertFalse(node.st_mode & 0o022)
            if item != path or directory:
                self.assertTrue(stat.S_ISDIR(node.st_mode))
            else:
                self.assertTrue(stat.S_ISREG(node.st_mode) and node.st_nlink == 1)
        if private:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if directory else 0o600)
        return path

    def cli(self, *args, data=b''):
        with io.TextIOWrapper(io.BytesIO()) as output, io.TextIOWrapper(io.BytesIO(data)) as incoming:
            with mock.patch.multiple(sys, argv=['provider_billing.py', *args], stdout=output, stdin=incoming,
                                     stderr=io.StringIO()):
                result = billing.main()
                output.flush()
                return result, output.buffer.getvalue(), sys.stderr.getvalue()

    def reviewed(self, *extra):
        result = self.cli(*self.review_arguments, *extra)
        self.assertEqual((result[0], result[2]), (0, ''))
        self.assertNotIn(SECRET.encode(), result[1])
        return result[1]

    def receive(self, raw):
        return self.cli('receive', '--credential-ref', REF, data=raw)

    def test_cli_issues_reviewed_terms_on_exact_read_only_project_lookup(self):
        private_request = self.directory / 'output-request.json'
        self.assertEqual(self.cli('request', '--credential-ref', REF, '--output', str(private_request)), (0, b'', ''))
        private_bundle = self.directory / 'output-bundle'
        self.assertEqual(self.cli(*self.review_arguments, '--request', str(private_request),
                                  '--output', str(private_bundle)), (0, b'', ''))
        self.assertEqual(stat.S_IMODE(private_bundle.stat().st_mode), 0o600)
        raw = private_bundle.read_bytes()
        self.assertNotIn(SECRET.encode(), raw)
        self.assertEqual(self.cli('receive', '--credential-ref', REF, '--bundle', str(private_bundle))[0], 0)
        self.assertEqual(self.receive(raw)[0], 0)
        request = self.connection.return_value.request
        request.assert_called_once()
        self.assertEqual(request.call_args.args, ('GET', '/v1/models/' + billing.MODEL))
        self.assertEqual(self.connection.call_args.args, ('api.openai.com', 443))
        self.assertEqual(request.call_args.kwargs['headers']['OpenAI-Organization'], ORG)
        self.assertEqual(request.call_args.kwargs['headers']['OpenAI-Project'], PROJECT)
        self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer ' + SECRET)
        self.assertIsNone(request.call_args.kwargs['body'])
        pricing, proofs, review = billing.authority(REF)
        self.assertEqual(pricing['max_context_tokens'], 200000)
        self.assertEqual(pricing['input_microusd_per_million'], 2123456)
        self.assertEqual(pricing['observed_models'], [billing.MODEL, billing.MODEL + '-observed'])
        for body in proofs.values():
            self.assertNotIn(SECRET.encode(), body)
        self.assertEqual(billing.current_digest(self.evidence / REF), billing.review_digest(review))

    def test_wrong_scope_signature_attachment_or_model_cannot_issue(self):
        raw = self.reviewed()
        changed = json.loads(raw)
        changed['review']['max_context_tokens'] -= 1
        self.assertEqual(self.receive(billing.canonical(changed))[0], 2)
        changed = json.loads(raw)
        attachment = changed['evidence']['context']
        changed['evidence']['context'] = ('A' if attachment[0] == 'B' else 'B') + attachment[1:]
        self.assertEqual(self.receive(billing.canonical(changed))[0], 2)
        self.assertEqual(self.cli('receive', '--credential-ref', 'unknown', data=raw)[0], 2)
        self.connection.assert_not_called()
        self.response.status = 404
        code, _, errors = self.receive(raw)
        self.assertEqual(code, 2)
        self.assertIn('model-unavailable', errors)
        self.assertFalse((self.evidence / REF / billing.ACTIVE).exists())

    def test_source_attachment_containing_an_api_key_cannot_be_signed(self):
        (self.directory / 'context').write_bytes(SECRET.encode())
        code, output, errors = self.cli(*self.review_arguments)
        self.assertEqual((code, output), (2, b''))
        self.assertIn('exclude API keys', errors)
        self.assertNotIn(SECRET, errors)

    def test_interrupted_pointer_publication_reuses_the_exact_retained_review(self):
        raw = self.reviewed()
        review = json.loads(raw)['review']
        reference = self.evidence / REF
        version = reference / billing.review_digest(review)
        with mock.patch.object(Path, 'replace', side_effect=OSError('interrupted active pointer')):
            self.assertEqual(self.receive(raw)[0], 2)
        self.assertTrue(version.is_dir())
        self.assertFalse((reference / billing.ACTIVE).exists())
        inode = version.stat().st_ino
        self.assertEqual(self.receive(raw)[0], 0)
        self.assertEqual(version.stat().st_ino, inode)
        self.assertEqual(billing.authority(REF)[2], review)

    def test_project_renewal_preserves_exact_receipt_and_fences_paid_requests(self):
        original = self.reviewed()
        self.assertEqual(self.receive(original)[0], 0)
        _, proofs, old_review = billing.authority(REF)
        original_digest = billing.review_digest(old_review)
        old = broker.Provider(SECRET, organization=ORG, project=PROJECT, review=old_review)
        self.clock.return_value += 1
        renewal = self.reviewed('--input-usd-per-million', '7')
        self.assertEqual(self.receive(renewal)[0], 0)
        self.assertEqual(self.receive(original)[0], 2)
        call = self.connection.return_value.request
        call.reset_mock()
        with self.assertRaisesRegex(ValueError, 'superseded'):
            old.responses(b'fixture', time.monotonic() + 10)
        call.assert_not_called()
        self.assertEqual(billing.proofs_at(self.evidence / REF / original_digest), proofs)
        pricing, _, current = billing.authority(REF)
        self.assertEqual(pricing['input_microusd_per_million'], 7000000)
        new = broker.Provider(SECRET, organization=ORG, project=PROJECT, review=current)
        new.responses(b'fixture', time.monotonic() + 10)
        self.assertEqual(call.call_args.args, ('POST', '/v1/responses'))
        self.assertEqual(call.call_args.kwargs['headers']['OpenAI-Project'], PROJECT)
        self.assertEqual(call.call_args.kwargs['headers']['OpenAI-Organization'], ORG)
        call.reset_mock()
        self.clock.return_value = current['expires_unix']
        with self.assertRaisesRegex(ValueError, 'expired'):
            new.responses(b'fixture', time.monotonic() + 10)
        call.assert_not_called()

    def test_changed_key_fails_before_discovery_or_paid_effect(self):
        signed = self.reviewed()
        self.assertEqual(self.receive(signed)[0], 0)
        _, _, review = billing.authority(REF)
        scoped = broker.Provider(SECRET, organization=ORG, project=PROJECT, review=review)
        key = self.credentials / REF
        key.write_bytes(b'sk-proj-different-fixture-never-sent')
        self.connection.reset_mock()
        self.assertEqual(self.receive(signed)[0], 2)
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            scoped.responses(b'fixture', time.monotonic() + 10)
        self.connection.assert_not_called()


if __name__ == '__main__':
    unittest.main()
