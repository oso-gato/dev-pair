"""Exercise the independent access transport and its signed-response boundary."""

from hashlib import sha256
import io
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import bootstrap
import day0_access_exchange as access
from destination_observation import access_envelope, encoding

NOW = int(time.time())
REQUEST = {
    'version': 1, 'kind': bootstrap.CORE_ACCESS_CUTOVER, 'source_sha': 'a' * 40,
    'machine_id': 'b' * 32, 'boot_id': '11111111-2222-3333-4444-555555555555',
    'job_id': 'host-access', 'node_id': 'node', 'tailnet': 'example.ts.net', 'dns_name': 'host.example.ts.net',
    'keys_sha256': 'c' * 64, 'tailnet_addresses': {'ipv4': '100.64.0.1', 'ipv6': 'fd7a:115c:a1e0::1'},
}
RAW = encoding(REQUEST)
ID = sha256(RAW).hexdigest()
COMMAND = f'{access.COMMAND} {ID}'


class AccessExchangeTests(unittest.TestCase):
    def setUp(self):
        home = pwd.getpwuid(os.geteuid()).pw_dir
        self.mailbox = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='dev-pair-courier-test-', dir=home)))

    def run_cli(self, *args, raw=b'', original=''):
        return subprocess.run(['/usr/bin/python3', '-IB', str(TOOLS / 'day0_access_exchange.py'),
                               '--mailbox', str(self.mailbox), *args],
                              env={**access.ENV, 'SSH_ORIGINAL_COMMAND': original},
                              input=raw, capture_output=True, timeout=5, check=False)

    def test_station_cli_round_trip_preserves_an_actual_independent_signature(self):
        first = self.run_cli('receive', raw=RAW, original=COMMAND)
        self.assertEqual((first.returncode, first.stdout, first.stderr), (0, b'', b''))
        leaf = self.mailbox / (ID + '.request')
        self.assertEqual(leaf.read_bytes(), RAW)
        pending = self.run_cli('pending', '--kind', REQUEST['kind'])
        self.assertEqual(pending.stdout.decode().strip(), str(leaf))
        self.assertEqual(self.run_cli('pending', '--kind', 'agent-workload-candidate').stdout, b'')

        with tempfile.TemporaryDirectory(dir=self.mailbox) as path:
            key = Path(path) / 'signer'
            receipt = Path(path) / 'receipt.json'
            signers = Path(path) / 'allowed_signers'
            receipt.write_bytes(encoding({**REQUEST, 'expires_at': 2_200_000_000}))
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-N', '', '-t', 'ed25519', '-f', str(key)],
                           check=True, timeout=5, capture_output=True)
            signers.write_bytes(f'{access.ACCESS_PRINCIPAL} namespaces="{access.ACCESS_NAMESPACE}" '.encode() +
                                key.with_suffix('.pub').read_bytes())
            subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', access.ACCESS_NAMESPACE,
                            str(receipt)], check=True, timeout=5, capture_output=True)
            envelope = access_envelope(receipt.read_bytes(), receipt.with_suffix('.json.sig').read_bytes())
            published = self.run_cli('publish', ID, raw=envelope)
            self.assertEqual((published.returncode, published.stderr), (0, b''))
            second = self.run_cli('receive', raw=RAW, original=COMMAND)
            self.assertEqual((second.returncode, second.stdout, second.stderr), (0, envelope, b''))
            self.assertEqual(self.run_cli('pending').stdout, b'')
            self.assertEqual(len(list(self.mailbox.glob('*.request'))), 1)
            payload, signature = access.read_access_envelope(io.BytesIO(second.stdout))
            self.assertEqual(signature, receipt.with_suffix('.json.sig').read_bytes())
            self.assertEqual(subprocess.run(
                ['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', access.ACCESS_PRINCIPAL,
                 '-n', access.ACCESS_NAMESPACE, '-s', str(receipt.with_suffix('.json.sig'))],
                input=payload, timeout=5, capture_output=True).returncode, 0)

    def test_rejects_foreign_request_or_response_and_refreshes_an_expired_receipt(self):
        outgoing = io.BytesIO()
        with self.assertRaisesRegex(bootstrap.Blocked, 'digest differs'):
            access.receive(self.mailbox, COMMAND, io.BytesIO(encoding({**REQUEST, 'source_sha': 'd' * 40})),
                           outgoing, NOW)
        with self.assertRaisesRegex(bootstrap.Blocked, 'fixed access request'):
            access.receive(self.mailbox, COMMAND + ' ; extra', io.BytesIO(RAW), outgoing, NOW)
        self.assertEqual(list(self.mailbox.iterdir()), [])
        access.receive(self.mailbox, COMMAND, io.BytesIO(RAW), outgoing, NOW)
        wrong = access_envelope(encoding({**REQUEST, 'kind': bootstrap.WORKLOAD_ACCESS_CUTOVER,
                                          'expires_at': NOW + 120}), b'fixture')
        with self.assertRaisesRegex(bootstrap.Blocked, 'does not identify'):
            access.publish(self.mailbox, ID, io.BytesIO(wrong), NOW)
        first = access_envelope(encoding({**REQUEST, 'expires_at': NOW + 1}), b'fixture')
        access.publish(self.mailbox, ID, io.BytesIO(first), NOW)
        with self.assertRaisesRegex(bootstrap.Blocked, 'already exists'):
            access.publish(self.mailbox, ID, io.BytesIO(first.replace(b'Zml4dHVyZQ==', b'c2Vjb25k')), NOW)
        access.receive(self.mailbox, COMMAND, io.BytesIO(RAW), outgoing, NOW + 1)
        self.assertEqual(outgoing.getvalue(), b'')
        renewed = access_envelope(encoding({**REQUEST, 'expires_at': NOW + 120}), b'fixture')
        access.publish(self.mailbox, ID, io.BytesIO(renewed), NOW + 1)
        access.receive(self.mailbox, COMMAND, io.BytesIO(RAW), outgoing, NOW + 1)
        self.assertEqual(outgoing.getvalue(), renewed)

    def test_transport_does_not_inherit_ssh_config_forwarding_or_unpinned_hosts(self):
        def ssh(command, **kwargs):
            self.assertEqual(command[:6], ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-i', str(access.IDENTITY)])
            self.assertEqual(command[-4:], ['--', 'courier@100.64.0.8', access.COMMAND, ID])
            for option in ('StrictHostKeyChecking=yes', 'IdentityAgent=none', 'ForwardAgent=no',
                           'GlobalKnownHostsFile=/dev/null', 'ClearAllForwardings=yes'):
                self.assertIn(option, command)
            self.assertEqual(kwargs['input'], RAW)
            self.assertEqual(kwargs['env'], access.ENV)
            kwargs['stdout'].write(b'fixture bytes')
            return subprocess.CompletedProcess(command, 0)

        temporary = tempfile.TemporaryFile
        with (patch.object(access, 'configuration', return_value={'host': '100.64.0.8', 'user': 'courier'}),
              patch.object(access.subprocess, 'run', side_effect=ssh),
              patch.object(access.tempfile, 'TemporaryFile', side_effect=lambda **_: temporary(dir=self.mailbox))):
            self.assertEqual(access.exchange(RAW), b'fixture bytes')
        with patch.object(access, 'configuration', return_value=None):
            with self.assertRaises(access.ExchangeUnavailable):
                access.exchange(RAW)
        for host, account in [('192.0.2.1', 'courier'), ('100.64.0.1', 'root'), ('fd7a:115c:a1e0::1%lo', 'courier'),
                              ('100.64.0.1', 'a -o ForwardAgent=yes')]:
            with self.assertRaises(bootstrap.Blocked):
                access.contact(host, account)

    def test_station_capacity_is_finite_and_an_existing_request_is_repeatable(self):
        for offset in range(access.MAILBOX_LIMIT):
            raw = encoding({**REQUEST, 'source_sha': f'{offset:040x}'})
            access.receive(self.mailbox, f'{access.COMMAND} {sha256(raw).hexdigest()}', io.BytesIO(raw),
                           io.BytesIO(), NOW)
        with self.assertRaisesRegex(bootstrap.Blocked, 'mailbox is full'):
            access.receive(self.mailbox, COMMAND, io.BytesIO(RAW), io.BytesIO(), NOW)
        raw = encoding({**REQUEST, 'source_sha': '0' * 40})
        access.receive(self.mailbox, f'{access.COMMAND} {sha256(raw).hexdigest()}', io.BytesIO(raw),
                       io.BytesIO(), NOW)
        self.assertEqual(len(list(self.mailbox.glob('*.request'))), access.MAILBOX_LIMIT)


if __name__ == '__main__':
    unittest.main()
