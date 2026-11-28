import io
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import nullcontext
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import agent_observer_station as station
import bootstrap
import destination_observation as d
import renewal as r
from renewal_site import CandidateAccess

measure_tailnet_policy = d.measure_tailnet_policy


class CandidateObservation(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2])))
        self.control = self.root / 'renewal'
        self.control.mkdir(mode=0o700)
        for name in ('plans', 'platform-bindings', 'platform-observations'):
            (self.control / name).mkdir(mode=0o700)
        self.previous, self.reference, self.platform = ('1' * 64, '2' * 64, '3' * 64)
        self.operation = 'agent-ci-94-' + self.platform[:24]
        self.identity = {'machine_id': 'a' * 32, 'boot_id': '12345678-1234-4234-8123-123456789abc'}
        self.route = {'source_sha': 'b' * 40, 'dns_name': 'erebus.lab.fixture.ts.net', 'node_id': 'node1', 'tailnet': 'fixture'}
        self.addresses = {'ipv4': '100.64.0.12', 'ipv6': 'fd7a:115c:a1e0::12'}
        self.guard = {'target': self.route, 'guard_sha256': 'c' * 64, 'acl_sha256': 'd' * 64, 'core_keys_sha256': 'e' * 64,
                      'provider_recovery': 'hostinger://test-vps/recovery', 'public_addresses': {'ipv4': '8.8.4.4', 'ipv6': None}}
        self.host = Mock()
        self.host.destination_identity.side_effect = lambda: self.identity.copy()
        self.host.tailscale_state.return_value = ({}, self.route['dns_name'])
        self.host.access_addresses.return_value = self.addresses
        self.host.access_keys_digest.return_value = self.guard['core_keys_sha256']
        self.host.identity_fields.return_value = (self.route['tailnet'], self.route['node_id'])
        self.host.verify_workload_access.return_value = self.guard
        self.host.verify_final_guard.return_value = self.guard
        self.signers = self.root / 'signers'
        self.host.path.return_value = self.signers
        self.releases = {}
        self.current = self.previous
        self.journal = None
        self.attempt = None
        self.controller = SimpleNamespace(root=self.root, control=self.control, live_release=lambda: self.current,
                                          release=lambda reference: self.releases[reference],
                                          transition=lambda: (self.attempt, self.journal))
        self.access = CandidateAccess(self.controller, self.host)
        self.site = {'version': 1, **self.route, 'machine_id': self.identity['machine_id'], 'tailnet_addresses': self.addresses,
                     'keys_sha256': self.guard['core_keys_sha256'], 'guard_sha256': self.guard['guard_sha256'],
                     'acl_sha256': self.guard['acl_sha256'], 'provider_recovery': self.guard['provider_recovery'],
                     'public_addresses': self.guard['public_addresses'], 'host_artifact_sha256': '4' * 64, 'devbox_image': '5' * 64}
        for reference, portable, changed in ((self.previous, '6' * 64, False), (self.reference, self.platform, True)):
            plan = {'development_manifests': {'checklist': ('7' if changed else '8') * 64}}
            plan_digest = r.identity(plan)
            r.replace_json(self.control / 'plans' / (plan_digest + '.json'), plan)
            self.releases[reference] = {'plan_sha256': plan_digest, 'config_sha256': '9' * 64,
                                        'components': {'host': {'artifact_sha256': self.site['host_artifact_sha256']},
                                        'devbox': {'artifact_sha256': self.site['devbox_image']},
                                        'maintenance-agent': {'platform_sha256': portable, 'artifact_sha256': ('a' if changed else 'b') * 64},
                                        'development-agent': {'artifact_sha256': ('c' if changed else 'd') * 64}}}
            binding = {'release_sha256': reference, 'platform_sha256': portable, 'base_platform_sha256': '6' * 64,
                       'site_config_sha256': 'a' * 64, 'plan_sha256': plan_digest}
            r.replace_json(self.control / 'platform-bindings' / (reference + '.json'), binding)
            r.replace_json(self.control / 'platform-observations' / (reference + '.json'),
                           {**binding, 'boot_id': self.identity['boot_id']})
        r.replace_json(self.control / 'site-current.json', self.previous)
        self.binding = self.access.prepare({'previous_release_sha256': self.previous, 'operation': self.operation}, self.reference)
        self.authorized = self.gen_key('authorized')
        self.reviewer = self.gen_key('reviewer')
        self.signers.write_text(
            'dev-pair-observer-authorized namespaces="' + d.NAMESPACE + '" ' + self.authorized.with_suffix('.pub').read_text() +
            'dev-pair-access-review namespaces="' + d.FINAL_NAMESPACE + '" ' + self.reviewer.with_suffix('.pub').read_text())
        collector = bootstrap.Bootstrap.observer_public_key(self.authorized.with_suffix('.pub').read_text())
        self.host.agent_observer_signers.return_value = (bootstrap.AGENT_OBSERVER_PREFIX + collector + '\n').encode()
        self.host.lock.return_value = nullcontext()
        self.enterContext(patch.object(d, 'checked_file', side_effect=lambda path: Path(path)))
        self.enterContext(patch.object(bootstrap, 'checked_file', side_effect=lambda path: Path(path)))
        self.enterContext(patch.object(d, 'configured_signers', return_value=self.signers))
        self.policy = self.enterContext(patch.object(d, 'measure_tailnet_policy', return_value=self.guard['acl_sha256']))
        self.calls = []

    def gen_key(self, name):
        path = self.root / name
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
        return path

    def probe(self, binding, family, envelope, *_):
        raw, signature = d.read_access_envelope(io.BytesIO(envelope))
        challenge, proof_digest = d.verify_bytes(raw, signature, 'dev-pair-observer-authorized', self.signers, d.NAMESPACE)
        d.agent_probe_challenge(challenge)
        self.assertEqual(challenge['candidate'], self.reference)
        self.assertEqual(challenge['family'], family)
        self.assertEqual(challenge['request_sha256'], d.digest(d.encoding(binding)))
        self.assertEqual(self.current, self.previous)
        self.calls.append((challenge['role'], family))
        return d.encoding({**d.expected_role_probe(binding, challenge['role'] + '-authorized', family),
                           'challenge_sha256': proof_digest, 'runtime_result_sha256': 'f' * 64})

    def response(self):
        observations = self.root / 'observations'
        observations.mkdir(mode=0o700, exist_ok=True)
        with patch.object(d, 'state_dir', return_value=observations), patch.object(d, 'ssh_candidate_probe', self.probe):
            wire = d.collect_candidate(self.binding, self.site, observations, None, None, self.authorized)
        collection = self.root / 'collection.bundle'
        collection.write_bytes(wire)
        return d.assemble_candidate(self.binding, self.site, collection, self.reviewer, None)

    def test_independent_probes_admit_exact_candidate_only_when_fenced_and_preserve_proof(self):
        wire = self.response()
        self.assertCountEqual(self.calls, [(role, family) for role in d.AGENT_ROLES for family in d.FAMILIES])
        self.access.receive(wire, self.binding)
        self.assertIsNone(self.access.admitted(self.reference, self.guard))
        with self.assertRaisesRegex(ValueError, 'fenced activation'):
            self.access.accept(self.reference, self.operation)
        self.journal = {'phase': 'applying', 'request': {'scope': 'agent', 'target_sha256': self.reference,
                                                        'previous_sha256': self.previous, 'operation': self.operation}}
        self.attempt = Path('attempt')
        (self.root / 'renewal-fence').mkdir()
        r.replace_json(self.root / 'renewal-fence' / 'frozen', self.attempt.name)
        self.access.accept(self.reference, self.operation)
        self.assertEqual(self.access.admitted(self.reference, self.guard)['role_artifacts'], self.binding['role_artifacts'])
        self.identity['boot_id'] = '12345678-1234-4234-8123-123456789abd'
        with self.assertRaisesRegex(ValueError, 'on this boot'):
            self.access.fresh(self.reference, self.previous, self.operation)
        self.assertIsNotNone(self.access.admitted(self.reference, self.guard))
        with self.assertRaisesRegex(ValueError, 'live site or exact candidate'):
            self.access.admitted(self.reference, {**self.guard, 'guard_sha256': '0' * 64})

    def test_incorrect_challenge_and_changed_route_never_get_signed(self):
        observations = self.root / 'observations'
        observations.mkdir(mode=0o700)
        with patch.object(d, 'state_dir', return_value=observations), patch.object(d, 'ssh_candidate_probe', return_value=b'{}'):
            with self.assertRaisesRegex(bootstrap.Blocked, 'does not prove the fresh challenge'):
                d.collect_candidate(self.binding, self.site, observations, None, None, self.authorized)
        with self.assertRaisesRegex(bootstrap.Blocked, 'admitted ingress'):
            d.candidate_site(self.binding, {**self.site, 'devbox_image': '0' * 64}, int(time.time()))

    def test_current_policy_change_blocks_signature_and_stale_signed_measurement_is_denied(self):
        self.policy.return_value = '0' * 64
        with self.assertRaisesRegex(bootstrap.Blocked, 'policy changed'):
            self.response()
        self.policy.return_value = self.guard['acl_sha256']
        raw, _ = d.read_access_envelope(io.BytesIO(self.response()))
        receipt = json.loads(raw)
        receipt['policy_measurement']['observed_at'] = receipt['issued_at'] - 1801
        changed = d.encoding(receipt)
        wire = d.access_envelope(changed, d.sign_observation(changed, self.reviewer, d.FINAL_NAMESPACE))
        with self.assertRaisesRegex(ValueError, 'policy measurement is stale'):
            self.access.receive(wire, self.binding)
        self.assertFalse(self.access.proof_path(self.reference).exists())

    def test_policy_request_is_read_only_and_refuses_unapproved_token_scope(self):
        credential = self.root / 'oauth.json'
        credential.write_bytes(d.encoding({'client_id': 'fixture-id', 'client_secret': 'fixture-secret'}))
        token = {'token_type': 'Bearer', 'expires_in': 3600, 'scope': 'policy_file:read', 'access_token': 'a' * 30}
        policy = {'acls': [], 'grants': []}
        with (patch.object(d, 'policy_credential', return_value=credential),
              patch.object(d, 'tailscale_json', side_effect=[token, policy]) as calls):
            actual = measure_tailnet_policy('fixture.example', credential)
        self.assertEqual(actual, d.digest(d.encoding(policy)))
        request, policy_get = calls.call_args_list
        self.assertEqual(request.args[:2], ('POST', '/api/v2/oauth/token'))
        self.assertEqual(parse_qs(request.kwargs['body'])['scope'], ['policy_file:read'])
        self.assertEqual(policy_get.args[:2], ('GET', '/api/v2/tailnet/fixture.example/acl'))
        self.assertEqual(policy_get.kwargs['headers']['Cache-Control'], 'no-cache')
        with (patch.object(d, 'policy_credential', return_value=credential),
              patch.object(d, 'tailscale_json', return_value={**token, 'scope': 'all:read'}) as calls,
              self.assertRaisesRegex(bootstrap.Blocked, 'exactly the approved policy read scopes')):
            measure_tailnet_policy('fixture.example', credential)
        self.assertEqual(calls.call_count, 1)

    def test_final_signer_cannot_replace_independently_signed_collector_results(self):
        raw, _ = d.read_access_envelope(io.BytesIO(self.response()))
        receipt = json.loads(raw)
        receipt['probes'][0]['reading']['runtime_result_sha256'] = '0' * 64
        changed = d.encoding(receipt)
        wire = d.access_envelope(changed, d.sign_observation(changed, self.reviewer, d.FINAL_NAMESPACE))
        with self.assertRaisesRegex(bootstrap.Blocked, 'invalid independent signature'):
            self.access.receive(wire, self.binding)
        self.assertFalse(self.access.proof_path(self.reference).exists())

    def test_collector_enrollment_distinguishes_keys_and_withdraws_only_its_exact_scope(self):
        host = bootstrap.Bootstrap(self.root)
        collector = host.observer_public_key(self.authorized.with_suffix('.pub').read_text())
        reviewer = host.observer_public_key(self.reviewer.with_suffix('.pub').read_text())
        old = (f'# Independently maintained trust\n'
               f'dev-pair-access-review namespaces="{d.FINAL_NAMESPACE}" {reviewer}\n'
               f'* namespaces="{d.NAMESPACE}" {reviewer}\n')
        host.atomic(bootstrap.TRUST_SIGNERS, old, mode=0o640)
        path = host.signer_trust_file()
        payload = d.encoding({'challenge': 'isolated collector scope'})
        accepted = d.sign_observation(payload, self.authorized, d.NAMESPACE)
        other = d.sign_observation(payload, self.reviewer, d.NAMESPACE)
        with self.assertRaisesRegex(bootstrap.Blocked, 'unavailable or withdrawn'):
            d.verify_agent_observer(payload, other, host)
        with self.assertRaisesRegex(bootstrap.Blocked, 'shared with another'):
            host.update_agent_observer(host.signer_fingerprint(reviewer), public=reviewer)
        with self.assertRaisesRegex(bootstrap.Blocked, 'fingerprint does not match'):
            host.update_agent_observer(host.signer_fingerprint(reviewer), public=collector)
        fingerprint = host.signer_fingerprint(collector)
        stock = subprocess.check_output(['/usr/bin/ssh-keygen', '-lf', str(self.authorized.with_suffix('.pub'))], text=True)
        self.assertEqual(fingerprint, stock.split()[1])
        host.atomic('/etc/ssh/dev-pair-keys/core', collector + '\n')
        with self.assertRaisesRegex(bootstrap.Blocked, 'named SSH or station transport require distinct keys'):
            host.update_agent_observer(fingerprint, public=collector)
        host.path('/etc/ssh/dev-pair-keys/core').unlink()
        import provider_billing

        host.atomic('/etc/dev-pair/provider-evidence/reviewer.json', '{}\n')
        with (patch.object(provider_billing, 'reviewer_state', return_value={'key': collector}, create=True),
              self.assertRaisesRegex(bootstrap.Blocked, 'collector and billing reviewers require distinct keys')):
            host.update_agent_observer(fingerprint, public=collector)
        host.path('/etc/dev-pair/provider-evidence/reviewer.json').unlink()
        host.update_agent_observer(fingerprint, public=collector)
        enrolled = path.read_bytes()
        host.update_agent_observer(fingerprint, public=collector)
        self.assertEqual(path.read_bytes(), enrolled)
        self.assertEqual(d.verify_agent_observer(payload, accepted, host)[0], json.loads(payload))
        with self.assertRaisesRegex(bootstrap.Blocked, 'invalid independent signature'):
            d.verify_agent_observer(payload, other, host)
        with self.assertRaisesRegex(bootstrap.Blocked, 'differs from the withdrawal'):
            host.update_agent_observer(host.signer_fingerprint(reviewer))
        host.update_agent_observer(fingerprint)
        self.assertEqual(path.read_text(), old)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        with self.assertRaisesRegex(bootstrap.Blocked, 'unavailable or withdrawn'):
            d.verify_agent_observer(payload, accepted, host)

    def test_broker_receives_real_unix_peer_and_denies_wrong_route_and_replay(self):
        import platform_release_intake

        root = Path(__file__).resolve().parents[1]
        serve = runpy.run_path(str(root / 'runtime' / 'renewal' / 'agent-observer'))['serve']
        challenge = {'role': 'maintenance', 'family': 'ipv4', 'source_sha': self.binding['source_sha'],
                     'candidate': self.reference, 'request_sha256': d.digest(d.encoding(self.binding)),
                     'challenge': '1b49542b-d290-4bd1-9f81-e8d5c558d453', 'expires_at': int(time.time()) + 90}
        raw = d.encoding(challenge)
        envelope = d.access_envelope(raw, d.sign_observation(raw, self.authorized, d.NAMESPACE))
        transport = {'SSH_CONNECTION': 'test fixture validated by route adapter'}
        route = {'local': self.addresses['ipv6']}
        self.host.observed_ssh_peer.return_value = route

        def driver(incoming, *, candidate, peer_reader, challenge):
            self.assertTrue(candidate)
            self.assertEqual(incoming['candidate'], self.reference)
            challenge(self.binding, peer_reader())
            return {'status': 'exact offline probe fixture'}

        def send():
            left, right = socket.socketpair()
            with left, right:
                left.sendall(d.encoding({'envelope': envelope.decode('ascii'), 'transport': transport}))
                left.shutdown(socket.SHUT_WR)
                serve(right)
                return json.loads(left.recv(8192))

        with (patch.dict(serve.__globals__, {'Bootstrap': lambda: self.host}),
              patch.object(r, 'DEFAULT_ROOT', self.root),
              patch.object(r.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())),
              patch.object(runpy, 'run_path', return_value={'access_probe': driver}),
              patch.object(platform_release_intake, 'protected', side_effect=Path),
              patch.object(r.protocol, 'workload_access_lease', return_value=nullcontext())):
            with self.assertRaisesRegex(bootstrap.Blocked, 'SSH family'):
                send()
            route['local'] = self.addresses['ipv4']
            self.assertEqual(send()['challenge_sha256'], d.digest(raw))
            with self.assertRaisesRegex(bootstrap.Blocked, 'spent or its retry was exhausted'):
                send()
        self.host.observed_ssh_peer.assert_called_with(client_pid=os.getpid(), transport=transport)

    def test_station_queue_produces_signed_response_through_three_fixed_roles(self):
        import day0_access_exchange as exchange

        mailbox = self.root / 'mailbox'
        observations = self.root / 'station-observations'
        for leaf in (mailbox, observations):
            leaf.mkdir(mode=0o700)
        site = self.root / 'site.json'
        site.write_bytes(d.encoding(self.site))
        request = d.encoding(self.binding)
        reference = d.digest(request)
        command = exchange.COMMAND + ' ' + reference
        initial = io.BytesIO()
        config = {'site': site, 'courier': {'user': 'courier', 'mailbox': mailbox},
                  'collector': {'user': 'collector', 'observations': observations,
                                'core_key': self.authorized, 'known_hosts': self.authorized, 'signer': self.authorized},
                  'reviewer': {'user': 'reviewer', 'signer': self.reviewer, 'acl_oauth': self.reviewer}}
        roles = []

        def call(profile, argv, *, data=None, **_):
            roles.append(profile['user'])
            if 'pending' in argv:
                return str(mailbox / (reference + '.request')).encode() + b'\n'
            if 'cleanup' in argv:
                return b''
            if 'install' in str(argv[0]):
                Path(argv[-1]).mkdir(mode=0o700)
                return b''
            if 'collect-candidate' in argv:
                directory = Path(argv[argv.index('--directory') + 1])
                with patch.object(d, 'state_dir', return_value=directory), patch.object(d, 'ssh_candidate_probe', self.probe):
                    return d.collect_candidate(self.binding, self.site, directory, None, None, self.authorized)
            if 'assemble-candidate' in argv:
                return d.assemble_candidate(self.binding, self.site, Path(argv[argv.index('--collection') + 1]), self.reviewer, None)
            self.assertEqual(argv[-2:], ('publish', reference))
            exchange.publish(mailbox, reference, io.BytesIO(data), int(time.time()))
            return b''

        with patch.object(exchange, 'state_dir', return_value=mailbox):
            exchange.receive(mailbox, command, io.BytesIO(request), initial, int(time.time()))
            self.assertFalse(initial.getvalue())
            self.assertEqual(station.reconcile(config, caller=call, scratch=self.root), 'candidate-observation-published')
            received = io.BytesIO()
            exchange.receive(mailbox, command, io.BytesIO(request), received, int(time.time()))
        self.access.receive(received.getvalue(), self.binding)
        self.assertEqual(roles, ['courier', 'collector', 'collector', 'collector', 'reviewer', 'courier'])
        self.assertEqual(self.controller.live_release(), self.previous)


if __name__ == '__main__':
    unittest.main()
