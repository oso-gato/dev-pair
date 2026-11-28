"""Bounded checklist observation fixtures with no target or external network."""
from contextlib import contextmanager
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import io
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import destination_observation as o
import bootstrap

NOW = 2000
DNS = 'erebus.test-tailnet.ts.net'
MACHINE = '1' * 32
BOOT = str(uuid.UUID(int=12))
NEW_BOOT = str(uuid.UUID(int=13))


def split_site(plan):
    release = plan['kind'] == 'checklist-release'
    site_keys = o.SITE | (o.SITE_RELEASE if release else o.ACCESS)
    binding_keys = o.BINDING | (o.BINDING_RELEASE if release else set())
    return ({key: plan[key] for key in binding_keys}, {key: plan[key] for key in site_keys})


def fixture_plan():
    return {
        'version': 1, 'kind': 'checklist-release', 'job_id': 'owner-fixture',
        'source_sha': '1' * 40, 'release_source': '2' * 40,
        'publisher_run_id': 371, 'publisher_run_attempt': 2,
        'machine_id': MACHINE, 'boot_id': BOOT, 'issued_at': NOW - 500, 'expires_at': NOW + 500,
        'ceremony_id': str(uuid.UUID(int=42)), 'guard_sha256': '3' * 64, 'dns_name': DNS,
        'image': 'ghcr.io/oso-gato/dev-pair/checklist@sha256:' + '4' * 64, 'rollback_image': None,
        'clients': {name: 'fixture-' + name for name in o.VANTAGES},
        'provider_recovery': 'hostinger://unit-test/recovery',
        'public_addresses': {'ipv4': '8.8.8.8', 'ipv6': None},
        'tailnet_addresses': {'ipv4': '100.64.0.1', 'ipv6': 'fd7a:115c:a1e0::1'},
        'negative_routes': {
            'denied': {
                'ipv4': {'source_address': '100.64.0.2', 'control_address': '100.64.0.3', 'control_dns': 'control.example.com'},
                'ipv6': {'source_address': 'fd7a:115c:a1e0::2', 'control_address': 'fd7a:115c:a1e0::3', 'control_dns': 'control.example.com'},
            },
            'public': {
                'ipv4': {'source_address': '10.1.0.12', 'control_address': '1.1.1.1', 'control_dns': 'control.example.com'},
                'ipv6': None,
            },
        },
    }


def command(*args, payload=None):
    return subprocess.run(args, input=payload, capture_output=True, check=True, timeout=15).stdout


@contextmanager
def checklist_server(db):
    child = subprocess.Popen(['/usr/bin/python3', str(ROOT / 'examples/checklist/checklist.py'),
                              'serve', '--database', str(db), '--port', '0'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not select.select([child.stdout], [], [], 5)[0]:
            raise AssertionError('loopback checklist did not become ready')
        url = child.stdout.readline().decode().strip()
        if not url.startswith('http://127.0.0.1:'):
            raise AssertionError('the fixture did not bind only loopback')
        yield url + '/'
    finally:
        child.terminate()
        child.communicate(timeout=5)


@unittest.skipUnless(shutil.which('chromium') and importlib.util.find_spec('playwright'), 'managed browser runtime unavailable')
class RealChecklistBrowser(unittest.TestCase):
    def test_actual_page_completes_item_and_reconnects_to_it_after_process_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'checklist.db'
            title = 'Private checklist observation fixture'
            with checklist_server(db) as url:
                initial = o.browser_item(url, '127.0.0.1', title, add=True, sandbox=False)
                again = o.browser_item(url, '127.0.0.1', title, add=True, sandbox=False)
            with checklist_server(db) as url:
                reopened = o.browser_item(url, '127.0.0.1', title, add=False, sandbox=False)
        self.assertEqual((initial['added'], initial['completed']), (201, 200))
        self.assertEqual(again, reopened)
        self.assertEqual(reopened['item_id'], initial['item_id'])
        self.assertNotIn('added', reopened)


class FixtureReply(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(self.server.code)
        self.send_header('Content-Length', '0')
        self.end_headers()


@contextmanager
def tls_server(cert, private, code):
    with HTTPServer(('127.0.0.1', 0), FixtureReply) as server:
        server.code = code
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, private)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        worker.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            worker.join(5)


class RealHttpsDenial(unittest.TestCase):
    def test_actual_denial_uses_healthy_control_and_rejects_untrusted_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, private = str(Path(tmp) / 'cert.pem'), str(Path(tmp) / 'private.pem')
            command('/usr/bin/openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes',
                    '-keyout', private, '-out', cert, '-days', '1', '-subj', '/CN=checklist.fixture.test',
                    '-addext', 'subjectAltName=DNS:checklist.fixture.test,DNS:control.fixture.test')
            trust = ssl.create_default_context(cafile=cert)
            with tls_server(cert, private, 403) as denied, tls_server(cert, private, 204) as healthy:
                def request(host, ip, family, source):
                    port = healthy if host == 'control.fixture.test' else denied
                    return o.https_status(host, ip, family, source, tls=trust, port=port)

                route = {'source_address': '127.0.0.1', 'control_address': '127.0.0.1',
                         'control_dns': 'control.fixture.test'}
                result = o.denied_request('checklist.fixture.test', '127.0.0.1', 'ipv4', route, request=request)
                self.assertEqual([result[key] for key in ('control_before', 'target', 'control_after')], [204, 403, 204])
                with self.assertRaises(ssl.SSLCertVerificationError):
                    o.https_status('checklist.fixture.test', '127.0.0.1', 'ipv4', '127.0.0.1', port=denied)
                with self.assertRaisesRegex(o.Blocked, 'did not observe'):
                    o.denied_request('control.fixture.test', '127.0.0.1', 'ipv4', route, request=request)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.plan = fixture_plan()
        o.validate_plan(self.plan, NOW)
        self.plan_sha = o.digest(o.encoding(self.plan))
        self.expected = o.probe_plan(self.plan)

    def test_prepare_preserves_ceremony_and_rejects_other_site(self):
        binding, site = split_site(self.plan)
        prepared = o.prepare_plan(binding, site, NOW, None)
        self.assertEqual(o.prepare_plan(binding, site, NOW + 1, prepared), prepared)
        with self.assertRaisesRegex(o.Blocked, 'differs'):
            o.prepare_plan({**binding, 'dns_name': 'other.site.ts.net'}, site, NOW, None)

    def test_ordinary_export_refuses_wrong_or_missing_publisher_attempt(self):
        from product_release import product

        plan = self.plan
        release = {'source_sha': plan['release_source'], 'subject': plan['image'],
                   'run_id': plan['publisher_run_id'], 'run_attempt': plan['publisher_run_attempt'],
                   'source_tree': '5' * 40, 'artifact_sha256': plan['image'].rsplit(':', 1)[1],
                   'pull_request': 7, 'review_head': '6' * 40}
        live = dict(release, dns_name=DNS)
        promotion = {'job_id': plan['job_id'], 'phase': 'awaiting-independent-destination',
                     'release': release, 'binding': {'dns_name': DNS}}

        @contextmanager
        def release_gate():
            yield {'platform_sha': plan['source_sha']}, None, DNS

        destination = SimpleNamespace(
            release_gate=release_gate,
            current_proof_source=lambda provision: provision['platform_sha'],
            initial_activation=lambda: {'active': live, 'pending': None, 'route_pending': False, 'previous': None},
            serve_config=lambda dns: dns == DNS,
            destination_identity=lambda: {'machine_id': MACHINE, 'boot_id': BOOT},
            verify_final_guard=lambda: {name: plan[name] for name in ('provider_recovery', 'public_addresses', 'guard_sha256')},
        )
        job = plan['job_id']
        with tempfile.TemporaryDirectory() as tmp, patch.object(product, 'JOBS', Path(tmp)), \
                patch.object(o.os, 'geteuid', return_value=0), patch('destination_release.Destination', return_value=destination):
            root = product.job_path(job)
            root.mkdir(mode=0o700)
            product.durable_json(root / 'promotion.json', promotion)
            for value in (1, None, True):
                with self.subTest(activation_attempt=value):
                    if value is None:
                        live.pop('run_attempt')
                    else:
                        live['run_attempt'] = value
                    with self.assertRaisesRegex(o.Blocked, 'selected exact release'):
                        o.export_release(job)
            live['run_attempt'] = release['run_attempt']
            exported = o.export_release(job)
            self.assertEqual((exported['publisher_run_id'], exported['publisher_run_attempt']), (371, 2))
            self.assertEqual(exported['image'], plan['image'])
            release.pop('run_attempt')
            product.durable_json(root / 'promotion.json', promotion)
            with self.assertRaisesRegex(o.Blocked, 'selected exact release'):
                o.export_release(job)

    def test_receipt_verifies_distinct_keys_and_recovery_order_without_inventing_missing_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            signers = path / 'allowed_signers'
            private, lines = {}, []
            for role in o.VANTAGES:
                key = path / role
                command('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
                private[role] = key
                lines.append(o.observer_principal(role) + f' namespaces="{o.NAMESPACE}" ' + key.with_suffix('.pub').read_text())
            signers.write_text(''.join(lines))

            def save(name, record, role):
                raw = o.encoding(record)
                (path / name).write_bytes(raw)
                signature = command('/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(private[role]),
                                    '-n', o.NAMESPACE, payload=raw)
                (path / (name + '.sig')).write_bytes(signature)

            assemble = partial(o.assembled_receipt, self.plan, self.plan_sha, path, now=NOW,
                               verify=partial(o.verify_file, signers=signers))
            with self.assertRaisesRegex(o.Blocked, 'waiting for independent observation'):
                assemble()
            times = {'restart': NOW - 400, 'reboot': NOW - 350, 'clean-restore': NOW - 270,
                     'tailnet-loss': NOW - 180, 'tailnet-restored': NOW - 110}
            for event, stamp in times.items():
                before, after = {
                    'restart': (str(uuid.UUID(int=128)), str(uuid.UUID(int=129))),
                    'reboot': (BOOT, NEW_BOOT), 'clean-restore': ('volume-old', 'volume-clean'),
                    'tailnet-loss': ('private-reachable', 'private-unreachable'),
                    'tailnet-restored': ('private-unreachable', 'private-reachable'),
                }[event]
                record = o.event_record(self.plan, self.plan_sha, event, before, after, b'fixture only', stamp)
                save(o.record_name(event, 'event'), record, o.EVENTS[event])
            for (test, family), (_, role, _) in self.expected.items():
                if test in ('browser-add-and-complete', *o.CONTINUITY):
                    initial = test == 'browser-add-and-complete'
                    stamp = NOW - 450 if initial else times[o.CONTINUITY[test]] + 10
                    detail = {'page': 200, 'inventory': 200, 'peer': self.plan['tailnet_addresses'][family],
                              'item_id': 34 if initial and family == 'ipv6' else 33,
                              'item_title_sha256': o.digest(o.title_for(self.plan, family if initial else 'ipv4').encode())}
                    if initial:
                        detail.update(added=201, completed=200)
                    record = o.make_probe(self.plan, self.plan_sha, test, family, self.expected, 'checklist-browser', detail, stamp)
                elif test == 'unauthorized-app' or test == 'public-app' and family == 'ipv4':
                    route = self.plan['negative_routes'][role][family]
                    peer = self.plan['public_addresses' if role == 'public' else 'tailnet_addresses'][family]
                    detail = {'peer': peer, 'source_address': route['source_address'], 'target': 403,
                              'control_peer': route['control_address'], 'control_before': 200, 'control_after': 200}
                    record = o.make_probe(self.plan, self.plan_sha, test, family, self.expected, 'direct-verified-https', detail, NOW - 40)
                else:
                    stamp = times['tailnet-loss'] + 10 if test == 'tailnet-loss-app' else NOW - 50
                    record = o.external_probe(self.plan, self.plan_sha, test, family, self.expected, b'fixture only', stamp)
                    if test == 'public-app':
                        role = 'provider'
                save(o.record_name(test, family), record, role)
            receipt = assemble()
            publication = {'job_id', 'publisher_run_id', 'publisher_run_attempt'}
            fields = {'dns_name', 'release_source', 'image', 'guard_sha256', 'item_id', 'item_title_sha256', 'probes'} | publication
            self.assertEqual(set(receipt), o.BASE | fields)
            self.assertEqual({key: receipt[key] for key in publication}, {key: self.plan[key] for key in publication})
            self.assertEqual(receipt['boot_id'], NEW_BOOT)
            self.assertEqual(receipt['item_id'], 33)
            self.assertEqual(len(receipt['probes']), len(self.expected))
            final_principal = 'dev-pair-access-review'
            final_key = path / 'access-review-key'
            command('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(final_key))
            signers.write_text(final_principal + ' ' + final_key.with_suffix('.pub').read_text())
            final_path = path / 'receipt.json'
            final_path.write_bytes(o.encoding(receipt))
            final_path.with_suffix('.json.sig').write_bytes(command(
                '/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(final_key), '-n', o.FINAL_NAMESPACE,
                payload=final_path.read_bytes()))

            def verifier(*args, input_text, **_):
                return command(*args, payload=input_text.encode()).decode()

            with patch.object(bootstrap, 'checked_file', side_effect=Path), patch.object(bootstrap.time, 'time', return_value=NOW), \
                    patch.object(o.Bootstrap, 'destination_source', return_value=self.plan['source_sha']), \
                    patch.object(o.Bootstrap, 'destination_identity', return_value={'machine_id': MACHINE, 'boot_id': NEW_BOOT}), \
                    patch.object(o.Bootstrap, 'path', return_value=signers):
                D = o.Bootstrap(run=verifier)
                self.assertEqual(D.recent_destination_evidence(final_path, final_principal, fields, lifetime=1800), receipt)
            signers.write_text(''.join(lines))
            name = o.record_name('unauthorized-app', 'ipv4')
            record = json.loads((path / name).read_bytes())
            save(name, record, 'authorized')
            with self.assertRaisesRegex(o.Blocked, 'invalid independent signature for dev-pair-observer-denied'):
                assemble()

    def test_cutover_preserves_the_existing_bootstrap_probe_plan_and_requires_independent_recovery(self):
        plan = {key: self.plan[key] for key in o.PLAN}
        plan.update(kind='access-cutover', tailnet='test-tailnet', node_id='fixture-node', keys_sha256='5' * 64,
                    acl_sha256='6' * 64, execution_route='provider-recovery')
        o.validate_plan(plan, NOW)
        expected = o.probe_plan(plan)
        plan_sha = o.digest(o.encoding(plan))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for test, family in expected:
                stamp = NOW - 30
                if test == 'reopened-recovery':
                    stamp = NOW - 45
                elif 'restored' in test:
                    stamp = NOW - 10
                path = directory / o.record_name(test, family)
                record = o.external_probe(plan, plan_sha, test, family, expected, b'fixture only', stamp)
                path.write_bytes(o.encoding(record))

            def verify(path, principal):
                raw = path.read_bytes()
                record = json.loads(raw)
                self.assertEqual(principal, o.observer_principal(record['vantage']))
                return record, o.digest(raw)

            receipt = o.assembled_receipt(plan, plan_sha, directory, now=NOW, verify=verify)
            self.assertEqual(set(receipt), o.BASE | o.ACCESS | {'dns_name', 'provider_recovery', 'public_addresses', 'probes'})
            self.assertEqual(len(receipt['probes']), len(expected))
            path = directory / o.record_name('recovery-during-loss', 'provider')
            record = json.loads(path.read_bytes())
            path.write_bytes(o.encoding({**record, 'observed_at': NOW - 7}))
            with self.assertRaisesRegex(o.Blocked, 'before loss'):
                o.assembled_receipt(plan, plan_sha, directory, now=NOW, verify=verify)

    def test_host_selected_core_and_workload_plans_have_separate_exact_proofs(self):
        site = {key: self.plan[key] for key in o.SITE}
        site.update(kind=o.CORE_ACCESS_CUTOVER, tailnet='example', acl_sha256='c' * 64,
                    execution_route='provider-recovery', public_addresses={'ipv4': '8.8.8.8', 'ipv6': None})
        binding = {'version': 1, 'kind': o.CORE_ACCESS_CUTOVER, 'job_id': 'host-access', 'source_sha': 'a' * 40,
                   'machine_id': MACHINE, 'boot_id': BOOT, 'dns_name': DNS, 'node_id': 'node', 'tailnet': 'example',
                   'keys_sha256': 'b' * 64, 'tailnet_addresses': {'ipv4': '100.64.0.16', 'ipv6': 'fd7a:115c:a1e0::16'}}
        roles = {key: 'e' * 64 for key in o.ROLE_ARTIFACTS - {'job'}} | {'job': 'checklist'}
        selected = o.prepare_plan(binding, site, NOW - 60, None)
        self.assertNotIn(('maintenance-authorized', 'ipv4'), o.probe_plan(selected))
        with self.assertRaisesRegex(o.Blocked, 'differs'):
            o.prepare_plan({**binding, 'tailnet': 'foreign'}, site, NOW - 60, None)
        for workload in (False, True):
            if workload:
                chosen = {**binding, 'kind': o.WORKLOAD_ACCESS_CUTOVER, 'role_artifacts': roles}
                selected = o.prepare_plan(chosen, site, NOW - 60, None)
            expected = o.probe_plan(selected)
            plan_sha = o.digest(o.encoding(selected))
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for test, family in expected:
                    stamp = NOW - (45 if test == 'reopened-recovery' else 10 if 'restored' in test else 30)
                    exact = o.expected_role_probe(selected, test, family)
                    if exact:
                        with self.assertRaisesRegex(o.Blocked, 'exact confined'):
                            o.external_probe(selected, plan_sha, test, family, expected,
                                             o.encoding({**exact, 'address': '100.64.0.5'}), stamp)
                    transcript = o.encoding(exact) if exact else b'independent fixture observation'
                    probe = o.external_probe(selected, plan_sha, test, family, expected, transcript, stamp)
                    (directory / o.record_name(test, family)).write_bytes(o.encoding(probe))

                def verify(path, principal):
                    record = json.loads(path.read_bytes())
                    provider_absence = record['family'] == 'ipv6' and record['vantage'] == 'public'
                    self.assertEqual(principal, o.observer_principal('provider' if provider_absence else record['vantage']))
                    return record, o.digest(path.read_bytes())

                receipt = o.assembled_receipt(selected, plan_sha, directory, now=NOW, verify=verify)
                payload, sig = o.read_access_envelope(io.BytesIO(o.access_envelope(o.encoding(receipt), b'detached fixture')))
                self.assertEqual((json.loads(payload), sig), (receipt, b'detached fixture'))
                self.assertEqual(receipt['kind'], selected['kind'])
                self.assertEqual(receipt.get('role_artifacts'), roles if workload else None)
                with self.assertRaisesRegex(o.Blocked, 'exceeds'):
                    o.read_access_envelope(io.BytesIO(b'x' * (o.MAX_ACCESS_ENVELOPE + 1)))


if __name__ == '__main__':
    unittest.main()
