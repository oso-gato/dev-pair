"""Offline checks for the scoped role-to-provider transport."""

from contextlib import closing, contextmanager, nullcontext
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import gptbox_runtime as runtime
import provider_broker as broker


UUID = '01932ec5-b41c-7181-851a-8c780aa48246'
MODEL = 'gpt-6.2-sol'


def selection():
    return {'schema': 2, 'operation': 'turn-one', 'action': 'start', 'role': 'development',
            'job': 'sample', 'logical_session': 'worker', 'session_uuid': None, 'workspace': '/work/job',
            'provider': 'gptbox', 'model': MODEL, 'effort': 'high', 'standards_sha': runtime.STANDARDS,
            'repository': 'owner/product', 'candidate_sha': 'a' * 40, 'agreement_sha256': 'e' * 64,
            'requirements_sha256': '1' * 64, 'config_sha256': '2' * 64,
            'prompt_sha256': '3' * 64, 'startup_sha256': '4' * 64, 'turn_seconds': 30}


def grant(request_sha):
    return {'schema': 1, 'auth_profile': 'openai-api-key', 'request_sha256': request_sha,
            'allowance_ref': 'offline-fixture', 'allowance_sha256': 'a' * 64, 'peer_uid': os.getuid(), 'peer_gid': os.getgid(),
            'spend_microusd': 1600, 'seconds': 30, 'expires_unix': 1800000000, 'max_requests': 2,
            'max_request_bytes': 4096, 'max_context_tokens': 1024, 'max_output_tokens': 32,
            'input_microusd_per_million': 1000000, 'output_microusd_per_million': 2000000,
            'observed_models': [MODEL]}


def request(**changes):
    return broker.canonical({'model': MODEL, 'reasoning': {'effort': 'high'}, 'stream': True, 'store': False,
                             'tools': [], 'input': [{'type': 'message', 'role': 'user',
                                                    'content': [{'type': 'input_text', 'text': 'fixture-private-text'}]}],
                             **changes})


def events(model=MODEL):
    response = {'id': 'resp_fixture', 'model': model}
    completed = {**response, 'usage': {'input_tokens': 12, 'output_tokens': 3, 'total_tokens': 15}}
    return b''.join(broker.sse(kind, {'type': kind, 'response': value})
                    for kind, value in (('response.created', response), ('response.completed', completed)))


class FakeResponse(io.BytesIO):
    status = 200

    def read1(self, length):
        # Make complete provider frames cross multiple reads.
        return super().read1(min(length, 19))

    @staticmethod
    def getheader(name, default=None):
        return 'text/event-stream' if name == 'Content-Type' else default


class FakeProvider:
    def __init__(self, reply):
        self.reply = reply
        self.bodies = []

    def responses(self, body, _deadline):
        self.bodies.append(json.loads(body))
        stream = FakeResponse(self.reply)
        return stream, stream


@contextmanager
def local_runtime(path, request_sha):
    with patch.object(runtime, 'PROVIDER_SOCKET', path), runtime.HTTPServer(('127.0.0.1', 0), runtime.LocalResponses) as server:
        server.binding = bytes.fromhex(request_sha)
        server.deadline = time.monotonic() + 3
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join(timeout=2)


class JobSelectionTests(unittest.TestCase):
    def read(self, data, **changes):
        raw = broker.canonical(data)
        arguments = {'expected_sha': hashlib.sha256(raw).hexdigest(), 'role': data['role'],
                     'job': data['job'], 'operation': data['operation'], **changes}
        return runtime.job_selection(raw, **arguments)

    def test_start_and_resume_use_fixed_version_and_explicit_uuid(self):
        start = self.read(selection())
        resume = self.read({**start, 'action': 'resume', 'operation': 'turn-two', 'session_uuid': UUID})
        self.assertEqual(runtime.job_codex_argv(start, 4567)[-1:], ['-'])
        self.assertEqual(runtime.job_codex_argv(resume, 4567)[-3:], ['resume', UUID, '-'])
        for args in (runtime.job_codex_argv(start, 4567), runtime.job_codex_argv(resume, 4567)):
            self.assertIn(MODEL, args)
            self.assertIn('model_reasoning_effort="high"', args)
            self.assertNotIn('--last', args)

    def test_rejects_cross_role_digest_and_resume_without_uuid(self):
        for value, changes in ((selection(), {'role': 'maintenance'}), (selection(), {'expected_sha': '0' * 64}),
                               ({**selection(), 'action': 'resume'}, {}), ({**selection(), 'session_uuid': UUID}, {}),
                               ({**selection(), 'workspace': '/workspace/product'}, {})):
            with self.subTest(value=value), self.assertRaises((RuntimeError, ValueError)):
                self.read(value, **changes)

    def test_resume_retains_saved_selection_while_candidate_changes(self):
        start = self.read(selection())
        resume = self.read({**start, 'action': 'resume', 'session_uuid': UUID, 'candidate_sha': 'b' * 40})
        self.assertEqual(runtime.session_binding(start, UUID), runtime.session_binding(resume, UUID))
        self.assertNotEqual(runtime.session_binding(start, UUID), runtime.session_binding({**resume, 'effort': 'medium'}, UUID))

    def test_nested_role_mounts_match_image_policy(self):
        from devbox import db

        self.assertEqual(set(db.ADMISSION_ROLE), set(map(str, runtime.JOB_READONLY_MOUNTS)))
        policy, _ = runtime.role_policy('fixture directive', live=True, development=True)
        self.assertEqual(policy['permissions']['product-child']['filesystem'][db.JOB_BUILD], 'write')
        self.assertNotIn(db.JOB_BUILD, runtime.ENV['PATH'])

    def test_probe_and_live_options_reach_host_with_public_argv(self):
        from bootstrap import Bootstrap
        import devbox
        import job_protocol as protocol
        from test_devbox import manifest

        with tempfile.TemporaryDirectory(prefix='dp-role-argv-') as path:
            fixture = Path(path).resolve()
            host = Bootstrap(fixture)
            root = host.path('/var/lib/dev-pair')
            candidate = root / 'manifest.json'
            host.atomic('/var/lib/dev-pair/manifest.json', '{}')
            marker = root / protocol.WORKLOAD_ACCESS
            lease = root / protocol.WORKLOAD_LEASE
            selected = manifest()
            roles = {'release_sha256': 'a' * 64, 'maintenance_image': 'f' * 64,
                     'development_image': selected['inner']['image_id'], 'devbox_image': selected['outer']['image_id']}
            setup = ['--manifest', str(candidate), '--sha256', 'b' * 64]
            live = ['--operation', 'resume-turn', '--request-sha256', 'c' * 64]
            operation = ('b' * 64, 'resume-turn', 'c' * 64)

            # Map only the temporary tree's controller ownership and its host ancestors.
            # Keep the fixture file modes, identities, contents, and kernel locks real.
            ancestors = set(marker.parents) | set(lease.parents)
            real_lstat, real_fstat = Path.lstat, os.fstat
            protected_inodes = set()

            def controller_lstat(node_path):
                node = real_lstat(node_path)
                if node_path in ancestors:
                    mode = node.st_mode if node_path.is_relative_to(fixture) else node.st_mode & ~0o022
                    return SimpleNamespace(st_uid=0, st_mode=mode)
                return node

            def controller_fstat(fd):
                node = real_fstat(fd)
                if (node.st_dev, node.st_ino) in protected_inodes:
                    return SimpleNamespace(st_uid=0, st_mode=node.st_mode, st_nlink=node.st_nlink,
                                           st_size=node.st_size, st_dev=node.st_dev, st_ino=node.st_ino)
                return node

            def launch_turn(*args):
                if args[-1] is not None:
                    with self.assertRaises(BlockingIOError), protocol.workload_access_lease(root, exclusive=True):
                        self.fail('activation acquired the lease during the admitted turn')
                return {'turn': {'status': 'completed-turn'}}

            def execute(argv, expected, blocked=None):
                with self.subTest(argv=argv), patch.object(sys, 'argv', ['devbox.py', *argv]), \
                        patch.object(sys, 'stdout', new_callable=io.StringIO), patch.object(devbox.signal, 'signal'), \
                        patch.object(sys, 'stderr', new_callable=io.StringIO) as diagnostics, \
                        patch.object(devbox, 'ROOT', root / 'development'), \
                        patch.object(Path, 'lstat', controller_lstat), patch.object(os, 'fstat', controller_fstat), \
                        patch.object(devbox, 'host_account'), patch.object(devbox, 'host_env'), patch.object(devbox, 'enforcing'), \
                        patch.object(devbox.db, 'read_manifest', return_value=selected), \
                        patch.object(devbox.db, 'immutable_image'), patch.object(devbox.db, 'remove_owned'), \
                        patch.object(devbox, 'ownership', return_value=nullcontext(('owner', 'hooks'))), \
                        patch.object(devbox, 'placement', return_value=({}, {})) as placement, \
                        patch.object(devbox, 'launch', side_effect=launch_turn) as launch:
                    self.assertEqual(devbox.main(), 2 if blocked else 0, diagnostics.getvalue())
                    if blocked:
                        self.assertIn(blocked, diagnostics.getvalue())
                        placement.assert_not_called()
                        launch.assert_not_called()
                        return
                    self.assertEqual(placement.call_args.args[-1], expected)
                    self.assertEqual(launch.call_args.args[-1], expected)

            execute(['run', *setup], None)
            execute(['run', *setup, *live], operation, 'workload access observation is unavailable')
            host.publish_workload_gate('admitted', roles)
            for protected in (marker, lease):
                node = protected.stat()
                protected_inodes.add((node.st_dev, node.st_ino))
            execute(['run', *setup, *live], operation)
            execute([*live, 'run', *setup], operation)


class ProviderGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dp-bridge-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'peer'
        self.path.mkdir(mode=0o750)
        self.path.chmod(0o750)
        self.receipt = self.root / 'evidence.json'
        self.request_sha = hashlib.sha256(broker.canonical(selection())).hexdigest()
        self.grant = grant(self.request_sha)

    @contextmanager
    def provider(self, reply, allowance=None):
        api = FakeProvider(reply)
        journal = broker.Journal(self.receipt, selection(), self.grant)
        path = self.path / 'responses.sock'
        errors = []

        def listen():
            try:
                broker.listen(path, api, selection(), self.grant, journal, time.monotonic() + 1.5, allowance=allowance)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=listen)
        worker.start()
        try:
            end = time.monotonic() + 1
            while journal.value['status'] != 'listening' and time.monotonic() < end:
                time.sleep(.002)
            self.assertEqual(journal.value['status'], 'listening')
            yield api, path
        finally:
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(path.exists())
            self.assertFalse(errors)

    def post(self, port, path='/v1/responses', data=None, token=runtime.LOCAL_BEARER):
        with closing(http.client.HTTPConnection('127.0.0.1', port, timeout=1)) as channel:
            channel.request('POST', path, request() if data is None else data,
                            {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
            reply = channel.getresponse()
            return reply.status, reply.read()

    def test_socket_and_loopback_allow_only_bound_response_and_charge_before_forward(self):
        with self.provider(events()) as (api, path), local_runtime(path, self.request_sha) as port:
            self.assertEqual(self.post(port, path='/v1/models')[0], 400)
            self.assertEqual(self.post(port, token='foreign')[0], 400)
            self.assertEqual(self.post(port, data=request(model='gpt-6.2-astra'))[0], 400)
            self.assertEqual(self.post(port, data=request(tools=[{'type': 'web_search'}]))[0], 400)
            self.assertEqual(self.post(port), (200, events()))
            self.assertEqual(self.post(port)[0], 409)
            self.assertEqual(len(api.bodies), 1)
            self.assertEqual(api.bodies[0]['service_tier'], 'default')
            self.assertEqual(api.bodies[0]['max_output_tokens'], 32)
        raw = self.receipt.read_bytes()
        self.assertNotIn(b'fixture-private-text', raw)
        self.assertNotIn(runtime.LOCAL_BEARER.encode(), raw)
        entry, = json.loads(raw)['attempts']
        self.assertEqual(entry['observed_model'], MODEL)
        self.assertEqual(entry['usage']['total_tokens'], 15)
        self.assertEqual(entry['reserved_microusd'], 1088)
        with self.assertRaises(FileExistsError):
            broker.Journal(self.receipt, selection(), self.grant)

    def test_unapproved_model_is_withheld_and_effect_remains_reserved(self):
        with self.provider(events('gpt-6.2-astra')) as (api, path), local_runtime(path, self.request_sha) as port:
            status, body = self.post(port)
            self.assertEqual(status, 502)
            self.assertNotIn(b'gpt-6.2-astra', body)
            self.assertEqual(len(api.bodies), 1)
        entry, = json.loads(self.receipt.read_bytes())['attempts']
        self.assertEqual(entry['status'], 'billing-bound-violated')
        self.assertEqual(entry['billing_violation'], 'unpriced-model')
        self.assertEqual(entry['unpriced_model_sha256'], hashlib.sha256(b'gpt-6.2-astra').hexdigest())
        self.assertNotIn('observed_model', entry)

    def test_sanitizes_a_late_provider_error_after_stream_started(self):
        created, _ = events().split(b'\n\n', 1)
        raw = created + b'\n\n' + broker.sse('response.failed', {
            'type': 'response.failed', 'response': {'model': MODEL, 'error': {
                'code': 'private-upstream-code', 'message': 'private diagnostic across frames'}}})
        with self.provider(raw) as (api, path), local_runtime(path, self.request_sha) as port:
            status, body = self.post(port)
            self.assertEqual(status, 200)
            self.assertIn(b'event: response.created', body)
            self.assertIn(broker.FAILED_FRAME, body)
            self.assertNotIn(b'private', body)
            self.assertEqual(len(api.bodies), 1)
        entry, = json.loads(self.receipt.read_bytes())['attempts']
        self.assertEqual(entry['status'], 'provider-stream-failed')

    def test_excessive_provider_usage_is_recorded_quarantined_and_withheld(self):
        created, _ = events().split(b'\n\n', 1)
        raw = created + b'\n\n' + broker.sse('response.completed', {
            'type': 'response.completed', 'response': {'id': 'resp_overrun', 'model': MODEL, 'usage': {
                'input_tokens': 1600, 'output_tokens': 16, 'total_tokens': 1616}}})
        allowance = Mock()
        allowance.network_lease.side_effect = lambda: nullcontext(True)
        allowance.reserve.side_effect = [True, False]
        self.grant['spend_microusd'] = 3200
        with self.provider(raw, allowance) as (api, path), local_runtime(path, self.request_sha) as port:
            status, body = self.post(port)
            self.assertEqual(status, 200)
            self.assertIn(broker.FAILED_FRAME, body)
            self.assertNotIn(b'response.completed', body)
            self.assertEqual(self.post(port)[0], 409)
            allowance.quarantine.assert_called_once()
            self.assertEqual(len(api.bodies), 1)
        entry, = json.loads(self.receipt.read_bytes())['attempts']
        self.assertEqual(entry['status'], 'billing-bound-violated')
        self.assertEqual(entry['reserved_microusd'], 1088)
        self.assertEqual(entry['observed_cost_upper_microusd'], 1632)

    def test_foreign_raw_channel_digest_is_rejected_before_provider(self):
        with self.provider(events()) as (api, path), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(1)
            channel.connect(str(path))
            channel.sendall(bytes(32) + struct.pack('!I', len(request())) + request())
            status, = struct.unpack('!H', runtime.receive_exact(channel, 2))
            self.assertEqual(status, 403)
            self.assertFalse(api.bodies)

    def test_checks_exact_tls_origin_without_network(self):
        provider = broker.Provider('offline-fixture-key-never-sent')
        with patch.object(broker.http.client, 'HTTPSConnection') as factory:
            fake = factory.return_value
            result = fake.getresponse.return_value
            result.status = 200
            result.read.return_value = broker.canonical({'id': MODEL})
            self.assertEqual(provider.discover(MODEL, time.monotonic() + 5), 'available')
            factory.assert_called_once()
            self.assertEqual(factory.call_args.args, ('api.openai.com', 443))
            self.assertEqual(fake.request.call_args.args, ('GET', '/v1/models/' + MODEL))
            result.status = 404
            self.assertEqual(provider.discover(MODEL, time.monotonic() + 5), 'model-unavailable')

    def test_socket_creation_restores_context_on_success_and_failure(self):
        label = b'system_u:system_r:container_t:s0:c23,c65'
        library = Mock()
        library.security_getenforce.return_value = 1
        library.getsockcreatecon_raw.return_value = 0
        library.setsockcreatecon_raw.return_value = 0
        with patch.object(broker.ctypes, 'CDLL', return_value=library), patch.object(broker.socket, 'socket') as create:
            self.assertIs(broker.labeled_listener(label), create.return_value)
            self.assertEqual(library.setsockcreatecon_raw.call_args_list, [call(label), call(None)])
            library.setsockcreatecon_raw.reset_mock()
            create.side_effect = OSError('no fixture socket')
            with self.assertRaises(OSError):
                broker.labeled_listener(label)
            self.assertEqual(library.setsockcreatecon_raw.call_args_list, [call(label), call(None)])


class SharedAllowanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='dp-budget-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.job = self.root / 'sample'
        self.job.mkdir()
        self.selection = selection()
        self.grant = grant('a' * 64)
        proof = {key: self.grant[key] for key in broker.TARIFF_FIELDS}
        for suffix in ('context', 'tariff'):
            data = ('offline-fixture-' + suffix).encode()
            (self.job / (MODEL + '.' + suffix)).write_bytes(data)
            proof[suffix + '_evidence_sha256'] = hashlib.sha256(data).hexdigest()
        self.policy = {'schema': 1, 'kind': broker.billing.ALLOWANCE_KIND, 'job': 'sample',
                       'auth_profile': broker.PROFILE, 'allowance_ref': self.grant['allowance_ref'],
                       'spend_microusd': 1900, 'expires_unix': self.grant['expires_unix'],
                       'repository': self.selection['repository'], 'agreement_sha256': self.selection['agreement_sha256'],
                       'models': {MODEL: proof}}
        raw = broker.canonical(self.policy)
        (self.job / 'allowance.json').write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.grant['allowance_sha256'] = self.digest
        location = patch.object(broker, 'ALLOWANCES', self.root)
        location.start()
        self.addCleanup(location.stop)
        # The fixture substitutes protected ancestry only. It retains actual
        # bounded file reads, verified digests and SQLite reservation commits.
        custody = patch.object(broker, 'protected_file', side_effect=runtime.fixed_read)
        custody.start()
        self.addCleanup(custody.stop)

    def increase_fixture_cap(self):
        self.policy['spend_microusd'] = 4352
        raw = broker.canonical(self.policy)
        (self.job / 'allowance.json').write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.grant.update(allowance_sha256=self.digest, spend_microusd=4352)

    def submit(self, api, allowance, chosen, grant_value, journal, payload):
        client, server = socket.socketpair()
        with client, server:
            client.settimeout(2)
            client.sendall(bytes.fromhex(grant_value['request_sha256']) + struct.pack('!I', len(payload)) + payload)
            broker.forward(server, api, chosen, grant_value, journal, time.monotonic() + 2, allowance=allowance)
            status, = struct.unpack('!H', runtime.receive_exact(client, 2))
            return status

    def test_held_cost_is_shared_across_role_and_grant_and_survives_reopen(self):
        allowance = broker.load_allowance('sample', self.digest)
        pricing = {key: self.grant[key] for key in broker.TARIFF_FIELDS}
        review = {'request': {'model': MODEL, 'effort': 'high', 'credential_ref': self.grant['allowance_ref']},
                  'expires_unix': self.grant['expires_unix']}
        with patch.object(broker.billing, 'validate_proofs', return_value=(pricing, review)), \
                patch.object(broker.billing, 'assert_current'), \
                patch.object(broker.billing, 'credential_from', return_value='fixture-signed-key'), \
                patch.object(broker.billing, 'matches_request', return_value=True):
            allowance.validate_grant(self.selection, self.grant)
            self.assertEqual(broker.remaining_allowance('sample', self.digest)['remaining_microusd'], 1900)
        self.assertFalse((self.job / 'usage.sqlite').exists())
        self.assertTrue(allowance.reserve(self.selection, self.grant, 1, 1088, 'c' * 64))
        other = {**self.selection, 'role': 'maintenance', 'operation': 'second'}
        next_grant = {**self.grant, 'request_sha256': 'b' * 64}
        reopened = broker.load_allowance('sample', self.digest)
        self.assertEqual(reopened.remaining()['status'], 'unresolved')
        self.assertEqual(reopened.remaining()['remaining_microusd'], 0)
        self.assertFalse(reopened.reserve(other, next_grant, 1, 1088, 'd' * 64))
        allowance.finish(self.selection, self.grant, 1, 'c' * 64, 'uncertain')
        self.assertFalse(reopened.reserve(other, next_grant, 1, 1088, 'd' * 64))
        self.assertEqual(reopened.remaining()['remaining_microusd'], 812)
        reopened.quarantine()
        self.assertEqual(broker.remaining_allowance('sample', self.digest)['status'], 'quarantined')
        self.assertEqual(reopened.remaining()['remaining_microusd'], 0)

    def test_job_effect_lease_blocks_overlap_while_quarantining(self):
        first = broker.load_allowance('sample', self.digest)
        second = broker.load_allowance('sample', self.digest)
        with first.network_lease() as claimed, second.network_lease() as overlapping:
            self.assertTrue(claimed)
            self.assertFalse(overlapping)
        with second.network_lease() as recovered:
            self.assertTrue(recovered)

    def test_uncertain_request_fences_normalized_retry_and_different_next_body(self):
        self.increase_fixture_cap()
        allowance = broker.load_allowance('sample', self.digest)
        journal = broker.Journal(self.root / 'ambiguous.json', self.selection, self.grant)
        api = FakeProvider(b'')
        self.assertEqual(self.submit(api, allowance, self.selection, self.grant, journal, request()), 502)
        attempt, = journal.value['attempts']
        self.assertEqual(attempt['status'], 'effect-uncertain')
        # Client telemetry is removed by normalization.
        retry = request(client_metadata={'retry': 'different input bytes'})
        self.assertEqual(self.submit(api, allowance, self.selection, self.grant, journal, retry), 409)
        self.assertEqual(journal.value['repeat_blocked'], {'reason': 'earlier-effect-unresolved', 'attempt': 1,
                                                        'request_body_sha256': attempt['request_body_sha256']})
        reopened = broker.load_allowance('sample', self.digest)
        self.assertEqual(reopened.remaining()['status'], 'available')
        self.assertEqual(reopened.remaining()['reserved_microusd'], 1088)
        self.assertFalse(reopened.reserve(self.selection, self.grant, 2, 1088, 'c' * 64))
        self.assertEqual(len(api.bodies), 1)

    def test_completed_effect_allows_distinct_next_request_but_fences_replay(self):
        self.increase_fixture_cap()
        allowance = broker.load_allowance('sample', self.digest)
        journal = broker.Journal(self.root / 'tool.json', self.selection, self.grant)
        api = FakeProvider(events())
        self.assertEqual(self.submit(api, allowance, self.selection, self.grant, journal, request()), 200)
        self.assertEqual(self.submit(api, allowance, self.selection, self.grant, journal, request()), 409)
        different = request(input=[{'type': 'function_call_output', 'call_id': 'call_fixture', 'output': '/work/job'}])
        self.assertEqual(self.submit(api, allowance, self.selection, self.grant, journal, different), 200)
        self.assertEqual([row['status'] for row in journal.value['attempts']], ['completed', 'completed'])
        self.assertEqual(len(api.bodies), 2)
        self.assertEqual(allowance.remaining()['reserved_microusd'], 2176)

    def test_unpriced_model_in_failed_frame_quarantines_both_roles_without_usage(self):
        self.increase_fixture_cap()
        allowance = broker.load_allowance('sample', self.digest)
        journal = broker.Journal(self.root / 'unpriced.json', self.selection, self.grant)
        reported = 'synthetic-unpriced-identity'
        api = FakeProvider(broker.sse('response.failed', {'type': 'response.failed', 'response': {
            'model': reported, 'error': {'message': 'synthetic private diagnostic'}}}))
        self.assertEqual(self.submit(api, allowance, self.selection, self.grant, journal, request()), 502)
        raw = journal.path.read_bytes()
        self.assertNotIn(reported.encode(), raw)
        self.assertNotIn(b'private diagnostic', raw)
        attempt, = json.loads(raw)['attempts']
        self.assertEqual(attempt['status'], 'billing-bound-violated')
        self.assertEqual(attempt['unpriced_model_sha256'], hashlib.sha256(reported.encode()).hexdigest())
        self.assertTrue(attempt['quarantine_recorded'])
        other = {**self.selection, 'role': 'maintenance', 'operation': 'different'}
        other_grant = {**self.grant, 'request_sha256': 'b' * 64}
        later = broker.Journal(self.root / 'other.json', other, other_grant)
        reopened = broker.load_allowance('sample', self.digest)
        self.assertEqual(reopened.remaining()['status'], 'quarantined')
        self.assertEqual(self.submit(api, reopened, other, other_grant, later, request()), 429)
        self.assertEqual(len(api.bodies), 1)
        self.assertFalse(later.value['attempts'])

    def test_job_rejects_unproven_context_and_missing_or_changed_pricing(self):
        allowance = broker.load_allowance('sample', self.digest)
        with self.assertRaises(RuntimeError):
            allowance.validate_grant(self.selection, {**self.grant, 'max_context_tokens': 1023})
        (self.job / (MODEL + '.tariff')).write_text('unapproved changed price')
        with self.assertRaises(RuntimeError):
            allowance.validate_grant(self.selection, self.grant)
        with self.assertRaises(RuntimeError):
            broker.remaining_allowance('sample', 'f' * 64)

    def test_legacy_allowance_is_readable_for_history_but_cannot_authorize_a_send(self):
        self.policy['kind'] = 'verified-full-billable-context'
        raw = broker.canonical(self.policy)
        (self.job / 'allowance.json').write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        allowance = broker.load_allowance('sample', digest)
        self.assertEqual(allowance.remaining()['spend_microusd'], 1900)
        self.assertEqual(allowance.remaining()['remaining_microusd'], 0)
        self.assertEqual(allowance.remaining()['status'], 'historical-unscoped')
        with self.assertRaisesRegex(RuntimeError, 'Historical unscoped'):
            allowance.validate_grant(self.selection, self.grant)


class BrokerLifecycleTests(unittest.TestCase):
    def invoke(self, available):
        with tempfile.TemporaryDirectory(prefix='dp-idle-') as temp:
            root = Path(temp)
            inputs = selection()
            raw = broker.canonical(inputs)
            request_sha = hashlib.sha256(raw).hexdigest()
            template = grant(request_sha)
            expiry_seconds = 20
            accept_timeout = 0.01
            clock = SimpleNamespace(time=lambda: template['expires_unix'] - expiry_seconds,
                                    monotonic=Mock(return_value=0.0))
            idle_timeouts = []
            directory = root / 'channel'
            directory.mkdir()
            directory.chmod(0o750)
            path = directory / 'responses.sock'
            destination = root / 'development' / inputs['job']
            destination.mkdir(parents=True)
            destination.chmod(0o700)
            receipt = destination / (inputs['operation'] + '.json')

            class IdleSocket(socket.socket):
                def listen(listener, backlog):
                    super().listen(backlog)
                    # Reach the signed expiry only after the actual socket is listening.
                    clock.monotonic.return_value = expiry_seconds - accept_timeout

                def accept(listener):
                    self.assertFalse(idle_timeouts, 'broker attempted another accept after idle expiry')
                    self.assertTrue(path.is_socket())
                    self.assertEqual(json.loads(receipt.read_bytes())['status'], 'listening')
                    self.assertAlmostEqual(listener.gettimeout(), accept_timeout, places=5)
                    try:
                        return super().accept()
                    except TimeoutError:
                        idle_timeouts.append(listener.gettimeout())
                        clock.monotonic.return_value = float(expiry_seconds)
                        raise

            approved = Mock()
            approved.validate_grant.return_value = {'request': {}, 'organization': 'org-fixture', 'project': 'proj_fixture'}
            approved.remaining.return_value = {'remaining_microusd': 3000}
            api = Mock()
            api.discover.return_value = 'available'
            args = ['provider_broker.py', '--grant', str(root / 'grant'), '--request', str(root / 'request'),
                    '--credential-file', str(root / template['allowance_ref']), '--socket', str(path), '--receipt', str(receipt)]
            with patch.object(sys, 'argv', args), patch.object(broker, 'EVIDENCE', root), \
                    patch.object(broker, 'time', clock), \
                    patch.object(broker.billing, 'CREDENTIALS', root), \
                    patch.object(broker.billing, 'credential_from', return_value='offline-fixture-key-never-sent'), \
                    patch.object(broker.billing, 'matches_request', return_value=True), \
                    patch.object(broker, 'provider_host_path', return_value=directory), \
                    patch.object(broker, 'protected_file', side_effect=[broker.canonical(template), raw, b'fixture-key']), \
                    patch.object(broker, 'host_repository_approval'), \
                    patch.object(broker.os, 'geteuid', side_effect=[0] + [os.getuid()] * 8), \
                    patch.object(broker, 'broker_channel_label', return_value=b'fixture-label'), \
                    patch.object(broker, 'labeled_listener', side_effect=lambda _label: IdleSocket(socket.AF_UNIX)) as sockets, \
                    patch.object(broker, 'load_allowance', return_value=approved,
                                 side_effect=None if available else FileNotFoundError('allowance unproven')), \
                    patch.object(broker, 'Provider', return_value=api) as acquire, \
                    patch.object(sys, 'stderr', new_callable=io.StringIO):
                result = broker.main()
            self.assertFalse(path.exists())
            if not available:
                acquire.assert_not_called()
                sockets.assert_not_called()
                self.assertFalse(receipt.exists())
                return result, None
            api.discover.assert_called_once()
            api.responses.assert_not_called()
            self.assertEqual(len(idle_timeouts), 1)
            return result, json.loads(receipt.read_bytes())

    def test_idle_clock_expiry_closes_normally_without_interruption(self):
        result, receipt = self.invoke(True)
        self.assertEqual(result, 0)
        self.assertEqual(receipt['status'], 'closed')
        self.assertEqual(receipt['attempts'], [])

    def test_missing_allowance_blocks_before_any_provider_initialization(self):
        self.assertEqual(self.invoke(False), (2, None))


if __name__ == '__main__':
    unittest.main()
