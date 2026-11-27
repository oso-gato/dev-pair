"""Offline checks for the scoped role-to-provider transport."""

from contextlib import closing, contextmanager
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
            'allowance_ref': 'offline-fixture', 'peer_uid': os.getuid(), 'peer_gid': os.getgid(),
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
    return b''.join(b'data: ' + broker.canonical({'type': kind, 'response': value}) + b'\n\n'
                    for kind, value in (('response.created', response), ('response.completed', completed)))


class FakeResponse(io.BytesIO):
    status = 200

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
    def provider(self, reply):
        api = FakeProvider(reply)
        journal = broker.Journal(self.receipt, selection(), self.grant)
        path = self.path / 'responses.sock'
        errors = []

        def listen():
            try:
                broker.listen(path, api, selection(), self.grant, journal, time.monotonic() + 1.5)
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
            self.assertEqual(self.post(port)[0], 429)
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
        self.assertEqual(entry['status'], 'effect-uncertain')
        self.assertNotIn('observed_model', entry)

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


if __name__ == '__main__':
    unittest.main()
