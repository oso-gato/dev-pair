#!/usr/bin/python3
"""Trusted controller for one admitted OpenAI API job operation."""

import argparse
from contextlib import ExitStack, closing, contextmanager, suppress
import ctypes
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptbox_runtime import (HEX_SHA, JOB, PROVIDER_BODY_MAX, PROVIDER_REPLY_MAX, fixed_read,
                            host_repository_approval, job_selection, provider_host_path, receive_exact, require,
                            sync_directory, unique_object)

HOST = 'api.openai.com'
PROFILE = 'openai-api-key'
ALLOWANCES = Path('/var/lib/dev-pair/provider-allowances')
EVIDENCE = Path('/var/lib/dev-pair/provider-evidence')
REQUEST_FIELDS = set(('model stream service_tier input tools tool_choice parallel_tool_calls reasoning store '
                      'stream_options include prompt_cache_key prompt_cache_options text client_metadata '
                      'access_programs').split())
GRANT_FIELDS = set(('schema auth_profile request_sha256 peer_uid peer_gid allowance_ref spend_microusd '
                    'seconds expires_unix max_requests max_request_bytes max_context_tokens max_output_tokens '
                    'input_microusd_per_million output_microusd_per_million observed_models allowance_sha256').split())
TARIFF_FIELDS = ('max_context_tokens', 'input_microusd_per_million', 'output_microusd_per_million', 'observed_models')
USAGE_FIELDS = ('input_tokens', 'output_tokens', 'total_tokens')


class BrokerStopped(BaseException):
    pass


class BrokerExpired(BaseException):
    pass


def broker_channel_label(directory):
    label = os.getxattr(directory, 'security.selinux').rstrip(b'\0')
    match = re.fullmatch(rb'system_u:object_r:container_file_t:(s0:c[0-9]+(?:[,.]c[0-9]+))', label)
    require(match is not None, 'the broker channel requires the exact role SELinux categories')
    return b'system_u:system_r:container_t:' + match[1]


def labeled_listener(label):
    library = ctypes.CDLL('libselinux.so.1', use_errno=True)
    require(library.security_getenforce() == 1, 'provider listener requires SELinux enforcement')
    current = ctypes.c_char_p()
    require(library.getsockcreatecon_raw(ctypes.byref(current)) == 0, 'cannot inspect broker socket context')
    if current:
        library.freecon(current)
        raise RuntimeError('broker must start without an inherited socket context')
    setter = library.setsockcreatecon_raw
    setter.argtypes = (ctypes.c_char_p,)
    listener = None
    try:
        require(setter(label) == 0, 'cannot set the exact confined provider socket context')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    finally:
        if setter(None) != 0:
            if listener is not None:
                listener.close()
            raise RuntimeError('cannot restore trusted broker socket context')
    return listener


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def protected_file(path, maximum, *, secret=False):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'broker file path must be absolute and regular')
    for parent in path.parents:
        info = parent.stat()
        require(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022, 'broker file ancestry is writable')
    info = path.lstat()
    require(info.st_uid in (0, os.geteuid()) and not info.st_mode & (0o077 if secret else 0o022),
            'broker file permissions are unsafe')
    return fixed_read(path, maximum)


def grant_document(raw):
    grant = json.loads(raw, object_pairs_hook=unique_object)
    require(type(grant) is dict and grant.keys() == GRANT_FIELDS and type(grant['schema']) is int
            and grant['schema'] == 1 and grant['auth_profile'] == PROFILE,
            'unsupported provider authorization profile')
    require(type(grant['request_sha256']) is str and HEX_SHA.fullmatch(grant['request_sha256']) and
            type(grant['allowance_sha256']) is str and HEX_SHA.fullmatch(grant['allowance_sha256']) and
            type(grant['allowance_ref']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', grant['allowance_ref']),
            'provider operation or allowance identity missing')
    limits = {'peer_uid': (1000, 2**31 - 1), 'peer_gid': (1000, 2**31 - 1), 'seconds': (10, 720),
              'max_requests': (1, 32), 'max_request_bytes': (1, PROVIDER_BODY_MAX),
              'max_context_tokens': (1024, 2000000), 'max_output_tokens': (16, 65536),
              'spend_microusd': (1, 100000000), 'expires_unix': (1, 2**63 - 1),
              'input_microusd_per_million': (1, 10**9), 'output_microusd_per_million': (1, 10**9)}
    require(all(type(grant[key]) is int and low <= grant[key] <= high for key, (low, high) in limits.items()),
            'missing or unsupported provider bounds')
    models = grant['observed_models']
    require(type(models) is list and 0 < len(models) <= 8
            and all(type(model) is str and re.fullmatch(r'gpt-[a-z0-9][a-z0-9.-]{1,95}', model) for model in models)
            and len(set(models)) == len(models), 'approved provider model identities missing')
    return grant


def token_cost(grant, input_tokens, output_tokens):
    cost = (input_tokens * grant['input_microusd_per_million'] + output_tokens * grant['output_microusd_per_million'])
    return (cost + 999999) // 1000000


def reserved_cost(grant):
    # Host custodian verifies the provider's full billable input ceiling,
    # including provider-supplied overhead. Use the worst applicable tariff.
    return token_cost(grant, grant['max_context_tokens'], grant['max_output_tokens'])


def load_allowance(job, expected_sha):
    require(type(job) is str and JOB.fullmatch(job) and type(expected_sha) is str and HEX_SHA.fullmatch(expected_sha),
            'invalid job allowance identity')
    root = ALLOWANCES / job
    raw = protected_file(root / 'allowance.json', 16384)
    require(hashlib.sha256(raw).hexdigest() == expected_sha, 'job allowance digest mismatch')
    approval = json.loads(raw, object_pairs_hook=unique_object)
    fields = {'schema', 'kind', 'job', 'auth_profile', 'allowance_ref', 'repository', 'agreement_sha256',
              'spend_microusd', 'expires_unix', 'models'}
    require(type(approval) is dict and approval.keys() == fields and type(approval['schema']) is int and
            approval['schema'] == 1 and approval['kind'] == 'verified-full-billable-context' and
            approval['job'] == job and approval['auth_profile'] == PROFILE and
            type(approval['spend_microusd']) is int and 0 < approval['spend_microusd'] <= 100000000 and
            type(approval['expires_unix']) is int and 0 < approval['expires_unix'] < 2**63 and
            type(approval['models']) is dict and 0 < len(approval['models']) <= 8, 'invalid protected job allowance')
    return JobAllowance(root, expected_sha, approval)


class JobAllowance:
    def __init__(self, root, digest, approval):
        self.root, self.digest, self.approval = root, digest, approval
        self.path = root / 'usage.sqlite'

    def validate_grant(self, selection, grant):
        approval = self.approval
        require(all(approval[key] == selection[key] for key in ('job', 'repository', 'agreement_sha256')) and
                all(approval[key] == grant[key] for key in ('auth_profile', 'allowance_ref')) and
                grant['expires_unix'] <= approval['expires_unix'] and grant['spend_microusd'] <= approval['spend_microusd'],
                'provider grant exceeds independently approved job/account scope')
        model = selection['model']
        proof = approval['models'].get(model)
        require(type(proof) is dict and proof.keys() == {*TARIFF_FIELDS, 'context_evidence_sha256', 'tariff_evidence_sha256'}
                and all(type(proof[key]) is type(grant[key]) and proof[key] == grant[key] for key in TARIFF_FIELDS),
                'no exact approved full-input billable ceiling and tariff')
        # The protected evidence must be reviewed for the default-tier text
        # Responses contract, including local tool schemas and provider overhead.
        for suffix in ('context', 'tariff'):
            evidence = protected_file(self.root / (model + '.' + suffix), 1024 * 1024)
            require(hashlib.sha256(evidence).hexdigest() == proof[suffix + '_evidence_sha256'],
                    'approved model billing evidence digest mismatch')

    def connection(self, *, writable=False):
        if writable:
            try:
                os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
                sync_directory(self.root)
            except FileExistsError:
                pass
        node = self.path.lstat()
        require(self.path.resolve(strict=True) == self.path and stat.S_ISREG(node.st_mode) and node.st_nlink == 1
                and node.st_uid == os.geteuid() and stat.S_IMODE(node.st_mode) == 0o600,
                'unsafe provider allowance ledger')
        mode = 'rw' if writable else 'ro'
        return closing(sqlite3.connect(self.path.as_uri() + '?mode=' + mode, uri=True, timeout=1))

    def read_state(self, db):
        row = db.execute('SELECT digest, quarantined FROM allowance LIMIT 2').fetchall()
        require(len(row) == 1 and row[0][0] == self.digest and row[0][1] in (0, 1),
                'provider allowance ledger belongs to a different budget')
        amount, = db.execute('SELECT coalesce(sum(amount), 0) FROM hold').fetchone()
        require(type(amount) is int and 0 <= amount <= self.approval['spend_microusd'], 'invalid provider reservations')
        return row[0][1], amount

    def remaining(self):
        quarantined = reserved = 0
        if os.path.lexists(self.path):
            with self.connection() as db:
                quarantined, reserved = self.read_state(db)
        expired = time.time() >= self.approval['expires_unix']
        status = 'quarantined' if quarantined else 'expired' if expired else 'available'
        remaining = self.approval['spend_microusd'] - reserved if status == 'available' else 0
        return {'job': self.approval['job'], 'allowance_sha256': self.digest, 'spend_microusd': self.approval['spend_microusd'],
                'expires_unix': self.approval['expires_unix'], 'status': status, 'reserved_microusd': reserved,
                'remaining_microusd': remaining}

    def reserve(self, selection, grant, number, amount):
        require(type(amount) is int and amount == reserved_cost(grant) > 0 and grant['allowance_sha256'] == self.digest,
                'provider request lacks its exact full reservation')
        raw = protected_file(self.root / 'allowance.json', 16384)
        require(hashlib.sha256(raw).hexdigest() == self.digest, 'provider allowance was revoked or changed')
        with self.connection(writable=True) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS allowance(digest TEXT PRIMARY KEY, quarantined INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS hold(role TEXT, operation TEXT, attempt INTEGER, digest TEXT, amount INTEGER,'
                       ' PRIMARY KEY(role, operation, attempt))')
            db.execute('INSERT INTO allowance SELECT ?, 0 WHERE NOT EXISTS (SELECT 1 FROM allowance)', (self.digest,))
            quarantined, reserved = self.read_state(db)
            if (quarantined or time.time() >= self.approval['expires_unix']
                    or reserved + amount > self.approval['spend_microusd']):
                return False
            db.execute('INSERT INTO hold VALUES(?, ?, ?, ?, ?)', (selection['role'], selection['operation'],
                                                                  number, grant['request_sha256'], amount))
        return True

    def quarantine(self):
        with self.connection(writable=True) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            self.read_state(db)
            db.execute('UPDATE allowance SET quarantined=1 WHERE digest=?', (self.digest,))

    @contextmanager
    def network_lease(self):
        # One bounded provider effect per job in flight. Hold through usage
        # reconciliation so a contradicted billable ceiling stops the next one.
        path = self.root / 'dispatch.lock'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            node = os.fstat(fd)
            require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_uid == os.geteuid()
                    and stat.S_IMODE(node.st_mode) == 0o600, 'unsafe provider job dispatch lease')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
            else:
                yield True
        finally:
            os.close(fd)


def remaining_allowance(job, expected_sha):
    return load_allowance(job, expected_sha).remaining()


def local_tool(tool):
    if type(tool) is not dict:
        return False
    kind = tool.get('type')
    if kind in ('function', 'custom'):
        return type(tool.get('name')) is str and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', tool['name']))
    if kind == 'namespace':
        return (type(tool.get('name')) is str and type(tool.get('tools')) is list and
                all(type(item) is dict and item.get('type') in ('function', 'custom') and local_tool(item)
                    for item in tool['tools']))
    return False


def responses_request(raw, selection, grant):
    require(0 < len(raw) <= grant['max_request_bytes'], 'payload exceeds approved request bound')
    body = json.loads(raw, object_pairs_hook=unique_object)
    require(type(body) is dict and body.keys() <= REQUEST_FIELDS and body.get('model') == selection['model'] and
            type(body.get('reasoning')) is dict and body['reasoning'].get('effort') == selection['effort'],
            'provider request differs from recorded model or effort')
    require(body.get('stream') is True and body.get('store') is False and
            body.get('service_tier', 'default') in ('default', 'auto') and body.get('access_programs') is None and
            body.get('tool_choice', 'auto') in ('auto', 'none') and type(body.get('input')) is list,
            'request exceeds the scoped Responses operation')
    tools = body.get('tools', [])
    require(type(tools) is list and len(tools) <= 32 and all(map(local_tool, tools)), 'provider-hosted tools are disabled')
    for item in body['input']:
        require(type(item) is dict and item.get('type') in ('message', 'reasoning', 'function_call',
                'function_call_output', 'custom_tool_call', 'custom_tool_call_output'), 'unsupported Responses input')
        content = item.get('content', [])
        require(type(content) is list and all(type(part) is dict and part.get('type') in
                ('input_text', 'output_text', 'reasoning_text', 'refusal') for part in content),
                'provider input is restricted to text')
    # Local CLI telemetry and project-specific retention/pricing hints are not forwarded.
    for field in ('client_metadata', 'access_programs', 'prompt_cache_options'):
        body.pop(field, None)
    body.update(service_tier='default', truncation='disabled', max_output_tokens=grant['max_output_tokens'])
    output = canonical(body)
    require(len(output) <= grant['max_request_bytes'], 'normalized request exceeds bound')
    return output


class Provider:
    def __init__(self, credential):
        require(re.fullmatch(r'[!-~]{20,512}', credential), 'invalid external API credential')
        self.credential = credential

    def request(self, method, path, deadline, *, body=None):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'provider deadline expired')
        connection = http.client.HTTPSConnection(HOST, 443, timeout=min(15, remaining),
                                                 context=ssl.create_default_context())
        headers = {'Authorization': 'Bearer ' + self.credential, 'Connection': 'close',
                   'Accept': 'text/event-stream' if body else 'application/json'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        try:
            connection.request(method, path, body=body, headers=headers)
            return connection, connection.getresponse()
        except BaseException:
            connection.close()
            raise

    def discover(self, model, deadline):
        connection, response = self.request('GET', '/v1/models/' + model, deadline)
        try:
            if response.status == 200:
                data = response.read(8193)
                require(len(data) <= 8192, 'model availability response exceeds bound')
                discovered = json.loads(data, object_pairs_hook=unique_object)
                if type(discovered) is dict and discovered.get('id') == model:
                    return 'available'
            if response.status in (401, 403):
                return 'authentication-rejected'
            if response.status == 404:
                return 'model-unavailable'
            return 'availability-unverified'
        finally:
            connection.close()

    def responses(self, body, deadline):
        return self.request('POST', '/v1/responses', deadline, body=body)


class EventWitness:
    def __init__(self, grant, attempt, allowance):
        self.grant = grant
        self.attempt = attempt
        self.allowance = allowance
        self.buffer = bytearray()
        self.data = []
        self.event = None
        self.seen = 0

    def response_field(self, item):
        response = item.get('response')
        require(type(response) is dict and response.get('model') in self.grant['observed_models'],
                'provider returned an unapproved model')
        if response.get('service_tier') not in (None, 'default'):
            self.billing_violation()
        if 'observed_model' in self.attempt:
            require(response['model'] == self.attempt['observed_model'], 'provider model identity changed within request')
        else:
            self.attempt['observed_model'] = response['model']
        return response

    def billing_violation(self):
        self.attempt['status'] = 'billing-bound-violated'
        if self.allowance:
            self.allowance.quarantine()
        raise RuntimeError('provider exceeded its approved billable bound')

    def usage(self, response):
        usage = response.get('usage')
        require(type(usage) is dict and all(type(usage.get(key)) is int and usage[key] >= 0 for key in USAGE_FIELDS)
                and usage['total_tokens'] == usage['input_tokens'] + usage['output_tokens'], 'provider usage unverified')
        cost = token_cost(self.grant, usage['input_tokens'], usage['output_tokens'])
        self.attempt.update(usage={key: usage[key] for key in USAGE_FIELDS}, observed_cost_upper_microusd=cost)
        if (usage['input_tokens'] > self.grant['max_context_tokens'] or usage['output_tokens'] > self.grant['max_output_tokens']
                or cost > self.attempt['reserved_microusd']):
            self.billing_violation()

    def frame(self, name, data):
        item = json.loads(data, object_pairs_hook=unique_object)
        require(type(item) is dict and type(item.get('type')) is str, 'invalid provider stream frame')
        kind = item['type']
        require(name in (None, kind) or name == 'error', 'provider frame identity differs')
        response = item.get('response')
        if (kind in ('response.failed', 'response.incomplete', 'error') or name == 'error'
                or item.get('error') is not None or type(response) is dict and response.get('error') is not None):
            if type(response) is dict and response.get('usage') is not None:
                self.usage(self.response_field(item))
            self.attempt['status'] = 'provider-stream-failed'
            return FAILED_FRAME
        if kind == 'response.created':
            response = self.response_field(item)
            return sse(kind, {'type': kind, 'response': {key: response[key] for key in ('id', 'model') if key in response}})
        if kind == 'response.completed':
            response = self.response_field(item)
            self.usage(response)
            self.attempt['status'] = 'completed'
            return sse(kind, {'type': kind, 'response': {key: response[key] for key in ('id', 'model', 'usage') if key in response}})
        if kind in OUTPUT_EVENTS:
            require('observed_model' in self.attempt, 'provider output preceded verified model identity')
            return sse(kind, item)
        return b''

    def feed(self, chunk):
        self.seen += len(chunk)
        require(self.seen <= PROVIDER_REPLY_MAX, 'provider reply exceeded byte bound')
        self.buffer.extend(chunk)
        frames = []
        while (end := self.buffer.find(b'\n')) >= 0:
            line = bytes(self.buffer[:end]).rstrip(b'\r')
            del self.buffer[:end + 1]
            if not line:
                data, self.data = b'\n'.join(self.data), []
                event, self.event = self.event, None
                if data and data != b'[DONE]' and (frame := self.frame(event, data)):
                    frames.append(frame)
                    if self.finished():
                        break
            elif line.startswith(b'data:'):
                self.data.append(line[5:].removeprefix(b' '))
            elif line.startswith(b'event:'):
                require(self.event is None, 'duplicated provider event name')
                self.event = line[6:].removeprefix(b' ').decode('ascii')
        return frames

    def finished(self):
        return self.attempt['status'] in ('completed', 'provider-stream-failed')


OUTPUT_EVENTS = frozenset({
    'response.output_item.added', 'response.output_item.done', 'response.output_text.delta',
    'response.custom_tool_call_input.delta', 'response.reasoning_summary_text.delta',
    'response.reasoning_summary_text.done', 'response.reasoning_text.delta',
    'response.reasoning_summary_part.added',
})


def sse(kind, data):
    return b'event: ' + kind.encode('ascii') + b'\ndata: ' + canonical(data) + b'\n\n'


FAILED_FRAME = sse('response.failed', {'type': 'response.failed', 'response': {
    'error': {'code': 'server_error', 'message': 'Scoped provider stream failed.'}}})


def send_frame(channel, frame):
    for offset in range(0, len(frame), 16384):
        part = frame[offset:offset + 16384]
        channel.sendall(struct.pack('!I', len(part)) + part)


class Journal:
    def __init__(self, path, selection, grant):
        require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, 'invalid broker evidence directory')
        info = path.parent.stat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'broker evidence directory is not private')
        self.path = path
        self.value = {key: selection[key] for key in ('job', 'operation', 'role', 'logical_session', 'model', 'effort')}
        self.value.update({key: grant[key] for key in ('auth_profile', 'request_sha256', 'allowance_ref', 'allowance_sha256', 'seconds',
                              'expires_unix', 'max_requests', 'max_request_bytes', 'max_context_tokens',
                              'max_output_tokens', 'spend_microusd', 'input_microusd_per_million',
                              'output_microusd_per_million', 'observed_models')})
        self.value.update(schema=1, status='claimed', availability='unverified', attempts=[])
        self.write(path)

    def write(self, path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(self.value) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(path.parent)

    def update(self):
        stage = self.path.with_suffix(self.path.suffix + '.new')
        self.write(stage)
        os.replace(stage, self.path)
        sync_directory(self.path.parent)


def bounded_peer(channel, grant, expected_label):
    _, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if (uid, gid) != (grant['peer_uid'], grant['peer_gid']):
        return False
    if expected_label:
        observed = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 256).rstrip(b'\0')
        return observed == expected_label
    return True


@contextmanager
def provider_alarm(deadline, enabled):
    if enabled:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerExpired()
        signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        yield
    finally:
        if enabled:
            signal.setitimer(signal.ITIMER_REAL, 0)


def forward(channel, provider, selection, grant, journal, deadline, expected_label=None, allowance=None):
    started = False
    attempt = None
    status = 400
    resources = ExitStack()
    try:
        if not bounded_peer(channel, grant, expected_label):
            status = 403
            return
        input_end = min(deadline, time.monotonic() + 2)
        channel.settimeout(2)
        binding = receive_exact(channel, 32, input_end)
        if binding != bytes.fromhex(grant['request_sha256']):
            status = 403
            return
        size, = struct.unpack('!I', receive_exact(channel, 4, input_end))
        if not 0 < size <= grant['max_request_bytes']:
            status = 413
            return
        payload = responses_request(receive_exact(channel, size, input_end), selection, grant)
        reserved = reserved_cost(grant)
        if (len(journal.value['attempts']) >= grant['max_requests'] or
                (len(journal.value['attempts']) + 1) * reserved > grant['spend_microusd']):
            status = 429
            return
        if time.monotonic() >= deadline:
            status = 503
            return
        number = len(journal.value['attempts']) + 1
        if allowance:
            if (not resources.enter_context(allowance.network_lease())
                    or not allowance.reserve(selection, grant, number, reserved)):
                status = 429
                return
        attempt = {'number': number, 'status': 'reserved',
                   'request_bytes': len(payload), 'request_body_sha256': hashlib.sha256(payload).hexdigest(),
                   'reserved_microusd': reserved, 'peer_uid_gid_verified': True, 'peer_selinux_verified': bool(expected_label)}
        journal.value['attempts'].append(attempt)
        journal.update()
        status = 502
        with provider_alarm(deadline, expected_label is not None):
            connection, response = provider.responses(payload, deadline)
            try:
                attempt['http_status'] = response.status
                content = response.getheader('Content-Type', '').partition(';')[0].strip()
                if response.status != 200 or content != 'text/event-stream' or response.getheader('Content-Encoding'):
                    attempt['status'] = 'provider-rejected'
                    status = response.status if response.status in (400, 403, 429, 503) else 502
                    return
                witness = EventWitness(grant, attempt, allowance)
                channel.settimeout(2)
                while not witness.finished() and time.monotonic() < deadline and (chunk := response.read1(16384)):
                    for frame in witness.feed(chunk):
                        if not started:
                            require('observed_model' in attempt, 'provider model identity unavailable')
                            channel.sendall(struct.pack('!H', 200))
                            started = True
                        send_frame(channel, frame)
                require(started and witness.finished() and time.monotonic() < deadline, 'incomplete provider stream')
                channel.sendall(struct.pack('!I', 0))
            finally:
                connection.close()
    except (BrokerExpired, OSError, RuntimeError, ValueError, TypeError, http.client.HTTPException, RecursionError, sqlite3.Error):
        if attempt is not None and attempt['status'] == 'reserved':
            attempt['status'] = 'effect-uncertain'
        if started:
            with suppress(OSError):
                send_frame(channel, FAILED_FRAME)
                channel.sendall(struct.pack('!I', 0))
    finally:
        try:
            if attempt is not None:
                journal.update()
            if not started:
                with suppress(OSError):
                    channel.sendall(struct.pack('!H', status))
        finally:
            resources.close()


def listen(channel_path, provider, selection, grant, journal, deadline, *, channel_label=None, allowance=None):
    require(channel_path.name == 'responses.sock' and channel_path.is_absolute() and
            channel_path.parent.resolve(strict=True) == channel_path.parent, 'invalid provider channel location')
    directory = channel_path.parent.stat()
    require(directory.st_uid == os.geteuid() and directory.st_gid == grant['peer_gid'] and
            stat.S_IMODE(directory.st_mode) == 0o750, 'unsafe provider channel directory')
    server = labeled_listener(channel_label) if channel_label else socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with server:
        server.bind(str(channel_path))
        node = channel_path.lstat()
        try:
            os.chown(channel_path, -1, grant['peer_gid'], follow_symlinks=False)
            channel_path.chmod(0o660)
            if channel_label:
                require(broker_channel_label(channel_path) == channel_label, 'bound provider inode label differs')
                journal.value['channel_selinux_context'] = channel_label.decode('ascii')
            server.listen(4)
            journal.value['status'] = 'listening'
            journal.update()
            while (remaining := deadline - time.monotonic()) > 0:
                server.settimeout(remaining)
                try:
                    channel, _ = server.accept()
                except TimeoutError:
                    break
                with channel:
                    forward(channel, provider, selection, grant, journal, deadline, channel_label, allowance)
        finally:
            current = channel_path.lstat()
            require((current.st_dev, current.st_ino) == (node.st_dev, node.st_ino), 'provider channel cleanup identity changed')
            channel_path.unlink()


def interrupted(_signum, _frame):
    raise BrokerStopped('broker stop requested')


def expired(_signum, _frame):
    raise BrokerExpired()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--grant', type=Path, required=True)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--credential-file', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    journal = None
    handlers = {signum: signal.signal(signum, handler) for signum, handler in
                ((signal.SIGINT, interrupted), (signal.SIGTERM, interrupted), (signal.SIGALRM, expired))}
    try:
        os.umask(0o077)
        grant = grant_document(protected_file(args.grant, 8192))
        raw = protected_file(args.request, 4096)
        identity = json.loads(raw, object_pairs_hook=unique_object)
        selection = job_selection(raw, grant['request_sha256'], identity['role'], identity['job'], identity['operation'])
        require(os.geteuid() == 0 and args.socket == provider_host_path(grant['request_sha256']) / 'responses.sock',
                'provider broker requires the protected exact role channel')
        evidence = EVIDENCE / selection['role'] / selection['job']
        require(args.receipt == evidence / (selection['operation'] + '.json'), 'provider evidence location mismatch')
        host_repository_approval(selection)
        allowance = load_allowance(selection['job'], grant['allowance_sha256'])
        allowance.validate_grant(selection, grant)
        seconds = min(grant['seconds'], grant['expires_unix'] - time.time())
        remaining = allowance.remaining()['remaining_microusd']
        require(seconds > 0 and reserved_cost(grant) <= min(remaining, grant['spend_microusd']),
                'provider allowance exhausted or expired')
        deadline = time.monotonic() + seconds
        channel_label = broker_channel_label(args.socket.parent)
        # Confirm this host can create the role-labeled socket before contacting the provider.
        with labeled_listener(channel_label):
            pass
        journal = Journal(args.receipt, selection, grant)
        provider = Provider(protected_file(args.credential_file, 1024, secret=True).decode('ascii').removesuffix('\n'))
        discovery_end = min(deadline, time.monotonic() + 15)
        with provider_alarm(discovery_end, True):
            journal.value['availability'] = provider.discover(selection['model'], discovery_end)
        journal.update()
        if journal.value['availability'] != 'available':
            return 2
        listen(args.socket, provider, selection, grant, journal, deadline, channel_label=channel_label, allowance=allowance)
        uncertain = any(attempt['status'] in ('reserved', 'effect-uncertain', 'billing-bound-violated')
                        for attempt in journal.value['attempts'])
        journal.value['status'] = 'closed-effects-uncertain' if uncertain else 'closed'
        journal.update()
        return 0
    except BrokerStopped:
        if journal is not None:
            journal.value['status'] = 'interrupted'
            journal.update()
        return 2
    except BrokerExpired:
        if journal is not None:
            journal.value['status'] = 'availability-deadline'
            journal.update()
        return 2
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, http.client.HTTPException, sqlite3.Error):
        print('Provider broker blocked; inspect its protected receipt locally', file=sys.stderr)
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    sys.exit(main())
