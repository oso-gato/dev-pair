#!/usr/bin/python3
"""Trusted controller for one admitted OpenAI API job operation."""

import argparse
from contextlib import suppress
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gptbox_runtime import (HEX_SHA, PROVIDER_BODY_MAX, PROVIDER_REPLY_MAX, fixed_read,
                            job_selection, provider_host_path, receive_exact, require, sync_directory, unique_object)

HOST = 'api.openai.com'
PROFILE = 'openai-api-key'
REQUEST_FIELDS = set(('model stream service_tier input tools tool_choice parallel_tool_calls reasoning store '
                      'stream_options include prompt_cache_key prompt_cache_options text client_metadata '
                      'access_programs').split())
GRANT_FIELDS = set(('schema auth_profile request_sha256 peer_uid peer_gid allowance_ref spend_microusd '
                    'seconds expires_unix max_requests max_request_bytes max_context_tokens max_output_tokens '
                    'input_microusd_per_million output_microusd_per_million observed_models').split())


class BrokerStopped(BaseException):
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


def reserved_cost(grant):
    # Reserve the approved model's entire context at uncached rates for each
    # attempted response. An ambiguous provider effect still consumes its claim.
    cost = (grant['max_context_tokens'] * grant['input_microusd_per_million'] +
            grant['max_output_tokens'] * grant['output_microusd_per_million'])
    return (cost + 999999) // 1000000


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
    body.update(service_tier='default', max_output_tokens=grant['max_output_tokens'])
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
    def __init__(self, grant, attempt):
        self.grant = grant
        self.attempt = attempt
        self.buffer = bytearray()
        self.seen = 0

    def response_field(self, item):
        response = item.get('response')
        require(type(response) is dict and response.get('model') in self.grant['observed_models'],
                'provider returned an unapproved model')
        if 'observed_model' in self.attempt:
            require(response['model'] == self.attempt['observed_model'], 'provider model identity changed within request')
        else:
            self.attempt['observed_model'] = response['model']
        return response

    def feed(self, chunk):
        self.seen += len(chunk)
        require(self.seen <= PROVIDER_REPLY_MAX, 'provider reply exceeded byte bound')
        self.buffer.extend(chunk)
        while (end := self.buffer.find(b'\n')) >= 0:
            line = bytes(self.buffer[:end]).rstrip(b'\r')
            del self.buffer[:end + 1]
            if not line.startswith(b'data: '):
                continue
            item = json.loads(line[6:], object_pairs_hook=unique_object)
            if type(item) is not dict:
                continue
            kind = item.get('type')
            if kind == 'response.created':
                self.response_field(item)
            if kind in ('response.completed', 'response.incomplete'):
                response = self.response_field(item)
                usage = response.get('usage')
                require(type(usage) is dict and all(type(usage.get(key)) is int and usage[key] >= 0
                                                    for key in ('input_tokens', 'output_tokens', 'total_tokens')) and
                        usage['output_tokens'] <= self.grant['max_output_tokens'] and
                        usage['total_tokens'] == usage['input_tokens'] + usage['output_tokens'],
                        'provider usage unverified')
                self.attempt['usage'] = {key: usage[key] for key in ('input_tokens', 'output_tokens', 'total_tokens')}
                self.attempt['status'] = 'completed' if kind == 'response.completed' else 'incomplete'
        require(len(self.buffer) <= PROVIDER_REPLY_MAX, 'provider stream line exceeds bound')


class Journal:
    def __init__(self, path, selection, grant):
        require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, 'invalid broker evidence directory')
        info = path.parent.stat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'broker evidence directory is not private')
        self.path = path
        self.value = {key: selection[key] for key in ('job', 'operation', 'role', 'logical_session', 'model', 'effort')}
        self.value.update({key: grant[key] for key in ('auth_profile', 'request_sha256', 'allowance_ref', 'seconds',
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


def forward(channel, provider, selection, grant, journal, deadline, expected_label=None):
    started = False
    attempt = None
    status = 400
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
        attempt = {'number': len(journal.value['attempts']) + 1, 'status': 'reserved',
                   'request_bytes': len(payload), 'request_body_sha256': hashlib.sha256(payload).hexdigest(),
                   'reserved_microusd': reserved, 'peer_uid_gid_verified': True, 'peer_selinux_verified': bool(expected_label)}
        journal.value['attempts'].append(attempt)
        journal.update()
        status = 502
        connection, response = provider.responses(payload, deadline)
        try:
            attempt['http_status'] = response.status
            content = response.getheader('Content-Type', '').partition(';')[0].strip()
            if response.status != 200 or content != 'text/event-stream' or response.getheader('Content-Encoding'):
                attempt['status'] = 'provider-rejected'
                status = response.status if response.status in (400, 403, 429, 503) else 502
                return
            witness = EventWitness(grant, attempt)
            channel.settimeout(2)
            pending = bytearray()
            while time.monotonic() < deadline and (chunk := response.read1(16384)):
                witness.feed(chunk)
                if not started and 'observed_model' not in attempt:
                    pending.extend(chunk)
                    require(len(pending) <= 65536, 'provider model identity not delivered promptly')
                    continue
                if not started:
                    channel.sendall(struct.pack('!H', 200))
                    started = True
                    for index in range(0, len(pending), 16384):
                        piece = pending[index:index + 16384]
                        channel.sendall(struct.pack('!I', len(piece)) + piece)
                channel.sendall(struct.pack('!I', len(chunk)) + chunk)
            require(started and attempt['status'] in ('completed', 'incomplete') and time.monotonic() < deadline,
                    'incomplete provider stream')
            channel.sendall(struct.pack('!I', 0))
        finally:
            connection.close()
    except (OSError, RuntimeError, ValueError, TypeError, http.client.HTTPException, RecursionError):
        if attempt is not None and attempt['status'] == 'reserved':
            attempt['status'] = 'effect-uncertain'
    finally:
        if attempt is not None:
            journal.update()
        if not started:
            with suppress(OSError):
                channel.sendall(struct.pack('!H', status))


def listen(channel_path, provider, selection, grant, journal, deadline, *, channel_label=None):
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
                    forward(channel, provider, selection, grant, journal, deadline, channel_label)
        finally:
            current = channel_path.lstat()
            require((current.st_dev, current.st_ino) == (node.st_dev, node.st_ino), 'provider channel cleanup identity changed')
            channel_path.unlink()


def interrupted(_signum, _frame):
    raise BrokerStopped('broker stop requested')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--grant', type=Path, required=True)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--credential-file', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    journal = None
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(signum, interrupted)
    try:
        os.umask(0o077)
        grant = grant_document(protected_file(args.grant, 8192))
        raw = protected_file(args.request, 4096)
        identity = json.loads(raw, object_pairs_hook=unique_object)
        selection = job_selection(raw, grant['request_sha256'], identity['role'], identity['job'], identity['operation'])
        require(os.geteuid() == 0 and args.socket == provider_host_path(grant['request_sha256']) / 'responses.sock',
                'provider broker requires the protected exact role channel')
        evidence = Path('/var/lib/dev-pair/provider-evidence') / selection['role'] / selection['job']
        require(args.receipt == evidence / (selection['operation'] + '.json'), 'provider evidence location mismatch')
        seconds = min(grant['seconds'], grant['expires_unix'] - time.time())
        require(seconds > 0 and reserved_cost(grant) <= grant['spend_microusd'], 'provider allowance exhausted or expired')
        deadline = time.monotonic() + seconds
        signal.setitimer(signal.ITIMER_REAL, seconds)
        channel_label = broker_channel_label(args.socket.parent)
        # Confirm this host can create the role-labeled socket before contacting the provider.
        with labeled_listener(channel_label):
            pass
        journal = Journal(args.receipt, selection, grant)
        provider = Provider(protected_file(args.credential_file, 1024, secret=True).decode('ascii').removesuffix('\n'))
        journal.value['availability'] = provider.discover(selection['model'], min(deadline, time.monotonic() + 15))
        journal.update()
        if journal.value['availability'] != 'available':
            return 2
        listen(args.socket, provider, selection, grant, journal, deadline, channel_label=channel_label)
        journal.value['status'] = 'closed'
        journal.update()
        return 0
    except BrokerStopped:
        if journal is not None:
            journal.value['status'] = 'interrupted'
            journal.update()
        return 2
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, http.client.HTTPException):
        print('Provider broker blocked; inspect its protected receipt locally', file=sys.stderr)
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    sys.exit(main())
