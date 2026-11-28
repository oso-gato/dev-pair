#!/usr/bin/env python3
"""Carry exact access-review requests and signed responses over a pinned SSH route."""

import argparse
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).absolute().parent))

from bootstrap import Blocked, CORE_ACCESS_CUTOVER, WORKLOAD_ACCESS_CUTOVER, relay, validate_public_keys
from destination_observation import (CORE_BINDING, MAX_ACCESS_ENVELOPE, bounded_file, encoding, read_access_envelope,
                                     state_dir)

CONFIG = Path('/etc/dev-pair/day0/access-exchange.json')
HOST_KEY = CONFIG.with_name('access-exchange-known-hosts')
IDENTITY = CONFIG.with_name('access-exchange-ed25519')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
ACCESS_PRINCIPAL = 'dev-pair-access-review'
ACCESS_NAMESPACE = 'dev-pair-destination'
KINDS = {CORE_ACCESS_CUTOVER, WORKLOAD_ACCESS_CUTOVER, 'agent-workload-candidate'}
RANGES = (ipaddress.ip_network('100.64.0.0/10'), ipaddress.ip_network('fd7a:115c:a1e0::/48'))
REQUEST_LIMIT = 16384
MAILBOX_LIMIT = 64
RETENTION_SECONDS = 7 * 86400
COMMAND = 'day0-access-v1'


class ExchangeUnavailable(Blocked):
    """The approved transfer route is not configured or cannot currently connect."""


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def key(value, *, hardware=False):
    parts = value.split()
    admitted = {'ssh-ed25519', 'sk-ssh-ed25519@openssh.com'} if hardware else {'ssh-ed25519'}
    require(len(parts) >= 2 and len(value) <= 1024 and parts[0] in admitted and value.isascii(),
            'Enter the independently supplied OpenSSH Ed25519 public key.')
    try:
        return validate_public_keys((' '.join(parts[:2]) + '\n').encode()).strip()
    except Blocked:
        raise Blocked('The supplied Ed25519 public key is invalid.') from None


def contact(host, user):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise Blocked('Enter the verifier station’s numeric Tailscale address.') from None
    require(type(host) is str and str(address) == host and '%' not in host and any(address in network for network in RANGES)
            and type(user) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user) and user != 'root',
            'The verifier requires a canonical Tailscale address and a dedicated non-root transport account.')
    return host, user


def protected_file(path):
    for node in (path, *path.parents):
        info = node.lstat()
        proper = (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                  and 0 < info.st_size <= 4096
                  if node == path else stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022)
        require(info.st_uid == 0 and proper, 'Independent access exchange requires protected root-owned files.')
    return path


def configuration():
    if not os.path.lexists(CONFIG):
        return None
    raw = bounded_file(protected_file(CONFIG), 4096)
    profile = json.loads(raw, object_pairs_hook=relay.unique)
    require(type(profile) is dict and set(profile) == {'version', 'host', 'user', 'host_key'}
            and type(profile['version']) is int and profile['version'] == 1 and encoding(profile) == raw,
            'The protected independent access exchange profile is invalid.')
    contact(profile['host'], profile['user'])
    require(type(profile['host_key']) is str and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]{68}', profile['host_key'])
            and bounded_file(protected_file(HOST_KEY), 4096) ==
            f"{profile['host']} {profile['host_key']}\n".encode(),
            'The protected independent station SSH host key differs.')
    protected_file(IDENTITY)
    return profile


def identity_public(app):
    if not os.path.lexists(IDENTITY):
        with tempfile.TemporaryDirectory(prefix='dev-pair-access-key-', dir='/run') as directory:
            generated = Path(directory) / 'id'
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(generated)],
                           env=ENV, stdin=subprocess.DEVNULL, timeout=10, check=True)
            app.atomic(str(IDENTITY), generated.read_text())
    return public_identity()


def public_identity():
    public = subprocess.check_output(['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(protected_file(IDENTITY))],
                                     env=ENV, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    return key(public.decode('ascii'))


def configure(app, host, user, host_key):
    contact(host, user)
    host_key = key(host_key)
    require(host_key != identity_public(app), 'The station host key must be separate from the request transport key.')
    app.atomic(str(HOST_KEY), f'{host} {host_key}\n')
    app.atomic(str(CONFIG), encoding({'version': 1, 'host': host, 'user': user, 'host_key': host_key}).decode())
    return configuration()


def request_value(raw):
    require(0 < len(raw) <= REQUEST_LIMIT, 'Independent access request exceeds its bound.')
    data = json.loads(raw, object_pairs_hook=relay.unique)
    require(type(data) is dict and type(data.get('version')) is int and data['version'] == 1 and
            type(data.get('kind')) is str and data['kind'] in KINDS and encoding(data) == raw,
            'Expected the exact canonical independent access request.')
    require(CORE_BINDING <= data.keys() and type(data['tailnet_addresses']) is dict and
            set(data['tailnet_addresses']) == {'ipv4', 'ipv6'},
            'Independent access request is missing its live host binding.')
    return data


def exchange(request):
    """Return untouched signed response bytes, or None while independent review is pending."""
    binding = request_value(request)
    profile = configuration()
    if profile is None:
        raise ExchangeUnavailable('The independent access exchange station is not configured.')
    require(profile['host'] not in binding['tailnet_addresses'].values(),
            'The access review station must be separate from the selected VPS.')
    options = ('BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
               'GlobalKnownHostsFile=/dev/null', f'UserKnownHostsFile={HOST_KEY}', 'HostKeyAlgorithms=ssh-ed25519',
               'CheckHostIP=no', 'UpdateHostKeys=no', 'ControlMaster=no', 'ProxyCommand=none', 'ProxyJump=none',
               'ClearAllForwardings=yes', 'ForwardAgent=no', 'PreferredAuthentications=publickey',
               'ConnectTimeout=8', 'ConnectionAttempts=1', 'ServerAliveInterval=5', 'ServerAliveCountMax=2')
    command = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-i', str(IDENTITY)]
    for option in options:
        command += ['-o', option]
    command += ['--', f"{profile['user']}@{profile['host']}", COMMAND, sha256(request).hexdigest()]

    def limits():
        ceiling = MAX_ACCESS_ENVELOPE + 1
        resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, ceiling))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    try:
        with tempfile.TemporaryFile(dir='/run') as response:
            result = subprocess.run(command, env=ENV, input=request, stdout=response, stderr=subprocess.DEVNULL,
                                    timeout=25, preexec_fn=limits, check=False)
            if response.tell() > MAX_ACCESS_ENVELOPE:
                raise Blocked('Independent station response exceeded its bound.')
            if result.returncode:
                raise ExchangeUnavailable('The pinned independent station could not be reached over the approved SSH route.')
            response.seek(0)
            return response.read() or None
    except (OSError, subprocess.SubprocessError) as error:
        raise ExchangeUnavailable('The independent access transport did not complete within its bound.') from error


def response_value(raw, request):
    payload, _ = read_access_envelope(io.BytesIO(raw))
    receipt = json.loads(payload, object_pairs_hook=relay.unique)
    fields = {'kind', 'version', 'machine_id', 'boot_id', 'source_sha', 'dns_name', 'node_id', 'tailnet',
              'tailnet_addresses', 'keys_sha256', 'role_artifacts', 'candidate'}
    require(type(receipt) is dict and all(receipt.get(field) == request[field] for field in fields & request.keys())
            and type(receipt.get('expires_at')) is int, 'Signed response does not identify this access request.')
    return receipt


@contextmanager
def mailbox_lock(path):
    state_dir(path)
    flags = os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
    descriptor = os.open(path / '.lock', flags, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'Independent station mailbox lock is unsafe.')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def store(path, data):
    # The mailbox lock serializes publication and gives interrupted writers one
    # reusable staging leaf, even across forced-command process loss.
    name = path.parent / '.staging'
    flags = os.O_CREAT | os.O_NOFOLLOW | os.O_WRONLY | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, 0o600), 'wb') as staging:
        info = os.fstat(staging.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'Independent station staging file is unsafe.')
        os.ftruncate(staging.fileno(), 0)
        staging.write(data)
        staging.flush()
        os.fsync(staging.fileno())
    os.replace(name, path)
    descriptor = os.open(path.parent, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def current_response(path, request, now):
    if os.path.lexists(path):
        raw = bounded_file(path, MAX_ACCESS_ENVELOPE)
        if response_value(raw, request)['expires_at'] > now:
            return raw
    return None


def pending_requests(path, now):
    count = 0
    with os.scandir(path) as entries:
        for entry in entries:
            name = entry.name
            if name.endswith('.request') and re.fullmatch(r'[0-9a-f]{64}', name[:-8]):
                count += 1
                require(count <= MAILBOX_LIMIT, 'Independent station mailbox exceeded its request bound.')
                leaf = Path(entry.path)
                if now - entry.stat(follow_symlinks=False).st_mtime > RETENTION_SECONDS:
                    leaf.with_suffix('.response').unlink(missing_ok=True)
                    leaf.unlink()
                else:
                    yield leaf


def receive(mailbox, original_command, incoming, outgoing, now):
    match = re.fullmatch(COMMAND + ' ([0-9a-f]{64})', original_command)
    require(match, 'Independent station accepts only its fixed access request protocol.')
    raw = incoming.read(REQUEST_LIMIT + 1)
    request = request_value(raw)
    name = sha256(raw).hexdigest()
    require(name == match[1], 'Independent access request digest differs.')
    leaf = mailbox / (name + '.request')
    with mailbox_lock(mailbox):
        if not os.path.lexists(leaf):
            require(sum(1 for _ in pending_requests(mailbox, now)) < MAILBOX_LIMIT,
                    'Independent station mailbox is full.')
            store(leaf, raw)
        else:
            require(bounded_file(leaf, REQUEST_LIMIT) == raw, 'Existing independent access request differs.')
        response = current_response(leaf.with_suffix('.response'), request, now)
    if response is not None:
        outgoing.write(response)


def publish(mailbox, name, incoming, now):
    require(re.fullmatch(r'[0-9a-f]{64}', name), 'Expected the exact request identifier from the independent mailbox.')
    response = incoming.read(MAX_ACCESS_ENVELOPE + 1)
    with mailbox_lock(mailbox):
        leaf = mailbox / (name + '.request')
        raw = bounded_file(leaf, REQUEST_LIMIT)
        require(sha256(raw).hexdigest() == name, 'Stored independent access request digest differs.')
        request = request_value(raw)
        require(response_value(response, request)['expires_at'] > now, 'Signed response has expired.')
        target = leaf.with_suffix('.response')
        existing = current_response(target, request, now)
        require(existing is None or existing == response, 'An unexpired response already exists for this request.')
        if existing is None:
            store(target, response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mailbox', required=True, type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('receive')
    pending = commands.add_parser('pending')
    pending.add_argument('--kind', choices=sorted(KINDS))
    reply = commands.add_parser('publish')
    reply.add_argument('request')
    args = parser.parse_args()
    os.umask(0o077)
    now = time.time()
    try:
        if args.command == 'receive':
            # Also bounds a client that keeps stdin open without completing the request.
            signal.alarm(30)
            receive(args.mailbox, os.environ.get('SSH_ORIGINAL_COMMAND', ''), sys.stdin.buffer, sys.stdout.buffer, now)
        elif args.command == 'publish':
            publish(args.mailbox, args.request, sys.stdin.buffer, now)
        else:
            with mailbox_lock(args.mailbox):
                for leaf in sorted(pending_requests(args.mailbox, now)):
                    request = request_value(bounded_file(leaf, REQUEST_LIMIT))
                    if (args.kind in (None, request['kind'])
                            and current_response(leaf.with_suffix('.response'), request, now) is None):
                        print(leaf)
        return 0
    except (Blocked, OSError, ValueError, TypeError, KeyError) as error:
        print(f'Independent access exchange paused. {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
