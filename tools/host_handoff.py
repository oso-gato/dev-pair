#!/usr/bin/env python3
"""Authenticated local-process handoff for one approved checklist artifact."""
import argparse
import contextlib
import ctypes
import errno
import fcntl
import http.client
import os
import pathlib
import resource
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

import job_protocol as p
from ledger_recovery import read_private, trusted_directory

RECIPE = 'app-state-after-restart'
EXPECTED = 'The same item ID is present and completed after one service restart'
REASON = 'Observe application state across a maintenance-controlled restart'
CAPABILITIES = ['loopback-http', 'owned-process-restart']
EFFECTS = ['create-item', 'complete-item', 'restart-owned-service', 'remove-disposable-data']
CLEANUP = {'plan': 'Stop only the owned child processes and remove the attempt database',
           'preserve': ['source', 'checkpoints', 'evidence', 'deliverables']}
OPERATIONS = ('submit', 'execute', 'consume')
WIRE_SECONDS = 3
MAX_APP_RESPONSE = 8192
MAX_FILE_BYTES = 1024 * 1024
BWRAP = pathlib.Path('/usr/bin/bwrap')
APP_PYTHON = pathlib.Path('/usr/bin/python3')
SELF = pathlib.Path(__file__).resolve()
JOB_PROTOCOL = pathlib.Path(p.__file__).resolve()
LIBC = ctypes.CDLL(None, use_errno=True)
# Linux UAPI constants also cover Python builds that omit these names.
ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
FULL_SEALS = 0x000F  # Seal the seal set, writes, growth and shrinking.


RECIPE_SHA256 = p.sha256(SELF.read_bytes())
RECIPE_REVISION = p.identity({'adapter': RECIPE_SHA256, 'protocol': p.sha256(JOB_PROTOCOL.read_bytes())})


def recipe_identity():
    return {'recipe': RECIPE, 'recipe_sha256': RECIPE_SHA256, 'revision': RECIPE_REVISION}


def tls_principal(directory, *, maintenance):
    directory = trusted_directory(directory)
    cert = read_private(directory / 'cert.pem', 8192).decode('ascii')
    peer = read_private(directory / 'peer.pem', 8192).decode('ascii')
    own_fingerprint = p.sha256(ssl.PEM_cert_to_DER_cert(cert))
    peer_fingerprint = p.sha256(ssl.PEM_cert_to_DER_cert(peer))
    p.require(own_fingerprint != peer_fingerprint, 'distinct TLS certificates required')
    key = directory / 'key.pem'
    p.private_file(key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if maintenance else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # The exact configured certificate is pinned below regardless of its names.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=peer)
    context.load_cert_chain(directory / 'cert.pem', keyfile=key, password=lambda: '')
    principals = ((peer_fingerprint, own_fingerprint) if maintenance
                  else (own_fingerprint, peer_fingerprint))
    return context, peer_fingerprint, principals


def bindings(controller, principals):
    return ['controller:' + controller, 'development-cert-sha256:' + principals[0],
            'maintenance-cert-sha256:' + principals[1]]


def produce_request(checkpoint, request_id, controller, principals, budget):
    p.validate(checkpoint, 'checkpoint')
    p.require(checkpoint['test'] == recipe_identity(), 'checkpoint uses a different recipe')
    return p.envelope('request', **{key: checkpoint[key] for key in ('job_id', 'checkpoint_id', 'candidate', 'test')},
                      request_id=request_id, boundary=p.APP_PROCESS_BOUNDARY, reason=REASON,
                      capabilities=CAPABILITIES, permitted_effects=EFFECTS, workspace=checkpoint['job_id'],
                      fixtures=bindings(controller, principals), budgets=budget,
                      checks=[{'id': RECIPE, 'expected': EXPECTED}], cleanup=CLEANUP)


def check_request(request, controller, principals):
    p.validate(request, 'request')
    p.require(request['boundary'] == p.APP_PROCESS_BOUNDARY and request['test'] == recipe_identity() and
              request['workspace'] == request['job_id'] and request['reason'] == REASON and
              request['capabilities'] == CAPABILITIES and
              request['permitted_effects'] == EFFECTS and request['fixtures'] == bindings(controller, principals) and
              request['checks'] == [{'id': RECIPE, 'expected': EXPECTED}] and request['cleanup'] == CLEANUP,
              'request differs from the fixed recipe or TLS principal bindings')


def time_left(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('operation deadline expired')
    return remaining


def read_exact(stream, length, deadline):
    data = bytearray()
    while len(data) < length:
        stream.settimeout(time_left(deadline))
        part = stream.recv(length - len(data))
        p.require(bool(part), 'truncated transport frame')
        data.extend(part)
    return bytes(data)


def receive(stream, deadline):
    length, = struct.unpack('!I', read_exact(stream, 4, deadline))
    p.number(length, 1, p.MAX_MESSAGE)
    return p.loads(read_exact(stream, length, deadline))


def send(stream, message, deadline):
    data = p.canonical(message).encode()
    p.number(len(data), 1, p.MAX_MESSAGE)
    stream.settimeout(time_left(deadline))
    stream.sendall(struct.pack('!I', len(data)) + data)


def check_peer(stream, expected):
    peer = stream.getpeercert(binary_form=True)
    p.require(peer and p.sha256(peer) == expected, 'TLS peer fingerprint mismatch')


@contextlib.contextmanager
def sealed_candidate(source, expected):
    data = p.read_data(source, p.MAX_MESSAGE)
    p.require(p.sha256(data) == expected, 'approved candidate artifact digest mismatch')
    fd = os.memfd_create('dev-pair-checklist', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(data)
        fcntl.fcntl(fd, ADD_SEALS, FULL_SEALS)
        p.require(fcntl.fcntl(fd, GET_SEALS) == FULL_SEALS, 'candidate descriptor seals are incomplete')
        yield fd, len(data)
    finally:
        os.close(fd)


@contextlib.contextmanager
def process_filter():
    lib = ctypes.CDLL('libseccomp.so.2')
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    context = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    p.require(context, 'cannot initialize the single-process sandbox filter')
    try:
        with tempfile.TemporaryFile() as rules:
            for name in (b'clone', b'clone3', b'fork', b'vfork', b'io_uring_setup', b'memfd_create'):
                syscall = lib.seccomp_syscall_resolve_name(name)
                p.require(lib.seccomp_rule_add(context, 0x00050000 | errno.EPERM, syscall, 0) == 0,
                          'cannot restrict process and anonymous file creation')
            p.require(lib.seccomp_export_bpf(context, rules.fileno()) == 0, 'cannot publish sandbox filter')
            yield rules
    finally:
        lib.seccomp_release(context)


def child_limits(parent, seconds):
    # Linux PR_SET_PDEATHSIG: the fixture cannot outlive a killed controller.
    if LIBC.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(125)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))


def launch(artifact, database, rules, listener, seconds):
    parent = os.getpid()
    listen_fd = listener.fileno()
    rules.seek(0)
    command = [str(BWRAP), '--unshare-all', '--unshare-user', '--disable-userns', '--die-with-parent',
               '--new-session', '--cap-drop', 'ALL', '--clearenv', '--setenv', 'LC_ALL', 'C.UTF-8',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
               '--proc', '/proc', '--dev', '/dev', '--remount-ro', '/dev',
               '--size', str(MAX_FILE_BYTES), '--tmpfs', '/data', '--bind', str(database), '/data/checklist.sqlite3',
               '--remount-ro', '/', '--seccomp', str(rules.fileno()),
               '--chdir', '/data', '--', str(APP_PYTHON), '-IB', '/proc/self/fd/' + str(artifact), 'serve',
               '--database', '/data/checklist.sqlite3', '--listen-fd', str(listen_fd)]
    return subprocess.Popen(command,
                            pass_fds=(artifact, listen_fd, rules.fileno()), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env={'PATH': '/usr/bin', 'LC_ALL': 'C.UTF-8'},
                            preexec_fn=lambda: child_limits(parent, seconds))


def stop(child):
    try:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)
    finally:
        child.stdout.close()


def await_readiness(child, port, deadline):
    data = bytearray()
    while len(data) < 64 and not data.endswith(b'\n'):
        ready, _, _ = select.select([child.stdout], [], [], time_left(deadline))
        if not ready:
            raise TimeoutError('application startup deadline expired')
        char = os.read(child.stdout.fileno(), 1)
        if not char:
            break
        data.extend(char)
    expected = f'http://127.0.0.1:{port}\n'.encode('ascii')
    p.require(data == expected and child.poll() is None, 'application readiness did not match the owned listener')


@contextlib.contextmanager
def service(artifact, database, rules, seconds, deadline, children):
    time_left(deadline)
    with socket.socket(socket.AF_INET) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        child = launch(artifact, database, rules, listener, seconds)
        children.append(child)
        try:
            await_readiness(child, port, deadline)
            yield child, port
        finally:
            stop(child)


def expire(_signum, _frame):
    raise TimeoutError('application operation deadline expired')


def app_http(port, deadline, method, path, expected, document=None):
    remaining = time_left(deadline)
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=remaining)
    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        headers = {'Content-Type': 'application/json'} if document is not None else {}
        body = p.canonical(document).encode() if document is not None else None
        connection.request(method, path, body=body, headers=headers)
        reply = connection.getresponse()
        p.require(reply.status == expected, 'application returned an unexpected HTTP status')
        data = reply.read(MAX_APP_RESPONSE + 1)
        p.require(len(data) <= MAX_APP_RESPONSE, 'application response exceeds byte limit')
        return p.loads(data)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        connection.close()


def valid_item(item):
    p.fields(item, 'id title done')
    p.number(item['id'], 1, 2**63 - 1)
    p.text(item['title'], 2000)
    p.require(type(item['done']) is bool, 'invalid application completion value')


def run_attempt(ledger, request, attempt, scratch, artifact, rules):
    deadline = time.monotonic() + request['budgets']['seconds']
    seconds = request['budgets']['seconds']
    workspace = scratch / attempt
    database = workspace / 'checklist.sqlite3'
    title = RECIPE + '-' + attempt
    children, effects = [], []
    evidence = ['artifact-sha256:' + request['candidate']['artifact_sha256'],
                'kernel-release:' + os.uname().release,
                'controller-python-version:' + '.'.join(map(str, sys.version_info[:3]))]
    created = False
    stage = 'allocate the disposable test workspace'
    try:
        workspace.mkdir(mode=0o700)
        created = True
        os.close(os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        stage = 'start the approved application'
        with service(artifact, database, rules, seconds, deadline, children) as (first, port):
            evidence.append('first-supervisor-pid:' + str(first.pid))
            stage = 'create and complete the test item'
            item = app_http(port, deadline, 'POST', '/items', 201, {'title': title})
            valid_item(item)
            p.require(item['title'] == title and item['done'] is False, 'unexpected created item')
            effects.append('Created the attempt item in the disposable database')
            expected = dict(item, done=True)
            completed = app_http(port, deadline, 'POST', '/items/' + str(item['id']) + '/complete', 200)
            valid_item(completed)
            p.require(completed == expected, 'unexpected completed item')
            effects.append('Completed the attempt item')
            evidence.append('completed-item-id:' + str(item['id']))
        stage = 'restart the owned application'
        with service(artifact, database, rules, seconds, deadline, children) as (second, port):
            evidence.append('second-supervisor-pid:' + str(second.pid))
            effects.append('Replaced the owned process once using the same database')
            stage = 'read the item after restart'
            observed = app_http(port, deadline, 'GET', '/items', 200)
        p.require(type(observed) is list, 'application item list is invalid')
        for entry in observed:
            valid_item(entry)
        survived = [entry for entry in observed if entry['id'] == item['id'] or entry['title'] == title]
        if survived == [expected]:
            status = 'pass'
            actual = 'The same item ID and title were returned with done=true after restart'
            diagnostic = 'The completed item survived one restart using the same database'
        else:
            status = 'fail'
            actual = 'The completed item was missing, changed or duplicated after restart'
            diagnostic = 'Keep item IDs and completion state in the declared database across restart'
    except (OSError, ValueError, subprocess.SubprocessError, http.client.HTTPException):
        status, actual = 'blocked', 'The persistence observation could not complete'
        diagnostic = 'Could not ' + stage
    finally:
        cleanup = {'status': 'complete' if created else 'not-needed',
                   'diagnostics': 'Owned children stopped and disposable data removed' if created
                   else 'No disposable resources created'}
        try:
            for child in reversed(children):
                stop(child)
            if created:
                shutil.rmtree(workspace)
        except (OSError, subprocess.SubprocessError):
            cleanup = {'status': 'unresolved', 'diagnostics': 'Owned test cleanup requires operator inspection'}
    if cleanup['status'] == 'unresolved':
        # Retain the reserved attempt so a subsequent request cannot cross an
        # unresolved resource boundary. No successful result is published.
        raise ValueError('application attempt remains in flight after unresolved cleanup')
    check = dict(request['checks'][0], actual=actual, status=status, diagnostics=diagnostic,
                 exit_status=None, evidence=evidence)
    executor = {'controller_id': ledger.controller_id, 'environment': p.app_environment(request),
                'boundary': p.APP_PROCESS_BOUNDARY, 'implementation_sha256': request['test']['recipe_sha256']}
    return p.envelope('result', **{name: request[name] for name in
                      ('job_id', 'request_id', 'checkpoint_id', 'candidate', 'test')},
                      request_sha256=p.identity(request), attempt_id=attempt, executor=executor, status=status,
                      checks=[check], diagnostics=diagnostic, evidence=evidence, effects=effects, cleanup=cleanup)


def dispatch(ledger, scratch, artifact, size, rules, job_id, candidate, principals, packet):
    p.fields(packet, 'operation request')
    operation, request = packet['operation'], packet['request']
    p.require(operation in OPERATIONS, 'unknown handoff operation')
    check_request(request, ledger.controller_id, principals)
    p.require(request['job_id'] == job_id and request['candidate'] == candidate,
              'request is outside the approved job and candidate')
    p.require(size <= request['budgets']['artifact_bytes'], 'approved artifact exceeds request byte limit')
    if operation == 'submit':
        return ledger.submit(request, authenticated=True)
    request_id = request['request_id']
    if operation == 'consume':
        return ledger.consume(request_id, authenticated_request=request)
    attempt, previous = ledger.begin(request_id, authenticated_request=request)
    if previous is not None:
        return previous
    return ledger.finish(run_attempt(ledger, request, attempt, scratch, artifact, rules))


def serve(args):
    p.token(args.job_id)
    p.number(args.lifetime, 1, 600)
    candidate = {'source_revision': args.source_revision, 'artifact_sha256': args.artifact_sha256}
    p.candidate(candidate)
    scratch = trusted_directory(args.scratch)
    paths = [scratch, pathlib.Path(args.state).absolute(), pathlib.Path(args.tls).absolute()]
    p.require(len(set(paths)) == len(paths) and all(not path.resolve().is_relative_to('/usr') for path in paths),
              'ledger, scratch and TLS directories must be separate and outside the sandbox system mount')
    for executable in (BWRAP, APP_PYTHON):
        info = executable.stat()
        p.require(info.st_uid == 0 and not info.st_mode & 0o6022 and os.access(executable, os.X_OK),
                  'expected protected unprivileged sandbox tools')
    context, expected_peer, principals = tls_principal(args.tls, maintenance=True)
    with process_filter() as rules, sealed_candidate(args.candidate, args.artifact_sha256) as (artifact, size), \
            contextlib.closing(p.Ledger(args.state)) as ledger, socket.socket(socket.AF_INET) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        print(p.canonical({'port': listener.getsockname()[1], 'controller_id': ledger.controller_id}), flush=True)
        deadline = time.monotonic() + args.lifetime
        while time.monotonic() < deadline:
            listener.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                return
            with connection:
                connection.settimeout(WIRE_SECONDS)
                try:
                    with context.wrap_socket(connection, server_side=True) as stream:
                        check_peer(stream, expected_peer)
                        packet = receive(stream, time.monotonic() + WIRE_SECONDS)
                        try:
                            data = dispatch(ledger, scratch, artifact, size, rules, args.job_id, candidate, principals, packet)
                            response = {'ok': True, 'data': data}
                        except ValueError as exc:
                            response = {'ok': False, 'data': str(exc)}
                        send(stream, response, time.monotonic() + WIRE_SECONDS)
                except (OSError, ValueError):
                    # Drop unauthenticated, malformed, partial and lost connections.
                    # Any committed ledger state remains available to the same principal.
                    continue


def exchange(port, context, expected_peer, operation, request):
    p.number(port, 1, 65535)
    with socket.create_connection(('127.0.0.1', port), timeout=WIRE_SECONDS) as connection:
        with context.wrap_socket(connection) as stream:
            check_peer(stream, expected_peer)
            send(stream, {'operation': operation, 'request': request}, time.monotonic() + WIRE_SECONDS)
            reply = receive(stream, time.monotonic() + request['budgets']['seconds'] + 5 * WIRE_SECONDS)
    p.fields(reply, 'ok data')
    p.require(type(reply['ok']) is bool, 'invalid transport response')
    if not reply['ok']:
        p.text(reply['data'])
        raise ValueError(reply['data'])
    return reply['data']


def check_reply(operation, data, request, controller):
    if operation == 'submit':
        p.fields(data, 'request state attempt_id result reconciliation_required')
        p.require(data['request'] == request, 'submitted request identity mismatch')
        if data['result'] is None:
            p.require((data['state'] == 'pending' and data['attempt_id'] is None and
                       data['reconciliation_required'] is False) or
                      (data['state'] == 'in-flight' and type(data['attempt_id']) is str and
                       data['reconciliation_required'] is True), 'invalid request state')
            return
    elif operation == 'consume':
        p.fields(data, 'progress result')
    result = data if operation == 'execute' else data['result']
    p.validate(result, 'result')
    p.match_result(request, result, controller)
    if operation == 'submit':
        p.require(data['state'] == 'completed' and data['attempt_id'] == result['attempt_id'] and
                  data['reconciliation_required'] is False, 'invalid completed request state')
    if operation == 'consume':
        p.require(data['progress'] == p.result_progress(result), 'invalid consumed progress')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('recipe')
    maintenance = commands.add_parser('serve', help='start the disposable loopback executor with an approved artifact')
    for name in ('state', 'scratch', 'candidate', 'tls', 'job-id', 'source-revision', 'artifact-sha256'):
        maintenance.add_argument('--' + name, required=True)
    maintenance.add_argument('--lifetime', type=int, default=120)
    request = commands.add_parser('request', help='produce the fixed request from a checkpoint JSON file')
    request.add_argument('checkpoint', type=pathlib.Path)
    request.add_argument('request_id')
    request.add_argument('--seconds', type=int, required=True)
    request.add_argument('--artifact-bytes', type=int, required=True)
    client = commands.add_parser('send', help='send a request from stdin using the development TLS principal')
    client.add_argument('operation', choices=OPERATIONS)
    client.add_argument('--port', type=int, required=True)
    for command in (request, client):
        command.add_argument('--tls', required=True)
        command.add_argument('--controller-id', required=True)
    args = parser.parse_args(argv)
    if args.command == 'recipe':
        print(p.canonical(recipe_identity()))
        return
    if args.command == 'serve':
        serve(args)
        return
    context, expected_peer, principals = tls_principal(args.tls, maintenance=False)
    if args.command == 'request':
        checkpoint = p.loads(p.read_data(args.checkpoint, p.MAX_MESSAGE))
        budget = {'seconds': args.seconds, 'artifact_bytes': args.artifact_bytes, 'spend_usd': 0}
        result = produce_request(checkpoint, args.request_id, args.controller_id, principals, budget)
    else:
        message = p.loads(sys.stdin.buffer.read(p.MAX_MESSAGE + 1))
        check_request(message, args.controller_id, principals)
        result = exchange(args.port, context, expected_peer, args.operation, message)
        check_reply(args.operation, result, message, args.controller_id)
    print(p.canonical(result))


if __name__ == '__main__':
    try:
        main()
    except OSError:
        print('Blocked: local handoff I/O or TLS failed', file=sys.stderr)
        sys.exit(2)
    except ValueError as exc:
        print('Blocked: ' + str(exc), file=sys.stderr)
        sys.exit(2)
