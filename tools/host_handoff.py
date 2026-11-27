#!/usr/bin/env python3
"""Authenticated checklist handoff for local and Fedora Quadlet checks."""
import argparse
import contextlib
import ctypes
import errno
import fcntl
import http.client
import importlib.util
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
HOST_OPERATIONS = (*OPERATIONS, 'status')
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
HOST_RUNTIME = SELF.parent.parent / 'runtime/checklist/checklist_quadlet.py'
HOST_RECIPE = 'checklist-quadlet-persistence-v1'
HOST_CAPABILITIES = ['rootless-quadlet', 'enforcing-selinux', 'loopback-http', 'owned-service-restart']
HOST_EFFECTS = ['create-item', 'complete-item', 'restart-owned-service', 'remove-disposable-data']
HOST_CLEANUP = dict(CLEANUP, plan='Stop the owned Quadlet and remove its disposable test data')
HOST_REASON = 'Observe persistence across an approved rootless systemd service restart on Fedora'


def recipe_identity(*, host=False):
    if host:
        implementation = p.identity({'adapter': RECIPE_SHA256, 'runtime': p.sha256(HOST_RUNTIME.read_bytes()),
                                     'quadlet': p.sha256(HOST_RUNTIME.with_name('acceptance.container').read_bytes())})
        return {'recipe': HOST_RECIPE, 'recipe_sha256': implementation,
                'revision': p.identity({'implementation': implementation, 'protocol': p.sha256(JOB_PROTOCOL.read_bytes())})}
    return {'recipe': RECIPE, 'recipe_sha256': RECIPE_SHA256, 'revision': RECIPE_REVISION}


def host_runtime():
    spec = importlib.util.spec_from_file_location('checklist_quadlet', HOST_RUNTIME)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    return runtime


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


def produce_request(checkpoint, request_id, controller, principals, budget, *, host=False):
    p.validate(checkpoint, 'checkpoint')
    p.require(checkpoint['test'] == recipe_identity(host=host), 'checkpoint uses a different recipe')
    boundary, reason, capabilities, effects, check, cleanup = (
        (p.APP_QUADLET_BOUNDARY, HOST_REASON, HOST_CAPABILITIES, HOST_EFFECTS, HOST_RECIPE, HOST_CLEANUP)
        if host else (p.APP_PROCESS_BOUNDARY, REASON, CAPABILITIES, EFFECTS, RECIPE, CLEANUP))
    request = p.envelope('request', **{key: checkpoint[key] for key in ('job_id', 'checkpoint_id', 'candidate', 'test')},
                         request_id=request_id, boundary=boundary, reason=reason,
                         capabilities=capabilities, permitted_effects=effects, workspace=checkpoint['job_id'],
                         fixtures=bindings(controller, principals), budgets=budget,
                         checks=[{'id': check, 'expected': EXPECTED}], cleanup=cleanup)
    if host:
        p.require(request['budgets']['seconds'] >= host_runtime().CHECK_SECONDS,
                  'checklist host budget must allow startup, restart and bounded cleanup')
    return request


def check_request(request, controller, principals, *, host=False):
    p.validate(request, 'request')
    checkpoint = p.envelope('checkpoint', **{key: request[key] for key in
                            ('job_id', 'checkpoint_id', 'candidate', 'test')}, summary='Check request', evidence=[])
    p.require(request == produce_request(checkpoint, request['request_id'], controller, principals, request['budgets'],
                                         host=host),
              'request differs from the fixed recipe or TLS principal bindings')


def check_host_status_request(request, controller, principals):
    p.validate(request, 'request')
    p.require(request['boundary'] == p.APP_QUADLET_BOUNDARY and request['fixtures'] == bindings(controller, principals),
              'stored host request requires the same controller and TLS principals')


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


class UnexpectedHTTP(ValueError):
    def __init__(self, status, expected):
        super().__init__(f'application returned HTTP {status}, expected {expected}')


def app_http(port, deadline, method, path, expected, document=None, *, authority=None):
    remaining = time_left(deadline)
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=remaining)
    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        headers = {'Content-Type': 'application/json'} if document is not None else {}
        if authority is not None:
            headers['Host'] = authority
        body = p.canonical(document).encode() if document is not None else None
        connection.request(method, path, body=body, headers=headers)
        reply = connection.getresponse()
        if reply.status != expected:
            raise UnexpectedHTTP(reply.status, expected)
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


def run_host_attempt(ledger, request, attempt, unit, authorization, runtime):
    end = time.monotonic() + request['budgets']['seconds']
    deadline = end - runtime.CLEANUP_SECONDS
    title = 'Checklist restart test ' + attempt
    evidence = [*authorization, 'effect-id:' + attempt, 'kernel-release:' + os.uname().release]
    effects = []
    stage = 'checklist host prerequisites'
    actual = 'The checklist restart observation could not complete'
    status = 'blocked'

    def http(port, method, path, expected, body=None):
        return app_http(port, deadline, method, path, expected, body, authority=runtime.APP_AUTHORITY)

    def ready_items(port):
        while True:
            try:
                return http(port, 'GET', '/items', 200)
            except (ConnectionRefusedError, ConnectionResetError, http.client.RemoteDisconnected):
                time.sleep(min(0.05, time_left(deadline)))

    try:
        evidence.extend(unit.prepare(deadline, p.identity(request)))
        stage = 'start the approved Quadlet'
        port, first_invocation, first_container = unit.service('start', deadline)
        evidence.extend(['first-invocation:' + first_invocation, 'first-container:' + first_container])
        stage = 'create and complete the test item'
        try:
            p.require(ready_items(port) == [], 'disposable checklist data was not initially empty')
            item = http(port, 'POST', '/items', 201, {'title': title})
            valid_item(item)
            p.require(item['title'] == title and item['done'] is False, 'unexpected item from create')
            effects.append('Created a uniquely named test item')
            expected = dict(item, done=True)
            completed = http(port, 'POST', '/items/' + str(item['id']) + '/complete', 200)
            valid_item(completed)
            p.require(completed == expected, 'unexpected item from complete')
            effects.append('Completed the test item')
            evidence.append('completed-item-id:' + str(item['id']))
        except ValueError as exc:
            raise HostCheckFailure('Create or complete did not yield the expected item', exc) from exc
        stage = 'restart the owned Quadlet'
        port, second_invocation, second_container = unit.service('restart', deadline)
        p.require(first_invocation != second_invocation and first_container != second_container,
                  'restart did not replace both the systemd invocation and container')
        evidence.extend(['second-invocation:' + second_invocation, 'second-container:' + second_container])
        effects.append('Replaced the owned systemd invocation and container using the same data mount')
        stage = 'verify the completed item after restart'
        try:
            observed = ready_items(port)
            p.require(type(observed) is list, 'invalid checklist item list')
            for entry in observed:
                valid_item(entry)
            p.require(observed == [expected], 'completed item was missing, changed or duplicated')
        except ValueError as exc:
            raise HostCheckFailure('The completed item did not survive restart with its ID and state', exc) from exc
        actual = 'The same item ID and title returned with done=true after a new systemd invocation'
        status = 'pass'
        diagnostic = 'Checklist SQLite state persisted across one owned Quadlet restart'
    except HostCheckFailure as exc:
        status = 'fail'
        actual = exc.actual
        diagnostic = exc.diagnostic
    except (OSError, ValueError, subprocess.SubprocessError, http.client.HTTPException) as exc:
        error = str(exc) if type(exc) is ValueError else type(exc).__name__
        diagnostic = bounded_diagnostic(stage + ': ' + error)
    finally:
        try:
            unit.cleanup(end)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise ValueError('host effect remains in flight after unresolved Quadlet cleanup') from exc
    logs = 'host-steps:' + ','.join(unit.logs)
    p.text(logs, 1200)
    check = dict(request['checks'][0], actual=actual, status=status, diagnostics=diagnostic, exit_status=None,
                 evidence=evidence)
    executor = {'controller_id': ledger.controller_id, 'environment': p.app_environment(request),
                'boundary': p.APP_QUADLET_BOUNDARY, 'implementation_sha256': request['test']['recipe_sha256']}
    cleanup = {'status': 'complete' if unit.path_created else 'not-needed',
               'diagnostics': 'Owned unit and disposable data removed' if unit.path_created else
               'No owned test service or data created'}
    return p.envelope('result', **{name: request[name] for name in
                      ('job_id', 'request_id', 'checkpoint_id', 'candidate', 'test')},
                      request_sha256=p.identity(request), attempt_id=attempt, executor=executor, status=status,
                      checks=[check], diagnostics=diagnostic, evidence=[*evidence, logs],
                      effects=effects, cleanup=cleanup)


def bounded_diagnostic(text):
    return p.canonical(text)[1:-1][:400] or 'Host operation interrupted'


class HostCheckFailure(Exception):
    def __init__(self, actual, exc):
        self.actual = actual
        # Candidate-supplied JSON fragments and exception content need not leave the executor.
        detail = str(exc) if isinstance(exc, UnexpectedHTTP) or type(exc) is ValueError else 'Invalid item response'
        self.diagnostic = bounded_diagnostic(detail) + '. Check use of /data/checklist.sqlite3 for item IDs and completion state.'


def dispatch_host(ledger, runtime, env, runtime_dir, approval, principals, packet):
    p.fields(packet, 'operation request')
    operation, request = packet['operation'], packet['request']
    p.require(operation in HOST_OPERATIONS, 'unknown host handoff operation')
    if operation == 'status':
        check_host_status_request(request, ledger.controller_id, principals)
        status = ledger.status(request['request_id'])
        ledger.check_transport(status, request)
        return status
    check_request(request, ledger.controller_id, principals, host=True)
    request_id = request['request_id']
    with runtime.dispatch_gate():
        if operation == 'submit':
            runtime.approval(approval, request)
            return ledger.submit(request, authenticated=True)
        if operation == 'consume':
            return ledger.consume(request_id, authenticated_request=request)
        status = ledger.status(request_id)
        ledger.check_transport(status, request)
        if status['state'] == 'completed':
            ledger.current(request)
            return status['result']
        p.require(status['state'] == 'pending', 'unresolved in-flight effects require reconciliation; execution refused')
        image, authorization = runtime.approval(approval, request)
        attempt, previous = ledger.begin(request_id, authenticated_request=request)
        if previous is not None:
            return previous
        unit = runtime.Quadlet(runtime_dir, env, attempt, image, request['candidate'], request['budgets']['seconds'])
        return ledger.finish(run_host_attempt(ledger, request, attempt, unit, authorization, runtime))


def serve_connections(listener, lifetime, context, expected_peer, dispatch_packet):
    deadline = time.monotonic() + lifetime
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
                        data = dispatch_packet(packet)
                        response = {'ok': True, 'data': data}
                    except ValueError as exc:
                        response = {'ok': False, 'data': bounded_diagnostic(str(exc))}
                    send(stream, response, time.monotonic() + WIRE_SECONDS)
            except (OSError, ValueError):
                # Lost clients do not roll back effects or committed history.
                continue


def serve_host(args):
    p.number(args.lifetime, 1, 600)
    p.number(args.port, 0, 65535)
    runtime = host_runtime()
    for code in (SELF, JOB_PROTOCOL, HOST_RUNTIME, runtime.TEMPLATE, pathlib.Path(sys.modules['ledger_recovery'].__file__)):
        runtime.protected(code, file=True)
    directory, env = runtime.rootless_environment()
    state = trusted_directory(args.state)
    tls = trusted_directory(args.tls)
    p.require(state == runtime.HOME / 'ledger' and tls == runtime.HOME / 'tls',
              'durable ledger and TLS require their fixed protected home leaves')
    approval = pathlib.Path(args.approval).absolute()
    p.require(approval == runtime.APPROVAL, 'host approval requires its fixed protected leaf')
    runtime.protected(approval.parent, file=False)
    context, expected_peer, principals = tls_principal(tls, maintenance=True)
    lock_path = directory / 'dev-pair-checklist.lock'
    with os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600), 'rb+') as lock:
        p.private_file(lock_path)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('checklist host executor is already active') from exc
        with contextlib.closing(p.Ledger(state)) as ledger, socket.socket(socket.AF_INET) as listener:
            listener.bind(('127.0.0.1', args.port))
            listener.listen(4)
            print(p.canonical({'port': listener.getsockname()[1], 'controller_id': ledger.controller_id}), flush=True)
            serve_connections(listener, args.lifetime, context, expected_peer,
                              lambda packet: dispatch_host(ledger, runtime, env, directory, approval, principals, packet))


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
        serve_connections(listener, args.lifetime, context, expected_peer,
                          lambda packet: dispatch(ledger, scratch, artifact, size, rules, args.job_id,
                                                  candidate, principals, packet))


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
    if operation in ('submit', 'status'):
        p.fields(data, 'request state attempt_id result reconciliation_required')
        p.require(data['request'] == request, 'stored request identity mismatch')
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
    if operation in ('submit', 'status'):
        p.require(data['state'] == 'completed' and data['attempt_id'] == result['attempt_id'] and
                  data['reconciliation_required'] is False, 'invalid completed request state')
    if operation == 'consume':
        p.require(data['progress'] == p.result_progress(result), 'invalid consumed progress')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    recipe = commands.add_parser('recipe')
    maintenance = commands.add_parser('serve', help='start the disposable loopback executor with an approved artifact')
    for name in ('state', 'scratch', 'candidate', 'tls', 'job-id', 'source-revision', 'artifact-sha256'):
        maintenance.add_argument('--' + name, required=True)
    maintenance.add_argument('--lifetime', type=int, default=120)
    host = commands.add_parser('serve-host', help='start the protected Fedora checklist Quadlet executor')
    for name in ('state', 'tls', 'approval'):
        host.add_argument('--' + name, required=True)
    host.add_argument('--lifetime', type=int, default=300)
    host.add_argument('--port', type=int, default=0)
    approve = commands.add_parser('approve-host', help='issue one bounded grant from a protected candidate receipt')
    approve.add_argument('--candidate-receipt', required=True, type=pathlib.Path)
    approve.add_argument('--lifetime', type=int, default=300)
    approve.add_argument('--publish', action='store_true', help='activate the approval at its fixed root-owned leaf')
    release = commands.add_parser('render-release', help='render a reviewed loopback-only deployment Quadlet to stdout')
    for name in ('image', 'hostname'):
        release.add_argument('--' + name, required=True)
    for name in ('port', 'uid'):
        release.add_argument('--' + name, type=int, required=True)
    request = commands.add_parser('request', help='produce the fixed request from a checkpoint JSON file')
    request.add_argument('checkpoint', type=pathlib.Path)
    request.add_argument('request_id')
    request.add_argument('--seconds', type=int, required=True)
    request.add_argument('--artifact-bytes', type=int, required=True)
    client = commands.add_parser('send', help='send a request from stdin using the development TLS principal')
    client.add_argument('operation', choices=HOST_OPERATIONS)
    client.add_argument('--port', type=int, required=True)
    for command in (request, client):
        command.add_argument('--tls', required=True)
        command.add_argument('--controller-id', required=True)
    for command in (recipe, request, client):
        command.add_argument('--host', action='store_true', help='use the protected Fedora Quadlet recipe')
    args = parser.parse_args(argv)
    if args.command == 'recipe':
        print(p.canonical(recipe_identity(host=args.host)))
        return
    if args.command == 'serve':
        serve(args)
        return
    if args.command == 'serve-host':
        serve_host(args)
        return
    if args.command == 'approve-host':
        message = p.validate(p.loads(sys.stdin.buffer.read(p.MAX_MESSAGE + 1)), 'request')
        controller, *principals = p.app_transport(message)
        check_request(message, controller, principals, host=True)
        runtime = host_runtime()
        approval = runtime.issue_approval(args.candidate_receipt, message, args.lifetime)
        if args.publish:
            runtime.publish_approval(approval)
        print(p.canonical(approval))
        return
    if args.command == 'render-release':
        sys.stdout.buffer.write(host_runtime().deployment_unit(args.image, args.hostname, args.port, args.uid))
        return
    context, expected_peer, principals = tls_principal(args.tls, maintenance=False)
    if args.command == 'request':
        checkpoint = p.loads(p.read_data(args.checkpoint, p.MAX_MESSAGE))
        budget = {'seconds': args.seconds, 'artifact_bytes': args.artifact_bytes, 'spend_usd': 0}
        result = produce_request(checkpoint, args.request_id, args.controller_id, principals, budget, host=args.host)
    else:
        p.require(args.host or args.operation in OPERATIONS, 'status requires the protected host recipe')
        message = p.loads(sys.stdin.buffer.read(p.MAX_MESSAGE + 1))
        if args.operation == 'status':
            check_host_status_request(message, args.controller_id, principals)
        else:
            check_request(message, args.controller_id, principals, host=args.host)
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
