#!/usr/bin/python3
"""Immutable in-unit anonymous-pipe relay and bounded stderr decoder."""
import argparse
import ctypes
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

CAPACITY = 4096
INPUT_LIMIT = 16384
MAXIMA = (262144, 1048576, 4194304)
ERROR_STATUS = 250
QUERY_SECONDS = 5
HEADER = struct.Struct('!c3sI')
MAGIC = b'DP1'


def require(value):
    if not value:
        raise ValueError('native relay protocol rejected')


def overhead(maximum):
    require(maximum in MAXIMA)
    return 8 * math.ceil(maximum / CAPACITY) + 256


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


class Decoder:
    def __init__(self, maximum):
        require(maximum in MAXIMA)
        self.maximum, self.raw = maximum, 0
        self.header, self.body = bytearray(), bytearray()
        self.kind, self.length, self.control = None, None, None
        self.failure = None
        self.partial = False
        self.frames = 0

    def feed(self, data):
        self.raw += len(data)
        require(self.raw <= self.maximum + overhead(self.maximum))
        output = []
        view = memoryview(data)
        while view:
            require(self.control is None and self.failure is None)
            if self.length is None:
                count = min(8 - len(self.header), len(view))
                self.header.extend(view[:count]); view = view[count:]
                if len(self.header) < 8:
                    continue
                kind, magic, size = HEADER.unpack(self.header)
                require(magic == MAGIC and kind in (b'D', b'C', b'F') and 0 < size <= (4096 if kind == b'D' else 248))
                require(not (kind == b'D' and self.partial))
                self.kind, self.length = kind, size
                self.header.clear()
            count = min(self.length - len(self.body), len(view))
            self.body.extend(view[:count]); view = view[count:]
            if len(self.body) == self.length:
                if self.kind == b'D':
                    self.frames += 1
                    require(self.frames <= math.ceil(self.maximum / CAPACITY))
                    self.partial = self.length < CAPACITY
                    output.append(bytes(self.body))
                elif self.kind == b'F':
                    value = json.loads(self.body, object_pairs_hook=unique)
                    require(type(value) is dict and set(value) == {'v', 'done', 'stage', 'reason', 'property', 'observed'} and
                            type(value['v']) is int and value['v'] == 1 and value['done'] is False and value['stage'] == 'effective-profile' and
                            value['reason'] == 'rejected' and type(value['property']) is str and value['property'] in PROFILE_KEYS and
                            ProfileError(value['property'], value['observed']).value == value['observed'])
                    self.failure = value
                else:
                    value = json.loads(self.body, object_pairs_hook=unique)
                    require(type(value) is dict and set(value) == {'v', 'done', 'status', 'uid', 'domain', 'helper', 'p'} and
                            type(value['v']) is int and value['v'] == 1 and type(value['p']) is int and value['p'] == 1 and value['done'] is True and
                            type(value['status']) is int and -64 <= value['status'] <= 255 and
                            type(value['uid']) is int and value['uid'] >= 0 and value['domain'] == 'unconfined_service_t' and
                            type(value['helper']) is str and len(value['helper']) == 64 and all(c in '0123456789abcdef' for c in value['helper']))
                    self.control = value
                self.body.clear(); self.kind, self.length = None, None
        return output

    def finish(self, native_status, expected_uid, helper_sha):
        require(self.control is not None and not self.header and not self.body and self.length is None)
        value = self.control
        require(value['uid'] == expected_uid and value['helper'] == helper_sha and value['status'] != ERROR_STATUS)
        # systemd-run maps clean service signals to0 and other signals to255;
        # neither is an ordinary successful payload exit. Signals are outside
        # this provisioning contract, independently of any caller's allowed set.
        require(value['status'] >= 0 and native_status == value['status'])
        return value


def pipe_pair():
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        require(fcntl.fcntl(reader, fcntl.F_SETPIPE_SZ, CAPACITY) == CAPACITY and fcntl.fcntl(reader, fcntl.F_GETPIPE_SZ) == CAPACITY)
        return reader, writer
    except BaseException:
        os.close(reader); os.close(writer)
        raise


def privacy():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0)  # PR_SET/GET_DUMPABLE


def verify_process(expected_uid):
    require(os.getuid() == os.geteuid() == expected_uid)
    with open('/proc/self/attr/current') as stream:
        context = stream.read(193).rstrip('\x00\n')
    require(len(context) <= 192 and len(context.split(':')) >= 4 and context.split(':')[2] == 'unconfined_service_t')
    return 'unconfined_service_t'


def node_identity(value):
    import re
    require(type(value) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,19}):[1-9][0-9]{0,19}', value))
    device, inode = map(int, value.split(':'))
    require(device < 2**64 and 0 < inode < 2**64)
    return device, inode


def verify_fds(args):
    args.diagnostic_ready = False
    pairs = [args.stdout_node, args.stderr_node]
    profile_require(args.stdin_node is not None if args.stdin else args.stdin_node is None, 'FD0')
    if args.stdin:
        pairs.append(args.stdin_node)
    profile_require(len(pairs) == len(set(pairs)), 'FD1')
    for fd, expected in ((2, args.stderr_node), (1, args.stdout_node)):
        info = os.fstat(fd)
        profile_require((info.st_dev, info.st_ino) == expected and stat.S_ISFIFO(info.st_mode) and info.st_uid == 0 and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                        fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
                        fcntl.fcntl(fd, fcntl.F_GETPIPE_SZ) == CAPACITY, 'FD'+str(fd))
        if fd == 2:
            args.diagnostic_ready = True
    info = os.fstat(0)
    profile_require(fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY, 'FD0')
    if args.stdin:
        profile_require((info.st_dev, info.st_ino) == args.stdin_node and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= INPUT_LIMIT and
                        os.lseek(0, 0, os.SEEK_CUR) == 0, 'FD0')
    else:
        profile_require(stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3), 'FD0')


def check_deadline(end):
    require(type(end) in (int, float) and math.isfinite(end) and 0 < end - time.monotonic() <= 2280)


def pump(argv, data, maximum, end, control):
    require(data is None or isinstance(data, (bytes, bytearray)) and len(data) <= INPUT_LIMIT)
    require(maximum in MAXIMA and argv)
    check_deadline(end)
    pairs, process = [], None
    selector = selectors.DefaultSelector()
    queues = {'stdout': bytearray(), 'stderr': bytearray()}
    wire = bytearray()
    stderr_header = b''
    header_offset, wire_offset = 0, 0
    input_offset, total = 0, 0
    eof = {'stdout': False, 'stderr': False}
    try:
        for _ in range(3 if data is not None else 2):
            pairs.append(pipe_pair())
        out, err = pairs[:2]
        incoming = pairs[2] if data is not None else None
        for reader, writer in (out, err):
            os.set_blocking(reader, False)
        if incoming:
            os.set_blocking(incoming[1], False)
        os.set_blocking(1, False); os.set_blocking(2, False)
        check_deadline(end)
        process = subprocess.Popen(argv, stdin=incoming[0] if incoming else subprocess.DEVNULL,
                                   stdout=out[1], stderr=err[1], close_fds=True, start_new_session=True)
        for fd in (out[1], err[1], *( (incoming[0],) if incoming else () )):
            os.close(fd)
        owned = {out[0], err[0], *( (incoming[1],) if incoming else () )}
        # Closed ends are not cleaned twice if another allocation reuses an fd.
        pairs.clear()
        while True:
            require(time.monotonic() < end)
            if incoming and input_offset == len(data):
                os.close(incoming[1]); owned.remove(incoming[1]); incoming = None
            if eof['stderr'] and queues['stderr'] and not wire:
                wire.extend(queues['stderr']); queues['stderr'].clear()
            if len(queues['stderr']) == CAPACITY and not wire:
                wire.extend(queues['stderr']); queues['stderr'].clear()
            if wire and not stderr_header:
                stderr_header = HEADER.pack(b'D', MAGIC, len(wire))
                header_offset, wire_offset = 0, 0
            if all(eof.values()) and not queues['stdout'] and not queues['stderr'] and not wire and process.poll() is not None:
                break
            selector.close(); selector = selectors.DefaultSelector()
            if incoming:
                selector.register(incoming[1], selectors.EVENT_WRITE, 'stdin')
            if not eof['stdout'] and len(queues['stdout']) < CAPACITY:
                selector.register(out[0], selectors.EVENT_READ, 'stdout')
            if not eof['stderr'] and not wire and len(queues['stderr']) < CAPACITY:
                selector.register(err[0], selectors.EVENT_READ, 'stderr')
            if queues['stdout']:
                selector.register(1, selectors.EVENT_WRITE, 'out-write')
            if wire:
                selector.register(2, selectors.EVENT_WRITE, 'err-write')
            for key, _ in selector.select(min(.1, max(0, end - time.monotonic()))):
                kind, fd = key.data, key.fileobj
                try:
                    if kind == 'stdin':
                        input_offset += os.write(fd, data[input_offset:input_offset + CAPACITY])
                    elif kind == 'out-write':
                        count = os.write(fd, queues['stdout']); del queues['stdout'][:count]
                    elif kind == 'err-write':
                        if header_offset < 8:
                            header_offset += os.write(fd, stderr_header[header_offset:])
                        else:
                            wire_offset += os.write(fd, memoryview(wire)[wire_offset:])
                            if wire_offset == len(wire):
                                wire.clear(); stderr_header = b''
                    else:
                        limit = min(CAPACITY - len(queues[kind]), maximum - total + 1)
                        chunk = os.read(fd, limit)
                        if not chunk:
                            eof[kind] = True
                        else:
                            total += len(chunk); require(total <= maximum)
                            queues[kind].extend(chunk)
                except BlockingIOError:
                    continue
        status = process.wait(timeout=max(.001, end - time.monotonic()))
        message = json.dumps({**control, 'v': 1, 'done': True, 'status': status}, sort_keys=True, separators=(',', ':')).encode()
        require(len(message) <= 248)
        frame = HEADER.pack(b'C', MAGIC, len(message)) + message
        offset = 0
        while offset < len(frame):
            require(time.monotonic() < end)
            try:
                offset += os.write(2, frame[offset:])
            except BlockingIOError:
                time.sleep(.001)
        return status
    finally:
        selector.close()
        if process is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        for fd in locals().get('owned', set()):
            with contextlib.suppress(OSError):
                os.close(fd)
        for pair in pairs:
            for fd in pair:
                with contextlib.suppress(OSError):
                    os.close(fd)


UNIT_SCHEMA = (('Id','s'), ('Transient','b'), ('LoadState','s'), ('ActiveState','s'),
               ('FragmentPath','s'), ('SourcePath','s'), ('DropInPaths','as'))
SERVICE_SCHEMA = (('Type','s'), ('Restart','s'), ('MainPID','u'), ('ControlGroup','s'), ('Slice','s'),
                  ('User','s'), ('Group','s'), ('TimeoutStartUSec','t'), ('TimeoutStopUSec','t'), ('RuntimeMaxUSec','t'),
                  ('TimeoutStartFailureMode','s'), ('TimeoutStopFailureMode','s'), ('KillMode','s'), ('SendSIGKILL','b'),
                  ('FinalKillSignal','i'), ('LimitCORE','t'), ('MemoryMax','t'), ('TasksMax','t'), ('CPUQuotaPerSecUSec','t'),
                  ('StandardInput','s'), ('StandardOutput','s'), ('StandardError','s'), ('SELinuxContext','(bs)'),
                  ('RootDirectory','s'), ('RootImage','s'), ('PrivateUsers','b'), ('PrivateNetwork','b'), ('NoNewPrivileges','b'))
PROFILE_PROPERTIES = tuple(key for key, signature in UNIT_SCHEMA + SERVICE_SCHEMA)
PROFILE_KEYS = frozenset(PROFILE_PROPERTIES) | {'ProcUid', 'ProcGid', 'ProcCgroup', 'Query', 'Options', 'Deadline', 'FD0', 'FD1', 'FD2', 'GetUnit', 'UnitGet', 'ServiceGet'}


class ProfileError(ValueError):
    def __init__(self, key, value='unavailable'):
        self.key = key if key in PROFILE_KEYS else 'Query'
        safe = {'yes', 'no', 'kill', 'abort', 'terminate', 'exec', 'simple', 'active', 'activating', 'loaded', 'failed', 'control-group', 'mixed', 'process', 'infinity', 'unavailable', 'unexpected', 'unexpected-path', 'other-account', 'timeout', 'output-limit', 'malformed', 'exit-nonzero', 'missing', 'duplicate'}
        self.value = value if (type(value) is int and 0 <= value <= 10**12) or (type(value) is str and value in safe) else 'unexpected'
        super().__init__('native effective profile rejected')


def profile_require(condition, key, actual='unexpected'):
    if not condition:
        raise ProfileError(key, actual)


def typed_record(line, signature, key):
    try:
        require(len(line) <= 512)
        value = json.loads(line, object_pairs_hook=unique)
        require(type(value) is dict and set(value) == {'type', 'data'} and value['type'] == signature)
        data = value['data']
        if signature == 's':
            require(type(data) is str)
        elif signature == 'b':
            require(type(data) is bool)
        elif signature in ('u', 't', 'i'):
            low, high = {'u': (0, 2**32-1), 't': (0, 2**64-1), 'i': (-2**31, 2**31-1)}[signature]
            require(type(data) is int and low <= data <= high)
        elif signature == 'as':
            require(type(data) is list and len(data) == 1 and type(data[0]) is str)
        elif signature == '(bs)':
            require(type(data) is list and len(data) == 2 and type(data[0]) is bool and type(data[1]) is str)
        else:
            raise ValueError()
        return data
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ProfileError(key, 'malformed') from None


def property_records(raw, schema):
    lines = raw.splitlines()
    if len(lines) != len(schema):
        raise ProfileError('Query', 'missing' if len(lines) < len(schema) else 'unexpected')
    return {key: typed_record(line, signature, key) for line, (key, signature) in zip(lines, schema)}


def unit_object(raw):
    import re
    try:
        require(len(raw) <= 512)
        value = json.loads(raw, object_pairs_hook=unique)
        require(type(value) is dict and set(value) == {'type', 'data'} and value['type'] == 'o' and
                type(value['data']) is list and len(value['data']) == 1 and type(value['data'][0]) is str)
        path = value['data'][0]
        require(re.fullmatch(r'/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+', path) and len(path) <= 384)
        return path
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ProfileError('Query', 'malformed') from None


def query_process(argv, stop, used):
    pairs, process = [], None
    selected = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        if time.monotonic() >= stop:
            raise ProfileError('Query', 'timeout')
        for _ in range(2):
            pairs.append(pipe_pair())
        for reader, writer in pairs:
            os.set_blocking(reader, False)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=pairs[0][1], stderr=pairs[1][1],
                                   close_fds=True, start_new_session=True,
                                   env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/'})
        for index, (name, (reader, writer)) in enumerate(zip(('stdout', 'stderr'), pairs)):
            os.close(writer)
            pairs[index] = (reader, None)
            selected.register(reader, selectors.EVENT_READ, name)
        while selected.get_map() or process.poll() is None:
            if time.monotonic() >= stop:
                raise ProfileError('Query', 'timeout')
            for key, _ in selected.select(min(.1, max(0, stop - time.monotonic()))):
                chunk = os.read(key.fd, min(4096, 8192 - used[0] + 1))
                if not chunk:
                    selected.unregister(key.fd)
                else:
                    used[0] += len(chunk)
                    if used[0] > 8192:
                        raise ProfileError('Query', 'output-limit')
                    buffers[key.data].extend(chunk)
        status = process.wait(timeout=.1)
        if status != 0 or buffers['stderr']:
            raise ProfileError('Query', status if 0 < status <= 255 else 'exit-nonzero')
        return bytes(buffers['stdout'])
    finally:
        selected.close()
        if process is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
        for reader, writer in pairs:
            for fd in (reader, writer):
                if fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(fd)


def profile_query(unit, end):
    import re
    profile_require(type(unit) is str and re.fullmatch(r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}|ci-observe-[0-9a-f]{16})\.service', unit), 'Options')
    stop, used = min(end, time.monotonic()+QUERY_SECONDS), [0]
    base = ['/usr/bin/busctl', '--system', '--json=short', '--no-pager']
    stage = 'GetUnit'
    try:
        if time.monotonic() >= stop:
            raise ProfileError(stage, 'timeout')
        check_deadline(end)
        path = unit_object(query_process([*base, 'call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                                         'org.freedesktop.systemd1.Manager', 'GetUnit', 's', unit], stop, used))
        result = {}
        for interface, schema in (('Unit', UNIT_SCHEMA), ('Service', SERVICE_SCHEMA)):
            stage = interface+'Get'
            raw = query_process([*base, 'get-property', 'org.freedesktop.systemd1', path, 'org.freedesktop.systemd1.'+interface,
                                 *(key for key, signature in schema)], stop, used)
            result.update(property_records(raw, schema))
        if time.monotonic() >= stop:
            raise ProfileError('Query', 'timeout')
        return result
    except ProfileError as error:
        if error.key == 'Query':
            raise ProfileError(stage, error.value) from None
        raise
    except OSError:
        raise ProfileError(stage, 'unavailable') from None
    except (ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        raise ProfileError(stage, 'malformed') from None


def expected_profile(args):
    import re
    base = args.unit.removesuffix('.service')
    profile_require(re.fullmatch(r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}|ci-observe-[0-9a-f]{16})', base) and args.unit == base + '.service', 'Options')
    profile_require(args.key in (base, args.unit), 'Options')
    family = 'root' if base.startswith('dev-pair-initialize-') else ('maintenance' if base.startswith('dev-pair-gptbox-') else 'observation')
    profile_require(args.profile == family and (args.uid == 0 if family == 'root' else args.uid >= 1000), 'Options')
    profile_require(1000 <= args.start_us <= 5000000 and 1000 <= args.runtime_us <= 2280000000, 'Options')
    return {'Id': args.unit, 'Transient': True, 'LoadState': 'loaded', 'Type': 'exec', 'ActiveState': 'active',
            'MainPID': os.getpid(), 'ControlGroup': '/system.slice/' + args.unit,
            'DropInPaths': ['/run/systemd/system/' + args.unit + '.d/10-timeout-abort.conf'],
            'FragmentPath': '/run/systemd/transient/' + args.unit, 'SourcePath': '',
            'TimeoutStartUSec': args.start_us, 'RuntimeMaxUSec': args.runtime_us,
            'TimeoutStopUSec': {'root': 5000000, 'maintenance': 10000000, 'observation': 1000000}[family],
            'TimeoutStartFailureMode': 'kill', 'TimeoutStopFailureMode': 'kill', 'KillMode': 'control-group',
            'SendSIGKILL': True, 'FinalKillSignal': 9, 'Restart': 'no', 'LimitCORE': 0,
            'MemoryMax': 2147483648, 'TasksMax': 512, 'CPUQuotaPerSecUSec': 1000000, 'Slice': 'system.slice',
            'StandardInput': 'file' if args.stdin else 'null', 'StandardOutput': 'file', 'StandardError': 'file',
            'SELinuxContext': [False, ''], 'RootDirectory': '', 'RootImage': '', 'PrivateUsers': False, 'PrivateNetwork': False, 'NoNewPrivileges': False}


def verify_profile(args):
    expected = expected_profile(args)
    values = profile_query(args.unit, args.deadline)
    for key, value in expected.items():
        actual = values.get(key)
        profile_require(type(actual) is type(value) and actual == value, key, actual if type(actual) in (int, str) else 'unexpected')
    import pwd
    account = pwd.getpwuid(args.uid)
    user = ('', 'root') if args.profile == 'root' else ('dp-maint',)
    group = ('', 'root') if args.profile == 'root' else ('', 'dp-maint')
    profile_require(values.get('User') in user, 'User', 'other-account')
    profile_require(values.get('Group') in group, 'Group', 'other-account')
    with open('/proc/self/status') as source:
        status = source.read(65537)
    profile_require(len(status) <= 65536, 'ProcUid')
    for name, value, key in (('Uid', args.uid, 'ProcUid'), ('Gid', account.pw_gid, 'ProcGid')):
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith(name + ':')]
        profile_require(len(rows) == 1 and rows[0] == [str(value)] * 4, key)
    with open('/proc/self/cgroup') as source:
        cgroup = source.read(4097)
    profile_require(cgroup == '0::' + expected['ControlGroup'] + '\n', 'ProcCgroup')
    check_deadline(args.deadline)


def failure_frame(error, end):
    body = json.dumps({'v': 1, 'done': False, 'stage': 'effective-profile', 'reason': 'rejected',
                       'property': error.key, 'observed': error.value}, separators=(',', ':')).encode()
    require(len(body) <= 248)
    wire = HEADER.pack(b'F', MAGIC, len(body)) + body
    offset, stop = 0, min(end, time.monotonic() + .05)
    os.set_blocking(2, False)
    while offset < len(wire) and time.monotonic() < stop:
        try:
            offset += os.write(2, wire[offset:])
        except BlockingIOError:
            time.sleep(.001)

def main():
    try:
        privacy()  # Before any secret input is read or child is launched.
        class Parser(argparse.ArgumentParser):
            def error(self, message):
                raise ValueError('invalid relay arguments')
        parser = Parser(add_help=False, allow_abbrev=False)
        parser.add_argument('--unit', required=True)
        parser.add_argument('--key', required=True)
        parser.add_argument('--profile', choices=('root', 'maintenance', 'observation'), required=True)
        parser.add_argument('--start-us', type=int, required=True)
        parser.add_argument('--runtime-us', type=int, required=True)
        parser.add_argument('--stdout-node', type=node_identity, required=True)
        parser.add_argument('--stderr-node', type=node_identity, required=True)
        parser.add_argument('--stdin-node', type=node_identity)
        parser.add_argument('--uid', type=int, required=True)
        parser.add_argument('--stdin', type=int, choices=(0, 1), required=True)
        parser.add_argument('--maximum', type=int, choices=MAXIMA, required=True)
        parser.add_argument('--deadline', type=float, required=True)
        parser.add_argument('--helper', required=True)
        parser.add_argument('argv', nargs=argparse.REMAINDER)
        option_end = sys.argv.index('--') if '--' in sys.argv else len(sys.argv)
        options = [value.split('=', 1)[0] for value in sys.argv[1:option_end] if value.startswith('--')]
        require(len(options) == len(set(options)))
        args = parser.parse_args()
        require(args.argv and args.argv[0] == '--' and args.helper == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        check_deadline(args.deadline)
        domain = verify_process(args.uid)
        verify_fds(args)
        verify_profile(args)
        check_deadline(args.deadline)  # Before any secret byte is read.
        data = None
        if args.stdin:
            data = bytearray()
            while True:
                check_deadline(args.deadline)
                chunk = os.read(0, INPUT_LIMIT - len(data) + 1)
                if not chunk:
                    break
                require(len(data) + len(chunk) <= INPUT_LIMIT)
                data.extend(chunk)
        os.close(0)
        status = pump(args.argv[1:], data, args.maximum, args.deadline, {'uid': args.uid, 'domain': domain, 'helper': args.helper, 'p': 1})
        if status < 0:
            if -status not in (signal.SIGKILL, signal.SIGSTOP):
                signal.signal(-status, signal.SIG_DFL)
            os.kill(os.getpid(), -status)
            return ERROR_STATUS
        return status
    except ProfileError as error:
        if 'args' in locals() and getattr(args, 'diagnostic_ready', False):
            with contextlib.suppress(Exception):
                failure_frame(error, args.deadline)
        return ERROR_STATUS
    except BaseException:
        return ERROR_STATUS  # No exception/argv/environment/input/traceback export.


if __name__ == '__main__':
    raise SystemExit(main())
