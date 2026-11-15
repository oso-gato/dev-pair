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
        self.partial = False
        self.frames = 0

    def feed(self, data):
        self.raw += len(data)
        require(self.raw <= self.maximum + overhead(self.maximum))
        output = []
        view = memoryview(data)
        while view:
            require(self.control is None)
            if self.length is None:
                count = min(8 - len(self.header), len(view))
                self.header.extend(view[:count]); view = view[count:]
                if len(self.header) < 8:
                    continue
                kind, magic, size = HEADER.unpack(self.header)
                require(magic == MAGIC and kind in (b'D', b'C') and 0 < size <= (4096 if kind == b'D' else 248))
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
                else:
                    value = json.loads(self.body, object_pairs_hook=unique)
                    require(type(value) is dict and set(value) == {'v', 'done', 'status', 'uid', 'domain', 'helper'} and
                            type(value['v']) is int and value['v'] == 1 and value['done'] is True and
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


def verify_fds(has_input):
    for fd in (1, 2):
        info = os.fstat(fd)
        require(stat.S_ISFIFO(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                fcntl.fcntl(fd, fcntl.F_GETPIPE_SZ) == CAPACITY)
    info = os.fstat(0)
    require((stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= INPUT_LIMIT)
            if has_input else (stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)))


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


def main():
    try:
        privacy()  # Before any secret input is read or child is launched.
        class Parser(argparse.ArgumentParser):
            def error(self, message):
                raise ValueError('invalid relay arguments')
        parser = Parser(add_help=False)
        parser.add_argument('--uid', type=int, required=True)
        parser.add_argument('--stdin', type=int, choices=(0, 1), required=True)
        parser.add_argument('--maximum', type=int, choices=MAXIMA, required=True)
        parser.add_argument('--deadline', type=float, required=True)
        parser.add_argument('--helper', required=True)
        parser.add_argument('argv', nargs=argparse.REMAINDER)
        args = parser.parse_args()
        require(args.argv and args.argv[0] == '--' and args.helper == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        check_deadline(args.deadline)
        domain = verify_process(args.uid)
        verify_fds(args.stdin == 1)
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
        status = pump(args.argv[1:], data, args.maximum, args.deadline, {'uid': args.uid, 'domain': domain, 'helper': args.helper})
        if status < 0:
            if -status not in (signal.SIGKILL, signal.SIGSTOP):
                signal.signal(-status, signal.SIG_DFL)
            os.kill(os.getpid(), -status)
            return ERROR_STATUS
        return status
    except BaseException:
        return ERROR_STATUS  # No exception/argv/environment/input/traceback export.


if __name__ == '__main__':
    raise SystemExit(main())
