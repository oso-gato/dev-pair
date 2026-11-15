"""Private manager-opened transient-service streams, with exact owned recovery."""
import contextlib
import fcntl
import json
import hashlib
import importlib.util
import pwd
import os
from pathlib import Path
import re
import stat

ROOT = Path('/run/dev-pair-command-io')
STREAM_ROOT = Path('/run/systemd/dev-pair-stdio')
RELAY_ROOT = Path('/usr/local/libexec/dev-pair-native-io')
EXPECTED_CONTEXT = 'system_u:object_r:init_var_run_t:s0'
_spec = importlib.util.spec_from_file_location('dev_pair_native_relay', Path(__file__).with_name('native_relay.py'))
relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay)

CAPACITY = 4096
INPUT_LIMIT = 16384
UNIT = r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}(?:\.service)?|ci-observe-[0-9a-f]{16}\.service)'


def require(value, text):
    if not value:
        raise ValueError(text)


def identity(path):
    info = path.lstat()
    require(info.st_uid == os.geteuid() and not stat.S_ISLNK(info.st_mode) and info.st_nlink >= 1, 'Transport ownership/type changed')
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode, 'uid': info.st_uid, 'links': info.st_nlink}


def guard_root():
    require(os.geteuid() == 0, 'Native transport controller requires root')
    for path in dict.fromkeys((*reversed(ROOT.parents), *reversed(STREAM_ROOT.parents))):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe transport ancestor')
    for path in (ROOT, ROOT / 'records', STREAM_ROOT):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe transport root')


def expected_uid(args):
    user = next((value[6:] for value in args if value.startswith('--uid=')), None)
    require(user in (None, 'root', 'dp-maint'), 'Unexpected native relay user')
    try:
        return pwd.getpwnam(user).pw_uid if user else 0
    except KeyError:
        raise ValueError('Native relay account unavailable') from None


def stage_relay():
    source = Path(__file__).with_name('native_relay.py')
    for path in (source, *source.parents):
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022, 'Unprotected relay source')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 65536, 'Invalid relay source')
        data = stream.read(65537)
        require(len(data) == info.st_size and len(data) <= 65536, 'Relay source changed')
    digest = hashlib.sha256(data).hexdigest()
    target = RELAY_ROOT / digest / 'relay.py'
    for path in reversed(target.parent.parents):
        if not path.exists():
            path.mkdir(mode=0o755)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unprotected relay artifact ancestor')
    try:
        target.parent.mkdir(mode=0o755)
    except FileExistsError:
        pass
    info = target.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unprotected relay artifact directory')
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o444)
    except FileExistsError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o444)
            output.write(data); output.flush(); os.fsync(output.fileno())
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o444 and info.st_nlink == 1 and info.st_size == len(data) and
                stream.read(65537) == data, 'Relay artifact collision preserved')
    return target, digest


def verify_labels(transport, control, timeout):
    for path in (STREAM_ROOT, transport.path, *(transport.path / name for name in transport.state['nodes'])):
        expected = control._call('/usr/sbin/matchpathcon', '-n', str(path), timeout=timeout, maximum=4096).strip()
        actual = os.getxattr(path, 'security.selinux', follow_symlinks=False).decode().rstrip('\x00\n')
        require(expected == actual == EXPECTED_CONTEXT, 'Native manager stream context mismatch')
    transport.verify()


def pipe_pair():
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        require(fcntl.fcntl(reader, fcntl.F_SETPIPE_SZ, CAPACITY) == CAPACITY and fcntl.fcntl(reader, fcntl.F_GETPIPE_SZ) == CAPACITY,
                'Declared launcher pipe capacity unavailable')
        os.set_blocking(reader, False)
        return reader, writer
    except BaseException:
        os.close(reader)
        os.close(writer)
        raise


class NativeTransport:
    def __init__(self, unit):
        require(re.fullmatch(UNIT, unit or ''), 'Unrecognized owned native transport unit')
        self.unit = unit
        self.path = STREAM_ROOT / unit
        self.record = ROOT / 'records' / (unit + '.json')
        self.state = {'version': 2, 'unit': unit, 'directory': None, 'nodes': {}, 'cleanup_started': False}
        self.readers, self.keepers = {}, []
        self.created_intent = False

    def save(self, first=False):
        data = (json.dumps(self.state, sort_keys=True) + '\n').encode()
        require(len(data) <= 4096, 'Transport metadata bound exceeded')
        target = self.record if first else self.record.with_suffix('.next')
        if not first:
            require(identity(self.record) == self.record_identity, 'Transport ownership record replaced')
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if not first:
            os.replace(target, self.record)
        self.record_identity = identity(self.record)
        directory = os.open(self.record.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def setup(self, stdin_data, register=None):
        require(stdin_data is None or len(stdin_data) <= INPUT_LIMIT, 'Native stdin byte budget exceeded')
        guard_root()
        require(not (ROOT / self.unit).exists() and not (ROOT / self.unit).is_symlink(), 'Legacy transport retained for explicit reconciliation')
        self.save(first=True)  # Intent precedes every allocation and any secret.
        self.created_intent = True
        if register is not None:
            register(self.unit)  # Exclusive intent won; collisions never enter another owner list.
        self.path.mkdir(mode=0o700)
        self.state['directory'] = identity(self.path)
        self.save()
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            require((info.st_dev, info.st_ino) == (self.state['directory']['device'], self.state['directory']['inode']), 'Transport directory fd mismatch')
            for name in ('stdout', 'stderr'):
                os.mkfifo(name, 0o600, dir_fd=directory)
                self.state['nodes'][name] = identity(self.path / name)
                self.save()
            if stdin_data is not None:
                path = self.path / 'stdin'
                fd = os.open('stdin', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                try:
                    self.state['nodes']['stdin'] = identity(path)
                    info = os.fstat(fd)
                    require((info.st_dev, info.st_ino) == (self.state['nodes']['stdin']['device'], self.state['nodes']['stdin']['inode']), 'Transport stdin fd mismatch')
                    self.save()  # Persist proof BEFORE writing even one input byte.
                    offset = 0
                    while offset < len(stdin_data):
                        offset += os.write(fd, stdin_data[offset:])
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)
        self.verify()

    def verify(self):
        if self.state['cleanup_started'] and not self.path.exists() and not self.path.is_symlink():
            return
        require(self.state['directory'] is not None and identity(self.path) == self.state['directory'] and
                stat.S_ISDIR(self.state['directory']['mode']) and stat.S_IMODE(self.state['directory']['mode']) == 0o700,
                'Transport directory identity changed or unproven')
        present = {p.name for p in self.path.iterdir()}
        require(present <= set(self.state['nodes']) and (self.state['cleanup_started'] or present == set(self.state['nodes'])), 'Unknown or unproven transport entry preserved')
        for name, expected in self.state['nodes'].items():
            if self.state['cleanup_started'] and name not in present:
                continue
            require(name in ('stdout', 'stderr', 'stdin') and identity(self.path / name) == expected and
                    stat.S_IMODE(expected['mode']) == 0o600 and expected['links'] == 1 and
                    (stat.S_ISREG(expected['mode']) if name == 'stdin' else stat.S_ISFIFO(expected['mode'])), 'Transport node identity changed')
            if name == 'stdin':
                require((self.path / name).lstat().st_size <= INPUT_LIMIT, 'Transport stdin size changed')

    def open_streams(self):
        self.verify()
        for name in ('stdout', 'stderr'):
            fd = os.open(self.path / name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.readers[name] = fd
            require(fcntl.fcntl(fd, fcntl.F_SETPIPE_SZ, CAPACITY) == CAPACITY and fcntl.fcntl(fd, fcntl.F_GETPIPE_SZ) == CAPACITY,
                    'Declared native FIFO capacity unavailable')
            self.keepers.append(os.open(self.path / name, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC))
        self.verify()

    def release(self):
        for fd in self.keepers:
            os.close(fd)
        self.keepers.clear()

    def close(self):
        self.release()
        for fd in self.readers.values():
            os.close(fd)
        self.readers.clear()

    def properties(self):
        return ('--property=StandardInput=' + ('file:' + str(self.path / 'stdin') if 'stdin' in self.state['nodes'] else 'null'),
                '--property=StandardOutput=file:' + str(self.path / 'stdout'), '--property=StandardError=file:' + str(self.path / 'stderr'))

    @classmethod
    def recover(cls, unit):
        # Caller must first prove this exact native unit inactive/not-found.
        transport = cls(unit)
        guard_root()
        require(not (ROOT / unit).exists() and not (ROOT / unit).is_symlink(), 'Legacy transport retained for explicit reconciliation')
        if not transport.record.exists() and not transport.record.is_symlink():
            require(not transport.path.exists() and not transport.path.is_symlink(), 'Unregistered transport retained')
            return
        recorded = identity(transport.record)
        require(stat.S_ISREG(recorded['mode']) and stat.S_IMODE(recorded['mode']) == 0o600 and recorded['links'] == 1,
                'Unsafe transport ownership record')
        fd = os.open(transport.record, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            require(info.st_size <= 4096 and (info.st_dev, info.st_ino) == (recorded['device'], recorded['inode']), 'Transport ownership record changed or too large')
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    require(key not in value, 'Duplicate transport ownership field')
                    value[key] = item
                return value
            state = json.loads(source.read(4097), object_pairs_hook=unique)
        require(identity(transport.record) == recorded, 'Transport ownership record replaced')
        require(type(state) is dict and set(state) == {'version', 'unit', 'directory', 'nodes', 'cleanup_started'} and type(state['version']) is int and state['version'] == 2 and state['unit'] == unit and
                type(state['cleanup_started']) is bool and type(state['nodes']) is dict and set(state['nodes']) <= {'stdout', 'stderr', 'stdin'} and
                (state['directory'] is not None or state['nodes'] == {}), 'Invalid transport ownership record')
        for entry in ([state['directory']] if state['directory'] is not None else []) + list(state['nodes'].values()):
            require(type(entry) is dict and set(entry) == {'device', 'inode', 'mode', 'uid', 'links'} and all(type(value) is int and value >= 0 for value in entry.values()), 'Invalid persisted transport identity')
        transport.state, transport.record_identity = state, recorded
        if state['directory'] is None:
            require(not transport.path.exists() and not transport.path.is_symlink(), 'Unproven transport directory retained')
        else:
            transport.verify()
            # Durable cleanup intent permits resuming only missing previously
            # proven objects; foreign replacements still fail verification.
            if not state['cleanup_started']:
                state['cleanup_started'] = True
                transport.save()
                recorded = transport.record_identity
            if transport.path.exists():
                for name in state['nodes']:
                    (transport.path / name).unlink(missing_ok=True)
                transport.path.rmdir()
        require(identity(transport.record) == recorded, 'Transport ownership record changed')
        transport.record.unlink()
