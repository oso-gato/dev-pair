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
import time

ROOT = Path('/run/dev-pair-command-io')
STREAM_ROOT = Path('/run/systemd/dev-pair-stdio')
RELAY_ROOT = Path('/usr/local/libexec/dev-pair-native-io')
EXPECTED_CONTEXT = 'system_u:object_r:init_var_run_t:s0'
_spec = importlib.util.spec_from_file_location('dev_pair_native_relay', Path(__file__).with_name('native_relay.py'))
relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay)

CAPACITY = 4096
INPUT_LIMIT = 16384
UNIT = r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}|ci-observe-[0-9a-f]{16})(?:\.service)?'


def require(value, text):
    if not value:
        raise ValueError(text)


def exists_strict(path):
    try:
        Path(path).lstat()
        return True
    except FileNotFoundError:
        return False


def bounded_names(path, allowed, reason, end=None):
    require(end is None or time.monotonic() < end, 'Transport verification deadline exceeded')
    present = set()
    with os.scandir(path) as entries:
        for entry in entries:
            require(end is None or time.monotonic() < end, 'Transport verification deadline exceeded')
            # Do not retain an unknown name or consume the rest of its directory.
            require(entry.name in allowed and entry.name not in present, reason)
            present.add(entry.name)
    require(end is None or time.monotonic() < end, 'Transport verification deadline exceeded')
    return present


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
    streams = (STREAM_ROOT, transport.path, *(transport.path / name for name in transport.state['nodes']))
    paths = (*streams, transport.profile_path, transport.profile_path / MASK)
    contexts = control._call('/usr/sbin/matchpathcon', '-n', *(str(path) for path in paths), timeout=timeout, maximum=8192).splitlines()
    require(len(contexts) == len(paths), 'Native standard context evidence missing')
    for path, expected in zip(paths, contexts):
        actual = os.getxattr(path, 'security.selinux', follow_symlinks=False).decode().rstrip('\x00\n')
        require(expected and expected == actual and (path not in streams or actual == EXPECTED_CONTEXT), 'Native manager stream context mismatch')
    transport.verify()


PROFILE_ROOT = Path('/run/systemd/system')
MASK = '10-timeout-abort.conf'
PROFILE_ID = 'dev-pair-native-v1'
LOOKUP_PATHS = frozenset('/etc/systemd/system.control /run/systemd/system.control /run/systemd/transient /run/systemd/generator.early /etc/systemd/system /etc/systemd/system.attached /run/systemd/system /run/systemd/system.attached /run/systemd/generator /usr/local/lib/systemd/system /usr/lib/systemd/system /run/systemd/generator.late /lib/systemd/system'.split())


def canonical_unit(unit):
    base = unit.removesuffix('.service')
    require(re.fullmatch(r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}|ci-observe-[0-9a-f]{16})', base or ''), 'Invalid canonical native unit')
    return base + '.service'


def protected_directory(path):
    # Only the distribution's conventional /lib alias is accepted.
    path = Path(path)
    if str(path).startswith('/lib/'):
        require(Path('/lib').is_symlink() and Path('/lib').lstat().st_uid == os.geteuid() and Path('/lib').resolve() == Path('/usr/lib'), 'Unexpected distro alias')
        path = Path('/usr/lib') / path.relative_to('/lib')
    missing = False
    for part in reversed((path, *path.parents)):
        if missing:
            break
        try:
            info = part.lstat()
        except FileNotFoundError:
            missing = True
            continue
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'Unprotected manager lookup directory')
    return None if missing else path


def lookup_paths(control, timeout):
    text = control._call('/usr/bin/systemctl', 'show', '--property=UnitPath', timeout=timeout, maximum=8192)
    require(text.startswith('UnitPath=') and text.count('\n') <= 1, 'Manager UnitPath unavailable')
    values = text.strip().removeprefix('UnitPath=').split(' ')
    require(1 <= len(values) <= 24 and len(set(values)) == len(values) and all(value in LOOKUP_PATHS for value in values), 'Unknown manager UnitPath')
    require(str(PROFILE_ROOT) in values, 'Runtime lookup path unavailable')
    return tuple(values)


def configuration_snapshot(paths, unit, owned_mask=False, end=None):
    unit = canonical_unit(unit)
    stem = unit.removesuffix('.service')
    names = [unit] + [stem[:match.end()] + '.service' for match in re.finditer('-', stem)] + ['service']
    snapshot = []
    count, size = 0, 0
    for value in paths:
        require(end is None or time.monotonic() < end, 'Configuration admission deadline exceeded')
        path = protected_directory(value)
        if path is None:
            snapshot.append((value, None))
            continue
        info = path.lstat()
        snapshot.append((str(path), info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_mtime_ns // 1000))
        require(not exists_strict(path / unit), 'Existing native fragment or alias')
        for name in names:
            for suffix in ('.d', '.wants', '.requires', '.upholds'):
                require(end is None or time.monotonic() < end, 'Configuration admission deadline exceeded')
                directory = path / (name + suffix)
                if not exists_strict(directory):
                    continue
                require(protected_directory(directory) is not None, 'Unknown applicable configuration')
                before = directory.lstat()
                snapshot.append((str(directory), before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_mtime_ns // 1000))
                # Path.iterdir eagerly materializes directory contents on supported
                # CPython versions. Consume the kernel iterator under the bounds.
                with os.scandir(directory) as entries:
                    for entry in entries:
                        require(end is None or time.monotonic() < end, 'Configuration admission deadline exceeded')
                        count += 1; size += len(entry.name.encode())
                        require(count <= 256 and size <= 16384, 'Applicable configuration inventory bound exceeded')
                        require(suffix == '.d', 'Applicable dependency effects are forbidden')
                        path_entry = directory / entry.name
                        allowed = path_entry == Path('/usr/lib/systemd/system/service.d') / MASK or (owned_mask and path_entry == PROFILE_ROOT / (unit + '.d') / MASK)
                        require(allowed, 'Unknown applicable drop-in')
                        info = entry.stat(follow_symlinks=False)
                        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022 and info.st_nlink == 1 and info.st_size <= 4096,
                                'Unprotected applicable configuration')
                        if owned_mask and path_entry == PROFILE_ROOT / (unit + '.d') / MASK:
                            require(info.st_size == 0 and stat.S_IMODE(info.st_mode) == 0o644, 'Controlled mask changed')
                        snapshot.append((str(path_entry), info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns))
                require(end is None or time.monotonic() < end, 'Configuration admission deadline exceeded')
                require(directory.lstat() == before, 'Concurrent configuration mutation')
    return tuple(snapshot)


CGROUP_ROOT = Path('/sys/fs/cgroup/system.slice')


def verify_inactive_cgroup(unit):
    path = CGROUP_ROOT / canonical_unit(unit)
    if not exists_strict(path):
        return
    require(protected_directory(path) is not None, 'Owned cgroup path unverified')
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as source:
            require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'Owned cgroup events type invalid')
            data = source.read(1025)
        require(len(data) <= 1024, 'Owned cgroup evidence bound exceeded')
        rows = [line.split() for line in data.decode('ascii').splitlines()]
        require(rows and all(len(row) == 2 and row[0] in ('populated', 'frozen') and row[1] in ('0', '1') for row in rows) and
                len({row[0] for row in rows}) == len(rows) and dict(rows).get('populated') == '0', 'Owned cgroup remains populated or unavailable')
    finally:
        os.close(directory)


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
    def __init__(self, unit, deadline=None):
        self.deadline = deadline
        require(re.fullmatch(UNIT, unit or ''), 'Unrecognized owned native transport unit')
        self.unit = unit
        self.canonical = canonical_unit(unit)
        self.profile_path = PROFILE_ROOT / (self.canonical + '.d')
        self.path = STREAM_ROOT / unit
        self.record = ROOT / 'records' / (unit + '.json')
        self.state = {'version': 3, 'unit': unit, 'directory': None, 'nodes': {}, 'cleanup_started': False,
                      'profile': {'id': PROFILE_ID, 'directory': None, 'file': None, 'parent': None, 'before_us': None, 'after_us': None}}
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
        require(not exists_strict(self.record.with_suffix('.next')), 'Unproven journal update retained')
        self.save(first=True)  # Intent precedes every allocation and any secret.
        self.created_intent = True
        if register is not None:
            register(self.unit)  # Exclusive intent won; collisions never enter another owner list.
        self.create_profile()
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

    def create_profile(self):
        require(protected_directory(PROFILE_ROOT) is not None, 'Runtime configuration parent unavailable')
        before = PROFILE_ROOT.lstat()
        self.profile_path.mkdir(mode=0o755)  # Never adopt a preexisting directory.
        descriptor = os.open(self.profile_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            current = self.profile_path.lstat()
            require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), 'Profile creation descriptor mismatch')
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
        profile = self.state['profile']
        profile['directory'] = identity(self.profile_path)
        profile['parent'] = {key: value for key, value in identity(PROFILE_ROOT).items() if key != 'links'}
        profile['before_us'] = before.st_mtime_ns // 1000
        profile['after_us'] = PROFILE_ROOT.lstat().st_mtime_ns // 1000
        self.save()
        require(profile['after_us'] > profile['before_us'], 'Lookup directory timestamp did not advance')
        directory = os.open(self.profile_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(MASK, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644, dir_fd=directory)
            try:
                os.fchmod(fd, 0o644)
                profile['file'] = identity(self.profile_path / MASK)
                require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (profile['file']['device'], profile['file']['inode']), 'Mask descriptor mismatch')
                self.save()
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)

    def verify_profile(self):
        if self.state['version'] == 2:
            require(not exists_strict(self.profile_path), 'Unowned profile mask retained')
            return
        profile = self.state['profile']
        present = exists_strict(self.profile_path)
        if profile['directory'] is None:
            require(not present and profile['file'] is None, 'Unproven profile directory retained')
            return
        require({key: value for key, value in identity(PROFILE_ROOT).items() if key != 'links'} == profile['parent'], 'Profile parent changed')
        if not present and self.state['cleanup_started']:
            return
        require(present and identity(self.profile_path) == profile['directory'] and
                stat.S_ISDIR(profile['directory']['mode']) and stat.S_IMODE(profile['directory']['mode']) == 0o755, 'Profile directory changed')
        entries = bounded_names(self.profile_path, {MASK}, 'Foreign profile entry preserved', self.deadline)
        if profile['file'] is None:
            require(not entries, 'Unproven profile mask retained')
            return
        if not entries and self.state['cleanup_started']:
            return
        info = (self.profile_path / MASK).lstat()
        require(identity(self.profile_path / MASK) == profile['file'] and stat.S_ISREG(info.st_mode) and
                stat.S_IMODE(info.st_mode) == 0o644 and info.st_nlink == 1 and info.st_size == 0, 'Profile mask changed')

    def cleanup_profile(self):
        self.verify_profile()
        if self.state['version'] == 2 or not exists_strict(self.profile_path):
            return
        directory = os.open(self.profile_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            expected = self.state['profile']['directory']
            require((info.st_dev, info.st_ino) == (expected['device'], expected['inode']), 'Profile cleanup descriptor mismatch')
            if exists_strict(self.profile_path / MASK):
                current = os.stat(MASK, dir_fd=directory, follow_symlinks=False)
                expected = self.state['profile']['file']
                require(expected is not None and (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_nlink, current.st_size) ==
                        (expected['device'], expected['inode'], expected['mode'], expected['uid'], expected['links'], 0), 'Profile cleanup file changed')
                os.unlink(MASK, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
        self.profile_path.rmdir()

    def verify(self):
        self.verify_profile()
        if self.state['cleanup_started'] and not self.path.exists() and not self.path.is_symlink():
            return
        require(self.state['directory'] is not None and identity(self.path) == self.state['directory'] and
                stat.S_ISDIR(self.state['directory']['mode']) and stat.S_IMODE(self.state['directory']['mode']) == 0o700,
                'Transport directory identity changed or unproven')
        present = bounded_names(self.path, set(self.state['nodes']), 'Unknown or unproven transport entry preserved', self.deadline)
        require(self.state['cleanup_started'] or present == set(self.state['nodes']), 'Unknown or unproven transport entry preserved')
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
    def recover(cls, unit, deadline=None):
        # Caller must first prove this exact native unit inactive/not-found.
        transport = cls(unit, deadline=deadline)
        guard_root()
        require(not (ROOT / unit).exists() and not (ROOT / unit).is_symlink(), 'Legacy transport retained for explicit reconciliation')
        require(not exists_strict(transport.record.with_suffix('.next')), 'Unproven journal update retained')
        if not transport.record.exists() and not transport.record.is_symlink():
            require(not exists_strict(transport.profile_path), 'Unregistered profile retained')
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
        base = {'version', 'unit', 'directory', 'nodes', 'cleanup_started'}
        require(type(state) is dict and type(state.get('version')) is int and state['version'] in (2, 3) and
                set(state) == (base if state['version'] == 2 else base | {'profile'}) and state['unit'] == unit and
                type(state['cleanup_started']) is bool and type(state['nodes']) is dict and set(state['nodes']) <= {'stdout', 'stderr', 'stdin'} and
                (state['directory'] is not None or state['nodes'] == {}), 'Invalid transport ownership record')
        if state['version'] == 3:
            profile = state['profile']
            require(type(profile) is dict and set(profile) == {'id', 'directory', 'file', 'parent', 'before_us', 'after_us'} and profile['id'] == PROFILE_ID and
                    all(profile[key] is None or type(profile[key]) is int and profile[key] >= 0 for key in ('before_us', 'after_us')) and
                    ((profile['directory'] is None and all(profile[key] is None for key in ('file', 'parent', 'before_us', 'after_us'))) or
                     (profile['directory'] is not None and profile['parent'] is not None and type(profile['before_us']) is int and type(profile['after_us']) is int)), 'Invalid profile journal')
            for key in ('directory', 'file', 'parent'):
                entry = profile[key]
                require(entry is None or type(entry) is dict and set(entry) == ({'device', 'inode', 'mode', 'uid'} if key == 'parent' else {'device', 'inode', 'mode', 'uid', 'links'}) and
                        all(type(value) is int and value >= 0 for value in entry.values()), 'Invalid profile identity')
        for entry in ([state['directory']] if state['directory'] is not None else []) + list(state['nodes'].values()):
            require(type(entry) is dict and set(entry) == {'device', 'inode', 'mode', 'uid', 'links'} and all(type(value) is int and value >= 0 for value in entry.values()), 'Invalid persisted transport identity')
        transport.state, transport.record_identity = state, recorded
        transport.verify_profile()
        if state['directory'] is None:
            require(not exists_strict(transport.path), 'Unproven transport directory retained')
        else:
            transport.verify()
        if not state['cleanup_started']:
            state['cleanup_started'] = True
            transport.save()
            recorded = transport.record_identity
        if state['directory'] is None:
            require(not transport.path.exists() and not transport.path.is_symlink(), 'Unproven transport directory retained')
        else:
            transport.verify()
            if transport.path.exists():
                for name in state['nodes']:
                    (transport.path / name).unlink(missing_ok=True)
                transport.path.rmdir()
        transport.cleanup_profile()
        require(identity(transport.record) == recorded, 'Transport ownership record changed')
        transport.record.unlink()
