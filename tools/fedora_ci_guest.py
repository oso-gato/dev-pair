#!/usr/bin/env python3
"""Secret-free Fedora VM initialization probe, launched by authenticated public payload."""
import argparse
import contextlib
import array
import fcntl
import hashlib
import importlib.util
import shlex
import json
import math
import os
import pathlib
import platform
import pwd
import re
import secrets
import tempfile
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import termios
import tty

SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
REPORT_LIMIT = 65536
REPORT_VERSION = 5
GUEST_PHASES = ('fedora-preflight', 'guest-inputs', 'bootstrap-inspect', 'bootstrap-status',
                'bootstrap-prepare', 'maintenance-gptbox', 'bootstrap-post-inspect', 'bootstrap-post-status')
INPUT_LENGTHS = {'controller_sha256': 64, 'source_sha': 40, 'helper_sha256': 64, 'fedora_helper_sha256': 64, 'manifest_sha256': 64, 'payload_sha256': 64,
                 'context_sha256': 64, 'distrobox_sha': 40, 'standards_sha': 40,
                 'codex_sha256': 64, 'codex_source_sha': 40}
GUEST_ADMISSION_SECONDS = 60
INITIALIZE_SECONDS = 2280
INITIALIZE_CLEANUP_SECONDS = 45
GUEST_FINAL_SECONDS = 60
PAYLOAD_PATH = pathlib.Path('/run/dev-pair-payload')
INPUT_DESTINATION = pathlib.Path('/root/dev-pair-ci-inputs')
SECRET_DIRECTORY = pathlib.Path('/run/dev-pair-ci-secrets')
SERVICE_NAME = 'dev-pair-ci-provision.service'
SERVICE_SCRIPT = pathlib.Path('/usr/local/libexec/dev-pair-ci/guest.py')
SERVICE_UNIT = pathlib.Path('/etc/systemd/system') / SERVICE_NAME
SERVICE_REQUEST = pathlib.Path('/var/lib/dev-pair/ci-executor/request.json')
SERVICE_MASK = SERVICE_UNIT.parent / (SERVICE_NAME + '.d') / '10-timeout-abort.conf'
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
SERVICE_SECONDS = GUEST_ADMISSION_SECONDS + INITIALIZE_SECONDS + INITIALIZE_CLEANUP_SECONDS + GUEST_FINAL_SECONDS
SERVICE_STOP_SECONDS = 5
STATE_ROOT = pathlib.Path('/var/lib/dev-pair/bootstrap')
INITIALIZATION_KEYS = set(('source_sha context_sha256 distrobox_sha exit_status phase prepare maintenance_gptbox cleanup '
                           'prepared_image_id assembled_image_id boundary_and_version_cycles runtime_container_removed job_admission '
                           'prepared_image_verified assembled_image_verified packages_sha256 package_count').split())
REPORT_BEGIN = b'DP_FEDORA_REPORT_V1\n'
REPORT_END = b'\nDP_FEDORA_REPORT_END\n'
REPORT_FRAME_LIMIT = REPORT_LIMIT + len(REPORT_BEGIN) + len(REPORT_END)
REPORT_WRITE_SECONDS = 30


def service_unit(expected, guest_sha):
    validate_inputs(expected)
    require(re.fullmatch('[0-9a-f]{64}', guest_sha), 'Invalid staged guest identity')
    argv = ['/usr/bin/env', '-i', 'PATH=' + SAFE_ENV['PATH'], 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
            '/usr/bin/python3', '-I', str(SERVICE_SCRIPT), '--native-service', '--source', expected['source_sha'],
            '--inputs-json', json.dumps(expected, sort_keys=True), '--guest-sha256', guest_sha]
    # Values are fixed paths/public hashes and validated integers. systemd's own
    # quoting parser receives argv directly; no shell or manifest hash cycle.
    command = ' '.join('"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"' for value in argv)
    return ('[Unit]\nDescription=Dev-pair disposable CI provisioning\nAfter=network-online.target\n'
            '[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\n'
            'StandardInput=null\nStandardOutput=null\nStandardError=null\n'
            'RuntimeMaxSec=' + str(SERVICE_SECONDS) + 's\nTimeoutStartSec=10s\nTimeoutStopSec=' + str(SERVICE_STOP_SECONDS) + 's\n'
            'KillMode=control-group\nTimeoutStopFailureMode=kill\nSendSIGKILL=yes\nFinalKillSignal=SIGKILL\nRestart=no\nExecStart=' + command + '\n')


def observed_context(value):
    # procfs includes a terminating NUL on the measured Fedora executor.
    value = value.rstrip('\x00\n')
    require(len(value) <= 200 and re.fullmatch(r'[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:s[0-9]+(?::c[0-9]+(?:\.c[0-9]+)?(?:,c[0-9]+(?:\.c[0-9]+)?)*)?(?:-s[0-9]+(?::c[0-9]+(?:\.c[0-9]+)?(?:,c[0-9]+(?:\.c[0-9]+)?)*)?)?', value),
            'Malformed observed SELinux context')
    return value


def executor_profile():
    return {'Type': 'exec', 'User': 'root', 'Group': 'root', 'StandardInput': 'null', 'StandardOutput': 'null',
            'StandardError': 'null', 'KillMode': 'control-group', 'Restart': 'no', 'DropInPaths': str(SERVICE_MASK),
            'TimeoutStopFailureMode': 'kill', 'SendSIGKILL': 'yes', 'FinalKillSignal': '9',
            'SELinuxContext': '', 'RootDirectory': '', 'RootImage': '',
            'RuntimeMaxUSec': SERVICE_SECONDS, 'TimeoutStopUSec': SERVICE_STOP_SECONDS}


def duration_seconds(value):
    units = {'us': .000001, 'ms': .001, 's': 1, 'min': 60, 'h': 3600, 'd': 86400}
    parts = list(re.finditer(r'([0-9]+(?:\.[0-9]+)?)\s*(us|ms|min|s|h|d)', value))
    require(parts and not re.sub(r'([0-9]+(?:\.[0-9]+)?)\s*(us|ms|min|s|h|d)', '', value).strip(), 'Unsupported native duration evidence')
    return sum(float(match[1]) * units[match[2]] for match in parts)


def executor_profile_hash():
    return hashlib.sha256(json.dumps(executor_profile(), sort_keys=True).encode()).hexdigest()


def verify_executor_profile(observed):
    for key, value in executor_profile().items():
        actual = observed.get(key)
        if key in ('RuntimeMaxUSec', 'TimeoutStopUSec'):
            require(type(actual) is str and duration_seconds(actual) == value, 'Native effective runtime/stop bound mismatch')
        else:
            require(actual == value, 'Unexpected native fragment/drop-in/effective configuration')
    return executor_profile_hash()


def executor_file(path, data, mode):
    path = pathlib.Path(path)
    require(path.is_absolute(), 'Executor file path must be absolute')
    for position, parent in enumerate(reversed(path.parents)):
        if not parent.exists():
            parent.mkdir(mode=0o755)
        info = parent.lstat()
        if not (stat.S_ISDIR(info.st_mode) and not parent.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022):
            raise ExecutorPathError(position, info)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read_mask_file(path):
    # Open nonblocking/no-follow; reject devices before reading the same inode.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644 and info.st_size == 0 and info.st_nlink == 1,
                'Owned service mask must be an empty regular0644 file')
        require(os.read(fd, 1) == b'', 'Owned service mask content changed')
        final = pathlib.Path(path).lstat()
        require((final.st_dev, final.st_ino, final.st_mode, final.st_uid, final.st_gid, final.st_size, final.st_nlink) ==
                (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_nlink), 'Owned service mask path identity changed')
        return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino, 'sha256': EMPTY_SHA256}, info.st_uid
    finally:
        os.close(fd)


def validate_mask_record(value):
    require(type(value) is dict and set(value) == {'path', 'device', 'inode', 'sha256'} and value['path'] == str(SERVICE_MASK) and
            value['sha256'] == EMPTY_SHA256 and type(value['device']) is int and value['device'] >= 0 and
            type(value['inode']) is int and value['inode'] > 0, 'Invalid owned service mask identity')
    return value


def mask_identity():
    for parent in (SERVICE_MASK, *SERVICE_MASK.parents):
        info = parent.lstat()
        require(not parent.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022, 'Owned mask path ownership/protection changed')
    identity, owner = read_mask_file(SERVICE_MASK)
    require(owner == 0, 'Owned mask file must be root-owned')
    return validate_mask_record(identity)


def executor_control(argv, end):
    # Measured TCG daemon-reload exceeded5s. Only this exact fixed operation
    # gets30s; every allocation remains clipped to the original admission end.
    maximum_seconds = 30 if argv == ['/usr/bin/systemctl', 'daemon-reload'] else 5
    # Only these pre-credential fixed public operations may retain stderr. It
    # goes to an owned size-limited regular file, never a forwarded stream pipe.
    public = argv in (
        ['/usr/sbin/restorecon', '-F', str(SERVICE_SCRIPT.parent), str(SERVICE_SCRIPT), str(SERVICE_REQUEST.parent), str(SERVICE_REQUEST), str(SERVICE_UNIT), str(SERVICE_MASK.parent), str(SERVICE_MASK)],
        ['/usr/bin/systemctl', 'daemon-reload'], ['/usr/bin/systemctl', '--no-block', 'start', SERVICE_NAME])
    with contextlib.ExitStack() as stack:
        stderr = subprocess.DEVNULL
        limit = None
        if public:
            info = SERVICE_REQUEST.parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and not SERVICE_REQUEST.parent.is_symlink() and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                    'Unsafe executor diagnostic directory')
            stderr = stack.enter_context(tempfile.TemporaryFile(dir=SERVICE_REQUEST.parent))
            require(stat.S_ISREG(os.fstat(stderr.fileno()).st_mode) and stat.S_IMODE(os.fstat(stderr.fileno()).st_mode) == 0o600, 'Unsafe executor diagnostic file')
            def limit():
                resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
        def diagnostic():
            if not public:
                return None
            stderr.seek(0)
            data = stderr.read(4097)
            require(len(data) <= 4096, 'Executor diagnostic file bound exceeded')
            return {'captured_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'capture_limit_reached': len(data) == 4096, 'tail': safe_text(data, 768), 'tail_truncated': len(data) > 768}
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
                                    env=SAFE_ENV, close_fds=True, start_new_session=True, preexec_fn=limit, timeout=remaining(end, maximum_seconds))
        except subprocess.TimeoutExpired as error:
            error.public_diagnostic = diagnostic()
            raise
        if result.returncode != 0:
            raise ExecutorControlError(result.returncode, diagnostic())


STAGING_OPERATIONS = ('root-identity', 'script-snapshot', 'source-identity', 'render-unit', 'launcher-context',
                      'install-script', 'install-request', 'install-unit', 'install-mask', 'verify-mask', 'restore-contexts', 'reload-manager',
                      'start-service', 'observe-startup')
STARTUP_MARKER = b'DP_NATIVE_START_BLOCKED '


class ExecutorControlError(ValueError):
    def __init__(self, status, diagnostic=None):
        super().__init__('Fixed executor control operation rejected')
        self.status = status
        self.public_diagnostic = diagnostic


class ExecutorPathError(ValueError):
    def __init__(self, position, info):
        super().__init__('Executor path must be root-owned and protected')
        self.metadata = {'position': position, **path_metadata(info)}


def path_metadata(info):
    return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'type': stat.S_IFMT(info.st_mode), 'bytes': info.st_size}


class ExecutorStagingError(ValueError):
    def __init__(self, operation, error, started):
        super().__init__('Fixed staging operation rejected: ' + operation)
        self.fields = {'step': operation, 'kind': 'validation', 'errno': None, 'exit_status': None,
                       'elapsed_ms': min(60000, max(0, int((time.monotonic() - started) * 1000))),
                       'uid': os.getuid(), 'euid': os.geteuid()}
        self.startup = error.fields if isinstance(error, ExecutorStartupError) else {'availability': 'unavailable'}
        if isinstance(error, ExecutorControlError):
            self.fields.update(kind='control-exit', exit_status=error.status)
        elif isinstance(error, subprocess.TimeoutExpired):
            self.fields['kind'] = 'timeout'
        elif isinstance(error, OSError):
            self.fields.update(kind='os-error', errno=error.errno)
        elif isinstance(error, ExecutorStartupError):
            self.fields.update(kind='startup-observation', exit_status=error.query_exit_status)
        if isinstance(error, ExecutorPathError):
            self.fields['path_metadata'] = error.metadata
        if getattr(error, 'public_diagnostic', None) is not None:
            self.fields['control_diagnostic'] = error.public_diagnostic


def stage_executor(expected, guest_sha):
    started = time.monotonic()
    end = started + GUEST_ADMISSION_SECONDS
    operation = 'root-identity'
    try:
        require(os.getuid() == os.geteuid() == 0, 'Native provisioning staging requires root')
        operation = 'script-snapshot'
        script = read_bytes(pathlib.Path(__file__), 1024 ** 2)
        operation = 'source-identity'
        require(hashlib.sha256(script).hexdigest() == guest_sha, 'Staging script differs from controller target')
        operation = 'render-unit'
        unit = service_unit(expected, guest_sha).encode()
        operation = 'launcher-context'
        context = observed_context(pathlib.Path('/proc/self/attr/current').read_text())
        request = {'version': 2, 'source_sha': expected['source_sha'], 'inputs': expected, 'guest_sha256': guest_sha,
                   'unit_sha256': hashlib.sha256(unit).hexdigest(), 'launcher_context': context, 'admission_deadline': end}
        operation = 'install-script'
        executor_file(SERVICE_SCRIPT, script, 0o444)
        operation = 'install-mask'
        executor_file(SERVICE_MASK, b'', 0o644)
        operation = 'verify-mask'
        request['mask'] = mask_identity()
        operation = 'install-request'
        executor_file(SERVICE_REQUEST, json.dumps(request, sort_keys=True).encode() + b'\n', 0o600)
        operation = 'install-unit'
        executor_file(SERVICE_UNIT, unit, 0o644)
        operation = 'restore-contexts'
        executor_control(['/usr/sbin/restorecon', '-F', str(SERVICE_SCRIPT.parent), str(SERVICE_SCRIPT),
                          str(SERVICE_REQUEST.parent), str(SERVICE_REQUEST), str(SERVICE_UNIT), str(SERVICE_MASK.parent), str(SERVICE_MASK)], end)
        operation = 'reload-manager'
        executor_control(['/usr/bin/systemctl', 'daemon-reload'], end)
        operation = 'start-service'
        executor_control(['/usr/bin/systemctl', '--no-block', 'start', SERVICE_NAME], end)
        operation = 'observe-startup'
        observe_executor_start(end)
        return request
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise ExecutorStagingError(operation, error, started) from None


class ExecutorStartupError(ValueError):
    def __init__(self, fields, query_exit_status=None):
        super().__init__('Native startup observation failed')
        self.fields = fields
        self.query_exit_status = query_exit_status


def startup_properties():
    return tuple(dict.fromkeys(('MainPID', 'User', 'ActiveState', 'LoadState', 'Result', 'ExecMainCode',
                               'ExecMainStatus', 'FragmentPath', *executor_profile())))


def startup_property_limit(key, value):
    if (key == 'DropInPaths' and value == str(SERVICE_MASK)) or (key == 'FragmentPath' and value == str(SERVICE_UNIT)):
        return len(value)  # Exact known public paths stay lossless.
    if key in ('Type', 'User', 'Group', 'StandardInput', 'StandardOutput', 'StandardError', 'Restart',
               'TimeoutStopFailureMode', 'SendSIGKILL', 'FinalKillSignal', 'ExecMainCode', 'ExecMainStatus'):
        return 16
    if key in ('MainPID', 'ActiveState', 'LoadState', 'KillMode'):
        return 24
    if key in ('Result', 'RuntimeMaxUSec', 'TimeoutStopUSec'):
        return 32
    return 64


def startup_property_value(key, value):
    return safe_text(value, startup_property_limit(key, value))


def observe_executor_start(end):
    # A plain selected-property query forwards no stream FDs over D-Bus.
    # Its stdout goes to an owned bounded regular file, not a cloud-init pipe.
    stop = min(end, time.monotonic() + 5)
    properties = startup_properties()
    observed = {}
    query_exit_status = None
    while time.monotonic() < stop:
        parent = SERVICE_REQUEST.parent
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not parent.is_symlink() and info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'Unsafe executor observation directory')
        with tempfile.TemporaryFile(dir=parent) as output:
            require(stat.S_ISREG(os.fstat(output.fileno()).st_mode) and stat.S_IMODE(os.fstat(output.fileno()).st_mode) == 0o600, 'Unsafe executor observation file')
            def file_limit():
                resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
            result = subprocess.run(['/usr/bin/systemctl', 'show', *('--property=' + key for key in properties), SERVICE_NAME],
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, env=SAFE_ENV,
                                    close_fds=True, start_new_session=True, preexec_fn=file_limit, timeout=remaining(stop, 2))
            output.seek(0)
            data = output.read(4097)
            require(len(data) <= 4096, 'Native startup property byte limit exceeded')
        query_exit_status = result.returncode
        observed = dict(line.split('=', 1) for line in data.decode('utf-8').splitlines() if '=' in line)
        if result.returncode == 0 and observed.get('ActiveState') == 'active':
            if (observed.get('User') == 'root' and observed.get('FragmentPath') == str(SERVICE_UNIT) and
                    observed.get('MainPID', '').isdigit() and int(observed['MainPID']) > 1):
                try:
                    verify_executor_profile(observed)
                    return observed
                except ValueError:
                    break
            break
        if observed.get('ActiveState') == 'failed' or observed.get('LoadState') in ('error', 'bad-setting', 'not-found'):
            break
        time.sleep(min(.05, max(0, stop - time.monotonic())))
    raise ExecutorStartupError({key: startup_property_value(key, observed.get(key, 'unavailable')) for key in properties}, query_exit_status)


def validate_startup_witness(value, expected, guest_sha):
    # This is failure evidence only. It supplies no native process or phase pass.
    keys = {'version', 'operation', 'outcome', 'source_sha', 'controller_sha256', 'guest_sha256',
            'requested_unit_sha256', 'startup_properties', 'staging'}
    require(type(value) is dict and set(value) == keys and type(value['version']) is int and value['version'] == 1 and
            value['operation'] == 'native-executor-staging' and value['outcome'] == 'blocked', 'Invalid startup witness envelope')
    require(value['source_sha'] == expected['source_sha'] and value['controller_sha256'] == expected['controller_sha256'] and
            value['guest_sha256'] == guest_sha and value['requested_unit_sha256'] == hashlib.sha256(service_unit(expected, guest_sha).encode()).hexdigest(),
            'Startup witness target mismatch')
    metadata = value['staging']
    required = {'step', 'kind', 'errno', 'exit_status', 'elapsed_ms', 'uid', 'euid'}
    require(type(metadata) is dict and required <= set(metadata) <= required | {'path_metadata', 'control_diagnostic'} and
            metadata['step'] in STAGING_OPERATIONS and metadata['kind'] in ('validation', 'control-exit', 'timeout', 'os-error', 'startup-observation', 'unavailable') and
            type(metadata['elapsed_ms']) is int and 0 <= metadata['elapsed_ms'] <= 60000 and
            all(type(metadata[key]) is int and 0 <= metadata[key] < 2 ** 32 for key in ('uid', 'euid')) and
            (metadata['errno'] is None or type(metadata['errno']) is int and 0 <= metadata['errno'] < 65536) and
            (metadata['exit_status'] is None or type(metadata['exit_status']) is int and -128 <= metadata['exit_status'] <= 255), 'Invalid fixed staging metadata')
    if 'path_metadata' in metadata:
        path = metadata['path_metadata']
        require(type(path) is dict and set(path) == {'position', 'uid', 'gid', 'mode', 'type', 'bytes'} and
                all(type(item) is int and 0 <= item < 2 ** 63 for item in path.values()) and path['position'] < 16 and
                path['mode'] <= 0o7777 and path['type'] in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK),
                'Invalid selected path metadata')
    if 'control_diagnostic' in metadata:
        diagnostic = metadata['control_diagnostic']
        require(type(diagnostic) is dict and set(diagnostic) == {'captured_bytes', 'sha256', 'capture_limit_reached', 'tail', 'tail_truncated'} and
                type(diagnostic['captured_bytes']) is int and 0 <= diagnostic['captured_bytes'] <= 4096 and
                type(diagnostic['sha256']) is str and re.fullmatch('[0-9a-f]{64}', diagnostic['sha256']) and
                type(diagnostic['capture_limit_reached']) is bool and type(diagnostic['tail_truncated']) is bool and
                type(diagnostic['tail']) is str and len(diagnostic['tail']) <= 768 and
                metadata['step'] in ('restore-contexts', 'reload-manager', 'start-service') and metadata['kind'] in ('control-exit', 'timeout') and
                value['startup_properties'] == {'availability': 'unavailable'}, 'Invalid fixed public control diagnostic')
    properties = value['startup_properties']
    require(type(properties) is dict and (properties == {'availability': 'unavailable'} or
            set(properties) == set(startup_properties()) and all(type(item) is str and len(item) <= startup_property_limit(key, item) and all(32 <= ord(c) < 127 for c in item) for key, item in properties.items())),
            'Invalid selected startup properties')
    return value


def write_startup_failure(witness):
    # A failure-only console witness is never a native result or console salvage.
    # Missing dedicated report still fails controller admission.
    data = STARTUP_MARKER + json.dumps(witness, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
    require(len(data) <= 4096, 'Startup witness byte limit exceeded')
    fd = os.open('/dev/ttyS0', os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode), 'Startup diagnostics require the guest console')
        offset = 0
        stop = time.monotonic() + 1
        while offset < len(data):
            require(time.monotonic() < stop, 'Startup diagnostic deadline exceeded')
            try:
                offset += os.write(fd, data[offset:])
            except BlockingIOError:
                time.sleep(.01)
    finally:
        os.close(fd)
    executor_control(['/usr/bin/systemctl', 'poweroff', '--no-block'], time.monotonic() + 2)


def verify_executor_target(request, expected, guest_sha, script, unit):
    require(type(request) is dict and set(request) == {'version', 'source_sha', 'inputs', 'guest_sha256', 'unit_sha256', 'launcher_context', 'admission_deadline', 'mask'} and
            type(request['version']) is int and request['version'] == 2 and request['source_sha'] == expected['source_sha'] and
            request['inputs'] == expected and request['guest_sha256'] == guest_sha, 'Staged executor target mismatch')
    validate_mask_record(request['mask'])
    unit_sha = hashlib.sha256(service_unit(expected, guest_sha).encode()).hexdigest()
    require(hashlib.sha256(script).hexdigest() == guest_sha and unit == service_unit(expected, guest_sha).encode() and hashlib.sha256(unit).hexdigest() == request['unit_sha256'] == unit_sha,
            'Actual script/unit differ from controller-bound target')
    require(type(request['admission_deadline']) in (int, float) and time.monotonic() < request['admission_deadline'] <= time.monotonic() + GUEST_ADMISSION_SECONDS,
            'Staged executor admission budget exhausted or invalid')
    return unit_sha


def native_executor_identity(expected, guest_sha):
    require(os.getuid() == os.geteuid() == 0, 'Native provisioning executor must be real/effective root')
    for path, mode in ((SERVICE_SCRIPT, 0o444), (SERVICE_REQUEST, 0o600), (SERVICE_UNIT, 0o644)):
        for parent in (path, *path.parents):
            info = parent.lstat()
            require(not parent.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022, 'Executor path ownership/protection changed')
        require(stat.S_ISREG(path.lstat().st_mode) and stat.S_IMODE(path.stat().st_mode) == mode, 'Executor file mode/type changed')
    request = read_json(SERVICE_REQUEST, 65536)
    require(digest(pathlib.Path(__file__)) == guest_sha, 'Executing service script differs from controller target')
    unit_sha = verify_executor_target(request, expected, guest_sha, read_bytes(SERVICE_SCRIPT, 1024 ** 2), read_bytes(SERVICE_UNIT, 16384))
    require(mask_identity() == request['mask'], 'Actual owned mask differs from staged identity')
    fields = command(['/usr/bin/systemctl', 'show', '--property=MainPID', '--property=ActiveState', '--property=FragmentPath', *('--property=' + key for key in executor_profile()), SERVICE_NAME], timeout=remaining(request['admission_deadline'], 5)).decode()
    observed = dict(line.split('=', 1) for line in fields.splitlines() if '=' in line)
    configuration_sha = verify_executor_profile(observed)
    cgroup = pathlib.Path('/proc/self/cgroup').read_text().strip()
    context = observed_context(pathlib.Path('/proc/self/attr/current').read_text())
    require(observed.get('MainPID') == str(os.getpid()) and observed.get('User') == 'root' and observed.get('ActiveState') == 'active' and
            observed.get('FragmentPath') == str(SERVICE_UNIT) and cgroup == '0::/system.slice/' + SERVICE_NAME and
            context and ':cloud_init_t:' not in context, 'Actual native provisioning executor identity mismatch')
    return {'kind': 'native-systemd-service', 'source_sha': expected['source_sha'], 'controller_sha256': expected['controller_sha256'],
            'unit': SERVICE_NAME, 'mask': request['mask'], 'unit_sha256': unit_sha, 'configuration_sha256': configuration_sha, 'script_sha256': guest_sha, 'uid': os.getuid(), 'euid': os.geteuid(),
            'main_pid': os.getpid(), 'manager_main_pid': int(observed['MainPID']), 'cgroup': cgroup, 'context': context,
            'launcher_context': safe_text(request['launcher_context'], 200), 'admission_deadline': request['admission_deadline']}


def validate_executor(value, expected, guest_sha):
    keys = {'kind', 'source_sha', 'controller_sha256', 'unit', 'unit_sha256', 'script_sha256', 'uid', 'euid',
            'main_pid', 'manager_main_pid', 'cgroup', 'context', 'launcher_context', 'admission_deadline', 'configuration_sha256', 'mask'}
    require(type(value) is dict and set(value) == keys, 'Missing/unknown native executor evidence')
    validate_mask_record(value['mask'])
    require(value['kind'] == 'native-systemd-service' and value['source_sha'] == expected['source_sha'] and
            value['controller_sha256'] == expected['controller_sha256'] and value['unit'] == SERVICE_NAME and
            value['unit_sha256'] == hashlib.sha256(service_unit(expected, guest_sha).encode()).hexdigest() and value['script_sha256'] == guest_sha and value['configuration_sha256'] == executor_profile_hash(),
            'Native executor source/controller/unit identity mismatch')
    require(type(value['uid']) is type(value['euid']) is int and value['uid'] == value['euid'] == 0 and
            type(value['main_pid']) is int and value['main_pid'] > 1 and type(value['manager_main_pid']) is int and
            value['main_pid'] == value['manager_main_pid'] and value['cgroup'] == '0::/system.slice/' + SERVICE_NAME and
            type(value['context']) is str and observed_context(value['context']) == value['context'] and ':cloud_init_t:' not in value['context'], 'Native executor actual process identity mismatch')
    require(type(value['launcher_context']) is str and len(value['launcher_context']) <= 200 and type(value['admission_deadline']) in (int, float), 'Invalid executor staging evidence')
    return value


def encode_report(report):
    data = json.dumps(report, sort_keys=True, ensure_ascii=True).encode()
    require(0 < len(data) <= REPORT_LIMIT, 'Guest report JSON exceeds byte limit')
    return REPORT_BEGIN + data + REPORT_END


def write_report(report, path='/dev/ttyS1', timeout=REPORT_WRITE_SECONDS):
    """Write one raw, drained frame directly; never use cloud-init stdout."""
    def expired(signum, frame):
        raise ValueError('Dedicated guest report deadline exceeded')
    old_handler = signal.signal(signal.SIGALRM, expired)
    old_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    started = time.monotonic()
    fd = None
    selector = selectors.DefaultSelector()
    try:
        data = encode_report(report)
        fd = os.open(path, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW)
        require(stat.S_ISCHR(os.fstat(fd).st_mode), 'Dedicated report output must be a terminal device')
        tty.setraw(fd, termios.TCSANOW)
        attributes = termios.tcgetattr(fd)
        attributes[2] |= termios.CLOCAL | termios.CREAD
        attributes[2] &= ~getattr(termios, 'CRTSCTS', 0)
        attributes[4] = attributes[5] = termios.B115200
        termios.tcsetattr(fd, termios.TCSANOW, attributes)
        selector.register(fd, selectors.EVENT_WRITE)
        offset = 0
        while offset < len(data):
            require(time.monotonic() - started < timeout, 'Dedicated guest report deadline exceeded')
            if not selector.select(timeout=min(.1, max(0, timeout - (time.monotonic() - started)))):
                continue
            try:
                offset += os.write(fd, data[offset:])
            except (BlockingIOError, InterruptedError):
                continue
        # Bound native tcdrain as well: an ignored CTS or stuck driver must not
        # indefinitely delay shutdown. Explicit raw115200 preserves CR/LF bytes.
        queued = array.array('i', [0])
        while True:
            fcntl.ioctl(fd, termios.TIOCOUTQ, queued, True)
            if queued[0] == 0:
                break
            require(time.monotonic() - started < timeout, 'Dedicated guest report drain deadline exceeded')
            time.sleep(.01)
        termios.tcdrain(fd)
    finally:
        selector.close()
        if fd is not None:
            os.close(fd)
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        if old_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, old_timer[0] - (time.monotonic() - started)), old_timer[1])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 ** 2), b''):
            value.update(chunk)
    return value.hexdigest()


def safe_text(value, limit=4000):
    text = value.decode('utf-8', 'replace') if isinstance(value, bytes) else str(value)
    text = ''.join(c if c in '\n\t' or 32 <= ord(c) < 127 else '?' for c in text)
    marker = '[truncated] '
    return marker + text[-(limit - len(marker)):] if len(text) > limit else text


def validate_inputs(value):
    require(type(value) is dict and set(value) == set(INPUT_LENGTHS) | {'payload_bytes'}, 'invalid public input identity fields')
    for key, length in INPUT_LENGTHS.items():
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{%d}' % length, value[key]), 'invalid public input identity')
    require(type(value['payload_bytes']) is int and 0 < value['payload_bytes'] <= 192 * 1024 ** 2, 'invalid public payload size')
    return value


def validate_initialization(value, expected):
    new=type(value) is dict and value.get('state_schema')==2
    require(type(value) is dict and set(value)==(INITIALIZATION_KEYS|{'state_schema','host_prerequisites','candidate_image'} if new else INITIALIZATION_KEYS),'invalid initialization evidence fields')
    if new:
        require(type(value['state_schema']) is int and all(value[k] in ('pending','complete','blocked') for k in ('host_prerequisites','candidate_image')) and
            (value['prepare']!='complete' or value['host_prerequisites']==value['candidate_image']=='complete') and
            (value['candidate_image']!='complete' or value['prepare']==value['host_prerequisites']=='complete'),'invalid host/image completion state')
    require(value['source_sha'] == expected['source_sha'] and value['context_sha256'] == expected['context_sha256'] and
            value['distrobox_sha'] == expected['distrobox_sha'], 'initialization evidence target mismatch')
    require(value['exit_status'] is None or type(value['exit_status']) is int, 'invalid initializer exit status')
    require(value['phase'] in ('prepare', 'maintenance-gptbox', 'complete') and
            all(value[key] in ('pending', 'complete', 'blocked') for key in ('prepare', 'maintenance_gptbox')),
            'invalid initialization phase evidence')
    require(value['maintenance_gptbox'] != 'complete' or value['prepare'] == 'complete', 'assembly without prerequisite phase')
    require(value['phase'] != 'complete' or value['prepare'] == value['maintenance_gptbox'] == 'complete', 'inconsistent complete phase')
    require(type(value['cleanup']) is str and len(value['cleanup']) <= 200 and value['job_admission'] is False,
            'invalid initialization cleanup/admission evidence')
    for key in ('prepared_image_id', 'assembled_image_id', 'packages_sha256'):
        require(value[key] is None or type(value[key]) is str and re.fullmatch('[0-9a-f]{64}', value[key]), 'invalid image evidence identity')
    require(type(value['package_count']) is int and 0 <= value['package_count'] <= 1000, 'invalid package evidence count')
    require(type(value['boundary_and_version_cycles']) is int and value['boundary_and_version_cycles'] in (0, 2), 'invalid probe count')
    require(all(type(value[key]) is bool for key in ('runtime_container_removed', 'prepared_image_verified', 'assembled_image_verified')),
            'invalid image verification evidence')
    return value


def unique_object(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON field')
        value[key] = item
    return value


def read_bytes(path, maximum=262144):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'nonregular or excessive evidence input')
        data = stream.read(maximum + 1)
        require(len(data) == info.st_size and len(data) <= maximum, 'evidence size changed')
    return data


def read_json(path, maximum=262144, expected_sha=None):
    data = read_bytes(path, maximum)
    if expected_sha is not None:
        require(hashlib.sha256(data).hexdigest() == expected_sha, 'Evidence snapshot digest mismatch')
    return json.loads(data, object_pairs_hook=unique_object)


def remaining(end, maximum):
    value = min(maximum, end - time.monotonic())
    require(value > 0, 'Guest phase execution budget exhausted')
    return value


def command(argv, timeout=30, **kwargs):
    code, output = capture(argv, timeout, **kwargs)
    require(code == 0, 'Command exit ' + str(code) + ': ' + safe_text(output))
    return output


class CaptureOverflow(ValueError):
    def __init__(self, output):
        super().__init__('Guest diagnostic command exceeded byte limit (truncated)')
        self.output = output


def capture(argv, timeout=15, maximum=65536, tick=None):
    started = time.monotonic()
    process = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    complete = False
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=SAFE_ENV, start_new_session=True)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            require(time.monotonic() - started < timeout, 'Guest diagnostic command deadline exceeded')
            if tick:
                tick()
            for key, _ in selector.select(timeout=min(.1, max(0, timeout - (time.monotonic() - started)))):
                data = os.read(key.fileobj.fileno(), min(4096, maximum - len(output) + 1))
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(data) > maximum:
                    output.extend(data[:maximum - len(output)])
                    raise CaptureOverflow(bytes(output))
                output.extend(data)
        code = process.wait(timeout=1)
        require(time.monotonic() - started < timeout, 'Guest diagnostic command deadline exceeded')
        complete = True
        return code, bytes(output)
    finally:
        if process is not None and not complete:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)
        selector.close()
        if process is not None:
            process.stdout.close()


def stage_source(payload, destination, archive_sha, bundle_sha):
    require(digest(payload / 'source.tar') == archive_sha and digest(payload / 'source.bundle') == bundle_sha,
            'Public payload bytes do not match controller handoff')
    require(not destination.exists(), 'Protected source staging must be new')
    destination.mkdir(mode=0o700)
    # Bundle is retained for the later real Git-based candidate verifier. No
    # runner config or .git/config is supplied. This first baseline does not
    # install Git or claim guest Git-object verification when Git is absent.
    shutil.copyfile(payload / 'source.bundle', destination / 'source.bundle')
    source = destination / 'source'
    source.mkdir(mode=0o700)
    with tarfile.open(payload / 'source.tar', 'r:') as archive:
        members = archive.getmembers()
        require(sum(member.size for member in members) <= 32 * 1024 ** 2, 'Source archive exceeds bound')
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and
                    (member.isdir() or member.isfile()), 'Non-regular/unsafe source archive member denied')
        for member in members:
            target = source / member.name
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                require(not target.exists(), 'Duplicate source archive entry denied')
                with open(target, 'xb') as stream:
                    shutil.copyfileobj(archive.extractfile(member), stream)
                target.chmod(0o400)
    return source


def root_filesystem():
    try:
        with open('/proc/self/mountinfo', 'rb') as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'Mount metadata bound exceeded')
        data = raw.decode()
        matches = []
        for line in data.splitlines():
            before, separator, after = line.partition(' - ')
            fields, filesystem = before.split(), after.split()
            if separator and len(fields) >= 6 and fields[4] == '/' and len(filesystem) >= 3:
                require(re.fullmatch('[A-Za-z0-9_.-]{1,32}', filesystem[0]), 'Invalid filesystem type')
                options = set(fields[5].split(',')) | set(filesystem[2].split(','))
                matches.append({'type': filesystem[0], 'quota_flags': sorted(options & {'usrquota', 'grpquota', 'prjquota', 'pquota', 'uquota', 'gquota'})})
        require(len(matches) == 1, 'Ambiguous root filesystem')
        return matches[0]
    except (OSError, ValueError, UnicodeError):
        return {'availability': 'unavailable'}


def baseline(end=None):
    release = pathlib.Path('/etc/os-release').read_text()
    require('ID=fedora' in release and 'VERSION_ID=44' in release, 'Guest is not Fedora 44')
    require(platform.machine() == 'x86_64', 'Unexpected guest architecture')
    require(os.geteuid() == 0 and pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd',
            'Guest must boot real systemd as PID 1 with a root console executor')
    selinux = command(['/usr/sbin/getenforce'], timeout=remaining(end, 30) if end is not None else 30).decode().strip()
    require(selinux == 'Enforcing', 'Stock image SELinux is not Enforcing; transition matrix is outside this probe')
    require(pathlib.Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'Unified cgroup v2 unavailable')
    policy = pathlib.Path('/sys/fs/selinux/policy')
    require(policy.is_file(), 'Active SELinux policy unavailable')
    return {'os': 'Fedora 44', 'kernel': platform.release(), 'architecture': platform.machine(),
            'pid1': 'systemd', 'selinux': selinux, 'cgroup': 'v2',
            'root_free_bytes': shutil.disk_usage('/').free, 'root_filesystem': root_filesystem(),
            'executor_context': pathlib.Path('/proc/self/attr/current').read_text().strip(),
            'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


AUDIT_TYPES = {'AVC': 'AVC', '1400': 'AVC', 'USER_AVC': 'USER_AVC', '1107': 'USER_AVC'}
AUDIT_COMMS = {'podman', 'crun', 'conmon', 'distrobox-init', 'python3', 'dnf', 'dnf5', 'systemd-run', 'systemctl', 'systemd', 'dbus-broker', 'polkitd', 'sshd', 'getenforce', 'chpasswd'}
AUDIT_DOMAINS = {'cloud_init_t', 'system_dbusd_t', 'init_t', 'unconfined_service_t', 'container_t', 'sshd_t', 'setfiles_t', 'dnf_t'}
AUDIT_CONTEXT = re.compile(r'[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:s[0-9]+(?::c[0-9]+(?:\.c[0-9]+)?(?:,c[0-9]+(?:\.c[0-9]+)?)*)?(?:-s[0-9]+(?::c[0-9]+(?:\.c[0-9]+)?(?:,c[0-9]+(?:\.c[0-9]+)?)*)?)?')
AUDIT_SYMBOL = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,31}')


def audit_require(value):
    if not value:
        raise ValueError('malformed audit security fields')


def audit_fields(tokens):
    result = {}
    for token in tokens:
        if '=' not in token:
            continue
        key, value = token.split('=', 1)
        audit_require(key not in result)
        result[key] = value
    return result


def audit_record(line):
    audit_require(len(line.encode()) <= 4096)
    header = re.fullmatch(r'type=(AVC|USER_AVC|1400|1107)\s+msg=audit\(([0-9]{1,12}(?:\.[0-9]{1,9})?:[0-9]{1,12})\):\s*(.*)', line)
    audit_require(header)
    kind, event, body = header.groups()
    outer = shlex.split(body, posix=True)
    selected = audit_fields(outer)
    if AUDIT_TYPES[kind] == 'USER_AVC':
        audit_require('msg' in selected)
        # Only the structural nested msg field is parsed. Quoted path/name/
        # proctitle data is never rescanned for embedded fake security tokens.
        payload = selected.pop('msg')
        tokens = shlex.split(payload, posix=True)
    else:
        tokens = outer
    audit_require(tokens[:3] == ['avc:', 'denied', '{'] and '}' in tokens)
    end = tokens.index('}')
    permissions = tokens[3:end]
    audit_require(0 < len(permissions) <= 8 and len(set(permissions)) == len(permissions) and all(AUDIT_SYMBOL.fullmatch(p) for p in permissions))
    nested = audit_fields(tokens[end + 1:])
    if AUDIT_TYPES[kind] == 'USER_AVC':
        audit_require(not (set(selected) & set(nested)))
        selected.update(nested)
    else:
        selected = nested
    result = {'type': AUDIT_TYPES[kind], 'audit_event_id': event, 'permissions': permissions}
    for key in ('scontext', 'tcontext'):
        value = selected.get(key)
        audit_require(type(value) is str and len(value) <= 192 and AUDIT_CONTEXT.fullmatch(value))
        result[key] = value
    audit_require(type(selected.get('tclass')) is str and AUDIT_SYMBOL.fullmatch(selected['tclass']))
    result['tclass'] = selected['tclass']
    if 'pid' in selected:
        audit_require(re.fullmatch('[0-9]{1,10}', selected['pid']))
        result['pid'] = int(selected['pid'])
    if 'permissive' in selected:
        audit_require(selected['permissive'] in ('0', '1'))
        result['permissive'] = int(selected['permissive'])
    if selected.get('comm') in AUDIT_COMMS:
        result['comm'] = selected['comm']
    return result


def project_avcs(raw, *, truncated=False, available=True):
    seen, malformed, candidates = 0, 0, []
    for line in raw.decode('utf-8', 'replace').splitlines():
        if not re.match(r'^type=(?:AVC|USER_AVC|1400|1107)(?:\s|$)', line):
            continue
        seen += 1
        try:
            candidates.append(audit_record(line))
        except (ValueError, TypeError):
            malformed += 1
    def relevant(row):
        return row.get('comm') in AUDIT_COMMS or any(row[key].split(':')[2] in AUDIT_DOMAINS for key in ('scontext', 'tcontext'))
    ordered = [row for row in reversed(candidates) if relevant(row)] + [row for row in reversed(candidates) if not relevant(row)]
    output = []
    for row in ordered:
        if len(output) < 8 and len(json.dumps(output + [row], sort_keys=True, ensure_ascii=True).encode()) <= 3000:
            output.append(row)
    return {'records': output, 'typed_seen': seen, 'projected': len(output), 'malformed': malformed,
            'omitted_for_cap': len(candidates) - len(output), 'input_truncated': bool(truncated), 'unavailable': not available,
            'selection_scope': 'same boot; latest known comm/domain first; counts cover captured input only'}


def diagnostics(end=None):
    observed = {}
    for name, argv in (
            ('listener_inventory', ['/usr/bin/ss', '-H', '-lntup']),
            ('service_health', ['/usr/bin/systemctl', 'show', '--property=ActiveState', '--property=Result', 'systemd-resolved.service', 'tailscaled.service', 'sshd.service', 'chronyd.service']),
            ('selinux_avcs', ['/usr/sbin/ausearch', '-m', 'AVC,USER_AVC', '-ts', 'boot', '--raw']),
            ('rpm_baseline', ['/usr/bin/rpm', '-q', 'kernel-core', 'selinux-policy-targeted', 'systemd', 'cloud-init', 'podman'])):
        try:
            code, output = capture(argv, timeout=remaining(end, 1) if end is not None else 15)
            if name == 'selinux_avcs':
                observed[name] = {'exit_status': code, **project_avcs(output, available=code in (0, 1))}
            else:
                observed[name] = {'exit_status': code, 'tail': safe_text(output, 3000), 'captured_bytes': len(output)}
        except CaptureOverflow as exc:
            observed[name] = {'status': 'incomplete', **project_avcs(exc.output, truncated=True)} if name == 'selinux_avcs' else {'status': 'unavailable', 'detail': 'Diagnostic capture limit exceeded'}
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            observed[name] = {'status': 'unavailable', 'detail': safe_text(exc, 500)}
    return observed



def admit_inputs(payload, expected, destination, timeout=GUEST_ADMISSION_SECONDS):
    require(digest(payload / 'public_inputs.py') == expected['helper_sha256'], 'Public extractor implementation identity mismatch')
    require(digest(payload / 'fedora_oci.py') == expected['fedora_helper_sha256'], 'Fedora input verifier implementation identity mismatch')
    result = json.loads(command(['/usr/bin/python3', str(payload / 'public_inputs.py'), 'extract',
                         '--manifest', str(payload / 'manifest.json'), '--payload', str(payload / 'maintenance-inputs.tar.gz'),
                         '--expected-manifest-sha256', expected['manifest_sha256'], '--output', str(destination)],
                         timeout=timeout), object_pairs_hook=unique_object)
    require(result['source_sha'] == expected['source_sha'] and result['context_sha256'] == expected['context_sha256'],
            'Extracted source/context differs from controller target')
    manifest = read_json(payload / 'manifest.json', expected_sha=expected['manifest_sha256'])
    require(manifest['payload'] == {'sha256': expected['payload_sha256'], 'bytes': expected['payload_bytes']} and
            manifest['source_sha'] == expected['source_sha'] and manifest['context_sha256'] == expected['context_sha256'] and
            manifest['distrobox_sha'] == expected['distrobox_sha'] and manifest['standards_sha'] == expected['standards_sha'],
            'Authenticated input identities do not match controller handoff')
    receipt = read_json(destination / 'evidence/verification-receipt.json')
    require(receipt['helper_source_sha'] == expected['source_sha'] and receipt['exit_status'] == 0 and receipt['result'] == 'Verified OK' and
            receipt['codex_binary_sha256'] == expected['codex_sha256'] and receipt['codex_source_sha'] == expected['codex_source_sha'],
            'Original strict verification receipt mismatch')
    require(digest(destination / 'evidence/cosign-verification.txt') == receipt['verification_output_sha256'],
            'Original verification evidence mismatch')
    return destination / 'dev-pair'


@contextlib.contextmanager
def make_password(directory):
    directory.mkdir(mode=0o700)
    require(directory.stat().st_uid == os.geteuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Guest secret directory is not executor-private')
    path = directory / 'core-password'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(secrets.token_urlsafe(48) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        yield path
    finally:
        # Also covers write/fsync failure before a pathname is returned to main.
        path.unlink(missing_ok=True)


def remove_password_after_prepare(secret, state_root, expected):
    path = state_root / 'initialize.json'
    if secret.exists() and path.exists():
        state = read_json(path)
        target = {'source_sha': expected['source_sha'], 'context_sha256': expected['context_sha256'],
                  'distrobox_sha': expected['distrobox_sha'], 'bootstrap_sources': ['192.0.2.9/32']}
        if state.get('target') == target and state.get('prepare') == 'complete':
            secret.unlink()


def initialize_projection(state, expected, exit_status):
    target = {'source_sha': expected['source_sha'], 'context_sha256': expected['context_sha256'],
              'distrobox_sha': expected['distrobox_sha'], 'bootstrap_sources': ['192.0.2.9/32']}
    require(type(state) is dict and state.get('target') == target and state.get('job_admission') is False,
            'Initialization record target/admission mismatch')
    require(state.get('phase') in ('prepare', 'maintenance-gptbox', 'complete') and
            all(state.get(key) in ('pending', 'complete', 'blocked') for key in ('prepare', 'maintenance_gptbox')),
            'Invalid initialization phase record')
    result = {'source_sha': expected['source_sha'], 'context_sha256': expected['context_sha256'],
              'distrobox_sha': expected['distrobox_sha'], 'exit_status': exit_status,
              'phase': state['phase'], 'prepare': state['prepare'], 'maintenance_gptbox': state['maintenance_gptbox'],
              'cleanup': safe_text(state.get('cleanup', 'not recorded'), 200),
              'prepared_image_id': None, 'assembled_image_id': None, 'boundary_and_version_cycles': 0,
              'runtime_container_removed': False, 'job_admission': False,
              'prepared_image_verified': False, 'assembled_image_verified': False, 'packages_sha256': None, 'package_count': 0}
    schema=state.get('schema',1)
    require(type(schema) is int and schema in (1,2),'Unsupported initialization schema')
    if schema==2:
        require(state.get('prepare_budget_scope')=='host-prerequisites' and type(state.get('adapter_commenced')) is bool,'Invalid host phase scope')
        result.update(state_schema=2,host_prerequisites=state.get('host_prerequisites'),candidate_image=state.get('candidate_image'))
    if state['maintenance_gptbox'] == 'complete':
        observed = state.get('result', {})
        require(observed.get('source_sha') == expected['source_sha'] and observed.get('context_sha256') == expected['context_sha256'] and
                observed.get('distrobox_sha') == expected['distrobox_sha'] and observed.get('boundary_and_version_cycles') == 2 and
                observed.get('runtime_container_removed') is True and observed.get('job_admission') is False,
                'Completed initialization result identity/evidence mismatch')
        result.update(assembled_image_id=observed['assembled_image_id'], boundary_and_version_cycles=2, runtime_container_removed=True)
    return validate_initialization(result, expected)


def native_image_capture(source, argv, timeout):
    # The protected exact public source was already authenticated on admission.
    spec = importlib.util.spec_from_file_location('dev_pair_observe_bootstrap', source / 'tools/bootstrap.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        run = module.Commands()
        metadata = {}
        run.metadata_diagnostic = metadata.update
        with run.phase(timeout, 'dev-pair-ci-observe', native=False):
            return run._call(*argv, timeout=timeout, maximum=262144).encode()
    except module.Blocked:
        detail = 'stage=' + str(metadata.get('admission_stage', 'unavailable')) + ' reason=' + str(metadata.get('admission_reason', 'unavailable'))
        failure = metadata.get('relay_failure')
        if failure is not None:
            detail += ' property=' + failure['property'] + ' observed=' + str(failure['observed'])
        raise ValueError('Native image observation blocked; ' + detail) from None


def storage_observer(source):
    spec=importlib.util.spec_from_file_location('dev_pair_public_storage_observation',source/'tools/storage_observation.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def storage_public_projection(state_root,expected,source):
    result={stage:{'status':'unavailable','reason':'not-recorded'} for stage in ('prepared-image','assembled-postcleanup')}
    if source is None:return result
    try:
        observer=storage_observer(source)
        prepared=read_json(state_root/'gptbox-image.json',16384)
        require(type(prepared) is dict and prepared['source_sha']==expected['source_sha'] and prepared['context_sha256']==expected['context_sha256'],
                'Storage prepared identity mismatch')
        if prepared.get('kind')=='full-adapter-candidate':validate_full_candidate(prepared,expected,source)
        elif prepared.get('kind') not in (None,'host-maintenance-gptbox-oci-candidate'):raise ValueError('Unknown prepared recipe kind')
        require(type(prepared['image_id']) is str, 'Storage image identity missing')
        image=prepared['image_id'].removeprefix('sha256:')
        require(re.fullmatch('[0-9a-f]{64}',image), 'Storage image identity missing')
    except (OSError,ValueError,KeyError,TypeError):return result
    for stage in result:
        try:
            sealed=None
            if stage=='prepared-image':path=state_root/'storage-prepared.json'
            else:
                target=state_root/'gptbox-adapter'/expected['context_sha256']
                completed=read_json(target/'result.json',16384)
                require(completed['source_sha']==expected['source_sha'] and completed['context_sha256']==expected['context_sha256'] and
                        completed['runtime_container_removed'] is True and completed['job_admission'] is False,
                        'Storage cleanup not verified')
                sealed=completed['assembled_image_id'];path=target/'storage-assembled-postcleanup.json'
            result[stage]=observer.validate(read_json(path,16384),stage,expected['source_sha'],expected['context_sha256'],image,sealed)
        except (OSError,ValueError,KeyError,TypeError):pass
    return result


def validate_full_candidate(record,expected,source):
    keys=set('schema kind source_sha context_sha256 standards_sha base_image codex_sha256 distrobox_sha init_sha256 runtime_sha256 inputs_sha256 recipe_sha256 platform distrobox_assembled runtime_validated image_id fedora_base'.split())
    require(type(record) is dict and set(record)==keys and type(record['schema']) is int and record['schema']==1 and
        record['kind']=='full-adapter-candidate' and record['source_sha']==expected['source_sha'] and record['context_sha256']==expected['context_sha256'] and
        record['standards_sha']==expected['standards_sha'] and record['codex_sha256']==expected['codex_sha256'] and record['distrobox_sha']==expected['distrobox_sha'] and
        record['platform']=={'os':'linux','architecture':'amd64'} and record['distrobox_assembled'] is False and record['runtime_validated'] is False and
        all(type(record[k]) is str and re.fullmatch('[0-9a-f]{64}',record[k]) for k in ('image_id','init_sha256','runtime_sha256','inputs_sha256','recipe_sha256')) and
        record['runtime_sha256']==digest(source/'tools/gptbox_runtime.py'),'Full candidate completion mismatch')
    spec=importlib.util.spec_from_file_location('public_full_candidate_oci',source/'tools/fedora_oci.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    require(record['base_image']==module.IMAGE,'Full candidate signed base mismatch');module.validate_import_proof(record['fedora_base'])
    return record


def image_evidence(expected, projection, state_root, source, end, logical_observations=None):
    images = []
    if projection['prepare'] == 'complete':
        desired = read_json(state_root / 'prepared')
        record = read_json(state_root / 'gptbox-image.json')
        require(desired['gptbox_context_sha256'] == expected['context_sha256'] and desired['standards_sha'] == expected['standards_sha'] and
                record['source_sha'] == expected['source_sha'] and record['context_sha256'] == expected['context_sha256'] and
                record['codex_sha256'] == expected['codex_sha256'] and desired['bootstrap_sha256'] == digest(source / 'tools/bootstrap.py'), 'Prepared image evidence does not match target')
        if projection.get('state_schema')==2:validate_full_candidate(record,expected,source)
        packages = read_bytes(state_root / 'packages.txt', 32768)
        lines = packages.decode('utf-8').splitlines()
        require(0 < len(lines) <= 1000 and all(any(line.startswith(name + '-') for line in lines) for name in ('podman', 'distrobox', 'tailscale')),
                'Actual prerequisite package evidence missing')
        projection.update(packages_sha256=hashlib.sha256(packages).hexdigest(), package_count=len(lines))
        projection['prepared_image_id'] = record['image_id'].removeprefix('sha256:')
        images.append(projection['prepared_image_id'])
    if projection['assembled_image_id'] is not None:
        images.append(projection['assembled_image_id'])
    require(images and all(re.fullmatch('[0-9a-f]{64}', value) for value in images), 'Invalid immutable image evidence')
    uid = pwd.getpwnam('dp-maint').pw_uid
    require(uid >= 1000, 'Invalid maintenance executor UID')
    unit = 'dev-pair-ci-observe-' + expected['context_sha256'][:16] + '.service'
    timeout = remaining(end, 10)
    require(timeout >= 2, 'Insufficient bounded time for native image observation')
    argv = ['/usr/bin/systemd-run', '--unit=' + unit, '--description=dev-pair-owned-' + unit,
            '--uid=dp-maint', '--quiet', '--wait', '--collect', '--service-type=exec',
            '--property=RuntimeMaxSec=' + str(max(1, int(timeout - 1))), '--property=TimeoutStopSec=1', '--property=KillMode=control-group',
            '--property=MemoryMax=2G', '--property=TasksMax=512', '--property=CPUQuota=100%',
            '/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin', 'HOME=/usr/local/libexec/dev-pair-gptbox/home',
            'XDG_RUNTIME_DIR=/run/user/' + str(uid), 'CONTAINERS_CONF=/usr/local/libexec/dev-pair-gptbox/containers.conf',
            '/usr/bin/podman', '--root=/var/lib/dev-pair/maintenance/images', '--runroot=/run/user/' + str(uid) + '/dev-pair-gptbox',
            '--storage-driver=vfs', 'image', 'inspect', *images]
    rows = json.loads(native_image_capture(source, argv, timeout))
    require(type(rows) is list and len(rows) == len(images), 'Actual engine image evidence missing')
    for index, (identity, row) in enumerate(zip(images, rows)):
        labels = row.get('Labels') or row.get('Config', {}).get('Labels', {})
        require(row['Id'].removeprefix('sha256:') == identity and row.get('Architecture') == 'amd64' and row.get('Os') == 'linux' and
                labels.get('dev-pair.context') == expected['context_sha256'] and labels.get('org.opencontainers.image.revision') == expected['source_sha'],
                'Actual engine image identity/source mismatch')
        if index == 0:
            require(labels.get('dev-pair.role') == 'maintenance' and labels.get('dev-pair.standards') == expected['standards_sha'] and
                    labels.get('dev-pair.codex.version') == '0.169.0', 'Actual prerequisite image labels mismatch')
            if projection.get('state_schema')==2:
                require(all(labels.get(k)==record[v] for k,v in (('dev-pair.inputs','inputs_sha256'),('dev-pair.runtime','runtime_sha256'),('dev-pair.init','init_sha256'),('dev-pair.codex.sha256','codex_sha256'))),'Actual full image input labels mismatch')
            projection['prepared_image_verified'] = True
        else:
            require(labels.get('dev-pair.distrobox') == expected['distrobox_sha'], 'Actual sealed image upstream mismatch')
            projection['assembled_image_verified'] = True
        if logical_observations is not None:
            logical_observations['prepared' if index==0 else 'assembled']={
                'source_sha':expected['source_sha'],'context_sha256':expected['context_sha256'],
                'image_id':identity,**storage_observer(source).logical(row)}
    return projection


def sudo_public_projection(record):
    """Closed typed fields only; a policy listing is never public evidence."""
    result = {'package': {'availability': 'unavailable'}, 'denials': {}}
    package = record.get('sudo_package')
    base = {'availability', 'supported', 'provenance', 'policy_plugin_verified'}
    if type(package) is dict and package.get('provenance') == 'package-only' and package.get('policy_plugin_verified') is False:
        if set(package) == base and package.get('availability') == 'unavailable' and package.get('supported') is False:
            result['package'] = dict(package)
        elif (set(package) == base | {'name','version','release','arch'} and package.get('availability') == 'observed' and
              type(package.get('supported')) is bool and all(type(package.get(k)) is str and
              re.fullmatch(r'[A-Za-z0-9_.+-]{1,64}', package[k]) for k in ('name','version','release','arch'))):
            supported = (package['name'] == 'sudo' and package['version'] == '1.9.17' and
                         re.fullmatch(r'[0-9]+\.p2\.fc44',package['release']) is not None and
                         package['arch'] in ('x86_64','aarch64'))
            if supported == package['supported']:
                result['package'] = dict(package)
    denials = record.get('sudo_denials', {})
    if type(denials) is not dict:
        return result
    fields = set(('operation_id role execution_kind relay_applicability payload_exit native_exit relay_verified exact_denial hostname_bound stderr_empty '
                  'complete_input stdout_bytes stderr_bytes package_supported outcome').split())
    for role, operation in (('dp-maint','maintenance-sudo-denial'),('dp-dev','development-sudo-denial')):
        value = denials.get(operation)
        if type(value) is not dict or set(value) != fields or value.get('role') != role or value.get('operation_id') != operation:
            continue
        booleans = ('relay_verified','exact_denial','hostname_bound','stderr_empty','complete_input','package_supported')
        if not all(type(value[k]) is bool for k in booleans):
            continue
        if value['package_supported'] and result['package'].get('supported') is not True:
            continue
        if not all(value[k] is None or type(value[k]) is int and -255 <= value[k] <= 255 for k in ('payload_exit','native_exit')):
            continue
        if not all(type(value[k]) is int and 0 <= value[k] <= 1048576 for k in ('stdout_bytes','stderr_bytes')):
            continue
        if value['execution_kind'] not in ('native','direct'):
            continue
        if value['relay_applicability'] != ('required' if value['execution_kind'] == 'native' else 'not-applicable'):
            continue
        transport = ((value['execution_kind'] == 'native' and value['relay_verified'] and value['native_exit'] == 0) or
                     (value['execution_kind'] == 'direct' and not value['relay_verified'] and value['native_exit'] is None))
        denied = (all(value[k] for k in booleans if k != 'relay_verified') and transport and value['payload_exit'] == 0 and
                  value['stderr_bytes'] == 0 and value['stdout_bytes'] == len('User '+role+' is not allowed to run sudo on erebus.\n'))
        if value['outcome'] != ('denied' if denied else 'blocked'):
            continue
        result['denials'][operation] = dict(value)
    return result


PREPARE_COST_STEPS=('pre-prepare','input-admission','host-preflight','context-content','context-source','git-prerequisite',
    'adapter-source-and-upstream','desired-state','resolved-discovery','packages','operator','host-identity-time',
    'sudo-package-provenance','dp-maint','maintenance-directories','dp-dev','development-directories','managed-limits',
    'ingress-guard','tailscale-package-config','tailscale-package','package-inventory','maintenance-gptbox-build',
    'preparation-completion','finalization','unattributed')
PREPARE_COST_COLUMNS=('visits','wall_seconds','command_count','accepted','rejected_with_launcher_handle',
                      'rejected_without_launcher_handle','command_elapsed_seconds')
PREPARE_COST_SCOPE='emitted-top-level-prepare-and-source-check-callbacks'


def prepare_cost_projection(state,expected,budget_available):
    unavailable={'availability':'unavailable'}
    value=state.get('prepare_cost')
    if (type(value) is dict and set(value)=={'availability','reason'} and value.get('availability')=='unavailable' and
            value.get('reason') in ('projection-overflow','interrupted-accounting-update')):return dict(value)
    try:
        require(budget_available, 'Prepare cost phase witness unavailable')
        keys=set(('schema source_sha context_sha256 attempt_id phase phase_budget_sha256 status wall_complete commands_complete elapsed_seconds '
                  'command_records unknown_records scope nested_controls columns steps').split())
        require(type(value) is dict and set(value)==keys and type(value['schema']) is int and value['schema']==1,
                'Invalid prepare cost fields')
        require(value['source_sha']==expected['source_sha'] and value['context_sha256']==expected['context_sha256'] and
                type(value['attempt_id']) is str and re.fullmatch('[0-9a-f]{32}',value['attempt_id']) and
                value['attempt_id']==state.get('prepare_cost_attempt') and value['phase']==('host-prerequisites' if state.get('schema')==2 else 'prepare'), 'Prepare cost target mismatch')
        digest=hashlib.sha256(json.dumps(state['prepare_budget_witness'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        require(value['phase_budget_sha256']==digest and value['scope']==('emitted-top-level-host-prerequisites-and-source-check-callbacks' if state.get('schema')==2 else PREPARE_COST_SCOPE) and
                value['nested_controls']=='included-in-parent-elapsed-not-counted-again' and value['columns']==list(PREPARE_COST_COLUMNS),
                'Invalid prepare cost binding/scope')
        def count(item):return type(item) is int and 0<=item<=4096
        def finite(item):return type(item) in (int,float) and 0<=item<=3300 and math.isfinite(item)
        require(all(type(value[k]) is bool for k in ('wall_complete','commands_complete')) and
                value['status'] in ('complete','interrupted','incomplete','overflow') and
                (value['status'] in ('complete','interrupted'))==(value['wall_complete'] and value['commands_complete']),
                'Invalid prepare cost completeness')
        require(count(value['command_records']) and count(value['unknown_records']) and
                (finite(value['elapsed_seconds']) or value['elapsed_seconds'] is None and not value['wall_complete']), 'Invalid prepare cost totals')
        rows=value['steps'];require(type(rows) is dict and set(rows)<=set(PREPARE_COST_STEPS), 'Unknown prepare cost step')
        for row in rows.values():
            require(type(row) is list and len(row)==7 and count(row[0]) and finite(row[1]) and all(count(v) for v in row[2:6]) and
                    row[2]==sum(row[3:6]) and (finite(row[6]) or row[6] is None and not value['commands_complete']), 'Invalid prepare cost row')
        require(sum(row[2] for row in rows.values())+value['unknown_records']==value['command_records'] and
                (not value['commands_complete'] or value['unknown_records']==0), 'Prepare cost command accounting mismatch')
        require(not value['wall_complete'] or abs(sum(row[1] for row in rows.values())-value['elapsed_seconds'])<=.01,
                'Prepare cost wall accounting mismatch')
        result={'availability':'observed',**value}
        require(len(json.dumps(result,separators=(',',':')).encode())<=4096, 'Prepare cost projection bound')
        return result
    except (ValueError,TypeError,KeyError):return unavailable


def prepare_observations(state, expected):
    # Reuse the exact target/admission validation before admitting timing or
    # owner evidence. Durations do not establish a primary failure cause.
    initialize_projection(state,expected,None)
    result = {'source_sha':expected['source_sha'],'context_sha256':expected['context_sha256'],
              'budget':{'availability':'unavailable'},'budget_scope':state.get('prepare_budget_scope','legacy-prepare'),'role_directories':{}}
    def finite(value,low,high):
        return type(value) in (int,float) and low <= value <= high and math.isfinite(value)
    witness=state.get('prepare_budget_witness')
    fields={'configured_seconds','effective_seconds','elapsed_seconds','deadline_reached_at_exit','timer_fired'}
    if (type(witness) is dict and set(witness)==fields and type(witness['configured_seconds']) is int and
            witness['configured_seconds']==600 and finite(witness['effective_seconds'],0.000001,600) and
            finite(witness['elapsed_seconds'],0,3300) and
            all(type(witness[k]) is bool for k in ('deadline_reached_at_exit','timer_fired')) and
            witness['deadline_reached_at_exit'] == (witness['elapsed_seconds'] >= witness['effective_seconds'])):
        result['budget']={'availability':'observed',**witness}
    elapsed=state.get('prepare_elapsed_seconds')
    result['prepare_elapsed_seconds']=elapsed if finite(elapsed,0,3300) else None
    batches=state.get('role_directory_batches',{})
    if type(batches) is dict:
        for role in ('maintenance','development'):
            value=batches.get(role)
            if (type(value) is dict and set(value)=={'role','checked_lookups','completed_directories','outcome'} and
                    value['role']==role and type(value['checked_lookups']) is int and 0<=value['checked_lookups']<=2 and
                    type(value['completed_directories']) is int and 0<=value['completed_directories']<=8 and
                    (value['completed_directories']==0 or value['checked_lookups']==2) and
                    value['outcome'] in ('complete','blocked') and
                    (value['outcome']!='complete' or value['checked_lookups']==2 and value['completed_directories']==8)):
                result['role_directories'][role]=dict(value)
    result['cost']=prepare_cost_projection(state,expected,result['budget'].get('availability')=='observed')
    return result


DECODER_REASONS=('unavailable','raw-byte-bound','after-terminal-frame','header-invalid','data-after-partial','frame-count',
    'failure-json','failure-shape','control-json','control-shape','control-version','control-complete','control-status',
    'control-uid','control-domain','control-helper','control-protocol','incomplete-frame','uid-mismatch','helper-mismatch',
    'relay-error-status','payload-signal','native-status-mismatch')

NATIVE_FAILURE_POINTS=('not-reached','transport-verification','launcher-start','pipe-read','relay-feed','launcher-wait','relay-finish','payload-status')
NATIVE_FAILURE_CATEGORIES=('decoder-rejected','wait-timeout','io-error','text-decode','value-rejected','subprocess-error',
                           'blocked-or-interrupted','deadline','output-limit','status-rejected')


def launcher_projection(value,context=None):
    """Validate diagnostics from the selected owned launcher, never admission."""
    unavailable={'availability':'unavailable'}
    try:
        keys={'summary','timing','bytes','complete'}
        require(type(value) is dict and set(value)==(keys|{'executor'} if context is not None else keys),'Launcher shape')
        if context is not None:
            executor=value['executor']
            require(type(context) is str and re.fullmatch('[0-9a-f]{64}',context) and type(executor) is dict and
                set(executor)=={'context_sha256','unit','suboperation'} and executor['context_sha256']==context and
                executor['unit']=='dev-pair-gptbox-'+context+'.service' and executor['suboperation'] in ('load','save','build','inspect'),'Launcher executor')
        require(type(value['bytes']) is int and 0<=value['bytes']<=1048577 and type(value['complete']) is bool,'Launcher counters')
        summary=value['summary'];timing=value['timing']
        if summary!=unavailable:
            require(type(summary) is dict and set(summary) in ({'availability','result'},{'availability','result','code','status'}) and
                summary['availability']=='observed' and summary['result'] in ('success','resources','protocol','timeout','exit-code','signal',
                'core-dump','watchdog','start-limit-hit','oom-kill','exec-condition') and value['complete'] and value['bytes']<=8192,'Launcher summary')
            if 'code' in summary:
                require(summary['code'] in ('exited','killed','dumped') and type(summary['status']) is int and
                    (0<=summary['status']<=255 if summary['code']=='exited' else 1<=summary['status']<=64),'Launcher status')
        if timing!=unavailable:
            require(type(timing) is dict and set(timing)=={'availability','start_us','runtime_us','command_remaining_us','phase_remaining_us','helper_margin_us'} and
                timing['availability']=='observed','Launcher timing')
            require(all(type(timing[k]) is int and 0<=timing[k]<=900000000 for k in ('start_us','runtime_us','command_remaining_us','helper_margin_us')) and
                0<timing['start_us']<=5000000 and timing['runtime_us']>0 and timing['helper_margin_us']<=100001 and
                (timing['phase_remaining_us'] is None or type(timing['phase_remaining_us']) is int and 0<=timing['phase_remaining_us']<=900000000),'Launcher timing bounds')
        return value
    except (ValueError,KeyError,TypeError):return unavailable


def signed_load_projection(entry,expected,phase='maintenance-gptbox'):
    unavailable={'availability':'unavailable'}
    try:
        identity=entry.get('diagnostic_identity');value=entry.get('signed_load_payload')
        require(type(identity) is dict and set(identity)=={'source_sha','context_sha256','phase'} and
                identity['source_sha']==expected['source_sha'] and identity['context_sha256']==expected['context_sha256'] and
                identity['phase']==phase=='maintenance-gptbox' and entry.get('step')=='candidate-image' and
                entry.get('operation_id')=='candidate-native-executor','Signed load scope')
        keys={'schema','availability','context_sha256','uid','suboperation','launch_handle_observed','control_verified','status','streams','classification'}
        require(type(value) is dict and set(value) in (keys,keys|{'identity'}) and type(value['schema']) is int and value['schema']==1 and
                value['availability'] in ('observed','partial','unavailable') and value['context_sha256']==identity['context_sha256'] and
                type(value['uid']) is int and 1000<=value['uid']<2**32 and value['suboperation']=='load','Signed load schema')
        if 'identity' in value:require(value['identity']==identity,'Signed load identity')
        require(type(value['launch_handle_observed']) is bool and type(value['control_verified']) is bool,'Signed load flags')
        status=value['status'];verified=value['control_verified']
        require((verified and value['launch_handle_observed'] and type(status) is int and 0<=status<=255 and
                 entry.get('relay_verified') is True and type(entry.get('native_exit_status')) is int and entry['native_exit_status']==status) or
                (not verified and status is None),'Signed load control evidence')
        streams=value['streams'];require(type(streams) is dict and set(streams)=={'stdout','stderr'},'Signed load streams')
        for stream in streams.values():
            require(type(stream) is dict and set(stream)=={'bytes','sha256','complete'} and type(stream['complete']) is bool,'Signed load stream schema')
            count=stream['bytes'];digest=stream['sha256']
            require((count is None and digest is None and not stream['complete']) or
                (type(count) is int and 0<=count<=4194304 and type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) and
                 (count>0 or stream['complete'] and digest==EMPTY_SHA256)),'Signed load stream bounds')
        complete=all(v['complete'] for v in streams.values())
        require(sum(v['bytes'] for v in streams.values() if v['bytes'] is not None)<=4194304 and
            (not complete or verified) and (value['availability']=='observed')==complete and
            (value['availability']!='partial' or any(v['bytes'] is not None for v in streams.values())) and
            (value['availability']!='unavailable' or all(v['bytes'] is None for v in streams.values())),'Signed load completion')
        classification=value['classification']
        require(type(classification) is dict and set(classification)=={'family','path_role'} and classification['family'] in ('unknown','reported-owner','reported-stat-enoent','reported-stat-eacces'),'Signed load family')
        if classification['family']=='unknown':require(classification['path_role']=='none','Unknown signed load path')
        else:
            forms={'reported-owner':b'path "/usr/local/libexec/dev-pair-gptbox/home/.config" exists and it is not owned by the current user\n',
                'reported-stat-enoent':b'stat /usr/local/libexec/dev-pair-gptbox/home/.config: no such file or directory\n',
                'reported-stat-eacces':b'stat /usr/local/libexec/dev-pair-gptbox/home/.config: permission denied\n'}
            message=forms[classification['family']]
            require(complete and status==1 and streams['stdout']['bytes']==0 and
                (streams['stderr']['bytes'],streams['stderr']['sha256'])==(len(message),hashlib.sha256(message).hexdigest()) and
                classification['path_role']=='old-home-config','Signed load family evidence')
        result={'identity':dict(identity),**value}
        require(len(json.dumps(result,separators=(',',':')).encode())<=1024,'Signed load projection bound')
        return result
    except (ValueError,KeyError,TypeError,AttributeError):return unavailable


def native_failure_projection(entry,expected,phase=None):
    unavailable={'availability':'unavailable'}
    try:
        identity=entry.get('diagnostic_identity')
        require(type(identity) is dict and set(identity)=={'source_sha','context_sha256','phase'} and
                identity['source_sha']==expected['source_sha'] and identity['context_sha256']==expected['context_sha256'] and
                identity['phase'] in ('prepare','maintenance-gptbox') and (phase is None or identity['phase']==phase), 'Native failure identity mismatch')
        value=entry.get('native_failure');keys={'point','category','launcher_handle_observed','status_sampled_before_interrupt','launcher_status_before_interrupt','decoder'}
        require(type(value) is dict and keys<=set(value)<=keys|{'cache_comparison','launcher'} and value['point'] in NATIVE_FAILURE_POINTS and
                value['category'] in NATIVE_FAILURE_CATEGORIES, 'Native failure schema mismatch')
        require(type(value['launcher_handle_observed']) is bool and type(value['status_sampled_before_interrupt']) is bool,
                'Native failure flags mismatch')
        status=value['launcher_status_before_interrupt']
        require(status is None or type(status) is int and -255<=status<=255, 'Invalid pre-interrupt status')
        require((value['launcher_handle_observed'] or not value['status_sampled_before_interrupt']) and
                (value['status_sampled_before_interrupt'] or status is None), 'Native failure status mismatch')
        decoder=value['decoder']
        if 'cache_comparison' in value:
            cache=value['cache_comparison']
            require(entry.get('admission_stage')=='cache-recheck' and entry.get('admission_reason')=='cache-final-comparison',
                    'Cache witness stage mismatch')
            if cache!={'availability':'unavailable'}:
                require(type(cache) is dict and set(cache)=={'availability','stage','rows','order_only_equal','row_index','row_side',
                    'path_class','lookup_index','changed_fields','truncated'} and cache['availability']=='observed' and
                    cache['stage']=='cache-final-comparison','Cache witness schema mismatch')
                require(type(cache['rows']) is list and len(cache['rows'])==2 and all(type(v) is int and 0<=v<=1024 for v in cache['rows']) and
                    type(cache['order_only_equal']) is bool and cache['truncated'] is False and cache['row_side'] in ('before','after') and
                    type(cache['row_index']) is int and 0<=cache['row_index']<cache['rows'][0 if cache['row_side']=='before' else 1],
                    'Cache witness counters invalid')
                require(cache['path_class'] in ('lookup-directory','owned-mask-directory','owned-mask','global-mask-directory','global-mask','applicable-directory') and
                    type(cache['lookup_index']) is int and 0<=cache['lookup_index']<12 and
                    type(cache['changed_fields']) is int and 0<=cache['changed_fields']<128 and
                    (not cache['order_only_equal'] or cache['changed_fields']==0 and cache['rows'][0]==cache['rows'][1]),
                    'Cache witness classification invalid')
        if decoder!={'availability':'unavailable'}:
            require(type(decoder) is dict and set(decoder)=={'reason','maximum','raw_bytes','raw_bytes_clamped','data_frames','frame_kind',
                'header_present','body_present','control_present','failure_present','partial_frame','complete'}, 'Decoder witness schema mismatch')
            require(decoder['reason'] in DECODER_REASONS and type(decoder['maximum']) is int and
                    decoder['maximum'] in (262144,1048576,4194304) and decoder['frame_kind'] in ('D','C','F','unknown','unavailable'),
                    'Decoder witness enum mismatch')
            limit=decoder['maximum'];frames=(limit+4095)//4096;bound=limit+8*frames+256+8192
            require(type(decoder['raw_bytes']) is int and 0<=decoder['raw_bytes']<=bound and
                    type(decoder['data_frames']) is int and 0<=decoder['data_frames']<=frames+1, 'Decoder witness counters invalid')
            require(all(type(decoder[k]) is bool for k in ('raw_bytes_clamped','header_present','body_present','control_present','failure_present','partial_frame','complete')),
                    'Decoder witness flags invalid')
            require(not decoder['raw_bytes_clamped'] or decoder['raw_bytes']==bound, 'Decoder witness bound mismatch')
            require(decoder['complete']==(decoder['control_present'] and not decoder['partial_frame']) and
                    (not decoder['complete'] or not decoder['header_present'] and not decoder['body_present']), 'Decoder completion mismatch')
        result={'availability':'observed','identity':dict(identity),**value}
        if 'launcher' in result:
            tailscale=(identity['phase']=='prepare' and entry.get('step')=='tailscale-package' and entry.get('operation_id')=='signed-packages')
            maintenance=((identity['phase']=='prepare' and entry.get('step')=='maintenance-gptbox-build' or
                identity['phase']=='maintenance-gptbox' and entry.get('step')=='candidate-image') and entry.get('operation_id')=='candidate-native-executor')
            result['launcher']=(launcher_projection(value['launcher'],expected['context_sha256']) if maintenance else
                launcher_projection(value['launcher']) if tailscale else unavailable)
            if len(json.dumps(result,separators=(',',':')).encode())>1536:result['launcher']=unavailable
        require(len(json.dumps(result,separators=(',',':')).encode())<=1536, 'Native failure projection bound')
        return result
    except (ValueError,KeyError,TypeError,AttributeError):return unavailable


def public_diagnostics(state_root, expected, source=None):
    selected = {'storage_observations':storage_public_projection(state_root,expected,source)}
    selected['image_progress']={'availability':'unavailable'}
    try:
        stage=read_json(state_root/'gptbox-adapter'/expected['context_sha256']/'image-progress.json',2048)
        require(type(stage) is dict and set(stage)=={'schema','source_sha','context_sha256','phase','stage'} and type(stage['schema']) is int and stage['schema']==1 and
            stage['source_sha']==expected['source_sha'] and stage['context_sha256']==expected['context_sha256'] and stage['phase']=='candidate-image' and
            stage['stage'] in ('executor-setup','input-staging','signed-import','build','immutable-inspect','completion-record','storage','prepared-marker','assembly','runtime','complete'),'Invalid image stage')
        selected['image_progress']={'availability':'observed',**stage}
    except (OSError,ValueError,KeyError,TypeError):pass
    for name, path in (('prepare', state_root / 'prepare-diagnostics.json'),
                       ('adapter', state_root / 'gptbox-adapter' / expected['context_sha256'] / 'diagnostics.json')):
        try:
            record = read_json(path, 524288)
            failures = record.get('failures', [])
            selected[name] = {'available_failures': len(failures), 'retained_failures': min(2, len(failures)), 'records': []}
            selected[name]['sudo_evidence'] = sudo_public_projection(record)
            selected[name]['recent_metadata'] = [{key: item.get(key) for key in
                    ('operation_id', 'step', 'status', 'outcome', 'accepted_exit', 'allowed_exit_statuses', 'native', 'elapsed_seconds', 'admission_stage', 'admission_outcome', 'admission_reason', 'relay_failure', 'relay_verified', 'native_exit_status')}
                    for item in record.get('recent', [])[-4:]]
            for recent, item in zip(selected[name]['recent_metadata'], record.get('recent', [])[-4:]):
                recent['native_failure']=native_failure_projection(item,expected,'prepare' if name=='prepare' else 'maintenance-gptbox')
                if 'signed_load_payload' in item:recent['signed_load_payload']=signed_load_projection(item,expected,'prepare' if name=='prepare' else 'maintenance-gptbox')
                if item.get('operation') in ('selinux-enforcement', 'resolved-service-identity'):
                    recent['public_stdout_tail'] = safe_text(item.get('stdout_tail', ''), 300)
                    recent['public_stderr_tail'] = safe_text(item.get('stderr_tail', ''), 300)
                    recent['output_bytes'] = item.get('output_bytes')
            for item in failures[-2:]:
                entry = {'status': item['status'] if type(item['status']) is int else safe_text(item['status'], 100),
                         'output_bytes': item.get('output_bytes'),
                         'operation_id': safe_text(item.get('operation_id', 'unavailable'), 80),
                         'step': safe_text(item.get('step', 'unavailable'), 80),
                         'outcome': safe_text(item.get('outcome', 'legacy-unknown'), 40),
                         'accepted_exit': item.get('accepted_exit'), 'allowed_exit_statuses': item.get('allowed_exit_statuses'),
                         'native': item.get('native', {'availability': 'not-recorded'}),
                         **{key: item[key] for key in ('elapsed_seconds', 'admission_stage', 'admission_outcome', 'admission_reason', 'relay_failure', 'relay_verified', 'native_exit_status') if key in item}}
                if item.get('operation_id') in ('maintenance-sudo-denial', 'development-sudo-denial', 'sudo-package-provenance'):
                    projected = sudo_public_projection({'sudo_package': item.get('sudo_package', record.get('sudo_package')),
                        'sudo_denials': {item['operation_id']: item.get('sudo_denial')}})
                    entry['sudo_evidence'] = projected
                entry['native_failure']=native_failure_projection(item,expected,'prepare' if name=='prepare' else 'maintenance-gptbox')
                if 'signed_load_payload' in item:entry['signed_load_payload']=signed_load_projection(item,expected,'prepare' if name=='prepare' else 'maintenance-gptbox')
                for stream in ('stdout', 'stderr'):
                    text = item.get(stream + '_tail', '')
                    entry[stream + '_tail'] = safe_text(text, 1500)
                    entry[stream + '_truncated'] = bool(item.get(stream + '_truncated')) or len(text) > 1500
                selected[name]['records'].append(entry)
        except (OSError, ValueError, KeyError):
            selected[name] = 'No bounded public failure record available'
    try:
        state = read_json(state_root / 'initialize.json')
        initialize_projection(state, expected, None)
        selected['prepare_progress'] = {'step': safe_text(state.get('prepare_step', 'unavailable'), 80),
                                        'source_verification': state.get('source_verification', {'outcome': 'unavailable'}),
                                        'observations':prepare_observations(state,expected)}
    except (OSError, ValueError, KeyError):
        selected['prepare_progress'] = {'step': 'unavailable', 'source_verification': {'outcome': 'unavailable'}}
    try:
        witness = read_json(state_root / 'resolved-discovery.json', 8192)
        require(type(witness) is dict, 'Invalid discovery witness object')
        reasons = {'none','config-directory-mode','config-owner-or-type','config-file-mode','config-file-conflict','config-label-mismatch',
                   'merged-config-conflict','runtime-discovery-enabled','runtime-properties-unavailable','runtime-properties-malformed','discovery-listener-remains',
                   'retained-listener-missing','resolved-identity-rejected'}
        require(witness.get('version') == 1 and witness.get('status') in ('pass','blocked') and witness.get('reason') in reasons,
                'Invalid discovery witness')
        require(witness.get('context_sha256') in (None, expected['context_sha256'])
                and witness.get('source_sha') in (None, expected['source_sha'])
                and re.fullmatch('[0-9a-f]{64}', witness.get('bootstrap_sha256','')), 'Discovery target mismatch')
        for key in ('directory_mode','file_mode'):
            require(witness.get(key) is None or type(witness[key]) is int and 0 <= witness[key] <= 0o7777, 'Invalid discovery mode')
        for key in ('owner_and_type_verified','stock_labels_match','runtime_discovery_disabled'):
            require(type(witness.get(key)) is bool, 'Invalid discovery observation')
        selected['resolved_discovery'] = {key:witness[key] for key in ('status','reason','directory_mode','file_mode',
                    'owner_and_type_verified','stock_labels_match','runtime_discovery_disabled','bootstrap_sha256','source_sha','context_sha256')}
    except (OSError, ValueError, KeyError, TypeError):
        selected['resolved_discovery'] = {'status':'unavailable'}
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--stage-systemd', action='store_true')
    mode.add_argument('--native-service', action='store_true')
    parser.add_argument('--source', required=True)
    parser.add_argument('--inputs-json', required=True)
    parser.add_argument('--guest-sha256', required=True)
    args = parser.parse_args()
    expected = validate_inputs(json.loads(args.inputs_json, object_pairs_hook=unique_object))
    require(expected['source_sha'] == args.source, 'Seed source/input identity mismatch')
    if args.stage_systemd:
        try:
            stage_executor(expected, args.guest_sha256)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            write_startup_failure({'version': 1, 'operation': 'native-executor-staging', 'outcome': 'blocked',
                                   'source_sha': args.source, 'controller_sha256': expected['controller_sha256'],
                                   'guest_sha256': args.guest_sha256,
                                   'requested_unit_sha256': hashlib.sha256(service_unit(expected, args.guest_sha256).encode()).hexdigest(),
                                   'startup_properties': error.startup if isinstance(error, ExecutorStagingError) else error.fields if isinstance(error, ExecutorStartupError) else {'availability': 'unavailable'},
                                   'staging': error.fields if isinstance(error, ExecutorStagingError) else {'step': 'observe-startup', 'kind': 'unavailable', 'errno': None, 'exit_status': None, 'elapsed_ms': 0, 'uid': os.getuid(), 'euid': os.geteuid()}})
        return
    phases = {name: {'status': 'blocked', 'detail': 'Prerequisite not completed'} for name in GUEST_PHASES}
    report = {'version': REPORT_VERSION, 'source_sha': args.source, 'guest_sha256': args.guest_sha256,
              'inputs': expected, 'initialization': {}, 'phases': phases, 'identity': {}, 'diagnostics': {}}
    source = None
    secret = None
    state_root = STATE_ROOT
    active = 'fedora-preflight'
    try:
        payload = PAYLOAD_PATH
        require(digest(pathlib.Path(__file__)) == args.guest_sha256, 'Executing guest script identity mismatch')
        report['identity']['executor_observation'] = {'uid': os.getuid(), 'euid': os.geteuid(), 'pid': os.getpid(),
                                                     'context': safe_text(pathlib.Path('/proc/self/attr/current').read_text().strip('\x00\n'), 200),
                                                     'cgroup': pathlib.Path('/proc/self/cgroup').read_text().strip()}
        executor = native_executor_identity(expected, args.guest_sha256)
        admission_end = executor['admission_deadline']
        report['identity'] = baseline(end=admission_end)
        report['identity']['provisioning_executor'] = executor
        require(report['identity']['root_free_bytes'] >= 8 * 1024 ** 3, 'Guest capacity below unchanged8GiB reserve')
        phases[active] = {'status': 'pass', 'detail': 'Actual Fedora44 kernel, Enforcing, systemd PID1 and cgroupv2 observed'}
        active = 'guest-inputs'
        remaining(admission_end, GUEST_ADMISSION_SECONDS)
        destination = INPUT_DESTINATION
        source = admit_inputs(payload, expected, destination, timeout=remaining(admission_end, GUEST_ADMISSION_SECONDS))
        phases[active] = {'status': 'pass', 'detail': 'Exact authenticated compressed inputs, original strict-Cosign evidence and sanitized Git source admitted'}
        for phase, stage in (('bootstrap-inspect', 'inspect'), ('bootstrap-status', 'status')):
            active = phase
            observed = json.loads(command(['/usr/bin/python3', str(source / 'tools/bootstrap.py'), stage], timeout=remaining(admission_end, 10)))
            if stage == 'status':
                require(observed.get('enrollment_recorded') is False, 'Unexpected enrollment is outside this probe')
            phases[phase] = {'status': 'pass', 'detail': 'Actual pre-initialize bootstrap ' + stage + ' completed'}
        active = 'bootstrap-prepare'
        with make_password(SECRET_DIRECTORY) as secret:
            argv = ['/usr/bin/python3', str(source / 'tools/bootstrap.py'), 'initialize', '--apply',
                    '--source-sha', args.source, '--distrobox-source', str(destination / 'distrobox'),
                    '--gptbox-context', str(destination / 'context'), '--expected-context-sha256', expected['context_sha256'],
                    '--bootstrap-source', '192.0.2.9/32', '--password-file', str(secret)]
            def remove_after_prepare():
                remove_password_after_prepare(secret, state_root, expected)
            started = time.monotonic()
            try:
                code, output = capture(argv, timeout=INITIALIZE_SECONDS + INITIALIZE_CLEANUP_SECONDS, tick=remove_after_prepare)
                report['diagnostics']['initialize_cli'] = {'exit_status': code, 'tail': safe_text(output, 1500)}
                report['initialization'] = initialize_projection(read_json(state_root / 'initialize.json'), expected, code)
                phases['bootstrap-prepare'] = {'status': 'blocked', 'detail': 'Initialize exit' + str(code) + '; awaiting actual protected prerequisite/image verification'}
                phases['maintenance-gptbox'] = {'status': 'blocked', 'detail': 'Initialize exit' + str(code) + '; maintenance phase=' + report['initialization']['maintenance_gptbox']}
            finally:
                report['identity']['initialize_wall_seconds'] = round(time.monotonic() - started, 3)
                secret.unlink(missing_ok=True)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        phases[active] = {'status': 'blocked', 'detail': safe_text(exc, 2000)}
    finally:
        if secret is not None:
            try:
                secret.unlink(missing_ok=True)
            except OSError:
                phases['bootstrap-prepare'] = {'status': 'blocked', 'detail': 'Disposable password cleanup failed; owned VM teardown required'}
        final_end = time.monotonic() + GUEST_FINAL_SECONDS
        evidence_end = final_end - REPORT_WRITE_SECONDS - 5
        if source is not None:
            try:
                if not report['initialization'] and (state_root / 'initialize.json').exists():
                    report['initialization'] = initialize_projection(read_json(state_root / 'initialize.json'), expected, None)
                projection = report['initialization']
                if projection:
                    report['initialization'] = image_evidence(expected, projection, state_root, source, evidence_end,
                        logical_observations=report['diagnostics'].setdefault('image_logical_storage',{}))
                    if projection['prepare'] == 'complete' and projection['prepared_image_verified']:
                        phases['bootstrap-prepare'] = {'status': 'pass', 'detail': 'Shared initialize completed preparation; protected exact-target evidence and actual prerequisite image verified'}
                    if (projection['exit_status'] == 0 and projection['phase'] == 'complete' and projection['maintenance_gptbox'] == 'complete' and projection['assembled_image_verified']):
                        phases['maintenance-gptbox'] = {'status': 'pass', 'detail': 'Genuine upstream init, sealed image, two frozen boundary/version cycles and removed runtime recorded; actual sealed image verified'}
                    else:
                        phases['maintenance-gptbox'] = {'status': 'blocked', 'detail': 'Shared initialize did not complete exact-target maintenance assembly; inspect selected bounded evidence'}
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                if report['initialization'].get('prepared_image_verified') is True:
                    phases['bootstrap-prepare'] = {'status': 'pass', 'detail': 'Exact protected preparation record and actual prerequisite image verified; assembly evidence blocked'}
                report['diagnostics']['initialization_evidence'] = safe_text(exc, 1500)
            for phase, stage in (('bootstrap-post-inspect', 'inspect'), ('bootstrap-post-status', 'status')):
                try:
                    observed = json.loads(command(['/usr/bin/python3', str(source / 'tools/bootstrap.py'), stage], timeout=remaining(evidence_end, 4)))
                    if stage == 'status':
                        require(observed.get('enrollment_recorded') is False, 'Unexpected enrollment is outside this probe')
                    phases[phase] = {'status': 'pass', 'detail': 'Actual post-initialize bootstrap ' + stage + ' completed'}
                except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                    phases[phase] = {'status': 'blocked', 'detail': safe_text(exc, 1000)}
            report['diagnostics']['public_operations'] = public_diagnostics(state_root, expected, source)
            try:
                packages = read_bytes(state_root / 'packages.txt', 32768)
                report['diagnostics']['host_packages'] = {'sha256': hashlib.sha256(packages).hexdigest(),
                                                         'bytes': len(packages), 'tail': safe_text(packages, 3000)}
            except (OSError, ValueError):
                report['diagnostics']['host_packages'] = 'No bounded public package record available'
        report['diagnostics'].update(diagnostics(evidence_end))
        report['identity']['final_root_free_bytes'] = shutil.disk_usage('/').free
        if report['identity']['final_root_free_bytes'] < 8 * 1024 ** 3:
            phases['maintenance-gptbox'] = {'status': 'blocked', 'detail': 'Final measured guest free capacity is below the unchanged8GiB reserve'}
        password_absent = not (SECRET_DIRECTORY / 'core-password').exists()
        report['diagnostics']['guest_cleanup'] = {'password_absent': password_absent, 'native': 'Exact initialization cleanup status retained',
                                                   'vm_teardown': 'Remaining guest resources end at shutdown/outer teardown'}
        if not password_absent:
            phases['bootstrap-prepare'] = {'status': 'blocked', 'detail': 'Disposable password absence not verified; owned VM teardown required'}
        write_report(report, timeout=remaining(final_end - 5, REPORT_WRITE_SECONDS))
        result = subprocess.run(['/usr/bin/systemctl', 'poweroff', '--no-block'], env=SAFE_ENV, timeout=remaining(final_end, 5))
        require(result.returncode == 0, 'Guest poweroff request failed; controller/native deadline remains the final bound')


if __name__ == '__main__':
    main()
