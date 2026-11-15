#!/usr/bin/env python3
"""Secret-free Fedora VM initialization probe, launched by authenticated public payload."""
import argparse
import contextlib
import array
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import secrets
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
REPORT_VERSION = 2
GUEST_PHASES = ('fedora-preflight', 'guest-inputs', 'bootstrap-inspect', 'bootstrap-status',
                'bootstrap-prepare', 'maintenance-gptbox', 'bootstrap-post-inspect', 'bootstrap-post-status')
INPUT_LENGTHS = {'source_sha': 40, 'helper_sha256': 64, 'manifest_sha256': 64, 'payload_sha256': 64,
                 'context_sha256': 64, 'distrobox_sha': 40, 'standards_sha': 40,
                 'codex_sha256': 64, 'codex_source_sha': 40}
GUEST_ADMISSION_SECONDS = 60
INITIALIZE_SECONDS = 2280
INITIALIZE_CLEANUP_SECONDS = 45
GUEST_FINAL_SECONDS = 60
PAYLOAD_PATH = pathlib.Path('/run/dev-pair-payload')
INPUT_DESTINATION = pathlib.Path('/root/dev-pair-ci-inputs')
SECRET_DIRECTORY = pathlib.Path('/run/dev-pair-ci-secrets')
STATE_ROOT = pathlib.Path('/var/lib/dev-pair/bootstrap')
INITIALIZATION_KEYS = set(('source_sha context_sha256 distrobox_sha exit_status phase prepare maintenance_gptbox cleanup '
                           'prepared_image_id assembled_image_id boundary_and_version_cycles runtime_container_removed job_admission '
                           'prepared_image_verified assembled_image_verified packages_sha256 package_count').split())
REPORT_BEGIN = b'DP_FEDORA_REPORT_V1\n'
REPORT_END = b'\nDP_FEDORA_REPORT_END\n'
REPORT_FRAME_LIMIT = REPORT_LIMIT + len(REPORT_BEGIN) + len(REPORT_END)
REPORT_WRITE_SECONDS = 30


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
    require(type(value) is dict and set(value) == INITIALIZATION_KEYS, 'invalid initialization evidence fields')
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
                require(len(output) + len(data) <= maximum, 'Guest diagnostic command exceeded byte limit (truncated)')
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


def baseline():
    release = pathlib.Path('/etc/os-release').read_text()
    require('ID=fedora' in release and 'VERSION_ID=44' in release, 'Guest is not Fedora 44')
    require(platform.machine() == 'x86_64', 'Unexpected guest architecture')
    require(os.geteuid() == 0 and pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd',
            'Guest must boot real systemd as PID 1 with a root console executor')
    selinux = command(['/usr/sbin/getenforce']).decode().strip()
    require(selinux == 'Enforcing', 'Stock image SELinux is not Enforcing; transition matrix is outside this probe')
    require(pathlib.Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'Unified cgroup v2 unavailable')
    policy = pathlib.Path('/sys/fs/selinux/policy')
    require(policy.is_file(), 'Active SELinux policy unavailable')
    return {'os': 'Fedora 44', 'kernel': platform.release(), 'architecture': platform.machine(),
            'pid1': 'systemd', 'selinux': selinux, 'cgroup': 'v2',
            'root_free_bytes': shutil.disk_usage('/').free,
            'executor_context': pathlib.Path('/proc/self/attr/current').read_text().strip(),
            'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


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
                lines = output.decode('utf-8', 'replace').splitlines()
                selected = [line for line in lines if re.search(r'type=(?:AVC|USER_AVC|1400|1107)\b', line) and
                            re.search(r'comm="(?:podman|crun|conmon|distrobox-init|python3|dnf5?|systemd-run|systemctl|systemd|dbus-broker|polkitd|sshd|getenforce|chpasswd)"', line)]
                observed[name] = {'exit_status': code, 'tail': safe_text('\n'.join(selected), 3000),
                                  'selected_lines': len(selected), 'omitted_lines': len(lines) - len(selected)}
            else:
                observed[name] = {'exit_status': code, 'tail': safe_text(output, 3000), 'captured_bytes': len(output)}
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            observed[name] = {'status': 'unavailable', 'detail': safe_text(exc, 500)}
    return observed



def admit_inputs(payload, expected, destination):
    require(digest(payload / 'public_inputs.py') == expected['helper_sha256'], 'Public extractor implementation identity mismatch')
    result = json.loads(command(['/usr/bin/python3', str(payload / 'public_inputs.py'), 'extract',
                         '--manifest', str(payload / 'manifest.json'), '--payload', str(payload / 'maintenance-inputs.tar.gz'),
                         '--expected-manifest-sha256', expected['manifest_sha256'], '--output', str(destination)],
                         timeout=GUEST_ADMISSION_SECONDS), object_pairs_hook=unique_object)
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
    if state['maintenance_gptbox'] == 'complete':
        observed = state.get('result', {})
        require(observed.get('source_sha') == expected['source_sha'] and observed.get('context_sha256') == expected['context_sha256'] and
                observed.get('distrobox_sha') == expected['distrobox_sha'] and observed.get('boundary_and_version_cycles') == 2 and
                observed.get('runtime_container_removed') is True and observed.get('job_admission') is False,
                'Completed initialization result identity/evidence mismatch')
        result.update(assembled_image_id=observed['assembled_image_id'], boundary_and_version_cycles=2, runtime_container_removed=True)
    return validate_initialization(result, expected)


def image_evidence(expected, projection, state_root, source, end):
    images = []
    if projection['prepare'] == 'complete':
        desired = read_json(state_root / 'prepared')
        record = read_json(state_root / 'gptbox-image.json')
        require(desired['gptbox_context_sha256'] == expected['context_sha256'] and desired['standards_sha'] == expected['standards_sha'] and
                record['source_sha'] == expected['source_sha'] and record['context_sha256'] == expected['context_sha256'] and
                record['codex_sha256'] == expected['codex_sha256'] and desired['bootstrap_sha256'] == digest(source / 'tools/bootstrap.py'), 'Prepared image evidence does not match target')
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
            '--uid=dp-maint', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
            '--property=RuntimeMaxSec=' + str(max(1, int(timeout - 1))), '--property=TimeoutStopSec=1', '--property=KillMode=control-group',
            '--property=MemoryMax=2G', '--property=TasksMax=512', '--property=CPUQuota=100%',
            '/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin', 'HOME=/usr/local/libexec/dev-pair-gptbox/home',
            'XDG_RUNTIME_DIR=/run/user/' + str(uid), 'CONTAINERS_CONF=/usr/local/libexec/dev-pair-gptbox/containers.conf',
            '/usr/bin/podman', '--root=/var/lib/dev-pair/maintenance/images', '--runroot=/run/user/' + str(uid) + '/dev-pair-gptbox',
            '--storage-driver=vfs', 'image', 'inspect', *images]
    rows = json.loads(command(argv, timeout=timeout, maximum=262144))
    require(type(rows) is list and len(rows) == len(images), 'Actual engine image evidence missing')
    for index, (identity, row) in enumerate(zip(images, rows)):
        labels = row.get('Labels') or row.get('Config', {}).get('Labels', {})
        require(row['Id'].removeprefix('sha256:') == identity and row.get('Architecture') == 'amd64' and row.get('Os') == 'linux' and
                labels.get('dev-pair.context') == expected['context_sha256'] and labels.get('org.opencontainers.image.revision') == expected['source_sha'],
                'Actual engine image identity/source mismatch')
        if index == 0:
            require(labels.get('dev-pair.role') == 'maintenance' and labels.get('dev-pair.standards') == expected['standards_sha'] and
                    labels.get('dev-pair.codex.version') == '0.169.0', 'Actual prerequisite image labels mismatch')
            projection['prepared_image_verified'] = True
        else:
            require(labels.get('dev-pair.distrobox') == expected['distrobox_sha'], 'Actual sealed image upstream mismatch')
            projection['assembled_image_verified'] = True
    return projection


def public_diagnostics(state_root, expected):
    selected = {}
    for name, path in (('prepare', state_root / 'prepare-diagnostics.json'),
                       ('adapter', state_root / 'gptbox-adapter' / expected['context_sha256'] / 'diagnostics.json')):
        try:
            record = read_json(path, 524288)
            failures = record.get('failures', [])
            selected[name] = {'available_failures': len(failures), 'retained_failures': min(2, len(failures)), 'records': []}
            selected[name]['recent_metadata'] = [{key: item.get(key) for key in
                    ('operation_id', 'step', 'status', 'outcome', 'accepted_exit', 'allowed_exit_statuses', 'native')}
                    for item in record.get('recent', [])[-4:]]
            for recent, item in zip(selected[name]['recent_metadata'], record.get('recent', [])[-4:]):
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
                         'native': item.get('native', {'availability': 'not-recorded'})}
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
                                        'source_verification': state.get('source_verification', {'outcome': 'unavailable'})}
    except (OSError, ValueError, KeyError):
        selected['prepare_progress'] = {'step': 'unavailable', 'source_verification': {'outcome': 'unavailable'}}
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--inputs-json', required=True)
    parser.add_argument('--guest-sha256', required=True)
    args = parser.parse_args()
    expected = validate_inputs(json.loads(args.inputs_json, object_pairs_hook=unique_object))
    require(expected['source_sha'] == args.source, 'Seed source/input identity mismatch')
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
        report['identity'] = baseline()
        require(report['identity']['root_free_bytes'] >= 8 * 1024 ** 3, 'Guest capacity below unchanged8GiB reserve')
        phases[active] = {'status': 'pass', 'detail': 'Actual Fedora44 kernel, Enforcing, systemd PID1 and cgroupv2 observed'}
        active = 'guest-inputs'
        admission_end = time.monotonic() + GUEST_ADMISSION_SECONDS
        destination = INPUT_DESTINATION
        source = admit_inputs(payload, expected, destination)
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
                    report['initialization'] = image_evidence(expected, projection, state_root, source, evidence_end)
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
            report['diagnostics']['public_operations'] = public_diagnostics(state_root, expected)
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
