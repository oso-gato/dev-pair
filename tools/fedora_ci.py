#!/usr/bin/env python3
"""Bounded secret-free Fedora Cloud VM probe on a public standard CI runner.

This controller never installs packages into the runner or launches agents.
Full bootstrap/maintenance assembly is explicitly blocked in this first slice.
"""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

GIB = 1024 ** 3
MIB = 1024 ** 2
BASE = 'registry.fedoraproject.org/fedora:44@sha256:48f4a2b507ad36a6a8bb83646ee81164aff80a62be06d03b143b80594d2b558e'
FINGERPRINT = '36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6'
IMAGE_NAME = 'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'
IMAGE_SHA256 = '28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f'
IMAGE_BYTES = 583729152
IMAGE_ROOT = 'https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/'
CHECKSUM_NAME = 'Fedora-Cloud-44-1.7-x86_64-CHECKSUM'
CHECKSUM_SHA256 = 'a436186ff0e930d77637d03e6f357206b686c4ef3fcde234b6f1da63041d4b32'
HOST_RESERVE = 3 * GIB
OVERLAY_LIMIT = 8 * GIB
OVERHEAD_LIMIT = 2 * GIB
LOG_LIMIT = 8 * MIB
DU_CAPTURE_LIMIT = 65536  # unchanged until actual diagnostic volume/type is known
SOURCE_LIMIT = 32 * MIB
CONTAINER_SECONDS = 1050  # >= 15-minute TCG boot allowance, finite native lifetime
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
PHASES = ('runner-preflight', 'signed-cloud-image', 'tooling', 'source-payload',
          'fedora-boot', 'fedora-preflight', 'bootstrap-inspect', 'bootstrap-status',
          'bootstrap-prepare', 'maintenance-gptbox', 'cleanup')


def scratch_root(runner_temp):
    require(runner_temp and pathlib.Path(runner_temp).is_dir(), 'RUNNER_TEMP unavailable')
    # Podman 4.9 rejects runroot paths longer than 50 characters. The normal
    # /home/runner/work/_temp prefix plus our leaf already exceeds that limit.
    # All storage/disks/accounting stay together in one private, short leaf.
    parent = pathlib.Path('/tmp')
    info = parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and not parent.is_symlink() and info.st_uid == 0 and
            (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), 'short scratch parent is not trusted')
    root = pathlib.Path(tempfile.mkdtemp(prefix='dpvm-', dir=parent))
    root.chmod(0o755)  # public payload only; engine storage retains private modes
    return root


def mounts_below(root):
    for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        require(len(fields) >= 6, 'cannot validate scratch mount inventory')
        decoded = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        mounted = pathlib.Path(decoded)
        if mounted == root or root in mounted.parents:
            return True
    return False


class Blocked(Exception):
    pass


class StorageMeasurementBlocked(Blocked):
    def __init__(self, message, diagnostics):
        super().__init__(message)
        self.diagnostics = diagnostics


def require(condition, message):
    if not condition:
        raise Blocked(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@contextlib.contextmanager
def deadline(seconds):
    def expired(signum, frame):
        raise Blocked('public dependency phase wall-time budget exceeded')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def file_hash(path):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(MIB), b''):
            result.update(chunk)
    return result.hexdigest()


def sanitize(data, limit=12000):
    """Public candidate output is untrusted: escape workflow and terminal controls."""
    text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else str(data)
    text = ''.join(c if c in '\n\t' or 32 <= ord(c) < 127 else '?' for c in text)
    # Both current ::command:: and legacy ##[command] forms are recognized
    # anywhere in a runner log line. Break complete colon runs, not only pairs.
    text = re.sub(r':{2,}', lambda match: ' '.join(match.group()), text).replace('##[', '# #[')
    return ('[truncated; tail follows]\n' if len(text) > limit else '') + text[-limit:]


def safe_json(value):
    """Keep JSON evidence lossless while escaping runner command introducers."""
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True)
    # Escape inside JSON strings only; structural colons remain valid JSON.
    # json.loads reconstructs every original string/key, including literal
    # backslashes, while the runner never sees either command introducer.
    return re.sub(r'"(?:\\.|[^"\\])*"',
                  lambda match: match.group().replace(':', r'\u003a').replace('#', r'\u0023'), encoded)


def emit_json(prefix, value):
    print(prefix + ' ' + safe_json(value), flush=True)


def emit_text(prefix, value, limit=12000):
    print(prefix + sanitize(value, limit), flush=True)


def evidence_tail(value, limit):
    text = value.decode('utf-8', 'replace') if isinstance(value, bytes) else str(value)
    return ('[truncated; tail follows]\n' if len(text) > limit else '') + text[-limit:]


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(newurl.startswith('https://'), 'non-HTTPS dependency redirect denied')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, maximum, exact_size=None, expected_sha=None, deadline=600):
    require(url.startswith('https://'), 'only official HTTPS dependency URLs are supported')
    started = time.monotonic()
    total = 0
    opener = urllib.request.build_opener(HTTPSOnly())
    with opener.open(url, timeout=30) as response, open(destination, 'xb') as output:
        require(response.geturl().startswith('https://'), 'non-HTTPS response denied')
        while True:
            require(time.monotonic() - started <= deadline, 'dependency download deadline exceeded')
            data = response.read(min(MIB, maximum - total + 1))
            if not data:
                break
            total += len(data)
            require(total <= maximum, 'dependency download exceeds byte limit')
            output.write(data)
    if exact_size is not None:
        require(total == exact_size, 'dependency byte length mismatch')
    if expected_sha is not None:
        require(file_hash(destination) == expected_sha, 'dependency SHA256 mismatch')
    return total


def checksum_identity(plaintext):
    """Require exactly one matching named image/length pair in verified plaintext."""
    text = plaintext.decode('utf-8') if isinstance(plaintext, bytes) else plaintext
    digests = re.findall(r'^SHA256 \(' + re.escape(IMAGE_NAME) + r'\) = ([0-9a-f]{64})$', text, re.M)
    lengths = re.findall(r'^# ' + re.escape(IMAGE_NAME) + r': ([0-9]+) bytes$', text, re.M)
    require(digests == [IMAGE_SHA256] and lengths == [str(IMAGE_BYTES)], 'signed checksum image identity mismatch')
    return {'name': IMAGE_NAME, 'sha256': digests[0], 'bytes': int(lengths[0])}


def run_small(argv, timeout=30, cwd=None, input_data=None):
    result = subprocess.run(argv, cwd=cwd, input=input_data, capture_output=True,
                            env=SAFE_ENV, timeout=timeout)
    require(result.returncode == 0, 'command failed: ' + evidence_tail(result.stderr, 1500))
    require(len(result.stdout) <= SOURCE_LIMIT, 'command output exceeds limit')
    return result.stdout


def verify_checksum(key_bundle, signed_checksum, home):
    home.mkdir(mode=0o700)
    gpg = ['/usr/bin/gpg', '--batch', '--no-auto-key-retrieve', '--homedir', str(home)]
    run_small(gpg + ['--import', str(key_bundle)])
    key = run_small(gpg + ['--export', FINGERPRINT])
    require(key, 'Fedora 44 signing key absent')
    keyring = home / 'fedora44.gpg'
    keyring.write_bytes(key)
    # Explicit isolated keyring: no trust in other Fedora keys from the bundle.
    result = subprocess.run(gpg + ['--no-default-keyring', '--keyring', str(keyring), '--status-fd=1',
                                  '--verify', str(signed_checksum)], capture_output=True, env=SAFE_ENV, timeout=30)
    require(result.returncode == 0, 'Fedora checksum signature verification failed')
    fingerprints = re.findall(rb'^\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) ', result.stdout, re.M)
    require(fingerprints == [FINGERPRINT.encode()], 'unexpected Fedora signer fingerprint')
    # Only parse the text after successful cryptographic verification. The
    # immutable file digest also rules out ambiguous extra clear-signed content.
    require(file_hash(signed_checksum) == CHECKSUM_SHA256, 'signed checksum file identity mismatch')
    return checksum_identity(signed_checksum.read_bytes())


def check_capacity(root, before_boot=False):
    free = shutil.disk_usage(root).free
    require(free >= HOST_RESERVE + (OVERLAY_LIMIT if before_boot else 0),
            'capacity blocked: insufficient free disk for declared overlay and host reserve')
    return free


def du_disappearance(root, line):
    match = re.fullmatch(rb"(?:/usr/bin/)?du: cannot (access|read directory) '([^'\r\n]+)': No such file or directory", line)
    if match is not None and match[2].startswith(os.fsencode(root) + b'/') and b'..' not in match[2].split(b'/'):
        return match[1].decode()
    fatal = re.fullmatch(rb'(?:/usr/bin/)?du: fts_read failed: ([^\r\n]+): No such file or directory', line)
    if fatal is not None and fatal[1].startswith(os.fsencode(root) + b'/') and b'..' not in fatal[1].split(b'/'):
        return 'fts_read'
    return None


def du_diagnostics(root, result, seen=None, truncated=False):
    counts = {'access_enoent': 0, 'read_directory_enoent': 0, 'fatal_fts_enoent': 0, 'other': 0}
    for line in result.stderr.splitlines():
        kind = du_disappearance(root, line)
        field = {'access': 'access_enoent', 'read directory': 'read_directory_enoent', 'fts_read': 'fatal_fts_enoent'}.get(kind, 'other')
        counts[field] += 1
    return {'exit_status': result.returncode, 'capture_limit_bytes': DU_CAPTURE_LIMIT,
            'stdout_bytes_seen': (seen or {}).get('stdout', len(result.stdout)),
            'stderr_bytes_seen': (seen or {}).get('stderr', len(result.stderr)),
            'retained_diagnostic_lines': sum(counts.values()), 'retained_line_types': counts,
            'retained_trailing_partial_line': bool(result.stderr and not result.stderr.endswith(b'\n')),
            'truncated': truncated, 'counts_cover': 'retained prefix only' if truncated else 'complete captured output',
            'stderr_tail': evidence_tail(result.stderr, 2048), 'stdout_tail': evidence_tail(result.stdout, 512)}


def capture_du(root, argv):
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    seen = {'stdout': 0, 'stderr': 0}
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=SAFE_ENV, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    started = time.monotonic()
    failure = None
    try:
        while selector.get_map():
            require(time.monotonic() - started < 5, 'storage measurement deadline exceeded')
            for key, _ in selector.select(timeout=.1):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                seen[key.data] += len(data)
                remaining = DU_CAPTURE_LIMIT - sum(map(len, buffers.values()))
                buffers[key.data].extend(data[:remaining])
                require(sum(seen.values()) <= DU_CAPTURE_LIMIT, 'storage measurement diagnostic limit exceeded')
        return subprocess.CompletedProcess(argv, process.wait(timeout=1), bytes(buffers['stdout']), bytes(buffers['stderr']))
    except (Blocked, subprocess.SubprocessError) as exc:
        result = subprocess.CompletedProcess(argv, process.poll(), bytes(buffers['stdout']), bytes(buffers['stderr']))
        failure = StorageMeasurementBlocked(str(exc), du_diagnostics(root, result, seen, truncated=True))
        raise failure from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            try:
                if argv[0] == 'sudo':
                    # SIGTERM lets sudo relay to its root command. Independently,
                    # the root-side timeout below bounds even an orphaned scan.
                    process.terminate()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.wait(timeout=7 if argv[0] == 'sudo' else 1)
            except subprocess.TimeoutExpired:
                if failure:
                    failure.diagnostics['termination'] = 'controller wait expired; fixed root-side timeout remains the scan bound'
                try:
                    process.kill()
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass  # failure remains blocked; root-side timeout is independent
        if failure:
            failure.diagnostics['controller_exit_status'] = process.poll()


def parse_du(root, result):
    try:
        return validate_du(root, result)
    except Blocked as exc:
        raise StorageMeasurementBlocked(str(exc), du_diagnostics(root, result)) from exc


def validate_du(root, result):
    require(len(result.stdout) + len(result.stderr) <= DU_CAPTURE_LIMIT, 'storage measurement diagnostic limit exceeded')
    summary = re.fullmatch(rb'([0-9]+)\t' + re.escape(os.fsencode(root)) + rb'\n', result.stdout)
    if result.returncode == 0:
        require(summary is not None, 'invalid storage measurement summary')
        require(not result.stderr, 'unexpected storage measurement diagnostics')
        return int(summary[1]), False
    require(result.returncode == 1 and result.stderr, 'storage measurement failed')
    # Accept only GNU du's precise ENOENT traversal race, beneath this owned
    # root. Permission, I/O, mount, sudo and unrecognized errors stay blockers.
    kinds = [du_disappearance(root, line) for line in result.stderr.splitlines()]
    require(all(kind is not None for kind in kinds), 'storage measurement has non-disappearance errors')
    if summary is None:
        require(result.stdout == b'' and 'fts_read' in kinds, 'invalid storage measurement summary')
        # A fatal traversal race supplies no total. It is retryable evidence,
        # never zero bytes or an independently usable measurement.
        return None, True
    return int(summary[1]), True


def measure_storage(root, live=False, sudo=True, attempts=3):
    require(type(attempts) is int and 1 <= attempts <= 3, 'invalid storage retry bound')
    argv = (['sudo', '-n'] if sudo else []) + ['/usr/bin/timeout', '--signal=TERM', '--kill-after=1s', '5s',
            '/usr/bin/du', '--summarize', '--block-size=1',
            '--one-file-system', '--exclude=guest.qcow2', str(root)]
    maximum = None
    usable = missing = 0
    for attempt in range(attempts):
        try:
            result = capture_du(root, argv)
            size, vanished = parse_du(root, result)
        except StorageMeasurementBlocked as exc:
            exc.diagnostics.update(attempts=attempt + 1, usable_samples=usable,
                                   missing_total_samples=missing, max_observed_bytes=maximum)
            raise
        if size is None:
            missing += 1
        else:
            usable += 1
            maximum = size if maximum is None else max(maximum, size)
        context = {'attempts': attempt + 1, 'usable_samples': usable,
                   'missing_total_samples': missing, 'max_observed_bytes': maximum}
        if maximum is not None and maximum > OVERHEAD_LIMIT:
            raise StorageMeasurementBlocked('capacity blocked: tooling/source overhead limit exceeded',
                                            {**du_diagnostics(root, result), **context})
        if not vanished:
            return {'bytes': maximum, 'provisional': False, **context}
    # Live churn can produce valid but incomplete traversals. Keep the largest
    # observed count; it is provisional, never a completed-phase validation.
    if maximum is None:
        raise StorageMeasurementBlocked('storage measurement produced no usable total within bounded retries',
                                        {**du_diagnostics(root, result), **context})
    if not live:
        raise StorageMeasurementBlocked('storage measurement did not stabilize within bounded retries',
                                        {**du_diagnostics(root, result), **context})
    return {'bytes': maximum, 'provisional': True, **context}


def tooling_recipe():
    # Repository packages resolve at execution time. GPG checking is mandatory;
    # exact installed NEVRAs are emitted, not claimed reproducible from a lock.
    return f'''FROM {BASE}
RUN /usr/bin/timeout --signal=TERM --kill-after=10s 540s /usr/bin/dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 --setopt=keepcache=True --setopt=install_weak_deps=False install qemu-system-x86-core qemu-img genisoimage python3 seabios-bin && /usr/bin/find /var/cache -type f -name '*.rpm' -exec /usr/bin/sha256sum {{}} + > /tool-rpm-sha256.txt && /usr/bin/test -s /tool-rpm-sha256.txt && /usr/bin/dnf clean all
RUN /usr/bin/rpm -qa --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' | /usr/bin/sort > /tool-rpms.txt
COPY qemu_entry.py /usr/local/bin/dp-qemu-entry.py
ENTRYPOINT ["/usr/bin/python3", "/usr/local/bin/dp-qemu-entry.py"]
'''


def seed_data(source, archive_sha, bundle_sha, guest_sha):
    for value, length in ((source, 40), (archive_sha, 64), (bundle_sha, 64), (guest_sha, 64)):
        require(re.fullmatch('[0-9a-f]{%d}' % length, value), 'invalid payload identity')
    # No credentials/passwords/tokens are placed in cloud-init or serial text.
    command = ['/usr/bin/python3', '/run/dev-pair-payload/guest.py', '--source', source,
               '--archive-sha256', archive_sha, '--bundle-sha256', bundle_sha, '--guest-sha256', guest_sha]
    return ('#cloud-config\n'
            'disable_root: true\nssh_pwauth: false\n'
            'bootcmd:\n  - [mkdir, -p, /run/dev-pair-payload]\n'
            '  - [mount, -o, "ro,nosuid,nodev,noexec", "LABEL=DPPAYLOAD", /run/dev-pair-payload]\n'
            'runcmd:\n  - ' + json.dumps(command) + '\n')


def parse_serial(data, expected_source, expected_guest):
    # Treat serial assertions as candidate-controlled test evidence. Require
    # one complete result, exact identities and every requested phase.
    matches = re.findall(rb'^DP_FEDORA_RESULT ([^\r\n]+)\r?$', data, re.M)
    require(len(matches) == 1, 'missing or ambiguous completed Fedora serial result')
    require(len(matches[0]) <= 65536, 'guest result exceeds byte limit')
    def unique(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate guest result field')
            value[key] = item
        return value
    result = json.loads(matches[0], object_pairs_hook=unique)
    require(type(result) is dict and set(result) == {'version', 'source_sha', 'guest_sha256', 'phases', 'identity', 'diagnostics'}, 'invalid guest result shape')
    require(type(result['version']) is int and result['version'] == 1 and
            result['source_sha'] == expected_source and result['guest_sha256'] == expected_guest,
            'guest source/implementation identity mismatch')
    required = {'fedora-preflight', 'bootstrap-inspect', 'bootstrap-status', 'bootstrap-prepare', 'maintenance-gptbox'}
    require(type(result['phases']) is dict and set(result['phases']) == required, 'missing guest phases')
    for phase in result['phases'].values():
        require(type(phase) is dict and set(phase) == {'status', 'detail'} and
                phase['status'] in ('pass', 'fail', 'blocked') and type(phase['detail']) is str and
                len(phase['detail']) <= 4000, 'invalid guest phase')
    return result


class Probe:
    def __init__(self, source, root):
        self.source = source
        self.repo = pathlib.Path(__file__).resolve().parents[1]
        self.root = root
        info = root.lstat()
        require(stat.S_ISDIR(info.st_mode) and not root.is_symlink() and info.st_uid == os.getuid(),
                'scratch must be an owned nonsymlink directory')
        require(all(len(os.fsencode(root / name)) <= 50 for name in ('graph', 'runroot', 'tmp')),
                'scratch engine paths exceed Podman 50-byte runroot compatibility limit')
        self.scratch_identity = (info.st_dev, info.st_ino)
        self.engine_activity = False
        self.report = {'version': 1, 'source_sha': source, 'executor': 'public-standard-ubuntu-24.04/Fedora44-QEMU',
                       'controller_sha256': file_hash(pathlib.Path(__file__)),
                       'workflow_sha256': file_hash(self.repo / '.github/workflows/fedora-vm.yml'),
                       'phases': {name: {'status': 'blocked', 'detail': 'Not reached'} for name in PHASES},
                       'limits': {'overlay_bytes': OVERLAY_LIMIT, 'host_reserve_bytes': HOST_RESERVE,
                                  'overhead_bytes': OVERHEAD_LIMIT, 'log_bytes': LOG_LIMIT,
                                  'storage_diagnostic_bytes': DU_CAPTURE_LIMIT,
                                  'container_seconds': CONTAINER_SECONDS, 'guest_virtual_bytes': 12 * GIB,
                                  'cpus': 3, 'memory_bytes': 8 * GIB, 'guest_cpus': 2, 'guest_memory_bytes': 6 * GIB},
                       'hostinger_acceptance': False, 'job_admission': False}
        self.podman = ['sudo', '-n', '/usr/bin/podman', '--root=' + str(root / 'graph'),
                       '--runroot=' + str(root / 'runroot'), '--tmpdir=' + str(root / 'tmp'),
                       '--hooks-dir=' + str(root / 'empty-hooks'),
                       '--storage-driver=overlay']
        self.container = 'dp-fedora-probe-' + root.name.rsplit('-', 1)[-1]
        self.log_used = 0

    def phase(self, name, status, detail):
        self.report['phases'][name] = {'status': status, 'detail': evidence_tail(detail, 4000)}
        emit_json('DP_PHASE', {'phase': name, **self.report['phases'][name]})

    def initialize_directories(self):
        # Podman version can create graph/runroot/tmp while validating config.
        # Establish every declared leaf first; no post-probe mkdir may assume
        # the engine left those paths absent.
        for name in ('graph', 'runroot', 'tmp', 'payload', 'disks', 'empty-hooks'):
            path = self.root / name
            path.mkdir(mode=0o700 if name in ('graph', 'runroot', 'tmp') else 0o755, exist_ok=True)
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid == os.getuid() and
                    not info.st_mode & 0o022 and info.st_dev == self.scratch_identity[0],
                    'declared scratch directory is unsafe or on another filesystem: ' + name)

    def storage_measurement(self, live=False):
        try:
            return measure_storage(self.root, live=live)
        except StorageMeasurementBlocked as exc:
            self.report['storage_measurement_failure'] = exc.diagnostics
            raise

    def bounded(self, argv, timeout, name, disk_check=True, file_limit=None):
        """Bound logs/time and watch storage while a native child runs."""
        log = bytearray()
        started = time.monotonic()
        def child_limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if file_limit is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, env=SAFE_ENV, start_new_session=True,
                                   preexec_fn=child_limits)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                require(time.monotonic() - started < timeout, name + ' deadline exceeded')
                if disk_check:
                    check_capacity(self.root)
                    # Rootful Podman owns private storage directories. Measure
                    # via a fixed read-only privileged tool, never silently skip
                    # inaccessible files in an unprivileged os.walk.
                    measurement = self.storage_measurement(live=True)
                    if measurement['provisional']:
                        self.report['provisional_storage_samples'] = self.report.get('provisional_storage_samples', 0) + 1
                for key, _ in selector.select(timeout=1):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    self.log_used += len(data)
                    require(self.log_used <= LOG_LIMIT, 'aggregate diagnostic byte limit exceeded (truncated)')
                    log.extend(data)
            process.wait(timeout=5)
            require(process.returncode == 0, name + ' failed with exit ' + str(process.returncode))
            if disk_check:
                check_capacity(self.root)
                self.report['last_stable_overhead_bytes'] = self.storage_measurement()['bytes']
            return bytes(log)
        except BaseException:
            # Podman/conmon scopes may outlive the CLI; cleanup also force-removes
            # only our named container. Native --timeout limits the VM itself.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            emit_text('', bytes(log), 12000)
            raise
        finally:
            selector.close()
            process.stdout.close()

    def helper(self, args, timeout=60, **kwargs):
        self.engine_activity = True  # version-only preflight never starts resources
        return self.bounded(self.podman + args, timeout, 'tooling command', **kwargs)

    def run_args(self, entrypoint, mounts=True):
        args = ['run', '--rm', '--name=' + self.container, '--timeout=' + str(CONTAINER_SECONDS),
                '--restart=no', '--network=none', '--read-only', '--read-only-tmpfs=false',
                '--user=' + str(os.getuid()) + ':' + str(os.getgid()), '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--pids-limit=1024', '--memory=8g', '--cpus=3',
                '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--entrypoint=' + entrypoint]
        if mounts:
            args += ['--volume=' + str(self.root / 'payload') + ':/payload:ro',
                     '--volume=' + str(self.root / 'disks') + ':/disks:rw']
        return args

    def preflight(self):
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'oso-gato/dev-pair',
                'this mutating test harness is restricted to the authorized public CI repository')
        release = pathlib.Path('/etc/os-release').read_text()
        require('ID=ubuntu' in release and 'VERSION_ID="24.04"' in release, 'only ubuntu-24.04 standard runner supported')
        require(re.fullmatch('[0-9a-f]{40}', self.source), 'invalid exact source SHA')
        require(run_small(['/usr/bin/git', '-C', str(self.repo), 'rev-parse', 'HEAD']).decode().strip() == self.source, 'checkout differs from exact PR head')
        require(not run_small(['/usr/bin/git', '-C', str(self.repo), 'status', '--porcelain']), 'source checkout must be clean')
        for command in ('/usr/bin/podman', '/usr/bin/gpg', '/usr/bin/git', '/usr/bin/sudo',
                        '/usr/bin/timeout', '/usr/bin/du'):
            require(pathlib.Path(command).is_file(), 'required preinstalled runner tool unavailable: ' + command)
        require(os.cpu_count() >= 2, 'at least two CPUs required')
        mem = int(re.search(r'^MemTotal:\s+(\d+) kB$', pathlib.Path('/proc/meminfo').read_text(), re.M)[1]) * 1024
        require(mem >= 10 * GIB, 'insufficient runner memory')
        free = check_capacity(self.root, before_boot=True)
        version = run_small(self.podman + ['version', '--format=json']).decode()
        self.report['runner'] = {'kernel': os.uname().release, 'image_version': os.environ.get('ImageVersion', 'unreported'),
                                 'podman': json.loads(version), 'free_bytes': free, 'memory_bytes': mem,
                                 'merge_sha': os.environ.get('DP_MERGE_SOURCE', 'unreported'),
                                 'scratch_device': self.scratch_identity[0], 'scratch_root': str(self.root)}
        self.phase('runner-preflight', 'pass', 'Actual standard-runner OS/source/tools/capacity checked; no host packages installed')

    def inputs(self):
        with deadline(600):
            self.download_inputs()

    def download_inputs(self):
        downloads = self.root / 'downloads'
        downloads.mkdir()
        key = downloads / 'fedora.gpg'
        checksum = downloads / CHECKSUM_NAME
        download('https://fedoraproject.org/fedora.gpg', key, MIB)
        download(IMAGE_ROOT + CHECKSUM_NAME, checksum, 65536, expected_sha=CHECKSUM_SHA256)
        identity = verify_checksum(key, checksum, self.root / 'gnupg')
        download(IMAGE_ROOT + IMAGE_NAME, self.root / 'payload/base.qcow2', IMAGE_BYTES,
                 exact_size=IMAGE_BYTES, expected_sha=IMAGE_SHA256)
        self.report['cloud_image'] = {**identity, 'signer': FINGERPRINT, 'signature': 'verified-gpg'}
        self.phase('signed-cloud-image', 'pass', json.dumps(self.report['cloud_image']))

    def tooling(self):
        build = self.root / 'tool-build'
        build.mkdir()
        (build / 'Containerfile').write_text(tooling_recipe())
        shutil.copyfile(self.repo / 'tools/fedora_ci_qemu.py', build / 'qemu_entry.py')
        (self.root / 'empty-auth.json').write_text('{"auths":{}}\n')
        self.image = self.helper(['build', '--pull=always', '--http-proxy=false', '--authfile=' + str(self.root / 'empty-auth.json'),
                                  '--memory=2g', '--cpu-quota=200000', '--force-rm',
                                  '--ulimit=fsize=2147483648:2147483648', '--iidfile=' + str(self.root / 'tool-image'),
                                  '--file=' + str(build / 'Containerfile'), str(build)], timeout=600)
        self.image = run_small(['sudo', '-n', '/usr/bin/cat', str(self.root / 'tool-image')]).decode().strip()
        require(re.fullmatch('sha256:[0-9a-f]{64}', self.image), 'tool image ID missing')
        packages = self.helper(self.run_args('/usr/bin/cat', mounts=False) + [self.image, '/tool-rpms.txt', '/tool-rpm-sha256.txt'])
        self.report['tooling'] = {'base': BASE, 'image_id': self.image, 'rpm_manifest': packages.decode()}
        emit_text('DP_TOOL_RPMS\n', packages, 32000)
        self.phase('tooling', 'pass', 'Disposable image with GPG-checked RPMs; exact NEVRAs recorded, live repositories remain a reproducibility limit')

    def payload(self):
        payload = self.root / 'payload'
        guest = self.repo / 'tools/fedora_ci_guest.py'
        shutil.copyfile(guest, payload / 'guest.py')
        self.guest_sha = file_hash(guest)
        self.bounded(['/usr/bin/git', '-C', str(self.repo), 'bundle', 'create', str(payload / 'source.bundle'), 'HEAD'],
                     60, 'public source bundle', file_limit=SOURCE_LIMIT)
        # A bundle contains Git objects, never checkout .git/config or CI env.
        run_small(['/usr/bin/git', '-C', str(self.repo), 'bundle', 'verify', str(payload / 'source.bundle')])
        self.bounded(['/usr/bin/git', '-C', str(self.repo), 'archive', '--format=tar',
                      '--output=' + str(payload / 'source.tar'), self.source],
                     30, 'public source archive', file_limit=SOURCE_LIMIT)
        bundle = payload / 'source.bundle'
        require(bundle.stat().st_size <= SOURCE_LIMIT, 'public Git bundle exceeds source limit')
        archive_sha, bundle_sha = file_hash(payload / 'source.tar'), file_hash(bundle)
        seed = self.root / 'seed'
        seed.mkdir()
        (seed / 'user-data').write_text(seed_data(self.source, archive_sha, bundle_sha, self.guest_sha))
        (seed / 'meta-data').write_text('instance-id: dev-pair-' + self.source + '\nlocal-hostname: fedora-ci\n')
        # Only these reviewed public payload files reach the VM, never runner
        # environment, worktree .git metadata/config, credentials or private rules.
        self.helper(self.run_args('/usr/bin/genisoimage') + ['--volume=' + str(seed) + ':/seed:ro', self.image,
                    '-quiet', '-output', '/disks/seed.iso', '-volid', 'cidata', '-joliet', '-rock', '/seed'])
        # Base disk is excluded from the source ISO to avoid duplication.
        self.helper(self.run_args('/usr/bin/genisoimage') + [self.image, '-quiet', '-output', '/disks/payload.iso',
                    '-volid', 'DPPAYLOAD', '-joliet', '-rock', '-graft-points',
                    'guest.py=/payload/guest.py', 'source.tar=/payload/source.tar', 'source.bundle=/payload/source.bundle'])
        base_info = json.loads(self.helper(self.run_args('/usr/bin/qemu-img') +
                                          [self.image, 'info', '--output=json', '/payload/base.qcow2']))
        require(base_info.get('format') == 'qcow2' and not base_info.get('backing-filename') and
                0 < base_info.get('virtual-size', 0) <= 12 * GIB, 'signed base disk layout exceeds declared scope')
        self.report['cloud_image']['virtual_bytes'] = base_info['virtual-size']
        self.helper(self.run_args('/usr/bin/qemu-img') + [self.image, 'create', '-f', 'qcow2', '-F', 'qcow2',
                    '-b', '/payload/base.qcow2', '/disks/guest.qcow2', '12G'])
        self.report['payload'] = {'source_sha': self.source, 'guest_sha256': self.guest_sha,
                                  'archive_sha256': archive_sha, 'bundle_sha256': bundle_sha}
        self.phase('source-payload', 'pass', json.dumps(self.report['payload']))

    def boot(self):
        check_capacity(self.root, before_boot=True)
        accel = 'tcg'
        # Merely finding /dev/kvm is insufficient. Prove VM initialization with
        # QEMU's native paused-start + QMP quit, bounded separately.
        if pathlib.Path('/dev/kvm').exists() and os.access('/dev/kvm', os.R_OK | os.W_OK):
            try:
                command = self.run_args('/usr/bin/python3', mounts=False) + ['--device=/dev/kvm',
                           '--group-add=' + str(pathlib.Path('/dev/kvm').stat().st_gid), self.image,
                           '-c', "import subprocess,sys; p=subprocess.run(['/usr/bin/qemu-system-x86_64','-machine','accel=kvm','-m','128','-nodefaults','-display','none','-S','-qmp','stdio'],input=b'{\"execute\":\"qmp_capabilities\"}\\n{\"execute\":\"quit\"}\\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10); sys.stdout.buffer.write(p.stdout+p.stderr); raise SystemExit(p.returncode)"]
                self.helper(command, timeout=20)
                accel = 'kvm'
            except (Blocked, OSError, subprocess.SubprocessError):
                self.report['kvm'] = 'actual initialization failed; bounded TCG fallback selected'
                # A failed --rm command may still be stopping; remove own name.
                subprocess.run(self.podman + ['rm', '--force', self.container], env=SAFE_ENV, capture_output=True, timeout=15)
        self.report['acceleration'] = accel
        args = self.run_args('/usr/bin/python3')
        if accel == 'kvm':
            args += ['--device=/dev/kvm', '--group-add=' + str(pathlib.Path('/dev/kvm').stat().st_gid)]
        args += [self.image, '/usr/local/bin/dp-qemu-entry.py', '-machine', 'q35,accel=' + accel,
                 '-cpu', 'host' if accel == 'kvm' else 'max', '-smp', '2', '-m', '6144',
                 '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                 '-nic', 'none', '-drive', 'file=/disks/guest.qcow2,if=virtio,format=qcow2,cache=none',
                 '-drive', 'file=/disks/seed.iso,media=cdrom,readonly=on,format=raw',
                 '-drive', 'file=/disks/payload.iso,media=cdrom,readonly=on,format=raw']
        serial = self.helper(args, timeout=300 if accel == 'kvm' else 900)
        emit_text('DP_SERIAL_TAIL\n', serial, 24000)
        guest = parse_serial(serial, self.source, self.guest_sha)
        self.report['guest'] = guest
        self.phase('fedora-boot', 'pass', 'Real signed Fedora Cloud image booted and emitted a complete candidate-bound serial result using ' + accel)
        for name, phase in guest['phases'].items():
            self.phase(name, phase['status'], phase['detail'])

    def cleanup(self):
        # No system reset, prune, shared storage deletion or runner cleanup.
        # Rootful storage exists solely below the controller's mkdtemp leaf.
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and not self.root.is_symlink() and info.st_uid == os.getuid() and
                (info.st_dev, info.st_ino) == self.scratch_identity, 'scratch identity changed; cleanup refused')
        if self.engine_activity:
            result = subprocess.run(self.podman + ['rm', '--force', '--all'], capture_output=True, env=SAFE_ENV, timeout=20)
            require(result.returncode == 0, 'engine cleanup failed; owned scratch preserved for reconciliation: ' +
                    evidence_tail(result.stderr, 1500))
            remaining = subprocess.run(self.podman + ['ps', '--all', '--external', '--format={{.ID}}'],
                                       capture_output=True, env=SAFE_ENV, timeout=20)
            require(remaining.returncode == 0 and not remaining.stdout.strip(),
                    'engine resource inventory unresolved; owned scratch preserved: ' +
                    evidence_tail(remaining.stderr, 1500))
        require(not mounts_below(self.root), 'active scratch mounts remain; owned scratch preserved')
        # Preflight-only failures need no working engine or sudo. After actual
        # engine use, root-owned storage can require narrowly scoped removal.
        try:
            shutil.rmtree(self.root)
        except PermissionError:
            cleanup = subprocess.run(['sudo', '-n', '/bin/rm', '-rf', '--', str(self.root)],
                                     capture_output=True, env=SAFE_ENV, timeout=60)
            require(cleanup.returncode == 0, 'own scratch cleanup incomplete')
        require(not self.root.exists(), 'own scratch cleanup incomplete')
        self.phase('cleanup', 'pass', 'Only this run\'s isolated Podman containers and unique scratch/storage/disks were removed')

    def execute(self):
        active = 'runner-preflight'
        try:
            self.initialize_directories()
            self.preflight()
            for active, action in (('signed-cloud-image', self.inputs), ('tooling', self.tooling),
                                   ('source-payload', self.payload), ('fedora-boot', self.boot)):
                action()
        except (Blocked, OSError, ValueError, subprocess.SubprocessError) as exc:
            self.report['blocker'] = evidence_tail(exc, 4000)
            self.phase(active, 'blocked', self.report['blocker'])
            emit_text('DP_BLOCKED ', self.report['blocker'], 4000)
        finally:
            try:
                self.cleanup()
            except (Blocked, OSError, subprocess.SubprocessError) as exc:
                self.phase('cleanup', 'fail', str(exc))
            emit_json('DP_REPORT', self.report)
            summary = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with open(summary, 'a') as output:
                    output.write('### Fedora 44 VM component probe\n\n')
                    output.write('Source: `' + self.source + '`; Hostinger/pair acceptance: **unverified**.\n\n')
                    for name, phase in self.report['phases'].items():
                        output.write('- ' + name + ': **' + phase['status'] + '** — ' + sanitize(phase['detail'], 500).replace('\n', ' ') + '\n')
                    output.write('\nNo artifact/cache uploads, secrets, enrollment or model calls.\n')
        # The intentionally blocked assembly phase keeps this initial route
        # from becoming a green claim of maintenance-runtime acceptance.
        return 0 if all(p['status'] == 'pass' for p in self.report['phases'].values()) else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source', required=True)
    args = parser.parse_args()
    root = scratch_root(os.environ.get('RUNNER_TEMP'))
    return Probe(args.expected_source, root).execute()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, OSError) as exc:
        emit_text('DP_BLOCKED ', str(exc))
        sys.exit(2)
