#!/usr/bin/env python3
"""Bounded secret-free Fedora Cloud VM probe on a public standard CI runner.

This controller never installs packages into the runner or launches agents.
Runs the shared first-bootstrap preparation/maintenance path with public verified inputs.
"""
import argparse
import base64
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

from fedora_ci_guest import (REPORT_BEGIN, REPORT_END, REPORT_LIMIT, REPORT_FRAME_LIMIT, REPORT_WRITE_SECONDS,
                             REPORT_VERSION, GUEST_PHASES, validate_inputs, validate_initialization, unique_object)
import public_inputs as public

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
OVERLAY_LIMIT = 16 * GIB
OVERHEAD_LIMIT = 4 * GIB
LOG_LIMIT = 8 * MIB
DU_CAPTURE_LIMIT = 65536  # unchanged until actual diagnostic volume/type is known
SOURCE_LIMIT = 32 * MIB
CONTAINER_SECONDS = 1050  # short helper ceiling retained
VM_SECONDS = 2640
VM_CONTAINER_SECONDS = VM_SECONDS + 30
PUBLIC_SECONDS = 540
CLEANUP_SECONDS = 120
CONTROLLER_SECONDS = 3300
VIRTUAL_BYTES = 32 * GIB
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
PHASES = ('runner-preflight', 'signed-cloud-image', 'tooling', 'source-payload',
          'fedora-boot', 'fedora-preflight', 'bootstrap-inspect', 'bootstrap-status',
          'guest-inputs', 'bootstrap-prepare', 'maintenance-gptbox', 'bootstrap-post-inspect', 'bootstrap-post-status', 'cleanup')


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
    # Preserve existing absolute timer when bounding nested controller work.
    started = time.monotonic()
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    old_end = started + old_timer[0] if old_timer[0] else None
    end = min(started + seconds, old_end or float('inf'))
    require(end > time.monotonic(), 'controller execution budget exhausted')
    def expired(signum, frame):
        raise Blocked('public dependency phase wall-time budget exceeded')
    previous = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, max(.000001, end - time.monotonic()))
        yield
    finally:
        elapsed = time.monotonic() >= end
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if old_end is not None:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, old_end - time.monotonic()), old_timer[1])
        require(not elapsed, 'controller phase wall-time budget exceeded')


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


def verification_evidence(directory, source):
    # Preserve bounded original public crypto evidence before downstream
    # packaging failures or isolated scratch cleanup can remove it.
    receipt_data, _ = public.capture_regular(directory / 'receipt.json', 65536)
    receipt = json.loads(receipt_data, object_pairs_hook=unique_object)
    expected_artifacts = {name: {'bytes': size, 'sha256': sha} for name, (_, size, sha) in public.ARTIFACTS.items()}
    require(type(receipt) is dict and set(receipt) == set(('version kind helper_source_sha exit_status result codex_source_sha codex_binary_sha256 codex_binary_bytes artifacts verification_output_sha256 note').split()),
            'Original verification receipt schema mismatch')
    require(type(receipt.get('version')) is int and receipt.get('version') == 1 and receipt.get('kind') == 'public-codex-verification-receipt' and
            receipt.get('helper_source_sha') == source and type(receipt.get('exit_status')) is int and receipt.get('exit_status') == 0 and receipt.get('result') == 'Verified OK' and
            receipt.get('codex_source_sha') == public.CODEX_SOURCE and receipt.get('codex_binary_sha256') == public.CODEX_SHA and
            receipt.get('artifacts') == expected_artifacts and receipt.get('codex_binary_bytes') == public.CODEX_BYTES and receipt.get('note') == public.VERIFICATION, 'Original public verification receipt identity mismatch')
    bundle, bundle_sha = public.capture_regular(directory / 'codex.sigstore', public.ARTIFACTS['codex.sigstore'][1],
                                               exact_size=public.ARTIFACTS['codex.sigstore'][1])
    require(bundle_sha == public.ARTIFACTS['codex.sigstore'][2], 'Original signature bundle mismatch')
    proof, proof_sha = public.capture_regular(directory / 'cosign-verification.txt', MIB)
    require(proof_sha == receipt['verification_output_sha256'] and b'Verified OK' in proof, 'Original verification output mismatch')
    return {'receipt': receipt, 'bundle_base64': base64.b64encode(bundle).decode(), 'bundle_sha256': bundle_sha,
            'output_base64': base64.b64encode(proof[:32768]).decode(), 'output_sha256': proof_sha,
            'output_bytes': len(proof), 'output_truncated': len(proof) > 32768}


def seed_data(source, inputs, guest_sha):
    validate_inputs(inputs)
    require(inputs['source_sha'] == source and re.fullmatch('[0-9a-f]{64}', guest_sha), 'invalid payload identity')
    # Only public hashes and filenames enter NoCloud; password exists in guest only.
    command = ['/usr/bin/python3', '/run/dev-pair-payload/guest.py', '--source', source,
               '--inputs-json', json.dumps(inputs, sort_keys=True), '--guest-sha256', guest_sha]
    return ('#cloud-config\n'
            'disable_root: true\nssh_pwauth: false\n'
            'bootcmd:\n  - [mkdir, -p, /run/dev-pair-payload]\n'
            '  - [mount, -o, "ro,nosuid,nodev,noexec", "LABEL=DPPAYLOAD", /run/dev-pair-payload]\n'
            'runcmd:\n  - ' + json.dumps(command) + '\n')


def parse_serial(data, expected_source, expected_guest, expected_inputs):
    # Treat serial assertions as candidate-controlled test evidence. Require
    # one complete result, exact identities and every requested phase.
    require(len(data) <= REPORT_FRAME_LIMIT and data.startswith(REPORT_BEGIN) and data.endswith(REPORT_END) and
            data.count(REPORT_BEGIN) == data.count(REPORT_END) == 1, 'missing, partial or ambiguous dedicated Fedora report frame')
    body = data[len(REPORT_BEGIN):-len(REPORT_END)]
    require(0 < len(body) <= REPORT_LIMIT, 'guest result exceeds byte limit')
    def unique(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate guest result field')
            value[key] = item
        return value
    result = json.loads(body, object_pairs_hook=unique)
    require(type(result) is dict and set(result) == {'version', 'source_sha', 'guest_sha256', 'inputs', 'initialization', 'phases', 'identity', 'diagnostics'}, 'invalid guest result shape')
    require(type(result['version']) is int and result['version'] == REPORT_VERSION and
            result['source_sha'] == expected_source and result['guest_sha256'] == expected_guest,
            'guest source/implementation identity mismatch')
    validate_inputs(result['inputs'])
    validate_inputs(expected_inputs)
    require(result['inputs'] == expected_inputs and result['inputs']['source_sha'] == expected_source, 'guest public input identity mismatch')
    require(type(result['identity']) is dict and type(result['diagnostics']) is dict and type(result['initialization']) is dict, 'invalid guest evidence objects')
    required = set(GUEST_PHASES)
    require(type(result['phases']) is dict and set(result['phases']) == required, 'missing guest phases')
    for phase in result['phases'].values():
        require(type(phase) is dict and set(phase) == {'status', 'detail'} and
                phase['status'] in ('pass', 'fail', 'blocked') and type(phase['detail']) is str and
                len(phase['detail']) <= 4000, 'invalid guest phase')
    observed = result['initialization']
    if observed:
        validate_initialization(observed, expected_inputs)
    for name in ('bootstrap-prepare', 'maintenance-gptbox'):
        if result['phases'][name]['status'] == 'pass':
            require(observed.get('source_sha') == expected_source and observed.get('context_sha256') == expected_inputs['context_sha256'] and
                    observed.get('distrobox_sha') == expected_inputs['distrobox_sha'] and observed.get('job_admission') is False and
                    observed.get('prepare') == 'complete' and observed.get('prepared_image_verified') is True and
                    type(observed.get('packages_sha256')) is str and observed.get('package_count', 0) > 0 and
                    type(observed.get('prepared_image_id')) is str and re.fullmatch('[0-9a-f]{64}', observed['prepared_image_id']), 'missing matching actual preparation evidence')
            if name == 'maintenance-gptbox':
                require(observed.get('exit_status') == 0 and observed.get('phase') == 'complete' and
                        observed.get('maintenance_gptbox') == 'complete' and observed.get('assembled_image_verified') is True and
                        observed.get('boundary_and_version_cycles') == 2 and observed.get('runtime_container_removed') is True and
                        type(observed.get('assembled_image_id')) is str and re.fullmatch('[0-9a-f]{64}', observed['assembled_image_id']), 'missing matching actual assembly evidence')
    return result


def report_witness(data, overflow=False):
    complete = (not overflow and 0 < len(data) - len(REPORT_BEGIN) - len(REPORT_END) <= REPORT_LIMIT and
                data.startswith(REPORT_BEGIN) and data.endswith(REPORT_END) and
                data.count(REPORT_BEGIN) == data.count(REPORT_END) == 1)
    return {'retained_bytes': len(data), 'sha256': sha256(data), 'overflow': overflow,
            'framing_complete': complete,
            'frame_limit_bytes': REPORT_FRAME_LIMIT, 'begin_markers': data.count(REPORT_BEGIN),
            'end_markers': data.count(REPORT_END), 'starts_with_begin': data.startswith(REPORT_BEGIN),
            'ends_with_end': data.endswith(REPORT_END), 'head_hex': data[:128].hex(), 'tail_hex': data[-128:].hex(),
            'retained_base64': base64.b64encode(data).decode('ascii')}


class ReportPipe:
    """One controller-owned pipe pair; QEMU must never fall back to base."""
    def __init__(self, directory):
        self.directory = directory
        self.base = directory / 'result'
        self.reader = self.keeper = None
        self.paths = {}
        self.data = bytearray()
        self.overflow = False

    def __enter__(self):
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not self.directory.is_symlink() and info.st_uid == os.getuid() and
                not info.st_mode & 0o022, 'report pipe directory must be owned and protected')
        require(not os.path.lexists(self.base), 'QEMU report fallback base must be absent')
        try:
            for suffix in ('.in', '.out'):
                path = pathlib.Path(str(self.base) + suffix)
                os.mkfifo(path, 0o600)
                info = path.lstat()
                self.paths[path] = (info.st_dev, info.st_ino)
                require(stat.S_ISFIFO(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                        'report pipe must be owned nonsymlink FIFO0600')
            output = pathlib.Path(str(self.base) + '.out')
            self.reader = os.open(output, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            self.keeper = os.open(output, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            for fd in (self.reader, self.keeper):
                info = os.fstat(fd)
                require(stat.S_ISFIFO(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                        (info.st_dev, info.st_ino) == self.paths[output], 'report pipe changed while opening')
            require(not os.path.lexists(self.base), 'QEMU report fallback base appeared')
            return self
        except BaseException:
            self.close()
            raise

    def release_keeper(self):
        if self.keeper is not None:
            os.close(self.keeper)
            self.keeper = None

    def close(self):
        self.release_keeper()
        if self.reader is not None:
            os.close(self.reader)
            self.reader = None
        for path, identity in self.paths.items():
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISFIFO(info.st_mode) and (info.st_dev, info.st_ino) == identity:
                path.unlink()

    def __exit__(self, *args):
        self.close()


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
        self.report = {'version': REPORT_VERSION, 'source_sha': source, 'executor': 'public-standard-ubuntu-24.04/Fedora44-QEMU',
                       'controller_sha256': file_hash(pathlib.Path(__file__)),
                       'workflow_sha256': file_hash(self.repo / '.github/workflows/fedora-vm.yml'),
                       'phases': {name: {'status': 'blocked', 'detail': 'Not reached'} for name in PHASES},
                       'limits': {'overlay_bytes': OVERLAY_LIMIT, 'host_reserve_bytes': HOST_RESERVE,
                                  'overhead_bytes': OVERHEAD_LIMIT, 'log_bytes': LOG_LIMIT,
                                  'storage_diagnostic_bytes': DU_CAPTURE_LIMIT,
                                  'report_json_bytes': REPORT_LIMIT, 'report_frame_bytes': REPORT_FRAME_LIMIT,
                                  'report_write_seconds': REPORT_WRITE_SECONDS,
                                  'container_seconds': CONTAINER_SECONDS, 'vm_container_seconds': VM_CONTAINER_SECONDS, 'guest_virtual_bytes': VIRTUAL_BYTES,
                                  'controller_seconds': CONTROLLER_SECONDS, 'public_seconds': PUBLIC_SECONDS, 'vm_seconds': VM_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
                                  'cpus': 3, 'memory_bytes': 8 * GIB, 'guest_cpus': 2, 'guest_memory_bytes': 6 * GIB},
                       'hostinger_acceptance': False, 'job_admission': False}
        self.podman = ['sudo', '-n', '/usr/bin/podman', '--root=' + str(root / 'graph'),
                       '--runroot=' + str(root / 'runroot'), '--tmpdir=' + str(root / 'tmp'),
                       '--hooks-dir=' + str(root / 'empty-hooks'),
                       '--storage-driver=overlay']
        self.container = 'dp-fedora-probe-' + root.name.rsplit('-', 1)[-1]
        self.log_used = 0
        self.phase_end = None

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

    def bounded(self, argv, timeout, name, disk_check=True, file_limit=None, report_pipe=None, observe_network=False):
        """Bound logs/time and watch storage while a native child runs."""
        if self.phase_end is not None:
            timeout = min(timeout, self.phase_end - time.monotonic())
        require(timeout > 0, name + ' phase execution budget exhausted')
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
        selector.register(process.stdout, selectors.EVENT_READ, 'console')
        if report_pipe is not None:
            selector.register(report_pipe.reader, selectors.EVENT_READ, 'report')
        exited = None
        next_storage = 0
        network_observed = not observe_network
        try:
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                require(now - started < timeout, name + ' deadline exceeded')
                if not network_observed and now - started > 1:
                    self.observe_vm_network()
                    network_observed = True
                if process.poll() is not None and exited is None:
                    exited = now
                    if report_pipe is not None:
                        report_pipe.release_keeper()
                if disk_check and exited is None and now >= next_storage:
                    check_capacity(self.root)
                    # Rootful Podman owns private storage directories. Measure
                    # via a fixed read-only privileged tool, never silently skip
                    # inaccessible files in an unprivileged os.walk.
                    measurement = self.storage_measurement(live=True)
                    if measurement['provisional']:
                        self.report['provisional_storage_samples'] = self.report.get('provisional_storage_samples', 0) + 1
                    next_storage = time.monotonic() + 1
                events = selector.select(timeout=.1 if report_pipe is not None else 1)
                for key, _ in events:
                    maximum = min(65536, max(1, LOG_LIMIT - self.log_used + 1))
                    if key.data == 'report':
                        maximum = min(maximum, REPORT_FRAME_LIMIT - len(report_pipe.data) + 1)
                    descriptor = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
                    try:
                        data = os.read(descriptor, maximum)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    self.log_used += len(data)
                    if key.data == 'report':
                        report_pipe.data.extend(data)
                        report_pipe.overflow = len(report_pipe.data) > REPORT_FRAME_LIMIT
                        require(not report_pipe.overflow, 'dedicated report frame byte limit exceeded (truncated)')
                    require(self.log_used <= LOG_LIMIT, 'aggregate diagnostic byte limit exceeded (truncated)')
                    if key.data == 'console':
                        log.extend(data)
                # Executor completion, not FIFO EOF, bounds final draining. A
                # held writer cannot keep this controller alive indefinitely.
                if report_pipe is not None and exited is not None and time.monotonic() - exited >= 1:
                    break
            process.wait(timeout=5)
            require(network_observed, 'VM exited before its actual network isolation could be inspected')
            require(process.returncode == 0, name + ' failed with exit ' + str(process.returncode))
            if disk_check:
                check_capacity(self.root)
                self.report['last_stable_overhead_bytes'] = self.storage_measurement()['bytes']
            return (bytes(log), bytes(report_pipe.data)) if report_pipe is not None else bytes(log)
        except BaseException:
            # Podman/conmon scopes may outlive the CLI; cleanup also force-removes
            # only our named container. Native --timeout limits the VM itself.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            process.wait(timeout=5)
            emit_text('', bytes(log), 12000)
            raise
        finally:
            selector.close()
            process.stdout.close()
            if report_pipe is not None:
                report_pipe.release_keeper()
                self.report['dedicated_report_witness'] = report_witness(bytes(report_pipe.data), report_pipe.overflow)
                self.report['dedicated_report_witness']['aggregate_limit_exceeded'] = self.log_used > LOG_LIMIT
                self.report['dedicated_report_witness']['executor_exit_status'] = process.poll()
                # Native container timeout/removal covers root conmon scopes;
                # local unprivileged descendant writers are killed here too.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

    def helper(self, args, timeout=60, **kwargs):
        self.engine_activity = True  # version-only preflight never starts resources
        return self.bounded(self.podman + args, timeout, 'tooling command', **kwargs)

    def run_args(self, entrypoint, mounts=True, vm=False):
        args = ['run', '--rm', '--name=' + self.container, '--timeout=' + str(VM_CONTAINER_SECONDS if vm else CONTAINER_SECONDS),
                '--restart=no', '--network=' + ('slirp4netns:allow_host_loopback=false' if vm else 'none'), '--read-only', '--read-only-tmpfs=false',
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
                        '/usr/bin/timeout', '/usr/bin/du', '/usr/bin/slirp4netns'):
            require(pathlib.Path(command).is_file(), 'required preinstalled runner tool unavailable: ' + command)
        require(os.cpu_count() >= 2, 'at least two CPUs required')
        mem = int(re.search(r'^MemTotal:\s+(\d+) kB$', pathlib.Path('/proc/meminfo').read_text(), re.M)[1]) * 1024
        require(mem >= 10 * GIB, 'insufficient runner memory')
        free = check_capacity(self.root, before_boot=True)
        require(free >= HOST_RESERVE + OVERLAY_LIMIT + OVERHEAD_LIMIT, 'capacity blocked:23GiB initial disk budget required')
        slirp_version = run_small(['/usr/bin/slirp4netns', '--version'], timeout=5).decode()
        require('slirp4netns' in slirp_version, 'preinstalled slirp implementation unavailable')
        version = run_small(self.podman + ['version', '--format=json']).decode()
        self.report['runner'] = {'kernel': os.uname().release, 'image_version': os.environ.get('ImageVersion', 'unreported'),
                                 'podman': json.loads(version), 'slirp_version': evidence_tail(slirp_version, 1000), 'free_bytes': free, 'memory_bytes': mem,
                                 'merge_sha': os.environ.get('DP_MERGE_SOURCE', 'unreported'),
                                 'scratch_device': self.scratch_identity[0], 'scratch_root': str(self.root)}
        self.phase('runner-preflight', 'pass', 'Actual standard-runner OS/source/tools/capacity checked; no host packages installed')

    def inputs(self):
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
        helper = self.repo / 'tools/public_inputs.py'
        cache = self.root / 'public-cache'
        handoff = self.root / 'public-handoff'
        self.bounded([sys.executable, str(helper), 'fetch', '--output', str(cache)], PUBLIC_SECONDS, 'fixed public input download')
        try:
            output = self.bounded([sys.executable, str(helper), 'build', '--cache', str(cache),
                                  '--distrobox-source', str(cache / 'distrobox'), '--output', str(handoff)], PUBLIC_SECONDS, 'strict public input verification/build')
        finally:
            if (handoff / 'verification/receipt.json').exists():
                self.report['input_verification'] = verification_evidence(handoff / 'verification', self.source)
        produced = json.loads(output)
        manifest_data, manifest_sha = public.capture_regular(handoff / 'manifest.json', public.MANIFEST_LIMIT)
        record = public.parse_manifest(manifest_data, manifest_sha, produced['manifest_sha256'])
        require(record['source_sha'] == self.source and produced['source_sha'] == self.source and
                produced['context_sha256'] == record['context_sha256'] and produced['payload_sha256'] == record['payload']['sha256'],
                'Public producer target differs from exact checked out candidate')
        self.handoff = {'source_sha': self.source, 'helper_sha256': file_hash(helper), 'manifest_sha256': manifest_sha,
                        'payload_sha256': record['payload']['sha256'], 'payload_bytes': record['payload']['bytes'],
                        'context_sha256': record['context_sha256'], 'distrobox_sha': record['distrobox_sha'],
                        'standards_sha': record['standards_sha'], 'codex_sha256': public.CODEX_SHA, 'codex_source_sha': public.CODEX_SOURCE}
        validate_inputs(self.handoff)
        for name in ('manifest.json', 'maintenance-inputs.tar.gz'):
            shutil.copyfile(handoff / name, payload / name)
            (payload / name).chmod(0o444)
        shutil.copyfile(helper, payload / 'public_inputs.py')
        (payload / 'public_inputs.py').chmod(0o444)
        require(file_hash(payload / 'maintenance-inputs.tar.gz') == record['payload']['sha256'] and
                (payload / 'maintenance-inputs.tar.gz').stat().st_size == record['payload']['bytes'], 'Payload copy identity mismatch')
        receipt = json.loads((handoff / 'verification/receipt.json').read_text())
        self.report['public_inputs'] = {**self.handoff, 'verification_receipt': receipt}
        seed = self.root / 'seed'
        seed.mkdir()
        (seed / 'user-data').write_text(seed_data(self.source, self.handoff, self.guest_sha))
        (seed / 'meta-data').write_text('instance-id: dev-pair-' + self.source + '\nlocal-hostname: fedora-ci\n')
        # Only these reviewed public payload files reach the VM, never runner
        # environment, worktree .git metadata/config, credentials or private rules.
        self.helper(self.run_args('/usr/bin/genisoimage') + ['--volume=' + str(seed) + ':/seed:ro', self.image,
                    '-quiet', '-output', '/disks/seed.iso', '-volid', 'cidata', '-joliet', '-rock', '/seed'])
        # Base disk is excluded from the source ISO to avoid duplication.
        self.helper(self.run_args('/usr/bin/genisoimage') + [self.image, '-quiet', '-output', '/disks/payload.iso',
                    '-volid', 'DPPAYLOAD', '-joliet', '-rock', '-graft-points',
                    'guest.py=/payload/guest.py', 'public_inputs.py=/payload/public_inputs.py',
                    'manifest.json=/payload/manifest.json', 'maintenance-inputs.tar.gz=/payload/maintenance-inputs.tar.gz'])
        base_info = json.loads(self.helper(self.run_args('/usr/bin/qemu-img') +
                                          [self.image, 'info', '--output=json', '/payload/base.qcow2']))
        require(base_info.get('format') == 'qcow2' and not base_info.get('backing-filename') and
                0 < base_info.get('virtual-size', 0) <= VIRTUAL_BYTES, 'signed base disk layout exceeds declared scope')
        self.report['cloud_image']['virtual_bytes'] = base_info['virtual-size']
        self.helper(self.run_args('/usr/bin/qemu-img') + [self.image, 'create', '-f', 'qcow2', '-F', 'qcow2',
                    '-b', '/payload/base.qcow2', '/disks/guest.qcow2', '32G'])
        self.report['payload'] = {'source_sha': self.source, 'guest_sha256': self.guest_sha,
                                  'inputs': self.handoff}
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
        args = self.run_args('/usr/bin/python3', vm=True)
        if accel == 'kvm':
            args += ['--device=/dev/kvm', '--group-add=' + str(pathlib.Path('/dev/kvm').stat().st_gid)]
        args += [self.image, '/usr/local/bin/dp-qemu-entry.py', '-machine', 'q35,accel=' + accel,
                 '-cpu', 'host' if accel == 'kvm' else 'max', '-smp', '2', '-m', '6144',
                 '-display', 'none', '-serial', 'stdio', '-serial', 'pipe:/disks/result', '-monitor', 'none', '-no-reboot',
                 '-nic', 'user,model=virtio-net-pci,ipv6=off', '-drive', 'file=/disks/guest.qcow2,if=virtio,format=qcow2,cache=none',
                 '-drive', 'file=/disks/seed.iso,media=cdrom,readonly=on,format=raw',
                 '-drive', 'file=/disks/payload.iso,media=cdrom,readonly=on,format=raw']
        with ReportPipe(self.root / 'disks') as report_pipe:
            console, report_data = self.helper(args, timeout=VM_SECONDS, report_pipe=report_pipe, observe_network=True)
        emit_text('DP_SERIAL_TAIL\n', console, 24000)
        guest = parse_serial(report_data, self.source, self.guest_sha, self.handoff)
        self.report['guest'] = guest
        self.phase('fedora-boot', 'pass', 'Real signed Fedora Cloud image booted and emitted a complete candidate-bound serial result using ' + accel)
        for name, phase in guest['phases'].items():
            self.phase(name, phase['status'], phase['detail'])

    def observe_vm_network(self):
        data = run_small(self.podman + ['inspect', '--type=container', self.container], timeout=5)
        rows = json.loads(data)
        require(type(rows) is list and len(rows) == 1, 'Owned VM network inspection unavailable')
        row = rows[0]
        host = row['HostConfig']
        require(host.get('NetworkMode') in ('slirp4netns', 'slirp4netns:allow_host_loopback=false') and
                not host.get('PortBindings') and not row.get('NetworkSettings', {}).get('Ports') and not host.get('Privileged'),
                'Actual VM network/port isolation mismatch')
        pid = row['State']['Pid']
        require(type(pid) is int and pid > 1, 'Owned VM process unavailable for namespace observation')
        namespace = run_small(['sudo', '-n', '/usr/bin/readlink', '/proc/' + str(pid) + '/ns/net'], timeout=5).decode().strip()
        require(namespace and namespace != os.readlink('/proc/self/ns/net'), 'VM tooling shares runner network namespace')
        self.report['network'] = {'mode': host['NetworkMode'], 'requested': 'slirp4netns:allow_host_loopback=false', 'published_ports': 'none', 'namespace': namespace,
                                  'runner_namespace': os.readlink('/proc/self/ns/net'),
                                  'qemu': 'IPv4 usernet; no forwarding', 'destination_acl': False}

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
        execution_started = time.monotonic()
        try:
            self.phase_end = execution_started + PUBLIC_SECONDS
            with deadline(PUBLIC_SECONDS):
                self.initialize_directories()
                self.preflight()
                for active, action in (('signed-cloud-image', self.inputs), ('tooling', self.tooling), ('source-payload', self.payload)):
                    action()
            active = 'fedora-boot'
            self.phase_end = min(execution_started + CONTROLLER_SECONDS - CLEANUP_SECONDS, time.monotonic() + VM_SECONDS)
            with deadline(self.phase_end - time.monotonic()):
                self.boot()
        except (Blocked, OSError, ValueError, subprocess.SubprocessError) as exc:
            self.report['blocker'] = evidence_tail(exc, 4000)
            self.phase(active, 'blocked', self.report['blocker'])
            emit_text('DP_BLOCKED ', self.report['blocker'], 4000)
        finally:
            try:
                self.phase_end = None
                with deadline(min(CLEANUP_SECONDS, max(.001, execution_started + CONTROLLER_SECONDS - time.monotonic()))):
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
        # Passing is exact-candidate disposable VM component evidence only.
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
