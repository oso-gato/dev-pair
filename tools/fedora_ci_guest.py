#!/usr/bin/env python3
"""Read-only Fedora VM baseline probe, launched by NoCloud without credentials."""
import argparse
import array
import fcntl
import hashlib
import json
import os
import pathlib
import platform
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


def command(argv, timeout=30):
    code, output = capture(argv, timeout)
    require(code == 0, 'Command exit ' + str(code) + ': ' + safe_text(output))
    return output


def capture(argv, timeout=15, maximum=65536):
    started = time.monotonic()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=SAFE_ENV, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    try:
        while selector.get_map():
            require(time.monotonic() - started <= timeout, 'Guest diagnostic command deadline exceeded')
            for key, _ in selector.select(timeout=.25):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                require(len(output) + len(data) <= maximum, 'Guest diagnostic command exceeded byte limit (truncated)')
                output.extend(data)
        return process.wait(timeout=5), bytes(output)
    finally:
        if process.poll() is None:
            import signal
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        selector.close()
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


def diagnostics():
    observed = {}
    for name, argv in (
            ('startup_errors', ['/usr/bin/journalctl', '-b', '-p', 'err', '--no-pager', '-n', '30']),
            ('selinux_avcs', ['/usr/sbin/ausearch', '-m', 'AVC,USER_AVC', '-ts', 'boot', '--raw']),
            ('rpm_baseline', ['/usr/bin/rpm', '-q', 'kernel-core', 'selinux-policy-targeted', 'systemd', 'cloud-init', 'podman'])):
        try:
            code, output = capture(argv, timeout=15)
            observed[name] = {'exit_status': code, 'tail': safe_text(output, 3000)}
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            observed[name] = {'status': 'unavailable', 'detail': safe_text(exc, 500)}
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--bundle-sha256', required=True)
    parser.add_argument('--guest-sha256', required=True)
    args = parser.parse_args()
    phases = {name: {'status': 'blocked', 'detail': 'Prerequisite not completed'} for name in
              ('fedora-preflight', 'bootstrap-inspect', 'bootstrap-status', 'bootstrap-prepare', 'maintenance-gptbox')}
    report = {'version': 1, 'source_sha': args.source, 'guest_sha256': args.guest_sha256,
              'phases': phases, 'identity': {}, 'diagnostics': {}}
    try:
        payload = pathlib.Path('/run/dev-pair-payload')
        require(digest(pathlib.Path(__file__)) == args.guest_sha256, 'Executing guest script identity mismatch')
        source = stage_source(payload, pathlib.Path('/root/dev-pair-ci-staging'), args.archive_sha256, args.bundle_sha256)
        report['identity'] = baseline()
        require(report['identity']['root_free_bytes'] >= 8 * 1024 ** 3,
                'Guest capacity below the unchanged 8GiB preparation/assembly reserve')
        phases['fedora-preflight'] = {'status': 'pass', 'detail': 'Actual Fedora44 kernel, enforcing policy, systemd PID1, cgroup v2 and handoff bytes verified'}
        for phase, stage in (('bootstrap-inspect', 'inspect'), ('bootstrap-status', 'status')):
            try:
                output = command(['/usr/bin/python3', str(source / 'tools/bootstrap.py'), stage])
                observed = json.loads(output)
                phases[phase] = {'status': 'pass', 'detail': 'Actual read-only bootstrap ' + stage + ': ' + safe_text(json.dumps(observed), 3000)}
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                phases[phase] = {'status': 'blocked', 'detail': safe_text(exc)}
        phases['bootstrap-prepare'] = {'status': 'blocked', 'detail': 'First route checkpoint: verified Codex/Cosign and Distrobox payload plus bounded signed-package provisioning not yet implemented; no console password generated or preparation attempted'}
        phases['maintenance-gptbox'] = {'status': 'blocked', 'detail': 'Requires real bootstrap prepare and separately verified inputs; no fixture, model call, relaxed 8GiB reserve or enlarged 900s assembly/180s runtime limit substituted'}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        phases['fedora-preflight'] = {'status': 'blocked', 'detail': safe_text(exc)}
    finally:
        report['diagnostics'] = diagnostics()
        # ttyS0 remains diagnostic console only. Failed dedicated delivery has
        # no console fallback and cannot become a passing controller report.
        try:
            write_report(report)
        finally:
            subprocess.run(['/usr/bin/systemctl', 'poweroff', '--no-block'], env=SAFE_ENV, timeout=10)


if __name__ == '__main__':
    main()
