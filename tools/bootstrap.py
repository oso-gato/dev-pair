#!/usr/bin/python3
"""Explicit Fedora Cloud 44 host preparation; never launches submitted code or apps."""
import argparse
import base64
import contextlib
import contextvars
import fcntl
import hashlib
import http.client
import ipaddress
import importlib.util
import shutil
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
SOURCE_BASELINE = '4dcf92e256a49770ddd89e4420b105319885910f'
STATE = '/var/lib/dev-pair/bootstrap'
PACKAGES = ('podman', 'distrobox', 'passt', 'fuse-overlayfs', 'container-selinux',
            'policycoreutils', 'shadow-utils', 'sudo', 'openssh-server', 'nftables', 'git-core', 'util-linux',
            'mosh', 'tmux', 'chrony', 'slirp4netns')
REPO = '''[tailscale-stable]
name=Tailscale stable
baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=1
gpgkey=https://pkgs.tailscale.com/stable/fedora/repo.gpg
'''
GUARD = '''# dev-pair bootstrap v1; owns only this table, never flushes other rules
add table inet dev_pair_bootstrap
flush table inet dev_pair_bootstrap
add chain inet dev_pair_bootstrap input { type filter hook input priority -10; policy drop; }
add rule inet dev_pair_bootstrap input iifname != "tailscale0" udp dport 60000-61000 drop
add rule inet dev_pair_bootstrap input ct state established,related accept
add rule inet dev_pair_bootstrap input iifname "lo" accept
add rule inet dev_pair_bootstrap input iifname "tailscale0" tcp dport 22 accept
add rule inet dev_pair_bootstrap input iifname "tailscale0" udp dport 60000-61000 accept
{bootstrap_rules}
add rule inet dev_pair_bootstrap input udp dport 41641 accept
add rule inet dev_pair_bootstrap input meta l4proto { icmp, ipv6-icmp } accept
add rule inet dev_pair_bootstrap input udp sport 67 udp dport 68 accept
add rule inet dev_pair_bootstrap input udp sport 547 udp dport 546 accept
add chain inet dev_pair_bootstrap forward { type filter hook forward priority -10; policy drop; }
'''
UNIT = '''[Unit]
Description=Dev-pair temporary bootstrap ingress guard
Before=tailscaled.service sshd.service
After=local-fs.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/dev-pair/bootstrap.nft
[Install]
WantedBy=multi-user.target
'''
TAILSCALE_UNIT = '''[Unit]
Requires=dev-pair-bootstrap-guard.service
After=dev-pair-bootstrap-guard.service
'''

# Only Bash's interactive profile path enters tmux. Remote commands, scp/sftp and
# mosh's SSH startup run noninteractive shells and must retain their protocol.
OPERATOR_PROFILE = """# dev-pair core reconnect; installed by authorized bootstrap
case $- in
  *i*)
    if [ "$(/usr/bin/id -un)" = core ] && [ -z "${TMUX:-}" ] && [ -t 0 ] && [ -t 1 ]; then
        exec /usr/bin/tmux new-session -A -s dev-pair-core
    fi
    ;;
esac
"""
KEYS_URL = 'https://github.com/oso-gato.keys'
KEYS_MAX_BYTES = 262144
KEYS_FETCH_TIMEOUT = 25
KEYS_FETCH_ATTEMPTS = 3

class Blocked(Exception):
    pass

_PHASE_DEADLINE = contextvars.ContextVar('dev_pair_phase_deadline', default=None)


class Commands:
    """Bounded execution with secret-safe, explicitly public diagnostics."""
    deadline = None
    native_prefix = None
    diagnostic = None
    metadata_diagnostic = None
    native_register = None
    _cleanup_deadline = None
    current_step = 'unscoped'

    def execution_deadline(self):
        # Explicit cleanup controls are finite and may run after an execution
        # deadline; ordinary fresh runners always inherit the enclosing phase.
        if self._cleanup_deadline is not None:
            return self._cleanup_deadline
        return min((value for value in (self.deadline, _PHASE_DEADLINE.get()) if value is not None), default=None)

    def limit_timeout(self, timeout):
        deadline = self.execution_deadline()
        remaining = timeout if deadline is None else min(timeout, deadline - time.monotonic())
        if remaining <= 0:
            raise Blocked('phase execution budget exhausted')
        return remaining

    @contextlib.contextmanager
    def phase(self, seconds, prefix, native=True):
        previous = self.deadline, self.native_prefix
        started = time.monotonic()
        old_timer = signal.getitimer(signal.ITIMER_REAL)
        old_timer_deadline = started + old_timer[0] if old_timer[0] else None
        phase_deadline = min(started + seconds, self.execution_deadline() or float('inf'),
                             old_timer_deadline or float('inf'))
        remaining = phase_deadline - time.monotonic()
        if remaining <= 0:
            raise Blocked('phase execution budget exhausted')
        def expired(signum, frame):
            raise Blocked('phase execution budget exhausted')
        old_handler = signal.getsignal(signal.SIGALRM)
        token = None
        try:
            signal.signal(signal.SIGALRM, expired)
            token = _PHASE_DEADLINE.set(phase_deadline)
            self.deadline = phase_deadline
            self.native_prefix = prefix + '-' + uuid.uuid4().hex[:8] if native else None
            signal.setitimer(signal.ITIMER_REAL, remaining)
            yield
        finally:
            elapsed = time.monotonic() >= phase_deadline
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.deadline, self.native_prefix = previous
            if token is not None:
                _PHASE_DEADLINE.reset(token)
            signal.signal(signal.SIGALRM, old_handler)
            if old_timer_deadline is not None:
                # Restore the absolute deadline, never a fresh outer duration.
                signal.setitimer(signal.ITIMER_REAL, max(.000001, old_timer_deadline - time.monotonic()), old_timer[1])
            if elapsed:
                raise Blocked('phase execution budget exhausted')

    @staticmethod
    def public_operation(args):
        if args == ('/usr/sbin/getenforce',):
            return 'selinux-enforcement'
        if (len(args) == 7 and args[:2] == ('/usr/bin/systemctl', 'show') and args[-1] == 'systemd-resolved.service' and
                set(args[2:-1]) == {'--property=MainPID', '--property=User', '--property=ActiveState', '--property=LoadState'}):
            return 'resolved-service-identity'
        if args and args[0] == '/usr/bin/dnf':
            return 'signed-packages'
        if args and args[0] == '/usr/bin/systemd-run' and '/usr/bin/podman' in args:
            operation = args[args.index('/usr/bin/podman') + 1:]
            if 'pull' in operation or 'build' in operation:
                return 'candidate-image'
        return None

    @staticmethod
    def operation_id(args):
        # IDs are fixed enums; never echo argv, paths or environment.
        if args == ('/usr/sbin/getenforce',):
            return 'selinux-enforcement'
        if (len(args) == 7 and args[:2] == ('/usr/bin/systemctl', 'show') and args[-1] == 'systemd-resolved.service' and
                set(args[2:-1]) == {'--property=MainPID', '--property=User', '--property=ActiveState', '--property=LoadState'}):
            return 'resolved-service-identity'
        fixed = {'/usr/bin/git': 'source-git-read', '/usr/bin/dnf': 'signed-packages',
                 '/usr/bin/ss': 'listener-inventory', '/usr/sbin/nft': 'firewall-control',
                 '/usr/bin/hostnamectl': 'host-identity', '/usr/bin/chronyc': 'time-status',
                 '/usr/bin/rpm': 'package-inventory', '/usr/sbin/chpasswd': 'operator-password'}
        if args and args[0] == '/usr/sbin/sshd':
            return 'sshd-effective' if '-T' in args else 'sshd-validation'
        if args and args[0] == '/usr/bin/systemctl':
            return {'is-active': 'service-active', 'show': 'service-properties', 'restart': 'service-restart',
                    'start': 'service-start', 'enable': 'service-enable', 'daemon-reload': 'service-reload',
                    'reload': 'service-reload', 'stop': 'service-stop'}.get(args[1] if len(args) > 1 else '', 'service-control')
        if args and args[0] == '/usr/bin/systemd-run':
            return 'candidate-native-executor'
        return fixed.get(args[0] if args else '', 'withheld-operation')

    @staticmethod
    def native_diagnostic(args):
        unit = next((value[7:] for value in args if value.startswith('--unit=')), None)
        description = next((value[14:] for value in args if value.startswith('--description=')), None)
        if not unit or description != 'dev-pair-owned-' + unit:
            return {'availability': 'not-controller-owned-or-not-native'}
        if not re.fullmatch(r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}(?:\.service)?)', unit):
            return {'availability': 'unrecognized-controller-unit'}
        control = Commands()
        control._cleanup_deadline = time.monotonic() + 2
        properties = ('Description', 'LoadState', 'ActiveState', 'Result', 'ExecMainCode', 'ExecMainStatus', 'StatusErrno')
        try:
            text = control('/usr/bin/systemctl', 'show', *('--property=' + key for key in properties), unit,
                           ok=(0, 1, 4), timeout=2)
            values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
            if values.get('LoadState') == 'not-found':
                return {'availability': 'unavailable-collected-or-not-started', 'unit': unit}
            if values.get('Description') != description:
                return {'availability': 'ownership-unverified', 'unit': unit}
            return {'availability': 'observed', 'unit': unit, **{key: values.get(key, 'unavailable')[:80] for key in properties if key != 'Description'}}
        except (Blocked, OSError, ValueError, subprocess.SubprocessError):
            return {'availability': 'observation-failed', 'unit': unit}

    @staticmethod
    def native_args(args, timeout):
        rewritten = []
        for value in args:
            if value.startswith('--property=RuntimeMaxSec='):
                current = value.rsplit('=', 1)[1].removesuffix('s')
                if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', current):
                    raise Blocked('invalid native lifetime')
                ceiling = min(float(current), timeout)
                if ceiling < .001:
                    raise Blocked('native execution budget exhausted; zero disables systemd lifetime')
                value = '--property=RuntimeMaxSec=%.3fs' % (int(ceiling * 1000) / 1000)
            rewritten.append(value)
        return tuple(rewritten)

    @staticmethod
    def reconcile_native(args, env):
        # Only fixed controller-created descriptions permit exact-unit cleanup.
        unit = next((v[7:] for v in args if v.startswith('--unit=')), None)
        description = next((v[14:] for v in args if v.startswith('--description=')), None)
        if not unit or description != 'dev-pair-owned-' + unit:
            return
        # A separate bounded runner has no phase/native wrapper or diagnostic
        # callback: cleanup observations cannot recursively launch more units.
        control = Commands()
        control._cleanup_deadline = time.monotonic() + 20
        observed = control('/usr/bin/systemctl', 'show', '--property=Description', '--property=ActiveState',
                           '--property=LoadState', '--property=User', unit, ok=(0, 1, 4), timeout=5)
        values = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
        if values.get('ActiveState') in ('active', 'activating', 'deactivating', 'reloading'):
            expected_user = next((v[6:] for v in args if v.startswith('--uid=')), '')
            if values.get('Description') != description or values.get('User', '') not in ((expected_user,) if expected_user else ('', 'root')):
                raise Blocked('native unit ownership mismatch; foreign unit preserved')
            control('/usr/bin/systemctl', 'stop', unit, timeout=10)
            after = control('/usr/bin/systemctl', 'show', '--property=ActiveState', '--property=LoadState',
                            unit, ok=(0, 1, 4), timeout=5)
            states = dict(line.split('=', 1) for line in after.splitlines() if '=' in line)
            if states.get('ActiveState') not in ('inactive', 'failed'):
                raise Blocked('native unit remains unresolved; no duplicate effects')
        elif values.get('ActiveState') not in ('inactive', 'failed'):
            raise Blocked('native unit observation failed; no duplicate effects')

    def interrupt(self, process, args, env):
        # A reaped/exited launcher still owns its session's process group, and
        # the exact native unit can outlive that launcher independently.
        failed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            failed = True
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            failed = True
        try:
            self.reconcile_native(args, env)
        except (Blocked, OSError, subprocess.SubprocessError):
            failed = True
        if failed:
            raise Blocked('native cleanup unresolved; retained ownership record and finite lifetime')

    def __call__(self, *args, ok=(0,), input_text=None, timeout=900):
        timeout = self.limit_timeout(timeout)
        original = args
        public = self.public_operation(args) if input_text is None else None
        unit = None
        description = None
        # Existing user transient units are already native executors. Tighten
        # their ceilings rather than putting them outside the phase budget.
        if args and args[0] == '/usr/bin/systemd-run':
            args = self.native_args(args, timeout)
        elif self.native_prefix:
            if timeout < .001:
                raise Blocked('native execution budget exhausted')
            unit = self.native_prefix + '-' + uuid.uuid4().hex[:8]
            description = 'dev-pair-owned-' + unit
            if self.native_register:
                self.native_register(unit)
            args = ('/usr/bin/systemd-run', '--unit=' + unit, '--description=' + description,
                    '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
                    '--property=RuntimeMaxSec=%.3fs' % (int(timeout * 1000) / 1000), '--property=TimeoutStopSec=5',
                    '--property=KillMode=control-group', '--property=MemoryMax=2G',
                    '--property=TasksMax=512', '--property=CPUQuota=100%',
                    '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin', 'LANG=C', 'LC_ALL=C', 'HOME=/root', *args)
        env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
        started = time.monotonic()
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        total = 0
        status = 'not-started'
        process = None
        completed = False
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(args, env=env, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            status = 'running'
            stdin_data = input_text.encode() if input_text is not None else b''
            stdin_offset = 0
            if input_text is not None:
                # Nonblocking stdin shares the command deadline even if a child
                # never reads. UTF-8 passwords can exceed one PIPE_BUF.
                if len(stdin_data) > 16384:
                    raise Blocked('stdin byte budget exceeded; output withheld')
                if stdin_data:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
                else:
                    process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map() or process.poll() is None:
                if time.monotonic() - started >= timeout:
                    raise Blocked('command deadline exceeded; output withheld')
                for key, _ in selector.select(timeout=.1):
                    if key.data == 'stdin':
                        try:
                            stdin_offset += os.write(key.fileobj.fileno(), stdin_data[stdin_offset:stdin_offset + 4096])
                        except BlockingIOError:
                            continue
                        if stdin_offset == len(stdin_data):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                        continue
                    block = os.read(key.fileobj.fileno(), min(8192, 1048576 - total + 1))
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(block)
                    if total > 1048576:
                        raise Blocked('command output byte budget exceeded; output withheld')
                    if input_text is None:
                        buffers[key.data].extend(block)
            status = process.wait(timeout=1)
            if time.monotonic() - started >= timeout:
                raise Blocked('command deadline exceeded; output withheld')
            self.limit_timeout(timeout)
            if status not in ok:
                raise Blocked('%s failed (exit %s; output withheld)' % (Path(original[0]).name, status))
            result = bytes(buffers['stdout']).decode() if input_text is None else ''
            completed = True
            return result
        except (OSError, subprocess.SubprocessError):
            status = 'failed-or-timed-out'
            raise Blocked('command failed or timed out; output withheld') from None
        except BaseException:
            if status == 'running' or (not completed and status in ok):
                status = 'interrupted-or-failed'
            raise
        finally:
            cleanup_error = None
            if process is not None and not completed:
                try:
                    self.interrupt(process, args, env)
                except (Blocked, OSError, subprocess.SubprocessError) as exc:
                    cleanup_error = exc
                    status = 'cleanup-unresolved'
            selector.close()
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                process.stdout.close()
                process.stderr.close()
            if self.diagnostic or self.metadata_diagnostic:
                record = {'operation': public or 'withheld', 'operation_id': self.operation_id(original),
                          'step': self.current_step, 'outcome': 'accepted' if completed else 'rejected',
                          'accepted_exit': completed, 'allowed_exit_statuses': list(ok), 'status': status,
                          'elapsed_seconds': round(time.monotonic() - started, 3), 'sensitive_stdin': input_text is not None}
                if not completed or type(status) is int and status != 0:
                    record['native'] = self.native_diagnostic(args)
                if self.metadata_diagnostic:
                    self.metadata_diagnostic(dict(record))
                if public:
                    record.update(output_bytes=total, capture_limit_bytes=1048576,
                                  **{name + '_tail': bytes(data[-8192:]).decode(errors='replace') for name, data in buffers.items()},
                                  **{name + '_truncated': len(data) > 8192 for name, data in buffers.items()})
                if self.diagnostic:
                    self.diagnostic(record)
            if cleanup_error is not None:
                raise Blocked('native cleanup unresolved; retained ownership record and finite lifetime') from None

def checked_file(path, *, secret=False):
    p = Path(path)
    if not p.is_absolute():
        raise Blocked('input file must be absolute')
    for parent in [p, *p.parents]:
        s = parent.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise Blocked('input path must be root-owned, without symlinks or group/world writes')
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_size > 16384:
        raise Blocked('input must be a small regular file')
    if secret and s.st_mode & 0o077:
        raise Blocked('secret file must have mode 0600 or stricter')
    return p

def validate_public_keys(payload):
    """Admit the complete GitHub response or nothing; no authorized_keys options."""
    try:
        if not payload or len(payload) > KEYS_MAX_BYTES:
            raise ValueError()
        text = payload.decode('ascii')
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines or len(lines) > 256:
            raise ValueError()
        admitted = []
        deadline = time.monotonic() + 20
        for line in lines:
            if time.monotonic() >= deadline:
                raise ValueError()
            if len(line) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in line):
                raise ValueError()
            fields = line.split()
            kind = fields[0]
            if (len(fields) < 2 or kind not in ('ssh-ed25519', 'ssh-rsa',
                    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                    'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com')):
                raise ValueError()
            blob = base64.b64decode(fields[1], validate=True)
            length = int.from_bytes(blob[:4], 'big')
            if length != len(kind) or blob[4:4 + length] != kind.encode():
                raise ValueError()
            # ssh-keygen checks the full public-key structure, beyond the type header.
            with tempfile.NamedTemporaryFile(mode='w') as key:
                key.write(line + '\n')
                key.flush()
                Commands()('/usr/bin/ssh-keygen', '-l', '-f', key.name, timeout=5)
            normalized = kind + ' ' + fields[1]
            if normalized not in admitted:
                admitted.append(normalized)
        return '\n'.join(admitted) + '\n'
    except (ValueError, UnicodeError, IndexError, Blocked):
        raise Blocked('GitHub keys response failed validation; existing keys preserved') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_github_response():
    """One bounded-body request, executed only inside the disposable fetch child."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        request = urllib.request.Request(KEYS_URL, headers={'User-Agent': 'dev-pair-bootstrap'})
        deadline = time.monotonic() + 20
        with opener.open(request, timeout=5) as response:
            if response.status != 200 or response.geturl() != KEYS_URL:
                raise ValueError()
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                chunk = response.read1(min(16384, KEYS_MAX_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > KEYS_MAX_BYTES:
                    raise ValueError()
        return b''.join(chunks)
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError):
        raise Blocked('GitHub HTTPS request failed; output withheld') from None


def github_keys():
    # A disposable process gives DNS/TLS/header/body work a wall-clock deadline.
    # Socket timeouts alone do not bound libc DNS resolution. No inherited auth,
    # Python startup hooks or proxy environment reaches the reviewed child.
    command = [sys.executable, '-I', str(Path(__file__).resolve()), '_fetch-github-keys']
    env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
    for attempt in range(KEYS_FETCH_ATTEMPTS):
        try:
            result = subprocess.run(command, env=env, capture_output=True, timeout=KEYS_FETCH_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode == 0:
            return validate_public_keys(result.stdout)
    raise Blocked('bounded GitHub HTTPS fetch failed; existing keys preserved')


def operator_password(path):
    password = checked_file(path, secret=True).read_bytes().decode('utf-8')
    # Exactly one line. Never accept chpasswd separators/control bytes or empty passwords.
    password = password.removesuffix('\n')
    if (not password or len(password) > 1024 or ':' in password
            or any(ord(c) < 32 or ord(c) == 127 for c in password)):
        raise Blocked('operator password file must contain one nonempty line without control characters or colon')
    return password


def validate_sources(sources):
    try:
        networks = sorted({str(ipaddress.ip_network(x, strict=True)) for x in sources})
    except ValueError:
        raise Blocked('bootstrap sources must be explicit canonical CIDRs') from None
    if not networks or any(ipaddress.ip_network(x).prefixlen == 0 for x in networks):
        raise Blocked('unrestricted bootstrap sources are not allowed')
    return networks

class Bootstrap:
    # Alternate roots/runners are internal unit-test boundaries, absent from CLI.
    def __init__(self, root=Path('/'), run=None):
        self.root, self.run = Path(root), run or Commands()
        self.state = self.path(STATE)

    def path(self, value):
        return self.root / value.lstrip('/')

    def text(self, value, default=''):
        p = self.path(value)
        return p.read_text() if p.exists() else default

    def atomic(self, path, content, mode=0o600, expected=None):
        p = self.path(path)
        for parent in [p, *p.parents]:
            if parent.exists() or parent.is_symlink():
                if parent.is_symlink():
                    raise Blocked('refusing symlink in managed path')
                info = parent.stat()
                if info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                    raise Blocked('managed configuration path must be root-owned and protected')
            if parent == self.root:
                break
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if p.exists():
            if p.read_text() == content:
                if stat.S_IMODE(p.stat().st_mode) != mode:
                    raise Blocked('managed file permissions conflict')
                return
            if expected is None or p.read_text() != expected:
                raise Blocked(f'conflicting managed file: {path}')
        fd, name = tempfile.mkstemp(prefix='.bootstrap-', dir=p.parent)
        try:
            with os.fdopen(fd, 'w') as f:
                os.fchmod(f.fileno(), mode)
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, p)
            d = os.open(p.parent, os.O_DIRECTORY)
            try:
                os.fsync(d)
            finally:
                os.close(d)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def preflight(self):
        if os.geteuid() != 0:
            raise Blocked('root is required')
        release = dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']*)', self.text('/etc/os-release'), re.M))
        if release.get('ID') != 'fedora' or release.get('VERSION_ID') != '44':
            raise Blocked('only Fedora 44 is supported; no changes made')
        if platform.machine() not in ('x86_64', 'aarch64'):
            raise Blocked('only x86_64/aarch64 supported')
        if self.text('/proc/1/comm').strip() != 'systemd':
            raise Blocked('host PID 1 must be systemd')
        if self.run('/usr/sbin/getenforce').strip() != 'Enforcing':
            raise Blocked('SELinux must be enforcing; run selinux_bootstrap.py initial convergence first')
        transition = self.path('/var/lib/dev-pair/selinux-bootstrap')
        if (transition / 'intent.json').exists():
            try:
                complete = json.loads((transition / 'complete.json').read_text())
                modes = re.findall(r'^\s*SELINUX\s*=\s*["\']?([^#\s"\']+)',
                                   self.text('/etc/selinux/config'), re.M)
                if not isinstance(complete, dict) or complete.get('phase') != 'enforcing' or modes != ['enforcing']:
                    raise ValueError()
            except (OSError, ValueError):
                raise Blocked('checked initial SELinux transition is incomplete; workloads remain blocked') from None
        repos = self.path('/etc/yum.repos.d')
        if repos.exists():
            for repo in repos.glob('*.repo'):
                if repo.name != 'dev-pair-tailscale.repo' and re.search(r'^\s*\[tailscale-stable\]\s*$', repo.read_text(), re.M):
                    raise Blocked('existing tailscale-stable repository conflicts with managed repo')
        self.run('/usr/sbin/sshd', '-t')
        settings = self.run('/usr/sbin/sshd', '-T')
        if re.findall(r'^port (\d+)$', settings, re.M) != ['22']:
            raise Blocked('bootstrap supports existing SSH port 22 only')
        for service in ('firewalld.service', 'nftables.service'):
            if self.run('/usr/bin/systemctl', 'is-active', service, ok=(0, 3, 4)).strip() == 'active':
                raise Blocked('competing firewall manager is active; inspect without disabling it')
        if self.path('/usr/sbin/nft').exists():
            tables = self.run('/usr/sbin/nft', 'list', 'tables').splitlines()
            if any(line.strip() != 'table inet dev_pair_bootstrap' for line in tables):
                raise Blocked('existing nftables rules conflict with vanilla bootstrap')
        # Reject application listeners before creating users, installing packages or changing rules.
        for line in self.run('/usr/bin/ss', '-H', '-lntup').splitlines():
            columns = line.split()
            if len(columns) < 5:
                raise Blocked('cannot parse listener inventory')
            proto, address = columns[0], columns[4]
            host, _, port = address.rpartition(':')
            try:
                local = ipaddress.ip_address(host.strip('[]').split('%')[0]).is_loopback
            except ValueError:
                local = False
            allowed = (proto == 'tcp' and port == '22') or (local and proto in ('tcp', 'udp') and port == '53') or (
                proto == 'udp' and (port in ('68', '546', '41641') or (local and port in ('53', '123', '323'))))
            if (not allowed and proto in ('tcp', 'udp') and port == '5355'
                    and not self.path(f'{STATE}/prepared').exists()):
                allowed = self.resolved_listener(line)
            if not allowed and proto == 'tcp':
                allowed = self.peerapi_listener(line, host.strip('[]'))
            if not allowed and proto == 'udp' and port.isdigit() and 60000 <= int(port) <= 61000:
                allowed = self.mosh_listener(line)
            if not allowed:
                raise Blocked('unexpected listener: host is not vanilla; inspect inventory before proceeding')
        return {'os': 'Fedora 44', 'arch': platform.machine(), 'selinux': 'Enforcing',
                'phase': 'temporary-bootstrap', 'ssh_cutover': 'not implemented'}

    def resolved_service(self):
        observed = self.run('/usr/bin/systemctl', 'show', '--property=MainPID', '--property=User',
                            '--property=ActiveState', '--property=LoadState', 'systemd-resolved.service', ok=(0, 1, 4))
        fields = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
        if fields.get('LoadState') == 'not-found' and fields.get('ActiveState') == 'inactive':
            return None
        if fields.get('LoadState') != 'loaded' or fields.get('ActiveState') != 'active' or fields.get('User') != 'systemd-resolve':
            raise Blocked('systemd-resolved service identity/state is not the supported Fedora baseline')
        pid = fields.get('MainPID', '')
        if not pid.isdigit() or int(pid) <= 1:
            raise Blocked('systemd-resolved has no valid main process')
        executable = '/usr/lib/systemd/systemd-resolved'
        if str(self.path('/proc/' + pid + '/exe').readlink()) != executable:
            raise Blocked('systemd-resolved executable mismatch')
        binary = self.path(executable)
        for item in [binary, *binary.parents]:
            info = item.lstat()
            if item.is_symlink() or info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                raise Blocked('systemd-resolved executable path is not protected')
            if item == self.root:
                break
        if not stat.S_ISREG(binary.stat().st_mode):
            raise Blocked('systemd-resolved executable is not regular')
        account = self.run('/usr/bin/getent', 'passwd', 'systemd-resolve').strip().split(':')
        uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$', self.text('/proc/' + pid + '/status'), re.M)
        if (len(account) != 7 or account[0] != 'systemd-resolve' or not account[2].isdigit()
                or account[2] == '0' or not uid or any(value != account[2] for value in uid.groups())
                or self.text('/proc/' + pid + '/cgroup').strip() != '0::/system.slice/systemd-resolved.service'):
            raise Blocked('systemd-resolved process owner/cgroup mismatch')
        return pid

    def resolved_listener(self, line):
        # The observed Fedora discovery listener is temporary provisioning input,
        # never a general port allowance or post-prepare service policy.
        owners = re.findall(r'\("([^"\n]+)",pid=(\d+),fd=\d+\)', line)
        try:
            return len(owners) == 1 and owners[0][0] == 'systemd-resolve' and owners[0][1] == self.resolved_service()
        except (Blocked, OSError, ValueError):
            return False

    @staticmethod
    def listener_endpoints(inventory):
        result = set()
        for line in inventory.splitlines():
            columns = line.split()
            if len(columns) < 5:
                raise Blocked('cannot parse listener inventory')
            result.add((columns[0], columns[4]))
        return result

    def configure_resolved(self):
        before = self.listener_endpoints(self.run('/usr/bin/ss', '-H', '-lntup'))
        pid = self.resolved_service()
        self.atomic('/etc/systemd/resolved.conf.d/90-dev-pair-discovery.conf',
                    '[Resolve]\nLLMNR=no\nMulticastDNS=no\n', mode=0o644)
        merged = self.run('/usr/bin/systemd-analyze', 'cat-config', 'systemd/resolved.conf')
        section, values = '', {}
        for raw in merged.splitlines():
            line = raw.strip()
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1]
            elif section == 'Resolve' and '=' in line and not line.startswith(('#', ';')):
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
        if any(values.get(key) != 'no' for key in ('LLMNR', 'MulticastDNS')):
            raise Blocked('effective resolved discovery configuration conflicts')
        if pid is not None:
            self.run('/usr/bin/systemctl', 'restart', 'systemd-resolved.service')
            self.resolved_service()
        after = self.listener_endpoints(self.run('/usr/bin/ss', '-H', '-lntup'))
        if any(address.rpartition(':')[2] in ('5353', '5355') for proto, address in after if proto in ('tcp', 'udp')):
            raise Blocked('discovery listener remains after persistent resolved configuration')
        def retained(endpoint):
            proto, address = endpoint
            host, _, port = address.rpartition(':')
            if proto == 'tcp' and port == '22':
                return True
            try:
                return port == '53' and ipaddress.ip_address(host.strip('[]').split('%')[0]).is_loopback
            except ValueError:
                return False
        if not {value for value in before if retained(value)}.issubset(after):
            raise Blocked('SSH or loopback DNS listener disappeared after resolved configuration')

    def mosh_listener(self, line):
        match = re.search(r'users:\(\("mosh-server",pid=(\d+),', line)
        if not match or not self.path(f'{STATE}/identity-core.json').exists():
            return False
        pid = match.group(1)
        try:
            if str(self.path(f'/proc/{pid}/exe').readlink()) != '/usr/bin/mosh-server':
                return False
            wanted = self.run('/usr/bin/id', '-u', 'core').strip()
            uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$',
                            self.text(f'/proc/{pid}/status'), re.M)
            return bool(uid and wanted.isdigit() and int(wanted) >= 1000
                        and all(value == wanted for value in uid.groups()))
        except (OSError, Blocked):
            return False

    def peerapi_listener(self, line, host):
        # Permit only root's actual official tailscaled executable on this node's own IP.
        match = re.search(r'users:\(\("tailscaled",pid=(\d+),', line)
        if not match or not self.path('/usr/bin/tailscale').exists():
            return False
        pid = match.group(1)
        try:
            exe = self.path(f'/proc/{pid}/exe').readlink()
            if str(exe) != '/usr/sbin/tailscaled':
                return False
            uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$', self.text(f'/proc/{pid}/status'), re.M)
            if not uid or any(x != '0' for x in uid.groups()):
                return False
            live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json', ok=(0, 1)))
            return host in live.get('TailscaleIPs', []) and live.get('BackendState') == 'Running'
        except (OSError, ValueError, Blocked):
            return False

    @contextlib.contextmanager
    def lock(self, name='lock'):
        self.directory('/var/lib/dev-pair', mode=0o755)
        for parent in [self.state, *self.state.parents]:
            if parent.is_symlink():
                raise Blocked('symlink in bootstrap state path')
            if parent.exists():
                info = parent.stat()
                if info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                    raise Blocked('bootstrap state path must be root-owned and protected')
            if parent == self.root:
                break
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.state.is_symlink() or stat.S_IMODE(self.state.stat().st_mode) != 0o700:
            raise Blocked('bootstrap state directory must be private and not a symlink')
        fd = os.open(self.state / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocked('another bootstrap operation is running') from None
            yield
        finally:
            os.close(fd)

    def event(self, action, status):
        # Only fixed action names/status, never command output, credentials or argv.
        fd = os.open(self.state / 'journal.jsonl', os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps({'time': int(time.time()), 'action': action, 'status': status}) + '\n')
            f.flush()
            os.fsync(f.fileno())

    def mark_prepare_step(self, value):
        self.prepare_step = value
        if isinstance(self.run, Commands):
            self.run.current_step = value

    def step(self, action, callback):
        self.mark_prepare_step(action)
        self.event(action, 'begin')
        try:
            callback()
        except BaseException:
            self.event(action, 'interrupted-or-failed')
            raise
        self.event(action, 'complete')

    def directory(self, name, mode=0o700, owner=None):
        # Traverse by descriptors: a runtime-owned parent cannot redirect root's chmod/chown.
        relative = Path(name)
        if not relative.is_absolute() or '..' in relative.parts:
            raise Blocked('invalid managed directory')
        uid = int(self.run('/usr/bin/id', '-u', owner).strip()) if owner else (0 if self.root == Path('/') else os.getuid())
        gid = int(self.run('/usr/bin/id', '-g', owner).strip()) if owner else os.getgid()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = relative.parts[1:]
            for index, part in enumerate(parts):
                leaf = index == len(parts) - 1
                created = False
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    os.mkdir(part, mode if leaf else 0o755, dir_fd=fd)
                    created = True
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                if leaf:
                    if created:
                        os.fchmod(fd, mode)
                        if owner:
                            os.fchown(fd, uid, gid)
                    info = os.fstat(fd)
                    if stat.S_IMODE(info.st_mode) != mode or info.st_uid != uid:
                        raise Blocked(f'conflicting directory: {name}')
        except OSError:
            raise Blocked('unsafe or conflicting managed directory traversal') from None
        finally:
            os.close(fd)

    def identity(self, name, shell, substart=None):
        marker = f'{STATE}/identity-{name}.json'
        intent = json.dumps({'name': name, 'shell': shell, 'substart': substart}, sort_keys=True) + '\n'
        account = self.run('/usr/bin/getent', 'passwd', name, ok=(0, 2)).strip()
        if account and self.text(marker) != intent:
            raise Blocked('refusing to adopt an existing account')
        self.atomic(marker, intent)
        if not account:
            self.run('/usr/sbin/useradd', '--create-home', '--user-group', '--shell', shell,
                     '-K', 'SUB_UID_COUNT=0', '-K', 'SUB_GID_COUNT=0', name)
            account = self.run('/usr/bin/getent', 'passwd', name).strip()
        fields = account.split(':')
        if len(fields) != 7 or fields[5:] != [f'/home/{name}', shell] or int(fields[2]) < 1000:
            raise Blocked('account configuration conflicts')
        if name != 'core':
            self.run('/usr/sbin/usermod', '--lock', name)
        groups = self.run('/usr/bin/id', '-nG', name).split()
        if groups != [name]:
            raise Blocked('managed account must have only its private primary group')
        if substart is not None:
            for file in ('/etc/subuid', '/etc/subgid'):
                content = self.text(file)
                wanted = f'{name}:{substart}:65536'
                own = []
                for line in content.splitlines():
                    parts = line.split(':')
                    if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
                        raise Blocked('malformed subordinate ID configuration')
                    who, begin, count = parts[0], int(parts[1]), int(parts[2])
                    if who in (name, fields[2]):
                        own.append(line)
                    elif begin < substart + 65536 and substart < begin + count:
                        raise Blocked('subordinate ID range overlaps an existing account')
                if own and own != [wanted]:
                    raise Blocked('conflicting subordinate ID allocation')
                if not own:
                    self.atomic(file, content.rstrip('\n') + ('\n' if content else '') + wanted + '\n',
                                mode=0o644, expected=content)
            self.run('/usr/bin/loginctl', 'enable-linger', name)

    def password_operator(self, password):
        marker = f'{STATE}/operator-password-set'
        if not self.path(marker).exists():
            # An interruption after chpasswd can safely reapply the same external input.
            self.run('/usr/sbin/chpasswd', input_text='core:' + password + '\n')
        observed = self.run('/usr/bin/passwd', '-S', 'core').split()
        # shadow-utils uses P; Fedora's historical passwd/libuser uses PS.
        # Both mean a set, unlocked password; L/LK/NP and absent output fail.
        if len(observed) < 2 or observed[0] != 'core' or observed[1] not in ('P', 'PS'):
            raise Blocked('core password is not usable; recovery required')
        self.atomic(marker, 'password configured; value remains external\n')

    def host_identity(self):
        # cloud-init must not restore a provider hostname on the next boot.
        self.atomic('/etc/cloud/cloud.cfg.d/99-dev-pair-hostname.cfg',
                    '#cloud-config\npreserve_hostname: true\n', mode=0o644)
        self.run('/usr/bin/hostnamectl', 'set-hostname', 'erebus')
        if self.run('/usr/bin/hostnamectl', '--static').strip() != 'erebus':
            raise Blocked('persistent hostname observation failed')
        self.run('/usr/bin/systemctl', 'enable', '--now', 'chronyd.service')
        self.run('/usr/bin/chronyc', 'tracking')
        self.reserve_mosh_ports()
        # Daemon observation is not proof of synchronized time; acceptance uses real host evidence.
        self.atomic('/etc/profile.d/90-dev-pair-core-tmux.sh', OPERATOR_PROFILE, mode=0o644)

    def reserve_mosh_ports(self):
        # The early public mosh drop also covers established UDP. Reserve its port
        # range so unrelated outbound clients do not receive replies in that range.
        ranges = []
        for entry in self.text('/proc/sys/net/ipv4/ip_local_reserved_ports').strip().split(','):
            if not entry:
                continue
            if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', entry):
                raise Blocked('invalid existing reserved port ranges')
            endpoints = [int(value) for value in entry.split('-')]
            low, high = endpoints[0], endpoints[-1]
            if not 1 <= low <= high <= 65535:
                raise Blocked('invalid existing reserved port ranges')
            ranges.append((low, high))
        ranges.append((60000, 61000))
        merged = []
        for low, high in sorted(ranges):
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        value = ','.join(str(low) if low == high else f'{low}-{high}' for low, high in merged)
        self.atomic('/etc/sysctl.d/90-dev-pair-mosh.conf',
                    'net.ipv4.ip_local_reserved_ports = ' + value + '\n', mode=0o644)
        self.run('/usr/sbin/sysctl', '-p', str(self.path('/etc/sysctl.d/90-dev-pair-mosh.conf')))

    def operator_keys(self, name, key):
        target = f'/etc/ssh/dev-pair-keys/{name}'
        marker = f'{STATE}/operator-keys.json'
        prior = self.text(marker)
        hashes = json.loads(prior) if prior else {}
        current = self.text(target)
        current_hash = hashlib.sha256(current.encode()).hexdigest() if current else None
        if current and current_hash not in (hashes.get('previous'), hashes.get('wanted')):
            raise Blocked('operator key file conflicts with protected import record')
        intent = json.dumps({'previous': current_hash, 'wanted': hashlib.sha256(key.encode()).hexdigest()}, sort_keys=True) + '\n'
        self.atomic(marker, intent, expected=prior or None)
        # Validation/fetch was completed before any of these files are touched. The intent
        # admits both sides of an interrupted rename, so retry can finish without key loss.
        self.atomic(target, key, mode=0o644, expected=current or None)

    def ssh_operator(self, name, key):
        self.directory('/etc/ssh/dev-pair-keys', mode=0o755)
        self.operator_keys(name, key)
        self.run('/usr/sbin/restorecon', '-RF', str(self.path('/etc/ssh/dev-pair-keys')))
        # This named human operator has explicit administration authority; runtime users do not.
        sudo = f'Defaults:{name} authenticate,!rootpw,!targetpw,!runaspw\n{name} ALL=(ALL) PASSWD: ALL\n'
        self.atomic('/etc/sudoers.d/dev-pair-operator', sudo, mode=0o440)
        self.run('/usr/sbin/visudo', '-cf', str(self.path('/etc/sudoers.d/dev-pair-operator')))
        self.run('/usr/sbin/visudo', '-c')
        effective_sudo = self.run('/usr/bin/sudo', '-l', '-U', name)
        if any(token in effective_sudo for token in ('NOPASSWD', '!authenticate')):
            raise Blocked('effective core sudo policy bypasses password authentication')
        ssh = (f'# dev-pair bootstrap: only the named operator; initial root route retained\n'
               'DenyUsers dp-maint dp-dev\n'
               f'Match User {name}\n    AuthorizedKeysFile /etc/ssh/dev-pair-keys/{name}\n'
               '    AuthenticationMethods publickey\n    PasswordAuthentication no\n'
               '    KbdInteractiveAuthentication no\n    PubkeyAuthentication yes\nMatch all\n')
        target = '/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'
        created = not self.path(target).exists()
        self.atomic(target, ssh, mode=0o600)
        try:
            self.run('/usr/sbin/sshd', '-t')
            effective = self.run('/usr/sbin/sshd', '-T', '-C', f'user={name},host=bootstrap,addr=100.64.0.1')
            required = ('authenticationmethods publickey', 'passwordauthentication no',
                        'kbdinteractiveauthentication no', 'pubkeyauthentication yes',
                        f'authorizedkeysfile /etc/ssh/dev-pair-keys/{name}')
            if not all(x in effective.splitlines() for x in required):
                raise Blocked('effective operator SSH settings conflict')
            self.run('/usr/bin/systemctl', 'reload', 'sshd.service')
        except BaseException:
            # Never leave a newly introduced invalid fragment active after a failed validation.
            if created:
                self.path(target).unlink(missing_ok=True)
            raise

    def prepare(self, name, key, sources, gptbox_context=None, expected_context=None, *, password=None, source_check=None):
        self.mark_prepare_step('input-admission')
        if gptbox_context is not None and (not isinstance(expected_context, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_context)):
            raise Blocked('a separately trusted context SHA256 is required before preparation')
        sources = validate_sources(sources)
        connection = os.environ.get('SSH_CONNECTION')
        if connection:
            try:
                remote = ipaddress.ip_address(connection.split()[0])
            except ValueError:
                raise Blocked('invalid current SSH source') from None
            if not any(remote in ipaddress.ip_network(c) for c in sources):
                raise Blocked('current SSH source is outside declared bootstrap CIDRs')
        if name != 'core' or (password is None and not self.path(f'{STATE}/operator-password-set').exists()):
            raise Blocked('core operator and securely supplied password are required')
        self.mark_prepare_step('host-preflight')
        self.preflight()
        if gptbox_context is not None:
            self.mark_prepare_step('context-content')
            self.check_gptbox_inputs(gptbox_context, expected_context)
            if self.path('/usr/bin/git').exists():
                self.mark_prepare_step('context-source')
                self.validate_gptbox_context(gptbox_context, expected_context)
        with self.lock():
            if gptbox_context is not None:
                if not self.path('/usr/bin/git').exists():
                    self.step('git-prerequisite', lambda: self.run('/usr/bin/dnf', '-y',
                              '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--disablerepo=*',
                              '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'))
                self.mark_prepare_step('context-source')
                # Full source verification precedes desired binding, accounts, ingress and normal packages.
                self.validate_gptbox_context(gptbox_context, expected_context)
                if source_check:
                    self.mark_prepare_step('adapter-source-and-upstream')
                    source_check()
            self.mark_prepare_step('desired-state')
            desired = json.dumps({'schema': 1, 'standards_sha': STANDARDS,
                                  'source_baseline': SOURCE_BASELINE,
                                  'bootstrap_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                  'gptbox_context_sha256': expected_context, 'operator': name,
                                  'keys_source': KEYS_URL, 'bootstrap_sources': sources}, sort_keys=True) + '\n'
            self.atomic(f'{STATE}/desired.json', desired)
            self.step('resolved-discovery', self.configure_resolved)
            self.step('packages', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                       '--setopt=localpkg_gpgcheck=1', '--disablerepo=*', '--enablerepo=fedora',
                       '--enablerepo=updates', 'install', *PACKAGES))
            self.step('operator', lambda: (self.identity(name, '/bin/bash'), self.ssh_operator(name, key),
                                         self.password_operator(password)))
            self.step('host-identity-time', self.host_identity)
            for who, begin, role in [('dp-maint', 1000000, 'maintenance'), ('dp-dev', 1065536, 'development')]:
                self.step(who, lambda who=who, begin=begin: self.identity(who, '/usr/sbin/nologin', begin))
                # sudo -l exits 1 only when this user has no permitted commands.
                self.run('/usr/bin/sudo', '-l', '-U', who, ok=(1,))
                self.directory(f'/var/lib/dev-pair/{role}', owner=who)
                for directory in ('workspaces', 'checkpoints', 'evidence', 'deliverables', 'builds', 'cache', 'state'):
                    self.directory(f'/var/lib/dev-pair/{role}/{directory}', owner=who)
            self.mark_prepare_step('managed-limits')
            self.atomic('/etc/dev-pair/limits.json', json.dumps({
                'jobs_enabled': False, 'per_role_memory_max': '2G', 'per_role_tasks_max': 512,
                'per_role_cpu_quota': '100%', 'storage_budget_bytes': 21474836480,
                'minimum_free_bytes': 8589934592, 'inactive_retention_days': 7,
                'note': 'No jobs admitted until storage enforcement and lifecycle validation exist.'}, indent=2) + '\n', mode=0o644)
            # Actual cgroup ceilings apply to the entire unprivileged user, not one container.
            for who in ('dp-maint', 'dp-dev'):
                uid = self.run('/usr/bin/id', '-u', who).strip()
                self.atomic(f'/etc/systemd/system/user-{uid}.slice.d/50-dev-pair.conf',
                            '[Slice]\nMemoryMax=2G\nTasksMax=512\nCPUQuota=100%\n', mode=0o644)
            self.step('ingress-guard', lambda: self.guard(sources))
            self.mark_prepare_step('tailscale-package-config')
            self.atomic('/etc/yum.repos.d/dev-pair-tailscale.repo', REPO, mode=0o644)
            self.step('tailscale-package', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                      '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates',
                      '--enablerepo=tailscale-stable', 'install', 'tailscale'))
            self.atomic('/etc/systemd/system/tailscaled.service.d/50-dev-pair-guard.conf', TAILSCALE_UNIT, mode=0o644)
            self.run('/usr/bin/systemctl', 'daemon-reload')
            self.run('/usr/bin/systemctl', 'enable', '--now', 'tailscaled.service')
            self.mark_prepare_step('package-inventory')
            versions = self.run('/usr/bin/rpm', '-q', *PACKAGES, 'tailscale')
            self.atomic(f'{STATE}/packages.txt', versions, expected=self.text(f'{STATE}/packages.txt') or None)
            if gptbox_context is not None:
                self.step('maintenance-gptbox-build', lambda: self.build_gptbox(gptbox_context, expected_context))
            self.mark_prepare_step('preparation-completion')
            self.atomic(f'{STATE}/prepared', desired)
            self.event('prepare', 'complete')
        return self.status()

    def candidate_tool(self):
        path = Path(__file__).with_name('candidate.py')
        spec = importlib.util.spec_from_file_location('dev_pair_candidate', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def check_gptbox_inputs(self, context, expected):
        """Python-only input checks before any mutation; does not admit source or runtime."""
        if platform.machine() != 'x86_64':
            raise Blocked('current pinned Codex context supports x86_64 maintenance builds only')
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise Blocked('a separately trusted context SHA256 is required')
        tool = self.candidate_tool()
        source = Path(context)
        if not source.is_absolute():
            raise Blocked('gptbox context path must be absolute')
        # Protect transferred bytes before snapshot/verification; only root can race this source.
        if self.root == Path('/'):
            for entry in [source, *source.parents, *source.iterdir()]:
                info = entry.lstat()
                if entry.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise Blocked('gptbox context must be root-owned, protected and nonsymlink')
        try:
            _, manifest = tool._verify_content(source, expected)
            if manifest['role'] != 'maintenance':
                raise Blocked('first bootstrap accepts only maintenance-role gptbox contexts')
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Blocked('gptbox context/source verification failed; no host changes permitted') from None
        return tool, source, manifest

    def validate_gptbox_context(self, context, expected):
        tool, source, manifest = self.check_gptbox_inputs(context, expected)
        try:
            tool.verify(source, expected)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Blocked('gptbox context/source verification failed; no admission') from None
        return tool, source, manifest

    def build_gptbox(self, context, expected):
        tool, source, manifest = self.validate_gptbox_context(context, expected)
        try:
            stage = f'/var/lib/dev-pair/artifacts/gptbox/{expected}'
            self.directory('/var/lib/dev-pair/artifacts', mode=0o755)
            self.directory('/var/lib/dev-pair/artifacts/gptbox', mode=0o755)
            self.directory(stage, mode=0o755)
            for name in ('inputs.json', 'codex', 'Containerfile', 'candidate.json'):
                data = (source / name).read_bytes()
                # All four files are public build inputs, never credentials or writable home state.
                target = self.path(stage) / name
                if target.exists() or target.is_symlink():
                    if target.is_symlink() or target.read_bytes() != data or target.stat().st_mode & 0o222:
                        raise Blocked('staged gptbox context conflicts')
                else:
                    temporary = target.with_name('.staging-' + name)
                    # A previous interrupted writer can leave only its private staging file.
                    if temporary.exists() or temporary.is_symlink():
                        info = temporary.lstat()
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                or info.st_nlink != 1):
                            raise Blocked('unsafe interrupted gptbox staging file')
                        temporary.unlink()
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
                    try:
                        with os.fdopen(fd, 'wb') as out:
                            os.fchmod(out.fileno(), 0o444)
                            out.write(data)
                            out.flush()
                            os.fsync(out.fileno())
                        os.replace(temporary, target)
                    finally:
                        temporary.unlink(missing_ok=True)
            tool.verify(self.path(stage), expected)
        except (ValueError, subprocess.SubprocessError):
            raise Blocked('gptbox context verification failed; no engine invoked') from None
        uid = self.run('/usr/bin/id', '-u', 'dp-maint').strip()
        if not uid.isdigit() or int(uid) < 1000:
            raise Blocked('invalid maintenance runtime UID')
        self.run('/usr/bin/systemctl', 'start', f'user@{uid}.service')
        storage = '/var/lib/dev-pair/maintenance/images'
        self.directory(storage, owner='dp-maint')
        base = ['/usr/bin/systemd-run', '--wait', '--pipe', '--collect', '--service-type=exec',
                '--uid=dp-maint', f'--unit=dev-pair-gptbox-{expected}.service',
                f'--description=dev-pair-owned-dev-pair-gptbox-{expected}.service',
                '--property=RuntimeMaxSec=600', '--property=TimeoutStopSec=10',
                '--property=KillMode=control-group', '--property=MemoryMax=2G',
                '--property=TasksMax=512', '--property=CPUQuota=100%', '/usr/bin/env', '-i',
                'HOME=/home/dp-maint', 'USER=dp-maint', 'LOGNAME=dp-maint',
                'PATH=/usr/sbin:/usr/bin', f'XDG_RUNTIME_DIR=/run/user/{uid}',
                '/usr/bin/podman', '--root', str(self.path(storage)),
                '--runroot', f'/run/user/{uid}/dev-pair-gptbox-build', '--storage-driver=vfs']
        tag = f'localhost/dev-pair/maintenance-gptbox:{expected}'
        record_path = f'{STATE}/gptbox-image.json'
        intent = {'context_sha256': expected, 'local_tag': tag, 'source_sha': manifest['source_sha']}
        self.atomic(f'{STATE}/gptbox-build-intent.json', json.dumps(intent, sort_keys=True) + '\n')
        self.event('gptbox-build-intent', 'recorded')
        prior = json.loads(self.text(record_path)) if self.path(record_path).exists() else None
        if prior:
            if (prior.get('context_sha256') != expected or prior.get('source_sha') != manifest['source_sha']
                    or prior.get('base_image') != manifest['fedora']['image'] or prior.get('codex_sha256') != manifest['codex']['sha256']
                    or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', prior.get('image_id', ''))):
                raise Blocked('protected gptbox completion record conflicts')
            inspect = self.run(*base, 'image', 'inspect', prior['image_id'], ok=(0, 125))
            if not inspect:
                raise Blocked('recorded gptbox artifact is missing; explicit recovery required')
        else:
            # A writable image-store label/tag is never a completion/provenance record.
            # Interrupted unrecorded builds are rebuilt from the same protected context.
            if shutil.disk_usage(self.path(storage)).free < 8 * 1024 ** 3:
                raise Blocked('insufficient free storage reserve for gptbox build')
            self.run(*base, 'pull', '--policy=always', manifest['fedora']['image'])
            built_id = self.run(*base, 'build', '--quiet', '--network=none', '--pull=never', '--format=oci',
                     '--label', f'dev-pair.context={expected}', '--tag', tag,
                     '--file', str(self.path(stage) / 'Containerfile'), str(self.path(stage))).strip()
            if not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', built_id):
                raise Blocked('gptbox build returned no unambiguous immutable image ID')
            inspect = self.run(*base, 'image', 'inspect', built_id)
        try:
            images = json.loads(inspect)
            if not isinstance(images, list) or len(images) != 1:
                raise ValueError()
            image = images[0]
            image_id = image['Id']
            expected_id = prior['image_id'] if prior else built_id
            if image_id.removeprefix('sha256:') != expected_id.removeprefix('sha256:'):
                raise ValueError()
            if not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', image_id):
                raise ValueError()
            labels = image.get('Labels') or image.get('Config', {}).get('Labels', {})
            wanted = {'dev-pair.context': expected, 'dev-pair.role': 'maintenance',
                      'dev-pair.standards': STANDARDS,
                      'org.opencontainers.image.revision': manifest['source_sha'],
                      'dev-pair.codex.version': manifest['codex']['version']}
            if any(labels.get(key) != value for key, value in wanted.items()):
                raise ValueError()
            if image.get('Architecture') != 'amd64' or image.get('Os') != 'linux':
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise Blocked('gptbox artifact inspection identity mismatch') from None
        record = {'kind': 'host-maintenance-gptbox-oci-candidate', 'context_sha256': expected,
                  'source_sha': manifest['source_sha'], 'base_image': manifest['fedora']['image'],
                  'codex_sha256': manifest['codex']['sha256'], 'image_id': image_id,
                  'local_tag': tag, 'runtime_user': 'dp-maint', 'storage_driver': 'vfs',
                  'launch': 'blocked: stock Distrobox 1.8.2.5 adds privileged, label=disable and host mounts',
                  'distrobox_assembled': False, 'runtime_validated': False}
        self.atomic(record_path, json.dumps(record, sort_keys=True, indent=2) + '\n')
        return record

    def guard(self, sources):
        rules = '\n'.join(f'add rule inet dev_pair_bootstrap input {"ip6" if ":" in cidr else "ip"} saddr {cidr} tcp dport 22 accept' for cidr in sources)
        guard = GUARD.replace('{bootstrap_rules}', rules)
        config = '/etc/dev-pair/bootstrap.nft'
        if not self.path(config).exists():
            tables = self.run('/usr/sbin/nft', 'list', 'tables')
            if 'dev_pair_bootstrap' in tables:
                raise Blocked('existing bootstrap nft table has no managed configuration')
        self.atomic(config, guard, mode=0o600)
        self.atomic('/etc/systemd/system/dev-pair-bootstrap-guard.service', UNIT, mode=0o644)
        self.run('/usr/sbin/nft', '--check', '-f', str(self.path(config)))
        self.run('/usr/bin/systemctl', 'daemon-reload')
        self.run('/usr/bin/systemctl', 'enable', 'dev-pair-bootstrap-guard.service')
        # nft -f commits its own table transaction atomically. Reapply on resume to reconcile live drift.
        self.run('/usr/sbin/nft', '-f', str(self.path(config)))
        self.run('/usr/bin/systemctl', 'start', 'dev-pair-bootstrap-guard.service')

    def enroll(self, secret, tailnet):
        self.preflight()
        secret = checked_file(secret, secret=True)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.@-]{0,252}', tailnet):
            raise Blocked('invalid expected tailnet name')
        with self.lock():
            if not self.path(f'{STATE}/prepared').exists():
                raise Blocked('prepare must complete before enrollment')
            intent = f'{STATE}/enrollment-intent.json'
            expected = json.dumps({'tailnet': tailnet}, sort_keys=True) + '\n'
            same_intent = self.text(intent) == expected
            accepted = self.path(f'{STATE}/node.json').exists()
            try:
                live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json', ok=(0, 1)))
                if not isinstance(live, dict):
                    raise Blocked('invalid Tailscale status observation')
            except BaseException:
                if same_intent and not accepted:
                    self.disconnect_unverified()
                raise
            state = live.get('BackendState')
            if state == 'Running' and not same_intent:
                raise Blocked('refusing to adopt an already enrolled node')
            if accepted:
                if state != 'Running':
                    raise Blocked('previous node lost enrollment; explicit recovery required')
                self.check_node(live, tailnet)
                return self.status()
            try:
                if self.path(f'{STATE}/enrollment-recovery-required.json').exists():
                    raise Blocked('enrollment identity requires explicit recovery/new credentials; automatic retry denied')
                if state not in ('Running', 'NeedsLogin', 'NoState', 'Stopped'):
                    raise Blocked('unexpected Tailscale state; no automatic reauthentication')
                if state == 'Stopped' and not same_intent:
                    raise Blocked('stopped unowned enrollment requires explicit recovery')
                observed_tailnet, _ = self.identity_fields(live)
                if state != 'Running' and observed_tailnet and observed_tailnet != tailnet:
                    if same_intent:
                        self.require_enrollment_recovery(tailnet)
                    raise Blocked('stopped enrollment tailnet mismatch; explicit recovery/new credentials required')
                self.atomic(intent, expected)
                if state != 'Running':
                    self.step('enroll', lambda: self.run('/usr/bin/tailscale', 'up', '--auth-key=file:' + str(secret),
                             '--accept-routes=false', '--accept-dns=false', '--ssh=false',
                             '--advertise-exit-node=false', '--netfilter-mode=off', '--timeout=60s'))
                live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json'))
                if not isinstance(live, dict) or live.get('BackendState') != 'Running':
                    raise Blocked('enrollment did not reach Running; bootstrap access retained')
                self.check_node(live, tailnet, disconnect_on_mismatch=False)
                self.event('enrollment-observed', 'complete')
            except BaseException:
                # CLI success is insufficient: observation, decoding and persistence must also succeed.
                # Disconnect is attempted even if a full disk makes journaling fail.
                self.disconnect_unverified()
                # No prior accepted marker existed on this new-enrollment path.
                # A write may have become visible before its fsync/completion failed.
                self.path(f'{STATE}/node.json').unlink(missing_ok=True)
                raise
        return self.status()

    def require_enrollment_recovery(self, tailnet):
        self.atomic(f'{STATE}/enrollment-recovery-required.json',
                    json.dumps({'expected_tailnet': tailnet, 'reason': 'observed identity mismatch'}, sort_keys=True) + '\n')

    def disconnect_unverified(self):
        try:
            self.run('/usr/bin/tailscale', 'down')
        except BaseException:
            try:
                self.event('enrollment-failure-cleanup', 'failed')
            except OSError:
                pass
            raise Blocked('enrollment unverified and Tailscale disconnect failed; initial SSH retained, inspect/revoke externally') from None
        try:
            self.event('enrollment-failure-cleanup', 'complete')
        except OSError:
            pass

    @staticmethod
    def identity_fields(live):
        # Official Status uses nullable *TailnetStatus and *PeerStatus fields.
        current, own = live.get('CurrentTailnet'), live.get('Self')
        current = {} if current is None else current
        own = {} if own is None else own
        if not isinstance(current, dict) or not isinstance(own, dict):
            raise Blocked('invalid Tailscale identity schema')
        name, node_id = current.get('Name'), own.get('ID')
        if any(value is not None and not isinstance(value, str) for value in (name, node_id)):
            raise Blocked('invalid Tailscale identity fields')
        return name, node_id

    def check_node(self, live, tailnet, disconnect_on_mismatch=True):
        try:
            observed_tailnet, node_id = self.identity_fields(live)
        except Blocked:
            if disconnect_on_mismatch:
                self.disconnect_unverified()
            raise
        node = json.dumps({'tailnet': tailnet, 'node_id': node_id}, sort_keys=True) + '\n'
        previous = self.text(f'{STATE}/node.json')
        if (observed_tailnet != tailnet or not node_id
                or (previous and previous != node)):
            try:
                self.require_enrollment_recovery(tailnet)
            finally:
                if disconnect_on_mismatch:
                    self.disconnect_unverified()
            raise Blocked('tailnet identity mismatch: unverified node taken down; initial SSH retained, revoke key externally')
        self.atomic(f'{STATE}/node.json', node)

    def status(self):
        return {'prepared': self.path(f'{STATE}/prepared').exists(),
                'initialization': json.loads(self.text(f'{STATE}/initialize.json', '"not requested"')),
                'maintenance_gptbox': (json.loads(self.text(f'{STATE}/gptbox-image.json'))
                                       if self.path(f'{STATE}/gptbox-image.json').exists() else 'not built'),
                'enrollment_recorded': self.path(f'{STATE}/node.json').exists(),
                'phase': 'temporary-bootstrap', 'applications_started': False,
                'root_and_initial_ssh_retained': True, 'access_cutover': 'blocked pending external evidence',
                'runtime_acceptance': 'not verified', 'state': STATE,
                'note': 'Recorded state only; not proof of current external reachability or recovery'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='stage', required=True)
    sub.add_parser('inspect')
    sub.add_parser('_fetch-github-keys', help=argparse.SUPPRESS)
    init = sub.add_parser('initialize', help='prepare then genuine maintenance assembly; no jobs/authentication')
    init.add_argument('--source-sha', required=True)
    init.add_argument('--distrobox-source', required=True)
    init.add_argument('--retry', action='store_true')
    prep = sub.add_parser('prepare')
    for entry in (prep, init):
        entry.add_argument('--apply', action='store_true', help='perform host changes; absent means inspect only')
        entry.add_argument('--gptbox-context', required=True, help='real maintenance-role context; fixtures denied')
        entry.add_argument('--expected-context-sha256', required=True, help='trusted handoff digest outside context')
        entry.add_argument('--operator', choices=('core',), default='core')
        entry.add_argument('--password-file', help='protected root-owned core console/sudo password file; never an argv value')
        entry.add_argument('--bootstrap-source', action='append', required=True, help='explicit IPv4/IPv6 CIDR; repeatable')
    en = sub.add_parser('enroll')
    en.add_argument('--apply', action='store_true', help='enroll; absent means inspect only')
    en.add_argument('--auth-key-file', required=True)
    en.add_argument('--tailnet', required=True, help='exact expected CurrentTailnet.Name')
    sub.add_parser('status')
    sub.add_parser('finalize')
    args = p.parse_args()
    try:
        if args.stage == 'initialize':
            forwarded = [sys.executable, str(Path(__file__).with_name('gptbox.py')), 'initialize',
                         '--context', args.gptbox_context, '--expected-context-sha256', args.expected_context_sha256,
                         '--source-sha', args.source_sha, '--distrobox-source', args.distrobox_source]
            for source in args.bootstrap_source:
                forwarded.extend(['--bootstrap-source', source])
            if args.password_file:
                forwarded.extend(['--password-file', args.password_file])
            if args.apply:
                forwarded.append('--apply')
            if args.retry:
                forwarded.append('--retry')
            os.execv(sys.executable, forwarded)
        if args.stage == '_fetch-github-keys':
            sys.stdout.buffer.write(fetch_github_response())
            return 0
        b = Bootstrap()
        if args.stage == 'inspect':
            result = b.preflight()
        elif args.stage == 'prepare':
            if args.apply:
                password = operator_password(args.password_file) if args.password_file else None
                keys = github_keys()
                result = b.prepare(args.operator, keys, args.bootstrap_source,
                                   args.gptbox_context, args.expected_context_sha256, password=password)
            else:
                result = {**b.preflight(), 'preview': 'prepare', 'sources': validate_sources(args.bootstrap_source)}
                b.check_gptbox_inputs(args.gptbox_context, args.expected_context_sha256)
                if args.password_file:
                    operator_password(args.password_file)
                elif not b.path(f'{STATE}/operator-password-set').exists():
                    raise Blocked('first preparation requires --password-file')
                github_keys()
                result['operator'] = 'core; GitHub keys validated; console/sudo password supplied externally'
                if b.path('/usr/bin/git').exists():
                    b.validate_gptbox_context(args.gptbox_context, args.expected_context_sha256)
                    result['gptbox_context'] = 'content and source verified read-only; build not executed'
                else:
                    result['gptbox_context'] = 'content checked; Git source verification pending prerequisite install; not admitted'
        elif args.stage == 'enroll':
            result = b.enroll(args.auth_key_file, args.tailnet) if args.apply else {**b.preflight(), 'preview': 'enroll'}
        elif args.stage == 'finalize':
            raise Blocked('cutover is not implemented: preserve initial SSH/root until external named-admin tailnet access and independent recovery are proven')
        else:
            result = b.status()
        print(json.dumps(result, indent=2))
        return 0
    except (Blocked, OSError, ValueError) as e:
        # JSON/OS exceptions may contain external payloads/paths: do not echo them.
        print('bootstrap blocked: ' + (str(e) if isinstance(e, Blocked) else 'invalid input or local filesystem state'), file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
