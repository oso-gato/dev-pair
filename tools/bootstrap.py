#!/usr/bin/python3
"""Explicit Fedora Cloud 44 host preparation; never launches submitted code or apps."""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import importlib.util
import shutil
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time

STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
SOURCE_BASELINE = '4dcf92e256a49770ddd89e4420b105319885910f'
STATE = '/var/lib/dev-pair/bootstrap'
PACKAGES = ('podman', 'distrobox', 'passt', 'fuse-overlayfs', 'container-selinux',
            'policycoreutils', 'shadow-utils', 'sudo', 'openssh-server', 'nftables', 'git-core', 'util-linux')
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
add rule inet dev_pair_bootstrap input ct state established,related accept
add rule inet dev_pair_bootstrap input iifname "lo" accept
add rule inet dev_pair_bootstrap input iifname "tailscale0" tcp dport 22 accept
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

class Blocked(Exception):
    pass

class Commands:
    def __call__(self, *args, ok=(0,)):
        # No caller PATH, shell, environment auth keys, or captured daemon output in errors.
        env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
        try:
            p = subprocess.run(args, env=env, text=True, capture_output=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked(f'{Path(args[0]).name} failed or timed out; inspect locally (output withheld)') from None
        if p.returncode not in ok:
            raise Blocked(f'{Path(args[0]).name} failed (exit {p.returncode}; output withheld)')
        return p.stdout

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

def public_key(path):
    p = checked_file(path)
    key = p.read_text().strip()
    if '\n' in key or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?', key):
        raise Blocked('provide exactly one unoptioned ssh-ed25519 public key')
    Commands()('/usr/bin/ssh-keygen', '-l', '-f', str(p))
    return key + '\n'

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
            raise Blocked('SELinux must already be enforcing')
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
            if not allowed and proto == 'tcp':
                allowed = self.peerapi_listener(line, host.strip('[]'))
            if not allowed:
                raise Blocked('unexpected listener: host is not vanilla; inspect inventory before proceeding')
        return {'os': 'Fedora 44', 'arch': platform.machine(), 'selinux': 'Enforcing',
                'phase': 'temporary-bootstrap', 'ssh_cutover': 'not implemented'}

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
    def lock(self):
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
        fd = os.open(self.state / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
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

    def step(self, action, callback):
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

    def ssh_operator(self, name, key):
        self.directory('/etc/ssh/dev-pair-keys', mode=0o755)
        self.atomic(f'/etc/ssh/dev-pair-keys/{name}', key, mode=0o644)
        self.run('/usr/sbin/restorecon', '-RF', str(self.path('/etc/ssh/dev-pair-keys')))
        # This named human operator has explicit administration authority; runtime users do not.
        sudo = f'{name} ALL=(ALL) NOPASSWD: ALL\n'
        self.atomic('/etc/sudoers.d/dev-pair-operator', sudo, mode=0o440)
        self.run('/usr/sbin/visudo', '-cf', str(self.path('/etc/sudoers.d/dev-pair-operator')))
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

    def prepare(self, name, key, sources, gptbox_context=None, expected_context=None):
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
        if not re.fullmatch(r'[a-z][a-z0-9-]{2,24}', name) or name in ('dp-maint', 'dp-dev'):
            raise Blocked('invalid named operator')
        self.preflight()
        if gptbox_context is not None:
            self.check_gptbox_inputs(gptbox_context, expected_context)
            if self.path('/usr/bin/git').exists():
                self.validate_gptbox_context(gptbox_context, expected_context)
        with self.lock():
            if gptbox_context is not None:
                if not self.path('/usr/bin/git').exists():
                    self.step('git-prerequisite', lambda: self.run('/usr/bin/dnf', '-y',
                              '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--disablerepo=*',
                              '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'))
                # Full source verification precedes desired binding, accounts, ingress and normal packages.
                self.validate_gptbox_context(gptbox_context, expected_context)
            desired = json.dumps({'schema': 1, 'standards_sha': STANDARDS,
                                  'source_baseline': SOURCE_BASELINE,
                                  'bootstrap_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                  'gptbox_context_sha256': expected_context, 'operator': name,
                                  'key_sha256': hashlib.sha256(key.encode()).hexdigest(), 'bootstrap_sources': sources}, sort_keys=True) + '\n'
            self.atomic(f'{STATE}/desired.json', desired)
            self.step('packages', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                       '--setopt=localpkg_gpgcheck=1', '--disablerepo=*', '--enablerepo=fedora',
                       '--enablerepo=updates', 'install', *PACKAGES))
            self.step('operator', lambda: (self.identity(name, '/bin/bash'), self.ssh_operator(name, key)))
            for who, begin, role in [('dp-maint', 1000000, 'maintenance'), ('dp-dev', 1065536, 'development')]:
                self.step(who, lambda who=who, begin=begin: self.identity(who, '/usr/sbin/nologin', begin))
                self.directory(f'/var/lib/dev-pair/{role}', owner=who)
                for directory in ('workspaces', 'checkpoints', 'evidence', 'deliverables', 'builds', 'cache', 'state'):
                    self.directory(f'/var/lib/dev-pair/{role}/{directory}', owner=who)
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
            self.atomic('/etc/yum.repos.d/dev-pair-tailscale.repo', REPO, mode=0o644)
            self.step('tailscale-package', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                      '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates',
                      '--enablerepo=tailscale-stable', 'install', 'tailscale'))
            self.atomic('/etc/systemd/system/tailscaled.service.d/50-dev-pair-guard.conf', TAILSCALE_UNIT, mode=0o644)
            self.run('/usr/bin/systemctl', 'daemon-reload')
            self.run('/usr/bin/systemctl', 'enable', '--now', 'tailscaled.service')
            versions = self.run('/usr/bin/rpm', '-q', *PACKAGES, 'tailscale')
            self.atomic(f'{STATE}/packages.txt', versions, expected=self.text(f'{STATE}/packages.txt') or None)
            if gptbox_context is not None:
                self.step('maintenance-gptbox-build', lambda: self.build_gptbox(gptbox_context, expected_context))
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
                '--uid=dp-maint', f'--unit=dev-pair-gptbox-{expected}',
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
            if prior.get('context_sha256') != expected or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', prior.get('image_id', '')):
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
    prep = sub.add_parser('prepare')
    prep.add_argument('--apply', action='store_true', help='perform host changes; absent means inspect only')
    prep.add_argument('--gptbox-context', required=True, help='real maintenance-role context; fixtures denied')
    prep.add_argument('--expected-context-sha256', required=True, help='trusted handoff digest outside context')
    prep.add_argument('--operator', required=True)
    prep.add_argument('--public-key-file', required=True)
    prep.add_argument('--bootstrap-source', action='append', required=True, help='explicit IPv4/IPv6 CIDR; repeatable')
    en = sub.add_parser('enroll')
    en.add_argument('--apply', action='store_true', help='enroll; absent means inspect only')
    en.add_argument('--auth-key-file', required=True)
    en.add_argument('--tailnet', required=True, help='exact expected CurrentTailnet.Name')
    sub.add_parser('status')
    sub.add_parser('finalize')
    args = p.parse_args()
    try:
        b = Bootstrap()
        if args.stage == 'inspect':
            result = b.preflight()
        elif args.stage == 'prepare':
            if args.apply:
                result = b.prepare(args.operator, public_key(args.public_key_file), args.bootstrap_source,
                                   args.gptbox_context, args.expected_context_sha256)
            else:
                result = {**b.preflight(), 'preview': 'prepare', 'sources': validate_sources(args.bootstrap_source)}
                b.check_gptbox_inputs(args.gptbox_context, args.expected_context_sha256)
                public_key(args.public_key_file)
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
