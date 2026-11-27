#!/usr/bin/python3
"""Provision the isolated checklist executor and deploy one verified release on erebus."""
import argparse
import contextlib
import fcntl
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
import uuid

from bootstrap import Blocked, Bootstrap, checked_file, relay
from release_trust import DIGEST, SHA, ReleaseTrust, protect, require

ROOT = '/var/lib/dev-pair'
HOME = ROOT + '/checklist-executor'
VALIDATION = ROOT + '/checklist-validation'
LIVE = ROOT + '/checklist-live'
CONTROL = ROOT + '/checklist-release'
FENCE = ROOT + '/renewal-fence'
RECEIPTS = ROOT + '/checklist-receipts'
CODE = '/usr/libexec/dev-pair/checklist'
TRUST_CODE = '/usr/libexec/dev-pair/tools'
OWNER = 'dp-checklist'
CONTAINER = 'dp-checklist-app'
UNIT = CONTAINER + '.service'
GATE = '/etc/dev-pair/checklist'
PROVISION = CONTROL + '/provision.json'
ACTIVATION = CONTROL + '/release.json'
STORAGE = {'validation': VALIDATION, 'live': LIVE}
NETWORKS = {'validation': 'dev-pair-checklist-internal', 'live': 'dev-pair-checklist-release'}
FILES = ('tools/host_handoff.py', 'tools/job_protocol.py', 'tools/ledger_recovery.py', 'tools/jobs.py',
         'runtime/checklist/checklist_quadlet.py', 'runtime/checklist/acceptance.container',
         'examples/checklist/checklist.py')
EXECUTOR = 'dev-pair-checklist-executor@.service'
PORT = 18279
PROXY = f'http://127.0.0.1:{PORT}'
TLS_FILES = ('cert.pem', 'peer.pem', 'key.pem')
COMPATIBILITY = 'checklist-sqlite-v1'
RUNUSER = '/usr/sbin/runuser'
SYSTEMCTL = '/usr/bin/systemctl'
TAILSCALE = '/usr/bin/tailscale'
MIB = 1024**2


def record_text(value):
    return json.dumps(value, sort_keys=True) + '\n'


class Destination(Bootstrap):
    def record(self, path):
        return json.loads(checked_file(path).read_bytes(), object_pairs_hook=relay.unique)

    def account(self):
        user = pwd.getpwnam(OWNER)
        require(user.pw_uid == user.pw_gid >= 1000 and user.pw_dir == HOME and user.pw_shell == '/usr/sbin/nologin'
                and grp.getgrgid(user.pw_gid).gr_name == OWNER and os.getgrouplist(OWNER, user.pw_gid) == [user.pw_gid],
                'checklist account must be a dedicated nonlogin identity with one private group')
        fields = self.run('/usr/bin/passwd', '-S', OWNER, timeout=10).split()
        require(len(fields) >= 2 and fields[:2] in ([OWNER, 'L'], [OWNER, 'LK']), 'checklist password is not locked')
        return user.pw_uid

    def subprocess_role(self, uid, *args, timeout=30, **options):
        runtime = f'/run/user/{uid}'
        return self.run(RUNUSER, '-u', OWNER, '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin',
                        f'HOME={HOME}', f'USER={OWNER}', f'LOGNAME={OWNER}', 'LC_ALL=C.UTF-8',
                        f'XDG_RUNTIME_DIR={runtime}', f'DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus',
                        *args, timeout=timeout, **options)

    def user_unit(self, uid, *args):
        return self.subprocess_role(uid, SYSTEMCTL, '--user', *args)

    def podman(self, uid, role, *args, timeout=30):
        suffix = '-live' if role == 'live' else ''
        return self.subprocess_role(uid, '/usr/bin/podman', '--root', STORAGE[role] + '/graph',
                                    '--runroot', f'/run/user/{uid}/dev-pair-checklist{suffix}-runroot',
                                    *args, timeout=timeout)

    def owned_directory(self, path, uid):
        self._directory_as(path, 0o700, uid, uid, change_owner=True, check_gid=True)

    def subid(self, file, flag, uid, start, live):
        lines = protect(file).read_text().splitlines()
        end = start + 65536
        owned = []
        for line in lines:
            user, lower, count = line.split(':')
            lower, count = int(lower), int(count)
            require(lower > 0 and count > 0 and lower + count <= 2**32 - 1, 'invalid existing subordinate ID range')
            if user in (OWNER, str(uid)):
                owned.append((lower, count))
            else:
                require(lower + count <= start or end <= lower, 'selected checklist subordinate IDs overlap an existing range')
        require(not any(start <= value < end for value in live) and owned in ([], [(start, 65536)]),
                'selected checklist subordinate IDs overlap a live identity or existing allocation')
        if not owned and flag:
            self.run('/usr/sbin/usermod', flag, f'{start}-{end - 1}', OWNER, timeout=15)
            require(self.subid(file, None, uid, start, live), 'checklist subordinate allocation did not persist')
        return bool(owned)

    def storage_ready(self, path, uid):
        # Use the same native filesystem, byte/inode and ownership oracle as the host executor.
        command = ('import sys; sys.path[:0] = [sys.argv[1] + "/tools", sys.argv[1] + "/runtime/checklist"]; '
                   'import checklist_quadlet as check; from pathlib import Path; '
                   'assert check.storage_identity(Path(sys.argv[2]))')
        if path == VALIDATION:
            self.subprocess_role(uid, '/usr/bin/python3', '-IB', '-c', command, CODE, path)
        else:
            self.mount_observation(path, self.record(PROVISION)['mounts']['live'])

    def mount_observation(self, path, spec):
        mounted = json.loads(self.run('/usr/bin/findmnt', '--json', '--mountpoint', path,
                                      '--output', 'SOURCE,FSTYPE,OPTIONS', timeout=10))['filesystems']
        require(len(mounted) == 1 and mounted[0]['fstype'] == 'ext4', 'checklist requires its dedicated ext4 mount')
        options = mounted[0]['options'].split(',')
        require({'rw', 'nodev', 'nosuid'}.issubset(options) and 'discard' not in options,
                'checklist mount does not enforce the private data boundary')
        source = mounted[0]['source']
        device = Path(path).stat().st_dev
        require(re.fullmatch(r'/dev/loop[0-9]+', source) and device != Path(path).parent.stat().st_dev,
                'checklist mount does not have its own reserved backing device')
        backing = Path(f'/sys/dev/block/{os.major(device)}:{os.minor(device)}/loop/backing_file').read_text().strip()
        image = protect(backing)
        require(str(image) == spec['image'] and image.stat().st_blocks * 512 >= spec['mib'] * MIB,
                'checklist mount does not use its fully reserved owned backing file')
        geometry = os.statvfs(path)
        require(0 < geometry.f_blocks * geometry.f_frsize <= spec['mib'] * MIB
                and 0 < geometry.f_files <= 65536 and geometry.f_files <= spec['inodes'] + 512,
                'checklist mount exceeds declared geometry')
        matches = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                   if line.split()[2] == f'{os.major(device)}:{os.minor(device)}']
        require(len(matches) == 1, 'checklist storage has an additional mount alias')

    def reserve(self, path, spec, uid, reserve_mib, reserve_inodes):
        self.directory(ROOT + '/checklist-storage')
        image = Path(spec['image'])
        size = spec['mib'] * MIB
        descriptor = os.open(image, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            protect(image)
            old = os.fstat(descriptor)
            require(stat.S_IMODE(old.st_mode) == 0o600 and old.st_size in (0, size), 'unexpected checklist backing file')
            remaining = max(size - old.st_blocks * 512, 0)
            space = os.statvfs(image.parent)
            require(space.f_bavail * space.f_frsize >= reserve_mib * MIB + remaining
                    and space.f_favail >= reserve_inodes, 'selected VPS cannot preserve the declared free reserve')
            if remaining:
                os.posix_fallocate(descriptor, 0, size)
                os.fsync(descriptor)
            current = os.fstat(descriptor)
            require(current.st_size == size and current.st_blocks * 512 >= size, 'checklist backing is not fully allocated')
        finally:
            os.close(descriptor)
        observed = self.run('/usr/sbin/blkid', '-p', '-o', 'export', str(image), ok=(0, 2), timeout=10)
        expected = {'UUID': spec['uuid'], 'TYPE': 'ext4'}
        if not observed:
            self.run('/usr/sbin/mkfs.ext4', '-q', '-N', str(spec['inodes']), '-m', '0', '-U', spec['uuid'],
                     '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', str(image), timeout=120)
            observed = self.run('/usr/sbin/blkid', '-p', '-o', 'export', str(image), timeout=10)
        fields = dict(line.split('=', 1) for line in observed.splitlines())
        require(all(fields.get(key) == value for key, value in expected.items()), 'foreign checklist backing filesystem')
        unit = self.run('/usr/bin/systemd-escape', '--path', '--suffix=mount', path, timeout=10).strip()
        require(re.fullmatch(r'[a-z0-9\\x-]+\.mount', unit), 'unexpected checklist mount unit name')
        # An unmounted mount point remains root-owned. Only the mounted filesystem is role-owned.
        if not Path(path).exists():
            self.directory(path, mode=0o755)
        self.atomic('/etc/systemd/system/' + unit,
                    '[Unit]\nDescription=Dedicated Dev-pair checklist storage\n'
                    f'[Mount]\nWhat={image}\nWhere={path}\nType=ext4\nOptions=loop,nodiscard,nodev,nosuid\n'
                    '[Install]\nWantedBy=local-fs.target\n', mode=0o644)
        self.run(SYSTEMCTL, 'daemon-reload', timeout=15)
        self.run(SYSTEMCTL, 'enable', '--now', unit, timeout=40)
        self.mount_observation(path, spec)
        root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(root)
            require(info.st_uid in (0, uid) and info.st_gid in (0, uid), 'foreign checklist filesystem owner')
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, uid, 0o700):
                os.fchown(root, uid, uid)
                os.fchmod(root, 0o700)
                os.fsync(root)
        finally:
            os.close(root)
        for name in ('graph', 'attempts') if path == VALIDATION else ('graph', 'data', 'backups'):
            self.owned_directory(path + '/' + name, uid)

    def role_secret(self, directory, name, data, uid):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, 'checklist secret directory is not private')
            try:
                file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            except FileNotFoundError:
                file = None
            if file is not None:
                with os.fdopen(file, 'rb') as stream:
                    existing = os.fstat(stream.fileno())
                    require(stat.S_ISREG(existing.st_mode) and existing.st_nlink == 1 and existing.st_uid == uid
                            and stat.S_IMODE(existing.st_mode) == 0o600 and stream.read(len(data) + 1) == data,
                            'existing checklist secret differs from the independently supplied profile')
                return
            part = '.hold-' + uuid.uuid4().hex
            try:
                with os.fdopen(os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                                       dir_fd=descriptor), 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fchown(stream.fileno(), uid, uid)
                    os.fsync(stream.fileno())
                os.link(part, name, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(part, dir_fd=descriptor)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def source_files(self, source):
        self.destination_source(source)
        repo = Path(__file__).absolute().parents[1]
        files = (*FILES, 'runtime/checklist/' + EXECUTOR, 'tools/release_trust.py', 'tools/bootstrap.py',
                 'tools/native_io.py', 'tools/native_relay.py', 'tools/selected_payload.py', 'tools/destination_release.py')
        selected = {}
        for name in files:
            actual = protect(repo / name).read_text()
            require(self.run('/usr/bin/git', '-C', str(repo), 'show', source + ':' + name, timeout=15) == actual,
                    'checklist installation code differs from the admitted platform source')
            selected[name] = actual
        return selected

    def provision(self, args):
        if not os.path.lexists(PROVISION):
            self.preflight()
        require(Path('/sys/fs/cgroup/cgroup.controllers').is_file() and self.text('/proc/sys/kernel/hostname').strip() == 'erebus'
                and self.run('/usr/sbin/getenforce', timeout=10).strip() == 'Enforcing',
                'checklist provisioning requires erebus with cgroup v2')
        require(1000 <= args.uid < 2**31 and 65536 <= args.subid_start <= 2**32 - 1 - 65536
                and args.reserve_mib >= 8192 and args.reserve_inodes >= 128,
                'invalid checklist identity or protected free reserve')
        sizing = {'validation': (args.validation_mib, args.validation_inodes), 'live': (args.live_mib, args.live_inodes)}
        require(all(128 <= size <= 2048 and 1024 <= inodes <= 65024 for size, inodes in sizing.values()),
                'selected checklist filesystem geometry is outside the supported bounds')
        code = self.source_files(args.platform_sha)
        secrets = {file: checked_file(Path(args.tls_profile) / file, secret=True).read_bytes() for file in TLS_FILES}
        require(all(0 < len(value) <= 8192 for value in secrets.values()), 'invalid checklist TLS profile size')
        live_groups = [entry.gr_gid for entry in grp.getgrall()]
        live_users = [entry.pw_uid for entry in pwd.getpwall()]
        require(not args.subid_start <= args.uid < args.subid_start + 65536, 'checklist UID overlaps its subordinate range')
        with self.lock('checklist-release.lock'):
            self.directory(CONTROL)
            previous = self.record(PROVISION) if Path(PROVISION).exists() else {}
            if not previous:
                require(args.uid not in live_users and args.uid not in live_groups
                        and all(user.pw_name != OWNER for user in pwd.getpwall())
                        and all(group.gr_name != OWNER for group in grp.getgrall()), 'refusing to adopt an existing checklist identity')
                for role in STORAGE:
                    require(not os.path.lexists(STORAGE[role]) and not os.path.lexists(ROOT + '/checklist-storage/' + role + '.img'),
                            'refusing to adopt existing checklist storage without an owned intent')
            specs = {role: {'mib': size, 'inodes': inodes, 'image': ROOT + '/checklist-storage/' + role + '.img',
                            'uuid': previous['mounts'][role]['uuid'] if previous else str(uuid.uuid4())}
                     for role, (size, inodes) in sizing.items()}
            identity = self.destination_identity()['machine_id']
            intent = {'version': 1, 'machine_id': identity, 'platform_sha': args.platform_sha, 'uid': args.uid,
                      'subid_start': args.subid_start, 'reserve_mib': args.reserve_mib, 'reserve_inodes': args.reserve_inodes,
                      'mounts': specs, 'tls': {name: hashlib.sha256(value).hexdigest() for name, value in secrets.items()}}
            if previous:
                require(previous == intent, 'provisioning retry changes protected host intent')
            for file, live in (('/etc/subuid', live_users), ('/etc/subgid', live_groups)):
                self.subid(file, None, args.uid, args.subid_start, live)
            self.atomic(PROVISION, record_text(intent))
            if not any(user.pw_name == OWNER for user in pwd.getpwall()):
                self.run('/usr/sbin/useradd', '--no-create-home', '--home-dir', HOME, '--user-group', '--uid',
                         str(args.uid), '--shell', '/usr/sbin/nologin', '-K', 'SUB_UID_COUNT=0', '-K', 'SUB_GID_COUNT=0', OWNER,
                         timeout=20)
            self.run('/usr/sbin/usermod', '--lock', OWNER, timeout=10)
            uid = self.account()
            require(uid == args.uid, 'checklist account changed from protected intent')
            self.run('/usr/sbin/visudo', '-c', timeout=10)
            self.run('/usr/bin/sudo', '-n', '-l', '-U', OWNER, ok=(1,), timeout=10)
            for file, flag, live in (('/etc/subuid', '--add-subuids', live_users), ('/etc/subgid', '--add-subgids', live_groups)):
                self.subid(file, flag, uid, args.subid_start, live)
            for relative, contents in code.items():
                if relative.endswith('/' + EXECUTOR):
                    target = '/etc/systemd/system/' + EXECUTOR
                elif relative in FILES:
                    target = CODE + '/' + relative
                else:
                    target = TRUST_CODE + '/' + Path(relative).name
                self.atomic(target, contents, mode=0o644)
            self.directory(GATE, mode=0o755)
            self.directory(FENCE, mode=0o755)
            self.atomic(FENCE + '/owner.lock', '', mode=0o644)
            self.directory(RECEIPTS)
            for path in (HOME, HOME + '/ledger', HOME + '/tls'):
                self.owned_directory(path, uid)
            for name, value in secrets.items():
                self.role_secret(HOME + '/tls', name, value, uid)
            for role, path in STORAGE.items():
                self.reserve(path, specs[role], uid, args.reserve_mib, args.reserve_inodes)
            self.atomic(f'/etc/systemd/system/user@{uid}.service.d/60-dev-pair-checklist.conf',
                        '[Unit]\nRequiresMountsFor=' + VALIDATION + ' ' + LIVE + '\n', mode=0o644)
            self.run('/usr/sbin/restorecon', '-RF', CODE, TRUST_CODE, '/etc/systemd/system/' + EXECUTOR, timeout=15)
            self.run(SYSTEMCTL, 'daemon-reload', timeout=15)
            self.run('/usr/bin/loginctl', 'enable-linger', OWNER, timeout=15)
            self.run(SYSTEMCTL, 'start', f'user@{uid}.service', timeout=30)
            self.user_unit(uid, 'show', '--property=Version')
            for role, path in STORAGE.items():
                self.storage_ready(path, uid)
                self.setup_network(uid, role)
            unit = f'dev-pair-checklist-executor@{uid}.service'
            self.run(SYSTEMCTL, 'enable', '--now', unit, timeout=30)
            self.executor_ready(unit, uid)
            self.atomic(CONTROL + '/ready.json', record_text(intent))
            return {'provisioned': True, 'uid': uid, 'platform_sha': args.platform_sha, 'executor': unit}

    def executor_ready(self, unit, uid):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            pid = self.run(SYSTEMCTL, 'show', '--property=MainPID', '--value', unit, timeout=3).strip()
            listeners = self.run('/usr/bin/ss', '-H', '-ltnp', 'sport = :19425', timeout=3).splitlines()
            if re.fullmatch(r'[1-9][0-9]+', pid) and len(listeners) == 1 and len(listeners[0].split()) >= 6:
                actual = listeners[0].split()[3]
                if actual == '127.0.0.1:19425' and re.findall(r'pid=(\d+),', listeners[0]) == [pid]:
                    if Path('/proc/' + pid).stat().st_uid == uid:
                        return
            time.sleep(0.2)
        raise Blocked('checklist executor did not acquire its exact owned loopback listener')

    def setup_network(self, uid, role):
        info = json.loads(self.podman(uid, role, 'info', '--format', 'json'))
        host = info['host']
        require(host['security']['rootless'] is True and host['security']['selinuxEnabled'] is True
                and host['cgroupVersion'] == 'v2' and host['cgroupManager'] == 'systemd'
                and info['store']['graphRoot'] == STORAGE[role] + '/graph', 'checklist Podman confinement prerequisites differ')
        name = NETWORKS[role]
        rows = json.loads(self.podman(uid, role, 'network', 'ls', '--format', 'json'))
        if not any(row.get('name') == name for row in rows):
            self.podman(uid, role, 'network', 'create', '--driver', 'bridge', '--internal', name)
        network, = json.loads(self.podman(uid, role, 'network', 'inspect', name))
        require(network['name'] == name and network['driver'] == 'bridge' and network['internal'] is True,
                'checklist rootless bridge is not internal')

    @contextlib.contextmanager
    def release_gate(self, *, require_cutover=True):
        with self.lock('checklist-release.lock'):
            fence = protect(FENCE + '/owner.lock')
            with fence.open('rb') as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise Blocked('checklist release is frozen by renewal') from exc
                require(not os.path.lexists(FENCE + '/frozen'), 'checklist release is frozen by renewal')
                ready = self.record(CONTROL + '/ready.json')
                require(ready == self.record(PROVISION) and ready['machine_id'] == self.destination_identity()['machine_id'],
                        'checklist destination lacks same-machine protected provisioning')
                uid = self.account()
                require(uid == ready['uid'] and self.run('/usr/sbin/getenforce', timeout=10).strip() == 'Enforcing',
                        'release requires the isolated checklist account and enforcing SELinux')
                dns = None
                if require_cutover:
                    guard = self.verify_final_guard()
                    _, dns = self.tailscale_state()
                    require(guard['target']['dns_name'] == dns, 'checklist proxy differs from independently verified cutover')
                    self.storage_ready(LIVE, uid)
                else:
                    self.guard_hash()
                    self.run(SYSTEMCTL, 'is-active', 'dev-pair-bootstrap-guard.service', timeout=10)
                    self.storage_ready(VALIDATION, uid)
                    self.executor_ready(f'dev-pair-checklist-executor@{uid}.service', uid)
                yield ready, uid, dns

    def pull(self, uid, role, image, secret):
        auth = []
        path = None
        try:
            if secret:
                data = checked_file(secret, secret=True).read_bytes()
                directory = f'/run/user/{uid}'
                name = 'dev-pair-registry-' + uuid.uuid4().hex
                self.role_secret(directory, name, data, uid)
                path = Path(directory) / name
                auth = ['--authfile', str(path)]
            self.podman(uid, role, 'pull', '--quiet', '--platform', 'linux/amd64', *auth, image, timeout=180)
        finally:
            if path:
                path.unlink(missing_ok=True)

    def image_identity(self, uid, role, image, source, *, production):
        metadata, = json.loads(self.podman(uid, role, 'image', 'inspect', image))
        labels = metadata.get('Labels') or metadata['Config']['Labels']
        digest = image.rsplit('@', 1)[1]
        ident = metadata['Id'].removeprefix('sha256:')
        require(metadata['Architecture'] == 'amd64' and metadata['Os'] == 'linux' and re.fullmatch(DIGEST, ident)
                and metadata['Digest'] == digest and image in metadata['RepoDigests']
                and labels['org.opencontainers.image.revision'] == source,
                'Podman image manifest, platform or source differs from the held release')
        require(not production or labels.get('dev-pair.data-compatibility') == COMPATIBILITY,
                'checklist image does not declare the supported rollback data format')
        return ident

    def preload_validation(self, receipt_path, secret):
        with self.release_gate(require_cutover=False) as (_, uid, _dns):
            receipt = protect(receipt_path)
            require(receipt.parent == Path(RECEIPTS), 'validation receipt must be held by the protected build conductor')
            result = self.record(receipt)
            require(set(result) == {'version', 'job_id', 'candidate', 'image'} and type(result['version']) is int
                    and result['version'] == 1 and type(result['job_id']) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{0,79}', result['job_id']),
                    'validation receipt has an invalid shape')
            candidate, image = result['candidate'], result['image']
            require(set(candidate) == {'source_revision', 'artifact_sha256'} and re.fullmatch(SHA, candidate['source_revision'])
                    and re.fullmatch(DIGEST, candidate['artifact_sha256'])
                    and re.fullmatch(r'(?:localhost|ghcr\.io/oso-gato)/[a-z0-9][a-z0-9/_.-]*@sha256:' + candidate['artifact_sha256'], image),
                    'validation receipt does not pin the conductor-approved exact image')
            if not image.startswith('localhost/'):
                self.pull(uid, 'validation', image, secret)
            ident = self.image_identity(uid, 'validation', image, candidate['source_revision'], production=False)
            return {'job_id': result['job_id'], 'image_id': ident, 'receipt_sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()}

    def serve_config(self, dns):
        status = json.loads(self.run(TAILSCALE, 'serve', 'status', '--json', timeout=10), object_pairs_hook=relay.unique)
        expected = {'TCP': {'443': {'HTTPS': True}},
                    'Web': {f'{dns}:443': {'Handlers': {'/': {'Proxy': PROXY}}}}}
        require(status in (None, {}, expected), 'unexpected Tailscale route or Funnel state conflicts with checklist ingress')
        return bool(status)

    def publish_route(self, dns):
        if not self.serve_config(dns):
            self.run(TAILSCALE, 'serve', '--bg', '--https=443', PROXY, timeout=40)
        require(self.serve_config(dns), 'tailnet HTTPS route did not converge')

    def render_unit(self, uid, dns, release):
        source = protect(CODE + '/tools/host_handoff.py')
        return self.run('/usr/bin/python3', '-EBs', str(source), 'render-release', '--image', release['subject'],
                        '--hostname', dns, '--port', str(PORT), '--uid', str(uid), timeout=10)

    def unit_path(self, uid):
        return f'/etc/containers/systemd/users/{uid}/{CONTAINER}.container'

    def current_unit(self, uid, allowed):
        path = self.unit_path(uid)
        previous = protect(path).read_text() if os.path.lexists(path) else ''
        require(previous in allowed, 'refusing to change an unowned checklist Quadlet')
        return previous

    def install_unit(self, uid, dns, release, allowed):
        previous = self.current_unit(uid, allowed)
        wanted = self.render_unit(uid, dns, release)
        require(hashlib.sha256(wanted.encode()).hexdigest() == release['unit_sha256'], 'release does not bind its exact Quadlet')
        self.atomic(self.unit_path(uid), wanted, mode=0o644, expected=previous or None)
        self.user_unit(uid, 'daemon-reload')
        self.user_unit(uid, 'restart', UNIT)

    def health(self, uid, dns, release):
        fields = dict(line.split('=', 1) for line in self.user_unit(uid, 'show', '--property=SourcePath,FragmentPath,DropInPaths,ActiveState,InvocationID', UNIT).splitlines())
        generators = {'generator', 'generator.early', 'generator.late'}
        require(fields['SourcePath'] == self.unit_path(uid) and fields['DropInPaths'] == ''
                and fields['FragmentPath'] in {f'/run/user/{uid}/systemd/{name}/{UNIT}' for name in generators}
                and fields['ActiveState'] == 'active' and re.fullmatch('[0-9a-f]{32}', fields['InvocationID']),
                'checklist service is not the protected generated Quadlet')
        fmt = ('{{.Image}}\n{{.State.Running}}\n{{.ProcessLabel}}\n{{.MountLabel}}\n'
               '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}} {{.HostConfig.PidsLimit}} {{.Config.User}}')
        ident, running, process, mount, config = self.podman(uid, 'live', 'container', 'inspect', '--format', fmt, CONTAINER).splitlines()
        process, mount = process.split(':', 3), mount.split(':', 3)
        data_label = os.getxattr(LIVE + '/data', 'security.selinux').decode('ascii').rstrip('\0').split(':', 3)
        require(ident.removeprefix('sha256:') == release['image_id'] and running == 'true'
                and config == 'true false 32 65532:65532' and len(process) == len(mount) == len(data_label) == 4
                and process[2] == 'container_t' and mount[2] == 'container_file_t' and mount[2:] == data_label[2:]
                and process[3] == mount[3] and re.fullmatch(r's0:c[0-9]+,c[0-9]+', process[3]),
                'checklist runtime digest, privilege or SELinux data label differs')
        published = self.podman(uid, 'live', 'port', CONTAINER, '8000/tcp').strip()
        require(published == f'127.0.0.1:{PORT}', 'checklist listener is not restricted to its assigned loopback port')
        deadline = time.monotonic() + 8
        while True:
            try:
                with contextlib.closing(http.client.HTTPConnection('127.0.0.1', PORT, timeout=1)) as connection:
                    connection.request('GET', '/', headers={'Host': dns})
                    response = connection.getresponse()
                    require(response.status == 200 and b'<title>Checklist</title>' in response.read(16384),
                            'checklist loopback browser journey did not respond')
                    return fields['InvocationID']
            except OSError:
                if time.monotonic() >= deadline:
                    raise Blocked('checklist loopback service did not become ready') from None
                time.sleep(0.2)

    def backup(self, uid, attempt):
        source = LIVE + '/data/checklist.sqlite3'
        backup = LIVE + '/backups/' + attempt + '.sqlite3'
        restored = backup + '.restore'
        tool = protect(CODE + '/examples/checklist/checklist.py')
        if not os.path.lexists(backup):
            self.subprocess_role(uid, '/usr/bin/python3', '-IB', str(tool), 'backup', '--database', source, '--output', backup)
        if os.path.lexists(restored):
            self.subprocess_role(uid, '/usr/bin/rm', '--', restored)
        self.subprocess_role(uid, '/usr/bin/python3', '-IB', str(tool), 'restore', '--backup', backup, '--database', restored)
        self.subprocess_role(uid, '/usr/bin/rm', '--', restored)
        return backup

    def save_activation(self, state):
        self.atomic(ACTIVATION, record_text(state), expected=self.text(ACTIVATION) or None)

    def initial_activation(self):
        if os.path.lexists(ACTIVATION):
            return self.record(ACTIVATION)
        return {'version': 1, 'active': None, 'previous': None, 'pending': None, 'confirmed': None}

    def deploy(self, source, image, run_id, secret):
        with self.release_gate() as (_, uid, dns):
            state = self.initial_activation()
            self.serve_config(dns)
            release = ReleaseTrust(self.run).verify('checklist', source, image, run_id)
            active, previous, pending = state['active'], state['previous'], state['pending']
            if pending:
                require(pending['operation'] == 'deploy' and all(pending['release'][key] == value for key, value in release.items()),
                        'an interrupted different release requires rollback before further deployment')
            elif active and all(active[key] == value for key, value in release.items()):
                self.health(uid, dns, active)
                self.publish_route(dns)
                return state
            require(not active or state['confirmed'] == active['artifact_sha256'], 'current release requires independent destination confirmation before replacement')
            self.pull(uid, 'live', image, secret)
            release.update(image_id=self.image_identity(uid, 'live', image, source, production=True), dns_name=dns,
                           compatibility=COMPATIBILITY)
            new_unit = self.render_unit(uid, dns, release)
            release['unit_sha256'] = hashlib.sha256(new_unit.encode()).hexdigest()
            old_unit = self.render_unit(uid, dns, active) if active else ''
            self.current_unit(uid, (old_unit, new_unit) if pending else (old_unit,))
            ReleaseTrust(self.run).main(source)
            if pending:
                require(pending['release'] == release, 'interrupted release artifact differs from protected intent')
            else:
                if not active:
                    require(not self.serve_config(dns) and not os.path.lexists(LIVE + '/data/checklist.sqlite3'),
                            'refusing to adopt an existing checklist proxy or database without deployment state')
                pending = {'operation': 'deploy', 'release': release, 'attempt': uuid.uuid4().hex}
                state['pending'] = pending
                self.save_activation(state)
            try:
                backup = self.backup(uid, pending['attempt']) if active else None
                self.install_unit(uid, dns, release, (old_unit, new_unit))
                self.health(uid, dns, release)
                self.publish_route(dns)
            except Exception:
                self.recover(uid, dns, state)
                raise
            promoted = {**state, 'active': {**release, 'backup': backup}, 'previous': active, 'pending': None, 'confirmed': None}
            self.save_activation(promoted)
            if previous and previous.get('backup'):
                self.prune_backup(uid, previous['backup'])
            return promoted

    def prune_backup(self, uid, path):
        require(re.fullmatch(re.escape(LIVE) + r'/backups/[0-9a-f]{32}\.sqlite3', path), 'foreign checklist backup path')
        self.subprocess_role(uid, '/usr/bin/rm', '-f', '--', path)

    def recover(self, uid, dns, state):
        active, pending = state['active'], state['pending']
        wanted = pending['release']
        new = self.render_unit(uid, dns, wanted)
        if active:
            require(active['compatibility'] == COMPATIBILITY and active['dns_name'] == dns
                    and self.image_identity(uid, 'live', active['subject'], active['source_sha'], production=True) == active['image_id'],
                    'prior compatible checksum is unavailable for recovery')
            old = self.render_unit(uid, dns, active)
            self.install_unit(uid, dns, active, ('', old, new))
            self.health(uid, dns, active)
            self.publish_route(dns)
            self.save_activation({**state, 'pending': None})
            self.prune_backup(uid, LIVE + '/backups/' + pending['attempt'] + '.sqlite3')
            return
        if self.current_unit(uid, ('', new)):
            self.user_unit(uid, 'stop', UNIT)
            Path(self.unit_path(uid)).unlink()
            self.user_unit(uid, 'daemon-reload')
        if self.serve_config(dns):
            self.run(TAILSCALE, 'serve', '--https=443', 'off', timeout=20)
            require(not self.serve_config(dns), 'first-release proxy could not be removed')
        # Retain the first attempt's data and identity for inspection and exact retry.

    def rollback(self):
        with self.release_gate() as (_, uid, dns):
            state = self.initial_activation()
            if state['pending'] and state['pending']['operation'] == 'deploy':
                self.recover(uid, dns, state)
                return self.initial_activation()
            active, prior = state['active'], state['previous']
            require(active and prior and prior.get('verified_destination') is True
                    and prior['compatibility'] == active['compatibility'] == COMPATIBILITY
                    and prior['dns_name'] == dns and active['dns_name'] == dns,
                    'no known compatible previous checklist release')
            require(self.image_identity(uid, 'live', prior['subject'], prior['source_sha'], production=True) == prior['image_id'],
                    'previous exact digest is unavailable for rollback')
            old, new = (self.render_unit(uid, dns, item) for item in (active, prior))
            self.current_unit(uid, (old, new) if state['pending'] else (old,))
            if not state['pending']:
                state['pending'] = {'operation': 'rollback', 'release': prior, 'attempt': uuid.uuid4().hex}
                self.save_activation(state)
            try:
                backup = self.backup(uid, state['pending']['attempt'])
                self.install_unit(uid, dns, prior, (old, new))
                self.health(uid, dns, prior)
                self.publish_route(dns)
            except Exception:
                self.recover(uid, dns, state)
                raise
            rolled_back = {**state, 'active': {**prior, 'backup': backup}, 'previous': active,
                           'pending': None, 'confirmed': prior['artifact_sha256']}
            self.save_activation(rolled_back)
            if prior.get('backup'):
                self.prune_backup(uid, prior['backup'])
            return rolled_back

    def confirm(self, evidence):
        with self.release_gate() as (setup, uid, dns):
            state = self.initial_activation()
            release = state['active']
            require(release and not state['pending'], 'no settled rollout to confirm')
            data = self.recent_destination_evidence(evidence, 'dev-pair-access-review',
                                                    {'release_source', 'image', 'dns_name', 'guard_sha256', 'checks'}, lifetime=1800)
            checks = {'authorized_browser', 'public_app_denied', 'unauthorized_app_denied', 'tailnet_loss_denied',
                      'reboot_persistence', 'clean_restore', 'remote_root_denied'}
            require(data['source_sha'] == setup['platform_sha'] and data['release_source'] == release['source_sha']
                    and data['image'] == release['subject'] and data['dns_name'] == dns
                    and data['guard_sha256'] == self.verify_final_guard()['guard_sha256']
                    and set(data['checks']) == checks and all(value is True for value in data['checks'].values()),
                    'external destination evidence lacks exact successful release/access checks')
            self.health(uid, dns, release)
            require(self.serve_config(dns), 'checklist tailnet route is unavailable')
            state['confirmed'] = release['artifact_sha256']
            state['active'] = {**release, 'verified_destination': True,
                               'destination_receipt_sha256': hashlib.sha256(protect(evidence).read_bytes()).hexdigest()}
            self.save_activation(state)
            return {'url': f'https://{dns}/', 'source_sha': release['source_sha'], 'image': release['subject'], 'confirmed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest='stage', required=True)
    provision = stages.add_parser('provision')
    provision.add_argument('--platform-sha', required=True)
    provision.add_argument('--tls-profile', required=True)
    for option in ('uid', 'subid-start', 'validation-mib', 'validation-inodes', 'live-mib', 'live-inodes', 'reserve-mib', 'reserve-inodes'):
        provision.add_argument('--' + option, required=True, type=int)
    preload = stages.add_parser('preload-validation')
    preload.add_argument('--receipt', required=True)
    deploy = stages.add_parser('deploy')
    deploy.add_argument('--source-sha', required=True)
    deploy.add_argument('--image', required=True)
    deploy.add_argument('--run-id', required=True, type=int)
    for stage in (preload, deploy):
        stage.add_argument('--registry-auth-file')
    rollback = stages.add_parser('rollback')
    confirm = stages.add_parser('confirm')
    confirm.add_argument('--evidence', required=True)
    for stage in (provision, preload, deploy, rollback, confirm):
        stage.add_argument('--apply', action='store_true', required=True)
    stages.add_parser('status')
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'use the authorized root destination controller')
        app = Destination()
        if args.stage == 'provision':
            result = app.provision(args)
        elif args.stage == 'preload-validation':
            result = app.preload_validation(args.receipt, args.registry_auth_file)
        elif args.stage == 'deploy':
            result = app.deploy(args.source_sha, args.image, args.run_id, args.registry_auth_file)
        elif args.stage == 'rollback':
            result = app.rollback()
        elif args.stage == 'confirm':
            result = app.confirm(args.evidence)
        else:
            result = app.initial_activation()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        print('checklist destination blocked: ' + (str(exc) if isinstance(exc, Blocked) else 'required protected destination evidence unavailable'), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
