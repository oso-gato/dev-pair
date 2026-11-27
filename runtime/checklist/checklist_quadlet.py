"""Fixed Fedora host operations for the checklist restart acceptance recipe."""
import contextlib
import fcntl
import grp
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid

import job_protocol as p
from ledger_recovery import sync_directory, trusted_directory, write_private

SOURCE = Path(__file__).resolve()
TEMPLATE = SOURCE.with_name('acceptance.container')
STORAGE = Path('/var/lib/dev-pair/checklist-validation')
HOME = Path('/var/lib/dev-pair/checklist-executor')
FENCE = Path('/var/lib/dev-pair/renewal-fence')
APPROVAL = Path('/etc/dev-pair/checklist/approval.json')
GETENFORCE = '/usr/bin/getenforce'
ACCOUNT = 'dp-checklist'
NETWORK = 'dev-pair-checklist-internal'
CHECK_SECONDS = 25
CLEANUP_SECONDS = 12
MAX_STORAGE = 2 * 1024 ** 3
MAX_INODES = 65536
MAX_CAPTURE = 8192
APP_AUTHORITY = '127.0.0.1:8000'
LIVE_STORAGE = Path('/var/lib/dev-pair/checklist-live')
IMAGE = r'[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}'
ID = r'(?:sha256:)?([0-9a-f]{64})'


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('checklist host deadline expired')
    return seconds


def protected(path, *, file):
    path = Path(path).absolute()
    p.require(path.resolve(strict=True) == path, 'host recipe and approvals require canonical paths')
    for part in (path, *path.parents):
        info = part.lstat()
        p.require(info.st_uid == 0 and not info.st_mode & 0o022,
                  'host recipe and approvals require root-owned protected paths')
        if part == path and file:
            p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                      'host recipe and approval leaves must be unique regular files')
        else:
            p.require(stat.S_ISDIR(info.st_mode), 'host recipe path has a non-directory ancestor')
    return path


def approval(path, request):
    try:
        data = p.read_data(protected(path, file=True), min(MAX_CAPTURE, request['budgets']['artifact_bytes']))
    except FileNotFoundError as exc:
        raise ValueError('no protected approval is available for this host request') from exc
    record = p.loads(data)
    p.fields(record, 'version request_sha256 image receipt_sha256 machine_id expires_at')
    p.number(record['version'], 1, 1)
    for key in ('request_sha256', 'receipt_sha256'):
        p.digest(record[key])
    p.digest(record['machine_id'], 32)
    p.number(record['expires_at'], 1, 2**63 - 1)
    now = time.time()
    p.require(request['budgets']['seconds'] < record['expires_at'] - now <= 3600,
              'host approval must cover the operation budget and expire within one hour')
    p.require(record['machine_id'] == Path('/etc/machine-id').read_text().strip(),
              'approval is for a different executor')
    p.require(record['request_sha256'] == p.identity(request), 'request lacks an exact host approval')
    image = candidate_image(record['image'], request)
    return image, ['approval-sha256:' + p.sha256(data), 'candidate-receipt-sha256:' + record['receipt_sha256'],
                   'executor-machine-sha256:' + p.sha256(record['machine_id'].encode())]


def candidate_image(image, request):
    p.text(image, 250)
    p.require(re.fullmatch(IMAGE, image) and
              image.endswith('@sha256:' + request['candidate']['artifact_sha256']),
              'approval image must pin the exact candidate manifest digest')
    return image


def issue_approval(receipt, request, lifetime):
    p.require(os.geteuid() == 0, 'host approval requires the protected provisioner')
    p.number(lifetime, request['budgets']['seconds'] + 2, 3600)
    data = p.read_data(protected(receipt, file=True), MAX_CAPTURE)
    record = p.loads(data)
    p.fields(record, 'version job_id candidate image')
    p.number(record['version'], 1, 1)
    p.require(record['job_id'] == request['job_id'] and record['candidate'] == request['candidate'],
              'authorized candidate receipt differs from the requested job or candidate')
    machine = Path('/etc/machine-id').read_text().strip()
    p.digest(machine, 32)
    return {'version': 1, 'request_sha256': p.identity(request), 'image': candidate_image(record['image'], request),
            'receipt_sha256': p.sha256(data), 'machine_id': machine, 'expires_at': int(time.time()) + lifetime}


def publish_approval(record):
    p.require(os.geteuid() == 0, 'host approval publication requires the protected provisioner')
    directory = protected(APPROVAL.parent, file=False)
    if os.path.lexists(APPROVAL):
        protected(APPROVAL, file=True)
    fd, name = tempfile.mkstemp(prefix='.approval-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(p.canonical(record).encode() + b'\n')
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(name, APPROVAL)
        sync_directory(directory)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


@contextlib.contextmanager
def dispatch_gate():
    try:
        path = protected(FENCE / 'owner.lock', file=True)
    except FileNotFoundError as exc:
        raise ValueError('protected checklist renewal gate is unavailable') from exc
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as lock:
        info = os.fstat(lock.fileno())
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                  stat.S_IMODE(info.st_mode) == 0o644, 'invalid root-owned renewal dispatch gate')
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('checklist dispatch is frozen by renewal') from exc
        current = path.lstat()
        p.require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'renewal dispatch gate changed')
        p.require(not os.path.lexists(FENCE / 'frozen'), 'checklist dispatch is frozen by renewal')
        yield


def storage_identity(path):
    protected(path.parent, file=False)
    path = trusted_directory(path)
    rows = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    mounts = [row for row in rows if row[4] == str(path)]
    p.require(len(mounts) == 1, 'owned checklist block filesystem must be mounted at the storage leaf')
    mount = mounts[0]
    fs, source, options = mount[mount.index('-') + 1:][:3]
    device = path.stat().st_dev
    p.require(mount[2] == f'{os.major(device)}:{os.minor(device)}' and device != path.parent.stat().st_dev
              and mount[3] == '/' and fs in ('ext4', 'xfs') and source.startswith('/dev/')
              and 'rw' in mount[5].split(',') and not {'discard', 'discard=async'} & set(options.split(','))
              and sum(row[2] == mount[2] for row in rows) == 1,
              'checklist filesystem must be a dedicated, non-discarding ext4 or XFS root')
    backing = Path('/sys/dev/block') / mount[2] / 'loop/backing_file'
    if backing.exists():
        image = protected(Path(backing.read_text().strip()), file=True)
        info = image.stat()
        p.require(info.st_blocks * 512 >= info.st_size, 'checklist loop backing is not fully allocated')
    limits = os.statvfs(path)
    capacity = limits.f_blocks * limits.f_frsize
    p.require(0 < capacity <= MAX_STORAGE and 0 < limits.f_files <= MAX_INODES,
              'checklist filesystem exceeds its byte or inode limit')
    for leaf in ('graph', 'attempts'):
        p.require(trusted_directory(path / leaf).stat().st_dev == device,
                  'checklist writable leaf is outside the dedicated filesystem')
    return [f'storage-bytes:{capacity}', f'storage-inodes:{limits.f_files}', f'storage-fsid:{limits.f_fsid}']


def capture(argv, deadline, env):
    output = bytearray()
    with selectors.DefaultSelector() as sel:
        remaining(deadline)
        with subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, start_new_session=True) as child:
            try:
                sel.register(child.stdout, selectors.EVENT_READ)
                while True:
                    if not sel.select(remaining(deadline)):
                        raise TimeoutError('host command exceeded its deadline')
                    data = os.read(child.stdout.fileno(), min(4096, MAX_CAPTURE + 1 - len(output)))
                    if not data:
                        break
                    output.extend(data)
                    p.require(len(output) <= MAX_CAPTURE, 'host command exceeded its output limit')
                code = child.wait(timeout=remaining(deadline))
            except BaseException:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=1)
                raise
    remaining(deadline)
    return code, bytes(output)


def render(template, *, name, image, data, graph, runroot, seconds, tailnet_host=None, port=None):
    origin, network, restart = '', NETWORK, 'no'
    if tailnet_host is not None:
        p.require(len(tailnet_host) <= 253 and
                  re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}ts\.net', tailnet_host),
                  'deployment requires its exact .ts.net proxy hostname')
        p.number(port, 1024, 65535)
        p.require(seconds is None, 'persistent deployment uses independent service lifetime')
        origin = '--tailnet-host=' + tailnet_host
        network, restart, seconds = 'dev-pair-checklist-release', 'on-failure', 'infinity'
    else:
        p.require(port is None, 'validation uses a disposable loopback port')
        p.number(seconds, 1, 60)
    p.require(re.fullmatch(IMAGE, image), 'Quadlet requires an exact immutable OCI reference')
    substitutions = {'NAME': name, 'IMAGE': image, 'DATA': data, 'GRAPH': graph,
                     'RUNROOT': runroot, 'SECONDS': seconds, 'ORIGIN': origin, 'NETWORK': network,
                     'PORT': port or '', 'RESTART': restart}
    for key, value in substitutions.items():
        value = str(value)
        p.require(re.fullmatch(r'[a-zA-Z0-9/:@._=-]*', value), 'invalid fixed Quadlet substitution')
        template = template.replace('@' + key + '@', value)
    p.require(not re.search(r'@[A-Z_]+@', template), 'unexpanded Quadlet placeholder')
    if tailnet_host is not None:
        template += '\n[Install]\nWantedBy=default.target\n'
    return template.encode()


def deployment_unit(image, hostname, port, uid):
    p.number(uid, 1000, 2**31 - 1)
    template = p.read_data(TEMPLATE, MAX_CAPTURE).decode('ascii')
    return render(template, name='dp-checklist-app', image=image, data=LIVE_STORAGE / 'data',
                  graph=LIVE_STORAGE / 'graph', runroot=Path('/run/user') / str(uid) / 'dev-pair-checklist-live-runroot',
                  seconds=None, tailnet_host=hostname, port=port)


def rootless_environment():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    p.require((release.get('ID', '').strip('"'), release.get('VERSION_ID', '').strip('"')) == ('fedora', '44'),
              'checklist host check requires designated Fedora 44')
    account = pwd.getpwuid(os.getuid())
    p.require(account.pw_name == ACCOUNT and account.pw_uid == os.geteuid() >= 1000 and
              account.pw_gid == os.getgid() == os.getegid() and os.getgroups() in ([], [account.pw_gid]),
              'checklist executor requires its dedicated rootless account')
    p.require(Path(account.pw_dir) == HOME and account.pw_shell in ('/sbin/nologin', '/usr/sbin/nologin'),
              'checklist executor requires its fixed private home and nonlogin shell')
    trusted_directory(HOME)
    subordinate_ids(Path('/etc/subuid'), account.pw_uid, (entry.pw_uid for entry in pwd.getpwall()))
    subordinate_ids(Path('/etc/subgid'), account.pw_gid, (entry.gr_gid for entry in grp.getgrall()))
    runtime = trusted_directory(Path('/run/user') / str(account.pw_uid))
    bus = (runtime / 'bus').lstat()
    p.require(stat.S_ISSOCK(bus.st_mode) and bus.st_uid == account.pw_uid,
              'the checklist executor user systemd bus is unavailable')
    for command in ('/usr/bin/podman', '/usr/bin/systemctl', GETENFORCE, '/usr/bin/rm'):
        verify_executable(command)
    env = {'HOME': account.pw_dir, 'USER': ACCOUNT, 'PATH': '/usr/bin:/usr/sbin',
           'XDG_RUNTIME_DIR': str(runtime), 'LC_ALL': 'C.UTF-8',
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(runtime / 'bus')}
    return runtime, env


def verify_executable(command):
    path = protected(command, file=True)
    p.require(os.access(path, os.X_OK), 'required protected host executable is not executable')
    return path


def subordinate_ids(path, identity, live):
    data = p.read_data(protected(path, file=True), p.MAX_MESSAGE).decode('ascii')
    own, others = [], []
    for line in data.splitlines():
        name, start, size = line.split(':')
        start, size = int(start), int(size)
        p.number(start, 1, 2**32 - 2)
        p.number(size, 1, 2**32 - 1 - start)
        (own if name in (ACCOUNT, str(identity)) else others).append((start, start + size))
    p.require(len(own) == 1 and own[0][1] - own[0][0] == 65536,
              'checklist executor requires one 65,536-ID subordinate range')
    start, end = own[0]
    p.require(not any(start <= value < end for value in live) and
              all(right <= start or end <= left for left, right in others),
              'checklist executor subordinate range overlaps another identity')


class Quadlet:
    def __init__(self, runtime, env, attempt, image, candidate, budget):
        p.require(str(uuid.UUID(attempt)) == attempt, 'invalid checklist effect identity')
        self.name = 'dp-checklist-' + attempt
        self.unit = self.name + '.service'
        self.unit_path = runtime / 'containers/systemd' / (self.name + '.container')
        self.runtime = runtime
        self.env = env
        self.path = STORAGE / 'attempts' / attempt
        self.data = self.path / 'data'
        self.graph = STORAGE / 'graph'
        self.runroot = runtime / 'dev-pair-checklist-runroot'
        self.image = image
        self.candidate = candidate
        self.budget = budget
        self.logs = []
        self.storage_evidence = []
        self.path_created = False
        self.unit_written = False
        self.unit_stage = self.unit_path.with_suffix('.pending')
        self.unit_stage_owned = False

    def command(self, stage, argv, deadline, *, admit=(0,)):
        try:
            code, data = capture(argv, deadline, self.env)
        except (OSError, ValueError, subprocess.SubprocessError):
            self.logs.append(stage + ':command-interrupted')
            raise
        self.logs.append(f'{stage}:exit-{code}')
        p.require(code in admit, stage + ' did not complete')
        return code, data.decode('utf-8').strip()

    def systemd(self, stage, deadline, *args, admit=(0,)):
        return self.command(stage, ['/usr/bin/systemctl', '--user', '--no-pager', '--no-ask-password', *args],
                            deadline, admit=admit)[1]

    def podman(self, stage, deadline, *args, admit=(0,)):
        return self.command(stage, ['/usr/bin/podman', '--root', str(self.graph),
                                    '--runroot', str(self.runroot), *args], deadline, admit=admit)

    def enforcing(self, deadline):
        text = self.command('selinux', [GETENFORCE], deadline)[1]
        p.require(text == 'Enforcing', 'checklist host requires enforcing SELinux')

    def prepare(self, deadline, request_sha):
        self.enforcing(deadline)
        self.storage_evidence = storage_identity(STORAGE)
        p.require(next((STORAGE / 'attempts').iterdir(), None) is None,
                  'unresolved checklist resources require operator reconciliation')
        for directory in (self.unit_path.parent.parent, self.unit_path.parent, self.runroot):
            remaining(deadline)
            directory.mkdir(mode=0o700, exist_ok=True)
            trusted_directory(directory)
        _, network = self.podman('network-check', deadline, 'network', 'inspect', '--format',
                                 '{{.Name}} {{.Driver}} {{.Internal}}', NETWORK)
        p.require(network == NETWORK + ' bridge true', 'isolated internal bridge required')
        _, info = self.podman('podman-check', deadline, 'info', '--format',
                              '{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}} '
                              '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}} {{.Store.GraphRoot}} {{.Store.RunRoot}}')
        p.require(info == f'true true v2 systemd {self.graph} {self.runroot}',
                  'wrong rootless Podman storage or confinement')
        _, image = self.podman('image-check', deadline, 'image', 'inspect', '--format',
                               '{{.ID}}\n{{.Digest}}\n{{json .RepoDigests}}\n{{index .Labels "org.opencontainers.image.revision"}}',
                               self.image)
        fields = image.splitlines()
        p.require(len(fields) == 4, 'preloaded image or candidate identity is incomplete')
        references = p.loads(fields[2])
        identity = re.fullmatch(ID, fields[0])
        p.require(identity and fields[1] == 'sha256:' + self.candidate['artifact_sha256'] and
                  type(references) is list and self.image in references and fields[3] == self.candidate['source_revision'],
                  'preloaded image source or manifest digest differs from the approval')
        self.image_id = identity[1]
        code, _ = self.podman('verify-name-unoccupied', deadline, 'container', 'exists', self.name, admit=(0, 1))
        p.require(code == 1, 'preexisting checklist container identity is reserved')
        remaining(deadline)
        self.path.mkdir(mode=0o700)
        self.path_created = True
        remaining(deadline)
        self.data.mkdir(mode=0o700)
        remaining(deadline)
        write_private(self.path / 'operation.json', p.canonical({
            'attempt_id': self.path.name, 'request_sha256': request_sha, 'unit': self.unit,
            'image': self.image, 'image_id': self.image_id,
        }).encode())
        sync_directory(self.path)
        sync_directory(self.path.parent)
        template = p.read_data(TEMPLATE, MAX_CAPTURE).decode('ascii')
        content = render(template, name=self.name, image=self.image, data=self.data, graph=self.graph,
                         runroot=self.runroot, seconds=self.budget // 2)
        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL
        remaining(deadline)
        with os.fdopen(os.open(self.unit_stage, flags, 0o600), 'wb') as stream:
            self.unit_stage_owned = True
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        remaining(deadline)
        os.link(self.unit_stage, self.unit_path, follow_symlinks=False)
        self.unit_written = True
        remaining(deadline)
        self.unit_stage.unlink()
        self.unit_stage_owned = False
        self.systemd('load-quadlet', deadline, 'daemon-reload')
        manager = self.manager(deadline)
        p.require(manager['ActiveState'] == 'inactive', 'checklist unit must initially be inactive')
        return ['image-id:' + self.image_id, 'selinux:enforcing']

    def manager(self, deadline):
        output = self.systemd('inspect-manager', deadline, 'show',
                              '--property=SourcePath,FragmentPath,DropInPaths,ActiveState,InvocationID', self.unit)
        fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        p.fields(fields, 'SourcePath FragmentPath DropInPaths ActiveState InvocationID')
        generators = ('generator', 'generator.early', 'generator.late')
        p.require(fields['SourcePath'] == str(self.unit_path) and fields['DropInPaths'] == '' and
                  fields['FragmentPath'] in {str(self.runtime / 'systemd' / leaf / self.unit) for leaf in generators},
                  'systemd did not load the exact generated Quadlet without overrides')
        return fields

    def service(self, action, deadline):
        p.require(action in ('start', 'restart'), 'unsupported checklist service action')
        remaining(deadline)
        if action == 'restart':
            write_private(self.path / 'restart-requested', b'restart\n')
            sync_directory(self.path)
        self.systemd(action, deadline, action, self.unit)
        manager = self.manager(deadline)
        p.require(manager['ActiveState'] == 'active' and re.fullmatch(r'[0-9a-f]{32}', manager['InvocationID']),
                  'Quadlet unit is not active with a unique invocation')
        self.enforcing(deadline)
        _, result = self.podman('inspect-container', deadline, 'container', 'inspect', '--format',
                                '{{.ID}}\n{{.Image}}\n{{.State.Running}}\n{{.State.Pid}}\n{{.ProcessLabel}}\n{{.MountLabel}}\n'
                                '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}} {{.HostConfig.PidsLimit}} {{.Config.User}}',
                                self.name)
        fields = result.splitlines()
        p.require(len(fields) == 7 and re.fullmatch(ID, fields[0]) and re.fullmatch(ID, fields[1])
                  and re.fullmatch(ID, fields[1])[1] == self.image_id and fields[2] == 'true'
                  and fields[3].isdigit() and int(fields[3]) > 1, 'container image or process identity differs')
        p.require(fields[6] == 'true false 32 65532:65532', 'container does not match read-only process policy')
        process, mounted = (field.split(':', 3) for field in fields[4:6])
        actual = os.getxattr(self.data, 'security.selinux').decode('ascii').rstrip('\x00').split(':', 3)
        p.require(len(process) == len(mounted) == len(actual) == 4 and process[2] == 'container_t'
                  and mounted[2] == 'container_file_t' and mounted[2:] == actual[2:]
                  and process[3] == mounted[3] and re.fullmatch(r's0:c[0-9]+,c[0-9]+', process[3]),
                  'container and data SELinux isolation could not be established')
        _, published = self.podman('inspect-loopback', deadline, 'port', self.name, '8000/tcp')
        found = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})', published)
        p.require(found and 0 < int(found[1]) <= 65535, 'checklist service is not bound to IPv4 loopback only')
        return int(found[1]), manager['InvocationID'], re.fullmatch(ID, fields[0])[1]

    def cleanup(self, deadline):
        if self.unit_stage_owned:
            remaining(deadline)
            self.unit_stage.unlink()
        if self.unit_written:
            self.manager(deadline)
            self.systemd('stop', deadline, 'stop', self.unit)
            p.require(self.manager(deadline)['ActiveState'] == 'inactive', 'owned checklist service did not stop')
            code, _ = self.podman('verify-container-absent', deadline, 'container', 'exists', self.name, admit=(0, 1))
            p.require(code == 1, 'owned checklist container remained after stop')
            remaining(deadline)
            self.unit_path.unlink()
            self.systemd('unload-quadlet', deadline, 'daemon-reload')
        if self.path_created:
            self.command('remove-test-data', ['/usr/bin/rm', '-rf', '--one-file-system', '--', str(self.path)], deadline)
            p.require(not self.path.exists(), 'owned checklist test data remained after cleanup')
            sync_directory(self.path.parent)

    def verify_absent(self, deadline, staged):
        self.enforcing(deadline)
        storage = storage_identity(STORAGE)
        if staged is not None and staged['cleanup']['status'] == 'complete':
            sampled = [entry for entry in staged['evidence'] if entry.startswith('storage-fsid:')]
            p.require(len(sampled) == 1 and sampled[0] in storage,
                      'checklist filesystem identity changed since the staged observation')
        p.require(not any(os.path.lexists(path) for path in (self.path, self.unit_path, self.unit_stage)),
                  'matching checklist workspace or unit source is still present')
        output = self.systemd('verify-unit-absent', deadline, 'show',
                              '--property=LoadState,ActiveState,MainPID,ControlPID', self.unit, admit=(0, 1))
        fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        p.require(fields.get('LoadState') == 'not-found' and fields.get('ActiveState') == 'inactive' and
                  fields.get('MainPID', '0') == fields.get('ControlPID', '0') == '0',
                  'matching checklist systemd unit is present or its state is uncertain')
        code, _ = self.podman('verify-container-absent', deadline, 'container', 'exists', self.name, admit=(0, 1))
        p.require(code == 1, 'matching checklist container is still present')
        remaining(deadline)
