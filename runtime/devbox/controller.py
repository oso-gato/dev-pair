#!/usr/bin/python3
"""Fixed, offline DevBox capability controller and shared launch contract."""

from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
DISTROBOX = '40c3cd724faa434aeb0a23e28776665b92de68bd'
ENTER_SHA256 = '75359e1965dcb9897a221db7818be098138154ee11c2eb2de34989a37c4b8bb8'
CODEX_VERSION = '0.169.0'
BASE = Path('/usr/lib/dev-pair/devbox')
GPTBOX = '/usr/lib/dev-pair/gptbox'
PODMAN = '/usr/bin/podman'
CRUN = '/usr/bin/crun'
GIB = 1024 ** 3
MANIFEST_LIMIT = 65536
OUTPUT_LIMIT = 1024 * 1024
OUTER_SECONDS = 600
INNER_SECONDS = 180
CLEANUP_SECONDS = 45
GRAPHROOT = '/devbox/graph'
RUNROOT = '/run/dev-pair'
ARCHIVE = '/admission/development.oci.tar'
MANIFEST = '/admission/manifest.json'
PARENT_JOB = '/devbox/job'
JOB_TARGETS = {'workspaces': '/work/job', 'state': '/state', 'cache': '/cache/job'}
CAP_KEYS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
OUTER_CAPS = (0, 0, 0, 0xc0, 0)
NS_NAMES = ('user', 'mnt', 'pid', 'ipc', 'uts', 'net')
STARTED = re.compile(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})')


class Blocked(RuntimeError):
    """A failed precondition or confinement check."""


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def unique_pairs(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate JSON field')
    return result


def json_data(data):
    try:
        return json.loads(data, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Blocked('invalid JSON from manifest or runtime') from error


def fields(value, keys, name):
    require(type(value) is dict and value.keys() == set(keys.split()), f'{name} fields mismatch')


def hex_id(value, size=64):
    require(isinstance(value, str) and re.fullmatch(f'[0-9a-f]{{{size}}}', value),
            'invalid immutable digest')
    return value


def engine_id(value):
    require(isinstance(value, str), 'missing engine identity')
    return hex_id(value.removeprefix('sha256:'))


def file_hash(path, maximum, deadline, *, content=False):
    digest = hashlib.sha256()
    pieces = []
    size = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                f'{path.name} is not a bounded regular file')
        while piece := os.read(fd, 1024 * 1024):
            require(time.monotonic() < deadline, f'{path.name} hashing timed out')
            size += len(piece)
            require(size <= before.st_size, f'{path.name} grew during verification')
            digest.update(piece)
            if content:
                pieces.append(piece)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    current = path.stat(follow_symlinks=False)
    require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (size, after.st_mtime_ns, after.st_ctime_ns)
            and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
            (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns),
            f'{path.name} changed during verification')
    return digest.hexdigest(), size, b''.join(pieces)


def read_manifest(path, expected, deadline):
    actual, _, content = file_hash(path, MANIFEST_LIMIT, deadline, content=True)
    require(actual == hex_id(expected), 'manifest SHA-256 mismatch')
    result = json_data(content)
    fields(result, 'kind standards_sha job storage_bytes outer inner categories', 'manifest')
    require(result['kind'] == 'dev-pair-development-nested-v1' and result['standards_sha'] == STANDARDS,
            'development placement or standards pin mismatch')
    require(isinstance(result['job'], str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', result['job']),
            'job must identify one development leaf')
    budget = result['storage_bytes']
    require(type(budget) is int and 0 < budget <= 20 * GIB, 'invalid storage ceiling')
    outer, inner = result['outer'], result['inner']
    fields(outer, 'image_id source_sha', 'DevBox candidate')
    fields(inner, 'image_id source_sha context_sha256 inputs_sha256 sealed_sha256 archive_sha256 archive_bytes diff_ids',
           'development gptbox candidate')
    for image in (outer, inner):
        hex_id(image['image_id'])
        hex_id(image['source_sha'], 40)
    require(outer['image_id'] != inner['image_id'], 'outer and inner image identities must differ')
    for key in ('context_sha256', 'inputs_sha256', 'sealed_sha256', 'archive_sha256'):
        hex_id(inner[key])
    require(type(inner['archive_bytes']) is int and 0 < inner['archive_bytes'] < budget,
            'archive does not fit the dedicated storage ceiling')
    arrays = inner['diff_ids']
    require(type(arrays) is list and 1 <= len(arrays) <= 128, 'missing or excessive image layer identities')
    for value in arrays:
        require(isinstance(value, str) and value == 'sha256:' + engine_id(value), 'invalid image layer digest')
    fields(result['categories'], 'outer inner', 'SELinux allocation')
    for key, count in (('outer', 3), ('inner', 2)):
        values = result['categories'][key]
        require(type(values) is list and len(values) == count
                and all(type(value) is int and 0 <= value <= 1023 for value in values)
                and values == sorted(set(values)), f'invalid {key} SELinux categories')
    require(set(result['categories']['inner']) < set(result['categories']['outer']),
            'inner categories must be a proper subset of the parent envelope')
    return result


def label_level(manifest, side):
    return 's0:' + ','.join(f'c{category}' for category in manifest['categories'][side])


def process_label(manifest, side):
    label_type = 'container_engine_t' if side == 'outer' else 'container_t'
    return f'system_u:system_r:{label_type}:{label_level(manifest, side)}'


def file_label(manifest, side):
    return 'system_u:object_r:container_file_t:' + label_level(manifest, side)


def local_env(path='/usr/bin:/usr/sbin:/bin'):
    return {'PATH': path, 'LANG': 'C.UTF-8'}


def bounded(argv, deadline, *, env, seconds=30, allowed=(0,)):
    end = min(deadline, time.monotonic() + seconds)
    require(end > time.monotonic(), 'operation deadline expired')
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd='/', env=env, start_new_session=True)
    except OSError as error:
        raise Blocked(f'{Path(argv[0]).name} unavailable: {error.strerror}') from error
    output, stderr = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, output)
            selector.register(child.stderr, selectors.EVENT_READ, stderr)
            while selector.get_map():
                remaining = end - time.monotonic()
                require(remaining > 0, 'command timed out')
                for key, _ in selector.select(remaining):
                    piece = os.read(key.fd, 65536)
                    if not piece:
                        selector.unregister(key.fileobj)
                    else:
                        key.data.extend(piece)
                        require(len(output) + len(stderr) <= OUTPUT_LIMIT, 'command output limit exceeded')
        remaining = end - time.monotonic()
        require(remaining > 0, 'command timed out')
        status = child.wait(timeout=remaining)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        raise
    finally:
        child.stdout.close()
        child.stderr.close()
    if status not in allowed:
        details = stderr[-2048:].decode('utf-8', errors='replace')
        details = ''.join(character if character.isprintable() else ' ' for character in details).strip()
        raise Blocked(f'command exit {status}' + (f' — {details}' if details else ''))
    return status, bytes(output)


class Engine:
    def __init__(self, command, env, deadline):
        self.command, self.env, self.deadline = command, env, deadline

    def __call__(self, stage, *args, seconds=30, allowed=(0,)):
        try:
            return bounded([*self.command, *args], self.deadline, env=self.env, seconds=seconds, allowed=allowed)
        except (Blocked, subprocess.TimeoutExpired) as error:
            raise Blocked(f'{stage}: {error}') from error

    def inspect(self, kind, identity):
        _, result = self('inspect ' + kind, 'inspect', '--type=' + kind, identity, seconds=10)
        rows = json_data(result)
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
                'ambiguous ' + kind + ' inspection')
        return rows[0]


def immutable_image(engine, manifest, side):
    release = manifest[side]
    row = engine.inspect('image', release['image_id'])
    require(engine_id(row.get('Id')) == release['image_id'] and row.get('Os') == 'linux'
            and row.get('Architecture') == 'amd64', 'local immutable image/config identity mismatch')
    expected = {'dev-pair.role': 'devbox' if side == 'outer' else 'development',
                'dev-pair.standards': STANDARDS, 'dev-pair.distrobox': DISTROBOX,
                'org.opencontainers.image.revision': release['source_sha']}
    if side == 'inner':
        expected.update({'dev-pair.context': release['context_sha256'],
                         'dev-pair.inputs': release['inputs_sha256'],
                         'dev-pair.codex.version': CODEX_VERSION})
        require(row['RootFS']['Layers'] == release['diff_ids'], 'loaded image layer identities mismatch')
    labels = row.get('Labels') or row.get('Config', {}).get('Labels') or {}
    require(all(labels.get(key) == value for key, value in expected.items()),
            f'{side} image role or provenance mismatch')


def bind(source, target, rw, *, executable=False):
    access = 'rw' if rw else 'ro'
    safety = '' if executable else ',noexec'
    return f'--volume={source}:{target}:{access},nosuid,nodev,rprivate{safety}'


def container_args(name, owner, manifest, side, hooks):
    outer = side == 'outer'
    args = [f'--name={name}', f'--label=dev-pair.devbox-owner={owner}', '--pull=never', '--restart=no',
            f'--timeout={OUTER_SECONDS if outer else INNER_SECONDS}', '--read-only', '--read-only-tmpfs=false',
            '--user=1000:1000', '--userns=keep-id:uid=1000,gid=1000', '--network=none', '--pid=private',
            '--ipc=private', '--uts=private', '--cap-drop=ALL', '--log-driver=k8s-file',
            '--log-opt=max-size=1mb', '--no-hosts', '--no-hostname', '--dns=none',
            '--image-volume=ignore', '--http-proxy=false', '--sdnotify=ignore', '--systemd=false',
            f'--hooks-dir={hooks}', '--workdir=/', '--unsetenv-all',
            f'--security-opt=label=level:{label_level(manifest, side)}']
    for path, size in (('/run', '64m' if outer else '16m'), ('/tmp', '64m' if outer else '16m')):
        args.append(f'--tmpfs={path}:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=0700,notmpcopyup,size={size}')
    if outer:
        return args + ['--cap-add=SETUID', '--cap-add=SETGID',
                       '--security-opt=label=nested', '--security-opt=label=type:container_engine_t',
                       '--cgroupns=private', '--memory=2g', '--memory-swap=2g', '--pids-limit=512',
                       '--cpus=1', '--rm']
    return args + ['--security-opt=no-new-privileges', '--security-opt=label=type:container_t',
                   '--cgroups=disabled', '--cgroupns=host',
                   '--label=manager=distrobox', '--label=distrobox.unshare_groups=0',
                   '--env=HOME=/home/gpt', '--env=PATH=/opt/dev-pair/bin:/usr/bin:/bin']


def inspect_policy(row, identity, owner, manifest, side, mounts):
    outer = side == 'outer'
    config, host = row['Config'], row['HostConfig']
    require(engine_id(row.get('Id')) == identity and engine_id(row.get('Image')) == manifest[side]['image_id']
            and config.get('Labels', {}).get('dev-pair.devbox-owner') == owner,
            f'{side} container identity/image/ownership mismatch')
    require(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
            and config.get('User') == '1000:1000' and host.get('NetworkMode') == 'none'
            and all(host.get(key) == 'private' for key in ('PidMode', 'IpcMode', 'UTSMode'))
            and host.get('UsernsMode') in ('private', 'keep-id'),
            f'{side} runtime readonly/namespace policy mismatch')
    require(row.get('ProcessLabel') == process_label(manifest, side)
            and row.get('MountLabel') == file_label(manifest, side), f'{side} SELinux policy mismatch')
    require(config.get('Timeout') == (OUTER_SECONDS if outer else INNER_SECONDS)
            and host.get('RestartPolicy', {}).get('Name', '') in ('', 'no')
            and not host.get('PortBindings') and not host.get('Devices'), f'{side} lifetime/device policy mismatch')
    security = host.get('SecurityOpt') or []
    require(not any('unconfined' in option or 'label=disable' in option for option in security),
            f'{side} contains a confinement exception')
    require(set(host.get('Tmpfs') or {}) == {'/run', '/tmp'}, f'{side} temporary mount allowlist mismatch')
    actual = {}
    for mount in row.get('Mounts', []):
        target = mount['Destination']
        if mount['Type'] == 'tmpfs' and target in ('/run', '/tmp'):
            continue
        require(mount['Type'] == 'bind' and target not in actual, f'{side} undeclared mount')
        actual[target] = (mount['Source'], mount['RW'])
    require(actual == mounts, f'{side} bind allowlist mismatch')
    if outer:
        require(host.get('CgroupMode') == 'private' and host.get('Memory') == 2 * GIB
                and host.get('PidsLimit') == 512 and host.get('NanoCpus') == 1000000000,
                'parent inspected aggregate cgroup policy mismatch')
    else:
        require(host.get('Cgroups') == 'disabled' and row.get('EffectiveCaps') == []
                and row.get('BoundingCaps') == [] and not host.get('CapAdd')
                and config.get('Labels', {}).get('manager') == 'distrobox',
                'inner cgroup, capability or Distrobox policy mismatch')


def remove_owned(engine, name, owner, image):
    status, _ = engine('look up owned container', 'container', 'exists', name, allowed=(0, 1))
    if status == 1:
        return
    try:
        row = engine.inspect('container', name)
    except Blocked:
        status, _ = engine('recheck owned container', 'container', 'exists', name, allowed=(0, 1))
        if status == 1:
            return
        raise
    require(row.get('Name', '').lstrip('/') == name and engine_id(row.get('Image')) == image
            and row.get('Config', {}).get('Labels', {}).get('dev-pair.devbox-owner') == owner,
            'container cleanup ownership mismatch')
    identity = engine_id(row.get('Id'))
    engine('remove owned container', 'rm', '--ignore', '--force', '--time=5', identity, seconds=20)
    status, _ = engine('verify owned container removal', 'container', 'exists', identity, allowed=(0, 1))
    require(status == 1, 'owned container still exists after removal')


@contextmanager
def owned_container(engine, name, owner, image):
    remove_owned(engine, name, owner, image)

    def cleanup():
        deadline = min(engine.deadline + CLEANUP_SECONDS, time.monotonic() + CLEANUP_SECONDS)
        recovery = Engine(engine.command, engine.env, deadline)
        remove_owned(recovery, name, owner, image)

    try:
        yield
    except BaseException as failure:
        try:
            cleanup()
        except (Blocked, OSError) as error:
            raise Blocked(f'{failure}; owned container cleanup unresolved: {error}') from failure
        raise
    else:
        cleanup()


def ids(rows, allowed, caller):
    entries = [tuple(int(number) for number in line.split()) for line in rows.splitlines()]
    require(0 < len(entries) <= 8 and all(len(entry) == 3 for entry in entries),
            'invalid namespace map entry count')
    mapping = {}
    for start, outside, count in entries:
        require(start >= 0 and outside > 0 and 0 < count <= 65537,
                'namespace mapping includes ancestor root or an invalid range')
        require(start + count <= 65537 and all(key not in mapping for key in range(start, start + count)),
                'namespace map ranges overlap')
        mapping.update((start + offset, outside + offset) for offset in range(count))
    wanted = set().union(*(range(start, start + count) for start, count in allowed))
    require(caller > 0 and caller not in wanted, 'caller overlaps a reserved namespace range')
    wanted.add(caller)
    require(set(mapping) == set(range(len(wanted))) and set(mapping.values()) == wanted
            and mapping.get(1000) == caller and 65534 in mapping, 'namespace subordinate-ID composition mismatch')
    return entries


def proc_snapshot(root, capabilities, nnp, label, uid, gid):
    status = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines() if ':' in line)
    require(tuple(int(status[key], 16) for key in CAP_KEYS) == capabilities
            and status['NoNewPrivs'].strip() == str(nnp) and status['Seccomp'].strip() == '2',
            'effective capability, NNP or seccomp policy mismatch')
    require(status['Uid'].split() == [str(uid)] * 4 and status['Gid'].split() == [str(gid)] * 4
            and status['Groups'].split() in ([], [str(gid)]), 'effective UID, GID or groups policy mismatch')
    actual = (root / 'attr/current').read_text().strip('\x00\n')
    require(actual == label, 'effective SELinux process label mismatch')
    return {'namespaces': {name: os.readlink(root / 'ns' / name) for name in NS_NAMES},
            'cgroup': (root / 'cgroup').read_text().strip(), 'label': actual}


def observed_mounts(root, binds):
    rows = {}
    for line in (root / 'mountinfo').read_text().splitlines():
        leading, trailing = line.split(' - ', 1)
        values = leading.split()
        rows.setdefault(values[4], []).append((set(values[5].split(',')), trailing.split(' ', 1)[0]))

    def find(target):
        entries = rows.get(target, [])
        require(len(entries) == 1, f'expected exactly one active mount at {target}')
        return entries[0]

    require('ro' in find('/')[0], 'effective root filesystem is writable')
    if '/sys/fs/cgroup' in rows:
        require('ro' in find('/sys/fs/cgroup')[0], 'effective cgroup filesystem is writable')
    for target in ('/run', '/tmp'):
        options, kind = find(target)
        require(kind == 'tmpfs' and {'rw', 'nosuid', 'nodev', 'noexec'} <= options,
                f'unsafe effective temporary mount at {target}')
    for target, is_writable in binds.items():
        options, _ = find(target)
        expected = {'nosuid', 'nodev', 'rw' if is_writable else 'ro'}
        if target != GRAPHROOT:
            expected.add('noexec')
        require(expected <= options, f'effective mount flags differ at {target}')


def probe_parent_writes():
    for path in ('/usr', '/etc', '/home/gpt', str(BASE)):
        probe = Path(path) / f'.devbox-{os.getpid()}-write-probe'
        try:
            descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except PermissionError:
            continue
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            os.close(descriptor)
            probe.unlink()
            raise Blocked(f'parent protected path is writable: {path}')


def inner_environment():
    env = local_env(str(BASE / 'bin') + ':/usr/bin:/usr/sbin:/bin')
    env.update({'HOME': '/home/gpt', 'USER': 'gpt', 'LOGNAME': 'gpt', 'DBX_CONTAINER_MANAGER': 'podman',
                'XDG_CONFIG_HOME': str(BASE / 'xdg-config'), 'XDG_CACHE_HOME': '/tmp',
                'XDG_RUNTIME_DIR': '/run/user/1000', 'CONTAINERS_CONF': str(BASE / 'containers.conf'),
                'STORAGE_DRIVER': 'vfs'})
    return env


def helper_caps():
    for name, cap in (('newuidmap', 7), ('newgidmap', 6)):
        path = Path('/usr/bin') / name
        mode = path.stat().st_mode
        require(not path.is_symlink() and stat.S_ISREG(mode) and not mode & (stat.S_ISUID | stat.S_ISGID),
                f'unsafe mapping helper mode: {name}')
        data = os.getxattr(path, 'security.capability')
        permitted = (0x02000001, 1 << cap, 0, 0, 0)
        valid = (len(data) == 20 and struct.unpack('<5I', data) == permitted
                 or len(data) == 24 and struct.unpack('<6I', data) == (0x03000001, *permitted[1:], 0))
        require(valid, f'expected mapping helper xattr is unavailable: {name}')


def ready(engine, identity, check, previous):
    end = min(time.monotonic() + 30, engine.deadline)
    started = None
    while time.monotonic() < end:
        row = engine.inspect('container', identity)
        check(row)
        state = row['State']
        current = state.get('StartedAt')
        require(state.get('Running') is True and type(current) is str and STARTED.fullmatch(current)
                and current != previous and (started is None or current == started),
                'inner frozen start exited or changed identity before readiness')
        started = current
        _, output = engine('current frozen readiness logs', 'logs', '--since=' + started, '--tail=20', identity,
                           seconds=5)
        if b'container_setup_done' in output.splitlines():
            return row
        time.sleep(0.2)
    raise Blocked('inner frozen readiness deadline exceeded')


def check_inner_inputs(engine, identity, release):
    evidence = {}
    for name in ('inputs', 'sealed'):
        _, output = engine('immutable development ' + name, 'exec', '--user=1000:1000', identity,
                           '/usr/bin/cat', f'{GPTBOX}/{name}.json')
        require(hashlib.sha256(output).hexdigest() == release[name + '_sha256'],
                f'inner {name} digest mismatch')
        evidence[name] = json_data(output)
    inputs, sealed = evidence['inputs'], evidence['sealed']
    require(inputs.get('role') == 'development' and inputs.get('source_sha') == release['source_sha']
            and sealed.get('kind') == 'genuine-distrobox-assembled'
            and sealed.get('source_sha') == release['source_sha']
            and sealed.get('inputs_sha256') == release['inputs_sha256']
            and (sealed.get('uid'), sealed.get('gid')) == (1000, 1000),
            'separate development-role frozen assembly identity missing')


def fixed_entry(engine, identity, operation, check, started):
    require(operation in ('probe', 'version'), 'unsupported Distrobox capability operation')
    def live():
        row = engine.inspect('container', identity)
        check(row)
        require(row['State'].get('Running') is True and row['State'].get('StartedAt') == started,
                'entry requires the current running identity')
    live()
    try:
        _, output = bounded([str(BASE / 'distrobox-enter'), '--name', identity, '--no-tty', '--no-workdir',
                             '--clean-path', '--', '/usr/bin/python3', '-I', GPTBOX + '/runtime.py',
                             'entry', operation], engine.deadline, env=engine.env)
    except Blocked as error:
        raise Blocked(f'pinned Distrobox {operation}: {error}') from error
    live()
    return output


def controller(expected, owner, seconds):
    end = time.monotonic() + seconds
    manifest = read_manifest(Path(MANIFEST), expected, end)
    require(os.getuid() == os.getgid() == 1000 and os.getgroups() in ([], [1000]), 'controller user mismatch')
    self_proc = Path('/proc/self')
    parent = proc_snapshot(self_proc, OUTER_CAPS, 0, process_label(manifest, 'outer'), 1000, 1000)
    observed_mounts(self_proc, {GRAPHROOT: True, ARCHIVE: False, MANIFEST: False,
                               **{f'{PARENT_JOB}/{key}': True for key in JOB_TARGETS}})
    probe_parent_writes()
    helper_caps()
    require(file_hash(BASE / 'distrobox-enter', MANIFEST_LIMIT, end)[0] == ENTER_SHA256,
            'pinned Distrobox entry bytes mismatch')
    require(not Path('/run/podman/podman.sock').exists() and not Path('/run/host').exists(),
            'parent engine socket/host bridge exposed')
    Path('/run/user/1000').mkdir(mode=0o700, parents=True, exist_ok=True)
    env = inner_environment()
    engine = Engine([PODMAN, '--remote=false', '--runtime=' + CRUN, '--root=' + GRAPHROOT, '--runroot=' + RUNROOT,
                     '--storage-driver=vfs', '--events-backend=file', '--cgroup-manager=cgroupfs'], env, end)
    _, info = engine('nested rootless VFS engine', 'info', '--format=json')
    info = json_data(info)
    require(info['host']['security'].get('rootless') is True and info['host']['security'].get('selinuxEnabled') is True
            and info['store']['graphDriverName'] == 'vfs' and info['store']['graphRoot'] == GRAPHROOT
            and info['store']['runRoot'] == RUNROOT, 'nested rootless VFS/SELinux policy mismatch')
    _, mappings = engine('nested UID/GID mapping', 'unshare', '/usr/bin/cat', '/proc/self/uid_map', '/proc/self/gid_map')
    lines = mappings.decode('ascii').splitlines()
    require(len(lines) == 6, 'unexpected engine mapping ranks')
    for section in (lines[:3], lines[3:]):
        # Podman unshare maps its caller to namespace root before creating the keep-id child.
        triples = [tuple(int(number) for number in line.split()) for line in section]
        require(sorted(triples) == [(0, 1000, 1), (1, 1, 999), (1000, 1001, 64536)],
                'rootless engine user namespace map mismatch')
    release = manifest['inner']
    archive = Path(ARCHIVE)
    archive_identity = (release['archive_sha256'], release['archive_bytes'])
    require(file_hash(archive, release['archive_bytes'], end)[:2] == archive_identity,
            'development OCI archive digest or byte count mismatch')
    engine('load development OCI archive', 'load', '--input', ARCHIVE, seconds=250)
    require(file_hash(archive, release['archive_bytes'], end)[:2] == archive_identity,
            'development OCI archive changed during import')
    immutable_image(engine, manifest, 'inner')
    name = 'dp-nested-' + owner[:24]
    target = {dest: (f'{PARENT_JOB}/{key}', True) for key, dest in JOB_TARGETS.items()}
    mounts = [bind(src, dest, rw) for dest, (src, rw) in target.items()]
    cycles = []
    def check(row):
        inspect_policy(row, identity, owner, manifest, 'inner', target)
    with owned_container(engine, name, owner, release['image_id']):
        _, created = engine('create nested development gptbox', 'create',
                            *container_args(name, owner, manifest, 'inner', BASE / 'empty-hooks'), *mounts,
                            '--entrypoint=/usr/bin/distrobox-init', release['image_id'], '--name', 'gpt', '--user',
                            '1000', '--group', '1000', '--home', '/home/gpt', '--init', '0', '--pre-init-hooks',
                            'exec /usr/bin/python3 -I ' + GPTBOX + '/runtime.py frozen')
        identity = engine_id(created.decode('ascii').strip())
        check(engine.inspect('container', identity))
        previous = None
        for _ in range(2):
            engine('start nested development gptbox', 'start', identity)
            state = ready(engine, identity, check, previous)['State']
            previous = state['StartedAt']
            pid = state.get('Pid')
            require(type(pid) is int and pid > 1, 'inner PID is unavailable to parent')
            proc = Path('/proc') / str(pid)
            child = proc_snapshot(proc, (0, 0, 0, 0, 0), 1, process_label(manifest, 'inner'), 1000, 1000)
            observed_mounts(proc, dict.fromkeys(JOB_TARGETS.values(), True))
            require(child['cgroup'] == parent['cgroup']
                    and all(child['namespaces'][key] != parent['namespaces'][key] for key in NS_NAMES),
                    'inner process does not have private namespaces inside the outer cgroup')
            for kind in ('uid', 'gid'):
                child[kind + '_map'] = ids((proc / (kind + '_map')).read_text(), [(1, 999), (1001, 64536)], 1000)
            check_inner_inputs(engine, identity, release)
            probe = json_data(fixed_entry(engine, identity, 'probe', check, previous))
            require(probe.get('boundary_probe') == 'passed' and probe.get('uid') == 1000
                    and probe.get('selinux_label') == child['label'], 'Distrobox inner protected-write probe failed')
            version = fixed_entry(engine, identity, 'version', check, previous).strip()
            require(version == f'codex-cli {CODEX_VERSION}'.encode(), 'Distrobox Codex version mismatch')
            engine('stop nested development gptbox', 'stop', '--time=5', identity, seconds=15)
            cycles.append({'started_at': previous, 'proc': child, 'probe': probe, 'version': version.decode('ascii')})
    return {'kind': 'dev-pair-devbox-probe-v1', 'manifest_sha256': expected, 'owner': owner,
            'inner_container_id': identity, 'inner_image_id': release['image_id'], 'cycles': cycles,
            'inner_removed': True, 'job_admission': False}


def interrupt(signum, _frame):
    raise Blocked(f'interrupted by signal {signum}')


if __name__ == '__main__':
    try:
        signal.signal(signal.SIGTERM, interrupt)
        signal.signal(signal.SIGINT, interrupt)
        require(len(sys.argv) == 4, 'expected manifest digest, ownership token and probe seconds')
        budget = int(sys.argv[3])
        require(0 < budget < OUTER_SECONDS - CLEANUP_SECONDS, 'invalid nested time budget')
        print(json.dumps(controller(hex_id(sys.argv[1]), hex_id(sys.argv[2]), budget), sort_keys=True))
    except (Blocked, OSError, KeyError, ValueError, TypeError, IndexError, subprocess.TimeoutExpired) as error:
        print(f'DevBox controller blocked: {error}', file=sys.stderr)
        sys.exit(2)
