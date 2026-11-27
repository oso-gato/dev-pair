#!/usr/bin/python3
"""Stage the exact portable release into prepared Fedora role stores."""

import argparse
import gzip
import copy
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

import devbox
import gptbox
import platform_release as release
import platform_release_intake as intake
from storage import MANAGED_CEILING
from platform_release_protocol import (
    ARCHIVE_LIMIT, CONTROL_LIMIT, EXPANSION_LIMIT, GIB, HOST_LIMIT, Blocked, canonical, fields,
    file_hash, hex_id, json_bytes, regular, require, seconds,
)

ROOT = Path('/var/lib/dev-pair')
INSTALL = Path('/usr/libexec/dev-pair')
HOST_RELEASES = INSTALL / 'host-releases'
SITE_CONFIGS = Path('/etc/dev-pair/renewal/site-configs')
HOST_CONFIGS = Path('/etc/dev-pair/host-releases')
MAINTENANCE = ROOT / 'maintenance/images'
ADAPTER = ROOT / 'bootstrap/gptbox-adapter'
ENGINE_CONTROL = Path('/usr/local/libexec/dev-pair-gptbox')
G_ENTRY = INSTALL / 'tools/native_placements.py'
P_ENTRY = INSTALL / 'tools/gptbox.py'
CGROUP_ROOT = Path('/sys/fs/cgroup/system.slice')
SYSTEMCTL = '/usr/bin/systemctl'
PODMAN = '/usr/bin/podman'
TIME_LIMIT = 900
MAX_JOBS = 32
HOST_RELEASE_HEADROOM = 3 * (HOST_LIMIT + CONTROL_LIMIT)
ENV = {'PATH': '/usr/bin:/usr/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}


def protected_json(path, expected=None):
    raw, value = release.readonly_json(intake.protected(path), 0)
    if expected is not None:
        require(release.digest(raw) == hex_id(expected), 'protected site or release record digest changed')
    return value, raw


def site_configuration(path, identity):
    config, _ = protected_json(path, identity)
    fields(config, 'schema hostname host_config_sha256 jobs')
    require(type(config['schema']) is int and config['schema'] == 1 and type(config['hostname']) is str and
            re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', config['hostname']), 'protected platform site configuration is invalid')
    hex_id(config['host_config_sha256'])
    jobs = config['jobs']
    require(type(jobs) is dict and 0 < len(jobs) <= MAX_JOBS, 'site placement slots exceed their bound')
    reserved = set()
    for job, item in jobs.items():
        require(type(job) is str and re.fullmatch('[a-z0-9][a-z0-9-]{0,47}', job), 'invalid site job slot')
        fields(item, 'storage_bytes categories')
        amount = item['storage_bytes']
        require(type(amount) is int and 8 * GIB <= amount <= 16 * GIB and amount % GIB == 0,
                'approved job storage ceiling is invalid')
        levels = fields(item['categories'], 'outer inner')
        outer, inner = levels['outer'], levels['inner']
        require(type(outer) is type(inner) is list and len(outer) == 3 and len(inner) == 2 and
                all(type(value) is int and 0 <= value <= 1023 for value in outer + inner) and
                outer == sorted(set(outer)) and inner == sorted(set(inner)) and set(inner) < set(outer) and
                reserved.isdisjoint(outer), 'approved site SELinux categories are invalid or shared')
        reserved.update(outer)
    return config


def bounded(argv, end, limit=CONTROL_LIMIT, allowed=(0,), *, data=None):
    deadline = min(end, time.monotonic() + 300)
    child = subprocess.Popen(argv, env=ENV, stdin=data if data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    result = bytearray()
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            while ready.get_map():
                for key, _ in ready.select(min(.1, seconds(deadline, 300))):
                    chunk = os.read(key.fd, min(4096, limit + 1 - len(result)))
                    if chunk:
                        result.extend(chunk)
                        require(len(result) <= limit, 'native installation command output exceeds its bound')
                    else:
                        ready.unregister(key.fileobj)
            status = child.wait(timeout=seconds(deadline, 300))
        require(status in allowed, f'native installation command failed with status {status}')
        return status, bytes(result)
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=3)
        child.stdout.close()


def current_boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value), 'live boot identity is unavailable')
    return value


def machine(config, end):
    require(os.getuid() == os.geteuid() == 0 and os.uname().machine == 'x86_64' and os.uname().nodename == config['hostname'],
            'approved x86_64 Fedora host and protected operator required')
    facts = dict(row.split('=', 1) for row in Path('/etc/os-release').read_text().splitlines() if '=' in row)
    require(facts.get('ID', '').strip('"') == 'fedora' and facts.get('VERSION_ID', '').strip('"') == '44' and
            Path('/proc/1/comm').read_text().strip() == 'systemd' and
            bounded(['/usr/sbin/getenforce'], time.monotonic() + min(5, seconds(end, 5)))[1].strip() == b'Enforcing',
            'native systemd and enforcing Fedora 44 are required')
    target, _ = protected_json(HOST_CONFIGS / (config['host_config_sha256'] + '.json'), config['host_config_sha256'])
    fields(target, 'schema hostname platform selinux launch_contract role_launch_seconds')
    require(type(target['schema']) is type(target['launch_contract']) is int and
            target['schema'] == target['launch_contract'] == 1 and target['hostname'] == config['hostname'] and
            target['platform'] == 'fedora-44' and target['selinux'] == 'enforcing' and
            type(target['role_launch_seconds']) is int and 90 <= target['role_launch_seconds'] <= 169,
            'approved physical host configuration differs from the destination')
    return current_boot()


def stage_identity(identity, end):
    identity = hex_id(identity)
    value = intake.previous_release(identity, end)
    return intake.protected(intake.ROOT / identity, directory=True), value


def approved_placement(identity, base, site, config, phase, end):
    executable = intake.protected(G_ENTRY)
    boot = current_boot()
    outer = None
    jobs = {}
    for job in sorted(config['jobs']):
        argv = ['/usr/bin/python3', '-B', str(executable), 'install-release', '--phase', phase,
                '--platform-sha256', identity, '--job', job]
        _, raw = bounded(argv, end)
        value = fields(json_bytes(raw), 'schema phase platform_sha256 base_platform_sha256 site_config_sha256 boot_id '
                       'job outer manifest_sha256')
        require(type(value['schema']) is int and value['schema'] == 1 and value['phase'] == phase and value['job'] == job and
                value['platform_sha256'] == identity and value['base_platform_sha256'] == base and
                value['site_config_sha256'] == site and value['boot_id'] == boot,
                'G deployed-placement entry did not prove its exact prepared scope')
        observed = fields(value['outer'], 'oci_config_sha256 oci_manifest_sha256')
        require(outer in (None, observed), 'G placement changed its outer image across scopes')
        outer = observed
        if phase == 'preflight':
            require(value['manifest_sha256'] is None, 'prepared G scope supplied an unverified manifest')
        else:
            jobs[job] = {'manifest_sha256': hex_id(value['manifest_sha256'])}
    return {'outer': outer, 'jobs': jobs}


def bounded_volume(graph, reserve=0, *, need_import=True):
    require(hasattr(devbox, 'managed_storage'), 'G managed ext4 capacity observer is unavailable in installed source')
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(1024**2 + 1)
    require(0 < len(raw) <= 1024**2, 'native mount inventory exceeds its bound')
    state = devbox.managed_storage(raw.decode())
    node = graph.lstat()
    device = f'{os.major(node.st_dev)}:{os.minor(node.st_dev)}'
    require(graph.resolve(strict=True) == graph and stat.S_ISDIR(node.st_mode) and device == state['device'] and
            state['available_inodes'] >= 512 and state['available_bytes'] >= reserve + HOST_RELEASE_HEADROOM,
            'bounded maintenance image store lacks its import overlap or inode headroom' if need_import else
            'bounded maintenance image store lacks its physical recovery reserve')
    return state


def maintenance_identity():
    account = pwd.getpwnam('dp-maint')
    require(account.pw_uid >= 1000 and account.pw_gid >= 1000 and account.pw_shell == '/usr/sbin/nologin' and
            os.getgrouplist(account.pw_name, account.pw_gid) == [account.pw_gid],
            'prepared maintenance identity or supplementary groups differ')
    runtime = Path(f'/run/user/{account.pw_uid}')
    source = runtime.lstat()
    require(runtime.resolve(strict=True) == runtime and stat.S_ISDIR(source.st_mode) and source.st_uid == account.pw_uid and
            stat.S_ISSOCK((runtime / 'bus').lstat().st_mode), 'prepared maintenance user manager is unavailable')
    graph = MAINTENANCE.lstat()
    require(stat.S_ISDIR(graph.st_mode) and graph.st_uid == account.pw_uid and not graph.st_mode & 0o022,
            'prepared maintenance image store owner differs')
    intake.protected(ENGINE_CONTROL / 'containers.conf')
    intake.protected(ROOT / 'bootstrap/prepared')
    for name in ('home', 'xdg-config', 'empty-hooks'):
        directory = intake.protected(ENGINE_CONTROL / name, directory=True)
        require(next(directory.iterdir(), None) is None, 'prepared maintenance controller directory is not empty')
    require(file_hash(intake.protected(ENGINE_CONTROL / 'distrobox-enter'), CONTROL_LIMIT,
                      time.monotonic() + 5, owner=0)[0] == devbox.db.ENTER_SHA256,
            'prepared maintenance Distrobox entry differs from the pinned upstream')
    wrapper = intake.protected(ENGINE_CONTROL / 'bin/podman')
    gateway = intake.protected(ENGINE_CONTROL / 'job-bin/podman')
    require(os.access(wrapper, os.X_OK) and hasattr(gptbox, 'JOB_ENTER_WRAPPER') and
            file_hash(gateway, CONTROL_LIMIT, time.monotonic() + 5, owner=0)[0] ==
            release.digest(gptbox.JOB_ENTER_WRAPPER.encode()), 'prepared maintenance job gateway differs')
    return account, runtime


def empty_cgroup(unit):
    path = CGROUP_ROOT / unit
    if not os.path.lexists(path):
        return
    intake.protected(path, directory=True)
    with (path / 'cgroup.events').open('rb') as status:
        events = status.read(1025).splitlines()
    require(len(events) <= 2 and events.count(b'populated 0') == 1,
            'release installer native process cleanup is unresolved')


class Maintenance:
    def __init__(self, account, runtime, copy):
        self.account, self.runtime, self.copy = account, runtime, copy
        self.runroot = runtime / 'dev-pair-gptbox'
        self.command = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8',
                        f'HOME={ENGINE_CONTROL}/home', f'CONTAINERS_CONF={ENGINE_CONTROL}/containers.conf',
                        f'XDG_RUNTIME_DIR={runtime}', f'TMPDIR={copy}', PODMAN,
                        f'--root={MAINTENANCE}', f'--runroot={self.runroot}', '--storage-driver=vfs',
                        '--events-backend=file', '--remote=false']

    def call(self, args, end, *, data=None, allowed=(0,)):
        timeout = min(240, int(seconds(end, 240)))
        require(timeout >= 5, 'maintenance import has insufficient bounded native time')
        unit = 'dev-pair-platform-install-' + secrets.token_hex(12) + '.service'
        command = ['/usr/bin/systemd-run', '--unit=' + unit, '--description=dev-pair-owned-' + unit,
                   '--uid=dp-maint', '--quiet', '--wait', '--collect', '--pipe', '--service-type=exec',
                   '--property=RuntimeMaxSec=' + str(timeout - 3), '--property=TimeoutStopSec=2',
                   '--property=KillMode=control-group', '--property=MemoryMax=2G', '--property=TasksMax=512',
                   '--property=CPUQuota=100%', *self.command, *args]
        answer = bounded(command, min(end, time.monotonic() + timeout), allowed=allowed, data=data)
        empty_cgroup(unit)
        return answer

    def observe_store(self, end):
        _, raw = self.call(('info', '--format=json'), min(end, time.monotonic() + 20))
        value = json_bytes(raw)
        store, security = value['store'], value['host']['security']
        require(security['rootless'] is True and security['selinuxEnabled'] is True and
                store['graphRoot'] == str(MAINTENANCE) and store['runRoot'] == str(self.runroot) and
                store['graphDriverName'] == 'vfs' and store['imageCopyTmpDir'] == str(self.copy),
                'actual maintenance rootless overlay, runroot or copy directory differs')

    def inspect(self, image, manifest, end):
        _, raw = self.call(('image', 'inspect', 'sha256:' + image), min(end, time.monotonic() + 20))
        rows = json_bytes(raw)
        require(type(rows) is list and len(rows) == 1 and rows[0]['Id'].removeprefix('sha256:') == image and
                rows[0]['Digest'] == 'sha256:' + manifest and rows[0]['Os'] == 'linux' and rows[0]['Architecture'] == 'amd64',
                'installed maintenance image failed local config or OCI manifest digest readback')


def fixed_file(path, raw):
    require(path.parent.resolve(strict=True) == path.parent, 'immutable destination directory changed')
    if os.path.lexists(path):
        stream, node = regular(intake.protected(path), len(raw), 0)
        with stream:
            require(stat.S_IMODE(node.st_mode) == 0o600 and stream.read(len(raw) + 1) == raw,
                    'existing protected release record conflicts')
        return
    descriptor, staged = tempfile.mkstemp(dir=path.parent, prefix='.platform-record-')
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            os.fsync(output.fileno())
        os.link(staged, path)
        release.sync_directory(path.parent)
    finally:
        os.unlink(staged)


def publish_observation(path, value, *, installed=False):
    raw = canonical(value)
    if not os.path.lexists(path):
        fixed_file(path, raw)
        return
    prior, prior_raw = protected_json(path)
    require(stat.S_IMODE(path.lstat().st_mode) == 0o600, 'prior native observation has unexpected ownership')
    if prior_raw == raw:
        return
    expected, observed = copy.deepcopy(value), copy.deepcopy(prior)
    require(expected.pop('boot_id') != observed.pop('boot_id'), 'same-boot native observation changed')
    if installed:
        del expected['components']['maintenance']['result_sha256']
        del observed['components']['maintenance']['result_sha256']
    require(expected == observed, 'reboot readback changes an immutable installation binding')
    descriptor, staged = tempfile.mkstemp(dir=path.parent, prefix='.platform-observation-')
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            os.fsync(output.fileno())
        require(protected_json(path)[1] == prior_raw, 'native observation changed before replacement')
        os.replace(staged, path)
        release.sync_directory(path.parent)
    finally:
        if os.path.lexists(staged):
            os.unlink(staged)


def maintenance_probe(stage, index, phase, end):
    row = index['components']['maintenance-agent']
    bindings = {'platform_sha256': stage.name, 'source_sha': index['source_sha'], 'context_sha256': row['context_sha256'],
                'image_id': row['oci_config_sha256'], 'oci_manifest_sha256': row['oci_manifest_sha256']}
    executable = intake.protected(P_ENTRY)
    argv = ['/usr/bin/python3', '-B', str(executable), 'verify-installed-maintenance', '--phase', phase,
            '--platform-sha256', bindings['platform_sha256'], '--source-sha', bindings['source_sha'],
            '--context-sha256', bindings['context_sha256'], '--image', bindings['image_id'],
            '--oci-manifest-sha256', bindings['oci_manifest_sha256']]
    _, raw = bounded(argv, end)
    if phase == 'preflight':
        value = json_bytes(raw)
        require(value == {'schema': 1, 'phase': 'preflight', **bindings, 'boot_id': current_boot()},
                'local maintenance gateway did not prove the exact import scope')
        return None

    _, part = release.readonly_json(stage / 'maintenance/part.json', 0)
    path = ADAPTER / row['context_sha256'] / 'imported-releases' / (bindings['image_id'] + '.json')
    value, raw = protected_json(path)
    expected = {'schema': 1, 'kind': 'maintenance-imported-release-admission', **bindings,
                'boot_id': current_boot(), 'distrobox_sha': release.public_inputs.DBX_SOURCE,
                'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False,
                'producer_result_sha256': part['producer']['result_sha256']}
    require(path.lstat().st_mode & 0o777 == 0o600 and value == expected and type(value['schema']) is int and
            type(value['boundary_and_version_cycles']) is int and value['runtime_container_removed'] is True and
            value['job_admission'] is False, 'actual restricted native maintenance probe evidence differs')
    return {'context_sha256': row['context_sha256'], 'oci_config_sha256': bindings['image_id'],
            'oci_manifest_sha256': bindings['oci_manifest_sha256'], 'result_sha256': release.digest(raw)}


def install_maintenance(stage, index, account, runtime, end):
    row = index['components']['maintenance-agent']
    source = intake.protected(stage / 'maintenance/maintenance.oci.tar')
    bounded_volume(MAINTENANCE, 1024**2)
    copy = Path(tempfile.mkdtemp(prefix='.platform-import-', dir=MAINTENANCE))
    owned = copy.lstat()
    os.chown(copy, account.pw_uid, account.pw_gid)
    finished = False
    try:
        bounded(['/usr/sbin/restorecon', '-F', str(copy)], min(end, time.monotonic() + 10))
        engine = Maintenance(account, runtime, copy)
        engine.observe_store(end)
        image, manifest = (row[name] for name in ('oci_config_sha256', 'oci_manifest_sha256'))
        status, _ = engine.call(('image', 'exists', 'sha256:' + image), min(end, time.monotonic() + 20), allowed=(0, 1))
        if status:
            bounded_volume(MAINTENANCE, rootless_import_peak(source, row, end))
            stream, node = regular(source, ARCHIVE_LIMIT, 0)
            with stream:
                require(node.st_size == row['archive_bytes'], 'maintenance source length differs at native import')
                engine.call(('load',), end, data=stream)
                after = os.fstat(stream.fileno())
                require((after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size) ==
                        (node.st_dev, node.st_ino, node.st_mtime_ns, node.st_ctime_ns, node.st_size),
                        'maintenance source changed during native import')
        engine.inspect(image, manifest, end)
        bounded_volume(MAINTENANCE, need_import=False)
        finished = True
    finally:
        if finished:
            observed = copy.lstat()
            require(shutil.rmtree.avoids_symlink_attacks and stat.S_ISDIR(observed.st_mode) and
                    (observed.st_dev, observed.st_ino) == (owned.st_dev, owned.st_ino),
                    'owned import spool identity changed before cleanup')
            shutil.rmtree(copy)
    evidence = {'schema': 1, 'kind': 'maintenance-native-oci-import', 'platform_sha256': stage.name,
                'source_sha': index['source_sha'], 'context_sha256': row['context_sha256'],
                'image_id': image, 'oci_manifest_sha256': manifest, 'boot_id': current_boot(),
                'archive_sha256': row['archive_sha256'], 'graphroot': str(MAINTENANCE),
                'runroot': str(runtime / 'dev-pair-gptbox')}
    publish_observation(stage / 'maintenance-import.json', evidence)
    return maintenance_probe(stage, index, 'verify', end)


def stage_budget(stage, capacity):
    node = stage.lstat()
    if f'{os.major(node.st_dev)}:{os.minor(node.st_dev)}' == capacity['device']:
        return  # Kernel available space already charges these input bytes.
    remaining = MANAGED_CEILING - capacity['backing_bytes']
    require(remaining > 0, 'release archive backing does not fit the aggregate managed budget')
    mountinfo = Path('/proc/self/mountinfo').read_text()
    separate = devbox.storage_mount(intake.ROOT, remaining, mountinfo)
    device = Path('/sys/dev/block') / separate['device']
    sectors = int((device / 'size').read_text().strip())
    require(separate['bytes'] <= sectors * 512 and capacity['backing_bytes'] + sectors * 512 <= MANAGED_CEILING,
            'role and archive filesystems exceed the shared managed ceiling')


def rootless_import_peak(archive, row, end):
    """Budget both archive copies and the rootless VFS parent-layer replication."""
    peak = 2 * row['archive_bytes'] + 256 * 1024**2
    available = EXPANSION_LIMIT
    with tarfile.open(archive, 'r:') as bundle:
        entries = {devbox.db.archive_path(member.name): member for member in bundle if member.isreg()}
        with bundle.extractfile(entries['blobs/sha256/' + row['oci_manifest_sha256']]) as stream:
            manifest = devbox.db.json_data(stream.read(devbox.db.OCI_METADATA_LIMIT + 1))
        layers = manifest['layers']
        for index, layer in enumerate(layers):
            member = entries['blobs/sha256/' + layer['digest'].removeprefix('sha256:')]
            with bundle.extractfile(member) as stream:
                if layer['mediaType'].endswith('+gzip'):
                    with gzip.GzipFile(fileobj=stream) as expanded:
                        size = devbox.db.hash_layer(expanded, available, end)[1]
                else:
                    size = member.size
                require(0 < size <= available, 'maintenance archive expansion capacity differs')
                available -= size
                peak += (len(layers) - index) * size
    return peak


def check_host_bundle(directory, row, end):
    root = intake.protected(directory, directory=True)
    require(not root.stat().st_mode & 0o222, 'installed host release directory is writable')
    manifest, _ = protected_json(root / 'manifest.json', row['bundle_manifest_sha256'])
    require(manifest['source_revision'] == row['source_sha'] and manifest['state_contract'] == 1,
            'installed host bundle source or state contract differs')
    found = set()
    pending = [root]
    while pending:
        parent = pending.pop()
        for member in parent.iterdir():
            if parent == root and member.name == 'manifest.json':
                continue
            name = member.relative_to(root).as_posix()
            info = member.lstat()
            if stat.S_ISDIR(info.st_mode):
                intake.protected(member, directory=True)
                require(not info.st_mode & 0o222 and any(path.startswith(name + '/') for path in manifest['files']),
                        'installed host release contains a writable or unexpected directory')
                pending.append(member)
                continue
            require(name in manifest['files'] and stat.S_IMODE(info.st_mode) in (0o444, 0o555) and
                    file_hash(intake.protected(member), 4 * 1024**2, end, owner=0)[0] == manifest['files'][name],
                    'installed host release file differs from its verified identity')
            found.add(name)
            require(len(found) <= release.HOST_FILES, 'installed host release file count exceeds its bound')
    require(found == set(manifest['files']), 'installed host release files are incomplete')
    return {'manifest_sha256': row['bundle_manifest_sha256']}


def install_host(stage, row, end, *, reuse_only=False):
    store = intake.protected(HOST_RELEASES, directory=True)
    destination = store / row['bundle_manifest_sha256']
    if not os.path.lexists(destination):
        require(not reuse_only, 'agent refresh requires the retained installed host bundle')
        siblings = list(store.iterdir())
        require(len(siblings) < 3 and all(re.fullmatch('[0-9a-f]{64}', node.name) and
                                         intake.protected(node, directory=True) for node in siblings),
                'bounded installed host bundle inventory needs authorized reconciliation')
        with tempfile.TemporaryDirectory(dir=store, prefix='.platform-host-') as work:
            temporary = Path(work)
            require(release.validate_host(stage / 'host', row['source_sha'], end, temporary) == row['bundle_manifest_sha256'],
                    'host archive changed before native installation')
            for leaf, _, _ in os.walk(temporary, topdown=False):
                os.chmod(leaf, 0o555)
                release.sync_directory(Path(leaf))
            require(not os.path.lexists(destination), 'host installation destination appeared')
            temporary.rename(destination)
            release.sync_directory(store)
    return check_host_bundle(destination, row, end)


def exact_local_programs(base_stage, end):
    manifest, _ = protected_json(base_stage / 'host/host-manifest.json')
    for program in (G_ENTRY, P_ENTRY):
        expected = hex_id(manifest['files']['tools/' + program.name])
        require(file_hash(intake.protected(program), 4 * 1024**2, end, owner=0)[0] == expected,
                f'installed {program.name} differs from the approved stable host release')


def development_request(stage, index, base, base_index, site_sha):
    outer = base_index['components']['devbox']
    row = index['components']['development-agent']
    _, part = release.readonly_json(stage / 'development/part.json', 0)
    value = {'schema': 1, 'platform_sha256': stage.name, 'base_platform_sha256': base,
             'site_config_sha256': site_sha, 'source_sha': index['source_sha'],
             'outer': {key: outer[key] for key in ('source_sha', 'oci_config_sha256', 'oci_manifest_sha256')},
             'inner': part['producer'], 'inner_oci_manifest_sha256': row['oci_manifest_sha256']}
    fixed_file(stage / 'development-placement.json', canonical(value))
    return {key: outer[key] for key in ('oci_config_sha256', 'oci_manifest_sha256')}


def check_development(stage, index, base_index, site, reported, end):
    current = index['components']['development-agent']
    outer = base_index['components']['devbox']
    observed = fields(reported['outer'], 'oci_config_sha256 oci_manifest_sha256')
    require(observed == {key: outer[key] for key in observed}, 'local outer DevBox differs from its admitted config or OCI manifest digest')
    _, part = release.readonly_json(stage / 'development/part.json', 0)
    inner = part['producer']
    require(inner['image_id'] == current['oci_config_sha256'] and inner['archive_sha256'] == current['archive_sha256'] and
            inner['source_sha'] == index['source_sha'], 'local development producer identity differs')
    records = {}
    for job, evidence in reported['jobs'].items():
        manifest_sha = hex_id(fields(evidence, 'manifest_sha256')['manifest_sha256'])
        build = ROOT / 'development/builds' / job
        directory = build / 'inputs' / manifest_sha
        require(directory.resolve(strict=True) == directory and directory.stat().st_dev == build.stat().st_dev,
                'development manifest fell outside the dedicated build filesystem')
        path = directory / 'manifest.json'
        raw, manifest = release.readonly_json(path, 0)
        expected = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': index['standards_sha'], 'job': job,
                    'storage_bytes': site['jobs'][job]['storage_bytes'], 'inner': inner,
                    'outer': {'source_sha': outer['source_sha'], 'image_id': outer['oci_config_sha256']},
                    'categories': site['jobs'][job]['categories']}
        require(raw == canonical(manifest) and release.digest(raw) == manifest_sha and manifest == expected and
                not path.lstat().st_mode & 0o222, 'actual development manifest differs from approved site, inner or stable outer')
        archive = directory / 'development.oci.tar'
        require(archive.resolve(strict=True) == archive and archive.lstat().st_dev == build.stat().st_dev and
                not archive.lstat().st_mode & 0o222 and
                file_hash(archive, ARCHIVE_LIMIT, end, owner=0) == (current['archive_sha256'], current['archive_bytes']),
                'actual development OCI copy or confinement differs')
        for candidate in (archive, path):
            devbox.check_label(candidate, devbox.db.file_label(manifest, 'outer'))
        with open('/proc/self/mountinfo', 'r', encoding='utf-8') as stream:
            mountinfo = stream.read(1024**2 + 1)
        require(0 < len(mountinfo) <= 1024**2, 'native development mount inventory exceeds its bound')
        devbox.storage_mount(build, expected['storage_bytes'], mountinfo)
        records[job] = {'manifest_sha256': manifest_sha}
    result = {key: current[key] for key in ('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256')}
    result.update(inner_sha256=release.digest(canonical(inner)), jobs=records)
    return observed, result


def install(identity, site_sha, end):
    identity, site_sha = hex_id(identity), hex_id(site_sha)
    config = site_configuration(SITE_CONFIGS / (site_sha + '.json'), site_sha)
    boot = machine(config, end)
    stage, index = stage_identity(identity, end)
    agent = index['kind'] == 'dev-pair-agent-release'
    base = index['base_platform_sha256'] if agent else identity
    if agent:
        base_stage, base_index = stage_identity(base, end)
        require(base_index['kind'] == 'dev-pair-platform-release', 'stable agent refresh base lacks a complete platform')
    else:
        base_stage, base_index = stage, index
    exact_local_programs(base_stage, end)
    account, runtime = maintenance_identity()
    volume = bounded_volume(MAINTENANCE, need_import=False)
    stage_budget(stage, volume)
    if agent:
        stage_budget(base_stage, volume)
        # Agent update may only keep the actual installed host bundle.
        host_row = base_index['components']['host']
        check_host_bundle(HOST_RELEASES / host_row['bundle_manifest_sha256'], host_row, end)
    try:
        maintenance_probe(stage, index, 'preflight', end)
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise Blocked('accepted-import P entry or prepared maintenance gateway did not pass preflight') from None
    outer = development_request(stage, index, base, base_index, site_sha)
    try:
        planned = approved_placement(identity, base, site_sha, config, 'preflight', end)
        require(planned['outer'] == outer, 'prepared G scope selected a different stable DevBox')
    except (Blocked, devbox.db.Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise Blocked('prebuilt G deployment entry or its prepared scopes did not pass preflight') from None

    maintenance = install_maintenance(stage, index, account, runtime, end)
    host = install_host(base_stage, base_index['components']['host'], end, reuse_only=agent)
    installed = approved_placement(identity, base, site_sha, config, 'stage', end)
    devbox_row, development = check_development(stage, index, base_index, config, installed, end)
    bounded_volume(MAINTENANCE, need_import=False)
    require(current_boot() == boot, 'native host rebooted across installation readback')
    final = {'schema': 1, 'platform_sha256': identity, 'base_platform_sha256': base,
             'site_config_sha256': site_sha, 'boot_id': boot, 'source_sha': index['source_sha'],
             'components': {'host': host, 'maintenance': maintenance, 'devbox': devbox_row, 'development': development}}
    path = stage / 'installed.json'
    publish_observation(path, final, installed=True)
    return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform-sha256', required=True)
    parser.add_argument('--site-config-sha256', required=True)
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0, 'protected native installer operator required')
    os.umask(0o077)
    with intake.intake_lock():
        result = install(args.platform_sha256, args.site_config_sha256, time.monotonic() + TIME_LIMIT)
    print(canonical(result).decode(), end='')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, devbox.db.Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        print('native platform staging blocked: ' + str(exc)[:800], file=sys.stderr)
        sys.exit(2)
