#!/usr/bin/python3
"""Stage the exact portable release into prepared Fedora role stores."""

import argparse
import gzip
import copy
import errno
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
REOBSERVE_LIMIT = 390
MAX_JOBS = 32
HOST_RELEASE_HEADROOM = 3 * (HOST_LIMIT + CONTROL_LIMIT)
LEASE_NAME = '.platform-maintenance-lease.json'
SPOOL_PREFIX = '.platform-import-'
UNIT_PREFIX = 'dev-pair-platform-install-'
BOOT_PATTERN = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
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
    require(re.fullmatch(BOOT_PATTERN, value), 'live boot identity is unavailable')
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


def volume_identity(graph, *, for_recovery=False):
    require(hasattr(devbox, 'managed_storage'), 'G managed ext4 capacity observer is unavailable in installed source')
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(1024**2 + 1)
    require(0 < len(raw) <= 1024**2, 'native mount inventory exceeds its bound')
    state = devbox.managed_storage(raw.decode(), for_recovery=for_recovery)
    node = graph.lstat()
    device = f'{os.major(node.st_dev)}:{os.minor(node.st_dev)}'
    require(graph.resolve(strict=True) == graph and stat.S_ISDIR(node.st_mode) and device == state['device'],
            'maintenance image store differs from the measured managed filesystem')
    return state


def bounded_volume(graph, reserve=0, *, need_import=True):
    state = volume_identity(graph)
    require(state['available_inodes'] >= 512 and state['available_bytes'] >= reserve + HOST_RELEASE_HEADROOM,
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


class ImportLease:
    """Durable exclusive ownership under the protected release-intake lock."""

    def __init__(self, account, capacity):
        self.root = intake.protected(ROOT, directory=True)
        self.path = self.root / LEASE_NAME
        self.account = account
        self.boot = current_boot()
        self.parent = self.root.lstat()
        self.backing = [capacity['backing_inode'], capacity['backing_bytes']]
        require(self.parent.st_dev == MAINTENANCE.lstat().st_dev and
                f'{os.major(self.parent.st_dev)}:{os.minor(self.parent.st_dev)}' == capacity['device'],
                'maintenance copy and engine must use the same bounded filesystem')
        self.record = None

    @property
    def spool(self):
        return self.root / (SPOOL_PREFIX + self.record['nonce'])

    def read(self):
        value, raw = protected_json(self.path)
        require(self.path.lstat().st_mode & 0o777 == 0o600 and raw == canonical(value),
                'maintenance import lease is not a protected canonical record')
        fields(value, 'schema platform_sha256 image_id boot_id nonce owner backing parent inode unit')
        require(type(value['schema']) is int and value['schema'] == 1 and
                re.fullmatch(BOOT_PATTERN, value['boot_id']) and re.fullmatch('[0-9a-f]{24}', value['nonce']) and
                value['owner'] == [self.account.pw_uid, self.account.pw_gid] and value['backing'] == self.backing and
                type(value['parent']) is list and len(value['parent']) == 2 and
                value['parent'][1] == self.parent.st_ino and
                (value['boot_id'] != self.boot or value['parent'][0] == self.parent.st_dev) and
                (value['inode'] is None or type(value['inode']) is int and value['inode'] > 0),
                'maintenance import lease differs from the measured filesystem or role')
        for key in ('platform_sha256', 'image_id'):
            hex_id(value[key])
        if value['unit'] is not None:
            unit = fields(value['unit'], 'name operation quiesced')
            require(value['inode'] is not None and re.fullmatch(UNIT_PREFIX + '[0-9a-f]{24}\\.service', unit['name']) and
                    unit['operation'] in ('info', 'exists', 'load', 'inspect') and type(unit['quiesced']) is bool,
                    'invalid maintenance import unit lease')
        return value

    def update(self, **changes):
        require(self.read() == self.record, 'maintenance import lease changed during the operation')
        value = {**self.record, **changes}
        replace_observation(self.path, canonical(value))
        self.record = value

    def prepare(self, stage, image):
        self.record = {'schema': 1, 'platform_sha256': hex_id(stage.name), 'image_id': hex_id(image),
                       'boot_id': self.boot, 'nonce': secrets.token_hex(12),
                       'owner': [self.account.pw_uid, self.account.pw_gid], 'backing': self.backing,
                       'parent': [self.parent.st_dev, self.parent.st_ino], 'inode': None, 'unit': None}
        require(not os.path.lexists(self.path) and not os.path.lexists(self.spool),
                'previous maintenance import requires reconciliation')
        replace_observation(self.path, canonical(self.record))
        self.spool.mkdir(mode=0o700)
        release.sync_directory(self.root)
        self.update(inode=self.spool.lstat().st_ino)
        os.chown(self.spool, self.account.pw_uid, self.account.pw_gid)

    def begin(self, operation):
        require(self.record['unit'] is None, 'previous native import unit is unresolved')
        name = UNIT_PREFIX + secrets.token_hex(12) + '.service'
        self.update(unit={'name': name, 'operation': operation, 'quiesced': False})
        return name, self.description()

    def description(self):
        record = self.record
        return (f"dev-pair-owned-{record['unit']['name']} {record['nonce']} "
                f"{record['platform_sha256']} {record['unit']['operation']}")

    def properties(self, end):
        name = self.record['unit']['name']
        keys = ('Id', 'Description', 'User', 'Transient', 'LoadState', 'ActiveState', 'ControlGroup',
                'Result', 'ExecMainCode', 'ExecMainStatus')
        command = [SYSTEMCTL, 'show', '--all', '--property=' + ','.join(keys), '--', name]
        status, raw = bounded(command, min(end, time.monotonic() + 10), allowed=(0, 1, 4))
        rows = [line.split('=', 1) for line in raw.decode().splitlines()]
        props = dict(rows)
        require(set(props) >= {'Id', 'LoadState', 'ActiveState'} and len(rows) == len(props) and
                props['Id'] == name, 'maintenance import manager readback is unresolved')
        if props['LoadState'] == 'not-found':
            require(props['ActiveState'] == 'inactive' and not props.get('ControlGroup'),
                    'maintenance import manager absence is unresolved')
            return None
        require(status == 0 and set(props) == set(keys) and props['LoadState'] == 'loaded' and props['User'] == 'dp-maint' and
                props['Transient'] == 'yes' and props['Description'] == self.description() and
                props['ControlGroup'] in ('', f'/system.slice/{name}'), 'maintenance import unit ownership differs')
        return props

    def retire(self, end, *, completed=False, image_missing=False, recovering=False):
        unit = self.record['unit']
        name = unit['name']
        props = self.properties(end)
        if image_missing:
            require(props is not None and props['ActiveState'] == 'failed' and
                    props['Result'] == 'exit-code' and props['ExecMainCode'] == '1' and props['ExecMainStatus'] == '1',
                    'maintenance image absence lacks an exact local Podman exit')
        if self.record['boot_id'] != self.boot:
            require(props is None and not os.path.lexists(CGROUP_ROOT / name),
                    'earlier-boot maintenance unit still has a current host identity')
        elif unit['quiesced']:
            require(props is None or props['ActiveState'] == 'inactive', 'retired maintenance unit became active')
        elif props is None:
            require(completed, 'maintenance native launch is uncertain on this boot')
        else:
            bounded([SYSTEMCTL, 'stop', '--', name], min(end, time.monotonic() + 12), allowed=(0, 5))
            props = self.properties(end)
            require(props is None or props['ActiveState'] == 'inactive',
                    'maintenance owned unit has not stopped')
        _, jobs = bounded([SYSTEMCTL, 'list-jobs', '--no-legend', '--no-pager', '--plain', '--', name],
                          min(end, time.monotonic() + 10))
        require(not jobs.strip(), 'maintenance owned unit still has a queued manager operation')
        if not unit['quiesced']:
            try:
                self.update(unit={**unit, 'quiesced': True})
            except OSError as exc:
                # The live stop proof can authorize exact cleanup even when a
                # replacement lease cannot be allocated on this filesystem.
                if exc.errno not in (errno.ENOSPC, errno.EDQUOT):
                    raise
        empty_cgroup(name)
        if recovering:
            self.finish(retired_unit=name)
            return
        try:
            self.update(unit=None)
        except OSError as exc:
            if exc.errno not in (errno.ENOSPC, errno.EDQUOT):
                raise
            self.finish(retired_unit=name)
            raise Blocked('maintenance volume exhausted after native work; exact owned spool reclaimed for retry') from exc

    def finish(self, *, retired_unit=None):
        unit = self.record['unit']
        require(self.read() == self.record and (unit['name'] if unit else None) == retired_unit,
                'maintenance import lease or native cleanup is unresolved')
        if os.path.lexists(self.spool):
            node = self.spool.lstat()
            inode = self.record['inode']
            require(self.spool.resolve(strict=True) == self.spool and stat.S_ISDIR(node.st_mode) and
                    node.st_dev == self.parent.st_dev and stat.S_IMODE(node.st_mode) == 0o700 and
                    (node.st_uid, node.st_gid) in ((0, 0), (self.account.pw_uid, self.account.pw_gid)),
                    'maintenance import copy directory ownership changed')
            # Before the inode is recorded the root-created directory has never been handed to the role.
            if inode is None:
                require((node.st_uid, node.st_gid) == (0, 0), 'unpublished maintenance copy directory changed')
                self.spool.rmdir()
            else:
                require(node.st_ino == inode and shutil.rmtree.avoids_symlink_attacks,
                        'maintenance import copy directory identity changed')
                with Path('/proc/self/mountinfo').open('rb') as stream:
                    mounts = stream.read(1024**2 + 1)
                require(0 < len(mounts) <= 1024**2 and all(
                    row[4] != os.fsencode(self.spool) and not row[4].startswith(os.fsencode(self.spool) + b'/')
                    for row in (line.split() for line in mounts.splitlines())), 'maintenance copy directory contains a mount')
                shutil.rmtree(self.spool)
            release.sync_directory(self.root)
        require(not os.path.lexists(self.spool), 'maintenance import copy directory remains after cleanup')
        self.path.unlink()
        release.sync_directory(self.root)
        self.record = None

    def recover(self, end):
        if os.path.lexists(self.path):
            self.record = self.read()
            if self.record['unit'] is None:
                self.finish()
            else:
                self.retire(end, recovering=True)


def recover_maintenance(account, end):
    if os.path.lexists(ROOT / LEASE_NAME):
        identity = volume_identity(MAINTENANCE, for_recovery=True)
        ImportLease(account, identity).recover(end)


class Maintenance:
    def __init__(self, runtime, lease):
        self.lease = lease
        self.copy = lease.spool
        self.runroot = runtime / 'dev-pair-gptbox'
        self.command = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8',
                        f'HOME={ENGINE_CONTROL}/home', f'CONTAINERS_CONF={ENGINE_CONTROL}/containers.conf',
                        f'XDG_RUNTIME_DIR={runtime}', f'TMPDIR={self.copy}', PODMAN,
                        f'--root={MAINTENANCE}', f'--runroot={self.runroot}', '--storage-driver=vfs',
                        '--events-backend=file', '--remote=false']

    def call(self, args, end, *, data=None, allowed=(0,)):
        timeout = min(240, int(seconds(end, 240)))
        require(timeout >= 5, 'maintenance import has insufficient bounded native time')
        operation = args[1] if args[0] == 'image' else args[0]
        unit, description = self.lease.begin(operation)
        command = ['/usr/bin/systemd-run', '--unit=' + unit, '--description=' + description,
                   '--uid=dp-maint', '--quiet', '--wait', '--pipe', '--service-type=exec', '--slice=system.slice',
                   '--property=RuntimeMaxSec=' + str(timeout - 3), '--property=TimeoutStopSec=2',
                   '--property=KillMode=control-group', '--property=MemoryMax=2G', '--property=TasksMax=512',
                   '--property=CPUQuota=100%', *self.command, *args]
        answer = bounded(command, min(end, time.monotonic() + timeout), allowed=allowed, data=data)
        self.lease.retire(end, completed=answer[0] == 0, image_missing=operation == 'exists' and answer[0] == 1)
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


def replace_observation(path, raw):
    descriptor, staged = tempfile.mkstemp(dir=path.parent, prefix='.platform-observation-')
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            os.fsync(output.fileno())
        os.replace(staged, path)
        release.sync_directory(path.parent)
    finally:
        if os.path.lexists(staged):
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
    require(protected_json(path)[1] == prior_raw, 'native observation changed before replacement')
    replace_observation(path, raw)


def maintenance_bindings(stage, index):
    row = index['components']['maintenance-agent']
    return {'platform_sha256': stage.name, 'source_sha': index['source_sha'], 'context_sha256': row['context_sha256'],
            'image_id': row['oci_config_sha256'], 'oci_manifest_sha256': row['oci_manifest_sha256']}


def maintenance_probe(stage, index, phase, end):
    bindings = maintenance_bindings(stage, index)
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

    expected = maintenance_admission(stage, index, current_boot())
    _, raw = maintenance_admission_readback(expected)
    return maintenance_result(bindings, raw)


def maintenance_admission(stage, index, boot):
    bindings = maintenance_bindings(stage, index)
    _, part = release.readonly_json(stage / 'maintenance/part.json', 0)
    return {'schema': 1, 'kind': 'maintenance-imported-release-admission', **bindings,
            'boot_id': boot, 'distrobox_sha': release.public_inputs.DBX_SOURCE,
            'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False,
            'producer_result_sha256': part['producer']['result_sha256']}


def maintenance_admission_readback(expected):
    path = (ADAPTER / expected['context_sha256'] / 'imported-releases' / expected['platform_sha256'] /
            expected['image_id'] / (expected['boot_id'] + '.json'))
    value, raw = protected_json(path)
    require(path.lstat().st_mode & 0o777 == 0o600 and value == expected and type(value['schema']) is int and
            type(value['boundary_and_version_cycles']) is int and value['runtime_container_removed'] is True and
            value['job_admission'] is False and raw == gptbox.image_inputs_bytes(expected),
            'actual restricted native maintenance probe evidence differs')
    return value, raw


def maintenance_result(bindings, raw):
    return {'context_sha256': bindings['context_sha256'], 'oci_config_sha256': bindings['image_id'],
            'oci_manifest_sha256': bindings['oci_manifest_sha256'], 'result_sha256': release.digest(raw)}


def maintenance_import_record(stage, index, runtime, boot):
    return {'schema': 1, 'kind': 'maintenance-native-oci-import', **maintenance_bindings(stage, index), 'boot_id': boot,
            'archive_sha256': index['components']['maintenance-agent']['archive_sha256'],
            'graphroot': str(MAINTENANCE), 'runroot': str(runtime / 'dev-pair-gptbox')}


def observe_maintenance_engine(stage, index, account, runtime, end, *, allow_load):
    row = index['components']['maintenance-agent']
    recover_maintenance(account, end)
    capacity = bounded_volume(MAINTENANCE, 1024**2)
    lease = ImportLease(account, capacity)
    image, manifest = (row[name] for name in ('oci_config_sha256', 'oci_manifest_sha256'))
    try:
        lease.prepare(stage, image)
        bounded(['/usr/sbin/restorecon', '-F', str(lease.spool)], min(end, time.monotonic() + 10))
        engine = Maintenance(runtime, lease)
        engine.observe_store(end)
        if allow_load:
            status, _ = engine.call(('image', 'exists', 'sha256:' + image), min(end, time.monotonic() + 20), allowed=(0, 1))
            if status:
                source = intake.protected(stage / 'maintenance/maintenance.oci.tar')
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
    finally:
        if lease.record is not None and lease.record['unit'] is None and os.path.lexists(lease.path):
            lease.finish()


def install_maintenance(stage, index, account, runtime, end):
    observe_maintenance_engine(stage, index, account, runtime, end, allow_load=True)
    evidence = maintenance_import_record(stage, index, runtime, current_boot())
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


def exact_local_programs(base_stage, end, *, expected=None, programs=None):
    manifest, _ = protected_json(base_stage / 'host/host-manifest.json', expected)
    programs = (G_ENTRY, P_ENTRY) if programs is None else programs
    for program in programs:
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
    result.update(inner_sha256=release.digest(gptbox.image_inputs_bytes(inner)), jobs=records)
    return observed, result


def approved_maintenance_selection(stage, index, base, intake_sha, site_sha, site):
    # The invoking renewal path already holds its owner/effect fence. Read its
    # protected selection and journal without recursively taking those locks.
    import renewal

    control = renewal.Renewal(ROOT, None)
    current = control.live_release()
    selected = hex_id(renewal.read_json(control.control / 'site-current.json'))
    marker = ROOT / 'renewal-fence/frozen'
    fence = renewal.read_json(marker) if os.path.lexists(marker) else None
    if fence in (None, 'boot'):
        require(current == selected, 'renewal current and live site selection differ')
        references = {current}
    else:
        attempt, journal = control.transition()
        require(attempt is not None and attempt.name == fence and journal['attempt_id'] == fence and
                type(journal['schema']) is int and journal['schema'] == 1,
                'maintenance reobservation lacks a matching protected renewal fence')
        request = renewal.checked_request(journal['request'], journal['request']['scope'])
        previous, target = request['previous_sha256'], request['target_sha256']
        phase = journal['phase']
        require(previous != target and {current, selected} <= {previous, target},
                'renewal live selectors escaped the protected transition')
        if phase in ('prepared', 'freezing', 'backed-up', 'applying', 'verifying'):
            references = {previous, target}
        elif phase == 'accepted':
            references = {target}
        else:
            require(phase in ('rolling-back', 'rollback-verifying', 'rollback-accepted'),
                    'maintenance reobservation is outside an approved transition phase')
            references = {previous}
    matching = []
    for reference in sorted(references):
        selection = control.release(reference)
        component = selection['components']['maintenance-agent']
        platform = component.get('platform_sha256')
        path = control.control / 'platform-bindings' / (reference + '.json')
        plan_sha = selection['plan_sha256']
        if os.path.lexists(path):
            binding = renewal.read_json(path)
            if binding['platform_sha256'] != stage.name:
                require(platform != stage.name, 'maintenance component conflicts with the protected portable binding')
                continue
            require(platform in (None, stage.name) and type(binding['schema']) is int and binding == {
                'schema': 1, 'release_sha256': reference, 'platform_sha256': stage.name, 'base_platform_sha256': base,
                'site_config_sha256': site_sha, 'intake_sha256': intake_sha, 'plan_sha256': plan_sha} and
                selection['config_sha256'] == site['host_config_sha256'],
                'local release binding differs from approved portable maintenance evidence')
        elif platform != stage.name:
            continue
        # A deliberately mixed host/DevBox release retains the exact signed
        # maintenance component but derives a new local plan and host profile.
        plan, _ = protected_json(control.control / 'plans' / (hex_id(plan_sha) + '.json'), plan_sha)
        row = index['components']['maintenance-agent']
        require(plan['maintenance_context_sha256'] == row['context_sha256'] and
                component['artifact_sha256'] == row['oci_config_sha256'] and
                component['source_revision'] == index['source_sha'] and component['codex_version'] == row['codex_version'],
                'local release plan differs from approved portable maintenance evidence')
        matching.append(reference)
    require(matching, 'maintenance image is not selected by an exact approved local release')
    return tuple(matching)


def reobserve_maintenance(identity, site_sha, end):
    identity, site_sha = hex_id(identity), hex_id(site_sha)
    site = site_configuration(SITE_CONFIGS / (site_sha + '.json'), site_sha)
    boot = machine(site, end)
    stage, index, intake_sha = intake.retained_index(identity)
    if index['kind'] == 'dev-pair-agent-release':
        base = index['base_platform_sha256']
        base_stage, base_index, _ = intake.retained_index(base)
        require(base_index['kind'] == 'dev-pair-platform-release', 'retained maintenance release has no stable host base')
    else:
        base, base_stage, base_index = identity, stage, index
    reference = approved_maintenance_selection(stage, index, base, intake_sha, site_sha, site)
    exact_local_programs(base_stage, end, expected=base_index['components']['host']['bundle_manifest_sha256'],
                         programs=(P_ENTRY,))
    part_path = intake.protected(stage / 'maintenance/part.json')
    part = index['transports']['maintenance']['files']['part.json']
    require(file_hash(part_path, CONTROL_LIMIT, end, owner=0) == (part['sha256'], part['bytes']),
            'retained maintenance producer proof differs from its signed transport')
    installed_path = stage / 'installed.json'
    installed, raw = protected_json(installed_path)
    fields(installed, 'schema platform_sha256 base_platform_sha256 site_config_sha256 boot_id source_sha components')
    old_boot = installed['boot_id']
    require(installed_path.lstat().st_mode & 0o777 == 0o600 and raw == canonical(installed) and
            type(installed['schema']) is int and installed['schema'] == 1 and type(old_boot) is str and
            re.fullmatch(BOOT_PATTERN, old_boot) and installed['platform_sha256'] == identity and
            installed['base_platform_sha256'] == base and installed['site_config_sha256'] == site_sha and
            installed['source_sha'] == index['source_sha'], 'retained native installation differs from approved selection')
    _, historical = maintenance_admission_readback(maintenance_admission(stage, index, old_boot))
    bindings = maintenance_bindings(stage, index)
    retained = fields(installed['components'], 'maintenance development devbox host')['maintenance']
    require(retained == maintenance_result(bindings, historical),
            'retained native installation lacks the exact completed maintenance admission')

    account, runtime = maintenance_identity()
    import_path = stage / 'maintenance-import.json'
    prior, raw = protected_json(import_path)
    prior_boot = prior['boot_id']
    require(import_path.lstat().st_mode & 0o777 == 0o600 and raw == canonical(prior) and
            type(prior['schema']) is int and type(prior_boot) is str and re.fullmatch(BOOT_PATTERN, prior_boot) and
            prior == maintenance_import_record(stage, index, runtime, prior_boot),
            'retained native import does not identify the selected immutable image or store')
    recover_maintenance(account, end)
    volume = bounded_volume(MAINTENANCE, need_import=False)
    stage_budget(stage, volume)
    maintenance_probe(stage, index, 'preflight', end)
    observe_maintenance_engine(stage, index, account, runtime, end, allow_load=False)
    require(current_boot() == boot and approved_maintenance_selection(stage, index, base, intake_sha, site_sha, site) == reference,
            'boot or local release selection changed across maintenance readback')
    publish_observation(import_path, maintenance_import_record(stage, index, runtime, boot))
    return maintenance_probe(stage, index, 'verify', end)


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
    recover_maintenance(account, end)
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
    parser.add_argument('--reobserve-maintenance', action='store_true')
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0, 'protected native installer operator required')
    os.umask(0o077)
    with intake.intake_lock():
        if args.reobserve_maintenance:
            result = reobserve_maintenance(args.platform_sha256, args.site_config_sha256, time.monotonic() + REOBSERVE_LIMIT)
        else:
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
