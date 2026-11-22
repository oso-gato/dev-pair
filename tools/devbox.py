#!/usr/bin/env python3
"""Run one exact, offline DevBox and its nested development gptbox probe."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import sys
import time

RUNTIME = Path(__file__).resolve().parent.parent / 'runtime/devbox'
sys.path.insert(0, str(RUNTIME))
import controller as db

ROOT = Path('/var/lib/dev-pair/development')
DP_DEV_SUBORDINATES = [(1065536, 65536)]


def host_account():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    db.require((release.get('ID', '').strip('"'), release.get('VERSION_ID', '').strip('"')) == ('fedora', '44'),
               'designated Fedora 44 runner required')
    account = pwd.getpwuid(os.getuid())
    db.require(account.pw_name == 'dp-dev' and account.pw_uid == os.geteuid() >= 1000
               and account.pw_gid == os.getgid() == os.getegid()
               and os.getgroups() in ([], [account.pw_gid]), 'managed rootless dp-dev account required')
    db.require(Path(db.PODMAN).is_file() and Path(db.CRUN).is_file(), 'local Podman or crun unavailable')
    return account


def enforcing(end):
    _, output = db.bounded(['/usr/sbin/getenforce'], end, env=db.local_env(), seconds=5)
    db.require(output.strip() == b'Enforcing', 'host SELinux enforcement required')


def private_dir(path, account):
    db.require(path.resolve(strict=True) == path, f'symlink in {path.name} placement')
    info = path.stat()
    db.require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (account.pw_uid, account.pw_gid)
               and stat.S_IMODE(info.st_mode) == 0o700, f'{path.name} must be an owned private directory')
    return info


def storage_mount(path, ceiling, mountinfo):
    entries = [line.split() for line in mountinfo.splitlines()]
    rows = [entry for entry in entries if entry[4] == str(path)]
    db.require(len(rows) == 1, 'dedicated development block filesystem must be mounted at the build leaf')
    info = rows[0]
    separator = info.index('-')
    fs_type, source = info[separator + 1:separator + 3]
    db.require(info[3] == '/' and fs_type in ('ext4', 'xfs') and source.startswith('/dev/')
               and 'rw' in info[5].split(',')
               and sum(entry[2] == info[2] for entry in entries) == 1,
               'development storage is not a private dedicated filesystem root')
    dev = path.stat().st_dev
    db.require(info[2] == f'{os.major(dev)}:{os.minor(dev)}' and dev != path.parent.stat().st_dev,
               'development storage must be separate from the role filesystem')
    backing = Path('/sys/dev/block') / info[2] / 'loop/backing_file'
    if backing.exists():
        image = Path(backing.read_text().strip())
        info_backing = image.lstat()
        db.require(image.is_absolute() and image.resolve(strict=True) == image
                   and stat.S_ISREG(info_backing.st_mode) and info_backing.st_blocks * 512 >= info_backing.st_size,
                   'loop-backed development storage must be fully allocated')
    limits = os.statvfs(path)
    total = limits.f_blocks * limits.f_frsize
    db.require(0 < total <= ceiling, 'actual filesystem capacity exceeds the declared storage ceiling')
    host = os.statvfs(path.parent)
    db.require(host.f_bavail * host.f_frsize >= 8 * db.GIB, 'eight GiB host reserve required')
    return {'device': info[2], 'type': fs_type, 'bytes': total}


def check_label(path, expected):
    actual = os.getxattr(path, 'security.selinux').decode('ascii')
    db.require(db.same_label(actual, expected), f'{path.name} SELinux volume label mismatch')


def placement(account, manifest, actual_manifest):
    job = manifest['job']
    build = ROOT / 'builds' / job
    build_stat = private_dir(build, account)
    mountinfo = Path('/proc/self/mountinfo').read_text()
    storage = storage_mount(build, manifest['storage_bytes'], mountinfo)
    inputs = build / 'inputs'
    graph = build / 'graph'
    image_copy = build / 'image-copy'
    for directory in (graph, image_copy):
        db.require(private_dir(directory, account).st_dev == build_stat.st_dev,
                   f'{directory.name} must remain on bounded development storage')
        check_label(directory, db.file_label(manifest, 'outer'))
    db.require(inputs.resolve(strict=True) == inputs and inputs.stat().st_dev == build_stat.st_dev,
               'candidate inputs must remain on bounded storage')
    archive = inputs / 'development.oci.tar'
    db.require(actual_manifest == inputs / 'manifest.json', 'manifest must be at the selected job input leaf')
    for source in (actual_manifest, archive):
        info = source.lstat()
        db.require(stat.S_ISREG(info.st_mode) and info.st_dev == build_stat.st_dev and info.st_nlink == 1
                   and not info.st_mode & 0o222 and info.st_uid in (0, account.pw_uid),
                   'candidate inputs must be unique, read-only regular files on the dedicated filesystem')
        check_label(source, db.file_label(manifest, 'outer'))
    db.require(archive.stat().st_size == manifest['inner']['archive_bytes'], 'development archive byte count mismatch')
    mounts = {db.GRAPHROOT: (str(graph), True), db.IMAGE_COPY_DIR: (str(image_copy), True),
              db.ARCHIVE: (str(archive), False),
              db.MANIFEST: (str(actual_manifest), False)}
    for key in db.JOB_TARGETS:
        source = ROOT / key / job
        private_dir(source, account)
        check_label(source, db.file_label(manifest, 'inner'))
        db.require(next(source.iterdir(), None) is None, 'development probe requires fresh synthetic job data leaves')
        mounts[f'{db.PARENT_JOB}/{key}'] = (str(source), True)
    sources = {Path(source) for source, _ in mounts.values()} | {inputs}
    for line in mountinfo.splitlines():
        target = Path(line.split()[4])
        db.require(not any(target.is_relative_to(source) for source in sources),
                   'nested host mount intersects an admitted source')
    return mounts, storage


@contextmanager
def ownership(account, job, admission):
    base = ROOT / 'evidence'
    private_dir(base, account)
    root = base / job
    root.mkdir(mode=0o700, exist_ok=True)
    private_dir(root, account)
    lock = os.open(root / 'owner.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock)
        db.require(stat.S_ISREG(info.st_mode) and info.st_uid == account.pw_uid
                   and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe owner lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise db.Blocked('the selected development leaf is in use') from error
        path = root / 'owner.json'
        if not os.path.lexists(path):
            value = {'manifest_sha256': admission, 'owner': os.urandom(32).hex()}
            stage = root / 'owner.new'
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'w') as output:
                info = os.fstat(fd)
                db.require(stat.S_ISREG(info.st_mode) and info.st_uid == account.pw_uid
                           and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe owner staging file')
                output.truncate(0)
                output.write(json.dumps(value, sort_keys=True) + '\n')
                output.flush()
                os.fsync(fd)
            os.replace(stage, path)
            directory = os.open(root, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        info = path.lstat()
        db.require(stat.S_ISREG(info.st_mode) and info.st_uid == account.pw_uid and info.st_nlink == 1
                   and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe DevBox ownership record')
        _, _, payload = db.file_hash(path, db.MANIFEST_LIMIT, time.monotonic() + 5, content=True)
        record = db.json_data(payload)
        db.fields(record, 'manifest_sha256 owner', 'DevBox ownership record')
        db.require(record['manifest_sha256'] == admission, 'development leaf is bound to another admission')
        hooks = root / 'empty-hooks'
        hooks.mkdir(mode=0o700, exist_ok=True)
        private_dir(hooks, account)
        db.require(next(hooks.iterdir(), None) is None, 'host OCI hooks directory must be empty')
        yield db.hex_id(record['owner']), hooks
    finally:
        os.close(lock)


def host_env(account):
    env = db.local_env()
    runtime = f'/run/user/{account.pw_uid}'
    env.update({'HOME': account.pw_dir, 'USER': 'dp-dev', 'LOGNAME': 'dp-dev',
                'XDG_RUNTIME_DIR': runtime, 'XDG_CONFIG_HOME': str(RUNTIME),
                'DBUS_SESSION_BUS_ADDRESS': f'unix:path={runtime}/bus',
                'CONTAINERS_CONF': str(RUNTIME / 'host-containers.conf')})
    return env


def observe_parent(row, manifest, account):
    pid = row['State'].get('Pid')
    db.require(row['State'].get('Running') is True and type(pid) is int and pid > 1, 'outer DevBox is not running')
    proc = Path('/proc') / str(pid)
    observed = db.proc_snapshot(proc, db.OUTER_CAPS, 0, db.process_label(manifest, 'outer'),
                                account.pw_uid, account.pw_gid)
    db.require(all(observed['namespaces'][name] != os.readlink('/proc/self/ns/' + name) for name in db.NS_NAMES),
               'parent does not have private host-facing namespaces')
    db.require(os.readlink(proc / 'ns/cgroup') != os.readlink('/proc/self/ns/cgroup'),
               'parent does not have a private host-facing cgroup namespace')
    for kind, caller in (('uid', account.pw_uid), ('gid', account.pw_gid)):
        observed[kind + '_map'] = db.ids((proc / (kind + '_map')).read_text(), DP_DEV_SUBORDINATES, caller)
    match = re.fullmatch(r'0::(/[a-zA-Z0-9_.@/-]+)', observed['cgroup'])
    db.require(match is not None, 'central cgroup v2 membership required')
    group = Path('/sys/fs/cgroup') / match[1].lstrip('/')
    db.require(group.is_relative_to('/sys/fs/cgroup') and group.resolve(strict=True) == group,
               'invalid host cgroup membership')
    values = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    cpu = values['cpu.max'].split()
    db.require(values['memory.max'] == str(2 * db.GIB) and values['memory.swap.max'] == '0'
               and values['pids.max'] == '512' and len(cpu) == 2 and cpu[0] == cpu[1] and cpu[0].isdigit(),
               'effective outer aggregate cgroup ceilings mismatch')
    observed.update({'pid': pid, 'limits': values})
    return observed


def validate_result(receipt, admission, owner, manifest):
    db.fields(receipt, 'kind manifest_sha256 owner inner_container_id inner_image_id cycles inner_removed job_admission',
              'nested receipt')
    db.require(receipt['kind'] == 'dev-pair-devbox-probe-v1' and receipt['manifest_sha256'] == admission
               and receipt['owner'] == owner and receipt['inner_image_id'] == manifest['inner']['image_id']
               and receipt['inner_removed'] is True and receipt['job_admission'] is False,
               'nested receipt binding mismatch')
    db.hex_id(receipt['inner_container_id'])
    cycles = receipt['cycles']
    db.require(type(cycles) is list and len(cycles) == 2 and cycles[0]['started_at'] != cycles[1]['started_at'],
               'two independent nested starts are required')
    for cycle in cycles:
        label = db.process_label(manifest, 'inner')
        db.require(cycle['version'] == f'codex-cli {db.CODEX_VERSION}' and cycle['probe']['boundary_probe'] == 'passed'
                   and db.same_label(cycle['proc']['label'], label)
                   and db.same_label(cycle['probe']['selinux_label'], label), 'nested probe evidence mismatch')


def launch(engine, manifest, admission, account, owner, hooks, mounts):
    name = 'dp-devbox-' + owner[:24]
    image = manifest['outer']['image_id']
    with db.owned_container(engine, name, owner, image):
        mount_args = [db.bind(src, dest, rw, executable=dest == db.GRAPHROOT) for dest, (src, rw) in mounts.items()]
        _, result = engine('create confined DevBox', 'create',
                           *db.container_args(name, owner, manifest, 'outer', hooks), *mount_args,
                           '--entrypoint=/usr/bin/sleep', image, str(db.OUTER_SECONDS))
        identity = db.engine_id(result.decode('ascii').strip())

        def inspect():
            row = engine.inspect('container', identity)
            db.inspect_policy(row, identity, owner, manifest, 'outer', mounts)
            return row

        inspect()
        engine('start confined DevBox', 'start', identity)
        parent = observe_parent(inspect(), manifest, account)
        budget = int(engine.deadline - time.monotonic()) - db.CLEANUP_SECONDS - 5
        db.require(budget > 0, 'insufficient time left for nested entry and cleanup')
        _, output = engine('execute immutable nested controller', 'exec', '--user=1000:1000', identity,
                           '/usr/bin/python3', '-I', str(db.BASE / 'controller.py'), admission, owner,
                           str(budget), seconds=budget + db.CLEANUP_SECONDS)
        receipt = db.json_data(output)
        validate_result(receipt, admission, owner, manifest)
        db.require(observe_parent(inspect(), manifest, account) == parent, 'outer DevBox changed during nested entry')
        enforcing(engine.deadline)
    return {'outer_container_id': identity, 'outer_image_id': image, 'parent': parent, 'outer_removed': True, **receipt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('run',))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='independently recorded manifest SHA-256')
    args = parser.parse_args()
    end = time.monotonic() + db.OUTER_SECONDS
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, db.interrupt)
    try:
        account = host_account()
        enforcing(end)
        db.require(args.manifest.is_absolute() and args.manifest.resolve(strict=True) == args.manifest,
                   'use the absolute, nonsymlink manifest path')
        manifest = db.read_manifest(args.manifest, args.sha256, end)
        engine = db.Engine([db.PODMAN, '--remote=false', '--runtime=' + db.CRUN, '--cgroup-manager=systemd'],
                           host_env(account), end)
        db.immutable_image(engine, manifest, 'outer')
        with ownership(account, manifest['job'], args.sha256) as (owner, hooks):
            db.remove_owned(engine, 'dp-devbox-' + owner[:24], owner, manifest['outer']['image_id'])
            mounts, storage = placement(account, manifest, args.manifest)
            receipt = launch(engine, manifest, args.sha256, account, owner, hooks, mounts)
        print(json.dumps({**receipt, 'storage': storage, 'standards_sha': db.STANDARDS,
                          'outer_source_sha': manifest['outer']['source_sha'],
                          'inner_source_sha': manifest['inner']['source_sha'],
                          'archive_sha256': manifest['inner']['archive_sha256']}, sort_keys=True))
        return 0
    except (db.Blocked, OSError, KeyError, ValueError, TypeError, IndexError) as error:
        print(f'DevBox blocked: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
