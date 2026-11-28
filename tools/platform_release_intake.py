#!/usr/bin/python3
"""Read and stage one exact, independently attested platform package."""

import argparse
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

import platform_release as release
from storage import GUEST_RESERVE, MANAGED_CEILING
from platform_release_protocol import (
    ARCHIVE_LIMIT, CONTROL_LIMIT, ROLES, COMPONENT,
    Blocked, bounded_json, canonical, file_hash, hex_id, require, seconds, stream_exact, portable_index, portable_roles,
    site_predecessor,
)

GITHUB = '/usr/bin/gh'
ROOT = Path('/var/lib/dev-pair/platform-releases')
TRUST = Path(__file__).resolve().with_name('release_trust.py')
API = 'repos/' + release.REPOSITORY + '/'
CONTROL_SECONDS = 900
INITIAL_RUN_LIMIT = 8
PLATFORM_WORKFLOW = 'platform-release.yml'
ZIP_OVERHEAD = 1024 * 1024
META_LIMIT = 256 * 1024
TRANSFER_INODES = 512 + 24  # Installer reserve plus a complete transfer's control and payload leaves.
RETIREMENT = 'archives-retired.json'
TRANSFER_LEASE = '.intake-transfer.json'
TRANSFER_TICKET = '.transfer-owner.json'
TRANSFER_PREFIX = '.intake-stage-'
BOOT_PATTERN = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
ENV = {'PATH': '/usr/bin:/usr/sbin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
       'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1', 'GH_HOST': 'github.com'}


class InitialReleaseUnavailable(Blocked):
    def __init__(self, phase, reason):
        super().__init__(reason)
        self.phase = phase


def native_env():
    env = dict(ENV)
    for key in ('GH_CONFIG_DIR',):
        if key in os.environ:
            env[key] = str(protected(Path(os.environ[key]), directory=True))
    return env


def protected(path, *, directory=False):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'release intake requires canonical protected paths')
    for node in (path, *path.parents):
        info = node.lstat()
        wanted = stat.S_ISDIR(info.st_mode) if node != path or directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        require(info.st_uid == 0 and not info.st_mode & 0o022 and wanted, 'release intake path is not root protected')
    return path


def read_api(endpoint, end, *, limit=META_LIMIT, output=None):
    parent = os.getpid()
    if output is None:
        limit = min(limit, META_LIMIT)

    def limits():
        # A terminated intake must not leave a worker growing the anonymous ZIP.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(125)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    command = [GITHUB, 'api', '--hostname', 'github.com', '--method', 'GET',
               '-H', 'Accept: application/vnd.github+json', API + endpoint]

    def transfer(target):
        subprocess.run(command, env=native_env(), stdin=subprocess.DEVNULL, stdout=target, stderr=subprocess.DEVNULL,
                       timeout=seconds(end, 300), check=True, preexec_fn=limits)
        size = target.tell()
        require(0 < size <= limit, 'GitHub response exceeded the exact release transfer bound')

    if output is None:
        with tempfile.TemporaryFile(dir=ROOT) as target:
            transfer(target)
            target.seek(0)
            value = bounded_json(target.read(limit + 1), limit, 'GitHub REST metadata exceeds its bound')
            require(type(value) is dict, 'GitHub REST metadata must be an object')
            return value
    transfer(output)


def intake_limit(directory, files, headroom=0):
    demand = sum(files) + headroom + GUEST_RESERVE
    require(shutil.disk_usage(directory).free >= demand, 'release intake capacity and recovery reserve are insufficient')


def read_mountinfo():
    with Path('/proc/self/mountinfo').open('rb') as source:
        raw = source.read(1024**2 + 1)
    require(0 < len(raw) <= 1024**2, 'release mount inventory exceeds its byte bound')
    return raw.decode()


def archive_geometry(directory, managed, mountinfo):
    """Independently charge a separate archive backing once to the managed cap."""
    import devbox

    node = directory.lstat()
    if f'{os.major(node.st_dev)}:{os.minor(node.st_dev)}' != managed['device']:
        remaining = MANAGED_CEILING - managed['backing_bytes']
        require(remaining > 0, 'release archive backing does not fit the aggregate managed budget')
        separate = devbox.storage_mount(directory, remaining, mountinfo)
        device = Path('/sys/dev/block') / separate['device']
        sectors = int((device / 'size').read_text().strip())
        require(separate['bytes'] <= sectors * 512 and managed['backing_bytes'] + sectors * 512 <= MANAGED_CEILING,
                'role and archive filesystems exceed the shared managed ceiling')
    return node.st_dev


def portable_volume(*, for_recovery=False):
    import devbox

    mountinfo = read_mountinfo()
    prefix = os.fsencode(ROOT) + b'/'
    require(not any(os.fsencode(row.split()[4]).startswith(prefix) for row in mountinfo.splitlines()),
            'portable inputs have nested mounts; retirement is unresolved')
    managed = devbox.managed_storage(mountinfo, for_recovery=for_recovery)
    device = archive_geometry(ROOT, managed, mountinfo)
    mounts = [row.split() for row in mountinfo.splitlines()]
    archive_device = f'{os.major(device)}:{os.minor(device)}'
    mount_ids = tuple(row[0] for row in mounts if row[2] in {archive_device, managed['device']})
    return device, managed['backing_inode'], managed['backing_bytes'], mount_ids


def checked_run(value, source, run, agent):
    event = ('schedule', 'workflow_dispatch') if agent else ('push',)
    path = '.github/workflows/' + ('agent-refresh.yml' if agent else PLATFORM_WORKFLOW)
    require(value.get('id') == run and value.get('run_attempt') == 1 and value.get('event') in event and
            value.get('status') == 'completed' and value.get('conclusion') == 'success' and
            value.get('path') == path and value.get('head_sha') == source and
            value.get('head_branch') == 'main' and value.get('repository', {}).get('full_name') == release.REPOSITORY and
            value.get('head_repository', {}).get('full_name') == release.REPOSITORY, 'protected platform publisher run unavailable')


def artifacts(raw, source, agent, *, allow_expired=False):
    values = raw.get('artifacts')
    roles = (*ROLES, 'host') if not agent else ROLES[:2]
    names = {release.artifact_name(part, source) for part in (*roles, 'subjects')}
    if agent:
        names.add(f'agent-tooling-{source}')
    require(raw.get('total_count') == len(names) and type(values) is list and len(values) == len(names),
            'publisher artifact inventory differs from the closed release package')
    result = {}
    for row in values:
        name, identifier = row.get('name'), row.get('id')
        require(name in names and name not in result and type(identifier) is int and identifier > 0 and
                type(row.get('expired')) is bool and (allow_expired or not row['expired']) and type(row.get('digest')) is str and
                re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']) and
                type(row.get('size_in_bytes')) is int and row['size_in_bytes'] > 0, 'publisher artifact is expired or ambiguous')
        result[name] = row
    require(len({row['id'] for row in result.values()}) == len(result), 'duplicate artifact ID')
    return result


def extract_zip(source, destination, wanted, end):
    # Bound the central directory before zipfile reads or allocates it.
    end_record = zipfile._EndRecData(source)
    require(end_record is not None and end_record[zipfile._ECD_DISK_NUMBER] == 0 and
            end_record[zipfile._ECD_DISK_START] == 0 and
            end_record[zipfile._ECD_ENTRIES_THIS_DISK] == end_record[zipfile._ECD_ENTRIES_TOTAL] == len(wanted) and
            0 < end_record[zipfile._ECD_SIZE] <= CONTROL_LIMIT,
            'Actions ZIP central directory exceeds its closed two-file bound')
    source.seek(0)
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        require(len(members) == len(wanted) and {item.filename for item in members} == set(wanted),
                'Actions ZIP content differs from its exact component')
        for item in members:
            mode = item.external_attr >> 16
            require(not item.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG) and not item.flag_bits & 1 and
                    item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    'Actions ZIP contains a link, special file or unsupported member')
            expected, maximum = wanted[item.filename]
            require(0 < item.file_size <= maximum and (expected is None or item.file_size == maximum),
                    'Actions ZIP member byte limit or exact length differs')
            with archive.open(item) as content, (destination / item.filename).open('xb') as target:
                actual = stream_exact(content, item.file_size, end, target)
                require(not content.read(1) and (expected is None or actual == expected),
                        'Actions ZIP member failed its verified digest')
                os.fsync(target.fileno())
        release.sync_directory(destination)


def fetch_artifact(rows, name, destination, wanted, end):
    row = rows[name]
    maximum = ZIP_OVERHEAD + sum(value[1] for value in wanted.values())
    require(row['size_in_bytes'] <= maximum, 'Actions ZIP transport exceeds the approved byte bound')
    intake_limit(ROOT, [row['size_in_bytes'], sum(value[1] for value in wanted.values())])
    with tempfile.TemporaryFile(dir=ROOT) as transport:
        read_api(f'actions/artifacts/{row["id"]}/zip', end, limit=row['size_in_bytes'], output=transport)
        node = os.fstat(transport.fileno())
        require(node.st_nlink == 0 and node.st_uid == os.geteuid() and stat.S_IMODE(node.st_mode) == 0o600 and
                node.st_size == row['size_in_bytes'], 'Actions ZIP scratch or exact transport length differs')
        transport.seek(0)
        sha = stream_exact(transport, node.st_size, end)
        require(row['digest'] == 'sha256:' + sha and not transport.read(1),
                'Actions ZIP differs from its exact transport identity')
        extract_zip(transport, destination, wanted, end)


def verify_subject(path, identity, source, run, role, end):
    verify = protected(TRUST)
    subprocess.run(['/usr/bin/python3', '-EBs', str(verify), 'verify', '--component', role, '--source-sha', source,
                    '--subject', str(protected(path)), '--sha256', identity, '--run-id', str(run)],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, env=native_env(), timeout=seconds(end, 120), check=True)


def verify_local_parts(directory, value, end):
    for part, transfer in value['transports'].items():
        local = protected(directory / part, directory=True)
        require({item.name for item in local.iterdir()} == set(transfer['files']), 'local release component inventory changed')
        for name, row in transfer['files'].items():
            require(file_hash(protected(local / name), row['bytes'], end, owner=0) == (row['sha256'], row['bytes']),
                    'local release component no longer matches its digest')
        source = value['source_sha']
        if part == 'host':
            require(release.validate_host(local, source, end) == value['components']['host']['bundle_manifest_sha256'],
                    'portable host bundle identity differs')
        else:
            component = value['components'][COMPONENT[part]]
            checked, _ = release.validate_image_part(local, part, source, end, component if part != 'devbox' else None)
            require(release.portable_image(checked, component) == component, 'portable image identity differs from exact archive')


def retained_index(identity):
    previous = protected(ROOT / identity, directory=True)
    raw, value = release.readonly_json(protected(previous / 'platform.json'), 0)
    require(raw == canonical(value) and hashlib.sha256(raw).hexdigest() == identity,
            'retained previous platform manifest changed')
    portable_index(value, value['source_sha'], value['publisher_run'])
    path = protected(previous / 'intake.json')
    receipt_raw, receipt = release.readonly_json(path, 0)
    require(stat.S_IMODE(path.lstat().st_mode) == 0o600 and receipt_raw == canonical(receipt) and
            type(receipt['schema']) is int and receipt == {'schema': 2, 'platform_sha256': identity,
            'source_sha': value['source_sha'], 'publisher_run': value['publisher_run'], 'kind': value['kind']},
            'retained previous platform lacks exact prior trust receipt')
    if value['schema'] == 3:
        binding_path = protected(previous / 'site-predecessor.json')
        binding_raw, binding = release.readonly_json(binding_path, 0)
        require(stat.S_IMODE(binding_path.lstat().st_mode) == 0o600 and binding_raw == canonical(binding),
                'retained local predecessor evidence is not protected canonical data')
        site_predecessor(binding, identity, value['base_platform_sha256'])
        receipt_raw += binding_raw
    return previous, value, hashlib.sha256(receipt_raw).hexdigest()


def previous_release(identity, end):
    previous, value, _ = retained_index(identity)
    require(not os.path.lexists(previous / RETIREMENT), 'portable release has retired its archive transfer; choose an available predecessor')
    verify_local_parts(previous, value, end)
    return value


def staged_paths(end):
    paths = []
    with os.scandir(ROOT) as entries:
        for entry in entries:
            seconds(end, CONTROL_SECONDS)
            if entry.name != '.intake.lock':
                require(re.fullmatch('[0-9a-f]{64}', entry.name),
                        'portable staging contains an unresolved or foreign entry')
                paths.append(protected(Path(entry.path), directory=True))
    return paths


def durable_record(path, value):
    raw = canonical(value)
    parent = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
            os.link(f'/proc/self/fd/{fd}', path.name, dst_dir_fd=parent, follow_symlinks=True)
            os.fsync(parent)
    finally:
        os.close(parent)


def boot_identity():
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(BOOT_PATTERN, boot), 'portable transfer boot identity is unavailable')
    return boot


def transfer_record(path):
    raw, value = release.readonly_json(protected(path), 0)
    require(stat.S_IMODE(path.lstat().st_mode) == 0o600 and raw == canonical(value),
            'portable transfer ownership record is not protected canonical data')
    return raw, value


def transfer_entries(stage, raw, device):
    node = protected(stage, directory=True).lstat()
    require(node.st_dev == device and stat.S_IMODE(node.st_mode) == 0o700,
            'portable transfer directory differs from its owned allocation')
    ticket = stage / TRANSFER_TICKET
    if not os.path.lexists(ticket):
        require(next(stage.iterdir(), None) is None, 'portable scratch lacks its exact protected ownership ticket')
        return []
    require(transfer_record(ticket)[0] == raw, 'portable transfer workspace ownership ticket differs')
    checked = []
    controls = {'platform.json', 'intake.json', 'site-predecessor.json', TRANSFER_TICKET}
    for entry in stage.iterdir():
        if entry.name in controls:
            info = protected(entry).lstat()
            require(info.st_dev == device and info.st_size <= CONTROL_LIMIT,
                    'portable transfer control file exceeded its owned allocation')
            if entry != ticket:
                checked.append(entry)
            continue
        require(entry.name in {*ROLES, 'host'} and protected(entry, directory=True).lstat().st_dev == device,
                'foreign entry in portable transfer workspace')
        archive, evidence = (('host.tar', 'host-manifest.json') if entry.name == 'host' else
                             (f'{entry.name}.oci.tar', 'part.json'))
        for leaf in entry.iterdir():
            require(leaf.name in (archive, evidence), 'foreign leaf in portable transfer workspace')
            info = protected(leaf).lstat()
            ceiling = CONTROL_LIMIT if leaf.name == evidence else (release.HOST_LIMIT if entry.name == 'host' else ARCHIVE_LIMIT)
            require(info.st_dev == device and info.st_size <= ceiling,
                    'portable transfer file exceeded its owned allocation')
            checked.append(leaf)
        checked.append(entry)
    return checked + [ticket]


def recover_transfer():
    lease = ROOT / TRANSFER_LEASE
    if not os.path.lexists(lease):
        return
    raw, record = transfer_record(lease)
    require(set(record) == {'schema', 'platform_sha256', 'nonce', 'boot_id', 'root_inode', 'volume'} and
            type(record['schema']) is int and record['schema'] == 1 and re.fullmatch(BOOT_PATTERN, record['boot_id']) and
            re.fullmatch('[0-9a-f]{24}', record['nonce']) and record['root_inode'] == ROOT.lstat().st_ino,
            'portable transfer lease differs from its fixed protected scope')
    identity = record['platform_sha256']
    target = ROOT / hex_id(identity) if identity is not None else None
    stage = ROOT / (TRANSFER_PREFIX + record['nonce'])
    device, inode, size, mounts = portable_volume(for_recovery=True)
    volume = [device, inode, size, list(mounts)]
    saved = record['volume']
    require(type(saved) is list and len(saved) == len(volume) and saved[1:3] == volume[1:3] and
            (record['boot_id'] != boot_identity() or saved == volume),
            'portable transfer lease backing or mount identity changed')
    if os.path.lexists(stage):
        require(target is None or not os.path.lexists(target), 'portable transfer workspace and published target both exist')
        for path in transfer_entries(stage, raw, device):
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
            release.sync_directory(path.parent)
        stage.rmdir()
    elif target is not None and os.path.lexists(target):
        require(protected(target, directory=True).lstat().st_dev == device and transfer_record(target / TRANSFER_TICKET)[0] == raw,
                'portable transfer lease does not match published target custody')
        retained_index(target.name)
    release.sync_directory(ROOT)
    lease.unlink()
    release.sync_directory(ROOT)


@contextmanager
def transfer_workspace(identity):
    lease = ROOT / TRANSFER_LEASE
    nonce = secrets.token_hex(12)
    stage = ROOT / (TRANSFER_PREFIX + nonce)
    target = ROOT / hex_id(identity) if identity is not None else None
    require(not any(os.path.lexists(path) for path in (lease, stage, target) if path is not None),
            'portable transfer lease or target already exists')
    device, inode, size, mounts = portable_volume()
    value = {'schema': 1, 'platform_sha256': identity, 'nonce': nonce, 'boot_id': boot_identity(),
             'root_inode': ROOT.lstat().st_ino, 'volume': [device, inode, size, list(mounts)]}
    durable_record(lease, value)
    try:
        stage.mkdir(mode=0o700)
        release.sync_directory(ROOT)
        durable_record(stage / TRANSFER_TICKET, value)
        yield stage
        if target is not None:
            release.sync_directory(stage)
            require(not os.path.lexists(target), 'portable transfer publication target appeared')
            stage.rename(target)
            release.sync_directory(ROOT)
    finally:
        recover_transfer()


def portable_predecessor(directory, index):
    if index['schema'] == 3:
        _, binding = release.readonly_json(protected(directory / 'site-predecessor.json'), 0)
        return site_predecessor(binding, directory.name, index['base_platform_sha256'])
    return index['previous_platform_sha256']


def bound_local_platform(controller, reference, catalog, *, required=True):
    import renewal

    reference = hex_id(reference)
    local = controller.release(reference)
    path = controller.control / 'platform-bindings' / (reference + '.json')
    if not os.path.lexists(path):
        require(not required, 'retirement requires an exact portable binding for the selected or pending local release')
        return None
    binding = renewal.read_json(path)
    identity = hex_id(binding['platform_sha256'])
    hex_id(binding['site_config_sha256'])
    _, index, receipt = catalog[identity]
    component = local['components']['maintenance-agent']
    require(set(binding) == {'schema', 'release_sha256', 'platform_sha256', 'base_platform_sha256',
                             'site_config_sha256', 'plan_sha256', 'intake_sha256'} and type(binding['schema']) is int and
            binding['schema'] == 1 and binding['release_sha256'] == reference and binding['intake_sha256'] == receipt and
            binding['plan_sha256'] == local['plan_sha256'] and
            binding['base_platform_sha256'] == (index['base_platform_sha256'] or identity) and
            component.get('platform_sha256', identity) == identity and
            component['artifact_sha256'] == index['components']['maintenance-agent']['oci_config_sha256'] and
            component['source_revision'] == index['source_sha'], 'local and portable retirement authority differ')
    return identity


def retirement_scope(controller, catalog, expected_previous, base, end):
    import renewal
    from renewal_site import offer_record

    current = controller.live_release()
    _, journal = controller.transition()
    require(renewal.read_json(controller.control / 'site-current.json') == current and
            (journal is None or journal['phase'] in renewal.TERMINAL) and
            not os.path.lexists(controller.root / 'renewal-fence/frozen') and
            not os.path.lexists(controller.root / '.platform-maintenance-lease.json'),
            'pending renewal, boot observation or native ownership prevents portable archive retirement')
    active = bound_local_platform(controller, current, catalog)
    require(active == expected_previous and (catalog[active][1]['base_platform_sha256'] or active) == base and
            catalog[base][1]['kind'] == 'dev-pair-platform-release',
            'active site selection or stable portable base changed before retirement')
    lineage = set()
    reference = active
    while reference != base:
        seconds(end, CONTROL_SECONDS)
        require(reference in catalog and reference not in lineage, 'active portable predecessor chain is incomplete or cyclic')
        lineage.add(reference)
        directory, index, _ = catalog[reference]
        require(index['base_platform_sha256'] == base, 'active portable predecessor changes the stable base')
        reference = portable_predecessor(directory, index)
    lineage.add(base)
    keep = {base, active}
    if active != base:
        keep.add(portable_predecessor(*catalog[active][:2]))
    require(all(not os.path.lexists(catalog[identity][0] / RETIREMENT) for identity in keep),
            'active or recoverable portable release has missing retained archive authority')

    settled = None
    if journal is not None and journal['phase'] in ('rejected', 'rolled-back'):
        request = journal['request']
        settled = renewal.checked_request(request, request['scope'])
    for scope in ('initial', 'agent', 'stable'):
        path = controller.control / 'offers' / (scope + '.json')
        if os.path.lexists(path):
            offer = offer_record(renewal.read_json(path), scope)
            rejected_offer = (settled is not None and settled['scope'] == scope and
                              settled['previous_sha256'] == offer['previous_release_sha256'] and
                              all(settled[key] == offer[key] for key in ('operation', 'affected_jobs', 'reason')) and
                              bound_local_platform(controller, settled['target_sha256'], catalog) == offer['platform_sha256'])
            if not rejected_offer:
                keep.add(offer['platform_sha256'])
            if offer['previous_release_sha256'] is not None:
                keep.add(bound_local_platform(controller, offer['previous_release_sha256'], catalog))
    for scope in renewal.SCOPE_COMPONENTS:
        path = controller.control / 'requests' / (scope + '.json')
        if os.path.lexists(path):
            raw = renewal.read_json(path)
            request = renewal.checked_request(raw['request'] if scope in ('agent', 'stable') else raw, scope)
            keep.add(bound_local_platform(controller, request['previous_sha256'], catalog))
            if request != settled:
                keep.add(bound_local_platform(controller, request['target_sha256'], catalog))

    rejected = set()
    attempts = renewal.trusted_directory(controller.control / 'attempts')
    with os.scandir(attempts) as entries:
        for count, entry in enumerate(entries, 1):
            seconds(end, CONTROL_SECONDS)
            require(count <= renewal.MAX_ATTEMPTS, 'renewal journal exceeds its retained-attempt bound')
            attempt = renewal.trusted_directory(Path(entry.path))
            record = renewal.read_json(attempt / 'journal.json')
            require(type(record['schema']) is int and record['schema'] == 1 and record['attempt_id'] == attempt.name,
                    'retained renewal attempt identity differs')
            request = renewal.checked_request(record['request'], record['request']['scope'])
            if record['phase'] not in renewal.TERMINAL or (record['phase'] == 'deferred' and request['previous_sha256'] == current):
                keep.update(bound_local_platform(controller, request[key], catalog)
                            for key in ('previous_sha256', 'target_sha256'))
            if record['phase'] in ('rolled-back', 'rejected') and request['scope'] == 'agent':
                rejected.add(bound_local_platform(controller, request['target_sha256'], catalog, required=False))
    return current, keep, lineage - {active}, rejected


def retired_record(directory, receipt):
    path = directory / RETIREMENT
    if not os.path.lexists(path):
        return None
    raw, value = release.readonly_json(protected(path), 0)
    require(set(value) == {'schema', 'platform_sha256', 'intake_sha256', 'superseding_release_sha256'} and
            stat.S_IMODE(path.lstat().st_mode) == 0o600 and type(value['schema']) is int and value['schema'] == 1 and
            value['platform_sha256'] == directory.name and value['intake_sha256'] == receipt and raw == canonical(value),
            'portable archive retirement journal differs from its exact intake evidence')
    hex_id(value['superseding_release_sha256'])
    return value


def retireable_archives(directory, index, receipt, device, end):
    retired = retired_record(directory, receipt)
    owned = []
    for role, transfer in index['transports'].items():
        parent = protected(directory / role, directory=True)
        require(parent.lstat().st_dev == device, 'portable archive directory changed its measured filesystem')
        require({item.name for item in parent.iterdir()} <= set(transfer['files']),
                'foreign portable role file prevents archive retirement')
        for name, item in transfer['files'].items():
            path = parent / name
            archive = name == f'{role}.oci.tar'
            if archive and retired and not os.path.lexists(path):
                continue  # A prior invocation durably authorized this exact leaf.
            node = protected(path).lstat()
            require(node.st_dev == device and file_hash(path, item['bytes'], end, owner=0) == (item['sha256'], item['bytes']),
                    'portable transport changed before retirement')
            if archive:
                owned.append((path, archive_inode(node)))
    return retired, owned


def archive_inode(node):
    return (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid, node.st_nlink,
            node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def retain_for_transfer(paths, previous, base, demand, end):
    """Recover only verified surplus transfer files under actual package pressure."""
    def enough():
        state = os.statvfs(ROOT)
        return state.f_bavail * state.f_frsize >= demand + GUEST_RESERVE and state.f_favail >= TRANSFER_INODES

    volume = portable_volume()
    if enough():
        return
    import renewal

    catalog = {}
    for path in paths:
        seconds(end, CONTROL_SECONDS)
        catalog[path.name] = retained_index(path.name)
    controller = renewal.Renewal(ROOT.parent, None)
    with controller.lock():
        scope = retirement_scope(controller, catalog, previous, base, end)
    rollback = portable_predecessor(*catalog[previous][:2])
    if previous != base and rollback != base:
        previous_release(rollback, end)
    _, keep, historical, rejected = scope
    ordered = sorted(catalog.values(), key=lambda record: record[1]['publisher_run'])
    for directory, index, receipt in ordered:
        if index['kind'] != 'dev-pair-agent-release' or index['base_platform_sha256'] != base or directory.name in keep:
            continue
        if directory.name not in historical | rejected and portable_predecessor(directory, index) not in historical:
            continue
        retired, owned = retireable_archives(directory, index, receipt, volume[0], end)
        if not owned:
            continue
        with controller.lock():
            require(retirement_scope(controller, catalog, previous, base, end) == scope and portable_volume() == volume,
                    'portable retirement authority or physical backing changed')
            if retired is None:
                state = os.statvfs(directory)
                require(state.f_favail > 0 and state.f_bavail * state.f_frsize >= CONTROL_LIMIT,
                        'portable archive retirement needs space for its protected journal')
                durable_record(directory / RETIREMENT, {'schema': 1, 'platform_sha256': directory.name,
                               'intake_sha256': receipt, 'superseding_release_sha256': scope[0]})
            for path, node in owned:
                require(archive_inode(protected(path).lstat()) == node, 'owned portable archive changed after verification')
                path.unlink()
                release.sync_directory(path.parent)
        if enough():
            return
    raise Blocked('portable archive capacity and recovery reserve are insufficient after scoped retirement; '
                  'active, compatible previous and pending inputs remain reserved')


@contextmanager
def intake_lock():
    protected(ROOT, directory=True)
    lock = ROOT / '.intake.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        node = os.fstat(fd)
        require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1 and
                stat.S_IMODE(node.st_mode) == 0o600, 'release intake lock is not protected')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def initial_runs(source, end):
    branch = read_api('branches/main', end)
    require(branch.get('protected') is True, 'initial full release discovery requires protected main')
    if branch.get('commit', {}).get('sha') != source:
        raise InitialReleaseUnavailable('initial-source-not-published',
                                        'the reviewed checkout is not the current protected-main release source')
    listing = read_api(f'actions/workflows/{PLATFORM_WORKFLOW}/runs?branch=main&event=push&status=success'
                       f'&head_sha={source}&per_page={INITIAL_RUN_LIMIT}', end)
    rows = listing.get('workflow_runs')
    require(type(rows) is list and type(listing.get('total_count')) is int and
            len(rows) == listing['total_count'] <= INITIAL_RUN_LIMIT,
            'initial full release run inventory is incomplete or exceeds its safe selection bound')
    seen = set()
    candidates = []
    for row in rows:
        require(type(row) is dict, 'invalid initial full release run listing')
        run = row.get('id')
        require(type(run) is int and 0 < run < 2**63 and run not in seen,
                'initial full release run identifiers are invalid or ambiguous')
        seen.add(run)
        if (type(row.get('run_attempt')) is int and row['run_attempt'] == 1 and
                row.get('path') == '.github/workflows/' + PLATFORM_WORKFLOW and
                row.get('event') == 'push' and row.get('status') == 'completed' and row.get('conclusion') == 'success' and
                row.get('head_branch') == 'main' and row.get('head_sha') == source and
                (row.get('repository') or {}).get('full_name') == release.REPOSITORY and
                (row.get('head_repository') or {}).get('full_name') == release.REPOSITORY):
            candidates.append(run)
    return sorted(candidates, reverse=True)


def bootstrap_payloads(index):
    archives = {role: row['files']['host.tar' if role == 'host' else release.archive_name(role)]
                for role, row in index['transports'].items()}
    return index['components'], archives


def unselected_site():
    control = ROOT.parent / 'renewal'
    require(not any(os.path.lexists(control / name) for name in ('current.json', 'site-current.json')),
            'an existing or interrupted site selection prevents automatic initial intake')


def acquire_initial(source, end):
    """Select an initial protected release while the caller holds the intake lock."""
    source = hex_id(source, 40)
    require(os.getuid() == os.geteuid() == 0, 'protected initial release operator required')
    protected(ROOT, directory=True)
    unselected_site()
    recover_transfer()
    entries = staged_paths(end)
    if entries:
        require(len(entries) == 1, 'automatic initial intake found multiple staged packages')
        directory = entries[0]
        _, index, _ = retained_index(directory.name)
        require(index['kind'] == 'dev-pair-platform-release' and index['source_sha'] == source and
                index['previous_platform_sha256'] is None and not os.path.lexists(directory / RETIREMENT),
                'staged package is not the exact requested initial full release')
        verify_local_parts(directory, index, end)
        return release.readonly_json(protected(directory / 'intake.json'), 0)[1]

    source, run, identity = discover_full(source, None, end)
    unselected_site()
    return acquire(source, run, identity, None, end)


def discover_full(source, previous, end):
    """Select only protected full publications for the requested signed predecessor."""
    if source is None:
        branch = read_api('branches/main', end)
        require(branch.get('protected') is True, 'stable release discovery requires protected main')
        source = hex_id(branch['commit']['sha'], 40)
    if previous is not None:
        hex_id(previous)
    require(Path(GITHUB).is_file() and protected(TRUST).is_file(), 'protected read-only release tooling unavailable')
    intake_limit(ROOT, [META_LIMIT, 2 * CONTROL_LIMIT], ZIP_OVERHEAD)
    selected = None
    missing_assets = False
    for run in initial_runs(source, end):
        checked_run(read_api(f'actions/runs/{run}', end), source, run, False)
        inventory = read_api(f'actions/runs/{run}/artifacts?per_page=100', end)
        if type(inventory.get('total_count')) is int and inventory['total_count'] == 0 and inventory.get('artifacts') == []:
            missing_assets = True
            continue
        rows = artifacts(inventory, source, False, allow_expired=True)
        if any(row['expired'] for row in rows.values()):
            missing_assets = True
            continue
        with transfer_workspace(None) as stage:
            subject = stage / 'platform.json'
            fetch_artifact(rows, release.artifact_name('subjects', source), stage,
                           {'platform.json': (None, CONTROL_LIMIT)}, end)
            raw, index = release.readonly_json(subject, 0)
            portable_index(index, source, run)
            require(raw == canonical(index) and index['kind'] == 'dev-pair-platform-release',
                    'protected push did not publish a canonical full platform subject')
            if index['previous_platform_sha256'] != previous:
                continue
            identity = hashlib.sha256(raw).hexdigest()
            for role in (*ROLES, 'host'):
                verify_subject(subject, identity, source, run, role, end)
            payloads = bootstrap_payloads(index)
            if selected is None:
                selected = run, identity, payloads
            else:
                require(selected[2] == payloads, 'protected full publications disagree on deployed artifact identities')
    if selected is None:
        if previous is not None:
            raise InitialReleaseUnavailable('stable-full-release-selection',
                                            'no complete unexpired full publication binds the retained stable predecessor')
        if missing_assets:
            raise InitialReleaseUnavailable('initial-release-artifacts-expired',
                                            'no eligible initial full publication has a complete unexpired artifact set')
        raise InitialReleaseUnavailable('initial-full-release-selection',
                                        'no successful initial full publication exists for the exact reviewed source')
    run, identity, _ = selected
    return source, run, identity


def acquire(source, run, expected, previous, end, *, agent=False):
    hex_id(source, 40)
    hex_id(expected)
    require(type(run) is int and 0 < run < 2 ** 63 and os.getuid() == os.geteuid() == 0,
            'protected release operator and exact publisher run required')
    protected(ROOT, directory=True)
    require(Path(GITHUB).is_file(), 'protected read-only GitHub CLI unavailable')
    recover_transfer()
    require(not os.path.lexists(ROOT / expected), 'platform package already staged at its exact digest')
    entries = staged_paths(end)
    require(previous is not None or not entries, 'initial release intake requires an empty platform store')
    if previous is not None:
        hex_id(previous)
        require(previous != expected, 'platform release cannot reference itself for recovery')
    # Fetch the agent subject within its small metadata runway. The signed
    # manifest then supplies exact expansion bounds before any role download.
    if agent:
        require(previous is not None, 'agent refresh requires the previous verified platform')
        intake_limit(ROOT, [META_LIMIT, 2 * CONTROL_LIMIT], ZIP_OVERHEAD)
    else:
        intake_limit(ROOT, [release.FILE_BUDGET], ARCHIVE_LIMIT + ZIP_OVERHEAD)
    checked_run(read_api(f'actions/runs/{run}', end), source, run, agent)
    rows = artifacts(read_api(f'actions/runs/{run}/artifacts?per_page=100', end), source, agent)
    with transfer_workspace(expected) as stage:
        names = {name: (None, CONTROL_LIMIT) for name in release.SUBJECTS}
        fetch_artifact(rows, release.artifact_name('subjects', source), stage, names, end)
        raw, value = release.readonly_json(stage / 'platform.json', 0)
        require(hashlib.sha256(raw).hexdigest() == expected, 'platform subject differs from independently selected digest')
        value = portable_index(value, source, run)
        kind = 'dev-pair-agent-release' if agent else 'dev-pair-platform-release'
        require(value['kind'] == kind and (value['schema'] == 3 or value['previous_platform_sha256'] == previous),
                'protected recovery version or release kind differs')
        roles = portable_roles(kind)
        for role in roles if agent else (*roles, 'host'):
            verify_subject(stage / 'platform.json', expected, source, run, role, end)
        if previous is not None:
            prior = previous_release(previous, end)
            if not agent:
                require(prior['kind'] == 'dev-pair-platform-release' and prior['schema'] == 2,
                        'full stable publication requires a verified full predecessor')
            if agent:
                base = prior['base_platform_sha256'] or previous
                require(value['base_platform_sha256'] == base, 'agent refresh changes the retained host and DevBox base')
                if base != previous:
                    retained = previous_release(base, end)
                    require(retained['kind'] == 'dev-pair-platform-release', 'retained stable base is incomplete')
                expanded = []
                compressed = []
                for transport in value['transports'].values():
                    size = sum(item['bytes'] for item in transport['files'].values())
                    zipped = rows[transport['name']]['size_in_bytes']
                    require(zipped <= size + ZIP_OVERHEAD, 'Actions ZIP transport exceeds the approved byte bound')
                    expanded.append(size)
                    compressed.append(zipped)
                demand = sum(expanded) + max(compressed) + ZIP_OVERHEAD + 3 * CONTROL_LIMIT
                retain_for_transfer(entries, previous, base, demand, end)
        for part, transport in value['transports'].items():
            target = stage / part
            target.mkdir(mode=0o700)
            wanted = {name: (item['sha256'], item['bytes']) for name, item in transport['files'].items()}
            fetch_artifact(rows, transport['name'], target, wanted, end)
        verify_local_parts(stage, value, end)
        checked_run(read_api(f'actions/runs/{run}', end), source, run, agent)
        branch = read_api('branches/main', end)
        require(branch.get('protected') is True and branch.get('commit', {}).get('sha') == source,
                'protected main changed before release staging')
        receipt = {'schema': 2, 'platform_sha256': expected, 'source_sha': source,
                   'publisher_run': run, 'kind': value['kind']}
        release.write_json(stage / 'intake.json', receipt)
        if value['schema'] == 3:
            binding = {'schema': 1, 'platform_sha256': expected, 'base_platform_sha256': value['base_platform_sha256'],
                       'previous_platform_sha256': previous}
            site_predecessor(binding, expected, value['base_platform_sha256'])
            release.write_json(stage / 'site-predecessor.json', binding)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--platform-sha256')
    parser.add_argument('--agent-only', action='store_true')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--previous')
    mode.add_argument('--initial', action='store_true')
    args = parser.parse_args()
    automatic = args.run_id is None and args.platform_sha256 is None
    if automatic:
        if not args.initial or args.agent_only:
            parser.error('automatic discovery requires --initial and a full release')
    elif args.run_id is None or args.platform_sha256 is None:
        parser.error('--run-id and --platform-sha256 belong together')
    os.umask(0o077)
    require(os.getuid() == os.geteuid() == 0, 'protected release operator required')
    with intake_lock():
        end = time.monotonic() + CONTROL_SECONDS
        if automatic:
            result = acquire_initial(args.source, end)
        else:
            result = acquire(args.source, args.run_id, args.platform_sha256, args.previous, end, agent=args.agent_only)
    print(release.canonical(result).decode(), end='')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except InitialReleaseUnavailable as exc:
        print(f'platform intake pending ({exc.phase}): {exc}', file=sys.stderr)
        sys.exit(3)
    except (Blocked, ValueError, OSError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print('platform intake blocked: ' + str(exc)[:800], file=sys.stderr)
        sys.exit(2)
