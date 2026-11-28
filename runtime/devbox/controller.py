#!/usr/bin/python3
"""Fixed, offline DevBox capability controller and shared launch contract."""

from contextlib import contextmanager
import errno
import gzip
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
import tarfile
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
OCI_METADATA_LIMIT = 256 * 1024
OCI_MIME = 'application/vnd.oci.image.'
OCI_PLATFORM_FIELDS = 'architecture os os.version os.features variant'
OCI_RUN_FIELDS = 'User ExposedPorts Env Entrypoint Cmd Volumes WorkingDir Labels StopSignal ArgsEscaped'
OCI_HISTORY_FIELDS = 'created created_by author comment empty_layer'
OUTPUT_LIMIT = 1024 * 1024
OUTER_SECONDS = 600
INNER_SECONDS = 180
CLEANUP_SECONDS = 45
GRAPHROOT = '/devbox/graph'
IMAGE_COPY_DIR = '/devbox/image-copy'
RUNROOT = '/run/dev-pair'
ARCHIVE = '/admission/development.oci.tar'
MANIFEST = '/admission/manifest.json'
PARENT_JOB = '/devbox/job'
PARENT_BUILD = PARENT_JOB + '/build'
JOB_BUILD = '/build/job'
JOB_TARGETS = {'workspaces': '/work/job', 'state': '/state', 'cache': '/cache/job'}
ROLE_READONLY = ('/etc/codex', '/run/dev-pair-turn', '/run/dev-pair-provider',
                 *(f'/state/codex/{name}' for name in ('config.toml', 'hooks.json', 'AGENTS.md', 'AGENTS.override.md',
                                                     'skills', 'plugins', 'rules', 'agents', 'shell_snapshots',
                                                     '.tmp/plugins', '.tmp/marketplaces')))
ADMISSION_ROLE = {target: f'/admission/role/{index}' for index, target in enumerate(ROLE_READONLY)}
CAP_KEYS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
OUTER_CAPS = (0, 0, 0, 0xc0, 0)
OUTER_BOUNDING = {'CAP_SETUID', 'CAP_SETGID'}
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


def archive_path(name):
    return '.' if name in ('.', './') else name.removeprefix('./')


def check_archive_headers(path, size, deadline):
    # tarfile handles extended headers internally. Reject them before it can
    # allocate their declared sizes or use them to change a member's identity.
    seen = set()
    zero = bytes(512)
    require(size % 512 == 0, 'development archive has an invalid tar length')
    with path.open('rb') as stream:
        while stream.tell() < size:
            require(time.monotonic() < deadline, 'development archive header check timed out')
            raw = stream.read(512)
            require(len(raw) == 512, 'development archive header is truncated')
            if raw == zero:
                require(stream.read(512) == zero, 'development archive tar terminator is missing')
                while piece := stream.read(1024 * 1024):
                    require(time.monotonic() < deadline, 'development archive trailer check timed out')
                    require(not any(piece), 'development archive contains nonzero trailing data')
                return
            member = tarfile.TarInfo.frombuf(raw, 'utf-8', 'strict')
            name = archive_path(member.name)
            require(name not in seen and len(seen) < 135, 'development archive has duplicate or excessive entries')
            seen.add(name)
            if name in ('.', 'blobs', 'blobs/sha256'):
                require(member.type == tarfile.DIRTYPE and member.size == 0, 'invalid development archive directory')
            else:
                require((name in ('index.json', 'oci-layout') or re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', name))
                        and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and member.size > 0,
                        'unsupported development archive member or header')
            offset = stream.tell() + ((member.size + 511) // 512) * 512
            require(offset <= size, 'development archive member is truncated')
            stream.seek(offset)
    raise Blocked('development archive tar terminator is missing')


def hash_layer(stream, maximum, deadline):
    digest = hashlib.sha256()
    size = 0
    while True:
        require(time.monotonic() < deadline, 'development archive layer check timed out')
        data = stream.read(min(maximum - size + 1, 1024 * 1024))
        if not data:
            return 'sha256:' + digest.hexdigest(), size
        size += len(data)
        require(size <= maximum, 'development archive expanded layer budget exceeded')
        digest.update(data)


def archive_fields(value, kind, required, optional=''):
    # Go's JSON struct decoder also matches field names case-insensitively.
    # Permit only the canonical spelling of structural keys before import.
    needed = set(required.split())
    require(type(value) is dict and needed <= value.keys() <= needed.union(optional.split()),
            f'invalid development OCI {kind} structural keys')


def check_archive_image(path, release, storage_limit, deadline):
    check_archive_headers(path, release['archive_bytes'], deadline)
    with tarfile.open(path, 'r:') as archive:
        members = {archive_path(member.name): member for member in archive if member.isreg()}
        blobs = {f'sha256:{name.rsplit("/", 1)[-1]}': member
                 for name, member in members.items() if name.startswith('blobs/sha256/')}
        used = set()

        def descriptor(value, media_types):
            archive_fields(value, 'descriptor', 'digest size mediaType', 'annotations platform')
            if 'platform' in value:
                archive_fields(value['platform'], 'descriptor platform', '', OCI_PLATFORM_FIELDS)
            digest = value['digest']
            require(isinstance(digest, str) and digest in blobs and type(value['size']) is int
                    and value['size'] == blobs[digest].size and value['mediaType'] in media_types,
                    'development archive descriptor does not match an OCI blob')
            used.add(digest)
            return digest, blobs[digest]

        def metadata(member, digest=None):
            require(member is not None and member.size <= OCI_METADATA_LIMIT,
                    'missing or oversized development archive metadata')
            with archive.extractfile(member) as stream:
                data = stream.read(OCI_METADATA_LIMIT + 1)
            require(len(data) == member.size, 'development archive metadata is truncated')
            if digest is not None:
                require('sha256:' + hashlib.sha256(data).hexdigest() == digest,
                        'development archive metadata digest mismatch')
            value = json_data(data)
            require(type(value) is dict, 'invalid development archive metadata')
            return value

        require(metadata(members.get('oci-layout')) == {'imageLayoutVersion': '1.0.0'},
                'unsupported development OCI layout')
        index = metadata(members.get('index.json'))
        archive_fields(index, 'index', 'schemaVersion manifests', 'mediaType annotations')
        index_media = OCI_MIME + 'index.v1+json'
        manifests = index.get('manifests')
        require(type(index['schemaVersion']) is int and index['schemaVersion'] == 2
                and index.get('mediaType', index_media) == index_media
                and type(manifests) is list and len(manifests) == 1,
                'development OCI archive must select one image')
        manifest_media = OCI_MIME + 'manifest.v1+json'
        manifest_blob = descriptor(manifests[0], (manifest_media,))
        image = metadata(manifest_blob[1], manifest_blob[0])
        archive_fields(image, 'manifest', 'schemaVersion config layers', 'mediaType annotations')
        require(type(image['schemaVersion']) is int and image['schemaVersion'] == 2
                and image.get('mediaType', manifest_media) == manifest_media,
                'unsupported development OCI image manifest')
        config_digest, config_member = descriptor(image.get('config'), (OCI_MIME + 'config.v1+json',))
        require(config_digest == 'sha256:' + release['image_id'], 'development archive config identity mismatch')
        config = metadata(config_member, config_digest)
        archive_fields(config, 'image config', 'architecture os rootfs', 'config history created author os.version os.features variant')
        archive_fields(config['rootfs'], 'rootfs', 'type diff_ids')
        if 'config' in config:
            archive_fields(config['config'], 'runtime config', '', OCI_RUN_FIELDS)
        if 'history' in config:
            require(type(config['history']) is list, 'invalid development OCI history')
            for entry in config['history']:
                archive_fields(entry, 'history entry', '', OCI_HISTORY_FIELDS)
        require((config['os'], config['architecture']) == ('linux', 'amd64')
                and config['rootfs'] == {'type': 'layers', 'diff_ids': release['diff_ids']},
                'development archive config platform or ordered layers mismatch')
        layers = image.get('layers')
        require(type(layers) is list and len(layers) == len(release['diff_ids']),
                'development archive layer count mismatch')
        plain = OCI_MIME + 'layer.v1.tar'
        compressed = plain + '+gzip'
        remaining = storage_limit
        for layer, expected in zip(layers, release['diff_ids']):
            digest, member = descriptor(layer, (plain, compressed))
            with archive.extractfile(member) as stream:
                actual, size = hash_layer(stream, member.size, deadline)
            require((actual, size) == (digest, member.size), 'development archive layer blob digest mismatch')
            if layer['mediaType'] == compressed:
                with archive.extractfile(member) as stream, gzip.GzipFile(fileobj=stream) as expanded:
                    actual, size = hash_layer(expanded, remaining, deadline)
            require(actual == expected, 'development archive ordered layer DiffID mismatch')
            require(0 < size <= remaining, 'development archive expanded layer budget exceeded')
            remaining -= size
        require(set(blobs) == used, 'development archive contains unselected blobs')


def load_development_archive(engine, manifest, path, *, reuse=False):
    release = manifest['inner']
    expected = (release['archive_sha256'], release['archive_bytes'])
    deadline = engine.deadline
    require(file_hash(path, release['archive_bytes'], deadline)[:2] == expected,
            'development OCI archive digest or byte count mismatch')
    if reuse:
        status, _ = engine('check exact development image cache', 'image', 'exists', release['image_id'], allowed=(0, 1))
        if status == 0:
            return immutable_image(engine, manifest, 'inner', role_turn=True)
    try:
        check_archive_image(path, release, manifest['storage_bytes'], deadline)
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Blocked(f'invalid development OCI archive: {error}') from error
    engine('load development OCI archive', 'load', '--input', str(path), seconds=250)
    require(file_hash(path, release['archive_bytes'], deadline)[:2] == expected,
            'development OCI archive changed during import')
    if reuse:
        return immutable_image(engine, manifest, 'inner', role_turn=True)
    immutable_image(engine, manifest, 'inner')


def label_level(manifest, side):
    return 's0:' + ','.join(f'c{category}' for category in manifest['categories'][side])


def process_label(manifest, side):
    label_type = 'container_engine_t' if side == 'outer' else 'container_t'
    return f'system_u:system_r:{label_type}:{label_level(manifest, side)}'


def file_label(manifest, side):
    return 'system_u:object_r:container_file_t:' + label_level(manifest, side)


def selinux_label(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    value = value.removesuffix('\x00')
    if '\x00' in value:
        return None
    parts = value.split(':', 4)
    if len(parts) != 5 or any(not part for part in parts[:3]) or parts[3] != 's0':
        return None
    categories = set()
    for token in parts[4].split(','):
        match = re.fullmatch(r'c(0|[1-9][0-9]{0,3})(?:\.c(0|[1-9][0-9]{0,3}))?', token)
        if match is None:
            return None
        first = int(match[1])
        last = int(match[2] or match[1])
        group = range(first, last + 1)
        if last > 1023 or first > last or categories.intersection(group):
            return None
        categories.update(group)
    return (*parts[:3], frozenset(categories))


def same_label(actual, expected):
    parsed = selinux_label(actual)
    return parsed is not None and parsed == selinux_label(expected)


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


def immutable_image(engine, manifest, side, *, role_turn=False):
    release = manifest[side]
    row = engine.inspect('image', release['image_id'])
    require(engine_id(row.get('Id')) == release['image_id'] and row.get('Os') == 'linux'
            and row.get('Architecture') == 'amd64', 'local immutable image/config identity mismatch')
    expected = {'dev-pair.role': 'devbox' if side == 'outer' else 'development',
                'dev-pair.standards': STANDARDS, 'dev-pair.distrobox': DISTROBOX,
                'org.opencontainers.image.revision': release['source_sha']}
    if side == 'inner':
        expected.update({'dev-pair.context': release['context_sha256'],
                         'dev-pair.inputs': release['inputs_sha256']})
        if not role_turn:
            expected['dev-pair.codex.version'] = CODEX_VERSION
        require(row['RootFS']['Layers'] == release['diff_ids'], 'loaded image layer identities mismatch')
    labels = row.get('Labels') or row.get('Config', {}).get('Labels') or {}
    require(all(labels.get(key) == value for key, value in expected.items()),
            f'{side} image role or provenance mismatch')
    if role_turn:
        version = labels.get('dev-pair.codex.version')
        require(type(version) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version),
                'exact image lacks a stable Codex version')
        return version


def bind(source, target, rw, *, executable=False):
    access = 'rw' if rw else 'ro'
    safety = '' if executable else ',noexec'
    return f'--volume={source}:{target}:{access},nosuid,nodev,rprivate{safety}'


def container_args(name, owner, manifest, side, hooks):
    outer = side == 'outer'
    args = [f'--name={name}', f'--label=dev-pair.devbox-owner={owner}', '--pull=never', '--restart=no',
            f'--timeout={OUTER_SECONDS if outer else INNER_SECONDS}', '--read-only', '--read-only-tmpfs=false',
            '--user=1000:1000', '--userns=keep-id:uid=1000,gid=1000', '--network=none', '--pid=private',
            '--ipc=private', '--uts=private', '--log-driver=k8s-file',
            '--log-opt=max-size=1mb', '--no-hosts', '--no-hostname',
            '--image-volume=ignore', '--http-proxy=false', '--sdnotify=ignore', '--systemd=false',
            f'--hooks-dir={hooks}', '--workdir=/', '--unsetenv-all',
            f'--security-opt=label=level:{label_level(manifest, side)}']
    for path, size in (('/run', '64m' if outer else '16m'), ('/tmp', '64m' if outer else '16m')):
        args.append(f'--tmpfs={path}:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=0700,notmpcopyup,size={size}')
    if outer:
        # The host-only default capability set becomes bounding only for UID 1000.
        # Podman propagates explicit cap-add entries into the E/P/I/A sets as well.
        return args + ['--security-opt=label=nested', '--security-opt=label=type:container_engine_t',
                       '--cgroupns=private', '--memory=2g', '--memory-swap=2g', '--pids-limit=512',
                       '--cpus=1', '--rm']
    return args + ['--cap-drop=ALL', '--security-opt=no-new-privileges', '--security-opt=label=type:container_t',
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
    require(row.get('ResolvConfPath', '') == '' and all(host.get(key, []) == [] for key in ('Dns', 'DnsOptions', 'DnsSearch')),
            f'{side} offline runtime has engine-managed resolver configuration')
    require(same_label(row.get('ProcessLabel'), process_label(manifest, side))
            and same_label(row.get('MountLabel'), file_label(manifest, side)), f'{side} SELinux policy mismatch')
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
        require(not host.get('CapAdd') and row['EffectiveCaps'] in (None, [])
                and set(row.get('BoundingCaps') or []) == OUTER_BOUNDING,
                'parent inspected bounding-only capability policy mismatch')
        require(host.get('CgroupMode') == 'private' and host.get('Memory') == 2 * GIB
                and host.get('PidsLimit') == 512 and host.get('NanoCpus') == 1000000000,
                'parent inspected aggregate cgroup policy mismatch')
    else:
        require(host.get('Cgroups') == 'disabled' and row['EffectiveCaps'] in (None, [])
                and row['BoundingCaps'] in (None, []) and not host.get('CapAdd')
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
    actual = (root / 'attr/current').read_text().removesuffix('\n')
    require(same_label(actual, label), 'effective SELinux process label mismatch')
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
    require(not {'/etc/hostname', '/etc/hosts', '/etc/resolv.conf'}.intersection(rows),
            'unexpected runtime network configuration mount')
    if '/sys/fs/cgroup' in rows:
        require('ro' in find('/sys/fs/cgroup')[0], 'effective cgroup filesystem is writable')
    for target in ('/run', '/tmp'):
        options, kind = find(target)
        require(kind == 'tmpfs' and {'rw', 'nosuid', 'nodev', 'noexec'} <= options,
                f'unsafe effective temporary mount at {target}')
    for target, is_writable in binds.items():
        options, _ = find(target)
        expected = {'nosuid', 'nodev', 'rw' if is_writable else 'ro'}
        if target not in (GRAPHROOT, PARENT_BUILD, JOB_BUILD):
            expected.add('noexec')
        require(expected <= options, f'effective mount flags differ at {target}')


def offline_interfaces(proc):
    interfaces = [line.partition(':')[0].strip() for line in (proc / 'net/dev').read_text().splitlines()[2:]]
    require(interfaces == ['lo'], 'offline runtime must have only loopback')


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
                'STORAGE_DRIVER': 'vfs', 'TMPDIR': IMAGE_COPY_DIR})
    return env


def check_engine_info(info):
    security, store = info['host']['security'], info['store']
    require(security.get('rootless') is True and security.get('selinuxEnabled') is True
            and store['graphDriverName'] == 'vfs' and store['graphRoot'] == GRAPHROOT
            and store['runRoot'] == RUNROOT, 'nested rootless VFS/SELinux policy mismatch')
    require(store.get('imageCopyTmpDir') == IMAGE_COPY_DIR, 'nested image import temporary directory mismatch')


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


def fixed_entry(engine, identity, operation, check, started, job=None):
    require(operation in ('probe', 'version') and job is None or operation == 'job-turn' and job is not None,
            'unsupported Distrobox capability operation')
    def live():
        row = engine.inspect('container', identity)
        check(row)
        require(row['State'].get('Running') is True and row['State'].get('StartedAt') == started,
                'entry requires the current running identity')
    live()
    try:
        _, output = bounded([str(BASE / 'distrobox-enter'), '--name', identity, '--no-tty', '--no-workdir',
                             '--clean-path', '--', '/usr/bin/python3', '-I', GPTBOX + '/runtime.py',
                             'entry', operation, *(job or ())], engine.deadline, env=engine.env,
                            seconds=150 if job else 30)
    except Blocked as error:
        raise Blocked(f'pinned Distrobox {operation}: {error}') from error
    live()
    return output


def controller(expected, owner, seconds, operation=None, request_sha=None, *, probe_version=None):
    end = time.monotonic() + seconds
    manifest = read_manifest(Path(MANIFEST), expected, end)
    if operation is not None:
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', operation) and hex_id(request_sha)
                and file_hash(Path(ADMISSION_ROLE['/run/dev-pair-turn']) / 'request.json', 4096, end)[0] == request_sha,
                'protected development operation identity mismatch')
    job = (manifest['job'], operation, request_sha) if operation else None
    require(os.getuid() == os.getgid() == 1000 and os.getgroups() in ([], [1000]), 'controller user mismatch')
    self_proc = Path('/proc/self')
    parent = proc_snapshot(self_proc, OUTER_CAPS, 0, process_label(manifest, 'outer'), 1000, 1000)
    offline_interfaces(self_proc)
    observed_mounts(self_proc, {GRAPHROOT: True, IMAGE_COPY_DIR: True, ARCHIVE: False, MANIFEST: False,
                               **{f'{PARENT_JOB}/{key}': True for key in JOB_TARGETS},
                               **({PARENT_BUILD: True, **dict.fromkeys(ADMISSION_ROLE.values(), False)} if job else {})})
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
    check_engine_info(json_data(info))
    _, mappings = engine('nested UID/GID mapping', 'unshare', '/usr/bin/cat', '/proc/self/uid_map', '/proc/self/gid_map')
    lines = mappings.decode('ascii').splitlines()
    require(len(lines) == 6, 'unexpected engine mapping ranks')
    for section in (lines[:3], lines[3:]):
        # Podman unshare maps its caller to namespace root before creating the keep-id child.
        triples = [tuple(int(number) for number in line.split()) for line in section]
        require(sorted(triples) == [(0, 1000, 1), (1, 1, 999), (1000, 1001, 64536)],
                'rootless engine user namespace map mismatch')
    release = manifest['inner']
    if job or probe_version:
        codex_version = load_development_archive(engine, manifest, Path(ARCHIVE), reuse=True)
        if probe_version:
            require(codex_version == probe_version, 'selected probe version differs from the immutable development image')
    else:
        load_development_archive(engine, manifest, Path(ARCHIVE))
    name = 'dp-nested-' + owner[:24]
    target = {dest: (f'{PARENT_JOB}/{key}', True) for key, dest in JOB_TARGETS.items()}
    if job:
        target.update({JOB_BUILD: (PARENT_BUILD, True), **{dest: (source, False) for dest, source in ADMISSION_ROLE.items()}})
    mounts = [bind(src, dest, rw, executable=dest == JOB_BUILD) for dest, (src, rw) in target.items()]
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
        for _ in range(1 if job else 2):
            engine('start nested development gptbox', 'start', identity)
            state = ready(engine, identity, check, previous)['State']
            previous = state['StartedAt']
            pid = state.get('Pid')
            require(type(pid) is int and pid > 1, 'inner PID is unavailable to parent')
            proc = Path('/proc') / str(pid)
            child = proc_snapshot(proc, (0, 0, 0, 0, 0), 1, process_label(manifest, 'inner'), 1000, 1000)
            offline_interfaces(proc)
            observed_mounts(proc, {dest: writable for dest, (_, writable) in target.items()})
            require(child['cgroup'] == parent['cgroup']
                    and all(child['namespaces'][key] != parent['namespaces'][key] for key in NS_NAMES),
                    'inner process does not have private namespaces inside the outer cgroup')
            for kind in ('uid', 'gid'):
                child[kind + '_map'] = ids((proc / (kind + '_map')).read_text(), [(1, 999), (1001, 64536)], 1000)
            check_inner_inputs(engine, identity, release)
            if job:
                version = fixed_entry(engine, identity, 'version', check, previous).strip()
                require(version == f'codex-cli {codex_version}'.encode(), 'actual role binary version differs from exact image')
                require(end - time.monotonic() > 155, 'insufficient time for the role turn and owned cleanup')
                turn = json_data(fixed_entry(engine, identity, 'job-turn', check, previous, job))
                require(turn.get('schema') == 2 and turn.get('operation') == operation and turn.get('job') == manifest['job']
                        and turn.get('role') == 'development' and turn.get('request_sha256') == request_sha,
                        'development turn receipt identity mismatch')
                break
            probe = json_data(fixed_entry(engine, identity, 'probe', check, previous))
            require(probe.get('boundary_probe') == 'passed' and probe.get('uid') == 1000
                    and same_label(probe.get('selinux_label'), child['label']), 'Distrobox inner protected-write probe failed')
            version = fixed_entry(engine, identity, 'version', check, previous).strip()
            require(version == f'codex-cli {probe_version or CODEX_VERSION}'.encode(), 'Distrobox Codex version mismatch')
            engine('stop nested development gptbox', 'stop', '--time=5', identity, seconds=15)
            cycles.append({'started_at': previous, 'proc': child, 'probe': probe, 'version': version.decode('ascii')})
    if job:
        return {'kind': 'dev-pair-devbox-job-v1', 'manifest_sha256': expected, 'owner': owner,
                'inner_container_id': identity, 'inner_image_id': release['image_id'], 'child': child,
                'started_at': previous, 'inner_removed': True, 'codex_version': codex_version, 'turn': turn}
    return {'kind': 'dev-pair-devbox-probe-v1', 'manifest_sha256': expected, 'owner': owner,
            'inner_container_id': identity, 'inner_image_id': release['image_id'], 'cycles': cycles,
            'inner_removed': True, 'job_admission': False}


def interrupt(signum, _frame):
    raise Blocked(f'interrupted by signal {signum}')


if __name__ == '__main__':
    try:
        signal.signal(signal.SIGTERM, interrupt)
        signal.signal(signal.SIGINT, interrupt)
        require(len(sys.argv) in (4, 6), 'expected manifest digest, ownership token, budget and paired operation inputs')
        budget = int(sys.argv[3])
        require(0 < budget < OUTER_SECONDS - CLEANUP_SECONDS, 'invalid nested time budget')
        arguments = sys.argv[4:]
        if arguments[:1] == ['--probe-version']:
            require(len(arguments) == 2 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', arguments[1]),
                    'invalid approved offline probe version')
            result = controller(hex_id(sys.argv[1]), hex_id(sys.argv[2]), budget, probe_version=arguments[1])
        else:
            result = controller(hex_id(sys.argv[1]), hex_id(sys.argv[2]), budget, *arguments)
        print(json.dumps(result, sort_keys=True))
    except (Blocked, OSError, KeyError, ValueError, TypeError, IndexError, subprocess.TimeoutExpired) as error:
        print(f'DevBox controller blocked: {error}', file=sys.stderr)
        sys.exit(2)
