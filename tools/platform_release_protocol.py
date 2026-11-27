"""Fixed artifact format for the protected Fedora release path."""

import hashlib
import json
import os
import re
import stat
import struct
import time

GIB = 1024 ** 3
MIB = 1024 ** 2
ARCHIVE_LIMIT = 2 * GIB
EXPANSION_LIMIT = 8 * GIB
HOST_LIMIT = 32 * MIB
CONTROL_LIMIT = 64 * 1024
BLOCK_SIZE = MIB
MAGIC = b'DEV-PAIR-PLATFORM-ARCHIVE-v1\n'
END = b'\nDEV-PAIR-PLATFORM-END-v1\n'
SPOOL_LIMIT = ARCHIVE_LIMIT + CONTROL_LIMIT + len(MAGIC) + len(END) + 4
ROLES = ('maintenance', 'development', 'devbox')
STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
COMPONENT = {'maintenance': 'maintenance-agent', 'development': 'development-agent', 'devbox': 'devbox'}


class Blocked(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def hex_id(value, size=64):
    require(type(value) is str and re.fullmatch(f'[0-9a-f]{{{size}}}', value), 'invalid release digest')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def json_bytes(data):
    def unique(rows):
        result = dict(rows)
        require(len(result) == len(rows), 'duplicate release field')
        return result
    require(len(data) <= CONTROL_LIMIT, 'release metadata exceeds its bound')
    return json.loads(data, object_pairs_hook=unique)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), 'unexpected release record shape')
    return value


def seconds(end, maximum):
    value = min(maximum, end - time.monotonic())
    require(value > 0, 'release transfer deadline exceeded')
    return value


def regular(path, maximum, owner=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    stream = os.fdopen(fd, 'rb')
    try:
        node = os.fstat(fd)
        require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and
                (owner is None or node.st_uid == owner) and not node.st_mode & 0o022 and
                0 < node.st_size <= maximum, 'release input ownership, mode or byte bound invalid')
    except BaseException:
        stream.close()
        raise
    return stream, node


def stream_exact(source, size, end, output=None):
    pending = size
    digest = hashlib.sha256()
    while pending:
        seconds(end, 3600)
        block = source.read(min(BLOCK_SIZE, pending))
        require(bool(block), 'release artifact is truncated')
        digest.update(block)
        if output is not None:
            output.write(block)
        pending -= len(block)
    return digest.hexdigest()


def file_hash(path, maximum, end, *, owner=None, output=None):
    stream, node = regular(path, maximum, owner)
    with stream:
        digest = stream_exact(stream, node.st_size, end, output)
        final = os.fstat(stream.fileno())
        require(not stream.read(1) and (final.st_size, final.st_mtime_ns, final.st_ctime_ns) ==
                (node.st_size, node.st_mtime_ns, node.st_ctime_ns), 'release input changed during capture')
        return digest, node.st_size


def image_record(value):
    fields(value, 'role source_sha context_sha256 image_id archive_sha256 archive_bytes diff_ids')
    require(value['role'] in ROLES, 'unexpected image release role')
    hex_id(value['source_sha'], 40)
    for key in ('context_sha256', 'image_id', 'archive_sha256'):
        hex_id(value[key])
    require(type(value['archive_bytes']) is int and 0 < value['archive_bytes'] <= ARCHIVE_LIMIT,
            'image archive size is outside the release budget')
    diffs = value['diff_ids']
    require(type(diffs) is list and 1 <= len(diffs) <= 128 and
            all(type(item) is str and re.fullmatch('sha256:[0-9a-f]{64}', item) for item in diffs),
            'ordered image layer identities are invalid')
    return value


def frame_record(value):
    fields(value, 'schema nonce image receipt')
    require(type(value['schema']) is int and value['schema'] == 1, 'unsupported release frame')
    hex_id(value['nonce'], 32)
    image_record(value['image'])
    require(type(value['receipt']) is dict, 'release frame lacks producer evidence')
    return value


def send_frame(output, metadata, path, end, *, owner=None):
    metadata = frame_record(metadata)
    data = canonical(metadata)
    require(len(data) <= CONTROL_LIMIT, 'release frame metadata exceeds its bound')
    output.write(MAGIC + struct.pack('!I', len(data)) + data)
    image = metadata['image']
    require(file_hash(path, ARCHIVE_LIMIT, end, owner=owner, output=output) ==
            (image['archive_sha256'], image['archive_bytes']), 'release archive changed after production')
    output.write(END)
    output.flush()


def receive_frame(path, output, target, end):
    stream, node = regular(path, SPOOL_LIMIT, os.getuid())
    with stream:
        require(stream.read(len(MAGIC)) == MAGIC, 'missing protected release frame')
        length = stream.read(4)
        require(len(length) == 4, 'truncated release frame size')
        size = struct.unpack('!I', length)[0]
        require(0 < size <= CONTROL_LIMIT, 'protected release frame metadata exceeds byte bound')
        raw = stream.read(size)
        require(len(raw) == size, 'truncated release frame metadata')
        frame = frame_record(json_bytes(raw))
        image = frame['image']
        require(raw == canonical(frame) and frame['nonce'] == target['nonce'] and
                all(image[key] == target[key] for key in ('source_sha', 'role', 'context_sha256', 'image_id')),
                'release frame differs from the exact native result')
        require(node.st_size == len(MAGIC) + 4 + size + image['archive_bytes'] + len(END),
                'release frame size mismatch')
        with output.open('xb') as archive:
            digest = stream_exact(stream, image['archive_bytes'], end, archive)
            require(digest == image['archive_sha256'] and stream.read(len(END)) == END and not stream.read(1),
                    'release archive hash or frame terminator mismatch')
            os.fsync(archive.fileno())
        current = os.fstat(stream.fileno())
        require((current.st_size, current.st_mtime_ns, current.st_ctime_ns) ==
                (node.st_size, node.st_mtime_ns, node.st_ctime_ns), 'release spool changed during transfer')
    return frame


def portable_roles(kind):
    require(kind in ('dev-pair-platform-release', 'dev-pair-agent-release'), 'unsupported portable release kind')
    return ROLES if kind == 'dev-pair-platform-release' else ROLES[:2]


def portable_index(value, source, run):
    fields(value, 'schema kind repository source_sha publisher_run standards_sha contracts '
           'previous_platform_sha256 base_platform_sha256 components transports')
    require(type(value['schema']) is int and value['schema'] == 2 and value['repository'] == 'oso-gato/dev-pair' and
            value['source_sha'] == hex_id(source, 40) and type(value['publisher_run']) is int and
            value['publisher_run'] == run and run > 0 and value['standards_sha'] == STANDARDS,
            'portable index does not bind the exact reviewed source and run')
    contracts = fields(value['contracts'], 'ledger state release_policy')
    require(all(type(flag) is int and flag == 1 for flag in contracts.values()), 'portable release contracts differ')
    roles = portable_roles(value['kind'])
    agent_only = roles == ROLES[:2]
    previous, base = value['previous_platform_sha256'], value['base_platform_sha256']
    if agent_only:
        hex_id(previous)
        hex_id(base)
    else:
        require(base is None, 'full platform release carries its own host and DevBox')
        if previous is not None:
            hex_id(previous)
    components = fields(value['components'], ' '.join(COMPONENT[role] for role in roles) + ('' if agent_only else ' host'))
    transfers = fields(value['transports'], ' '.join(roles) + ('' if agent_only else ' host'))
    if not agent_only:
        host = fields(components['host'], 'source_sha bundle_manifest_sha256')
        require(host['source_sha'] == source, 'portable host artifact source differs')
        hex_id(host['bundle_manifest_sha256'])
    for role in roles:
        names = 'source_sha context_sha256 oci_config_sha256 oci_manifest_sha256 archive_sha256 archive_bytes'
        agent = role != 'devbox'
        item = fields(components[COMPONENT[role]], names + (' codex_version codex_source_sha codex_sha256' if agent else ''))
        require(item['source_sha'] == source and type(item['archive_bytes']) is int and
                0 < item['archive_bytes'] <= ARCHIVE_LIMIT, 'portable image source or archive bound differs')
        for key in ('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256', 'archive_sha256'):
            hex_id(item[key])
        if agent:
            require(type(item['codex_version']) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', item['codex_version']),
                    'portable image stable version missing')
            hex_id(item['codex_source_sha'], 40)
            hex_id(item['codex_sha256'])
    maintenance, development = (components[COMPONENT[role]] for role in ROLES[:2])
    require(all(maintenance[key] == development[key] for key in ('codex_version', 'codex_source_sha', 'codex_sha256')),
            'portable agent pair uses different verified tooling inputs')
    for name, row in transfers.items():
        fields(row, 'name files')
        require(row['name'] == f'platform-{name}-{source}', 'portable release transport name differs')
        archive = 'host.tar' if name == 'host' else f'{name}.oci.tar'
        evidence = 'host-manifest.json' if name == 'host' else 'part.json'
        files = fields(row['files'], f'{archive} {evidence}')
        for leaf, info in files.items():
            fields(info, 'sha256 bytes')
            hex_id(info['sha256'])
            cap = ((HOST_LIMIT if name == 'host' else ARCHIVE_LIMIT) if leaf == archive else CONTROL_LIMIT)
            require(type(info['bytes']) is int and 0 < info['bytes'] <= cap, 'portable release transfer exceeds its bound')
        if name == 'host':
            require(files[evidence]['sha256'] == components['host']['bundle_manifest_sha256'],
                    'portable host bundle manifest digest differs')
        else:
            image = components[COMPONENT[name]]
            require(files[archive] == {'sha256': image['archive_sha256'], 'bytes': image['archive_bytes']},
                    'portable archive transport differs from its image identity')
    return value
