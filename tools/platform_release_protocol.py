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
