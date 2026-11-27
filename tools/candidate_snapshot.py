"""Read a bounded Git workspace without following links or writing Git metadata."""

import base64
import hashlib
import json
import os
import posixpath
from pathlib import Path
import stat
import sys

MAX_FILES = 4096
MAX_BYTES = 16 * 1024 * 1024
MAX_PATH = 512
MARKER = 'dev-pair-source-sha256:'
SANDBOX_PLACEHOLDERS = {'.codex', '.agents', '.aws'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def revision(stat_result):
    return (stat_result.st_dev, stat_result.st_ino, stat_result.st_mode, stat_result.st_size,
            stat_result.st_mtime_ns, stat_result.st_ctime_ns, stat_result.st_nlink)


def source_path(name):
    require(type(name) is str and 0 < len(name.encode()) <= MAX_PATH and
            all(ord(char) >= 32 and ord(char) != 127 for char in name) and
            all(part and part.casefold() not in ('.', '..', '.git') for part in name.split('/')),
            'unsupported path in the authorized source tree')
    return name


def source_link(name, data):
    target = data.decode('utf-8')
    endpoint = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    require(target and not target.startswith('/') and endpoint != '..' and not endpoint.startswith('../') and
            all(part.casefold() != '.git' for part in endpoint.split('/')),
            'source symlink leaves the authorized workspace')


def scan(root, *, retain=False, sandbox=False):
    root = Path(root)
    require(root.is_absolute() and root.resolve(strict=True) == root, 'source workspace is not canonical')
    root_id = root.lstat()
    require(stat.S_ISDIR(root_id.st_mode), 'source workspace is not a directory')
    rows, manifest = [], []
    remaining = MAX_BYTES
    count = 0
    for current, directories, files, fd in os.fwalk(root, topdown=True, follow_symlinks=False):
        here = Path(current).relative_to(root)
        started = os.fstat(fd)
        require(started.st_dev == root_id.st_dev, 'source workspace crosses a filesystem')
        if here == Path('.'):
            if '.git' in directories:
                directories.remove('.git')
            require('.git' not in files, 'source workspace requires its owned Git directory')
            if sandbox:
                for name in SANDBOX_PLACEHOLDERS.intersection(directories):
                    node = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if node.st_dev != root_id.st_dev:
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            require(not os.listdir(child), 'unexpected content in a stock sandbox placeholder')
                        finally:
                            os.close(child)
                        directories.remove(name)
        for name in sorted(set(directories) | set(files)):
            count += 1
            require(count <= MAX_FILES, 'source workspace exceeds its entry limit')
            path = source_path((here / name).as_posix())
            node = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(node.st_dev == root_id.st_dev, 'source workspace crosses a filesystem')
            if stat.S_ISDIR(node.st_mode):
                continue
            if stat.S_ISLNK(node.st_mode):
                data = os.readlink(name, dir_fd=fd).encode()
                source_link(path, data)
                mode = '120000'
            else:
                require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_size <= remaining,
                        'source entry is unsupported or exceeds its byte limit')
                handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(handle, 'rb') as stream:
                    require(revision(os.fstat(stream.fileno())) == revision(node), 'source changed before capture')
                    data = stream.read(node.st_size + 1)
                    require(len(data) == node.st_size and revision(os.fstat(stream.fileno())) == revision(node),
                            'source changed during capture')
                mode = '100755' if node.st_mode & stat.S_IXUSR else '100644'
            require(revision(os.stat(name, dir_fd=fd, follow_symlinks=False)) == revision(node),
                    'source entry changed while captured')
            remaining -= len(data)
            require(remaining >= 0, 'source workspace exceeds its byte limit')
            manifest.append([path, mode, hashlib.sha256(data).hexdigest()])
            if retain:
                rows.append([path, mode, base64.b64encode(data).decode('ascii')])
        require(revision(os.fstat(fd)) == revision(started), 'source directory changed while captured')
    require(revision(root.lstat()) == revision(root_id), 'source workspace changed while captured')
    digest = hashlib.sha256(json.dumps(sorted(manifest), separators=(',', ':')).encode()).hexdigest()
    return digest, sorted(rows)


if __name__ == '__main__':
    try:
        if len(sys.argv) == 1:
            print(MARKER + scan(Path.cwd(), sandbox=True)[0])
        elif len(sys.argv) == 2:
            digest, entries = scan(Path(sys.argv[1]), retain=True)
            print(json.dumps({'sha256': digest, 'entries': entries}, separators=(',', ':')))
        else:
            raise ValueError('unknown source observation')
    except (OSError, ValueError, UnicodeError) as error:
        print('Source observation unavailable. ' + str(error), file=sys.stderr)
        raise SystemExit(2)
