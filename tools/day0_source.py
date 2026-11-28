"""Select the production commit described by a reviewed first-release handoff."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from ledger_recovery import sync_directory
from release_setup import decode, fingerprint, private_bytes
from release_trust import REPOSITORY, protect, require


REMOTE = 'https://github.com/' + REPOSITORY + '.git'
SOURCE_NAME = 'production-source-authority.json'
MAX_TREE = 256 * 1024
MAX_SOURCE = 64 * 1024 * 1024
MAX_LEAF = 4 * 1024 * 1024
AT_FDCWD = -100
RENAME_NOREPLACE = 1
GIT = '/usr/bin/git'
GIT_ENV = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
GIT_ARGS = (GIT, '--no-optional-locks', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
            '-c', 'core.fsmonitor=false', '-c', 'core.fileMode=true', '-c', 'core.fsync=all',
            '-c', 'fetch.fsckObjects=true', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
            '-c', 'http.followRedirects=false')


def git(repo, *args, timeout=15):
    location = ('-C', str(repo)) if repo is not None else ()
    argv = (*GIT_ARGS, *location, *args)
    result = subprocess.run(argv, env=GIT_ENV, cwd='/', stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_TREE, 'The exact protected source is unavailable from Git.')
    return result.stdout


def handoff(path, machine, digest=None):
    raw = private_bytes(path)
    if digest is not None:
        require(fingerprint(raw) == digest, 'Release handoff differs from the independently received fingerprint.')
    identity = json.loads(raw)
    require(type(identity) is dict, 'An independently verified first-release handoff is required.')
    return raw, decode(raw, identity.get('source_sha'), machine)


def reviewed_seed(grant, revision):
    require(revision in (grant['review']['review_head'], grant['source_sha']),
            'The delivered checkout is neither the independently reviewed head nor its approved merge.')


def verified_tree(repo, source, tree):
    protect(repo / '.git', directory=True)
    require(git(repo, 'rev-parse', '--verify', 'HEAD').strip() == source.encode() and
            git(repo, 'rev-parse', '--verify', 'HEAD^{tree}').strip() == tree.encode(),
            'The source commit or complete Git tree differs from the independent review.')
    require(not git(repo, 'status', '--porcelain=v1', '--untracked-files=all', '--ignored'),
            'The protected source checkout has local changes or untracked files.')
    entries = git(repo, 'ls-tree', '-r', '-z', 'HEAD')
    require(bool(entries) and entries.endswith(b'\0'), 'The complete reviewed tree is unavailable.')
    total = 0
    for entry in entries[:-1].split(b'\0'):
        match = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40})\t([A-Za-z0-9_.+@/-]+)', entry)
        require(match is not None, 'A reviewed source member has an unsupported path or mode.')
        mode, identity, member = match.groups()
        path = protect(repo / member.decode('ascii'))
        with path.open('rb') as stream:
            node = os.fstat(stream.fileno())
            total += node.st_size
            require(node.st_size <= MAX_LEAF and total <= MAX_SOURCE and
                    bool(node.st_mode & stat.S_IXUSR) == (mode == b'100755'),
                    'A reviewed source member differs in size or executable mode.')
            raw = stream.read(node.st_size + 1)
            blob = b'blob ' + str(node.st_size).encode() + b'\0' + raw
            require(len(raw) == node.st_size and hashlib.sha1(blob, usedforsecurity=False).hexdigest().encode() == identity,
                    'A protected source file differs from its reviewed Git blob.')
    return entries


def confirm_main(source):
    exact = (source + '\trefs/heads/main\n').encode()
    require(git(None, 'ls-remote', '--exit-code', '--refs', REMOTE, 'refs/heads/main', timeout=45) == exact,
            'Protected main has moved from the independently approved source. Obtain an updated independent release handoff.')


def production_checkout(kits, source):
    return kits / ('dev-pair-day0-' + source) / 'dev-pair'


def confirm_checkout(kits, grant, seed_tree=None):
    source = grant['source_sha']
    checkout = production_checkout(kits, source)
    with protect(checkout.parent / 'SOURCE').open('rb') as marker:
        require(marker.read(42) == (source + '\n').encode(), 'The protected production checkout source marker differs.')
    tree = verified_tree(checkout, source, grant['review']['source_tree'])
    require(seed_tree is None or tree == seed_tree, 'The production file identities and modes differ from the delivered reviewed tree.')
    return checkout


def publish_checkout(staged, destination):
    # Both names are under the same protected root directory and owner lease.
    # Preserve even an empty pre-existing administrator directory.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    if rename(AT_FDCWD, os.fsencode(staged), AT_FDCWD, os.fsencode(destination), RENAME_NOREPLACE) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), destination)
    sync_directory(destination.parent)


def stage_checkout(kits, grant, seed_tree):
    source = grant['source_sha']
    parent = production_checkout(kits, source).parent
    protect(kits, directory=True)
    if not os.path.lexists(parent):
        with tempfile.TemporaryDirectory(prefix='.dev-pair-source-', dir=kits) as private:
            staged = Path(private) / parent.name
            staged.mkdir(mode=0o700)
            checkout = staged / 'dev-pair'
            git(None, 'init', '-q', '--template=', checkout)
            git(checkout, 'fetch', '--depth=1', '--no-tags', '--no-recurse-submodules', '--', REMOTE, source, timeout=180)
            git(checkout, 'checkout', '--detach', '-q', source)
            require(verified_tree(checkout, source, grant['review']['source_tree']) == seed_tree,
                    'Production file identities and modes differ from the delivered reviewed tree.')
            (staged / 'SOURCE').write_text(source + '\n', encoding='ascii')
            for directory, _, names in os.walk(staged, topdown=False):
                for name in names:
                    with protect(Path(directory) / name).open('rb') as stream:
                        os.fsync(stream.fileno())
                sync_directory(Path(directory))
            publish_checkout(staged, parent)
    return confirm_checkout(kits, grant, seed_tree)
