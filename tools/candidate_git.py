"""Materialize an authenticated DevBox source snapshot with trusted Git custody."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import zlib

import candidate_snapshot as snapshot
import checklist_candidate as candidate
import job_protocol as p
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private

SCANNER = Path(snapshot.__file__).resolve()
SNAPSHOT_OUTPUT = 28 * 1024 * 1024
GIT_TRANSFER = 16 * 1024 * 1024
GIT_METADATA = 2 * 1024 * 1024
LOCAL_SETTINGS = (
    r'(?:core\.(?:repositoryformatversion|filemode|bare|logallrefupdates)|remote\.origin\.(?:url|fetch)|'
    r'branch\.[A-Za-z0-9/_.-]+\.(?:remote|merge)|user\.(?:name|email))'
)


def witness():
    # Use the same reviewed scanner inside the existing stock command sandbox.
    # The definition appears once even though the command observes both sides.
    payload = base64.b64encode(zlib.compress(SCANNER.read_bytes(), level=9)).decode('ascii')
    script = 'import base64,zlib;exec(zlib.decompress(base64.b64decode(' + repr(payload) + ')))'
    return ('cd /work/job && snapshot_source() { /usr/bin/python3 -IB -c ' + shlex.quote(script) +
            '; } && snapshot_source && (', ') && snapshot_source')


def workspace_at(root, job, revision, approval, end, *, transfer=False):
    root = root / 'development/workspaces' / job
    info = (root / '.git').lstat()
    p.require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022 and
              info.st_uid == candidate.pwd.getpwnam('dp-dev').pw_uid and (root / '.git').resolve(strict=True) == root / '.git',
              'materialization requires the ordinary owned Git directory')
    git = candidate.git_runner(root, 'dp-dev', end, allow_bundle=transfer)
    candidate.approved_checkout(git, root, approval, revision)
    for entry in git('config', '--local', '--no-includes', '--null', '--list', cap=8192).split(b'\0')[:-1]:
        key, separator, _ = entry.decode().partition('\n')
        p.require(separator and re.fullmatch(LOCAL_SETTINGS, key), 'unexpected local development Git setting')
    return root, git


def capture(root, git, end):
    p.require(not git('ls-files', '-z', '--others', '--ignored', '--exclude-standard', cap=GIT_METADATA),
              'ignored files are present in the source workspace; keep local build output in its declared build directory')
    raw = candidate.invoke(candidate.as_role('dp-dev', '/usr/bin/python3', '-IB', SCANNER, root),
                           end, cap=SNAPSHOT_OUTPUT)
    value = json.loads(raw)
    p.fields(value, 'sha256 entries')
    p.digest(value['sha256'])
    p.require(type(value['entries']) is list and len(value['entries']) <= snapshot.MAX_FILES,
              'unsupported source snapshot')
    entries, manifest = [], []
    total = 0
    for entry in value['entries']:
        p.require(type(entry) is list and len(entry) == 3, 'invalid captured source entry')
        name, mode, encoded = entry
        snapshot.source_path(name)
        p.require(mode in ('100644', '100755', '120000') and type(encoded) is str, 'unsupported captured source mode')
        data = base64.b64decode(encoded, validate=True)
        total += len(data)
        p.require(total <= snapshot.MAX_BYTES, 'captured source exceeds the approved byte limit')
        if mode == '120000':
            snapshot.source_link(name, data)
        entries.append((name, mode, data))
        manifest.append([name, mode, hashlib.sha256(data).hexdigest()])
    p.require([row[0] for row in entries] == sorted({row[0] for row in entries}) and
              p.identity(manifest) == value['sha256'], 'captured source manifest does not match its exact bytes')
    return value['sha256'], entries


def private_git(root, *args, end, data=None, settings=None, cap=GIT_METADATA):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0',
           **(settings or {})}
    p.require(data is None or len(data) <= GIT_METADATA, 'trusted Git metadata exceeds its limit')
    completed = subprocess.run([*candidate.GIT, '-c', 'protocol.file.allow=always', '-c', 'gc.auto=0',
                                '--git-dir=' + str(root), *map(str, args)],
                               input=data or b'', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=min(20, candidate.remaining(end)), check=False, env=env)
    p.require(completed.returncode == 0 and len(completed.stdout) <= cap,
              'trusted candidate Git operation failed or exceeded its output limit')
    return completed.stdout


def prepare_objects(scratch, entries, git, binding, end):
    base = binding['base_sha']
    bare = scratch / 'objects.git'
    private_git(bare, 'init', '--bare', '--template=', end=end)
    source = scratch / 'base.bundle'
    write_private(source, git('bundle', 'create', '-', 'HEAD', cap=GIT_TRANSFER))
    p.require(private_git(bare, 'bundle', 'list-heads', source, end=end) == (base + ' HEAD\n').encode(),
              'approved base bundle does not match the authenticated operation')
    private_git(bare, 'fetch', '--no-tags', '--no-auto-maintenance', '--no-write-fetch-head', source,
                'HEAD:refs/heads/approved-base', end=end)
    payload = scratch / 'source'
    payload.mkdir(mode=0o700)
    paths = []
    for position, (_, _, raw) in enumerate(entries):
        path = payload / str(position)
        with path.open('xb') as stream:
            stream.write(raw)
        paths.append(str(path).encode())
    hashes = private_git(bare, 'hash-object', '-w', '--no-filters', '--stdin-paths', end=end,
                         data=b'\n'.join(paths) + (b'\n' if paths else b'')).decode().splitlines()
    p.require(len(hashes) == len(entries), 'trusted Git did not record the complete source')
    for digest in hashes:
        p.digest(digest, 40)
    index = {'GIT_INDEX_FILE': str(scratch / 'index')}
    index_data = b''.join(f'{mode} {digest}\t{name}\0'.encode()
                          for (name, mode, _), digest in zip(entries, hashes))
    private_git(bare, 'read-tree', '--empty', end=end, settings=index)
    private_git(bare, 'update-index', '-z', '--index-info', end=end, data=index_data, settings=index)
    tree = private_git(bare, 'write-tree', end=end, settings=index).decode().strip()
    p.digest(tree, 40)
    original = private_git(bare, 'rev-parse', base + '^{tree}', end=end).decode().strip()
    if original == tree:
        return base, tree, None
    timestamp = int(private_git(bare, 'show', '-s', '--format=%ct', base, end=end).decode().strip())
    datetime = f'{timestamp + 1} +0000'
    identity = {'GIT_AUTHOR_NAME': 'dev-pair', 'GIT_AUTHOR_EMAIL': 'dev-pair@localhost',
                'GIT_COMMITTER_NAME': 'dev-pair', 'GIT_COMMITTER_EMAIL': 'dev-pair@localhost',
                'GIT_AUTHOR_DATE': datetime, 'GIT_COMMITTER_DATE': datetime}
    message = ('Materialize verified DevBox workspace\n\n'
               'Job: ' + binding['job_id'] + '\nOperation: ' + binding['operation'] +
               '\nSource snapshot: ' + binding['snapshot_sha256'] + '\n').encode()
    revision = private_git(bare, 'commit-tree', tree, '-p', base, end=end, data=message, settings=identity).decode().strip()
    p.digest(revision, 40)
    private_git(bare, 'update-ref', 'refs/heads/materialized', revision, end=end)
    return revision, tree, bare


def retained_bundle(store, expected):
    if expected is None:
        return None
    raw = read_private(store / 'candidate.bundle', GIT_TRANSFER)
    p.require(p.sha256(raw) == expected, 'retained candidate transfer differs from the authorized source')
    return raw


def materialize(root, job_root, approval, binding, end):
    job, base = binding['job_id'], binding['base_sha']
    store = job_root / 'candidate'
    exists = os.path.lexists(store)
    if exists:
        store = trusted_directory(store)
        receipt = p.loads(read_private(store / 'receipt.json', 8192))
        p.fields(receipt, 'binding candidate_sha tree_sha bundle_sha256 head_ref')
        p.require(receipt['binding'] == binding, 'retained materialization belongs to different tested work')
        for field in ('candidate_sha', 'tree_sha'):
            p.digest(receipt[field], 40)
        bundle = retained_bundle(store, receipt['bundle_sha256'])
    else:
        receipt = None
        bundle = None
    workspace = root / 'development/workspaces' / job
    status = candidate.git_runner(workspace, 'dp-dev', end)
    head = status('rev-parse', '--verify', 'HEAD').decode().strip()
    p.require(head == base or receipt is not None and head == receipt['candidate_sha'],
              'development HEAD changed outside the authorized candidate operation')
    workspace, git = workspace_at(root, job, head, approval, end, transfer=True)
    head_ref = git('rev-parse', '--symbolic-full-name', 'HEAD').decode().strip()
    p.require(head_ref == 'HEAD' or head_ref.startswith('refs/heads/'), 'unsupported owned development branch')
    if head == base:
        p.require(not git('diff', '--cached', '--name-only', '-z', base, cap=GIT_METADATA),
                  'development index contains separate staged work')
    elif git('diff', '--cached', '--name-only', '-z', receipt['candidate_sha'], cap=GIT_METADATA):
        p.require(not git('diff', '--cached', '--name-only', '-z', base, cap=GIT_METADATA),
                  'development index is outside the recoverable candidate states')
    observed, entries = capture(workspace, git, end)
    p.require(observed == binding['snapshot_sha256'], 'development files changed after the witnessed local test')
    if receipt is None:
        with tempfile.TemporaryDirectory(prefix='.candidate-', dir=job_root) as directory:
            scratch = Path(directory)
            publish = scratch / 'publish'
            publish.mkdir(mode=0o700)
            revision, tree, bare = prepare_objects(scratch, entries, git, binding, end)
            if bare is not None:
                transfer = publish / 'candidate.bundle'
                private_git(bare, 'bundle', 'create', transfer, 'refs/heads/materialized', '^' + base, end=end)
                with transfer.open('rb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    os.fsync(stream.fileno())
                bundle = read_private(transfer, GIT_TRANSFER)
            receipt = {'binding': binding, 'candidate_sha': revision, 'tree_sha': tree, 'head_ref': head_ref,
                       'bundle_sha256': None if bundle is None else p.sha256(bundle)}
            write_private(publish / 'receipt.json', p.canonical(receipt).encode())
            sync_directory(publish)
            publish.rename(store)
            sync_directory(job_root)
    p.require(receipt['head_ref'] == head_ref, 'owned development branch changed during materialization')
    revision = receipt['candidate_sha']
    if head == base and revision != base:
        p.require(bundle is not None, 'verified candidate transfer unavailable')
        handoff = root / 'development/conductor-inputs'
        account = candidate.pwd.getpwnam('dp-dev')
        node = handoff.lstat()
        p.require(handoff.resolve(strict=True) == handoff and stat.S_ISDIR(node.st_mode) and
                  (node.st_uid, node.st_gid) == (account.pw_uid, account.pw_gid) and stat.S_IMODE(node.st_mode) == 0o700,
                  'fixed development Git transfer is unavailable')
        with tempfile.NamedTemporaryFile(dir=handoff) as stream:
            stream.write(bundle)
            stream.flush()
            os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
            os.fsync(stream.fileno())
            p.require(git('bundle', 'list-heads', stream.name) == (revision + ' refs/heads/materialized\n').encode(),
                      'verified candidate transfer identifies another commit')
            git('fetch', '--no-tags', '--no-auto-maintenance', '--no-write-fetch-head', '--recurse-submodules=no',
                stream.name, 'refs/heads/materialized:refs/dev-pair/materialized/' + binding['operation'])
        p.require(git('rev-parse', revision + '^{tree}').decode().strip() == receipt['tree_sha'] and
                  git('rev-parse', revision + '^').decode().strip() == base,
                  'imported candidate differs from its retained tree or parent')
        p.require(capture(workspace, git, end)[0] == observed and
                  git('rev-parse', '--symbolic-full-name', 'HEAD').decode().strip() == head_ref,
                  'development files or branch changed before candidate publication')
        git('update-ref', '--no-deref', head_ref, revision, base)
    if git('diff', '--cached', '--name-only', '-z', revision, cap=GIT_METADATA):
        git('read-tree', revision)
    p.require(git('rev-parse', '--symbolic-full-name', 'HEAD').decode().strip() == head_ref and
              git('rev-parse', 'HEAD').decode().strip() == revision and
              git('rev-parse', 'HEAD^{tree}').decode().strip() == receipt['tree_sha'] and
              not git('status', '--porcelain=v1', '--untracked-files=all', cap=GIT_METADATA) and
              capture(workspace, git, end)[0] == observed,
              'materialized checkout differs from the tested candidate; source data was retained')
    return receipt
