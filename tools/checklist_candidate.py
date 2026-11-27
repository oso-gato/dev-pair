#!/usr/bin/env python3
"""Build and admit one authorized checklist Git object through the fixed OCI recipe."""
import hashlib
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

import host_handoff as h
import job_protocol as p
from ledger_recovery import sync_directory, trusted_directory, write_private

ROOT = Path('/var/lib/dev-pair')
KIT = Path('/usr/libexec/dev-pair')
RECEIPTS = ROOT / 'checklist-receipts'
BASE = Path('/etc/dev-pair/checklist/build-base.json')
RECIPE = Path(__file__).resolve().parent.parent / 'examples/checklist/Containerfile'
APP = 'examples/checklist/checklist.py'
MAX_SOURCE = 64 * 1024
MAX_ARCHIVE = 320 * 1024 * 1024
MAX_BUNDLE = 16 * 1024 * 1024
RUNUSER = '/usr/bin/runuser'
GIT = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
       '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never']
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8'}


def remaining(end):
    return h.time_left(end)


def invoke(argv, end, *, cap=p.MAX_MESSAGE, data=None):
    """Bound command output independently of pipe reader and child lifetime."""
    # The only input is a bounded trusted-controller JSON document or prompt.
    with tempfile.TemporaryFile() as incoming, selectors.DefaultSelector() as ready:
        if data is not None:
            p.require(len(data) <= p.MAX_MESSAGE, 'fixed command input is too large')
            incoming.write(data)
            incoming.seek(0)
        remaining(end)
        with subprocess.Popen(argv, stdin=incoming, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=ENV, start_new_session=True) as process:
            output = bytearray()
            try:
                ready.register(process.stdout, selectors.EVENT_READ)
                while ready.select(remaining(end)):
                    chunk = os.read(process.stdout.fileno(), min(8192, cap + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    p.require(len(output) <= cap, 'fixed command output exceeds its limit')
                else:
                    raise TimeoutError('fixed command output deadline expired')
                code = process.wait(timeout=remaining(end))
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)
                raise
    p.require(code == 0, 'protected fixed command failed')
    return bytes(output)


def protected_file(path, limit=p.MAX_MESSAGE):
    path = h.host_runtime().protected(path, file=True)
    return p.read_data(path, limit)


def envelope_path(job, source):
    p.token(job)
    p.digest(source, 40)
    return RECEIPTS / (job + '--' + source + '.json')


def checkout_approval(job, repository, agreement_sha):
    p.require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', job), 'invalid role job identity')
    p.require(re.fullmatch(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', repository) and
              all(part not in ('.', '..') for part in repository.split('/')), 'invalid repository identity')
    p.digest(agreement_sha)
    raw = protected_file(ROOT / 'repository-approvals' / (job + '.json'), 4096)
    row = p.loads(raw)
    p.fields(row, 'schema job repository agreement_sha256 acquired_commit acquired_tree standards_sha '
                  'startup_project_revision startup_sha256')
    p.number(row['schema'], 1, 1)
    p.require((row['job'], row['repository'], row['agreement_sha256'], row['standards_sha']) ==
              (job, repository, agreement_sha, p.STANDARDS), 'role approval does not authorize the agreed repository')
    for key in ('acquired_commit', 'acquired_tree', 'startup_project_revision'):
        p.digest(row[key], 40)
    p.digest(row['startup_sha256'])
    return raw, row


def as_role(role, *argv, environment=None):
    account = pwd.getpwnam(role)
    values = {**ENV, 'HOME': account.pw_dir, 'USER': role, 'LOGNAME': role, **(environment or {})}
    return [RUNUSER, '--user', role, '--', '/usr/bin/env', '-i',
            *(key + '=' + value for key, value in values.items()), *map(str, argv)]


def git_runner(workspace, role, end, *, allow_bundle=False):
    p.require(workspace.resolve(strict=True) == workspace and workspace.is_dir(), 'unsafe job checkout path')
    git = GIT + (['-c', 'protocol.file.allow=always'] if allow_bundle else [])
    return lambda *args, cap=1024: invoke(as_role(role, *git, '-C', workspace, *args,
        environment={'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                     'GIT_NO_LAZY_FETCH': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0'}),
        min(end, time.monotonic() + 10), cap=cap)


def approved_source(git, workspace, approval, revision):
    p.digest(revision, 40)
    repository, base = approval['repository'], approval['acquired_commit']
    origin = git('config', '--local', '--no-includes', '--get-all', 'remote.origin.url').decode().removesuffix('\n')
    p.require(origin in (f'https://github.com/{repository}', f'https://github.com/{repository}.git',
                         f'git@github.com:{repository}.git'), 'checkout origin does not identify the authorized repository')
    p.require(git('rev-parse', '--show-toplevel').decode().removesuffix('\n') == str(workspace) and
              git('rev-parse', '--verify', 'HEAD').decode().strip() == revision and
              git('rev-parse', '--verify', base + '^{tree}').decode().strip() == approval['acquired_tree'],
              'checkout source or acquired tree changed')
    git('merge-base', '--is-ancestor', base, revision)
    record = git('ls-tree', '--full-tree', '-z', revision, '--', APP)
    match = re.fullmatch(rb'100(?:644|755) blob ([0-9a-f]{40})\texamples/checklist/checklist\.py\0', record)
    p.require(match, 'authorized commit must contain the fixed checklist source as one regular blob')
    blob = git('cat-file', 'blob', match[1].decode(), cap=MAX_SOURCE)
    calculated = hashlib.sha1(b'blob ' + str(len(blob)).encode() + b'\0' + blob).hexdigest()
    p.require(blob and calculated == match[1].decode(), 'checklist Git object failed its content verification')
    blob.decode('utf-8')
    return blob


def mirror_maintenance(job, approval, revision, end):
    maintenance = ROOT / 'maintenance/workspaces' / job
    development = ROOT / 'development/workspaces' / job
    source = git_runner(development, 'dp-dev', end)
    target = git_runner(maintenance, 'dp-maint', end, allow_bundle=True)
    base = approval['acquired_commit']
    head = target('rev-parse', '--verify', 'HEAD').decode().strip()
    if head == revision:
        approved_source(target, maintenance, approval, revision)
        return
    approved_source(target, maintenance, approval, base)
    # Checkout must not evaluate repository-provided commands or overwrite maintenance work.
    allowed = r'(?:core\.(?:repositoryformatversion|filemode|bare|logallrefupdates)|remote\.origin\.(?:url|fetch)|' \
              r'branch\.[A-Za-z0-9/_.-]+\.(?:remote|merge)|user\.(?:name|email))'
    for entry in target('config', '--local', '--no-includes', '--null', '--list', cap=8192).split(b'\0')[:-1]:
        key, separator, _ = entry.decode().partition('\n')
        p.require(separator and re.fullmatch(allowed, key), 'maintenance checkout has an unapproved local Git setting')
    p.require(not target('status', '--porcelain=v1', '--untracked-files=all'),
              'maintenance checkout contains work that must be retained')
    contents = source('bundle', 'create', '-', 'HEAD', '^' + base, cap=MAX_BUNDLE)
    holder = ROOT / 'maintenance/conductor-inputs'
    actor = pwd.getpwnam('dp-maint')
    info = holder.lstat()
    p.require(holder.resolve(strict=True) == holder and stat.S_ISDIR(info.st_mode) and
              info.st_uid == actor.pw_uid and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe maintenance transfer leaf')
    with tempfile.NamedTemporaryFile(dir=holder) as bundle:
        os.fchown(bundle.fileno(), actor.pw_uid, actor.pw_gid)
        bundle.write(contents)
        bundle.flush()
        os.fsync(bundle.fileno())
        heads = target('bundle', 'list-heads', bundle.name)
        p.require(heads == (revision + ' HEAD\n').encode(), 'exported bundle does not identify the candidate')
        target('fetch', '--quiet', '--no-tags', '--no-auto-maintenance', '--no-write-fetch-head',
               '--recurse-submodules=no', bundle.name, 'HEAD:refs/dev-pair/candidates/' + revision)
    target('checkout', '--quiet', '--no-overwrite-ignore', '--detach', revision)
    approved_source(target, maintenance, approval, revision)


def candidate_image(info, image, revision=None):
    p.require(type(info) is list and len(info) == 1, 'expected one immutable image manifest')
    row = info[0]
    p.require(row['Architecture'] == 'amd64' and row['Os'] == 'linux', 'wrong checklist image platform')
    ident = row['Id'].removeprefix('sha256:')
    p.digest(ident)
    digest = row['Digest'].removeprefix('sha256:')
    p.digest(digest)
    expected = image.split(':', 1)[0] + '@sha256:' + digest if '@' not in image else image
    p.require(expected.endswith('@sha256:' + digest) and expected in row['RepoDigests'],
              'exact image manifest is missing from storage')
    if revision is not None:
        labels = row.get('Labels') or row['Config']['Labels']
        p.require(labels['org.opencontainers.image.revision'] == revision,
                  'OCI source label does not match the authorized revision')
    return ident, digest, expected


def archive_manifest(path, ident, digest, end):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        node = os.fstat(stream.fileno())
        owner = pwd.getpwnam('dp-checklist').pw_uid
        p.require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_uid == owner and
                  0 < node.st_size <= MAX_ARCHIVE, 'invalid bounded builder OCI archive')
        wanted = {'index.json', 'blobs/sha256/' + digest, 'blobs/sha256/' + ident}
        captured = {}
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            for count, member in enumerate(archive, 1):
                remaining(end)
                p.require(count <= 4096, 'OCI archive member count exceeds its limit')
                name = member.name.removeprefix('./')
                if name in wanted:
                    p.require(name not in captured and member.isreg() and 0 < member.size <= p.MAX_MESSAGE,
                              'invalid OCI metadata member')
                    with archive.extractfile(member) as entry:
                        captured[name] = entry.read(p.MAX_MESSAGE + 1)
        p.require(set(captured) == wanted, 'OCI archive does not contain the exact graph')
    index = p.loads(captured['index.json'])
    manifest_name = 'blobs/sha256/' + digest
    p.require(index['schemaVersion'] == 2 and len(index['manifests']) == 1 and
              index['manifests'][0]['digest'] == 'sha256:' + digest and
              index['manifests'][0]['size'] == len(captured[manifest_name]) and
              index['manifests'][0]['mediaType'] == 'application/vnd.oci.image.manifest.v1+json' and
              p.sha256(captured[manifest_name]) == digest and p.sha256(captured['blobs/sha256/' + ident]) == ident,
              'OCI index or stored descriptor digest changed in transport')
    config = p.loads(captured[manifest_name])['config']
    p.require(config['digest'] == 'sha256:' + ident and config['size'] == len(captured['blobs/sha256/' + ident]),
              'OCI exported config differs from the inspected image')


def build(job, repository, agreement_sha, revision, end):
    p.require(os.geteuid() == 0, 'protected checklist build conductor required')
    runtime = h.host_runtime()
    _, approval = checkout_approval(job, repository, agreement_sha)
    work = ROOT / 'development/workspaces' / job
    source = approved_source(git_runner(work, 'dp-dev', end), work, approval, revision)
    path = envelope_path(job, revision)
    runtime.protected(RECEIPTS, file=False)
    if os.path.lexists(path):
        observed = p.loads(protected_file(path, 4096))
        p.require(observed['job_id'] == job and observed['candidate']['source_revision'] == revision,
                  'historical candidate receipt identity mismatch')
        return preload(path, observed, end)

    base = p.loads(protected_file(BASE, 4096))
    p.fields(base, 'version image verification_sha256')
    p.number(base['version'], 1, 1)
    p.digest(base['verification_sha256'])
    p.require(re.fullmatch(runtime.IMAGE, base['image']), 'approved build base must be an exact OCI reference')
    recipe = protected_file(RECIPE, 8192)
    runtime.storage_identity(runtime.STORAGE)
    account = pwd.getpwnam(runtime.ACCOUNT)
    build = runtime.STORAGE / 'builder'
    for leaf in (build, build / 'graph', build / 'tmp'):
        info = leaf.lstat()
        p.require(stat.S_ISDIR(info.st_mode) and leaf.resolve(strict=True) == leaf and
                  info.st_uid == account.pw_uid and stat.S_IMODE(info.st_mode) == 0o700 and
                  info.st_dev == runtime.STORAGE.stat().st_dev, 'builder storage must be private and bounded')
    run = Path('/run/user') / str(account.pw_uid)

    def podman(graph, runroot, *args, cap=p.MAX_MESSAGE):
        return invoke(as_role(runtime.ACCOUNT, '/usr/bin/podman', '--root', graph, '--runroot', runroot, *args,
                environment={'XDG_RUNTIME_DIR': str(run), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(run / 'bus'),
                             'TMPDIR': str(build / 'tmp')}), end, cap=cap)

    store = (build / 'graph', run / 'dev-pair-checklist-builder')
    validation = (runtime.STORAGE / 'graph', run / 'dev-pair-checklist-runroot')
    for graph, runroot in (store, validation):
        info = podman(graph, runroot, 'info', '--format', '{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}} '
                      '{{.Store.GraphRoot}} {{.Store.RunRoot}}').decode().strip()
        p.require(info == f'true true {graph} {runroot}', 'Podman build or import storage identity changed')
    _, _, checked_base = candidate_image(p.loads(podman(*store, 'image', 'inspect', base['image'])), base['image'])
    tag = 'localhost/dev-pair-checklist:' + revision
    with tempfile.TemporaryDirectory(prefix='stage-', dir=build / 'tmp') as temporary:
        work = Path(temporary)
        # Root owns the build context and hands only a separate spool to Podman.
        work.chmod(0o755)
        context, spool = work / 'input', work / 'output'
        context.mkdir(mode=0o755)
        spool.mkdir(mode=0o700)
        os.chown(spool, account.pw_uid, account.pw_gid)
        for filename, contents in (('Containerfile', recipe), ('checklist.py', source)):
            file = context / filename
            write_private(file, contents)
            file.chmod(0o444)
        podman(*store, 'build', '--quiet', '--platform', 'linux/amd64', '--format', 'oci', '--pull=never',
               '--network=none', '--timestamp=0', '--tag', tag, '--build-arg', 'CHECKLIST_BASE=' + checked_base,
               '--build-arg', 'CHECKLIST_SOURCE=' + revision, '--file', context / 'Containerfile', context)
        ident, digest, image = candidate_image(p.loads(podman(*store, 'image', 'inspect', tag)), tag, revision)
        archive = spool / 'candidate.oci'
        podman(*store, 'save', '--format=oci-archive', '--output', archive, tag)
        archive_manifest(archive, ident, digest, end)
        podman(*validation, 'load', '--input', archive)
        observed = candidate_image(p.loads(podman(*validation, 'image', 'inspect', image)), image, revision)
        p.require(observed == (ident, digest, image), 'validation store importer changed the exact candidate')
    result = {'version': 1, 'job_id': job, 'candidate': {'source_revision': revision, 'artifact_sha256': digest},
              'image': image}
    fd, pending = tempfile.mkstemp(prefix='.pending-', dir=RECEIPTS)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(p.canonical(result).encode())
            out.flush()
            os.fsync(out.fileno())
        preload(Path(pending), result, end, expected_id=ident)
        # The protected product owner lease serializes publication.
        p.require(not os.path.lexists(path), 'a named candidate receipt appeared during the build')
        os.rename(pending, path)
        sync_directory(RECEIPTS)
    finally:
        Path(pending).unlink(missing_ok=True)
    return path, result


def preload(path, receipt, end, *, expected_id=None):
    data = invoke(['/usr/bin/python3', '-EBs', str(KIT / 'tools/destination_release.py'),
                   'preload-validation', '--receipt', str(path), '--apply'], min(end, time.monotonic() + 55))
    result = p.loads(data)
    p.require(result['job_id'] == receipt['job_id'] and result['receipt_sha256'] == p.sha256(protected_file(path, 4096)),
              'destination preloader returned a foreign receipt')
    p.digest(result['image_id'])
    p.require(expected_id is None or result['image_id'] == expected_id, 'destination observed a different image ID')
    return path, receipt
