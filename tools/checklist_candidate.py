#!/usr/bin/env python3
"""Build and admit one authorized checklist Git object through the fixed OCI recipe."""
import contextlib
import hashlib
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

import checklist_build_storage as build_storage
import host_handoff as h
import job_protocol as p
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private

ROOT = Path('/var/lib/dev-pair')
KIT = Path('/usr/libexec/dev-pair')
RECEIPTS = ROOT / 'checklist-receipts'
BASE = Path('/etc/dev-pair/checklist/build-base.json')
CONTAINERS = BASE.with_name('validation-containers.conf')
SELF = Path(__file__).resolve()
RECIPE = SELF.parent.parent / 'examples/checklist/Containerfile'
BUILD_INPUTS = Path('/run/dev-pair/checklist-build-inputs')
APP = 'examples/checklist/checklist.py'
MAX_SOURCE = 64 * 1024
MAX_ARCHIVE = 320 * 1024 * 1024
MAX_BUNDLE = 16 * 1024 * 1024
RUNUSER = Path('/usr/sbin/runuser')
GIT = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
       '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never']
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8'}


def remaining(end):
    return h.time_left(end)


def invoke(argv, end, *, cap=p.MAX_MESSAGE, data=None, stdin=None, stdout=None):
    """Bound command output independently of pipe reader and child lifetime."""
    p.require(data is None or stdin is None, 'fixed command input has two sources')
    # The only input is a bounded trusted-controller JSON document or prompt.
    with tempfile.TemporaryFile() as incoming, selectors.DefaultSelector() as ready:
        if data is not None:
            p.require(len(data) <= p.MAX_MESSAGE, 'fixed command input is too large')
            incoming.write(data)
            incoming.seek(0)
        remaining(end)
        with subprocess.Popen(argv, stdin=incoming if stdin is None else stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=ENV, start_new_session=True) as process:
            output = bytearray()
            copied = 0
            try:
                ready.register(process.stdout, selectors.EVENT_READ)
                while ready.select(remaining(end)):
                    chunk = os.read(process.stdout.fileno(), min(8192, cap + 1 - copied))
                    if not chunk:
                        break
                    copied += len(chunk)
                    p.require(copied <= cap, 'fixed command output exceeds its limit')
                    if stdout is None:
                        output.extend(chunk)
                    else:
                        stdout.write(chunk)
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
    runuser = RUNUSER.resolve(strict=True)
    h.host_runtime().protected(runuser.parent, file=False)
    node = runuser.stat()
    p.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022 and os.access(runuser, os.X_OK),
              'trusted account switching executable required')
    return [str(runuser), '--user', role, '--', '/usr/bin/env', '-i',
            *(key + '=' + value for key, value in values.items()), *map(str, argv)]


def storage_witness(runtime):
    account = pwd.getpwnam(runtime.ACCOUNT)
    p.require(os.getuid() == os.geteuid() == account.pw_uid >= 1000 and
              os.getgid() == os.getegid() == account.pw_gid, 'managed checklist storage identity required')
    path = runtime.STORAGE
    before = path.lstat()
    evidence = runtime.storage_identity(path)
    after = path.lstat()
    p.require((before.st_dev, before.st_ino, before.st_uid, before.st_gid) ==
              (after.st_dev, after.st_ino, after.st_uid, after.st_gid), 'checklist storage root changed during verification')
    return {'device': after.st_dev, 'inode': after.st_ino, 'uid': after.st_uid, 'gid': after.st_gid,
            'evidence': evidence}


def checked_storage(runtime, end):
    runtime.protected(SELF, file=True)
    observed = p.loads(invoke(as_role(runtime.ACCOUNT, '/usr/bin/python3', '-EBs', SELF, '__storage-witness'),
                              min(end, time.monotonic() + 10), cap=4096))
    p.fields(observed, 'device inode uid gid evidence')
    current = runtime.STORAGE.lstat()
    account = pwd.getpwnam(runtime.ACCOUNT)
    p.require(all(type(observed[key]) is int for key in ('device', 'inode', 'uid', 'gid')) and
              (observed['device'], observed['inode'], observed['uid'], observed['gid']) ==
              (current.st_dev, current.st_ino, account.pw_uid, account.pw_gid) and
              (current.st_uid, current.st_gid) == (account.pw_uid, account.pw_gid) and
              stat.S_ISDIR(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700,
              'managed storage witness differs from the build mount')
    limits = os.statvfs(runtime.STORAGE)
    expected = [f'storage-bytes:{limits.f_blocks * limits.f_frsize}', f'storage-inodes:{limits.f_files}',
                f'storage-fsid:{limits.f_fsid}']
    p.require(observed['evidence'] == expected,
              'managed storage witness lacks the matching capacity and filesystem identity')
    return current.st_dev


@contextlib.contextmanager
def build_context(runtime, gid, recipe, source, end):
    parent = runtime.protected(BUILD_INPUTS, file=False)
    p.require(parent.stat().st_gid == gid and stat.S_IMODE(parent.stat().st_mode) == 0o750,
              'protected builder inputs require the checklist group and mode 0750')
    context = parent / 'active'
    contents = {'Containerfile': recipe, 'checklist.py': source}
    # One fixed bounded context under root custody. An exact retained context
    # can be used after interruption; a partial or foreign one is preserved.
    if not os.path.lexists(context):
        remaining(end)
        context.mkdir(mode=0o700)
        for name, data in contents.items():
            remaining(end)
            destination = context / name
            write_private(destination, data)
            os.chown(destination, 0, gid)
            destination.chmod(0o440)
        os.chown(context, 0, gid)
        context.chmod(0o550)
        sync_directory(context)
        sync_directory(parent)
    runtime.protected(context, file=False)
    p.require(context.stat().st_gid == gid and stat.S_IMODE(context.stat().st_mode) == 0o550 and
              {item.name for item in context.iterdir()} == set(contents), 'incomplete or foreign builder context')
    for name, data in contents.items():
        path = runtime.protected(context / name, file=True)
        p.require(path.stat().st_gid == gid and stat.S_IMODE(path.stat().st_mode) == 0o440 and
                  p.read_data(path, len(data)) == data, 'retained builder input differs from the exact candidate')
    try:
        yield context
    finally:
        context.chmod(0o750)
        for name in contents:
            (context / name).unlink()
        context.rmdir()
        sync_directory(parent)


def git_runner(workspace, role, end, *, allow_bundle=False):
    p.require(workspace.resolve(strict=True) == workspace and workspace.is_dir(), 'unsafe job checkout path')
    git = GIT + (['-c', 'protocol.file.allow=always'] if allow_bundle else [])
    return lambda *args, cap=1024: invoke(as_role(role, *git, '-C', workspace, *args,
        environment={'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                     'GIT_NO_LAZY_FETCH': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0'}),
        min(end, time.monotonic() + 10), cap=cap)


def approved_checkout(git, workspace, approval, revision):
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
    tree = git('rev-parse', '--verify', revision + '^{tree}').decode().strip()
    p.digest(tree, 40)
    return tree


def approved_source(git, workspace, approval, revision):
    approved_checkout(git, workspace, approval, revision)
    record = git('ls-tree', '--full-tree', '-z', revision, '--', APP)
    match = re.fullmatch(rb'100(?:644|755) blob ([0-9a-f]{40})\texamples/checklist/checklist\.py\0', record)
    p.require(match, 'authorized commit must contain the fixed checklist source as one regular blob')
    blob = git('cat-file', 'blob', match[1].decode(), cap=MAX_SOURCE)
    calculated = hashlib.sha1(b'blob ' + str(len(blob)).encode() + b'\0' + blob).hexdigest()
    p.require(blob and calculated == match[1].decode(), 'checklist Git object failed its content verification')
    blob.decode('utf-8')
    return blob


def mirror_maintenance(job, approval, revision, end, *, checklist=True):
    maintenance = ROOT / 'maintenance/workspaces' / job
    development = ROOT / 'development/workspaces' / job
    source = git_runner(development, 'dp-dev', end)
    target = git_runner(maintenance, 'dp-maint', end, allow_bundle=True)
    base = approval['acquired_commit']
    verify = approved_source if checklist else approved_checkout
    head = target('rev-parse', '--verify', 'HEAD').decode().strip()
    if head == revision:
        verify(target, maintenance, approval, revision)
        return
    verify(target, maintenance, approval, base)
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
    verify(target, maintenance, approval, revision)


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


def archive_manifest(path, ident, digest, end, *, protected=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        node = os.fstat(stream.fileno())
        owner = 0 if protected else pwd.getpwnam('dp-checklist').pw_uid
        p.require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_uid == owner and
                  (not protected or node.st_gid == 0 and stat.S_IMODE(node.st_mode) == 0o600) and
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


def transfer_spool(runtime, storage_dev, *, create):
    runtime.protected(RECEIPTS, file=False)
    control = RECEIPTS / '.build-lifecycle'
    if create:
        try:
            trusted_directory(control, create=True)
        except FileExistsError:
            pass
    return build_storage.Spool(control, runtime.STORAGE, storage_dev, MAX_ARCHIVE)


def sweep_spool(end):
    p.require(os.geteuid() == 0, 'protected checklist build conductor required')
    runtime = h.host_runtime()
    if not os.path.lexists(RECEIPTS / '.build-lifecycle'):
        return {'event': 'uninitialized'}
    with runtime.dispatch_gate():
        spool = transfer_spool(runtime, checked_storage(runtime, end), create=False)
        try:
            with spool.locked(create=False) as fd:
                return {'event': 'empty'} if fd is None else spool.reclaim(fd)
        except BlockingIOError:
            return {'event': 'active-build-retained'}


def input_proof(base, recipe, source):
    return p.canonical({'schema': 1, 'base': base, 'recipe_sha256': p.sha256(recipe),
                        'source_blob_sha256': p.sha256(source), 'target': 'linux/amd64',
                        'output_cache': 'clean', 'network': 'none', 'pull': 'never'}).encode()


def build(job, repository, agreement_sha, revision, end):
    p.require(os.geteuid() == 0, 'protected checklist build conductor required')
    runtime = h.host_runtime()
    _, approval = checkout_approval(job, repository, agreement_sha)
    work = ROOT / 'development/workspaces' / job
    source = approved_source(git_runner(work, 'dp-dev', end), work, approval, revision)
    path = envelope_path(job, revision)
    proof = path.with_suffix('.build-inputs')
    runtime.protected(RECEIPTS, file=False)
    # An exact prior receipt remains replayable, including releases predating input proof.
    retained = os.path.lexists(path)
    bound = os.path.lexists(proof)
    if retained and not bound:
        return retained_candidate(path, job, revision, end)
    base = p.loads(protected_file(BASE, 4096))
    p.fields(base, 'version image verification_sha256')
    p.number(base['version'], 1, 1)
    p.digest(base['verification_sha256'])
    p.require(re.fullmatch(runtime.IMAGE, base['image']), 'approved build base must be an exact OCI reference')
    recipe = protected_file(RECIPE, 8192)
    inputs = input_proof(base, recipe, source)
    if bound:
        p.require(read_private(proof, 4096) == inputs,
                  'checklist build inputs changed. The prior candidate remains available for its original validation')
    if retained:
        return retained_candidate(path, job, revision, end)

    storage_dev = checked_storage(runtime, end)
    account = pwd.getpwnam(runtime.ACCOUNT)
    build = runtime.STORAGE / 'builder'
    image_copy = runtime.STORAGE / 'image-copy'
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    volume = os.open(runtime.STORAGE, flags)
    try:
        mount = build_storage.mount_id(volume)
        for leaf in (build, build / 'graph', build / 'tmp', image_copy, runtime.STORAGE / 'graph'):
            fd = os.open(leaf, flags)
            try:
                info = os.fstat(fd)
                p.require(leaf.resolve(strict=True) == leaf and (info.st_uid, info.st_gid) ==
                          (account.pw_uid, account.pw_gid) and stat.S_IMODE(info.st_mode) == 0o700 and
                          info.st_dev == storage_dev and build_storage.mount_id(fd) == mount,
                          'builder storage must be private and bounded')
            finally:
                os.close(fd)
    finally:
        os.close(volume)
    p.require(protected_file(CONTAINERS, 4096) == f'[engine]\nimage_copy_tmp_dir="{image_copy}"\n'.encode(),
              'checklist build requires the declared bounded image-copy configuration')
    run = Path('/run/user') / str(account.pw_uid)

    def podman(graph, runroot, *args, cap=p.MAX_MESSAGE, stdin=None, stdout=None):
        return invoke(as_role(runtime.ACCOUNT, '/usr/bin/podman', '--root', graph, '--runroot', runroot, *args,
                environment={'XDG_RUNTIME_DIR': str(run), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(run / 'bus'),
                             'CONTAINERS_CONF': str(CONTAINERS), 'TMPDIR': str(build / 'tmp')}),
                      end, cap=cap, stdin=stdin, stdout=stdout)

    store = (build / 'graph', run / 'dev-pair-checklist-builder')
    validation = (runtime.STORAGE / 'graph', run / 'dev-pair-checklist-runroot')
    spool = transfer_spool(runtime, storage_dev, create=True)
    tag = 'localhost/dev-pair-checklist:' + p.identity([job, revision, p.sha256(inputs)])
    with spool.locked(create=True) as directory:
        with spool.transfer(directory, job, revision) as staged:
            ident, receipt = build_and_load(runtime, podman, store, validation, image_copy, account, base, recipe,
                                            source, job, revision, tag, staged, end)
        print(p.canonical({'job': job, 'revision': revision, 'spool': staged[2]}), file=sys.stderr, flush=True)
        if not bound:
            build_storage.replace_private(spool.control / 'inputs.new', proof, inputs)
        return publish_candidate(path, receipt, ident, end)


def retained_candidate(path, job, revision, end):
    observed = p.loads(protected_file(path, 4096))
    p.require(observed['job_id'] == job and observed['candidate']['source_revision'] == revision,
              'historical candidate receipt identity mismatch')
    return preload(path, observed, end)


def build_and_load(runtime, podman, store, validation, image_copy, account, base, recipe,
                   source, job, revision, tag, staged, end):
    for graph, runroot in (store, validation):
        info = podman(graph, runroot, 'info', '--format', '{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}} '
                      '{{.Store.GraphRoot}} {{.Store.RunRoot}} {{.Store.ImageCopyTmpDir}}').decode().strip()
        p.require(info == f'true true {graph} {runroot} {image_copy}', 'Podman build or import storage identity changed')
    base_id, base_digest, checked_base = candidate_image(
        p.loads(podman(*store, 'image', 'inspect', base['image'])), base['image'])
    archive, transfer, _ = staged
    with build_context(runtime, account.pw_gid, recipe, source, end) as context:
        podman(*store, 'build', '--quiet', '--platform', 'linux/amd64', '--format', 'oci', '--pull=never', '--no-cache',
               '--network=none', '--timestamp=0', '--tag', tag, '--build-arg', 'CHECKLIST_BASE=' + checked_base,
               '--build-arg', 'CHECKLIST_SOURCE=' + revision, '--file', context / 'Containerfile', context)
        ident, digest, image = candidate_image(p.loads(podman(*store, 'image', 'inspect', tag)), tag, revision)
        podman(*store, 'save', '--format=oci-archive', tag, cap=MAX_ARCHIVE, stdout=transfer)
        transfer.flush()
        os.fsync(transfer.fileno())
        archive_manifest(archive, ident, digest, end, protected=True)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(archive, flags), 'rb') as incoming:
            podman(*validation, 'load', stdin=incoming)
        observed = candidate_image(p.loads(podman(*validation, 'image', 'inspect', image)), image, revision)
        p.require(observed == (ident, digest, image), 'validation store importer changed the exact candidate')
    print(p.canonical({'event': 'checklist-build-inputs', 'job': job, 'revision': revision,
                       'base_config_sha256': base_id, 'base_manifest_sha256': base_digest,
                       'verified_local_base_hits': 1, 'input_downloads': 0, 'network': 'none',
                       'transfer_bytes': os.fstat(transfer.fileno()).st_size}),
          file=sys.stderr, flush=True)
    result = {'version': 1, 'job_id': job, 'candidate': {'source_revision': revision, 'artifact_sha256': digest},
              'image': image}
    return ident, result


def publish_candidate(path, result, ident, end):
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


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['sweep-spool']:
            os.umask(0o077)
            result = sweep_spool(time.monotonic() + 15)
        else:
            p.require(sys.argv[1:] == ['__storage-witness'], 'fixed checklist operation required')
            result = storage_witness(h.host_runtime())
        print(p.canonical(result))
    except (OSError, ValueError):
        raise SystemExit('managed checklist storage operation blocked') from None
