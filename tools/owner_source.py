"""Provision exact Git and startup inputs through the protected owner terminal."""

import contextlib
import fcntl
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_protocol as p
import owner_intake as owner
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private
from session_controller import SHARED
from startup_delivery import MAX_BYTES

STANDARD_REPOSITORY = 'oso-gato/standards'
CREDENTIALS = Path('/etc/dev-pair/repository-credentials')
PACK_BYTES = 2 * owner.candidate.MAX_BUNDLE
CHECKOUT_BYTES = 64 * 1024 * 1024
TREE_BYTES = 1024 * 1024
STAGE_PREFIX = '.source-stage-'
CHECKOUTS = {'acquired': 'commit', 'startup': 'startup_revision'}


def https_origin(repository):
    return f'https://github.com/{repository}.git'


def pending(message):
    return owner.SitePending('owner-repository-inputs', message)


def credential_path(repository):
    path = CREDENTIALS / repository
    if not os.path.lexists(path):
        if repository == STANDARD_REPOSITORY:
            raise pending('The authorized GitHub custodian must supply the root-private standards read credential.')
        return None
    trusted_directory(path.parent)
    p.private_file(path)
    return path


def credential_exchange(repository, action, incoming, outgoing):
    """Reply to Git's in-memory credential exchange for one HTTPS origin."""
    p.require(os.getuid() == os.geteuid() == 0, 'Repository credential helper requires root.')
    owner.repository_id(repository)
    if action in ('store', 'erase'):
        return
    data = incoming.read(4097)
    p.require(action == 'get' and len(data) <= 4096 and data.endswith(b'\n'),
              'Invalid repository credential request.')
    expected = {b'protocol=https', b'host=github.com', ('path=' + repository + '.git').encode()}
    rows = data.rstrip(b'\n').split(b'\n')
    scope = [row for row in rows if row.partition(b'=')[0] in (b'protocol', b'host', b'path')]
    p.require(len(scope) == len(expected) and set(scope) == expected, 'Repository credential scope mismatch.')
    path = credential_path(repository)
    p.require(path is not None, 'Repository credential is unavailable.')
    secret = read_private(path, 1025).removesuffix(b'\n')
    p.require(re.fullmatch(rb'[A-Za-z0-9_-]{12,1024}', secret), 'Repository credential format is invalid.')
    outgoing.write(b'username=x-access-token\npassword=' + secret + b'\n\n')
    outgoing.flush()


def fetch(checkout, repository, revision, *, shallow):
    origin = https_origin(repository)
    owner.fixed_git(checkout, 'init', '--template=')
    owner.fixed_git(checkout, 'config', '--local', '--replace-all', 'remote.origin.url', origin)
    if credential_path(repository) is None:
        auth = []
    else:
        command = shlex.join([owner.PYTHON, '-IB', str(Path(__file__).resolve()), '--git-credential', repository])
        auth = ['-c', 'credential.helper=!exec ' + command]
    git = ['/usr/bin/timeout', '--kill-after=5s', '115s',
           '/usr/bin/prlimit', f'--fsize={PACK_BYTES}:{PACK_BYTES}', '--core=0:0', '--',
           '/usr/bin/env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null', 'GIT_TERMINAL_PROMPT=0',
           *owner.candidate.GIT, '-C', str(checkout), '-c', 'protocol.https.allow=always',
           '-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true',
           '-c', 'credential.helper=', '-c', 'credential.useHttpPath=true',
           '-c', 'fetch.fsckObjects=true', '-c', 'fetch.unpackLimit=1', '-c', 'core.fsync=all', *auth]
    try:
        owner.candidate.invoke([*git, 'fetch', '--no-auto-maintenance', '--no-tags', '--no-recurse-submodules',
                               *(['--depth=1'] if shallow else []), origin, revision], time.monotonic() + 120, cap=8192)
    except (ValueError, OSError, subprocess.SubprocessError):
        raise pending(f'Could not fetch the approved exact commit from {repository}. Check the commit and the repository read access, then retry.') from None
    actual = owner.fixed_git(checkout, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}').strip().decode()
    p.require(actual == revision, 'The GitHub response differs from the approved commit.')


def checkout_exact(checkout, repository, revision, *, acquired):
    fetch(checkout, repository, revision, shallow=not acquired)
    inventory = owner.fixed_git(checkout, 'ls-tree', '-rlz', '--full-tree', revision, cap=TREE_BYTES)
    size = 0
    for row in inventory.split(b'\0')[:-1]:
        kind, object_type, _, length = row.split(b'\t', 1)[0].split()
        if object_type == b'blob':
            size += int(length)
        else:
            p.require((kind, object_type, length) == (b'160000', b'commit', b'-'), 'Unexpected Git tree object.')
    p.require(size <= CHECKOUT_BYTES, 'The approved source exceeds the first-owner checkout size limit.')
    owner.fixed_git(checkout, '-c', 'core.fsync=all', 'checkout', '--detach', '--no-recurse-submodules', revision)
    p.require(not owner.fixed_git(checkout, 'status', '--porcelain=v1', '--untracked-files=all'),
              'The provisioned checkout is not clean.')
    if acquired:
        p.require(owner.fixed_git(checkout, 'rev-parse', '--is-shallow-repository') == b'false\n',
                  'The approved acquisition requires its full Git history.')
        # Job preparation uses this same bounded export when it seeds both roles.
        owner.fixed_git(checkout, 'bundle', 'create', '-', 'HEAD', cap=owner.candidate.MAX_BUNDLE)
    for folder, _, names in os.walk(checkout, topdown=False):
        for name in names:
            path = Path(folder) / name
            if not path.is_symlink():
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        sync_directory(folder)


def standards_at(stage):
    checkout = stage / 'shared-git'
    checkout.mkdir(mode=0o700)
    fetch(checkout, STANDARD_REPOSITORY, p.STANDARDS, shallow=True)
    cache = stage / 'standards'
    cache.mkdir(mode=0o700)
    for name, digest in SHARED.items():
        body = owner.fixed_git(checkout, 'show', f'{p.STANDARDS}:{name}', cap=MAX_BYTES)
        p.require(p.sha256(body) == digest, 'The private standards differ from the adopted commit.')
        write_private(cache / name, body)
    sync_directory(cache)
    return cache


def existing_inputs(site, repository):
    base = site / 'repositories' / repository
    for root in (site, site / 'repositories', base.parent, base):
        if os.path.lexists(root):
            owner.protect_directory(root)
    paths = {key: base / key for key in CHECKOUTS}
    config = {}
    for key, path in paths.items():
        if os.path.lexists(path):
            owner.protect_directory(path)
            owner.protect_directory(path / '.git')
            owner.checked_file(path / '.git/config', 8192)
            if key == 'acquired':
                p.require(owner.fixed_git(path, 'rev-parse', '--is-shallow-repository') == b'false\n',
                          'The retained acquisition is missing full Git history. Preserve it for review.')
            revision = owner.fixed_git(path, 'rev-parse', '--verify', 'HEAD').strip().decode()
            p.digest(revision, 40)
            config[CHECKOUTS[key]] = revision
    cache = site / 'standards'
    if os.path.lexists(cache):
        owner.protect_directory(cache)
    missing_standards = []
    for name, digest in SHARED.items():
        if os.path.lexists(cache / name):
            p.require(p.sha256(owner.checked_file(cache / name, MAX_BYTES)) == digest,
                      'A retained private standards document differs from the adopted commit. Preserve it for review.')
        else:
            missing_standards.append(name)
    return paths, config, cache, missing_standards


def ensure_directory(path):
    try:
        owner.protect_directory(path)
    except FileNotFoundError:
        owner.protect_directory(path.parent)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        sync_directory(path.parent)
        owner.protect_directory(path)
    return path


@contextlib.contextmanager
def provision_lock(site):
    lock = ensure_directory(site) / '.source-provision.lock'
    try:
        write_private(lock, b'')
        sync_directory(site)
    except FileExistsError:
        pass
    p.private_file(lock)
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for stale in site.glob(STAGE_PREFIX + '*'):
            if re.fullmatch(r'\.source-stage-[a-z0-9_]{8}', stale.name):
                shutil.rmtree(trusted_directory(stale))
        yield


def read_revision(prompt, ask, default=None):
    value = ask(prompt) or default
    p.require(type(value) is str and re.fullmatch('[0-9a-f]{40}', value),
              'Enter the full 40-character approved Git commit SHA.')
    return value


def publish(stage, paths, retained, cache, missing_standards):
    if missing_standards:
        if not os.path.lexists(cache):
            (stage / 'standards').rename(cache)
            sync_directory(cache.parent)
        else:
            for name in missing_standards:
                (stage / 'standards' / name).rename(cache / name)
            sync_directory(cache)
    for key, path in paths.items():
        if CHECKOUTS[key] not in retained:
            for directory in (path.parent.parent.parent, path.parent.parent, path.parent):
                ensure_directory(directory)
            (stage / key).rename(path)
            sync_directory(path.parent)


def provision(intake, repository, workload, ask, say, *, approved=None):
    """Verify retained inputs or fill missing inputs after exact attended approval."""
    owner.repository_id(repository)
    p.require(repository.casefold() != STANDARD_REPOSITORY,
              'Select an authorized project repository outside the private standards repository.')
    paths, retained, cache, missing_standards = existing_inputs(intake.site, repository)
    config = ({key: approved[key] for key in CHECKOUTS.values()} if approved is not None else dict(retained))
    p.require(all(config[key] == value for key, value in retained.items()),
              'A retained checkout differs from the approved catalogue. Preserve it for review.')
    if not missing_standards and len(retained) == len(CHECKOUTS):
        owner.first_source(intake, repository, workload)
        return True
    if 'commit' not in config:
        config['commit'] = read_revision('Approved project source commit (full SHA)', ask)
    if 'startup_revision' not in config:
        config['startup_revision'] = read_revision('Approved startup commit (Enter for the source commit)', ask, config['commit'])
    say(f"Project origin {https_origin(repository)} at {config['commit']}.")
    say(f"Project startup commit {config['startup_revision']}.")
    say(f"Private standards origin {https_origin(STANDARD_REPOSITORY)} at {p.STANDARDS}.")
    if ask('Confirm read-only acquisition of these exact inputs? [y/N]').lower() not in ('y', 'yes'):
        say('Source provisioning remains pending.')
        return False
    with provision_lock(intake.site):
        paths, retained, cache, missing_standards = existing_inputs(intake.site, repository)
        p.require(all(config[key] == value for key, value in retained.items()),
                  'A retained checkout differs from the approved Git commit. Preserve it for review.')
        if missing_standards:
            credential_path(STANDARD_REPOSITORY)
        with tempfile.TemporaryDirectory(prefix=STAGE_PREFIX, dir=intake.site) as directory:
            stage = Path(directory)
            effective_paths = dict(paths)
            for key, setting in CHECKOUTS.items():
                if setting not in retained:
                    checkout = effective_paths[key] = stage / key
                    checkout.mkdir(mode=0o700)
                    checkout_exact(checkout, repository, config[setting], acquired=key == 'acquired')
            owner.verify_startup_adoption(repository, effective_paths['startup'], config['startup_revision'])
            effective_cache = standards_at(stage) if missing_standards else cache
            intake.verify_source(repository, config, effective_paths['acquired'], effective_paths['startup'],
                                 effective_cache, checklist=workload == owner.CHECKLIST)
            publish(stage, paths, retained, cache, missing_standards)
        owner.first_source(intake, repository, workload)
    say('The approved source, startup documents and private standards are ready.')
    return True


def restore(first, incoming, outgoing):
    def say(message):
        print(message, file=outgoing, flush=True)

    def ask(prompt):
        return owner.setup_answer(incoming, outgoing, prompt)

    try:
        if first.configured() is None:
            say('Run the attended owner setup to approve the first repository and exact commits.')
            return
        repositories, _ = first.intake.catalogue_settings()
        repository = next(iter(repositories)) if len(repositories) == 1 else owner.repository_id(ask('Approved repository (owner/name)'))
        p.require(repository in repositories, 'Select a repository in the existing approved catalogue.')
        config = repositories[repository]
        workloads = config.get('workloads', [owner.CHECKLIST])
        workload = owner.CHECKLIST if owner.CHECKLIST in workloads else workloads[0]
        if provision(first.intake, repository, workload, ask, say, approved=config):
            say('The retained catalogue inputs verify against its exact approved revisions.')
    except owner.SitePending as wait:
        say(wait.observation['message'])
    except (EOFError, KeyboardInterrupt):
        say('Source recovery was interrupted. Run the same command to check and restore missing inputs.')


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--git-credential':
            if sys.argv[3] == 'get':
                p.require(all(stat.S_ISFIFO(os.fstat(stream.fileno()).st_mode) for stream in (sys.stdin, sys.stdout)),
                          'Repository credential exchange requires Git protocol pipes.')
            credential_exchange(*sys.argv[2:], sys.stdin.buffer, sys.stdout.buffer)
        else:
            raise SystemExit(2)
    except (OSError, ValueError, owner.SitePending):
        raise SystemExit(2) from None
