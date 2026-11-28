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
import termios
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
TOKEN = re.compile(rb'[A-Za-z0-9_-]{12,1024}')


def https_origin(repository):
    return f'https://github.com/{repository}.git'


def pending(message):
    return owner.SitePending('owner-repository-inputs', message)


def read_credential(repository):
    path = CREDENTIALS / repository
    if not os.path.lexists(path):
        return None
    trusted_directory(path.parent)
    secret = read_private(path, 1025).removesuffix(b'\n')
    p.require(TOKEN.fullmatch(secret), 'Stored repository credential format is invalid.')
    return secret


def read_token(repository, *, required):
    """Read one bounded secret with echo disabled before displaying its prompt."""
    with open('/dev/tty', 'r+b', buffering=0) as terminal:
        fd = terminal.fileno()
        p.require(os.isatty(fd), 'Repository credential entry requires the protected root terminal.')
        normal = termios.tcgetattr(fd)
        hidden = list(normal)
        hidden[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
        try:
            prompt = f'Authorized GitHub Contents read token for {repository}'
            if not required:
                prompt += ' (Enter for public access)'
            terminal.write((prompt + ' ').encode())
            answer = terminal.readline(1026)
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, normal)
            terminal.write(b'\n')
    p.require(answer.endswith(b'\n'), 'Repository credential entry was interrupted or exceeded its bound.')
    secret = answer.removesuffix(b'\n')
    if not secret:
        if required:
            raise pending(f'An authorized read credential is required for {repository}. Source setup remains pending.')
        return None
    p.require(TOKEN.fullmatch(secret), 'Repository credential format is invalid.')
    return secret


def select_credential(repository, ask):
    current = read_credential(repository)
    if current is not None and ask(f'Replace the retained read credential for {repository}? [y/N]').lower() not in ('y', 'yes'):
        return current, False
    replacement = read_token(repository, required=current is not None or repository == STANDARD_REPOSITORY)
    return replacement, replacement is not None


def store_credential(repository, secret):
    ensure_directory(CREDENTIALS)
    path = CREDENTIALS / repository
    parent = trusted_directory(ensure_directory(path.parent))
    if os.path.lexists(path):
        p.private_file(path)
    # The replacement is fetched and verified before any credential is written.
    with tempfile.NamedTemporaryFile(prefix='.credential-candidate-', dir=parent, delete=False) as stage:
        candidate = Path(stage.name)
        try:
            stage.write(secret + b'\n')
            stage.flush()
            os.fsync(stage.fileno())
            os.replace(candidate, path)
            sync_directory(parent)
        finally:
            candidate.unlink(missing_ok=True)


@contextlib.contextmanager
def credential_fd(secret):
    """Carry the secret to the fixed Git helper through an inherited sealed descriptor."""
    fd = os.memfd_create('dev-pair-credential', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, 0o600)
        p.require(os.write(fd, secret) == len(secret), 'Repository credential could not be passed securely.')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield fd
    finally:
        os.close(fd)


def credential_exchange(repository, fd, action, incoming, outgoing):
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
    node = os.fstat(fd)
    p.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 0 and
              stat.S_IMODE(node.st_mode) == 0o600 and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE,
              'Repository credential descriptor is invalid.')
    secret = os.pread(fd, 1025, 0)
    p.require(TOKEN.fullmatch(secret), 'Repository credential format is invalid.')
    outgoing.write(b'username=x-access-token\npassword=' + secret + b'\n\n')
    outgoing.flush()


def fetch(checkout, repository, revision, *, shallow, secret):
    origin = https_origin(repository)
    owner.fixed_git(checkout, 'init', '--template=')
    owner.fixed_git(checkout, 'config', '--local', '--replace-all', 'remote.origin.url', origin)
    p.require(repository != STANDARD_REPOSITORY or secret is not None, 'The private standards require authorized read access.')
    git = ['/usr/bin/timeout', '--kill-after=5s', '115s',
           '/usr/bin/prlimit', f'--fsize={PACK_BYTES}:{PACK_BYTES}', '--core=0:0', '--',
           '/usr/bin/env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null', 'GIT_TERMINAL_PROMPT=0',
           *owner.candidate.GIT, '-C', str(checkout), '-c', 'protocol.https.allow=always',
           '-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true',
           '-c', 'credential.helper=', '-c', 'credential.useHttpPath=true',
           '-c', 'fetch.fsckObjects=true', '-c', 'fetch.unpackLimit=1', '-c', 'core.fsync=all']
    with credential_fd(secret) if secret is not None else contextlib.nullcontext() as descriptor:
        if descriptor is not None:
            command = shlex.join([owner.PYTHON, '-IB', str(Path(__file__).resolve()), '--git-credential', repository, str(descriptor)])
            git.extend(['-c', 'http.proactiveAuth=basic', '-c', 'credential.helper=!exec ' + command])
        try:
            owner.candidate.invoke([*git, 'fetch', '--no-auto-maintenance', '--no-tags', '--no-recurse-submodules',
                                   *(['--depth=1'] if shallow else []), origin, revision], time.monotonic() + 120, cap=8192,
                                   pass_fds=(descriptor,) if descriptor is not None else ())
        except (ValueError, OSError, subprocess.SubprocessError):
            raise pending(f'Could not fetch the approved exact commit from {repository}. Check the commit and the repository read access, then retry.') from None
    actual = owner.fixed_git(checkout, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}').strip().decode()
    p.require(actual == revision, 'The GitHub response differs from the approved commit.')


def checkout_exact(checkout, repository, revision, *, acquired, secret):
    fetch(checkout, repository, revision, shallow=not acquired, secret=secret)
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
        owner.verify_bundle(checkout)
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


def standards_at(stage, secret):
    checkout = stage / 'shared-git'
    checkout.mkdir(mode=0o700)
    fetch(checkout, STANDARD_REPOSITORY, p.STANDARDS, shallow=True, secret=secret)
    cache = stage / 'standards'
    cache.mkdir(mode=0o700)
    for name, digest in SHARED.items():
        body = owner.fixed_git(checkout, 'show', f'{p.STANDARDS}:{name}', cap=MAX_BYTES)
        p.require(p.sha256(body) == digest, 'The private standards differ from the adopted commit.')
        write_private(cache / name, body)
    sync_directory(cache)
    return cache


def require_private_directory(path):
    directory = owner.protect_directory(path)
    p.require(stat.S_IMODE(directory.lstat().st_mode) == 0o700,
              'Owner source custody requires root-private directories. Preserve the retained inputs for review.')
    return directory


def private_standards(cache):
    if os.path.lexists(cache):
        require_private_directory(cache)
    missing = []
    for name, digest in SHARED.items():
        path = cache / name
        if os.path.lexists(path):
            node = path.lstat()
            p.require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) in (0o400, 0o600),
                      'Private standards require root-private documents. Preserve the retained inputs for review.')
            p.require(p.sha256(owner.checked_file(path, MAX_BYTES)) == digest,
                      'A retained private standards document differs from the adopted commit. Preserve it for review.')
        else:
            missing.append(name)
    return missing


def existing_inputs(site, repository):
    base = site / 'repositories' / repository
    if os.path.lexists(site):
        require_private_directory(site)
    for root in (site / 'repositories', base.parent, base):
        if os.path.lexists(root):
            owner.protect_directory(root)
    paths = {key: base / key for key in CHECKOUTS}
    config = {}
    for key, path in paths.items():
        if os.path.lexists(path):
            owner.protect_directory(path)
            owner.protect_directory(path / '.git')
            owner.checked_file(path / '.git/config', 8192)
            revision = owner.fixed_git(path, 'rev-parse', '--verify', 'HEAD').strip().decode()
            p.digest(revision, 40)
            config[CHECKOUTS[key]] = revision
    cache = site / 'standards'
    return paths, config, cache, private_standards(cache)


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
    lock = require_private_directory(ensure_directory(site)) / '.source-provision.lock'
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
        if 'commit' in retained:
            owner.verify_bundle(paths['acquired'])
        credentials = {}
        if len(retained) != len(CHECKOUTS):
            credentials[repository] = select_credential(repository, ask)
        if missing_standards:
            credentials[STANDARD_REPOSITORY] = select_credential(STANDARD_REPOSITORY, ask)
        with tempfile.TemporaryDirectory(prefix=STAGE_PREFIX, dir=intake.site) as directory:
            stage = Path(directory)
            effective_paths = dict(paths)
            for key, setting in CHECKOUTS.items():
                if setting not in retained:
                    checkout = effective_paths[key] = stage / key
                    checkout.mkdir(mode=0o700)
                    checkout_exact(checkout, repository, config[setting], acquired=key == 'acquired', secret=credentials[repository][0])
            owner.verify_startup_adoption(repository, effective_paths['startup'], config['startup_revision'])
            effective_cache = standards_at(stage, credentials[STANDARD_REPOSITORY][0]) if missing_standards else cache
            intake.verify_source(repository, config, effective_paths['acquired'], effective_paths['startup'],
                                 effective_cache, checklist=workload == owner.CHECKLIST)
            for origin, (secret, replace) in credentials.items():
                if replace:
                    store_credential(origin, secret)
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


def rotate(first, incoming, outgoing):
    def say(message):
        print(message, file=outgoing, flush=True)

    def ask(prompt):
        return owner.setup_answer(incoming, outgoing, prompt)

    try:
        if first.configured() is None:
            say('Run the attended owner setup to approve the first repository and exact commits.')
            return
        repositories, _ = first.intake.catalogue_settings()
        repository = owner.repository_id(ask('Approved project repository or oso-gato/standards (owner/name)'))
        p.require(repository == STANDARD_REPOSITORY or repository in repositories,
                  'Select a repository in the approved catalogue or the adopted standards.')
        revision = p.STANDARDS if repository == STANDARD_REPOSITORY else repositories[repository]['commit']
        say(f'Check replacement read access to {https_origin(repository)} at {revision}.')
        if ask('Rotate the stored credential after this exact read check? [y/N]').lower() not in ('y', 'yes'):
            say('Credential rotation was deferred.')
            return
        with provision_lock(first.site):
            read_credential(repository)
            secret = read_token(repository, required=True)
            with tempfile.TemporaryDirectory(prefix=STAGE_PREFIX, dir=first.site) as directory:
                stage = Path(directory)
                if repository == STANDARD_REPOSITORY:
                    standards_at(stage, secret)
                else:
                    fetch(stage, repository, revision, shallow=True, secret=secret)
            store_credential(repository, secret)
        say('The verified repository read credential is in root custody.')
    except owner.SitePending as wait:
        say(wait.observation['message'])
    except (EOFError, KeyboardInterrupt):
        say('Credential rotation was interrupted. Retry the same attended command.')


if __name__ == '__main__':
    try:
        if len(sys.argv) == 5 and sys.argv[1] == '--git-credential':
            if sys.argv[4] == 'get':
                p.require(all(stat.S_ISFIFO(os.fstat(stream.fileno()).st_mode) for stream in (sys.stdin, sys.stdout)),
                          'Repository credential exchange requires Git protocol pipes.')
            credential_exchange(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.stdin.buffer, sys.stdout.buffer)
        else:
            raise SystemExit(2)
    except (OSError, ValueError, owner.SitePending):
        raise SystemExit(2) from None
