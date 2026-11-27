"""External, protected renewal of the existing role registries and job ledger."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_protocol as protocol
from ledger_recovery import backup, restore, read_private, sync_directory, trusted_directory, write_private
from session_controller import Observer, Registry, ROLES, STANDARDS, canonical, digest, loads, require, session, sha, token

SCOPE_COMPONENTS = {'agent': {'maintenance-agent', 'development-agent'},
                    'devbox': {'devbox'}, 'host': {'host'}}
COMPONENTS = set.union(*SCOPE_COMPONENTS.values())
TERMINAL = {'completed', 'rolled-back', 'deferred'}
MAX_CONTROL = 8 * 1024 * 1024
MAX_JOBS = 64
MAX_SESSIONS = 16
MAX_ATTEMPTS = 32
MIN_FREE_BYTES = 8 * 1024 ** 3
DEFAULT_ROOT = Path('/var/lib/dev-pair')
DEFAULT_DRIVER = Path('/usr/libexec/dev-pair/renewal/driver')
LEDGER_USER = 'dp-checklist'


def json_bytes(value):
    return canonical(value).encode()


def identity(value):
    return sha(json_bytes(value))


def diagnostic(error):
    record = {'type': type(error).__name__}
    if isinstance(error, ValueError) and type(error) is ValueError:
        record['reason'] = str(error)[:256]
    if isinstance(error, OSError) and error.errno is not None:
        record['errno'] = error.errno
    return record


def read_json(path):
    return loads(read_private(path, MAX_CONTROL))


def replace_json(path, value):
    data = json_bytes(value)
    require(len(data) <= MAX_CONTROL, 'renewal control record exceeds byte limit')
    fd, name = tempfile.mkstemp(prefix='.renewal-', dir=path.parent)
    with os.fdopen(fd, 'wb') as stream:
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(name, path)
            sync_directory(path.parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def create_directory(path):
    path.mkdir(mode=0o700)
    sync_directory(path.parent)
    return path


def checked_release(value):
    protocol.fields(value, 'schema source_revision config_sha256 plan_sha256 ledger_contract state_contract components')
    require(type(value['schema']) is int and value['schema'] == 1, 'unsupported renewal manifest')
    protocol.digest(value['source_revision'], 40)
    digest(value['config_sha256'])
    digest(value['plan_sha256'])
    require(type(value['ledger_contract']) is int and value['ledger_contract'] == protocol.VERSION and
            type(value['state_contract']) is int and value['state_contract'] == 1,
            'incompatible renewal state contract')
    components = value['components']
    require(type(components) is dict and set(components) == COMPONENTS, 'incomplete release components')
    for name, component in components.items():
        agent = name in SCOPE_COMPONENTS['agent']
        protocol.fields(component, 'source_revision config_sha256 artifact_sha256' + (' codex_version' if agent else ''))
        protocol.digest(component['source_revision'], 40)
        digest(component['config_sha256'])
        digest(component['artifact_sha256'])
        if agent:
            require(type(component['codex_version']) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', component['codex_version']),
                    'release does not name a stable Codex version')
    require(value['config_sha256'] == components['host']['config_sha256'], 'host release configuration mismatch')
    return value


def checked_request(value, scope):
    protocol.fields(value, 'schema operation scope previous_sha256 target_sha256 affected_jobs reason')
    require(type(value['schema']) is int and value['schema'] == 1 and value['scope'] == scope,
            'renewal request scope or schema mismatch')
    token(value['operation'])
    digest(value['previous_sha256'])
    digest(value['target_sha256'])
    protocol.text(value['reason'], 512)
    jobs = value['affected_jobs']
    require(type(jobs) is list and len(jobs) <= MAX_JOBS, 'invalid affected jobs')
    for job in jobs:
        token(job)
    require(jobs == sorted(set(jobs)), 'ambiguous affected jobs')
    return value


class SiteDriver:
    """The executable is installed by the external controller, never from a job."""

    def __init__(self, path, timeout=180):
        self.path = path
        self.timeout = timeout

    def invoke(self, action, payload):
        for part in (self.path, *self.path.parents):
            node = part.lstat()
            require(not stat.S_ISLNK(node.st_mode) and node.st_uid in (0, os.getuid()) and
                    (not node.st_mode & 0o022 or node.st_uid == 0 and node.st_mode & stat.S_ISVTX),
                    'untrusted renewal driver path')
        require(stat.S_ISREG(self.path.stat().st_mode), 'renewal driver is not a regular file')
        # Adapter output is bounded. A timed-out or broken adapter is never proof of cleanup.
        with tempfile.TemporaryFile() as output:
            completed = subprocess.run([str(self.path), action], input=json_bytes(payload), stdout=output,
                                       stderr=subprocess.DEVNULL, timeout=self.timeout, check=False,
                                       env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            require(completed.returncode == 0, 'renewal driver failed: ' + action)
            require(output.tell() <= MAX_CONTROL, 'renewal driver output limit')
            output.seek(0)
            return loads(output.read(MAX_CONTROL + 1))


class LedgerAccess:
    """Keep the app ledger under the same UID checked by its own recovery API."""

    def __init__(self, root, user=None):
        self.root = root
        self.path = root / 'checklist-executor' / 'ledger' if root == DEFAULT_ROOT else root / 'ledger'
        self.user = user

    def remote(self, action, value):
        require(self.root == DEFAULT_ROOT and os.geteuid() == 0 and self.user == LEDGER_USER,
                'cross-UID ledger helper is restricted to the installed controller')
        command = ['/usr/sbin/runuser', '--user', LEDGER_USER, '--', '/usr/bin/python3', '-I',
                   str(Path(__file__).resolve()), '__ledger-helper', action, value]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=30, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        require(completed.returncode == 0 and len(completed.stdout) <= MAX_CONTROL, 'ledger helper rejected operation')
        return loads(completed.stdout)

    def checkpoint(self, job):
        token(job)
        if self.user is not None:
            return self.remote('checkpoint', job)
        ledger = protocol.Ledger(self.path)
        try:
            with ledger.transaction():
                row = ledger.db.execute('SELECT checkpoint FROM jobs WHERE id=?', (job,)).fetchone()
                require(row is not None and row['checkpoint'] is not None, 'current job checkpoint unavailable')
                return [ledger.controller_id, ledger.record('job', job), ledger.record('checkpoint', row['checkpoint'])]
        finally:
            ledger.close()

    def inventory(self, path=None):
        if self.user is not None and path is None:
            return self.remote('inventory', '-')
        ledger = protocol.Ledger(path or self.path)
        try:
            with ledger.transaction():
                jobs = ledger.db.execute('SELECT id,checkpoint FROM jobs ORDER BY id LIMIT ?', (MAX_JOBS + 1,)).fetchall()
                require(len(jobs) <= MAX_JOBS, 'job catalogue exceeds bound')
                statuses = ledger.db.execute('SELECT id FROM requests ORDER BY id LIMIT 4097').fetchall()
                require(len(statuses) <= 4096, 'host request catalogue exceeds bound')
                requests = {}
                for row in statuses:
                    status = ledger.status(row['id'])
                    requests[row['id']] = {
                        'job': status['request']['job_id'], 'checkpoint': status['request']['checkpoint_id'],
                        'request_sha256': protocol.identity(status['request']), 'state': status['state'],
                        'attempt_id': status['attempt_id'],
                        'result_sha256': protocol.identity(status['result']) if status['result'] else None,
                    }
                return {'controller': ledger.controller_id,
                        'jobs': {row['id']: row['checkpoint'] for row in jobs}, 'requests': requests}
        finally:
            ledger.close()

    def capture(self, operation, destination, verification, deadline):
        if self.user is None:
            receipt = backup(self.path, destination, deadline)
        else:
            exchange = self.root / 'ledger-exchanges' / operation
            owner = pwd.getpwnam(self.user)
            exchange.mkdir(mode=0o700)
            os.chown(exchange, owner.pw_uid, owner.pw_gid)
            sync_directory(exchange.parent)
            receipt = self.remote('capture', operation)
            create_directory(destination)
            for name, limit in (('RECOVERY', 16384), ('COMPLETE', 16384), ('manifest.json', 16384),
                                ('snapshot.sqlite3', 16 * 1024 * 1024)):
                source = exchange / 'backup' / name
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    node = os.fstat(stream.fileno())
                    require(stat.S_ISREG(node.st_mode) and node.st_uid == owner.pw_uid and
                            node.st_nlink == 1 and node.st_size <= limit, 'invalid cross-UID ledger backup file')
                    data = stream.read(limit + 1)
                    require(len(data) <= limit, 'ledger exchange exceeded byte limit')
                write_private(destination / name, data)
            sync_directory(destination)
            # The helper is done and the authoritative, verified copy is now under renewal custody.
            shutil.rmtree(exchange)
            sync_directory(exchange.parent)
        restored = restore(destination, verification, deadline)
        require(restored['manifest_sha256'] == receipt['manifest_sha256'], 'ledger backup transfer changed')
        return receipt


def ledger_helper(action, value):
    require(pwd.getpwuid(os.getuid()).pw_name == LEDGER_USER, 'invalid ledger helper account')
    access = LedgerAccess(DEFAULT_ROOT)
    if action == 'inventory':
        return access.inventory()
    if action == 'checkpoint':
        return access.checkpoint(value)
    require(action == 'capture', 'unknown ledger helper action')
    token(value)
    exchange = trusted_directory(DEFAULT_ROOT / 'ledger-exchanges' / value)
    return backup(access.path, exchange / 'backup', time.monotonic() + 10)


class TreeCopy:
    """Hash or copy quiescent durable data without opening special files or symlinks."""

    def __init__(self, byte_limit, deadline):
        self.remaining = byte_limit
        self.deadline = deadline
        self.entries = 100000

    def visit(self, source, destination=None):
        result = hashlib.sha256()
        require(stat.S_ISDIR(source.lstat().st_mode), 'durable tree is missing or unsafe')
        self.walk(source, destination, '', result, source.lstat().st_dev)
        return result.hexdigest()

    def walk(self, source, destination, relative, result, device):
        self.entries -= 1
        require(self.entries >= 0 and time.monotonic() < self.deadline, 'renewal tree limit')
        info = source.lstat()
        require(info.st_dev == device, 'durable tree crosses a mount')
        mode = stat.S_IMODE(info.st_mode)
        attrs = {}
        for name in sorted(os.listxattr(source, follow_symlinks=False)):
            value = os.getxattr(source, name, follow_symlinks=False)
            self.remaining -= len(value)
            require(self.remaining >= 0, 'renewal backup byte limit')
            attrs[name] = value
        metadata = [relative, mode, info.st_uid, info.st_gid,
                    {name: base64.b64encode(value).decode('ascii') for name, value in attrs.items()}]
        if stat.S_ISDIR(info.st_mode):
            result.update(json_bytes([*metadata, 'directory']) + b'\n')
            if destination is not None:
                destination.mkdir(mode=0o700)
            names = sorted(p.name for p in source.iterdir())
            require(len(names) <= self.entries, 'renewal tree entry limit')
            for name in names:
                self.walk(source / name, destination / name if destination else None,
                          relative + '/' + name, result, device)
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(source)
            result.update(json_bytes([*metadata, 'symlink', target]) + b'\n')
            if destination is not None:
                destination.symlink_to(target)
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsupported durable tree entry')
            self.remaining -= info.st_size
            require(self.remaining >= 0, 'renewal backup byte limit')
            file_hash = hashlib.sha256()
            src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(src, 'rb') as stream, contextlib.ExitStack() as stack:
                held = os.fstat(stream.fileno())
                require(stat.S_ISREG(held.st_mode) and (held.st_dev, held.st_ino, held.st_size) ==
                        (info.st_dev, info.st_ino, info.st_size), 'durable source replaced during capture')
                target = stack.enter_context(destination.open('xb')) if destination is not None else None
                remaining = info.st_size
                while remaining:
                    require(time.monotonic() < self.deadline, 'renewal backup deadline')
                    data = stream.read(min(1024 * 1024, remaining))
                    require(data, 'durable source shrank during capture')
                    file_hash.update(data)
                    if target is not None:
                        target.write(data)
                    remaining -= len(data)
                require(not stream.read(1) and os.fstat(stream.fileno()).st_mtime_ns == info.st_mtime_ns,
                        'durable source changed during capture')
                if target is not None:
                    target.flush()
                    os.fsync(target.fileno())
            result.update(json_bytes([*metadata, 'file', info.st_size, file_hash.hexdigest()]) + b'\n')
        after = source.lstat()
        require((after.st_dev, after.st_ino, after.st_mtime_ns, after.st_mode) ==
                (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_mode), 'durable tree was modified')
        if destination is not None:
            copied = destination.lstat()
            if (copied.st_uid, copied.st_gid) != (info.st_uid, info.st_gid):
                os.chown(destination, info.st_uid, info.st_gid, follow_symlinks=False)
            for name, value in attrs.items():
                os.setxattr(destination, name, value, follow_symlinks=False)
            for name in set(os.listxattr(destination, follow_symlinks=False)) - attrs.keys():
                os.removexattr(destination, name, follow_symlinks=False)
            if not stat.S_ISLNK(info.st_mode):
                os.chmod(destination, mode, follow_symlinks=False)
                os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    sync_directory(destination)
                else:
                    fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)


class Renewal:
    def __init__(self, root, driver, byte_limit=512 * 1024 * 1024, seconds=240, *, ledger_user=None):
        self.root = root
        self.control = trusted_directory(root / 'renewal')
        self.driver = driver
        self.byte_limit = byte_limit
        self.seconds = seconds
        self.ledger = LedgerAccess(root, ledger_user)
        self.pointer = self.control / 'transition.json'

    @contextlib.contextmanager
    def lock(self, *, shared=False):
        path = self.control / 'owner.lock'
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path, flags, 0o600), 'rb+') as stream:
            node = os.fstat(stream.fileno())
            require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o600 and
                    node.st_uid == os.getuid() and node.st_nlink == 1, 'unsafe renewal owner lock')
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            require(path.stat().st_ino == node.st_ino, 'renewal owner lock changed')
            yield

    def transition(self):
        if not self.pointer.exists() and not self.pointer.is_symlink():
            return None, None
        operation = read_json(self.pointer)
        token(operation)
        attempt = trusted_directory(self.control / 'attempts' / operation)
        return attempt, read_json(attempt / 'journal.json')

    @contextlib.contextmanager
    def host_fence(self):
        path = self.root / 'renewal-fence'
        owner = path.lstat()
        require(stat.S_ISDIR(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o755 and
                owner.st_uid == os.getuid(), 'unsafe host effect fence')
        with os.fdopen(os.open(path / 'owner.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            node = os.fstat(stream.fileno())
            require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o644 and
                    node.st_uid == os.getuid() and node.st_nlink == 1, 'unsafe host effect lease')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def mark_host_fence(self, operation, *, frozen):
        marker = self.root / 'renewal-fence' / 'frozen'
        if marker.exists() or marker.is_symlink():
            require(read_json(marker) == operation, 'foreign host effect freeze')
            if not frozen:
                marker.unlink()
                sync_directory(marker.parent)
        elif frozen:
            replace_json(marker, operation)

    def release(self, reference):
        digest(reference)
        path = self.control / 'releases' / (reference + '.json')
        data = read_private(path, MAX_CONTROL)
        require(sha(data) == reference, 'renewal manifest digest mismatch')
        return checked_release(loads(data))

    def live_release(self):
        release = read_json(self.control / 'current.json')
        self.release(release)
        return release

    @contextlib.contextmanager
    def dispatch_gate(self, *, for_enrollment=False):
        """Required entry point for registry enrollment and ordinary role dispatch."""
        with self.lock(shared=not for_enrollment):
            _, state = self.transition()
            require(state is None or state['phase'] in TERMINAL, 'role dispatch frozen by renewal')
            yield self.live_release()

    def registry_path(self, role, job):
        require(role in ROLES, 'unknown role')
        token(job)
        return self.control / 'registries' / role / job

    def trees(self, role, job):
        return {kind: self.root / role / kind / job for kind in ('workspaces', 'state')}

    def register(self, binding):
        with self.dispatch_gate(for_enrollment=True):
            path = self.registry_path(binding['role'], binding['job_id'])
            staging = trusted_directory(self.control / 'registry-staging')
            with tempfile.TemporaryDirectory(dir=staging) as temporary:
                create = not os.path.lexists(path)
                registry = Registry(Path(temporary) / 'registry' if create else path, binding)
                try:
                    registry.role_checkpoint = self.ledger.checkpoint
                    checkpoint = registry.current_checkpoint()
                finally:
                    registry.close()
                if create:
                    registry.root.rename(path)
                    sync_directory(path.parent)
                return checkpoint

    def registries(self, stack):
        found = {}
        for role in ROLES:
            directory = trusted_directory(self.control / 'registries' / role)
            entries = sorted(directory.iterdir())
            require(0 < len(entries) <= MAX_JOBS, 'incomplete role registry catalogue')
            for path in entries:
                token(path.name)
                require(path.is_dir() and not path.is_symlink(), 'invalid catalogued role registry')
                registry = Registry(path)
                stack.callback(registry.close)
                binding = registry.meta['binding']
                require(binding.get('role') == role and binding['job_id'] == path.name, 'registry catalogue identity mismatch')
                registry.role_checkpoint = self.ledger.checkpoint
                found[role + '/' + path.name] = registry
        return found

    def role_turn(self, spec, prompt):
        """Run an ordinary approved start/resume through the same protected registry."""
        protocol.fields(spec, 'operation role job logical_session session_uuid request_sha256')
        for key in ('operation', 'job', 'logical_session'):
            token(spec[key])
        digest(spec['request_sha256'])
        if spec['session_uuid'] is not None:
            session(spec['session_uuid'])
        with contextlib.ExitStack() as owned:
            with self.dispatch_gate() as release:
                registry = Registry(self.registry_path(spec['role'], spec['job']))
                owned.callback(registry.close)
                registry.role_checkpoint = self.ledger.checkpoint
                require(registry.meta['binding'].get('role') == spec['role'] and
                        registry.meta['binding']['job_id'] == spec['job'], 'role turn registry binding changed')
                owned.enter_context(registry.owner())
                row, fresh = registry.reserve(spec['operation'], spec['logical_session'], prompt,
                                              time.monotonic() + 179, spec['session_uuid'],
                                              provider_request_sha256=spec['request_sha256'])
                if not fresh:
                    return row
                registry.admit_launch(spec['operation'])
                _, _, checkpoint = self.ledger.checkpoint(spec['job'])
            # Renewal can request freeze now but cannot seal this owned turn until it drains.
            try:
                require(protocol.identity(checkpoint) == row['checkpoint_sha256'], 'role turn checkpoint changed')
                proof = self.driver.invoke('turn', {**spec, 'release_sha256': release,
                                                   'prompt_sha256': row['prompt_sha256'],
                                                   'candidate_sha': checkpoint['candidate']['source_revision'],
                                                   'binding': registry.meta['binding']})
                self.check_proof(proof, spec, release, require_progress=False)
            except Exception:
                registry.update(spec['operation'], state='uncertain', reason='cleanup-unresolved')
                raise
            return registry.update(spec['operation'], state='completed-turn', exit_code=0,
                                   capture_complete=True, cleanup='owned-child-reaped',
                                   launch_handle_observed=True, uuid=proof['session_uuid'])

    def phase(self, attempt, state, phase, **fields):
        state.update(fields, phase=phase)
        replace_json(attempt / 'journal.json', state)

    def active_request(self, scope):
        request_path = self.control / 'requests' / (scope + '.json')
        if not request_path.exists() and not request_path.is_symlink():
            return None
        return checked_request(read_json(request_path), scope)

    def apply(self, scope):
        require(scope in SCOPE_COMPONENTS, 'unknown renewal scope')
        with self.lock():
            attempt, state = self.transition()
            if state is not None:
                if state['phase'] not in TERMINAL:
                    return self.resume(attempt, state)
                self.mark_host_fence(state['request']['operation'], frozen=False)
            request = self.active_request(scope)
            if request is None:
                return {'phase': 'no-approved-target', 'scope': scope}
            target = self.control / 'attempts' / request['operation']
            state = None
            if os.path.lexists(target):
                state = read_json(trusted_directory(target) / 'journal.json')
                require(state['request'] == request, 'renewal operation ID collision')
                if state['phase'] in TERMINAL:
                    return state
                require(state['phase'] == 'prepared' and not state['freezes'] and not state['proofs'],
                        'unpublished renewal attempt has consequential state')
            previous = self.release(request['previous_sha256'])
            replacement = self.release(request['target_sha256'])
            require(request['previous_sha256'] == self.live_release(), 'stale renewal previous digest')
            changed = {name for name in COMPONENTS if previous['components'][name] != replacement['components'][name]}
            require(changed and changed <= SCOPE_COMPONENTS[scope], 'renewal changes outside approved scope')
            if scope != 'host':
                require(previous['config_sha256'] == replacement['config_sha256'], 'host configuration changed outside host renewal')
            with self.host_fence():
                if state is None:
                    require(sum(1 for _ in (self.control / 'attempts').iterdir()) < MAX_ATTEMPTS,
                            'renewal backup retention bound')
                    with tempfile.TemporaryDirectory(dir=self.control / 'registry-staging') as temporary:
                        attempt = create_directory(Path(temporary) / 'attempt')
                        state = {'schema': 1, 'request': request, 'freezes': {}, 'proofs': {}}
                        self.phase(attempt, state, 'prepared')
                        attempt.rename(target)
                        sync_directory(target.parent)
                replace_json(self.pointer, request['operation'])
                self.mark_host_fence(request['operation'], frozen=True)
                return self.run(target, state)

    def refresh_agent_target(self):
        """Ask only the independently configured candidate service for an approval."""
        _, state = self.transition()
        if state is not None and state['phase'] not in TERMINAL:
            return True
        try:
            process = subprocess.run(['/usr/bin/systemctl', 'start', 'dev-pair-approved-agent-candidate.service'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=600, check=False)
            ready = process.returncode == 0
        except (OSError, subprocess.SubprocessError):
            ready = False
        status = {'schema': 1, 'observed_at': int(time.time()), 'release_sha256': self.live_release(),
                  'candidate_service': 'complete' if ready else 'unavailable'}
        replace_json(self.control / 'agent-refresh.json', status)
        return ready

    def resume(self, attempt, state):
        with self.host_fence():
            self.mark_host_fence(state['request']['operation'], frozen=True)
            return self.recover(attempt, state)

    def payload(self, state, reference):
        request = state['request']
        return {'operation': request['operation'], 'scope': request['scope'],
                'release_sha256': reference, 'release': self.release(reference)}

    def verify_driver(self, action, state, reference):
        payload = self.payload(state, reference)
        evidence = self.driver.invoke(action, payload)
        protocol.fields(evidence, 'release_sha256 components')
        require(evidence['release_sha256'] == reference and evidence['components'] == payload['release']['components'],
                'external release identity mismatch: ' + action)
        return evidence

    def freeze(self, attempt, state, registries):
        for key, registry in registries.items():
            binding = registry.meta['binding']
            current = registry.inventory()['dispatch']
            attempt_id = state['request']['operation']
            generation = (current['identity']['requested_generation'] if current['state'] == 'frozen'
                          else current['generation'])
            receipt = registry.request_freeze(attempt_id, generation, binding)
            require(key not in state['freezes'] or state['freezes'][key] == receipt, 'renewal freeze identity changed')
            state['freezes'][key] = receipt
            self.phase(attempt, state, 'freezing')

    def drain(self, registries):
        deadline = time.monotonic() + 185
        with contextlib.ExitStack() as stack:
            observers = []
            for registry in registries.values():
                observer = Observer(registry.root)
                stack.callback(observer.close)
                observers.append(observer)
            for observer in observers:
                while True:
                    view = observer.inventory()
                    require(all(row['state'] != 'uncertain' for row in view['operations']),
                            'role operation ownership requires reconciliation')
                    if view['owner_lease_observed'] == 'unheld':
                        break
                    require(time.monotonic() < deadline, 'role drain deadline exceeded')
                    time.sleep(0.05)

    def capture(self, attempt, state, registries):
        deadline = time.monotonic() + self.seconds
        capacity = os.statvfs(attempt)
        require(capacity.f_bavail * capacity.f_frsize >= MIN_FREE_BYTES + self.byte_limit,
                'renewal requires free capacity for backup and protected reserve')
        tree_copy = TreeCopy(self.byte_limit, deadline)
        backup_root = create_directory(attempt / 'backup')
        verification = create_directory(attempt / 'verified-restore')
        host = self.ledger.inventory()
        require(set(host['jobs']) == {registry.meta['binding']['job_id'] for registry in registries.values()},
                'role catalogue and job ledger differ')
        require(set(state['request']['affected_jobs']) <= set(host['jobs']), 'unknown affected product job')
        require(all(row['state'] != 'in-flight' for row in host['requests'].values()),
                'host effects require reconciliation before renewal')
        ledger_receipt = self.ledger.capture(state['request']['operation'], backup_root / 'ledger',
                                            verification / 'ledger', min(deadline, time.monotonic() + 30))
        require(self.ledger.inventory(verification / 'ledger') == host, 'restored job ledger identity changed')
        entries = {}
        sessions = []
        for key, registry in registries.items():
            role, job = key.split('/')
            checkpoint = registry.current_checkpoint()
            require(checkpoint['checkpoint_id'] == host['jobs'][job], 'current checkpoint changed during backup')
            snapshot = registry.seal_snapshot(state['freezes'][key], registry.meta['binding'])
            require(len(sessions) + len(snapshot['sessions']) <= MAX_SESSIONS, 'active session count exceeds renewal allowance')
            proof = self.driver.invoke('verify-sessions', {'role': role, 'job': job, 'sessions': snapshot['sessions'],
                                                         'binding': registry.meta['binding']})
            require(proof == {'sessions': snapshot['sessions']}, 'durable provider catalogue does not match registry')
            registry_name = role + '--' + job
            group = create_directory(backup_root / registry_name)
            replace_json(group / 'registry.json', snapshot)
            restored = Registry(verification / registry_name, snapshot['binding'])
            try:
                restored.restore_sealed(snapshot)
                require(restored.inventory()['dispatch']['snapshot'] == snapshot, 'registry restoration mismatch')
            finally:
                restored.close()
            data = {kind: tree_copy.visit(path, group / kind) for kind, path in self.trees(role, job).items()}
            sync_directory(group)
            pending_host = [request_id for request_id, row in host['requests'].items()
                            if row['job'] == job and row['state'] == 'pending']
            deferred_turns = [row['operation'] for row in snapshot['operations'] if row['state'] == 'deferred']
            entries[key] = {'registry_sha256': identity(snapshot), 'checkpoint': checkpoint, 'trees': data,
                            'pending_host': pending_host, 'deferred_turns': deferred_turns}
            for active in snapshot['sessions']:
                sessions.append({'role': role, 'job': job, 'logical_session': active['logical_session'],
                                 'provider_uuid': active['uuid'], 'checkpoint': checkpoint,
                                 'uncommitted_source_sha256': data['workspaces'],
                                 'session_state_sha256': data['state'], 'pending_host': pending_host,
                                 'deferred_turns': deferred_turns, 'target_sha256': state['request']['target_sha256'],
                                 'config_sha256': registry.meta['binding']['policy_sha256'],
                                 'credential_ref': registry.meta['binding']['credential_ref'],
                                 'standards_sha': STANDARDS})
        inventory = {'schema': 1, 'operation': state['request']['operation'],
                     'target_sha256': state['request']['target_sha256'], 'host': host,
                     'ledger_manifest_sha256': ledger_receipt['manifest_sha256'],
                     'registries': entries, 'sessions': sessions}
        backup_check = TreeCopy(self.byte_limit, deadline)
        for key, entry in entries.items():
            group = backup_root / key.replace('/', '--')
            for kind, saved in entry['trees'].items():
                require(backup_check.visit(group / kind) == saved, 'durable backup verification failed')
        replace_json(attempt / 'inventory.json', inventory)
        self.phase(attempt, state, 'backed-up', inventory_sha256=identity(inventory))
        return inventory

    def checked_inventory(self, attempt, state):
        inventory = read_json(attempt / 'inventory.json')
        require(identity(inventory) == state['inventory_sha256'], 'renewal inventory integrity mismatch')
        return inventory

    def confirm_tree(self, inventory, *, state_unchanged=False):
        tree_copy = TreeCopy(self.byte_limit, time.monotonic() + self.seconds)
        for key, entry in inventory['registries'].items():
            role, job = key.split('/')
            for kind, path in self.trees(role, job).items():
                if kind == 'workspaces' or state_unchanged:
                    require(tree_copy.visit(path) == entry['trees'][kind], 'renewal lost durable tree data')

    def confirm_registries(self, attempt, inventory, stack):
        for key, entry in inventory['registries'].items():
            role, job = key.split('/')
            snapshot = read_json(attempt / 'backup' / (role + '--' + job) / 'registry.json')
            require(identity(snapshot) == entry['registry_sha256'], 'registry backup integrity mismatch')
            path = self.registry_path(role, job)
            if not os.path.lexists(path):
                with tempfile.TemporaryDirectory(dir=self.control / 'registry-staging') as temporary:
                    registry = Registry(Path(temporary) / 'registry', snapshot['binding'])
                    try:
                        registry.restore_sealed(snapshot)
                    finally:
                        registry.close()
                    registry.root.rename(path)
                    sync_directory(path.parent)
        registries = self.registries(stack)
        require(set(registries) == set(inventory['registries']), 'restored role catalogue changed')
        for key, registry in registries.items():
            snapshot = registry.inventory()['dispatch']['snapshot']
            require(identity(snapshot) == inventory['registries'][key]['registry_sha256'], 'restored role identity changed')
        return registries

    def verify_pending(self, inventory):
        before = inventory['host']
        after = self.ledger.inventory()
        require(after == before, 'host operation/checkpoint changed during renewal')

    def check_proof(self, proof, spec, release, *, require_progress=True):
        protocol.fields(proof, 'release_sha256 operation role job logical_session session_uuid request_sha256 '
                        'events_sha256 progress_sha256 child_reaped provider_receipt_sha256')
        for field in ('operation', 'role', 'job', 'logical_session'):
            require(proof[field] == spec[field], 'role resume identity changed')
        session(proof['session_uuid'])
        require(spec['session_uuid'] is None or proof['session_uuid'] == spec['session_uuid'], 'provider UUID changed')
        require(proof['release_sha256'] == release and proof['child_reaped'] is True,
                'role release or child ownership unverified')
        digest(proof['request_sha256'])
        if 'request_sha256' in spec:
            require(proof['request_sha256'] == spec['request_sha256'], 'role request digest changed')
        digest(proof['events_sha256'])
        digest(proof['provider_receipt_sha256'])
        if require_progress or proof['progress_sha256'] is not None:
            digest(proof['progress_sha256'])

    def resume_payloads(self, state, reference, inventory, registries):
        for saved in inventory['sessions']:
            key = saved['role'] + '/' + saved['job']
            registry = registries[key]
            operation = 'renew-' + identity([state['request']['operation'], reference,
                                             saved['role'], saved['job'], saved['logical_session']])[:50]
            spec = {'operation': operation, 'role': saved['role'], 'job': saved['job'],
                    'logical_session': saved['logical_session'], 'session_uuid': saved['provider_uuid']}
            origin = next(row for row in registry.inventory()['operations']
                          if row['mode'] == 'start' and row['logical_session'] == saved['logical_session'])
            _, _, checkpoint = self.ledger.checkpoint(saved['job'])
            require(protocol.identity(checkpoint) == saved['checkpoint']['checkpoint_sha256'], 'resume checkpoint changed')
            payload = {**self.payload(state, reference), **spec, 'activation_operation': state['request']['operation'],
                       'checkpoint': saved['checkpoint'], 'binding': registry.meta['binding'],
                       'candidate_sha': checkpoint['candidate']['source_revision'],
                       'start_operation': origin['operation'], 'start_request_sha256': origin['provider_request_sha256'],
                       'pending_host': saved['pending_host']}
            yield spec, payload

    def readiness(self, attempt, state, inventory, registries):
        prepared = {}
        required_funds = {}
        deadline = int(time.time()) + 360 * len(inventory['sessions']) + 240
        keys = ('target_sha256', 'previous_sha256')
        for key in keys:
            reference = state['request'][key]
            for spec, payload in self.resume_payloads(state, reference, inventory, registries):
                approved = self.driver.invoke('preflight-resume', {**payload, 'minimum_grant_valid_until': deadline})
                protocol.fields(approved, 'operation request_sha256 job allowance_sha256 spend_microusd')
                require(approved['operation'] == spec['operation'] and approved['job'] == spec['job'],
                        'continuity preflight identity changed')
                digest(approved['request_sha256'])
                digest(approved['allowance_sha256'])
                protocol.number(approved['spend_microusd'], 1, 100000000)
                account = (approved['job'], approved['allowance_sha256'])
                required_funds[account] = required_funds.get(account, 0) + approved['spend_microusd']
                prepared[spec['operation']] = approved['request_sha256']
        require(len({job for job, _ in required_funds}) == len(required_funds), 'continuity allowances disagree within a job')
        allowance_proofs = []
        for (job, evidence), total in required_funds.items():
            approval = self.driver.invoke('preflight-allowance', {'job': job, 'allowance_sha256': evidence,
                                                                  'needed_microusd': total,
                                                                  'minimum_grant_valid_until': deadline,
                                                                  'release_sha256': state['request']['previous_sha256']})
            protocol.fields(approval, 'job allowance_sha256 remaining_microusd')
            require(approval['job'] == job and approval['allowance_sha256'] == evidence and
                    type(approval['remaining_microusd']) is int and approval['remaining_microusd'] >= total,
                    'authoritative continuity budget cannot cover recovery')
            allowance_proofs.append({**approval, 'required_microusd': total})
        self.phase(attempt, state, 'backed-up', continuity_requests=prepared, allowance_proofs=allowance_proofs)

    def prove(self, attempt, state, reference, inventory, registries, recovery=False):
        phase = 'rollback-verifying' if recovery else 'verifying'
        self.phase(attempt, state, phase)
        for spec, payload in self.resume_payloads(state, reference, inventory, registries):
            operation = spec['operation']
            proof = state['proofs'].get(operation)
            if proof is None:
                proof = self.driver.invoke('resume-without-effects', payload)
            self.check_proof(proof, {**spec, 'request_sha256': state['continuity_requests'][operation]}, reference)
            state['proofs'][operation] = proof
            self.phase(attempt, state, phase)
        self.confirm_tree(inventory)
        self.verify_pending(inventory)
        self.verify_driver('observe', state, reference)

    def thaw(self, attempt, state, terminal, registries=None):
        with contextlib.ExitStack() as stack:
            if registries is None:
                registries = self.registries(stack)
            for key, registry in registries.items():
                dispatch = registry.inventory()['dispatch']
                receipt = state['freezes'].get(key)
                if receipt is None and dispatch['state'] == 'frozen':
                    # The coordinator can die after SQLite commits but before its journal write.
                    candidate = dispatch['identity']
                    if candidate['attempt'] == state['request']['operation']:
                        receipt = candidate
                if receipt is not None:
                    binding = registry.meta['binding']
                    if terminal == 'deferred':
                        registry.cancel_unactivated(receipt, binding)
                    else:
                        registry.abort_freeze(receipt, binding)
            self.phase(attempt, state, terminal)
            self.mark_host_fence(state['request']['operation'], frozen=False)
        return state

    def run(self, attempt, state):
        request = state['request']
        previous, replacement = request['previous_sha256'], request['target_sha256']
        try:
            with contextlib.ExitStack() as stack:
                registries = self.registries(stack)
                self.verify_driver('observe', state, previous)
                self.verify_driver('validate', state, replacement)
                self.freeze(attempt, state, registries)
                self.drain(registries)
                inventory = self.capture(attempt, state, registries)
                self.readiness(attempt, state, inventory, registries)
            self.verify_pending(inventory)
            self.phase(attempt, state, 'applying')
            self.verify_driver('activate', state, replacement)
            self.confirm_tree(inventory, state_unchanged=True)
            with contextlib.ExitStack() as stack:
                registries = self.confirm_registries(attempt, inventory, stack)
                self.prove(attempt, state, replacement, inventory, registries)
                self.phase(attempt, state, 'accepted')
                replace_json(self.control / 'current.json', replacement)
                return self.thaw(attempt, state, 'completed', registries)
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
            # Keep cause text out of user-visible records. The external adapter owns its diagnostics.
            self.phase(attempt, state, state['phase'], failure=diagnostic(error))
            return self.recover(attempt, state)

    def restore_trees(self, attempt, state, inventory):
        tree_copy = TreeCopy(self.byte_limit, time.monotonic() + self.seconds)
        operation = state['request']['operation']
        for key, entry in inventory['registries'].items():
            role, job = key.split('/')
            group = attempt / 'backup' / (role + '--' + job)
            for kind, live in self.trees(role, job).items():
                saved = entry['trees'][kind]
                if live.exists() and TreeCopy(self.byte_limit, tree_copy.deadline).visit(live) == saved:
                    continue
                stage = live.with_name('.renewal-' + operation + '-' + job)
                failed = live.with_name('.replaced-' + operation + '-' + job)
                if not os.path.lexists(stage):
                    with tempfile.TemporaryDirectory(prefix='.restore-', dir=live.parent) as temporary:
                        part = Path(temporary) / 'data'
                        require(tree_copy.visit(group / kind, part) == saved, 'work or session backup hash mismatch')
                        part.rename(stage)
                        sync_directory(stage.parent)
                require(TreeCopy(self.byte_limit, tree_copy.deadline).visit(stage) == saved, 'restore staging is incomplete')
                if live.exists():
                    require(not failed.exists() and not failed.is_symlink(), 'restore already retained changed state')
                    live.rename(failed)
                    sync_directory(live.parent)
                stage.rename(live)
                sync_directory(live.parent)
        self.confirm_tree(inventory, state_unchanged=True)

    def recover(self, attempt, state):
        phase = state['phase']
        if phase == 'accepted':
            self.verify_driver('observe', state, state['request']['target_sha256'])
            self.verify_pending(self.checked_inventory(attempt, state))
            replace_json(self.control / 'current.json', state['request']['target_sha256'])
            return self.thaw(attempt, state, 'completed')
        if phase in ('prepared', 'freezing', 'backed-up'):
            self.verify_driver('observe', state, state['request']['previous_sha256'])
            return self.thaw(attempt, state, 'deferred')
        if phase == 'rollback-accepted':
            self.verify_driver('observe', state, state['request']['previous_sha256'])
            self.verify_pending(self.checked_inventory(attempt, state))
            return self.thaw(attempt, state, 'rolled-back')
        if phase == 'blocked':
            return state
        if phase == 'rollback-verifying':
            previous = state['request']['previous_sha256']
            inventory = self.checked_inventory(attempt, state)
            try:
                self.verify_driver('observe', state, previous)
                self.verify_pending(inventory)
                with contextlib.ExitStack() as stack:
                    self.prove(attempt, state, previous, inventory,
                               self.confirm_registries(attempt, inventory, stack), recovery=True)
                self.phase(attempt, state, 'rollback-accepted')
                return self.thaw(attempt, state, 'rolled-back')
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
                self.phase(attempt, state, 'blocked', rollback_failure=diagnostic(error))
                return state
        require(phase in ('applying', 'verifying', 'rolling-back'), 'unknown renewal transition phase')
        previous = state['request']['previous_sha256']
        inventory = self.checked_inventory(attempt, state)
        attempts = state.get('rollback_attempts', 0)
        if attempts >= 2:
            self.phase(attempt, state, 'blocked')
            return state
        self.phase(attempt, state, 'rolling-back', rollback_attempts=attempts + 1)
        try:
            self.verify_driver('quiesce', state, previous)
            with contextlib.ExitStack() as stack:
                registries = self.confirm_registries(attempt, inventory, stack)
                self.restore_trees(attempt, state, inventory)
                self.verify_pending(inventory)
                self.verify_driver('activate', state, previous)
                self.prove(attempt, state, previous, inventory, registries, recovery=True)
            self.phase(attempt, state, 'rollback-accepted')
            return self.thaw(attempt, state, 'rolled-back')
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
            self.phase(attempt, state, 'blocked', rollback_failure=diagnostic(error))
            return state


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '__ledger-helper':
        print(canonical(ledger_helper(*sys.argv[2:])))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    reconcile = sub.add_parser('reconcile')
    reconcile.add_argument('scope', choices=SCOPE_COMPONENTS)
    reconcile.add_argument('--check-candidate', action='store_true')
    sub.add_parser('status')
    sub.add_parser('recover')
    for command in ('register', 'turn'):
        command_parser = sub.add_parser(command)
        command_parser.add_argument('input', type=Path)
        if command == 'turn':
            command_parser.add_argument('prompt', type=Path)
    args = parser.parse_args()
    try:
        controller = Renewal(DEFAULT_ROOT, SiteDriver(DEFAULT_DRIVER), ledger_user=LEDGER_USER)
        if args.command == 'reconcile':
            if args.scope == 'agent' and args.check_candidate and not controller.refresh_agent_target():
                result = {'phase': 'candidate-unavailable', 'scope': args.scope,
                          'retained_release_sha256': controller.live_release()}
            else:
                result = controller.apply(args.scope)
        elif args.command == 'status':
            _, result = controller.transition()
        elif args.command == 'recover':
            with controller.lock():
                attempt, result = controller.transition()
                if result and result['phase'] not in TERMINAL:
                    result = controller.resume(attempt, result)
                elif result:
                    controller.mark_host_fence(result['request']['operation'], frozen=False)
        elif args.command == 'register':
            result = controller.register(read_json(args.input))
        else:
            prompt = read_private(args.prompt, 262144).decode()
            result = controller.role_turn(read_json(args.input), prompt)
        print(canonical(result))
        return 2 if result and result.get('phase') == 'blocked' else 0
    except BlockingIOError:
        parser.exit(75, 'renewal deferred while a trusted owner holds the lease\n')
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(2, 'renewal rejected: ' + type(error).__name__ + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
