#!/usr/bin/python3
"""Image-owned gptbox assembly and fixed headless role entry."""
from contextlib import suppress
import ctypes
import fcntl
import grp
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import tomllib
import uuid

BASE = Path('/usr/lib/dev-pair/gptbox')
CODEX = Path('/opt/dev-pair/bin/codex')
WORK = Path('/work/job')
BUILD = '/build/job'
STATE = Path('/state')
CODEX_HOME = STATE / 'codex'
REQUIREMENTS = Path('/etc/codex/requirements.toml')
TURN_INPUTS = Path('/run/dev-pair-turn')
CREDENTIAL = Path('/credentials/api-key')
LOADER_FILES = ('config.toml', 'hooks.json', 'AGENTS.md', 'AGENTS.override.md')
LOADER_DIRS = ('skills', 'plugins', 'rules', 'agents', 'shell_snapshots', '.tmp/plugins', '.tmp/marketplaces')
TURN_READONLY_MOUNTS = (REQUIREMENTS.parent, TURN_INPUTS, CREDENTIAL.parent,
                        *(CODEX_HOME / name for name in (*LOADER_FILES, *LOADER_DIRS)))
PROVIDER_DIR = Path('/run/dev-pair-provider')
PROVIDER_SOCKET = PROVIDER_DIR / 'responses.sock'
OFFLINE_CONFIG_FILES = ('/etc/hostname', '/etc/hosts', '/etc/resolv.conf')
REPOSITORY_APPROVALS = Path('/var/lib/dev-pair/repository-approvals')
JOB_READONLY_MOUNTS = (REQUIREMENTS.parent, TURN_INPUTS, PROVIDER_DIR,
                       *(CODEX_HOME / name for name in (*LOADER_FILES, *LOADER_DIRS)))
JOB_INPUTS = {'/etc/codex': 'requirements', str(TURN_INPUTS): 'turn',
              **{str(CODEX_HOME / name): 'loaders/' + name for name in (*LOADER_FILES, *LOADER_DIRS)}}
STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
OFFLINE_KEY = b'dev-pair-offline-synthetic-not-a-credential'
# This public marker satisfies Codex's local API-key check. The credential is
# held by the host broker and never crosses this boundary.
LOCAL_BEARER = 'dev-pair-local-provider-bridge'
OPERATION = re.compile(r'[a-z0-9][a-z0-9-]{0,63}')
JOB = re.compile(r'[a-z0-9][a-z0-9-]{0,47}')
HEX_SHA = re.compile(r'[0-9a-f]{64}')
STARTUP_IDS = ('project-readme', 'project-standards', 'project-requirements', 'project-architecture',
               'shared-governance', 'shared-engineering', 'shared-repository')
STARTUP_MAX = 262144
PROVIDER_BODY_MAX = 512 * 1024
PROVIDER_REPLY_MAX = 4 * 1024 * 1024
TURN_BYTES = 1024 * 1024
TURN_SECONDS = 20
JOB_TURN_SECONDS = 120
TURN_CLEANUP_SECONDS = 2
PR_SET_CHILD_SUBREAPER = 36
ENV = {'HOME': '/home/gpt', 'CODEX_HOME': str(CODEX_HOME),
       'PATH': '/opt/dev-pair/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp',
       'XDG_RUNTIME_DIR': '/run/user/1000', 'XDG_CACHE_HOME': '/cache/job',
       'XDG_STATE_HOME': '/state', 'XDG_CONFIG_HOME': '/home/gpt/.config'}
GIT_ENV = {**ENV, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': ''}

def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def inputs():
    return json.loads((BASE / 'inputs.json').read_text())

def verify_files():
    expected = inputs()
    for path, wanted in expected['files'].items():
        file = Path(path)
        if file.is_symlink() or not file.is_file() or digest(file) != wanted:
            raise RuntimeError('image-owned executable identity mismatch')
    return expected

def finalize():
    if os.getuid() != 0:
        raise RuntimeError('assembly finalizer requires container root')
    expected = verify_files()
    account = pwd.getpwnam('gpt')
    if (account.pw_uid, account.pw_gid, account.pw_dir) != (1000, 1000, '/home/gpt'):
        raise RuntimeError('upstream init did not create intended account')
    for user in ('root', 'gpt'):
        subprocess.run(['/usr/sbin/usermod', '--lock', user], check=True)
    subprocess.run(['/usr/sbin/usermod', '--groups', '', 'gpt'], check=True)
    for path in ('/etc/profile.d', '/home/gpt', '/run/host', '/etc/sudoers.d'):
        target = Path(path)
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            shutil.rmtree(target)
    for path in ('/usr/bin/distrobox-host-exec', '/usr/bin/host-spawn', '/usr/local/bin/distrobox-host-exec'):
        target = Path(path)
        if target.exists() or target.is_symlink():
            target.unlink()
    Path('/etc/profile.d').mkdir(mode=0o755)
    Path('/etc/sudoers.d').mkdir(mode=0o755)
    Path('/home/gpt').mkdir(mode=0o755)
    Path('/home/gpt/.codex').mkdir(mode=0o755)
    Path('/home/gpt/.agents').mkdir(mode=0o755)
    Path('/etc/profile').write_text('export PATH=/opt/dev-pair/bin:/usr/bin:/bin\n')
    Path('/home/gpt/.bashrc').write_text('# immutable gptbox shell\n')
    Path('/home/gpt/.bash_profile').write_text('. /etc/profile\n')
    Path('/etc/sudoers').write_text('Defaults env_reset\nroot ALL=(ALL) ALL\n')
    Path('/etc/sudoers').chmod(0o440)
    packages = subprocess.run(['/usr/bin/rpm', '-qa', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'],
                              text=True, capture_output=True, check=True).stdout
    (BASE / 'packages.txt').write_text('\n'.join(sorted(packages.splitlines())) + '\n')
    sealed = {'kind': 'genuine-distrobox-assembled', 'inputs_sha256': digest(BASE / 'inputs.json'),
              'source_sha': expected['source_sha'], 'uid': 1000, 'gid': 1000,
              'packages_sha256': digest(BASE / 'packages.txt')}
    (BASE / 'sealed.json').write_text(json.dumps(sealed, sort_keys=True) + '\n')
    for path in BASE.iterdir():
        if path.is_file():
            path.chmod(0o444)
    print(json.dumps(sealed, sort_keys=True))

def verify_offline_runtime(proc=Path('/proc/self')):
    interfaces = [line.partition(':')[0].strip() for line in (proc / 'net/dev').read_text().splitlines()[2:]]
    require(interfaces == ['lo'], 'offline runtime must have only loopback')
    mounts = [line.split(' - ', 1)[0].split() for line in (proc / 'mountinfo').read_text().splitlines()]
    roots = [row[5].split(',') for row in mounts if row[4] == '/']
    require(len(roots) == 1 and 'ro' in roots[0], 'effective runtime root is writable')
    require(not any(row[4] in OFFLINE_CONFIG_FILES for row in mounts), 'unexpected runtime network configuration mount')
    etc = proc / 'root/etc'
    require(etc.is_dir() and not etc.is_symlink(), 'runtime /etc is unavailable')
    for target in OFFLINE_CONFIG_FILES:
        path = etc / Path(target).name
        try:
            node = path.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISREG(node.st_mode) and os.statvfs(path).f_flag & os.ST_RDONLY,
                'runtime network configuration must be an image-owned read-only file')


def frozen():
    if (os.getuid(), os.getgid()) != (1000, 1000):
        raise RuntimeError('frozen init must be unprivileged')
    verify_offline_runtime()
    verify_files()
    sealed = json.loads((BASE / 'sealed.json').read_text())
    if sealed['inputs_sha256'] != digest(BASE / 'inputs.json') or sealed['packages_sha256'] != digest(BASE / 'packages.txt'):
        raise RuntimeError('sealed assembly evidence mismatch')
    print('container_setup_done', flush=True)
    # This process is only immutable keepalive; it launches no agent or shell.
    os.execv('/usr/bin/sleep', ['sleep', 'infinity'])

def probe():
    verify_offline_runtime()
    verify_files()
    if (os.getuid(), os.getgid()) != (1000, 1000) or os.getgroups() not in ([], [1000]):
        raise RuntimeError('runtime identity/groups mismatch')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if int(status['CapEff'].strip(), 16) or status['NoNewPrivs'].strip() != '1' or status['Seccomp'].strip() != '2':
        raise RuntimeError('runtime capabilities, NNP or seccomp mismatch')
    label = Path('/proc/self/attr/current').read_text().strip()
    if not label.startswith('system_u:system_r:container_t:s0:') or 'unconfined' in label:
        raise RuntimeError('effective container SELinux confinement missing')
    for target in ('/usr', '/etc', '/opt/dev-pair/bin', '/home/gpt', '/home/gpt/.codex', '/home/gpt/.agents'):
        path = Path(target) / '.dev-pair-write-probe'
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as error:
            if error.errno not in (13, 30):
                raise
        else:
            os.close(descriptor)
            path.unlink()
            raise RuntimeError('managed code/configuration is writable')
    for target in (*OFFLINE_CONFIG_FILES, '/etc/profile',
                   '/home/gpt/.bashrc', str(CODEX), '/usr/bin/distrobox-init', __file__):
        if not Path(target).exists():
            continue
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_APPEND)
        except OSError as error:
            if error.errno not in (13, 30):
                raise
        else:
            os.close(descriptor)
            raise RuntimeError('installed executable/configuration permits write access')
    for target in ('/work/job', '/state', '/cache/job'):
        path = Path(target) / '.dev-pair-write-probe'
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(descriptor, b'bounded writable-state probe\n')
        os.close(descriptor)
        path.unlink()
    for path in ('/run/host', '/usr/bin/distrobox-host-exec', '/usr/bin/host-spawn', '/run/podman/podman.sock'):
        if Path(path).exists() or Path(path).is_symlink():
            raise RuntimeError('host bridge is exposed')
    return {'boundary_probe': 'passed', 'uid': 1000, 'selinux_label': label,
            'codex_home': 'immutable; auth/session adapter not admitted'}


def require(predicate, message):
    if not predicate:
        raise RuntimeError(message)


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate role input field')
        result[key] = value
    return result


def role_policy(directive, *, live=False, development=False):
    features = dict.fromkeys(('plugins', 'remote_plugin', 'hooks', 'shell_snapshot',
                              'shell_snapshot_v2', 'apps', 'skill_mcp_dependency_install'), False)
    paths = (':minimal', '/usr', '/opt', '/etc/codex', '/home/gpt')
    requirements = {
        'additional_developer_instructions': directive,
        'cli_auth_credentials_store': 'file',
        'model_provider': 'openai',
        'sqlite_home': '/state/sqlite', 'log_dir': '/state/logs',
        'check_for_update_on_startup': False, 'allow_login_shell': False,
        'allow_managed_hooks_only': True, 'allow_browser_and_computer_use': False,
        'allow_remote_control': False, 'mcp_servers': {}, 'features': features,
        'default_permissions': 'product-child',
        'allowed_approval_policies': ['never'],
        'allowed_permission_profiles': {'product-child': True},
        'permissions': {
            'filesystem': {'deny_read': ['/credentials', '/state/sqlite', '/state/logs', '/state/turns',
                                         '/state/codex/sessions', str(TURN_INPUTS),
                                         *([str(PROVIDER_DIR), '/state/session-bindings'] if live else [])]},
            'product-child': {
                'filesystem': {**dict.fromkeys(paths, 'read'), str(WORK): 'write', '/tmp': 'write'},
                'network': {'enabled': False},
            },
        },
    }
    config = {
        'cli_auth_credentials_store': 'file', 'check_for_update_on_startup': False,
        'allow_login_shell': False, 'sqlite_home': '/state/sqlite', 'log_dir': '/state/logs',
        'analytics': {'enabled': False}, 'features': features,
        'projects': {str(WORK): {'trust_level': 'untrusted'}},
        'shell_environment_policy': {'inherit': 'none',
                                     'set': {key: ENV[key] for key in ('PATH', 'HOME', 'CODEX_HOME', 'TMPDIR')}},
    }
    if live:
        requirements['allowed_web_search_modes'] = ['disabled']
        config['web_search'] = 'disabled'
        if development:
            requirements['permissions']['product-child']['filesystem'][BUILD] = 'write'
    return requirements, config


def fixed_read(path, maximum, *, readonly=False):
    require(not any(parent.is_symlink() for parent in path.parents), 'symlinked role input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        node = os.fstat(stream.fileno())
        require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and 0 < node.st_size <= maximum,
                'role input is not a bounded regular file')
        if readonly:
            require(os.fstatvfs(stream.fileno()).f_flag & os.ST_RDONLY, 'role input mount is writable')
        data = stream.read(maximum + 1)
        require(len(data) == node.st_size, 'role input changed or exceeded its bound')
    return data


def turn_request(expected_role):
    for path in TURN_READONLY_MOUNTS:
        require(not any(parent.is_symlink() for parent in (path, *path.parents)) and
                os.statvfs(path).f_flag & os.ST_RDONLY, 'role configuration is not mounted read-only')
    selection = json.loads(fixed_read(TURN_INPUTS / 'request.json', 4096, readonly=True),
                           object_pairs_hook=unique_object)
    fields = {'schema', 'operation', 'role', 'provider', 'model', 'effort', 'standards_sha',
              'endpoint', 'requirements_sha256', 'config_sha256', 'prompt_sha256'}
    require(type(selection) is dict and set(selection) == fields and
            type(selection['schema']) is int and selection['schema'] == 1,
            'unsupported role request schema')
    require(expected_role in ('maintenance', 'development') and selection['role'] == expected_role
            and selection['provider'] == 'gptbox' and selection['standards_sha'] == STANDARDS,
            'role or standards do not match the sealed image')
    require(type(selection['operation']) is str and
            re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', selection['operation']), 'invalid operation ID')
    require(type(selection['model']) is str and
            re.fullmatch(r'gpt-[a-z0-9]+(?:[.-][a-z0-9]+)+', selection['model']) and
            selection['effort'] in ('low', 'medium', 'high', 'xhigh'), 'invalid saved model or effort')
    endpoint = selection['endpoint']
    match = re.fullmatch(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})/v1', endpoint) if type(endpoint) is str else None
    require(match and int(match[1]) <= 65535, 'role transport is limited to a local endpoint')
    prompt = fixed_read(TURN_INPUTS / 'prompt.txt', 16384, readonly=True)
    requirements = fixed_read(REQUIREMENTS, 65536, readonly=True)
    config = fixed_read(CODEX_HOME / 'config.toml', 8192, readonly=True)
    for field, data in (('requirements_sha256', requirements), ('config_sha256', config),
                        ('prompt_sha256', prompt)):
        require(hashlib.sha256(data).hexdigest() == selection[field], 'bound role input changed')
    policy = tomllib.loads(requirements.decode('utf-8'))
    directive = policy.get('additional_developer_instructions')
    require(type(directive) is str and 0 < len(directive.encode()) <= 32768, 'managed startup input missing')
    expected_requirements, expected_config = role_policy(directive)
    require(json.dumps(policy, sort_keys=True) == json.dumps(expected_requirements, sort_keys=True) and
            json.dumps(tomllib.loads(config.decode('utf-8')), sort_keys=True) ==
            json.dumps(expected_config, sort_keys=True), 'managed role configuration changed')
    require(not (CODEX_HOME / 'auth.json').exists() and not (CODEX_HOME / 'auth.json').is_symlink(),
            'local role entry cannot load saved provider credentials')
    key = fixed_read(CREDENTIAL, 128, readonly=True).removesuffix(b'\n')
    require(key == OFFLINE_KEY, 'local role entry requires a scoped synthetic credential')
    prompt.decode('utf-8')
    return selection, prompt, key.decode('ascii')


def private_directory(path, *, new=False):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        require(not new, 'operation already dispatched; inspect durable state')
    node = path.lstat()
    require(stat.S_ISDIR(node.st_mode) and node.st_uid == os.getuid() and
            stat.S_IMODE(node.st_mode) == 0o700, 'unsafe private turn state')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def completed_turn(output):
    rows = [json.loads(line, object_pairs_hook=unique_object) for line in output.splitlines()]
    require(rows and all(type(row) is dict for row in rows), 'invalid Codex event stream')
    kinds = [row.get('type') for row in rows]
    require(kinds.count('thread.started') == kinds.count('turn.started') == kinds.count('turn.completed') == 1
            and kinds[0] == 'thread.started' and kinds[-1] == 'turn.completed'
            and set(kinds) <= {'thread.started', 'turn.started', 'item.started', 'item.updated',
                               'item.completed', 'turn.completed'},
            'Codex did not complete exactly one turn')
    ident = rows[0].get('thread_id')
    require(type(ident) is str and str(uuid.UUID(ident)) == ident, 'invalid Codex session identity')
    items = (row.get('item') for row in rows[kinds.index('turn.started') + 1:] if row['type'] == 'item.completed')
    require(any(type(item) is dict and item.get('type') == 'agent_message' and
                type(item.get('text')) is str and bool(item['text']) for item in items),
            'Codex completed without an agent message')
    return ident


def reap_turn(process):
    # This standalone entry starts only the turn. Linux reparents its orphaned
    # descendants here even when they have left the original process group.
    deadline = time.monotonic() + TURN_CLEANUP_SECONDS
    parent = str(os.getpid()).encode()
    for _ in range(4096):
        if time.monotonic() >= deadline:
            return False
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid:
            if process is not None and pid == process.pid:
                process.returncode = os.waitstatus_to_exitcode(status)
            continue
        with os.scandir('/proc') as processes:
            for count, entry in enumerate(processes):
                if count >= 8192 or time.monotonic() >= deadline:
                    return False
                if not entry.name.isdigit():
                    continue
                # Pin the process before verifying direct kernel parentage.
                with suppress(ProcessLookupError, FileNotFoundError, PermissionError):
                    descriptor = os.pidfd_open(int(entry.name))
                    try:
                        with open(f'/proc/{entry.name}/status', 'rb') as source:
                            status = source.read(4096)
                        parents = [line.split()[1] for line in status.splitlines() if line.startswith(b'PPid:')]
                        if parents == [parent]:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    finally:
                        os.close(descriptor)
        time.sleep(.01)
    return False


def run_turn(argv, prompt, output, error, env, *, seconds=None):
    cancelled = False

    def request_stop(_signum, _frame):
        nonlocal cancelled
        cancelled = True

    handled = (signal.SIGTERM, signal.SIGINT)
    previous = {signum: signal.signal(signum, request_stop) for signum in handled}
    process = None
    launch_attempted = False
    failure = None
    cleanup = 'not-started'
    try:
        require(ctypes.CDLL(None).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0,
                'owned process reaper unavailable')
        descriptor = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(descriptor, 0)
        finally:
            os.close(descriptor)
        deadline = time.monotonic() + (TURN_SECONDS if seconds is None else seconds)
        # Give the CLI the validated snapshot and EOF independent of pipe capacity.
        flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        with os.fdopen(os.memfd_create('gptbox-prompt', flags), 'wb') as source:
            source.write(prompt)
            source.seek(0)
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(source, fcntl.F_ADD_SEALS, seals)
            if not cancelled:
                launch_attempted = True
                process = subprocess.Popen(argv, stdin=source, stdout=output, stderr=error,
                                           cwd=WORK, env=env, start_new_session=True)
        if process is not None:
            while not cancelled and (remaining := deadline - time.monotonic()) > 0:
                try:
                    process.wait(timeout=min(.1, remaining))
                except subprocess.TimeoutExpired:
                    continue
                if process.returncode != 0:
                    failure = 'codex-failed'
                break
            else:
                failure = 'deadline'
    except (OSError, RuntimeError):
        failure = 'execution-failed'
    finally:
        try:
            if launch_attempted:
                cleanup = 'unresolved'
                with suppress(OSError):
                    if reap_turn(process):
                        cleanup = 'reaped'
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    if cancelled:
        failure = 'cancelled'
    if cleanup == 'unresolved' and failure is None:
        failure = 'cleanup-failed'
    return failure, cleanup


def publish_turn(destination, result):
    temporary_result = destination / 'result.pending'
    with temporary_result.open('x') as record:
        json.dump(result, record, sort_keys=True)
        record.write('\n')
        record.flush()
        os.fsync(record.fileno())
    temporary_result.rename(destination / 'result.json')
    sync_directory(destination)


def verify_turn_environment():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    require((os.getuid(), os.getgid()) == (1000, 1000) and os.getgroups() in ([], [1000]) and
            status['NoNewPrivs'].strip() == '1' and
            all(int(status[name].strip(), 16) == 0 for name in ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'))
            and interfaces == ['lo'], 'isolated headless runtime required')


def turn():
    image = verify_files()
    verify_turn_environment()
    selection, prompt, key = turn_request(image.get('role'))
    os.umask(0o077)
    for path in (CODEX_HOME, STATE / 'sqlite', STATE / 'logs', STATE / 'turns'):
        private_directory(path)
    destination = STATE / 'turns' / selection['operation']
    private_directory(destination, new=True)
    sync_directory(STATE)
    sync_directory(destination.parent)
    argv = ['/usr/bin/prlimit', f'--fsize={TURN_BYTES}:{TURN_BYTES}', '--core=0:0', '--',
            str(CODEX), '--strict-config', '-c', 'openai_base_url=' + json.dumps(selection['endpoint']),
            '-c', 'model_reasoning_effort=' + json.dumps(selection['effort']),
            'exec', '--skip-git-repo-check', '--json', '--model', selection['model'], '-C', str(WORK), '-']
    with (destination / 'events.jsonl').open('xb') as output, (destination / 'stderr.txt').open('xb') as error:
        failure, cleanup = run_turn(argv, prompt, output, error, {**ENV, 'CODEX_API_KEY': key})
        if failure:
            print(f'gptbox turn stopped ({failure}), owned cleanup {cleanup}', file=sys.stderr)
        os.fsync(output.fileno())
        os.fsync(error.fileno())
    result = {'schema': 1, 'operation': selection['operation'],
              'role': selection['role'], 'model': selection['model'], 'effort': selection['effort'],
              'transport': 'local-synthetic', 'runtime_admitted': False, 'owned_cleanup': cleanup}
    if failure:
        publish_turn(destination, {**result, 'status': 'failed-turn', 'reason': failure})
        raise RuntimeError('fixed role turn failed')
    events = fixed_read(destination / 'events.jsonl', TURN_BYTES)
    result.update(status='completed-turn', session_uuid=completed_turn(events),
                  events_sha256=hashlib.sha256(events).hexdigest(), events_bytes=len(events))
    publish_turn(destination, result)
    print(json.dumps(result, sort_keys=True))


def uuid_text(value):
    return type(value) is str and str(uuid.UUID(value)) == value


def job_selection(raw, expected_sha, role, job, operation):
    require(type(expected_sha) is str and HEX_SHA.fullmatch(expected_sha) and
            hashlib.sha256(raw).hexdigest() == expected_sha, 'operation request digest mismatch')
    request = json.loads(raw, object_pairs_hook=unique_object)
    fields = {'schema', 'operation', 'action', 'role', 'job', 'logical_session', 'session_uuid',
              'workspace', 'provider', 'model', 'effort', 'standards_sha', 'repository', 'candidate_sha',
              'agreement_sha256', 'requirements_sha256', 'config_sha256', 'prompt_sha256', 'startup_sha256',
              'turn_seconds'}
    require(type(request) is dict and set(request) == fields and type(request['schema']) is int and
            request['schema'] == 2, 'invalid job turn schema')
    require(role in ('maintenance', 'development') and request['role'] == role and
            request['provider'] == 'gptbox' and request['standards_sha'] == STANDARDS and
            request['workspace'] == str(WORK), 'job role or platform policy mismatch')
    require(type(job) is str and JOB.fullmatch(job) and request['job'] == job and
            type(operation) is str and OPERATION.fullmatch(operation) and request['operation'] == operation and
            type(request['logical_session']) is str and OPERATION.fullmatch(request['logical_session']),
            'job, operation or logical session mismatch')
    require((request['action'] == 'start' and request['session_uuid'] is None) or
            (request['action'] == 'resume' and uuid_text(request['session_uuid'])), 'invalid start or resume identity')
    require(type(request['model']) is str and re.fullmatch(r'gpt-[a-z0-9]+(?:[.-][a-z0-9]+)+', request['model']) and
            request['effort'] in ('low', 'medium', 'high', 'xhigh'), 'invalid recorded model or effort')
    require(type(request['repository']) is str and
            re.fullmatch(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', request['repository']) and
            all(part not in ('.', '..') for part in request['repository'].split('/')) and
            type(request['candidate_sha']) is str and re.fullmatch(r'[0-9a-f]{40}', request['candidate_sha']) and
            all(type(request[key]) is str and HEX_SHA.fullmatch(request[key]) for key in fields if key.endswith('sha256')) and
            type(request['turn_seconds']) is int and 0 < request['turn_seconds'] <= JOB_TURN_SECONDS,
            'invalid recorded repository, input hashes or deadline')
    return request


def provider_host_path(request_sha):
    require(type(request_sha) is str and HEX_SHA.fullmatch(request_sha), 'invalid provider operation digest')
    return Path('/run/dev-pair/provider') / request_sha[:32]


def repository_origin(repository, remote):
    return type(remote) is str and remote in (f'https://github.com/{repository}', f'https://github.com/{repository}.git',
                                               f'git@github.com:{repository}.git')


def git_output(directory, *arguments):
    result = subprocess.run(['/usr/bin/git', '-C', str(directory), *arguments], check=True, capture_output=True,
                            env=GIT_ENV, timeout=4)
    require(0 < len(result.stdout) <= 1024, 'unexpected Git repository identity output')
    return result.stdout.decode('utf-8').removesuffix('\n')


def read_repository_approval(raw, selection):
    approval = json.loads(raw, object_pairs_hook=unique_object)
    bound = ('job', 'repository', 'agreement_sha256', 'standards_sha', 'startup_sha256')
    fields = {*bound, 'schema', 'acquired_commit', 'acquired_tree', 'startup_project_revision'}
    require(type(approval) is dict and approval.keys() == fields and type(approval['schema']) is int
            and approval['schema'] == 1 and all(approval[key] == selection[key] for key in bound)
            and all(type(approval[key]) is str and re.fullmatch(r'[0-9a-f]{40}', approval[key])
                    for key in ('acquired_commit', 'acquired_tree', 'startup_project_revision')),
            'trusted job repository or startup approval mismatch')
    return approval


def host_repository_approval(selection):
    require(JOB.fullmatch(selection['job']), 'invalid protected repository leaf')
    path = REPOSITORY_APPROVALS / (selection['job'] + '.json')
    for parent in (path, *path.parents):
        node = parent.lstat()
        require(node.st_uid == 0 and not node.st_mode & 0o022 and not stat.S_ISLNK(node.st_mode),
                'job repository approval lacks protected custody')
    raw = fixed_read(path, 4096)
    read_repository_approval(raw, selection)
    return raw


def verify_workspace(selection, approval):
    require(git_output(WORK, 'rev-parse', '--show-toplevel') == str(WORK) and
            repository_origin(selection['repository'],
                              git_output(WORK, 'config', '--local', '--no-includes', '--get-all', 'remote.origin.url')),
            'workspace checkout does not identify the approved repository')
    head = git_output(WORK, 'rev-parse', '--verify', 'HEAD')
    baseline = approval['acquired_commit']
    require(head == selection['candidate_sha'] and
            git_output(WORK, 'rev-parse', '--verify', baseline + '^{tree}') == approval['acquired_tree'],
            'workspace candidate or acquired source differs from its protected identity')
    ancestry = subprocess.run(['/usr/bin/git', '-C', str(WORK), 'merge-base', '--is-ancestor', baseline, head],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=GIT_ENV, timeout=4)
    require(ancestry.returncode == 0, 'workspace candidate is outside approved acquisition history')


def host_job_inputs(role, job, operation, request_sha, gid):
    require(role in ('maintenance', 'development') and JOB.fullmatch(job) and OPERATION.fullmatch(operation),
            'invalid role job or operation leaf')
    leaf = Path('/var/lib/dev-pair/turn-inputs') / role / job / operation
    provider = provider_host_path(request_sha)
    for directory in (*leaf.parents, *provider.parents, leaf, provider):
        node = directory.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022,
                'role input ancestry is not controlled by root')
    mounts = {destination: (str(leaf / relative), False) for destination, relative in JOB_INPUTS.items()}
    mounts[str(PROVIDER_DIR)] = (str(provider), False)
    for source, _ in mounts.values():
        path = Path(source)
        node = path.lstat()
        require(path.resolve(strict=True) == path and node.st_uid == 0 and not node.st_mode & 0o022 and
                (stat.S_ISDIR(node.st_mode) or stat.S_ISREG(node.st_mode) and node.st_nlink == 1),
                'role input source is not root protected')
    channel = (provider / PROVIDER_SOCKET.name).lstat()
    require(stat.S_ISSOCK(channel.st_mode) and (channel.st_uid, channel.st_gid) == (0, gid)
            and stat.S_IMODE(channel.st_mode) == 0o660
            and {node.name for node in provider.iterdir()} == {PROVIDER_SOCKET.name}, 'missing protected provider channel')
    request_path = leaf / 'turn' / 'request.json'
    node = request_path.lstat()
    require(node.st_uid == 0 and not node.st_mode & 0o222, 'job request file is writable')
    request = job_selection(fixed_read(request_path, 4096), request_sha, role, job, operation)
    mirror = leaf / 'turn' / 'approval.json'
    node = mirror.lstat()
    require(node.st_uid == 0 and not node.st_mode & 0o222 and fixed_read(mirror, 4096) == host_repository_approval(request),
            'staged approval differs from trusted job authorization')
    return mounts, request


def startup_documents(raw, selection, approval):
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    require(type(manifest) is dict and set(manifest) == {'version', 'mode', 'project_revision', 'standards_sha', 'documents'}
            and type(manifest['version']) is int and manifest['version'] == 1 and manifest['mode'] == 'private-runtime'
            and manifest['standards_sha'] == selection['standards_sha'] and
            manifest['project_revision'] == approval['startup_project_revision'] and
            type(manifest['documents']) is list and len(manifest['documents']) == len(STARTUP_IDS),
            'invalid private startup manifest')
    documents = []
    require({path.name for path in (TURN_INPUTS / 'startup').iterdir()} ==
            {'manifest.json', *(name + '.txt' for name in STARTUP_IDS)}, 'unknown private startup file')
    for name, row in zip(STARTUP_IDS, manifest['documents']):
        require(type(row) is dict and set(row) == {'id', 'bytes', 'sha256'} and row['id'] == name and
                type(row['bytes']) is int and 0 < row['bytes'] <= STARTUP_MAX, 'invalid startup document row')
        data = fixed_read(TURN_INPUTS / 'startup' / (name + '.txt'), row['bytes'], readonly=True)
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                'immutable startup document changed')
        data.decode('utf-8')
        documents.append(data)
    require(sum(map(len, documents)) <= STARTUP_MAX, 'startup corpus exceeds its bound')
    return documents


def job_turn_inputs(role, job, operation, request_sha):
    for path in JOB_READONLY_MOUNTS:
        require(not any(parent.is_symlink() for parent in (path, *path.parents)) and
                os.statvfs(path).f_flag & os.ST_RDONLY, 'job configuration mount is not read-only')
    require(stat.S_ISSOCK(PROVIDER_SOCKET.lstat().st_mode) and not os.path.lexists(CODEX_HOME / 'auth.json'),
            'job requires the dedicated provider channel and clean saved authentication')
    require({path.name for path in TURN_INPUTS.iterdir()} == {'request.json', 'approval.json', 'prompt.txt', 'startup'}
            and {path.name for path in REQUIREMENTS.parent.iterdir()} == {REQUIREMENTS.name},
            'unknown job configuration file')
    raw = fixed_read(TURN_INPUTS / 'request.json', 4096, readonly=True)
    request = job_selection(raw, request_sha, role, job, operation)
    approval = read_repository_approval(fixed_read(TURN_INPUTS / 'approval.json', 4096, readonly=True), request)
    prompt = fixed_read(TURN_INPUTS / 'prompt.txt', 16384, readonly=True)
    requirements = fixed_read(REQUIREMENTS, 65536, readonly=True)
    config = fixed_read(CODEX_HOME / 'config.toml', 8192, readonly=True)
    startup = fixed_read(TURN_INPUTS / 'startup' / 'manifest.json', 4096, readonly=True)
    for name, data in (('requirements', requirements), ('config', config), ('prompt', prompt), ('startup', startup)):
        require(hashlib.sha256(data).hexdigest() == request[name + '_sha256'], 'bound job input digest changed')
    prompt.decode('utf-8')
    policy = tomllib.loads(requirements.decode('utf-8'))
    directive = policy.get('additional_developer_instructions')
    require(type(directive) is str and 0 < len(directive.encode()) <= 32768, 'managed job directive missing')
    expected_requirements, expected_config = role_policy(directive, live=True, development=role == 'development')
    require(json.dumps(policy, sort_keys=True) == json.dumps(expected_requirements, sort_keys=True) and
            json.dumps(tomllib.loads(config.decode('utf-8')), sort_keys=True) == json.dumps(expected_config, sort_keys=True),
            'managed job permission policy changed')
    documents = startup_documents(startup, request, approval)
    verify_workspace(request, approval)
    if request['action'] == 'start':
        inputs = b'\n\n'.join(name.encode() + b'\n' + data for name, data in zip(STARTUP_IDS, documents))
        prompt = (b'Read the complete startup documents below before starting the authorized job.\n\n' + inputs +
                  b'\n\nAuthorized job request:\n' + prompt)
    return request, prompt


def receive_exact(channel, count, deadline=None):
    data = bytearray()
    while len(data) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('provider channel deadline expired')
            channel.settimeout(remaining)
        chunk = channel.recv(count - len(data))
        if not chunk:
            raise OSError('provider channel closed mid-message')
        data.extend(chunk)
    return bytes(data)


def provider_peer_label():
    return Path('/proc/self/attr/current').read_bytes().rstrip(b'\0\n')


class LocalResponses(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        self.request.settimeout(2)
        super().setup()

    def log_message(self, *_args):
        pass

    def do_GET(self):
        # The pinned CLI probes WebSockets before falling back to the Responses POST.
        if (self.path == '/v1/responses' and self.headers.get('Upgrade', '').lower() == 'websocket'
                and self.headers.get_all('Authorization') == ['Bearer ' + LOCAL_BEARER]):
            self.send_response(426)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self):
        raw = self.headers.get_all('Content-Length', [])
        if (self.path != '/v1/responses' or self.headers.get_all('Authorization') != ['Bearer ' + LOCAL_BEARER]
                or self.headers.get('Content-Type', '').split(';', 1)[0] != 'application/json'
                or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding')
                or len(raw) != 1 or not re.fullmatch(r'[1-9][0-9]{0,5}', raw[0]) or int(raw[0]) > PROVIDER_BODY_MAX):
            self.send_error(400)
            return
        body = self.rfile.read(int(raw[0]))
        if len(body) != int(raw[0]):
            self.send_error(400)
            return
        started = False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(max(.1, self.server.deadline - time.monotonic()))
                channel.connect(str(PROVIDER_SOCKET))
                wanted = getattr(self.server, 'provider_label', None)
                if wanted:
                    observed = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 256).rstrip(b'\0')
                    require(observed == wanted, 'confined provider socket peer label differs')
                channel.sendall(self.server.binding + struct.pack('!I', len(body)) + body)
                status, = struct.unpack('!H', receive_exact(channel, 2, self.server.deadline))
                require(status in (200, 400, 403, 409, 413, 429, 502, 503), 'invalid provider result')
                if status != 200:
                    self.send_error(status)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Connection', 'close')
                self.end_headers()
                started = True
                total = 0
                while True:
                    size, = struct.unpack('!I', receive_exact(channel, 4, self.server.deadline))
                    if not size:
                        break
                    total += size
                    require(size <= 16384 and total <= PROVIDER_REPLY_MAX and time.monotonic() < self.server.deadline,
                            'provider response exceeded transport limits')
                    self.wfile.write(receive_exact(channel, size, self.server.deadline))
        except (OSError, RuntimeError):
            if not started:
                with suppress(OSError):
                    self.send_error(503)


def job_codex_argv(selection, port):
    argv = ['/usr/bin/prlimit', f'--fsize={4 * TURN_BYTES}:{4 * TURN_BYTES}', '--core=0:0', '--',
            str(CODEX), '--strict-config', '-c', 'openai_base_url=' + json.dumps(f'http://127.0.0.1:{port}/v1'),
            '-c', 'model_reasoning_effort=' + json.dumps(selection['effort']),
            'exec', '--skip-git-repo-check', '--json', '--model', selection['model'], '-C', str(WORK)]
    if selection['action'] == 'resume':
        argv += ['resume', selection['session_uuid']]
    return argv + ['-']


def saved_session(selection, session):
    path = STATE / 'sqlite/state_5.sqlite'
    node = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(node.st_mode) and node.st_nlink == 1
            and node.st_uid == os.getuid() and 0 < node.st_size <= 64 * TURN_BYTES,
            'Codex state database unavailable')
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=.5) as db:
        db.execute('PRAGMA query_only=ON')
        row = db.execute('SELECT cwd, rollout_path, model_provider FROM threads WHERE id = ?', (session,)).fetchone()
    require(row and row[0] == str(WORK) and row[2] == 'openai' and type(row[1]) is str,
            'saved Codex session is missing or does not match this workspace/provider')
    rollout = Path(row[1])
    require(rollout.is_relative_to(CODEX_HOME / 'sessions') and rollout.resolve(strict=True) == rollout,
            'saved Codex rollout escaped private state')
    with os.fdopen(os.open(rollout, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        node = os.fstat(source.fileno())
        require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and 0 < node.st_size <= 4 * TURN_BYTES,
                'saved Codex rollout exceeds its bound')
        meta = json.loads(source.readline(65536), object_pairs_hook=unique_object)
        require(meta['type'] == 'session_meta' and meta['payload']['id'] == session and
                meta['payload']['cwd'] == selection['workspace'], 'saved Codex rollout identity mismatch')
        os.fsync(source.fileno())


def session_binding(selection, ident):
    keys = ('role', 'job', 'logical_session', 'model', 'effort', 'provider', 'workspace', 'standards_sha',
            'startup_sha256', 'agreement_sha256', 'repository')
    return {key: selection[key] for key in keys} | {'session_uuid': ident}


def verify_job_environment():
    verify_turn_environment()
    require(Path('/proc/self/attr/current').read_text().startswith('system_u:system_r:container_t:s0:') and
            os.statvfs('/').f_flag & os.ST_RDONLY and
            re.search(r'^Seccomp:\s+2$', Path('/proc/self/status').read_text(), re.MULTILINE) and
            not any(os.path.lexists(path) for path in
            ('/credentials', '/run/host', '/run/podman/podman.sock')), 'job confinement gate failed')


def job_turn(job, operation, request_sha):
    image = verify_files()
    verify_job_environment()
    selection, prompt = job_turn_inputs(image.get('role'), job, operation, request_sha)
    os.umask(0o077)
    bindings = STATE / 'session-bindings'
    for path in (CODEX_HOME, STATE / 'sqlite', STATE / 'logs', STATE / 'turns', bindings):
        private_directory(path)
    binding = bindings / selection['logical_session']
    if selection['action'] == 'resume':
        private_directory_existing(binding)
        expected = session_binding(selection, selection['session_uuid'])
        require(json.loads(fixed_read(binding / 'result.json', 4096), object_pairs_hook=unique_object) == expected,
                'resume differs from the original saved role/model/workspace binding')
        saved_session(selection, selection['session_uuid'])
    destination = STATE / 'turns' / selection['operation']
    private_directory(destination, new=True)
    sync_directory(STATE)
    sync_directory(destination.parent)
    if selection['action'] == 'start':
        # A conflicting or interrupted logical session remains available for audit.
        private_directory(binding, new=True)
        sync_directory(bindings)
    result = {**session_binding(selection, selection['session_uuid']), 'schema': 2, 'operation': operation,
              'action': selection['action'], 'request_sha256': request_sha, 'candidate_sha': selection['candidate_sha'],
              'transport': 'scoped-openai-responses', 'runtime_admitted': True}
    with HTTPServer(('127.0.0.1', 0), LocalResponses) as server:
        server.binding = bytes.fromhex(request_sha)
        server.provider_label = provider_peer_label()
        server.deadline = time.monotonic() + selection['turn_seconds']
        listener = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        listener.start()
        try:
            argv = job_codex_argv(selection, server.server_port)
            with (destination / 'events.jsonl').open('xb') as output, (destination / 'stderr.txt').open('xb') as error:
                failure, cleanup = run_turn(argv, prompt, output, error, {**ENV, 'CODEX_API_KEY': LOCAL_BEARER},
                                            seconds=selection['turn_seconds'])
                os.fsync(output.fileno())
                os.fsync(error.fileno())
        finally:
            server.shutdown()
            listener.join(timeout=TURN_CLEANUP_SECONDS)
    result['owned_cleanup'] = cleanup
    if failure is None:
        try:
            events = fixed_read(destination / 'events.jsonl', TURN_BYTES * 4)
            session = completed_turn(events)
            require(selection['action'] == 'start' or session == selection['session_uuid'], 'changed resume UUID')
            saved_session(selection, session)
            if selection['action'] == 'start':
                publish_turn(binding, session_binding(selection, session))
            result.update(status='completed-turn', session_uuid=session, events_bytes=len(events),
                          events_sha256=hashlib.sha256(events).hexdigest())
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error):
            failure = 'session-or-events-unverified'
    if failure:
        result.update(status='failed-turn', reason=failure)
    publish_turn(destination, result)
    print(json.dumps(result, sort_keys=True))


def private_directory_existing(path):
    require(os.path.lexists(path), 'original role session binding is unavailable')
    private_directory(path)


def entry(operation, *arguments):
    os.environ.clear()
    os.environ.update({**ENV, 'CODEX_HOME': '/home/gpt/.codex'})
    if operation == 'job-turn' and len(arguments) == 3:
        job_turn(*arguments)
        return
    require(not arguments, 'unexpected fixed entry arguments')
    if operation == 'probe':
        print(json.dumps(probe(), sort_keys=True))
    elif operation == 'version':
        verify_files()
        os.execv(str(CODEX), [str(CODEX), '--version'])
    elif operation == 'turn':
        turn()
    else:
        raise RuntimeError('invalid fixed role operation')

if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['finalize']:
            finalize()
        elif sys.argv[1:] == ['frozen']:
            frozen()
        elif len(sys.argv) >= 3 and sys.argv[1] == 'entry':
            entry(*sys.argv[2:])
        else:
            raise RuntimeError('invalid fixed runtime operation')
    except Exception:
        print('gptbox runtime check failed; no readiness or agent admission', file=sys.stderr)
        sys.exit(2)
