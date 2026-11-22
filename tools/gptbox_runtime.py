#!/usr/bin/python3
"""Image-owned gptbox assembly and fixed headless role entry."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tomllib
import uuid

BASE = Path('/usr/lib/dev-pair/gptbox')
CODEX = Path('/opt/dev-pair/bin/codex')
WORK = Path('/work/job')
STATE = Path('/state')
CODEX_HOME = STATE / 'codex'
REQUIREMENTS = Path('/etc/codex/requirements.toml')
TURN_INPUTS = Path('/run/dev-pair-turn')
CREDENTIAL = Path('/credentials/api-key')
LOADER_FILES = ('config.toml', 'hooks.json', 'AGENTS.md', 'AGENTS.override.md')
LOADER_DIRS = ('skills', 'plugins', 'rules', 'agents', 'shell_snapshots', '.tmp/plugins', '.tmp/marketplaces')
TURN_READONLY_MOUNTS = (REQUIREMENTS.parent, TURN_INPUTS, CREDENTIAL.parent,
                        *(CODEX_HOME / name for name in (*LOADER_FILES, *LOADER_DIRS)))
STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
OFFLINE_KEY = b'dev-pair-offline-synthetic-not-a-credential'
TURN_BYTES = 1024 * 1024
TURN_SECONDS = 20
ENV = {'HOME': '/home/gpt', 'CODEX_HOME': str(CODEX_HOME),
       'PATH': '/opt/dev-pair/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp',
       'XDG_RUNTIME_DIR': '/run/user/1000', 'XDG_CACHE_HOME': '/cache/job',
       'XDG_STATE_HOME': '/state', 'XDG_CONFIG_HOME': '/home/gpt/.config'}

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

def frozen():
    if (os.getuid(), os.getgid()) != (1000, 1000):
        raise RuntimeError('frozen init must be unprivileged')
    verify_files()
    sealed = json.loads((BASE / 'sealed.json').read_text())
    if sealed['inputs_sha256'] != digest(BASE / 'inputs.json') or sealed['packages_sha256'] != digest(BASE / 'packages.txt'):
        raise RuntimeError('sealed assembly evidence mismatch')
    print('container_setup_done', flush=True)
    # This process is only immutable keepalive; it launches no agent or shell.
    os.execv('/usr/bin/sleep', ['sleep', 'infinity'])

def probe():
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
    for target in ('/etc/hostname', '/etc/hosts', '/etc/resolv.conf', '/etc/profile',
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


def role_policy(directive):
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
                                         '/state/codex/sessions', str(TURN_INPUTS)]},
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


def turn():
    image = verify_files()
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    require((os.getuid(), os.getgid()) == (1000, 1000) and os.getgroups() in ([], [1000]) and
            status['NoNewPrivs'].strip() == '1' and
            all(int(status[name].strip(), 16) == 0 for name in ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'))
            and interfaces == ['lo'], 'isolated headless runtime required')
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
        process = subprocess.run(argv, input=prompt, stdout=output, stderr=error,
                                 cwd=WORK, env={**ENV, 'CODEX_API_KEY': key}, timeout=TURN_SECONDS)
        os.fsync(output.fileno())
        os.fsync(error.fileno())
    require(process.returncode == 0, 'stock Codex returned a failure')
    events = fixed_read(destination / 'events.jsonl', TURN_BYTES)
    result = {'schema': 1, 'status': 'completed-turn', 'operation': selection['operation'],
              'role': selection['role'], 'model': selection['model'], 'effort': selection['effort'],
              'session_uuid': completed_turn(events), 'events_sha256': hashlib.sha256(events).hexdigest(),
              'events_bytes': len(events), 'transport': 'local-synthetic', 'runtime_admitted': False}
    temporary_result = destination / 'result.pending'
    with temporary_result.open('x') as record:
        json.dump(result, record, sort_keys=True)
        record.write('\n')
        record.flush()
        os.fsync(record.fileno())
    temporary_result.rename(destination / 'result.json')
    sync_directory(destination)
    print(json.dumps(result, sort_keys=True))


def entry(operation):
    os.environ.clear()
    os.environ.update({**ENV, 'CODEX_HOME': '/home/gpt/.codex'})
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
        elif len(sys.argv) == 3 and sys.argv[1] == 'entry':
            entry(sys.argv[2])
        else:
            raise RuntimeError('invalid fixed runtime operation')
    except Exception:
        print('gptbox runtime check failed; no readiness or agent admission', file=sys.stderr)
        sys.exit(2)
