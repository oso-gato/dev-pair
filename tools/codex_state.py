#!/usr/bin/env python3
"""Offline stock-Codex state/policy component checks; never an agent/job launcher."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time
import tomllib

from public_inputs import CODEX_SHA, CODEX_BYTES, CODEX_SOURCE

VERSION = 1
SECONDS = 180
OUTPUT_BYTES = 2 * 1024 ** 2
STATE_BYTES = 32 * 1024 ** 2
SNAPSHOT_BYTES = 384 * 1024 ** 2
MEMORY_BYTES = 2 * 1024 ** 3
FILE_BYTES = 16 * 1024 ** 2
REPORT_BYTES = 4 * 1024 ** 2
FEATURES = ('plugins', 'remote_plugin', 'hooks', 'shell_snapshot', 'shell_snapshot_v2', 'apps', 'skill_mcp_dependency_install')
READS = (':minimal', '/usr', '/opt', '/etc/codex', '/home/gpt', '/job')
WRITES = ('/job/src', '/job/build', '/tmp')
LOADER_FILES = ('config.toml', 'hooks.json', 'AGENTS.md', 'AGENTS.override.md')
LOADER_DIRS = ('skills', 'plugins', 'rules', 'agents', 'shell_snapshots', '.tmp/plugins', '.tmp/marketplaces')
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/home/gpt', 'CODEX_HOME': '/state/codex', 'TMPDIR': '/tmp', 'LANG': 'C.UTF-8'}
GATES = ('Fedora/Podman/Distrobox confinement and toolchain path inventory', 'distinct root/job ownership and protected credential links',
         'all real agent tool paths use managed child policy', 'complete loader/model-catalog inventory',
         'credential refresh, selected-model entitlement and UUID/session recovery')


def require(condition, text):
    if not condition:
        raise ValueError(text)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def generated_policy():
    features = {key: False for key in FEATURES}
    requirements = {'cli_auth_credentials_store': 'file', 'model_provider': 'openai', 'sqlite_home': '/state/sqlite',
                    'log_dir': '/state/logs', 'check_for_update_on_startup': False, 'allow_login_shell': False,
                    'allow_managed_hooks_only': True, 'allow_browser_and_computer_use': False, 'allow_remote_control': False,
                    'mcp_servers': {}, 'features': features, 'default_permissions': 'product-child',
                    'allowed_approval_policies': ['never'], 'allowed_permission_profiles': {'product-child': True},
                    'permissions': {'filesystem': {'deny_read': ['/credentials', '/state/sqlite', '/state/logs']},
                                    'product-child': {'filesystem': {**{p: 'read' for p in READS}, **{p: 'write' for p in WRITES}},
                                                      'network': {'enabled': False}}}}
    config = {'cli_auth_credentials_store': 'file', 'check_for_update_on_startup': False, 'allow_login_shell': False,
              'sqlite_home': '/state/sqlite', 'log_dir': '/state/logs', 'analytics': {'enabled': False}, 'features': features,
              'projects': {'/job/src': {'trust_level': 'untrusted'}},
              'shell_environment_policy': {'inherit': 'none', 'set': {k: ENV[k] for k in ('PATH', 'HOME', 'CODEX_HOME', 'TMPDIR')}}}
    return {'requirements': requirements, 'config': config}


def validate_policy(value):
    # Stock strict-config silently ignores unknown requirements. Exact local
    # structural AND scalar-type validation is mandatory before invoking it.
    def same(actual, expected):
        if type(actual) is not type(expected):
            return False
        if isinstance(expected, dict):
            return set(actual) == set(expected) and all(same(actual[k], v) for k, v in expected.items())
        if isinstance(expected, list):
            return len(actual) == len(expected) and all(same(a, b) for a, b in zip(actual, expected))
        return actual == expected
    require(same(value, generated_policy()), 'Unknown, changed or mistyped managed policy')
    return value


def toml(value):
    lines = []
    def emit(table, path):
        if path:
            lines.append('[' + '.'.join(json.dumps(p) for p in path) + ']')
        for key, item in table.items():
            if not isinstance(item, dict):
                lines.append(json.dumps(key) + ' = ' + json.dumps(item))
        for key, item in table.items():
            if isinstance(item, dict):
                emit(item, path + [key])
    emit(value, [])
    return '\n'.join(lines) + '\n'


def inventory(root):
    rows = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        require(not path.is_symlink() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'Unexpected seeded skill type')
        if path.is_file():
            require(info.st_size <= 4 * 1024 ** 2 and len(rows) < 2048, 'Seeded skills exceed budget')
            rows[str(path.relative_to(root))] = {'bytes': info.st_size, 'sha256': digest(path.read_bytes())}
    require(rows and any('.system/' in key for key in rows), 'Stock bundled skills were not seeded')
    require(sum(v['bytes'] for v in rows.values()) <= STATE_BYTES, 'Seeded skills exceed byte budget')
    return rows


def layout():
    return {'immutable': ['/usr', '/opt/codex', '/etc/codex', '/home/gpt', '/job',
                          *('/state/codex/' + n for n in (*LOADER_FILES, *LOADER_DIRS))],
            'writable_state': ['/state/codex', '/state/sqlite', '/state/logs'], 'product': ['/job/src', '/job/build'],
            'external_credentials': '/credentials', 'ephemeral': ['/tmp']}


def validate_manifest(value, skills):
    expected = {'version': VERSION, 'binary_sha256': CODEX_SHA, 'binary_bytes': CODEX_BYTES, 'codex_source_sha': CODEX_SOURCE,
                'harness_sha256': digest(Path(__file__).read_bytes()), 'policy_sha256': digest(canonical(generated_policy())),
                'requirements_sha256': digest(toml(generated_policy()['requirements']).encode()),
                'config_sha256': digest(toml(generated_policy()['config']).encode()),
                'skills_sha256': digest(canonical(skills)), 'skills': skills, 'layout': layout()}
    require(type(value) is dict and set(value) == set(expected) and canonical(value) == canonical(expected), 'Unknown or mismatched layout/policy manifest')
    require(type(value['version']) is int and type(value['binary_bytes']) is int, 'Mistyped manifest identity')
    require(type(skills) is dict and 0 < len(skills) <= 2048, 'Invalid skills inventory')
    for name, record in skills.items():
        require(type(name) is str and name and len(name.encode()) <= 512 and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')) and
                type(record) is dict and set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int and 0 <= record['bytes'] <= 4 * 1024 ** 2 and
                type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}', record['sha256']), 'Invalid skill inventory member')
    require(sum(record['bytes'] for record in skills.values()) <= STATE_BYTES and '.system/.codex-system-skills.marker' in skills, 'Missing or excessive bundled skills')
    return value


def make_manifest(skills):
    policy = generated_policy()
    return validate_manifest({'version': VERSION, 'binary_sha256': CODEX_SHA, 'binary_bytes': CODEX_BYTES, 'codex_source_sha': CODEX_SOURCE,
                              'harness_sha256': digest(Path(__file__).read_bytes()), 'policy_sha256': digest(canonical(policy)),
                              'requirements_sha256': digest(toml(policy['requirements']).encode()), 'config_sha256': digest(toml(policy['config']).encode()),
                              'skills_sha256': digest(canonical(skills)), 'skills': skills, 'layout': layout()}, skills)


def verify_returned_requirements(response):
    require(type(response) is dict and 'result' in response and type(response['result']) is dict, 'Managed requirements response missing')
    requirements = response['result'].get('requirements')
    required = {'cliAuthCredentialsStore': 'file', 'modelProvider': 'openai', 'sqliteHome': 'file:///state/sqlite', 'logDir': 'file:///state/logs',
                'checkForUpdateOnStartup': False, 'allowLoginShell': False, 'allowManagedHooksOnly': True,
                'allowBrowserAndComputerUse': False, 'allowRemoteControl': False, 'defaultPermissions': 'product-child',
                'allowedApprovalPolicies': ['never'], 'allowedPermissionProfiles': {'product-child': True},
                'featureRequirements': {key: False for key in FEATURES}}
    require(type(requirements) is dict and all(key in requirements and canonical(requirements[key]) == canonical(value) for key, value in required.items()),
            'Returned managed requirements do not match generated policy')
    return required


def verify_skills_response(response):
    require(type(response) is dict and type(response.get('result')) is dict, 'Stock skill response missing')
    data = response['result'].get('data')
    require(type(data) is list and len(data) == 1 and type(data[0]) is dict and data[0].get('cwd') == '/job' and data[0].get('errors') == [], 'Stock skill discovery errors or wrong cwd')
    skills = data[0].get('skills')
    require(type(skills) is list and skills and all(type(item) is dict and type(item.get('path')) is str and
            item['path'].startswith('/state/codex/skills/.system/') and '..' not in item['path'].split('/') and
            item.get('name') != 'product-marker' for item in skills), 'Mutable/unknown skill root or absent bundled skills')
    return skills


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate stock response field')
        value[key] = item
    return value


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))


class Harness:
    def __init__(self, root, binary):
        self.root = Path(root)
        self.end = time.monotonic() + SECONDS
        self.used = 0
        self.records = []
        self.checks = {}
        self.observations = {}
        self.rpc_buffers = {}
        self.binary = self.root / 'codex'
        fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source, self.binary.open('xb') as output:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size == CODEX_BYTES, 'Pinned binary regular-file size mismatch')
            hasher = hashlib.sha256()
            size = 0
            while data := source.read(1024 ** 2):
                self.remaining()
                size += len(data)
                require(size <= CODEX_BYTES, 'Binary changed or exceeded bound')
                hasher.update(data)
                output.write(data)
            require(size == CODEX_BYTES and hasher.hexdigest() == CODEX_SHA, 'Pinned stock binary digest mismatch')
        self.binary.chmod(0o500)
        self.fixture = self.root / 'fixture'
        for name in ('etc/codex', 'home', 'job/src/.git', 'job/build', 'state/codex', 'state/sqlite', 'state/logs', 'credentials'):
            (self.fixture / name).mkdir(parents=True, exist_ok=True)
        policy = validate_policy(generated_policy())
        for name, contents in (('etc/codex/requirements.toml', toml(policy['requirements'])), ('state/codex/config.toml', toml(policy['config'])),
                               ('state/codex/hooks.json', '{"hooks":{}}'), ('state/codex/AGENTS.md', ''), ('state/codex/AGENTS.override.md', ''),
                               ('credentials/marker', 'NONCREDENTIAL_AUTHORITY_MARKER'), ('state/codex/marker', 'SYNTHETIC_STATE_MARKER'),
                               ('state/sqlite/marker', 'SYNTHETIC_DB_MARKER'), ('job/src/.codex/config.toml', 'model="mutable-project-marker"\n'),
                               ('job/src/.agents/skills/product-marker/SKILL.md', '---\nname: product-marker\ndescription: offline marker only\n---\nNever installed runtime code.\n')):
            path = self.fixture / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        for name in LOADER_DIRS:
            (self.fixture / 'state/codex' / name).mkdir(parents=True, exist_ok=True)
        (self.fixture / 'job/src/credential-alias').symlink_to('/credentials/marker')
        # The enclosing user namespace maps this same fixture owner. This is
        # NOT distinct-owner/sticky/auth-link evidence and never claimed as such.
        self.command(['/usr/bin/true'], frozen=False)

    def remaining(self, maximum=20):
        value = min(maximum, self.end - time.monotonic())
        require(value > 0, 'Offline acceptance deadline exhausted')
        return value

    def budget(self):
        size = 0
        for count, path in enumerate(self.root.rglob('*')):
            require(count < 4096, 'Offline fixture entry budget exceeded')
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
        require(size <= SNAPSHOT_BYTES and size - CODEX_BYTES <= STATE_BYTES, 'Offline fixture storage budget exceeded')

    def argv(self, args, frozen=True):
        f = self.fixture
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--ro-bind', '/usr', '/usr',
                   '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
                   '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/etc', '--ro-bind', str(f / 'etc/codex'), '/etc/codex',
                   '--ro-bind', str(f / 'home'), '/home/gpt', '--dir', '/job', '--bind', str(f / 'job/src'), '/job/src',
                   '--bind', str(f / 'job/build'), '/job/build', '--dir', '/state', '--bind', str(f / 'state/codex'), '/state/codex',
                   '--bind', str(f / 'state/sqlite'), '/state/sqlite', '--bind', str(f / 'state/logs'), '/state/logs',
                   '--bind', str(f / 'credentials'), '/credentials', '--ro-bind', str(self.binary), '/opt/codex']
        if frozen:
            for name in (*LOADER_FILES, *LOADER_DIRS):
                command += ['--ro-bind', str(f / 'state/codex' / name), '/state/codex/' + name]
        return command + ['--remount-ro', '/', '--cap-drop', 'ALL', '--chdir', '/job', '--', *args]

    def start(self, args, frozen=True):
        return subprocess.Popen(self.argv(args, frozen), env={**ENV, 'OFFLINE_PARENT_CANARY': 'NONCREDENTIAL_MARKER'},
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=child_limits)

    def stop(self, process):
        try:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        finally:
            self.rpc_buffers.pop(process.pid, None)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def collect(self, process, pending=None):
        selector = selectors.DefaultSelector()
        for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        buffer = self.rpc_buffers.setdefault(process.pid, bytearray()) if pending is not None else None
        end = time.monotonic() + self.remaining()
        def response():
            while buffer is not None and b'\n' in buffer:
                line, _, rest = buffer.partition(b'\n')
                buffer[:] = rest
                require(len(line) <= 262144, 'Stock RPC line budget exceeded')
                try:
                    value = json.loads(line, object_pairs_hook=unique_object)
                except (ValueError, RecursionError):
                    raise ValueError('Malformed or duplicate stock RPC frame') from None
                require(type(value) is dict, 'Stock RPC must be an object')
                if 'id' in value:
                    require(type(value['id']) is int and value['id'] == pending, 'Unexpected stock RPC response identity')
                    return value
            return None
        next_disk = 0
        try:
            while selector.get_map():
                self.remaining()
                require(time.monotonic() < end, 'Offline child deadline exhausted')
                if time.monotonic() >= next_disk:
                    self.budget()
                    next_disk = time.monotonic() + .1
                value = response()
                if value is not None:
                    return value, output
                for key, _ in selector.select(min(.1, max(0, end - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), min(65536, OUTPUT_BYTES - self.used + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    self.used += len(data)
                    require(self.used <= OUTPUT_BYTES, 'Offline aggregate output budget exceeded')
                    output[key.data].extend(data)
                    if buffer is not None and key.data == 'stdout':
                        buffer.extend(data)
                        require(len(buffer) <= 262144, 'Stock RPC line budget exceeded')
            value = response()
            if value is not None:
                return value, output
            require(pending is None, 'Stock app-server ended before matching response')
            return process.wait(timeout=self.remaining()), output
        finally:
            selector.close()

    def command(self, args, frozen=True):
        process = self.start(args, frozen)
        try:
            process.stdin.close()
            code, output = self.collect(process)
            self.records.append({'operation': args[:3], 'exit_status': code, 'stdout_sha256': digest(output['stdout']),
                                 'stderr_sha256': digest(output['stderr']), 'stdout_bytes': len(output['stdout']), 'stderr_bytes': len(output['stderr'])})
            require(code == 0, 'Offline fixed command failed; bounded evidence: ' + bytes(output['stderr'][-1500:]).decode(errors='replace'))
            self.budget()
            return bytes(output['stdout'])
        finally:
            self.stop(process)

    @contextlib.contextmanager
    def rpc(self, frozen=True):
        process = self.start(['/opt/codex', 'app-server', '--strict-config'], frozen)
        counter = 0
        def call(method, params):
            nonlocal counter
            require(method in ('initialize', 'skills/list', 'config/read', 'configRequirements/read', 'config/value/write', 'thread/delete'), 'Unsupported offline RPC')
            counter += 1
            process.stdin.write(canonical({'id': counter, 'method': method, 'params': params}) + b'\n')
            process.stdin.flush()
            value, output = self.collect(process, counter)
            require(isinstance(value, dict), 'Stock app-server ended before response')
            self.records.append({'operation': method, 'response': value, 'stderr_sha256': digest(output['stderr']), 'stderr_bytes': len(output['stderr'])})
            self.budget()
            return value
        try:
            require('result' in call('initialize', {'clientInfo': {'name': 'dev_pair_offline', 'version': '1'}, 'capabilities': {'experimentalApi': True}}), 'Stock initialize failed')
            process.stdin.write(b'{"method":"initialized","params":{}}\n')
            process.stdin.flush()
            yield call
        finally:
            self.stop(process)

    def exercise(self):
        checks = self.checks
        identity = json.loads(self.command(['/usr/bin/python3', '-c', "import os,json,platform;from pathlib import Path;s=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x);print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'kernel':platform.release(),'network_namespace':os.readlink('/proc/self/ns/net'),'cap_eff':s['CapEff'].strip(),'no_new_privs':s['NoNewPrivs'].strip()}))"]))
        require(identity['network_namespace'] != os.readlink('/proc/self/ns/net') and int(identity['cap_eff'], 16) == 0, 'Actual outer namespace/capability boundary missing')
        checks['isolated_namespace_no_capabilities'] = True
        with self.rpc(frozen=False) as call:
            verify_skills_response(call('skills/list', {'cwds': ['/job'], 'forceReload': True}))
        skills = inventory(self.fixture / 'state/codex/skills')
        manifest = make_manifest(skills)
        checks['assembly_seeded_skills'] = True
        with self.rpc() as call:
            requirements = call('configRequirements/read', {})
            verify_returned_requirements(requirements)
            config = call('config/read', {'cwd': '/job', 'includeLayers': False})
            require(config.get('result', {}).get('config', {}).get('model_provider') == 'openai' and
                    config['result']['config'].get('sqlite_home') == '/state/sqlite', 'Stock configuration source/state mismatch')
            skills_response = call('skills/list', {'cwds': ['/job'], 'forceReload': True})
            verify_skills_response(skills_response)
            checks['fixed_cwd_discovery'] = True
            for key, value, expected_error in (('features.plugins', True, 'configValidationError'), ('sqlite_home', '/job/src/rogue-sqlite', 'configRequirementReadonly')):
                response = call('config/value/write', {'keyPath': key, 'value': value, 'mergeStrategy': 'replace'})
                require(response.get('error', {}).get('data', {}).get('config_write_error_code') == expected_error, 'Managed mutation did not produce its exact rejection')
            checks['managed_mutation_rejected'] = True
        features = self.command(['/opt/codex', '-c', 'features.plugins=true', 'features', 'list']).decode()
        resolved = {line.split()[0]: line.split()[-1] for line in features.splitlines() if line.split()}
        require(all(resolved.get(name) == 'false' for name in FEATURES), 'Resolved managed feature requirements not enforced')
        checks['resolved_feature_override_rejected'] = True
        self.synthetic_delete()
        checks['lexical_index_delete'] = True
        self.mount_check()
        checks['immutable_loader_mounts'] = True
        self.child_check()
        checks['managed_child_and_reinvoke'] = True
        databases = {}
        for path in sorted((self.fixture / 'state/sqlite').glob('*.sqlite')):
            with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as connection:
                databases[path.name] = connection.execute('PRAGMA integrity_check').fetchall()
        require(set(('state_5.sqlite', 'logs_2.sqlite', 'goals_1.sqlite', 'memories_1.sqlite', 'queue_1.sqlite')) <= set(databases) and
                all(rows == [('ok',)] for rows in databases.values()), 'Actual stock SQLite lifecycle/integrity failed')
        checks['sqlite_restarts_integrity'] = True
        require(inventory(self.fixture / 'state/codex/skills') == skills, 'Frozen bundled skills changed')
        return {'version': VERSION, 'scope': 'offline-stock-component-only', 'runtime_admitted': False,
                'checks': checks, 'observations': self.observations, 'identity': identity, 'sqlite_integrity': databases, 'manifest': manifest, 'remaining_gates': GATES, 'operations': self.records,
                'provenance': 'exact pinned digest; original signature receipt remains external',
                'budgets': {'monitor_interval_seconds': .1, 'memory_bytes_per_process': MEMORY_BYTES, 'native_file_bytes': FILE_BYTES, 'entries': 4096, 'seconds': SECONDS, 'output_bytes': OUTPUT_BYTES, 'state_bytes': STATE_BYTES, 'snapshot_bytes': SNAPSHOT_BYTES}}

    def synthetic_delete(self):
        uuid = '11111111-2222-4333-8444-555555555555'
        stamp = '2026-11-15T00:00:00Z'
        home = self.fixture / 'state/codex'
        rollout = home / ('sessions/2026/11/15/rollout-2026-11-15T00-00-00-' + uuid + '.jsonl')
        rollout.parent.mkdir(parents=True, exist_ok=True)
        rollout.write_bytes(canonical({'timestamp': stamp, 'type': 'session_meta', 'payload': {'id': uuid, 'timestamp': stamp, 'cwd': '/job',
                             'originator': 'offline_fixture', 'cli_version': '0.169.0', 'source': 'cli', 'model_provider': 'openai', 'history_mode': 'legacy'}}) + b'\n')
        index = home / 'session_index.jsonl'
        require(not index.is_symlink(), 'Session index may not be redirected through a file symlink')
        index.write_bytes(canonical({'id': uuid, 'thread_name': 'offline-synthetic', 'updated_at': stamp}) + b'\n')
        with self.rpc() as call:
            require('result' in call('thread/delete', {'threadId': uuid}), 'Stock synthetic delete failed')
        require(not rollout.exists() and not index.is_symlink() and uuid not in index.read_text(), 'Stock lexical index rewrite failed')

    def mount_check(self):
        script = r'''
import pathlib,os,json
r={}
for name,p,action in [('config-truncate','/state/codex/config.toml','write'),('config-unlink','/state/codex/config.toml','unlink'),
                      ('skills-rename','/state/codex/skills','rename'),('home-loader','/home/gpt/AGENTS.md','write'),('cwd-loader','/job/AGENTS.md','write')]:
 try:
  if action=='write':pathlib.Path(p).write_text('must be rejected')
  elif action=='unlink':pathlib.Path(p).unlink()
  else:pathlib.Path(p).rename(p+'-moved')
  r[name]=False
 except OSError as e:r[name]=e.errno in (13,16,30)
pathlib.Path('/state/codex/legitimate-state').write_text('state survives')
r['legitimate-state']=True
print(json.dumps(r))
'''
        result = json.loads(self.command(['/usr/bin/python3', '-c', script]))
        self.observations['immutable_mounts'] = result
        require(set(result) == {'config-truncate', 'config-unlink', 'skills-rename', 'home-loader', 'cwd-loader', 'legitimate-state'} and
                all(value is True for value in result.values()), 'Immutable mount or legitimate state check failed')

    def child_check(self):
        baseline = self.command(['/usr/bin/python3', '-c', "from pathlib import Path;assert all(Path(p).read_bytes() for p in ['/credentials/marker','/state/codex/marker','/state/sqlite/marker']);print('supervisor-readable')"])
        require(baseline.strip() == b'supervisor-readable', 'Supervisor markers unavailable; denial test vacuous')
        script = r'''
import os,json,pathlib,subprocess
r={'environment_cleared':'OFFLINE_PARENT_CANARY' not in os.environ}
for p in ['/credentials/marker','/state/codex/marker','/state/sqlite/marker','/job/src/credential-alias','/proc/1/root/credentials/marker']:
 try:pathlib.Path(p).read_bytes();r[p]=False
 except OSError as e:r[p]=e.errno in (2,13)
for p in ['/job/src/child-work','/job/build/child-work']:pathlib.Path(p).write_text('legitimate product write')
for p in ['/job/src/fresh-home','/job/src/fresh-codex']:pathlib.Path(p).mkdir(exist_ok=True)
nested_code="import pathlib,json\ntry:pathlib.Path('/credentials/marker').read_bytes();print(json.dumps({'executed':True,'denied':False}))\nexcept OSError as e:print(json.dumps({'executed':True,'denied':e.errno==13}))"
nested=subprocess.run(['/opt/codex','sandbox','--permission-profile',':danger-full-access','--','/usr/bin/python3','-c',nested_code],env=dict(os.environ,HOME='/job/src/fresh-home',CODEX_HOME='/job/src/fresh-codex'),capture_output=True,timeout=10)
r['nested_reinvoke_denied']=nested.returncode==0 and json.loads(nested.stdout)=={'executed':True,'denied':True}
print(json.dumps(r))
'''
        result = json.loads(self.command(['/opt/codex', 'sandbox', '--permission-profile', 'product-child', '--include-managed-config', '--cd', '/job', '--', '/usr/bin/python3', '-c', script]))
        self.observations['managed_child'] = result
        require(set(result) == {'environment_cleared', 'nested_reinvoke_denied', '/credentials/marker', '/state/codex/marker', '/state/sqlite/marker', '/job/src/credential-alias', '/proc/1/root/credentials/marker'} and
                all(value is True for value in result.values()), 'Managed child denied-read/environment/reinvoke check failed')
        require(all((self.fixture / p).read_text() == 'legitimate product write' for p in ('job/src/child-work', 'job/build/child-work')), 'Legitimate product writes failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    require(not args.report.exists() and not args.report.is_symlink(), 'Report destination must be new')
    report = {'version': VERSION, 'scope': 'offline-stock-component-only', 'runtime_admitted': False, 'status': 'blocked'}
    runner = None
    try:
        with tempfile.TemporaryDirectory(prefix='dev-pair-codex-') as root:
            runner = Harness(root, args.binary)
            report.update(runner.exercise(), status='pass')
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        report['blocker'] = str(error)[-2000:]
        if runner is not None:
            report.update(checks=runner.checks, observations=runner.observations, operations=runner.records, captured_bytes=runner.used)
    data = canonical(report) + b'\n'
    require(len(data) <= REPORT_BYTES, 'Offline report budget exceeded')
    fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
