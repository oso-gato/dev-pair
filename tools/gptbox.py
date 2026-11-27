#!/usr/bin/python3
"""Confined gptbox assembly, controlled role entry and development image export."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time
from types import ModuleType

from bootstrap import (Bootstrap, Blocked, STATE, DEVELOPMENT_HOST_INTENT, Commands, PrepareCost, KEYS_URL, PACKAGES, SOURCE_BASELINE,
                       SUDO_PACKAGE_QUERY, _RoleIdentity, _canonical_role_id, github_keys, operator_password,
                       role_subordinate_range, validate_sources)
import candidate
from gptbox_runtime import TURN_READONLY_MOUNTS

DBX_SHA = '40c3cd724faa434aeb0a23e28776665b92de68bd'
CODEX_SHA = 'b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b'
import fedora_oci
FEDORA = fedora_oci.IMAGE
BASE = '/usr/lib/dev-pair/gptbox'
RUNTIME = BASE + '/runtime.py'
CONTROL = '/usr/local/libexec/dev-pair-gptbox'
ROOT = STATE + '/gptbox-adapter'
ARTIFACTS = '/var/lib/dev-pair/artifacts/gptbox-adapter'
DEVELOPMENT_ROOT = STATE + '/gptbox-development'
DEVELOPMENT_ARTIFACTS = '/var/lib/dev-pair/artifacts/gptbox-development'
DEVELOPMENT_ARCHIVE_LIMIT = 2 * 1024 ** 3
DEVELOPMENT_EXPANSION_LIMIT = 8 * 1024 ** 3
DEVELOPMENT_EXECUTION = 2040
RELEASE_ARCHIVE = 'development.oci.tar'
RELEASE_INNER = 'inner.json'
INIT = ['/usr/bin/distrobox-init', '--name', 'gpt', '--user', '1000', '--group', '1000', '--home', '/home/gpt', '--init', '0']
FINAL_HOOK = 'exec /usr/bin/python3 ' + RUNTIME + ' finalize'
FROZEN_HOOK = 'exec /usr/bin/python3 ' + RUNTIME + ' frozen'
ASSEMBLY_LIFETIME = 900
RUNTIME_LIFETIME = 180
INITIALIZE_EXECUTION = 2280
PREPARE_EXECUTION = 600
PREPARE_NATIVE = 'dev-pair-initialize-prepare'
ADAPTER_EXECUTION = 1620
IMAGE_EXECUTION = 600
CLEANUP_EXECUTION = 45
COMMAND_CLEANUP_GRACE = 45
ADAPTER_SOURCE_FILES = ('gptbox.py', 'gptbox_runtime.py', 'bootstrap.py', 'selinux_bootstrap.py',
                        'candidate.py', 'native_io.py', 'native_relay.py', 'fedora_oci.py',
                        'public_inputs.py', 'storage.py', 'storage_observation.py', 'selected_payload.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def image_inputs_bytes(inputs):
    return json.dumps(inputs, sort_keys=True).encode() + b'\n'


def image_id(value):
    if type(value) is not str:
        raise Blocked('engine returned no immutable image/container identity')
    value = value.strip().removeprefix('sha256:')
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise Blocked('engine returned no immutable image/container identity')
    return value


def image_diff_ids(value):
    if (type(value) is not list or not 1 <= len(value) <= 128
            or any(type(diff) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', diff) for diff in value)):
        raise Blocked('missing or invalid ordered image DiffIDs')
    return value


def capture_release_file(path, maximum, owner, *, output=None, contents=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        node = os.fstat(stream.fileno())
        if (not stat.S_ISREG(node.st_mode) or node.st_nlink != 1 or node.st_uid != owner
                or not 0 < node.st_size <= maximum):
            raise Blocked('unsafe development release file or byte limit exceeded')
        digest = hashlib.sha256()
        data = bytearray()
        size = 0
        while block := stream.read(min(1024 * 1024, node.st_size - size + 1)):
            size += len(block)
            if size > node.st_size:
                raise Blocked('development release file grew during capture')
            digest.update(block)
            if output is not None:
                output.write(block)
            elif contents:
                data.extend(block)
        current = os.fstat(stream.fileno())
        if (size, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                node.st_size, node.st_size, node.st_mtime_ns, node.st_ctime_ns):
            raise Blocked('development release file changed during capture')
        return digest.hexdigest(), size, bytes(data)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ProbeCommands(Commands):
    """Bounded diagnostics only for credential-free assembly/probe operations."""
    diagnostic = None

    def __call__(self, *args, ok=(0,), input_text=None, timeout=900, sudo_probe=None, sudo_package=False):
        if sudo_probe is not None or sudo_package:
            return super().__call__(*args, ok=ok, input_text=input_text, timeout=timeout,
                                    sudo_probe=sudo_probe, sudo_package=sudo_package)
        if self.diagnostic is None:
            return super().__call__(*args, ok=ok, input_text=input_text, timeout=timeout)
        if input_text is not None:
            raise Blocked('probe diagnostics cannot accept stdin credentials or prompts')
        try:
            return self._call(*args, ok=ok, timeout=timeout, maximum=4194304, probe=True)
        except Blocked as error:
            raise Blocked('probe command failed or timed out; ' + ('cleanup-unresolved' if 'cleanup unresolved' in str(error) else 'interrupted-or-failed') + '; ' + str(error)) from None


class Gptbox(Bootstrap):
    role = 'maintenance'
    artifact_root = ARTIFACTS
    control = CONTROL

    def __init__(self, root=Path('/'), run=None):
        super().__init__(root, run or ProbeCommands())

    def protected(self, path):
        path = Path(path)
        if not path.is_absolute():
            raise Blocked('absolute reviewed input path required')
        for item in [path, *path.parents]:
            info = item.lstat()
            if item.is_symlink() or info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                raise Blocked('input/control path must be owned, protected and nonsymlink')
            if item == self.root:
                break
        return path

    def source(self, revision):
        if not re.fullmatch(r'[0-9a-f]{40}', revision or ''):
            raise Blocked('full reviewed adapter source revision required')
        repo = Path(__file__).resolve().parents[1]
        if self.run('/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD').strip() != revision:
            raise Blocked('adapter source HEAD differs from requested exact target')
        for name in ADAPTER_SOURCE_FILES:
            data = self.protected(Path(__file__).with_name(name)).read_bytes()
            recorded = self.run('/usr/bin/git', '-C', str(repo), 'show', revision + ':tools/' + name)
            if recorded.encode() != data:
                raise Blocked('adapter revision does not identify executing source')

    def context_inputs(self, context, expected, revision):
        self.protected(context)
        for file in Path(context).iterdir():
            self.protected(file)
        _, _, manifest = self.check_gptbox_inputs(context, expected, expected_role=self.role)
        if (manifest['role'] != self.role or manifest['fedora']['image'] != FEDORA
                or manifest['codex']['version'] != '0.169.0' or manifest['codex']['sha256'] != CODEX_SHA):
            raise Blocked('adapter requires independently verified pinned inputs for its role')
        if manifest['source_sha'] != revision or not re.fullmatch(r'[0-9a-f]{40}', revision or ''):
            raise Blocked('context source differs from requested adapter target')
        return manifest

    def inputs(self, context, expected, upstream, revision):
        manifest = self.context_inputs(context, expected, revision)
        self.source_stage = 'context-source'
        candidate.verify(context, expected)
        self.source_stage = 'executing-source'
        self.source(revision)
        self.source_stage = 'upstream-head-and-bytes'
        upstream = self.protected(upstream)
        if self.run('/usr/bin/git', '-C', str(upstream), 'rev-parse', 'HEAD').strip() != DBX_SHA:
            raise Blocked('upstream Distrobox HEAD differs from pinned target')
        scripts = {}
        for name in ('distrobox-init', 'distrobox-enter'):
            path = self.protected(upstream / name)
            recorded = self.run('/usr/bin/git', '-C', str(upstream), 'show', DBX_SHA + ':' + name)
            if recorded.encode() != path.read_bytes():
                raise Blocked('upstream Distrobox script does not match exact Git object')
            scripts[name] = path.read_bytes()
        self.protected(Path(fedora_oci._public_inputs().__file__))
        actual = self.run('/usr/bin/git','-C',str(Path(__file__).resolve().parents[1]),'show',revision+':tools/public_inputs.py')
        if actual.encode() != Path(fedora_oci._public_inputs().__file__).read_bytes():
            raise Blocked('executing public input dependency differs from reviewed source')
        return manifest, scripts

    def execute(self, *args, timeout=120, ok=(0,)):
        prefix = [value.replace('RuntimeMaxSec=1800', 'RuntimeMaxSec=' + str(timeout)) for value in self.executor]
        image_diagnostic=bool(getattr(self,'image_phase_active',False))
        previous_metadata = self.run.metadata_diagnostic if isinstance(self.run, Commands) else None
        if isinstance(self.run, ProbeCommands):
            current_diagnostic_recorded=False
            def diagnostic(buffers, status):
                nonlocal current_diagnostic_recorded
                path = self.target + '/diagnostics.json'
                prior = json.loads(self.text(path, '{"recent":[],"failures":[]}'))
                entry = {'status': status, 'scope': 'credential-free assembly/probe',
                         'diagnostic_identity':getattr(self,'failure_diagnostic_identity',None),
                         **{name + '_tail': ('' if image_diagnostic else bytes(data[-16384:]).decode('utf-8', errors='replace')) for name, data in buffers.items()},
                         **{name + '_truncated': len(data) > 16384 for name, data in buffers.items()},
                         **{name + '_bytes': len(data) for name, data in buffers.items()}}
                prior['recent'] = (prior['recent'] + [entry])[-4:]
                if status != 0:
                    prior['failures'] = (prior['failures'] + [entry])[-4:]
                self.record('diagnostics', prior)
                current_diagnostic_recorded=True
            def metadata(record):
                if not current_diagnostic_recorded:raise Blocked('current command diagnostic record unavailable')
                path = self.target + '/diagnostics.json'
                history = json.loads(self.text(path, '{"recent":[],"failures":[]}'))
                selected = {key: record[key] for key in ('operation_id','step','admission_stage', 'admission_outcome', 'admission_reason', 'relay_failure', 'relay_verified', 'native_exit_status', 'accepted_exit', 'elapsed_seconds','native_failure','signed_load_payload') if key in record}
                latest = history['recent'][-1] if history['recent'] else None
                failed = bool(latest is not None and history['failures'] and history['failures'][-1] == latest)
                if latest is not None:
                    latest.update(selected)
                if failed:
                    history['failures'][-1].update(selected)
                if 'sealed_signed_load' in record and 'sealed_signed_load' not in history:
                    history['sealed_signed_load']=record['sealed_signed_load']
                    history['sealed_signed_load_binding']={key:record[key] for key in ('step','operation_id','relay_verified','native_exit_status','signed_load_payload') if key in record}
                    history['sealed_signed_load_binding']['diagnostic_identity']=getattr(self,'failure_diagnostic_identity',None)
                self.record('diagnostics', history)
            self.run.diagnostic = diagnostic
            self.run.metadata_diagnostic = metadata
        try:
            scope=self.run.adapter_image_launcher(self.target.rsplit('/',1)[-1],self.uid,getattr(self,'failure_diagnostic_identity',None)) if image_diagnostic and isinstance(self.run,Commands) else contextlib.nullcontext()
            previous_step=getattr(self.run,'current_step',None)
            try:
                if image_diagnostic:self.run.current_step='candidate-image'
                with scope:return self.run(*prefix,*args,timeout=timeout+30,ok=ok)
            finally:
                if image_diagnostic:self.run.current_step=previous_step
        finally:
            if isinstance(self.run, ProbeCommands):
                self.run.diagnostic = None
                self.run.metadata_diagnostic = previous_metadata

    def engine(self, *args, timeout=120, ok=(0,)):
        return self.execute(self.wrapper, *args, timeout=timeout, ok=ok)

    def setup_executor(self, retry=False, *, verified=None):
        if self.role == 'development':
            if type(verified) is not _RoleIdentity or verified.name != 'dp-maint':
                raise Blocked('development executor requires live verified builder identity')
            uid, self.gid = str(verified.uid), str(verified.gid)
        else:
            uid = self.run('/usr/bin/id', '-u', 'dp-maint').strip()
            if not uid.isdigit() or int(uid) < 1000:
                raise Blocked('invalid maintenance runtime UID')
            self.gid = self.run('/usr/bin/id', '-g', 'dp-maint').strip()
            if not self.gid.isdigit() or int(self.gid) < 1000:
                raise Blocked('invalid maintenance primary GID')
        self.uid = uid
        control = self.control
        self.directory('/usr/local/libexec', mode=0o755)
        self.directory(control, mode=0o755)
        self.directory(control + '/home', mode=0o755)
        self.directory(control + '/xdg-config', mode=0o755)
        self.directory(control + '/bin', mode=0o755)
        self.directory(control + '/empty-hooks', mode=0o755)
        if any(self.path(control + '/empty-hooks').iterdir()) or any(self.path(control + '/home').iterdir()) or any(self.path(control + '/xdg-config').iterdir()):
            raise Blocked('controller home/hooks contain undeclared parent integration')
        config = '[containers]\nnetns="private"\n[engine]\nevents_logger="file"\n'
        self.atomic(control + '/containers.conf', config, mode=0o444)
        context = self.target.rsplit('/', 1)[-1]
        if self.role == 'development':
            storage = self.artifact_root + '/' + context + '/image-store'
            self._directory_as(storage, 0o700, verified.uid, verified.gid, change_owner=True, check_gid=True)
        else:
            storage = '/var/lib/dev-pair/maintenance/images'
            self.directory(storage, owner='dp-maint')
        runroot = f'/run/user/{uid}/dev-pair-gptbox'
        script = '#!/bin/sh\n'
        if self.role == 'development':
            runroot += '-development-' + context
            destination = self.path(self.artifact_root + '/' + context + '/export-work/image-copy') / RELEASE_ARCHIVE
            self.atomic(control + '/export-containers.conf', config + 'image_copy_tmp_dir = ' +
                        json.dumps(str(destination.parent)) + '\n', mode=0o444)
            engine = f'/usr/bin/podman --root {shlex.quote(str(self.path(storage)))} --runroot {runroot} --storage-driver=vfs --events-backend=file'
            limit = DEVELOPMENT_ARCHIVE_LIMIT
            script += (f'if [ "$#" = 5 ] && [ "$1" = save ] && [ "$2" = --format=oci-archive ] && '
                       f'[ "$3" = --output ] && [ "$4" = {shlex.quote(str(destination))} ]; then '
                       f'exec /usr/bin/prlimit --fsize={limit}:{limit} {engine} "$@"; fi\n')
        else:
            engine = f'/usr/bin/podman --root {self.path(storage)} --runroot {runroot} --storage-driver=vfs --events-backend=file'
        limit = fedora_oci.SAVE_FILE_LIMIT
        script += (f'if [ "$1" = save ]; then exec /usr/bin/prlimit --fsize={limit}:{limit} {engine} "$@"; fi\n'
                   f'exec {engine} "$@"\n')
        self.wrapper = str(self.path(control + '/bin/podman'))
        self.atomic(control + '/bin/podman', script, mode=0o555)
        self.atomic(control + '/distrobox-enter', self.scripts['distrobox-enter'].decode(), mode=0o555)
        self.run('/usr/sbin/restorecon', '-RF', str(self.path(control)))
        self.run('/usr/bin/systemctl', 'start', f'user@{uid}.service')
        self.unit = 'dev-pair-gptbox-' + self.target.rsplit('/', 1)[-1] + '.service'
        status = self.run('/usr/bin/systemctl', 'show', '--property=User', '--property=Description', '--property=ActiveState', self.unit, ok=(0, 1, 4))
        values = dict(line.split('=', 1) for line in status.splitlines() if '=' in line)
        if values.get('ActiveState') in ('active', 'activating', 'deactivating', 'reloading'):
            if not retry or values.get('User') != 'dp-maint' or values.get('Description') != 'dev-pair-owned-' + self.unit:
                raise Blocked('context executor is still busy; explicit bounded retry required')
            self.run('/usr/bin/systemctl', 'stop', self.unit, timeout=30)
            after = self.run('/usr/bin/systemctl', 'show', '--property=ActiveState', self.unit, ok=(0, 1, 4))
            if any(value in after for value in ('=active', '=activating', '=deactivating', '=reloading')):
                raise Blocked('prior context executor has not stopped; no cleanup or duplicate operation')
        if retry and isinstance(self.run, Commands):
            self.run.reconcile_native(('--unit=' + self.unit, '--description=dev-pair-owned-' + self.unit, '--uid=dp-maint'), {})
        self.executor = ['/usr/bin/systemd-run', '--unit=' + self.unit, '--description=dev-pair-owned-' + self.unit, '--quiet', '--wait', '--collect', '--service-type=exec',
                         '--uid=dp-maint', '--property=RuntimeMaxSec=1800', '--property=TimeoutStopSec=10',
                         '--property=KillMode=control-group', '--property=MemoryMax=2G', '--property=TasksMax=512',
                         '--property=CPUQuota=100%', '/usr/bin/env', '-i', 'PATH=' + str(self.path(control + '/bin')) + ':/usr/bin:/usr/sbin:/bin',
                         'HOME=' + str(self.path(control + '/home')), 'USER=gpt', 'LOGNAME=gpt',
                         'XDG_RUNTIME_DIR=/run/user/' + uid, 'XDG_CONFIG_HOME=' + str(self.path(control + '/xdg-config')),
                         'CONTAINERS_CONF=' + str(self.path(control + '/containers.conf')),
                         'DBX_CONTAINER_MANAGER=podman']

    def record(self, name, value):
        path = self.target + '/' + name + '.json'
        self.atomic(path, json.dumps(value, sort_keys=True) + '\n', expected=self.text(path) or None)

    def inspect_container(self, identity, sealed, runtime=True, timeout=30):
        rows = json.loads(self.engine('inspect', '--type=container', identity, timeout=timeout))
        if not isinstance(rows, list) or len(rows) != 1:
            raise Blocked('ambiguous engine inspection')
        item = rows[0]
        host, config = item['HostConfig'], item['Config']
        if image_id(item['Id']) != identity or image_id(item['Image']) != sealed:
            raise Blocked('container identity/image mismatch')
        if host.get('Privileged') or any('label=disable' in str(value) or 'unconfined' in str(value) for value in host.get('SecurityOpt', [])):
            raise Blocked('privilege or confinement bypass in inspected container')
        network_ok = host.get('NetworkMode') == 'none' if runtime else host.get('NetworkMode') in ('slirp4netns', 'slirp4netns:allow_host_loopback=false')
        if host.get('PidMode') != 'private' or host.get('IpcMode') != 'private' or host.get('UTSMode') != 'private' or not network_ok:
            raise Blocked('host/shared namespaces are not admitted')
        if host.get('UsernsMode') not in (('private', 'keep-id') if runtime else ('private',)):
            raise Blocked('host user namespace is not admitted')
        if runtime:
            if (not host.get('ReadonlyRootfs') or config.get('User') != '1000:1000'
                    or host.get('CapAdd') or item.get('EffectiveCaps') != [] or item.get('BoundingCaps') != []
                    or not any('no-new-privileges' in str(value) for value in host.get('SecurityOpt', []))):
                raise Blocked('runtime code/privilege policy mismatch')
            if not re.fullmatch(r'system_u:system_r:container_t:s0:c[0-9]+,c[0-9]+', item.get('ProcessLabel', '')):
                raise Blocked('effective confined SELinux process label missing')
            if not item.get('MountLabel', '').startswith('system_u:object_r:container_file_t:s0:'):
                raise Blocked('effective SELinux mount label missing')
            mappings = item.get('HostConfig', {}).get('IDMappings') or item.get('IDMappings', {})
            # Probe also proves writable bind ownership. Mapping metadata must show keep-id.
            for key, host_id in (('UidMap', self.uid), ('GidMap', self.gid)):
                values = mappings.get(key, [])
                if not any(value in ('1000:0:1', '1000:' + host_id + ':1') for value in values):
                    raise Blocked('keep-id mapping for writable service-account data is not proven')
            if (host.get('Memory') != 2147483648 or host.get('PidsLimit') != 256
                    or host.get('NanoCpus') != 1000000000):
                raise Blocked('runtime resource budget mismatch')
            if config.get('Labels', {}).get('manager') != 'distrobox' or config.get('Labels', {}).get('distrobox.unshare_groups') != '0':
                raise Blocked('actual Distrobox entry metadata mismatch')
        if not runtime:
            if (host.get('Memory') != 2147483648 or host.get('PidsLimit') != 512 or host.get('NanoCpus') != 1000000000
                    or ':container_engine_t:s0:' not in item.get('ProcessLabel', '')):
                raise Blocked('isolated assembly budget/confinement mismatch')
        if config.get('Timeout') != (RUNTIME_LIFETIME if runtime else ASSEMBLY_LIFETIME):
            raise Blocked('independent native container lifetime is missing or mismatched')
        policy = host.get('RestartPolicy', {})
        if policy.get('Name') not in ('no', '') or policy.get('MaximumRetryCount', 0) != 0:
            raise Blocked('automatic OCI restart would bypass finite candidate lifetime')
        tmpfs = host.get('Tmpfs')
        if not isinstance(tmpfs, dict) or set(tmpfs) != {'/run', '/tmp'}:
            raise Blocked('tmpfs mounts must exactly match the private runtime allowlist')
        for destination, value in tmpfs.items():
            if not isinstance(value, str):
                raise Blocked('invalid tmpfs inspection format')
            options = set(value.split(','))
            if not {'rw', 'nosuid', 'nodev'} <= options or options & {'ro', 'suid', 'dev'}:
                raise Blocked('tmpfs access/security options mismatch')
            expected_mode = 0o700 if runtime else (0o755 if destination == '/run' else 0o1777)
            mode = [entry[5:] for entry in options if entry.startswith('mode=')]
            if len(mode) != 1 or not re.fullmatch(r'[0-7]{3,4}', mode[0]) or int(mode[0], 8) != expected_mode:
                raise Blocked('tmpfs mode differs from the fixed construction policy')
            for entry in options:
                if entry in {'rw', 'nosuid', 'nodev', 'noexec', 'rprivate', 'private', 'relatime', 'noatime', 'strictatime'} or entry.startswith('mode='):
                    continue
                if entry.startswith(('uid=', 'gid=')):
                    if entry.split('=', 1)[1] != ('1000' if runtime else '0'):
                        raise Blocked('tmpfs ownership mismatch')
                elif not re.fullmatch(r'size=[0-9]+[kKmMgG]?', entry):
                    raise Blocked('undeclared tmpfs option')
            if runtime and not {'uid=1000', 'gid=1000'} <= options:
                raise Blocked('runtime tmpfs ownership is not inspected')
        actual = {}
        for mount in item.get('Mounts', []):
            if mount.get('Type') == 'tmpfs' and mount.get('Destination') in ('/run', '/tmp'):
                continue
            if mount.get('Type') != 'bind':
                raise Blocked('undeclared mount type')
            actual[mount['Destination']] = (mount['Source'], bool(mount.get('RW')))
        if actual != (self.mounts if runtime else {}):
            raise Blocked('unexpected/missing host bind mount')
        return item

    def enter(self, identity, sealed, operation):
        if operation not in ('probe', 'version', 'turn'):
            raise Blocked('unsupported fixed role entry')
        before = self.inspect_container(identity, sealed)
        if before['State']['Status'] != 'running':
            raise Blocked('entry requires an already running exact target; no auto-create/start fallback')
        if operation == 'turn':
            expected = {'/work/job': True, '/state': True, '/cache/job': True,
                        **dict.fromkeys(map(str, TURN_READONLY_MOUNTS), False)}
            actual = [mount for mount in before['Mounts'] if mount.get('Type') == 'bind']
            if (len(actual) != len(expected)
                    or {mount['Destination']: mount.get('RW') for mount in actual} != expected
                    or not before['State'].get('StartedAt')):
                raise Blocked('headless role entry requires the exact running job mounts')
        output = self.execute(str(self.path(CONTROL + '/distrobox-enter')),
                          '--name', identity, '--no-tty', '--no-workdir', '--clean-path', '--',
                          '/usr/bin/python3', '-I', RUNTIME, 'entry', operation, timeout=30)
        after = self.inspect_container(identity, sealed)
        if operation == 'turn' and (after['State']['Status'] != 'running' or
                                   before['State']['StartedAt'] != after['State'].get('StartedAt')):
            raise Blocked('runtime changed during headless entry; inspect durable turn state')
        return output

    def ready(self, identity, sealed, previous_start=None):
        deadline = time.monotonic() + 30
        first = self.inspect_container(identity, sealed, timeout=5)
        started = first.get('State', {}).get('StartedAt')
        if (not isinstance(started, str) or not re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})', started)
                or started == previous_start):
            raise Blocked('current container start identity is missing or stale')
        while time.monotonic() < deadline:
            observed = self.inspect_container(identity, sealed, timeout=5)
            if observed['State']['Status'] != 'running' or observed['State'].get('StartedAt') != started:
                raise Blocked('frozen initializer exited or changed start identity before readiness')
            logs = self.engine('logs', '--since=' + started, '--tail=20', identity, timeout=5)
            if 'container_setup_done' in logs.splitlines():
                return started
            time.sleep(0.2)
        raise Blocked('frozen Distrobox readiness deadline exceeded')

    def recover_resources(self, expected):
        record = json.loads(self.text(self.target + '/resources.json', '{}'))
        if not record:
            return
        for name, wanted_image in record.items():
            if not re.fullmatch(r'dp-gptbox-[ar]-' + expected[:16] + r'-[12]', name):
                raise Blocked('resource recovery name is outside bounded target')
            raw = self.engine('inspect', '--type=container', name, ok=(0, 125))
            rows = json.loads(raw) if raw.strip() else []
            if not rows:
                continue
            if (not isinstance(rows, list) or len(rows) != 1
                    or rows[0]['Config'].get('Labels', {}).get('dev-pair.context') != expected
                    or image_id(rows[0]['Image']) != wanted_image):
                raise Blocked('foreign container collision preserved during recovery')
            self.engine('rm', '--force', image_id(rows[0]['Id']))

    def recover_image_work(self, expected):
        work = self.path(self.artifact_root + '/' + expected + '/image-work')
        if not work.exists() and not work.is_symlink(): return
        self.protected(work)
        def reconcile():
            if isinstance(self.run, Commands):
                self.run.reconcile_native(('--unit='+self.unit,'--description=dev-pair-owned-'+self.unit,'--uid=dp-maint'), {})
        fedora_oci.recover_workspaces(work,uid=int(self.uid),reconcile=reconcile)

    def observe_assembled_storage(self,expected,revision,sealed):
        prepared=json.loads(self.text(STATE+'/gptbox-image.json'))
        if prepared.get('source_sha')!=revision or prepared.get('context_sha256')!=expected:
            raise Blocked('storage prepared identity mismatch')
        return self.observe_storage('assembled-postcleanup',revision,expected,prepared['image_id'],sealed)

    def _prepared_completion(self,context,expected,revision,manifest):
        path=self.protected(self.path(STATE+'/gptbox-image.json'))
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            node=os.fstat(stream.fileno())
            if not stat.S_ISREG(node.st_mode) or node.st_nlink!=1 or stat.S_IMODE(node.st_mode)!=0o600 or node.st_size>16384:raise Blocked('unsafe prepared completion')
            try:record=json.loads(stream.read(16385),object_pairs_hook=fedora_oci.unique)
            except (ValueError,UnicodeError):raise Blocked('invalid prepared completion JSON') from None
        if type(record) is not dict:raise Blocked('invalid prepared completion')
        common=(record.get('source_sha')==revision and record.get('context_sha256')==expected and record.get('base_image')==FEDORA and
            record.get('codex_sha256')==manifest['codex']['sha256'] and record.get('distrobox_assembled') is False and record.get('runtime_validated') is False and
            type(record.get('image_id')) is str and re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}',record['image_id']))
        if not common:raise Blocked('prepared completion target/pins mismatch')
        if record.get('kind')=='host-maintenance-gptbox-oci-candidate':
            keys=set('kind source_sha context_sha256 base_image codex_sha256 image_id local_tag runtime_user storage_driver launch distrobox_assembled runtime_validated fedora_base'.split())
            if not keys<=set(record)<=keys|{'logical_storage'} or record['local_tag']!='localhost/dev-pair/maintenance-gptbox:'+expected or record['runtime_user']!='dp-maint' or record['storage_driver']!='vfs' or record['launch']!='blocked: stock Distrobox 1.8.2.5 adds privileged, label=disable and host mounts':raise Blocked('unsupported legacy prepared completion')
            if 'logical_storage' in record:
                value=record['logical_storage']
                if type(value) is not dict or set(value)!={'logical_size_bytes','layer_count','layer_digests','semantics'} or value['semantics']!='logical-descriptors-not-unique-physical-usage':raise Blocked('invalid legacy logical descriptors')
                size=value['logical_size_bytes'];layers=value['layer_digests'];count=value['layer_count']
                if not (size is None or type(size) is int and 0<=size<2**63) or not (layers is None and count is None or type(layers) is list and len(layers)<=128 and type(count) is int and count==len(layers) and all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v) for v in layers)):raise Blocked('invalid legacy logical descriptors')
        elif record.get('kind')=='full-adapter-candidate':
            keys=set('schema kind source_sha context_sha256 standards_sha base_image codex_sha256 distrobox_sha init_sha256 runtime_sha256 inputs_sha256 recipe_sha256 platform distrobox_assembled runtime_validated image_id fedora_base'.split())
            if set(record)!=keys or type(record['schema']) is not int or record['schema']!=1 or record['standards_sha']!=candidate.STANDARDS or record['distrobox_sha']!=DBX_SHA or record['platform']!={'os':'linux','architecture':'amd64'} or record['runtime_sha256']!=sha(Path(__file__).with_name('gptbox_runtime.py').read_bytes()) or record['init_sha256']!=sha(self.scripts['distrobox-init']):raise Blocked('invalid full prepared completion')
            build=self.path('/var/lib/dev-pair/artifacts/gptbox-adapter/'+expected+'/build')
            for name,key in (('inputs.json','inputs_sha256'),('Containerfile','recipe_sha256')):
                if sha(self.protected(build/name).read_bytes())!=record[key]:raise Blocked('prepared recipe/input hash mismatch')
        else:raise Blocked('unknown prepared recipe kind')
        try:fedora_oci.validate_import_proof(record['fedora_base'])
        except (ValueError,KeyError,TypeError):raise Blocked('prepared signed import proof rejected') from None
        return record

    def assemble(self, context, expected, upstream, revision, apply=False, retry=False):
        self.preflight()
        manifest, self.scripts = self.inputs(context, expected, upstream, revision)
        self.failure_diagnostic_identity={'source_sha':revision,'context_sha256':expected,'phase':'maintenance-gptbox'}
        if not apply:
            return {'preview': True, 'changes': False, 'job_admission': False,
                    'operation': 'genuine Distrobox assembly, seal, boundary/version entry and restart probes'}
        if not self.path(STATE + '/prepared').exists():
            raise Blocked('normal host preparation must complete first')
        with self.lock():
            return self._assemble_locked(context,expected,upstream,revision,manifest,retry=retry)

    def _assemble_locked(self,context,expected,upstream,revision,manifest,*,retry=False,fresh=False,on_prepared=None):
        prepared=self._prepared_completion(context,expected,revision,manifest) if not fresh else None
        self.target = ROOT + '/' + expected
        self.directory(self.target, mode=0o755)
        previous = json.loads(self.text(self.target + '/attempt.json', '{}'))
        if previous and (set(previous)!={'source_sha','context_sha256','distrobox_sha','count'} or type(previous.get('count')) is not int or not 1<=previous['count']<=2):raise Blocked('invalid protected attempt record')
        if previous and (previous.get('source_sha') != revision or previous.get('context_sha256') != expected or previous.get('distrobox_sha') != DBX_SHA):
            raise Blocked('changed assembly target requires separately reviewed recovery')
        self.image_stage('executor-setup',revision,expected)
        self.setup_executor(retry=bool(previous and retry))
        def verify_prepared_image():
            if prepared is None:return
            rows=json.loads(self.engine('image','inspect',prepared['image_id']))
            if type(rows) is not list or len(rows)!=1 or type(rows[0]) is not dict or type(rows[0].get('Id')) is not str or image_id(rows[0]['Id'])!=image_id(prepared['image_id']) or rows[0].get('Os')!='linux' or rows[0].get('Architecture')!='amd64':raise Blocked('prepared immutable image unavailable')
            labels=rows[0].get('Labels') or (rows[0].get('Config',{}).get('Labels',{}) if type(rows[0].get('Config',{})) is dict else {})
            wanted={'dev-pair.context':expected,'org.opencontainers.image.revision':revision,'dev-pair.role':'maintenance','dev-pair.standards':candidate.STANDARDS,'dev-pair.codex.version':'0.169.0'}
            if prepared['kind']=='full-adapter-candidate':wanted.update({'dev-pair.distrobox':DBX_SHA,'dev-pair.inputs':prepared['inputs_sha256'],'dev-pair.runtime':prepared['runtime_sha256'],'dev-pair.init':prepared['init_sha256'],'dev-pair.codex.sha256':prepared['codex_sha256']})
            if type(labels) is not dict or any(labels.get(k)!=v for k,v in wanted.items()):raise Blocked('prepared immutable image labels mismatch')
        if self.path(self.target + '/result.json').exists():
            verify_prepared_image()
            if fresh or self.path(self.target+'/candidate-image.json').exists():
                if not self.path(self.target+'/candidate-image.json').exists():raise Blocked('completed initialize lacks full candidate record')
                self._full_candidate(context,expected,revision,manifest,fresh=fresh,on_prepared=on_prepared)
            result = json.loads(self.text(self.target + '/result.json'))
            if (result.get('source_sha') != revision or result.get('context_sha256') != expected
                    or result.get('distrobox_sha') != DBX_SHA or result.get('boundary_and_version_cycles') != 2
                    or result.get('runtime_container_removed') is not True or result.get('job_admission') is not False):
                raise Blocked('completed adapter identity/evidence mismatch')
            self.recover_resources(expected)
            rows = json.loads(self.engine('image', 'inspect', result['assembled_image_id']))
            labels = (rows[0].get('Labels') or rows[0].get('Config', {}).get('Labels', {})) if len(rows) == 1 else {}
            if (len(rows) != 1 or image_id(rows[0]['Id']) != result['assembled_image_id']
                    or labels.get('dev-pair.context') != expected or labels.get('dev-pair.distrobox') != DBX_SHA
                    or labels.get('org.opencontainers.image.revision') != revision):
                raise Blocked('recorded assembled image is unavailable')
            self.observe_assembled_storage(expected,revision,result['assembled_image_id'])
            return {**result, 'reused_completed_evidence': True}
        if previous and not retry:
            raise Blocked('incomplete attempt requires explicit --retry; evidence remains intact')
        count = previous.get('count', 0) + 1
        if count > 2:
            cleanup_path = self.target + '/cleanup-only.json'
            cleanup = json.loads(self.text(cleanup_path, '{"count":0}'))
            if cleanup.get('count', 0) >= 2:
                raise Blocked('cleanup-only retry budget exhausted; native lifetimes still bound candidates')
            cleanup = {'count': cleanup['count'] + 1, 'phase': 'begin', 'build_attempts': previous['count']}
            self.record('cleanup-only', cleanup)
            self.recover_resources(expected)
            self.recover_image_work(expected)
            self.record('cleanup-only', {**cleanup, 'phase': 'complete'})
            raise Blocked('build budget exhausted; exact owned resources cleaned without another build')
        if previous:
            self.recover_resources(expected)
            self.recover_image_work(expected)
        if shutil.disk_usage(self.path('/var/lib/dev-pair')).free < 8 * 1024 ** 3:
            raise Blocked('eight GiB free reserve is required before assembly')
        verify_prepared_image()
        self.record('attempt', {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA, 'count': count})
        base,imported,inputs=self._full_candidate(context,expected,revision,manifest,fresh=fresh,on_prepared=on_prepared)
        if shutil.disk_usage(self.path('/var/lib/dev-pair')).free < 8 * 1024 ** 3:
            raise Blocked('eight GiB free reserve is required after image construction before actual assembly')
        self.image_stage('assembly',revision,expected)
        stage = runtime_id = None
        stage_name, runtime_name = 'dp-gptbox-a-' + expected[:16] + '-' + str(count), 'dp-gptbox-r-' + expected[:16] + '-' + str(count)
        self.record('resources', {stage_name: base})
        try:
            stage = self.create_assembly_stage(stage_name, expected, base)
            sealed, _ = self.seal_assembly_stage(stage, base, revision, inputs)
            self.record('resources', {stage_name: base, runtime_name: sealed})
            # A separate immutable runtime, never the writable assembly container.
            self.mounts = {}
            mount_args = []
            for directory, destination in (('workspaces', '/work/job'), ('state', '/state'), ('cache', '/cache/job')):
                source = '/var/lib/dev-pair/maintenance/' + directory + '/gptbox-probe'
                self.directory(source, owner='dp-maint')
                self.mounts[destination] = (str(self.path(source)), True)
                mount_args += ['--volume', str(self.path(source)) + ':' + destination + ':rw,Z']
            self.image_stage('runtime',revision,expected)
            runtime_id = image_id(self.engine('create', '--name=' + runtime_name, '--label=dev-pair.context=' + expected, '--timeout=' + str(RUNTIME_LIFETIME), '--restart=no', '--read-only', '--read-only-tmpfs=false', '--user=1000:1000',
                '--userns=keep-id:uid=1000,gid=1000', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--network=none', '--pid=private', '--ipc=private', '--uts=private', '--memory=2g', '--pids-limit=256', '--cpus=1',
                '--no-hosts', '--no-hostname', '--dns=none', '--tmpfs=/run:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,notmpcopyup', '--tmpfs=/tmp:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,notmpcopyup',
                '--hooks-dir=' + str(self.path(CONTROL + '/empty-hooks')), '--label=manager=distrobox', '--label=distrobox.unshare_groups=0',
                *mount_args, '--entrypoint=/usr/bin/distrobox-init', sealed, *INIT[1:], '--pre-init-hooks', FROZEN_HOOK))
            self.inspect_container(runtime_id, sealed)
            previous_start = None
            for cycle in range(2):
                self.engine('start', runtime_id)
                previous_start = self.ready(runtime_id, sealed, previous_start)
                observed = json.loads(self.enter(runtime_id, sealed, 'probe'))
                if observed.get('boundary_probe') != 'passed':
                    raise Blocked('runtime boundary probe did not pass')
                if self.enter(runtime_id, sealed, 'version').strip() != 'codex-cli 0.169.0':
                    raise Blocked('actual Distrobox entry returned unexpected Codex identity')
                self.engine('stop', '--time=10', runtime_id)
            result = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': revision, 'context_sha256': expected,
                      'distrobox_sha': DBX_SHA, 'fedora_base': imported, 'assembled_image_id': sealed, 'runtime_container_id': runtime_id,
                      'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False, 'authentication': 'not verified',
                      'model_access': 'not verified', 'nested_placement': 'not verified',
                      'note': 'Probe-only candidate; no Codex job, credential or model request is admitted.'}
        except BaseException:
            self.record('failure', {'status': 'blocked-or-interrupted', 'job_admission': False,
                                   'diagnostics': 'bounded protected diagnostics.json; collect additional scoped audit AVCs externally'})
            raise
        finally:
            for identity in (runtime_id, stage):
                if identity:
                    self.engine('rm', '--force', identity)
        self.observe_assembled_storage(expected,revision,sealed)
        self.record('result', result)
        self.image_stage('complete',revision,expected)
        return result

    def create_assembly_stage(self, name, expected, base):
        return image_id(self.engine('create', '--name=' + name, '--label=dev-pair.context=' + expected,
            '--timeout=' + str(ASSEMBLY_LIFETIME), '--restart=no',
            '--network=slirp4netns:allow_host_loopback=false', '--pid=private', '--ipc=private', '--uts=private',
            '--userns=private', '--cap-add=SYS_ADMIN', '--security-opt=no-new-privileges',
            '--security-opt=label=type:container_engine_t', '--memory=2g', '--pids-limit=512', '--cpus=1',
            '--tmpfs=/run:rw,nosuid,nodev,mode=0755,notmpcopyup', '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777,notmpcopyup',
            '--hooks-dir=' + str(self.path(self.control + '/empty-hooks')), '--entrypoint=/usr/bin/distrobox-init',
            base, *INIT[1:], '--', FINAL_HOOK))

    def seal_assembly_stage(self, stage, base, revision, inputs):
        self.inspect_container(stage, base, runtime=False)
        output = self.engine('start', '--attach', stage, timeout=ASSEMBLY_LIFETIME)
        lines = output.strip().splitlines()
        attestation = json.loads(lines[-1], object_pairs_hook=fedora_oci.unique) if lines else None
        if (type(attestation) is not dict or attestation.get('kind') != 'genuine-distrobox-assembled'
                or attestation.get('inputs_sha256') != sha(image_inputs_bytes(inputs))
                or attestation.get('source_sha') != revision or attestation.get('uid') != 1000 or attestation.get('gid') != 1000):
            raise Blocked('actual upstream finalizer attestation is missing or mismatched')
        self.record('assembly-attestation', attestation)
        if self.role == 'development':
            stopped = self.inspect_container(stage, base, runtime=False)['State']
            if stopped.get('Status') not in ('exited', 'stopped') or stopped.get('Running') is not False:
                raise Blocked('development commit requires the exact stopped Distrobox stage')
            format_args = ('--format=oci',)
        else:
            stopped = json.loads(self.engine('inspect', '--type=container', stage))[0]['State']
            format_args = ()
        if stopped.get('ExitCode') != 0 or stopped.get('Running'):
            raise Blocked('actual upstream assembly did not exit successfully')
        return image_id(self.engine('commit', '--pause=false', *format_args, stage)), attestation


    def image_stage(self,stage,revision,expected):
        allowed=('executor-setup','input-staging','signed-import','build','immutable-inspect','completion-record','storage','prepared-marker','assembly','runtime','export','complete')
        if stage not in allowed:raise Blocked('unknown image stage')
        self.record('image-progress',{'schema':1,'source_sha':revision,'context_sha256':expected,'phase':'candidate-image','stage':stage})

    def _full_candidate(self,context,expected,revision,manifest,*,fresh=False,on_prepared=None):
        budget=self.run.phase(IMAGE_EXECUTION,'dev-pair-gptbox-image',native=False) if isinstance(self.run,Commands) else contextlib.nullcontext()
        inherited_native=getattr(self.run,'native_prefix',None)
        self.image_phase_active=True;previous_marker=self.text(STATE+'/prepared')
        try:
            with budget:
                # Engine argv already names its unit; root storage collection
                # still needs the enclosing adapter's registered native wrapper.
                if isinstance(self.run,Commands):self.run.native_prefix=inherited_native
                result=self._candidate_image(context,expected,revision,manifest,fresh=fresh)
            if on_prepared:on_prepared()
            return result
        except BaseException:
            # A late timer/publication failure cannot leave this attempt's new
            # marker as public admission; durable image proof remains for retry.
            if fresh and not previous_marker and self.text(STATE+'/prepared')==self.text(STATE+'/desired.json'):
                marker=self.path(STATE+'/prepared')
                if marker.exists():self.protected(marker).unlink()
            raise
        finally:self.image_phase_active=False

    def _candidate_image(self,context,expected,revision,manifest,*,fresh=False,on_prepared=None):
        self.image_stage('input-staging',revision,expected)
        self.directory('/var/lib/dev-pair/artifacts', mode=0o755)
        self.directory(self.artifact_root, mode=0o755)
        self.directory(self.artifact_root + '/' + expected, mode=0o755)
        build = self.artifact_root + '/' + expected + '/build'
        self.directory(build, mode=0o755)
        runtime = Path(__file__).with_name('gptbox_runtime.py').read_bytes()
        files = {'codex': Path(context, 'codex').read_bytes(), 'distrobox-init': self.scripts['distrobox-init'],
                 'runtime.py': runtime}
        inputs = {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA,
                  'role': self.role,
                  'files': {'/opt/dev-pair/bin/codex': sha(files['codex']), '/usr/bin/distrobox-init': sha(files['distrobox-init']), RUNTIME: sha(runtime)}}
        input_bytes = image_inputs_bytes(inputs)
        input_digest = sha(input_bytes)
        # Match the pinned upstream setup_dnf availability resolution; aliases
        # absent from Fedora's architecture-specific metadata are not forced.
        dependencies = ('bash bash-completion bc bzip2 cracklib-dicts curl diffutils dnf-plugins-core findutils '
                        'glibc-all-langpacks glibc-common glibc-locale-source gnupg2 gnupg2-smime hostname iproute '
                        'iputils keyutils krb5-libs less lsof man-db man-pages mtr ncurses nss-mdns openssh-clients '
                        'pam passwd pigz pinentry procps-ng rsync shadow-utils sudo tcpdump time traceroute tree '
                        'tzdata unzip util-linux util-linux-script vte-profile wget wget2-wget which whois words '
                        'xorg-x11-xauth xz zip mesa-dri-drivers mesa-vulkan-drivers vulkan')
        recipe = (f'FROM {FEDORA}\n'
                  'RUN set -eu; dnf -y --refresh --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 --disablerepo="*" --enablerepo=fedora --enablerepo=updates upgrade; for file in /etc/dnf/dnf.conf /etc/yum.conf; do '
                  'if [ -f "$file" ]; then sed -i "/tsflags=nodocs/d" "$file"; fi; done; dnf -q --setopt=gpgcheck=1 --disablerepo="*" --enablerepo=fedora --enablerepo=updates list '
                  + dependencies + ' > /tmp/upstream-packages; '
                  'grep -v Packages /tmp/upstream-packages | grep "$(uname -m)" | cut -d" " -f1 > /tmp/resolved-packages; '
                  'test -s /tmp/resolved-packages; '
                  'dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 --disablerepo="*" --enablerepo=fedora --enablerepo=updates '
                  'install --allowerasing python3 coreutils $(cat /tmp/resolved-packages); '
                  'test -d /usr/share/i18n/charmaps; test -f /usr/share/zoneinfo/UTC; '
                  'locale -a | grep -qi en_us.utf8 || localedef -i en_US -f UTF-8 en_US.UTF-8; '
                  'mkdir -p /usr/lib/dev-pair/gptbox; '
                  'rpm -qa --qf "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n" | sort > /usr/lib/dev-pair/gptbox/rpms.txt; '
                  'rm /tmp/upstream-packages /tmp/resolved-packages; dnf clean all\n'
                  f'COPY --chmod=0555 codex /opt/dev-pair/bin/codex\nCOPY --chmod=0555 distrobox-init /usr/bin/distrobox-init\nCOPY --chmod=0555 runtime.py {RUNTIME}\nCOPY --chmod=0444 inputs.json {BASE}/inputs.json\n'
                  f'LABEL dev-pair.context={expected} dev-pair.distrobox={DBX_SHA} org.opencontainers.image.revision={revision} dev-pair.role={self.role} dev-pair.standards={candidate.STANDARDS} dev-pair.codex.version=0.169.0 dev-pair.inputs={input_digest} dev-pair.runtime={sha(runtime)} dev-pair.init={sha(files['distrobox-init'])} dev-pair.codex.sha256={sha(files['codex'])}\nENV HOME=/home/gpt PATH=/opt/dev-pair/bin:/usr/bin:/bin container=podman LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8\n')
        lines = recipe.splitlines()
        # Fixed source-controlled package/locale operation, never submitted
        # script input. This native inner bound also covers detached RUN
        # helpers; remaining build/VM budgets can still end sooner.
        lines[1] = 'RUN /usr/bin/timeout --signal=TERM --kill-after=10s 540s /bin/sh -ec ' + shlex.quote(lines[1][4:])
        recipe = '\n'.join(lines) + '\n'
        for name, data in {**files, 'inputs.json': input_bytes, 'Containerfile': recipe.encode()}.items():
            # Binary-safe atomic creation in a protected new build directory.
            destination = self.path(build) / name
            if destination.exists():
                if destination.is_symlink() or destination.read_bytes() != data or stat.S_IMODE(destination.stat().st_mode) != 0o444:
                    raise Blocked('staged adapter build bytes conflict')
                continue
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
            with os.fdopen(descriptor, 'wb') as output:
                os.fchmod(output.fileno(), 0o444)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        if sha(files['codex'])!=manifest['codex']['sha256']:
            raise Blocked('full candidate Codex input identity mismatch')
        binding={'schema':1,'kind':'full-adapter-candidate','source_sha':revision,'context_sha256':expected,
            'standards_sha':candidate.STANDARDS,'base_image':FEDORA,'codex_sha256':sha(files['codex']),
            'distrobox_sha':DBX_SHA,'init_sha256':sha(files['distrobox-init']),'runtime_sha256':sha(runtime),
            'inputs_sha256':input_digest,'recipe_sha256':sha(recipe.encode()),
            'platform':{'os':'linux','architecture':'amd64'},'distrobox_assembled':False,'runtime_validated':False}
        location=self.target+'/candidate-image.json'
        path=self.path(location);exists=path.exists() or path.is_symlink();prior=None
        if exists:
            self.protected(path)
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise Blocked('unsafe full candidate completion record')
                prior=json.loads(stream.read(16385),object_pairs_hook=fedora_oci.unique)
            if type(prior) is not dict:raise Blocked('invalid full candidate completion record')
        if prior is not None:
            if type(prior) is not dict or type(prior.get('schema')) is not int or prior.get('distrobox_assembled') is not False or prior.get('runtime_validated') is not False or set(prior)!=set(binding)|{'image_id','fedora_base'} or any(prior[k]!=v for k,v in binding.items()):
                raise Blocked('full candidate completion identity/schema conflict')
            if type(prior['image_id']) is not str or not re.fullmatch('[0-9a-f]{64}',prior['image_id']):raise Blocked('invalid full candidate image ID')
            base=image_id(prior['image_id']);imported=prior['fedora_base']
        else:
            first_error=None
            def image_call(*args,**kwargs):
                nonlocal first_error
                try:return self.execute(*args,**kwargs)
                except BaseException as error:
                    if first_error is None:first_error=error
                    raise
            def reconcile_copy():
                if isinstance(self.run, Commands):
                    self.run.reconcile_native(('--unit='+self.unit,'--description=dev-pair-owned-'+self.unit,'--uid=dp-maint'), {})
            work = self.artifact_root + '/' + expected + '/image-work'
            self.directory(work, mode=0o755)
            try:
                with fedora_oci.image_workspaces(self.path(work), uid=int(self.uid), reconcile=reconcile_copy, reserve=8*1024**3) as (copy_tmp, verification_root):
                    try:
                        self.image_stage('signed-import',revision,expected)
                        with fedora_oci.verified(context, temporary_parent=verification_root, leased=True) as (plain, proof):
                            imported = fedora_oci.import_image(lambda *args, **kw: image_call('/usr/bin/env','TMPDIR='+str(copy_tmp),self.wrapper,*args,**kw), plain, uid=int(self.uid))
                        self.image_stage('build',revision,expected)
                        base = image_id(image_call('/usr/bin/env','TMPDIR='+str(copy_tmp),self.wrapper,'build', '--quiet', '--network=slirp4netns:allow_host_loopback=false', '--pull=never', '--http-proxy=false', '--file', str(self.path(build) / 'Containerfile'), str(self.path(build)), timeout=600))
                    except BaseException as error:
                        if first_error is None:first_error=error
                        raise
            except BaseException:
                try:self.record('image-failure',{'stage':'candidate-image','cleanup':'uncertain; exact ownership retained','job_admission':False})
                except Exception:pass  # A diagnostic write cannot replace the first image failure.
                if first_error is not None:raise first_error from None
                raise
            self.record('fedora-base', imported)
        try:fedora_oci.validate_import_proof(imported)
        except (ValueError,TypeError,KeyError):raise Blocked('stored signed import/saveback proof rejected') from None
        self.image_stage('immutable-inspect',revision,expected)
        rows=json.loads(self.engine('image','inspect',base))
        if type(rows) is not list or len(rows)!=1 or type(rows[0]) is not dict or type(rows[0].get('Id')) is not str:raise Blocked('malformed full candidate immutable inspection')
        config=rows[0].get('Config',{})
        if type(config) is not dict:raise Blocked('malformed full candidate labels')
        labels=rows[0].get('Labels') or config.get('Labels',{})
        if type(labels) is not dict:raise Blocked('malformed full candidate labels')
        wanted={'dev-pair.context':expected,'dev-pair.distrobox':DBX_SHA,'org.opencontainers.image.revision':revision,
            'dev-pair.role':self.role,'dev-pair.standards':candidate.STANDARDS,'dev-pair.codex.version':'0.169.0',
            'dev-pair.inputs':binding['inputs_sha256'],'dev-pair.runtime':binding['runtime_sha256'],'dev-pair.init':binding['init_sha256'],'dev-pair.codex.sha256':binding['codex_sha256']}
        if (type(rows) is not list or len(rows)!=1 or image_id(rows[0]['Id'])!=base or rows[0].get('Architecture')!='amd64' or
            rows[0].get('Os')!='linux' or any(labels.get(k)!=v for k,v in wanted.items())):
            raise Blocked('full candidate immutable image/platform/labels mismatch')
        complete={**binding,'image_id':base,'fedora_base':imported}
        self.image_stage('completion-record',revision,expected)
        if prior is None:self.record('candidate-image',complete)
        if self.role == 'maintenance':
            existing=json.loads(self.text(STATE+'/gptbox-image.json','null'),object_pairs_hook=fedora_oci.unique)
            if type(existing) is dict and existing.get('kind')=='full-adapter-candidate' and existing!=complete:raise Blocked('prepared full candidate record conflict')
            if fresh:self._publish_prepared(complete,revision,expected)
        return base,imported,inputs


    def _validate_host_ready(self,ready,revision,expected):
        path=self.protected(self.path(STATE+'/host-ready.json'))
        actual=json.loads(path.read_text(),object_pairs_hook=fedora_oci.unique)
        wanted={'schema':1,'kind':'host-prerequisites','source_sha':revision,'context_sha256':expected,
            'standards_sha':candidate.STANDARDS,'bootstrap_sha256':sha(Path(__file__).with_name('bootstrap.py').read_bytes()),
            'desired_sha256':sha(self.text(STATE+'/desired.json').encode()),'packages_sha256':sha(self.text(STATE+'/packages.txt').encode())}
        if actual!=wanted or ready!=wanted:raise Blocked('fresh host prerequisite identity mismatch')
        return actual

    def _publish_prepared(self,complete,revision,expected):
        ready=json.loads(self.text(STATE+'/host-ready.json'),object_pairs_hook=fedora_oci.unique)
        self._validate_host_ready(ready,revision,expected)
        path=STATE+'/gptbox-image.json';old=self.text(path)
        if old and json.loads(old,object_pairs_hook=fedora_oci.unique)!=complete:
            raise Blocked('prepared record conflict; no silent minimal/full migration')
        self.atomic(path,json.dumps(complete,sort_keys=True)+'\n',expected=old or None)
        self.image_stage('storage',revision,expected)
        self.observe_storage('prepared-image',revision,expected,complete['image_id'])
        desired=self.text(STATE+'/desired.json')
        old_marker=self.text(STATE+'/prepared')
        if old_marker and old_marker!=desired:raise Blocked('prepared marker identity conflict')
        self.image_stage('prepared-marker',revision,expected)
        self.atomic(STATE+'/prepared',desired,expected=old_marker or None)
        self.event('prepare','complete')

    def preparation(self):
        return Bootstrap(self.root, Commands())

    def initialize(self, context, expected, upstream, revision, sources, password_file=None, apply=False, retry=False):
        # The outer ceiling includes admission/fetch and a finite cleanup reserve.
        # Read-only admission uses no native unit; ordinary effects have their
        # own registered native cgroups and tighter phase ceilings below.
        with self.run.phase(INITIALIZE_EXECUTION, 'dev-pair-initialize', native=False):
            return self._initialize(context, expected, upstream, revision, sources, password_file, apply, retry)

    def _initialize(self, context, expected, upstream, revision, sources, password_file=None, apply=False, retry=False):
        self.preflight()
        validate_sources(sources)
        _, _, manifest = self.check_gptbox_inputs(context, expected)
        if manifest['source_sha'] != revision or not re.fullmatch(r'[0-9a-f]{40}', revision or ''):
            raise Blocked('initialize context/source target mismatch')
        # Python-only protection/content admission precedes even the narrow Git
        # prerequisite. Full Git identity verification follows before normal effects.
        self.protected(upstream)
        for name in ('distrobox-init', 'distrobox-enter'):
            self.protected(Path(upstream) / name)
        for name in ADAPTER_SOURCE_FILES:
            self.protected(Path(__file__).with_name(name))
        self.protected(Path(fedora_oci._public_inputs().__file__))
        if self.path('/usr/bin/git').exists():
            self.inputs(context, expected, upstream, revision)
        password = operator_password(password_file) if password_file else None
        if password is None and not self.path(STATE + '/operator-password-set').exists():
            raise Blocked('first initialization requires a securely supplied core password file')
        if not apply:
            return {'preview': 'initialize', 'changes': False, 'source_sha': revision,
                    'context_sha256': expected, 'distrobox_sha': DBX_SHA, 'job_admission': False,
                    'source_verification': 'complete' if self.path('/usr/bin/git').exists() else 'pending signed Git prerequisite'}
        target = {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA,
                  'bootstrap_sources': validate_sources(sources)}
        path = STATE + '/initialize.json'
        # The journey lock and existing global bootstrap lock span the private
        # host handoff and image/assembly; public entry points take that lock separately.
        with self.lock('initialize.lock'), self.lock():
            self._reject_development_host_intent()
            prior = json.loads(self.text(path, '{}'))
            if prior and (type(prior.get('schema',1)) is not int or prior.get('schema',1) not in (1,2)):raise Blocked('unsupported initializer state schema')
            if prior and (prior.get('phase') not in ('prepare','maintenance-gptbox','complete') or any(prior.get(k) not in ('pending','blocked','complete') for k in ('prepare','maintenance_gptbox'))):raise Blocked('invalid initializer phase record')
            if prior and prior.get('target') != target:
                raise Blocked('initialize target differs from protected prior intent')
            if prior and prior.get('phase') != 'complete' and not retry:
                raise Blocked('partial initialize requires explicit exact-target --retry')
            if prior and retry:
                # Reconcile the exact durable root-unit names before any retry
                # effects; descriptions prevent stopping an unrelated unit.
                for unit in prior.get('native_units', []):
                    if not re.fullmatch(r'dev-pair-initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}', unit):
                        raise Blocked('invalid protected initializer unit identity')
                    self.run.reconcile_native(('--unit=' + unit, '--description=dev-pair-owned-' + unit),
                                              {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
            record = {'schema':2,'host_prerequisites':'pending','candidate_image':'pending','adapter_commenced':False,'native_units': prior.get('native_units', []), 'target': target, 'phase': 'prepare', 'prepare': 'pending', 'maintenance_gptbox': 'pending',
                      'job_admission': False, 'limits_seconds': {
                          'execution': INITIALIZE_EXECUTION, 'prepare': PREPARE_EXECUTION, 'adapter': ADAPTER_EXECUTION,
                          'image': IMAGE_EXECUTION, 'cleanup': CLEANUP_EXECUTION, 'command_cleanup_grace': COMMAND_CLEANUP_GRACE,
                          'assembly_native': ASSEMBLY_LIFETIME, 'runtime_native': RUNTIME_LIFETIME}}
            def save():
                self.atomic(path, json.dumps(record, sort_keys=True) + '\n', expected=self.text(path) or None)
            cost=None
            def diagnostic(entry,phase='prepare'):
                entry={**entry,'diagnostic_identity':{'source_sha':revision,'context_sha256':expected,'phase':phase}}
                if cost is not None and phase=='prepare':cost.command(entry)
                location = STATE + '/prepare-diagnostics.json' if phase=='prepare' else self.target+'/diagnostics.json'
                history = json.loads(self.text(location, '{"recent":[],"failures":[]}'))
                history['recent'] = (history['recent'] + [entry])[-4:]
                if entry.get('accepted_exit') is not True:
                    history['failures'] = (history['failures'] + [entry])[-4:]
                if 'sudo_package' in entry:
                    history['sudo_package'] = entry['sudo_package']
                if entry.get('operation_id') in ('maintenance-sudo-denial', 'development-sudo-denial') and 'sudo_denial' in entry:
                    history.setdefault('sudo_denials', {})[entry['operation_id']] = entry['sudo_denial']
                self.atomic(location, json.dumps(history, sort_keys=True) + '\n', expected=self.text(location) or None)
            save()
            def register(unit):
                if unit not in record['native_units']:
                    if len(record['native_units']) >= 512:
                        raise Blocked('initializer native unit evidence budget exhausted')
                    record['native_units'].append(unit)
                    save()
            preparation = self.preparation()
            preparation.run.native_register = register
            self.run.native_register = register
            preparation.run.diagnostic = diagnostic
            def source_check():
                previous = self.run.metadata_diagnostic
                def source_diagnostic(metadata):
                    status = metadata['status']
                    diagnostic({'operation': 'withheld', 'operation_id': 'source-git-read',
                                'step': 'adapter-source-and-upstream', 'status': status,
                                'accepted_exit': metadata['accepted_exit'], 'outcome': metadata['outcome'],
                                **{key:metadata[key] for key in ('elapsed_seconds','launcher_handle_observed','native_failure') if key in metadata}},phase='maintenance-gptbox' if record['host_prerequisites']=='complete' else 'prepare')
                try:
                    self.run.metadata_diagnostic = source_diagnostic
                    self.source_stage = 'input-content'
                    observed_inputs=self.inputs(context, expected, upstream, revision)
                    record['source_verification'] = {'stage': 'all-inputs', 'outcome': 'complete'}
                    return observed_inputs
                except BaseException:
                    record['source_verification'] = {'stage': getattr(self, 'source_stage', 'unavailable'), 'outcome': 'blocked-or-interrupted'}
                    raise
                finally:
                    self.run.metadata_diagnostic = previous
                    save()
            prepare_started = time.monotonic()
            record['prepare_cost_attempt']=os.urandom(16).hex()
            record['prepare_budget_scope']='host-prerequisites'
            cost=PrepareCost(revision,expected,record['prepare_cost_attempt'],prepare_started,phase='host-prerequisites')
            preparation.prepare_cost=cost
            adapter_started = None
            def snapshot_prepare_observations():
                cost.finish(record['host_prerequisites']=='complete')
                witness = getattr(preparation.run,'phase_budget_witness',None)
                record['prepare_budget_witness'] = dict(witness) if type(witness) is dict else None
                record['prepare_cost']=cost.snapshot(witness)
                record['role_directory_batches'] = {key:dict(value) for key,value in
                    getattr(preparation,'role_directory_batches',{}).items()}
            try:
                with preparation.run.phase(PREPARE_EXECUTION, PREPARE_NATIVE):
                    keys = github_keys()
                    # The shared preparation/adapter context unit has a fixed
                    # owner description. Retry reconciles it before prepare.
                    if prior and retry:
                        unit = 'dev-pair-gptbox-' + expected + '.service'
                        preparation.run.reconcile_native(('--unit=' + unit, '--description=dev-pair-owned-' + unit, '--uid=dp-maint'),
                                                         {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
                    ready=preparation._host_prerequisites('core',keys,sources,context,expected,password=password,source_check=source_check)
                    cost.mark('finalization')
                cost.finish(True)
                snapshot_prepare_observations()
                record.update(phase='maintenance-gptbox',host_prerequisites='complete',
                              host_prepare_elapsed_seconds=round(time.monotonic() - prepare_started, 3))
                self.target = ROOT + '/' + expected
                save()
                adapter_started = time.monotonic()
                with self.run.phase(ADAPTER_EXECUTION, 'dev-pair-initialize-adapter'):
                    self._validate_host_ready(ready,revision,expected)
                    self.directory(self.target,mode=0o755)
                    manifest,self.scripts=source_check()
                    self.failure_diagnostic_identity={'source_sha':revision,'context_sha256':expected,'phase':'maintenance-gptbox'}
                    record.update(adapter_commenced=True,candidate_image='pending');save()
                    def prepared():
                        record.update(prepare='complete',candidate_image='complete',prepare_elapsed_seconds=round(time.monotonic()-prepare_started,3));save()
                    result=self._assemble_locked(context,expected,upstream,revision,manifest,retry=retry,fresh=True,on_prepared=prepared)
                record.update(phase='complete', maintenance_gptbox='complete', result=result,
                              adapter_elapsed_seconds=round(time.monotonic() - adapter_started, 3))
                save()
                return record
            except BaseException:
                snapshot_prepare_observations()
                # Preserve successful prerequisite phase independently. Native
                # per-command and OCI lifetimes remain finite after interruption.
                if record['prepare'] != 'complete':
                    record['prepare'] = 'blocked'
                    record['prepare_elapsed_seconds'] = round(time.monotonic() - prepare_started, 3)
                    if record['adapter_commenced']:record['candidate_image']='blocked'
                    else:record['host_prerequisites']='blocked'
                else:
                    record['maintenance_gptbox'] = 'blocked'
                    record['adapter_elapsed_seconds'] = round(time.monotonic() - (adapter_started or time.monotonic()), 3)
                record['prepare_step'] = getattr(preparation, 'prepare_step', 'not-started')
                record['failure'] = 'blocked-or-interrupted; inspect protected diagnostics; explicit retry required'
                record['cleanup'] = 'not verified; root-only native stdin transport may remain until exact retry/reboot; native/OCI lifetimes remain finite'
                if record['adapter_commenced']:
                    try:
                        with self.run.phase(CLEANUP_EXECUTION, 'dev-pair-initialize-cleanup'):
                            cleanup = json.loads(self.text(self.target + '/cleanup-only.json', '{"count":0}'))
                            if cleanup.get('count', 0) >= 2:
                                raise Blocked('shared adapter cleanup-only budget exhausted')
                            cleanup = {'count': cleanup['count'] + 1, 'phase': 'begin',
                                       'origin': 'initialize-failure', 'context_sha256': expected, 'source_sha': revision}
                            self.record('cleanup-only', cleanup)
                            self.setup_executor(retry=True)
                            self.recover_resources(expected)
                            self.recover_image_work(expected)
                            self.record('cleanup-only', {**cleanup, 'phase': 'complete'})
                        record['cleanup'] = 'exact owned executor/recorded resources reconciled'
                    except BaseException:
                        record['cleanup'] = 'blocked; exact resources retained; native lifetimes enforced'
                save()
                raise
            finally:
                self.run.native_register = None
                preparation.run.native_register = None


class DevelopmentGptbox(Gptbox):
    role = 'development'
    artifact_root = DEVELOPMENT_ARTIFACTS

    def protect_host_sources(self, upstream, revision):
        def regular(path):
            node = self.protected(path).lstat()
            if not stat.S_ISREG(node.st_mode) or node.st_nlink != 1:
                raise Blocked('development host source requires protected regular files')

        repo = Path(__file__).parents[1]
        upstream = Path(upstream)
        for name in ADAPTER_SOURCE_FILES:
            regular(repo / 'tools' / name)
        regular(Path(fedora_oci._public_inputs().__file__))
        regular(repo / 'runtime/devbox/controller.py')
        for name in ('distrobox-init', 'distrobox-enter'):
            regular(upstream / name)
        # Only sanitized, digest-verified public-input extraction is admitted.
        # Protect the Git inputs too, including configuration and object paths.
        for checkout, head in ((repo, revision), (upstream, DBX_SHA)):
            metadata = checkout / '.git'
            for relative, names in (('', {'HEAD', 'config', 'shallow', 'refs', 'objects'}),
                                    ('refs', {'heads'}), ('refs/heads', {'public-input'}),
                                    ('objects', {'pack'})):
                directory = self.protected(metadata / relative)
                if {p.name for p in directory.iterdir()} != names:
                    raise Blocked('development host requires the extracted public-input Git layout')
            for relative, value in {
                'HEAD': 'ref: refs/heads/public-input\n',
                'config': '[core]\nrepositoryformatversion=0\nbare=false\nfilemode=true\n',
                'shallow': head + '\n', 'refs/heads/public-input': head + '\n',
            }.items():
                data = self.protected_bytes(metadata / relative, 4096)
                if data != value.encode():
                    raise Blocked('development host Git metadata differs from the extracted target')
            pack = self.protected(metadata / 'objects/pack')
            names = {p.name for p in pack.iterdir()}
            if len(names) not in (2, 3) or any(not re.fullmatch(r'pack-[0-9a-f]{40}\.(pack|idx|rev)', name) for name in names):
                raise Blocked('unexpected development host Git object layout')
            prefix = next(iter(names)).rsplit('.', 1)[0]
            if names not in ({prefix + '.pack', prefix + '.idx'}, {prefix + '.pack', prefix + '.idx', prefix + '.rev'}):
                raise Blocked('development host Git object pack and index do not match')
            for name in names:
                regular(pack / name)

    def prepare_development_host(self, context, expected, upstream, revision, sources, password_file=None,
                                 apply=False, retry=False):
        sources = validate_sources(sources)
        result = {'kind': 'development-host-prerequisites', 'source_sha': revision,
                  'context_sha256': expected, 'job_admission': False}
        with contextlib.ExitStack() as locked:
            with self.run.phase(PREPARE_EXECUTION, PREPARE_NATIVE, native=False):
                self.preflight()
                self.context_inputs(context, expected, revision)
                self.protect_host_sources(upstream, revision)
                git_available = self.path('/usr/bin/git').exists()
                if not apply:
                    if git_available:
                        self.inputs(context, expected, upstream, revision)
                    return {**result, 'preview': 'prepare-development-host', 'changes': False,
                            'source_verification': 'complete' if git_available else 'pending signed Git prerequisite'}
                locked.enter_context(self.lock())
                preparation = self.preparation()
                with preparation.run.phase(PREPARE_EXECUTION, PREPARE_NATIVE):
                    ready = self._prepare_development_host(preparation, context, expected, upstream, revision,
                                                           sources, password_file, retry)
            if ready is not None:
                # No readiness can be consumed after a failed phase or expiry.
                self.atomic(STATE + '/host-ready.json', image_inputs_bytes(ready).decode())
        return {**result, 'host_prerequisites': 'complete', 'reused': ready is None}

    def _prepare_development_host(self, preparation, context, expected, upstream, revision, sources,
                                  password_file, retry):
        target = {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA,
                  'bootstrap_sources': sources}
        intent = self.path(DEVELOPMENT_HOST_INTENT)
        members = {node.name for node in self.state.iterdir()}
        raw = None
        record = {'schema': 1, 'target': target, 'phase_prefixes': [], 'native_units': []}
        desired = preparation._host_desired('core', sources, expected).encode()
        if intent.name in members:
            raw = self.protected_bytes(intent, 65536, 0o600).decode()
            record = json.loads(raw, object_pairs_hook=fedora_oci.unique)
            if (type(record) is not dict or set(record) != {'schema', 'target', 'phase_prefixes', 'native_units'}
                    or type(record['schema']) is not int or record['schema'] != 1 or record['target'] != target):
                raise Blocked('development host target differs from protected prior intent')
            phases, units = record['phase_prefixes'], record['native_units']
            if (type(phases) is not list or not 1 <= len(phases) <= 2
                    or any(type(prefix) is not str or not re.fullmatch(PREPARE_NATIVE + r'-[0-9a-f]{8}', prefix) for prefix in phases)
                    or len(set(phases)) != len(phases) or type(units) is not list or len(units) > 512
                    or any(type(unit) is not str or unit.rsplit('-', 1)[0] not in phases
                           or not re.fullmatch(PREPARE_NATIVE + r'-[0-9a-f]{8}-[0-9a-f]{8}', unit) for unit in units)
                    or len(set(units)) != len(units)):
                raise Blocked('invalid protected development host native ownership record')
            if members & {'initialize.json', 'prepared', 'gptbox-image.json', 'gptbox-adapter', 'node.json', 'enrollment-intent.json'}:
                raise Blocked('prior maintenance bootstrap state conflicts with development host intent')
            if 'desired.json' in members and self.protected_bytes(self.path(STATE + '/desired.json'), 16384, 0o600) != desired:
                raise Blocked('development host desired state differs from protected prior intent')
            if 'packages.txt' in members:
                self.protected_bytes(self.path(STATE + '/packages.txt'), 16384, 0o600)
            if 'host-ready.json' in members:
                self.inputs(context, expected, upstream, revision)
                self.verify_host_readiness(revision, expected)
                self.verify_builder()
                return None
            if not retry:
                raise Blocked('partial development host preparation requires explicit exact-target --retry')
        elif members - {'lock'}:
            raise Blocked('development host preparation requires a fresh bootstrap state')

        # Before the desired record, this operation could only have installed signed Git.
        if 'desired.json' not in members:
            if members & {'operator-password-set', 'packages.txt', 'identity-core.json', 'identity-dp-maint.json', 'identity-dp-dev.json'}:
                raise Blocked('unbound bootstrap state preserved')
            for name in ('/etc/dev-pair', '/etc/ssh/dev-pair-keys', '/etc/ssh/sshd_config.d/00-dev-pair-operator.conf',
                         '/etc/sudoers.d/dev-pair-operator', '/etc/systemd/resolved.conf.d/90-dev-pair-discovery.conf',
                         '/etc/cloud/cloud.cfg.d/99-dev-pair-hostname.cfg', '/etc/sysctl.d/90-dev-pair-mosh.conf',
                         '/etc/profile.d/90-dev-pair-core-tmux.sh', '/etc/yum.repos.d/dev-pair-tailscale.repo',
                         '/etc/systemd/system/dev-pair-bootstrap-guard.service',
                         '/etc/systemd/system/tailscaled.service.d/50-dev-pair-guard.conf',
                         '/var/lib/dev-pair/maintenance', '/var/lib/dev-pair/development'):
                path = self.path(name)
                if path.exists() or path.is_symlink():
                    raise Blocked('development host preparation refuses unbound managed host paths')
            for name in ('core', 'dp-maint', 'dp-dev'):
                home = self.path('/home/' + name)
                if (home.exists() or home.is_symlink()
                        or self.run('/usr/bin/getent', 'passwd', name, ok=(0, 2), timeout=10).strip()):
                    raise Blocked('development host preparation refuses preexisting bootstrap accounts')
        password = operator_password(password_file) if password_file else None
        if 'operator-password-set' in members:
            if self.protected_bytes(self.path(STATE + '/operator-password-set'), 4096, 0o600) != b'password configured; value remains external\n':
                raise Blocked('existing operator password marker conflicts with development host intent')
        elif password is None:
            raise Blocked('first development host preparation requires a protected core password file')

        for unit in record['native_units']:
            preparation.run.reconcile_native(('--unit=' + unit, '--description=dev-pair-owned-' + unit), {})
        if len(record['phase_prefixes']) >= 2:
            raise Blocked('development host preparation retry budget exhausted')
        source = self.inputs(context, expected, upstream, revision)[0] if self.path('/usr/bin/git').exists() else None

        def save():
            nonlocal raw
            data = image_inputs_bytes(record).decode()
            self.atomic(DEVELOPMENT_HOST_INTENT, data, expected=raw)
            raw = data

        prefix = preparation.run.native_prefix
        if not re.fullmatch(PREPARE_NATIVE + r'-[0-9a-f]{8}', prefix or '') or prefix in record['phase_prefixes']:
            raise Blocked('development host native phase identity collision')
        record['phase_prefixes'].append(prefix)
        save()

        def register(unit):
            if (not re.fullmatch(re.escape(prefix) + r'-[0-9a-f]{8}', unit)
                    or unit in record['native_units'] or len(record['native_units']) >= 512):
                raise Blocked('development host native unit ownership limit or conflict')
            record['native_units'].append(unit)
            save()

        def prove_source():
            return source if source is not None else self.inputs(context, expected, upstream, revision)[0]

        preparation.run.native_register = register
        try:
            return preparation._host_prerequisites('core', github_keys, sources, context, expected,
                                                    password=password, source_check=prove_source, development_host=True)
        finally:
            preparation.run.native_register = None

    def source(self, revision):
        super().source(revision)
        repo = Path(__file__).resolve().parents[1]
        relative = 'runtime/devbox/controller.py'
        path = self.protected(repo / relative)
        _, _, data = capture_release_file(path, 262144, os.getuid(), contents=True)
        recorded = self.run('/usr/bin/git', '-C', str(repo), 'show', revision + ':' + relative)
        if recorded.encode() != data:
            raise Blocked('DevBox archive verifier differs from the exact reviewed source')
        # Execute the exact verified bytes without importing an unbound cache/module.
        self.archive_verifier = ModuleType('dev_pair_development_archive_verifier')
        exec(compile(data, str(path), 'exec'), self.archive_verifier.__dict__)

    def protected_bytes(self, path, maximum, mode=None):
        try:
            self.protected(path)
            if mode is not None and stat.S_IMODE(path.lstat().st_mode) != mode:
                raise Blocked('protected development input permissions conflict')
            return capture_release_file(path, maximum, os.getuid(), contents=True)[2]
        except FileNotFoundError:
            raise Blocked(f'required protected development evidence is missing: {path.name}') from None

    def verify_host_readiness(self, revision=None, expected=None):
        desired_raw = self.protected_bytes(self.path(STATE + '/desired.json'), 16384, 0o600)
        desired = json.loads(desired_raw, object_pairs_hook=fedora_oci.unique)
        fields = {'schema', 'standards_sha', 'source_baseline', 'bootstrap_sha256',
                  'gptbox_context_sha256', 'operator', 'keys_source', 'bootstrap_sources'}
        if (type(desired) is not dict or set(desired) != fields or type(desired['schema']) is not int
                or desired['schema'] != 1 or desired['standards_sha'] != candidate.STANDARDS
                or desired['source_baseline'] != SOURCE_BASELINE or desired['operator'] != 'core'
                or desired['keys_source'] != KEYS_URL or type(desired['bootstrap_sources']) is not list
                or validate_sources(desired['bootstrap_sources']) != desired['bootstrap_sources']
                or any(type(desired[key]) is not str or not re.fullmatch('[0-9a-f]{64}', desired[key])
                       for key in ('bootstrap_sha256', 'gptbox_context_sha256'))):
            raise Blocked('existing authorized host desired state is invalid')
        packages = self.protected_bytes(self.path(STATE + '/packages.txt'), 16384, 0o600)
        ready = self.path(STATE + '/host-ready.json')
        intent = self.path(DEVELOPMENT_HOST_INTENT)
        development_host = intent.exists() or intent.is_symlink()
        if ready.exists() or ready.is_symlink():
            record = json.loads(self.protected_bytes(ready, 16384, 0o600), object_pairs_hook=fedora_oci.unique)
            pins = {'schema': 1, 'kind': 'host-prerequisites', 'context_sha256': desired['gptbox_context_sha256'],
                    'standards_sha': candidate.STANDARDS, 'bootstrap_sha256': desired['bootstrap_sha256'],
                    'desired_sha256': sha(desired_raw), 'packages_sha256': sha(packages)}
            if (type(record) is not dict or type(record.get('schema')) is not int
                    or type(record.get('source_sha')) is not str or not re.fullmatch('[0-9a-f]{40}', record['source_sha'])
                    or record != {**pins, 'source_sha': record['source_sha']}):
                raise Blocked('protected host prerequisite record does not match existing host evidence')
            if development_host and (record['source_sha'], record['context_sha256']) != (revision, expected):
                raise Blocked('build target differs from the prepared development host')
        elif development_host:
            raise Blocked('development host preparation has not published readiness')
        elif self.protected_bytes(self.path(STATE + '/prepared'), 16384, 0o600) != desired_raw:
            raise Blocked('protected prepared marker does not match authorized host desired state')
        if self.run('/usr/bin/rpm', '-q', *PACKAGES, 'tailscale', timeout=15).encode() != packages:
            raise Blocked('live host package inventory differs from protected readiness evidence')

    def verify_builder(self):
        name, shell, start = 'dp-maint', '/usr/sbin/nologin', 1000000
        marker = self.protected_bytes(self.path(STATE + '/identity-' + name + '.json'), 4096, 0o600)
        if marker != image_inputs_bytes({'name': name, 'shell': shell, 'substart': start}):
            raise Blocked('managed builder identity marker does not match the bootstrap role')
        passwd = self.run('/usr/bin/getent', 'passwd', name, timeout=10).strip().split(':')
        if len(passwd) != 7 or passwd[0] != name or passwd[5:] != ['/home/' + name, shell]:
            raise Blocked('live builder account differs from the managed nologin role')
        uid, gid = (_canonical_role_id(value + '\n') for value in passwd[2:4])
        if (uid != _canonical_role_id(self.run('/usr/bin/id', '-u', name, timeout=10))
                or gid != _canonical_role_id(self.run('/usr/bin/id', '-g', name, timeout=10))
                or self.run('/usr/bin/id', '-nG', name, timeout=10).split() != [name]):
            raise Blocked('live builder UID, GID or private group differs from the managed account')
        role_root = self.path('/var/lib/dev-pair/maintenance')
        self.protected(role_root.parent)
        node = role_root.lstat()
        if (not stat.S_ISDIR(node.st_mode) or stat.S_IMODE(node.st_mode) != 0o700
                or (node.st_uid, node.st_gid) != (uid, gid)):
            raise Blocked('live builder account differs from the provisioned maintenance directory owner')
        status = self.run('/usr/bin/passwd', '-S', name, timeout=10).split()
        if len(status) < 2 or status[0] != name or status[1] not in ('L', 'LK'):
            raise Blocked('managed builder password must remain locked')
        for location in ('/etc/subuid', '/etc/subgid'):
            content = self.protected_bytes(self.path(location), 65536).decode('ascii')
            if not role_subordinate_range(content, name, str(uid), start):
                raise Blocked('live builder subordinate ID allocation is missing')
        if self.run('/usr/bin/hostnamectl', '--static', timeout=10).strip() != 'erebus':
            raise Blocked('managed builder requires the verified bootstrap host identity')
        package = self.run(*SUDO_PACKAGE_QUERY, timeout=10, sudo_package=True)
        proof = self.run('/usr/bin/sudo', '-l', '-U', name, timeout=10,
                         sudo_probe={'role': name, 'host_verified': True, 'package': package})
        if type(proof) is not dict or proof.get('outcome') != 'denied':
            raise Blocked('live builder sudo denial was not verified')
        return _RoleIdentity(name, uid, gid)

    def assemble(self, context, expected, upstream, revision, apply=False, retry=False):
        def phase(seconds):
            if isinstance(self.run, Commands):
                return self.run.phase(seconds, 'dev-pair-development-image', native=False)
            return contextlib.nullcontext()

        with phase(120):
            self.preflight()
            manifest, self.scripts = self.inputs(context, expected, upstream, revision)
        if not apply:
            return {'preview': 'build-development', 'changes': False, 'source_sha': revision,
                    'context_sha256': expected, 'job_admission': False}
        self.target = DEVELOPMENT_ROOT + '/' + expected
        self.control = '/usr/local/libexec/dev-pair-gptbox-development/' + expected
        self.failure_diagnostic_identity = {'source_sha': revision, 'context_sha256': expected,
                                            'phase': 'development-gptbox'}
        artifact_target = self.artifact_root + '/' + expected
        release = self.path(artifact_target + '/release')
        pending = self.path(artifact_target + '/release.pending')
        export_work = artifact_target + '/export-work'
        with self.lock():
            with phase(DEVELOPMENT_EXECUTION):
                self.verify_host_readiness(revision, expected)
                builder = self.verify_builder()
                attempt = self.read_attempt(expected, revision)
                publication = self.read_publication(attempt)
                reused = release.exists() or release.is_symlink()
                if reused:
                    if not publication or publication['phase'] != 'ready' or pending.exists() or pending.is_symlink():
                        raise Blocked('published development release requires its exact ready evidence')
                    inner = self.read_release(release, publication)
                elif publication and publication['phase'] in ('verified', 'ready'):
                    if not retry:
                        raise Blocked('verified pending development release requires explicit --retry')
                    inner = self.read_release(pending, publication)
                    if publication['phase'] == 'verified':
                        self.setup_executor(retry=True, verified=builder)
                        self.reconcile_development_work(expected, export_work)
                        self.record('publication', {**publication, 'phase': 'ready'})
                else:
                    inner = self.stage_release(context, manifest, attempt, publication, pending, export_work, retry, builder)
            # Publish the directory only after the phase and its exact cleanup complete.
            if not reused:
                if release.exists() or release.is_symlink():
                    raise Blocked('conflicting development release path preserved')
                os.rename(pending, release)
                sync_directory(release.parent)
        return {'kind': 'development-gptbox-release-candidate', 'archive': str(release / RELEASE_ARCHIVE),
                'inner_record': str(release / RELEASE_INNER), 'inner': inner, 'reused': reused,
                'job_admission': False}

    def read_attempt(self, expected, revision):
        target = {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA}
        intent = self.path(self.target + '/attempt.json')
        if not intent.exists() and not intent.is_symlink():
            return {**target, 'count': 0}
        prior = json.loads(self.protected_bytes(intent, 4096, 0o600), object_pairs_hook=fedora_oci.unique)
        count = prior.get('count') if type(prior) is dict else None
        if type(count) is not int or not 1 <= count <= 2 or prior != {**target, 'count': count}:
            raise Blocked('invalid protected development attempt record')
        return prior

    def read_publication(self, attempt):
        path = self.path(self.target + '/publication.json')
        if not path.exists() and not path.is_symlink():
            return None
        value = json.loads(self.protected_bytes(path, 16384, 0o600), object_pairs_hook=fedora_oci.unique)
        common = {'schema', 'attempt', 'phase', 'directory'}
        phases = {'copying': common, 'verified': common | {'inner', 'inner_sha256'},
                  'ready': common | {'inner', 'inner_sha256'}}
        if (type(value) is not dict or type(value.get('phase')) is not str or set(value) != phases.get(value['phase'])
                or type(value['schema']) is not int or value['schema'] != 1 or not attempt['count']
                or image_inputs_bytes(value['attempt']) != image_inputs_bytes(attempt)
                or type(value['directory']) is not list or len(value['directory']) != 5
                or any(type(number) is not int for number in value['directory'])):
            raise Blocked('invalid protected development publication evidence')
        return value

    def release_directory(self, path):
        node = self.protected(path).lstat()
        if not stat.S_ISDIR(node.st_mode) or stat.S_IMODE(node.st_mode) != 0o700:
            raise Blocked('invalid protected development release directory')
        return [node.st_dev, node.st_ino, node.st_uid, node.st_gid, node.st_mode]

    def read_release(self, release, publication):
        if (self.release_directory(release) != publication['directory']
                or {node.name for node in release.iterdir()} != {RELEASE_ARCHIVE, RELEASE_INNER}):
            raise Blocked('development release directory conflicts')
        raw = self.protected_bytes(release / RELEASE_INNER, 16384, 0o444)
        inner = publication['inner']
        attempt = publication['attempt']
        keys = {'source_sha', 'image_id', 'context_sha256', 'inputs_sha256', 'sealed_sha256',
                'archive_sha256', 'archive_bytes', 'diff_ids'}
        if (type(inner) is not dict or set(inner) != keys or sha(raw) != publication['inner_sha256']
                or raw != image_inputs_bytes(inner) or inner['source_sha'] != attempt['source_sha']
                or inner['context_sha256'] != attempt['context_sha256'] or type(inner['archive_bytes']) is not int
                or not 0 < inner['archive_bytes'] <= DEVELOPMENT_ARCHIVE_LIMIT
                or any(type(inner[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}', inner[key])
                       for key in ('image_id', 'inputs_sha256', 'sealed_sha256', 'archive_sha256'))):
            raise Blocked('development inner record differs from protected publication evidence')
        image_diff_ids(inner['diff_ids'])
        archive = self.protected(release / RELEASE_ARCHIVE)
        if stat.S_IMODE(archive.lstat().st_mode) != 0o444:
            raise Blocked('development release archive permissions changed')
        digest, size, _ = capture_release_file(archive, inner['archive_bytes'], os.getuid())
        if (digest, size) != (inner['archive_sha256'], inner['archive_bytes']):
            raise Blocked('published development archive no longer matches its inner record')
        return inner

    def reconcile_executor(self):
        if isinstance(self.run, Commands):
            self.run.reconcile_native(('--unit=' + self.unit, '--description=dev-pair-owned-' + self.unit,
                                       '--uid=dp-maint'), {})

    def reconcile_development_work(self, expected, export_work):
        self.recover_resources(expected)
        self.recover_image_work(expected)
        work = self.path(export_work)
        if work.exists() or work.is_symlink():
            fedora_oci.recover_workspaces(self.protected(work), uid=int(self.uid), reconcile=self.reconcile_executor)

    def pending_members(self, pending, publication):
        if not publication or self.release_directory(pending) != publication['directory']:
            raise Blocked('unowned pending development release preserved')
        members = list(pending.iterdir())
        for node in members:
            info = self.protected(node).lstat()
            if node.name not in {RELEASE_ARCHIVE, RELEASE_INNER} or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Blocked('unowned pending development release member preserved')
        return members

    def stage_release(self, context, manifest, attempt, publication, pending, export_work, retry, builder):
        expected, revision, count = attempt['context_sha256'], attempt['source_sha'], attempt['count']
        if count and not retry:
            raise Blocked('development assembly retry requires explicit --retry')
        pending_exists = pending.exists() or pending.is_symlink()
        if pending_exists:
            self.pending_members(pending, publication)
        self.directory(self.target, mode=0o755)
        self.directory('/var/lib/dev-pair/artifacts', mode=0o755)
        self.directory(self.artifact_root, mode=0o755)
        self.directory(self.artifact_root + '/' + expected, mode=0o755)
        self.image_stage('executor-setup', revision, expected)
        self.setup_executor(retry=bool(count), verified=builder)
        if count:
            self.reconcile_development_work(expected, export_work)
            if pending_exists:
                for node in self.pending_members(pending, publication):
                    node.unlink()
                pending.rmdir()
                sync_directory(pending.parent)
            if publication:
                path = self.path(self.target + '/publication.json')
                path.unlink()
                sync_directory(path.parent)
        if count == 2:
            raise Blocked('development assembly build retry budget exhausted')
        reserve = 8 * 1024 ** 3 + 2 * DEVELOPMENT_ARCHIVE_LIMIT
        if shutil.disk_usage(pending.parent).free < reserve:
            raise Blocked('insufficient capacity for the bounded development export and eight GiB reserve')
        attempt = {**attempt, 'count': count + 1}
        self.record('attempt', attempt)
        base, _, inputs = self._full_candidate(context, expected, revision, manifest)
        self.image_stage('assembly', revision, expected)
        stage_name = f'dp-gptbox-a-{expected[:16]}-{count + 1}'
        snapshot_name = f'dp-gptbox-r-{expected[:16]}-{count + 1}'
        self.record('resources', {stage_name: base})
        stage = snapshot = None
        primary = None
        try:
            stage = self.create_assembly_stage(stage_name, expected, base)
            sealed, seal = self.seal_assembly_stage(stage, base, revision, inputs)
            if sealed == base:
                raise Blocked('development commit did not produce a new immutable image')
            self.image_stage('export', revision, expected)
            self.record('resources', {stage_name: base, snapshot_name: sealed})
            snapshot = image_id(self.engine('create', '--name=' + snapshot_name, '--label=dev-pair.context=' + expected,
                '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--hooks-dir=' + str(self.path(self.control + '/empty-hooks')), '--entrypoint=/usr/bin/false', 'sha256:' + sealed))
            publication = self.export_release(attempt, sealed, inputs, seal, snapshot, pending, export_work, reserve)
        except BaseException as error:
            primary = error
            raise
        finally:
            cleanup_error = None
            for identity in (snapshot, stage):
                if identity:
                    try:
                        self.engine('rm', '--force', identity)
                    except (Blocked, OSError, ValueError, subprocess.SubprocessError) as error:
                        if cleanup_error is None:
                            cleanup_error = error
            if cleanup_error is not None and primary is None:
                raise cleanup_error
        self.record('publication', {**publication, 'phase': 'ready'})
        self.image_stage('complete', revision, expected)
        return publication['inner']

    def export_release(self, attempt, sealed, inputs, seal, snapshot, pending, export_work, reserve):
        expected, revision = attempt['context_sha256'], attempt['source_sha']
        rows = json.loads(self.engine('inspect', '--type=container', snapshot), object_pairs_hook=fedora_oci.unique)
        if (type(rows) is not list or len(rows) != 1 or image_id(rows[0]['Id']) != snapshot
                or image_id(rows[0]['Image']) != sealed or rows[0]['State']['Status'] not in ('configured', 'created')
                or rows[0]['State'].get('Running') is not False):
            raise Blocked('development raw file read requires the exact never-started image snapshot')
        labels = {'dev-pair.role': 'development', 'dev-pair.context': expected,
                  'dev-pair.inputs': sha(image_inputs_bytes(inputs)), 'dev-pair.standards': candidate.STANDARDS,
                  'dev-pair.distrobox': DBX_SHA, 'dev-pair.codex.version': '0.169.0',
                  'org.opencontainers.image.revision': revision}
        rows = json.loads(self.engine('image', 'inspect', 'sha256:' + sealed), object_pairs_hook=fedora_oci.unique)
        if (type(rows) is not list or len(rows) != 1 or image_id(rows[0]['Id']) != sealed
                or rows[0]['Os'] != 'linux' or rows[0]['Architecture'] != 'amd64'):
            raise Blocked('sealed development image inspection mismatch')
        image = rows[0]
        actual_labels = image.get('Labels') or image['Config'].get('Labels', {})
        if type(actual_labels) is not dict or any(actual_labels.get(key) != value for key, value in labels.items()):
            raise Blocked('sealed development image labels mismatch')
        diff_ids = image_diff_ids(image['RootFS']['Layers'])
        self.directory(export_work, mode=0o755)
        with fedora_oci.copy_workspace(self.path(export_work), uid=int(self.uid),
                                       reconcile=self.reconcile_executor, reserve=reserve) as work:
            for name, wanted in (('inputs.json', inputs), ('sealed.json', seal)):
                self.execute('/usr/bin/prlimit', '--fsize=16384:16384', self.wrapper, 'cp', '--archive=false',
                             snapshot + ':' + BASE + '/' + name, str(work / name), timeout=30)
                _, _, raw = capture_release_file(work / name, 16384, int(self.uid), contents=True)
                if raw != image_inputs_bytes(wanted):
                    raise Blocked('immutable development input or seal bytes differ from the Distrobox assembly')
                if name == 'sealed.json':
                    sealed_digest = sha(raw)
            source = work / RELEASE_ARCHIVE
            self.execute('/usr/bin/env', 'TMPDIR=' + str(work),
                         'CONTAINERS_CONF=' + str(self.path(self.control + '/export-containers.conf')),
                         self.wrapper, 'save', '--format=oci-archive', '--output', str(source), 'sha256:' + sealed, timeout=240)
            pending.mkdir(mode=0o700)
            pending.chmod(0o700)
            sync_directory(pending.parent)
            publication = {'schema': 1, 'attempt': attempt, 'phase': 'copying',
                           'directory': self.release_directory(pending)}
            self.record('publication', publication)
            archive = pending / RELEASE_ARCHIVE
            with archive.open('xb') as out:
                archive_sha, archive_bytes, _ = capture_release_file(source, DEVELOPMENT_ARCHIVE_LIMIT,
                                                                      int(self.uid), output=out)
                os.fchmod(out.fileno(), 0o444)
                out.flush()
                os.fsync(out.fileno())
            inner = {'source_sha': revision, 'image_id': sealed, 'context_sha256': expected,
                     'inputs_sha256': labels['dev-pair.inputs'], 'sealed_sha256': sealed_digest,
                     'archive_sha256': archive_sha, 'archive_bytes': archive_bytes, 'diff_ids': diff_ids}
            self.verify_archive(archive, inner, labels)
            raw_inner = image_inputs_bytes(inner)
            with (pending / RELEASE_INNER).open('xb') as out:
                out.write(raw_inner)
                os.fchmod(out.fileno(), 0o444)
                out.flush()
                os.fsync(out.fileno())
            sync_directory(pending)
            publication.update(phase='verified', inner=inner, inner_sha256=sha(raw_inner))
            self.record('publication', publication)
        return publication

    def verify_archive(self, path, inner, labels):
        verifier = self.archive_verifier
        deadline = time.monotonic() + 240
        try:
            verifier.check_archive_image(path, inner, DEVELOPMENT_EXPANSION_LIMIT, deadline)
            # The shared check proved the unique config blob and its bounded raw digest.
            with tarfile.open(path, 'r:') as archive:
                name = 'blobs/sha256/' + inner['image_id']
                config = next(member for member in archive if verifier.archive_path(member.name) == name)
                with archive.extractfile(config) as stream:
                    data = stream.read(verifier.OCI_METADATA_LIMIT + 1)
            raw_labels = verifier.json_data(data).get('config', {}).get('Labels', {})
            if type(raw_labels) is not dict or any(raw_labels.get(key) != value for key, value in labels.items()):
                raise Blocked('development archive labels differ from the inspected immutable image')
        except (verifier.Blocked, tarfile.TarError, EOFError, StopIteration) as error:
            raise Blocked(f'development archive verification failed: {error}') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('assemble', 'initialize', 'prepare-development-host', 'build-development'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--retry', action='store_true', help='reconcile and retry one incomplete exact target; at most two attempts')
    parser.add_argument('--context', required=True)
    parser.add_argument('--expected-context-sha256', required=True)
    parser.add_argument('--distrobox-source', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--bootstrap-source', action='append')
    parser.add_argument('--password-file')
    args = parser.parse_args()
    if args.stage == 'prepare-development-host' and not args.bootstrap_source:
        parser.error('prepare-development-host requires --bootstrap-source')
    try:
        app = DevelopmentGptbox() if args.stage in ('prepare-development-host', 'build-development') else Gptbox()
        if args.stage == 'initialize':
            result = app.initialize(args.context, args.expected_context_sha256, args.distrobox_source, args.source_sha,
                                    args.bootstrap_source, args.password_file, args.apply, args.retry)
        elif args.stage == 'prepare-development-host':
            result = app.prepare_development_host(args.context, args.expected_context_sha256, args.distrobox_source,
                                                  args.source_sha, args.bootstrap_source, args.password_file,
                                                  args.apply, args.retry)
        else:
            result = app.assemble(args.context, args.expected_context_sha256, args.distrobox_source, args.source_sha, args.apply, args.retry)
        print(json.dumps(result, indent=2))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        print('gptbox operation blocked; no job/runtime admission; inspect protected evidence locally', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
