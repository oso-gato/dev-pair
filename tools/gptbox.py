#!/usr/bin/python3
"""Actual confined maintenance Distrobox assembly and probe-only controlled entry."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import selectors
import signal
import stat
import subprocess
import sys
import time

from bootstrap import Bootstrap, Blocked, STATE, Commands, github_keys, operator_password, validate_sources
import candidate

DBX_SHA = '40c3cd724faa434aeb0a23e28776665b92de68bd'
CODEX_SHA = 'b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b'
FEDORA = 'registry.fedoraproject.org/fedora:44@sha256:48f4a2b507ad36a6a8bb83646ee81164aff80a62be06d03b143b80594d2b558e'
BASE = '/usr/lib/dev-pair/gptbox'
RUNTIME = BASE + '/runtime.py'
CONTROL = '/usr/local/libexec/dev-pair-gptbox'
ROOT = STATE + '/gptbox-adapter'
INIT = ['/usr/bin/distrobox-init', '--name', 'gpt', '--user', '1000', '--group', '1000', '--home', '/home/gpt', '--init', '0']
FINAL_HOOK = 'exec /usr/bin/python3 ' + RUNTIME + ' finalize'
FROZEN_HOOK = 'exec /usr/bin/python3 ' + RUNTIME + ' frozen'
ASSEMBLY_LIFETIME = 900
RUNTIME_LIFETIME = 180
INITIALIZE_EXECUTION = 2280
PREPARE_EXECUTION = 600
ADAPTER_EXECUTION = 1620
IMAGE_EXECUTION = 600
CLEANUP_EXECUTION = 45
COMMAND_CLEANUP_GRACE = 45


def sha(data):
    return hashlib.sha256(data).hexdigest()


def image_id(value):
    value = value.strip().removeprefix('sha256:')
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise Blocked('engine returned no immutable image/container identity')
    return value


class ProbeCommands(Commands):
    """Bounded diagnostics only for credential-free assembly/probe operations."""
    diagnostic = None

    def __call__(self, *args, ok=(0,), input_text=None, timeout=900):
        timeout = self.limit_timeout(timeout)
        args = self.native_args(args, timeout)
        if self.diagnostic is None:
            return super().__call__(*args, ok=ok, input_text=input_text, timeout=timeout)
        if input_text is not None:
            raise Blocked('probe diagnostics cannot accept stdin credentials or prompts')
        environment = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
        process = None
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        selector = selectors.DefaultSelector()
        deadline, total = time.monotonic() + timeout, 0
        try:
            process = subprocess.Popen(args, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > 4194304:
                        raise Blocked('probe output budget exceeded')
                    buffers[key.data].extend(chunk)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                raise TimeoutError()
            self.limit_timeout(timeout)
            if process.returncode not in ok:
                raise Blocked('probe command exited with disallowed status')
            output = bytes(buffers['stdout']).decode('utf-8')
        except BaseException:
            cleanup = 'interrupted-or-failed'
            try:
                if process is not None:
                    self.interrupt(process, args, environment)
            except (Blocked, OSError, subprocess.SubprocessError):
                cleanup = 'cleanup-unresolved'
            actual_status = process.returncode if process is not None else None
            status = actual_status if actual_status is not None and actual_status not in ok else cleanup
            self.diagnostic(buffers, status)
            raise Blocked('probe command failed or timed out; bounded protected diagnostics retained; ' + cleanup) from None
        finally:
            selector.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
        self.diagnostic(buffers, process.returncode)
        return output


class Gptbox(Bootstrap):
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
        for name in ('gptbox.py', 'gptbox_runtime.py', 'bootstrap.py', 'selinux_bootstrap.py', 'candidate.py'):
            data = self.protected(Path(__file__).with_name(name)).read_bytes()
            recorded = self.run('/usr/bin/git', '-C', str(repo), 'show', revision + ':tools/' + name)
            if recorded.encode() != data:
                raise Blocked('adapter revision does not identify executing source')

    def inputs(self, context, expected, upstream, revision):
        self.protected(context)
        for file in Path(context).iterdir():
            self.protected(file)
        _, _, manifest = self.check_gptbox_inputs(context, expected)
        candidate.verify(context, expected)
        if (manifest['role'] != 'maintenance' or manifest['fedora']['image'] != FEDORA
                or manifest['codex']['version'] != '0.169.0' or manifest['codex']['sha256'] != CODEX_SHA):
            raise Blocked('first adapter accepts only the independently verified pinned maintenance inputs')
        if manifest['source_sha'] != revision:
            raise Blocked('context source differs from requested adapter target')
        self.source(revision)
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
        return manifest, scripts

    def execute(self, *args, timeout=120, ok=(0,)):
        prefix = [value.replace('RuntimeMaxSec=1800', 'RuntimeMaxSec=' + str(timeout)) for value in self.executor]
        if isinstance(self.run, ProbeCommands):
            def diagnostic(buffers, status):
                path = self.target + '/diagnostics.json'
                prior = json.loads(self.text(path, '{"recent":[],"failures":[]}'))
                entry = {'status': status, 'scope': 'credential-free assembly/probe',
                         **{name + '_tail': bytes(data[-16384:]).decode('utf-8', errors='replace') for name, data in buffers.items()},
                         **{name + '_truncated': len(data) > 16384 for name, data in buffers.items()},
                         **{name + '_bytes': len(data) for name, data in buffers.items()}}
                prior['recent'] = (prior['recent'] + [entry])[-4:]
                if status != 0:
                    prior['failures'] = (prior['failures'] + [entry])[-4:]
                self.record('diagnostics', prior)
            self.run.diagnostic = diagnostic
        try:
            return self.run(*prefix, *args, timeout=timeout + 30, ok=ok)
        finally:
            if isinstance(self.run, ProbeCommands):
                self.run.diagnostic = None

    def engine(self, *args, timeout=120, ok=(0,)):
        return self.execute(self.wrapper, *args, timeout=timeout, ok=ok)

    def setup_executor(self, retry=False):
        uid = self.run('/usr/bin/id', '-u', 'dp-maint').strip()
        if not uid.isdigit() or int(uid) < 1000:
            raise Blocked('invalid maintenance runtime UID')
        self.uid = uid
        self.gid = self.run('/usr/bin/id', '-g', 'dp-maint').strip()
        if not self.gid.isdigit() or int(self.gid) < 1000:
            raise Blocked('invalid maintenance primary GID')
        self.directory('/usr/local/libexec', mode=0o755)
        self.directory(CONTROL, mode=0o755)
        self.directory(CONTROL + '/home', mode=0o755)
        self.directory(CONTROL + '/bin', mode=0o755)
        self.directory(CONTROL + '/empty-hooks', mode=0o755)
        if any(self.path(CONTROL + '/empty-hooks').iterdir()) or any(self.path(CONTROL + '/home').iterdir()):
            raise Blocked('controller home/hooks contain undeclared parent integration')
        self.atomic(CONTROL + '/containers.conf', '[containers]\nnetns="private"\n[engine]\nevents_logger="file"\n', mode=0o444)
        storage = '/var/lib/dev-pair/maintenance/images'
        self.directory(storage, owner='dp-maint')
        self.wrapper = str(self.path(CONTROL + '/bin/podman'))
        script = (f'#!/bin/sh\nexec /usr/bin/podman --root {self.path(storage)} --runroot /run/user/{uid}/dev-pair-gptbox '
                  '--storage-driver=vfs --events-backend=file "$@"\n')
        self.atomic(CONTROL + '/bin/podman', script, mode=0o555)
        self.atomic(CONTROL + '/distrobox-enter', self.scripts['distrobox-enter'].decode(), mode=0o555)
        self.run('/usr/sbin/restorecon', '-RF', str(self.path(CONTROL)))
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
        self.executor = ['/usr/bin/systemd-run', '--unit=' + self.unit, '--description=dev-pair-owned-' + self.unit, '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
                         '--uid=dp-maint', '--property=RuntimeMaxSec=1800', '--property=TimeoutStopSec=10',
                         '--property=KillMode=control-group', '--property=MemoryMax=2G', '--property=TasksMax=512',
                         '--property=CPUQuota=100%', '/usr/bin/env', '-i', 'PATH=' + str(self.path(CONTROL + '/bin')) + ':/usr/bin:/usr/sbin:/bin',
                         'HOME=' + str(self.path(CONTROL + '/home')), 'USER=gpt', 'LOGNAME=gpt',
                         'XDG_RUNTIME_DIR=/run/user/' + uid, 'CONTAINERS_CONF=' + str(self.path(CONTROL + '/containers.conf')),
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
        if operation not in ('probe', 'version'):
            raise Blocked('job/auth/model execution is not admitted')
        before = self.inspect_container(identity, sealed)
        if before['State']['Status'] != 'running':
            raise Blocked('entry requires an already running exact target; no auto-create/start fallback')
        output = self.execute(str(self.path(CONTROL + '/distrobox-enter')),
                          '--name', identity, '--no-tty', '--no-workdir', '--clean-path', '--',
                          '/usr/bin/python3', RUNTIME, 'entry', operation, timeout=30)
        self.inspect_container(identity, sealed)
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

    def assemble(self, context, expected, upstream, revision, apply=False, retry=False):
        self.preflight()
        manifest, self.scripts = self.inputs(context, expected, upstream, revision)
        if not apply:
            return {'preview': True, 'changes': False, 'job_admission': False,
                    'operation': 'genuine Distrobox assembly, seal, boundary/version entry and restart probes'}
        if not self.path(STATE + '/prepared').exists():
            raise Blocked('normal host preparation must complete first')
        with self.lock():
            self.target = ROOT + '/' + expected
            self.directory(self.target, mode=0o755)
            previous = json.loads(self.text(self.target + '/attempt.json', '{}'))
            if previous and (previous.get('source_sha') != revision or previous.get('context_sha256') != expected or previous.get('distrobox_sha') != DBX_SHA):
                raise Blocked('changed assembly target requires separately reviewed recovery')
            self.setup_executor(retry=bool(previous and retry))
            if self.path(self.target + '/result.json').exists():
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
                self.record('cleanup-only', {**cleanup, 'phase': 'complete'})
                raise Blocked('build budget exhausted; exact owned resources cleaned without another build')
            if previous:
                self.recover_resources(expected)
            if shutil.disk_usage(self.path('/var/lib/dev-pair')).free < 8 * 1024 ** 3:
                raise Blocked('eight GiB free reserve is required before assembly')
            self.record('attempt', {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA, 'count': count})
            self.directory('/var/lib/dev-pair/artifacts', mode=0o755)
            self.directory('/var/lib/dev-pair/artifacts/gptbox-adapter', mode=0o755)
            self.directory('/var/lib/dev-pair/artifacts/gptbox-adapter/' + expected, mode=0o755)
            build = '/var/lib/dev-pair/artifacts/gptbox-adapter/' + expected + '/build'
            self.directory(build, mode=0o755)
            runtime = Path(__file__).with_name('gptbox_runtime.py').read_bytes()
            files = {'codex': Path(context, 'codex').read_bytes(), 'distrobox-init': self.scripts['distrobox-init'],
                     'runtime.py': runtime}
            inputs = {'source_sha': revision, 'context_sha256': expected, 'distrobox_sha': DBX_SHA,
                      'files': {'/opt/dev-pair/bin/codex': sha(files['codex']), '/usr/bin/distrobox-init': sha(files['distrobox-init']), RUNTIME: sha(runtime)}}
            # Match the pinned upstream setup_dnf availability resolution; aliases
            # absent from Fedora's architecture-specific metadata are not forced.
            dependencies = ('bash bash-completion bc bzip2 cracklib-dicts curl diffutils dnf-plugins-core findutils '
                            'glibc-all-langpacks glibc-common glibc-locale-source gnupg2 gnupg2-smime hostname iproute '
                            'iputils keyutils krb5-libs less lsof man-db man-pages mtr ncurses nss-mdns openssh-clients '
                            'pam passwd pigz pinentry procps-ng rsync shadow-utils sudo tcpdump time traceroute tree '
                            'tzdata unzip util-linux util-linux-script vte-profile wget wget2-wget which whois words '
                            'xorg-x11-xauth xz zip mesa-dri-drivers mesa-vulkan-drivers vulkan')
            recipe = (f'FROM {FEDORA}\n'
                      'RUN set -eu; for file in /etc/dnf/dnf.conf /etc/yum.conf; do '
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
                      f'LABEL dev-pair.context={expected} dev-pair.distrobox={DBX_SHA} org.opencontainers.image.revision={revision}\nENV HOME=/home/gpt PATH=/opt/dev-pair/bin:/usr/bin:/bin container=podman LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8\n')
            for name, data in {**files, 'inputs.json': json.dumps(inputs, sort_keys=True).encode() + b'\n', 'Containerfile': recipe.encode()}.items():
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
            image_budget = self.run.phase(IMAGE_EXECUTION, 'dev-pair-gptbox-image', native=False) if isinstance(self.run, Commands) else contextlib.nullcontext()
            with image_budget:
                self.engine('pull', '--policy=missing', FEDORA, timeout=600)
                base = image_id(self.engine('build', '--quiet', '--pull=never', '--http-proxy=false', '--file', str(self.path(build) / 'Containerfile'), str(self.path(build)), timeout=600))
            if shutil.disk_usage(self.path('/var/lib/dev-pair')).free < 8 * 1024 ** 3:
                raise Blocked('eight GiB free reserve is required after image construction before actual assembly')
            stage = runtime_id = None
            stage_name, runtime_name = 'dp-gptbox-a-' + expected[:16] + '-' + str(count), 'dp-gptbox-r-' + expected[:16] + '-' + str(count)
            self.record('resources', {stage_name: base})
            try:
                stage = image_id(self.engine('create', '--name=' + stage_name, '--label=dev-pair.context=' + expected, '--timeout=' + str(ASSEMBLY_LIFETIME), '--restart=no',
                    '--network=slirp4netns:allow_host_loopback=false', '--pid=private', '--ipc=private', '--uts=private', '--userns=private', '--cap-add=SYS_ADMIN',
                    '--security-opt=no-new-privileges', '--security-opt=label=type:container_engine_t',
                    '--memory=2g', '--pids-limit=512', '--cpus=1', '--tmpfs=/run:rw,nosuid,nodev,mode=0755,notmpcopyup', '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777,notmpcopyup',
                    '--hooks-dir=' + str(self.path(CONTROL + '/empty-hooks')), '--entrypoint=/usr/bin/distrobox-init', base,
                    *INIT[1:], '--', FINAL_HOOK))
                self.inspect_container(stage, base, runtime=False)
                output = self.engine('start', '--attach', stage, timeout=900)
                attestation = json.loads(output.strip().splitlines()[-1])
                if (attestation.get('kind') != 'genuine-distrobox-assembled'
                        or attestation.get('inputs_sha256') != sha(json.dumps(inputs, sort_keys=True).encode() + b'\n')
                        or attestation.get('source_sha') != revision or attestation.get('uid') != 1000 or attestation.get('gid') != 1000):
                    raise Blocked('actual upstream finalizer attestation is missing or mismatched')
                self.record('assembly-attestation', attestation)
                stopped = json.loads(self.engine('inspect', '--type=container', stage))[0]
                if stopped['State'].get('ExitCode') != 0 or stopped['State'].get('Running'):
                    raise Blocked('actual upstream assembly did not exit successfully')
                sealed = image_id(self.engine('commit', '--pause=false', stage))
                self.record('resources', {stage_name: base, runtime_name: sealed})
                # A separate immutable runtime, never the writable assembly container.
                self.mounts = {}
                mount_args = []
                for directory, destination in (('workspaces', '/work/job'), ('state', '/state'), ('cache', '/cache/job')):
                    source = '/var/lib/dev-pair/maintenance/' + directory + '/gptbox-probe'
                    self.directory(source, owner='dp-maint')
                    self.mounts[destination] = (str(self.path(source)), True)
                    mount_args += ['--volume', str(self.path(source)) + ':' + destination + ':rw,Z']
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
                          'distrobox_sha': DBX_SHA, 'assembled_image_id': sealed, 'runtime_container_id': runtime_id,
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
            self.record('result', result)
            return result


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
        for name in ('gptbox.py', 'gptbox_runtime.py', 'bootstrap.py', 'selinux_bootstrap.py', 'candidate.py'):
            self.protected(Path(__file__).with_name(name))
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
        # This separate lock spans the two operations. Their existing bootstrap
        # locks remain separate: prepare exits its lock before assemble enters.
        with self.lock('initialize.lock'):
            prior = json.loads(self.text(path, '{}'))
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
            record = {'native_units': prior.get('native_units', []), 'target': target, 'phase': 'prepare', 'prepare': 'pending', 'maintenance_gptbox': 'pending',
                      'job_admission': False, 'limits_seconds': {
                          'execution': INITIALIZE_EXECUTION, 'prepare': PREPARE_EXECUTION, 'adapter': ADAPTER_EXECUTION,
                          'image': IMAGE_EXECUTION, 'cleanup': CLEANUP_EXECUTION, 'command_cleanup_grace': COMMAND_CLEANUP_GRACE,
                          'assembly_native': ASSEMBLY_LIFETIME, 'runtime_native': RUNTIME_LIFETIME}}
            def save():
                self.atomic(path, json.dumps(record, sort_keys=True) + '\n', expected=self.text(path) or None)
            def diagnostic(entry):
                location = STATE + '/prepare-diagnostics.json'
                history = json.loads(self.text(location, '{"recent":[],"failures":[]}'))
                history['recent'] = (history['recent'] + [entry])[-4:]
                if entry['status'] != 0:
                    history['failures'] = (history['failures'] + [entry])[-4:]
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
            prepare_started = time.monotonic()
            adapter_started = None
            try:
                with preparation.run.phase(PREPARE_EXECUTION, 'dev-pair-initialize-prepare'):
                    keys = github_keys()
                    # The shared preparation/adapter context unit has a fixed
                    # owner description. Retry reconciles it before prepare.
                    if prior and retry:
                        unit = 'dev-pair-gptbox-' + expected + '.service'
                        preparation.run.reconcile_native(('--unit=' + unit, '--description=dev-pair-owned-' + unit, '--uid=dp-maint'),
                                                         {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
                    preparation.prepare('core', keys, sources, context, expected, password=password,
                                        source_check=lambda: self.inputs(context, expected, upstream, revision))
                record.update(phase='maintenance-gptbox', prepare='complete',
                              prepare_elapsed_seconds=round(time.monotonic() - prepare_started, 3))
                self.target = ROOT + '/' + expected
                save()
                adapter_started = time.monotonic()
                with self.run.phase(ADAPTER_EXECUTION, 'dev-pair-initialize-adapter'):
                    result = self.assemble(context, expected, upstream, revision, apply=True, retry=retry)
                record.update(phase='complete', maintenance_gptbox='complete', result=result,
                              adapter_elapsed_seconds=round(time.monotonic() - adapter_started, 3))
                save()
                return record
            except BaseException:
                # Preserve successful prerequisite phase independently. Native
                # per-command and OCI lifetimes remain finite after interruption.
                if record['prepare'] != 'complete':
                    record['prepare'] = 'blocked'
                    record['prepare_elapsed_seconds'] = round(time.monotonic() - prepare_started, 3)
                else:
                    record['maintenance_gptbox'] = 'blocked'
                    record['adapter_elapsed_seconds'] = round(time.monotonic() - (adapter_started or time.monotonic()), 3)
                record['failure'] = 'blocked-or-interrupted; inspect protected diagnostics; explicit retry required'
                record['cleanup'] = 'not verified; recorded native command/OCI lifetimes remain finite'
                if record['prepare'] == 'complete':
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
                            self.record('cleanup-only', {**cleanup, 'phase': 'complete'})
                        record['cleanup'] = 'exact owned executor/recorded resources reconciled'
                    except BaseException:
                        record['cleanup'] = 'blocked; exact resources retained; native lifetimes enforced'
                save()
                raise
            finally:
                self.run.native_register = None
                preparation.run.native_register = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('assemble', 'initialize'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--retry', action='store_true', help='reconcile and retry one incomplete exact target; at most two attempts')
    parser.add_argument('--context', required=True)
    parser.add_argument('--expected-context-sha256', required=True)
    parser.add_argument('--distrobox-source', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--bootstrap-source', action='append')
    parser.add_argument('--password-file')
    args = parser.parse_args()
    try:
        app = Gptbox()
        if args.stage == 'initialize':
            result = app.initialize(args.context, args.expected_context_sha256, args.distrobox_source, args.source_sha,
                                    args.bootstrap_source, args.password_file, args.apply, args.retry)
        else:
            result = app.assemble(args.context, args.expected_context_sha256, args.distrobox_source, args.source_sha, args.apply, args.retry)
        print(json.dumps(result, indent=2))
        return 0
    except (Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('gptbox operation blocked; no job/runtime admission; inspect protected evidence locally', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
