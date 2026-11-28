#!/usr/bin/python3 -IB
"""Commission the approved initial platform on the selected Fedora host."""
import argparse
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time

KIT = Path(__file__).absolute().parent.parent
INSTALL = '/usr/libexec/dev-pair'
STATE = '/var/lib/dev-pair'
PRIVATE = STATE + '/bootstrap/host-commissioning'
AUTOMATIC_POLICY = PRIVATE + '/automatic-policy.json'
INITIAL_SITE = PRIVATE + '/initial-site.json'
ACTIVATION = PRIVATE + '/workload-activation.json'
DAY0_PROGRESS = '/var/lib/dev-pair-day0/progress.json'
CONTROL = STATE + '/renewal'
FENCE = STATE + '/renewal-fence'
MANIFEST = 'runtime/commissioning/manifest.json'
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'
UNIT_ROOT = '/etc/systemd/system'
BOOT_FENCE = 'dev-pair-renewal-boot-fence.service'
RECOVERY = 'dev-pair-renewal-recovery.service'
TIMERS = {
    'agent-renewal': ('dev-pair-renewal-agent.timer', 'dev-pair-renewal@agent.service'),
    'checklist-spool': ('dev-pair-checklist-spool.timer', 'dev-pair-checklist-spool.service'),
    'checklist-promotion': ('dev-pair-promotion-scan.timer', 'dev-pair-promotion-scan.service'),
    'owner-intake': ('dev-pair-intake-recovery.timer', 'dev-pair-intake-recovery.service'),
}
AGENT_BRIDGE = ('dev-pair-agent-bridge.timer', 'dev-pair-agent-bridge@poll.service')
GITHUB_CONFIG = Path('/root/.config/gh')
WORKLOAD_GUARDS = {
    'agent-renewal': ('dev-pair-renewal@agent.service', AGENT_BRIDGE[1]),
    'checklist-spool': ('dev-pair-checklist-spool.service',),
    'checklist-promotion': ('dev-pair-promotion-scan.service', 'dev-pair-promotion@.service'),
    'owner-intake': ('dev-pair-intake-recovery.service', 'dev-pair-intake@.service', 'dev-pair-product@.service'),
}
TLS_FILES = ('cert.pem', 'peer.pem', 'key.pem')
CHECKLIST_SERVER = '/etc/dev-pair/checklist-server'
CHECKLIST_CLIENT = '/etc/dev-pair/checklist-client'
LOCAL_CHECKLIST_TLS = '/etc/dev-pair/.checklist-local-tls'
OPENSSL = '/usr/bin/openssl'
DEFAULT_SITE_SLOT = 'job-1'
DEFAULT_SITE_BYTES = 8 * 1024**3
CORE_HELD_FEATURES = tuple(sorted(TIMERS))
WORKLOAD_SCOPE_FIELDS = ('boot_id', 'release_sha256', 'proof_sha256')
DEFAULT_CHECKLIST = {'uid': 2200, 'subid_start': 2000000, 'validation_mib': 1536, 'validation_inodes': 32768,
                     'live_mib': 1024, 'live_inodes': 16384, 'reserve_mib': 1024, 'reserve_inodes': 1024}
NUMBERS = {'uid': (1000, 2**31 - 1), 'subid_start': (65536, 2**32 - 1 - 65536),
           'validation_mib': (128, 2048), 'live_mib': (128, 2048),
           'validation_inodes': (1024, 65024), 'live_inodes': (1024, 65024),
           'reserve_mib': (1024, 20 * 1024), 'reserve_inodes': (128, 1310720)}
FILE_LIMIT = 4 * 1024**2


class Blocked(RuntimeError):
    pass


class Pending(Exception):
    def __init__(self, prerequisite, message, *, source_gap=False):
        super().__init__(prerequisite)
        self.report = {'phase': 'source-gap' if source_gap else 'pending',
                       'prerequisite': prerequisite, 'message': message}


def require(value, reason):
    if not value:
        raise Blocked(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_id(value, size=64):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{%d}' % size, value), 'invalid exact site or release identity')
    return value


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate key in protected commissioning JSON')
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def exact_fields(value, fields, reason):
    require(type(value) is dict and set(value) == set(fields), reason)


def protected(path, owner, *, directory=False, mode=None):
    require(path.is_absolute(), 'commissioning paths must be absolute')
    for member in (path, *path.parents):
        node = member.lstat()
        leaf = member == path and not directory
        require(node.st_uid in (0, owner) and node.st_gid in (0, owner) and not node.st_mode & 0o022 and
                (stat.S_ISREG(node.st_mode) and node.st_nlink == 1 if leaf else stat.S_ISDIR(node.st_mode)),
                'protected commissioning path ownership, ancestry or inode differs')
        if member == path and mode is not None:
            require(stat.S_IMODE(node.st_mode) == mode, 'protected commissioning path mode differs')
    return path


def capture(path, owner, *, mode=None, maximum=FILE_LIMIT):
    protected(path, owner, mode=mode)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 and
                (mode is None or stat.S_IMODE(info.st_mode) == mode) and 0 < info.st_size <= maximum,
                'protected commissioning content is unavailable or outside its bound')
        data = stream.read(maximum + 1)
    require(len(data) == info.st_size and len(data) <= maximum, 'protected commissioning content changed')
    return data


def immutable_path(value):
    require(type(value) is str and value.startswith('/') and not value.startswith('//') and
            PurePosixPath(value).as_posix() == value and '..' not in PurePosixPath(value).parts,
            'protected absolute path is not canonical')
    return value


def read_policy(raw, source):
    value = parse(raw)
    exact_fields(value, ('schema', 'source_sha', 'machine_id', 'platform_sha256', 'site_config_sha256',
                         'timers', 'checklist'), 'commissioning policy fields differ')
    require(type(value['schema']) is int and value['schema'] == 1 and value['source_sha'] == source,
            'commissioning policy names a different reviewed source')
    hex_id(value['machine_id'], 32)
    hex_id(value['platform_sha256'])
    hex_id(value['site_config_sha256'])
    timers = value['timers']
    require(type(timers) is list and all(type(item) is str and item in TIMERS for item in timers)
            and timers == sorted(set(timers)), 'ambiguous or unapproved commissioning timer set')
    settings = value['checklist']
    exact_fields(settings, ('tls_profile', *NUMBERS), 'commissioning checklist profile differs')
    immutable_path(settings['tls_profile'])
    for key, (minimum, maximum) in NUMBERS.items():
        require(type(settings[key]) is int and minimum <= settings[key] <= maximum,
                'checklist role geometry is outside the supported bounds')
    return value


def install_target(target):
    immutable_path(target)
    require(re.fullmatch(r'/usr/libexec/dev-pair/(?:tools|runtime|renewal|examples)/[a-zA-Z0-9_./@-]+', target)
            or re.fullmatch(r'/etc/(?:systemd/system|tmpfiles.d)/dev-pair-[a-z0-9./@_-]+', target)
            or target in ('/usr/local/bin/dev-pair', '/etc/sudoers.d/60-dev-pair-owner'),
            'commissioning manifest contains an unapproved install target')
    return target


def workload_guard_command(feature):
    return f'{PYTHON} -IB {INSTALL}/tools/commission_host.py guard {feature}'


def workload_guard_files(features):
    return {f'{UNIT_ROOT}/{unit}.d/81-dev-pair-workload-guard.conf':
            (('[Service]\nExecCondition=' + workload_guard_command(feature) + '\n').encode(), 0o644, feature)
            for feature in features for unit in WORKLOAD_GUARDS[feature]}


def validate_feature_grant(grant):
    from owner_intake import job_id

    exact_fields(grant, ('subject', 'expires_unix', 'sha256'), 'invalid retained workload grant')
    job_id(grant['subject'])
    require(grant['expires_unix'] is None or type(grant['expires_unix']) is int and grant['expires_unix'] > 0,
            'invalid retained workload grant scope')
    hex_id(grant['sha256'])
    return grant


def workload_scope_fields(value):
    scope = {key: value[key] for key in WORKLOAD_SCOPE_FIELDS}
    require(type(scope['boot_id']) is str and re.fullmatch(r'[0-9a-f-]{36}', scope['boot_id']),
            'invalid recorded workload boot identity')
    hex_id(scope['release_sha256'])
    hex_id(scope['proof_sha256'])
    return scope


def verify_checkout(kit, revision, owner):
    # Establish the exact source before making any checkout module importable.
    protected(kit / '.git', owner, directory=True)
    env = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    git = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '-C', str(kit),
           '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false']

    def output(*argv):
        result = subprocess.run([*git, *argv], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True, timeout=15)
        require(len(result.stdout) <= FILE_LIMIT, 'commissioning Git evidence exceeded its byte bound')
        return result.stdout

    require(output('rev-parse', '--verify', 'HEAD').strip() == revision.encode() and
            not output('status', '--porcelain=v1', '--untracked-files=all', '--ignored'),
            'commissioning needs the clean exact reviewed Git checkout')
    manifest = capture(kit / MANIFEST, owner, maximum=65536)
    require(output('cat-file', 'blob', revision + ':' + MANIFEST) == manifest,
            'commissioning manifest differs from the approved Git object')
    close = ['tools/commission_host.py']
    for entry in parse(manifest)['files']:
        if type(entry['source']) is str and re.fullmatch(r'tools/[a-z_]+\.py', entry['source']):
            close.append(entry['source'])
    for source in close:
        require(output('cat-file', 'blob', revision + ':' + source) == capture(kit / source, owner),
                'commissioning tool differs from the approved Git object')


class Commission:
    # The root and manager injection points are only for isolated source tests.
    def __init__(self, kit, root, commands, owner, services):
        self.kit, self.root, self.run, self.owner, self.services = kit, root, commands, owner, services

    def path(self, value):
        return self.root / value.lstrip('/')

    def read(self, value, mode=0o600, maximum=65536):
        return capture(self.path(value), self.owner, mode=mode, maximum=maximum)

    def directory(self, value, mode=0o755):
        path = self.path(value)
        if not os.path.lexists(path):
            if path.parent != self.root and not os.path.lexists(path.parent):
                self.directory('/' + str(path.parent.relative_to(self.root)))
            protected(path.parent, self.owner, directory=True)
            path.mkdir(mode=mode)
            path.chmod(mode)
            self.sync(path.parent)
        return protected(path, self.owner, directory=True, mode=mode)

    def file(self, target, raw, mode, *, save=True):
        path = self.path(target)
        if os.path.lexists(path):
            require(self.read(target, mode, FILE_LIMIT) == raw, 'existing commissioning file conflicts: ' + target)
            if save:
                self.sync(path.parent)
            return
        if not save:
            # The nearest existing ancestor must be protected before any install.
            parent = next(parent for parent in path.parents if os.path.lexists(parent))
            protected(parent, self.owner, directory=True)
            return
        if not path.parent.exists():
            self.directory('/' + str(path.parent.relative_to(self.root)))
        protected(path.parent, self.owner, directory=True)
        if target == '/etc/sudoers.d/60-dev-pair-owner':
            self.publish_sudoers(path, raw, mode)
        else:
            self.publish_file(path, raw, mode)
        require(self.read(target, mode, FILE_LIMIT) == raw, 'installed commissioning bytes changed')

    @staticmethod
    def publish_file(path, raw, mode):
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            descriptor = os.open('.', os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, mode, dir_fd=parent)
            with os.fdopen(descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                descriptors = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    # Anonymous staging leaves at most one name even if the
                    # operator dies before cleanup. The final link cannot replace a peer.
                    os.link(str(stream.fileno()), path.name, src_dir_fd=descriptors, dst_dir_fd=parent, follow_symlinks=True)
                except FileExistsError:
                    pass  # The caller verifies the exact protected bytes after publication.
                finally:
                    os.close(descriptors)
            os.fsync(parent)
        finally:
            os.close(parent)

    def publish_sudoers(self, path, raw, mode):
        file_descriptor, name = tempfile.mkstemp(dir=path.parent, prefix='.dev-pair-commission-')
        try:
            with os.fdopen(file_descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.run('/usr/sbin/visudo', '-cf', name, timeout=12)
        finally:
            os.unlink(name)
        self.publish_file(path, raw, mode)

    @staticmethod
    def sync(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextmanager
    def lock(self):
        self.directory(PRIVATE, 0o700)
        path = self.path(PRIVATE + '/owner.lock')
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path, flags, 0o600), 'rb+') as stream:
            node = os.fstat(stream.fileno())
            require(stat.S_ISREG(node.st_mode) and node.st_uid == self.owner and node.st_nlink == 1 and
                    stat.S_IMODE(node.st_mode) == 0o600, 'commissioning lock is not protected')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(path.lstat().st_ino == node.st_ino, 'commissioning lock was replaced')
            yield

    def source_bytes(self, source, revision):
        require(type(source) is str and re.fullmatch(r'(?:tools|runtime|examples)/[A-Za-z0-9_./@-]+', source) and
                '..' not in PurePosixPath(source).parts and PurePosixPath(source).as_posix() == source,
                'unsafe commissioning source member')
        raw = capture(self.kit / source, self.owner)
        committed = self.run('/usr/bin/git', '-C', str(self.kit), 'show', revision + ':' + source, timeout=15)
        require(raw == committed.encode(), 'commissioning source differs from the exact reviewed checkout')
        return raw

    def package(self, policy, bundle, *, retained=(), activation=False):
        revision = policy['source_sha']
        raw = self.source_bytes(MANIFEST, revision)
        require(bundle.get(MANIFEST) == digest(raw), 'commissioning manifest is outside the approved host bundle')
        manifest = parse(raw)
        exact_fields(manifest, ('schema', 'files'), 'invalid commissioning manifest')
        require(type(manifest['schema']) is int and manifest['schema'] == 1 and
                type(manifest['files']) is list and 20 <= len(manifest['files']) <= 128,
                'commissioning manifest inventory differs')
        files, all_targets = {}, set()
        features = {'base', *policy['timers']}
        if 'owner-intake' in features:
            features.add('owner-entry')
        for row in manifest['files']:
            exact_fields(row, ('source', 'target', 'mode', 'feature'), 'invalid commissioning manifest entry')
            source, target = row['source'], install_target(row['target'])
            require(target not in all_targets and row['feature'] in ('base', 'owner-entry', 'agent-bridge', *TIMERS) and
                    row['mode'] in ('0644', '0755', '0440'), 'ambiguous commissioning install entry')
            all_targets.add(target)
            contents = self.source_bytes(source, revision)
            # The fixed example recipe stays in the independently vetted
            # checkout. F's portable host manifest includes tools and runtime.
            if source != 'examples/checklist/Containerfile':
                require(bundle.get(source) == digest(contents), 'reviewed host bundle bytes differ from commissioning kit')
            feature = 'agent-renewal' if row['feature'] == 'agent-bridge' else row['feature']
            legacy_agent_timer = target == UNIT_ROOT + '/' + TIMERS['agent-renewal'][0]
            if (feature in features and (row['feature'] != 'agent-bridge' or activation) and
                    not (activation and legacy_agent_timer)):
                files[target] = (contents, int(row['mode'], 8), feature)
            elif feature in retained or (feature == 'owner-entry' and 'owner-intake' in retained):
                self.file(target, contents, int(row['mode'], 8), save=False)
            else:
                require(not os.path.lexists(self.path(target)), 'disabled feature has installed commissioning files')
        for target, item in workload_guard_files(TIMERS).items():
            contents, mode, feature = item
            if activation and feature in features:
                files[target] = item
            elif feature in retained:
                self.file(target, contents, mode, save=False)
            else:
                require(not os.path.lexists(self.path(target)), 'unowned workload guard was preserved')
        return files

    def inspect(self, policy):
        live = self.services.inventory(policy['source_sha'])
        require(live['machine_id'] == policy['machine_id'] and live['host'] == 'erebus' and
                live['arch'] == 'x86_64' and live['pid1'] == 'systemd' and live['selinux'] == '1',
                'the inspected destination is not the approved enforcing Fedora host')
        distro = dict(line.split('=', 1) for line in live['os_release'].splitlines() if '=' in line)
        require(distro.get('ID', '').strip('"') == 'fedora' and distro.get('VERSION_ID', '').strip('"') == '44',
                'the inspected destination does not run the approved Fedora release')
        return live

    def automatic(self, action, revision):
        identity = self.services.identity()
        observed = self.inspect({'source_sha': revision, 'machine_id': identity['machine_id']})
        require(observed['boot_id'] == identity['boot_id'], 'destination boot changed during commissioning observation')
        prepared = os.path.lexists(self.path(AUTOMATIC_POLICY))
        checked_parts = False
        if prepared:
            raw = self.read(AUTOMATIC_POLICY)
            policy = read_policy(raw, revision)
            require(raw == encoded(policy), 'recorded automatic commissioning policy bytes differ')
            require(policy['machine_id'] == observed['machine_id'] and not policy['timers'],
                    'automatic commissioning policy belongs to another machine or admission scope')
            host_profile = None
        else:
            acquire = action in ('prepare', 'apply')
            if acquire and os.path.lexists(self.path(PRIVATE + '/intent.json')):
                raise Blocked('existing commissioning uses a different protected site authority')
            site_sha, site = self.automatic_site(observed, revision, persist=acquire)
            platform = self.services.initial_platform(revision, acquire=acquire)
            host_profile = self.services.initial_host_profile(site, observed)
            if acquire:
                with self.lock():
                    require(not os.path.lexists(self.path(PRIVATE + '/intent.json')),
                            'existing commissioning uses a different protected site authority')
                    self.services.verify_initial_parts(platform)
                    checked_parts = True
                    self.services.check_initial_capacity(identity, site)
                    self.services.prepare_checklist_pair(self, observed, revision)
            policy = read_policy(encoded({'schema': 1, 'source_sha': revision, 'machine_id': observed['machine_id'],
                                         'platform_sha256': platform, 'site_config_sha256': site_sha, 'timers': [],
                                         'checklist': self.services.initial_checklist(identity, site, revision)}), revision)
            raw = encoded(policy)
        report = {'phase': 'prepared' if prepared else 'discovered', 'platform_sha256': policy['platform_sha256'],
                  'site_config_sha256': policy['site_config_sha256'], 'held_features': list(CORE_HELD_FEATURES)}
        if action in ('status', 'discover'):
            if prepared:
                self.require_first_site(observed['machine_id'], policy['site_config_sha256'])
                self.services.authority(policy)
            listener = '/var/lib/dev-pair/checklist-release/managed-listener.json'
            if action == 'status' and prepared and os.path.lexists(self.path(listener)):
                recorded = parse(self.read(listener))
                report['recorded_listener_phase'] = recorded['phase']
                report['listener_observation_on_current_boot'] = recorded['boot'] == observed['boot_id']
            if action == 'status' and prepared:
                activation = self.activation_record(digest(raw), observed['machine_id'])
                if activation is not None:
                    report['recorded_activation'] = {'current_boot': activation['boot_id'] == observed['boot_id'],
                                                     'features': {name: {'phase': row['phase'], 'next': row['next']}
                                                                  for name, row in activation['features'].items()}}
            return report
        policy_sha = digest(raw)
        with self.lock():
            activation = self.activation_record(policy_sha, observed['machine_id'])
            applying = os.path.lexists(self.path(PRIVATE + '/intent.json'))
            if applying:
                prior = parse(self.read(PRIVATE + '/intent.json'))
                require(prior.get('policy_sha256') == policy_sha,
                        'existing commissioning uses a different protected site authority')
            selectors = [os.path.lexists(self.path(CONTROL + '/' + name + '.json')) for name in ('current', 'site-current')]
            placed = all(selectors)
            can_restore = prepared and not applying and not any(selectors)
            first_site = self.require_first_site(observed['machine_id'], policy['site_config_sha256'], restore=can_restore)
            if not placed and not checked_parts:
                self.services.verify_initial_parts(policy['platform_sha256'])
            restored = (can_restore and first_site is not None and self.services.first_site_profiles_missing(first_site))
            if restored:
                self.restore_prepared_site(policy, observed, first_site)
            if host_profile is not None:
                target, contents = host_profile
                self.file(target, contents, 0o600)
            site, bundle = self.services.authority(policy)
            if prepared and not restored:
                # The native stage checks its own remaining allocation after an
                # owned apply starts. Its existing backing must not be counted twice.
                self.verify_prepared_checklist(policy, observed, site, placed=placed or applying)
            owned = activation['features'] if activation else ()
            files = self.package(policy, bundle, retained=owned)
            if action == 'prepare':
                self.services.configuration(policy, site)
            else:
                self.restore_owned_guards(owned)
            self.file(AUTOMATIC_POLICY, raw, 0o600)
        if action == 'prepare':
            return {**report, 'phase': 'prepared'}
        core = self.apply(policy, policy_sha, observed['boot_id'], site, files, retained=owned)
        if core['phase'] != 'ready':
            return {**core, 'held_features': list(CORE_HELD_FEATURES)}
        return self.advance_workloads(policy, policy_sha, observed, site, bundle, core)

    def activation_record(self, policy_sha, machine):
        if not os.path.lexists(self.path(ACTIVATION)):
            return None
        value = parse(self.read(ACTIVATION))
        exact_fields(value, ('schema', 'policy_sha256', 'machine_id', 'boot_id', 'release_sha256', 'proof_sha256', 'features'),
                     'unknown automatic workload activation record')
        require(type(value['schema']) is int and value['schema'] == 1 and value['policy_sha256'] == policy_sha and
                value['machine_id'] == machine and type(value['features']) is dict and set(value['features']) <= set(TIMERS),
                'workload activation belongs to another commissioning policy')
        workload_scope_fields(value)
        for saved in value['features'].values():
            require(type(saved) is dict, 'invalid workload activation state')
            exact_fields(saved, ('phase', 'grant', 'next', 'runtime') if 'runtime' in saved else ('phase', 'grant', 'next'),
                         'invalid workload activation state')
            require(saved['phase'] in ('staging', 'active', 'armed', 'held') and type(saved['next']) is list and
                    len(saved['next']) <= 2 and all(type(value) is str and 0 < len(value) <= 128 for value in saved['next']) and
                    (saved['phase'] == 'armed') == bool(saved['next']), 'invalid workload activation phase or timer readback')
            validate_feature_grant(saved['grant'])
            if 'runtime' in saved:
                require(saved['phase'] in ('active', 'armed'), 'held workload has a runtime observation')
                exact_fields(saved['runtime'], WORKLOAD_SCOPE_FIELDS, 'unknown automatic workload requalification record')
                workload_scope_fields(saved['runtime'])
        return value

    def save_activation(self, value):
        from renewal import replace_json

        replace_json(self.path(ACTIVATION), value)

    def restore_owned_guards(self, owned):
        # Recreate the exact deny-by-default guard before any core daemon reload.
        for target, (contents, mode, _) in workload_guard_files(owned).items():
            if not os.path.lexists(self.path(target)):
                self.file(target, contents, mode)
                self.run('/usr/sbin/restorecon', '-F', target, timeout=10)

    def require_runtime_feature(self, feature, *, owner_entry=False):
        from renewal import TERMINAL

        require(feature in TIMERS, 'unknown automatic workload feature')
        controller = self.services.renewal()
        with self.lock(), controller.lock(shared=True), controller.host_fence(shared=True):
            raw = self.read(AUTOMATIC_POLICY)
            decoded = parse(raw)
            policy = read_policy(raw, hex_id(decoded['source_sha'], 40))
            identity = self.services.identity()
            saved = self.activation_record(digest(raw), identity['machine_id'])
            row = saved['features'].get(feature) if saved else None
            require(row is not None and (row['phase'] == 'armed' or row['phase'] == 'active' and not owner_entry),
                    'automatic workload feature is held')
            grant = row['grant']
            require(grant['expires_unix'] is None or grant['expires_unix'] > time.time(), 'automatic workload grant expired')
            if feature == 'owner-intake':
                try:
                    self.provider_fence().require_ready()
                except (OSError, ValueError) as exc:
                    raise Pending('provider-transition', 'Provider starts are held for the current broker transition.') from exc
            selected, boot = controller.live_release(), identity['boot_id']
            _, journal = controller.transition()
            require((journal is None or journal['phase'] in TERMINAL)
                    and not os.path.lexists(self.path(FENCE + '/frozen'))
                    and selected == parse(self.read(CONTROL + '/site-current.json')),
                    'automatic workload is frozen until renewal settles')
            prior = row.get('runtime') or workload_scope_fields(saved)
            changed = (selected, boot) != (prior['release_sha256'], prior['boot_id'])
            if changed:
                # This verifies the committed portable/base/site contract. A new
                # full host or DevBox scope needs its own approved policy.
                self.services.verify_selection(controller, selected, policy)
            proof = self.services.workload_scope(self, policy, selected, boot, ssh=changed)
            require(changed or proof == prior['proof_sha256'], 'automatic workload authorization changed')
            # Promotion's digest embeds the originally approved local release.
            # Re-measure its present enrolled material in that same digest scope.
            authority_release = saved['release_sha256'] if feature == 'checklist-promotion' else selected
            require(self.services.feature_authority(feature, authority_release, recorded=grant) == grant,
                    'automatic workload authorization changed')
            require(self.services.identity() == identity and (grant['expires_unix'] is None or grant['expires_unix'] > time.time()),
                    'automatic workload grant or host changed during verification')
            if changed:
                row['runtime'] = workload_scope_fields({'boot_id': boot, 'release_sha256': selected, 'proof_sha256': proof})
                self.save_activation(saved)

    def advance_workloads(self, policy, policy_sha, observed, site, bundle, core):
        selected = core['selected_release']
        machine, boot = observed['machine_id'], observed['boot_id']
        with self.lock(), self.services.renewal().lock(shared=True):
            saved = self.activation_record(policy_sha, machine)
            features = saved['features'] if saved else {}
            try:
                proof = self.services.workload_scope(self, policy, selected, boot)
            except Pending as wait:
                proof, pending = None, wait.report['prerequisite']
            if proof is None and not features:
                return {**core, 'held_features': list(CORE_HELD_FEATURES),
                        'pending_features': dict.fromkeys(TIMERS, pending)}
            current = {'schema': 1, 'policy_sha256': policy_sha, 'machine_id': machine, 'boot_id': boot,
                       'release_sha256': selected, 'proof_sha256': proof or saved['proof_sha256'], 'features': features}
            if saved and any(saved[key] != current[key] for key in ('boot_id', 'release_sha256', 'proof_sha256')):
                for feature in features.values():
                    feature.update(phase='held', next=[])
                    feature.pop('runtime', None)
                self.save_activation(current)

            timers, holds, retained_services = {}, {}, {}
            for feature in CORE_HELD_FEATURES:
                try:
                    if proof is None:
                        raise Pending(pending, 'Current independent workload access is pending.')
                    if feature == 'owner-intake' and core.get('provider_start_pending'):
                        raise Pending('provider-transition', core['provider_start_pending'])
                    grant = self.services.feature_authority(feature, selected)
                except Pending as wait:
                    holds[feature] = wait.report['prerequisite']
                    if feature in features:
                        retained_services[feature] = self.hold_owned_workload(feature, policy, bundle, current)
                    continue
                validate_feature_grant(grant)
                selected_policy = {**policy, 'timers': [feature]}
                files = self.package(selected_policy, bundle, retained=features, activation=True)
                previous = features.get(feature)
                missing = any(member == feature and not os.path.lexists(self.path(target))
                              for target, (_, _, member) in files.items())
                if previous is None or previous['phase'] not in ('active', 'armed') or previous['grant'] != grant or missing:
                    features[feature] = {'phase': 'staging', 'grant': grant, 'next': []}
                    self.save_activation(current)
                    self.install_workload(feature, selected_policy, site, files, selected)
                    try:
                        self.verify_feature_authority(feature, policy, selected, boot, proof, grant)
                    except Pending as wait:
                        holds[feature] = wait.report['prerequisite']
                        retained_services[feature] = self.hold_owned_workload(feature, policy, bundle, current)
                        continue
                    features[feature]['phase'] = 'active'
                    self.save_activation(current)
                else:
                    for target, (contents, mode, member) in files.items():
                        if member == feature:
                            require(self.read(target, mode, FILE_LIMIT) == contents, 'active workload file changed')
                timer, readback = self.arm_timer(feature, files, activation=True)
                try:
                    self.verify_feature_authority(feature, policy, selected, boot, proof, grant)
                    if feature == 'owner-intake':
                        self.publish_owner_entry(files)
                        self.verify_feature_authority(feature, policy, selected, boot, proof, grant)
                except Pending as wait:
                    holds[feature] = wait.report['prerequisite']
                    retained_services[feature] = self.hold_owned_workload(feature, policy, bundle, current)
                    continue
                confirmed = {'phase': 'armed', 'grant': grant, 'next': readback['next']}
                if features[feature] != confirmed:
                    features[feature] = confirmed
                    self.save_activation(current)
                timers[timer] = readback
            report = {**core, 'timers': timers, 'held_features': sorted(holds), 'pending_features': holds,
                      'owner_terminal': '/usr/local/bin/dev-pair' if 'owner-intake' not in holds else None}
            still_running = {feature: units for feature, units in retained_services.items() if units}
            if still_running:
                report['retained_services'] = still_running
            if AGENT_BRIDGE[0] in timers:
                report['agent_publication'] = self.services.agent_publication_status(selected)
            return report

    def verify_feature_authority(self, feature, policy, selected, boot, proof, grant):
        if (self.services.workload_scope(self, policy, selected, boot) != proof or
                self.services.feature_authority(feature, selected, recorded=grant) != grant):
            raise Pending('workload-authorization-changed', 'Workload authorization changed during activation.')

    def hold_owned_workload(self, feature, policy, bundle, current):
        features = current['features']
        if features[feature]['phase'] != 'held':
            features[feature].update(phase='held', next=[])
            features[feature].pop('runtime', None)
            self.save_activation(current)
        files = self.package({**policy, 'timers': [feature]}, bundle, retained=features, activation=True)
        if feature == 'owner-intake':
            self.withdraw_owner_entry(files)
        self.disable_owned_timer(feature, files)
        lingering = []
        units = WORKLOAD_GUARDS[feature] if feature == 'agent-renewal' else (TIMERS[feature][1],)
        for unit in units:
            fragment = UNIT_ROOT + '/' + re.sub(r'@[^.]+\.service$', '@.service', unit)
            if os.path.lexists(self.path(fragment)) and self.unit(unit, files)['ActiveState'] != 'inactive':
                lingering.append(unit)
        return lingering

    def install_workload(self, feature, policy, site, files, selected):
        changed = []
        # A partial first install cannot leave a loaded service without its fixed guard.
        for target, (contents, mode, member) in sorted(files.items(), key=lambda row: not row[0].endswith('81-dev-pair-workload-guard.conf')):
            if member == feature:
                self.file(target, contents, mode)
                changed.append(target)
        self.run('/usr/sbin/restorecon', '-F', *changed, timeout=30)
        self.run(SYSTEMCTL, 'daemon-reload', timeout=25)
        if feature == 'owner-intake':
            self.verify_owner_units(site, files)
        self.services.post_provision(policy, selected)
        if feature == 'agent-renewal':
            self.unit(TIMERS[feature][1], files)
        if feature == 'checklist-promotion':
            self.unit('dev-pair-promotion@preflight.service', files)
        self.check_timer(feature, files, activation=True)

    def disable_owned_timer(self, feature, files):
        timer, _ = AGENT_BRIDGE if feature == 'agent-renewal' else TIMERS[feature]
        target = UNIT_ROOT + '/' + timer
        if not os.path.lexists(self.path(target)):
            self.require_inactive(timer)
            return
        self.file(target, *files[target][:2], save=False)
        row = self.unit(timer, files, timer=True)
        if row['ActiveState'] != 'inactive' or row['UnitFileState'] == 'enabled':
            self.run(SYSTEMCTL, 'disable', '--now', timer, timeout=25)
        self.require_inactive(timer)

    def withdraw_owner_entry(self, files):
        # Remove the no-password authorization before the public launcher.
        paths = ('/etc/sudoers.d/60-dev-pair-owner', '/usr/local/bin/dev-pair')
        for target in paths:
            if not os.path.lexists(self.path(target)):
                continue
            raw, mode, feature = files[target]
            require(feature == 'owner-entry' and self.read(target, mode, FILE_LIMIT) == raw,
                    'existing owner command or sudo rule is outside the owned activation')
            path = self.path(target)
            path.unlink()
            self.sync(path.parent)

    def publish_owner_entry(self, files):
        for target, (contents, mode, feature) in files.items():
            if feature == 'owner-entry':
                self.file(target, contents, mode)
                self.run('/usr/sbin/restorecon', '-F', target, timeout=10)
        self.run('/usr/sbin/visudo', '-c', timeout=15)

    def automatic_site(self, observed, revision, *, persist):
        if not persist:
            candidate = self.initial_site_candidate(observed)
            if candidate is not None:
                return candidate
            raise Pending('initial-site-config', 'The first site profile will be derived when the verified Day 0 installation resumes.')
        with self.lock():
            candidate = self.initial_site_candidate(observed, restore=True)
            record = self.first_site_intent(observed['machine_id'])
            if candidate is not None:
                if record is not None:
                    # A prior process may have linked the site before syncing its directory.
                    self.services.publish_first_site(self, record)
                return candidate
            require(not os.path.lexists(self.path(PRIVATE + '/intent.json')),
                    'existing commissioning uses a different protected site authority')
            origin = self.services.first_site_authority(observed, revision)
            identity = {'schema': 1, 'machine_id': observed['machine_id'], 'source_sha': revision,
                        'bootstrap_source_sha': origin}
            if record is not None:
                require(all(record[key] == value for key, value in identity.items()),
                        'protected first-site intent belongs to another installation')
            else:
                host, site = self.services.derive_first_site(observed)
                record = {**identity, 'host': host, 'site': site}
                self.file(INITIAL_SITE, encoded(record), 0o600)
            require(record['site']['hostname'] == observed['host'], 'protected first site names a different destination')
            site_sha = self.services.publish_first_site(self, record)
            validated_sha, site = self.services.initial_site(observed['host'])
            require(validated_sha == site_sha, 'published first site differs from its approved identity')
            return validated_sha, site

    def initial_site_candidate(self, observed, *, restore=False):
        try:
            selected = self.services.initial_site(observed['host'])
        except Pending as waiting:
            if waiting.report['prerequisite'] != 'initial-site-config':
                raise
            return None
        self.require_first_site(observed['machine_id'], selected[0], restore=restore)
        return selected

    def first_site_intent(self, machine):
        if not os.path.lexists(self.path(INITIAL_SITE)):
            return None
        record = parse(self.read(INITIAL_SITE))
        exact_fields(record, ('schema', 'machine_id', 'source_sha', 'bootstrap_source_sha', 'site', 'host'),
                     'invalid protected first-site intent')
        require(type(record['schema']) is int and record['schema'] == 1 and record['machine_id'] == machine and
                type(record['site']) is dict and type(record['host']) is dict,
                'protected first-site intent belongs to another installation')
        hex_id(record['source_sha'], 40)
        hex_id(record['bootstrap_source_sha'], 40)
        return record

    def require_first_site(self, machine, selected, *, restore=False):
        record = self.first_site_intent(machine)
        if record is not None:
            require(selected == digest(encoded(record['site'])), 'selected site differs from the protected first-site intent')
            self.services.verify_first_site_host(record, restore=restore)
        return record

    def restore_prepared_site(self, policy, observed, record):
        # An alternate protected site may have been restored in place of ours.
        self.initial_site_candidate(observed, restore=True)
        revision = policy['source_sha']
        require(record['source_sha'] == revision and record['site']['hostname'] == observed['host'],
                'prepared first-site intent belongs to another source or host')
        origin = self.services.first_site_authority(observed, revision)
        require(record['bootstrap_source_sha'] == origin, 'prepared first-site intent belongs to another bootstrap')
        self.verify_prepared_checklist(policy, observed, record['site'], placed=False)
        self.services.publish_first_site(self, record)

    def verify_prepared_checklist(self, policy, observed, site, *, placed):
        revision = policy['source_sha']
        self.services.prepare_checklist_pair(self, observed, revision, issue=False)
        require(self.services.initial_checklist(observed, site, revision, placed=placed) == policy['checklist'],
                'observed checklist geometry differs from the protected commissioning policy')

    def selectors(self, policy, boot, site, intent):
        controller = self.services.renewal()
        release_path, site_path = CONTROL + '/current.json', CONTROL + '/site-current.json'
        with controller.lock():
            saved = [hex_id(parse(self.read(path))) if os.path.lexists(self.path(path)) else None
                     for path in (release_path, site_path)]
            if all(saved):
                require(saved[0] == saved[1], 'divergent live release selectors preserved')
                self.services.verify_selection(controller, saved[0], policy)
                if intent is None:
                    require(self.services.initial_selection(controller, saved[0], policy, boot),
                            'unowned live release selectors preserved')
                    self.file(PRIVATE + '/initial-release.json', encoded(saved[0]), 0o600)
                return saved[0]
            if any(saved):
                require(intent is not None and saved.count(intent) == 1,
                        'unowned partial live release selection preserved')
            if not intent:
                intent = self.services.resolve_initial(controller, policy, boot, site)
                self.file(PRIVATE + '/initial-release.json', encoded(intent), 0o600)
            self.services.verify_selection(controller, intent, policy)
            for path in (release_path, site_path):
                self.file(path, encoded(intent), 0o600)
            return intent

    def unit(self, unit, files, *, uid=None, timer=False):
        import provider_transition
        import systemd_service_profile as profile

        template = re.sub(r'@[^.]+\.service$', '@.service', unit)
        fragment = UNIT_ROOT + '/' + template
        instance = UNIT_ROOT + '/' + unit
        drops = sorted(name for name in files if name.startswith((fragment + '.d/', instance + '.d/')))
        properties = 'LoadState,FragmentPath,DropInPaths,UnitFileState,ActiveState,SubState,' + (
            'Unit,NextElapseUSecRealtime,NextElapseUSecMonotonic' if timer else
            ','.join(('ExecStart', 'User', 'Group', *profile.PROPERTIES)))
        output = self.run(SYSTEMCTL, 'show', '--all', '--property=' + properties, unit, timeout=15)
        try:
            row = profile.manager_properties(output, properties.split(','))
        except ValueError:
            raise Blocked('systemd unit property readback differs for ' + unit) from None
        require(row['LoadState'] == 'loaded' and row['FragmentPath'] == fragment,
                'systemd loaded a different fragment for ' + unit)
        if timer:
            require(row['DropInPaths'].split() == drops, 'systemd loaded a different timer override for ' + unit)
        else:
            try:
                service = row
                guards = [files[name][0].decode().split('ExecCondition=', 1)[1].strip() for name in drops
                          if name == provider_transition.DROP_IN or name.endswith('/81-dev-pair-workload-guard.conf')]
                if guards:
                    start_guard = guards[0].replace('%i', unit.partition('@')[2].removesuffix('.service'))
                    require(len(guards) == 1 and profile.exec_start_matches(row['ExecCondition'], start_guard),
                            'systemd workload guard differs for ' + unit)
                    service = {**row, 'ExecCondition': ''}
                profile.observe(service, drops, self.path, self.run, owner=self.owner)
            except ValueError as error:
                raise Blocked('unverified effective service profile for ' + unit + '. ' + str(error)) from None
            if uid is None:
                raw = files[fragment][0].decode()
                command = re.findall(r'^ExecStart=(.+)$', raw, re.M)
                require(len(command) == 1, 'approved service command differs')
                start = command[0].replace('%i', unit.partition('@')[2].removesuffix('.service'))
                require(row['User'] == 'root' and row['Group'] in ('', 'root'),
                        'systemd effective service owner differs for ' + unit)
            else:
                start = INSTALL + '/renewal/checklist-entry'
                require(row['User'] == row['Group'] == 'dp-checklist',
                        'systemd checklist executor identity differs')
            require(profile.exec_start_matches(row['ExecStart'], start),
                    'systemd effective command differs for ' + unit)
        return row

    def check_timer(self, feature, files, *, activation=False):
        timer, service = AGENT_BRIDGE if activation and feature == 'agent-renewal' else TIMERS[feature]
        self.unit(service, files)
        pending = self.unit(timer, files, timer=True)
        require(pending['Unit'] == service, 'timer is not linked to its approved service')
        return timer, service, pending

    def arm_timer(self, feature, files, *, activation=False):
        timer, service, pending = self.check_timer(feature, files, activation=activation)
        if pending['UnitFileState'] != 'enabled' or pending['ActiveState'] != 'active':
            self.run(SYSTEMCTL, 'enable', '--now', timer, timeout=25)
        active = self.unit(timer, files, timer=True)
        scheduled = [active[key] for key in ('NextElapseUSecRealtime', 'NextElapseUSecMonotonic')
                     if active[key] not in ('', '0', 'n/a', 'infinity')]
        require(active['Unit'] == service and active['UnitFileState'] == 'enabled' and
                active['ActiveState'] == 'active' and scheduled,
                'systemd timer lacks its exact active and scheduled readback: ' + timer)
        return timer, {'service': service, 'next': scheduled}

    def timers(self, policy, files, *, retained=()):
        results = {}
        for name, (timer, service) in TIMERS.items():
            if name not in policy['timers']:
                if name not in retained:
                    for unit in (timer, service):
                        self.require_inactive(unit)
                continue
            _, results[timer] = self.arm_timer(name, files)
        return results

    def require_inactive(self, unit):
        output = self.run(SYSTEMCTL, 'show', '--all', '--property=ActiveState,UnitFileState', unit, ok=(0, 1, 4), timeout=12)
        row = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        require(set(row) == {'ActiveState', 'UnitFileState'} and row['ActiveState'] == 'inactive' and
                row['UnitFileState'] in ('', 'static', 'disabled', 'masked'),
                'disabled feature has an active or enabled root unit: ' + unit)

    def verify_owner_units(self, site, files):
        sample = sorted(site['jobs'])[0]
        for unit in ('dev-pair-provider@' + '0' * 64 + '.service',
                     f'dev-pair-intake@{sample}.service', f'dev-pair-product@{sample}.service'):
            self.unit(unit, files)

    def provider_fence(self):
        from provider_transition import Fence

        return Fence(self.root, self.run)

    def provider_transition(self):
        from provider_transition import Deferred

        try:
            self.provider_fence().converge()
        except Deferred as exc:
            return str(exc)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            return 'Provider starts are held until the exact installed manager and pending billing authority can be verified.'
        return None

    def apply(self, policy, policy_sha, boot, site, files, *, retained=()):
        # Check targets, credentials and protected site policy before installing anything.
        self.require_first_site(policy['machine_id'], policy['site_config_sha256'])
        for target, (contents, mode, _) in files.items():
            self.file(target, contents, mode, save=False)
        self.services.configuration(policy, site)
        for feature, units in TIMERS.items():
            if feature not in policy['timers'] and feature not in retained:
                for unit in units:
                    self.require_inactive(unit)
        if 'agent-renewal' not in retained:
            for unit in AGENT_BRIDGE:
                self.require_inactive(unit)
        initial_file = PRIVATE + '/initial-release.json'
        intent = {'schema': 1, 'policy_sha256': policy_sha, 'source_sha': policy['source_sha'],
                  'platform_sha256': policy['platform_sha256'], 'site_config_sha256': policy['site_config_sha256'],
                  'machine_id': policy['machine_id']}
        with self.lock():
            self.require_first_site(policy['machine_id'], policy['site_config_sha256'])
            existing = [os.path.lexists(self.path(CONTROL + '/' + name + '.json')) for name in ('current', 'site-current')]
            initial = hex_id(parse(self.read(initial_file))) if os.path.lexists(self.path(initial_file)) else None
            if any(existing) and not all(existing):
                require(initial is not None, 'unowned partial live release selection preserved')
            self.file(PRIVATE + '/intent.json', encoded(intent), 0o600)
            self.directory(INSTALL + '/host-releases', 0o755)
            for target, (contents, mode, feature) in files.items():
                if feature != 'owner-entry':
                    self.file(target, contents, mode)
            self.run('/usr/sbin/restorecon', '-F', INSTALL + '/host-releases',
                     *(target for target, item in files.items() if item[2] != 'owner-entry'),
                     timeout=30)
            self.run('/usr/bin/systemd-tmpfiles', '--create', '/etc/tmpfiles.d/dev-pair-renewal.conf', timeout=30)
            self.run(SYSTEMCTL, 'daemon-reload', timeout=25)
            for unit in (BOOT_FENCE, RECOVERY, 'dev-pair-renewal-host-observe.service'):
                self.unit(unit, files)
            if 'owner-intake' in policy['timers']:
                self.verify_owner_units(site, files)
            if not any(existing):
                self.services.prepare_host_bundle(policy)
                self.services.stage(policy, boot)
            selected = self.selectors(policy, boot, site, initial)
            provision = self.services.provision(policy)
            require(provision['listener_mode'] == 'managed' and provision['uid'] == policy['checklist']['uid'],
                    'destination provision returned different checklist identity')
            fence = self.unit(BOOT_FENCE, files)
            require(fence['ActiveState'] == 'active', 'managed checklist commissioning lacks the external boot fence service')
            if fence['UnitFileState'] != 'enabled':
                self.run(SYSTEMCTL, 'enable', BOOT_FENCE, timeout=20)
                require(self.unit(BOOT_FENCE, files)['UnitFileState'] == 'enabled', 'boot fence service enablement differs')
            if not provision['provisioned']:
                return {'phase': provision['listener_state'], 'selected_release': selected, 'timers': {}}
            listener = self.unit(provision['executor'], files, uid=provision['uid'])
            recovery = self.unit(RECOVERY, files)
            require(listener['ActiveState'] == 'active' and listener['UnitFileState'] == 'enabled' and
                    recovery['UnitFileState'] == 'enabled' and not os.path.lexists(self.path(FENCE + '/frozen')),
                    'managed checklist listener or recovery gate is still pending')
            self.services.post_provision(policy, selected)
            provider_pending = self.provider_transition()
            allowed = policy if provider_pending is None else {
                **policy, 'timers': [item for item in policy['timers'] if item != 'owner-intake']}
            if provider_pending is not None and 'owner-intake' in policy['timers']:
                retained = (*retained, 'owner-intake')
            armed = self.timers(allowed, files, retained=retained)
            if 'owner-intake' in allowed['timers']:
                self.publish_owner_entry(files)
            result = {'phase': 'ready', 'selected_release': selected, 'timers': armed,
                      'owner_terminal': '/usr/local/bin/dev-pair' if 'owner-intake' in allowed['timers'] else None}
            if provider_pending is not None:
                result['provider_start_pending'] = provider_pending
            return result


class Live:
    """Use the existing site admission, native image readback and listener controller."""
    def __init__(self, kit, bootstrap):
        import platform_release_install
        import renewal
        import renewal_site

        self.kit, self.bootstrap, self.run = kit, bootstrap, bootstrap.run
        self.installer, self.renewal_module, self.resolver = platform_release_install, renewal, renewal_site

    def inventory(self, revision):
        return self.bootstrap.console_inspect(revision)

    def identity(self):
        return self.bootstrap.destination_identity()

    def initial_inputs(self, directory):
        if not os.path.lexists(directory):
            return ()
        protected(directory, 0, directory=True)
        with os.scandir(directory) as members:
            paths = []
            for entry in members:
                require(len(paths) < 32, 'bounded initial commissioning authority inventory exceeded')
                paths.append(Path(entry.path))
        return sorted(paths)

    def initial_platform(self, revision, *, acquire=False):
        from release_setup import FIRST_TRUST, installed
        from release_trust import POLICY, ReleaseTrust

        intake = self.installer.intake
        candidates = []
        transfer_pending = False
        for path in self.initial_inputs(intake.ROOT):
            identity = path.name
            if identity == '.intake.lock':
                continue
            if identity == intake.TRANSFER_LEASE or identity.startswith(intake.TRANSFER_PREFIX):
                transfer_pending = True
                continue
            _, index, _ = intake.retained_index(hex_id(identity))
            if (index['kind'] == 'dev-pair-platform-release' and index['source_sha'] == revision
                    and index['previous_platform_sha256'] is None and not os.path.lexists(path / intake.RETIREMENT)):
                candidates.append(identity)
        require(len(candidates) <= 1, 'more than one protected full release is eligible for this exact source')
        if not candidates or transfer_pending:
            first_grant = (installed(revision, self.identity()['machine_id'], finish=acquire, policy=POLICY)
                           if os.path.lexists(FIRST_TRUST) else None)
            if not os.path.lexists(POLICY):
                raise Pending('release-trust', 'Independent protected release trust has not been provisioned.')
            for role in ('host', 'devbox', 'maintenance', 'development'):
                ReleaseTrust(self.run).policy(role)
            self.require_release_custody(grant=first_grant)
            if not hasattr(intake, 'acquire_initial'):
                raise Pending('initial-full-release-selection', 'The trusted initial publisher selector is unavailable in this kit.',
                              source_gap=True)
            if not acquire:
                prerequisite = 'initial-platform-transfer' if transfer_pending else 'initial-full-release-selection'
                raise Pending(prerequisite, 'The initial full release has yet to finish protected intake.')
            return self.acquire_initial_platform(intake, revision)
        return candidates[0]

    def acquire_initial_platform(self, intake, revision):
        from native_placements import managed_snapshot

        managed_snapshot()
        if not os.path.lexists(intake.ROOT):
            self.bootstrap.directory(str(intake.ROOT), mode=0o700)
        with intake.intake_lock():
            try:
                receipt = intake.acquire_initial(revision, time.monotonic() + intake.CONTROL_SECONDS)
            except intake.InitialReleaseUnavailable as waiting:
                raise Pending(waiting.phase, str(waiting)) from None
            identity = hex_id(receipt['platform_sha256'])
            _, index, _ = intake.retained_index(identity)
            require(index['kind'] == 'dev-pair-platform-release' and index['source_sha'] == revision and
                    index['previous_platform_sha256'] is None,
                    'initial publisher result does not bind the reviewed full release')
        return identity

    def require_release_custody(self, *, config=None, grant=None):
        from bootstrap import Blocked as BootstrapBlocked

        intake = self.installer.intake
        if config is None:
            config = Path(intake.native_env().get('GH_CONFIG_DIR', str(GITHUB_CONFIG)))
        credential = config / 'hosts.yml'
        gh = Path(intake.GITHUB)
        message = 'The protected read-only GitHub intake identity or tool is unavailable.'
        if not gh.is_file() or not os.path.lexists(credential):
            raise Pending('release-read-custody', message)
        gh = intake.protected(gh)
        if not os.access(gh, os.X_OK):
            raise Pending('release-read-custody', message)
        path = intake.protected(credential)
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            node = os.fstat(descriptor)
            if (not stat.S_ISREG(node.st_mode) or (node.st_uid, node.st_gid) != (0, 0)
                    or node.st_nlink != 1 or stat.S_IMODE(node.st_mode) != 0o600
                    or not 0 < node.st_size <= 128 * 1024):
                raise Pending('release-read-custody', 'The GitHub intake credential file is empty or outside root-private custody.')
        finally:
            os.close(descriptor)
        if grant is not None:
            from release_setup import registered_read

            try:
                require(config == GITHUB_CONFIG, 'new release read custody must use its fixed root scope')
                registered_read(grant, path)
            except (Blocked, BootstrapBlocked, OSError, ValueError, KeyError, TypeError, AttributeError):
                raise Pending('release-read-custody', 'The installed GitHub credential differs from the approved first-host handoff.') from None

    def initial_site(self, hostname):
        candidates = []
        for path in self.initial_inputs(self.installer.SITE_CONFIGS):
            if not path.name.endswith('.json'):
                raise Blocked('unexpected protected site authority input')
            reference = hex_id(path.name[:-5])
            site = self.installer.site_configuration(path, reference)
            if site['hostname'] == hostname:
                candidates.append((reference, site))
        if not candidates:
            raise Pending('initial-site-config',
                          'No approved site profile supplies the job slots, storage and exclusive SELinux categories for this host.',
                          source_gap=True)
        require(len(candidates) == 1, 'more than one protected site profile matches the selected host')
        return candidates[0]

    def first_site_authority(self, observed, revision):
        from gptbox import Gptbox, ROOT as MAINTENANCE_ROOT, STATE as BOOTSTRAP

        if not os.path.lexists(DAY0_PROGRESS):
            raise Pending('day0-host-confirmation', 'The protected Day 0 host confirmation and offline maintenance probe are pending.')
        progress = parse(capture(Path(DAY0_PROGRESS), 0, mode=0o600, maximum=8192))
        exact_fields(progress, ('schema', 'source_sha', 'machine_id', 'phase', 'next'), 'unknown protected Day 0 state')
        require(type(progress['schema']) is int and progress['schema'] == 1 and
                progress['machine_id'] == observed['machine_id'], 'Day 0 confirmation belongs to a different machine')
        status = self.bootstrap.status()
        if (progress['phase'] not in ('host-bootstrap-complete', 'commissioning-pending', 'commissioned')
                or status['prepared'] is not True or status['phase'] != 'tailnet-only'):
            raise Pending('day0-host-confirmation', 'Complete the observed Day 0 maintenance and access checks before deriving the initial site.')
        self.bootstrap.verify_final_guard()
        self.bootstrap.verify_final_ssh()
        app = Gptbox()
        _, desired = app.read_config_record(BOOTSTRAP + '/desired.json')
        context = hex_id(desired['gptbox_context_sha256'])
        app.target = MAINTENANCE_ROOT + '/' + context
        with app.lock():
            ready = app.maintenance_host_readiness(context)
            origin = hex_id(ready['source_sha'], 40)
            require(ready['context_sha256'] == context and progress['source_sha'] in (origin, revision),
                    'Day 0 confirmation does not match the original bootstrap or reviewed controller')
            _, result = app.read_config_record(app.target + '/result.json')
            app.admitted_maintenance_image(context, origin, hex_id(result['assembled_image_id']))
        return origin

    def derive_first_site(self, observed):
        from gptbox import DevelopmentGptbox
        from native_placements import ROOT as PLACEMENT, allocate_categories, role_account, used_categories

        # A fresh capacity slot grants no repository, workload or credential.
        # Preserve existing development allocations for the selected site owner.
        existing = PLACEMENT / 'release/records/placement.json'
        if os.path.lexists(existing) or self.initial_inputs(PLACEMENT / 'records'):
            raise Pending('existing-placement-ownership', 'Retained DevBox allocations already belong to an earlier deployment.')
        role_account(DevelopmentGptbox())
        host = self.default_host_profile(observed['host'])
        categories = allocate_categories(used_categories())
        site = {'schema': 1, 'hostname': observed['host'], 'host_config_sha256': digest(encoded(host)),
                'jobs': {DEFAULT_SITE_SLOT: {'storage_bytes': DEFAULT_SITE_BYTES, 'categories': categories}}}
        self.check_initial_capacity(observed, site)
        return host, site

    def first_site_profiles(self, record):
        host, site = record['host'], record['site']
        host_bytes, site_bytes = encoded(host), encoded(site)
        site_sha, host_sha = digest(site_bytes), digest(host_bytes)
        self.resolver.closed_site(site_bytes)
        require(host == self.default_host_profile(site['hostname']) and site['host_config_sha256'] == host_sha and
                set(site['jobs']) == {DEFAULT_SITE_SLOT} and site['jobs'][DEFAULT_SITE_SLOT]['storage_bytes'] == DEFAULT_SITE_BYTES,
                'protected first-site host profile differs from the reviewed default')
        return (self.installer.HOST_CONFIGS / (host_sha + '.json'), host_bytes,
                self.installer.SITE_CONFIGS / (site_sha + '.json'), site_bytes)

    def first_site_profiles_missing(self, record):
        host_path, _, site_path, _ = self.first_site_profiles(record)
        return not os.path.lexists(host_path) or not os.path.lexists(site_path)

    def verify_first_site_host(self, record, *, restore):
        host_path, host_bytes, _, _ = self.first_site_profiles(record)
        if not os.path.lexists(host_path):
            if restore:
                return
            raise Pending('initial-host-config', 'The recorded first host profile is missing.')
        require(capture(host_path, 0, mode=0o600, maximum=65536) == host_bytes,
                'host profile differs from the protected first-site intent')

    def publish_first_site(self, app, record):
        host_path, host_bytes, site_path, site_bytes = self.first_site_profiles(record)
        app.file(str(host_path), host_bytes, 0o600)
        app.file(str(site_path), site_bytes, 0o600)
        return site_path.stem

    @staticmethod
    def default_host_profile(hostname):
        return {'schema': 1, 'hostname': hostname, 'platform': 'fedora-44', 'selinux': 'enforcing',
                'launch_contract': 1, 'role_launch_seconds': 145}

    def openssl(self, *args):
        tool = Path(OPENSSL)
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise Pending('checklist-local-crypto', 'The signed Fedora OpenSSL tool for the local checklist pair is unavailable.')
        protected(tool, 0)
        return self.run(str(tool), *map(str, args), timeout=15)

    def verify_checklist_pair(self, server, client):
        from bootstrap import Blocked as BootstrapBlocked
        from host_handoff import tls_principal

        hashes = {}
        if any(not os.path.lexists(path / name) for path in (server, client) for name in TLS_FILES):
            raise Pending('checklist-peer-custody', 'Both complete protected checklist TLS profiles are required.')
        for role, path in (('server', server), ('client', client)):
            protected(path, 0, directory=True, mode=0o700)
            hashes[role] = {name: digest(capture(path / name, 0, mode=0o600, maximum=8192)) for name in TLS_FILES}
        require(hashes['server']['key.pem'] != hashes['client']['key.pem'],
                'checklist server and conductor need distinct private keys')
        for role, path in (('server', server), ('client', client)):
            _, _, principals = tls_principal(path, maintenance=role == 'server')
            if role == 'server':
                pair = principals
            else:
                require(principals == pair, 'checklist TLS peers do not pin each other')
            try:
                self.openssl('verify', '-no-CAfile', '-no-CApath', '-no-CAstore',
                             '-trusted', path / 'peer.pem', '-purpose',
                             'sslclient' if role == 'server' else 'sslserver', path / 'peer.pem')
            except BootstrapBlocked:
                raise Pending('checklist-peer-custody', 'The dedicated checklist TLS peer is expired or cannot be verified.') from None
        return hashes

    def prepare_checklist_pair(self, app, observed, revision, *, issue=True):
        from bootstrap import Blocked as BootstrapBlocked
        from destination_release import PROVISION

        targets = {'server': Path(CHECKLIST_SERVER), 'client': Path(CHECKLIST_CLIENT)}
        working = Path(LOCAL_CHECKLIST_TLS)
        recorded = working / 'pair.json'
        intent = Path(PRIVATE + '/checklist-tls-intent.json')
        scope = {'schema': 1, 'machine_id': observed['machine_id'], 'source_sha': revision}
        staged = {role: working / role for role in targets}
        if not os.path.lexists(intent):
            if all(os.path.lexists(path) for path in targets.values()):
                self.verify_checklist_pair(*targets.values())
                return
            if not issue or any(os.path.lexists(path) for path in targets.values()) or os.path.lexists(PROVISION):
                raise Pending('checklist-peer-custody', 'An independently supplied checklist TLS profile is incomplete.')
            require(not os.path.lexists(working), 'unowned checklist TLS staging area is preserved')
            scope['bootstrap_source_sha'] = self.first_site_authority(observed, revision)
            app.file(str(intent), encoded(scope), 0o600)
        else:
            prior = parse(capture(intent, 0, mode=0o600, maximum=4096))
            scope['bootstrap_source_sha'] = hex_id(prior['bootstrap_source_sha'], 40)
            require(prior == scope, 'local checklist TLS issuance belongs to a different installation')
        if not issue:
            hashes = self.verify_checklist_pair(*targets.values())
            require(parse(capture(recorded, 0, mode=0o600, maximum=4096)) == {**scope, 'profiles': hashes},
                    'checklist TLS inputs differ from the recorded local issuance')
            return
        app.directory(str(working), 0o700)
        if not os.path.lexists(recorded):
            require(not any(os.path.lexists(path) for path in targets.values()),
                    'existing checklist TLS custody cannot be replaced by a local issuance')
            for role, path in staged.items():
                app.directory(str(path), 0o700)
                for leaf in self.initial_inputs(path):
                    require(leaf.name in TLS_FILES, 'unrecognized file in the owned local TLS staging area')
                    node = protected(leaf, 0, mode=0o600).lstat()
                    require(node.st_uid == node.st_gid == 0, 'local checklist TLS staging lost private ownership')
                    leaf.unlink()
                try:
                    self.openssl('req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                                 '-noenc', '-days', 365, '-subj', '/CN=dev-pair-checklist-' + role,
                                 '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
                                 '-addext', 'extendedKeyUsage=' + ('serverAuth' if role == 'server' else 'clientAuth'),
                                 '-keyout', path / 'key.pem', '-out', path / 'cert.pem')
                except BootstrapBlocked:
                    raise Pending('checklist-local-crypto', 'The local checklist certificate issuance could not finish.') from None
                for name in ('key.pem', 'cert.pem'):
                    with protected(path / name, 0, mode=0o600).open('rb') as stream:
                        os.fsync(stream.fileno())
            for role, other in (('server', 'client'), ('client', 'server')):
                certificate = capture(staged[other] / 'cert.pem', 0, mode=0o600, maximum=8192)
                app.file(str(staged[role] / 'peer.pem'), certificate, 0o600)
            hashes = self.verify_checklist_pair(*staged.values())
            app.file(str(recorded), encoded({**scope, 'profiles': hashes}), 0o600)
        binding = parse(capture(recorded, 0, mode=0o600, maximum=4096))
        current = {}
        for role, target in targets.items():
            source = staged[role]
            require(os.path.lexists(target) != os.path.lexists(source), 'checklist TLS issuance has ambiguous or missing custody')
            current[role] = target if os.path.lexists(target) else source
        hashes = self.verify_checklist_pair(*current.values())
        require(binding == {**scope, 'profiles': hashes}, 'checklist TLS inputs differ from the recorded local issuance')
        for role, target in targets.items():
            if current[role] != target:
                require(not os.path.lexists(target), 'checklist TLS destination appeared during custody transfer')
                os.rename(current[role], target)
                app.sync(target.parent)
                app.sync(working)

    def initial_host_profile(self, site, observed):
        reference = hex_id(site['host_config_sha256'])
        path = self.installer.HOST_CONFIGS / (reference + '.json')
        if os.path.lexists(path):
            self.installer.protected_json(path, reference)
            return None
        body = encoded(self.default_host_profile(observed['host']))
        if digest(body) != reference:
            raise Pending('initial-host-config',
                          'The approved site references a host configuration that has not been delivered.',
                          source_gap=True)
        return str(path), body

    def initial_checklist(self, identity, site, revision, *, placed=False):
        from bootstrap import Blocked as BootstrapBlocked, checked_file
        from destination_release import Destination, PROVISION
        from host_handoff import tls_principal

        root = Path(CHECKLIST_SERVER)
        tls = {}
        for name in TLS_FILES:
            path = root / name
            if not os.path.lexists(path):
                raise Pending('checklist-peer-custody', 'The independently provisioned checklist server TLS profile is unavailable.')
            raw = capture(checked_file(path, secret=True), 0, maximum=8192)
            tls[name] = digest(raw)
        tls_principal(root, maintenance=True)
        destination = Destination()
        if os.path.lexists(PROVISION):
            prior = destination.record(PROVISION)
            require(prior['version'] == 1 and prior['machine_id'] == identity['machine_id']
                    and prior['platform_sha'] == revision and prior['tls'] == tls,
                    'checklist provisioning authority belongs to a different machine, source or peer')
            settings = {key: prior[key] for key in ('uid', 'subid_start', 'reserve_mib', 'reserve_inodes')}
            for role in ('validation', 'live'):
                for key in ('mib', 'inodes'):
                    settings[f'{role}_{key}'] = prior['mounts'][role][key]
            return {'tls_profile': CHECKLIST_SERVER, **settings}
        users, groups = pwd.getpwall(), grp.getgrall()
        uid, start = DEFAULT_CHECKLIST['uid'], DEFAULT_CHECKLIST['subid_start']
        if any(row.pw_uid == uid or row.pw_name == 'dp-checklist' for row in users) or any(
                row.gr_gid == uid or row.gr_name == 'dp-checklist' for row in groups):
            raise Pending('checklist-account-allocation', 'The proposed checklist identity conflicts with an existing account.')
        try:
            for path, live in (('/etc/subuid', [row.pw_uid for row in users]), ('/etc/subgid', [row.gr_gid for row in groups])):
                if destination.subid(path, None, uid, start, live):
                    raise Pending('checklist-account-allocation', 'A previous checklist identity allocation needs protected reconciliation.')
        except BootstrapBlocked:
            raise Pending('checklist-account-allocation', 'The proposed checklist subordinate IDs conflict with existing allocations.') from None
        self.check_initial_capacity(identity, site, placed=placed)
        return {'tls_profile': CHECKLIST_SERVER, **DEFAULT_CHECKLIST}

    def check_initial_capacity(self, identity, site, *, placed=False):
        from destination_release import Destination, MANAGED_INTENT, MANAGED_INODES, MANAGED_READY
        from native_placement_release import OUTER_BYTES
        from native_placements import HOST_INODE_HEADROOM, HOST_METADATA_BYTES, SCRATCH_BYTES

        if not os.path.lexists(MANAGED_INTENT) or not os.path.lexists(MANAGED_READY):
            raise Pending('managed-storage', 'The measured bounded Fedora allocation has not finished preparation.')
        destination = Destination()
        managed = destination.record(MANAGED_INTENT)
        require(managed == destination.record(MANAGED_READY) and managed['machine_id'] == identity['machine_id'],
                'managed storage readiness belongs to a different machine or allocation')
        destination.mount_observation(STATE, managed['filesystem'], max_inodes=MANAGED_INODES)
        capacity = os.statvfs(STATE)
        checklist = sum(DEFAULT_CHECKLIST[key] for key in ('validation_mib', 'live_mib', 'reserve_mib')) * 1024**2
        bytes_needed = checklist
        if not placed:
            jobs = sum(row['storage_bytes'] for row in site['jobs'].values())
            bytes_needed += jobs + OUTER_BYTES + SCRATCH_BYTES + HOST_METADATA_BYTES
        # Each child ext4 is stored in a backing file. Its internal inode
        # budget does not consume parent inodes. Charge its backing and receipt.
        inodes_needed = max(HOST_INODE_HEADROOM, DEFAULT_CHECKLIST['reserve_inodes']) + 2 * 2
        if capacity.f_bavail * capacity.f_frsize < bytes_needed or capacity.f_favail < inodes_needed:
            raise Pending('checklist-storage-capacity', 'The approved placement and checklist storage do not fit the observed allocation.')

    def authority(self, policy):
        from platform_release import readonly_json, validate_host

        identity, revision = policy['platform_sha256'], policy['source_sha']
        stage, index, _ = self.installer.intake.retained_index(identity)
        require(index['kind'] == 'dev-pair-platform-release' and index['source_sha'] == revision and
                index['previous_platform_sha256'] is None,
                'initial commissioning requires the trusted full platform for the reviewed source')
        row = index['components']['host']
        host_bytes, bundle = readonly_json(stage / 'host/host-manifest.json', 0)
        require(digest(host_bytes) == row['bundle_manifest_sha256'] ==
                validate_host(stage / 'host', revision, time.monotonic() + 30),
                'protected full platform host bundle differs')
        site_sha = policy['site_config_sha256']
        site = self.installer.site_configuration(self.installer.SITE_CONFIGS / (site_sha + '.json'), site_sha)
        require(self.installer.machine(site, time.monotonic() + 15) == self.bootstrap.destination_identity()['boot_id'],
                'physical site profile is unavailable for this boot')
        return site, bundle['files']

    def verify_initial_parts(self, identity):
        self.installer.intake.previous_release(identity, time.monotonic() + 180)

    def configuration(self, policy, site):
        from bootstrap import checked_file
        from gptbox import Gptbox

        if policy['timers']:
            self.bootstrap.verify_workload_access()
        _, index, _ = self.installer.intake.retained_index(policy['platform_sha256'])
        for name in TLS_FILES:
            path = checked_file(Path(policy['checklist']['tls_profile']) / name, secret=True)
            require(0 < path.stat().st_size <= 8192, 'protected checklist TLS file is outside its bound')
        app = Gptbox()
        app.maintenance_host_readiness(index['components']['maintenance-agent']['context_sha256'])
        if 'owner-intake' in policy['timers']:
            from owner_intake import Intake

            repositories, slots = Intake().catalogue_settings()
            require(set(slots) <= set(site['jobs']), 'owner slots fall outside the approved site layout')
            if any('checklist-persistence' in row.get('workloads', ['checklist-persistence'])
                   for row in repositories.values()):
                self.checklist_builder_policy()

    def checklist_builder_policy(self):
        from checklist_candidate import BASE, protected_file
        from host_handoff import tls_principal

        data = parse(protected_file(BASE, 8192))
        exact_fields(data, ('version', 'image', 'verification_sha256'), 'checklist builder policy differs')
        require(type(data['version']) is int and data['version'] == 1 and isinstance(data['image'], str)
                and re.fullmatch(r'[a-z0-9][a-z0-9./:_-]+@sha256:[0-9a-f]{64}', data['image']),
                'checklist builder base must be an independently verified immutable reference')
        hex_id(data['verification_sha256'])
        tls_principal(Path('/etc/dev-pair/checklist-client'), maintenance=False)
        return data

    def stage(self, policy, boot):
        raw = self.run(PYTHON, '-EBs', INSTALL + '/tools/platform_release_install.py',
                       '--platform-sha256', policy['platform_sha256'], '--site-config-sha256',
                       policy['site_config_sha256'], timeout=930)
        result = parse(raw)
        require(result['boot_id'] == boot and result['source_sha'] == policy['source_sha']
                and result['platform_sha256'] == policy['platform_sha256']
                and result['site_config_sha256'] == policy['site_config_sha256']
                and result['base_platform_sha256'] == policy['platform_sha256'],
                'native installation readback differs from the approved initial platform')

    def prepare_host_bundle(self, policy):
        stage, index, _ = self.installer.intake.retained_index(policy['platform_sha256'])
        host = index['components']['host']
        expected = {'manifest_sha256': host['bundle_manifest_sha256']}
        require(self.installer.install_host(stage, host, time.monotonic() + 60) == expected,
                'protected initial host bundle store readback differs')

    def renewal(self):
        return self.renewal_module.Renewal(Path(STATE), None)

    def resolve_initial(self, controller, policy, boot, site):
        path = controller.control / 'offers/initial.json'
        offer = {'schema': 2, 'scope': 'initial', 'operation': 'initial-commissioning',
                 'platform_sha256': policy['platform_sha256'], 'previous_release_sha256': None,
                 'site_config_sha256': policy['site_config_sha256'], 'affected_jobs': sorted(site['jobs']),
                 'reason': 'Protected initial site commissioning'}
        r = self.renewal_module
        if os.path.lexists(path):
            offer = self.resolver.offer_record(r.read_json(path), 'initial')
            require(offer['platform_sha256'] == policy['platform_sha256'] and
                    offer['site_config_sha256'] == policy['site_config_sha256'],
                    'existing initial offer selects a different protected platform or site')
        else:
            r.replace_json(path, offer)
        result = self.resolver.Resolver(controller).resolve(offer, boot=boot)
        return hex_id(result['release_sha256'])

    def verify_selection(self, controller, selected, policy):
        r = self.renewal_module
        release = controller.release(hex_id(selected))
        binding = r.read_json(controller.control / 'platform-bindings' / (selected + '.json'))
        exact_fields(binding, ('schema', 'release_sha256', 'platform_sha256', 'base_platform_sha256',
                              'site_config_sha256', 'plan_sha256', 'intake_sha256'),
                     'protected current selection has an unknown portable binding')
        base = policy['platform_sha256']
        require(type(binding['schema']) is int and binding['schema'] == 1 and
                binding['release_sha256'] == selected and binding['base_platform_sha256'] == base and
                binding['site_config_sha256'] == policy['site_config_sha256'] and
                binding['plan_sha256'] == release['plan_sha256'],
                'current release or rollback base differs from the site commitment')
        _, selected_index, intake = self.installer.intake.retained_index(hex_id(binding['platform_sha256']))
        require(intake == binding['intake_sha256'] and
                (selected_index['base_platform_sha256'] or binding['platform_sha256']) == base,
                'selected portable release differs from verified native intake')
        _, index, _ = self.installer.intake.retained_index(base)
        rows = {**index['components'], **selected_index['components']}
        for role in ('maintenance-agent', 'development-agent', 'devbox'):
            component = release['components'][role]
            portable = rows[role]
            require((component['source_revision'], component['config_sha256'], component['artifact_sha256']) ==
                    (portable['source_sha'], portable['context_sha256'], portable['oci_config_sha256']) and
                    (role == 'devbox' or component['codex_version'] == portable['codex_version']),
                    'selected role release differs from the exact portable artifact')
        require(release['components']['maintenance-agent']['platform_sha256'] == binding['platform_sha256'],
                'maintenance launch lacks the exact selected portable scope')
        host = release['components']['host']
        site_sha = policy['site_config_sha256']
        site = self.installer.site_configuration(self.installer.SITE_CONFIGS / (site_sha + '.json'), site_sha)
        require(host['artifact_sha256'] == index['components']['host']['bundle_manifest_sha256'] and
                host['source_revision'] == policy['source_sha'] and host['config_sha256'] == site['host_config_sha256'],
                'selected host bundle differs from the explicitly approved stable installation')
        self.installer.check_host_bundle(self.installer.HOST_RELEASES / host['artifact_sha256'], index['components']['host'],
                                         time.monotonic() + 20)
        return binding

    def initial_selection(self, controller, selected, policy, boot):
        binding = self.verify_selection(controller, selected, policy)
        record = self.renewal_module.read_json(controller.control / 'platform-observations' / (selected + '.json'))
        return binding['platform_sha256'] == policy['platform_sha256'] and record['boot_id'] == boot

    def workload_scope(self, app, policy, selected, boot, *, ssh=True):
        from bootstrap import Blocked as BootstrapBlocked
        from destination_release import Destination, MANAGED_LISTENER, require_commissioned_listener

        try:
            if ssh:
                self.bootstrap.verify_final_ssh()
            proof = self.bootstrap.verify_workload_access()
            listener = parse(app.read(MANAGED_LISTENER))
            require_commissioned_listener(listener)
            require(proof.get('role_artifacts', {}).get('release_sha256') == selected and proof.get('scope') is None and
                    self.identity() == {'machine_id': policy['machine_id'], 'boot_id': boot} and
                    not os.path.lexists(app.path(FENCE + '/frozen')),
                    'independent workload access or live checklist recovery differs')
            if ssh:
                live, dns = self.bootstrap.tailscale_state()
                target = proof['target']
                require(dns == target['dns_name'] and self.bootstrap.identity_fields(live) == (target['tailnet'], target['node_id']),
                        'current named tailnet route differs from the verified access scope')
                destination = Destination()
                destination.verify_settled_listener(listener, selected, boot, policy['checklist']['uid'])
        except (AttributeError, Blocked, BootstrapBlocked, OSError, RuntimeError, ValueError, TypeError, KeyError,
                subprocess.SubprocessError):
            raise Pending('workload-access', 'The exact current role access and managed checklist probe is pending.') from None
        return digest(encoded(proof))

    @staticmethod
    def credential_stamp(path):
        protected(path, 0, mode=0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            node = os.fstat(fd)
            require(stat.S_ISREG(node.st_mode) and (node.st_uid, node.st_gid, node.st_nlink, stat.S_IMODE(node.st_mode)) ==
                    (0, 0, 1, 0o600) and 0 < node.st_size <= 128 * 1024,
                    'workload credential is outside its approved custody')
            return [node.st_dev, node.st_ino, node.st_ctime_ns, node.st_size]
        finally:
            os.close(fd)

    def owner_slot_grant(self, intake, job):
        from owner_intake import CREDENTIALS, checked_file, verify_slot_billing

        profile, roles, proofs = intake.slot_documents(job)
        settings = parse(profile)
        expires = settings['expires_unix']
        require(type(expires) is int and expires > time.time(), 'owner provider approval expired')
        verify_slot_billing(settings, proofs)
        inputs = {'catalogue': digest(checked_file(intake.site / 'repositories.json')), 'slot': digest(profile)}
        for role, raw in roles.items():
            credential = parse(raw)['credential_ref']
            require(type(credential) is str and re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', credential) and
                    credential not in ('.', '..'), 'invalid protected provider credential reference')
            inputs[role] = [digest(raw), self.credential_stamp(CREDENTIALS / credential)]
        for kind, proof in proofs.items():
            inputs[kind] = digest(proof)
        return {'subject': job, 'expires_unix': expires, 'sha256': digest(encoded(inputs))}

    def owner_feature_authority(self, selected, recorded):
        from bootstrap import Blocked as BootstrapBlocked
        from owner_intake import CHECKLIST, Intake

        intake, end = Intake(), time.monotonic() + 45
        if not os.path.lexists(intake.site / 'repositories.json'):
            raise Pending('owner-catalogue-selection', 'The first owner catalogue needs an inspected and confirmed repository and provider scope.')
        failures = (Blocked, BootstrapBlocked, OSError, ValueError, RuntimeError, TypeError, KeyError, subprocess.SubprocessError)
        try:
            repositories, slots = intake.catalogue_settings()
            _, reference, manifests = intake.release_slots()
            require(reference == selected and set(slots) <= set(manifests), 'owner slots differ from the current release')
        except failures:
            raise Pending('owner-catalogue', 'Protected repository and slot authority is unavailable.') from None
        if recorded is None:
            for repository, row in sorted(repositories.items()):
                if time.monotonic() >= end:
                    break
                try:
                    intake.source(repository, row, checklist=CHECKLIST in row.get('workloads', [CHECKLIST]))
                    break
                except failures:
                    continue
            else:
                raise Pending('owner-repository-inputs', 'The exact approved repository and startup corpus are unavailable.')
            if time.monotonic() >= end:
                raise Pending('owner-repository-inputs', 'The bounded repository authority check did not finish.')
            grant = None
            for job in slots:
                if time.monotonic() >= end:
                    break
                try:
                    intake.slot(job, manifests[job])
                    grant = self.owner_slot_grant(intake, job)
                    break
                except failures:
                    continue
            if grant is None:
                raise Pending('provider-slot-authority', 'No approved provider slot has valid current custody and bounded pricing.')
        else:
            require(recorded['subject'] in slots, 'the approved provider slot was withdrawn')
            grant = self.owner_slot_grant(intake, recorded['subject'])
        if any(CHECKLIST in row.get('workloads', [CHECKLIST]) for row in repositories.values()):
            from checklist_build_storage import StoragePressure

            try:
                self.checklist_builder(prepare=recorded is None)
            except StoragePressure:
                raise Pending('checklist-build-base-capacity', 'The measured validation filesystem cannot hold the verified base and bounded build reserve.') from None
            except failures:
                raise Pending('checklist-build-base', 'The independently verified checklist base is not ready in the rootless builder store.') from None
        return grant

    def verified_workload_bundle(self, selected):
        controller = self.renewal()
        host = controller.release(selected)['components']['host']
        binding = self.renewal_module.read_json(controller.control / 'platform-bindings' / (selected + '.json'))
        require(binding['release_sha256'] == selected, 'workload helper requires the selected protected host release')
        _, index, _ = self.installer.intake.retained_index(hex_id(binding['base_platform_sha256']))
        row = index['components']['host']
        require((host['artifact_sha256'], host['source_revision']) == (row['bundle_manifest_sha256'], row['source_sha']),
                'workload helper differs from the signed stable host bundle')
        root = self.installer.HOST_RELEASES / hex_id(host['artifact_sha256'])
        self.installer.check_host_bundle(root, row, time.monotonic() + 15)
        return root

    def agent_bridge_authority(self, selected, *, confirm_read):
        from agent_release_bridge import confirm_publisher_read
        import platform_release_protocol
        from release_trust import POLICY, ReleaseTrust

        self.require_release_custody(config=GITHUB_CONFIG)
        collector = self.bootstrap.agent_observer_signers()
        if collector is None:
            raise Pending('agent-observer-key', 'Enroll the independent agent observation collector key to enable unattended renewal.')
        trust = ReleaseTrust(self.run)
        refresh = [trust.policy(role)['components'][role]['agent_refresh'] for role in ('maintenance', 'development')]
        require(refresh[0] == refresh[1] and refresh[0]['workflow'] == '.github/workflows/agent-refresh.yml',
                'independent nightly trust differs from the fixed publisher')
        verified = self.verified_workload_bundle(selected)
        bridge = 'tools/agent_release_bridge.py'
        require(capture(self.bootstrap.path(INSTALL) / bridge, 0, mode=0o644) == capture(verified / bridge, 0),
                'the installed agent bridge differs from the signed host bundle')
        intake = self.installer.intake
        intake.portable_volume()
        intake.intake_limit(intake.ROOT, [intake.META_LIMIT, 2 * intake.CONTROL_LIMIT], intake.ZIP_OVERHEAD)
        authority = [verified.name, digest(capture(Path(POLICY), 0, maximum=65536)),
                     self.credential_stamp(GITHUB_CONFIG / 'hosts.yml'), digest(collector)]
        if confirm_read:
            try:
                config = intake.native_env().get('GH_CONFIG_DIR', str(GITHUB_CONFIG))
                require(Path(config) == GITHUB_CONFIG, 'agent publisher read custody differs from the installed service')
                confirm_publisher_read(intake, platform_release_protocol, time.monotonic() + 10)
            except (AttributeError, Blocked, OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                raise Pending('agent-publication-read', 'The approved GitHub identity cannot verify current agent publication access.') from None
        return {'subject': 'approved-publisher', 'expires_unix': None, 'sha256': digest(encoded(authority))}

    def agent_publication_status(self, selected):
        controller = self.renewal()
        path = controller.control / 'offers/agent.json'
        if not os.path.lexists(path):
            return 'awaiting-signed-publication'
        try:
            offer = self.resolver.offer_record(parse(capture(path, 0, mode=0o600, maximum=65536)), 'agent')
            _, index, _ = self.resolver.Resolver(controller).index(offer['platform_sha256'])
            require(offer['previous_release_sha256'] == selected and index['kind'] == self.resolver.AGENT,
                    'offer does not authorize a current agent release')
        except (Blocked, OSError, ValueError, TypeError, KeyError):
            return 'offer-unavailable'
        return 'staged-approved-offer'

    def feature_authority(self, feature, selected, *, recorded=None):
        from bootstrap import Blocked as BootstrapBlocked

        if feature == 'checklist-promotion':
            from promotion_setup import EXTERNAL_ERRORS, enrollment, runtime_grant

            try:
                try:
                    saved = enrollment()
                except FileNotFoundError:
                    saved = None
                if saved is None or saved['state'] == 'staging':
                    raise Pending('promotion-enrollment', 'Attended checklist promotion enrollment is available.')
                if saved['state'] in ('withdrawing', 'withdrawn'):
                    raise Pending('promotion-withdrawn', 'Checklist promotion custody is withdrawn.')
                return runtime_grant(selected)
            except (*EXTERNAL_ERRORS, Blocked):
                raise Pending('promotion-custody', 'The protected checklist promotion enrollment is held.') from None
        try:
            if feature == 'owner-intake':
                return self.owner_feature_authority(selected, recorded)
            if feature == 'checklist-spool':
                from checklist_candidate import checked_storage
                from host_handoff import host_runtime

                runtime = host_runtime()
                helper = self.verified_workload_bundle(selected) / 'tools/checklist_candidate.py'
                with runtime.dispatch_gate():
                    device = checked_storage(runtime, time.monotonic() + 10, witness=helper)
                    node = runtime.STORAGE.lstat()
                return {'subject': 'managed-validation', 'expires_unix': None,
                        'sha256': digest(encoded([selected, device, node.st_ino]))}
            # A normal apply measures remote scope once. Subsequent checks in
            # the same attempt bind the immutable local authority. The poll
            # itself authenticates its own reads before any publication effect.
            return self.agent_bridge_authority(selected, confirm_read=recorded is None)
        except (Blocked, BootstrapBlocked, OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            prerequisite = {'owner-intake': 'provider-slot-authority', 'checklist-spool': 'checklist-validation-storage',
                            'agent-renewal': 'agent-release-authority'}[feature]
            raise Pending(prerequisite, 'The protected runtime authority for this workload feature is unavailable.') from None

    def provision(self, policy):
        args = policy['checklist']
        argv = [PYTHON, '-EBs', str(self.kit / 'tools/destination_release.py'), 'provision', '--apply',
                '--platform-sha', policy['source_sha'], '--tls-profile', args['tls_profile']]
        for key in NUMBERS:
            argv.extend(('--' + key.replace('_', '-'), str(args[key])))
        return parse(self.run(*argv, timeout=300))

    def role_directory(self, path, user):
        actor = pwd.getpwnam(user)
        self.bootstrap._directory_as(path, 0o700, actor.pw_uid, actor.pw_gid, change_owner=True, check_gid=True)

    def post_provision(self, policy, selected):
        if 'owner-intake' not in policy['timers'] and 'checklist-spool' not in policy['timers']:
            return
        if 'owner-intake' in policy['timers']:
            self.run('/usr/bin/systemd-tmpfiles', '--create',
                     '/etc/tmpfiles.d/dev-pair-product.conf', '/etc/tmpfiles.d/dev-pair-intake.conf', timeout=30)
            self.bootstrap.atomic(STATE + '/product-jobs/owner.lock', '', mode=0o600)
            for leaf in ('jobs', 'profiles'):
                self.bootstrap.directory(STATE + '/product-jobs/' + leaf)
            for role, account in (('maintenance', 'dp-maint'), ('development', 'dp-dev')):
                self.role_directory(STATE + '/' + role + '/conductor-inputs', account)
        self.role_directory(STATE + '/checklist-executor/conductor-inputs', 'dp-checklist')
        if 'owner-intake' in policy['timers']:
            from owner_intake import Intake
            intake = Intake()
            repositories, slots = intake.catalogue_settings()
            _, observed, plans = intake.release_slots()
            require(observed == selected and set(slots) <= set(plans), 'owner slot plan changed during commissioning')
            for job in slots:
                if intake.slot_unused(job):
                    intake.slot(job, plans[job])
            if any('checklist-persistence' in row.get('workloads', ['checklist-persistence'])
                   for row in repositories.values()):
                self.checklist_builder()

    def checklist_builder(self, *, prepare=True):
        from checklist_candidate import checked_storage, preloaded_base
        from host_handoff import host_runtime, tls_principal
        from release_setup import FIRST_TRUST, GitHubRead

        runtime = host_runtime()
        end = time.monotonic() + (180 if prepare else 15)
        tls_principal(Path(CHECKLIST_CLIENT), maintenance=False)
        if prepare:
            with runtime.dispatch_gate():
                checked_storage(runtime, min(end, time.monotonic() + 10))
                base = runtime.STORAGE / 'builder'
                leaves = (base, base / 'graph', base / 'tmp')
                account = pwd.getpwnam(runtime.ACCOUNT)
                for path in leaves:
                    if not os.path.lexists(path):
                        self.role_directory(str(path), runtime.ACCOUNT)
                    node = path.lstat()
                    require(stat.S_ISDIR(node.st_mode) and (node.st_uid, node.st_gid) == (account.pw_uid, account.pw_gid),
                            'checklist builder preparation encountered foreign storage')
                self.run('/usr/sbin/restorecon', '-F', *map(str, leaves), timeout=15)
        trust = GitHubRead(GITHUB_CONFIG, end, self.run).trust
        return preloaded_base(runtime, trust, end, prepare=prepare, require_proof=os.path.lexists(FIRST_TRUST))


def require_installed_workload(feature, *, owner_entry=False):
    path = Path(__file__).absolute()
    require(os.getuid() == os.geteuid() == 0 and path == Path(INSTALL + '/tools/commission_host.py'),
            'use the exact installed automatic workload guard')
    protected(path, 0)
    protected(path.parent, 0, directory=True)
    sys.path.insert(0, str(path.parent))
    from bootstrap import Bootstrap

    bootstrap = Bootstrap()
    live = Live(Path(INSTALL), bootstrap)
    try:
        Commission(Path(INSTALL), Path('/'), bootstrap.run, 0, live).require_runtime_feature(feature, owner_entry=owner_entry)
    except Pending:
        raise Blocked('current protected workload authorization is pending') from None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['guard']:
        try:
            require(len(argv) == 2, 'provide one exact workload guard')
            require_installed_workload(argv[1])
            return 0
        except (Blocked, OSError, RuntimeError, ValueError, TypeError, KeyError, ImportError, subprocess.SubprocessError):
            # ExecCondition returns 1 for an intentionally withheld service.
            print('The protected dev-pair workload feature is held.', file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inspect', 'apply', 'discover', 'prepare', 'status'))
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--policy')
    parser.add_argument('--policy-sha256')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        require(os.getuid() == os.geteuid() == 0, 'use the authorized root terminal on the inspected host')
        revision = hex_id(args.source_sha, 40)
        require(bool(args.policy) == bool(args.policy_sha256) and
                (not args.policy or args.operation in ('inspect', 'apply')) and
                (args.operation != 'inspect' or args.policy),
                'explicit policy and digest belong together on the protected inspect/apply path')
        protected(Path(__file__).absolute(), 0)
        protected(KIT / 'tools', 0, directory=True)
        verify_checkout(KIT, revision, 0)
        sys.path.insert(0, str(KIT / 'tools'))
        from bootstrap import Bootstrap

        bootstrap = Bootstrap()
        live = Live(KIT, bootstrap)
        app = Commission(KIT, Path('/'), bootstrap.run, 0, live)
        if not args.policy:
            report = app.automatic(args.operation, revision)
        else:
            raw = capture(Path(immutable_path(args.policy)), 0, mode=0o600, maximum=65536)
            require(digest(raw) == hex_id(args.policy_sha256), 'approved commissioning policy digest changed')
            policy = read_policy(raw, revision)
            observed = app.inspect(policy)
            if args.operation == 'inspect':
                report = {**observed, 'phase': 'inspection', 'policy_sha256': args.policy_sha256}
            else:
                require('checklist-promotion' not in policy['timers'],
                        'checklist promotion uses only the attended automatic commissioning path')
                site, bundle = live.authority(policy)
                files = app.package(policy, bundle)
                report = app.apply(policy, args.policy_sha256, observed['boot_id'], site, files)
        print(json.dumps(report, sort_keys=True))
        return 0
    except Pending as wait:
        print(json.dumps(wait.report, sort_keys=True))
        return 0
    except (Blocked, OSError, RuntimeError, ValueError, TypeError, KeyError, ImportError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, Blocked) else 'required protected host or release observation failed'
        print('Host commissioning blocked. ' + detail, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
