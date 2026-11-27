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
    'owner-intake': ('dev-pair-intake-recovery.timer', 'dev-pair-intake-recovery.service'),
}
TLS_FILES = ('cert.pem', 'peer.pem', 'key.pem')
CHECKLIST_SERVER = '/etc/dev-pair/checklist-server'
CORE_HELD_FEATURES = tuple(sorted(TIMERS))
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
        return protected(path, self.owner, directory=True, mode=mode)

    def file(self, target, raw, mode, *, save=True):
        path = self.path(target)
        if os.path.lexists(path):
            require(self.read(target, mode, FILE_LIMIT) == raw, 'existing commissioning file conflicts: ' + target)
            return
        if not save:
            # The nearest existing ancestor must be protected before any install.
            parent = next(parent for parent in path.parents if os.path.lexists(parent))
            protected(parent, self.owner, directory=True)
            return
        if not path.parent.exists():
            self.directory('/' + str(path.parent.relative_to(self.root)))
        protected(path.parent, self.owner, directory=True)
        file_descriptor, name = tempfile.mkstemp(dir=path.parent, prefix='.dev-pair-commission-')
        try:
            with os.fdopen(file_descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if target == '/etc/sudoers.d/60-dev-pair-owner':
                self.run('/usr/sbin/visudo', '-cf', name, timeout=12)
            os.link(name, path)
        finally:
            os.unlink(name)
        self.sync(path.parent)
        require(self.read(target, mode, FILE_LIMIT) == raw, 'installed commissioning bytes changed')

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

    def package(self, policy, bundle):
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
            require(target not in all_targets and row['feature'] in ('base', 'owner-entry', *TIMERS) and
                    row['mode'] in ('0644', '0755', '0440'), 'ambiguous commissioning install entry')
            all_targets.add(target)
            contents = self.source_bytes(source, revision)
            # The fixed example recipe stays in the independently vetted
            # checkout. F's portable host manifest includes tools and runtime.
            if source != 'examples/checklist/Containerfile':
                require(bundle.get(source) == digest(contents), 'reviewed host bundle bytes differ from commissioning kit')
            if row['feature'] in features:
                files[target] = (contents, int(row['mode'], 8), row['feature'])
            else:
                require(not os.path.lexists(self.path(target)), 'disabled feature has installed commissioning files')
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
        if prepared:
            raw = self.read(AUTOMATIC_POLICY)
            policy = read_policy(raw, revision)
            require(raw == encoded(policy), 'recorded automatic commissioning policy bytes differ')
            require(policy['machine_id'] == observed['machine_id'], 'automatic commissioning policy belongs to another machine')
            host_profile = None
        else:
            platform = self.services.initial_platform(revision)
            site_sha, site = self.services.initial_site(observed['host'])
            host_profile = self.services.initial_host_profile(site, observed)
            policy = read_policy(encoded({'schema': 1, 'source_sha': revision, 'machine_id': observed['machine_id'],
                                         'platform_sha256': platform, 'site_config_sha256': site_sha, 'timers': [],
                                         'checklist': self.services.initial_checklist(identity, site, revision)}), revision)
            raw = encoded(policy)
        report = {'phase': 'prepared' if prepared else 'discovered', 'platform_sha256': policy['platform_sha256'],
                  'site_config_sha256': policy['site_config_sha256'], 'held_features': list(CORE_HELD_FEATURES)}
        if action in ('status', 'discover'):
            if prepared:
                self.services.authority(policy)
            listener = '/var/lib/dev-pair/checklist-release/managed-listener.json'
            if action == 'status' and prepared and os.path.lexists(self.path(listener)):
                recorded = parse(self.read(listener))
                report['recorded_listener_phase'] = recorded['phase']
                report['listener_observation_on_current_boot'] = recorded['boot'] == observed['boot_id']
            return report
        policy_sha = digest(raw)
        with self.lock():
            if os.path.lexists(self.path(PRIVATE + '/intent.json')):
                prior = parse(self.read(PRIVATE + '/intent.json'))
                require(prior.get('policy_sha256') == policy_sha,
                        'existing commissioning uses a different protected site authority')
            if host_profile is not None:
                target, contents = host_profile
                self.file(target, contents, 0o600)
            site, bundle = self.services.authority(policy)
            files = self.package(policy, bundle)
            if action == 'prepare':
                self.services.configuration(policy, site)
            self.file(AUTOMATIC_POLICY, raw, 0o600)
        if action == 'prepare':
            return {**report, 'phase': 'prepared'}
        return {**self.apply(policy, policy_sha, observed['boot_id'], site, files),
                'held_features': list(CORE_HELD_FEATURES)}

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
        import systemd_service_profile as profile

        template = re.sub(r'@[^.]+\.service$', '@.service', unit)
        fragment = UNIT_ROOT + '/' + template
        drops = sorted(name for name in files if name.startswith(fragment + '.d/'))
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
                profile.observe(row, drops, self.path, self.run, owner=self.owner)
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

    def timers(self, policy, files):
        results = {}
        for name, (timer, service) in TIMERS.items():
            if name not in policy['timers']:
                for unit in (timer, service):
                    self.require_inactive(unit)
                continue
            # Check both root service argv and the timer's binding before any enable.
            self.unit(service, files)
            pending = self.unit(timer, files, timer=True)
            require(pending['Unit'] == service, 'timer is not linked to its approved service')
            if pending['UnitFileState'] != 'enabled' or pending['ActiveState'] != 'active':
                self.run(SYSTEMCTL, 'enable', '--now', timer, timeout=25)
            active = self.unit(timer, files, timer=True)
            scheduled = [active[key] for key in ('NextElapseUSecRealtime', 'NextElapseUSecMonotonic')
                         if active[key] not in ('', '0', 'n/a', 'infinity')]
            require(active['Unit'] == service and active['UnitFileState'] == 'enabled' and
                    active['ActiveState'] == 'active' and scheduled,
                    'systemd timer lacks its exact active and scheduled readback: ' + timer)
            results[timer] = {'service': service, 'next': scheduled}
        return results

    def require_inactive(self, unit):
        output = self.run(SYSTEMCTL, 'show', '--all', '--property=ActiveState,UnitFileState', unit, ok=(0, 1, 4), timeout=12)
        row = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        require(set(row) == {'ActiveState', 'UnitFileState'} and row['ActiveState'] == 'inactive' and
                row['UnitFileState'] in ('', 'static', 'disabled', 'masked'),
                'disabled feature has an active or enabled root unit: ' + unit)

    def apply(self, policy, policy_sha, boot, site, files):
        # Check targets, credentials and protected site policy before installing anything.
        for target, (contents, mode, _) in files.items():
            self.file(target, contents, mode, save=False)
        self.services.configuration(policy, site)
        for feature, units in TIMERS.items():
            if feature not in policy['timers']:
                for unit in units:
                    self.require_inactive(unit)
        initial_file = PRIVATE + '/initial-release.json'
        intent = {'schema': 1, 'policy_sha256': policy_sha, 'source_sha': policy['source_sha'],
                  'platform_sha256': policy['platform_sha256'], 'site_config_sha256': policy['site_config_sha256'],
                  'machine_id': policy['machine_id']}
        with self.lock():
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
                sample = sorted(site['jobs'])[0]
                for unit in ('dev-pair-provider@' + '0' * 64 + '.service',
                             f'dev-pair-intake@{sample}.service', f'dev-pair-product@{sample}.service'):
                    self.unit(unit, files)
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
            armed = self.timers(policy, files)
            for target, (contents, mode, feature) in files.items():
                if feature == 'owner-entry':
                    self.file(target, contents, mode)
                    self.run('/usr/sbin/restorecon', '-F', target, timeout=10)
            if 'owner-intake' in policy['timers']:
                self.run('/usr/sbin/visudo', '-c', timeout=15)
            return {'phase': 'ready', 'selected_release': selected, 'timers': armed,
                    'owner_terminal': '/usr/local/bin/dev-pair' if 'owner-intake' in policy['timers'] else None}


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

    def initial_platform(self, revision):
        from release_trust import POLICY, ReleaseTrust

        intake = self.installer.intake
        candidates = []
        for path in self.initial_inputs(intake.ROOT):
            identity = path.name
            if identity == '.intake.lock':
                continue
            if identity == intake.TRANSFER_LEASE or identity.startswith(intake.TRANSFER_PREFIX):
                raise Pending('initial-platform-transfer', 'The protected platform intake still owns an interrupted transfer.')
            _, index, _ = intake.retained_index(hex_id(identity))
            if (index['kind'] == 'dev-pair-platform-release' and index['source_sha'] == revision
                    and index['previous_platform_sha256'] is None and not os.path.lexists(path / intake.RETIREMENT)):
                candidates.append(identity)
        if not candidates:
            if not os.path.lexists(POLICY):
                raise Pending('release-trust', 'Independent protected release trust has not been provisioned.')
            for role in ('host', 'devbox', 'maintenance', 'development'):
                ReleaseTrust(self.run).policy(role)
            gh = Path(intake.GITHUB)
            config = Path(intake.native_env().get('GH_CONFIG_DIR', '/root/.config/gh'))
            if not gh.is_file() or not os.path.lexists(config / 'hosts.yml'):
                raise Pending('release-read-custody', 'The protected read-only GitHub intake identity or tool is unavailable.')
            intake.protected(config / 'hosts.yml')
            raise Pending('initial-full-release-selection',
                          'No eligible full release has reached protected intake. The initial publisher selection has no automated producer.',
                          source_gap=True)
        require(len(candidates) == 1, 'more than one protected full release is eligible for this exact source')
        return candidates[0]

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

    def initial_host_profile(self, site, observed):
        reference = hex_id(site['host_config_sha256'])
        path = self.installer.HOST_CONFIGS / (reference + '.json')
        if os.path.lexists(path):
            self.installer.protected_json(path, reference)
            return None
        body = encoded({'schema': 1, 'hostname': observed['host'], 'platform': 'fedora-44', 'selinux': 'enforcing',
                        'launch_contract': 1, 'role_launch_seconds': 145})
        if digest(body) != reference:
            raise Pending('initial-host-config',
                          'The approved site references a host configuration that has not been delivered.',
                          source_gap=True)
        return str(path), body

    def initial_checklist(self, identity, site, revision):
        from bootstrap import Blocked as BootstrapBlocked, checked_file
        from destination_release import Destination, MANAGED_INTENT, MANAGED_INODES, MANAGED_READY, PROVISION
        from native_placement_release import OUTER_BYTES
        from native_placements import HOST_METADATA_BYTES, SCRATCH_BYTES
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
        if not os.path.lexists(MANAGED_INTENT) or not os.path.lexists(MANAGED_READY):
            raise Pending('managed-storage', 'The measured bounded Fedora allocation has not finished preparation.')
        managed = destination.record(MANAGED_INTENT)
        require(managed == destination.record(MANAGED_READY) and managed['machine_id'] == identity['machine_id'],
                'managed storage readiness belongs to a different machine or allocation')
        destination.mount_observation(STATE, managed['filesystem'], max_inodes=MANAGED_INODES)
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
        capacity = os.statvfs(STATE)
        jobs = sum(row['storage_bytes'] for row in site['jobs'].values())
        checklist = sum(DEFAULT_CHECKLIST[key] for key in ('validation_mib', 'live_mib', 'reserve_mib')) * 1024**2
        bytes_needed = jobs + OUTER_BYTES + SCRATCH_BYTES + HOST_METADATA_BYTES + checklist
        inodes_needed = sum(DEFAULT_CHECKLIST[key] for key in ('validation_inodes', 'live_inodes', 'reserve_inodes'))
        if capacity.f_bavail * capacity.f_frsize < bytes_needed or capacity.f_favail < inodes_needed:
            raise Pending('checklist-storage-capacity', 'The approved placement and checklist storage do not fit the observed allocation.')
        return {'tls_profile': CHECKLIST_SERVER, **DEFAULT_CHECKLIST}

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

    def configuration(self, policy, site):
        from bootstrap import checked_file
        from gptbox import Gptbox

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

    def checklist_builder(self):
        from checklist_candidate import CONTAINERS, candidate_image
        from destination_release import Destination

        policy = self.checklist_builder_policy()
        app = Destination()
        uid = app.account()
        base = '/var/lib/dev-pair/checklist-validation/builder'
        for path in (base, base + '/graph', base + '/tmp'):
            self.role_directory(path, 'dp-checklist')
        self.run('/usr/sbin/restorecon', '-RF', base, timeout=15)
        # Match the conductor's store exactly. The digest and its independent
        # verification receipt are installed beforehand under site custody.
        raw = app.subprocess_role(uid, '/usr/bin/env', 'TMPDIR=' + base + '/tmp',
                                  'CONTAINERS_CONF=' + str(CONTAINERS), '/usr/bin/podman',
                                  '--root', base + '/graph',
                                  '--runroot', f'/run/user/{uid}/dev-pair-checklist-builder',
                                  'image', 'inspect', policy['image'], timeout=20)
        candidate_image(parse(raw), policy['image'])


def main(argv=None):
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
