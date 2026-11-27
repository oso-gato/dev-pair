"""Exercise commissioning's actual durable filesystem and bounded manager boundary."""
from contextlib import nullcontext
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import commission_host as c
import systemd_service_profile as profile

SOURCE = '1' * 40
PLATFORM = '2' * 64
SITE = '3' * 64
RELEASE = '4' * 64
NEXT = '5' * 64
POLICY = '6' * 64
BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
JOBS = {'jobs': {'checklist': {}}}
FIRST = {'schema': 1, 'source_sha': SOURCE, 'machine_id': '7' * 32, 'platform_sha256': PLATFORM,
         'site_config_sha256': SITE, 'timers': sorted(c.TIMERS),
         'checklist': {'tls_profile': '/root/checklist-tls', 'uid': 1210, 'subid_start': 4000000,
                       'validation_mib': 1500, 'live_mib': 1200, 'validation_inodes': 20000, 'live_inodes': 12000,
                       'reserve_mib': 1200, 'reserve_inodes': 4096}}


class Systemd:
    """Synthetic manager, reading each observed fragment from the real installed fixture tree."""
    def __init__(self, root, steps):
        self.root, self.steps = root, steps
        self.enabled, self.active = set(), set()
        self.bad_exec = None
        self.vendor_key = b'public Fedora test key'
        self.vendor_payload = b'# Fedora test payload\n[Service]\nTimeoutStopFailureMode=abort\n'
        self.vendor_facts = {}
        self.missing_properties = set()

    def __call__(self, binary, command, *args, **unused):
        if binary == '/usr/bin/rpm':
            self.steps.append('vendor-rpm')
            if args[-1] == '--info':
                return 'Signature   : RSA/SHA256, Thu 01 Jan 1970, Key ID ' + profile.FINGERPRINT[-16:] + '\n'
            return 'systemd\t1.fc44\tx86_64\t8\n' + (
                profile.VENDOR + '\t' + c.digest(self.vendor_payload) + '\t-rw-r--r--\troot\troot\n')
        if binary != c.SYSTEMCTL:
            self.steps.append(command if binary.endswith('restorecon') else binary)
            return ''
        if command in ('daemon-reload', 'enable', 'disable'):
            self.steps.append(command if command == 'daemon-reload' else command + ':' + args[-1])
            if command == 'enable':
                self.enabled.add(args[-1])
                if '--now' in args:
                    self.active.add(args[-1])
            if command == 'disable':
                self.enabled.discard(args[-1])
                self.active.discard(args[-1])
            return ''
        if command != 'show':
            raise AssertionError('unexpected manager command')
        unit = args[-1]
        fields = next(arg.removeprefix('--property=') for arg in args if arg.startswith('--property=')).split(',')
        template = re.sub(r'@[^.]+\.service$', '@.service', unit)
        fragment = c.UNIT_ROOT + '/' + template
        path = self.root / fragment.lstrip('/')
        instance = path.with_name(unit + '.d')
        drops = sorted(set(path.with_name(path.name + '.d').glob('*.conf')) | set(instance.glob('*.conf')))
        vendor = self.root / profile.VENDOR.lstrip('/')
        if unit.endswith('.service') and vendor.exists():
            drops.insert(0, vendor)
        exists = path.exists()
        data = path.read_text() if exists else ''
        command = next((line[10:] for line in data.splitlines() if line.startswith('ExecStart=')), '')
        guard = ''
        for drop in drops:
            command = next((line[10:] for line in drop.read_text().splitlines() if line.startswith('ExecStart=/')), command)
            guard = next((line[14:] for line in drop.read_text().splitlines() if line.startswith('ExecCondition=')), guard)
        if unit == self.bad_exec:
            command = '/usr/bin/false'
        user = 'dp-checklist' if unit.startswith('dev-pair-checklist-executor@') else 'root'
        active = unit in self.active
        next_unit = next((short for timer, short in (*c.TIMERS.values(), c.AGENT_BRIDGE) if timer == unit), '')
        executable = command.split()[0] if command else ''
        row = {'LoadState': 'loaded' if exists else 'not-found',
               'FragmentPath': fragment if exists else '',
               'DropInPaths': ' '.join('/' + str(drop.relative_to(self.root)) for drop in drops),
               'UnitFileState': 'enabled' if unit in self.enabled else 'disabled' if exists else '',
               'ActiveState': 'active' if active else 'inactive', 'SubState': 'waiting' if active else 'dead',
               'User': user, 'Group': user,
               'ExecStart': '{ path=' + executable + ' ; argv[]=' +
                 command.replace('%i', unit.partition('@')[2].removesuffix('.service')) + ' ; }',
               'Unit': next_unit, 'NextElapseUSecRealtime': 'Fri 2026-11-27 19:00:00 UTC' if active else '',
               'NextElapseUSecMonotonic': 'n/a'}
        row.update(dict.fromkeys(profile.PROPERTIES, ''), NeedDaemonReload='no', KillMode='control-group',
                   SendSIGKILL='yes', FinalKillSignal='9', TimeoutStartFailureMode='terminate',
                   TimeoutStopFailureMode='abort' if vendor.exists() else 'terminate')
        if guard:
            row['ExecCondition'] = '{ path=' + guard.split()[0] + ' ; argv[]=' + guard + ' ; }'
        row.update(self.vendor_facts)
        return ''.join(f'{key}={row[key]}\n' for key in fields if key not in self.missing_properties
                       and (key not in profile.COMMAND_HOOKS or row[key]))


class ExistingPaths:
    """Stage boundaries used by F, U and D, each asserting observable preconditions."""
    def __init__(self, app, manager):
        self.app, self.manager = app, manager
        self.steps = manager.steps
        self.progress = 0
        self.allowed = {RELEASE, NEXT}

    def configuration(self, policy, site):
        self.steps.append('site-policy')

    def renewal(self):
        return self

    def lock(self, *, shared=False):
        return nullcontext()

    def stage(self, policy, boot):
        self.steps.append('F-stage')
        assert 'daemon-reload' in self.steps
        assert self.steps.index('F-host-bundle') < self.steps.index('F-stage')

    def prepare_host_bundle(self, policy):
        store = self.app.path(c.INSTALL + '/host-releases')
        assert store.is_dir() and store.stat().st_mode & 0o777 == 0o755
        self.steps.append('F-host-bundle')

    def resolve_initial(self, controller, policy, boot, site):
        self.steps.append('U-resolve')
        assert 'F-stage' in self.steps
        return RELEASE

    def verify_selection(self, controller, selected, policy):
        if selected not in self.allowed:
            raise AssertionError('selected an unrelated release')

    def initial_selection(self, controller, selected, policy, boot):
        return selected == RELEASE

    def provision(self, policy):
        self.steps.append('D-provision')
        assert self.app.read(c.CONTROL + '/current.json') == self.app.read(c.CONTROL + '/site-current.json')
        executor = 'dev-pair-checklist-executor@1210.service'
        self.progress += 1
        marker = self.app.path(c.FENCE + '/frozen')
        self.manager.active.add(c.BOOT_FENCE)
        if self.progress == 1:
            self.app.file(c.FENCE + '/frozen', c.encoded('boot'), 0o600)
        else:
            if marker.exists():
                marker.unlink()
            self.manager.enabled.update((executor, c.RECOVERY))
            self.manager.active.add(executor)
        return {'uid': 1210, 'listener_mode': 'managed', 'executor': executor,
                'provisioned': self.progress >= 2, 'listener_state': 'host-observation-queued'}

    def post_provision(self, policy, selected):
        self.steps.append('post-provision')
        assert not self.app.path(c.FENCE + '/frozen').exists()


class HostCommissioning(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(dir=Path(__file__).resolve().parents[2])
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.steps = []
        self.manager = Systemd(self.root, self.steps)
        self.app = c.Commission(self.root, self.root, self.manager, os.getuid(), None)
        self.services = ExistingPaths(self.app, self.manager)
        self.app.services = self.services

    def files(self, timers=None):
        selected = set(c.TIMERS if timers is None else timers)
        units = {
            c.BOOT_FENCE: '/usr/bin/python3 -IB /usr/libexec/dev-pair/tools/renewal.py boot-fence',
            c.RECOVERY: '/usr/bin/python3 -I /usr/libexec/dev-pair/tools/renewal.py recover',
            'dev-pair-renewal-host-observe.service': c.INSTALL + '/renewal/host-release observe',
            'dev-pair-provider@.service': c.INSTALL + '/renewal/provider-run %i',
            'dev-pair-renewal@.service': '/usr/bin/python3 -EBs /usr/libexec/dev-pair/tools/task.py',
            'dev-pair-checklist-executor@.service': '/usr/bin/python3 fixture',
        }
        if 'owner-intake' in selected:
            units.update({'dev-pair-intake@.service': '/usr/bin/python3 intake %i',
                          'dev-pair-product@.service': '/usr/bin/python3 product %i'})
        features = {'dev-pair-intake@.service': 'owner-intake', 'dev-pair-product@.service': 'owner-intake',
                    'dev-pair-intake-recovery.service': 'owner-intake',
                    'dev-pair-checklist-spool.service': 'checklist-spool'}
        files = {'/etc/tmpfiles.d/dev-pair-renewal.conf': (b'# fixture tmpfiles\n', 0o644, 'base')}
        for feature in selected:
            timer, service = c.TIMERS[feature]
            service = re.sub(r'@[^.]+\.service$', '@.service', service)
            units[service] = '/usr/bin/python3 -EBs /usr/libexec/dev-pair/tools/task.py'
            files[c.UNIT_ROOT + '/' + timer] = (b'[Timer]\nOnCalendar=hourly\n', 0o644, feature)
        for unit, command in units.items():
            files[c.UNIT_ROOT + '/' + unit] = (f'[Service]\nExecStart={command}\n'.encode(), 0o644, features.get(unit, 'base'))
        files[c.UNIT_ROOT + '/dev-pair-checklist-executor@.service.d/checklist-release.conf'] = (
            b'[Service]\nExecStart=\nExecStart=/usr/libexec/dev-pair/renewal/checklist-entry\n', 0o644, 'base')
        if 'owner-intake' in selected:
            files['/usr/local/bin/dev-pair'] = (b'#!/bin/sh\nexit 0\n', 0o755, 'owner-entry')
            files['/etc/sudoers.d/60-dev-pair-owner'] = (
                b'core ALL=(root) NOPASSWD: /usr/libexec/dev-pair/tools/owner_intake.py ""\n', 0o440, 'owner-entry')
        return files

    def apply(self, timers=None):
        policy = FIRST if timers is None else {**FIRST, 'timers': timers}
        return self.app.apply(policy, POLICY, BOOT, JOBS, self.files(timers))

    def test_fenced_observation_then_timers_and_owner_terminal(self):
        result = self.apply()
        self.assertEqual(result['phase'], 'host-observation-queued')
        self.assertTrue(self.app.path(c.FENCE + '/frozen').exists())
        self.assertFalse(self.app.path('/etc/sudoers.d/60-dev-pair-owner').exists())
        self.assertEqual(self.manager.enabled, {c.BOOT_FENCE})
        self.assertEqual(self.steps.count('F-stage'), 1)
        result = self.apply()
        self.assertEqual(result['phase'], 'ready')
        self.assertEqual(set(result['timers']), {timer for timer, _ in c.TIMERS.values()})
        self.assertEqual(result['owner_terminal'], '/usr/local/bin/dev-pair')
        self.assertLess(self.steps.index('post-provision'), self.steps.index('enable:dev-pair-intake-recovery.timer'))
        self.assertLess(self.steps.index('U-resolve'), self.steps.index('D-provision'))
        self.assertEqual(self.app.path('/usr/local/bin/dev-pair').stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.app.path('/etc/sudoers.d/60-dev-pair-owner').stat().st_mode & 0o777, 0o440)
        before = self.app.path(c.CONTROL + '/current.json').stat().st_ino
        self.assertEqual(self.apply()['phase'], 'ready')
        self.assertEqual(self.app.path(c.CONTROL + '/current.json').stat().st_ino, before)
        self.assertEqual(self.steps.count('F-stage'), 1)
        self.assertEqual(self.steps.count('enable:dev-pair-intake-recovery.timer'), 1)

    def test_admitted_successor_stays_selected_and_work_is_preserved_on_reapply(self):
        self.apply()
        self.apply()
        for name in ('current', 'site-current'):
            self.app.path(c.CONTROL + '/' + name + '.json').write_bytes(c.encoded(NEXT))
        source = 'c' * 64
        self.app.file(c.STATE + '/product-jobs/jobs/retained.json', c.encoded(source), 0o600)
        self.assertEqual(self.apply()['selected_release'], NEXT)
        self.assertEqual(self.app.read(c.STATE + '/product-jobs/jobs/retained.json'), c.encoded(source))
        self.assertEqual(self.steps.count('F-stage'), 1)

    def test_unowned_partial_selection_is_preserved_before_install(self):
        self.app.file(c.CONTROL + '/current.json', c.encoded(RELEASE), 0o600)
        with self.assertRaisesRegex(c.Blocked, 'unowned partial'):
            self.apply()
        self.assertEqual(self.app.read(c.CONTROL + '/current.json'), c.encoded(RELEASE))
        self.assertFalse(self.app.path(c.UNIT_ROOT + '/' + c.BOOT_FENCE).exists())

    def test_exact_prior_intent_can_finish_a_partial_pointer_commit(self):
        self.apply()
        self.app.path(c.CONTROL + '/site-current.json').unlink()
        self.assertEqual(self.apply()['selected_release'], RELEASE)
        self.assertEqual(self.app.read(c.CONTROL + '/site-current.json'), c.encoded(RELEASE))
        self.assertEqual(self.steps.count('F-stage'), 1)

    def test_disabled_features_do_not_activate_a_root_service_or_install_sudo(self):
        self.assertEqual(self.apply([])['phase'], 'host-observation-queued')
        self.assertEqual(self.apply([])['timers'], {})
        self.assertFalse(self.app.path('/usr/local/bin/dev-pair').exists())
        self.assertFalse(self.app.path('/etc/sudoers.d/60-dev-pair-owner').exists())
        for timer, service in c.TIMERS.values():
            self.assertNotIn(timer, self.manager.enabled)
            self.assertNotIn(service, self.manager.active)
            self.assertFalse(self.app.path(c.UNIT_ROOT + '/' + timer).exists())

    def test_effective_service_drift_blocks_timer_activation(self):
        self.apply()
        self.manager.bad_exec = 'dev-pair-checklist-spool.service'
        with self.assertRaisesRegex(c.Blocked, 'effective command differs'):
            self.apply()
        self.assertNotIn('dev-pair-checklist-spool.timer', self.manager.enabled)
        self.assertFalse(self.app.path('/etc/sudoers.d/60-dev-pair-owner').exists())

    def test_stock_empty_hooks_are_omitted_but_forbidden_hooks_and_missing_execstart_block(self):
        self.assertEqual(self.apply()['phase'], 'host-observation-queued')
        self.manager.vendor_facts['ExecStopPost'] = '{ path=/usr/bin/false ; argv[]=/usr/bin/false ; }'
        with self.assertRaisesRegex(c.Blocked, 'effective process profile differs'):
            self.apply()
        self.manager.vendor_facts.clear()
        self.manager.missing_properties.add('ExecStart')
        with self.assertRaisesRegex(c.Blocked, 'unit property readback differs'):
            self.apply()
        self.assertNotIn('enable:dev-pair-intake-recovery.timer', self.steps)

    def test_fedora_vendor_dropin_is_measured_and_effective_properties_are_checked(self):
        with patch.object(profile, 'KEY_SHA', c.digest(self.manager.vendor_key)):
            self.app.file(profile.VENDOR_KEY, self.manager.vendor_key, 0o644)
            self.app.file(profile.VENDOR, self.manager.vendor_payload, 0o644)
            self.assertEqual(self.apply()['phase'], 'host-observation-queued')
            self.assertGreaterEqual(self.steps.count('vendor-rpm'), 2)
            self.manager.vendor_facts['TimeoutStopFailureMode'] = 'terminate'
            with self.assertRaisesRegex(c.Blocked, 'effective timeout mode differs'):
                self.apply()
            self.manager.vendor_facts.clear()
            target = self.app.path(profile.VENDOR)
            target.write_bytes(self.manager.vendor_payload + b'ExecStartPre=/usr/bin/false\n')
            with self.assertRaisesRegex(c.Blocked, 'installed RPM payload'):
                self.apply()
            self.manager.vendor_payload = target.read_bytes()
            with self.assertRaisesRegex(c.Blocked, 'unapproved settings'):
                self.apply()

    def test_incompatible_host_release_store_blocks_before_f_native_stage(self):
        self.app.directory(c.INSTALL + '/host-releases', 0o700)
        with self.assertRaisesRegex(c.Blocked, 'mode differs'):
            self.apply()
        self.assertNotIn('F-stage', self.steps)
        self.assertNotIn('F-host-bundle', self.steps)

    def test_policy_rejects_unbound_source_and_arbitrary_units(self):
        self.assertEqual(c.read_policy(c.encoded(FIRST), SOURCE), FIRST)
        for changed in ({'timers': ['sshd.service']}, {'source_sha': '0' * 40},
                        {'checklist': {**FIRST['checklist'], 'tls_profile': '/tmp/../root'}}):
            with self.subTest(changed=changed), self.assertRaises(c.Blocked):
                c.read_policy(c.encoded({**FIRST, **changed}), SOURCE)

    def automatic_services(self):
        machine = {'machine_id': FIRST['machine_id'], 'boot_id': BOOT}
        self.services.identity = lambda: machine
        self.services.inventory = lambda revision: {
            **machine, 'host': 'erebus', 'arch': 'x86_64', 'pid1': 'systemd',
            'selinux': '1', 'os_release': 'ID=fedora\nVERSION_ID=44\n'}
        self.services.initial_platform = lambda revision, **kwargs: PLATFORM
        self.services.initial_site = lambda hostname: (SITE, JOBS)
        self.services.initial_host_profile = lambda site, observed: None
        self.services.initial_checklist = lambda identity, site, revision, **kwargs: FIRST['checklist']
        self.services.verify_initial_parts = lambda platform: self.steps.append('verified-full-parts')
        self.services.prepare_checklist_pair = lambda *args, **kwargs: None
        self.services.check_initial_capacity = lambda *args: None
        self.services.authority = lambda policy: (JOBS, {})
        def workload_scope(*args, **kwargs):
            raise c.Pending('workload-access', 'Independent role proof is absent.')

        self.services.workload_scope = workload_scope
        def package(policy, bundle, *, retained=(), activation=False):
            files = self.files(policy['timers'])
            if activation:
                files.update(c.workload_guard_files(policy['timers']))
                if 'agent-renewal' in policy['timers']:
                    repository = Path(__file__).resolve().parents[1]
                    for name in (c.AGENT_BRIDGE[0], 'dev-pair-agent-bridge@.service'):
                        files[c.UNIT_ROOT + '/' + name] = ((repository / 'runtime/renewal' / name).read_bytes(),
                                                          0o644, 'agent-renewal')
            return files

        self.app.package = package

    def test_normal_automatic_policy_is_private_pinned_and_reused(self):
        self.automatic_services()
        self.assertEqual(self.app.automatic('discover', SOURCE)['phase'], 'discovered')
        leaf = self.app.path(c.AUTOMATIC_POLICY)
        self.assertFalse(leaf.exists())
        self.assertEqual(self.app.automatic('prepare', SOURCE)['phase'], 'prepared')
        self.assertEqual(leaf.stat().st_mode & 0o777, 0o600)
        saved = leaf.read_bytes()
        self.assertEqual(c.read_policy(saved, SOURCE)['platform_sha256'], PLATFORM)
        self.assertFalse(self.app.path(c.CONTROL + '/current.json').exists())
        with patch.object(self.services, 'initial_platform', side_effect=AssertionError('reselected platform')):
            self.assertEqual(self.app.automatic('apply', SOURCE)['phase'], 'host-observation-queued')
            ready = self.app.automatic('apply', SOURCE)
        self.assertEqual(ready['phase'], 'ready')
        self.assertEqual(set(ready['held_features']), set(c.TIMERS))
        self.assertEqual(leaf.read_bytes(), saved)
        self.assertEqual(self.steps.count('F-stage'), 1)
        self.assertEqual(self.steps.count('verified-full-parts'), 2)

    def test_cached_prepare_and_apply_reverify_peer_and_geometry_before_stage(self):
        self.automatic_services()
        self.app.automatic('prepare', SOURCE)
        saved = self.app.read(c.AUTOMATIC_POLICY)
        for action in ('prepare', 'apply'):
            with self.subTest(action=action), patch.object(self.services, 'initial_checklist',
                    side_effect=c.Blocked('changed private TLS peer')):
                with self.assertRaisesRegex(c.Blocked, 'changed private TLS peer'):
                    self.app.automatic(action, SOURCE)
        with patch.object(self.services, 'initial_checklist', return_value={**FIRST['checklist'], 'uid': 2001}):
            with self.assertRaisesRegex(c.Blocked, 'observed checklist geometry'):
                self.app.automatic('apply', SOURCE)
        self.assertEqual(self.app.read(c.AUTOMATIC_POLICY), saved)
        self.assertNotIn('F-stage', self.steps)
        self.assertFalse(self.app.path(c.UNIT_ROOT + '/' + c.BOOT_FENCE).exists())

    def test_incomplete_full_parts_block_before_policy_or_host_effects(self):
        self.automatic_services()
        with patch.object(self.services, 'verify_initial_parts', side_effect=FileNotFoundError('missing devbox archive')):
            for action in ('prepare', 'apply'):
                with self.subTest(action=action), self.assertRaisesRegex(FileNotFoundError, 'missing devbox archive'):
                    self.app.automatic(action, SOURCE)
        self.assertFalse(self.app.path(c.AUTOMATIC_POLICY).exists())
        self.assertFalse(self.app.path(c.INSTALL + '/host-releases').exists())
        self.assertNotIn('F-stage', self.steps)

    def test_existing_manual_authority_stops_initial_derivation_and_acquisition(self):
        self.automatic_services()
        self.app.file(c.PRIVATE + '/intent.json', c.encoded({'policy_sha256': 'b' * 64}), 0o600)
        with patch.object(self.services, 'initial_site', side_effect=AssertionError('rederived owner configuration')), \
                patch.object(self.services, 'initial_platform', side_effect=AssertionError('reselected platform')):
            with self.assertRaisesRegex(c.Blocked, 'different protected site authority'):
                self.app.automatic('apply', SOURCE)

    def test_normal_reapply_arms_only_qualified_feature_and_holds_stale_authority(self):
        self.automatic_services()
        self.app.automatic('apply', SOURCE)
        self.assertEqual(self.app.automatic('apply', SOURCE)['pending_features'], dict.fromkeys(c.TIMERS, 'workload-access'))
        initial = self.app.read(c.AUTOMATIC_POLICY)
        intent = self.app.read(c.PRIVATE + '/intent.json')
        history = '/var/lib/dev-pair/product-jobs/saved-work'
        self.app.file(history, b'owned work\n', 0o600)
        scope = 'a' * 64
        self.services.workload_scope = lambda *args, **kwargs: scope
        grant = {'subject': 'managed-validation', 'expires_unix': None, 'sha256': 'b' * 64}

        def feature_authority(feature, selected, *, recorded=None):
            if feature == 'checklist-spool':
                return grant
            reason = 'owner-catalogue' if feature == 'owner-intake' else 'agent-release-authority'
            raise c.Pending(reason, 'This feature has no verified authority.')

        self.services.feature_authority = feature_authority
        result = self.app.automatic('apply', SOURCE)
        timer, service = c.TIMERS['checklist-spool']
        self.assertEqual(set(result['timers']), {timer})
        self.assertEqual(result['timers'][timer]['service'], service)
        self.assertEqual(result['pending_features'], {'agent-renewal': 'agent-release-authority', 'owner-intake': 'owner-catalogue'})
        guard = self.app.path(next(iter(c.workload_guard_files(('checklist-spool',)))))
        guarded = guard.read_bytes()
        self.app.require_runtime_feature('checklist-spool')
        guard.unlink()
        self.assertEqual(self.app.automatic('apply', SOURCE), result)
        self.assertEqual(guard.read_bytes(), guarded)
        self.assertEqual(self.steps.count('enable:' + timer), 1)
        with patch.object(self.services, 'identity', return_value={'machine_id': FIRST['machine_id'], 'boot_id': NEXT}):
            with self.assertRaisesRegex(c.Blocked, 'not current on this boot'):
                self.app.require_runtime_feature('checklist-spool')
        with patch.object(self.services, 'workload_scope', side_effect=c.Pending('workload-access', 'retained access withdrawn')):
            with self.assertRaises(c.Pending):
                self.app.require_runtime_feature('checklist-spool')
            held = self.app.automatic('apply', SOURCE)
        self.assertFalse(held['timers'])
        self.assertIn('disable:' + timer, self.steps)
        self.assertEqual(self.app.read(history), b'owned work\n')
        self.assertEqual((self.app.read(c.AUTOMATIC_POLICY), self.app.read(c.PRIVATE + '/intent.json')), (initial, intent))

    def test_partial_owner_entry_retries_and_expired_provider_scope_blocks_mutation(self):
        self.automatic_services()
        self.app.automatic('apply', SOURCE)
        self.services.workload_scope = lambda *args, **kwargs: 'a' * 64
        expires = int(time.time()) + 500
        grant = {'subject': 'checklist', 'expires_unix': expires, 'sha256': 'c' * 64}

        def feature_authority(feature, selected, *, recorded=None):
            if feature == 'owner-intake' and time.time() < expires:
                return grant
            raise c.Pending('feature-unavailable', 'Feature authority is missing.')

        self.services.feature_authority = feature_authority
        real_file = self.app.file

        def interrupt_sudo(target, *args, **kwargs):
            if target == '/etc/sudoers.d/60-dev-pair-owner' and kwargs.get('save', True):
                raise InterruptedError('interrupted final sudo publication')
            return real_file(target, *args, **kwargs)

        with patch.object(self.app, 'file', side_effect=interrupt_sudo):
            with self.assertRaisesRegex(InterruptedError, 'interrupted final sudo'):
                self.app.automatic('apply', SOURCE)
        self.app.require_runtime_feature('owner-intake')
        with self.assertRaisesRegex(c.Blocked, 'feature is held'):
            self.app.require_runtime_feature('owner-intake', owner_entry=True)
        result = self.app.automatic('apply', SOURCE)
        self.assertEqual(result['owner_terminal'], '/usr/local/bin/dev-pair')
        self.app.require_runtime_feature('owner-intake', owner_entry=True)
        with patch.object(c.time, 'time', return_value=expires + 1):
            with self.assertRaisesRegex(c.Blocked, 'grant expired'):
                self.app.require_runtime_feature('owner-intake', owner_entry=True)
            held = self.app.automatic('apply', SOURCE)
        self.assertIsNone(held['owner_terminal'])
        self.assertFalse(held['timers'])
        self.assertFalse(self.app.path('/etc/sudoers.d/60-dev-pair-owner').exists())
        self.assertFalse(self.app.path('/usr/local/bin/dev-pair').exists())

    def test_late_owner_withdrawal_never_publishes_readiness_and_keeps_inflight_service_visible(self):
        self.automatic_services()
        self.app.automatic('apply', SOURCE)
        self.services.workload_scope = lambda *args, **kwargs: 'a' * 64
        authority = {'ready': True}
        grant = {'subject': 'a' * 48, 'expires_unix': int(time.time()) + 500, 'sha256': 'c' * 64}

        def feature_authority(feature, selected, *, recorded=None):
            if feature == 'owner-intake' and authority['ready']:
                return grant
            raise c.Pending('withdrawn-owner-slot' if feature == 'owner-intake' else 'feature-unavailable', 'Held.')

        self.services.feature_authority = feature_authority
        timer, service = c.TIMERS['owner-intake']

        def late_change(binary, verb, *args, **kwargs):
            response = self.manager(binary, verb, *args, **kwargs)
            if (binary, verb) == (c.SYSTEMCTL, 'enable') and args[-1] == timer:
                authority['ready'] = False
                self.manager.active.add(service)
            return response

        with patch.object(self.app, 'run', side_effect=late_change):
            denied = self.app.automatic('apply', SOURCE)
        self.assertIsNone(denied['owner_terminal'])
        self.assertNotIn(timer, denied['timers'])
        self.assertEqual(denied['pending_features']['owner-intake'], 'withdrawn-owner-slot')
        self.assertEqual(denied['retained_services'], {'owner-intake': [service]})
        self.assertNotIn(timer, self.manager.enabled)
        self.assertFalse(self.app.path('/etc/sudoers.d/60-dev-pair-owner').exists())
        self.assertFalse(self.app.path('/usr/local/bin/dev-pair').exists())
        self.assertEqual(self.app.automatic('apply', SOURCE), denied)
        self.assertEqual(c.validate_feature_grant(grant), grant)
        with self.assertRaisesRegex(ValueError, 'Invalid job ID'):
            c.validate_feature_grant({**grant, 'subject': 'a' * 49})

    def test_withdrawal_preserves_unrelated_privileged_entry(self):
        path = '/etc/sudoers.d/60-dev-pair-owner'
        raw = b'# Separate administrator authority\n'
        self.app.file(path, raw, 0o440)
        with self.assertRaisesRegex(c.Blocked, 'outside the owned activation'):
            self.app.withdraw_owner_entry(self.files(['owner-intake']))
        self.assertEqual(self.app.read(path, 0o440), raw)

    def test_cli_auto_path_reports_source_gap_without_policy_arguments_writes_or_install(self):
        self.automatic_services()
        with patch.object(c, 'protected'), patch.object(c, 'verify_checkout'), \
                patch.object(c.os, 'getuid', return_value=0), patch.object(c.os, 'geteuid', return_value=0), \
                patch.object(c, 'Commission', return_value=self.app), patch.object(c, 'Live', return_value=self.services), \
                patch.object(self.services, 'initial_platform', side_effect=c.Pending(
                    'initial-full-release-selection', 'No eligible full release.', source_gap=True)), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(c.main(['apply', '--source-sha', SOURCE]), 0)
        self.assertEqual(json.loads(output.getvalue()), {'phase': 'source-gap',
            'prerequisite': 'initial-full-release-selection', 'message': 'No eligible full release.'})
        self.assertFalse(self.app.path(c.AUTOMATIC_POLICY).exists())
        self.assertNotIn('F-stage', self.steps)


if __name__ == '__main__':
    unittest.main()
