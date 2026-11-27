"""Exercise commissioning's actual durable filesystem and bounded manager boundary."""
from contextlib import nullcontext
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
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
        if command in ('daemon-reload', 'enable'):
            self.steps.append(command if command == 'daemon-reload' else 'enable:' + args[-1])
            if command == 'enable':
                self.enabled.add(args[-1])
                if '--now' in args:
                    self.active.add(args[-1])
            return ''
        if command != 'show':
            raise AssertionError('unexpected manager command')
        unit = args[-1]
        fields = next(arg.removeprefix('--property=') for arg in args if arg.startswith('--property=')).split(',')
        template = re.sub(r'@[^.]+\.service$', '@.service', unit)
        fragment = c.UNIT_ROOT + '/' + template
        path = self.root / fragment.lstrip('/')
        drops = sorted(path.with_name(path.name + '.d').glob('*.conf'))
        vendor = self.root / profile.VENDOR.lstrip('/')
        if unit.endswith('.service') and vendor.exists():
            drops.insert(0, vendor)
        exists = path.exists()
        data = path.read_text() if exists else ''
        command = next((line[10:] for line in data.splitlines() if line.startswith('ExecStart=')), '')
        for drop in drops:
            command = next((line[10:] for line in drop.read_text().splitlines() if line.startswith('ExecStart=/')), command)
        if unit == self.bad_exec:
            command = '/usr/bin/false'
        user = 'dp-checklist' if unit.startswith('dev-pair-checklist-executor@') else 'root'
        active = unit in self.active
        next_unit = next((short for timer, short in c.TIMERS.values() if timer == unit), '')
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
        row.update(self.vendor_facts)
        return ''.join(f'{key}={row[key]}\n' for key in fields)


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

    def lock(self):
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
            'dev-pair-checklist-executor@.service': '/usr/bin/python3 fixture',
        }
        if 'owner-intake' in selected:
            units.update({'dev-pair-intake@.service': '/usr/bin/python3 intake %i',
                          'dev-pair-product@.service': '/usr/bin/python3 product %i'})
        files = {'/etc/tmpfiles.d/dev-pair-renewal.conf': (b'# fixture tmpfiles\n', 0o644, 'base')}
        for feature in selected:
            timer, service = c.TIMERS[feature]
            service = re.sub(r'@[^.]+\.service$', '@.service', service)
            units[service] = '/usr/bin/python3 -EBs /usr/libexec/dev-pair/tools/task.py'
            files[c.UNIT_ROOT + '/' + timer] = (b'[Timer]\nOnCalendar=hourly\n', 0o644, feature)
        for unit, command in units.items():
            files[c.UNIT_ROOT + '/' + unit] = (f'[Service]\nExecStart={command}\n'.encode(), 0o644, 'base')
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


if __name__ == '__main__':
    unittest.main()
