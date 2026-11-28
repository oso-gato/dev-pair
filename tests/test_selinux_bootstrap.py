"""Local transaction/state tests; these do not establish Fedora relabel/boot evidence."""
import importlib.util
import io
import shutil
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import selinux_bootstrap as s

BOOT0 = '00000000-0000-0000-0000-000000000000'
BOOT1 = '11111111-1111-1111-1111-111111111111'
BOOT2 = '22222222-2222-2222-2222-222222222222'
CONFIG = '# provider comment\nSELINUX=disabled # keep comment\nSELINUXTYPE=targeted\nAUTORELABEL=1\n'

class Runner:
    def __init__(self):
        self.calls = []
        self.mode = 'Disabled'
        self.fail = None
        self.enforce_works = True
        self.mount_uuid = {}
        self.mount_root = {}

    def __call__(self, *args, ok=(0,), **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and self.fail(args):
            raise s.Blocked('injected command failure')
        if args[0] == '/usr/bin/findmnt':
            return json.dumps({'filesystems': [{'uuid': self.mount_uuid.get(args[-1], '12345678-1234-1234-1234-123456789abc'),
                                                'fsroot': self.mount_root.get(args[-1], '/')} ]})
        if args[:3] == ('/usr/bin/rpm', '-q', '--qf'):
            return 'policycoreutils\n'
        if args == ('/usr/sbin/getenforce',):
            return self.mode + '\n'
        if args == ('/usr/sbin/setenforce', '1') and self.enforce_works:
            self.mode = 'Enforcing'
        return ''

class SELinuxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run = Runner()
        self.app = s.SELinuxBootstrap(self.root, self.run)
        for name, value in [('/etc/os-release', 'ID=fedora\nVERSION_ID=44\n'),
                            ('/proc/1/comm', 'systemd\n'),
                            ('/proc/self/mounts', 'root / ext4 rw,seclabel 0 0\nproc /proc proc rw,nosuid 0 0\n'),
                            ('/etc/selinux/targeted/contexts/files/file_contexts', 'fixture file contexts'),
                            ('/usr/lib/systemd/system/selinux-autorelabel.service', 'fixture-vendor-unit'),
                            ('/usr/bin/setfiles', 'fixture-native-binary-not-runtime-evidence'), ('/proc/cmdline', 'quiet root=UUID=fixture\n'),
                            ('/proc/sys/kernel/random/boot_id', BOOT0), ('/etc/selinux/config', CONFIG),
                            ('/etc/selinux/targeted/policy/policy.33', 'fixture-policy-not-runtime-evidence')]:
            path = self.app.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        self.app.path('/usr/bin/setfiles').chmod(0o755)
        self.patch = patch.object(s.os, 'geteuid', return_value=0)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def start(self, reboot=False):
        return self.app.converge(apply=True, reboot=reboot, expected=s.code_digest(), source_sha='a' * 40)

    def boot(self, identity, mode='Permissive'):
        self.app.path('/proc/sys/kernel/random/boot_id').write_text(identity)
        self.run.mode = mode

    def relabel_done(self):
        self.start()
        self.boot(BOOT1)
        self.app.relabel()

    def test_installed_boot_actions_enter_from_unrelated_cwd_without_source_imports(self):
        self.start()
        installed = self.app.path(s.INSTALL)
        self.assertEqual({path.name for path in installed.iterdir()}, set(s.BOOT_FILES))
        self.assertEqual(s.code_digest(installed), s.code_digest())
        outside = self.root / 'unrelated'
        outside.mkdir(mode=0o755)
        # The real installed entries must import and reach their protected host
        # gates. Run them unprivileged so this fixture cannot touch the host.
        credentials = {'user': 65534, 'group': 65534, 'extra_groups': []} if os.getuid() == 0 else {}
        self.root.chmod(0o755)
        for parent in installed.parents:
            if parent == self.root:
                break
            parent.chmod(0o755)
        for action, unit in (('_relabel', self.app.path(s.OVERRIDE)), ('_finalize', self.app.path(s.FINALIZER))):
            raw = next(row for row in unit.read_text().splitlines() if row.endswith(f' {action} --apply'))
            command = raw.removeprefix('ExecStart=').replace(s.HELPER, str(installed / 'selinux_bootstrap.py')).split()
            result = subprocess.run(command, text=True, capture_output=True, cwd=outside, env={}, timeout=5, **credentials)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('SELinux transition blocked', result.stderr)
            self.assertNotIn('ModuleNotFoundError', result.stderr)

    def test_preview_is_readonly_and_does_not_trust_permissive(self):
        self.run.mode = 'Permissive'
        result = self.app.converge()
        self.assertTrue(result['preview'])
        self.assertFalse(self.app.state.exists())
        self.assertFalse(self.app.path('/.autorelabel').exists())
        self.assertFalse(any(call[0][0] != '/usr/sbin/getenforce' for call in self.run.calls))
        with self.assertRaises(s.Blocked):
            self.app.finalize()

    def test_full_automatic_transition_requires_checked_relabel_and_different_boot(self):
        result = self.start(reboot=True)
        self.assertEqual(result['phase'], 'reboot-requested')
        self.assertEqual(s.config_mode(self.app.text('/etc/selinux/config')), 'permissive')
        self.assertIn('# keep comment', self.app.text('/etc/selinux/config'))
        self.assertIn('AUTORELABEL=1', self.app.text('/etc/selinux/config'))
        self.assertEqual(self.app.text('/.autorelabel'), '-F\n')
        with self.assertRaises(s.Blocked):
            self.app.relabel()
        self.boot(BOOT1)
        self.app.relabel()
        self.assertFalse(self.app.path('/.autorelabel').exists())
        self.assertEqual(self.app.state_json('relabel-done')['boot_id'], BOOT1)
        self.assertTrue(any(call[0][:7] == ('/usr/bin/setfiles', '-E', '-C', '-F', '-I', '-T', '1') and call[1] == {'timeout': 1800} for call in self.run.calls))
        with self.assertRaises(s.Blocked):
            self.app.finalize()
        self.boot(BOOT2)
        result = self.app.finalize()
        self.assertEqual(result['phase'], 'enforcing')
        self.assertEqual(self.run.mode, 'Enforcing')
        self.assertEqual(s.config_mode(self.app.text('/etc/selinux/config')), 'enforcing')
        self.assertTrue(self.app.state_json('complete'))
        self.assertFalse(self.app.path(s.OVERRIDE).exists())
        self.app.converge(apply=True)
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/bin/setfiles']), 1)
        self.assertEqual(len([call for call in self.run.calls if call[0] == ('/usr/bin/systemctl', 'reboot')]), 2)

    def test_no_reboot_without_explicit_authorization_and_later_resume_is_automatic(self):
        self.assertEqual(self.start()['phase'], 'pending-explicit-reboot')
        self.assertFalse(any(call[0] == ('/usr/bin/systemctl', 'reboot') for call in self.run.calls))
        self.assertEqual(self.app.converge(apply=True, reboot=True)['phase'], 'reboot-requested')
        self.boot(BOOT1)
        self.app.relabel()
        self.assertTrue(self.app.state_json('intent')['reboot_authorized'])
        self.boot(BOOT2)
        self.app.finalize()
        self.assertTrue(self.app.state_json('complete'))

    def test_initial_enforcing_is_not_downgraded_or_rebooted(self):
        self.run.mode = 'Enforcing'
        self.app.path('/etc/selinux/config').write_text(s.config_mode(CONFIG, 'enforcing'))
        self.app.converge(apply=True, reboot=True)
        self.assertFalse(any(call[0][0] in ('/usr/bin/dnf', '/usr/sbin/setenforce') or call[0] == ('/usr/bin/systemctl', 'reboot') for call in self.run.calls))
        self.assertFalse(self.app.path(s.OVERRIDE).exists())

    def test_kernel_conflicts_bad_config_missing_policy_and_bad_digest_block(self):
        for argument in ('selinux=0', 'enforcing=0', 'enforcing=1', 'lsm=landlock,apparmor', 'security=apparmor', 'autorelabel', 'autorelabel=0', 'systemd.unit=selinux-autorelabel.target'):
            self.app.path('/proc/cmdline').write_text(argument)
            with self.assertRaises(s.Blocked):
                self.start()
            self.assertFalse(self.app.state.exists())
        self.app.path('/proc/cmdline').write_text('selinux=1')
        with self.assertRaises(s.Blocked):
            self.app.converge(apply=True, expected='0' * 64, source_sha='a' * 40)
        self.assertFalse(any(call[0][0] == '/usr/bin/dnf' for call in self.run.calls))
        self.app.path('/etc/selinux/targeted/policy/policy.33').unlink()
        with self.assertRaises(s.Blocked):
            self.start()
        self.assertFalse(self.app.path(s.OVERRIDE).exists())
        self.app.path('/etc/selinux/config').write_text(CONFIG + 'SELINUX=enforcing\n')
        with self.assertRaises(s.Blocked):
            self.app.inspect()

    def test_config_write_interruption_reconciles_arming_before_reboot(self):
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path == '/etc/selinux/config':
                raise OSError('injected atomic failure')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.start()
        self.assertTrue(self.app.state_json('intent'))
        self.assertFalse(self.app.path('/.autorelabel').exists())
        self.app.atomic = original
        self.app.converge(apply=True)
        self.assertEqual(self.app.text('/.autorelabel'), '-F\n')
        self.assertEqual(s.config_mode(self.app.text('/etc/selinux/config')), 'permissive')

    def test_failed_relabel_never_records_completion_or_enforces_and_retries_are_bounded(self):
        self.start(reboot=True)
        self.boot(BOOT1)
        self.run.fail = lambda args: args[0] == '/usr/bin/setfiles'
        for _ in range(2):
            with self.assertRaises(s.Blocked):
                self.app.relabel()
        self.run.fail = None
        with self.assertRaises(s.Blocked):
            self.app.relabel()
        self.assertFalse(self.app.state_json('relabel-done'))
        self.assertTrue(self.app.path('/.autorelabel').exists())
        self.assertFalse(any(call[0][0] == '/usr/sbin/setenforce' for call in self.run.calls))
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/bin/setfiles']), 2)

    def test_successful_retry_after_first_relabel_failure_and_marker_remove_interruption(self):
        self.start()
        self.boot(BOOT1)
        self.run.fail = lambda args: args[0] == '/usr/bin/setfiles'
        with self.assertRaises(s.Blocked):
            self.app.relabel()
        self.run.fail = None
        original = self.app.remove_marker
        self.app.remove_marker = lambda: (_ for _ in ()).throw(OSError('injected unlink failure'))
        with self.assertRaises(OSError):
            self.app.relabel()
        self.assertTrue(self.app.state_json('relabel-done'))
        self.app.remove_marker = original
        self.app.relabel()
        self.assertFalse(self.app.path('/.autorelabel').exists())
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/bin/setfiles']), 2)

    def test_enforcement_command_readback_and_persistent_write_failures_never_disarm(self):
        self.relabel_done()
        self.boot(BOOT2)
        self.run.fail = lambda args: args[0] == '/usr/sbin/setenforce'
        with self.assertRaises(s.Blocked):
            self.app.finalize()
        self.run.fail = None
        self.run.enforce_works = False
        with self.assertRaises(s.Blocked):
            self.app.finalize()
        self.assertFalse(self.app.state_json('complete'))
        self.assertTrue(self.app.path(s.OVERRIDE).exists())
        self.run.enforce_works = True
        original = self.app.atomic
        def fail(path, *args, **kwargs):
            if path == '/etc/selinux/config':
                raise OSError('injected persistence failure')
            return original(path, *args, **kwargs)
        self.app.atomic = fail
        with self.assertRaises(OSError):
            self.app.finalize()
        self.assertEqual(self.run.mode, 'Enforcing')
        self.assertFalse(self.app.state_json('complete'))
        self.assertTrue(self.app.path(s.OVERRIDE).exists())
        self.app.atomic = original
        self.app.finalize()
        self.assertTrue(self.app.state_json('complete'))

    def test_foreign_config_marker_code_and_symlink_are_preserved(self):
        self.start()
        self.app.path('/etc/selinux/config').write_text('foreign edited configuration\n')
        with self.assertRaises(s.Blocked):
            self.app.converge(apply=True)
        self.assertEqual(self.app.text('/etc/selinux/config'), 'foreign edited configuration\n')
        self.app.path('/etc/selinux/config').write_text(s.config_mode(CONFIG, 'permissive'))
        installed = self.app.path(s.HELPER)
        installed.chmod(0o755)
        installed.write_text('tampered')
        with self.assertRaises(s.Blocked):
            self.app.converge(apply=True)
        installed.unlink()
        installed.symlink_to(ROOT / 'tools/selinux_bootstrap.py')
        with self.assertRaises(s.Blocked):
            self.app.converge(apply=True)

    def test_incomplete_transition_blocks_existing_prepare_even_after_live_enforcement(self):
        self.start()
        self.run.mode = 'Enforcing'
        tool = s.Bootstrap(self.root, self.run)
        with self.assertRaisesRegex(s.Blocked, 'incomplete'):
            tool.preflight()

    def test_finalizer_cleanup_failure_keeps_checked_success_and_retries_safely(self):
        self.relabel_done()
        self.boot(BOOT2)
        self.run.fail = lambda args: args[:2] == ('/usr/bin/systemctl', 'disable')
        with self.assertRaises(s.Blocked):
            self.app.finalize()
        self.assertTrue(self.app.state_json('complete'))
        self.assertEqual(self.run.mode, 'Enforcing')
        self.run.fail = None
        self.app.converge(apply=True)
        self.assertFalse(self.app.path(s.OVERRIDE).exists())
        self.assertNotIn('ConditionPathExists=!' + s.STATE + '/complete.json', s.UNIT)

    def test_internal_cli_requires_explicit_apply(self):
        for stage in ('_relabel', '_finalize'):
            with patch.object(sys, 'argv', ['selinux_bootstrap.py', stage]), \
                    patch.object(s, 'SELinuxBootstrap', return_value=self.app), \
                    patch.object(sys, 'stderr', io.StringIO()):
                self.assertEqual(s.main(), 2)
            self.assertFalse(self.app.state.exists())
            self.assertFalse(self.run.calls)

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze unavailable')
    def test_unit_and_override_syntax_with_local_user_manager_verifier(self):
        # User-manager parsing avoids writing protected /run/systemd in this worker.
        # Dependencies are fixtures; this establishes syntax only, never system boot behavior.
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            helper = str(ROOT / 'tools/selinux_bootstrap.py')
            finalizer = directory / 'dev-pair-selinux-finalize.service'
            finalizer.write_text(s.UNIT.replace(s.HELPER, helper))
            vendor = directory / 'selinux-autorelabel.service'
            vendor.write_text('[Unit]\nDescription=Synthetic vendor unit\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/false\nTimeoutSec=0\n')
            drop = directory / 'selinux-autorelabel.service.d'
            drop.mkdir()
            (drop / '90-dev-pair-checked.conf').write_text(s.DROPIN.replace(s.HELPER, helper))
            for target in ('local-fs.target', 'multi-user.target'):
                (directory / target).write_text('[Unit]\nDescription=Fixture target\n')
            env = {**os.environ, 'XDG_RUNTIME_DIR': str(directory),
                   'SYSTEMD_UNIT_PATH': str(directory) + ':/usr/lib/systemd/user'}
            result = subprocess.run(['/usr/bin/systemd-analyze', '--user', 'verify', str(finalizer), str(vendor)],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_foreign_vendor_override_or_changed_package_unit_blocks_before_arming(self):
        foreign = self.app.path('/run/systemd/system/selinux-autorelabel.service.d/override.conf')
        foreign.parent.mkdir(parents=True)
        foreign.write_text('[Service]\nExecStart=/usr/bin/true\n')
        with self.assertRaises(s.Blocked):
            self.start()
        self.assertFalse(self.app.state.exists())
        self.assertEqual(foreign.read_text(), '[Service]\nExecStart=/usr/bin/true\n')
        foreign.unlink()
        original = self.run
        def changed(*args, **kwargs):
            if args[:3] == ('/usr/bin/rpm', '-V', '--nomtime'):
                return 'S.5....T. /usr/lib/systemd/system/selinux-autorelabel.service\n'
            return original(*args, **kwargs)
        self.app.run = changed
        with self.assertRaises(s.Blocked):
            self.start()
        self.assertFalse(self.app.state_json('intent'))

    def test_native_setfiles_failure_cannot_be_hidden_by_successful_cleanup(self):
        self.start(reboot=True)
        self.boot(BOOT1)
        original = self.run
        def native_failure(*args, **kwargs):
            if args[0] == '/usr/bin/setfiles':
                # Real harmless nonzero child stands in for the native relabel syscall boundary.
                return s.Commands()(sys.executable, '-c', 'import sys; sys.exit(23)', timeout=5)
            return original(*args, **kwargs)
        self.app.run = native_failure
        with self.assertRaises(s.Blocked):
            self.app.relabel()
        self.assertFalse(self.app.state_json('relabel-done'))
        self.assertFalse(self.app.state_json('complete'))
        self.assertTrue(self.app.path('/.autorelabel').exists())
        self.assertEqual(len([call for call in self.run.calls if call[0] == ('/usr/bin/systemctl', 'reboot')]), 1)
        self.assertFalse(any(call[0][0] == '/usr/sbin/fixfiles' for call in self.run.calls))

    def test_mount_selection_honors_seclabel_rw_exclusions_and_escaped_space(self):
        for directory in ('/mnt/keep', '/mnt/read-only', '/mnt/data set'):
            self.app.path(directory).mkdir(parents=True)
        self.app.path('/proc/self/mounts').write_text(
            'root / ext4 rw,seclabel 0 0\n'
            'boot /boot ext4 rw,seclabel 0 0\n'
            'data /mnt/data\\040set xfs rw,seclabel 0 0\n'
            'disk /mnt/read-only ext4 ro,seclabel 0 0\n'
            'proc /proc proc rw,nosuid 0 0\n')
        self.app.path('/etc/selinux/fixfiles_exclude_dirs').write_text('# keep\nrelative\n/absent\n/mnt/keep\n')
        self.start()
        self.boot(BOOT1)
        self.app.relabel()
        plan = self.app.state_json('relabel-plan')
        self.assertEqual(plan['mounts'], ['/', '/boot', '/mnt/data set'])
        self.assertEqual(plan['excluded'], ['/mnt/keep', '/mnt/read-only'])
        command = next(call[0] for call in self.run.calls if call[0][0] == '/usr/bin/setfiles')
        self.assertIn(str(self.app.path('/mnt/data set')), command)
        self.assertEqual(command.count('-e'), 2)
        self.assertNotIn('-m', command)
        self.assertEqual(self.app.state_json('relabel-done')['method'], 'checked-setfiles')

    def test_no_root_label_coverage_readonly_critical_mount_or_critical_exclusion_blocks(self):
        self.app.path('/proc/self/mounts').write_text('root / ext4 rw 0 0\n')
        with self.assertRaises(s.Blocked):
            self.app.relabel_plan()
        self.app.path('/proc/self/mounts').write_text('root / ext4 rw,seclabel 0 0\nusr /usr ext4 ro,seclabel 0 0\n')
        with self.assertRaises(s.Blocked):
            self.app.relabel_plan()
        self.app.path('/proc/self/mounts').write_text('root / ext4 rw,seclabel 0 0\nusr /usr/lib squashfs ro 0 0\n')
        with self.assertRaises(s.Blocked):
            self.app.relabel_plan()
        self.app.path('/proc/self/mounts').write_text('root / ext4 rw,seclabel 0 0\nusr /usr/lib tmpfs rw,seclabel 0 0\n')
        with self.assertRaises(s.Blocked):
            self.app.relabel_plan()
        self.app.path('/proc/self/mounts').write_text('root / ext4 rw,seclabel 0 0\nefi /boot/efi vfat ro 0 0\n')
        self.app.relabel_plan()
        self.app.path('/etc/selinux/fixfiles_exclude_dirs').write_text('/etc\n')
        with self.assertRaises(s.Blocked):
            self.app.relabel_plan()

    def test_unexpected_later_relabel_boot_never_reboots_again(self):
        self.start(reboot=True)
        self.boot(BOOT1)
        self.app.relabel()
        before = len([call for call in self.run.calls if call[0] == ('/usr/bin/systemctl', 'reboot')])
        for digit in ('2', '3', '4', '5', '6', '7'):
            identity = digit * 8 + '-' + digit * 4 + '-' + digit * 4 + '-' + digit * 4 + '-' + digit * 12
            self.boot(identity)
            with self.assertRaises(s.Blocked):
                self.app.relabel()
        self.assertEqual(len([call for call in self.run.calls if call[0] == ('/usr/bin/systemctl', 'reboot')]), before)
        self.assertLessEqual(len(self.app.state_json('boots')['ids']), 4)

    def test_total_reboot_budget_cannot_reset_across_boots(self):
        self.start(reboot=True)
        intent = self.app.state_json('intent')
        self.boot(BOOT1)
        self.app.relabel()
        self.app.record('reboots', {BOOT0: 3, BOOT1: 3})
        with self.assertRaisesRegex(s.Blocked, 'budget'):
            self.app.reboot(intent, BOOT1)
        self.assertEqual(sum(self.app.state_json('reboots').values()), 6)

    def test_post_done_marker_crash_consumes_only_one_extra_boot_and_auto_finalizes(self):
        self.start(reboot=True)
        self.boot(BOOT1)
        original = self.app.remove_marker
        self.app.remove_marker = lambda: (_ for _ in ()).throw(OSError('injected marker unlink crash'))
        with self.assertRaises(OSError):
            self.app.relabel()
        self.assertTrue(self.app.state_json('relabel-done'))
        self.assertTrue(self.app.path('/.autorelabel').exists())
        self.app.remove_marker = original
        self.boot(BOOT2)
        self.app.relabel()
        self.assertEqual(self.app.state_json('marker-recovery')['boot_id'], BOOT2)
        self.assertFalse(self.app.path('/.autorelabel').exists())
        self.boot('33333333-3333-3333-3333-333333333333')
        self.app.finalize()
        self.assertTrue(self.app.state_json('complete'))
        self.assertEqual(len(self.app.state_json('boots')['ids']), 4)
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/bin/setfiles']), 1)

    def test_marker_recovery_allowance_is_durable_before_unlink_and_cannot_reset(self):
        self.relabel_done()
        self.app.path('/.autorelabel').write_text('-F\n')
        self.boot(BOOT2)
        original = self.app.remove_marker
        self.app.remove_marker = lambda: (_ for _ in ()).throw(OSError('injected recovery crash'))
        with self.assertRaises(OSError):
            self.app.relabel()
        self.assertEqual(self.app.state_json('marker-recovery')['boot_id'], BOOT2)
        self.app.remove_marker = original
        self.boot('33333333-3333-3333-3333-333333333333')
        with self.assertRaises(s.Blocked):
            self.app.relabel()
        self.assertEqual(self.app.state_json('marker-recovery')['boot_id'], BOOT2)
        self.assertTrue(self.app.path('/.autorelabel').exists())

    def test_malformed_done_evidence_never_removes_marker_or_reboots(self):
        self.start(reboot=True)
        self.boot(BOOT1)
        self.app.record('relabel-done', {'method': 'checked-setfiles'})
        before = self.app.text('/.autorelabel')
        with self.assertRaises(s.Blocked):
            self.app.converge(apply=True)
        self.assertEqual(self.app.text('/.autorelabel'), before)
        self.assertEqual(len([call for call in self.run.calls if call[0] == ('/usr/bin/systemctl', 'reboot')]), 1)

    def test_new_transient_mount_after_relabel_is_allowed_but_new_persistent_mount_blocks(self):
        self.relabel_done()
        self.boot(BOOT2)
        mounts = self.app.path('/proc/self/mounts')
        mounts.write_text(mounts.read_text() + 'tmpfs /run/user/0 tmpfs rw,seclabel 0 0\n')
        self.app.finalize()
        self.assertTrue(self.app.state_json('complete'))

    def test_changed_persistent_identity_subvolume_or_context_companion_blocks(self):
        self.relabel_done()
        self.boot(BOOT2)
        root = str(self.app.path('/'))
        for field in (self.run.mount_uuid, self.run.mount_root):
            field[root] = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' if field is self.run.mount_uuid else '/different-subvolume'
            with self.assertRaises(s.Blocked):
                self.app.finalize()
            field.clear()
        mounts = self.app.path('/proc/self/mounts')
        original = mounts.read_text()
        mounts.write_text(original + 'disk /mnt/new ext4 rw,seclabel 0 0\n')
        with self.assertRaises(s.Blocked):
            self.app.finalize()
        mounts.write_text(original)
        for suffix in ('.local', '.homedirs', '.subs', '.subs_dist', '.bin'):
            path = self.app.path('/etc/selinux/targeted/contexts/files/file_contexts' + suffix)
            path.write_text('changed policy input')
            with self.assertRaises(s.Blocked):
                self.app.finalize()
            path.unlink()
        self.assertFalse(self.app.state_json('complete'))
        self.assertFalse(any(call[0][0] == '/usr/sbin/setenforce' for call in self.run.calls))

    def test_fedora44_merged_sbin_uses_canonical_native_package_path(self):
        alias = self.app.path('/usr/sbin')
        self.assertFalse(alias.exists())
        alias.symlink_to('bin')
        self.start()
        self.boot(BOOT1)
        self.app.relabel()
        self.assertTrue(self.app.state_json('relabel-done'))
        self.assertTrue(any(call[0][0] == '/usr/bin/setfiles' for call in self.run.calls))
        self.assertFalse(any('/usr/sbin/setfiles' in call[0] for call in self.run.calls))

    def test_readonly_or_configured_ancestor_cannot_hide_writable_child(self):
        self.app.path('/proc/self/mounts').write_text(
            'root / ext4 rw,seclabel 0 0\n'
            'parent /opt ext4 ro,seclabel 0 0\n'
            'child /opt/service ext4 rw,seclabel 0 0\n')
        with self.assertRaisesRegex(s.Blocked, 'excluded ancestor'):
            self.app.relabel_plan()
        self.app.path('/opt').mkdir()
        self.app.path('/proc/self/mounts').write_text(
            'root / ext4 rw,seclabel 0 0\nchild /opt/service ext4 rw,seclabel 0 0\n')
        self.app.path('/etc/selinux/fixfiles_exclude_dirs').write_text('/opt\n')
        with self.assertRaisesRegex(s.Blocked, 'excluded ancestor'):
            self.app.relabel_plan()

    def test_native_implicit_nonseclabel_ancestor_cannot_hide_writable_child(self):
        self.app.path('/proc/self/mounts').write_text(
            'root / ext4 rw,seclabel 0 0\n'
            'parent /mnt vfat rw 0 0\n'
            'child /mnt/data ext4 rw,seclabel 0 0\n')
        with self.assertRaisesRegex(s.Blocked, 'excluded ancestor'):
            self.app.relabel_plan()
        self.app.path('/proc/self/mounts').write_text(
            'root / ext4 rw,seclabel 0 0\n'
            'efi /boot/efi vfat rw 0 0\n'
            'proc /proc proc rw 0 0\nsys /sys sysfs ro 0 0\n'
            'child /mnt/data ext4 rw,seclabel 0 0\n')
        self.assertEqual(self.app.relabel_plan()['mounts'], ['/', '/mnt/data'])

    def test_timeout_kills_forked_descendant_before_later_write(self):
        marker = self.root / 'orphan-write'
        handshake = self.root / 'fork-handshake'
        code = ('import os,sys,time\nfrom pathlib import Path\n'
                'child=os.fork()\n'
                'if child == 0:\n'
                '    Path(sys.argv[2]).write_text("forked")\n'
                '    time.sleep(0.6)\n'
                '    Path(sys.argv[1]).write_text("orphan survived")\n'
                '    os._exit(0)\n'
                'time.sleep(60)\n')
        with self.assertRaisesRegex(s.Blocked, 'process group terminated'):
            s.Commands()(sys.executable, '-c', code, str(marker), str(handshake), timeout=0.25)
        self.assertTrue(handshake.exists())
        time.sleep(0.7)
        self.assertFalse(marker.exists())
        self.assertIn('KillMode=control-group', s.DROPIN)
        self.assertIn('TimeoutStopSec=10s', s.UNIT)

    def test_reboot_failures_stay_pending_and_budget_is_bounded(self):
        self.run.fail = lambda args: args == ('/usr/bin/systemctl', 'reboot')
        for _ in range(3):
            with self.assertRaises(s.Blocked):
                self.start(reboot=True)
        with self.assertRaises(s.Blocked):
            self.app.converge(apply=True, reboot=True)
        self.assertFalse(self.app.state_json('complete'))
        self.assertEqual(len([call for call in self.run.calls if call[0] == ('/usr/bin/systemctl', 'reboot')]), 3)

if __name__ == '__main__':
    unittest.main()
