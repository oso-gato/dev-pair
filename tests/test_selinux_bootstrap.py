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

    def __call__(self, *args, ok=(0,), **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and self.fail(args):
            raise s.Blocked('injected command failure')
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
                            ('/usr/lib/systemd/system/selinux-autorelabel.service', 'fixture-vendor-unit'), ('/proc/cmdline', 'quiet root=UUID=fixture\n'),
                            ('/proc/sys/kernel/random/boot_id', BOOT0), ('/etc/selinux/config', CONFIG),
                            ('/etc/selinux/targeted/policy/policy.33', 'fixture-policy-not-runtime-evidence')]:
            path = self.app.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
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
        self.assertIn((('/usr/sbin/fixfiles', '-F', '-T', '1', 'restore'), {'timeout': 1800}), self.run.calls)
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
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/sbin/fixfiles']), 1)
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
        for argument in ('selinux=0', 'enforcing=0', 'enforcing=1', 'lsm=landlock,apparmor', 'security=apparmor'):
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
        self.run.fail = lambda args: args[0] == '/usr/sbin/fixfiles'
        for _ in range(2):
            with self.assertRaises(s.Blocked):
                self.app.relabel()
        self.run.fail = None
        with self.assertRaises(s.Blocked):
            self.app.relabel()
        self.assertFalse(self.app.state_json('relabel-done'))
        self.assertTrue(self.app.path('/.autorelabel').exists())
        self.assertFalse(any(call[0][0] == '/usr/sbin/setenforce' for call in self.run.calls))
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/sbin/fixfiles']), 2)

    def test_successful_retry_after_first_relabel_failure_and_marker_remove_interruption(self):
        self.start()
        self.boot(BOOT1)
        self.run.fail = lambda args: args[0] == '/usr/sbin/fixfiles'
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
        self.assertEqual(len([call for call in self.run.calls if call[0][0] == '/usr/sbin/fixfiles']), 2)

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
