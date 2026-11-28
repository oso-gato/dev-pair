import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import provider_billing as billing
import provider_transition as transition
from ledger_recovery import write_private
from test_host_commissioning import Systemd

BOOT = '11111111-2222-4333-8444-555555555555'
OTHER_BOOT = '11111111-2222-4333-8444-666666666666'
PREVIOUS = transition.PREFIX + 'a' * 64 + '.service'


def fixture_fence(root):
    manager = Systemd(root, [])
    fence = transition.Fence(root, manager)
    for name, raw in (('/proc/sys/kernel/random/boot_id', (BOOT + '\n').encode()),
                      (transition.TEMPLATE, (ROOT / 'runtime/renewal/dev-pair-provider@.service').read_bytes()),
                      (transition.DROP_IN, (ROOT / 'runtime/renewal/provider-start-fence.conf').read_bytes()),
                      (transition.GATE, (ROOT / 'tools/provider_transition.py').read_bytes()),
                      *((name, (ROOT / 'tools' / Path(name).name).read_bytes()) for name in transition.BILLING_TOOLS),
                      (transition.LAUNCHER, (ROOT / 'runtime/renewal/provider-run').read_bytes())):
        leaf = fence.path(name)
        leaf.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(leaf, raw)
    fence.state.parent.mkdir(parents=True, mode=0o700)
    fence.runtime.parent.mkdir(mode=0o700, exist_ok=True)
    return fence, manager


@unittest.skipUnless(os.getuid() == 0, 'protected manager fixture needs mapped root')
class ProviderTransitionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.fence, self.manager = fixture_fence(self.root)
        self.enterContext(mock.patch.object(billing, 'protected', side_effect=self.protected))

    def protected(self, path, *, directory=False, private=False):
        self.assertTrue(path.is_relative_to(self.root))
        self.assertEqual(path.resolve(strict=True), path)
        node = path.lstat()
        if directory:
            self.assertTrue(path.is_dir())
        else:
            self.assertTrue(path.is_file())
            self.assertEqual(node.st_nlink, 1)
        self.assertEqual((node.st_uid, node.st_gid), (0, 0))
        if private:
            self.assertEqual(node.st_mode & 0o777, 0o700 if directory else 0o600)
        return path

    def test_clean_install_is_default_deny_and_reproves_after_reboot(self):
        with self.assertRaisesRegex(transition.Deferred, 'pending device readback'):
            self.fence.require_ready()
        self.fence.converge()
        self.fence.require_ready()
        before = self.fence.ready.stat().st_ino
        self.fence.converge()
        self.assertEqual(self.fence.ready.stat().st_ino, before)
        boot = self.fence.path('/proc/sys/kernel/random/boot_id')
        boot.write_text(OTHER_BOOT + '\n')
        with self.assertRaisesRegex(ValueError, 'new proof'):
            self.fence.require_ready()
        self.fence.converge()
        self.assertEqual(billing.json_bundle(self.fence.ready.read_bytes())['boot'], OTHER_BOOT)

    def test_activating_job_and_active_instance_prevent_custody_acknowledgement(self):
        self.fence.converge()
        self.manager.queued.add(PREVIOUS)
        with mock.patch.object(billing, '_withdraw_reference', return_value=100) as apply:
            with self.assertRaisesRegex(transition.Deferred, 'still starting or finishing'):
                self.fence.change('withdraw-reference', {'reference': 'fixture-api'})
            self.assertFalse(self.fence.ready.exists())
            self.assertIn('fixture-api', self.fence.pending.read_text())
            apply.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'old broker instances'):
                self.fence.require_ready()
            self.manager.queued.remove(PREVIOUS)
            self.manager.active.add(PREVIOUS)
            restarted = transition.Fence(self.root, self.manager)
            with self.assertRaises(transition.Deferred):
                restarted.converge()
            apply.assert_not_called()
            self.manager.active.remove(PREVIOUS)
            restarted.converge()
            restarted.require_ready()
            apply.assert_called_once_with('fixture-api')
            self.assertFalse(restarted.pending.exists())
            restarted.converge()
            apply.assert_called_once()

    def test_unknown_manager_definition_and_unreported_populated_group_hold(self):
        def no_loaded_guard(*args, **kwargs):
            answer = self.manager(*args, **kwargs)
            return '\n'.join(line for line in answer.splitlines() if not line.startswith('ExecCondition='))

        unknown = transition.Fence(self.root, no_loaded_guard)
        with self.assertRaisesRegex(ValueError, 'has not loaded the exact'):
            unknown.converge()
        self.assertFalse(unknown.ready.exists())
        group = self.fence.path('/sys/fs/cgroup/system.slice/' + PREVIOUS)
        group.mkdir(parents=True)
        events = group / 'cgroup.events'
        events.write_text('populated 1\nfrozen 0\n')
        with self.assertRaises(transition.Deferred):
            self.fence.converge()
        self.assertFalse(self.fence.ready.exists())
        events.write_text('populated 0\nfrozen 0\n')
        self.fence.converge()
        self.fence.require_ready()

    def test_loaded_manager_reload_and_unit_alias_must_be_proved_again(self):
        self.fence.converge()
        self.manager.vendor_facts['NeedDaemonReload'] = 'yes'
        with self.assertRaisesRegex(ValueError, 'has not loaded the exact'):
            self.fence.converge()
        self.assertFalse(self.fence.ready.exists())
        self.manager.vendor_facts.clear()
        alias = self.fence.path(transition.TEMPLATE).with_name('unexpected-broker@.service')
        alias.symlink_to(Path(transition.TEMPLATE).name)
        with self.assertRaisesRegex(ValueError, 'unapproved alias'):
            self.fence.converge()
        self.assertFalse(self.fence.ready.exists())
        alias.unlink()
        self.fence.converge()
        self.fence.require_ready()

    def test_boot_reproof_keeps_attended_effect_pending_without_replaying_it(self):
        self.fence.converge()
        self.manager.queued.add(PREVIOUS)
        with self.assertRaises(transition.Deferred):
            self.fence.change('withdraw-reference', {'reference': 'fixture-api'})
        self.manager.queued.clear()
        self.fence.path('/proc/sys/kernel/random/boot_id').write_text(OTHER_BOOT + '\n')
        with mock.patch.object(billing, '_withdraw_reference', return_value=100) as effect:
            with self.assertRaisesRegex(transition.Deferred, 'attended custody operation'):
                self.fence.converge(resume_custody=False)
            self.assertTrue(self.fence.pending.exists())
            self.assertFalse(self.fence.ready.exists())
            effect.assert_not_called()
            self.fence.converge()
            self.fence.require_ready()
            effect.assert_called_once_with('fixture-api')

    def test_resume_durably_replays_transition_across_ready_publication_failure(self):
        self.fence.converge()
        publish = billing.replace_record

        def interrupt(path, value):
            if path == self.fence.ready:
                raise OSError('interrupted after custody write')
            publish(path, value)

        with mock.patch.object(billing, '_withdraw_reference', return_value=100) as apply:
            with mock.patch.object(billing, 'replace_record', side_effect=interrupt):
                with self.assertRaisesRegex(OSError, 'interrupted'):
                    self.fence.change('withdraw-reference', {'reference': 'fixture-api'})
            apply.assert_called_once_with('fixture-api')
            self.assertFalse(self.fence.ready.exists())
            transition.Fence(self.root, self.manager).converge()
            self.fence.require_ready()
            self.assertFalse(self.fence.pending.exists())
            apply.assert_called_once()
