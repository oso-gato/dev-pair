from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import bootstrap
import renewal
import stable_renewal as stable
import systemd_service_profile as profile


class Manager:
    def __init__(self, boot):
        self.boot = boot
        self.loaded = set()
        self.foreign = None

    def run(self, program, *args, timeout):
        if program.endswith('restorecon'):
            return ''
        recovery = args[-1] == stable.RECOVERY_UNIT
        if program.endswith('busctl'):
            recovery = 'renewal_2drecovery_2eservice' in args[3]
            active = self.boot.reconcile in self.loaded and not recovery
            rows = [['ConditionPathExists', False, True, str(stable.BOOT_HOLD), 0]] if active else []
            return '\n'.join(json.dumps({'type': 'a(sbbsi)', 'data': data}) for data in (rows, []))
        if args[0] == 'daemon-reload':
            self.loaded = {name for name in self.boot.files if self.boot.app.path(name).exists()}
            return ''
        unit = args[-1]
        fragment = self.boot.unit_root + (stable.RECOVERY_UNIT if recovery else self.boot.template)
        scope = unit.partition('@')[2].removesuffix('.service')
        if recovery:
            argv = self.boot.argv if self.boot.recovery in self.loaded else stable.LEGACY_RECOVERY
        else:
            argv = (*stable.LEGACY_RECOVERY[:-1], 'reconcile', scope, '--check-candidate')
        drops = {name for name in self.loaded if name.startswith(fragment + '.d/')}
        if self.foreign and recovery:
            drops.add(self.foreign)
        row = dict.fromkeys(args[2].split('=', 1)[1].split(','), '')
        row.update(Id=unit, LoadState='loaded', FragmentPath=fragment, DropInPaths=' '.join(sorted(drops)),
                   ExecStart='{ path=' + argv[0] + ' ; argv[]=' + ' '.join(argv) + ' ; ignore_errors=no }',
                   User='root', Group='root', Type='oneshot', NeedDaemonReload='no',
                   TimeoutStartFailureMode='terminate', TimeoutStopFailureMode='terminate',
                   KillMode='control-group', SendSIGKILL='yes', FinalKillSignal='9')
        return '\n'.join(f'{name}={value}' for name, value in row.items())


class BootHandoffTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.control = self.root / 'var/lib/dev-pair/renewal'
        self.control.mkdir(parents=True)
        self.controller = SimpleNamespace(root=self.control.parent, control=self.control, lock=nullcontext)
        self.operation = 'retained-stable-window'
        self.grant = {'platform_sha256': 'a' * 64, 'operation': self.operation, 'target_release_sha256': 'b' * 64}
        self.request = {'operation': self.operation, 'target_sha256': 'b' * 64}
        self.approval = {'schema': 1, 'request': self.request, 'offer_sha256': 'c' * 64}
        self.enterContext(patch.object(stable, 'host_bundle', return_value=ROOT))
        self.enterContext(patch.object(stable, 'lease', nullcontext))
        self.boot = stable.BootHandoff(self.controller, self.grant)
        self.boot.app = bootstrap.Bootstrap(self.root)
        self.manager = Manager(self.boot)
        self.boot.app.run = self.manager.run
        for unit in (stable.RECOVERY_UNIT, self.boot.template):
            self.boot.app.atomic(self.boot.unit_root + unit, (ROOT / 'runtime/renewal' / unit).read_text(), mode=0o644)
        # The mapped-root installed-path fixture verifies the actual POSIX
        # ancestry and UIDs. The source suite can also run without root.
        self.enterContext(patch.object(profile, 'protected', side_effect=lambda path, *args, **kw: path.read_bytes()))

    def test_arm_and_cleanup_only_the_two_exact_files(self):
        self.boot.arm(self.approval)
        self.assertEqual(self.manager.loaded, set(self.boot.files))
        self.assertEqual(renewal.read_json(self.boot.marker), self.approval)
        self.assertEqual(self.boot.confirm_files(), self.boot.files)
        self.boot.arm(self.approval)
        self.boot.cleanup(self.approval)
        self.assertEqual(self.manager.loaded, set())
        self.assertFalse(self.boot.marker.exists())
        self.assertEqual(self.boot.confirm_files(), {})

    def test_foreign_override_blocks_before_publishing_open_authority(self):
        self.manager.foreign = self.boot.unit_root + stable.RECOVERY_UNIT + '.d/50-local.conf'
        self.boot.app.atomic(self.manager.foreign, '[Unit]\nConditionPathExists=/approved-admin-hold\n', mode=0o644)
        foreign = self.boot.app.path(self.manager.foreign)
        retained = foreign.read_bytes()
        with self.assertRaisesRegex(ValueError, 'unknown or missing override'):
            self.boot.arm(self.approval)
        self.assertFalse(self.boot.marker.exists())
        self.assertEqual(self.boot.confirm_files(), {})
        self.assertEqual(foreign.read_bytes(), retained)

    def test_partial_install_before_marker_returns_to_legacy_after_cleaning(self):
        self.boot.app.atomic(self.boot.recovery, self.boot.files[self.boot.recovery].decode(), mode=0o644)
        self.boot.system('daemon-reload')
        self.controller.transition = lambda: (None, None)
        with (patch.object(stable, 'BootHandoff', return_value=self.boot),
              patch.object(stable, '__file__', self.boot.argv[2]),
              patch.object(stable, 'binding', return_value=self.grant),
              patch.object(stable.os, 'execv', side_effect=SystemExit(0)) as fallback):
            with self.assertRaises(SystemExit):
                stable.boot_recover(self.controller, self.grant['platform_sha256'])
        fallback.assert_called_once_with(stable.LEGACY_RECOVERY[0], stable.LEGACY_RECOVERY)
        self.assertEqual(self.boot.confirm_files(), {})

    def test_boot_reuses_only_the_authorized_active_operation_and_polls_for_fresh_access(self):
        self.boot.arm(self.approval)
        attempt = self.control / 'attempts' / self.operation
        state = {'phase': 'applying', 'request': self.request}
        self.controller.transition = lambda: (attempt, state)
        path = self.control / stable.REQUEST
        path.parent.mkdir()
        renewal.replace_json(path, self.approval)
        ready = {'phase': 'completed', 'request': self.request}
        access = Mock(side_effect=[{'phase': 'verifying', 'forward_access_pending': {'boot_id': 'new'}},
                                   {'phase': 'awaiting-independent-stable-access'}, ready])
        with (patch.object(stable, 'BootHandoff', return_value=self.boot),
              patch.object(stable, '__file__', self.boot.argv[2]),
              patch.object(stable, 'binding', return_value=self.grant),
              patch.object(stable, 'approved_request', return_value=(self.request, {})),
              patch.object(stable, 'apply_with_access', access), patch.object(stable.time, 'sleep')):
            self.assertEqual(stable.boot_recover(self.controller, self.grant['platform_sha256']), ready)
        self.assertEqual([call.args for call in access.call_args_list], [(self.controller, self.operation)] * 3)

    def test_another_active_operation_leaves_the_durable_handoff_closed(self):
        self.boot.arm(self.approval)
        attempt = self.control / 'attempts' / 'other-window'
        self.controller.transition = lambda: (attempt, {'phase': 'applying', 'request': {'operation': attempt.name}})
        with (patch.object(stable, 'BootHandoff', return_value=self.boot),
              patch.object(stable, '__file__', self.boot.argv[2]),
              patch.object(stable, 'binding', return_value=self.grant),
              patch.object(stable, 'approved_request', return_value=(self.request, {})),
              patch.object(stable, 'apply_with_access') as apply, patch.object(stable.os, 'execv') as fallback):
            with self.assertRaisesRegex(ValueError, 'does not authorize the active attempt'):
                stable.boot_recover(self.controller, self.grant['platform_sha256'])
        apply.assert_not_called()
        fallback.assert_not_called()
        self.assertEqual(renewal.read_json(self.boot.marker), self.approval)


if __name__ == '__main__':
    unittest.main()
