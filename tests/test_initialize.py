"""Local orchestration/process evidence only; no Fedora/systemd/engine acceptance."""
import contextlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap as b
import gptbox as g

SOURCE = '1' * 40
CONTEXT = 'a' * 64


class InitializeFixture(g.Gptbox):
    def __init__(self, root):
        super().__init__(root)
        self.order = []
        self.fail = False

    def preflight(self):
        return {'fixture': 'not Fedora evidence'}

    def protected(self, path):
        return Path(path)

    def check_gptbox_inputs(self, context, expected):
        return None, Path(context), {'source_sha': SOURCE}

    def inputs(self, *args):
        self.order.append('identity')
        return {}, {}

    def preparation(self):
        app = self
        class LocalCommands(b.Commands):
            @staticmethod
            def reconcile_native(args, env):
                app.order.append('fixture-native-reconcile')
        class Preparation:
            run = LocalCommands()
            def prepare(self, *args, source_check=None, **kwargs):
                with app.lock():
                    source_check()
                    app.order.append('prepare')
                    app.atomic(b.STATE + '/prepared', 'fixture prerequisite only\n')
        return Preparation()

    def assemble(self, *args, **kwargs):
        with self.lock():
            self.order.append('assemble')
            if self.fail:
                raise b.Blocked('fixture assembly failure')
            return {'source_sha': SOURCE, 'context_sha256': CONTEXT, 'job_admission': False,
                    'fixture': 'no engine acceptance'}

    def setup_executor(self, retry=False):
        self.order.append('cleanup-executor')

    def recover_resources(self, expected):
        self.order.append('cleanup-resources')


class InitializeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = InitializeFixture(Path(self.tmp.name))
        self.app.directory('/var/lib/dev-pair', mode=0o755)
        self.app.state.mkdir(parents=True, mode=0o700)
        (self.app.state / 'operator-password-set').write_text('fixture preexisting password marker\n')

    def initialize(self, **kwargs):
        with patch.object(g, 'github_keys', return_value='fixture public key only\n'):
            return self.app.initialize('/context', CONTEXT, '/upstream', SOURCE, ['192.0.2.9/32'], apply=True, **kwargs)

    def test_separate_locks_partial_failure_and_explicit_exact_target_reapply(self):
        self.app.fail = True
        with self.assertRaisesRegex(b.Blocked, 'fixture assembly'):
            self.initialize()
        prior = json.loads(self.app.text(b.STATE + '/initialize.json'))
        self.assertEqual((prior['prepare'], prior['maintenance_gptbox']), ('complete', 'blocked'))
        self.assertEqual(prior['phase'], 'maintenance-gptbox')
        self.assertIn('cleanup-resources', self.app.order)
        self.assertFalse(prior['job_admission'])
        calls = len(self.app.order)
        with self.assertRaisesRegex(b.Blocked, 'explicit exact-target'):
            self.initialize()
        self.assertEqual(len(self.app.order), calls)
        self.app.fail = False
        prior['native_units'] = ['dev-pair-initialize-cleanup-12345678-12345678']
        self.app.atomic(b.STATE + '/initialize.json', json.dumps(prior) + '\n', expected=self.app.text(b.STATE + '/initialize.json'))
        with patch.object(self.app.run, 'reconcile_native') as reconcile:
            self.assertEqual(self.initialize(retry=True)['phase'], 'complete')
            self.assertIn('--unit=dev-pair-initialize-cleanup-12345678-12345678', reconcile.call_args.args[0])
        self.assertEqual(self.app.order[-2:], ['prepare', 'assemble'])
        self.assertEqual(self.initialize()['phase'], 'complete')
        with patch.object(self.app, 'check_gptbox_inputs', return_value=(None, Path('/context'), {'source_sha': '2' * 40})):
            with self.assertRaisesRegex(b.Blocked, 'context/source'):
                self.initialize(retry=True)

    def test_prepare_failure_never_runs_adapter_or_claims_completion(self):
        with patch.object(self.app, 'preparation', side_effect=b.Blocked('fixture admission')):
            with self.assertRaises(b.Blocked):
                self.initialize()
        record = json.loads(self.app.text(b.STATE + '/initialize.json'))
        self.assertEqual(record['prepare'], 'pending')
        self.assertEqual(record['maintenance_gptbox'], 'pending')
        self.assertNotIn('assemble', self.app.order)

    def test_failure_cleanup_shares_existing_two_attempt_cleanup_budget(self):
        self.app.fail = True
        for retry in (False, True, True):
            with self.assertRaises(b.Blocked):
                self.initialize(retry=retry)
        self.assertEqual(self.app.order.count('cleanup-resources'), 2)
        cleanup = json.loads(self.app.text(g.ROOT + '/' + CONTEXT + '/cleanup-only.json'))
        self.assertEqual(cleanup['count'], 2)
        record = json.loads(self.app.text(b.STATE + '/initialize.json'))
        self.assertEqual(record['maintenance_gptbox'], 'blocked')
        self.assertTrue(record['cleanup'].startswith('blocked;'))

    def test_real_capture_caps_quiet_child_descendants_phase_and_secret_stdin(self):
        run = b.Commands()
        records = []
        run.diagnostic = records.append
        marker = Path(self.tmp.name) / 'escaped-child'
        script = ('import os,time,pathlib,sys; pid=os.fork(); '
                  'time.sleep(1) if pid==0 else time.sleep(5); pathlib.Path(sys.argv[1]).write_text("escaped")')
        with self.assertRaisesRegex(b.Blocked, 'deadline'):
            run(sys.executable, '-c', script, str(marker), timeout=.05)
        time.sleep(1.1)
        self.assertFalse(marker.exists())
        with self.assertRaisesRegex(b.Blocked, 'output byte budget'):
            run(sys.executable, '-c', 'import os; os.write(1,b"x"*1100000)', timeout=3)
        with self.assertRaisesRegex(b.Blocked, 'phase execution budget'):
            with run.phase(0, 'expired-no-effect', native=False):
                self.fail('expired phase entered')
        self.assertIsNone(run.deadline)
        with self.assertRaisesRegex(b.Blocked, 'phase execution budget'):
            with run.phase(.05, 'local-no-native-fixture', native=False):
                time.sleep(3)
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'secret-env-sentinel'}):
            self.assertEqual(run(sys.executable, '-c', 'import os;print(os.getenv("OPENAI_API_KEY"))').strip(), 'None')
        self.assertEqual(run(sys.executable, '-c', 'import sys;print(sys.stdin.read())', input_text='secret-stdin-sentinel'), '')
        self.assertEqual(run(sys.executable, '-c', 'import sys;sys.stdin.read()', input_text='core:' + '\U0001f642' * 1024 + '\n'), '')
        with self.assertRaisesRegex(b.Blocked, 'deadline'):
            run(sys.executable, '-c', 'import time;time.sleep(5)', input_text='x' * 16384, timeout=.05)
        self.assertNotIn('secret-stdin-sentinel', json.dumps(records))
        self.assertNotIn('secret-env-sentinel', json.dumps(records))

    def test_separate_runners_share_earliest_phase_timer_and_child_native_limit(self):
        outer, inner, third = b.Commands(), b.Commands(), b.Commands()
        records = []
        third.diagnostic = records.append
        for _ in range(3):
            with self.assertRaisesRegex(b.Blocked, 'deadline'):
                third(sys.executable, '-c', 'import time;time.sleep(.04)', timeout=.02)
            self.assertNotEqual(records[-1]['status'], 0)
        third.diagnostic = None
        started = time.monotonic()
        with self.assertRaisesRegex(b.Blocked, 'phase execution budget'):
            with outer.phase(.05, 'outer', native=False):
                with inner.phase(.2, 'inner', native=False):
                    time.sleep(.1)
        self.assertLess(time.monotonic() - started, .2)
        self.assertIsNone(outer.deadline)
        self.assertIsNone(inner.deadline)
        with self.assertRaisesRegex(b.Blocked, 'phase execution budget'):
            with outer.phase(.05, 'outer', native=False):
                with inner.phase(1, 'inner', native=False):
                    time.sleep(.005)
                time.sleep(.1)
        original = b.subprocess.Popen
        ceilings = []
        def spawned(args, **kwargs):
            ceilings.append(float(next(v.rsplit('=', 1)[1].removesuffix('s') for v in args
                                       if v.startswith('--property=RuntimeMaxSec='))))
            return original(args[args.index(sys.executable):], **kwargs)
        with patch.object(b.subprocess, 'Popen', side_effect=spawned):
            with outer.phase(.15, 'outer', native=False):
                with inner.phase(1, 'inner', native=False):
                    self.assertLess(third.limit_timeout(900), .15)
                    third('/usr/bin/systemd-run', '--property=RuntimeMaxSec=180',
                          sys.executable, '-c', 'print("local native-argv dispatch only")')
        self.assertEqual(len(ceilings), 1)
        self.assertGreater(ceilings[0], 0)
        self.assertLessEqual(ceilings[0], .15)
        with self.assertRaises(b.Blocked):
            with outer.phase(.05, 'outer', native=False):
                with inner.phase(1, 'inner', native=False):
                    third(sys.executable, '-c', 'import time;time.sleep(.3)', timeout=2)

    def test_expired_nested_phase_rejects_at_exit_even_with_alarm_delivery_blocked(self):
        outer, inner = b.Commands(), b.Commands()
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        try:
            with self.assertRaisesRegex(b.Blocked, 'phase execution budget'):
                with outer.phase(.02, 'outer', native=False):
                    with inner.phase(.2, 'inner', native=False):
                        time.sleep(.04)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            while signal.SIGALRM in signal.sigpending():
                signal.sigtimedwait({signal.SIGALRM}, 0)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        self.assertIsNone(outer.deadline)
        self.assertIsNone(inner.deadline)
        self.assertIsNone(b._PHASE_DEADLINE.get())

    def test_exited_launcher_descendant_is_killed_and_native_dispatch_reconciled(self):
        original = b.subprocess.Popen
        for runner, native in ((b.Commands, False), (b.Commands, True), (g.ProbeCommands, True)):
            marker = Path(self.tmp.name) / ('escaped-after-exit-' + runner.__name__ + str(native))
            processes = []
            def spawned(args, **kwargs):
                if native:
                    args = args[args.index(sys.executable):]
                process = original(args, **kwargs)
                processes.append(process)
                return process
            script = ('import os,time,pathlib,sys; pid=os.fork(); '
                      'os._exit(0) if pid else None; time.sleep(.35); '
                      'pathlib.Path(sys.argv[1]).write_text("escaped")')
            run = runner()
            if isinstance(run, g.ProbeCommands):
                run.diagnostic = lambda buffers, status: None
            prefix = ('/usr/bin/systemd-run', '--unit=dev-pair-exited-test',
                      '--description=dev-pair-owned-dev-pair-exited-test', '--property=RuntimeMaxSec=180') if native else ()
            try:
                with patch.object(b.subprocess, 'Popen', side_effect=spawned), \
                        patch.object(run, 'reconcile_native') as reconcile:
                    with self.assertRaisesRegex(b.Blocked, 'deadline|timed out'):
                        run(*prefix, sys.executable, '-c', script, str(marker), timeout=.1)
                    self.assertEqual(processes[0].poll(), 0)
                    reconcile.assert_called_once()
                    self.assertEqual(reconcile.call_args.args[0][:len(prefix)], prefix[:-1] + ('--property=RuntimeMaxSec=0.100s',) if native else ())
                time.sleep(.4)
                self.assertFalse(marker.exists())
            finally:
                for process in processes:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_native_root_unit_is_recorded_before_spawn_and_runs_clean_environment(self):
        run = b.Commands()
        run.native_prefix = 'dev-pair-initialize-prepare-12345678'
        identities = []
        run.native_register = identities.append
        original = b.subprocess.Popen
        def spawned(args, **kwargs):
            unit = next(value[7:] for value in args if value.startswith('--unit='))
            self.assertEqual(identities, [unit])
            self.assertIn('--description=dev-pair-owned-' + unit, args)
            self.assertIn('--property=KillMode=control-group', args)
            # Execute the actual fixed env/child tail locally; this proves its
            # environment contract, not a running systemd native-unit boundary.
            position = args.index('/usr/bin/env')
            return original(args[position:], **kwargs)
        with patch.object(b.subprocess, 'Popen', side_effect=spawned), patch.dict(os.environ, {'OPENAI_API_KEY': 'native-secret-sentinel'}):
            output = run(sys.executable, '-c', 'import os;print(os.getenv("OPENAI_API_KEY"))')
        self.assertEqual(output.strip(), 'None')

    def test_native_ceiling_never_expands_and_cleanup_verifies_exact_description(self):
        native = ('/usr/bin/systemd-run', '--property=RuntimeMaxSec=180', '--unit=dev-pair-test',
                  '--description=dev-pair-owned-dev-pair-test')
        self.assertIn('--property=RuntimeMaxSec=180.000s', b.Commands.native_args(native, 600))
        self.assertIn('--property=RuntimeMaxSec=2.500s', b.Commands.native_args(native, 2.5))
        with self.assertRaisesRegex(b.Blocked, 'native execution budget'):
            b.Commands.native_args(native, .0001)
        with self.assertRaisesRegex(b.Blocked, 'native execution budget'):
            b.Commands.native_args(('--property=RuntimeMaxSec=0',), 3)
        results = ['Description=foreign\nActiveState=active\n']
        with patch.object(b.Commands, '__call__', side_effect=results) as calls:
            with self.assertRaisesRegex(b.Blocked, 'ownership mismatch'):
                b.Commands.reconcile_native(native, {})
            self.assertEqual(calls.call_count, 1)
        results = ['Description=dev-pair-owned-dev-pair-test\nActiveState=active\n', '', 'ActiveState=inactive\n']
        with patch.object(b.Commands, '__call__', side_effect=results) as calls:
            b.Commands.reconcile_native(native, {})
            self.assertEqual(calls.call_args_list[1].args, ('/usr/bin/systemctl', 'stop', 'dev-pair-test'))


if __name__ == '__main__':
    unittest.main()
