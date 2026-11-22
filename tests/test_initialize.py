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
from native_io_fixture import install, launch_payload, manager
import native_io

SOURCE = '1' * 40
CONTEXT = 'a' * 64
NATIVE_UNIT = 'dev-pair-gptbox-' + CONTEXT + '.service'


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
        install(self, self.tmp.name)
        self.app = InitializeFixture(Path(self.tmp.name))
        self.app.directory('/var/lib/dev-pair', mode=0o755)
        self.app.state.mkdir(parents=True, mode=0o700)
        (self.app.state / 'operator-password-set').write_text('fixture preexisting password marker\n')

    def initialize(self, **kwargs):
        with patch.object(g, 'github_keys', return_value='fixture public key only\n'):
            return self.app.initialize('/context', CONTEXT, '/upstream', SOURCE, ['192.0.2.9/32'], apply=True, **kwargs)

    def test_prepare_budget_snapshot_survives_later_adapter_failure_and_cleanup(self):
        original=self.app.preparation
        def preparation():
            result=original()
            result.role_directory_batches={role:{'role':role,'checked_lookups':2,'completed_directories':8,'outcome':'complete'}
                                           for role in ('maintenance','development')}
            return result
        self.app.fail=True
        with patch.object(self.app,'preparation',side_effect=preparation):
            with self.assertRaises(b.Blocked):self.initialize()
        record=json.loads(self.app.text(b.STATE+'/initialize.json'))
        self.assertEqual(record['prepare_budget_witness']['configured_seconds'],g.PREPARE_EXECUTION)
        self.assertFalse(record['prepare_budget_witness']['timer_fired'])
        self.assertFalse(record['prepare_budget_witness']['deadline_reached_at_exit'])
        self.assertEqual(record['role_directory_batches']['maintenance']['completed_directories'],8)
        self.assertIn('cleanup-resources',self.app.order)
        import fedora_ci_guest as guest
        expected={'source_sha':SOURCE,'context_sha256':CONTEXT,'distrobox_sha':g.DBX_SHA}
        public=guest.public_diagnostics(self.app.state,expected)['prepare_progress']['observations']
        self.assertEqual(public['budget']['configured_seconds'],600)
        self.assertEqual(public['source_sha'],SOURCE)
        self.assertFalse(public['budget']['timer_fired'])

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

    def test_prepare_cost_before_eviction_source_scope_and_retry_reset(self):
        self.app.atomic(b.STATE+'/prepare-diagnostics.json',json.dumps({'recent':[{'SECRET_OLD':'old'}],'failures':[]})+'\n')
        original=self.app.preparation;counts=iter((12,2))
        def preparation():
            result=original();count=next(counts)
            def prepare(*args,source_check=None,**kwargs):
                b.Bootstrap.mark_prepare_step(result,'adapter-source-and-upstream');source_check()
                b.Bootstrap.mark_prepare_step(result,'packages')
                for _ in range(count):
                    result.run.diagnostic({'step':'packages','accepted_exit':True,'launcher_handle_observed':True,
                        'elapsed_seconds':.001,'status':0,'operation_id':'signed-packages'})
            result.prepare=prepare;return result
        def inputs(*args):
            # One real local source-callback command; no Fedora/native claim.
            self.app.run(sys.executable,'-c','print("private local source fixture")')
            return {},{}
        self.app.fail=True
        with patch.object(self.app,'preparation',side_effect=preparation),patch.object(self.app,'inputs',side_effect=inputs):
            with self.assertRaises(b.Blocked):self.initialize()
            first=json.loads(self.app.text(b.STATE+'/initialize.json'));cost=first['prepare_cost']
            self.assertEqual(cost['command_records'],13)
            self.assertEqual(cost['steps']['packages'][2],12)
            self.assertEqual(cost['steps']['adapter-source-and-upstream'][2],1)
            self.assertEqual(cost['status'],'complete')  # Later adapter failure is independent.
            history=json.loads(self.app.text(b.STATE+'/prepare-diagnostics.json'))
            self.assertEqual(len(history['recent']),4);self.assertNotIn('SECRET_OLD',json.dumps(cost))
            with self.assertRaises(b.Blocked):self.initialize(retry=True)
            second=json.loads(self.app.text(b.STATE+'/initialize.json'))
            self.assertNotEqual(second['prepare_cost_attempt'],first['prepare_cost_attempt'])
            self.assertEqual(second['prepare_cost']['command_records'],3)
            self.assertEqual(second['prepare_cost']['steps']['packages'][2],2)

    def test_prepare_cost_interruption_keeps_active_step_and_primary_failure(self):
        original=self.app.preparation
        def preparation():
            result=original()
            def prepare(*args,**kwargs):
                b.Bootstrap.mark_prepare_step(result,'packages')
                raise b.Blocked('PRIMARY_PREPARE_FIXTURE')
            result.prepare=prepare;return result
        with patch.object(self.app,'preparation',side_effect=preparation):
            with self.assertRaisesRegex(b.Blocked,'PRIMARY_PREPARE_FIXTURE'):self.initialize()
        record=json.loads(self.app.text(b.STATE+'/initialize.json'))
        self.assertEqual(record['prepare'],'blocked');self.assertEqual(record['prepare_cost']['status'],'interrupted')
        self.assertGreater(record['prepare_cost']['steps']['packages'][1],0)
        self.assertNotIn('PRIMARY_PREPARE_FIXTURE',json.dumps(record['prepare_cost']))

    def test_real_native_registration_and_uid_bound_retry_after_completed_or_prelaunch_context_failure(self):
        original = subprocess.Popen
        for mode in ('completed-command', 'prelaunch-input'):
            with self.subTest(mode=mode):
                root = Path(self.tmp.name) / mode
                root.mkdir()
                callbacks, native_launches = [], []
                class App(InitializeFixture):
                    interrupt_prepare = True
                    def preparation(app):
                        class Preparation:
                            run = b.Commands()
                            def prepare(preparation, *args, source_check=None, **kwargs):
                                source_check()
                                if app.interrupt_prepare and mode == 'prelaunch-input':
                                    def unresolved(args, env):
                                        raise b.Blocked('fixture initial cleanup unavailable')
                                    preparation.run.reconcile_native = unresolved
                                preparation.run('/usr/bin/systemd-run', '--unit=' + NATIVE_UNIT,
                                                '--description=dev-pair-owned-' + NATIVE_UNIT, '--uid=dp-maint',
                                                '--wait', '--collect', '--property=RuntimeMaxSec=5', sys.executable,
                                                '-c', 'import sys;sys.stdin.read();print("context payload")',
                                                input_text='NONCREDENTIAL-retained-input')
                                preparation.run(sys.executable, '-c', 'print("root wrapper payload")')
                                if app.interrupt_prepare:
                                    raise b.Blocked('fixture post-command prepare interruption')
                        return Preparation()
                app = App(root)
                app.directory('/var/lib/dev-pair', mode=0o755)
                app.state.mkdir(parents=True, mode=0o700)
                (app.state / 'operator-password-set').write_text('fixture only')
                calls = []
                ordinary = manager(original, calls)
                def dispatch(args, **kwargs):
                    if args[0] == '/usr/bin/systemd-run':
                        native_launches.append(args)
                        if app.interrupt_prepare and mode == 'prelaunch-input':
                            path = native_io.STREAM_ROOT / NATIVE_UNIT
                            self.assertEqual((path / 'stdin').read_bytes(), b'NONCREDENTIAL-retained-input')
                            self.assertNotIn('NONCREDENTIAL', (native_io.ROOT / 'records' / (NATIVE_UNIT + '.json')).read_text())
                            raise OSError('fixture prelaunch interruption')
                    return ordinary(args, **kwargs)
                def initialize(retry=False):
                    return app.initialize('/context', CONTEXT, '/upstream', SOURCE, ['192.0.2.9/32'], apply=True, retry=retry)
                with patch.object(b.subprocess, 'Popen', side_effect=dispatch), patch.object(g, 'github_keys', return_value='fixture key'):
                    with self.assertRaises(b.Blocked):
                        initialize()
                    prior = json.loads(app.text(b.STATE + '/initialize.json'))
                    self.assertNotIn(NATIVE_UNIT, prior['native_units'])
                    self.assertTrue(all(__import__('re').fullmatch(r'dev-pair-initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}', value) for value in prior['native_units']))
                    if mode == 'prelaunch-input':
                        self.assertTrue((native_io.STREAM_ROOT / NATIVE_UNIT / 'stdin').exists())
                    else:
                        self.assertGreater(len(prior['native_units']), 0)
                    app.interrupt_prepare = False
                    reconcile = b.Commands.reconcile_native
                    def observe(args, env):
                        callbacks.append(tuple(args))
                        return reconcile(args, env)
                    with patch.object(b.Commands, 'reconcile_native', side_effect=observe):
                        self.assertEqual(initialize(retry=True)['phase'], 'complete')
                    explicit_retry = [args for args in callbacks if '--unit=' + NATIVE_UNIT in args and args[0] != '/usr/bin/systemd-run']
                    self.assertTrue(explicit_retry)
                    self.assertTrue(all('--uid=dp-maint' in args for args in explicit_retry))
                    self.assertFalse((native_io.STREAM_ROOT / NATIVE_UNIT).exists())
                    self.assertEqual(list((native_io.ROOT / 'records').iterdir()), [])
                    recorded = json.loads(app.text(b.STATE + '/initialize.json'))
                    self.assertNotIn(NATIVE_UNIT, recorded['native_units'])

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
            if args[0] != '/usr/bin/systemd-run':
                return manager(original, [])(args, **kwargs)
            ceilings.append(float(next(v.rsplit('=', 1)[1].removesuffix('s') for v in args
                                       if v.startswith('--property=RuntimeMaxSec='))))
            return launch_payload(original, args, kwargs, args[(args.index(sys.executable) if sys.executable in args else args.index('/usr/bin/python3')):])
        with patch.object(b.subprocess, 'Popen', side_effect=spawned):
            with outer.phase(.5, 'outer', native=False):
                with inner.phase(1, 'inner', native=False):
                    self.assertLess(third.limit_timeout(900), .5)
                    third('/usr/bin/systemd-run', '--unit=' + NATIVE_UNIT, '--description=dev-pair-owned-' + NATIVE_UNIT, '--property=RuntimeMaxSec=180',
                          sys.executable, '-c', 'print("local native-argv dispatch only")')
        self.assertEqual(len(ceilings), 1)
        self.assertGreater(ceilings[0], 0)
        self.assertLessEqual(ceilings[0], .5)
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
                    if args[0] != '/usr/bin/systemd-run':
                        return manager(original, [])(args, **kwargs)
                    process = launch_payload(original, args, kwargs, args[(args.index(sys.executable) if sys.executable in args else args.index('/usr/bin/python3')):])
                else:
                    process = original(args, **kwargs)
                processes.append(process)
                return process
            script = ('import os,time,pathlib,sys; pid=os.fork(); '
                      'os._exit(0) if pid else None; time.sleep(.35); '
                      'pathlib.Path(sys.argv[1]).write_text("escaped")')
            run = runner()
            if isinstance(run, g.ProbeCommands):
                run.diagnostic = lambda buffers, status: None
            prefix = ('/usr/bin/systemd-run', '--unit=' + NATIVE_UNIT,
                      '--description=dev-pair-owned-' + NATIVE_UNIT, '--property=RuntimeMaxSec=180') if native else ()
            try:
                with patch.object(b.subprocess, 'Popen', side_effect=spawned), \
                        patch.object(run, 'reconcile_native') as reconcile:
                    with self.assertRaisesRegex(b.Blocked, 'deadline|timed out'):
                        run(*prefix, sys.executable, '-c', script, str(marker), timeout=.2 if native else .1)
                    self.assertEqual(processes[0].poll(), 250 if native else 0)
                    reconcile.assert_called_once()
                    if native:
                        self.assertIn('--unit=' + NATIVE_UNIT, reconcile.call_args.args[0])
                        ceiling = float(next(v.rsplit('=', 1)[1].removesuffix('s') for v in reconcile.call_args.args[0] if v.startswith('--property=RuntimeMaxSec=')))
                        self.assertGreater(ceiling, 0)
                        self.assertLessEqual(ceiling, .2)
                time.sleep(.4)
                self.assertFalse(marker.exists())
            finally:
                for process in processes:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_failed_probe_launcher_with_closed_pipes_cleans_and_retains_exit_status(self):
        original = b.subprocess.Popen
        prefix = ('/usr/bin/systemd-run', '--unit=' + NATIVE_UNIT,
                  '--description=dev-pair-owned-' + NATIVE_UNIT, '--property=RuntimeMaxSec=180')
        for unresolved in (False, True):
            marker = Path(self.tmp.name) / ('closed-pipe-probe-' + str(unresolved))
            processes, records = [], []
            def spawned(args, **kwargs):
                if args[0] != '/usr/bin/systemd-run':
                    return manager(original, [])(args, **kwargs)
                process = launch_payload(original, args, kwargs, args[(args.index(sys.executable) if sys.executable in args else args.index('/usr/bin/python3')):])
                processes.append(process)
                return process
            script = ('import os,time,pathlib,sys; os.write(2,b"public failure fixture\\n"); '
                      'pid=os.fork(); os._exit(9) if pid else None; '
                      'os.close(1); os.close(2); time.sleep(.25); '
                      'pathlib.Path(sys.argv[1]).write_text("escaped")')
            run = g.ProbeCommands()
            run.diagnostic = lambda buffers, status: records.append({'status': status, 'stderr': bytes(buffers['stderr'])})
            try:
                with patch.object(b.subprocess, 'Popen', side_effect=spawned), \
                        patch.object(run, 'reconcile_native', side_effect=b.Blocked('foreign unit preserved') if unresolved else None) as reconcile:
                    with self.assertRaisesRegex(b.Blocked, 'cleanup-unresolved' if unresolved else 'interrupted-or-failed'):
                        run(*prefix, sys.executable, '-c', script, str(marker), timeout=2)
                    self.assertEqual(processes[0].poll(), 9)
                    reconcile.assert_called_once()
                    self.assertEqual(len(records), 1)
                    self.assertEqual(records[0]['status'], 9)
                    self.assertIn(b'public failure fixture', records[0]['stderr'])
                time.sleep(.3)
                self.assertFalse(marker.exists())
            finally:
                for process in processes:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for status in (0, 9):
            records = []
            run = g.ProbeCommands()
            run.diagnostic = lambda buffers, observed: records.append(observed)
            with patch.object(run, 'reconcile_native') as reconcile:
                output = run(sys.executable, '-c', 'import sys;print("allowed fixture");sys.exit(' + str(status) + ')', ok=(0, 9))
                self.assertEqual(output, 'allowed fixture\n')
                self.assertEqual(records, [status])
                reconcile.assert_not_called()

    def test_command_diagnostics_distinguish_accepted_nonzero_without_echoing_argv(self):
        records = []
        run = b.Commands()
        run.current_step = 'host-preflight'
        run.diagnostic = records.append
        value = 'synthetic-secret-argv-sentinel'
        output = run(sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', value, ok=(0, 1))
        self.assertIn(value, output)
        self.assertTrue(records[-1]['accepted_exit'])
        self.assertEqual(records[-1]['outcome'], 'accepted')
        self.assertEqual(records[-1]['allowed_exit_statuses'], [0, 1])
        self.assertNotIn(value, json.dumps(records))
        with self.assertRaises(b.Blocked):
            run(sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', value)
        self.assertFalse(records[-1]['accepted_exit'])
        self.assertEqual(records[-1]['outcome'], 'rejected')
        self.assertEqual(records[-1]['native']['availability'], 'not-controller-owned-or-not-native')
        self.assertNotIn(value, json.dumps(records))
        self.assertEqual(b.Commands.operation_id(('/usr/sbin/getenforce',)), 'selinux-enforcement')
        self.assertEqual(b.Commands.public_operation(('/usr/sbin/getenforce',)), 'selinux-enforcement')
        self.assertIsNone(b.Commands.public_operation(('/usr/sbin/getenforce', value)))
        resolved = ('/usr/bin/systemctl', 'show', '--property=MainPID', '--property=User',
                    '--property=ActiveState', '--property=LoadState', 'systemd-resolved.service')
        self.assertEqual(b.Commands.public_operation(resolved), 'resolved-service-identity')
        self.assertIsNone(b.Commands.public_operation(resolved[:-1] + ('--property=Environment', resolved[-1])))

    def test_native_diagnostic_collected_unit_is_explicitly_unavailable(self):
        unit = 'dev-pair-initialize-prepare-12345678-12345678'
        args = ('--unit=' + unit, '--description=dev-pair-owned-' + unit)
        with patch.object(b.Commands, '__call__', return_value='LoadState=not-found\nActiveState=inactive\n'):
            observed = b.Commands.native_diagnostic(args)
        self.assertEqual(observed['availability'], 'unavailable-collected-or-not-started')
        self.assertNotIn('ExecMainStatus', observed)
        with patch.object(b.Commands, '__call__', return_value='Description=foreign\nLoadState=loaded\nActiveState=failed\n'):
            self.assertEqual(b.Commands.native_diagnostic(args)['availability'], 'ownership-unverified')
        fields = 'Description=dev-pair-owned-' + unit + '\nLoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=7\nEnvironment=synthetic-secret-sentinel\n'
        with patch.object(b.Commands, '__call__', return_value=fields):
            observed = b.Commands.native_diagnostic(args)
        self.assertEqual(observed['ExecMainStatus'], '7')
        self.assertNotIn('synthetic-secret-sentinel', json.dumps(observed))

    def test_source_gate_failure_retains_fixed_stage_without_exception_or_git_output(self):
        preparation = self.app.preparation()
        preparation.prepare_step = 'adapter-source-and-upstream'
        def inputs(*args):
            self.app.source_stage = 'upstream-head-and-bytes'
            raise b.Blocked('synthetic-secret-path-and-raw-exception')
        with patch.object(self.app, 'preparation', return_value=preparation), patch.object(self.app, 'inputs', side_effect=inputs):
            with self.assertRaises(b.Blocked):
                self.initialize()
        record = json.loads(self.app.text(b.STATE + '/initialize.json'))
        self.assertEqual(record['prepare_step'], 'adapter-source-and-upstream')
        self.assertEqual(record['source_verification'], {'stage': 'upstream-head-and-bytes', 'outcome': 'blocked-or-interrupted'})
        self.assertNotIn('synthetic-secret-path', json.dumps(record))
        self.assertIsNone(self.app.run.diagnostic)

    def test_actual_source_check_keeps_commands_limit_dispatch_and_restores_metadata(self):
        run = self.app.run
        self.assertIsInstance(run, g.ProbeCommands)
        previous_metadata = lambda metadata: None
        run.metadata_diagnostic = previous_metadata
        self.assertIsNone(run.diagnostic)
        observed = []
        def source_child(size):
            def inputs(*args):
                # This is the production source_check closure reached from
                # initialize/prepare. Only the external Git boundary is replaced
                # by a real harmless child; no Fedora/source acceptance claimed.
                self.assertIsNone(run.diagnostic)
                self.assertIsNot(run.metadata_diagnostic, previous_metadata)
                value = run(sys.executable, '-c', 'import os;os.write(1,b"s"*' + str(size) + ')', timeout=3)
                observed.append(len(value))
                return {}, {}
            return inputs
        with patch.object(self.app, 'inputs', side_effect=source_child(32)):
            self.assertEqual(self.initialize()['phase'], 'complete')
        self.assertEqual(observed, [32])
        self.assertIs(run.metadata_diagnostic, previous_metadata)
        self.assertIsNone(run.diagnostic)
        with patch.object(self.app, 'inputs', side_effect=source_child(1100000)):
            with self.assertRaisesRegex(b.Blocked, 'output byte budget'):
                self.initialize()
        self.assertEqual(observed, [32])
        self.assertIs(run.metadata_diagnostic, previous_metadata)
        self.assertIsNone(run.diagnostic)
        record = json.loads(self.app.text(b.STATE + '/initialize.json'))
        self.assertEqual(record['prepare'], 'blocked')
        diagnostic = json.loads(self.app.text(b.STATE + '/prepare-diagnostics.json'))
        self.assertFalse(diagnostic['failures'][-1]['accepted_exit'])
        self.assertEqual(diagnostic['failures'][-1]['operation_id'], 'source-git-read')
        self.assertNotIn('stdout_tail', diagnostic['failures'][-1])
        self.assertNotIn('stderr_tail', diagnostic['failures'][-1])

    def test_native_root_unit_is_recorded_before_spawn_and_runs_clean_environment(self):
        run = b.Commands()
        run.native_prefix = 'dev-pair-initialize-prepare-12345678'
        identities = []
        run.native_register = identities.append
        original = b.subprocess.Popen
        def spawned(args, **kwargs):
            if args[0] != '/usr/bin/systemd-run':
                return manager(original, [])(args, **kwargs)
            unit = next(value[7:] for value in args if value.startswith('--unit='))
            self.assertEqual(identities, [unit])
            self.assertIn('--description=dev-pair-owned-' + unit, args)
            self.assertIn('--property=KillMode=control-group', args)
            # Execute the actual fixed env/child tail locally; this proves its
            # environment contract, not a running systemd native-unit boundary.
            position = args.index('/usr/bin/env')
            return launch_payload(original, args, kwargs, args[position:])
        with patch.object(b.subprocess, 'Popen', side_effect=spawned), patch.dict(os.environ, {'OPENAI_API_KEY': 'native-secret-sentinel'}):
            output = run(sys.executable, '-c', 'import os;print(os.getenv("OPENAI_API_KEY"))')
        self.assertEqual(output.strip(), 'None')

    def test_native_ceiling_never_expands_and_cleanup_verifies_exact_description(self):
        native = ('/usr/bin/systemd-run', '--property=RuntimeMaxSec=180', '--unit=' + NATIVE_UNIT,
                  '--description=dev-pair-owned-' + NATIVE_UNIT)
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
        results = ['Description=dev-pair-owned-' + NATIVE_UNIT + '\nActiveState=active\n', '', 'ActiveState=inactive\n']
        with patch.object(b.Commands, '__call__', side_effect=results) as calls:
            b.Commands.reconcile_native(native, {})
            self.assertEqual(calls.call_args_list[1].args, ('/usr/bin/systemctl', 'stop', NATIVE_UNIT))


if __name__ == '__main__':
    unittest.main()
