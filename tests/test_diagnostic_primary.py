"""Secondary callback failures never replace execution or cleanup authority."""
import json,subprocess,sys,time,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import bootstrap as b
import gptbox as g
from native_io_fixture import install,manager

class CallbackPrecedenceTests(unittest.TestCase):
    def test_real_direct_matrix_both_callbacks_primary_absent_present(self):
        for probe in (False,True):
            for primary in (False,True):
                for broken in ((True,False),(False,True),(True,True)):
                    run=b.Commands();calls=[]
                    def diagnostic(*args):
                        calls.append('diagnostic')
                        if broken[0]:raise OSError('PRIVATE diagnostic value')
                    def metadata(*args):
                        calls.append('metadata')
                        if broken[1]:raise OSError('PRIVATE metadata value')
                    run.diagnostic=diagnostic;run.metadata_diagnostic=metadata
                    script='raise SystemExit(7)' if primary else 'print("success")'
                    with self.assertRaises(b.Blocked) as seen:run._call(sys.executable,'-c',script,probe=probe)
                    self.assertEqual(set(calls),{'diagnostic','metadata'});self.assertNotIn('PRIVATE',str(seen.exception))
                    self.assertIn('exit 7' if primary else 'required command diagnostics unavailable',str(seen.exception))
    def native_timeout_case(self, *, cleanup, injected=None):
        """Real child/relay/FIFOs; only manager identity and optional failure are synthetic."""
        with tempfile.TemporaryDirectory() as tmp:
            root=install(self,tmp);calls=[];launchers=[];callbacks=[];records=[];owned_at_launch=[]
            dispatch=manager(subprocess.Popen,calls)
            def tracked(args,**kwargs):
                process=dispatch(args,**kwargs)
                if args[0]=='/usr/bin/systemd-run':
                    launchers.append(process)
                    owned_at_launch.append(bool(list((root/'records').iterdir())) and bool(list((root/'streams').iterdir())))
                return process
            run=b.Commands()
            def diagnostic(*values):
                callbacks.append('diagnostic');raise OSError('PRIVATE callback')
            def metadata(record):
                callbacks.append('metadata');records.append(record);raise OSError('PRIVATE callback2')
            run.diagnostic=diagnostic;run.metadata_diagnostic=metadata
            original_interrupt=run.interrupt
            def interrupt(*values):
                original_interrupt(*values)
                if cleanup:raise b.Blocked('PRIVATE unresolved cleanup')
            original_selector=b.selectors.DefaultSelector;injected_once=[]
            def selector_factory():
                selector=original_selector();original_select=selector.select
                def select(*values,**kwargs):
                    if injected is not None and launchers and not injected_once:
                        injected_once.append(True);raise injected
                    return original_select(*values,**kwargs)
                selector.select=select
                return selector
            args=('/usr/bin/systemd-run','--unit=dev-pair-gptbox-'+'a'*64+'.service','--description=dev-pair-owned-dev-pair-gptbox-'+'a'*64+'.service','--wait','--collect','--property=RuntimeMaxSec=3')
            with patch.object(b.subprocess,'Popen',side_effect=tracked),patch.object(b.selectors,'DefaultSelector',side_effect=selector_factory),patch.object(run,'interrupt',side_effect=interrupt) as interrupted,self.assertRaises(b.Blocked) as seen:
                run(*args,sys.executable,'-c','import time;time.sleep(2)',timeout=.25 if injected is None else 3)
            expected={'command deadline exceeded; output withheld','command failed or timed out; output withheld'}
            if cleanup:expected={'native cleanup unresolved; retained ownership record and finite lifetime'}
            elif injected is not None:
                expected={'command deadline exceeded; output withheld' if isinstance(injected,b.Blocked) else 'command failed or timed out; output withheld'}
            self.assertIn(str(seen.exception),expected);self.assertNotIn('PRIVATE',str(seen.exception))
            self.assertEqual(len(launchers),1);self.assertEqual(owned_at_launch,[True]);interrupted.assert_called_once()
            self.assertTrue(any(args[:2]==('/usr/bin/systemctl','show') for args in calls))
            self.assertIs(interrupted.call_args.args[0],launchers[0])
            self.assertIsNotNone(launchers[0].returncode)
            self.assertTrue(launchers[0].stdout.closed);self.assertTrue(launchers[0].stderr.closed)
            self.assertEqual(sorted(callbacks),['diagnostic','metadata'])
            self.assertTrue(records[0]['native_failure']['launcher_handle_observed'])
            self.assertTrue(records[0]['native_failure']['status_sampled_before_interrupt'])
            self.assertEqual(list((root/'records').iterdir()),[])
            self.assertEqual(list((root/'streams').iterdir()),[])
            if injected is not None:self.assertEqual(injected_once,[True])
    def test_real_native_timeout_cleanup_precedence_and_no_public_callback_values(self):
        for cleanup in (False,True):
            with self.subTest(cleanup=cleanup):self.native_timeout_case(cleanup=cleanup)
    def test_injected_native_primary_and_cleanup_precedence_after_real_launch(self):
        for kind in ('deadline','wait-timeout'):
            for cleanup in (False,True):
                with self.subTest(primary=kind,cleanup=cleanup):
                    primary=b.Blocked('command deadline exceeded; output withheld') if kind=='deadline' else subprocess.TimeoutExpired('PRIVATE argv',3)
                    self.native_timeout_case(cleanup=cleanup,injected=primary)
    def test_caller_active_exception_does_not_hide_callback_only_failure(self):
        run=b.Commands();run.metadata_diagnostic=lambda *a:(_ for _ in ()).throw(OSError('PRIVATE'))
        try:raise ValueError('outer caller exception')
        except ValueError:
            with self.assertRaisesRegex(b.Blocked,'required command diagnostics unavailable'):run(sys.executable,'-c','pass')

class PreparedCompletionTests(unittest.TestCase):
    def test_corrupt_and_unknown_records_reject_before_adapter_effects(self):
        import test_gptbox as fixture
        for key,value in (('kind','unknown'),('schema',999),('codex_sha256','0'*64),('base_image','sha256:'+'0'*64),('runtime_user','root'),('image_id',None),('fedora_base',None)):
            case=fixture.GptboxTests();case.setUp()
            try:
                app=case.app;path=g.STATE+'/gptbox-image.json';record=json.loads(app.text(path));record[key]=value
                app.atomic(path,json.dumps(record)+'\n',expected=app.text(path));before=len(case.engine.calls)
                with self.assertRaises(b.Blocked):case.assemble()
                self.assertEqual(len(case.engine.calls),before)
            finally:case.doCleanups()
    def test_supported_minimal_preserves_original_id_and_full_reapply(self):
        import test_gptbox as fixture
        case=fixture.GptboxTests();case.setUp()
        try:
            original=case.app.text(g.STATE+'/gptbox-image.json');case.assemble()
            self.assertEqual(case.app.text(g.STATE+'/gptbox-image.json'),original)
            before=sum('build' in args for args,_ in case.engine.calls);case.assemble()
            self.assertEqual(sum('build' in args for args,_ in case.engine.calls),before)
        finally:case.doCleanups()
    def test_failed_probe_append_cannot_mutate_old_history(self):
        import test_gptbox as fixture
        import test_maintenance_launcher_summary as native
        case=native.MaintenanceProcessTests();case.setUp();f=fixture.GptboxTests();f.setUp()
        try:
            app=f.app;app.target=g.ROOT+'/'+native.CONTEXT;app.scripts=app.inputs(f.context,native.CONTEXT,'/upstream','d'*40)[1];app.setup_executor()
            app.executor=[v.replace(str(f.root),'',1) for v in app.executor];app.wrapper='/usr/local/libexec/dev-pair-gptbox/bin/podman';app.run=g.ProbeCommands();app.image_phase_active=True
            app.directory(app.target,mode=0o755);old={'recent':[{'status':77,'old':'untouched'}],'failures':[{'status':77,'old':'untouched'}]};app.record('diagnostics',old)
            before=app.text(app.target+'/diagnostics.json');original=app.record
            def broken(name,value):
                if name=='diagnostics':raise OSError('PRIVATE diagnostic append')
                return original(name,value)
            work='/var/lib/dev-pair/artifacts/gptbox-adapter/'+native.CONTEXT+'/image-work'
            args=('/usr/bin/env','TMPDIR='+work+'/image-copy',app.wrapper,'load','--input',work+'/verification-work/dev-pair-fedora-abc123_4/base.oci.tar')
            with patch.object(app,'record',side_effect=broken),patch.object(b.subprocess,'Popen',side_effect=case.dispatch(native.summary())),self.assertRaises(b.Blocked):app.execute(*args,timeout=3)
            self.assertEqual(app.text(app.target+'/diagnostics.json'),before)
        finally:f.doCleanups();case.doCleanups()
