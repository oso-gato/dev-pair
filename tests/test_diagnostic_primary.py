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
    def test_real_native_timeout_cleanup_precedence_and_no_public_callback_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=install(self,tmp);calls=[];dispatch=manager(subprocess.Popen,calls)
            args=('/usr/bin/systemd-run','--unit=dev-pair-gptbox-'+'a'*64+'.service','--description=dev-pair-owned-dev-pair-gptbox-'+'a'*64+'.service','--wait','--collect','--property=RuntimeMaxSec=3')
            for cleanup in (False,True):
                run=b.Commands();run.diagnostic=lambda *a:(_ for _ in ()).throw(OSError('PRIVATE callback'))
                run.metadata_diagnostic=lambda *a:(_ for _ in ()).throw(OSError('PRIVATE callback2'))
                original=run.interrupt
                def interrupt(*values):
                    original(*values)
                    if cleanup:raise b.Blocked('PRIVATE unresolved cleanup')
                with patch.object(b.subprocess,'Popen',side_effect=dispatch),patch.object(run,'interrupt',side_effect=interrupt),self.assertRaises(b.Blocked) as seen:
                    run(*args,sys.executable,'-c','import time;time.sleep(2)',timeout=.25)
                self.assertNotIn('PRIVATE',str(seen.exception));self.assertIn('cleanup unresolved' if cleanup else 'command failed or timed out',str(seen.exception))
                self.assertEqual(list((root/'records').iterdir()),[])
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
