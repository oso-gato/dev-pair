"""Real private SQLite, leases, subprocess races and fixed local adapter effects."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import session_controller as c
import test_session_controller as f

PATHS=[str(Path(__file__).parent),str(Path(c.__file__).parent)]
def script(body):return 'import sys;sys.path[:0]='+repr(PATHS)+';import test_session_controller as f;import session_controller as c;import time,json,pathlib,os;'+body

class FreezeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.registry=f.make_registry(self.root);self.addCleanup(self.registry.close);self.binding=copy.deepcopy(self.registry.meta['binding'])
    def freeze(self,attempt='freeze-one',generation=0):return self.registry.request_freeze(attempt,generation,self.binding)
    def test_executable_drain_defer_snapshot_abort_then_new_owned_resume(self):
        f.run_fixed(self.registry,self.root)
        other=c.Registry(self.registry.root);self.addCleanup(other.close)
        with self.registry.owner():
            reserved,_=self.registry.reserve('deferred-beta','beta','fixed',time.monotonic()+3)
            receipt=other.request_freeze('freeze-one',0,self.binding)
            self.assertEqual(receipt,other.request_freeze('freeze-one',0,self.binding))
            with self.assertRaisesRegex(ValueError,'owner busy'):other.seal_snapshot(receipt,self.binding)
            with self.assertRaises(c.DispatchFrozen):c.TurnOwner(self.registry,'deferred-beta').launching()
            row=self.registry.row('deferred-beta');self.assertEqual(row['state'],'deferred');self.assertIs(row['launch_handle_observed'],False)
            self.assertEqual(row['cleanup'],'not-launched');self.assertEqual(row['deadline'],reserved['deadline'])
        with self.assertRaisesRegex(ValueError,'frozen'):self.registry.reserve('new','beta','fixed',time.monotonic()+2)
        duplicate,created=self.registry.reserve('deferred-beta','beta','fixed',time.monotonic()-1);self.assertFalse(created);self.assertEqual(duplicate,row)
        with self.assertRaisesRegex(ValueError,'collision'):self.registry.reserve('deferred-beta','beta','changed',time.monotonic()+2)
        snapshot=self.registry.seal_snapshot(receipt,self.binding);self.assertTrue(snapshot['quiescent']);self.assertEqual(len(snapshot['operations']),2)
        self.assertEqual(snapshot['unbound_operations'],['deferred-beta']);self.assertEqual(snapshot['sessions'],[{'logical_session':'alpha','uuid':f.UUID}])
        self.assertEqual(snapshot,self.registry.seal_snapshot(receipt,self.binding))
        before=self.registry.path.read_bytes();observer=c.Observer(self.registry.root)
        try:
            observed=observer.inventory();self.assertEqual(len(observed['operations']),2);self.assertEqual(observed['dispatch']['snapshot']['operation_count'],2)
            with self.assertRaisesRegex(ValueError,'observer'):observer.registry.abort_freeze(receipt,self.binding)
        finally:observer.close()
        self.assertEqual(before,self.registry.path.read_bytes())
        self.registry.abort_freeze(receipt,self.binding);self.assertIsNone(self.registry.inventory()['dispatch']['snapshot'])
        self.registry.abort_freeze(receipt,self.binding)
        result,journey,children=f.run_fixed(self.registry,self.root,phase='resume',expected=f.UUID)
        self.assertEqual(result[0],0);self.assertTrue(all(p.returncode==0 for p in children));self.assertEqual(self.registry.row('deferred-beta'),row)
        self.assertIsNone(self.registry.inventory()['dispatch']['snapshot'])
    def test_stale_tokens_binding_and_reused_attempt_cannot_thaw_later_freeze(self):
        first=self.freeze();self.registry.abort_freeze(first,self.binding)
        second=self.freeze('freeze-one',1);self.assertNotEqual(first['token'],second['token'])
        for token in (first,{**second,'token':'0'*32},{**second,'generation':1}):
            with self.assertRaisesRegex(ValueError,'freeze token'):self.registry.abort_freeze(token,self.binding)
        for key,value in (('source_revision','f'*40),('runtime_sha256','f'*64),('model','other'),('standards_sha','f'*40)):
            with self.assertRaises(ValueError):self.registry.abort_freeze(second,{**self.binding,key:value})
        with self.assertRaises(ValueError):self.freeze('freeze-one',0)
        self.assertEqual(self.registry.inventory()['dispatch']['state'],'frozen')
    def test_unleased_or_lost_reserved_row_cannot_be_retroactively_called_deferred(self):
        self.registry.reserve('unknown','alpha','fixed',time.monotonic()+3)
        receipt=self.freeze()
        with self.registry.owner(),self.assertRaisesRegex(ValueError,'owner mismatch'):self.registry.admit_launch('unknown')
        self.assertEqual(self.registry.row('unknown')['state'],'reserved')
        with self.assertRaisesRegex(ValueError,'draining'):self.registry.seal_snapshot(receipt,self.binding)
        self.registry.uncertain();self.registry.abort_freeze(receipt,self.binding)
        self.assertEqual(self.registry.row('unknown')['state'],'uncertain')
        with self.assertRaisesRegex(ValueError,'owner lease'):self.registry.admit_launch('unknown')
    def test_freeze_persists_across_process_commit_and_owner_loss(self):
        body='r=f.make_registry(sys.argv[1]);owner=r.owner();owner.__enter__();r.reserve("lost","alpha","fixed",time.monotonic()+3);token=r.request_freeze("crash-freeze",0,r.meta["binding"]);print(json.dumps(token),flush=True);os._exit(0)'
        child=subprocess.run([sys.executable,'-c',script(body),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual(child.returncode,0,child.stderr.decode());receipt=json.loads(child.stdout)
        observer=c.Observer(self.registry.root)
        try:self.assertEqual(observer.reattach('lost')['state'],'uncertain');self.assertEqual(observer.inventory()['dispatch']['state'],'frozen')
        finally:observer.close()
        with self.assertRaisesRegex(ValueError,'frozen'):self.registry.reserve('new','beta','fixed',time.monotonic()+2)
        with self.assertRaisesRegex(ValueError,'draining'):self.registry.seal_snapshot(receipt,self.binding)
        self.registry.uncertain();self.assertEqual(self.registry.row('lost')['reason'],'owner-loss')
    def test_actual_owned_child_drains_before_complete_snapshot(self):
        child=subprocess.Popen([sys.executable,'-c',script('f.owner_process(sys.argv[1])'),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            end=time.monotonic()+2
            while time.monotonic()<end:
                row=self.registry.row('turn-alpha-first')
                if row is not None and row['state']=='running':break
                time.sleep(.01)
            self.assertIsNone(child.poll());receipt=self.freeze()
            with self.assertRaisesRegex(ValueError,'owner busy'):self.registry.seal_snapshot(receipt,self.binding)
            (self.root/'observer-released').touch();out,err=child.communicate(timeout=4);self.assertEqual(child.returncode,0,err.decode())
            self.assertEqual((self.root/'progress').read_text(),'one-owned-effect')
            snapshot=self.registry.seal_snapshot(receipt,self.binding);self.assertEqual(snapshot['operations'][0]['cleanup'],'owned-child-reaped')
        finally:
            if child.poll() is None:os.killpg(child.pid,9)
            child.wait(timeout=2);child.stdout.close();child.stderr.close()
    def test_launch_freeze_race_has_one_serial_outcome_and_no_unrecorded_effect(self):
        with self.registry.owner():
            self.registry.reserve('raced','alpha','fixed',time.monotonic()+3)
            body='r=f.make_registry(sys.argv[1]);root=pathlib.Path(sys.argv[1]);(root/"ready").touch();end=time.monotonic()+2\nwhile not (root/"go").exists():\n assert time.monotonic()<end\n time.sleep(.001)\nprint(json.dumps(r.request_freeze("race",0,r.meta["binding"])),flush=True);r.close()'
            freezer=subprocess.Popen([sys.executable,'-c',script(body),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+2
                while not (self.root/'ready').exists():self.assertLess(time.monotonic(),end);time.sleep(.005)
                (self.root/'go').touch();owner=c.TurnOwner(self.registry,'raced');launched=False
                try:owner.launching()
                except c.DispatchFrozen:pass
                else:
                    launched=True;effect=self.root/'effect'
                    payload='import pathlib,json;pathlib.Path('+repr(str(effect))+').write_text("one");[print(json.dumps(r)) for r in '+repr(f.events())+']'
                    child=subprocess.Popen([sys.executable,'-c',payload],stdout=subprocess.PIPE,stderr=subprocess.PIPE);owner.child(child)
                    output,error=child.communicate(timeout=2)
                    for line in output.splitlines():owner.event(line)
                    owner.cleanup(True);owner.finish(child.returncode,True)
                output,error=freezer.communicate(timeout=3);self.assertEqual(freezer.returncode,0,error.decode());receipt=json.loads(output)
                row=self.registry.row('raced');self.assertEqual(row['state'],'completed-turn' if launched else 'deferred');self.assertEqual((self.root/'effect').exists(),launched)
            finally:
                if freezer.poll() is None:freezer.kill()
                freezer.wait(timeout=2);freezer.stdout.close();freezer.stderr.close()
        self.assertEqual(len(self.registry.seal_snapshot(receipt,self.binding)['operations']),1)
    def test_old_version_corrupt_metadata_and_omitted_snapshot_reject_without_reset(self):
        receipt=self.freeze();self.registry.seal_snapshot(receipt,self.binding)
        current=self.registry.dispatch()
        for mutation in ({**current,'extra':True},{**current,'generation':True},{**current,'identity':{**receipt,'binding_sha256':'0'*64}}):
            self.registry.db.execute("UPDATE metadata SET value=? WHERE key='dispatch'",(c.canonical(mutation),))
            with self.assertRaises(ValueError):self.registry.inventory()
        self.registry.db.execute("UPDATE metadata SET value=? WHERE key='dispatch'",(c.canonical(current),))
        path=self.registry.path;self.registry.db.execute('PRAGMA user_version=2');before=path.read_bytes()
        with self.assertRaises(ValueError):c.Registry(self.registry.root)
        self.assertEqual(before,path.read_bytes());self.registry.db.execute('PRAGMA user_version='+str(c.VERSION))
    def test_snapshot_capacity_all_unbound_rows_and_failed_cleanup_cannot_seal(self):
        with self.registry.owner():
            for n in range(c.ROWS):self.registry.reserve('op-'+str(n),'label-'+str(n),'fixed',time.monotonic()+3)
            receipt=self.freeze()
            for n in range(c.ROWS):
                with self.assertRaises(c.DispatchFrozen):self.registry.admit_launch('op-'+str(n))
        snapshot=self.registry.seal_snapshot(receipt,self.binding);self.assertEqual(len(snapshot['operations']),32);self.assertEqual(len(snapshot['unbound_operations']),32)
        self.assertLess(sum(p.stat().st_size for p in self.registry.root.iterdir()),c.BYTES)
        self.assertEqual(self.registry.dispatch()['generation'],1)

    def test_reservation_freeze_real_process_race_is_serial_and_never_admits_after_ack(self):
        body='r=f.make_registry(sys.argv[1]);root=pathlib.Path(sys.argv[1]);(root/"reserve-ready").touch();end=time.monotonic()+2\nwhile not (root/"reserve-go").exists():\n assert time.monotonic()<end\n time.sleep(.001)\ntry:\n row,created=r.reserve("raced-reserve","beta","fixed",time.monotonic()+3);print(json.dumps({"created":created}))\nexcept ValueError:\n print(json.dumps({"created":False}))\nfinally:r.close()'
        child=subprocess.Popen([sys.executable,'-c',script(body),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            end=time.monotonic()+2
            while not (self.root/'reserve-ready').exists():self.assertLess(time.monotonic(),end);time.sleep(.005)
            (self.root/'reserve-go').touch();receipt=self.freeze();output,error=child.communicate(timeout=4)
            self.assertEqual(child.returncode,0,error.decode());outcome=json.loads(output)
            self.assertEqual(self.registry.row('raced-reserve') is not None,outcome['created'])
            with self.assertRaisesRegex(ValueError,'frozen'):self.registry.reserve('after-ack','alpha','fixed',time.monotonic()+2)
            self.assertEqual(self.registry.dispatch()['identity'],receipt)
        finally:
            if child.poll() is None:child.kill()
            child.wait(timeout=2);child.stdout.close();child.stderr.close()
    def test_crash_before_freeze_commit_has_no_false_ack_and_original_dispatch_remains(self):
        body='r=f.make_registry(sys.argv[1]);original=r.store_dispatch\ndef crash(value):\n original(value)\n os._exit(23)\nr.store_dispatch=crash\nr.request_freeze("uncommitted",0,r.meta["binding"])'
        child=subprocess.run([sys.executable,'-c',script(body),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
        self.assertEqual(child.returncode,23,child.stderr.decode());self.assertEqual(child.stdout,b'')
        self.assertEqual(self.registry.inventory()['dispatch']['state'],'open');self.assertEqual(self.registry.dispatch()['generation'],0)
        result,journey,children=f.run_fixed(self.registry,self.root);self.assertEqual(result[0],0);self.assertTrue(all(p.returncode==0 for p in children))
    def test_snapshot_omission_duplication_and_unknown_cleanup_never_certify_quiescence(self):
        f.run_fixed(self.registry,self.root);receipt=self.freeze();self.registry.seal_snapshot(receipt,self.binding);record=self.registry.dispatch()
        for kind in ('omit','duplicate','session','generation','extra'):
            changed=copy.deepcopy(record);snapshot=changed['snapshot']
            if kind=='omit':snapshot['operations']=[];snapshot['sessions']=[]
            if kind=='duplicate':snapshot['operations']*=2
            if kind=='session':snapshot['sessions']=[]
            if kind=='generation':snapshot['registry_generation']+=1
            if kind=='extra':snapshot['unexpected']=True
            self.registry.db.execute("UPDATE metadata SET value=? WHERE key='dispatch'",(c.canonical(changed),))
            with self.assertRaises(ValueError):self.registry.inventory()
        self.registry.db.execute("UPDATE metadata SET value=? WHERE key='dispatch'",(c.canonical(record),))
        self.registry.abort_freeze(receipt,self.binding)
        row=self.registry.row('turn-alpha-first');row.update(state='uncertain',reason='cleanup-unresolved',exit_code=None,capture_complete=None,cleanup='unresolved');row['sequence']+=1
        self.registry.db.execute('UPDATE operations SET body=? WHERE id=?',(c.canonical(row),row['operation']))
        next_freeze=self.freeze('next',1)
        with self.assertRaisesRegex(ValueError,'draining'):self.registry.seal_snapshot(next_freeze,self.binding)
        self.registry.abort_freeze(next_freeze,self.binding);self.assertEqual(self.registry.row(row['operation'])['cleanup'],'unresolved')
    def test_generation_exhaustion_and_foreign_lease_file_do_not_reset_state(self):
        value={'schema':1,'generation':2147483647,'state':'frozen','identity':{'registry_id':self.registry.meta['registry_id'],'attempt':'exhausted','token':'a'*32,'generation':2147483647,'requested_generation':2147483646,'binding_sha256':c.sha(c.canonical(self.binding).encode())},'snapshot':None}
        self.registry.db.execute("UPDATE metadata SET value=? WHERE key='dispatch'",(c.canonical(value),))
        with self.assertRaisesRegex(ValueError,'generation'):self.registry.request_freeze('later',2147483647,self.binding)
        self.assertEqual(self.registry.dispatch(),value)
        lock=self.registry.root/'owner.lock';held=lock.with_name('owner.saved');lock.rename(held);lock.write_bytes(b'');lock.chmod(0o600)
        try:
            with self.assertRaisesRegex(ValueError,'unknown or missing|identity changed'):self.registry.seal_snapshot(value['identity'],self.binding)
        finally:lock.unlink();held.rename(lock)

    def test_failed_child_safe_cleanup_is_required_and_abort_does_not_clear_unknown(self):
        payload='import json,sys;[print(json.dumps(row)) for row in '+repr(f.events())+'];sys.exit(7)'
        with self.assertRaises(ValueError):f.run_fixed(self.registry,self.root,code=payload)
        row=self.registry.row('turn-alpha-first')
        self.assertEqual(row['state'],'failed');self.assertEqual(row['cleanup'],'owned-child-reaped');self.assertEqual(row['exit_code'],7)
        receipt=self.freeze();snapshot=self.registry.seal_snapshot(receipt,self.binding)
        self.assertEqual(snapshot['operations'][0]['state'],'failed')
        self.registry.abort_freeze(receipt,self.binding)
        self.assertEqual(self.registry.row('turn-alpha-first'),row)
    def test_launch_requires_same_lease_and_immutable_deadline_cannot_be_rebound(self):
        with self.registry.owner():row,_=self.registry.reserve('original','alpha','fixed',time.monotonic()+3)
        with self.registry.owner():
            for values in ({'owner_lease':self.registry.owner_token},{'deadline':time.monotonic()+100},{'request_sha256':'0'*64}):
                with self.assertRaisesRegex(ValueError,'immutable'):self.registry.update('original',**values)
            with self.assertRaisesRegex(ValueError,'owner mismatch'):self.registry.update('original',state='launching')
            with self.assertRaisesRegex(ValueError,'launch requires admission'):self.registry.update('original',state='running',launch_handle_observed=True)
        self.assertEqual(self.registry.row('original'),row)
    def test_abort_checks_current_trusted_job_binding_and_rolls_back_on_failure(self):
        receipt=self.freeze();before=self.registry.dispatch()
        job=self.registry.ledger.record('job',self.binding['job_id']);job['selection']['model']='gpt-6.1-sol'
        self.registry.ledger.db.execute('UPDATE records SET body=? WHERE kind=? AND id=?',(json.dumps(job),'job',self.binding['job_id']))
        with self.assertRaisesRegex(ValueError,'selection changed'):self.registry.abort_freeze(receipt,self.binding)
        self.assertEqual(self.registry.dispatch(),before)

    def test_registry_generation_overflow_rolls_back_freeze_acknowledgement(self):
        self.registry.db.execute("UPDATE metadata SET value='2147483647' WHERE key='generation'")
        before=self.registry.dispatch()
        with self.assertRaisesRegex(ValueError,'generation'):self.freeze()
        self.assertEqual(self.registry.dispatch(),before);self.assertEqual(self.registry.inventory()['generation'],2147483647)
