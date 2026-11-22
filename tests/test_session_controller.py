"""Real local SQLite/children/observers; selection and endpoint remain synthetic."""
import copy
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import session_controller as c
import codex_sessions as s
import codex_tools as t

UUID='11111111-1111-7111-8111-111111111111';OTHER='22222222-2222-7222-8222-222222222222'
NONCE='a'*32
RECEIPT={'startup':{'version':1,'standards_sha':c.STANDARDS,'model_consumption_verified':False,'delivery':'controller-hash-receipt-only','documents':{**{'repository/'+name:'a'*64 for name in c.PUBLIC},**{'shared/'+name:value for name,value in c.SHARED.items()}}},'identity':{key:'a'*64 for key in ('source_sha256','runtime_sha256','binary_sha256','policy_sha256','layout_sha256')}}
RECEIPT['identity']['source_revision']='b'*40

def make_registry(root):return s.fixture_registry(root,copy.deepcopy(RECEIPT))

def events(ident=UUID):
    return [{'type':'thread.started','thread_id':ident},{'type':'turn.started'},
            {'type':'item.completed','item':{'id':'owned-marker','type':'agent_message','text':'finite synthetic turn'}},{'type':'turn.completed','usage':{name:0 for name in ('input_tokens','cached_input_tokens','cache_write_input_tokens','output_tokens','reasoning_output_tokens')}}]

class Journey:
    negative=False
    def __init__(self,registry,end,phase='first',expected=None,label='alpha'):
        self.controller_registry=registry;self.controller_port=12345;self.nonce=NONCE;self.action_end=end;self.error=None
        self.turn={'label':label,'phase':phase,'expected_uuid':expected};self.observed=[];self.published=[];self.cleared=0
    def observe_cli(self,raw):self.observed.append(json.loads(raw))
    def publish_child(self,process):self.published.append(process)
    def clear_child(self):self.cleared+=1

def run_fixed(registry,root,rows=None,phase='first',expected=None,label='alpha',code=None,end=None):
    end=end or time.monotonic()+3;journey=Journey(registry,end,phase,expected,label);launched=[]
    original=subprocess.Popen
    def launch(argv,**kwargs):
        assert argv==s.cli_args(12345,s.prompt(label,phase,NONCE),expected)
        body=code if code is not None else 'import json;rows='+repr(events() if rows is None else rows)+';[print(json.dumps(row),flush=True) for row in rows]'
        process=original([sys.executable,'-c',body],**kwargs);launched.append(process);return process
    result=s.run_turn(s.cli_args(12345,s.prompt(label,phase,NONCE),expected),journey,t.Meter(),end,popen=launch)
    return result,journey,launched

def owner_process(root):
    root=Path(root);registry=make_registry(root)
    try:
        code=('import json,time,pathlib\nrows='+repr(events())+'\nprint(json.dumps(rows[0]),flush=True)\nprint(json.dumps(rows[1]),flush=True)\n'
              'release=pathlib.Path('+repr(str(root/'observer-released'))+')\nend=time.monotonic()+2\n'
              'while not release.exists():\n assert time.monotonic()<end\n time.sleep(.01)\n'
              'pathlib.Path('+repr(str(root/'progress'))+').write_text("one-owned-effect")\n'
              'print(json.dumps(rows[2]),flush=True)\nprint(json.dumps(rows[3]),flush=True)\n')
        run_fixed(registry,root,code=code)
    finally:registry.close()

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.registry=make_registry(self.root);self.addCleanup(self.registry.close)
    def test_real_fixed_turn_and_explicit_resume_with_new_current_checkpoint(self):
        result,journey,children=run_fixed(self.registry,self.root)
        self.assertEqual(result[0],0);self.assertEqual(journey.published,children);self.assertEqual(journey.cleared,1)
        self.assertTrue(all(p.returncode==0 for p in children));first=self.registry.row('turn-alpha-first')
        self.assertEqual(first['state'],'completed-turn');self.assertEqual(first['uuid'],UUID)
        cp=self.registry.ledger.record('checkpoint','fixed-session-inputs');cp.update(checkpoint_id='verified-next',evidence=['sha256:'+'c'*64])
        self.registry.ledger.checkpoint(cp)
        run_fixed(self.registry,self.root,phase='resume',expected=UUID)
        resumed=self.registry.row('turn-alpha-resume');self.assertEqual(resumed['checkpoint_id'],'verified-next');self.assertNotEqual(first['checkpoint_sha256'],resumed['checkpoint_sha256'])
        self.assertEqual(resumed['uuid'],UUID);self.assertEqual(len(self.registry.inventory()['sessions']),1)
    def test_duplicate_is_observe_only_collision_and_explicit_selection_rejection(self):
        run_fixed(self.registry,self.root)
        observer=c.Observer(self.registry.root);self.addCleanup(observer.close)
        before=observer.reattach('turn-alpha-first')
        with self.assertRaises(c.ExistingOperation) as observed:run_fixed(self.registry,self.root)
        self.assertEqual(observed.exception.observation,before)
        self.assertEqual(observer.reattach('turn-alpha-first'),before)
        with self.assertRaisesRegex(ValueError,'collision'):self.registry.reserve('turn-alpha-first','alpha','CHANGED',time.monotonic()+2)
        job=self.registry.ledger.record('job','offline-session-fixture');job['selection']['effort']='high'
        self.registry.ledger.db.execute('UPDATE records SET body=? WHERE kind=? AND id=?',(json.dumps(job),'job','offline-session-fixture'))
        with self.assertRaisesRegex(ValueError,'selection changed'):self.registry.reserve('new','beta','fixed',time.monotonic()+2)
    def test_active_uncertain_and_idle_sessions_all_in_inventory(self):
        run_fixed(self.registry,self.root)
        with self.registry.owner():self.registry.reserve('pending','beta','fixed',time.monotonic()+3)
        observer=c.Observer(self.registry.root);self.addCleanup(observer.close)
        self.assertEqual(observer.reattach('pending')['state'],'uncertain')
        self.assertEqual([r for r in observer.inventory()['operations'] if r['operation']=='pending'][0]['state'],'uncertain')
        self.registry.uncertain()
        with self.assertRaisesRegex(ValueError,'active or uncertain'):self.registry.reserve('new','beta','fixed',time.monotonic()+2)
        inventory=observer.inventory();self.assertEqual(len(inventory['operations']),2);self.assertEqual(inventory['sessions'],[{'logical_session':'alpha','uuid':UUID}])
        with self.assertRaisesRegex(ValueError,'observer'):observer.registry.reserve('write','beta','x',time.monotonic()+2)
    def test_wrong_missing_duplicate_fallback_order_error_and_partial_events_reject(self):
        variants=[events(OTHER),events()[1:],events()[:1]+events(),[events()[1],events()[0],*events()[2:]],
                  [*events()[:-1],{'type':'error','message':'SENTINEL secret'}],
                  [*events()[:-1],{'type':'unknown'}],events()[:-1],
                  [*events()[:2],{'type':'item.completed','item':{'id':'x','type':'agent_message','text':123}},events()[-1]],
                  [*events()[:2],{'type':'turn.completed','usage':{'input_tokens':True}}]]
        # Start uses an independently bound UUID only on resume.
        for index,rows in enumerate(variants):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as tmp:
                registry=make_registry(tmp)
                try:
                    if index==0:
                        run_fixed(registry,tmp);kwargs={'phase':'resume','expected':UUID}
                    else:kwargs={}
                    with self.assertRaises(ValueError):run_fixed(registry,tmp,rows=rows,**kwargs)
                    row=registry.row('turn-alpha-resume' if index==0 else 'turn-alpha-first');self.assertEqual(row['state'],'uncertain')
                    self.assertNotIn('SENTINEL',c.canonical(registry.inventory()))
                finally:registry.close()
    def test_partial_oversize_deadline_cleanup_and_original_budget(self):
        for kind,code in [('partial','print("{}",end="")'),('oversize','print("x"*262145)'),('deadline','import time;time.sleep(2)')]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                registry=make_registry(tmp)
                try:
                    with patch.object(t,'stop',wraps=t.stop) as stopped,self.assertRaises(ValueError):run_fixed(registry,tmp,code=code,end=time.monotonic()+.25)
                    stopped.assert_called_once();child=stopped.call_args.args[0]
                    self.assertIsNotNone(child.returncode);self.assertTrue(child.stdout.closed and child.stderr.closed)
                    row=registry.row('turn-alpha-first');self.assertEqual(row['state'],'uncertain');deadline=row['deadline']
                    observed=c.Observer(registry.root)
                    try:self.assertEqual(observed.reattach(row['operation'])['deadline'],deadline)
                    finally:observed.close()
                finally:registry.close()
    def test_same_cwd_distinct_uuid_collision_blocks(self):
        run_fixed(self.registry,self.root)
        with self.assertRaisesRegex(ValueError,'collision'):run_fixed(self.registry,self.root,label='beta')
        self.assertEqual(len(self.registry.inventory()['operations']),2)
    def test_fixed_adapter_rejects_submitted_argv_before_reservation_or_launch(self):
        end=time.monotonic()+2;journey=Journey(self.registry,end)
        with self.assertRaisesRegex(ValueError,'fixed session adapter'):
            s.run_turn(['/bin/sh','-c','SENTINEL'],journey,t.Meter(),end,popen=lambda *a,**k:self.fail('launched'))
        self.assertEqual(self.registry.inventory()['operations'],[])
    def test_private_symlink_corrupt_schema_and_oversize_reject(self):
        for kind in ('symlink','mode','version','unknown-file','corrupt','oversize'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                reg=make_registry(tmp);path=reg.root/'registry.sqlite3';root=reg.root;reg.close()
                if kind=='symlink':path.unlink();path.symlink_to('/dev/null')
                if kind=='mode':path.chmod(0o644)
                if kind=='version':
                    db=sqlite3.connect(path);db.execute('PRAGMA user_version=99');db.close()
                if kind=='unknown-file':(root/'foreign').write_text('SENTINEL')
                if kind=='corrupt':path.write_bytes(b'SENTINEL corrupt')
                if kind=='oversize':path.write_bytes(b'x'*(c.BYTES+1))
                with self.assertRaises((ValueError,sqlite3.Error)):c.Observer(root)
    def test_startup_receipt_private_hashes_only_and_missing_mismatch(self):
        repo=self.root/'repo';cache=self.root/'cache';repo.mkdir();cache.mkdir()
        for name in c.PUBLIC:(repo/name).write_text('synthetic public startup')
        for name in c.SHARED:(cache/name).write_text('SENTINEL private synthetic startup')
        expected={name:c.sha((cache/name).read_bytes()) for name in c.SHARED}
        with patch.object(c,'SHARED',expected):
            receipt=c.startup_receipt(repo,cache);self.assertFalse(receipt['model_consumption_verified']);self.assertNotIn('SENTINEL',c.canonical(receipt))
            (cache/'GOVERNANCE.md').write_text('changed')
            with self.assertRaisesRegex(ValueError,'mismatch'):c.startup_receipt(repo,cache)
            (cache/'GOVERNANCE.md').unlink()
            with self.assertRaisesRegex(ValueError,'unavailable'):c.startup_receipt(repo,cache)
    def test_observer_process_disconnect_child_progress_and_reattach(self):
        # A separate owner executes the fixed adapter; observer exits while its
        # actual child continues. The test parent only owns/reaps the owner.
        self.registry.close()
        script='import sys;sys.path[:0]='+repr([str(Path(__file__).parent),str(Path(c.__file__).parent)])+';import test_session_controller as f;f.owner_process(sys.argv[1])'
        owner=subprocess.Popen([sys.executable,'-c',script,str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            end=time.monotonic()+4;before=None
            while time.monotonic()<end:
                observer=c.Observer(self.root/'session-registry')
                try:
                    try:before=observer.reattach('turn-alpha-first')
                    except ValueError:pass
                finally:observer.close()
                if before and before['uuid']==UUID:break
                time.sleep(.02)
            self.assertIsNotNone(before);self.assertEqual(before['uuid'],UUID)
            raw=subprocess.check_output([sys.executable,str(Path(c.__file__)),'--registry',str(self.root/'session-registry'),'--operation','turn-alpha-first'],timeout=2)
            self.assertEqual(json.loads(raw)['uuid'],UUID)
            self.assertFalse((self.root/'progress').exists())
            # The exited observer cannot unblock or stop the child; only this
            # trusted test release lets the already-owned child advance.
            (self.root/'observer-released').write_text('observer has exited')
            stdout,stderr=owner.communicate(timeout=3);self.assertEqual(owner.returncode,0,stderr.decode())
            self.assertEqual((self.root/'progress').read_text(),'one-owned-effect')
            observer=c.Observer(self.root/'session-registry')
            try:after=observer.reattach('turn-alpha-first')
            finally:observer.close()
            self.assertEqual(after['uuid'],before['uuid']);self.assertEqual(after['operation'],before['operation']);self.assertGreater(after['sequence'],before['sequence']);self.assertEqual(after['state'],'completed-turn')
        finally:
            (self.root/'observer-released').touch()
            try:owner.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                os.killpg(owner.pid,signal.SIGKILL);owner.communicate(timeout=2)

    def test_transaction_dedupe_competing_processes_and_active_session_exclusion(self):
        script='import sys,time;sys.path[:0]='+repr([str(Path(__file__).parent),str(Path(c.__file__).parent)])+';import test_session_controller as f;r=f.make_registry(sys.argv[1]);row,created=r.reserve("competing","alpha","fixed",time.monotonic()+3);print(created);r.close()'
        children=[subprocess.Popen([sys.executable,'-c',script,str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        outputs=[]
        for child in children:
            stdout,stderr=child.communicate(timeout=4);self.assertEqual(child.returncode,0,stderr.decode());outputs.append(stdout.strip())
        self.assertEqual(sorted(outputs),[b'False',b'True']);self.assertEqual(len(self.registry.inventory()['operations']),1)
        with self.assertRaisesRegex(ValueError,'active or uncertain'):self.registry.reserve('second','alpha','fixed',time.monotonic()+2)

    def test_owner_death_after_reservation_never_replays_or_signals_recorded_pid(self):
        script='import os,sys,time;sys.path[:0]='+repr([str(Path(__file__).parent),str(Path(c.__file__).parent)])+';import test_session_controller as f;r=f.make_registry(sys.argv[1]);owner=r.owner();owner.__enter__();r.reserve("turn-alpha-first","alpha",f.s.prompt("alpha","first",f.NONCE),time.monotonic()+3);os._exit(0)'
        owner=subprocess.Popen([sys.executable,'-c',script,str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        owner.communicate(timeout=3);self.assertEqual(owner.returncode,0)
        observer=c.Observer(self.registry.root)
        try:
            self.assertEqual(observer.reattach('turn-alpha-first')['state'],'uncertain')
            inventory=observer.inventory();self.assertEqual(inventory['operations'][0]['state'],'uncertain')
            self.assertEqual(inventory['operations'][0]['uuid'],None)
            with patch.object(c.os,'kill',side_effect=AssertionError('PID authority forbidden')):
                self.assertEqual(observer.reattach('turn-alpha-first')['reason'],'owner-loss')
        finally:observer.close()
        with self.assertRaisesRegex(ValueError,'observe existing'):run_fixed(self.registry,self.root)
        self.assertEqual(self.registry.row('turn-alpha-first')['state'],'uncertain')

    def test_checkpoint_target_and_binding_changes_reject_before_launch(self):
        for field,value in [('model','gpt-6.1'),('runtime_sha256','f'*64),('provider','other'),('verification','verified')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                registry=make_registry(tmp)
                try:
                    job=registry.ledger.record('job','offline-session-fixture');job['selection'][field]=value
                    registry.ledger.db.execute('UPDATE records SET body=? WHERE kind=? AND id=?',(json.dumps(job),'job','offline-session-fixture'))
                    with self.assertRaises(ValueError):run_fixed(registry,tmp)
                    self.assertEqual(registry.inventory()['operations'],[])
                finally:registry.close()
        cp=self.registry.ledger.record('checkpoint','fixed-session-inputs');cp['candidate']['source_revision']='e'*40
        self.registry.ledger.db.execute('UPDATE records SET body=? WHERE kind=? AND id=?',(json.dumps(cp),'checkpoint','fixed-session-inputs'))
        with self.assertRaisesRegex(ValueError,'target changed'):run_fixed(self.registry,self.root)

    def test_row_and_private_bounds_and_no_secret_prompt_retention(self):
        with self.registry.owner():
            self.registry.reserve('private','alpha','SENTINEL secret prompt',time.monotonic()+3)
        self.assertNotIn(b'SENTINEL',self.registry.path.read_bytes())
        original=self.registry.row('private')
        for value in (True,0,'false'):
            row=copy.deepcopy(original);row['capture_complete']=value
            if value is True:continue
            self.registry.db.execute('UPDATE operations SET body=? WHERE id=?',(json.dumps(row),'private'))
            with self.assertRaises(ValueError):self.registry.inventory()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'incomplete';root.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError,'incomplete'):c.Registry(root,copy.deepcopy(self.registry.meta['binding']))


    def test_bounded_complete_unbound_inventory_and_duplicate_never_resets_deadline(self):
        with self.registry.owner():
            for index in range(c.ROWS):self.registry.reserve('reserved-'+str(index),'session-'+str(index),'fixed',time.monotonic()+2)
            with self.assertRaisesRegex(ValueError,'row bound'):self.registry.reserve('overflow','new','fixed',time.monotonic()+2)
        before=self.registry.row('reserved-0')
        row,created=self.registry.reserve('reserved-0','session-0','fixed',time.monotonic()-1)
        self.assertFalse(created);self.assertEqual(row,before)
        observer=c.Observer(self.registry.root)
        try:
            value=observer.inventory();self.assertEqual(len(value['operations']),c.ROWS)
            self.assertTrue(all(r['state']=='uncertain' and r['uuid'] is None for r in value['operations']))
            self.assertLessEqual(len(c.canonical(value).encode()),65536)
        finally:observer.close()

    def test_descriptor_identity_hardlink_and_private_root_rejection(self):
        old=self.registry.root;held=old.with_name('old-owned');old.rename(held);old.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'directory changed'):self.registry.inventory()
        self.assertEqual(list(old.iterdir()),[])
        self.registry.close()
        for variant in ('root-mode','hardlink','missing-lock'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as tmp:
                registry=make_registry(tmp);root=registry.root;registry.close()
                if variant=='root-mode':root.chmod(0o755)
                if variant=='hardlink':os.link(root/'registry.sqlite3',Path(tmp)/'extra-link')
                if variant=='missing-lock':(root/'owner.lock').unlink()
                with self.assertRaises(ValueError):c.Observer(root)

    def test_error_exit_and_cleanup_uncertainty_preserve_first_primary(self):
        with self.assertRaisesRegex(ValueError,'incomplete'):run_fixed(self.registry,self.root,code='raise SystemExit(1)')
        failed=self.registry.row('turn-alpha-first');self.assertEqual(failed['state'],'failed');self.assertEqual(failed['exit_code'],1)
        for primary in (False,True):
            with self.subTest(primary=primary),tempfile.TemporaryDirectory() as tmp:
                registry=make_registry(tmp);original=t.stop
                def stop(process):
                    original(process);raise OSError('SENTINEL cleanup detail')
                try:
                    with patch.object(t,'stop',side_effect=stop),self.assertRaises((ValueError,OSError)) as seen:
                        run_fixed(registry,tmp,code='print("{}",end="")' if primary else None)
                    if primary:self.assertIn('truncated',str(seen.exception))
                    self.assertNotIn('SENTINEL',str(seen.exception))
                    row=registry.row('turn-alpha-first');self.assertEqual(row['cleanup'],'unresolved');self.assertEqual(row['state'],'uncertain')
                    self.assertNotIn('SENTINEL',c.canonical(registry.inventory()))
                finally:registry.close()


    def test_launch_publication_and_terminal_commit_windows_retain_uncertainty(self):
        for stage in ('spawn','publication','terminal'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as tmp:
                registry=make_registry(tmp)
                try:
                    if stage=='spawn':
                        end=time.monotonic()+2;journey=Journey(registry,end)
                        with self.assertRaises(OSError):s.run_turn(s.cli_args(12345,s.prompt('alpha','first',NONCE)),journey,t.Meter(),end,popen=lambda *a,**k:(_ for _ in ()).throw(OSError('synthetic spawn uncertainty')))
                    elif stage=='publication':
                        with patch.object(Journey,'publish_child',side_effect=ValueError('publication unavailable')),patch.object(t,'stop',wraps=t.stop) as stopped,self.assertRaisesRegex(ValueError,'publication'):run_fixed(registry,tmp)
                        stopped.assert_called_once();self.assertIsNotNone(stopped.call_args.args[0].returncode)
                    else:
                        original=registry.update
                        def update(operation,**values):
                            if values.get('state')=='completed-turn':raise OSError('SENTINEL record failure')
                            return original(operation,**values)
                        with patch.object(registry,'update',side_effect=update),self.assertRaisesRegex(ValueError,'terminal record unavailable'):run_fixed(registry,tmp)
                    row=registry.row('turn-alpha-first');self.assertEqual(row['state'],'uncertain')
                    self.assertEqual(row['launch_handle_observed'],None if stage=='spawn' else True)
                    self.assertNotIn('SENTINEL',c.canonical(registry.inventory()))
                finally:registry.close()

    def test_bad_startup_receipt_blocks_before_private_state_or_launch(self):
        value=copy.deepcopy(RECEIPT);value['startup']['documents'].pop('shared/GOVERNANCE.md')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'document receipt'):s.fixture_registry(tmp,value)
            self.assertEqual(list(Path(tmp).iterdir()),[])
        before=self.registry.path.read_bytes();observer=c.Observer(self.registry.root)
        try:observer.inventory()
        finally:observer.close()
        self.assertEqual(self.registry.path.read_bytes(),before)
