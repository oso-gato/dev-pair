"""Complete synthetic startup bytes through real helper and fixed request loop."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import startup_delivery as d
import codex_sessions as s
import codex_tools as t
import test_codex_sessions as f

REV='a'*40

def managed(corpus,durable=False):
    item={'type':'message','role':'developer','id':'msg_'+f.IDS['alpha'],
          'content':[{'type':'input_text','text':d.rendered(corpus)}],
          s.METADATA:{'turn_id':f.IDS['beta'],'create_time':1700000000.25,'content_item_kinds':[d.KIND]}}
    if durable:item[s.METADATA]['content_item_metadata']=[{'provenance':{'type':'developer_instructions','from_additional_requirements':True}}]
    return item

class StartupTests(unittest.TestCase):
    def setUp(self):
        self.fixture=f.SessionsTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.corpus=d.synthetic(REV);self.docs=self.corpus.stage(self.root/'docs')
        self.j=s.Journey(self.root,time.monotonic()+10,t.Meter(),f.NONCE,startup_corpus=self.corpus);self.fixture.j=self.j
    def helper(self):
        # Only namespace mapping is injected; the real fixed helper loads all files.
        code='import sys;sys.path.insert(0,sys.argv[1]);import startup_delivery as d;d.ROOT=sys.argv[2];raise SystemExit(d.emit_fixed())'
        result=subprocess.run([sys.executable,'-c',code,str(Path(d.__file__).parent),str(self.docs)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2)
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stdout,self.corpus.output()+b'\n');return result.stdout.decode()
    def begin(self,label='alpha'):
        self.fixture.observed(label);return [managed(self.corpus),f.message(s.prompt(label,'first',f.NONCE))]
    def deliver(self,label='alpha'):
        inputs=self.begin(label);self.j.request(f.body(inputs));self.assertIsNone(self.j.turn['issued'])
        issued=copy.deepcopy(self.j.turn['startup_issued']);output={'type':'function_call_output','call_id':issued['call_id'],'output':f.terminal(self.helper())}
        inputs += [issued,output];self.j.request(f.body(inputs));return inputs
    def finish_first(self,label='alpha'):
        inputs=self.deliver(label);work=copy.deepcopy(self.j.turn['issued']);actual=self.fixture.run_action(work)
        output={'type':'function_call_output','call_id':work['call_id'],'output':f.terminal(actual)}
        self.j.request(f.body(inputs+[work,output]));self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        return inputs+[work,output]
    def test_complete_real_helper_bytes_then_work_and_exact_resume_without_second_read(self):
        original=self.finish_first();retained=copy.deepcopy(self.j.startup_records['alpha'])
        self.assertEqual(retained['issued']['call_id'],'startup-alpha');self.assertEqual(s.marker(self.root,'alpha',('first',),f.NONCE)['lines'],1)
        self.fixture.observed('alpha','resume');inputs=original+[f.message(s.prompt('alpha','resume',f.NONCE))]
        self.j.request(f.body(inputs));self.assertEqual(self.j.turn['issued']['call_id'],'session-alpha-resume');self.assertEqual(self.j.startup_records['alpha'],retained)
        work=copy.deepcopy(self.j.turn['issued']);actual=self.fixture.run_action(work);output={'type':'function_call_output','call_id':work['call_id'],'output':f.terminal(actual)}
        self.j.request(f.body(inputs+[work,output]));self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        self.assertEqual(s.marker(self.root,'alpha',('first','resume'),f.NONCE)['lines'],2)
    def test_missing_duplicate_changed_role_or_instruction_never_issues_work(self):
        for change in ('missing','duplicate','changed','role','metadata','id'):
            with self.subTest(change=change):
                inputs=self.begin();before=copy.deepcopy(self.j.entries)
                if change=='missing':inputs=inputs[1:]
                if change=='duplicate':inputs.insert(0,copy.deepcopy(inputs[0]))
                if change=='changed':inputs[0]['content'][0]['text']+='altered'
                if change=='role':inputs[0]['role']='user'
                if change=='metadata':inputs[0][s.METADATA]['unknown']='SENTINEL'
                if change=='id':inputs[0]['id']='msg_input_'+f.IDS['alpha']
                with self.assertRaises(ValueError):self.j.request(f.body(inputs))
                self.assertIsNone(self.j.turn['issued']);self.assertEqual(self.j.entries,before)
    def test_partial_forged_reordered_or_wrong_causal_pair_rejects_before_action(self):
        for change in ('truncated','changed-body','wrong-id','duplicate','order','wrong-command','managed-order'):
            with self.subTest(change=change):
                inputs=self.begin();self.j.request(f.body(inputs));issued=copy.deepcopy(self.j.turn['startup_issued'])
                result=self.corpus.output().decode()+'\n'
                if change=='truncated':result=result[:-20]
                if change=='changed-body':result=result.replace('Synthetic','Changed',1)
                output={'type':'function_call_output','call_id':issued['call_id'],'output':f.terminal(result)}
                if change=='wrong-id':output['call_id']='unissued'
                if change=='wrong-command':issued['arguments']='{}'
                history=inputs+[issued,output]
                if change=='duplicate':history.append(copy.deepcopy(output))
                if change=='order':history=inputs+[output,issued]
                if change=='managed-order':history[0],history[1]=history[1],history[0]
                with self.assertRaises(ValueError):self.j.request(f.body(history))
                self.assertIsNone(self.j.turn['issued']);self.assertFalse(self.j.startup_records);self.assertFalse((self.root/'job/src/session-alpha.jsonl').exists())
    def test_resume_changed_or_missing_startup_history_cannot_issue_continuation(self):
        original=self.finish_first()
        for change in ('missing','managed','output','reorder'):
            with self.subTest(change=change):
                self.fixture.observed('alpha','resume');history=copy.deepcopy(original)+[f.message(s.prompt('alpha','resume',f.NONCE))]
                if change=='missing':history.pop(2)
                if change=='managed':history[0]['content'][0]['text']+='changed'
                if change=='output':history[3]['output']+='changed'
                if change=='reorder':history[2],history[3]=history[3],history[2]
                with self.assertRaises(ValueError):self.j.request(f.body(history))
                self.assertIsNone(self.j.turn['issued'])
    def test_durable_managed_and_full_document_pairs_required(self):
        original=self.finish_first();entry=self.j.entries['alpha']
        durable_user=f.durable_message(s.prompt('alpha','first',f.NONCE));entry['user_context']=[f.source_wire(durable_user)]
        # Bind the independently observed equivalent user envelope for this source-shaped audit.
        items=[managed(self.corpus,True),durable_user,*original[2:]]
        entry['startup']['managed']=managed(self.corpus)
        path=self.root/'state/codex/sessions/rollout.jsonl';path.parent.mkdir(parents=True)
        rows=[{'type':'session_meta','payload':{'id':f.IDS['alpha'],'cwd':'/job'}},*({'type':'response_item','payload':item} for item in items)]
        self.fixture.write_rollout(path,rows);row=(f.IDS['alpha'],'/job','/state/codex/sessions/rollout.jsonl','openai')
        self.assertEqual(s.rollout_proof(self.root,row,entry,journey=self.j)['uuid'],f.IDS['alpha'])
        rows[1]['payload'][s.METADATA]['content_item_metadata'][0]['provenance']['from_additional_requirements']=False
        self.fixture.write_rollout(path,rows)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry,journey=self.j)
    def test_bundle_conflicts_and_no_private_fixture_output(self):
        for change in ('symlink','body','missing','extra','manifest'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                root=self.corpus.stage(Path(tmp)/'docs');path=root/(d.IDS[0]+'.txt')
                if change=='symlink':path.unlink();path.symlink_to(root/(d.IDS[1]+'.txt'))
                if change=='body':path.chmod(0o600);path.write_text('changed')
                if change=='missing':path.unlink()
                if change=='extra':(root/'unknown').write_text('extra')
                if change=='manifest':(root/'manifest.json').chmod(0o600);(root/'manifest.json').write_text('{}')
                with self.assertRaises((ValueError,OSError)):d.read_bundle(root)
        private=d.Corpus(REV,[b'SENTINEL_PRIVATE_FULL_BODY']*7,'private-runtime')
        self.assertNotIn('SENTINEL',repr(private));self.assertNotIn('SENTINEL',d.canonical(private.receipt()).decode())
        self.assertNotIn('synthetic fixture uses no actual',private.directive())
        with self.assertRaises(ValueError):d.Corpus(REV,[b'SENTINEL_PRIVATE_FULL_BODY']*7,'synthetic-fixture')
        self.assertEqual(private.private_document(d.IDS[0]),b'SENTINEL_PRIVATE_FULL_BODY')
        with self.assertRaises(ValueError):private.output()
        with self.assertRaises(ValueError):private.stage(self.root/'forbidden')
        with self.assertRaises(ValueError):s.Journey(self.root,time.monotonic()+1,t.Meter(),f.NONCE,startup_corpus=private)
    def test_pinned_marker_and_replacement_overhead_limit_never_truncates(self):
        overhead=len((d.OPEN+'\n'+d.NOTICE+'\n\n'+'\n'+d.CLOSE).encode())
        self.assertEqual(len(d.validate_directive('x'*(40000-overhead))),40000-overhead)
        with self.assertRaises(ValueError):d.validate_directive('x'*(40001-overhead))
        self.assertLess(len(self.corpus.output()),6000)
    def test_private_loader_checks_git_revision_and_full_fake_cache_without_public_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo=root/'repo';cache=root/'cache';repo.mkdir();cache.mkdir()
            for name in d.controller.PUBLIC:(repo/name).write_text('Synthetic repository '+name+'\n')
            for name in d.controller.SHARED:(cache/name).write_text('SENTINEL private synthetic '+name+'\n')
            env={**os.environ,'GIT_AUTHOR_NAME':'Fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid','GIT_COMMITTER_NAME':'Fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid'}
            subprocess.run(['git','init','-q',repo],check=True,env=env);subprocess.run(['git','-C',repo,'add','.'],check=True,env=env);subprocess.run(['git','-C',repo,'commit','-qm','synthetic'],check=True,env=env)
            rev=subprocess.check_output(['git','-C',repo,'rev-parse','HEAD'],text=True).strip()
            hashes={name:d.sha((cache/name).read_bytes()) for name in d.controller.SHARED}
            with patch.object(d.controller,'SHARED',hashes):
                private=d.load_private(repo,cache,rev,time.monotonic()+3)
                self.assertNotIn('SENTINEL',d.canonical(private.receipt()).decode());self.assertEqual(private.manifest['mode'],'private-runtime')
                (repo/'README.md').write_text('changed unpublished source')
                with self.assertRaises(ValueError):d.load_private(repo,cache,rev,time.monotonic()+3)


    def test_private_revision_read_has_hard_capture_and_cleanup_and_no_stderr_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo=root/'repo';cache=root/'cache';repo.mkdir();cache.mkdir()
            for name in d.controller.PUBLIC:(repo/name).write_text('Synthetic repository '+name+'\n')
            for name in d.controller.SHARED:(cache/name).write_text('Private synthetic fake cache '+name+'\n')
            hashes={name:d.sha((cache/name).read_bytes()) for name in d.controller.SHARED};children=[];original=subprocess.Popen
            def launch(argv,**kwargs):
                self.assertEqual(argv[:3],['/usr/bin/git','-C',str(repo)])
                child=original([sys.executable,'-c','import sys;sys.stdout.write("x"*300);sys.stderr.write("SENTINEL_PRIVATE_ERROR")'],**kwargs);children.append(child);return child
            with patch.object(d.controller,'SHARED',hashes),patch.object(d.subprocess,'Popen',side_effect=launch),self.assertRaises(ValueError) as seen:
                d.load_private(repo,cache,REV,time.monotonic()+3)
            self.assertNotIn('SENTINEL',str(seen.exception));self.assertTrue(children and all(p.returncode is not None and p.stdout.closed and p.stderr.closed for p in children))


    def test_every_retained_startup_pair_interleaving_rejects_before_continuation_effect(self):
        import itertools
        original=self.finish_first();before=(self.root/'job/src/session-alpha.jsonl').read_bytes()
        records=copy.deepcopy(self.j.records);entries=copy.deepcopy(self.j.entries);startup_records=copy.deepcopy(self.j.startup_records)
        current=f.message(s.prompt('alpha','resume',f.NONCE));pieces={'SC':original[2],'SO':original[3],'WC':original[4],'WO':original[5],'P':current}
        checked=0
        for order in itertools.permutations(pieces):
            if not (order.index('SC')<order.index('SO') and order.index('WC')<order.index('WO')<order.index('P')):continue
            with self.subTest(order=order):
                self.fixture.observed('alpha','resume');history=copy.deepcopy(original[:2]+[pieces[key] for key in order])
                if order==('SC','SO','WC','WO','P'):
                    self.j.request(f.body(history));self.assertEqual(self.j.turn['issued']['call_id'],'session-alpha-resume')
                else:
                    with self.assertRaisesRegex(ValueError,'startup delivery crossed original work or continuation'):self.j.request(f.body(history))
                    self.assertIsNone(self.j.turn['issued']);self.assertIsNone(self.j.turn['returned']);self.assertIsNone(self.j.turn['user_context'])
                    self.assertFalse(self.j.turn['finished'])
                self.assertEqual((self.root/'job/src/session-alpha.jsonl').read_bytes(),before)
                self.assertEqual(self.j.entries,entries);self.assertEqual(self.j.records,records);self.assertEqual(self.j.startup_records,startup_records)
                checked+=1
        self.assertEqual(checked,10)

    def test_retained_startup_checkpoint_identity_cannot_be_substituted_before_dispatch(self):
        original=self.finish_first();self.fixture.observed('alpha','resume')
        self.j.entries['alpha']['startup']['position']=999
        with self.assertRaisesRegex(ValueError,'startup delivery crossed original work or continuation'):
            self.j.request(f.body(original+[f.message(s.prompt('alpha','resume',f.NONCE))]))
        self.assertIsNone(self.j.turn['issued']);self.assertEqual(s.marker(self.root,'alpha',('first',),f.NONCE)['lines'],1)
