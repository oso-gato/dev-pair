"""Synthetic histories/tiny binaries test guards, never actual stock resume proof."""
import copy
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import codex_sessions as s
import codex_tools as t

IDS={'alpha':'11111111-1111-7111-8111-111111111111','beta':'22222222-2222-7222-8222-222222222222'}
NONCE='a'*32


def message(text):return {'type':'message','role':'user','content':[{'type':'input_text','text':text}]}
def body(items):return {'model':t.MODEL,'input':items,'tools':[{'type':'function','name':'exec_command'}]}
def terminal(output):return 'Chunk ID: fixture\nWall time: 0 seconds\nProcess exited with code 0\nOutput:\n'+output


def durable_message(text,kind='user.text',ident=IDS['alpha'],turn=IDS['beta'],created=1700000000.25):
    # Pinned producers persist attribution; non-RLite request preparation removes it.
    return dict(message(text),id=('msg_input_' if kind=='user.text' else 'msg_')+ident,
        **{s.METADATA:{'turn_id':turn,'create_time':created,'content_item_kinds':[kind],
            'content_item_metadata':[{'provenance':{'type':'user'}} if kind=='user.text' else
                                     {'provenance':{'type':'harness','hook':False}}]}})


def source_wire(item):
    result=copy.deepcopy(item);del result[s.METADATA]['content_item_metadata'];return result


class SessionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'job/src').mkdir(parents=True)
        (self.root/'job/src/uncommitted').write_bytes(s.UNCOMMITTED)
        self.j=s.Journey(self.root,time.monotonic()+10,t.Meter(),NONCE)

    def observed(self,label,phase='first'):
        self.j.begin(label,phase,IDS[label] if phase=='resume' else None)
        self.j.observe_cli(t.canonical({'type':'thread.started','thread_id':IDS[label]}))
        self.j.observe_cli(t.canonical({'type':'turn.started'}))

    def run_action(self,issued):
        args=shlex.split(json.loads(issued['arguments'])['cmd'])
        args[2]=args[2].replace('/job/src',str(self.root/'job/src'))
        actual=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2)
        self.assertEqual(actual.returncode,0,actual.stderr)
        return actual.stdout.decode()

    def first(self,label,preamble=()):
        self.observed(label)
        first=message(s.prompt(label,'first',NONCE));contexts=copy.deepcopy(list(preamble))+[first]
        self.j.request(body(contexts))
        issued=copy.deepcopy(self.j.turn['issued']);output=self.run_action(issued)
        returned={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(output)}
        self.j.request(body(contexts+[issued,returned]))
        self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        return issued,returned

    def history(self,label):
        entry=self.j.entries[label]
        return copy.deepcopy(entry['user_context'])+[copy.deepcopy(entry['call']),copy.deepcopy(entry['output']),
                message(s.prompt(label,'resume',NONCE))]

    def test_two_same_cwd_sessions_bound_to_retained_history_and_real_progress(self):
        self.first('alpha');self.first('beta')
        checkpoint=self.root/'checkpoint';self.j.checkpoint(checkpoint)
        self.assertEqual(self.j.read_checkpoint(checkpoint),IDS)
        for label in s.LABELS:
            self.observed(label,'resume');history=self.history(label);self.j.request(body(history))
            issued=copy.deepcopy(self.j.turn['issued']);actual=self.run_action(issued)
            output={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(actual)}
            self.j.request(body(history+[issued,output]))
            self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
            self.assertEqual(s.marker(self.root,label,('first','resume'),NONCE)['lines'],2)
        self.assertEqual(len(self.j.records),4)
        self.assertEqual({r['uuid'] for r in self.j.records},set(IDS.values()))
        self.assertEqual((self.root/'job/src/uncommitted').read_bytes(),s.UNCOMMITTED)
        self.assertEqual(checkpoint.stat().st_mode&0o777,0o600)
        self.assertEqual(self.j.read_checkpoint(checkpoint),IDS)

    def test_swapped_absent_duplicate_or_unbound_prior_history_never_admits_resume(self):
        self.first('alpha');self.first('beta')
        variants=[];valid=self.history('alpha')
        variants.append(self.history('beta'))
        variants.append(valid[1:])
        variants.append([valid[0],valid[2],valid[1],valid[3]])
        variants.append(valid+[copy.deepcopy(valid[2])])
        variants.append(valid+[{'type':'function_call_output','output':'orphan'}])
        variants.append(valid+[{'type':'function_call','name':'exec_command','arguments':'{}'}])
        variants.append(valid+[{'type':'custom_tool_call','call_id':'orphan','input':'x'}])
        changed=copy.deepcopy(valid);changed[2]['output']+='forged';variants.append(changed)
        changed=copy.deepcopy(valid);changed[1]['arguments']='{}';variants.append(changed)
        changed=copy.deepcopy(valid);changed[0]['role']='developer';variants.append(changed)
        for values in variants:
            self.observed('alpha','resume');before=copy.deepcopy(self.j.entries)
            with self.assertRaises(ValueError):self.j.request(body(values))
            self.assertIsNone(self.j.turn['issued'])
            self.assertEqual(self.j.entries,before)
        self.assertEqual(len(self.j.records),2)

    def metadata_first(self,label,turn_id):
        self.observed(label);first=message(s.prompt(label,'first',NONCE));self.j.request(body([first]))
        issued=copy.deepcopy(self.j.turn['issued']);actual=self.run_action(issued)
        call=copy.deepcopy(issued);call[s.METADATA]={'turn_id':turn_id}
        returned={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(actual),
                  s.METADATA:{'turn_id':turn_id,'create_time':1700000000.25}}
        self.j.request(body([first,call,returned]))
        self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        self.assertEqual(t.canonical(self.j.entries[label]['call']),t.canonical(call))
        self.assertEqual(t.canonical(self.j.entries[label]['output']),t.canonical(returned))
        return call,returned

    def test_kind_metadata_preserves_dicts_and_new_turn_differs_from_session_and_history(self):
        turn='33333333-3333-7333-8333-333333333333';new_turn='44444444-4444-7444-8444-444444444444'
        self.metadata_first('alpha',turn);self.first('beta')  # Existing absent-metadata contract.
        original=copy.deepcopy(self.j.entries['alpha']);self.observed('alpha','resume')
        history=self.history('alpha');self.j.request(body(history));issued=copy.deepcopy(self.j.turn['issued'])
        output=self.run_action(issued);call=copy.deepcopy(issued);call[s.METADATA]={'turn_id':new_turn}
        result={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(output),
                s.METADATA:{'turn_id':new_turn,'create_time':1700000001}}
        self.j.request(body(history+[call,result]));self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        self.assertEqual(self.j.entries['alpha'],original);self.assertIsNone(self.j.metadata_rejection)
        self.assertNotEqual(turn,IDS['alpha']);self.assertNotEqual(new_turn,turn)

    def test_closed_kind_metadata_rejects_null_extras_uuid_and_bad_timestamps(self):
        issued=s.action('alpha','first',NONCE);turn=IDS['beta']
        calls=[None,{}, {'turn_id':turn,'create_time':1},{'turn_id':turn,'unknown':'secret'},
               {'turn_id':'bad'},{'turn_id':None},{'turn_id':True}]
        outputs=[None,{}, {'turn_id':turn}, {'turn_id':turn,'create_time':1,'executed_tool_calls':[]}]
        outputs += [{'turn_id':turn,'create_time':value} for value in (True,float('nan'),float('inf'),0,-1,1e12,10**1000,'1')]
        for kind,variants in [('function_call',calls),('function_call_output',outputs)]:
            for value in variants:
                item=copy.deepcopy(issued) if kind=='function_call' else {'type':kind,'call_id':issued['call_id'],'output':'x'}
                item[s.METADATA]=value
                with self.assertRaises(s.MetadataRejected):s.history_item(item,issued,kind)

    def test_changed_removed_swapped_or_mismatched_metadata_cannot_replay_history(self):
        self.metadata_first('alpha',IDS['beta']);self.first('beta')
        valid=self.history('alpha');variants=[]
        for index in (1,2):
            changed=copy.deepcopy(valid);changed[index].pop(s.METADATA);variants.append(changed)
            changed=copy.deepcopy(valid);changed[index][s.METADATA]['turn_id']=IDS['alpha'];variants.append(changed)
        changed=copy.deepcopy(valid);changed[1][s.METADATA],changed[2][s.METADATA]=changed[2][s.METADATA],changed[1][s.METADATA];variants.append(changed)
        changed=copy.deepcopy(valid)
        for index in (1,2):changed[index][s.METADATA]['turn_id']='55555555-5555-7555-8555-555555555555'
        variants.append(changed)
        for values in variants:
            self.observed('alpha','resume');before=copy.deepcopy(self.j.entries)
            with self.assertRaises(ValueError):self.j.request(body(values))
            self.assertIsNone(self.j.turn['issued']);self.assertEqual(self.j.entries,before)

    def test_metadata_shape_witness_is_first_bounded_private_and_has_no_acceptance_effect(self):
        self.observed('alpha');first=message(s.prompt('alpha','first',NONCE));self.j.request(body([first]))
        issued=copy.deepcopy(self.j.turn['issued']);actual=self.run_action(issued)
        call=copy.deepcopy(issued);call[s.METADATA]={'turn_id':IDS['beta'],'SECRET_UNKNOWN_KEY':'SECRET_TRANSCRIPT_VALUE',
            'executed_tool_calls':[{'arguments':'SECRET_TRANSCRIPT_VALUE'*200}]*20}
        output={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(actual)}
        with self.assertRaises(s.MetadataRejected):self.j.request(body([first,call,output]))
        witness=copy.deepcopy(self.j.metadata_rejection);encoded=t.canonical(witness)
        self.assertLessEqual(len(encoded),2048);self.assertNotIn(b'SECRET',encoded);self.assertNotIn(IDS['beta'].encode(),encoded)
        self.assertEqual(witness['expected_kind'],'function_call');self.assertEqual(witness['item_index'],1)
        self.assertTrue(witness['issued_call_id_matches']);self.assertEqual(witness['unknown_key_count'],1)
        self.assertEqual(witness['recognized_keys']['executed_tool_calls'],{'present':True,'type':'array'})
        self.assertEqual(witness['request'],self.j.last_request);self.assertEqual(witness['harness_sha256'],t.sha(Path(s.__file__).read_bytes()))
        self.assertFalse(self.j.entries);self.assertFalse(self.j.records);self.assertIsNone(self.j.turn['returned'])
        self.assertFalse(self.j.turn['finished']);self.assertEqual(s.marker(self.root,'alpha',('first',),NONCE)['lines'],1)
        call[s.METADATA]=None
        with self.assertRaises(s.MetadataRejected):self.j.request(body([first,call,output]))
        self.assertEqual(self.j.metadata_rejection,witness)

    def test_real_local_rejected_metadata_report_keeps_witness_and_existing_effect(self):
        code="import copy,json,sys\nsys.path.insert(0,sys.argv[1]);import test_codex_sessions as tests\ns=tests.s;t=tests.t;case=tests.SessionsTests();case.setUp()\ntry:\n case.observed('alpha');first=tests.message(s.prompt('alpha','first',tests.NONCE));case.j.request(tests.body([first]))\n issued=copy.deepcopy(case.j.turn['issued']);actual=case.run_action(issued)\n call=copy.deepcopy(issued);call[s.METADATA]={'turn_id':tests.IDS['beta'],'SECRET_KEY':'SECRET_VALUE'}\n output={'type':'function_call_output','call_id':issued['call_id'],'output':tests.terminal(actual)}\n try:case.j.request(tests.body([first,call,output]))\n except s.MetadataRejected:pass\n print(json.dumps({'status':'blocked','witness':case.j.metadata_rejection,'accepted_turns':len(case.j.records),'checkpoints':len(case.j.entries),'actual_marker_lines':s.marker(case.root,'alpha',('first',),tests.NONCE)['lines']}))\nfinally:case.doCleanups()\n"
        result=subprocess.run([sys.executable,'-c',code,str(Path(__file__).parent)],capture_output=True,text=True,timeout=4)
        self.assertEqual(result.returncode,0,result.stderr);self.assertLess(len(result.stdout),4096);self.assertNotIn('SECRET',result.stdout)
        value=json.loads(result.stdout);self.assertEqual(value['status'],'blocked');self.assertEqual(value['accepted_turns'],0)
        self.assertEqual(value['checkpoints'],0);self.assertEqual(value['actual_marker_lines'],1)
        self.assertEqual(value['witness']['rejection_stage'],'metadata-schema')

    def test_sr1_observed_ordered_context_rejects_mutations_and_exact_resume_works(self):
        preamble=[message('actual first preamble'),message('actual second preamble')]
        self.first('alpha',preamble);self.first('beta')
        entry=self.j.entries['alpha'];expected=copy.deepcopy(preamble)+[message(s.prompt('alpha','first',NONCE))]
        self.assertEqual(entry['user_context'],expected)
        self.assertEqual(self.j.records[0]['context_sha256'],t.sha(t.canonical(expected)))
        self.assertNotEqual(self.j.records[0]['context_sha256'],t.sha(s.prompt('alpha','first',NONCE).encode()))
        valid=self.history('alpha');variants=[]
        for index in (0,2):
            for text in ('unobserved prefix ', ' unobserved suffix'):
                changed=copy.deepcopy(valid)
                changed[index]['content'][0]['text']=text+changed[index]['content'][0]['text']+text
                variants.append(changed)
        variants.append(valid[:1]+[message('injected prior user message')]+valid[1:])
        variants.append(valid[1:])
        variants.append([valid[1],valid[0],*valid[2:]])
        variants.append([valid[0],*valid])
        changed=copy.deepcopy(valid);changed[0]['id']='changed-history-id';variants.append(changed)
        changed=copy.deepcopy(valid);changed[-1]['content'][0]['text']+=' suffix';variants.append(changed)
        for items in variants:
            self.observed('alpha','resume');before=copy.deepcopy(self.j.entries)
            with self.assertRaises(ValueError):self.j.request(body(items))
            self.assertIsNone(self.j.turn['issued']);self.assertIsNone(self.j.turn['user_context'])
            self.assertEqual(self.j.entries,before)
        self.observed('alpha','resume');self.j.request(body(valid))
        issued=copy.deepcopy(self.j.turn['issued']);output=self.run_action(issued)
        returned={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(output)}
        self.j.request(body(valid+[issued,returned]))
        self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        self.assertEqual(s.marker(self.root,'alpha',('first','resume'),NONCE)['lines'],2)
        self.assertEqual(self.j.records[-1]['context_sha256'],t.sha(t.canonical(expected+[message(s.prompt('alpha','resume',NONCE))])))

    def test_sr1_first_result_retains_observation_and_does_not_undo_actual_effect(self):
        self.observed('alpha');contexts=[message('observed preamble'),message(s.prompt('alpha','first',NONCE))]
        self.j.request(body(contexts));retained=copy.deepcopy(self.j.turn['user_context'])
        issued=copy.deepcopy(self.j.turn['issued']);output=self.run_action(issued)
        returned={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(output)}
        contexts[0]['content'][0]['text']='changed after first request'
        with self.assertRaises(ValueError):self.j.request(body(contexts+[issued,returned]))
        self.assertEqual(self.j.turn['user_context'],retained)
        self.assertIsNone(self.j.turn['returned']);self.assertFalse(self.j.entries)
        self.assertEqual(s.marker(self.root,'alpha',('first',),NONCE)['lines'],1)

    def test_sr1_first_prompt_is_complete_exact_message_not_substring(self):
        expected=s.prompt('alpha','first',NONCE)
        cases=[[message('prefix '+expected)],[message(expected+' suffix')],
               [message(expected),message(expected)], [message(expected),message('extra after prompt')],
               [{'type':'message','role':'user','content':[{'type':'input_text','text':expected},{'type':'input_text','text':'extra'}]}]]
        for items in cases:
            self.observed('alpha')
            with self.assertRaises(ValueError):self.j.request(body(items))
            self.assertIsNone(self.j.turn['issued']);self.assertIsNone(self.j.turn['user_context'])

    def test_extra_tool_output_cannot_be_hidden_by_one_matching_json_line(self):
        self.observed('alpha');first=message(s.prompt('alpha','first',NONCE))
        self.j.request(body([first]));issued=copy.deepcopy(self.j.turn['issued'])
        output=self.run_action(issued)
        forged={'type':'function_call_output','call_id':issued['call_id'],'output':terminal('unexpected\n'+output)}
        with self.assertRaises(ValueError):self.j.request(body([first,issued,forged]))
        self.assertFalse(self.j.entries);self.assertIsNone(self.j.turn['returned'])

    def test_actual_uuid_and_completion_events_cannot_be_substituted(self):
        self.first('alpha')
        with self.assertRaises(ValueError):self.j.begin('alpha','resume',IDS['beta'])
        for event in ({'type':'thread.started','thread_id':'not-a-uuid'},
                      {'type':'thread.started','thread_id':IDS['beta']},
                      {'type':'thread.started','thread_id':IDS['alpha'],'extra':True}):
            self.j.begin('alpha','resume',IDS['alpha'])
            with self.assertRaises(ValueError):self.j.observe_cli(t.canonical(event))
        self.observed('alpha','resume')
        with self.assertRaises(ValueError):self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}))
        with self.assertRaises(ValueError):self.j.finish(0)
        self.j.negative=True;self.j.turn=None
        self.j.observe_cli(t.canonical({'type':'error','message':'unknown synthetic UUID'}))
        with self.assertRaises(ValueError):self.j.observe_cli(t.canonical({'type':'thread.started','thread_id':IDS['beta']}))

    def test_checkpoint_corruption_cannot_supply_two_matching_claims(self):
        self.first('alpha');self.first('beta');path=self.root/'checkpoint';self.j.checkpoint(path)
        original=path.read_bytes();values=json.loads(original)
        variants=[b'{',b'',t.canonical(dict(values,version=True)),t.canonical(dict(values,extra=True))]
        changed=copy.deepcopy(values);changed['entries']['alpha']['uuid']=IDS['beta'];variants.append(t.canonical(changed))
        changed=copy.deepcopy(values);changed['entries']['alpha']['output']['output']='forged';variants.append(t.canonical(changed))
        for data in variants:
            path.write_bytes(data)
            with self.assertRaises(ValueError):self.j.read_checkpoint(path)
        path.write_bytes(original)
        with self.assertRaises(FileExistsError):self.j.checkpoint(path)
        alias=self.root/'alias';alias.symlink_to(path)
        with self.assertRaises(ValueError):self.j.read_checkpoint(alias)
        path.unlink()
        with self.assertRaises(OSError):self.j.read_checkpoint(path)

    def test_progress_effects_are_exactly_once_even_if_command_is_replayed(self):
        for phase in ('first','resume'):
            issued=s.action('alpha',phase,NONCE);self.run_action(issued)
            args=shlex.split(json.loads(issued['arguments'])['cmd']);args[2]=args[2].replace('/job/src',str(self.root/'job/src'))
            duplicate=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2)
            self.assertNotEqual(duplicate.returncode,0)
        self.assertEqual(s.marker(self.root,'alpha',('first','resume'),NONCE)['lines'],2)
        path=self.root/'job/src/session-alpha.jsonl';path.write_bytes(path.read_bytes()+b'forged\n')
        with self.assertRaises(ValueError):s.marker(self.root,'alpha',('first','resume'),NONCE)

    def test_real_children_share_original_budget_and_are_reaped_on_later_failure(self):
        class Observer:
            error=None
            def __init__(self,end):self.action_end=end;self.rows=[]
            def observe_cli(self,line):self.rows.append(json.loads(line))
        children=[]
        def launch(*args,**kwargs):
            child=subprocess.Popen(*args,**kwargs);children.append(child);return child
        end=time.monotonic()+.3;observer=Observer(end);meter=t.Meter()
        status,_=s.run_turn([sys.executable,'-c','import json,os;print(json.dumps({"pid":os.getpid()}))'],observer,meter,end,popen=launch)
        self.assertEqual(status,0);used=meter.used
        with self.assertRaisesRegex(ValueError,'deadline'):
            s.run_turn([sys.executable,'-c','import time;time.sleep(2)'],observer,meter,end,popen=launch)
        self.assertGreater(used,0);self.assertGreaterEqual(meter.used,used)
        self.assertEqual(len({p.pid for p in children}),2)
        for child in children:
            self.assertIsNotNone(child.poll());self.assertTrue(child.stdout.closed and child.stderr.closed)
        observer=Observer(time.monotonic()+2);meter=t.Meter(0,100)
        with self.assertRaisesRegex(ValueError,'output budget'):
            s.run_turn([sys.executable,'-c','print("x"*101)'],observer,meter,observer.action_end,popen=launch)
        self.assertIsNotNone(children[-1].poll())

    def test_real_exited_parent_retained_pipe_and_cleanup_failure_never_pass(self):
        class Observer:
            error=None
            action_end=time.monotonic()+.1
            def observe_cli(self,line):json.loads(line)
        escaped=self.root/'escaped'
        code='import os,time,pathlib,sys;pid=os.fork();os._exit(0) if pid else None;time.sleep(.3);pathlib.Path(sys.argv[1]).write_text("escaped")'
        with self.assertRaises(ValueError):s.run_turn([sys.executable,'-c',code,str(escaped)],Observer(),t.Meter(),Observer.action_end)
        time.sleep(.35);self.assertFalse(escaped.exists())
        original=t.stop
        def fail_after_reap(process):original(process);raise OSError('synthetic cleanup failure')
        observer=Observer();observer.action_end=time.monotonic()+2
        with patch.object(t,'stop',side_effect=fail_after_reap),self.assertRaises(OSError):
            s.run_turn([sys.executable,'-c','print("{}")'],observer,t.Meter(),observer.action_end)

    def test_real_child_is_reaped_even_if_capture_setup_fails(self):
        children=[]
        def launch(*args,**kwargs):
            child=subprocess.Popen(*args,**kwargs);children.append(child);return child
        class Observer:
            error=None
            action_end=time.monotonic()+2
            def observe_cli(self,line):pass
        with patch.object(s.selectors,'DefaultSelector',side_effect=OSError('synthetic selector failure')):
            with self.assertRaises(OSError):
                s.run_turn([sys.executable,'-c','import time;time.sleep(3)'],Observer(),t.Meter(),Observer.action_end,popen=launch)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)

    def test_unknown_uuid_reason_requires_exact_source_backed_witness(self):
        expected='no rollout found for thread id '+s.UNKNOWN
        self.assertTrue(s.unknown_reason(expected))
        self.assertTrue(s.unknown_reason('Error: '+expected))
        for value in ('authentication failed',expected+' extra','prefix '+expected,expected.replace(s.UNKNOWN,IDS['alpha']),None):
            self.assertFalse(s.unknown_reason(value))

    def source_first_rollout(self):
        import sqlite3
        durable=[durable_message('whole observed environment context','environments.environment_context'),
                 durable_message(s.prompt('alpha','first',NONCE))]
        wire=[source_wire(item) for item in durable]
        self.observed('alpha');self.j.request(body(wire));issued=copy.deepcopy(self.j.turn['issued']);actual=self.run_action(issued)
        call=dict(issued,id='fc_'+IDS['alpha'],**{s.METADATA:{'turn_id':IDS['beta']}})
        output={'type':'function_call_output','id':'fco_'+IDS['alpha'],'call_id':issued['call_id'],'output':terminal(actual),
                s.METADATA:{'turn_id':IDS['beta'],'create_time':1700000001.25}}
        self.j.request(body(wire+[call,output]));self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        entry=self.j.entries['alpha'];database=self.root/'state/sqlite/state_5.sqlite';database.parent.mkdir(parents=True)
        path=self.root/'state/codex/sessions/fixture.jsonl';path.parent.mkdir(parents=True)
        rows=[{'type':'session_meta','payload':{'id':IDS['alpha'],'cwd':'/job'}},
              *({'type':'response_item','payload':item} for item in durable+[call,output])]
        self.write_rollout(path,rows)
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE threads (id TEXT,cwd TEXT,rollout_path TEXT,model_provider TEXT)')
            db.execute('INSERT INTO threads VALUES (?,?,?,?)',(IDS['alpha'],'/job','/state/codex/sessions/fixture.jsonl','openai'))
        row=s.database(self.root,{IDS['alpha']},integrity=True)[IDS['alpha']]
        return path,rows,row,entry

    def write_rollout(self,path,rows):
        path.write_bytes(b'\n'.join(t.canonical(v) for v in rows)+b'\n')

    def test_readonly_database_and_source_shaped_rollout_identity(self):
        path,rows,row,entry=self.source_first_rollout();original=copy.deepcopy(rows);wire=copy.deepcopy(entry['user_context'])
        result=s.rollout_proof(self.root,row,entry)
        self.assertEqual(result['uuid'],IDS['alpha']);self.assertEqual(rows,original)
        self.assertEqual(entry['user_context'],wire)
        self.assertNotEqual(result['raw_user_context_sha256'],result['wire_user_context_sha256'])
        self.assertEqual(result['projected_user_context_sha256'],result['wire_user_context_sha256'])
        with self.assertRaises(ValueError):s.database(self.root,set())
        for index,value in ((0,IDS['beta']),(1,'/foreign'),(3,'foreign')):
            bad=list(row);bad[index]=value
            with self.assertRaises(ValueError):s.rollout_proof(self.root,bad,entry)
        bad=copy.deepcopy(rows);bad[0]['payload']['id']=IDS['beta'];self.write_rollout(path,bad)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry)
        original_path=path.with_suffix('.saved');path.rename(original_path);path.symlink_to(original_path)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry)

    def test_closed_durable_projection_rejects_forged_shapes_without_mutation(self):
        valid=durable_message('entire original message');original=copy.deepcopy(valid)
        self.assertEqual(s.durable_user_to_wire(valid),source_wire(valid));self.assertEqual(valid,original)
        cases=[]
        for key,value in (('turn_id','bad'),('create_time',True),('create_time',float('inf')),
                          ('content_item_kinds',['unknown']),('content_item_kinds',[]),
                          ('content_item_metadata',[]),('content_item_metadata',None),
                          ('content_item_metadata',[{'provenance':{'type':'tool','namespace':'functions'}}]),
                          ('content_item_metadata',[{'provenance':{'type':'user','extra':'SECRET'}}]),
                          ('content_item_metadata',[{'provenance':{'type':'user'},'extra':'SECRET'}]),
                          ('content_item_metadata',[{'provenance':{'type':'harness','hook':False}}])):
            item=copy.deepcopy(valid);item[s.METADATA][key]=value;cases.append(item)
        for key in ('turn_id','create_time','content_item_kinds','content_item_metadata'):
            item=copy.deepcopy(valid);del item[s.METADATA][key];cases.append(item)
        for key,value in (('role','developer'),('type','function_call'),('id','unprefixed'),('status',None),
                          ('content',[{'type':'input_text','text':'x','extra':True}]),('SECRET_KEY','SECRET_VALUE')):
            item=copy.deepcopy(valid);item[key]=value;cases.append(item)
        item=copy.deepcopy(valid);item[s.METADATA]['SECRET_KEY']='SECRET_VALUE';cases.append(item)
        env=durable_message('env','environments.environment_context')
        for hook in (True,0,None):
            item=copy.deepcopy(env);item[s.METADATA]['content_item_metadata'][0]['provenance']['hook']=hook;cases.append(item)
        for item in cases:
            before=copy.deepcopy(item)
            with self.assertRaises(ValueError):s.durable_user_to_wire(item)
            self.assertEqual(t.canonical(item),t.canonical(before))

    def test_durable_projection_is_never_applied_to_resumed_wire(self):
        _,_,_,entry=self.source_first_rollout();before=copy.deepcopy(entry)
        history=self.history('alpha')
        history[0][s.METADATA]['content_item_metadata']=[{'provenance':{'type':'harness','hook':False}}]
        self.observed('alpha','resume')
        with patch.object(s,'durable_user_to_wire',side_effect=AssertionError('wire normalization attempted')):
            with self.assertRaisesRegex(ValueError,'prior ordered user context'):self.j.request(body(history))
        self.assertIsNone(self.j.turn['issued']);self.assertIsNone(self.j.turn['user_context'])
        self.assertEqual(self.j.entries['alpha'],before)

    def test_durable_context_requires_whole_exact_order_and_original_causal_pair(self):
        path,rows,row,entry=self.source_first_rollout();variants=[]
        for index in (1,2):
            for suffix in (' changed',' extra prefix equivalent'):
                changed=copy.deepcopy(rows);changed[index]['payload']['content'][0]['text']+=suffix;variants.append(changed)
            for key,value in (('id','msg_input_'+IDS['beta']),('role','developer'),('type','other')):
                changed=copy.deepcopy(rows);changed[index]['payload'][key]=value;variants.append(changed)
            for key,value in (('turn_id',IDS['alpha']),('create_time',1700000002.)):
                changed=copy.deepcopy(rows);changed[index]['payload'][s.METADATA][key]=value;variants.append(changed)
        variants += [rows[:1]+rows[2:], [rows[0],rows[2],rows[1],*rows[3:]], rows[:2]+[rows[1]]+rows[2:],
                     rows+[rows[1]], [rows[0],rows[1],rows[3],rows[2],rows[4]],
                     [*rows[:3],rows[4],rows[3]], rows+[rows[3]], rows+[rows[4]]]
        for index,key,value in ((3,'arguments','{}'),(4,'output','forged'),(3,'id','fc_'+IDS['beta'])):
            changed=copy.deepcopy(rows);changed[index]['payload'][key]=value;variants.append(changed)
        changed=copy.deepcopy(rows);changed[3]['payload'][s.METADATA]['turn_id']=IDS['alpha'];variants.append(changed)
        changed=copy.deepcopy(rows);changed[4]['payload'][s.METADATA]['SECRET_KEY']='SECRET_VALUE';variants.append(changed)
        variants.append(rows+[{'type':'response_item','payload':{'type':'function_call_output','call_id':'orphan','output':'x'}}])
        for changed in variants:
            before=copy.deepcopy(self.j.entries);self.write_rollout(path,changed)
            with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry,journey=self.j,checkpoint_sha256='a'*64)
            self.assertEqual(self.j.entries,before);self.assertEqual(len(self.j.records),1)
            self.assertEqual(s.marker(self.root,'alpha',('first',),NONCE)['lines'],1)

    def test_final_rollout_binds_later_observed_continuation_without_hiding_extra_users(self):
        path,rows,row,entry=self.source_first_rollout();self.observed('alpha','resume')
        durable=durable_message(s.prompt('alpha','resume',NONCE),ident=IDS['beta'],turn=IDS['alpha'],created=1700000002.)
        wire=source_wire(durable);history=copy.deepcopy(entry['user_context'])+[entry['call'],entry['output'],wire]
        self.j.request(body(history));issued=copy.deepcopy(self.j.turn['issued']);actual=self.run_action(issued)
        call=dict(issued,**{s.METADATA:{'turn_id':IDS['alpha']}})
        output={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(actual),
                s.METADATA:{'turn_id':IDS['alpha'],'create_time':1700000003.}}
        self.j.request(body(history+[call,output]));self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        rows += [{'type':'response_item','payload':item} for item in (durable,call,output)]
        self.write_rollout(path,rows);bound=self.j.continuations['alpha']
        self.assertEqual(s.rollout_proof(self.root,row,entry,continuation=bound)['uuid'],IDS['alpha'])
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry)  # First audit cannot hide later users.
        variants=[rows+[rows[1]], rows[:-3]+[rows[-2],rows[-3],rows[-1]],
                  rows[:3]+[rows[-3]]+rows[3:-3]+rows[-2:]]
        for changed in variants:
            self.write_rollout(path,changed)
            with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry,continuation=bound)

    def test_rollout_rejection_witness_is_bounded_first_private_and_cannot_commit(self):
        path,rows,row,entry=self.source_first_rollout();before=copy.deepcopy(self.j.entries)
        rows[1]['payload'][s.METADATA]['SECRET_KEY']='SECRET_VALUE';rows[1]['payload']['content'][0]['text']='SECRET_TEXT'*100
        self.write_rollout(path,rows)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry,journey=self.j,checkpoint_sha256='a'*64)
        witness=copy.deepcopy(self.j.rollout_rejection);encoded=t.canonical(witness)
        self.assertLessEqual(len(encoded),2048);self.assertNotIn(b'SECRET',encoded)
        self.assertNotIn(str(path).encode(),encoded);self.assertNotIn(IDS['alpha'].encode(),encoded)
        self.assertEqual(witness['stage'],'durable-context');self.assertEqual(witness['unknown_key_count'],1)
        self.assertEqual(witness['checkpoint_sha256'],'a'*64);self.assertEqual(witness['request'],self.j.last_request)
        self.assertEqual(self.j.entries,before);self.assertEqual(len(self.j.records),1)
        rows[1]['payload']['content'][0]['text']='another secret';self.write_rollout(path,rows)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry,journey=self.j)
        self.assertEqual(self.j.rollout_rejection,witness)

    def test_rollout_local_bounds_identity_and_ancestor_symlink_reject(self):
        path,rows,row,entry=self.source_first_rollout()
        for value in (b'x'*(2*1024**2+1), b'x'*(t.BODY_BYTES+1)+b'\n',b'{\n',b''):
            path.write_bytes(value)
            with self.assertRaises((ValueError,OSError)):s.rollout_proof(self.root,row,entry)
        self.write_rollout(path,rows)
        bad=copy.deepcopy(rows);bad[0]['payload']['cwd']='/foreign';self.write_rollout(path,bad)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry)
        self.write_rollout(path,rows);parent=path.parent;stored=parent.with_name('stored');parent.rename(stored);parent.symlink_to(stored)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,row,entry)

    def test_resume_argv_is_explicit_uuid_not_last_or_cwd_inference(self):
        argv=s.cli_args(12345,'synthetic-context',IDS['alpha'])
        index=argv.index('resume');self.assertEqual(argv[index+1],IDS['alpha'])
        self.assertNotIn('--last',argv);self.assertEqual(argv[-1],'synthetic-context')
        with self.assertRaises(ValueError):s.cli_args(12345,'x','a-thread-name')
        report=self.root/'existing-report';report.write_text('canary')
        with patch.object(sys,'argv',['codex_sessions.py','--binary','/unused','--catalog','/unused','--report',str(report)]),self.assertRaises(ValueError):s.main()
        self.assertEqual(report.read_text(),'canary')


if __name__=='__main__':unittest.main()
