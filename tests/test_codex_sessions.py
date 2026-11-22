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

    def first(self,label):
        self.observed(label)
        first=message(s.prompt(label,'first',NONCE));self.j.request(body([first]))
        issued=copy.deepcopy(self.j.turn['issued']);output=self.run_action(issued)
        returned={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(output)}
        self.j.request(body([first,issued,returned]))
        self.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));self.j.finish(0)
        return issued,returned

    def history(self,label):
        entry=self.j.entries[label]
        return [message(entry['context']),copy.deepcopy(entry['call']),copy.deepcopy(entry['output']),
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

    def test_readonly_database_and_rollout_identity_bind_actual_sources(self):
        import sqlite3
        self.first('alpha');entry=self.j.entries['alpha']
        database=self.root/'state/sqlite/state_5.sqlite';database.parent.mkdir(parents=True)
        rollout=self.root/'state/codex/sessions/fixture.jsonl';rollout.parent.mkdir(parents=True)
        rows=[{'type':'session_meta','payload':{'id':IDS['alpha'],'cwd':'/job'}},
              {'type':'response_item','payload':message(entry['context'])},
              {'type':'response_item','payload':entry['call']},
              {'type':'response_item','payload':entry['output']}]
        rollout.write_bytes(b'\n'.join(t.canonical(v) for v in rows)+b'\n')
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE threads (id TEXT,cwd TEXT,rollout_path TEXT,model_provider TEXT)')
            db.execute('INSERT INTO threads VALUES (?,?,?,?)',(IDS['alpha'],'/job','/state/codex/sessions/fixture.jsonl','openai'))
        found=s.database(self.root,{IDS['alpha']},integrity=True)
        self.assertEqual(s.rollout_proof(self.root,found[IDS['alpha']],entry)['uuid'],IDS['alpha'])
        with self.assertRaises(ValueError):s.database(self.root,set())
        bad=copy.deepcopy(rows);bad[0]['payload']['id']=IDS['beta']
        rollout.write_bytes(b'\n'.join(t.canonical(v) for v in bad)+b'\n')
        with self.assertRaises(ValueError):s.rollout_proof(self.root,found[IDS['alpha']],entry)
        original=rollout.with_suffix('.saved');rollout.rename(original);rollout.symlink_to(original)
        with self.assertRaises(ValueError):s.rollout_proof(self.root,found[IDS['alpha']],entry)

    def test_resume_argv_is_explicit_uuid_not_last_or_cwd_inference(self):
        argv=s.cli_args(12345,'synthetic-context',IDS['alpha'])
        index=argv.index('resume');self.assertEqual(argv[index+1],IDS['alpha'])
        self.assertNotIn('--last',argv);self.assertEqual(argv[-1],'synthetic-context')
        with self.assertRaises(ValueError):s.cli_args(12345,'x','a-thread-name')
        report=self.root/'existing-report';report.write_text('canary')
        with patch.object(sys,'argv',['codex_sessions.py','--binary','/unused','--catalog','/unused','--report',str(report)]),self.assertRaises(ValueError):s.main()
        self.assertEqual(report.read_text(),'canary')


if __name__=='__main__':unittest.main()
