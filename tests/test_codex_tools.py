"""Synthetic protocol and real child/file bounds; no model or host listener."""
import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import codex_tools as t


class OfflineTools(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for name,data in (('credentials/marker',b'NONCREDENTIAL_AUTHORITY_MARKER'),('credentials/valid.png',t.png()),('state/codex/marker',b'SYNTHETIC_STATE_MARKER'),('state/sqlite/marker',b'SYNTHETIC_DB_MARKER'),('etc/codex/requirements.toml',b'fixed'),('state/codex/config.toml',b'fixed'),('job/src/valid.png',t.png())):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        (self.root/'job/build').mkdir()

    def sequence(self,ident='patch-deny'):
        action=next(a for a in t.actions(12345) if a['id']==ident)
        return t.Sequence([action],self.root,time.monotonic()+2)

    def body(self,inputs=None):
        return {'model':t.MODEL,'input':inputs or [],'tools':[{'type':'custom','name':'apply_patch'}]}

    def test_sse_requires_actual_matching_output_and_preserves_protected_objects(self):
        seq=self.sequence();wire=seq.request(self.body())
        self.assertIn(b'response.output_item.done',wire);self.assertIn(b'patch-deny',wire)
        self.assertFalse(seq.records)
        output={'type':'custom_tool_call_output','call_id':'patch-deny','output':'Permission denied (os error 13)'}
        seq.request(self.body([output]));self.assertTrue(seq.records[0]['pass']);self.assertTrue(seq.finished)
        self.assertEqual((self.root/'credentials/marker').read_bytes(),b'NONCREDENTIAL_AUTHORITY_MARKER')
        for items in ([dict(output,call_id='orphan')],[output,output],[]):
            other=self.sequence();other.request(self.body())
            with self.assertRaises(ValueError):other.request(self.body(items))

    def test_exact_wire_kinds_reject_cross_kind_unknown_orphan_and_duplicates(self):
        for ident, expected in (('patch-deny', 'custom_tool_call_output'),
                                ('image-deny', 'function_call_output')):
            for kind in ('function_call_output', 'custom_tool_call_output',
                         'future_tool_output', 'message', None):
                seq = self.sequence(ident)
                seq.request(self.body())
                item = {'type': kind, 'call_id': ident,
                        'output': 'Permission denied (os error 13)'}
                if kind == expected:
                    seq.request(self.body([item]))
                    self.assertTrue(seq.records[0]['pass'])
                    self.assertEqual(seq.records[0]['emitted_call_kind'], seq.planned[0]['kind'])
                    self.assertEqual(seq.records[0]['returned_output_kind'], expected)
                else:
                    before = (seq.index, seq.action_end, seq.meter.used)
                    with self.assertRaises(ValueError):
                        seq.request(self.body([item]))
                    self.assertEqual((seq.index, seq.action_end, seq.meter.used), before)
                    self.assertEqual(seq.records, [])
                    self.assertFalse(seq.finished)

    def test_replayed_history_also_requires_unique_bound_output_kinds(self):
        planned = [next(a for a in t.actions(12345) if a['id'] == ident)
                   for ident in ('patch-deny', 'image-deny')]
        first = {'type': 'custom_tool_call_output', 'call_id': 'patch-deny',
                 'output': 'Permission denied (os error 13)'}
        last = {'type': 'function_call_output', 'call_id': 'image-deny',
                'output': 'Permission denied (os error 13)'}
        for historical in ([dict(first, type='function_call_output')],
                           [first, first], [dict(first, call_id='orphan')],
                           [dict(first, type='future_tool_output')]):
            seq = t.Sequence(planned, self.root, time.monotonic() + 2)
            seq.request(self.body())
            seq.request(self.body([first]))
            with self.assertRaises(ValueError):
                seq.request(self.body(historical + [last]))
            self.assertEqual(seq.index, 2)
            self.assertEqual(len(seq.records), 1)
            self.assertFalse(seq.finished)
        seq = t.Sequence(planned, self.root, time.monotonic() + 2)
        seq.request(self.body())
        seq.request(self.body([first]))
        seq.request(self.body([first, last]))
        self.assertTrue(seq.finished)
        self.assertEqual([r['returned_output_kind'] for r in seq.records],
                         ['custom_tool_call_output', 'function_call_output'])

    def test_invalid_image_and_unsupported_tool_text_are_never_denial_evidence(self):
        for ident,text in (('image-deny','invalid image data'),('patch-deny','unsupported tool'),('shell-deny','/credentials/marker /state/codex/marker /state/sqlite/marker')):
            seq=self.sequence(ident)
            with self.assertRaises(ValueError):seq.oracle(seq.planned[0],{'output':text})
        seq=self.sequence('image-allow')
        image={'type':'input_image','image_url':'data:image/png;base64,'+base64.b64encode(t.png()).decode()}
        self.assertTrue(seq.oracle(seq.planned[0],{'output':[image]})['pass'])
        image['image_url']='data:image/png;base64,AAAA'
        with self.assertRaises(ValueError):seq.oracle(seq.planned[0],{'output':[image]})

    def test_real_protected_mutation_blocks_and_failed_action_is_retained(self):
        seq=self.sequence();seq.request(self.body())
        (self.root/'credentials/marker').write_text('changed')
        with self.assertRaisesRegex(ValueError,'protected fixture changed'):
            seq.request(self.body([{'type':'custom_tool_call_output','call_id':'patch-deny','output':'Permission denied (os error 13)'}]))
        self.assertEqual(seq.records[-1]['pass'],False)

    def test_protocol_deadline_model_unknown_inventory_and_capture_meter(self):
        seq=self.sequence();seq.action_end=time.monotonic()-1
        with self.assertRaises(ValueError):seq.request(self.body())
        seq=self.sequence()
        with self.assertRaises(ValueError):seq.request(dict(self.body(),model='other'))
        names=t.tool_inventory([{'type':'namespace','name':'functions','tools':[{'name':'exec_command'}]},{'type':'web_search'}])
        self.assertEqual(names,['functions.exec_command','web_search'])
        meter=t.Meter(t.OUTPUT_BYTES-1);meter.add(1)
        with self.assertRaises(ValueError):meter.add(1)
        with self.assertRaises(ValueError):t.unique([('x',1),('x',2)])

    def test_real_child_capture_deadline_and_output_exhaustion(self):
        for script,budget,end in (('import os;os.write(1,b"x"*65536)',[t.OUTPUT_BYTES-5],time.monotonic()+2),('import time;time.sleep(5)',[0],time.monotonic()+.1)):
            process=subprocess.Popen([sys.executable,'-c',script],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                with self.assertRaises(ValueError):t.capture(process,end,budget)
            finally:t.stop(process)
            self.assertIsNotNone(process.poll())

    def test_real_subreaper_stops_and_reaps_detached_owned_descendant(self):
        # Handshake proves a real detached/adopted child before cleanup.
        # Scope this positive fixture's process inventory to that kernel task;
        # the separate exhaustion test covers the unchanged global scan bound.
        code = """
import ctypes, os, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
import codex_tools as t
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
read_fd, write_fd = os.pipe()
child = ('import os,time,sys;pid=os.fork();os._exit(0) if pid else None;'
         'os.setsid();os.write(int(sys.argv[1]),str(os.getpid()).encode()+bytes([10]));'
         'os.close(int(sys.argv[1]));time.sleep(10)')
p = subprocess.Popen([sys.executable, '-I', '-c', child, str(write_fd)],
                     pass_fds=(write_fd,), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.close(write_fd)
owned_pid = int(os.read(read_fd, 64))
os.close(read_fd)
p.wait(timeout=2)
assert owned_pid != p.pid and os.getsid(owned_pid) == owned_pid
with open('/proc/' + str(owned_pid) + '/status') as source:
    parents = [line.split()[1] for line in source if line.startswith('PPid:')]
assert parents == [str(os.getpid())], parents
real_scandir = t.os.scandir
def owned_inventory(path):
    assert path == '/proc'
    return real_scandir('/proc/' + str(owned_pid) + '/task')
t.os.scandir = owned_inventory
t.reap_owned(time.monotonic() + 2)
assert not os.path.exists('/proc/' + str(owned_pid))
try:
    os.waitpid(-1, os.WNOHANG)
except ChildProcessError:
    print('reaped')
else:
    raise AssertionError('owned child remains')
"""
        result = subprocess.run([sys.executable, '-I', '-c', code,
                                 str(Path(t.__file__).parent)],
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                capture_output=True, timeout=4)
        self.assertEqual((result.returncode, result.stdout), (0, b'reaped\n'),
                         result.stderr.decode(errors='replace'))

    def test_shared_process_inventory_exhaustion_blocks_without_foreign_signal(self):
        class Inventory:
            def __init__(self): self.consumed = 0; self.closed = False
            def __enter__(self): return self
            def __exit__(self, *args): self.closed = True
            def __iter__(self):
                for i in range(9000):
                    self.consumed += 1
                    yield type('Entry', (), {'name': str(i + 1)})()
        inventory = Inventory()
        with patch.object(t.os, 'waitpid', return_value=(0, 0)), \
             patch.object(t.os, 'scandir', return_value=inventory), \
             patch.object(t.os, 'pidfd_open', side_effect=PermissionError), \
             patch.object(t.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(ValueError, 'owned process inventory exceeded'):
                t.reap_owned(time.monotonic() + 2)
        self.assertEqual(inventory.consumed, 8193)
        self.assertTrue(inventory.closed)
        send.assert_not_called()

    def test_regular_bounded_snapshot_rejects_fifo_oversize_and_expiry(self):
        path=self.root/'data';path.write_bytes(b'abc')
        self.assertEqual(t.snapshot(path,3,time.monotonic()+1),b'abc')
        with self.assertRaises(ValueError):t.snapshot(path,2,time.monotonic()+1)
        with self.assertRaises(ValueError):t.snapshot(path,3,time.monotonic()-1)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaises(ValueError):t.snapshot(fifo,3,time.monotonic()+1)

    def test_cleanup_failure_never_keeps_passing_status(self):
        root=self.root/'owned';root.mkdir();(root/'marker').write_text('owned')
        real=t.shutil.rmtree
        def failed(path):real(path);raise OSError('injected after actual removal')
        report={'status':'pass','actions':[{'pass':True}]}
        with patch.object(t.shutil,'rmtree',side_effect=failed):t.finish_fixture(str(root),report,time.monotonic()+1)
        self.assertEqual(report['status'],'blocked');self.assertTrue(report['actions'][0]['pass']);self.assertFalse(root.exists())


class InventoryExtension(unittest.TestCase):
    setUp=OfflineTools.setUp
    body=OfflineTools.body
    def test_fixed_plan_preserves_original_and_32_mandatory_actions(self):
        planned=t.actions(12345)+t.inventory_actions()
        self.assertEqual(len(planned),32);self.assertEqual(len({a['id'] for a in planned}),32)
        self.assertEqual(sum(a['name']=='write_stdin' for a in planned),4)
        self.assertEqual(sum(a['kind']=='tool_search_call' for a in planned),3)
        self.assertFalse(any(a['name']=='spawn_agent' for a in planned))
        self.assertEqual((t.SECONDS,t.ACTION_SECONDS,t.REQUESTS,t.BODY_BYTES,t.OUTPUT_BYTES,t.REPORT_BYTES),(180,20,64,262144,2097152,4194304))

    def test_terminal_ids_are_only_bound_from_one_header_before_output(self):
        text='Chunk ID: x\nWall time: 0.2500 seconds\nProcess running with session ID 41\nOutput:\n'+t.PTY_READY
        self.assertEqual(t.terminal_header(text)[:2],(41,None))
        for value in ('Output:\nProcess running with session ID 41',
                      'Chunk ID: x\nOutput:\nProcess running with session ID 41',
                      text.replace('Output:','Process running with session ID 42\nOutput:'),
                      text.replace('Output:','Process exited with code 0\nOutput:')):
            with self.subTest(value=value),self.assertRaises(ValueError):t.terminal_header(value)

    def wire_item(self,wire):
        events=[json.loads(line[6:]) for line in wire.decode().splitlines() if line.startswith('data: ')]
        return next(event['item'] for event in events if event['type']=='response.output_item.done')

    def result(self,ident,text,kind='function_call_output'):
        return {'type':kind,'call_id':ident,'output':text}

    def test_dynamic_pty_poll_exact_input_retirement_and_replay(self):
        seq=t.Sequence(t.inventory_actions()[:5],self.root,time.monotonic()+5)
        self.wire_item(seq.request(self.body()))
        running='Chunk ID: x\nProcess running with session ID 41\nOutput:\n'+t.PTY_READY
        poll=self.wire_item(seq.request(self.body([self.result('pty-start',running)])))
        self.assertEqual(json.loads(poll['arguments'])['session_id'],41)
        self.assertEqual(self.wire_item(seq.request(self.body([self.result('pty-poll',running)])))['call_id'],'pty-input')
        marker=self.root/'job/src/pty-consumed';marker.write_text(t.PTY_TOKEN)
        proof={'consumed':True,'uid':1000,'cap_eff':'0','nnp':'1','netns':'different','denied':{'/credentials/marker':13,'/etc/codex/requirements.toml':30}}
        done='Process exited with code 0\nOutput:\n'+json.dumps(proof)
        stale=self.wire_item(seq.request(self.body([self.result('pty-input',done)])))
        self.assertEqual(json.loads(stale['arguments'])['session_id'],41)
        seq.request(self.body([self.result('pty-stale','write_stdin failed: Unknown process id 41')]))
        seq.request(self.body([self.result('pty-invalid','write_stdin failed: Unknown process id -1')]))
        self.assertTrue(seq.finished);self.assertTrue(seq.pty_retired);self.assertEqual(marker.read_text(),t.PTY_TOKEN)
        with self.assertRaisesRegex(ValueError,'finished'):seq.request(self.body())

    def test_pty_completion_poll_is_predeclared_once_and_failed_pending_record_is_retained(self):
        seq=t.Sequence(t.inventory_actions()[:5],self.root,time.monotonic()+5)
        seq.pty_id=19;seq.index=3
        marker=self.root/'job/src/pty-consumed';marker.write_text(t.PTY_TOKEN)
        running='Process running with session ID 19\nOutput:\n'
        seq.oracle(seq.planned[2],self.result('pty-input',running))
        self.assertEqual(seq.planned[3]['id'],'pty-complete');self.assertEqual(seq.planned[3]['arguments']['yield_time_ms'],5000)
        with self.assertRaises(ValueError):seq.oracle(seq.planned[3],self.result('pty-complete',running))
        other=t.Sequence(t.inventory_actions()[:5],self.root,time.monotonic()+5);marker.unlink()
        other.request(self.body());(self.root/'credentials/marker').write_text('changed')
        with self.assertRaises(ValueError):other.request(self.body([self.result('pty-start',running)]))
        self.assertFalse(other.records[-1]['pass']);self.assertFalse(other.finished)

    def database(self):
        import sqlite3
        path=self.root/'state/sqlite/goals_1.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE thread_goals (thread_id TEXT PRIMARY KEY,goal_id TEXT,objective TEXT,status TEXT,token_budget INTEGER,tokens_used INTEGER,time_used_seconds INTEGER,created_at_ms INTEGER,updated_at_ms INTEGER)')
            db.execute('INSERT INTO thread_goals VALUES (?,?,?,?,?,?,?,?,?)',('foreign','kept','foreign objective','active',None,0,0,1,1))
        return path

    def test_real_readonly_goal_database_scope_identity_and_wire_invariants(self):
        import sqlite3
        path=self.database();thread='00000000-0000-0000-0000-000000000001'
        seq=t.Sequence(t.inventory_actions()[6:15],self.root,time.monotonic()+5)
        seq.observe_cli(t.canonical({'type':'thread.started','thread_id':thread}));seq.metadata_products=seq.products()
        self.assertIsNone(seq.goal_state())
        seq.oracle(seq.planned[0],self.result('goal-empty',json.dumps({'goal':None})))
        seq.oracle(seq.planned[1],self.result('goal-missing','cannot update goal because this thread has no goal'))
        with sqlite3.connect(path) as db:db.execute('INSERT INTO thread_goals VALUES (?,?,?,?,?,?,?,?,?)',(thread,'owned',t.GOAL_OBJECTIVE,'active',None,0,0,2,2))
        payload={'goal':{'threadId':thread,'objective':t.GOAL_OBJECTIVE,'status':'active','tokensUsed':0,'timeUsedSeconds':0}}
        self.assertTrue(seq.oracle(seq.planned[4],self.result('goal-create',json.dumps(payload)))['pass'])
        before=path.read_bytes();self.assertEqual(t.goal_rows(path,thread_id=thread)[0]['goal_id'],'owned');self.assertEqual(path.read_bytes(),before)
        for field,value in (('threadId','wrong'),('objective','wrong'),('tokenBudget',10)):
            bad=json.loads(json.dumps(payload));bad['goal'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):seq.oracle(seq.planned[8],self.result('goal-get',json.dumps(bad)))
        with sqlite3.connect(path) as db:db.execute('UPDATE thread_goals SET goal_id=? WHERE thread_id=?',('replaced',thread))
        with self.assertRaisesRegex(ValueError,'identity replaced'):seq.oracle(seq.planned[5],self.result('goal-duplicate','cannot create a new goal because this thread has an unfinished goal; complete the existing goal first'))
        with sqlite3.connect(path) as db:db.execute('UPDATE thread_goals SET objective=? WHERE thread_id=?',('changed','foreign'))
        with self.assertRaisesRegex(ValueError,'unrelated'):seq.goal_state()
        with self.assertRaises(ValueError):seq.observe_cli(t.canonical({'type':'thread.started','thread_id':'not uuid'}))
        self.assertEqual(t.goal_rows(path,thread_id="' OR 1=1 --"),[])

    def search_namespace(self):
        props={name:{'type':kind} for name,kind in (('message','string'),('fork_context','boolean'),('model','string'),('reasoning_effort','string'))}
        props['items']={'type':'array','items':{'type':'object','properties':{name:{'type':'string'} for name in ('type','text','image_url','audio_url','path','name')},'additionalProperties':False}}
        return {'type':'namespace','name':'multi_agent_v1','description':'Tools for spawning and managing sub-agents.','tools':[{'type':'function','name':'spawn_agent','description':'metadata only','strict':False,'defer_loading':True,'parameters':{'type':'object','properties':props,'additionalProperties':False}}]}

    def test_special_search_wire_object_arguments_no_name_and_tools_meter(self):
        action=t.inventory_actions()[-3];seq=t.Sequence([action],self.root,time.monotonic()+5)
        body=self.body();body['tools']=[{'type':'tool_search','execution':'client','description':'Multi-agent tools'}]
        wire=self.wire_item(seq.request(body));self.assertEqual(wire['type'],'tool_search_call');self.assertNotIn('name',wire)
        self.assertIsInstance(wire['arguments'],dict);self.assertEqual(wire['execution'],'client')
        tools=[self.search_namespace()];self.assertEqual(t.search_definitions(tools),['multi_agent_v1.spawn_agent'])
        result={'type':'tool_search_output','call_id':'search-positive','status':'completed','execution':'client','tools':tools}
        before=seq.meter.used
        # Protocol dispatch and byte meter are checked independently of the
        # separate SQLite/registry effect oracle; synthetic outputs are not stock proof.
        with patch.object(seq,'oracle',return_value={'pass':True}):seq.request(dict(body,input=[result]))
        self.assertEqual(seq.meter.used-before,len(t.canonical(tools)))
        for kind in ('function_call_output','custom_tool_call_output'):
            other=t.Sequence([action],self.root,time.monotonic()+5);other.request(body)
            with self.assertRaisesRegex(ValueError,'cross-kind'):other.request(dict(body,input=[dict(result,type=kind)]))
        altered=json.loads(json.dumps(tools));altered[0]['tools'][0]['parameters']['properties']['unexpected']={'type':'string'}
        with self.assertRaises(ValueError):t.search_definitions(altered)

    def test_missing_search_source_and_changed_history_cannot_advance(self):
        seq=t.Sequence([t.inventory_actions()[-3]],self.root,time.monotonic()+5)
        with self.assertRaisesRegex(ValueError,'no evidenced'):seq.request(self.body())
        seq=t.Sequence([a for a in t.actions(123) if a['id'] in ('patch-deny','image-deny')],self.root,time.monotonic()+5)
        seq.request(self.body());first=self.result('patch-deny','Permission denied (os error 13)','custom_tool_call_output');seq.request(self.body([first]))
        with self.assertRaisesRegex(ValueError,'changed replayed'):seq.request(self.body([dict(first,output='changed'),self.result('image-deny','Permission denied (os error 13)')]))

    def test_empty_search_results_are_never_positive_or_handler_validator_evidence(self):
        import sqlite3
        path=self.database();thread='00000000-0000-0000-0000-000000000002'
        with sqlite3.connect(path) as db:db.execute('INSERT INTO thread_goals VALUES (?,?,?,?,?,?,?,?,?)',(thread,'owned',t.GOAL_OBJECTIVE,'complete',None,0,0,2,2))
        # The controller records the unrelated baseline before this synthetic
        # current-thread row; these assertions concern oracle semantics only.
        seq=t.Sequence(t.inventory_actions()[-3:],self.root,time.monotonic()+5)
        seq.goal_initial=[row for row in seq.goal_initial if row['thread_id']!=thread]
        seq.observe_cli(t.canonical({'type':'thread.started','thread_id':thread}))
        own=seq.goal_state();seq.goal_identity={k:own[k] for k in ('thread_id','goal_id','objective','token_budget','created_at_ms')}
        seq.metadata_products=seq.products()
        def output(ident):return {'type':'tool_search_output','call_id':ident,'status':'completed','execution':'client','tools':[]}
        with self.assertRaisesRegex(ValueError,'expected one evidenced'):seq.oracle(seq.planned[0],output('search-positive'))
        result=seq.oracle(seq.planned[1],output('search-whitespace'))
        self.assertTrue(result['pass']);self.assertFalse(result['handler_validation_witnessed'])
        self.assertEqual(result['coverage'],'bounded-invalid-input/no-definition')
        for altered in (dict(output('search-zero'),execution='server'),dict(output('search-zero'),status='failed'),dict(output('search-zero'),error='invented validator error')):
            with self.assertRaisesRegex(ValueError,'invalid special'):seq.oracle(seq.planned[2],altered)
        (self.root/'job/src/unplanned-search-effect').write_text('not metadata')
        with self.assertRaisesRegex(ValueError,'changed product'):seq.oracle(seq.planned[2],output('search-zero'))

    def test_real_pending_pty_is_stopped_on_fixture_failure(self):
        import pty
        master,slave=pty.openpty()
        child=subprocess.Popen([sys.executable,'-c','import os;print("ready",flush=True);os.read(0,1)'],
                               stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        os.close(slave)
        try:
            self.assertEqual(child.stdout.readline(),b'ready\n');self.assertIsNone(child.poll())
            with self.assertRaisesRegex(ValueError,'deadline'):t.capture(child,time.monotonic()+.05,[0])
        finally:
            t.stop(child);os.close(master)
        self.assertIsNotNone(child.poll());self.assertLess(child.returncode,0)

    def test_product_metadata_snapshot_never_follows_links_and_has_finite_inventory(self):
        seq=t.Sequence([],self.root,time.monotonic()+5)
        outside=self.root/'outside';outside.write_text('must not be read as product')
        (self.root/'job/src/linked').symlink_to(outside)
        proof=seq.products();self.assertEqual(proof['linked'],{'symlink':str(outside)})
        for i in range(129):(self.root/'job/src'/('bounded-'+str(i))).touch()
        with self.assertRaisesRegex(ValueError,'oracle bound'):seq.products()
        self.assertEqual(outside.read_text(),'must not be read as product')

    def test_named_goal_context_requires_correlated_creation_and_actual_database_identity(self):
        import sqlite3
        path=self.database();thread='00000000-0000-0000-0000-000000000003'
        planned=[a for a in t.inventory_actions() if a['id'] in ('goal-create','goal-duplicate')]
        seq=t.Sequence(planned,self.root,time.monotonic()+5)
        seq.observe_cli(t.canonical({'type':'thread.started','thread_id':thread}));seq.metadata_products=seq.products()
        context={'type':'function_call_output','namespace':'agent','name':'goal_objective','output':t.GOAL_OBJECTIVE}
        with self.assertRaisesRegex(ValueError,'established create'):seq.observe_goal_context(context)
        seq.request(self.body())
        with sqlite3.connect(path) as db:db.execute('INSERT INTO thread_goals VALUES (?,?,?,?,?,?,?,?,?)',(thread,'owned',t.GOAL_OBJECTIVE,'active',None,0,0,2,2))
        payload={'goal':{'threadId':thread,'objective':t.GOAL_OBJECTIVE,'status':'active','tokensUsed':0,'timeUsedSeconds':0}}
        result=self.result('goal-create',json.dumps(payload))
        seq.request(self.body([context,result]))
        self.assertEqual(seq.goal_context['caused_by_call_id'],'goal-create');self.assertEqual(seq.goal_context['goal_id'],'owned')
        seq.observe_goal_context(context)
        for bad in (dict(context,output='changed'),dict(context,name='other'),dict(context,namespace='functions'),dict(context,call_id=None)):
            with self.assertRaisesRegex(ValueError,'unknown uncorrelated'):seq.observe_goal_context(bad)
        with sqlite3.connect(path) as db:db.execute('UPDATE thread_goals SET goal_id=? WHERE thread_id=?',('foreign replacement',thread))
        with self.assertRaisesRegex(ValueError,'database identity'):seq.observe_goal_context(context)

    def test_goal_context_exception_never_admits_generic_orphan_null_or_duplicate_outputs(self):
        context={'type':'function_call_output','namespace':'agent','name':'goal_objective','output':t.GOAL_OBJECTIVE}
        for items in ([context],[context,context],[dict(context,call_id=None)],[dict(context,call_id='unissued')]):
            seq=t.Sequence([a for a in t.actions(123) if a['id']=='patch-deny'],self.root,time.monotonic()+5)
            seq.request(self.body());last=self.result('patch-deny','Permission denied (os error 13)','custom_tool_call_output')
            with self.assertRaises(ValueError):seq.request(self.body(items+[last]))
            self.assertIsNone(seq.goal_context);self.assertFalse(seq.finished)
            self.assertEqual(seq.last_outputs,items+[last])
            self.assertIsNotNone(seq.last_request_identity)
