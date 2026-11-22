"""Exact producer encodings and durable negative predicates; synthetic only."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'tools')]
import codex_sessions as s
import codex_tools as t

BARE='no rollout found for thread id '+s.UNKNOWN
TYPED='thread/resume: thread/resume failed: '+BARE+' (code -32600)'

class UnknownUUIDTests(unittest.TestCase):
    def journey(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        j=s.Journey(self.tmp.name,time.monotonic()+10,t.Meter(),'a'*32)
        j.negative=True;j.action_end=time.monotonic()+3
        return j
    def test_exact_source_grammar_and_controls(self):
        for value in (BARE,'Error: '+BARE,TYPED,'Error: '+TYPED):
            self.assertTrue(s.unknown_reason(value));self.assertNotEqual(s.stderr_reason_family((value+'\n').encode(),True),'none')
        variants=[TYPED.replace(s.UNKNOWN,'00000000-0000-4000-8000-000000000002'),TYPED.replace('-32600','-32601'),
            TYPED.replace('thread/resume','thread/start',1),TYPED.replace('thread/resume: ',''),TYPED+' data=null',
            'prefix '+TYPED,TYPED+' suffix',TYPED.replace('thread id','conversation id'),
            '\x1b[31m'+TYPED,TYPED+'\r',TYPED+'\nPRIVATE',TYPED+'\n\n','authentication failed','transport error',None]
        for value in variants:
            self.assertFalse(s.unknown_reason(value))
            if value is not None:self.assertIn(s.stderr_reason_family(value.encode(),True),(None,'none'))
        self.assertIsNone(s.stderr_reason_family(TYPED.encode(),False))
        self.assertEqual(s.stderr_reason_family(b'\xff'+TYPED.encode(),True),'none')
    def test_independent_predicate_matrix_persists_each_failure_before_guard(self):
        j=self.journey()
        for code in (1,0,2,-9,True):
            for delta in (0,1):
                for stderr,cli in ((False,False),(False,True),(True,False),(True,True)):
                    before=j.requests;report={}
                    def runner(*args):
                        j.requests+=delta;j.negative_reason_witnessed=cli
                        return code,{'unknown_uuid_reason_witnessed':stderr,'stderr_bytes':0,'stderr_sha256':s.sha(b''),
                            'stderr_capture_complete':True,'stderr_reason_family':'typed-thread' if stderr else 'none'}
                    accepted=type(code) is int and code==1 and delta==0 and (stderr or cli)
                    if accepted:s.check_unknown_uuid(report,j,[],j.meter,j.end,runner=runner)
                    else:
                        with self.assertRaisesRegex(ValueError,'unknown UUID rejection'):s.check_unknown_uuid(report,j,[],j.meter,j.end,runner=runner)
                    w=report['unknown_uuid_evidence'];self.assertEqual(w['stage'],'returned');self.assertEqual(w['exit_code'],code if type(code) is int else None);self.assertEqual(w['exit_status_valid'],type(code) is int)
                    self.assertEqual(w['requests_before'],before);self.assertEqual(w['request_delta'],delta)
                    self.assertIs(w['stderr_reason'],stderr);self.assertIs(w['cli_event_reason'],cli)
                    self.assertEqual(report.get('unknown_uuid_rejected',False),accepted)
    def test_exception_and_unlaunched_absence_preserves_primary_unknown_fields(self):
        j=self.journey();report={};error=OSError('PRIVATE synthetic launch failure')
        def runner(*args):raise error
        with self.assertRaises(OSError) as caught:s.check_unknown_uuid(report,j,[],j.meter,j.end,runner=runner)
        self.assertIs(caught.exception,error);w=report['unknown_uuid_evidence']
        self.assertEqual(w['stage'],'exception');self.assertIsNone(w['exit_code']);self.assertIsNone(w['launch_handle_observed'])
        self.assertIsNone(w['stderr_reason']);self.assertIsNone(w['stderr_bytes']);self.assertEqual(w['request_delta'],0)
        self.assertNotIn('PRIVATE',json.dumps(w));self.assertNotIn('unknown_uuid_rejected',report)
        report={}
        with self.assertRaises(FileNotFoundError):s.check_unknown_uuid(report,j,['/NONEXISTENT/PRIVATE'],j.meter,j.end)
        w=report['unknown_uuid_evidence'];self.assertFalse(w['launch_handle_observed']);self.assertIsNone(w['natural_exit_observed'])
        self.assertIsNone(w['stderr_bytes']);self.assertEqual(w['stage'],'exception');self.assertNotIn('PRIVATE',json.dumps(w))
    def run_child(self,script):
        j=self.journey();report={}
        try:s.check_unknown_uuid(report,j,[sys.executable,'-c',script],j.meter,j.end)
        except Exception as error:return j,report,error
        return j,report,None
    def test_real_complete_stderr_hash_and_truncation_without_raw_disclosure(self):
        raw=('Error: '+TYPED+'\n').encode();j,report,error=self.run_child('import os;os.write(2,'+repr(raw)+');raise SystemExit(1)')
        self.assertIsNone(error);w=report['unknown_uuid_evidence'];self.assertEqual(w['stderr_sha256'],s.sha(raw))
        self.assertEqual(w['stderr_bytes'],len(raw));self.assertTrue(w['stderr_capture_complete']);self.assertTrue(w['natural_exit_observed'])
        self.assertEqual(w['natural_exit_code'],1);self.assertTrue(w['launch_handle_observed']);self.assertNotIn(TYPED,json.dumps(w))
        j,report,error=self.run_child('import os;os.write(2,'+repr(raw+b'PRIVATE'*700)+');raise SystemExit(1)')
        self.assertIsNotNone(error);w=report['unknown_uuid_evidence'];self.assertFalse(w['stderr_capture_complete'])
        self.assertIsNone(w['stderr_sha256']);self.assertIsNone(w['stderr_reason']);self.assertEqual(w['stderr_retained_bytes'],4096)
        self.assertNotIn('PRIVATE',json.dumps(w))
    def test_cli_exact_errors_forbidden_events_and_malformed_stream_remain_blocking(self):
        for kind in ('error','turn.failed'):
            event={'type':kind,'message':TYPED} if kind=='error' else {'type':kind,'error':{'message':TYPED}}
            _,report,error=self.run_child('import json;print('+repr(json.dumps(event))+');raise SystemExit(1)')
            self.assertIsNone(error);self.assertTrue(report['unknown_uuid_evidence']['cli_event_reason'])
        for first in ({'type':'thread.started','thread_id':s.UNKNOWN},{'type':'turn.started'},
                {'type':'error','message':TYPED,'data':None},{'type':'turn.failed','error':{'message':TYPED,'code':-32600}}):
            wire=json.dumps(first)+'\n'+json.dumps({'type':'error','message':TYPED})+'\n'
            _,report,error=self.run_child('import os;os.write(1,'+repr(wire.encode())+');raise SystemExit(1)')
            self.assertIsNotNone(error);w=report['unknown_uuid_evidence'];self.assertEqual(w['stage'],'exception');self.assertNotIn('unknown_uuid_rejected',report)
            if first['type'] not in ('error','turn.failed'):self.assertTrue(w['forbidden_thread_event'])
        for wire in (b'{',b'{"type":"error","type":"error","message":"PRIVATE"}\n'):
            _,report,error=self.run_child('import os;os.write(1,'+repr(wire)+');raise SystemExit(1)')
            self.assertIsNotNone(error);self.assertNotIn('PRIVATE',json.dumps(report));self.assertIsNone(report['unknown_uuid_evidence']['exit_code'])
    def test_partial_capture_and_cleanup_failure_do_not_invent_natural_exit(self):
        j=self.journey();report={}
        with patch.object(s.selectors,'DefaultSelector',side_effect=OSError('PRIVATE selector')):
            with self.assertRaises(OSError):s.check_unknown_uuid(report,j,[sys.executable,'-c','import time;time.sleep(2)'],j.meter,j.end)
        w=report['unknown_uuid_evidence'];self.assertTrue(w['launch_handle_observed']);self.assertFalse(w['natural_exit_observed'])
        self.assertIsNone(w['natural_exit_code']);self.assertIsNone(w['exit_code']);self.assertFalse(w['stderr_capture_complete'])
        self.assertEqual(w['stderr_bytes'],0);self.assertIsNone(w['stderr_reason'])
        j=self.journey();j.meter=t.Meter(0,10);report={}
        with self.assertRaises(ValueError):s.check_unknown_uuid(report,j,[sys.executable,'-c','import os;os.write(2,b"PRIVATE"*900)'],j.meter,j.end)
        w=report['unknown_uuid_evidence'];self.assertGreater(w['stderr_bytes'],10);self.assertFalse(w['stderr_capture_complete'])
        self.assertIsNone(w['exit_code']);self.assertFalse(w['natural_exit_observed']);self.assertNotIn('PRIVATE',json.dumps(w))
    def test_final_database_and_both_durable_audits_still_required(self):
        j=self.journey();ids={'alpha':'1','beta':'2'};j.entries={'alpha':{},'beta':{}};j.continuations={'alpha':{},'beta':{}}
        source=Path(self.tmp.name)/'source';source.write_bytes(s.UNCOMMITTED)
        for failure in ('database','first-rollout','second-rollout',None):
            report={'status':'blocked','checkpoint_sha256':'a'*64,'unknown_uuid_rejected':True};calls=[]
            def proof(*args,**kw):
                calls.append(args)
                if failure==('first-rollout' if len(calls)==1 else 'second-rollout'):raise ValueError('durable audit')
                return {'verified':True}
            with patch.object(s,'database',side_effect=ValueError('database') if failure=='database' else None,return_value={'1':{},'2':{}}) as db,patch.object(s,'marker',return_value={}),patch.object(s,'rollout_proof',side_effect=proof):
                if failure:
                    with self.assertRaises(ValueError):s.final_session_audits(report,j,{},ids,source,root=self.tmp.name)
                    self.assertEqual(report['status'],'blocked')
                else:
                    s.final_session_audits(report,j,{},ids,source,root=self.tmp.name);self.assertEqual(report['status'],'pass');self.assertEqual(len(calls),2)
                db.assert_called_once_with(self.tmp.name,{'1','2'},integrity=True)

if __name__=='__main__':unittest.main()
