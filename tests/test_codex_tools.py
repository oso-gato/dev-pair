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
        code=('import sys,subprocess,ctypes,time,os;sys.path.insert(0,sys.argv[1]);import codex_tools as t;'
              'assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0;'
              'p=subprocess.Popen([sys.executable,"-c","import os,time;pid=os.fork();os._exit(0) if pid else None;os.setsid();time.sleep(10)"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
              'p.wait(timeout=2);t.reap_owned(time.monotonic()+2);print("reaped")')
        result=subprocess.run([sys.executable,'-c',code,str(Path(t.__file__).parent)],capture_output=True,timeout=4)
        self.assertEqual((result.returncode,result.stdout),(0,b'reaped\n'))

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
