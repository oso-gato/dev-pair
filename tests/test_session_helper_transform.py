"""Independent process evidence plus exact byte transform and private fallback."""
import copy
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import codex_sessions as s
import session_helper as h
import codex_tools as t
import test_session_helper as lock_fixture
import test_codex_sessions as session_fixture
IDS=session_fixture.IDS;NONCE=session_fixture.NONCE;body=session_fixture.body


def content(text):return [{'type':'input_text','text':text}]
def environment(path):
    return '<environment_context>\n  <cwd>/job</cwd>\n  <shell>bash</shell>\n  <current_date>2026-11-22</current_date>\n  <timezone>UTC</timezone>\n  <filesystem><workspace_roots><root>/job</root></workspace_roots><permission_profile type="managed"><file_system type="restricted"><entry access="read"><path>'+h.xml_text(path)+'</path></entry><entry access="deny" escalatable="false"><path>/credentials</path></entry></file_system></permission_profile></filesystem>\n</environment_context>'
def resumed(text,old,new):return text.replace('<cwd>/job</cwd>\n  ','').replace('<shell>bash</shell>\n  ','').replace('<path>'+h.xml_text(old)+'</path>','<path>'+h.xml_text(new)+'</path>')


class HelperTransformTests(unittest.TestCase):
    setUp=lock_fixture.OwnedHelperTests.setUp
    stop=lock_fixture.OwnedHelperTests.stop
    start=lock_fixture.OwnedHelperTests.start
    observer=lock_fixture.OwnedHelperTests.observer
    def pair(self):
        child=self.start();first=self.observer(child).capture();old=self.directory
        child.kill();child.wait(timeout=2)
        import shutil
        shutil.rmtree(old)  # No fabricated post-exit inspection of original.
        self.directory=self.aliases/'codex-arg0DEF456';self.directory.mkdir(mode=0o700)
        for name in ('apply_patch','applypatch','codex-linux-sandbox'):(self.directory/name).symlink_to(self.binary)
        current=self.start();second=self.observer(current).capture()
        original=environment(first.path);new=resumed(original,first.path,second.path)
        return first,second,original,new,current
    def test_exact_observed_rotation_only_and_all_security_body_mutations_block(self):
        first,second,old,new,_=self.pair()
        self.assertTrue(h.transformed(content(old),content(new),first,second,s.environment_components))
        self.assertFalse(h.transformed(content(old),content(new),{'path':first.path},{'path':second.path},s.environment_components))
        self.assertFalse(h.transformed(content(old),content(new),None,second,s.environment_components))
        variants=[new+' ',new.replace('access="read"','access="write"'),new.replace('escalatable="false"','escalatable="true"'),
            new.replace('type="restricted"','type="unrestricted"'),new.replace('<root>/job</root>','<root>/PRIVATE_OTHER</root>'),
            new.replace('2026-11-22','2026-11-23'),new.replace('<timezone>UTC</timezone>','<timezone>OTHER</timezone>'),
            new.replace(h.xml_text(second.path),'PRIVATE_FORGED'),new.replace('<entry access="deny"','<entry access="read"'),
            new.replace('</file_system>','<entry access="read"><path>'+h.xml_text(second.path)+'</path></entry></file_system>')]
        for variant in variants:self.assertFalse(h.transformed(content(old),content(variant),first,second,s.environment_components))
        duplicated=old.replace('</file_system>','<entry access="read"><path>'+h.xml_text(first.path)+'</path></entry></file_system>')
        self.assertFalse(h.transformed(content(duplicated),content(new),first,second,s.environment_components))
    def test_all_entry_fallback_distinguishes_encoding_order_access_and_privacy(self):
        first,second,old,new,_=self.pair();value=h.filesystem_witness(content(old),content(new),s.environment_components)
        self.assertEqual(value['status'],'observed');self.assertEqual(value['counts'][-1],1)
        self.assertEqual(value['counts'][4:6],[1,1]);self.assertFalse(value['truncated']);self.assertEqual(len(value['details']),1)
        self.assertNotIn(str(self.root),json.dumps(value));self.assertNotIn('/credentials',json.dumps(value))
        same=h.filesystem_witness(content(old),content(old),s.environment_components)
        self.assertEqual(same['checks'][1]&31,31)
        encoded=old.replace('<root>/job</root>','<root>&#47;job</root>')
        different=h.filesystem_witness(content(old),content(encoded),s.environment_components)
        self.assertFalse(different['checks'][1]&1);self.assertTrue(different['checks'][1]&2)
        entries=h.filesystem(content(old),s.environment_components)
        a,b=entries['entries'];start=old.index('<entry ');end=old.index('</file_system>')
        parts=old[start:end];split=parts.index('</entry>')+8;reordered=old[:start]+parts[split:]+parts[:split]+old[end:]
        order=h.filesystem_witness(content(old),content(reordered),s.environment_components)
        self.assertFalse(order['checks'][1]&2);self.assertTrue(order['checks'][1]&4)
        invalid=old.replace('access="read"','access="PRIVATE_INVALID"')
        self.assertEqual(h.filesystem_witness(content(old),content(invalid),s.environment_components),{'status':'unavailable'})
    def test_journey_requires_publication_then_replays_exact_suffix_and_bounds_witness(self):
        first,second,old,new,child=self.pair();case=session_fixture.SessionsTests();case.setUp();self.addCleanup(case.doCleanups)
        path,rows,row,entry,env,current,items=case.environment_resume()
        entry['user_context'][0]['content']=content(old);rows[1]['payload']['content']=content(old)
        case.write_rollout(path,rows);case.j.audit_first_rollout(row,'alpha')
        items[:2]=copy.deepcopy(entry['user_context']);items[-2]['content']=content(new)
        case.observed('alpha','resume');case.j.helper_binary=self.binary;case.j.helper_origins['alpha']=first
        original=h.OwnedChild
        with patch.object(h,'OwnedChild',side_effect=lambda process,end,binary:original(process,end,binary,self.aliases)):
            case.j.publish_child(child)
        self.addCleanup(case.j.clear_child)
        case.j.request(body(items));self.assertIsNotNone(case.j.turn['issued'])
        retained=copy.deepcopy(case.j.turn['user_context']);issued=copy.deepcopy(case.j.turn['issued'])
        output=case.run_action(issued)
        from test_codex_sessions import terminal
        returned={'type':'function_call_output','call_id':issued['call_id'],'output':terminal(output)}
        changed=copy.deepcopy(items);changed[-2]['content'][0]['text']+=' '
        with self.assertRaises(ValueError):case.j.request(body(changed+[issued,returned]))
        self.assertEqual(case.j.turn['user_context'],retained);self.assertIsNone(case.j.turn['returned'])
        witness=case.j.resume_context_rejection;self.assertLessEqual(len(t.canonical(witness)),2048)
        self.assertNotIn(str(self.root),json.dumps(witness));self.assertIn('filesystem',witness['environment_comparison'])
        case.j.request(body(items+[issued,returned]));self.assertTrue(case.j.turn['finished'])
        case.j.observe_cli(t.canonical({'type':'turn.completed','usage':{}}));case.j.finish(0)
        env['content']=content(new)
        rows += [{'type':'response_item','payload':value} for value in (env,current,issued,returned)]
        case.write_rollout(path,rows)
        self.assertEqual(s.rollout_proof(case.root,row,entry,continuation=case.j.continuations['alpha'])['uuid'],IDS['alpha'])
        rows[-4]['payload']['content'][0]['text']+=' '
        case.write_rollout(path,rows)
        with self.assertRaises(ValueError):s.rollout_proof(case.root,row,entry,continuation=case.j.continuations['alpha'])
        case.j.clear_child()
        with self.assertRaises(ValueError):case.j.observe_helper()
    def test_request_before_publication_and_other_turn_handle_block(self):
        case=session_fixture.SessionsTests();case.setUp();self.addCleanup(case.doCleanups);case.observed('alpha')
        case.j.helper_binary=self.binary;case.j.action_end=time.monotonic()+.01
        with self.assertRaises(ValueError):case.j.observe_helper()
        child=self.start();original=h.OwnedChild;case.j.action_end=time.monotonic()+2
        with patch.object(h,'OwnedChild',side_effect=lambda process,end,binary:original(process,end,binary,self.aliases)):case.j.publish_child(child)
        self.addCleanup(case.j.clear_child);case.j.child_turn={}
        with self.assertRaises(ValueError):case.j.observe_helper()

    def test_multi_entry_fallback_preserves_all_counts_and_bounds_without_values(self):
        first,second,old,new,_=self.pair()
        extra=''.join('<entry access="read"><path>/PRIVATE_OPAQUE_'+str(i)+'</path></entry>' for i in range(40))
        old=old.replace('</file_system>',extra+'</file_system>')
        new=resumed(old,first.path,second.path).replace('/PRIVATE_OPAQUE_','/PRIVATE_CHANGED_')
        case=session_fixture.SessionsTests();case.setUp();self.addCleanup(case.doCleanups)
        path,rows,row,entry,_,_,items=case.environment_resume()
        entry['user_context'][0]['content']=content(old);rows[1]['payload']['content']=content(old)
        case.write_rollout(path,rows);case.j.audit_first_rollout(row,'alpha')
        items[:2]=copy.deepcopy(entry['user_context']);items[-2]['content']=content(new)
        case.observed('alpha','resume')
        with self.assertRaises(ValueError):case.j.request(body(items))
        witness=case.j.resume_context_rejection;summary=witness['environment_comparison']['filesystem']
        self.assertLessEqual(len(t.canonical(witness)),2048);self.assertNotIn('PRIVATE',json.dumps(witness))
        self.assertEqual(summary['status'],'observed');self.assertEqual(summary['counts'][2:4],[42,42])
        self.assertEqual(summary['counts'][4:],[41,41,41]);self.assertTrue(summary['truncated'])
        self.assertTrue(summary['details']);self.assertIsNone(case.j.turn['issued'])


if __name__=='__main__':unittest.main()
