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

    def unavailable_resume(self):
        first,second,old,new,child=self.pair();case=session_fixture.SessionsTests();case.setUp();self.addCleanup(case.doCleanups)
        path,rows,row,entry,_,_,items=case.environment_resume()
        entry['user_context'][0]['content']=content(old);rows[1]['payload']['content']=content(old)
        case.write_rollout(path,rows);case.j.audit_first_rollout(row,'alpha')
        items[:2]=copy.deepcopy(entry['user_context']);items[-2]['content']=content(new)
        case.observed('alpha','resume');case.j.helper_binary=self.binary;case.j.helper_origins['alpha']=first
        original=h.OwnedChild
        with patch.object(h,'OwnedChild',side_effect=lambda process,end,binary:original(process,end,binary,self.aliases)):case.j.publish_child(child)
        self.addCleanup(case.j.clear_child)
        alias=self.directory/'apply_patch';alias.unlink();alias.symlink_to('/PRIVATE_INCOMPATIBLE_EXECUTABLE')
        return case,items,old

    def test_unavailable_helper_keeps_complete_resume_fallback_and_primary_rejection(self):
        case,items,old=self.unavailable_resume();retained=copy.deepcopy(case.j.entries)
        for same in (False,True):
            current=copy.deepcopy(items)
            if same:current[-2]['content']=content(old)
            case.j.resume_context_rejection=None;case.j.helper_rejection=None
            with self.assertRaisesRegex(ValueError,'^owned CLI helper binding unavailable$'):case.j.request(body(current))
            self.assertEqual(case.j.entries,retained);self.assertIsNone(case.j.turn['issued']);self.assertIsNone(case.j.turn['user_context'])
            self.assertFalse(case.j.continuations);self.assertEqual(case.j.helper_rejection['stage'],'binary-alias')
            witness=case.j.resume_context_rejection;summary=witness['filesystem']
            self.assertFalse(witness['helper_binding']['helper_available']);self.assertTrue(witness['helper_binding']['baseline_audited'])
            self.assertEqual(summary['status'],'observed');self.assertEqual(summary['counts'][2:4],[2,2])
            self.assertEqual(bool(summary['checks'][1]&2),same)
            self.assertEqual(witness['request'],case.j.last_request);self.assertEqual(witness['harness_sha256'],case.j.harness_sha256)
            self.assertLessEqual(len(t.canonical(witness)),2048);self.assertNotIn('PRIVATE',json.dumps(witness))
            first=copy.deepcopy(witness)
            with self.assertRaises(ValueError):case.j.request(body(current))
            self.assertEqual(case.j.resume_context_rejection,first)

    def test_unavailable_helper_missing_malformed_or_oversized_body_stays_truthful(self):
        case,items,old=self.unavailable_resume();variants=[]
        for value in ('<environment_context><filesystem PRIVATE="SECRET"/></environment_context>',
                '<!DOCTYPE x [<!ENTITY x "SECRET">]><environment_context/>',
                '<environment_context><cwd>'+'x'*17000+'</cwd></environment_context>'):
            changed=copy.deepcopy(items);changed[-2]['content']=content(value);variants.append(changed)
        variants.append(items[:-2]+[items[-1]])
        for changed in variants:
            case.j.resume_context_rejection=None;case.j.helper_rejection=None
            with self.assertRaisesRegex(ValueError,'^owned CLI helper binding unavailable$'):case.j.request(body(changed))
            witness=case.j.resume_context_rejection
            self.assertEqual(witness['filesystem'],{'status':'unavailable'})
            self.assertLessEqual(len(t.canonical(witness)),2048);self.assertNotIn('SECRET',json.dumps(witness))
            self.assertIsNone(case.j.turn['issued'])
        case.j.first_rollout_audits.clear();case.j.resume_context_rejection=None;case.j.helper_rejection=None
        with self.assertRaises(ValueError):case.j.request(body(items))
        self.assertFalse(case.j.resume_context_rejection['helper_binding']['old_body_available'])
        self.assertEqual(case.j.resume_context_rejection['filesystem'],{'status':'unavailable'})

    def test_first_unavailable_helper_never_fabricates_prior_filesystem(self):
        child=self.start();case=session_fixture.SessionsTests();case.setUp();self.addCleanup(case.doCleanups);case.observed('alpha')
        case.j.helper_binary=self.binary;original=h.OwnedChild
        with patch.object(h,'OwnedChild',side_effect=lambda process,end,binary:original(process,end,binary,self.aliases)):case.j.publish_child(child)
        self.addCleanup(case.j.clear_child);alias=self.directory/'apply_patch';alias.unlink();alias.symlink_to('/PRIVATE_WRONG')
        environment_item=session_fixture.source_wire(session_fixture.durable_message(environment(str(self.directory)),s.ENVIRONMENT_KIND))
        inputs=[environment_item,session_fixture.message(s.prompt('alpha','first',NONCE))]
        with self.assertRaisesRegex(ValueError,'^owned CLI helper binding unavailable$'):case.j.request(body(inputs))
        self.assertEqual(case.j.helper_origins,{});self.assertIsNone(case.j.turn['issued']);self.assertIsNone(case.j.resume_context_rejection)
        self.assertEqual(case.j.helper_rejection['filesystem'],{'status':'unavailable','reason':'missing-baseline'})
        self.assertTrue(case.j.helper_rejection['knownness']['new_body_available'])
        self.assertFalse(case.j.helper_rejection['knownness']['old_body_available'])
        first=copy.deepcopy(case.j.helper_rejection)
        with self.assertRaises(ValueError):case.j.request(body(inputs[-1:]))
        self.assertEqual(case.j.helper_rejection,first)

    def test_unavailable_fallback_preserves_whole_environment_contract(self):
        case,items,old=self.unavailable_resume()
        def rejected(incoming):
            before=copy.deepcopy((case.j.entries,case.j.turn,case.j.continuations));origins=dict(case.j.helper_origins)
            case.j.helper_rejection=None;case.j.resume_context_rejection=None
            with self.assertRaisesRegex(ValueError,'^owned CLI helper binding unavailable$'):case.j.request(body(incoming))
            self.assertEqual(before,(case.j.entries,case.j.turn,case.j.continuations));self.assertEqual(origins,case.j.helper_origins)
            witness=case.j.resume_context_rejection
            self.assertLessEqual(len(t.canonical(witness)),2048);self.assertNotIn('PRIVATE',json.dumps(witness))
            self.assertFalse(witness['helper_binding']['helper_available'])
            self.assertEqual(witness['request'],case.j.last_request)
            self.assertEqual(witness['harness_sha256'],case.j.harness_sha256)
            return witness
        def flag(witness,key):return s.comparison_flag({'checks':witness['environment_checks']},key)
        witness=rejected(items);expected=s.component_comparison(content(old),items[-2]['content'])
        self.assertEqual(witness['body'],[len(t.canonical(content(old))),len(t.canonical(items[-2]['content'])),t.sha(t.canonical(content(old))),t.sha(t.canonical(items[-2]['content']))])
        for key in ('status','presence','order','equal','wrapper_equal','complete'):self.assertEqual(witness['components'][key],expected[key])
        self.assertEqual(witness['components']['known'],3);self.assertTrue(witness['components']['truncated'])
        self.assertTrue(flag(witness,'causal_positions_valid'));self.assertTrue(flag(witness,'current_prompt_schema'))
        self.assertFalse(flag(witness,'exact_environment_content_equal'))
        moved=items[:3]+[items[-2],items[3],items[-1]]
        self.assertFalse(flag(rejected(moved),'causal_positions_valid'))
        changed=copy.deepcopy(items);changed[0]['content'][0]['text']+=' '
        self.assertFalse(rejected(changed)['exact_old_prefix_equal'])
        changed=copy.deepcopy(items);changed[2]['arguments']='{}'
        self.assertFalse(flag(rejected(changed),'original_pair_exact'))
        for target,key,value,check,expected_flag in [(-2,'id',None,'closed_environment_schema',False),
                (-1,'id','msg_input_'+IDS['alpha'],'current_prompt_schema',False)]:
            changed=copy.deepcopy(items);changed[target][key]=value;witness=rejected(changed)
            self.assertIs(flag(witness,check),expected_flag)
            self.assertEqual(witness['body'][3],t.sha(t.canonical(changed[-2]['content'])))
        for target,value,check,expected_flag in [(-2,None,'new_turn_valid',False),(-1,IDS['alpha'],'new_turn_matches_current_prompt',False)]:
            changed=copy.deepcopy(items);changed[target][s.METADATA]['turn_id']=value
            self.assertIs(flag(rejected(changed),check),expected_flag)
        case.j.first_rollout_audits.clear();witness=rejected(items)
        self.assertIsNone(witness['body'][0]);self.assertIsNone(witness['body'][2])
        self.assertIsNone(flag(witness,'baseline_schema'));self.assertIsNone(flag(witness,'exact_environment_content_equal'))
        self.assertEqual(witness['components']['status'][0],'unavailable')
        self.assertIsNone(witness['components']['presence'][0]);self.assertEqual(witness['components']['known'],2)
        entry=case.j.entries['alpha'];original=copy.deepcopy(entry)
        for contexts in ([original['user_context'][-1]],[original['user_context'][0],*original['user_context']]):
            entry.clear();entry.update(copy.deepcopy(original));entry['user_context']=copy.deepcopy(contexts)
            case.j.first_rollout_audits['alpha']=t.sha(t.canonical(entry))
            incoming=copy.deepcopy(contexts)+[entry['call'],entry['output'],items[-2],items[-1]]
            witness=rejected(incoming)
            self.assertEqual(witness['baseline_count'],0 if len(contexts)==1 else 2)
            self.assertIsNone(witness['body'][2]);self.assertEqual(witness['filesystem'],{'status':'unavailable'})

    def test_combined_core_budget_keeps_aggregates_before_optional_fields(self):
        case,items,old=self.unavailable_resume();entry=case.j.entries['alpha']
        old=old.replace('</workspace_roots>',''.join('<root>/PRIVATE_ROOT_'+str(i)+'</root>' for i in range(10))+'</workspace_roots>')
        old=old.replace('type="restricted"','type="restricted" glob_scan_max_depth="4294967295"')
        old=old.replace('</file_system>',''.join('<entry access="read"><path>/PRIVATE_OLD_'+str(i)+'</path></entry>' for i in range(40))+'</file_system>')
        old=old.replace('</environment_context>','<status>x</status><error>x</error><environments><environment id="x"><cwd>x</cwd></environment></environments><shell_version>x</shell_version><network enabled="true"><allowed>x</allowed></network><subagents>'+('x'*10000)+'</subagents></environment_context>')
        entry['user_context'][0]['content']=content(old)
        path=case.root/'state/codex/sessions/fixture.jsonl';rows=[json.loads(x) for x in path.read_text().splitlines()]
        rows[1]['payload']['content']=content(old);case.write_rollout(path,rows)
        row=s.database(case.root,{IDS['alpha']},integrity=True)[IDS['alpha']];case.j.audit_first_rollout(row,'alpha')
        items[:2]=copy.deepcopy(entry['user_context']);items[0]['content'][0]['text']+=' '
        new=old.replace('PRIVATE_OLD_','PRIVATE_NEW_').replace('PRIVATE_ROOT_','PRIVATE_NEW_ROOT_').replace('4294967295','4294967294')
        items[-2]['content']=content(new);items[-1]['content'][0]['text']+='x';items[-1]['id']='PRIVATE_BAD_ID'
        items[-1].update(encrypted_content='PRIVATE',status='PRIVATE',phase='PRIVATE')
        items[-1][s.METADATA].update({str(i):'PRIVATE' for i in range(1000)})
        before=copy.deepcopy((case.j.entries,case.j.turn,case.j.continuations));origins=dict(case.j.helper_origins)
        with self.assertRaisesRegex(ValueError,'^owned CLI helper binding unavailable$'):case.j.request(body(items))
        self.assertEqual(before,(case.j.entries,case.j.turn,case.j.continuations));self.assertEqual(origins,case.j.helper_origins)
        witness=case.j.resume_context_rejection;fs=witness['filesystem']
        self.assertEqual(fs['status'],'observed');self.assertEqual(fs['counts'],[11,11,42,42,40,40,40])
        self.assertTrue(fs['truncated']);self.assertNotIn('PRIVATE',json.dumps(witness))
        for key in ('ordered','multiset','roots','header'):self.assertEqual(fs[key],h.filesystem_witness(content(old),content(new),s.environment_components)[key])
        # Conservative input-byte maxima dominate reachable entry/user counts.
        # Exercise every combination of the independent boolean-sized fields,
        # plus maximum valid depth, field masks, metadata shape and counters.
        largest=0
        for bits in range(128):
            for optional in (False,True):
                w=copy.deepcopy(witness);f=w['filesystem']
                for bit,key in enumerate(('old_prefix_present','exact_old_prefix_equal','exact_final_continuation_prompt','original_pair_exact')):
                    w[key]=bool(bits&(1<<bit))
                for bit,key in enumerate(('wrapper_equal','complete','truncated'),4):w['components'][key]=bool(bits&(1<<bit))
                w.update(retained_count=t.BODY_BYTES,observed_count=t.BODY_BYTES,expected_count=t.BODY_BYTES+1,
                    first_mismatching_original_index=t.BODY_BYTES,baseline_count=128)
                w['prompt'].update(envelope=(1<<24)-1,metadata=(1<<12)-1,unknown=t.BODY_BYTES,failed=127,id_family='msg-input-uuid',exact_text=bool(bits&1))
                w['request']['bytes']=t.BODY_BYTES;w['body'][:2]=[t.BODY_BYTES,t.BODY_BYTES]
                w['environment_checks']=[16383,0 if bits&1 else 16383]
                w['components'].update(presence=[2047,2047],equal=2047,order=[(1<<44)-1]*2)
                for index,key in enumerate(w['helper_binding']):w['helper_binding'][key]=bool(bits&(1<<index))
                f['counts']=[128]*7;f['header']=[[2,2,'4294967295']]*2
                w['summaries']=[{'optional':'x'*128}] if optional else [];f['details']=[{'optional':'x'*128}] if optional else []
                s.compact_helper_witness(w);largest=max(largest,len(t.canonical(w)))
                self.assertLessEqual(len(t.canonical(w)),2048)
                for key in ('ordered','multiset','roots','header'):self.assertEqual(w['filesystem'][key],f[key])
                self.assertEqual(w['filesystem']['status'],'observed')
        self.assertLessEqual(largest,2025)
        # Helper stage is a separately exported bounded witness; it does not
        # compete with the resume-context core. Check every supported stage and
        # the longest publication-failure spelling with maximal request count.
        for stage in ('ancestry','helper-directory','owned-descriptor','exclusive-lock','binary-alias','recheck','owned-child-helper'):
            for bits in range(16):
                helper=copy.deepcopy(case.j.helper_rejection);helper['stage']=stage
                helper['request']['bytes']=t.BODY_BYTES
                for bit,key in enumerate(helper['knownness']):helper['knownness'][key]=bool(bits&(1<<bit))
                self.assertLessEqual(len(t.canonical(helper)),2048)


if __name__=='__main__':unittest.main()
