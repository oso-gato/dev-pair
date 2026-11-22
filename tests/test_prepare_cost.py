"""Local monotonic/metadata accounting only; no native performance/admission evidence."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap as b
import fedora_ci_guest as guest

SOURCE='1'*40;CONTEXT='a'*64;ATTEMPT='c'*32
BUDGET={'configured_seconds':600,'effective_seconds':600,'elapsed_seconds':7.,'deadline_reached_at_exit':False,'timer_fired':False}


def entry(step='packages',accepted=True,handle=True,elapsed=1.):
    return {'step':step,'accepted_exit':accepted,'launcher_handle_observed':handle,'elapsed_seconds':elapsed}


def state(value):
    return {'prepare_cost':value,'prepare_cost_attempt':ATTEMPT,'prepare_budget_witness':BUDGET}


class PrepareCostTests(unittest.TestCase):
    def cost(self):return b.PrepareCost(SOURCE,CONTEXT,ATTEMPT,0.)

    def project(self,cost):return guest.prepare_cost_projection(state(cost.snapshot(BUDGET)),{'source_sha':SOURCE,'context_sha256':CONTEXT},True)

    def test_controlled_repeated_steps_and_final_interruption_no_double_count(self):
        cost=self.cost()
        with patch.object(b.time,'monotonic',side_effect=[1.,3.,4.,7.]):
            cost.mark('packages');cost.mark('operator');cost.mark('packages');cost.finish(False)
        value=self.project(cost);self.assertEqual(value['availability'],'observed');self.assertEqual(value['status'],'interrupted')
        self.assertEqual(value['steps']['pre-prepare'][:2],[1,1.])
        self.assertEqual(value['steps']['packages'][:2],[2,5.]);self.assertEqual(value['steps']['operator'][:2],[1,1.])
        self.assertEqual(sum(row[1] for row in value['steps'].values()),7.)
        with patch.object(b.time,'monotonic',side_effect=AssertionError('finished snapshot retimed')):cost.finish(True)
        self.assertEqual(cost.snapshot(BUDGET)['status'],'interrupted')

    def test_command_categories_scope_unknown_and_overflow_are_explicit(self):
        cost=self.cost()
        for item in (entry(),entry(accepted=False),entry(accepted=False,handle=False)):cost.command(item)
        self.assertEqual(cost.rows['packages'][2:],[3,1,1,1,3.])
        for item in ({'step':'packages','accepted_exit':False,'elapsed_seconds':1.},entry(step='SECRET_UNKNOWN'),
                     entry(elapsed=float('nan')),entry(accepted=True,handle=False)):
            cost.command(item)
        self.assertEqual(cost.unknown_records,4);self.assertFalse(cost.commands_complete)
        with patch.object(b.time,'monotonic',return_value=1.):cost.finish(False)
        value=self.project(cost);self.assertEqual(value['status'],'incomplete');self.assertEqual(value['command_records'],7)
        self.assertNotIn('SECRET',json.dumps(value));self.assertEqual(value['scope'],b.PREPARE_COST_SCOPE)
        cost=self.cost()
        for _ in range(4097):cost.command(entry(elapsed=0.))
        with patch.object(b.time,'monotonic',return_value=1.):cost.finish(False)
        value=self.project(cost);self.assertEqual(value['status'],'overflow');self.assertEqual(value['command_records'],4096)
        self.assertFalse(value['commands_complete'])

    def test_closed_projection_binding_numbers_privacy_and_size(self):
        self.assertEqual(b.PREPARE_COST_STEPS,guest.PREPARE_COST_STEPS)
        cost=self.cost()
        with patch.object(b.time,'monotonic',return_value=1.):
            for step in b.PREPARE_COST_STEPS:cost.mark(step);cost.command(entry(step=step,elapsed=0.))
            cost.finish(True)
        original=cost.snapshot(BUDGET);value=self.project(cost);self.assertLessEqual(len(json.dumps(value,separators=(',',':')).encode()),4096)
        variants=[]
        for key,bad in (('source_sha','f'*40),('context_sha256','f'*64),('attempt_id','d'*32),('phase','adapter'),
                        ('phase_budget_sha256','d'*64),('scope','SECRET'),('command_records',True),('elapsed_seconds',float('inf')),
                        ('wall_complete','yes'),('SECRET','PRIVATE')):
            altered=copy.deepcopy(original);altered[key]=bad;variants.append(altered)
        altered=copy.deepcopy(original);altered['steps']['SECRET']=[0]*7;variants.append(altered)
        for index,bad in ((0,True),(1,-1),(1,float('nan')),(2,2**63),(3,False),(6,float('inf'))):
            altered=copy.deepcopy(original);altered['steps']['packages'][index]=bad;variants.append(altered)
        for altered in variants:
            output=guest.prepare_cost_projection(state(altered),{'source_sha':SOURCE,'context_sha256':CONTEXT},True)
            self.assertEqual(output,{'availability':'unavailable'});self.assertNotIn('SECRET',json.dumps(output))
        self.assertEqual(guest.prepare_cost_projection(state(original),{'source_sha':SOURCE,'context_sha256':CONTEXT},False),{'availability':'unavailable'})
        report={'source_sha':SOURCE,'diagnostics':{'prepare_cost':value}}
        self.assertLess(len(guest.encode_report(report)),guest.REPORT_LIMIT)
        report['padding']='x'*guest.REPORT_LIMIT
        with self.assertRaises(ValueError):guest.encode_report(report)

    def test_real_short_timer_preserves_blocked_alarm_and_active_step(self):
        code='''import json,sys,time
sys.path.insert(0,sys.argv[1]);import bootstrap as b
run=b.Commands();cost=b.PrepareCost("1"*40,"a"*64,"c"*32,time.monotonic());run.diagnostic=cost.command
try:
 with run.phase(.04,"local-cost",native=False):
  cost.mark("packages");run.current_step="packages";run(sys.executable,"-c","import time;time.sleep(5)",timeout=8)
except b.Blocked:pass
finally:cost.finish(False)
print(json.dumps({"budget":run.phase_budget_witness,"cost":cost.snapshot(run.phase_budget_witness)}))
'''
        result=subprocess.run([sys.executable,'-c',code,str(Path(b.__file__).parent)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);value=json.loads(result.stdout)
        self.assertTrue(value['budget']['timer_fired']);self.assertTrue(value['budget']['deadline_reached_at_exit'])
        self.assertEqual(value['cost']['status'],'interrupted');self.assertGreater(value['cost']['steps']['packages'][1],0)
        self.assertEqual(value['cost']['steps']['packages'][4],1)

    def test_actual_handle_fact_is_distinct_for_popen_failure_and_nonzero_exit(self):
        records=[];run=b.Commands();run.diagnostic=records.append
        with patch.object(b.subprocess,'Popen',side_effect=OSError('SECRET')),self.assertRaises(b.Blocked):run('/unused')
        self.assertFalse(records[-1]['launcher_handle_observed'])
        with self.assertRaises(b.Blocked):run(sys.executable,'-c','raise SystemExit(1)')
        self.assertTrue(records[-1]['launcher_handle_observed']);self.assertNotIn('SECRET',json.dumps(records))

    def test_unknown_clock_and_interrupted_update_never_fabricate_complete_zero(self):
        for bad in (-1.,float('nan'),float('inf')):
            cost=self.cost()
            with patch.object(b.time,'monotonic',return_value=bad):cost.mark('packages');cost.finish(False)
            self.assertFalse(cost.wall_complete);self.assertEqual(cost.snapshot(BUDGET)['status'],'incomplete')
        cost=self.cost();cost.command_pending=True
        self.assertEqual(cost.snapshot(BUDGET),{'availability':'unavailable','reason':'interrupted-accounting-update'})
        with patch.object(b.time,'monotonic',side_effect=b.Blocked('PRIMARY')):
            with self.assertRaisesRegex(b.Blocked,'PRIMARY'):cost.mark('packages')
        with patch.object(b.time,'monotonic',return_value=1.):cost.finish(False)
        self.assertEqual(cost.snapshot(BUDGET)['reason'],'interrupted-accounting-update')


if __name__=='__main__':unittest.main()
