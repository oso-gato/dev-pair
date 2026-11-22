"""Real local filesystem/timer behavior; role NSS, Fedora and root admission are fixtures."""
import copy
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap as b
import fedora_ci_guest as guest


class OwnerCommands:
    def __init__(self,uid,gid):self.uid=uid;self.gid=gid;self.calls=[];self.overrides={}
    def __call__(self,*args,**kwargs):
        self.calls.append(args)
        value=self.overrides.get((args[-1],args[1]),str(self.uid if args[1]=='-u' else self.gid)+'\n')
        if isinstance(value,Exception):raise value
        return value


class RoleDirectories(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.uid=os.getuid() if os.getuid()>=1000 else 1000
        self.gid=os.getgid() if os.getgid()>=1000 else 1000
        if os.getuid()!=0 and (os.getuid()<1000 or os.getgid()<1000):self.skipTest('local fixture lacks managed-range primary IDs')
        self.run=OwnerCommands(self.uid,self.gid);self.app=b.Bootstrap(self.root,self.run)

    def identity(self,name='dp-maint'):return b._RoleIdentity(name,self.uid,self.gid)

    def test_two_queries_per_role_real_eight_path_operations_and_fresh_reapply(self):
        for name,role in b.ROLE_DIRECTORIES.items():
            self.app._role_directories(self.identity(name))
            base=self.app.path('/var/lib/dev-pair/'+role)
            for path in (base,*(base/child for child in b.ROLE_CHILDREN)):
                info=path.stat();self.assertEqual((stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid),(0o700,self.uid,self.gid))
            self.assertEqual(self.app.role_directory_batches[role],{'role':role,'checked_lookups':2,'completed_directories':8,'outcome':'complete'})
        self.assertEqual(self.run.calls,[('/usr/bin/id',mode,name) for name in b.ROLE_DIRECTORIES for mode in ('-u','-g')])
        self.app._role_directories(self.identity())
        self.assertEqual(self.run.calls[-2:],[('/usr/bin/id','-u','dp-maint'),('/usr/bin/id','-g','dp-maint')])
        self.assertEqual(len(self.run.calls),6)
        self.app.directory('/unrelated-one',owner='dp-maint');self.app.directory('/unrelated-two',owner='dp-maint')
        self.assertEqual(len(self.run.calls),10)  # Ordinary callers still resolve each time.
        self.assertFalse(any('uid' in value or 'gid' in value for value in self.app.role_directory_batches.values()))
        before=len(self.run.calls)
        with patch.object(b.os,'fchown') as chown:self.app.directory('/ordinary-no-owner',owner='')
        chown.assert_not_called();self.assertEqual(len(self.run.calls),before)

    def test_bad_half_identity_or_role_binding_never_performs_ownership_effects(self):
        values=['0\n','1\n','+1000\n','01000\n',' 1000\n','1000\n1001\n','1000','4294967295\n','9'*40+'\n',True,None]
        for mode in ('-u','-g'):
            for value in values:
                self.run.overrides={('dp-maint',mode):value}
                with patch.object(self.app,'_directory_as') as effect:
                    with self.assertRaises(b.Blocked):self.app._role_directories(self.identity())
                    effect.assert_not_called()
        for mode in ('-u','-g'):
            self.run.overrides={('dp-maint',mode):str((self.uid if mode=='-u' else self.gid)+1)+'\n'}
            with patch.object(self.app,'_directory_as') as effect:
                with self.assertRaises(b.Blocked):self.app._role_directories(self.identity())
                effect.assert_not_called()
        for identity in (self.identity('core'),{'name':'dp-maint','uid':self.uid,'gid':self.gid}):
            before=len(self.run.calls)
            with self.assertRaises(b.Blocked):self.app._role_directories(identity)
            self.assertEqual(len(self.run.calls),before)
        self.assertFalse(self.app.path('/var').exists())

    def test_failed_second_query_and_interrupted_batch_resolve_fresh_on_retry(self):
        self.run.overrides={('dp-maint','-g'):b.Blocked('synthetic lookup failure')}
        with self.assertRaises(b.Blocked):self.app._role_directories(self.identity())
        self.assertFalse(self.app.path('/var').exists())
        self.assertEqual(self.app.role_directory_batches['maintenance']['checked_lookups'],1)
        self.run.overrides={};original=self.app._directory_as;count=0
        def interrupt(*args,**kwargs):
            nonlocal count
            original(*args,**kwargs);count+=1
            if count==3:raise b.Blocked('synthetic interrupted batch')
        with self.app.lock(),patch.object(self.app,'_directory_as',side_effect=interrupt):
            with self.assertRaises(b.Blocked):self.app.step('maintenance-directories',lambda:self.app._role_directories(self.identity()))
        self.assertEqual(self.app.role_directory_batches['maintenance']['outcome'],'blocked')
        events=[json.loads(line) for line in self.app.text(b.STATE+'/journal.jsonl').splitlines()]
        self.assertFalse(any(e['status']=='complete' for e in events))
        before=len(self.run.calls)
        with self.app.lock():self.app.step('maintenance-directories',lambda:self.app._role_directories(self.identity()))
        self.assertEqual(len(self.run.calls)-before,2)
        self.assertEqual(self.app.role_directory_batches['maintenance']['completed_directories'],8)

    def test_batch_symlink_swap_never_changes_victim_and_existing_conflicts_preserve(self):
        victim=self.root/'victim';victim.mkdir(mode=0o755);victim.chmod(0o755);(victim/'canary').write_text('preserved')
        before=(victim.stat().st_mode,victim.stat().st_uid,victim.stat().st_gid)
        original=b.os.mkdir
        def swap(path,mode=0o777,*,dir_fd=None):
            original(path,mode,dir_fd=dir_fd)
            if path=='cache' and dir_fd is not None:
                b.os.rmdir(path,dir_fd=dir_fd);b.os.symlink(str(victim),path,dir_fd=dir_fd)
        with patch.object(b.os,'mkdir',side_effect=swap),self.assertRaises(b.Blocked):self.app._role_directories(self.identity())
        self.assertEqual((victim.stat().st_mode,victim.stat().st_uid,victim.stat().st_gid),before)
        self.assertEqual((victim/'canary').read_text(),'preserved')
        self.app.path('/var/lib/dev-pair/maintenance/cache').unlink()
        self.app._role_directories(self.identity())
        conflict=self.app.path('/var/lib/dev-pair/maintenance/workspaces');conflict.chmod(0o755)
        with self.assertRaises(b.Blocked):self.app._role_directories(self.identity())
        self.assertEqual(stat.S_IMODE(conflict.stat().st_mode),0o755)
        conflict.chmod(0o700);inode=conflict.stat().st_ino;actual_stat=b.os.fstat
        for field in ('st_uid','st_gid'):
            def wrong(fd):
                info=actual_stat(fd)
                if info.st_ino==inode:
                    values={key:getattr(info,key) for key in ('st_mode','st_uid','st_gid')};values[field]+=1
                    return SimpleNamespace(**values)
                return info
            with patch.object(b.os,'fstat',side_effect=wrong),self.assertRaises(b.Blocked):self.app._role_directories(self.identity())
        self.assertEqual((conflict.stat().st_uid,conflict.stat().st_gid),(self.uid,self.gid))

    def test_fixed_ids_and_failed_lookup_diagnostics_withhold_output_and_error(self):
        for name,role in b.ROLE_DIRECTORIES.items():
            for mode,suffix in (('-u','uid'),('-g','gid')):
                self.assertEqual(b.Commands.operation_id(('/usr/bin/id',mode,name)),role+'-owner-'+suffix)
        self.assertEqual(b.Commands.operation_id(('/usr/bin/id','-u','core')),'withheld-operation')
        actual=subprocess.Popen
        def process(args,**kwargs):return actual([sys.executable,'-c','print("SYNTHETIC_SECRET_ROLE_VALUE");raise SystemExit(1)'],**kwargs)
        run=b.Commands();records=[];run.diagnostic=records.append
        with patch.object(b.subprocess,'Popen',side_effect=process),self.assertRaises(b.Blocked):run('/usr/bin/id','-u','dp-maint')
        self.assertEqual(records[-1]['operation_id'],'maintenance-owner-uid')
        self.assertNotIn('SYNTHETIC_SECRET',json.dumps(records));self.assertNotIn('stdout_tail',records[-1])


class PhaseWitness(unittest.TestCase):
    def test_cancellation_clamps_witness_without_changing_absolute_execution(self):
        for started in (256.,1e6,float(2**40),float(2**45)):
            configured=.05;deadline=started+configured;difference=deadline-started
            for observed in (math.nextafter(deadline,-math.inf),deadline,math.nextafter(deadline,math.inf)):
                run=b.Commands();reached=observed>=deadline
                with self.subTest(started=started,observed=observed):
                    with patch.object(b.time,'monotonic',side_effect=[started,started,observed]), \
                            patch.object(b.signal,'getitimer',return_value=(0.,0.)), \
                            patch.object(b.signal,'getsignal',return_value=b.signal.SIG_DFL), \
                            patch.object(b.signal,'signal'),patch.object(b.signal,'setitimer') as timer:
                        def execute():
                            with run.phase(configured,'deterministic-local',native=False):
                                self.assertEqual(run.deadline,deadline)
                                self.assertEqual(b._PHASE_DEADLINE.get(),deadline)
                        if reached:
                            with self.assertRaises(b.Blocked):execute()
                        else:execute()
                    witness=run.phase_budget_witness
                    self.assertEqual(witness['effective_seconds'],min(configured,difference))
                    self.assertLessEqual(witness['effective_seconds'],configured)
                    self.assertEqual(witness['deadline_reached_at_exit'],reached)
                    self.assertEqual(witness['elapsed_seconds']>=witness['effective_seconds'],reached)
                    self.assertFalse(witness['timer_fired'])  # No actual SIGALRM was delivered.
                    self.assertEqual(timer.call_args_list[0].args,(b.signal.ITIMER_REAL,difference))
                    self.assertIsNone(run.deadline);self.assertIsNone(b._PHASE_DEADLINE.get())
        # Exact hosted failure and a much larger cancellation error are deterministic.
        self.assertEqual((256.+.05)-256.,0.05000000000001137)
        self.assertGreater(((2.**40)+.05)-(2.**40),.05)

    def test_clipped_parent_timer_is_restored_without_budget_reset(self):
        started=float(2**40);configured=.05;old_remaining=.015
        deadline=started+old_remaining;observed=math.nextafter(deadline,-math.inf)
        run=b.Commands()
        with patch.object(b.time,'monotonic',side_effect=[started,started,observed,observed]), \
                patch.object(b.signal,'getitimer',return_value=(old_remaining,0.)), \
                patch.object(b.signal,'getsignal',return_value=b.signal.SIG_DFL), \
                patch.object(b.signal,'signal'),patch.object(b.signal,'setitimer') as timer:
            with run.phase(configured,'deterministic-parent',native=False):
                self.assertEqual(run.deadline,deadline)
        self.assertEqual(run.phase_budget_witness['effective_seconds'],deadline-started)
        self.assertFalse(run.phase_budget_witness['deadline_reached_at_exit'])
        self.assertFalse(run.phase_budget_witness['timer_fired'])
        self.assertEqual(timer.call_args_list[-1].args,(b.signal.ITIMER_REAL,deadline-observed,0.))
        self.assertLessEqual(timer.call_args_list[-1].args[1],old_remaining)
        # An unrepresentable tiny duration still blocks before starting any timer.
        run=b.Commands()
        with patch.object(b.time,'monotonic',return_value=float(2**50)), \
                patch.object(b.signal,'getitimer',return_value=(0.,0.)), \
                patch.object(b.signal,'setitimer') as timer:
            with self.assertRaises(b.Blocked):
                with run.phase(configured,'unrepresentable-local',native=False):self.fail('unrepresentable deadline admitted')
        timer.assert_not_called();self.assertIsNone(run.phase_budget_witness)

    def subprocess_witness(self,mode):
        code='''import json,signal,sys,time
sys.path.insert(0,sys.argv[1]);import bootstrap as b
run=b.Commands()
try:
 with run.phase(.05 if sys.argv[2]!='early' else 1,'local-test',native=False):
  if sys.argv[2]=='timer':run(sys.executable,'-c','import time;time.sleep(2)',timeout=3)
  elif sys.argv[2]=='cross':
   signal.setitimer(signal.ITIMER_REAL,0)
   try:raise b.Blocked('SYNTHETIC_SECRET_PRIMARY')
   finally:time.sleep(.08)
  else:raise b.Blocked('SYNTHETIC_SECRET_PRIMARY')
except b.Blocked:pass
print(json.dumps(run.phase_budget_witness))
'''
        result=subprocess.run([sys.executable,'-c',code,str(Path(b.__file__).parent),mode],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('SYNTHETIC_SECRET',result.stdout)
        return json.loads(result.stdout)

    def test_actual_alarm_early_failure_and_cleanup_crossing_are_distinct(self):
        timer=self.subprocess_witness('timer');self.assertTrue(timer['timer_fired']);self.assertTrue(timer['deadline_reached_at_exit'])
        early=self.subprocess_witness('early');self.assertFalse(early['timer_fired']);self.assertFalse(early['deadline_reached_at_exit'])
        crossed=self.subprocess_witness('cross');self.assertFalse(crossed['timer_fired']);self.assertTrue(crossed['deadline_reached_at_exit'])
        self.assertLessEqual(timer['effective_seconds'],timer['configured_seconds'])

    def state(self):
        expected={key:'a'*length for key,length in guest.INPUT_LENGTHS.items()}
        target={key:expected[key] for key in ('source_sha','context_sha256','distrobox_sha')};target['bootstrap_sources']=['192.0.2.9/32']
        state={'target':target,'job_admission':False,'phase':'prepare','prepare':'blocked','maintenance_gptbox':'pending',
            'prepare_elapsed_seconds':621.061,'prepare_budget_witness':{'configured_seconds':600,'effective_seconds':600,
            'elapsed_seconds':620,'deadline_reached_at_exit':True,'timer_fired':False},'role_directory_batches':{
            'maintenance':{'role':'maintenance','checked_lookups':2,'completed_directories':3,'outcome':'blocked'}},
            'raw_error':'SYNTHETIC_SECRET_PRIMARY','argv':['SYNTHETIC_SECRET_ARGV']}
        return state,expected

    def test_closed_public_projection_is_finite_target_bound_and_not_primary_cause(self):
        state,expected=self.state();value=guest.prepare_observations(state,expected)
        self.assertFalse(value['budget']['timer_fired']);self.assertTrue(value['budget']['deadline_reached_at_exit'])
        self.assertEqual(value['source_sha'],expected['source_sha']);self.assertNotIn('SYNTHETIC_SECRET',json.dumps(value))
        for key,bad in [('configured_seconds',True),('configured_seconds',601),('effective_seconds',0),
                        ('elapsed_seconds',float('nan')),('elapsed_seconds',float('inf')),('elapsed_seconds',10**1000),
                        ('elapsed_seconds',True),('timer_fired','yes'),('unknown','SYNTHETIC_SECRET')]:
            wrong=copy.deepcopy(state);wrong['prepare_budget_witness'][key]=bad
            self.assertEqual(guest.prepare_observations(wrong,expected)['budget'],{'availability':'unavailable'})
        wrong=copy.deepcopy(state);wrong['prepare_budget_witness'].pop('timer_fired')
        self.assertEqual(guest.prepare_observations(wrong,expected)['budget'],{'availability':'unavailable'})
        for key in ('source_sha','context_sha256'):
            wrong=copy.deepcopy(state);wrong['target'][key]='b'*len(expected[key])
            with self.assertRaises(ValueError):guest.prepare_observations(wrong,expected)
        for key,bad in [('checked_lookups',1),('completed_directories',9),('role','development'),('outcome','SYNTHETIC_SECRET')]:
            wrong=copy.deepcopy(state);wrong['role_directory_batches']['maintenance'][key]=bad
            self.assertEqual(guest.prepare_observations(wrong,expected)['role_directories'],{})


if __name__=='__main__':unittest.main()
