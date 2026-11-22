"""Native21 diagnostics: real local shell/processes, no engine or native claims."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fedora_ci as ci
import test_tooling_repair as repair


class ToolingDiagnostics(unittest.TestCase):
    setUp=repair.ToolingRepair.setUp
    fixture=repair.ToolingRepair.fixture

    def local_script(self,status=0,timeout=False):
        payload=ci.tooling_payload();calls=[0]
        def replacement(match):
            calls[0]+=1
            if calls[0]==1:return '/bin/sleep 3' if timeout else '/bin/sh -c '+shlex.quote('exit '+str(status))
            return '/usr/bin/true'
        changed=re.sub(r'dnf [^;]+',replacement,payload)
        self.assertEqual(calls[0],3)
        changed=re.sub(r'find /var/cache[^;]+','/usr/bin/true',changed)
        changed=changed.replace('test -s /tool-rpm-sha256.txt','/usr/bin/true')
        script=ci.tooling_shell().replace(shlex.quote(payload),shlex.quote(changed))
        self.assertNotEqual(script,ci.tooling_shell())
        if timeout:script=script.replace('--kill-after=10s 540s','--kill-after=0.01s 0.05s')
        return script

    def test_real_shell_preserves_success_payload_125_other_error_timeout_and_failed_printf(self):
        for status,timeout,expected in ((0,False,0),(125,False,125),(17,False,17),(0,True,124)):
            script=self.local_script(status,timeout)
            result=subprocess.run(['/bin/sh','-c',script],capture_output=True,timeout=2,env={'PATH':'/usr/bin:/bin'})
            self.assertEqual(result.returncode,expected,result.stderr)
            observed=ci.tooling_stage_evidence(result.stdout)
            self.assertEqual(observed['timeout_exit_status'],expected)
            self.assertFalse(observed['order_invalid']);self.assertFalse(observed['marker_invalid'])
            if expected==0:self.assertTrue(observed['all_stages_observed'])
            else:self.assertNotIn('install',observed['observed'])
            with open('/dev/full','wb') as full:
                failed=subprocess.run(['/bin/sh','-c',script],stdout=full,stderr=subprocess.PIPE,timeout=2,env={'PATH':'/usr/bin:/bin'})
            self.assertEqual(failed.returncode,expected,failed.stderr)
            self.assertLess(len(failed.stderr),4096)

    def test_real_timeout_setup_error_125_is_not_misreported_as_payload_entry(self):
        script=self.local_script().replace('540s','invalid-duration')
        result=subprocess.run(['/bin/sh','-c',script],capture_output=True,timeout=2)
        self.assertEqual(result.returncode,125)
        proof=ci.tooling_stage_evidence(result.stdout)
        self.assertEqual(proof['observed'],['run-shell-entered','timeout-launch','timeout-exit'])
        self.assertEqual(proof['timeout_exit_status'],125)

    def test_marker_projection_requires_whole_executed_lines_order_and_capture_completeness(self):
        echoed=('STEP 2: RUN '+ci.tooling_shell()+'\n"DP_TOOL_STAGE install"\n').encode()
        self.assertEqual(ci.tooling_stage_evidence(echoed)['observed'],[])
        self.assertEqual(ci.tooling_stage_evidence(b'echoed command\rDP_TOOL_STAGE upgrade\n')['observed'],[])
        self.assertEqual(ci.tooling_stage_evidence(b'quoted\rDP_TOOL_STAGE timeout-exit 125\n')['timeout_exit_status'],None)
        valid=b''.join(('DP_TOOL_STAGE '+stage+(' 0' if stage=='timeout-exit' else '')+'\n').encode() for stage in ci.TOOL_STAGES)
        self.assertTrue(ci.tooling_stage_evidence(echoed+valid)['all_stages_observed'])
        for raw,key in ((valid+b'DP_TOOL_STAGE upgrade\n','order_invalid'),(b'DP_TOOL_STAGE unknown\n','marker_invalid'),
                        (b'DP_TOOL_STAGE timeout-exit 256\n','marker_invalid'),(b'DP_TOOL_STAGE install 0\n','marker_invalid')):
            observed=ci.tooling_stage_evidence(raw);self.assertTrue(observed[key]);self.assertEqual(observed['availability'],'unavailable')
        partial=ci.tooling_stage_evidence(b'DP_TOOL_STAGE run-shell-entered\nDP_TOOL_STAGE upgrade')
        self.assertTrue(partial['partial_marker_discarded']);self.assertEqual(partial['observed'],['run-shell-entered'])
        self.assertFalse(ci.tooling_stage_evidence(valid,truncated=True)['all_stages_observed'])
        self.assertTrue(ci.tooling_stage_evidence(valid,truncated=True)['capture_truncated'])

    def test_production_recipe_keeps_one_timed_run_original_commands_limits_and_no_env_dump(self):
        recipe=ci.tooling_recipe();self.assertEqual(recipe.count('RUN '),2)
        self.assertEqual(recipe.count('/usr/bin/timeout --signal=TERM --kill-after=10s 540s'),1)
        for text in ('set -eu','--setopt=gpgcheck=1','--setopt=localpkg_gpgcheck=1','--setopt=keepcache=True','--setopt=install_weak_deps=False',
                     'qemu-system-x86-core qemu-img genisoimage python3 seabios-bin','sha256sum {} + > /tool-rpm-sha256.txt','test -s /tool-rpm-sha256.txt','dnf clean all'):
            self.assertIn(text,recipe)
        self.assertNotIn('set -x',recipe);self.assertNotIn('printenv',recipe)
        self.assertIn('else dp_tool_rc=$?',recipe);self.assertIn('exit "$dp_tool_rc"',recipe)

    def test_runtime_projection_is_closed_bounded_and_discards_valid_package(self):
        valid={'name':'crun','path':'/usr/bin/crun','version':'crun version 1\n::error::not workflow','package':'discard-this-package'}
        proof=ci.runtime_projection(json.dumps(valid).encode())
        self.assertEqual(proof['status'],'observed');self.assertNotIn('package',proof)
        self.assertNotIn('discard-this',json.dumps(proof))
        bad=[b'null',b'',b'{}',b'[]',b'warning\n'+json.dumps(valid).encode(),b'x'*4097,
             json.dumps(dict(valid,unknown=True)).encode(),json.dumps(dict(valid,package=None)).encode(),
             json.dumps(dict(valid,path='relative')).encode(),json.dumps(dict(valid,version='x'*2049)).encode(),
             json.dumps(dict(valid,name='')).encode(),b'{"name":"a","name":"b"}']
        bad += [json.dumps(dict(valid,**{key:'\ud800'})).encode() for key in ('name','path','version','package')]
        for data in bad:
            with self.subTest(data=data[:50]):self.assertEqual(ci.runtime_projection(data)['status'],'unavailable')
        capture=io.StringIO()
        with contextlib.redirect_stdout(capture):ci.emit_json('DP_TEST',proof)
        self.assertNotIn('::',capture.getvalue());self.assertEqual(json.loads(capture.getvalue().split(' ',1)[1]),proof)

    def test_actual_capture_retains_stage_projection_when_real_process_exits_nonzero(self):
        output=io.StringIO()
        code='import sys;print("DP_TOOL_STAGE run-shell-entered");print("DP_TOOL_STAGE timeout-exit 125");sys.exit(125)'
        with contextlib.redirect_stdout(output),self.assertRaises(ci.Blocked):
            self.probe.bounded([sys.executable,'-c',code],2,'fixed fixture only',disk_check=False,tooling_stages=True)
        self.assertEqual(self.probe.report['tooling_stages']['timeout_exit_status'],125)
        self.assertNotIn('install',self.probe.report['tooling_stages']['observed'])

    def test_fixed_runtime_query_uses_owned_prefix_clipped_deadline_and_preserves_failed_launch(self):
        observed=[];self.probe.phase_end=time.monotonic()+.4
        def bounded(argv,seconds,name,**kwargs):
            self.assertTrue(self.probe.engine_activity);self.assertTrue(self.probe.image_copy_active)
            self.assertLessEqual(seconds,.4);observed.append((argv,seconds,kwargs))
            self.assertEqual(argv[-2:],['info','--format={{json .Host.OCIRuntime}}'])
            self.assertIn('/usr/bin/env',argv);self.assertIn('-i',argv)
            self.assertIn('TMPDIR='+str(self.root/'image-copy'),argv)
            raise ci.Blocked('fixed runtime query failed fixture')
        with self.fixture(bounded),patch.object(ci,'PUBLIC_SECONDS',.4),patch.object(self.probe,'preflight'),patch.object(self.probe,'inputs'), \
             patch.dict(os.environ,{'GITHUB_STEP_SUMMARY':''}),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.probe.execute(),2)
        self.assertEqual(len(observed),1)
        self.assertEqual(self.probe.primary_image_failure,('runtime-info','fixed runtime query failed fixture'))
        self.assertEqual(self.probe.report['phases']['cleanup']['status'],'fail')
        self.assertTrue(self.probe.image_copy_active)
        self.assertTrue((self.root/'image-copy').exists());self.assertTrue((self.root/'verification-work').exists())

    def test_real_runtime_info_failures_suppress_package_body_and_preserve_primary_cleanup(self):
        canary='PACKAGE_MUST_BE_DISCARDED'
        for mode in ('exit125','exit17','timeout','capture-overflow'):
            with tempfile.TemporaryDirectory() as directory:
                self.root=Path(directory);self.probe=ci.Probe('a'*40,self.root)
                payload=json.dumps({'name':'crun','package':canary,'path':'/usr/bin/crun','version':'fixture-version'})+'\n'
                code='import os,sys,time;os.write(1,sys.argv[1].encode());'
                if mode.startswith('exit'):code+='sys.exit('+mode[4:]+')'
                elif mode=='timeout':code+='time.sleep(20)'
                else:code+='time.sleep(.02);os.write(1,b"x"*4096)'
                seen=[]
                def child(argv,seconds,name,**kwargs):
                    self.assertEqual(argv[-2:],['info','--format={{json .Host.OCIRuntime}}'])
                    self.assertTrue(kwargs['suppress_failure_output']);self.assertFalse(kwargs['tooling_stages'])
                    self.assertGreater(seconds,0);self.assertLessEqual(seconds,5)
                    self.assertTrue(self.probe.engine_activity);self.assertTrue(self.probe.image_copy_active)
                    seen.append((argv,seconds))
                    return ci.Probe.bounded(self.probe,[sys.executable,'-c',code,payload],seconds,name,
                                            disk_check=False,suppress_failure_output=kwargs['suppress_failure_output'])
                capture=io.StringIO();phase=.15 if mode=='timeout' else ci.PUBLIC_SECONDS;cap=256 if mode=='capture-overflow' else ci.LOG_LIMIT
                started=time.monotonic()
                with self.fixture(child),patch.object(self.probe,'preflight'),patch.object(self.probe,'inputs'), \
                     patch.object(ci,'PUBLIC_SECONDS',phase),patch.object(ci,'LOG_LIMIT',cap), \
                     patch.dict(os.environ,{'GITHUB_STEP_SUMMARY':''}),contextlib.redirect_stdout(capture):
                    self.assertEqual(self.probe.execute(),2)
                self.assertEqual(len(seen),1);self.assertLess(time.monotonic()-started,2)
                self.assertEqual(self.probe.primary_image_failure[0],'runtime-info')
                self.assertEqual(self.probe.report['oci_runtime'],{'status':'unavailable','reason':'not-collected'})
                self.assertIn('local image runtime-info:',self.probe.report['blocker'])
                self.assertGreaterEqual(self.probe.log_used,len(payload.encode()))
                if mode.startswith('exit'):self.assertIn('exit '+mode[4:],self.probe.report['blocker'])
                if mode=='capture-overflow':
                    self.assertIn('diagnostic byte limit',self.probe.report['blocker'])
                    self.assertLessEqual(self.probe.log_used,cap+1)
                self.assertEqual(self.probe.report['phases']['cleanup']['status'],'fail')
                self.assertTrue(self.probe.image_copy_active);self.assertTrue(self.probe.engine_activity)
                self.assertTrue((self.root/'image-copy').exists());self.assertTrue((self.root/'verification-work').exists())
                self.assertNotIn(canary,capture.getvalue());self.assertNotIn('fixture-version',capture.getvalue())
                self.assertNotIn(canary,json.dumps(self.probe.report))

    def test_other_failed_command_keeps_original_bounded_public_log_path(self):
        capture=io.StringIO()
        code='import sys;print("OTHER_FIXED_PUBLIC_DIAGNOSTIC",flush=True);sys.exit(125)'
        with contextlib.redirect_stdout(capture),self.assertRaises(ci.Blocked):
            self.probe.bounded([sys.executable,'-c',code],2,'unchanged public operation',disk_check=False)
        self.assertIn('OTHER_FIXED_PUBLIC_DIAGNOSTIC',capture.getvalue())
