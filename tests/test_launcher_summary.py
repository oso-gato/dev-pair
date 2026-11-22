"""Closed summary diagnostics from owned launcher pipes, never relay authority."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'tools')]
import bootstrap as b
import fedora_ci_guest as guest
from native_io_fixture import install,manager,launch_payload

SUMMARY=b'Finished with result: timeout\nMain processes terminated with: code=killed, status=15/TERM\n'

class SummaryTests(unittest.TestCase):
    def test_closed_summary_values_and_ancillary_lines(self):
        for result in ('timeout','resources','exit-code','signal','success'):
            raw=('Running as unit: dev-pair-initialize-prepare-12345678-12345678.service; invocation ID: '+'a'*32+'\nFinished with result: '+result+'\nMain processes terminated with: code=exited, status=1/FAILURE\nService runtime: 6.377s\nCPU time consumed: 12ms\nMemory peak: 5.2M (swap: 0B)\nIO Bytes: read 4K, written 1K\n').encode()
            self.assertEqual(b.launcher_summary(raw,True),{'availability':'observed','result':result,'code':'exited','status':1})
        self.assertEqual(b.launcher_summary(SUMMARY,True)['status'],15)
        self.assertEqual(b.launcher_summary(b'Finished with result: success\n',True),{'availability':'observed','result':'success'})
    def test_unknown_duplicate_control_truncated_and_oversized_are_private_unavailable(self):
        for raw,complete in [(b'',True),(SUMMARY,False),(SUMMARY*2,True),(SUMMARY+b'PRIVATE: SECRET\n',True),
            (SUMMARY.replace(b'timeout',b'PRIVATE'),True),(SUMMARY.replace(b'15/TERM',b'15/PRIVATE'),True),
            (SUMMARY.replace(b'killed',b'exited'),True),(SUMMARY+b'\x1b[31m',True),(SUMMARY+b'\r',True),
            (b'x'*8193,True),(SUMMARY.replace(b'15/TERM',b'999/TERM'),True)]:
            self.assertEqual(b.launcher_summary(raw,complete),{'availability':'unavailable'})

class LauncherProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=install(self,self.tmp.name);self.calls=[];self.original=subprocess.Popen;self.manager=manager(self.original,self.calls)
    def runner(self,emit=SUMMARY,payload_wire=False):
        def dispatch(args,**kw):
            if args[0]=='/usr/bin/systemd-run':
                self.calls.append(tuple(args))
                # Only manager execution is synthetic; owned pipes/FIFOs and
                # child wait status are real. No systemd, dnf or network runs.
                if not payload_wire:os.write(kw['stderr'],emit)
                filtered=[v for v in args if v not in ('-I','--helper')]
                script='import os;os.write(2,'+repr(emit)+');raise SystemExit(1)' if payload_wire else 'raise SystemExit(1)'
                return launch_payload(self.original,filtered,kw,[sys.executable,'-c',script])
            return self.manager(args,**kw)
        return dispatch
    def test_exact_selector_only_and_actual_timing_match_properties(self):
        for step,argv,stdin,selected in [('tailscale-package',b.TAILSCALE_PACKAGE,None,True),
            ('packages',b.TAILSCALE_PACKAGE,None,False),('tailscale-package',b.TAILSCALE_PACKAGE[:-1]+('other',),None,False),
            ('tailscale-package',b.TAILSCALE_PACKAGE,'',False)]:
            run=b.Commands();run.native_prefix='dev-pair-initialize-prepare-12345678';run.current_step=step
            records=[];run.metadata_diagnostic=records.append
            with patch.object(b.subprocess,'Popen',side_effect=self.runner()),self.assertRaises(b.Blocked):run(*argv,input_text=stdin,timeout=3.257)
            launch=[v for v in self.calls if v[0]=='/usr/bin/systemd-run'][-1]
            self.assertEqual('--quiet' not in launch,selected)
            self.assertTrue(all(v in launch for v in ('--wait','--collect','--service-type=exec','--property=MemoryMax=2G','--property=TasksMax=512','--property=KillMode=control-group')))
            record=records[-1];failure=record['native_failure']
            self.assertEqual('launcher' in failure,selected)
            if selected:
                diagnostic=failure['launcher'];timing=diagnostic['timing']
                self.assertEqual(diagnostic['summary']['result'],'timeout');self.assertTrue(diagnostic['complete'])
                self.assertEqual(failure['launcher_status_before_interrupt'],1);self.assertEqual(failure['decoder']['raw_bytes'],0)
                for key,prop in [('start_us','TimeoutStartSec'),('runtime_us','RuntimeMaxSec')]:
                    actual=next(v.rsplit('=',1)[1][:-1] for v in launch if v.startswith('--property='+prop+'='))
                    self.assertEqual(timing[key],round(float(actual)*1000000))
                self.assertLessEqual(timing['start_us']+timing['runtime_us'],3257000)
                self.assertLessEqual(timing['helper_margin_us'],100001);self.assertIsNone(timing['phase_remaining_us'])
                self.assertEqual(record['outcome'],'rejected')
                entry={**record,'diagnostic_identity':{'source_sha':'a'*40,'context_sha256':'b'*64,'phase':'prepare'}}
                projection=guest.native_failure_projection(entry,{'source_sha':'a'*40,'context_sha256':'b'*64},'prepare')
                self.assertEqual(projection['launcher']['summary']['result'],'timeout')
                self.assertNotIn('Finished with result',json.dumps(record));self.assertNotIn('invocation ID',json.dumps(record))
            self.assertEqual(list((self.root/'records').iterdir()),[])
    def test_payload_summary_cannot_populate_launcher_success_and_bad_summary_keeps_failure(self):
        for wire in (False,True):
            run=b.Commands();run.native_prefix='dev-pair-initialize-prepare-12345678';run.current_step='tailscale-package';records=[];run.metadata_diagnostic=records.append
            emit=b'Finished with result: success\nPRIVATE: SECRET\n' if not wire else b'Finished with result: success\n'
            with patch.object(b.subprocess,'Popen',side_effect=self.runner(emit,wire)),self.assertRaises(b.Blocked):run(*b.TAILSCALE_PACKAGE,timeout=3)
            failure=records[-1]['native_failure'];self.assertEqual(failure['launcher']['summary'],{'availability':'unavailable'})
            self.assertEqual(failure['category'],'decoder-rejected');self.assertNotIn('SECRET',json.dumps(records))
    def test_projection_malformed_secondary_does_not_erase_primary(self):
        value={'point':'relay-finish','category':'decoder-rejected','launcher_handle_observed':True,'status_sampled_before_interrupt':True,
            'launcher_status_before_interrupt':1,'decoder':{'availability':'unavailable'},'launcher':{'PRIVATE':'SECRET'}}
        entry={'native_failure':value,'step':'tailscale-package','operation_id':'signed-packages',
            'diagnostic_identity':{'source_sha':'a'*40,'context_sha256':'b'*64,'phase':'prepare'}}
        result=guest.native_failure_projection(entry,{'source_sha':'a'*40,'context_sha256':'b'*64},'prepare')
        self.assertEqual(result['availability'],'observed');self.assertEqual(result['point'],'relay-finish')
        self.assertEqual(result['launcher'],{'availability':'unavailable'});self.assertNotIn('PRIVATE',json.dumps(result))

if __name__=='__main__':unittest.main()
