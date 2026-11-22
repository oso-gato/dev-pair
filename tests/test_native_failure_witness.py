"""Real local FIFO/process rejection; native manager/UID/SELinux remain explicit fixtures."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap as b
import native_relay as r
import fedora_ci_guest as guest
from native_io_fixture import install,manager,launch_payload

UNIT='dev-pair-gptbox-'+'a'*64+'.service'
SOURCE='1'*40;CONTEXT='a'*64


def prefix(unit=UNIT):
    return ('/usr/bin/systemd-run','--unit='+unit,'--description=dev-pair-owned-'+unit,'--wait','--collect','--property=RuntimeMaxSec=30')


def control(**changes):
    value={'v':1,'done':True,'status':0,'uid':1000,'domain':'unconfined_service_t','helper':'a'*64,'p':1}
    value.update(changes);return value


def frame(kind,value):
    data=value if type(value) is bytes else json.dumps(value,separators=(',',':')).encode()
    return r.HEADER.pack(kind,r.MAGIC,len(data))+data


class DecoderWitness(unittest.TestCase):
    def reject(self,wire,reason,finish=None):
        decoder=r.Decoder(262144)
        with self.assertRaises(r.DecoderRejected):
            decoder.feed(wire)
            if finish is not None:decoder.finish(*finish)
        value=decoder.witness();self.assertEqual(value['reason'],reason)
        self.assertLess(len(json.dumps(value)),1024);self.assertNotIn('SECRET',json.dumps(value))
        return value

    def test_closed_reasons_reject_bad_frames_identity_status_and_truncation(self):
        self.assertEqual(r.DECODER_REASONS,guest.DECODER_REASONS)
        cases=[(b'SECRET!!','header-invalid',None),(frame(b'C',b'{'),'control-json',None),
            (frame(b'C',b'{"SECRET":1}'),'control-shape',None),(frame(b'F',b'{'),'failure-json',None),
            (frame(b'F',{'SECRET':'PRIVATE'}),'failure-shape',None),
            (frame(b'C',control(domain='SECRET_DOMAIN')),'control-domain',None),
            (frame(b'C',control(uid=True)),'control-uid',None),(frame(b'C',control(helper='SECRET')),'control-helper',None),
            (frame(b'C',control(status=True)),'control-status',None),(frame(b'C',control(status=256)),'control-status',None),
            (frame(b'C',control(v=True)),'control-version',None),(frame(b'C',control(p=False)),'control-protocol',None),
            (frame(b'C',control(done=False)),'control-complete',None),
            (frame(b'C',control()),'uid-mismatch',(0,1001,'a'*64)),
            (frame(b'C',control()),'helper-mismatch',(0,1000,'b'*64)),
            (frame(b'C',control(status=250)),'relay-error-status',(250,1000,'a'*64)),
            (frame(b'C',control(status=-9)),'payload-signal',(-9,1000,'a'*64)),
            (frame(b'C',control()),'native-status-mismatch',(125,1000,'a'*64)),
            (b'D','incomplete-frame',(0,1000,'a'*64))]
        for wire,reason,finish in cases:
            with self.subTest(reason=reason):self.reject(wire,reason,finish)
        self.reject(b'x'*270000,'raw-byte-bound')
        self.reject(frame(b'D',b'x')+frame(b'D',b'y'),'data-after-partial')
        self.reject(frame(b'C',control())+b'x','after-terminal-frame')

    def test_exact_prior_decoder_accepted_set_for_controls_and_valid_families(self):
        # Same representative accepted/rejected values as the immutable prior implementation.
        import types
        old=types.ModuleType('prior_decoder');old.__file__=r.__file__
        source=subprocess.check_output(['git','-C',str(Path(r.__file__).resolve().parents[1]),'show','de85467:tools/native_relay.py'],text=True)
        exec(compile(source,r.__file__,'exec'),old.__dict__)
        for uid in (0,1000):
            for status in (0,1,4,125,250,-9,True):
                outcomes=[];wire=frame(b'C',control(uid=uid,status=status))
                for module in (old,r):
                    decoder=module.Decoder(262144)
                    try:decoder.feed(wire);decoder.finish(status,uid,'a'*64);outcomes.append(True)
                    except ValueError:outcomes.append(False)
                self.assertEqual(outcomes[0],outcomes[1])


class ControllerWitness(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=install(self,self.tmp.name);self.calls=[]
        self.original=subprocess.Popen;self.manager=manager(self.original,self.calls)

    def test_real_pipe_rejection_samples_before_interrupt_and_keeps_cleanup_status_separate(self):
        processes=[]
        def dispatch(args,**kwargs):
            if args[0]=='/usr/bin/systemd-run':
                self.calls.append(tuple(args))
                # A deliberately malformed producer uses the real owned FIFOs;
                # there is no native service, additional process or privileged effect.
                filtered=[value for value in args if value not in ('-I','--helper')]
                process=launch_payload(self.original,filtered,kwargs,[sys.executable,'-c','import os,time;os.write(2,b"SECRET!!");time.sleep(5)'])
                processes.append(process);return process
            return self.manager(args,**kwargs)
        run=b.Commands();records=[];run.diagnostic=records.append
        with patch.object(b.subprocess,'Popen',side_effect=dispatch),self.assertRaises(b.Blocked):
            run(*prefix(),'/usr/bin/true')
        value=records[-1]['native_failure'];self.assertEqual(value['point'],'relay-feed')
        self.assertEqual(value['category'],'decoder-rejected');self.assertTrue(value['status_sampled_before_interrupt'])
        self.assertIsNone(value['launcher_status_before_interrupt']);self.assertEqual(records[-1]['native_exit_status'],-9)
        self.assertEqual(value['decoder']['reason'],'header-invalid');self.assertNotIn('SECRET',json.dumps(records))
        self.assertTrue(all(p.poll() is not None for p in processes));self.assertEqual(list((self.root/'records').iterdir()),[])
        self.assertFalse((self.root/'streams'/UNIT).exists())
        self.entry={**records[-1],'diagnostic_identity':{'source_sha':SOURCE,'context_sha256':CONTEXT,'phase':'prepare'}}
        projected=guest.native_failure_projection(self.entry,{'source_sha':SOURCE,'context_sha256':CONTEXT},'prepare')
        self.assertEqual(projected['availability'],'observed')

    def test_valid_root_and_maintenance_acceptance_stays_unchanged(self):
        with patch.object(b.subprocess,'Popen',side_effect=self.manager):
            for unit in (UNIT,'dev-pair-initialize-prepare-12345678-12345678.service'):
                run=b.Commands();records=[];run.diagnostic=records.append
                self.assertEqual(run(*prefix(unit),sys.executable,'-c','print("accepted")'),'accepted\n')
                self.assertTrue(records[-1]['accepted_exit']);self.assertNotIn('native_failure',records[-1])
        self.assertEqual(list((self.root/'records').iterdir()),[])

    def test_real_nonzero_deadline_and_output_rejections_stay_blocking(self):
        with patch.object(b.subprocess,'Popen',side_effect=self.manager):
            for script,timeout in [('raise SystemExit(7)',5),('import time;time.sleep(5)',1),
                    ('import os;os.write(1,b"x"*1048577)',5)]:
                records=[];run=b.Commands();run.diagnostic=records.append
                with self.assertRaises(b.Blocked):run(*prefix(),sys.executable,'-c',script,timeout=timeout)
                record=records[-1];value=record['native_failure']
                self.assertFalse(record['accepted_exit']);self.assertTrue(value['launcher_handle_observed'])
                self.assertTrue(value['status_sampled_before_interrupt'])
                self.assertIn(value['category'],guest.NATIVE_FAILURE_CATEGORIES)
                self.assertLess(len(json.dumps(value)),1536)
                self.assertEqual(list((self.root/'records').iterdir()),[])
                if script.startswith('raise'):
                    self.assertEqual(value['category'],'status-rejected')
                    self.assertEqual(value['launcher_status_before_interrupt'],7)

    def test_prelaunch_rejection_keeps_missing_decoder_and_status_unavailable(self):
        records=[];run=b.Commands();run.diagnostic=records.append
        with patch.object(b.subprocess,'Popen',side_effect=self.manager),self.assertRaises(b.Blocked):
            run(*prefix(),'--SECRET=PRIVATE','/usr/bin/true')
        value=records[-1]['native_failure']
        self.assertEqual(value['point'],'not-reached');self.assertFalse(value['launcher_handle_observed'])
        self.assertFalse(value['status_sampled_before_interrupt']);self.assertIsNone(value['launcher_status_before_interrupt'])
        self.assertEqual(value['decoder'],{'availability':'unavailable'})
        self.assertNotIn('SECRET',json.dumps(records))
        # Existing final diagnostics may query the exact unit; payload launch
        # and the relay remain unobserved on this pre-admission path.
        self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in self.calls))
        self.assertTrue(all(args[0]=='/usr/bin/systemctl' for args in self.calls))

    def test_public_projection_is_closed_target_phase_bound_and_private(self):
        value={'point':'relay-finish','category':'decoder-rejected','launcher_handle_observed':True,
            'status_sampled_before_interrupt':True,'launcher_status_before_interrupt':0,'decoder':r.Decoder(262144).witness()}
        entry={'status':'failed-or-timed-out','native_failure':value,'diagnostic_identity':{'source_sha':SOURCE,'context_sha256':CONTEXT,'phase':'prepare'}}
        expected={'source_sha':SOURCE,'context_sha256':CONTEXT}
        self.assertEqual(guest.native_failure_projection(entry,expected,'prepare')['availability'],'observed')
        for key,bad in [('point','SECRET'),('category','SECRET'),('launcher_status_before_interrupt',True),
                        ('launcher_status_before_interrupt',-256),('SECRET','PRIVATE')]:
            changed=copy.deepcopy(entry);changed['native_failure'][key]=bad
            self.assertEqual(guest.native_failure_projection(changed,expected,'prepare'),{'availability':'unavailable'})
        for key in ('source_sha','context_sha256','phase'):
            changed=copy.deepcopy(entry);changed['diagnostic_identity'][key]='SECRET'
            self.assertEqual(guest.native_failure_projection(changed,expected,'prepare'),{'availability':'unavailable'})
        self.assertEqual(guest.native_failure_projection(entry,expected,'maintenance-gptbox'),{'availability':'unavailable'})
        changed=copy.deepcopy(entry);changed['native_failure']['decoder']['raw_bytes']=10**1000
        self.assertEqual(guest.native_failure_projection(changed,expected,'prepare'),{'availability':'unavailable'})
        state=Path(self.tmp.name)/'state';state.mkdir()
        (state/'prepare-diagnostics.json').write_text(json.dumps({'recent':[entry],'failures':[entry]}))
        public=guest.public_diagnostics(state,expected)
        self.assertEqual(public['prepare']['records'][0]['native_failure']['availability'],'observed')
        self.assertLess(len(guest.encode_report({'source_sha':SOURCE,'diagnostics':public})),guest.REPORT_LIMIT)


if __name__=='__main__':unittest.main()
