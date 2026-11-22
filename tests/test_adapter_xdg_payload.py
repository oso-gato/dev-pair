"""Source-shaped engine env and real pipes; no Podman/Fedora/DAC admission."""
import copy
import hashlib
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
import gptbox as g
import fedora_ci as ci
import fedora_ci_guest as guest
import test_gptbox as fixture
from native_io_fixture import install,manager,launch_payload

CONTEXT='a'*64;SOURCE='d'*40;UID='1000'
EXPECTED={'source_sha':SOURCE,'context_sha256':CONTEXT}

def entry(payload,status=1):
    return {'diagnostic_identity':{'source_sha':SOURCE,'context_sha256':CONTEXT,'phase':'maintenance-gptbox'},
            'step':'candidate-image','operation_id':'candidate-native-executor','relay_verified':True,
            'native_exit_status':status,'signed_load_payload':payload}

def selected():return {'context_sha256':CONTEXT,'unit':'dev-pair-gptbox-'+CONTEXT+'.service','suboperation':'load'}

def payload(stderr=b'',stdout=b'',status=1,complete=True):
    return b.signed_load_payload({'stdout':bytearray(stdout),'stderr':bytearray(stderr)},selected(),UID,
        launched=True,verified=True,status=status,complete=complete)

class ConfigTests(unittest.TestCase):
    def case(self):
        case=fixture.GptboxTests();case.setUp();self.addCleanup(case.doCleanups)
        app=case.app;app.target=g.ROOT+'/'+CONTEXT;app.scripts=app.inputs(case.context,CONTEXT,'/upstream',SOURCE)[1]
        return case,app
    def test_actual_setup_env_producer_selects_all_fixed_operations_and_empty_protected_config(self):
        case,app=self.case();app.setup_executor()
        config=app.path(g.CONTROL+'/xdg-config');home=app.path(g.CONTROL+'/home')
        self.assertEqual(config.stat().st_mode&0o777,0o755);self.assertEqual(config.stat().st_uid,os.getuid());self.assertEqual(list(config.iterdir()),[])
        self.assertEqual(home.stat().st_mode&0o777,0o755);self.assertEqual(list(home.iterdir()),[])
        self.assertEqual(app.path(g.CONTROL+'/containers.conf').stat().st_mode&0o777,0o444)
        self.assertIn('XDG_CONFIG_HOME='+str(config),app.executor)
        prefix=tuple(v.replace(str(case.root),'',1).replace('RuntimeMaxSec=1800','RuntimeMaxSec=120') for v in app.executor)
        work='/var/lib/dev-pair/artifacts/gptbox-adapter/'+CONTEXT+'/image-work';wrapper=g.CONTROL+'/bin/podman'
        operations={'load':('/usr/bin/env','TMPDIR='+work+'/image-copy',wrapper,'load','--input',work+'/verification-work/dev-pair-fedora-abc123_4/base.oci.tar'),
                    'save':('/usr/bin/env','TMPDIR='+work+'/image-copy',wrapper,'save','--format=oci-archive','--output',work+'/verification-work/dev-pair-fedora-abc123_4/imported.oci.tar',g.FEDORA),
                    'inspect':(wrapper,'image','inspect','f'*64),
                    'build':('/usr/bin/env','TMPDIR='+work+'/image-copy',wrapper,'build','--quiet','--network=slirp4netns:allow_host_loopback=false','--pull=never','--http-proxy=false','--file',work.rsplit('/',1)[0]+'/build/Containerfile',work.rsplit('/',1)[0]+'/build')}
        run=b.Commands();run.current_step='candidate-image'
        with run.adapter_image_launcher(CONTEXT,app.uid):
            for name,args in operations.items():self.assertEqual(run.adapter_image_selection(prefix+args,None)['suboperation'],name)
            for change in ('XDG_CONFIG_HOME=/tmp','XDG_CONFIG_HOME='+g.CONTROL+'/home','XDG_CONFIG_HOME='+g.CONTROL+'/xdg-config/child'):
                wrong=tuple(change if v.startswith('XDG_CONFIG_HOME=') else v for v in prefix)
                self.assertIsNone(run.adapter_image_selection(wrong+operations['load'],None))
            self.assertIsNone(run.adapter_image_selection(tuple(v for v in prefix if not v.startswith('XDG_CONFIG_HOME='))+operations['load'],None))
        self.assertIsNone(run._adapter_image_binding)
    def test_real_symlink_mode_and_content_conflicts_preserved(self):
        for kind in ('symlink','mode','content'):
            with self.subTest(kind=kind):
                case,app=self.case();app.setup_executor();path=app.path(g.CONTROL+'/xdg-config')
                if kind=='symlink':path.rmdir();path.symlink_to(app.path(g.CONTROL+'/home'))
                elif kind=='mode':path.chmod(0o777)
                else:(path/'undeclared').write_text('PRIVATE sentinel')
                with self.assertRaises(g.Blocked):app.setup_executor()
                if kind=='content':self.assertEqual((path/'undeclared').read_text(),'PRIVATE sentinel')
    def test_injected_foreign_owner_and_no_agent_writable_overlap(self):
        case,app=self.case();app.setup_executor();path=app.path(g.CONTROL+'/xdg-config');identity=(path.stat().st_dev,path.stat().st_ino);original=os.fstat
        def foreign(fd):
            info=original(fd)
            if (info.st_dev,info.st_ino)==identity:
                values=list(info);values[4]=info.st_uid+1;return os.stat_result(values)
            return info
        with patch.object(b.os,'fstat',side_effect=foreign),self.assertRaises(g.Blocked):app.setup_executor()
        case.assemble()
        for source,_ in app.mounts.values():self.assertFalse(path==Path(source) or path.is_relative_to(Path(source)))

class ProjectionTests(unittest.TestCase):
    def test_complete_matched_and_unknown_binary_sentinel_are_hash_only(self):
        for family,raw in b.SIGNED_LOAD_ERRORS.items():
            value=payload(raw);public=guest.signed_load_projection(entry(value),EXPECTED)
            self.assertEqual(public['classification'],{'family':family,'path_role':'old-home-config'})
            self.assertEqual(public['streams']['stderr']['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertNotIn(raw.decode().strip(),json.dumps(public));self.assertLessEqual(len(json.dumps(public,separators=(',',':'))),1024)
        for raw in (b.SIGNED_LOAD_OWNER_ERROR,b'PRIVATE secret path /arbitrary/password',b'\x1b[31m'+b.SIGNED_LOAD_OWNER_ERROR,b'Error: '+b.SIGNED_LOAD_OWNER_ERROR,b.SIGNED_LOAD_OWNER_ERROR+b'\nPRIVATE',b'\xff\x00',b.SIGNED_LOAD_ERRORS['reported-stat-enoent'].replace(b'/home/.config',b'/home/PRIVATE'),b.SIGNED_LOAD_ERRORS['reported-stat-enoent'].replace(b'no such file or directory',b'unknown errno'),b.SIGNED_LOAD_ERRORS['reported-stat-enoent']+b'\n'):
            public=guest.signed_load_projection(entry(payload(raw)),EXPECTED)
            self.assertEqual(public['classification']['family'],'unknown');self.assertNotIn('PRIVATE',json.dumps(public));self.assertNotIn('/arbitrary',json.dumps(public))
    def test_absent_partial_conflicting_and_typed_mutation_rejects(self):
        self.assertIsNone(b.signed_load_payload({'stdout':bytearray(),'stderr':bytearray()},None,UID,launched=False,verified=False,status=None,complete=False))
        partial=b.signed_load_payload({'stdout':bytearray(),'stderr':bytearray()},selected(),UID,launched=False,verified=False,status=None,complete=False)
        self.assertIsNone(partial['streams']['stdout']['bytes']);self.assertFalse(partial['streams']['stdout']['complete'])
        self.assertEqual(guest.signed_load_projection(entry(payload(b.SIGNED_LOAD_OWNER_ERROR,complete=False)),EXPECTED)['classification']['family'],'unknown')
        self.assertEqual(guest.signed_load_projection(entry(payload(b.SIGNED_LOAD_OWNER_ERROR,b'PRIVATE')),EXPECTED)['classification']['family'],'unknown')
        self.assertEqual(guest.signed_load_projection(entry(payload(b.SIGNED_LOAD_OWNER_ERROR,status=0),0),EXPECTED)['classification']['family'],'unknown')
        base=entry(payload(b.SIGNED_LOAD_OWNER_ERROR+b'\n'))
        for change in ('scope','context','uid','hash','complete','extra','control'):
            with self.subTest(change=change):
                bad=copy.deepcopy(base);value=bad['signed_load_payload']
                if change=='scope':bad['step']='other'
                if change=='context':value['context_sha256']='b'*64
                if change=='uid':value['uid']=True
                if change=='hash':value['streams']['stderr']['sha256']='0'*64
                if change=='complete':value['streams']['stderr']['complete']=False
                if change=='extra':value['PRIVATE']='sentinel'
                if change=='control':bad['relay_verified']=False
                self.assertEqual(guest.signed_load_projection(bad,EXPECTED),{'availability':'unavailable'})
    def test_worst_bound_overbound_partial_and_public_store_projection(self):
        value=payload(b'x'*4194304);public=guest.signed_load_projection(entry(value),EXPECTED)
        self.assertEqual(public['streams']['stderr']['bytes'],4194304);self.assertEqual(public['classification']['family'],'unknown')
        bad=copy.deepcopy(value);bad['streams']['stderr']['bytes']=4194305
        self.assertEqual(guest.signed_load_projection(entry(bad),EXPECTED),{'availability':'unavailable'})
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'gptbox-adapter'/CONTEXT;path.mkdir(parents=True)
            row=entry(payload(b'PRIVATE'));row.update(status=1,outcome='rejected',accepted_exit=False,allowed_exit_statuses=[0],stdout_tail='',stderr_tail='')
            (path/'diagnostics.json').write_text(json.dumps({'recent':[row],'failures':[row]}))
            public=guest.public_diagnostics(root,EXPECTED)['adapter']
            self.assertEqual(public['records'][0]['signed_load_payload']['streams']['stderr']['bytes'],7)
            self.assertNotIn('PRIVATE',json.dumps(public))

class RealPayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.io=install(self,self.tmp.name)
        self.case=fixture.GptboxTests();self.case.setUp();self.addCleanup(self.case.doCleanups);self.app=self.case.app
        app=self.app;app.target=g.ROOT+'/'+CONTEXT;app.scripts=app.inputs(self.case.context,CONTEXT,'/upstream',SOURCE)[1]
        app.setup_executor();app.directory(app.target,mode=0o755)
        app.executor=[value.replace(str(self.case.root),'',1).replace('XDG_RUNTIME_DIR=/run/user/'+app.uid,'XDG_RUNTIME_DIR=/run/user/'+UID) for value in app.executor]
        app.uid=UID;app.wrapper=g.CONTROL+'/bin/podman';app.run=g.ProbeCommands();app.image_phase_active=True
        app.failure_diagnostic_identity={'source_sha':SOURCE,'context_sha256':CONTEXT,'phase':'maintenance-gptbox'}
        self.calls=[];self.children=[];self.original=subprocess.Popen;self.manager=manager(self.original,self.calls)
    def execute(self,stderr=b'',stdout=b'',code=1,operation='load',broken_collector=False,broken_cleanup=False,wrong_binding=False):
        work='/var/lib/dev-pair/artifacts/gptbox-adapter/'+CONTEXT+'/image-work'
        argv=('/usr/bin/env','TMPDIR='+work+'/image-copy',self.app.wrapper,'load','--input',work+'/verification-work/dev-pair-fedora-abc123_4/base.oci.tar')
        if operation=='save':argv=('/usr/bin/env','TMPDIR='+work+'/image-copy',self.app.wrapper,'save','--format=oci-archive','--output',work+'/verification-work/dev-pair-fedora-abc123_4/imported.oci.tar',g.FEDORA)
        script='import os;os.write(1,'+repr(stdout)+');os.write(2,'+repr(stderr)+');raise SystemExit('+str(code)+')'
        def dispatch(args,**kwargs):
            if args[0]=='/usr/bin/systemd-run':
                self.calls.append(tuple(args));index=args.index('--',args.index('--helper'))
                # CLI launcher channel is separate from the framed payload stderr.
                cli=('Running as unit: dev-pair-gptbox-'+CONTEXT+'.service; invocation ID: '+'b'*32+'\nFinished with result: exit-code\nMain processes terminated with: code=exited, status='+str(code)+'\n').encode()
                os.write(kwargs['stderr'],cli)
                replaced=(*args[:index+1],sys.executable,'-c',script)
                child=launch_payload(self.original,replaced,kwargs,[sys.executable,'-c',script]);self.children.append(child);return child
            return self.manager(args,**kwargs)
        original_interrupt=self.app.run.interrupt
        def interrupt(*args):
            original_interrupt(*args)
            if broken_cleanup:raise b.Blocked('PRIVATE cleanup uncertainty')
        if wrong_binding:self.app.executor=['XDG_CONFIG_HOME=/tmp' if v.startswith('XDG_CONFIG_HOME=') else v for v in self.app.executor]
        import contextlib
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(b.subprocess,'Popen',side_effect=dispatch));stack.enter_context(patch.object(b,'expected_uid',return_value=int(UID)))
            stack.enter_context(patch.object(self.app.run,'interrupt',side_effect=interrupt))
            if broken_collector:stack.enter_context(patch.object(b,'signed_load_payload',side_effect=OSError('PRIVATE collector failure')))
            result=self.app.execute(*argv,timeout=3)
        return result
    def history(self):return json.loads(self.app.text(self.app.target+'/diagnostics.json'))
    def test_verified_real_framed_failure_survives_tail_suppression_and_public_projection(self):
        raw=b.SIGNED_LOAD_OWNER_ERROR+b'\n'
        with self.assertRaisesRegex(b.Blocked,'exit 1'):self.execute(raw)
        record=self.history()['failures'][-1];self.assertEqual(record['stderr_tail'],'');self.assertEqual(record['stdout_tail'],'')
        self.assertTrue(record['relay_verified']);self.assertTrue(record['signed_load_payload']['control_verified'])
        public=guest.signed_load_projection(record,EXPECTED);self.assertEqual(public['streams']['stderr']['bytes'],len(raw));self.assertTrue(public['streams']['stderr']['complete'])
        self.assertEqual(public['classification']['family'],'reported-owner')
        self.assertTrue(all(p.returncode is not None for p in self.children));self.assertEqual(list((self.io/'records').iterdir()),[])
    def test_unselected_wrong_binding_and_nonload_never_gain_payload_field(self):
        for operation,wrong in (('save',False),('load',True)):
            with self.subTest(operation=operation,wrong=wrong),self.assertRaises(b.Blocked):self.execute(b'PRIVATE',operation=operation,wrong_binding=wrong)
            self.assertNotIn('signed_load_payload',self.history()['failures'][-1]);self.assertNotIn('PRIVATE',json.dumps(self.history()))
    def test_unknown_sentinel_outputcap_and_cleanup_uncertainty_never_claim_complete_family(self):
        with self.assertRaises(b.Blocked):self.execute(b'PRIVATE engine detail',b'PRIVATE stdout')
        record=self.history()['failures'][-1];public=guest.signed_load_projection(record,EXPECTED)
        self.assertEqual(public['classification']['family'],'unknown');self.assertNotIn('PRIVATE',json.dumps(self.history()))
        with self.assertRaises(b.Blocked):self.execute(b'x'*4194305)
        record=self.history()['failures'][-1];value=record['signed_load_payload']
        self.assertNotEqual(value['availability'],'observed');self.assertFalse(any(v['complete'] for v in value['streams'].values()))
        with self.assertRaisesRegex(b.Blocked,'cleanup-unresolved'):self.execute(b.SIGNED_LOAD_OWNER_ERROR,broken_cleanup=True)
        value=self.history()['failures'][-1]['signed_load_payload'];self.assertFalse(any(v['complete'] for v in value['streams'].values()));self.assertEqual(value['classification']['family'],'unknown')
    def test_collector_failure_keeps_primary_and_required_success_diagnostics_fail_closed(self):
        with self.assertRaisesRegex(b.Blocked,'exit 1') as seen:self.execute(b'PRIVATE payload',broken_collector=True)
        self.assertNotIn('PRIVATE',str(seen.exception));self.assertNotIn('PRIVATE',json.dumps(self.history()))
        with self.assertRaisesRegex(b.Blocked,'required command diagnostics unavailable') as seen:self.execute(code=0,broken_collector=True)
        self.assertNotIn('PRIVATE',str(seen.exception));self.assertTrue(all(p.returncode is not None for p in self.children))

class ReportConsumerTests(unittest.TestCase):
    def test_actual_report_encoder_consumer_agree_and_reject_forged_payload(self):
        from test_fedora_ci import fixture_inputs
        expected=fixture_inputs();expected.update(EXPECTED)
        row=entry(payload(b.SIGNED_LOAD_OWNER_ERROR+b'\n'));value=guest.signed_load_projection(row,expected)
        public={k:row[k] for k in ('step','operation_id','relay_verified','native_exit_status')};public['signed_load_payload']=value
        report={'version':guest.REPORT_VERSION,'source_sha':SOURCE,'guest_sha256':'b'*64,'inputs':expected,'initialization':{},
                'phases':{key:{'status':'blocked','detail':'synthetic source/local test'} for key in guest.GUEST_PHASES},'identity':{},
                'diagnostics':{'public_operations':{'adapter':{'records':[public],'recent_metadata':[public]}}}}
        frame=guest.encode_report(report);self.assertEqual(ci.parse_serial(frame,SOURCE,'b'*64,expected),report);self.assertLessEqual(len(frame),guest.REPORT_FRAME_LIMIT)
        for kind in ('extra','binding','family','status'):
            bad=copy.deepcopy(report);item=bad['diagnostics']['public_operations']['adapter']['records'][0];value=item['signed_load_payload']
            if kind=='extra':value['PRIVATE']='sentinel'
            if kind=='binding':value['identity']['context_sha256']='f'*64
            if kind=='family':value['classification']['family']='PRIVATE-family'
            if kind=='status':item['native_exit_status']=0
            with self.subTest(kind=kind),self.assertRaises(ci.Blocked):ci.parse_serial(guest.encode_report(bad),SOURCE,'b'*64,expected)
