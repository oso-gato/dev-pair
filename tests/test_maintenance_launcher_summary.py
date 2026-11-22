"""Exact maintenance diagnostic opt-in; real pipes with synthetic manager only."""
import ast
import contextlib
import shutil
from types import SimpleNamespace
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'tools')]
import bootstrap as b
import fedora_ci_guest as guest
import fedora_oci as oci
import test_bootstrap as builder_fixture
REAL_IMPORT=oci.import_image
REAL_VERIFICATION_TREE=oci._verification_tree
from native_io_fixture import install,manager,launch_payload

CONTEXT='a'*64;UNIT='dev-pair-gptbox-'+CONTEXT+'.service'
BASE='f54afb5ece014357c5e0ed33f4b70a2254fe9217'

def candidate_args(operation='load',context=CONTEXT,uid='1000'):
    work='/var/lib/dev-pair/artifacts/gptbox-image-work/'+context
    stage='/var/lib/dev-pair/artifacts/gptbox/'+context
    prefix=('/usr/bin/systemd-run','--wait','--collect','--service-type=exec','--uid=dp-maint','--unit=dev-pair-gptbox-'+context+'.service',
        '--description=dev-pair-owned-dev-pair-gptbox-'+context+'.service','--property=RuntimeMaxSec=600','--property=TimeoutStopSec=10',
        '--property=KillMode=control-group','--property=MemoryMax=2G','--property=TasksMax=512','--property=CPUQuota=100%',
        '/usr/bin/env','-i','HOME=/home/dp-maint','USER=dp-maint','LOGNAME=dp-maint','PATH=/usr/sbin:/usr/bin','XDG_RUNTIME_DIR=/run/user/'+uid)
    if operation!='inspect':prefix+=('TMPDIR='+work+'/image-copy',)
    if operation=='save':prefix+=('/usr/bin/prlimit','--fsize='+str(oci.SAVE_FILE_LIMIT)+':'+str(oci.SAVE_FILE_LIMIT),)
    prefix+=('/usr/bin/podman','--root','/var/lib/dev-pair/maintenance/images','--runroot','/run/user/'+uid+'/dev-pair-gptbox-build','--storage-driver=vfs')
    archive=work+'/verification-work/dev-pair-fedora-abc123_4/'
    operations={'load':('load','--input',archive+'base.oci.tar'),'save':('save','--format=oci-archive','--output',archive+'imported.oci.tar',oci.IMAGE),
        'inspect':('image','inspect',oci.IMAGE),'build':('build','--quiet','--network=slirp4netns:allow_host_loopback=false','--pull=never','--format=oci',
            '--label','dev-pair.context='+context,'--tag','localhost/dev-pair/maintenance-gptbox:'+context,'--file',stage+'/Containerfile',stage)}
    return prefix+operations[operation]

def summary(unit=UNIT,result='timeout'):
    return ('Running as unit: '+unit+'; invocation ID: '+'b'*32+'\nFinished with result: '+result+'\nMain processes terminated with: code=killed, status=15/TERM\n').encode()

class SelectionTests(unittest.TestCase):
    def test_exact_owned_commands_and_ephemeral_scope(self):
        run=b.Commands();run.current_step='maintenance-gptbox-build'
        self.assertIsNone(run.maintenance_launcher_selection(candidate_args(),None,False))
        with run.maintenance_launcher(CONTEXT,'1000'):
            for operation in ('load','save','inspect','build'):
                self.assertEqual(run.maintenance_launcher_selection(candidate_args(operation),None,False),
                    {'context_sha256':CONTEXT,'unit':UNIT,'suboperation':operation})
            with self.assertRaises(RuntimeError):
                with run.maintenance_launcher('c'*64,'1001'):raise RuntimeError()
            self.assertEqual(run._maintenance_launcher_binding,(CONTEXT,'1000'))
        self.assertIsNone(run._maintenance_launcher_binding)
    def test_wrong_context_owner_paths_step_stdin_probe_flags_and_operations_do_not_opt_in(self):
        run=b.Commands();run.current_step='maintenance-gptbox-build';original=candidate_args()
        with run.maintenance_launcher(CONTEXT,'1000'):
            for value in (candidate_args(context='c'*64),candidate_args(uid='1001'),
                tuple(v.replace('--uid=dp-maint','--uid=root') for v in original),
                tuple(v.replace('/var/lib/dev-pair/maintenance/images','/PRIVATE') for v in original),
                tuple(v.replace('dev-pair-gptbox-build','OTHER') for v in original),
                tuple(v.replace('--storage-driver=vfs','--storage-driver=overlay') for v in original),
                tuple(v.replace('abc123_4','../other') for v in original),original+('--extra',),
                original[:-3]+('pull','PRIVATE'),original[:1]+('--quiet',)+original[1:],original[:-1]+(None,)):
                self.assertIsNone(run.maintenance_launcher_selection(value,None,False))
            self.assertIsNone(run.maintenance_launcher_selection(original,'',False));self.assertIsNone(run.maintenance_launcher_selection(original,None,True))
            run.current_step='packages';self.assertIsNone(run.maintenance_launcher_selection(original,None,False))
    def test_maintenance_announcement_is_exact_and_prior_tailscale_parser_is_preserved(self):
        self.assertEqual(b.launcher_summary(summary(),True,UNIT)['result'],'timeout')
        for raw in (summary('dev-pair-gptbox-'+'c'*64+'.service'),summary(UNIT+'.other'),summary()+summary(),summary()+b'PRIVATE: SECRET\n',summary()+b'x'*8192):
            self.assertEqual(b.launcher_summary(raw,True,UNIT),{'availability':'unavailable'})
        self.assertEqual(b.launcher_summary(summary(),False,UNIT),{'availability':'unavailable'})
        self.assertEqual(b.launcher_summary(summary(),True),{'availability':'unavailable'})
    def test_production_builder_passes_identical_argv_and_all_non_diagnostic_functions_are_unchanged(self):
        source=Path(b.__file__);old=ast.parse(subprocess.check_output(['git','-C',str(source.parents[1]),'show',BASE+':tools/bootstrap.py'],text=True));new=ast.parse(source.read_text())
        def build(tree):return next(n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='Bootstrap' for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='build_gptbox')
        prior=build(old);current=copy.deepcopy(build(new));current.body=[n for n in current.body if not isinstance(n,ast.FunctionDef) or n.name!='candidate_execute']
        class Restore(ast.NodeTransformer):
            def visit_Call(self,node):
                self.generic_visit(node)
                if isinstance(node.func,ast.Name) and node.func.id=='candidate_execute':node.func=ast.Attribute(value=ast.Name(id='self',ctx=ast.Load()),attr='run',ctx=ast.Load())
                return node
        self.assertEqual(ast.dump(prior),ast.dump(Restore().visit(current)))
        def unrelated(tree):
            result={}
            for c in tree.body:
                if isinstance(c,ast.ClassDef):
                    for n in c.body:
                        if isinstance(n,ast.FunctionDef) and not(c.name=='Commands' and n.name in ('_call','maintenance_launcher','maintenance_launcher_selection')) and not(c.name=='Bootstrap' and n.name=='build_gptbox'):result[c.name+'.'+n.name]=ast.dump(n)
            return result
        self.assertEqual(unrelated(old),unrelated(new))

class MaintenanceProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=install(self,self.tmp.name)
        self.calls=[];self.original=subprocess.Popen;self.manager=manager(self.original,self.calls)
    def dispatch(self,raw,payload=False):
        def launch(args,**kw):
            if args[0]=='/usr/bin/systemd-run':
                self.calls.append(tuple(args))
                if not payload:os.write(kw['stderr'],raw)
                filtered=[v for v in args if v not in ('-I','--helper')]
                script='import os;os.write(2,'+repr(raw)+');raise SystemExit(1)' if payload else 'raise SystemExit(1)'
                return launch_payload(self.original,filtered,kw,[sys.executable,'-c',script])
            return self.manager(args,**kw)
        return launch
    def rejected(self,raw,payload=False):
        run=b.Commands();run.current_step='maintenance-gptbox-build';run.deadline=time.monotonic()+3.257;records=[];run.metadata_diagnostic=records.append
        with run.maintenance_launcher(CONTEXT,'1000'),patch.object(b.subprocess,'Popen',side_effect=self.dispatch(raw,payload)),self.assertRaises(b.Blocked):run(*candidate_args(),timeout=3.257)
        self.assertIsNone(run._maintenance_launcher_binding);self.assertEqual(list((self.root/'records').iterdir()),[])
        return records[-1]
    def test_real_launcher_capture_timing_and_source_bound_projection_without_launch_changes(self):
        record=self.rejected(summary());failure=record['native_failure'];launcher=failure['launcher']
        self.assertEqual(failure['launcher_status_before_interrupt'],1);self.assertEqual(failure['decoder']['raw_bytes'],0)
        self.assertEqual(launcher['summary']['result'],'timeout');self.assertEqual(launcher['executor'],{'context_sha256':CONTEXT,'unit':UNIT,'suboperation':'load'})
        args=next(v for v in self.calls if v[0]=='/usr/bin/systemd-run')
        self.assertNotIn('--quiet',args);self.assertIn('--uid=dp-maint',args);self.assertIn('--profile',args)
        self.assertEqual(args[args.index('--profile')+1],'maintenance')
        for key,prop in (('start_us','TimeoutStartSec'),('runtime_us','RuntimeMaxSec')):
            self.assertEqual(launcher['timing'][key],round(float(next(v.rsplit('=',1)[1][:-1] for v in args if v.startswith('--property='+prop+'=')))*1000000))
        entry={**record,'diagnostic_identity':{'source_sha':'d'*40,'context_sha256':CONTEXT,'phase':'prepare'}};expected={'source_sha':'d'*40,'context_sha256':CONTEXT}
        projected=guest.native_failure_projection(entry,expected,'prepare');self.assertEqual(projected['launcher']['summary']['result'],'timeout')
        self.assertLessEqual(len(json.dumps(projected,separators=(',',':')).encode()),1536);self.assertNotIn('Running as unit',json.dumps(record))
        for key,value in (('context_sha256','c'*64),('unit','dev-pair-gptbox-'+'c'*64+'.service'),('suboperation','PRIVATE')):
            changed=copy.deepcopy(entry);changed['native_failure']['launcher']['executor'][key]=value
            p=guest.native_failure_projection(changed,expected,'prepare');self.assertEqual(p['launcher'],{'availability':'unavailable'});self.assertEqual(p['point'],'relay-finish')
        for key,value in (('step','packages'),('operation_id','signed-packages')):
            changed=copy.deepcopy(entry);changed[key]=value;self.assertEqual(guest.native_failure_projection(changed,expected,'prepare')['launcher'],{'availability':'unavailable'})
    def test_payload_text_and_parser_failure_cannot_admit_or_leak(self):
        for raw,payload,available in ((summary(result='success'),False,True),(summary(result='success'),True,False),(summary()+b'PRIVATE: SECRET\n',False,False),(summary('dev-pair-gptbox-'+'c'*64+'.service'),False,False)):
            record=self.rejected(raw,payload);failure=record['native_failure']
            self.assertEqual(failure['category'],'decoder-rejected');self.assertFalse(record['accepted_exit'])
            self.assertEqual(failure['launcher']['summary']['availability'],'observed' if available else 'unavailable')
            self.assertNotIn('SECRET',json.dumps(record));self.assertNotIn('Running as unit',json.dumps(record))

    def test_valid_selected_relay_still_admits_and_raw_launcher_stays_separate(self):
        def dispatch(args,**kw):
            if args[0]=='/usr/bin/systemd-run':
                self.calls.append(tuple(args));os.write(kw['stderr'],summary(result='success'))
                changed=list(args);i=changed.index('--');changed[i+1:]=[sys.executable,'-c','print("payload")']
                return launch_payload(self.original,changed,kw,[])
            return self.manager(args,**kw)
        run=b.Commands();run.current_step='maintenance-gptbox-build';records=[];run.metadata_diagnostic=records.append
        with run.maintenance_launcher(CONTEXT,'1000'),patch.object(b.subprocess,'Popen',side_effect=dispatch):
            self.assertEqual(run(*candidate_args(),timeout=3),'payload\n')
        self.assertTrue(records[-1]['accepted_exit']);self.assertTrue(records[-1]['relay_verified'])
        self.assertNotIn('native_failure',records[-1]);self.assertNotIn('Running as unit',json.dumps(records))
    def test_worst_closed_witness_preserves_all_fields_and_oversized_secondary_is_unavailable(self):
        record=self.rejected(summary());value=record['native_failure'];d=value['decoder'];limit=4194304;frames=(limit+4095)//4096
        value.update(point=max(guest.NATIVE_FAILURE_POINTS,key=len),category=max(guest.NATIVE_FAILURE_CATEGORIES,key=len),launcher_status_before_interrupt=-255)
        value['launcher']['bytes']=8192;value['launcher']['executor']['suboperation']='inspect';d['maximum']=limit
        d.update(raw_bytes=limit+8*frames+256+8192,raw_bytes_clamped=True,data_frames=frames+1,frame_kind='unavailable',reason=max(guest.DECODER_REASONS,key=len),
            header_present=False,body_present=False,partial_frame=False,complete=False)
        value['launcher']['summary']={'availability':'observed','result':'start-limit-hit','code':'exited','status':255}
        value['launcher']['timing'].update(start_us=5000000,runtime_us=900000000,command_remaining_us=900000000,
            phase_remaining_us=900000000,helper_margin_us=100001)
        entry={**record,'diagnostic_identity':{'source_sha':'d'*40,'context_sha256':CONTEXT,'phase':'prepare'}};expected={'source_sha':'d'*40,'context_sha256':CONTEXT}
        normal=guest.native_failure_projection(entry,expected,'prepare')
        self.assertEqual(normal['launcher']['timing']['runtime_us'],900000000);self.assertEqual(normal['launcher']['summary']['result'],'start-limit-hit')
        cache={'availability':'observed','stage':'cache-final-comparison','rows':[1024,1024],'order_only_equal':False,
            'row_index':1023,'row_side':'before','path_class':'global-mask-directory','lookup_index':11,'changed_fields':127,'truncated':False}
        entry.update(admission_stage='cache-recheck',admission_reason='cache-final-comparison');entry['native_failure']['cache_comparison']=cache
        raw={'availability':'observed','identity':entry['diagnostic_identity'],**entry['native_failure']}
        self.assertLessEqual(len(json.dumps(raw,separators=(',',':')).encode()),1536)
        maximum=guest.native_failure_projection(entry,expected,'prepare')
        self.assertEqual(maximum['availability'],'observed');self.assertEqual(maximum['cache_comparison'],cache)
        self.assertEqual(maximum['point'],value['point']);self.assertEqual(maximum['decoder'],d)
        self.assertEqual(maximum['launcher'],value['launcher'])
        oversized=copy.deepcopy(entry);oversized['native_failure']['launcher']['summary']['result']='PRIVATE'*1200
        unavailable=guest.native_failure_projection(oversized,expected,'prepare')
        self.assertEqual(unavailable['availability'],'observed');self.assertEqual(unavailable['cache_comparison'],cache)
        self.assertEqual(unavailable['decoder'],d);self.assertEqual(unavailable['launcher'],{'availability':'unavailable'})
        self.assertNotIn('PRIVATE',json.dumps(unavailable));self.assertLessEqual(len(json.dumps(unavailable,separators=(',',':')).encode()),1536)

class RealBuilderSelectionTests(unittest.TestCase):
    def test_actual_builder_and_import_argv_opt_in_with_only_explicit_fixture_root_mapping(self):
        case=builder_fixture.BootstrapTests();case.setUp();self.addCleanup(case.doCleanups);case.prepare();context,digest=case.context()
        # Signature/graph and distinct-UID boundaries are injected, not admitted.
        # The production builder, import_image and tempfile path producer run.
        @contextlib.contextmanager
        def workspaces(parent,**kw):
            parent=Path(parent);copying=parent/'image-copy';verification=parent/'verification-work'
            copying.mkdir();verification.mkdir()
            try:yield copying,verification
            finally:shutil.rmtree(copying);shutil.rmtree(verification)
        @contextlib.contextmanager
        def verified(source,*,temporary_parent,**kw):
            with REAL_VERIFICATION_TREE(temporary_parent,True) as directory:
                plain=Path(directory)/'base.oci.tar';plain.write_bytes(b'synthetic archive, graph boundary injected')
                yield plain,{'fixture':'no signature proof'}
        selected=[];fake=case.fake;fixture_root=str(case.root)
        class RecordingCommands(builder_fixture.b.Commands):
            current_step='maintenance-gptbox-build'
            def __call__(self,*args,**kw):
                if args[0]=='/usr/bin/systemd-run':
                    # Only the owned tempfile root is projected to production /.
                    # Actual protected path suffixes/tempfile names are untouched.
                    def production(v):
                        if v.startswith(fixture_root+'/'):return v[len(fixture_root):]
                        if v.startswith('TMPDIR='+fixture_root+'/'):return 'TMPDIR='+v[len('TMPDIR='+fixture_root):]
                        return v
                    selected.append(self.maintenance_launcher_selection(tuple(production(v) for v in args),kw.get('input_text'),False))
                    operation=args[args.index('--storage-driver=vfs')+1:]
                    if operation==('image','inspect',oci.IMAGE):fake.calls.append(args);return '[]'
                    if operation[0]=='save':Path(operation[operation.index('--output')+1]).write_bytes(b'synthetic save; graph validation injected')
                return fake(*args,**kw)
        run=RecordingCommands();case.app.run=run
        def import_without_distinct_uid(engine,plain,uid=None,seconds=120):return REAL_IMPORT(engine,plain,uid=None,seconds=seconds)
        with patch.object(oci,'image_workspaces',side_effect=workspaces),patch.object(oci,'verified',side_effect=verified),                patch.object(oci,'import_image',side_effect=import_without_distinct_uid),patch.object(oci,'parse_oci',return_value={}),                patch.object(oci,'imported',return_value={}),patch.object(case.app,'observe_storage',return_value={}),                patch.object(run,'reconcile_native',return_value=None),patch.object(builder_fixture.b.shutil,'disk_usage',return_value=SimpleNamespace(free=10*1024**3)):
            case.app.build_gptbox(context,digest);case.app.build_gptbox(context,digest)
        self.assertTrue(selected);self.assertTrue(all(x is not None for x in selected))
        self.assertEqual([x['suboperation'] for x in selected],['load','inspect','save','build','inspect','inspect'])
        self.assertTrue(all(x['context_sha256']==digest and x['unit']=='dev-pair-gptbox-'+digest+'.service' for x in selected))
        self.assertIsNone(run._maintenance_launcher_binding)

if __name__=='__main__':unittest.main()
