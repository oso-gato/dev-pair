"""One-image transaction failure tests; host/source/native boundaries injected."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
import shutil
import tempfile
import fedora_input_fixture
from unittest.mock import patch
import bootstrap as b
import gptbox as g
REAL_IMPORT=g.fedora_oci.import_image
import fedora_ci_guest as guest
import test_gptbox as fixtures
import test_bootstrap as host_fixture

class OneImageTests(unittest.TestCase):
    def make(self):
        case=fixtures.GptboxTests();case.setUp();self.addCleanup(case.doCleanups);app=case.app;engine=case.engine
        app.path(b.STATE+'/prepared').unlink();app.path(b.STATE+'/gptbox-image.json').unlink()
        app.atomic(b.STATE+'/operator-password-set','fixture existing password')
        app.protected=lambda value:Path(value)
        app.check_gptbox_inputs=lambda *args:(None,case.context,{'source_sha':fixtures.SOURCE})
        phases=[];selected=[];outer=self
        class Runner(g.ProbeCommands):
            def __call__(self,*args,**kwargs):
                if args[0]=='/usr/bin/systemd-run' and self._adapter_image_binding is not None:
                    root=str(case.root)
                    def canonical(v):return v.replace(root,'',1) if root in v else v
                    selected.append(self.maintenance_launcher_selection(tuple(canonical(v) for v in args),None,True))
                if '/bin/podman' in ' '.join(args):
                    if 'save' in args and '--output' in args:Path(args[args.index('--output')+1]).write_bytes(b'synthetic saved archive')
                return engine(*args,**kwargs)
            @contextlib.contextmanager
            def phase(self,seconds,prefix,native=True):
                parent=self.execution_deadline()
                with super().phase(seconds,prefix,native=native):
                    phases.append((seconds,prefix,parent,self.execution_deadline()))
                    yield
            @staticmethod
            def reconcile_native(*args):pass
        app.run=Runner()
        @contextlib.contextmanager
        def workspace(parent,**kw):
            copying=Path(parent)/'image-copy';verifying=Path(parent)/'verification-work';copying.mkdir();verifying.mkdir()
            try:yield copying,verifying
            finally:shutil.rmtree(copying);shutil.rmtree(verifying)
        @contextlib.contextmanager
        def verified(source,*,temporary_parent,**kw):
            directory=Path(tempfile.mkdtemp(prefix='dev-pair-fedora-',dir=temporary_parent));plain=directory/'base.oci.tar';plain.write_bytes(b'synthetic archive')
            yield plain,{'fixture':'graph source boundary injected'}
        proof=fedora_input_fixture.synthetic_import(lambda *a,**k:None,Path('/synthetic'))
        def importer(engine,plain,uid=None,seconds=120):return REAL_IMPORT(engine,plain,uid=None,seconds=seconds)
        for boundary in (patch.object(g.fedora_oci,'image_workspaces',side_effect=workspace),patch.object(g.fedora_oci,'verified',side_effect=verified),
            patch.object(g.fedora_oci,'import_image',side_effect=importer),patch.object(g.fedora_oci,'parse_oci',side_effect=lambda *a,**k:proof['saveback'] if k.get('derived') else g.fedora_oci.PROVENANCE),
            patch.object(g.fedora_oci,'imported',return_value={k:proof[k] for k in ('source','imported_config','imported_manifest','conversion')})):
            boundary.start();self.addCleanup(boundary.stop)
        def observe(stage,source,context,image,sealed=None):
            if stage=='prepared-image':self.assertRegex(app.run.native_prefix,r'^dev-pair-initialize-adapter-[0-9a-f]{8}$')
            app.atomic(b.STATE+'/storage-prepared.json',json.dumps({'status':'unavailable','fixture':'not measured','image_id':image})+'\n')
            return {'status':'unavailable'}
        app.observe_storage=observe
        def preparation():
            ready=SimpleNamespace(run=b.Commands())
            ready.run.reconcile_native=lambda *args:None
            def host(*args,source_check=None,**kwargs):
                source_check();b.Bootstrap.mark_prepare_step(ready,'packages')
                desired=json.dumps({'gptbox_context_sha256':fixtures.EXPECTED,'standards_sha':b.STANDARDS,
                    'bootstrap_sha256':g.sha(Path(b.__file__).read_bytes())},sort_keys=True)+'\n'
                app.atomic(b.STATE+'/desired.json',desired);app.atomic(b.STATE+'/packages.txt','podman-fixture\ndistrobox-fixture\ntailscale-fixture\n')
                witness={'schema':1,'kind':'host-prerequisites','source_sha':fixtures.SOURCE,'context_sha256':fixtures.EXPECTED,
                    'standards_sha':b.STANDARDS,'bootstrap_sha256':g.sha(Path(b.__file__).read_bytes()),
                    'desired_sha256':g.sha(desired.encode()),'packages_sha256':g.sha(app.text(b.STATE+'/packages.txt').encode())}
                app.atomic(b.STATE+'/host-ready.json',json.dumps(witness,sort_keys=True)+'\n',expected=app.text(b.STATE+'/host-ready.json') or None)
                return witness
            ready._host_prerequisites=host;return ready
        app.preparation=preparation
        return case,phases,selected
    def run_initialize(self,case,retry=False):
        with patch.object(g,'github_keys',return_value='fixture public key'):
            return case.app.initialize(case.context,fixtures.EXPECTED,'/upstream',fixtures.SOURCE,['192.0.2.9/32'],apply=True,retry=retry)
    def test_fresh_one_build_prepared_then_real_assembly_contract_and_budgets(self):
        case,phases,selected=self.make()
        with patch.object(b.Bootstrap,'build_gptbox',side_effect=AssertionError('minimal constructor used')):
            result=self.run_initialize(case)
        self.assertEqual(result['phase'],'complete');self.assertEqual(result['host_prerequisites'],'complete');self.assertEqual(result['candidate_image'],'complete')
        operations=[args for args,_ in case.engine.calls if args[0]=='/usr/bin/systemd-run']
        for action in ('load','save','build'):self.assertEqual(sum(action in args for args in operations),1)
        self.assertEqual(case.engine.starts,2);self.assertEqual(len(case.app.entry_calls),4)
        full=json.loads(case.app.text(b.STATE+'/gptbox-image.json'));self.assertEqual(full['kind'],'full-adapter-candidate');self.assertEqual(full['image_id'],fixtures.BASE)
        self.assertFalse(full['distrobox_assembled']);self.assertFalse(full['runtime_validated'])
        self.assertTrue(all(item is not None for item in selected));self.assertIn('build',[item['suboperation'] for item in selected])
        self.assertEqual([x[0] for x in phases],[2280,1620,600])
        self.assertTrue(all(parent is None or end<=parent for _,_,parent,end in phases))
        self.assertEqual(result['prepare_budget_scope'],'host-prerequisites');self.assertEqual(result['prepare_cost']['phase'],'host-prerequisites')
        for key in ('recipe_sha256','runtime_sha256','init_sha256','inputs_sha256'):self.assertRegex(full[key],r'^[0-9a-f]{64}$')
    def test_fail_each_boundary_no_premature_prepared_and_cleanup(self):
        for boundary in ('load','save','build','inspect','record','storage','marker','assembly','runtime'):
            with self.subTest(boundary=boundary):
                case,_,_=self.make();app=case.app;engine=case.engine;primary=g.Blocked('PRIMARY_'+boundary)
                original_record=app.record;original_atomic=app.atomic;original_observe=app.observe_storage
                def record(name,data):
                    if boundary=='record' and name=='candidate-image':raise primary
                    return original_record(name,data)
                def atomic(path,data,**kwargs):
                    if boundary=='marker' and path==b.STATE+'/prepared':raise primary
                    return original_atomic(path,data,**kwargs)
                def observe(*args,**kw):
                    if boundary=='storage':raise primary
                    return original_observe(*args,**kw)
                def fail(args):
                    return boundary in ('load','save','build') and boundary in args or boundary=='inspect' and 'image' in args and 'inspect' in args or boundary=='assembly' and '--attach' in args or boundary=='runtime' and 'create' in args and '--read-only' in args
                engine.fail=fail
                with patch.object(app,'record',side_effect=record),patch.object(app,'atomic',side_effect=atomic),patch.object(app,'observe_storage',side_effect=observe):
                    with self.assertRaises(g.Blocked):self.run_initialize(case)
                state=json.loads(app.text(b.STATE+'/initialize.json'));self.assertEqual(state['host_prerequisites'],'complete');self.assertTrue(state['adapter_commenced'])
                if boundary in ('assembly','runtime'):self.assertEqual(state['prepare'],'complete')
                else:self.assertEqual(state['prepare'],'blocked');self.assertFalse(app.path(b.STATE+'/prepared').exists())
                self.assertIn('cleanup',state);self.assertFalse(state['job_admission'])
    def test_crash_record_before_marker_retry_reuses_one_image_and_preserves_attempts(self):
        case,_,_=self.make();app=case.app;original=app.atomic
        def crash(path,data,**kw):
            if path==b.STATE+'/prepared':raise g.Blocked('marker interruption')
            return original(path,data,**kw)
        with patch.object(app,'atomic',side_effect=crash),self.assertRaises(g.Blocked):self.run_initialize(case)
        self.assertTrue(app.path(app.target+'/candidate-image.json').exists());self.assertFalse(app.path(b.STATE+'/prepared').exists())
        with self.assertRaisesRegex(g.Blocked,'explicit exact-target'):self.run_initialize(case)
        self.assertEqual(self.run_initialize(case,retry=True)['phase'],'complete')
        builds=lambda:sum('build' in args for args,_ in case.engine.calls)
        self.assertEqual(builds(),1);self.assertEqual(json.loads(app.text(app.target+'/attempt.json'))['count'],2)
        self.assertEqual(self.run_initialize(case)['phase'],'complete');self.assertEqual(builds(),1)
    def test_closed_completion_and_signed_graph_corruption_block_reuse(self):
        for field,value in (('kind','unknown'),('runtime_sha256','f'*64),('fedora_base',None),('platform',{'os':'linux','architecture':'arm64'})):
            case,_,_=self.make();self.run_initialize(case);app=case.app;path=app.target+'/candidate-image.json';record=json.loads(app.text(path));record[field]=value
            app.atomic(path,json.dumps(record)+'\n',expected=app.text(path))
            before=sum('build' in a for a,_ in case.engine.calls)
            with self.assertRaises(g.Blocked):self.run_initialize(case)
            self.assertEqual(sum('build' in a for a,_ in case.engine.calls),before)
    def test_host_only_projection_is_not_prepared_or_admitted(self):
        state={'schema':2,'target':{'source_sha':fixtures.SOURCE,'context_sha256':fixtures.EXPECTED,'distrobox_sha':g.DBX_SHA,'bootstrap_sources':['192.0.2.9/32']},
            'phase':'maintenance-gptbox','prepare':'pending','maintenance_gptbox':'pending','host_prerequisites':'complete','candidate_image':'pending',
            'prepare_budget_scope':'host-prerequisites','adapter_commenced':True,'job_admission':False}
        expected={'source_sha':fixtures.SOURCE,'context_sha256':fixtures.EXPECTED,'distrobox_sha':g.DBX_SHA}
        result=guest.initialize_projection(state,expected,None);self.assertFalse(result['prepared_image_verified']);self.assertIsNone(result['prepared_image_id'])
        state['prepare']='complete'
        with self.assertRaises(ValueError):guest.initialize_projection(state,expected,None)
        state['schema']=3
        with self.assertRaises(ValueError):guest.initialize_projection(state,expected,None)
    def test_import_proof_closed_graph_and_malformed_inspections_block(self):
        proof=fedora_input_fixture.synthetic_import(lambda *a,**kw:None,Path('/synthetic'))
        self.assertEqual(g.fedora_oci.validate_import_proof(proof),proof)
        for changed in (None,{},dict(proof,PRIVATE=True),dict(proof,imported_config='sha256:'+'f'*64),dict(proof,saveback=None)):
            with self.assertRaises(ValueError):g.fedora_oci.validate_import_proof(changed)
        for field,value in (('config_sha256','f'*64),('diff_id_sha256','f'*64),('unknown',True)):
            changed=copy.deepcopy(proof);changed['saveback'][field]=value
            with self.assertRaises(ValueError):g.fedora_oci.validate_import_proof(changed)
        for row in (None,[],True,{'Id':None},{'Id':fixtures.BASE,'Labels':True}):
            case,_,_=self.make();original=case.engine.__call__
            # Inject only immutable candidate inspection; assembly never starts.
            run=case.app.run;dispatch=run.__call__
            def bad(*args,**kw):
                if args[0].endswith('/bin/podman') and args[1:3]==('image','inspect'):return json.dumps([row])
                return dispatch(*args,**kw)
            with patch.object(case.app,'engine',side_effect=lambda *a,**k:json.dumps([row]) if a[:2]==('image','inspect') else case.app.execute(case.app.wrapper,*a,**k)),self.assertRaises(g.Blocked):self.run_initialize(case)
            self.assertFalse(case.app.path(b.STATE+'/prepared').exists())
    def test_stale_host_ready_never_skips_host_revalidation_or_migrates_legacy(self):
        case,_,_=self.make();app=case.app
        app.atomic(b.STATE+'/host-ready.json',json.dumps({'schema':99,'kind':'foreign'})+'\n')
        original=app.preparation
        def stale():
            value=original()
            def host(*a,**kw):return {'schema':99,'kind':'foreign'}
            value._host_prerequisites=host;return value
        with patch.object(app,'preparation',side_effect=stale),self.assertRaises(g.Blocked):self.run_initialize(case)
        self.assertFalse(app.path(b.STATE+'/prepared').exists())
        case,_,_=self.make();app=case.app
        app.atomic(b.STATE+'/gptbox-image.json',json.dumps({'kind':'host-maintenance-gptbox-oci-candidate','image_id':'f'*64})+'\n')
        with self.assertRaisesRegex(g.Blocked,'no silent'):self.run_initialize(case)
        self.assertEqual(json.loads(app.text(b.STATE+'/gptbox-image.json'))['kind'],'host-maintenance-gptbox-oci-candidate')
        self.assertFalse(app.path(b.STATE+'/prepared').exists())

    def test_late_image_scope_failure_removes_new_marker_and_preserves_primary(self):
        case,_,_=self.make();original=case.app.run.phase;primary=g.Blocked('late image phase')
        @contextlib.contextmanager
        def phase(seconds,prefix,native=True):
            with original(seconds,prefix,native=native):yield
            if prefix=='dev-pair-gptbox-image':raise primary
        with patch.object(case.app.run,'phase',side_effect=phase):
            with self.assertRaises(g.Blocked) as seen:self.run_initialize(case)
        self.assertIs(seen.exception,primary);self.assertFalse(case.app.path(b.STATE+'/prepared').exists())
        self.assertTrue(case.app.path(case.app.target+'/candidate-image.json').exists())
        state=json.loads(case.app.text(b.STATE+'/initialize.json'));self.assertEqual(state['prepare'],'blocked')
    def test_failure_record_cannot_mask_first_image_error(self):
        case,_,_=self.make();app=case.app;original=app.record
        case.engine.fail=lambda args:'load' in args
        def record(name,data):
            if name=='image-failure':raise OSError('secondary diagnostic storage failure')
            return original(name,data)
        with patch.object(app,'record',side_effect=record),self.assertRaisesRegex(g.Blocked,'injected engine boundary failure'):self.run_initialize(case)
        self.assertFalse(app.path(b.STATE+'/prepared').exists())

    def test_real_host_primitive_never_calls_minimal_constructor_or_marks_prepared(self):
        case=host_fixture.BootstrapTests();case.setUp();self.addCleanup(case.doCleanups);context,digest=case.context()
        with case.app.lock(),patch.object(case.app,'build_gptbox',side_effect=AssertionError('minimal image invoked')):
            ready=case.app._host_prerequisites('core',host_fixture.KEY,['192.0.2.9/32'],context,digest,password='fixture-password',source_check=lambda:None)
        self.assertEqual(ready['kind'],'host-prerequisites');self.assertFalse(case.app.path(b.STATE+'/prepared').exists())
        self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in case.fake.calls))

if __name__=='__main__':unittest.main()
