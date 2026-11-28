"""Run20 source/local regressions; no engine, network, auth or VPS execution."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fedora_ci as ci


class ToolingRepair(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.probe=ci.Probe('a'*40,self.root)
        self.root=self.probe.root;self.root.mkdir()

    @contextlib.contextmanager
    def fixture(self,bounded,import_calls=False):
        plain=self.root/'authenticated-fixture.oci';plain.write_bytes(b'parser boundary mocked, no native claim')
        @contextlib.contextmanager
        def verified(*args,**kwargs):yield plain,{}
        def imported(engine,*args,**kwargs):
            if import_calls:
                engine('load','--input',str(plain))
                engine('image','inspect','sha256:'+'a'*64)
                engine('save','--format=oci-archive','--output',str(self.root/'saved'),'sha256:'+'a'*64)
            return {'fixture_only':True}
        def small(argv,**kwargs):
            if argv[:5]==['sudo','-n','/bin/rm','-rf','--']:
                target=Path(argv[-1]);self.assertIn(target,(self.root/'image-copy',self.root/'verification-work'));shutil.rmtree(target);return b''
            if argv[:3]==['sudo','-n','/usr/bin/cat']:return ('sha256:'+'b'*64).encode()
            self.fail('unexpected fixture command: '+repr(argv))
        with patch.object(ci,'download'),patch.object(ci.fedora_oci,'verified',side_effect=verified), \
             patch.object(ci.fedora_oci,'import_image',side_effect=imported),patch.object(ci,'run_small',side_effect=small), \
             patch.object(self.probe,'storage_measurement',return_value={'bytes':0,'provisional':False}), \
             patch.object(self.probe,'bounded',side_effect=bounded):
            yield

    def test_explicit_build_network_and_engine_activity_before_each_launch(self):
        observed=[];self.probe.phase_end=time.monotonic()+10
        def bounded(argv,seconds,name,**kwargs):
            operation=next(v for v in argv if v in ('load','image','save','build','run','info'))
            self.assertTrue(self.probe.engine_activity)
            if operation!='run':
                self.assertTrue(self.probe.image_copy_active)
                self.assertLessEqual(seconds,10)
            self.assertGreater(seconds,0)
            observed.append((operation,argv,name));return b'fixture-rpm-manifest'
        with self.fixture(bounded,import_calls=True),contextlib.redirect_stdout(io.StringIO()):self.probe.tooling()
        baseline_sequence=['load','image','save','info','build','run']
        self.assertEqual([row[0] for row in observed],[value for value in baseline_sequence if value!='info'])
        self.assertFalse(any('info' in argv for _,argv,_ in observed))
        self.assertEqual(self.probe.report['oci_runtime'],{'status':'unavailable','reason':'not-collected'})
        build=observed[3][1]
        self.assertEqual([a for a in build if a.startswith('--network=')],['--network=slirp4netns:allow_host_loopback=false'])
        for arg in ('--pull=never','--http-proxy=false','--memory=2g','--cpu-quota=200000','--force-rm','--ulimit=fsize=2147483648:2147483648'):
            self.assertIn(arg,build)
        for operation,argv,_ in observed[:3]:self.assertFalse(any(a.startswith('--network=') for a in argv))
        self.assertIn('--fsize='+str(ci.fedora_oci.SAVE_FILE_LIMIT)+':'+str(ci.fedora_oci.SAVE_FILE_LIMIT),observed[2][1])
        self.assertIn('--network=none',self.probe.run_args('/usr/bin/true'))
        self.assertIn('--network=slirp4netns:allow_host_loopback=false',self.probe.run_args('/usr/bin/true',vm=True))
        self.assertTrue(self.probe.engine_activity);self.assertFalse(self.probe.image_copy_active)
        self.assertIsNone(self.probe.primary_image_failure)
        with patch.object(ci.subprocess,'run',side_effect=[subprocess.CompletedProcess([],0,b'',b''),subprocess.CompletedProcess([],0,b'',b'')]) as run, \
             patch.object(self.probe.storage,'verify_engine_mount'), \
             patch.object(self.probe.storage,'release',side_effect=lambda:shutil.rmtree(self.root)),contextlib.redirect_stdout(io.StringIO()):
            self.probe.cleanup()
        self.assertEqual(run.call_count,2)
        self.assertEqual(run.call_args_list[0].args[0][-3:],['rm','--force','--all'])
        self.assertEqual(run.call_args_list[1].args[0][-4:],['ps','--all','--external','--format={{.ID}}'])
        self.assertFalse(self.root.exists())

    def test_real_nonzero_primary_survives_context_unwind_and_cleanup_remains_failed(self):
        marker=self.root/'preserved';marker.write_text('retain')
        def actual_child(argv,seconds,name,**kwargs):
            self.assertTrue(self.probe.engine_activity);self.assertTrue(self.probe.image_copy_active)
            # Real bounded nonzero process; this is not an engine/helper lifetime proof.
            code='import os,json,sys;print(json.dumps({"keys":sorted(os.environ)}));sys.exit(125)'
            return ci.Probe.bounded(self.probe,[sys.executable,'-c',code],seconds,name,disk_check=False)
        capture=io.StringIO()
        with self.fixture(actual_child),contextlib.redirect_stdout(capture), \
             patch.object(self.probe,'preflight'),patch.object(self.probe,'inputs'), \
             patch.dict(os.environ,{'GITHUB_STEP_SUMMARY':'','PRIVATE_PARENT_CANARY':'must-not-reach-child'}):
            self.assertEqual(self.probe.execute(),2)
        self.assertEqual(self.probe.primary_image_failure,('build','owned image copy failed with exit 125'))
        self.assertEqual(self.probe.report['blocker'],'local image build: owned image copy failed with exit 125')
        self.assertEqual(self.probe.report['phases']['tooling']['detail'],self.probe.report['blocker'])
        self.assertEqual(self.probe.report['phases']['cleanup']['status'],'fail')
        self.assertIn('unresolved',self.probe.report['phases']['cleanup']['detail'])
        self.assertTrue(self.probe.engine_activity);self.assertTrue(self.probe.image_copy_active)
        self.assertTrue((self.root/'image-copy').exists());self.assertTrue((self.root/'verification-work').exists())
        self.assertEqual(marker.read_text(),'retain');self.assertNotIn('must-not-reach-child',capture.getvalue())
        self.assertNotIn('PRIVATE_PARENT_CANARY',capture.getvalue())
        decoded=[json.loads(line.split(' ',1)[1]) for line in capture.getvalue().splitlines() if line.startswith('DP_REPORT ')]
        self.assertEqual(decoded[-1]['blocker'],self.probe.report['blocker'])

    def test_first_primary_is_capped_no_exception_chain_and_original_is_reraised(self):
        original=ci.Blocked('x'*10000+'terminal-public');original.__cause__=RuntimeError('PRIVATE_CAUSE_NOT_FOR_EXPORT')
        later=ci.Blocked('later failure must not replace first');seen=[]
        def fail(argv,*args,**kwargs):raise original if not seen else later
        def imported(engine,*args,**kwargs):
            for wanted in (original,later):
                try:engine('load','--input','fixed-public-fixture')
                except ci.Blocked as actual:self.assertIs(actual,wanted);seen.append(actual)
            raise original
        with self.fixture(fail),patch.object(ci.fedora_oci,'import_image',side_effect=imported), \
             patch.object(self.probe,'preflight'),patch.object(self.probe,'inputs'), \
             patch.dict(os.environ,{'GITHUB_STEP_SUMMARY':''}),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.probe.execute(),2)
        self.assertEqual(self.probe.primary_image_failure[0],'load')
        self.assertTrue(self.probe.report['blocker'].endswith('terminal-public'))
        self.assertLessEqual(len(self.probe.report['blocker']),4000)
        self.assertNotIn('PRIVATE_CAUSE',json.dumps(self.probe.report))
        self.assertNotIn('later failure',self.probe.report['blocker'])
        self.assertTrue(self.probe.image_copy_active)

    def test_prelaunch_storage_failure_never_marks_engine_launched_or_resets_live_failure(self):
        with self.fixture(lambda *args,**kwargs:self.fail('engine launch reached')), \
             patch.object(self.probe,'storage_measurement',side_effect=ci.Blocked('capacity blocked fixture')):
            with self.assertRaisesRegex(ci.Blocked,'capacity blocked fixture'):self.probe.tooling()
        self.assertFalse(self.probe.engine_activity);self.assertFalse(self.probe.image_copy_active)
        self.assertEqual(self.probe.primary_image_failure,('build','capacity blocked fixture'))
        self.assertFalse((self.root/'image-copy').exists());self.assertFalse((self.root/'verification-work').exists())

    @contextlib.contextmanager
    def preflight_fixture(self,help_output):
        real_read=Path.read_text;calls=[]
        def read(path,*args,**kwargs):
            if str(path)=='/etc/os-release':return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            if str(path)=='/proc/meminfo':return 'MemTotal: 16777216 kB\n'
            return real_read(path,*args,**kwargs)
        def small(argv,**kwargs):
            calls.append((argv,kwargs))
            if argv==['/usr/bin/slirp4netns','--version']:return b'slirp4netns version 1.2.1\n'
            if argv==['/usr/bin/slirp4netns','--help']:return help_output
            if argv[-2:]==['rev-parse','HEAD']:return b'a'*40+b'\n'
            if argv[-2:]==['status','--porcelain']:return b''
            if argv[-2:]==['version','--format=json']:return b'{"Client":{"Version":"4.9.3"}}'
            self.fail('unexpected preflight command')
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'oso-gato/dev-pair'}), \
             patch.object(Path,'read_text',read),patch.object(Path,'is_file',return_value=True), \
             patch.object(ci.os,'cpu_count',return_value=4),patch.object(self.probe.storage,'configure',return_value={}), \
             patch.object(self.probe,'initialize_directories',side_effect=self.probe.initialize_directories), \
             patch.object(ci,'run_small',side_effect=small),contextlib.redirect_stdout(io.StringIO()):
            yield calls

    def test_preflight_requires_actual_help_feature_names_without_network_fallback(self):
        good=b'  --disable-host-loopback deny loopback\n  --netns-type=TYPE namespace kind\n'
        with self.preflight_fixture(good) as calls:self.probe.preflight()
        self.assertEqual(self.probe.report['runner']['slirp_required_features'],['--disable-host-loopback','--netns-type'])
        self.assertEqual(self.probe.report['runner']['slirp_help_sha256'],ci.sha256(good))
        self.assertFalse(self.probe.engine_activity)
        help_calls=[row for row in calls if row[0]==['/usr/bin/slirp4netns','--help']]
        self.assertEqual(help_calls[0][1]['timeout'],5)
        for missing in (b'',b'--disable-host-loopback',b'--netns-type=path',b'--disable-host-loopback-extra --netns-type=path'):
            with self.preflight_fixture(missing),self.assertRaisesRegex(ci.Blocked,'lacks required'):self.probe.preflight()
            self.assertFalse(self.probe.engine_activity)

    def test_feature_preflight_still_obeys_existing_outer_wall_deadline(self):
        with self.preflight_fixture(b'--disable-host-loopback --netns-type=path'):
            fake=ci.run_small
            def slow(argv,**kwargs):
                if argv==['/usr/bin/slirp4netns','--help']:time.sleep(.3)
                return fake(argv,**kwargs)
            start=time.monotonic()
            with patch.object(ci,'run_small',side_effect=slow),self.assertRaisesRegex(ci.Blocked,'wall-time'),ci.deadline(.05):
                self.probe.preflight()
            self.assertLess(time.monotonic()-start,.2)
