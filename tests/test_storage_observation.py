"""Actual local collectors/children; no Fedora engine, capacity enforcement or admission proof."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap as b
import storage
import storage_observation as o
import fedora_ci_guest as guest

SOURCE='1'*40;CONTEXT='a'*64;PREPARED='b'*64;SEALED='c'*64


class StorageObservation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.run=b.Commands();self.app=b.Bootstrap(self.root,self.run)
        self.maintenance=self.app.path(o.ROOT);self.maintenance.mkdir(parents=True)
        self.state=self.app.path(b.STATE)

    def sample(self):return storage.inventory(self.maintenance,storage.Bounds(seconds=1))

    def collect(self):return self.app.observe_storage('prepared-image',SOURCE,CONTEXT,PREPARED)

    def test_real_cli_private_hardlinks_sparse_and_aggregate_only(self):
        secret=self.maintenance/'SECRET_NAME';secret.write_text('SECRET_CONTENT');os.link(secret,self.maintenance/'alias')
        with (self.maintenance/'sparse').open('wb') as f:f.truncate(8*1024**2)
        (self.maintenance/'images').mkdir();(self.maintenance/'link').symlink_to('/SECRET_TARGET')
        self.run.deadline=time.monotonic()+5
        value=self.collect();self.assertEqual(value['status'],'observed');sample=value['inventory']
        self.assertEqual(sample['hardlink_references'],1);self.assertEqual(sample['inode_types']['symlinks'],1)
        self.assertGreater(sample['regular_apparent_bytes'],sample['allocated_bytes'])
        self.assertEqual(value['graphroot'],'included-overlapping-subset-not-added')
        self.assertEqual(value['outside_sample'],o.OUTSIDE)
        self.assertFalse(value['quiescence_proven']);self.assertFalse(value['enforces_capacity']);self.assertFalse(value['runtime_admitted'])
        self.assertNotIn('SECRET',json.dumps(value));self.assertNotIn(str(self.root),json.dumps(value))
        self.assertEqual(o.validate(value,'prepared-image',SOURCE,CONTEXT,PREPARED),value)
        # Reconciliation/observation does not create another image or exporter.
        self.assertFalse((self.root/'var/lib/dev-pair/artifacts').exists())

    def test_unknown_capacity_keeps_real_counts_and_null_inodes(self):
        sample=self.sample();sample['filesystem']['total_inodes']=None;sample['filesystem']['available_inodes']=None
        sample.update(capacity_known=False,blockers=['filesystem-inode-capacity-unknown'])
        self.assertEqual(o.sample(sample)['entries'],sample['entries'])
        self.assertIsNone(o.sample(sample)['filesystem']['available_inodes'])
        class Fixed(b.Commands):
            def _call(inner,*args,**kwargs):return json.dumps(sample)
        self.app.run=Fixed();value=self.collect();self.assertEqual(value['status'],'observed')
        self.assertFalse(value['inventory']['capacity_known']);self.assertFalse(value['runtime_admitted'])

    def test_no_launch_without_original_budget_or_bounded_runner(self):
        with patch.object(self.run,'_call',side_effect=AssertionError('launched')):
            self.run.deadline=time.monotonic()-.01;self.assertEqual(self.collect()['reason'],'no-budget')
        self.app.run=lambda *args: (_ for _ in ()).throw(AssertionError('unbounded runner'))
        self.assertEqual(self.collect()['reason'],'bounded-runner-unavailable')

    def test_real_children_deadline_capture_and_lifecycle_evidence(self):
        original=subprocess.Popen
        for code in ('import time;time.sleep(20)', 'print("SECRET"*50000)'):
            children=[];calls=[]
            def launch(argv,**kwargs):
                calls.append(argv);child=original([sys.executable,'-c',code],**kwargs);children.append(child);return child
            metadata=[];self.run.metadata_diagnostic=metadata.append;self.run.deadline=time.monotonic()+2.1
            with patch.object(b.subprocess,'Popen',side_effect=launch):
                with self.assertRaises(b.Blocked):self.collect()
            self.assertTrue(children);self.assertIsNotNone(children[0].poll())
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
            self.assertEqual(calls[0][:2],('/usr/bin/python3','-I'))
            self.assertEqual(calls[0][3],str(self.maintenance))
            stored=json.loads((self.state/'storage-prepared.json').read_text())
            self.assertEqual(stored['reason'],'collector-lifecycle-failure')
            self.assertNotIn('SECRET',json.dumps(metadata));self.assertNotIn('stdout_tail',json.dumps(metadata))

    def test_complete_malformed_partial_duplicate_or_blocked_output_unavailable(self):
        for text,reason in [('SECRET','invalid-collector-output'),('{','invalid-collector-output'), (' '*16385,'invalid-collector-output'),
                            ('{"sample":1,"sample":2}','invalid-collector-output'),
                            (json.dumps({'sample':'blocked','reason':'inventory-deadline','enforces_capacity':False}),'collector-unavailable')]:
            class Fixed(b.Commands):
                def _call(inner,*args,**kwargs):
                    self.assertLessEqual(kwargs['timeout'],10);self.assertEqual(kwargs['maximum'],262144)
                    self.assertEqual(kwargs['ok'],(0,2));return text
            self.app.run=Fixed();result=self.collect();self.assertEqual(result['reason'],reason)
            self.assertIsNone(result['inventory']);self.assertNotIn('SECRET',json.dumps(result))

    def test_closed_sample_rejects_bad_numbers_unknown_and_contradictions(self):
        original=self.sample();cases=[]
        for key in ('allocated_bytes','entries','root_inode','mount_id','regular_apparent_bytes'):
            for value in (-1,True,2**63,float('nan')):
                sample=copy.deepcopy(original);sample[key]=value;cases.append(sample)
        for key,value in [('capacity_known',not original['capacity_known']),('quiescence_proven',True),('enforces_capacity',True),
                          ('SECRET_KEY','SECRET_VALUE'),('unique_inodes',0),('filesystem_type','remote')]:
            sample=copy.deepcopy(original);sample[key]=value;cases.append(sample)
        sample=copy.deepcopy(original);sample['filesystem']['available_bytes']=None;cases.append(sample)
        sample=copy.deepcopy(original);sample['bounds']['seconds']=float('inf');cases.append(sample)
        sample=copy.deepcopy(original);sample['bounds']['entries']=True;cases.append(sample)
        for sample in cases:
            with self.assertRaises(ValueError):o.sample(sample)

    def test_stage_schema_and_candidate_images_are_exactly_bound(self):
        value=o.record('assembled-postcleanup',SOURCE,CONTEXT,PREPARED,SEALED,True)
        value.update(status='observed',reason='none',inventory=self.sample())
        self.assertEqual(o.validate(value,'assembled-postcleanup',SOURCE,CONTEXT,PREPARED,SEALED),value)
        for key,item in [('source_sha','f'*40),('context_sha256','e'*64),('prepared_image_id','f'*64),
                         ('assembled_image_id','f'*64),('cleanup_verified',False),('stage','prepared-image'),
                         ('schema',True),('SECRET','PRIVATE'),('runtime_admitted',True)]:
            bad=copy.deepcopy(value);bad[key]=item
            with self.assertRaises(ValueError):o.validate(bad,'assembled-postcleanup',SOURCE,CONTEXT,PREPARED,SEALED)
        for stage,cleanup,sealed in [('unknown',False,None),('prepared-image',True,None),('assembled-postcleanup',False,SEALED)]:
            with self.assertRaises(ValueError):o.record(stage,SOURCE,CONTEXT,PREPARED,sealed,cleanup)

    def test_guest_public_slots_require_protected_completion_and_bound_ids(self):
        observed=self.collect();self.app.atomic(b.STATE+'/gptbox-image.json',json.dumps({'source_sha':SOURCE,'context_sha256':CONTEXT,'image_id':PREPARED})+'\n')
        expected={'source_sha':SOURCE,'context_sha256':CONTEXT};source=Path(__file__).resolve().parents[1]
        public=guest.storage_public_projection(self.state,expected,source)
        self.assertEqual(public['prepared-image'],observed)
        target=b.STATE+'/gptbox-adapter/'+CONTEXT;self.app.atomic(target+'/result.json',json.dumps({'source_sha':SOURCE,'context_sha256':CONTEXT,
            'assembled_image_id':SEALED,'runtime_container_removed':False,'job_admission':False})+'\n')
        value=o.record('assembled-postcleanup',SOURCE,CONTEXT,PREPARED,SEALED,True)
        self.app.atomic(target+'/storage-assembled-postcleanup.json',json.dumps(value)+'\n')
        self.assertEqual(guest.storage_public_projection(self.state,expected,source)['assembled-postcleanup']['reason'],'not-recorded')
        result=json.loads(self.app.text(target+'/result.json'));result['runtime_container_removed']=True
        self.app.atomic(target+'/result.json',json.dumps(result)+'\n',expected=self.app.text(target+'/result.json'))
        self.assertEqual(guest.storage_public_projection(self.state,expected,source)['assembled-postcleanup'],value)
        saved=self.state/'storage-prepared.json';raw=saved.read_text()
        saved.write_text(raw.rstrip()[:-1]+',"stage":"SECRET_DUPLICATE"}')
        projected=guest.storage_public_projection(self.state,expected,source)
        self.assertEqual(projected['prepared-image']['reason'],'not-recorded')
        self.assertNotIn('SECRET',json.dumps(projected));saved.write_text(raw)
        expected['source_sha']='f'*40
        self.assertEqual(guest.storage_public_projection(self.state,expected,source)['prepared-image']['reason'],'not-recorded')

    def test_native_prefix_uses_actual_decoder_and_cli_supported_cap(self):
        import test_native_relay as local_relay
        from unittest.mock import MagicMock
        class StopAtDecoder(BaseException):pass
        self.run.native_prefix='dev-pair-initialize-prepare-12345678'
        self.run.deadline=time.monotonic()+9
        original=b.Commands._call;constructor=b.relay.Decoder;seen=[]
        def dispatch(run,*args,**kwargs):
            if run is self.run:return original(run,*args,**kwargs)
            return 'LoadState=not-found\nActiveState=inactive\n'
        def decode(maximum):
            decoder=constructor(maximum);seen.append(maximum)
            # Actual relay argparse/pump/framing in a real local child. UID,
            # labels/profile are explicit fixtures; no native service is started.
            process=local_relay.launch('print("local-cap-contract")',maximum=maximum)
            try:stdout,wire=process.communicate(timeout=4)
            finally:
                if process.poll() is None:os.killpg(process.pid,9);process.wait(timeout=2)
            self.assertEqual(process.returncode,0);self.assertEqual(stdout,b'local-cap-contract\n')
            self.assertEqual(b''.join(decoder.feed(wire)),b'')
            decoder.finish(process.returncode,os.getuid(),local_relay.SHA)
            raise StopAtDecoder()
        transport=MagicMock();transport.created_intent=False
        with patch.object(b.Commands,'_call',new=dispatch),patch.object(b,'NativeTransport',return_value=transport), \
                patch.object(b,'lookup_paths',return_value=()),patch.object(b,'configuration_snapshot',return_value=()), \
                patch.object(b,'stage_relay',return_value=(Path(local_relay.r.__file__),local_relay.SHA)), \
                patch.object(b,'expected_uid',return_value=os.getuid()),patch.object(b.relay,'Decoder',side_effect=decode):
            with self.assertRaises(StopAtDecoder):self.collect()
        self.assertEqual(seen,[262144]);transport.setup.assert_called_once()
        self.assertEqual(json.loads((self.state/'storage-prepared.json').read_text())['reason'],'collector-lifecycle-failure')
        with self.assertRaises(ValueError):constructor(16384)  # Old candidate reproducibly failed this contract.

    def test_malformed_prepared_image_identity_preserves_public_report(self):
        expected={'source_sha':SOURCE,'context_sha256':CONTEXT}
        source=Path(__file__).resolve().parents[1]
        self.state.mkdir(parents=True,exist_ok=True)
        for value in (None,True,7,[],{'SECRET_KEY':'SECRET_VALUE'}):
            record={'source_sha':SOURCE,'context_sha256':CONTEXT,'image_id':value}
            (self.state/'gptbox-image.json').write_text(json.dumps(record))
            direct=guest.storage_public_projection(self.state,expected,source)
            public=guest.public_diagnostics(self.state,expected,source)
            self.assertEqual(public['storage_observations'],direct)
            self.assertTrue(all(v=={'status':'unavailable','reason':'not-recorded'} for v in direct.values()))
            report={'source_sha':SOURCE,'initialization':{'primary_failure':'preserved'},'diagnostics':public}
            frame=guest.encode_report(report)
            self.assertIn(b'preserved',frame);self.assertNotIn(b'SECRET',frame)
            self.assertEqual(report['source_sha'],SOURCE)
        for value in (None,True,7,[]):
            (self.state/'gptbox-image.json').write_text(json.dumps(value))
            self.assertEqual(guest.storage_public_projection(self.state,expected,source),direct)

    def test_logical_descriptors_are_optional_bounded_and_not_physical(self):
        for row in ({},{'Size':None},{'Size':True},{'Size':-1},{'Size':2**63},{'Size':float('nan')}):
            self.assertIsNone(o.logical(row)['logical_size_bytes'])
        row={'Size':0,'RootFS':{'Layers':['sha256:'+'a'*64]}}
        value=o.logical(row);self.assertEqual(value['logical_size_bytes'],0);self.assertEqual(value['layer_count'],1)
        self.assertIn('not-unique-physical',value['semantics'])
        for layers in (None,['SECRET'],['sha256:'+'a'*64]*129):
            self.assertIsNone(o.logical({'RootFS':{'Layers':layers}})['layer_count'])


if __name__=='__main__':unittest.main()
