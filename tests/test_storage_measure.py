"""Real allocated-block GNUdu differential; descriptor and caller failures closed."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import storage_measure as worker
import fedora_ci as ci
from test_fedora_ci import worker_result

class MeasurementTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def expected(self):return worker.identity(self.root.stat())
    def oracle(self):
        p=subprocess.run(['/usr/bin/du','--summarize','--block-size=1','--one-file-system','--exclude=guest.qcow2',str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
        self.assertEqual(p.returncode,0,p.stderr.decode());return int(p.stdout.split()[0])
    def test_actual_sparse_allocated_hardlink_symlink_directories_and_exact_exclusion(self):
        (self.root/'empty').touch();(self.root/'sparse').touch()
        with open(self.root/'sparse','r+b') as f:f.truncate(8*1024**2)
        (self.root/'allocated').write_bytes(b'x'*131072);os.link(self.root/'allocated',self.root/'hardlink')
        (self.root/'link').symlink_to('/dev/shm');(self.root/'dangling').symlink_to('/not-followed-synthetic')
        deep=self.root
        for i in range(8):deep=deep/('deep-'+str(i));deep.mkdir()
        (deep/'data').write_bytes(b'x'*123);(deep/'guest.qcow2').write_bytes(b'x'*65536);(self.root/'guest.qcow2').write_bytes(b'x'*65536)
        result=worker.scan(self.root,self.expected());self.assertEqual(result['status'],'complete');self.assertEqual(result['allocated_bytes'],self.oracle())
        actual=ci.measure_storage(self.root,sudo=False);self.assertFalse(actual['provisional']);self.assertEqual(actual['bytes'],self.oracle())
    def test_controlled_file_churn_never_becomes_a_stable_final_claim(self):
        tree=self.root/'files';tree.mkdir()
        for i in range(1000):(tree/str(i)).touch()
        stop=threading.Event()
        def churn():
            while not stop.is_set():
                for p in tree.iterdir():
                    if stop.is_set():break
                    try:p.unlink();p.touch()
                    except FileNotFoundError:pass
        thread=threading.Thread(target=churn);thread.start()
        try:
            try:
                observed=ci.measure_storage(self.root,live=True,sudo=False);self.assertGreater(observed['bytes'],0)
            except ci.StorageMeasurementBlocked as error:self.assertIn(error.diagnostics.get('worker',{}).get('reason'),('identity-changed','enumeration-disappeared'))
        finally:stop.set();thread.join(timeout=3);self.assertFalse(thread.is_alive())
        self.assertEqual(ci.measure_storage(self.root,sudo=False)['bytes'],self.oracle())
    def test_root_replacement_and_every_guard_produce_no_accepted_total(self):
        expected=self.expected();(self.root/'file').write_bytes(b'x')
        for kwargs,reason in (({'entry_limit':0},'entry-limit'),({'inode_limit':0},'inode-limit'),({'end':time.monotonic()-1},'deadline')):
            with self.subTest(reason=reason),self.assertRaisesRegex(worker.ScanError,reason):worker.scan(self.root,expected,**kwargs)
        child=self.root/'directory';child.mkdir()
        with self.assertRaisesRegex(worker.ScanError,'depth-limit'):worker.scan(self.root,expected,depth_limit=0)
        with self.assertRaisesRegex(worker.ScanError,'root-identity'):worker.scan(self.root,{**expected,'inode':expected['inode']+1})
        original=worker.os.stat;changed=False
        def replaced(name,*args,**kwargs):
            nonlocal changed
            if name=='directory' and kwargs.get('dir_fd') is not None and not changed:changed=True;child.rename(self.root/'moved');child.mkdir()
            return original(name,*args,**kwargs)
        with patch.object(worker.os,'stat',side_effect=replaced),self.assertRaisesRegex(worker.ScanError,'identity-changed'):worker.scan(self.root,expected)
    def test_descendant_enoent_only_and_supported_mount_refusal(self):
        (self.root/'file').touch()
        for number in (errno.EACCES,errno.EPERM,errno.EIO,errno.ELOOP,errno.EXDEV):
            with patch.object(worker,'_node',side_effect=OSError(number,'synthetic')),self.assertRaises(OSError):worker.scan(self.root,self.expected())
        with patch.object(worker,'_node',side_effect=FileNotFoundError(errno.ENOENT,'synthetic')):
            result=worker.scan(self.root,self.expected());self.assertEqual(result['status'],'provisional');self.assertGreater(result['allocated_bytes'],0)
    def test_parser_no_total_is_never_a_usable_integer_and_typed_failure_survives(self):
        expected=self.expected();sha=ci.file_hash(Path(worker.__file__))
        for kind in ('integer-no-total','wrong-root','wrong-source','extra','bool-size','signal','partial','unknown-failure'):
            value=json.loads(worker_result(self.root).stdout);code=0
            if kind=='integer-no-total':value.update(status='no-total',reason='none');code=1
            if kind=='wrong-root':value['root']['inode']+=1
            if kind=='wrong-source':value['worker_sha256']='0'*64
            if kind=='extra':value['PRIVATE']='sensitive'
            if kind=='bool-size':value['allocated_bytes']=False
            if kind=='signal':code=-6
            if kind=='partial':value={'schema':1}
            if kind=='unknown-failure':value.update(status='failed',reason='PRIVATE',allocated_bytes=None);code=2
            with self.subTest(kind=kind),self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.parse_storage(self.root,subprocess.CompletedProcess([],code,json.dumps(value).encode(),b''),expected,sha)
            self.assertNotIn('PRIVATE',json.dumps(seen.exception.diagnostics));self.assertNotIn('worker',seen.exception.diagnostics)
        value=json.loads(worker_result(self.root).stdout);value.update(status='failed',allocated_bytes=None,reason='mount-boundary')
        with self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.parse_storage(self.root,subprocess.CompletedProcess([],2,json.dumps(value).encode(),b''),expected,sha)
        self.assertEqual(seen.exception.diagnostics['worker']['reason'],'mount-boundary')
    def test_enumeration_disappearance_has_no_total_not_zero(self):
        class Missing:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __next__(self):raise FileNotFoundError(errno.ENOENT,'synthetic')
        with patch.object(worker.os,'scandir',return_value=Missing()):value=worker.scan(self.root,self.expected())
        self.assertIsNone(value['allocated_bytes']);self.assertEqual(value['status'],'no-total')
    def test_fixed_source_limits_and_measurement_cannot_clear_image_copy_latch(self):
        probe=ci.Probe('a'*40,self.root);probe.image_copy_active=True
        value=worker_result(self.root,ci.OVERHEAD_LIMIT-ci.fedora_oci.UNLINKED_RESERVE)
        with patch.object(ci,'capture_du',return_value=value):self.assertEqual(probe.storage_measurement()['unlinked_spool_reserve_bytes'],ci.fedora_oci.UNLINKED_RESERVE)
        self.assertTrue(probe.image_copy_active)
        with patch.object(ci,'capture_du',return_value=worker_result(self.root,ci.OVERHEAD_LIMIT-ci.fedora_oci.UNLINKED_RESERVE+512)),self.assertRaises(ci.Blocked):probe.storage_measurement()
        self.assertTrue(probe.image_copy_active)
        with patch.object(ci,'capture_du',return_value=subprocess.CompletedProcess([],-6,b'',b'PRIVATE')),self.assertRaises(ci.StorageMeasurementBlocked):probe.storage_measurement()
        self.assertTrue(probe.image_copy_active);self.assertNotIn('PRIVATE',json.dumps(probe.report))

    def test_root_disappearance_replacement_and_small_protocol_limit(self):
        expected=self.expected();(self.root/'entry').touch();original=worker._node;moved=self.root.with_name(self.root.name+'-held')
        def replace(fd,name):
            if self.root.exists():self.root.rename(moved);self.root.mkdir()
            return original(fd,name)
        try:
            with patch.object(worker,'_node',side_effect=replace),self.assertRaisesRegex(worker.ScanError,'root-identity'):worker.scan(self.root,expected)
        finally:self.root.rmdir();moved.rename(self.root)
        value=worker_result(self.root);value.stdout=b' '*2049+value.stdout
        with self.assertRaises(ci.StorageMeasurementBlocked):ci.parse_storage(self.root,value,expected,ci.file_hash(Path(worker.__file__)))
        absent=self.root/'absent'
        with self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.measure_storage(absent,sudo=False)
        self.assertEqual(seen.exception.diagnostics['availability'],'not-launched')
    def test_real_sigabrt_and_short_test_timeout_never_supply_a_total_or_core_file(self):
        for code,timeout in (('import os;os.abort()',None),('import time;time.sleep(3)',.1)):
            argv=['/usr/bin/prlimit','--core=0:0','--',sys.executable,'-I','-c',code]
            if timeout is not None:argv=['/usr/bin/timeout','--signal=TERM','--kill-after=1s',str(timeout)+'s',*argv]
            result=ci.capture_du(self.root,argv)
            self.assertNotEqual(result.returncode,0)
            with self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.parse_storage(self.root,result,self.expected(),ci.file_hash(Path(worker.__file__)))
            self.assertNotIn('worker',seen.exception.diagnostics)
        self.assertEqual(list(self.root.iterdir()),[])
    def test_no_read_of_fifo_and_file_symlink_swap_never_follows_target(self):
        os.mkfifo(self.root/'fifo');self.assertEqual(worker.scan(self.root,self.expected())['allocated_bytes'],self.oracle())
        file=self.root/'regular';file.write_bytes(b'x'*4096);original=worker.os.stat;changed=False
        def swapped(name,*args,**kwargs):
            nonlocal changed
            if name=='regular' and kwargs.get('dir_fd') is not None and not changed:changed=True;file.unlink();file.symlink_to('/dev/shm')
            return original(name,*args,**kwargs)
        with patch.object(worker.os,'stat',side_effect=swapped),self.assertRaisesRegex(worker.ScanError,'identity-changed'):worker.scan(self.root,self.expected())
