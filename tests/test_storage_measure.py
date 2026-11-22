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
import textwrap
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

    def isolated_mount_scan(self, fixture, mounts, check):
        sandbox=shutil.which('bwrap')
        if sandbox is None:self.skipTest('bubblewrap is unavailable')
        base=[sandbox,'--unshare-user','--uid','0','--gid','0','--unshare-pid','--unshare-net','--ro-bind','/','/']
        probe=subprocess.run([*base,'--','/usr/bin/true'],capture_output=True,text=True,timeout=5)
        if probe.returncode and ('namespace' in probe.stderr or 'Operation not permitted' in probe.stderr):
            self.skipTest('private mount namespace is unavailable')
        self.assertEqual(probe.returncode,0,probe.stderr)
        source=textwrap.dedent('''
            import os
            from pathlib import Path
            import subprocess
            import sys
            from unittest.mock import patch

            sys.path.insert(0,sys.argv[1])
            import storage_measure as worker

            root=Path(sys.argv[2])
            expected=worker.identity(root.stat())
            scandir=os.scandir
        ''')+textwrap.dedent(check)
        argv=[*base,'--bind',str(fixture),str(fixture),*map(str,mounts),'--proc','/proc','--dev','/dev','--',
              sys.executable,'-I','-c',source,str(Path(worker.__file__).resolve().parent),str(self.root)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_actual_mount_namespace_matches_gnu_du_for_owned_alias_cycle_and_foreign_mounts(self):
        # The space, backslash and newline exercise the mountinfo path quoting.
        source=self.root/'source space\\name\n'
        source.mkdir()
        (source/'single').write_bytes(b'x'*8192)
        hard=source/'hard';hard.write_bytes(b'x'*16384);os.link(hard,source/'hard-alias')
        (source/'payload-link').symlink_to('/dev/shm')
        alias=self.root/'sibling alias';alias.mkdir()
        single_alias=self.root/'single alias';single_alias.touch()
        cycle=self.root/'ancestor-cycle';cycle.mkdir()
        foreign=self.root/'foreign-dir';foreign.mkdir()
        foreign_file=self.root/'foreign-file';foreign_file.touch()
        if not Path('/dev/shm').is_dir():self.skipTest('a second filesystem is needed')
        with tempfile.TemporaryDirectory(dir='/dev/shm',prefix='dp-storage-oracle-') as foreign_fixture:
            file=Path(foreign_fixture)/'data';file.write_bytes(b'x'*32768)
            if file.stat().st_dev==self.root.stat().st_dev:self.skipTest('a second filesystem is needed')
            self.isolated_mount_scan(self.root,
                ['--bind',source,alias,'--bind',source/'single',single_alias,
                 '--bind',self.root,cycle,'--tmpfs',foreign,'--bind',file,foreign_file],
                '''
                (root/'foreign-dir'/'data').write_bytes(b'x'*32768)
                assert (root/'foreign-file').stat().st_dev != expected['device']
                assert (root/'sibling alias').stat().st_ino == (root/'source space\\\\name\\n').stat().st_ino
                assert (root/'ancestor-cycle').stat().st_ino == expected['inode']
                def same_device_only(fd):
                    assert os.fstat(fd).st_dev == expected['device']
                    return scandir(fd)
                with patch.object(worker.os,'scandir',side_effect=same_device_only):
                    measured=worker.scan(root,expected)
                native=subprocess.run(['/usr/bin/du','--summarize','--block-size=1','--one-file-system',
                    '--exclude=guest.qcow2',root],capture_output=True,check=True,timeout=3)
                assert not native.stderr, native.stderr
                assert measured['status']=='complete', measured
                assert measured['allocated_bytes']==int(native.stdout.split()[0]), (measured,native.stdout)
                real_open=open
                def missing_mountinfo(path,*args,**kwargs):
                    if path=='/proc/self/mountinfo':raise FileNotFoundError(path)
                    return real_open(path,*args,**kwargs)
                with patch('builtins.open',side_effect=missing_mountinfo):
                    try:worker.scan(root,expected)
                    except worker.ScanError as error:assert str(error)=='mount-boundary',error
                    else:raise AssertionError('missing mountinfo allowed a usable sample')
                ''')

    def test_same_device_mount_source_must_remain_inside_owned_scratch(self):
        fixture=self.root
        self.root=fixture/'scratch';self.root.mkdir()
        mounted=self.root/'mounted';mounted.mkdir()
        external=fixture/'outside';external.mkdir()
        (external/'do-not-enumerate').write_bytes(b'x'*8192)
        self.isolated_mount_scan(fixture,['--bind',external,mounted],'''
            def owned_only(fd):
                assert os.fstat(fd).st_ino != (root/'mounted').stat().st_ino
                return scandir(fd)
            with patch.object(worker.os,'scandir',side_effect=owned_only):
                try:worker.scan(root,expected)
                except worker.ScanError as error:assert str(error)=='mount-boundary',error
                else:raise AssertionError('an external same-device bind was accepted')
            ''')

    def test_bind_source_replacement_during_enumeration_invalidates_measurement(self):
        source=self.root/'internal';source.mkdir()
        (source/'data').write_bytes(b'x'*8192)
        alias=self.root/'mounted';alias.mkdir()
        self.isolated_mount_scan(self.root,['--bind',source,alias],'''
            exchanged=False
            def replace_source(fd):
                global exchanged
                if not exchanged and Path(os.readlink(f'/proc/self/fd/{fd}'))==root/'mounted':
                    (root/'internal').rename(root/'renamed')
                    (root/'internal').mkdir()
                    exchanged=True
                return scandir(fd)
            with patch.object(worker.os,'scandir',side_effect=replace_source):
                try:worker.scan(root,expected)
                except worker.ScanError as error:assert exchanged and str(error)=='mount-boundary',error
                else:raise AssertionError('the replaced source was accepted')
            ''')
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
        child_ino=child.stat().st_ino
        scandir=os.scandir
        def replaced_after_open(fd):
            if os.fstat(fd).st_ino==child_ino:
                child.rename(self.root/'moved-again')
                child.mkdir()
            return scandir(fd)
        with patch.object(worker.os,'scandir',side_effect=replaced_after_open),self.assertRaisesRegex(worker.ScanError,'identity-changed'):
            worker.scan(self.root,expected)
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
