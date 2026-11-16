"""Real local kernel/ownership/cache regressions; no native container admission."""
import contextlib
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fedora_oci as f
import public_inputs as p
import fedora_ci as ci

class SignedBaseRepair(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.parent=self.root/'owned';self.parent.mkdir(mode=0o755);self.parent.chmod(0o755)

    def test_kernel_save_limit_admits_source_spool_but_output_admission_stays_smaller(self):
        target=self.root/'extent'
        code='import os,sys;f=os.open(sys.argv[1],os.O_CREAT|os.O_WRONLY,0o600);os.ftruncate(f,int(sys.argv[2]));os.close(f)'
        for cap,wanted in ((f.PLAIN_LIMIT,False),(f.SAVE_FILE_LIMIT,True)):
            result=subprocess.run(['/usr/bin/prlimit','--fsize='+str(cap)+':'+str(cap),sys.executable,'-c',code,str(target),str(f.DIFF_BYTES)],capture_output=True,timeout=3)
            self.assertEqual(result.returncode==0,wanted)
        self.assertEqual(target.stat().st_size,f.DIFF_BYTES)
        with self.assertRaises(ValueError):p.capture_regular(target,f.PLAIN_LIMIT)

    def test_owned_copy_lease_reconciles_before_cleanup_and_preserves_foreign_collision(self):
        calls=[]
        with f.copy_workspace(self.parent,reconcile=lambda:calls.append('stopped')) as directory:
            (directory/'child').write_text('owned')
        self.assertEqual(calls,['stopped']);self.assertFalse(directory.exists())
        with self.assertRaisesRegex(RuntimeError,'uncertain'):
            with f.copy_workspace(self.parent,reconcile=lambda:(_ for _ in ()).throw(RuntimeError('uncertain'))) as directory:
                (directory/'marker').write_text('retained')
        self.assertTrue((directory/'marker').exists())
        with f.copy_workspace(self.parent,reconcile=lambda:calls.append('stopped')) as fresh:
            self.assertFalse((fresh/'marker').exists())
        directory.mkdir();(directory/'foreign').write_text('preserve')
        with self.assertRaises(ValueError):
            with f.copy_workspace(self.parent,reconcile=lambda:self.fail('foreign reconciliation')):pass
        self.assertEqual((directory/'foreign').read_text(),'preserve')

    def test_peak_reserve_blocks_before_any_allocation(self):
        from types import SimpleNamespace
        with patch.object(f.shutil,'disk_usage',return_value=SimpleNamespace(free=f.IMPORT_PEAK_RESERVE-1)):
            with self.assertRaisesRegex(ValueError,'capacity'):
                with f.copy_workspace(self.parent,reconcile=lambda:None):pass
        self.assertEqual(list(self.parent.iterdir()),[])
        probe=ci.Probe('a'*40,self.root)
        probe.image_copy_active=True
        with patch.object(ci,'measure_storage',return_value={'bytes':ci.OVERHEAD_LIMIT-f.UNLINKED_RESERVE+1}):
            with self.assertRaisesRegex(ci.Blocked,'unlinked'):probe.storage_measurement()

    def test_actual_cleared_environment_and_separate_readonly_input_surface(self):
        source=self.root/'source';source.mkdir();node=source/'base';node.write_text('authenticated');node.chmod(0o444);source.chmod(0o555)
        old=os.umask(0o077)
        try:
            with f.copy_workspace(self.parent,reconcile=lambda:None) as copy:
                code=('import os,sys;from pathlib import Path;s=Path(sys.argv[1]);'
                      'assert s.read_text()=="authenticated";assert set(os.environ)<={"PATH","TMPDIR","LC_CTYPE"};'
                      'Path(os.environ["TMPDIR"],"written").write_text("owned");'
                      '\nfor operation in (lambda:s.write_text("bad"),lambda:s.unlink()):\n'
                      ' try:operation()\n'
                      ' except PermissionError:pass\n'
                      ' else:raise AssertionError("input mutable")\n'
                      'print(os.getuid())')
                result=subprocess.run(['/usr/bin/env','-i','PATH=/usr/bin:/bin','TMPDIR='+str(copy),sys.executable,'-I','-c',code,str(node)],capture_output=True,timeout=3)
                self.assertEqual((result.returncode,result.stdout),(0,(str(os.getuid())+'\n').encode()),result.stderr)
                self.assertEqual((copy/'written').stat().st_mode&0o777,0o600)
        finally:os.umask(old);source.chmod(0o755)

    def test_verified_fedora_cache_avoids_second_network_acquisition_and_rejects_stale(self):
        # Tiny test identities inject only the immutable external artifact boundary.
        data=b'public fixture';sha=hashlib.sha256(data).hexdigest()
        fedora={name:('https://example.invalid/'+name,len(data),sha) for name in f.FILES}
        all_inputs={**fedora,'other':('https://example.invalid/other',len(data),sha)}
        cache=self.root/'cache';cache.mkdir()
        for name in fedora:(cache/name).write_bytes(data)
        urls=[]
        class Opener:
            def open(self,url,**kwargs):urls.append(url);return io.BytesIO(data)
        with patch.object(p,'ARTIFACTS',all_inputs),patch.object(f,'ARTIFACTS',fedora),patch.object(p.urllib.request,'build_opener',return_value=Opener()),patch.object(p,'command',return_value=(b'',b'')):
            output=self.root/'fetch';p.fetch(output,cache)
            self.assertEqual(urls,['https://example.invalid/other'])
            for name in fedora:self.assertEqual((output/name).read_bytes(),data)
            (cache/f.FILES[0]).write_bytes(b'wrong')
            with self.assertRaises(ValueError):p.fetch(self.root/'stale',cache)
            self.assertEqual((cache/f.FILES[0]).read_bytes(),b'wrong')
            self.assertFalse((self.root/'stale').exists())

    def test_actual_ci_tooling_then_payload_fetch_acquires_each_fedora_input_once(self):
        data=b'public fixture';sha=hashlib.sha256(data).hexdigest()
        fedora={name:('https://example.invalid/'+name,len(data),sha) for name in f.FILES}
        inputs={**fedora,'other':('https://example.invalid/other',len(data),sha)}
        urls=[]
        class Stop(Exception):pass
        @contextlib.contextmanager
        def verified(source,**kwargs):yield Path(source)/'unused',{}
        def download(url,target,*args,**kwargs):urls.append(url);Path(target).write_bytes(data)
        class Opener:
            def open(self,url,**kwargs):urls.append(url);return io.BytesIO(data)
        probe=ci.Probe('a'*40,self.parent);(self.parent/'payload').mkdir()
        def remove(argv,**kwargs):
            self.assertEqual(argv[:5],['sudo','-n','/bin/rm','-rf','--']);shutil.rmtree(argv[-1]);return b''
        with patch.object(ci,'run_small',side_effect=remove),patch.object(f,'ARTIFACTS',fedora),patch.object(p,'ARTIFACTS',inputs),patch.object(ci,'download',side_effect=download), \
             patch.object(f,'verified',side_effect=verified),patch.object(f,'import_image',side_effect=Stop), \
             patch.object(p.urllib.request,'build_opener',return_value=Opener()),patch.object(p,'command',return_value=(b'',b'')):
            with self.assertRaises(Stop):probe.tooling()
            def bounded(argv,*args,**kwargs):
                self.assertIn('fetch',argv)
                cache=Path(argv[argv.index('--output')+1]);source=Path(argv[argv.index('--fedora-cache')+1])
                p.fetch(cache,source);raise Stop()
            probe.bounded=bounded
            with self.assertRaises(Stop):probe.payload()
        for url,_,_ in fedora.values():self.assertEqual(urls.count(url),1)

    def test_real_sigkill_reclaims_recorded_verifier_and_copy_before_new_capacity(self):
        import selectors,signal
        # Portable source suite uses real parser work; the separately recorded
        # cached experiment below exercises all141MB signed verifier bytes.
        code=('import sys,time;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import fedora_oci as f;'
              '\nwith f.image_workspaces(Path(sys.argv[2]),reconcile=lambda:None) as (copy,verify):\n'
              ' (copy/"copy-marker").write_bytes(b"owned")\n'
              ' (verify/"private-incomplete").mkdir(mode=0o700)\n'
              ' (verify/"private-incomplete"/"partial").write_bytes(b"owned verification")\n'
              ' print("ready",flush=True);time.sleep(20)\n')
        process=subprocess.Popen([sys.executable,'-c',code,str(Path(f.__file__).parent),str(self.parent)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        selected=selectors.DefaultSelector();selected.register(process.stdout,selectors.EVENT_READ)
        try:
            self.assertTrue(selected.select(3));self.assertEqual(process.stdout.readline(),b'ready\n')
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
        finally:
            selected.close()
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
            process.stdout.close();process.stderr.close()
        self.assertTrue((self.parent/'verification-work/private-incomplete/partial').exists())
        (self.parent/'foreign').write_text('preserved')
        from types import SimpleNamespace
        calls=[]
        with patch.object(f.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(ValueError,'capacity'):
                with f.image_workspaces(self.parent,reconcile=lambda:calls.append('stopped')):pass
        self.assertEqual(calls,['stopped','stopped'])
        self.assertEqual(list(self.parent.iterdir()),[self.parent/'foreign'])

    def test_cleanup_only_reclaims_both_leases_without_new_allocation(self):
        def uncertain():raise RuntimeError('executor unresolved')
        for verification in (False,True):
            with self.assertRaises(RuntimeError):
                with f.copy_workspace(self.parent,reconcile=uncertain,verification=verification) as directory:
                    (directory/'marker').write_text('preserved until stopped')
        from types import SimpleNamespace
        calls=[]
        with patch.object(f.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
            f.recover_workspaces(self.parent,reconcile=lambda:calls.append('stopped'))
        self.assertEqual(calls,['stopped','stopped']);self.assertEqual(list(self.parent.iterdir()),[])

    def test_leased_verification_child_survives_until_exact_executor_reconciles(self):
        seen=[]
        def unresolved():
            seen.append((self.parent/'verification-work').exists())
            raise RuntimeError('executor still uncertain')
        with self.assertRaises(RuntimeError):
            with f.copy_workspace(self.parent,reconcile=unresolved,verification=True) as verifying:
                with f._verification_tree(verifying,True) as child:
                    child=Path(child);(child/'public-input').write_text('still owned')
                self.assertTrue((child/'public-input').exists())
        self.assertEqual(seen,[True]);self.assertTrue((child/'public-input').exists())
        f.recover_workspaces(self.parent,reconcile=lambda:seen.append('stopped'))
        self.assertFalse(child.exists())
