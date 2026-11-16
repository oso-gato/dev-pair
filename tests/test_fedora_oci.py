"""Local parser/crypto/fault checks; never a native image import verdict."""
import contextlib
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import fedora_oci as f


class FedoraOCI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def graph(self, *, alter=None, gzip_time=0, raw=None, declared_diff=None):
        raw = b'fixture rootfs bytes, never extracted' if raw is None else raw
        layer = gzip.compress(raw, mtime=gzip_time)
        h = lambda b: hashlib.sha256(b).hexdigest()
        config = json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':['sha256:'+(declared_diff or h(raw))]}}).encode()
        manifest = json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
                    'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+h(config),'size':len(config)},
                    'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':'sha256:'+h(layer),'size':len(layer)}]}).encode()
        index = json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[
                    {'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+h(manifest),'size':len(manifest)}]}).encode()
        entries = [('blobs', None), ('blobs/sha256', None), ('oci-layout', b'{"imageLayoutVersion":"1.0.0"}'),
                   ('index.json', index), ('blobs/sha256/'+h(manifest),manifest),
                   ('blobs/sha256/'+h(config),config),('blobs/sha256/'+h(layer),layer)]
        if alter: entries = alter(entries)
        plain = self.root / ('graph-'+str(time.monotonic_ns())+'.tar')
        with tarfile.open(plain,'w',format=tarfile.USTAR_FORMAT) as archive:
            for name, data in entries:
                node = tarfile.TarInfo(name)
                if isinstance(data, int): node.type=data; node.linkname='/foreign'; archive.addfile(node)
                elif data is None: node.type=tarfile.DIRTYPE; archive.addfile(node)
                else: node.size=len(data); archive.addfile(node,io.BytesIO(data))
        return plain, {'MANIFEST':h(manifest),'CONFIG':h(config),'LAYER':h(layer),'DIFF':h(raw),'DIFF_BYTES':len(raw)}

    def parse(self, path, pins):
        with contextlib.ExitStack() as stack:
            for key,value in pins.items(): stack.enter_context(patch.object(f,key,value))
            return f.parse_oci(path,time.monotonic()+2)

    def test_real_outer_tar_graph_hashes_diff_stream_and_unknown_types(self):
        path,pins=self.graph(); self.parse(path,pins)
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE,tarfile.FIFOTYPE):
            # tar types are byte codes; use an explicit node alteration below.
            bad=self.root/('kind-'+kind.decode()+'.tar')
            with tarfile.open(path) as src, tarfile.open(bad,'w') as dst:
                for member in src:
                    if member.name=='oci-layout': member.type=kind;member.size=0;member.linkname='/foreign';dst.addfile(member)
                    else: dst.addfile(member,src.extractfile(member) if member.isfile() else None)
            with self.subTest(kind=kind), self.assertRaises(ValueError):self.parse(bad,pins)

    def test_duplicate_traversal_missing_and_blob_corruption(self):
        mutations=(lambda e:e+[e[-1]],lambda e:[('../escape',b'x')]+e,
                   lambda e:e[:-1],lambda e:e[:-1]+[(e[-1][0],b'corrupted')])
        for alter in mutations:
            path,pins=self.graph(alter=alter)
            with self.assertRaises(ValueError):self.parse(path,pins)
        path,pins=self.graph();path.write_bytes(path.read_bytes()+b'not-zero')
        with self.assertRaises(ValueError):self.parse(path,pins)

    def test_parser_deadline_entry_and_expansion_bounds(self):
        path,pins=self.graph()
        with self.assertRaisesRegex(ValueError,'deadline'):f.parse_oci(path,time.monotonic()-1)
        with patch.object(f,'PLAIN_LIMIT',1),self.assertRaises(ValueError):self.parse(path,pins)
        with patch.object(f,'DIFF_LIMIT',1),self.assertRaises(ValueError):self.parse(path,pins)
        with self.assertRaisesRegex(ValueError,'duplicate'):f._json(b'{"x":1,"x":2}')

    def test_foreign_inputs_reject_before_decoder_and_owned_tree_is_removed(self):
        cache=self.root/'cache';cache.mkdir()
        (cache/f.FILES[0]).write_bytes(b'wrong')
        made=[];real=tempfile.TemporaryDirectory
        def owned(*args,**kwargs):
            item=real(*args,**kwargs);made.append(Path(item.name));return item
        with patch.object(f.tempfile,'TemporaryDirectory',side_effect=owned),patch.object(f.lzma,'open') as decoder:
            with self.assertRaises(ValueError):
                with f.verified(cache):pass
            decoder.assert_not_called()
        self.assertTrue(made);self.assertTrue(all(not p.exists() for p in made))
        (cache/f.FILES[0]).unlink();os.mkfifo(cache/f.FILES[0])
        with self.assertRaises(ValueError):
            with f.verified(cache):pass

    def test_import_requires_config_manifest_diff_and_saveback_before_success(self):
        row={'Id':f.IMAGE,'Digest':'sha256:'+f.MANIFEST,'ManifestType':'application/vnd.oci.image.manifest.v1+json',
             'Os':'linux','Architecture':'amd64','RootFS':{'Layers':['sha256:'+f.DIFF]}}
        f.imported([row])
        for key in ('Id','Digest','ManifestType','Os','Architecture','RootFS'):
            bad=dict(row);bad.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):f.imported([bad])
        plain=self.root/'plain';plain.write_bytes(b'input')
        with self.assertRaises((ValueError,tarfile.TarError)):
            f.import_image(lambda *args,**kwargs:self.fail('engine reached invalid input'),plain)
        plain,pins=self.graph()
        with contextlib.ExitStack() as stack:
            for key,value in pins.items():stack.enter_context(patch.object(f,key,value))
            stack.enter_context(patch.object(f,'IMAGE','sha256:'+pins['CONFIG']))
            row['Id']=f.IMAGE;row['Digest']='sha256:'+f.MANIFEST;row['RootFS']={'Layers':['sha256:'+f.DIFF]}
            calls=[]
            def engine(*args,**kwargs):
                calls.append(args)
                if args[:2]==('image','inspect'):return json.dumps([row])
                if args[0]=='save':Path(args[args.index('--output')+1]).write_bytes(b'invalid saveback')
                return ''
            with self.assertRaises((ValueError,tarfile.TarError)):f.import_image(engine,plain)
            self.assertEqual([c[0] for c in calls],['load','image','save'])
            self.assertFalse(any(c[0]=='pull' for c in calls))

    def test_extended_headers_and_optional_directory_transport_are_bounded(self):
        path,pins=self.graph(alter=lambda entries:[v for v in entries if v[1] is not None])
        self.parse(path,pins)
        raw=path.read_bytes()
        for kind in (tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK,tarfile.XHDTYPE,tarfile.XGLTYPE):
            node=tarfile.TarInfo('././@LongLink');node.type=kind;node.size=11
            altered=self.root/('extended-'+kind.decode()+'.tar')
            altered.write_bytes(node.tobuf(format=tarfile.GNU_FORMAT)+b'index.json\0'+bytes(501)+raw)
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.parse(altered,pins)

    def test_expired_verification_and_real_owned_child_timeout(self):
        for seconds in (0,-1,121,float('inf'),float('nan')):
            with self.assertRaises(ValueError):
                with f.verified(self.root,seconds=seconds):pass
        from public_inputs import command
        work=self.root/'command';work.mkdir();(work/'home').mkdir()
        import sys
        code='import time;time.sleep(5)'
        started=time.monotonic()
        with self.assertRaisesRegex(ValueError,'deadline'):
            command([sys.executable,'-c',code],work,timeout=.05)
        self.assertLess(time.monotonic()-started,2)

    def test_capture_deadline_inherits_and_restores_earliest_real_timer(self):
        import signal
        import public_inputs
        previous=signal.getsignal(signal.SIGALRM)
        for outer,inner in ((.05,.2),(.2,.05)):
            signal.signal(signal.SIGALRM,signal.SIG_IGN)
            signal.setitimer(signal.ITIMER_REAL,outer)
            started=time.monotonic()
            try:
                with patch.object(public_inputs,'capture_regular',side_effect=lambda *a,**k:time.sleep(.3)):
                    with self.assertRaisesRegex(ValueError,'deadline'):
                        with f.verified(self.root,seconds=inner):pass
                self.assertLess(time.monotonic()-started,.15)
                self.assertEqual(signal.getsignal(signal.SIGALRM),signal.SIG_IGN)
                if outer > inner:
                    remaining=signal.getitimer(signal.ITIMER_REAL)[0]
                    self.assertGreater(remaining,0);self.assertLess(remaining,outer)
            finally:
                signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

    def test_export_recompression_is_explicit_derivation_not_source_equality(self):
        source,pins=self.graph()
        derived,changed=self.graph(gzip_time=1)
        self.assertEqual(pins['CONFIG'],changed['CONFIG'])
        self.assertNotEqual(pins['LAYER'],changed['LAYER'])
        with contextlib.ExitStack() as stack:
            for key,value in pins.items():stack.enter_context(patch.object(f,key,value))
            with self.assertRaises(ValueError):f.parse_oci(derived,time.monotonic()+2)
            proof=f.parse_oci(derived,time.monotonic()+2,derived=True)
            self.assertEqual(proof['config_sha256'],pins['CONFIG'])
            self.assertEqual(proof['diff_id_sha256'],pins['DIFF'])
            self.assertEqual(proof['manifest_sha256'],changed['MANIFEST'])
            self.assertEqual(proof['compressed_layer_sha256'],changed['LAYER'])
            wrong,_=self.graph(raw=b'changed rootfs',declared_diff=pins['DIFF'])
            with self.assertRaises(ValueError):f.parse_oci(wrong,time.monotonic()+2,derived=True)

    def test_isolated_python_keeps_source_siblings_without_ambient_import_path(self):
        import subprocess
        tools=Path(f.__file__).parent
        result=subprocess.run([sys.executable,'-I',str(tools/'candidate.py'),'launch'],
                              capture_output=True,timeout=3,env={'PATH':'/usr/bin:/bin'})
        self.assertEqual(result.returncode,2)
        self.assertNotIn(b'ModuleNotFoundError',result.stderr)
        code=('import importlib.util,sys;from pathlib import Path;'
              's=importlib.util.spec_from_file_location("fedora_oci",Path(sys.argv[1]));'
              'm=importlib.util.module_from_spec(s);sys.modules["fedora_oci"]=m;s.loader.exec_module(m);'
              'p=m._public_inputs();assert Path(p.__file__).parent==Path(m.__file__).parent;print("bound")')
        result=subprocess.run([sys.executable,'-I','-c',code,str(tools/'fedora_oci.py')],
                              capture_output=True,timeout=3,env={'PATH':'/usr/bin:/bin'})
        self.assertEqual((result.returncode,result.stdout),(0,b'bound\n'),result.stderr)

    def test_real_signature_with_long_owned_home_needs_no_agent_socket(self):
        work=self.root/('long-owned-staging-'*7);work.mkdir();(work/'home').mkdir()
        data=Path(__file__).parent/'data/fedora44'
        shutil.copyfile(data/'container-key.asc',work/f.FILES[2])
        shutil.copyfile(data/'container-CHECKSUM',work/f.FILES[1])
        self.assertGreater(len(str(work/'gpg')),108)
        status=f._signature(work,time.monotonic()+10)
        self.assertIn('VALIDSIG '+f.FINGERPRINT,status)
        self.assertFalse(any(node.name.startswith('S.gpg-agent') for node in (work/'gpg').iterdir()))

    def test_real_gpg_rejects_altered_signed_checksum(self):
        # Public Fedora key and CHECKSUM are small committed fixtures; no network.
        data=Path(__file__).parent/'data/fedora44'
        work=self.root/'crypto';work.mkdir();(work/'home').mkdir()
        shutil.copyfile(data/'container-key.asc',work/f.FILES[2])
        original=(data/'container-CHECKSUM').read_bytes()
        (work/f.FILES[1]).write_bytes(original)
        status=f._signature(work,time.monotonic()+10)
        self.assertIn('VALIDSIG '+f.FINGERPRINT,status)
        shutil.rmtree(work/'gpg')
        (work/f.FILES[1]).write_bytes(original.replace(f.ARCHIVE_SHA.encode(),b'0'*64,1))
        with self.assertRaises(ValueError):f._signature(work,time.monotonic()+10)
