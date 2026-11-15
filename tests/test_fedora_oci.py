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

    def graph(self, *, alter=None):
        raw = b'fixture rootfs bytes, never extracted'
        layer = gzip.compress(raw, mtime=0)
        h = lambda b: hashlib.sha256(b).hexdigest()
        config = json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':['sha256:'+h(raw)]}}).encode()
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
        calls=[]
        def engine(*args,**kwargs):
            calls.append(args)
            if args[:2]==('image','inspect'):return json.dumps([row])
            if args[0]=='save':Path(args[args.index('--output')+1]).write_bytes(b'invalid saveback')
            return ''
        with self.assertRaises((ValueError,tarfile.TarError)):f.import_image(engine,plain)
        self.assertEqual([c[0] for c in calls],['load','image','save'])
        self.assertFalse(any(c[0]=='pull' for c in calls))

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
