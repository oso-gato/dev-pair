"""Disposable synthetic keys only; real GPG pipes, no engine or private corpus."""
import base64
import contextlib
import copy
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
import selected_payload as s
import fedora_ci_guest as guest
import bootstrap as b
import test_adapter_xdg_payload as previous

IDENTITY={'source_sha':'d'*40,'context_sha256':'a'*64,'phase':'maintenance-gptbox'}
EXPECTED={k:IDENTITY[k] for k in ('source_sha','context_sha256')}

def operands(raw=b'PRIVATE synthetic error\xff',status=125):
    buffers={'stdout':b'','stderr':raw}
    payload=b.signed_load_payload(buffers,{'suboperation':'load','context_sha256':'a'*64},'1000',launched=True,verified=True,status=status,complete=True)
    return buffers,payload

class CapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='seal-test-');cls.home=Path(cls.directory.name);cls.home.chmod(0o700)
        env={'PATH':'/usr/bin:/bin','HOME':str(cls.home),'LANG':'C','LC_ALL':'C'}
        args=['/usr/bin/gpg','--no-options','--homedir',str(cls.home),'--batch','--pinentry-mode','loopback','--passphrase','']
        p=subprocess.run(args+['--quick-generate-key','Synthetic Diagnostic <fixture.invalid>','rsa2048','encr','1d'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        if p.returncode:raise AssertionError('synthetic key generation failed')
        cls.key=subprocess.check_output(args+['--export'],env=env,timeout=3)
        cls.env=env;cls.args=args
        cls.empty=cls.home/'empty';cls.empty.mkdir(mode=0o500)
        cls.recipient=cls.home/'recipient.asc';cls.recipient.write_bytes(cls.key);cls.recipient.chmod(0o400)
    @classmethod
    def tearDownClass(cls):
        subprocess.run(['/usr/bin/gpgconf','--homedir',str(cls.home),'--kill','gpg-agent'],env=cls.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        cls.directory.cleanup()
    def setUp(self):
        self.enterContext(patch.object(s,'HOME',self.empty));self.enterContext(patch.object(s,'RECIPIENT',self.recipient))
    def seal(self,buffers,payload,end=None):
        with patch.object(s,'_recipient',return_value=self.key),patch.object(s,'_home',return_value=None):return s.seal(buffers,payload,IDENTITY,time.monotonic()+4 if end is None else end)
    def decrypt(self,cipher):
        p=subprocess.run(self.args+['--decrypt'],input=cipher,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,timeout=3)
        self.assertEqual(p.returncode,0);return p.stdout
    def test_real_public_recipient_roundtrip_nonutf8_and_2143_bytes(self):
        for raw in (b'\xff\x00'+b'x'*2141,b'x'*5000):
            with self.subTest(length=len(raw)):
                buffers,payload=operands(raw);result=self.seal(buffers,payload)
                self.assertRegex(result['fingerprint'],r'^[A-F0-9]{40}$');self.assertEqual(result['availability'],'sealed');self.assertNotIn('PRIVATE',json.dumps(result))
                cipher=base64.b64decode(result['ciphertext_base64']);plain=self.decrypt(cipher);envelope=json.loads(plain)
                self.assertLessEqual(len(plain),8192);self.assertEqual(envelope['identity'],IDENTITY);self.assertTrue(s.verify_plaintext(plain,result,EXPECTED,payload))
                self.assertEqual(envelope['attempt_id'],result['attempt_id']);self.assertEqual(envelope['status'],125)
                for name,data in buffers.items():self.assertEqual(base64.b64decode(envelope['streams'][name]['base64']),data)
                self.assertEqual(s.project(result,EXPECTED,payload),result);self.assertEqual(guest.sealed_load_projection(result,EXPECTED,payload),result);self.assertEqual(list(self.empty.iterdir()),[])
                tampered=bytearray(cipher);tampered[len(tampered)//2]^=1
                p=subprocess.run(self.args+['--decrypt'],input=tampered,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,timeout=3)
                self.assertNotEqual(p.returncode,0)
    def test_largest_complete_envelope_boundary_and_wrong_recipient(self):
        low,high=0,6145
        with patch.object(s,'_encrypt',return_value=b'cipher'):
            while low+1<high:
                mid=(low+high)//2;buffers,payload=operands(b'x'*mid)
                if self.seal(buffers,payload)['availability']=='sealed':low=mid
                else:high=mid
        buffers,payload=operands(b'x'*low);value=self.seal(buffers,payload)
        self.assertEqual(value['availability'],'sealed');self.assertLessEqual(len(self.decrypt(base64.b64decode(value['ciphertext_base64']))),8192)
        buffers,payload=operands(b'x'*high);self.assertEqual(self.seal(buffers,payload)['reason'],'too-large')
        with tempfile.TemporaryDirectory() as directory:
            wrong=Path(directory)/'wrong';wrong.write_bytes(b'invalid public key')
            with patch.object(s,'RECIPIENT',wrong),self.assertRaises(ValueError):s._encrypt(b'PRIVATE',time.monotonic()+2)
        with tempfile.TemporaryDirectory() as directory:
            p=subprocess.run(['/usr/bin/gpg','--no-options','--batch','--no-autostart','--homedir',directory,'--decrypt'],input=base64.b64decode(value['ciphertext_base64']),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,timeout=2)
            self.assertNotEqual(p.returncode,0)
    def test_decrypted_envelope_strict_binding_digest_schema_matrix(self):
        buffers,payload=operands();value=self.seal(buffers,payload);plain=self.decrypt(base64.b64decode(value['ciphertext_base64']));envelope=json.loads(plain)
        for key,wrong in (('schema',True),('status',1),('attempt_id','0'*32),('fingerprint','0'*40),('recipient_sha256','0'*64),('identity',{**IDENTITY,'source_sha':'0'*40}),('suboperation','save'),('PRIVATE','sentinel')):
            changed={**envelope,key:wrong};self.assertFalse(s.verify_plaintext(s.canonical(changed),value,EXPECTED,payload))
        for name in ('stdout','stderr'):
            for field,wrong in (('bytes',True),('sha256','0'*64),('complete',False),('base64','!')):
                changed=copy.deepcopy(envelope);changed['streams'][name][field]=wrong
                self.assertFalse(s.verify_plaintext(s.canonical(changed),value,EXPECTED,payload))
        for raw in (plain+b' ',plain[:-1],b'{}',b'x'*8193,b'[]',b'{"schema":1,"schema":1}',b'['*1100+b']'*1100):
            self.assertFalse(s.verify_plaintext(raw,value,EXPECTED,payload))
        changed=copy.deepcopy(envelope);changed['executor']['uid']=1001
        self.assertFalse(s.verify_plaintext(s.canonical(changed),value,EXPECTED,payload))
    def test_exact_production_public_recipient_fingerprint(self):
        key=Path(s.__file__).with_name('ci').joinpath('native35-diagnostic-recipient.asc').read_bytes()
        self.assertEqual(len(key),673);self.assertEqual(s.digest(key),s.RECIPIENT_SHA);self.assertRegex(s.FINGERPRINT,r'^[A-F0-9]{40}$')
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.run(['/usr/bin/gpg','--no-options','--batch','--no-autostart','--homedir',directory,'--with-colons','--show-keys'],input=key,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,timeout=2)
            self.assertEqual(result.returncode,0)
            fingerprints=[line.split(b':')[9].decode() for line in result.stdout.splitlines() if line.startswith(b'fpr:')]
            self.assertEqual(fingerprints[0],s.FINGERPRINT)
    def test_fixed_iso_source_recipient_and_deterministic_public_ownership(self):
        import fedora_ci as ci
        from test_public_inputs import PublicInputsTests

        fixture = PublicInputsTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        _, bundle, manifest, record = fixture.fixture_payload()
        probe = ci.Probe(record['source_sha'], fixture.root)
        probe.image = 'sha256:' + 'a' * 64
        probe.report['cloud_image'] = {}
        (probe.root / 'payload').mkdir(parents=True)

        def public_command(argv, *args):
            if 'fetch' in argv:
                return b'{}'
            self.assertIn('build', argv)
            self.assertEqual(argv[argv.index('--role') + 1], 'maintenance')
            handoff = Path(argv[argv.index('--output') + 1])
            (handoff / 'verification').mkdir(parents=True)
            shutil.copyfile(bundle, handoff / 'maintenance-inputs.tar.gz')
            shutil.copyfile(manifest, handoff / 'manifest.json')
            (handoff / 'verification/receipt.json').write_text('{}')
            return json.dumps({
                'source_sha': record['source_sha'],
                'manifest_sha256': ci.file_hash(manifest),
                'context_sha256': record['context_sha256'],
                'payload_sha256': record['payload']['sha256'],
            }).encode()

        def iso_helper(argv):
            return b'{"format":"qcow2","virtual-size":34359738368}' if 'info' in argv else b''

        with (
            patch.object(probe, 'bounded', side_effect=public_command),
            patch.object(probe, 'helper', side_effect=iso_helper) as helper,
            patch.object(ci, 'verification_evidence', return_value={'receipt': {}}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            probe.payload()

        payload_calls = [
            call.args[0] for call in helper.call_args_list
            if 'DPPAYLOAD' in call.args[0] or '/disks/payload.iso' in call.args[0]
        ]
        self.assertEqual(len(payload_calls), 1)
        argv = payload_calls[0]
        self.assertEqual(argv.count(probe.image), 1)
        image_index = argv.index(probe.image)
        podman_args = argv[:image_index]
        iso_args = argv[image_index + 1:]
        self.assertEqual(podman_args[:1], ['run'])
        entrypoints = [arg for arg in podman_args if arg == '--entrypoint' or arg.startswith('--entrypoint=')]
        self.assertEqual(entrypoints, ['--entrypoint=/usr/bin/genisoimage'])
        iso_prefix = [
            '-quiet', '-output', '/disks/payload.iso', '-volid', 'DPPAYLOAD',
            '-joliet', '-rock', '-uid', '0', '-gid', '0', '-graft-points',
        ]
        self.assertEqual(iso_args[:len(iso_prefix)], iso_prefix)
        self.assertCountEqual(iso_args[len(iso_prefix):], [
            'native35-recipient.asc=/payload/native35-recipient.asc',
            'native35-gpg-home=/payload/native35-gpg-home',
            'guest.py=/payload/guest.py',
            'public_inputs.py=/payload/public_inputs.py',
            'fedora_oci.py=/payload/fedora_oci.py',
            'manifest.json=/payload/manifest.json',
            'maintenance-inputs.tar.gz=/payload/maintenance-inputs.tar.gz',
        ])
    def test_bounded_header_variants_and_incomplete_streams(self):
        buffers,payload=operands(b'x'*5100)
        for uid in (1000,2**32-1):
            for status in (1,255):
                changed={**payload,'uid':uid,'status':status}
                self.assertEqual(self.seal(buffers,changed)['availability'],'sealed')
        for field in ('complete','bytes','sha256'):
            changed=copy.deepcopy(payload);changed['streams']['stderr'][field]={'complete':False,'bytes':0,'sha256':'0'*64}[field]
            self.assertNotEqual(self.seal(buffers,changed)['availability'],'sealed')
    def test_complete_selection_matrix_rejects_without_encryption(self):
        changes=[('status',0),('status',True),('uid',True),('uid',999),('control_verified',False),('launch_handle_observed',False),('suboperation','save'),('context_sha256','b'*64),('availability','partial')]
        for key,value in changes:
            buffers,payload=operands();payload[key]=value
            with self.subTest(key=key),patch.object(s,'_encrypt',side_effect=AssertionError('must not encrypt')):
                self.assertNotEqual(self.seal(buffers,payload)['availability'],'sealed')
        buffers,payload=operands();payload['streams']['stderr']['sha256']='0'*64
        self.assertEqual(self.seal(buffers,payload)['reason'],'incomplete')
        for identity in (None,{**IDENTITY,'source_sha':'bad'},{**IDENTITY,'extra':'PRIVATE'}):
            self.assertEqual(s.seal(buffers,payload,identity,time.monotonic()+2)['reason'],'not-selected')
    def test_size_budget_recipient_failures_and_no_plaintext_fallback(self):
        buffers,payload=operands(b'x'*8192);self.assertEqual(self.seal(buffers,payload)['reason'],'too-large')
        buffers,payload=operands();self.assertEqual(self.seal(buffers,payload,end=time.monotonic()-1)['reason'],'no-budget')
        for error in (OSError('PRIVATE'),ValueError('PRIVATE')):
            with patch.object(s,'_encrypt',side_effect=error):
                result=self.seal(buffers,payload);self.assertEqual(result['reason'],'encryption-unavailable');self.assertNotIn('PRIVATE',json.dumps(result))
        with patch.object(s,'_recipient',side_effect=FileNotFoundError):self.assertEqual(s.seal(buffers,payload,IDENTITY,time.monotonic()+2)['reason'],'not-collected')
    def test_projection_rejects_binding_and_closed_schema_forgeries(self):
        buffers,payload=operands();value=self.seal(buffers,payload)
        for key,wrong in [('uid',True),('status',0),('fingerprint','0'*40),('recipient_sha256','0'*64),('ciphertext_sha256','0'*64),('ciphertext_bytes',True),('attempt_id','bad'),('PRIVATE','secret'),('ciphertext_base64','!')]:
            changed={**value,key:wrong}
            self.assertEqual(s.project(changed,EXPECTED,payload),s.unavailable('invalid'))
            self.assertEqual(guest.sealed_load_projection(changed,EXPECTED,payload),s.unavailable('invalid'))
        self.assertEqual(s.project(value,{**EXPECTED,'source_sha':'0'*40},payload),s.unavailable('invalid'))
        self.assertEqual(s.project(value,{**EXPECTED,'context_sha256':'0'*64},payload),s.unavailable('invalid'))
    def test_timeout_and_capture_reap_only_owned_child(self):
        original=subprocess.Popen;children=[]
        def launch(args,**kwargs):
            child=original([sys.executable,'-c','import time;time.sleep(10)'],**kwargs);children.append(child);return child
        with patch.object(s.subprocess,'Popen',side_effect=launch),self.assertRaises(ValueError):s._encrypt(b'PRIVATE',time.monotonic()+.4)
        self.assertTrue(all(p.returncode is not None for p in children))
        def flood(args,**kwargs):
            child=original([sys.executable,'-c','import os;os.write(1,b"x"*20000)'],**kwargs);children.append(child);return child
        with patch.object(s.subprocess,'Popen',side_effect=flood),self.assertRaises(ValueError):s._encrypt(b'PRIVATE',time.monotonic()+2)
        self.assertTrue(all(p.returncode is not None for p in children))
    def test_fixed_recipient_symlink_writable_foreign_and_wrong_bytes_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'key';p.write_bytes(self.key);p.chmod(0o444)
            with patch.object(s,'RECIPIENT',p),self.assertRaises(ValueError):s._recipient()
            p.unlink();os.mkfifo(p,0o600)
            with patch.object(s,'RECIPIENT',p),self.assertRaises(ValueError):s._recipient()
            p.unlink();p.symlink_to('/dev/null')
            with patch.object(s,'RECIPIENT',p),self.assertRaises(OSError):s._recipient()
    def test_projection_requires_independent_matching_payload(self):
        buffers,payload=operands();value=self.seal(buffers,payload)
        for bound in (None,{**payload,'uid':1001},{**payload,'status':1},{**payload,'control_verified':False}):
            self.assertEqual(s.project(value,EXPECTED,bound),s.unavailable('invalid'))
            self.assertEqual(guest.sealed_load_projection(value,EXPECTED,bound),s.unavailable('invalid'))
    def test_report_actual_serialization_bound_max_cipher(self):
        buffers,payload=operands()
        with patch.object(s,'_encrypt',return_value=b'x'*16384):value=self.seal(buffers,payload)
        self.assertEqual(guest.sealed_load_projection(value,EXPECTED,payload),value)
        self.assertLess(len(guest.encode_report({'diagnostics':{'sealed_signed_load':value}})),65536)
        report={'diagnostics':{'public_operations':{'adapter':{'sealed_signed_load':value}}},'other':'x'*50000}
        self.assertLessEqual(len(guest.encode_report(report)),guest.REPORT_FRAME_LIMIT)
        self.assertEqual(report['diagnostics']['public_operations']['adapter']['sealed_signed_load']['reason'],'report-budget')
        with self.assertRaises(ValueError):guest.encode_report({'diagnostics':value,'other':'x'*65536})

class ChannelTests(previous.RealPayloadTests):
    def setUp(self):
        super().setUp();self.enterContext(patch.object(s,'_home',return_value=None))
    def test_real_verified_payload_encrypt_failure_keeps_primary_and_cleanup(self):
        import selected_payload
        # Module is loaded from exact source sibling dynamically; patch its shared GPG launcher.
        original=subprocess.Popen
        with patch.object(s,'_recipient',side_effect=OSError('PRIVATE')):
            with self.assertRaisesRegex(b.Blocked,'exit 1'):self.execute(b'PRIVATE engine bytes')
        history=self.history();self.assertNotIn('PRIVATE',json.dumps(history));self.assertIn('sealed_signed_load',history)
        self.assertTrue(all(child.returncode is not None for child in self.children))

    def test_verified_selected_channel_capsule_binding_and_public_report(self):
        with patch.object(s,'_recipient',return_value=b'public'),patch.object(s,'_encrypt',return_value=b'cipher'):
            with self.assertRaisesRegex(b.Blocked,'exit 1'):self.execute(b'PRIVATE engine bytes')
        history=self.history();value=history['sealed_signed_load'];self.assertEqual(value['availability'],'sealed')
        self.assertNotIn('PRIVATE',json.dumps(history));self.assertEqual(value['status'],1)
        state=self.app.path(b.STATE);public=guest.public_diagnostics(state,EXPECTED)
        self.assertEqual(public['adapter']['sealed_signed_load'],value)
        binding=public['adapter']['sealed_signed_load_binding'];self.assertEqual(binding['signed_load_payload']['uid'],1000)
        from test_fedora_ci import fixture_inputs
        import fedora_ci as ci
        expected=fixture_inputs();expected.update(EXPECTED)
        report={'version':guest.REPORT_VERSION,'source_sha':IDENTITY['source_sha'],'guest_sha256':'b'*64,'inputs':expected,'initialization':{},'phases':{k:{'status':'blocked','detail':'synthetic'} for k in guest.GUEST_PHASES},'identity':{},'diagnostics':{'public_operations':public}}
        self.assertEqual(ci.parse_serial(guest.encode_report(report),IDENTITY['source_sha'],'b'*64,expected),report)
        for key,wrong in (('uid',1001),('status',125),('ciphertext_sha256','0'*64)):
            changed=copy.deepcopy(report);changed['diagnostics']['public_operations']['adapter']['sealed_signed_load'][key]=wrong
            with self.assertRaises(ci.Blocked):ci.parse_serial(guest.encode_report(changed),IDENTITY['source_sha'],'b'*64,expected)
    def test_encryption_exception_cannot_replace_failed_payload_or_cleanup(self):
        with patch.object(s,'_recipient',return_value=b'public'),patch.object(s,'_encrypt',side_effect=OSError('PRIVATE crypto')):
            with self.assertRaisesRegex(b.Blocked,'exit 1'):self.execute(b'PRIVATE payload')
        self.assertEqual(self.history()['sealed_signed_load']['reason'],'encryption-unavailable')
        self.assertNotIn('PRIVATE',json.dumps(self.history()))
        with self.assertRaisesRegex(b.Blocked,'cleanup-unresolved'):self.execute(b'PRIVATE',broken_cleanup=True)
        self.assertTrue(all(child.returncode is not None for child in self.children))

    def test_success_unselected_and_incomplete_do_not_export_ciphertext(self):
        self.execute(code=0)
        self.assertNotIn('sealed_signed_load',self.history())
        with self.assertRaises(b.Blocked):self.execute(b'PRIVATE',wrong_binding=True)
        self.assertNotIn('sealed_signed_load',self.history())
        with self.assertRaises(b.Blocked):self.execute(b'PRIVATE',broken_cleanup=True)
        self.assertNotEqual(self.history().get('sealed_signed_load',{}).get('availability'),'sealed')
