"""Exact worker snapshot dependency closure; no CLI, model, namespace or network."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import codex_sessions as s

PROBE=r'''
import hashlib,json,pathlib,runpy,sys
root=pathlib.Path(sys.argv[1]).resolve()
worker=runpy.run_path(str(root/'worker.py'),run_name='isolated_session_import')
import codex_state,public_inputs,fedora_oci,startup_delivery,job_protocol,ledger_recovery
# These pure startup operations do not dispatch a CLI or touch private inputs.
policy=codex_state.generated_policy();layout=codex_state.layout()
corpus=startup_delivery.synthetic('a'*40)
assert json.loads(corpus.output())
assert corpus.receipt()['mode']=='synthetic-fixture'
modules={name:sys.modules[name] for name in ('codex_tools','session_helper','session_controller','job_protocol','ledger_recovery','startup_delivery','codex_state','public_inputs','fedora_oci')}
assert all(pathlib.Path(module.__file__).resolve().parent==root for module in modules.values())
print(json.dumps({'module_names':sorted(modules),'only_staged_modules':True,'policy':bool(policy),'layout':bool(layout),'synthetic_startup':True,'hashes':{name+'.py':hashlib.sha256(pathlib.Path(module.__file__).read_bytes()).hexdigest() for name,module in modules.items()}},sort_keys=True))
'''

class StagedDependencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.stage=self.root/'stage';self.stage.mkdir(mode=0o700)
    def run_probe(self):
        # -I ignores user site/PYTHONPATH; working directory is outside the checkout.
        return subprocess.run([sys.executable,'-I','-c',PROBE,str(self.stage)],cwd=self.root,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    def test_old_missing_dependency_fails_then_exact_changed_snapshot_safe_startup_passes(self):
        files=s.stage_session_sources(self.stage,time.monotonic()+3)
        fedora=files['fedora_oci.py'];data=fedora.read_bytes();fedora.unlink()
        old=self.run_probe();self.assertNotEqual(old.returncode,0);self.assertIn(b'fedora_oci.py',old.stderr)
        self.assertEqual(old.stdout,b'')
        fedora.write_bytes(data);fedora.chmod(0o444)
        changed=self.run_probe();self.assertEqual(changed.returncode,0,changed.stderr.decode())
        receipt=json.loads(changed.stdout);self.assertTrue(receipt['only_staged_modules']);self.assertTrue(receipt['synthetic_startup'])
        self.assertEqual(set(receipt['module_names']),{name[:-3] for name in s.SESSION_MODULES})
        for name in s.SESSION_MODULES:self.assertEqual(receipt['hashes'][name],hashlib.sha256(files[name].read_bytes()).hexdigest())
    def test_one_fixed_readonly_source_selection_binds_snapshot_mount_and_identity_hash(self):
        files=s.stage_session_sources(self.stage,time.monotonic()+3)
        self.assertEqual(set(files),{'worker.py',*s.SESSION_MODULES})
        sources=dict(s.session_sources());self.assertEqual(len(sources),10)
        for name,path in files.items():
            self.assertEqual(path.read_bytes(),sources[name].read_bytes());self.assertEqual(path.stat().st_mode&0o777,0o444)
        mounted=s.session_source_mounts(files);self.assertEqual(len(mounted),3*len(files))
        destinations={mounted[i+2]:mounted[i+1] for i in range(0,len(mounted),3)}
        self.assertEqual(set(destinations),{'/opt/tool_boundary.py',*('/opt/'+name for name in s.SESSION_MODULES)})
        self.assertEqual(destinations['/opt/fedora_oci.py'],str(files['fedora_oci.py']))
        self.assertTrue(all(mounted[i]=='--ro-bind' for i in range(0,len(mounted),3)))
        hashes={name:s.sha(path.read_bytes()) for name,path in files.items()};identity=s.sha(s.canonical(hashes))
        self.assertIn('fedora_oci.py',hashes)
        self.assertNotEqual(identity,s.sha(s.canonical({name:value for name,value in hashes.items() if name!='fedora_oci.py'})))
        for changed in ({name:path for name,path in files.items() if name!='fedora_oci.py'},{**files,'arbitrary.py':self.root/'foreign'}):
            with self.assertRaisesRegex(ValueError,'snapshot set mismatch'):s.session_source_mounts(changed)
