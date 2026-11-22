"""Real owned subprocess; phase-signal/cleanup scheduling injected, no engine."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap as b
import selected_payload as s
from test_selected_payload import operands,IDENTITY

class GpgCleanupTests(unittest.TestCase):
    def interrupted(self,kind):
        original=subprocess.Popen;children=[];waits=[]
        def expired(signum,frame):raise b.Blocked('phase execution budget exhausted')
        def launch(args,**kwargs):
            child=original([sys.executable,'-c','import time;time.sleep(10)'],**kwargs)
            children.append(child);waits.append(child.wait)
            def wait(*args,**kwargs):
                if kind=='signal':signal.raise_signal(signal.SIGALRM)
                if kind=='io':raise OSError('PRIVATE interrupted reap')
                if kind=='cancel':raise KeyboardInterrupt('PRIVATE cancellation')
                raise RuntimeError('PRIVATE interrupted reap')
            child.wait=wait;return child
        old=signal.signal(signal.SIGALRM,expired)
        try:
            buffers,payload=operands()
            with patch.object(s,'_recipient',return_value=b'public'),patch.object(s.subprocess,'Popen',side_effect=launch):
                result=s.seal(buffers,payload,IDENTITY,time.monotonic()+.4)
            self.assertEqual(result,s.unavailable('encryption-cleanup-unresolved'))
            owner=s._PENDING;self.assertIsNotNone(owner);self.assertIs(owner['process'],children[0])
            self.assertIsNone(children[0].returncode);self.assertTrue(owner['home'].is_dir())
            info=os.fstat(owner['fd']);self.assertEqual((info.st_dev,info.st_ino),(owner['home'].stat().st_dev,owner['home'].stat().st_ino))
            self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn(str(children[0].pid),json.dumps(result))
            with patch.object(s,'_encrypt',side_effect=AssertionError('no second child allowed')):
                self.assertEqual(s.seal(buffers,payload,IDENTITY,time.monotonic()+5),result)
            return owner,children,waits
        except BaseException:
            # A failed assertion must not leak the very child being checked.
            for child,wait in zip(children,waits):
                child.wait=wait
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                wait(timeout=2)
            if s._PENDING is not None:s.reconcile_pending()
            raise
        finally:signal.signal(signal.SIGALRM,old)
    def cleanup(self,owner,children,waits):
        for child,wait in zip(children,waits):
            child.wait=wait
            if child.poll() is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            wait(timeout=2) # Test harness owns this exact child; not a product deadline extension.
        self.assertTrue(s.reconcile_pending());self.assertIsNone(s._PENDING)
        self.assertFalse(owner['home'].exists());self.assertIsNone(owner['fd'])
    def test_phase_signal_and_all_other_cleanup_interruptions_retain_exact_live_owner(self):
        for kind in ('signal','io','runtime','cancel'):
            with self.subTest(kind=kind):
                owner,children,waits=self.interrupted(kind)
                self.cleanup(owner,children,waits)
    def test_foreign_replacement_is_preserved_until_original_owned_inode_returns(self):
        owner,children,waits=self.interrupted('signal');home=owner['home'];moved=home.with_name(home.name+'-held')
        try:
            for child,wait in zip(children,waits):child.wait=wait;wait(timeout=2)
            home.rename(moved);home.mkdir(mode=0o700);(home/'foreign').write_text('owned by unrelated fixture')
            self.assertFalse(s.reconcile_pending());self.assertEqual((home/'foreign').read_text(),'owned by unrelated fixture')
            (home/'foreign').unlink();home.rmdir();moved.rename(home)
        finally:
            self.cleanup(owner,children,waits)
    def test_no_new_wait_allowance_when_original_end_expired(self):
        owner,children,waits=self.interrupted('runtime')
        observed=[]
        try:
            owner['end']=time.monotonic()-1
            original_poll=children[0].poll
            def wait(*args,**kwargs):observed.append(kwargs['timeout']);raise RuntimeError('PRIVATE')
            with patch.object(children[0],'poll',return_value=None),patch.object(children[0],'wait',side_effect=wait):
                self.assertFalse(s.reconcile_pending())
            self.assertEqual(observed,[0]);self.assertTrue(owner['home'].exists())
        finally:self.cleanup(owner,children,waits)

    def test_retained_real_owner_cannot_replace_payload_or_native_cleanup_primary(self):
        from test_selected_payload import ChannelTests
        owner,children,waits=self.interrupted('signal');fixture=ChannelTests();fixture.setUp()
        try:
            with self.assertRaisesRegex(b.Blocked,'exit 1') as seen:fixture.execute(b'PRIVATE payload')
            self.assertNotIn('PRIVATE',str(seen.exception))
            self.assertEqual(fixture.history()['sealed_signed_load']['reason'],'encryption-cleanup-unresolved')
            with self.assertRaisesRegex(b.Blocked,'cleanup-unresolved'):fixture.execute(b'PRIVATE',broken_cleanup=True)
            self.assertIs(s._PENDING,owner);self.assertTrue(owner['home'].exists())
            self.assertTrue(all(child.returncode is not None for child in fixture.children))
            self.assertNotIn('PRIVATE',json.dumps(fixture.history()))
        finally:
            fixture.doCleanups();self.cleanup(owner,children,waits)

    def test_pipe_close_interruption_is_sticky_after_reap_and_reconciles_exact_state(self):
        original=subprocess.Popen;children=[]
        class InterruptedClose:
            def __init__(self,stream):self.stream=stream;self.first=True
            def __getattr__(self,name):return getattr(self.stream,name)
            def close(self):
                if self.first:self.first=False;raise OSError('PRIVATE close interruption')
                return self.stream.close()
        def launch(args,**kwargs):
            child=original([sys.executable,'-c','import os;os.write(1,b"synthetic ciphertext")'],**kwargs)
            children.append(child);child.stdout=InterruptedClose(child.stdout);return child
        try:
            buffers,payload=operands()
            with patch.object(s,'_recipient',return_value=b'public'),patch.object(s.subprocess,'Popen',side_effect=launch):
                value=s.seal(buffers,payload,IDENTITY,time.monotonic()+2)
            self.assertEqual(value,s.unavailable('encryption-cleanup-unresolved'))
            self.assertIsNotNone(children[0].returncode);self.assertTrue(s._PENDING['home'].exists())
            self.assertNotIn('PRIVATE',json.dumps(value))
        finally:
            self.assertTrue(s.reconcile_pending())
            for child in children:self.assertTrue(child.stdout.closed);self.assertIsNotNone(child.returncode)
