"""Real transition signals; exact fixed mask/handler restoration, no engines."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import selected_payload as s
import bootstrap as b
from test_selected_payload import operands,IDENTITY

class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.mask=signal.pthread_sigmask(signal.SIG_BLOCK,());self.saved={n:signal.getsignal(n) for n in (signal.SIGALRM,signal.SIGINT,signal.SIGTERM,signal.SIGHUP)};self.children=[]
    def tearDown(self):
        signal.pthread_sigmask(signal.SIG_BLOCK,self.saved)
        for n,h in self.saved.items():signal.signal(n,h)
        signal.pthread_sigmask(signal.SIG_SETMASK,self.mask)
        for p in self.children:
            if p.poll() is None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            p.wait(timeout=2)
            for stream in (p.stdin,p.stdout,p.stderr):
                if not stream.closed:stream.close()
        self.assertTrue(s.reconcile_pending())
    def seal(self):
        buffers,payload=operands()
        with patch.object(s,'_recipient',return_value=b'public'),patch.object(s,'_home',return_value=None):return s.seal(buffers,payload,IDENTITY,time.monotonic()+.4)
    def phase(self,n,f):raise b.Blocked('phase execution budget exhausted')
    def assert_restored(self,alarm):
        self.assertIs(signal.getsignal(signal.SIGALRM),alarm)
        self.assertTrue(all(signal.getsignal(n) is handler for n,handler in self.saved.items() if n!=signal.SIGALRM))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,()),self.mask)
        with self.assertRaises(b.Blocked):signal.raise_signal(signal.SIGALRM)
    def test_real_setup_signal_restores_mask_handlers_and_prevents_spawn(self):
        alarm=self.phase;signal.signal(signal.SIGALRM,alarm);signal.signal(signal.SIGINT,signal.default_int_handler)
        original=signal.signal;triggered=False
        def install(n,h):
            nonlocal triggered
            result=original(n,h)
            if n==signal.SIGALRM and h is not alarm and not triggered:triggered=True;signal.raise_signal(signal.SIGINT)
            return result
        with patch.object(s.signal,'signal',side_effect=install),patch.object(s.subprocess,'Popen',side_effect=AssertionError('known cancellation must not spawn')),self.assertRaises(KeyboardInterrupt):self.seal()
        self.assertTrue(triggered);self.assert_restored(alarm)
    def test_mask_change_after_effect_error_uses_already_saved_prior_mask(self):
        original=signal.pthread_sigmask;failed=False
        def change(how,mask):
            nonlocal failed
            result=original(how,mask)
            if how==signal.SIG_BLOCK and mask and not failed:failed=True;raise OSError('synthetic after-effect error')
            return result
        with patch.object(s.signal,'pthread_sigmask',side_effect=change):value=self.seal()
        self.assertEqual(value['reason'],'encryption-unavailable');self.assertEqual(original(signal.SIG_BLOCK,()),self.mask)
        self.assertTrue(all(signal.getsignal(n) is h for n,h in self.saved.items()))
    def test_nonmutating_prior_mask_query_interrupts_without_any_changed_state(self):
        original=signal.pthread_sigmask;failed=False
        def query(how,mask):
            nonlocal failed
            result=original(how,mask)
            if how==signal.SIG_BLOCK and not mask and not failed:failed=True;signal.raise_signal(signal.SIGINT)
            return result
        with patch.object(s.signal,'pthread_sigmask',side_effect=query),patch.object(s.subprocess,'Popen',side_effect=AssertionError('must not launch')),self.assertRaises(KeyboardInterrupt):self.seal()
        self.assertEqual(original(signal.SIG_BLOCK,()),self.mask);self.assertTrue(all(signal.getsignal(n) is h for n,h in self.saved.items()))
    def test_restore_mask_interruption_before_and_after_effect_restores_prior(self):
        for ordinal in (1,2):
            for after in (False,True):
                original=signal.pthread_sigmask;calls=0;failed=False
                def restore(how,mask):
                    nonlocal calls,failed
                    if how==signal.SIG_SETMASK:calls+=1
                    if how==signal.SIG_SETMASK and calls==ordinal and not failed:
                        failed=True
                        if after:original(how,mask)
                        raise OSError('synthetic mask restoration interruption')
                    return original(how,mask)
                with patch.object(s.signal,'pthread_sigmask',side_effect=restore),patch.object(s.subprocess,'Popen',side_effect=OSError('synthetic no child')):value=self.seal()
                self.assertEqual(value['reason'],'encryption-unavailable');self.assertTrue(failed);self.assertEqual(original(signal.SIG_BLOCK,()),self.mask)
                self.assertTrue(all(signal.getsignal(n) is h for n,h in self.saved.items()))
    def test_restore_setter_error_before_or_after_effect_keeps_restoration_knowledge(self):
        for after in (False,True):
            alarm=self.phase;signal.signal(signal.SIGALRM,alarm);original=signal.signal;failed=False
            def setter(n,h):
                nonlocal failed
                if n==signal.SIGALRM and h is alarm and not failed:
                    failed=True
                    if after:original(n,h)
                    raise OSError('synthetic restore setter')
                return original(n,h)
            with patch.object(s.signal,'signal',side_effect=setter),patch.object(s.subprocess,'Popen',side_effect=OSError('synthetic no child')):value=self.seal()
            self.assertEqual(value['reason'],'encryption-unavailable');self.assertTrue(failed);self.assert_restored(alarm)
    def test_prior_blocked_mask_is_preserved_without_adding_child_mask(self):
        original=subprocess.Popen;prior=set(self.mask)|{signal.SIGUSR1};signal.pthread_sigmask(signal.SIG_SETMASK,prior)
        def create(args,**kwargs):
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,()),prior)
            p=original([sys.executable,'-c','import os;os.write(1,b"cipher")'],**kwargs);self.children.append(p);return p
        with patch.object(s.subprocess,'Popen',side_effect=create):self.seal()
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,()),prior)
        signal.pthread_sigmask(signal.SIG_SETMASK,self.mask)
