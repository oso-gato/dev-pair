"""Fixed immutable inputs; actual processes/signals, no native mount claim."""
import contextlib
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import bootstrap as b
import selected_payload as s
from test_selected_payload import operands,IDENTITY

class GpgCleanupTests(unittest.TestCase):
    def setUp(self):self.children=[];self.waits=[];self.old_handlers={number:signal.getsignal(number) for number in (signal.SIGALRM,signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
    def tearDown(self):
        for number,handler in self.old_handlers.items():signal.signal(number,handler)
        for child,wait in zip(self.children,self.waits):
            child.wait=wait
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):os.killpg(child.pid,signal.SIGKILL)
            wait(timeout=2) # Owning test cleanup, never a product time extension.
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream is not None and not stream.closed:stream.close()
        self.assertTrue(s.reconcile_pending());self.assertIsNone(s._PENDING)
    def launch(self,code='import time;time.sleep(10)',boundary=None,interrupted_wait=None):
        original=subprocess.Popen
        def create(args,**kwargs):
            self.assertNotIn('preexec_fn',kwargs);self.assertEqual(args[:4],['/usr/bin/prlimit','--core=0:0','--','/usr/bin/gpg'])
            child=original([sys.executable,'-c',code],**kwargs);self.children.append(child);self.waits.append(child.wait)
            if interrupted_wait is not None:child.wait=interrupted_wait
            if boundary is not None:signal.raise_signal(boundary)
            return child
        return create
    def seal(self):
        buffers,payload=operands()
        with patch.object(s,'_recipient',return_value=b'public'),patch.object(s,'_home',return_value=None):return s.seal(buffers,payload,IDENTITY,time.monotonic()+.4)
    def test_launch_publication_defers_then_propagates_phase_interrupt_and_keyboard(self):
        def phase(signum,frame):raise b.Blocked('phase execution budget exhausted')
        for number,handler,kind in ((signal.SIGALRM,phase,b.Blocked),(signal.SIGINT,signal.default_int_handler,KeyboardInterrupt),(signal.SIGTERM,lambda n,f:(_ for _ in ()).throw(SystemExit(17)),SystemExit)):
            with self.subTest(signal=number):
                signal.signal(number,handler)
                with patch.object(s.subprocess,'Popen',side_effect=self.launch(boundary=number)),self.assertRaises(kind):self.seal()
                child=self.children[-1];self.assertIsNotNone(child.returncode);self.assertIsNone(s._PENDING)
                self.assertIs(signal.getsignal(number),handler)
    def test_actual_existing_phase_handler_is_delivered_after_publication(self):
        command=b.Commands()
        with self.assertRaises(b.Blocked):
            with command.phase(1,'synthetic-diagnostic',native=False):
                with patch.object(s.subprocess,'Popen',side_effect=self.launch(boundary=signal.SIGALRM)):self.seal()
        self.assertTrue(command.phase_budget_witness['timer_fired']);self.assertFalse(command.phase_budget_witness['deadline_reached_at_exit'])
        self.assertTrue(all(child.returncode is not None for child in self.children));self.assertIsNone(s._PENDING)
    def test_failed_launch_still_delivers_pending_phase_cancellation(self):
        def phase(n,f):raise b.Blocked('phase execution budget exhausted')
        signal.signal(signal.SIGALRM,phase)
        def failed(*a,**k):signal.raise_signal(signal.SIGALRM);raise OSError('synthetic launch failure')
        with patch.object(s.subprocess,'Popen',side_effect=failed),self.assertRaises(b.Blocked):self.seal()
        self.assertIsNone(s._PENDING);self.assertIs(signal.getsignal(signal.SIGALRM),phase)
    def test_reap_cancellation_retains_owner_and_reconcile_does_not_swallow_it(self):
        def interrupted(*a,**k):raise KeyboardInterrupt('cancel')
        with patch.object(s.subprocess,'Popen',side_effect=self.launch(interrupted_wait=interrupted)),self.assertRaises(KeyboardInterrupt):self.seal()
        owner=s._PENDING;self.assertIs(owner['process'],self.children[0]);self.assertEqual(set(owner),{'process','end'})
        # The real child may already have exited after the first cleanup sent SIGKILL.
        # Keep this second check on the interrupted-wait path regardless of timing.
        with patch.object(owner['process'], 'poll', return_value=None):
            with self.assertRaises(KeyboardInterrupt):
                s.reconcile_pending()
        self.assertIs(s._PENDING,owner)
        with patch.object(s,'_encrypt',side_effect=AssertionError('second child forbidden')):self.assertEqual(self.seal()['reason'],'encryption-cleanup-unresolved')
    def test_cleanup_phase_signal_propagates_and_pending_has_no_fresh_wait(self):
        def phase(n,f):raise b.Blocked('phase execution budget exhausted')
        signal.signal(signal.SIGALRM,phase)
        def wait(*a,**kwargs):signal.raise_signal(signal.SIGALRM)
        with patch.object(s.subprocess,'Popen',side_effect=self.launch(interrupted_wait=wait)),self.assertRaises(b.Blocked):self.seal()
        owner=s._PENDING;owner['end']=time.monotonic()-1;observed=[]
        def bounded(*a,**kwargs):observed.append(kwargs['timeout']);raise OSError('safe fixture')
        with patch.object(owner['process'],'poll',return_value=None),patch.object(owner['process'],'wait',side_effect=bounded):self.assertFalse(s.reconcile_pending())
        self.assertEqual(observed,[0])
    def test_ordinary_reap_error_stays_typed_uncertainty(self):
        def wait(*a,**kwargs):raise OSError('PRIVATE reap')
        with patch.object(s.subprocess,'Popen',side_effect=self.launch(interrupted_wait=wait)):
            value=self.seal()
        self.assertEqual(value,s.unavailable('encryption-cleanup-unresolved'));self.assertNotIn('PRIVATE',json.dumps(value));self.assertIsNotNone(s._PENDING)
    def test_removed_directory_findings_are_eliminated_not_repaired_by_path_delete(self):
        source=inspect.getsource(s)
        for forbidden in ('rmtree','mkdtemp','TemporaryDirectory','preexec_fn',"owner['home']","owner['fd']"):
            self.assertNotIn(forbidden,source)
        with tempfile.TemporaryDirectory() as directory:
            foreign=Path(directory)/'foreign';foreign.write_text('foreign retained')
            owner={'process':None,'end':time.monotonic()};s._PENDING=owner
            self.assertTrue(s.reconcile_pending());self.assertEqual(foreign.read_text(),'foreign retained')
    def test_pipe_close_failure_is_idempotent_after_confirmed_reap(self):
        original=self.launch('import os;os.write(1,b"cipher")')
        class InterruptedClose:
            def __init__(self,stream):self.stream=stream;self.first=True
            def __getattr__(self,name):return getattr(self.stream,name)
            def close(self):
                if self.first:self.first=False;raise OSError('PRIVATE close')
                self.stream.close()
        def create(args,**kwargs):
            child=original(args,**kwargs);child.stdout=InterruptedClose(child.stdout);return child
        with patch.object(s.subprocess,'Popen',side_effect=create):value=self.seal()
        self.assertEqual(value['reason'],'encryption-cleanup-unresolved');self.assertIsNotNone(self.children[0].returncode)
        self.assertTrue(s.reconcile_pending());self.assertTrue(self.children[0].stdout.closed)
    def test_known_native_primary_retained_when_diagnostic_cancellation_occurs(self):
        from test_selected_payload import ChannelTests
        fixture=ChannelTests();fixture.setUp()
        try:
            for error in (b.Blocked('phase execution budget exhausted'),KeyboardInterrupt(),SystemExit(7)):
                with patch.object(s,'seal',side_effect=error),self.assertRaisesRegex(b.Blocked,'exit 1'):fixture.execute(b'PRIVATE payload')
            with patch.object(s,'seal',side_effect=KeyboardInterrupt()),self.assertRaisesRegex(b.Blocked,'cleanup-unresolved'):fixture.execute(b'PRIVATE',broken_cleanup=True)
            self.assertNotIn('PRIVATE',json.dumps(fixture.history()));self.assertTrue(all(p.returncode is not None for p in fixture.children))
        finally:fixture.doCleanups()

class ImmutableInputTests(unittest.TestCase):
    def test_empty_fixed_home_validation_uses_actual_directory_and_readonly_mount_fact(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as root:
            home=Path(root)/'home';home.mkdir(mode=0o500)
            real_fstat=os.fstat
            def root_uid(fd):
                value=real_fstat(fd);return SimpleNamespace(st_mode=value.st_mode,st_uid=0)
            with patch.object(s,'HOME',home),patch.object(s.os,'fstat',side_effect=root_uid),patch.object(s.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
                s._home()
                (home/'unexpected').touch() if os.geteuid()==0 else None
                if os.geteuid()!=0:
                    with self.assertRaises(PermissionError):os.open(home/'write-probe',os.O_CREAT|os.O_WRONLY,0o600)
                home.chmod(0o700);(home/'unexpected').touch();home.chmod(0o500)
                with self.assertRaises(ValueError):s._home()
                home.chmod(0o700);(home/'unexpected').unlink();home.chmod(0o500)
                with patch.object(s.os,'fstatvfs',return_value=SimpleNamespace(f_flag=0)),self.assertRaises(ValueError):s._home()
            with patch.object(s,'HOME',home),self.assertRaises(ValueError):s._home() # actual UID1000, not root.
            home.chmod(0o700);home.rmdir();home.symlink_to(Path(root))
            with patch.object(s,'HOME',home),self.assertRaises(OSError):s._home()
    def test_exact_prlimit_gpg_flags_env_no_preexec_and_no_inherited_signal_mask(self):
        original=subprocess.Popen;seen=[]
        code='import json,resource,signal;print(json.dumps({"blocked":[int(n) for n in signal.pthread_sigmask(signal.SIG_BLOCK,[])],"core":resource.getrlimit(resource.RLIMIT_CORE)}))'
        # Run the actual existing prlimit utility; substitute only its GPG payload.
        def launch(args,**kwargs):
            seen.append((args,kwargs));return original(args[:3]+[sys.executable,'-c',code],**kwargs)
        with patch.object(s.subprocess,'Popen',side_effect=launch):output=s._encrypt(b'input',time.monotonic()+2)
        proof=json.loads(output);self.assertEqual(proof['core'],[0,0]);self.assertEqual(proof['blocked'],[])
        args,kwargs=seen[0];self.assertNotIn('preexec_fn',kwargs)
        for flag in ('--no-options','--no-autostart','--no-auto-key-retrieve','--no-default-keyring','--no-keyring','--no-auto-check-trustdb','--no-random-seed-file'):self.assertIn(flag,args)
        self.assertEqual(args[args.index('--homedir')+1],str(s.HOME));self.assertEqual(args[args.index('--recipient-file')+1],str(s.RECIPIENT))
        self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/bin','HOME':str(s.HOME),'LANG':'C','LC_ALL':'C'})
    def test_prlimit_failure_is_typed_and_no_plaintext_or_child_leak(self):
        original=subprocess.Popen;children=[]
        def launch(args,**kwargs):
            child=original(['/usr/bin/prlimit','--definitely-invalid-option'],**kwargs);children.append(child);return child
        buffers,payload=operands()
        with patch.object(s,'_recipient',return_value=b'public'),patch.object(s,'_home',return_value=None),patch.object(s.subprocess,'Popen',side_effect=launch):value=s.seal(buffers,payload,IDENTITY,time.monotonic()+2)
        self.assertEqual(value,s.unavailable('encryption-unavailable'));self.assertIsNone(s._PENDING)
        self.assertTrue(all(p.returncode is not None for p in children));self.assertNotIn('PRIVATE',json.dumps(value))
