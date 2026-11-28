"""Real owned processes/locks; pinned stock and namespace are not invoked."""
import copy
import fcntl
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import session_helper as h


class OwnedHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.binary=self.root/'immutable-python'
        shutil.copyfile(os.readlink('/proc/self/exe'),self.binary);self.binary.chmod(0o500)
        self.aliases=self.root/'arg0-linux';self.aliases.mkdir(mode=0o700)
        self.directory=self.aliases/'codex-arg0ABC123';self.directory.mkdir(mode=0o700)
        for name in ('apply_patch','applypatch','codex-linux-sandbox'):(self.directory/name).symlink_to(self.binary)
        self.children=[]
        self.addCleanup(self.stop)
    def stop(self):
        for child in self.children:
            if child.poll() is None:child.kill()
            child.wait(timeout=2)
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream:stream.close()
    def start(self,locked=True):
        script='import os,fcntl,sys;fd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600);'+('fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);' if locked else '')+'print("ready",flush=True);'+('sys.stdin.readline();fcntl.flock(fd,fcntl.LOCK_UN);print("unlocked",flush=True);' if getattr(self,'release_on_line',False) else '')+'sys.stdin.read()'
        child=subprocess.Popen([str(self.binary),'-c',script,str(self.directory/'.lock')],env=dict(os.environ,PYTHONHOME=sys.base_prefix,PYTHONPATH=''),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        self.children.append(child);selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
        try:self.assertTrue(selector.select(3));self.assertEqual(child.stdout.readline(),b'ready\n')
        finally:selector.close()
        return child
    def observer(self,child):
        owned=h.OwnedChild(child,time.monotonic()+5,self.binary,self.aliases);self.addCleanup(owned.close);return owned
    def test_actual_child_exclusive_lock_binary_and_alias_binding(self):
        child=self.start();owned=self.observer(child);before=len(os.listdir('/proc/self/fd'))
        state=owned.capture();self.assertEqual(state['path'],str(self.directory));self.assertEqual(owned.capture(),state)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        self.assertEqual(state['start'][0],child.pid)
    def test_missing_foreign_lock_and_dead_or_wrong_start_block(self):
        child=self.start(False);owned=self.observer(child)
        with self.assertRaises(ValueError):owned.capture()
        child.kill();child.wait(timeout=2)
        with self.assertRaises(ValueError):owned.capture()
        locked=self.start();observed=self.observer(locked);observed.start=(locked.pid,observed.start[1]+1)
        with self.assertRaises(ValueError):observed.capture()
        foreign=self.start(False);foreign_owned=self.observer(foreign)
        with self.assertRaises(ValueError):foreign_owned.capture()
    def test_wrong_alias_extra_child_replaced_inode_and_executable_block(self):
        owned=self.observer(self.start());self.assertTrue(owned.capture())
        alias=self.directory/'apply_patch';alias.unlink();alias.symlink_to('/PRIVATE_WRONG_BINARY')
        with self.assertRaises(ValueError):owned.capture()
        alias.unlink();alias.symlink_to(self.binary)
        extra=self.directory/'PRIVATE_EXTRA';extra.write_text('private')
        with self.assertRaises(ValueError):owned.capture()
        extra.unlink();wrong=self.root/'wrong';shutil.copyfile(self.binary,wrong);wrong.chmod(0o500)
        owned.binary=wrong
        with self.assertRaises(ValueError):owned.capture()
        owned.binary=self.binary;self.assertTrue(owned.capture())
        lock=self.directory/'.lock';lock.rename(self.directory/'old-lock');lock.touch(mode=0o600)
        with self.assertRaises(ValueError):owned.capture()
    def test_symlink_parent_and_lock_release_during_inspection_block(self):
        owned=self.observer(self.start());original=os.readlink
        def change(name,*args,**kwargs):
            result=original(name,*args,**kwargs)
            if name=='applypatch':
                self.directory.rename(self.aliases/'saved');self.directory.symlink_to(self.aliases/'saved')
            return result
        with patch.object(h.os,'readlink',side_effect=change),self.assertRaises(ValueError):owned.capture()

    def test_actual_unlock_with_open_descriptor_and_foreign_owner_still_block(self):
        self.release_on_line=True;child=self.start();owned=self.observer(child);original=os.readlink;released=[]
        def unlock(name,*args,**kwargs):
            result=original(name,*args,**kwargs)
            if name=='apply_patch' and not released:
                released.append(True);child.stdin.write(b'unlock\n');child.stdin.flush()
                selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
                try:self.assertTrue(selector.select(2));self.assertEqual(child.stdout.readline(),b'unlocked\n')
                finally:selector.close()
            return result
        with patch.object(h.os,'readlink',side_effect=unlock),self.assertRaises(ValueError):owned.capture()
        real=os.stat
        def foreign(name,*args,**kwargs):
            info=real(name,*args,**kwargs)
            if name=='.lock':
                fields=list(info);fields[4]=12345;return os.stat_result(fields)
            return info
        with patch.object(h.os,'stat',side_effect=foreign),self.assertRaises(ValueError):owned.capture()


if __name__=='__main__':unittest.main()
