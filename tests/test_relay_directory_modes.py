"""Real umask/descriptor/path effects; root ownership is explicitly injected."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_io as io


class RelayDirectoryModes(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]);self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.base.chmod(0o755)
        (self.base/'tools').mkdir(mode=0o755)
        self.source=self.base/'tools/native_relay.py';self.source.write_bytes(Path(io.__file__).with_name('native_relay.py').read_bytes());self.source.chmod(0o644)
        self.root=self.base/'libexec'/'dev-pair-native-io';self.digest=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.lstat=Path.lstat;self.fstat=os.fstat
        def root_info(info):
            values=list(info);values[4]=0;return os.stat_result(values)
        self.root_info=root_info
        for boundary in (patch.object(io,'__file__',str(self.base/'tools/native_io.py')),patch.object(io,'RELAY_ROOT',self.root),
                patch.object(Path,'lstat',lambda p:root_info(self.lstat(p))),patch.object(io.os,'fstat',lambda fd:root_info(self.fstat(fd)))):
            boundary.start();self.addCleanup(boundary.stop)

    def mode(self,path):return stat.S_IMODE(self.lstat(path).st_mode)

    def test_real_0077_creation_and_reuse_leave_private_paths_and_umask_unchanged(self):
        private=self.base/'private';private.mkdir(mode=0o700);fifo=private/'fifo';os.mkfifo(fifo,0o600)
        previous=os.umask(0o077)
        try:
            target,digest=io.stage_relay()
            self.assertEqual(digest,self.digest)
            for path in (self.base/'libexec',self.root,target.parent):self.assertEqual(self.mode(path),0o755)
            self.assertEqual(self.mode(target),0o444);self.assertEqual(target.read_bytes(),self.source.read_bytes())
            self.assertEqual(os.umask(0o077),0o077)
            # Existing dedicated ancestors and shared parents are never chmodded.
            with patch.object(io.os,'fchmod',side_effect=AssertionError('unexpected chmod on reuse')):
                self.assertEqual(io.stage_relay(),(target,digest))
            self.assertEqual(self.mode(private),0o700);self.assertEqual(self.mode(fifo),0o600)
            result=subprocess.run([sys.executable,'-c','import os,pathlib,sys;assert os.geteuid()!=0;assert pathlib.Path(sys.argv[1]).read_bytes()==pathlib.Path(sys.argv[2]).read_bytes();print("non-root fixture read")',str(target),str(self.source)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,b'non-root fixture read\n')
            # This child is really non-root, but shares the fixture file owner.
            # Distinct dp-maint ownership, SELinux and Fedora execution are unproved.
        finally:os.umask(previous)

    def test_existing_restrictive_shared_and_legacy_directories_block_without_chmod(self):
        (self.base/'libexec').mkdir(mode=0o700)
        with patch.object(io.os,'fchmod',side_effect=AssertionError('existing path chmod')):
            with self.assertRaisesRegex(ValueError,'traversal'):io.stage_relay()
        self.assertEqual(self.mode(self.base/'libexec'),0o700);self.assertFalse(self.root.exists())
        (self.base/'libexec').chmod(0o755);self.root.mkdir(mode=0o700)
        with patch.object(io.os,'fchmod',side_effect=AssertionError('legacy path chmod')):
            with self.assertRaisesRegex(ValueError,'traversal'):io.stage_relay()
        self.assertEqual(self.mode(self.root),0o700)

    def test_symlink_writable_foreign_owner_and_creation_failure_preserve_conflicts(self):
        (self.base/'libexec').mkdir(mode=0o755);(self.base/'libexec').chmod(0o755);foreign=self.base/'foreign';foreign.mkdir(mode=0o755);foreign.chmod(0o755)
        self.root.symlink_to(foreign)
        with self.assertRaises((ValueError,OSError)):io.stage_relay()
        self.assertTrue(self.root.is_symlink());self.assertEqual(self.mode(foreign),0o755)
        self.root.unlink();self.root.mkdir(mode=0o777);self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'Unprotected'):io.stage_relay()
        self.assertEqual(self.mode(self.root),0o777);self.root.chmod(0o755)
        def foreign_owner(fd):
            info=self.root_info(self.fstat(fd))
            if os.readlink('/proc/self/fd/'+str(fd))==str(self.root):
                values=list(info);values[4]=12345;return os.stat_result(values)
            return info
        with patch.object(io.os,'fstat',side_effect=foreign_owner),self.assertRaisesRegex(ValueError,'Unprotected'):io.stage_relay()
        self.assertFalse((self.root/self.digest).exists())
        mkdir=os.mkdir
        def fail_creation(name,*args,**kwargs):
            if name==self.digest:raise PermissionError('synthetic creation failure')
            return mkdir(name,*args,**kwargs)
        with patch.object(io.os,'mkdir',side_effect=fail_creation):
            with self.assertRaises(PermissionError):io.stage_relay()
        self.assertFalse((self.root/self.digest).exists())

    def test_inode_exchange_before_chmod_blocks_and_preserves_replacement(self):
        original=os.open;exchanged=[]
        def exchange(name,flags,*args,**kwargs):
            if name==self.digest and not exchanged:
                path=self.root/self.digest;path.rename(self.root/'saved-incomplete')
                path.mkdir(mode=0o700);exchanged.append(path)
            return original(name,flags,*args,**kwargs)
        with patch.object(io.os,'open',side_effect=exchange):
            with self.assertRaisesRegex(ValueError,'identity'):io.stage_relay()
        self.assertEqual(self.mode(exchanged[0]),0o700)
        self.assertFalse((exchanged[0]/'relay.py').exists());self.assertTrue((self.root/'saved-incomplete').is_dir())

    def test_interrupted_mode_creation_leaves_incomplete_directory_blocked_on_reapply(self):
        (self.base/'libexec').mkdir(mode=0o755);(self.base/'libexec').chmod(0o755);self.root.mkdir(mode=0o755);self.root.chmod(0o755)
        before=len(os.listdir('/proc/self/fd'));previous=os.umask(0o077)
        try:
            with patch.object(io.os,'fchmod',side_effect=OSError('synthetic mode failure')):
                with self.assertRaises(OSError):io.stage_relay()
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
            self.assertEqual(self.mode(self.root/self.digest),0o700)
            with self.assertRaisesRegex(ValueError,'traversal'):io.stage_relay()
            self.assertFalse((self.root/self.digest/'relay.py').exists())
        finally:os.umask(previous)

    def test_file_symlink_and_hardlink_conflicts_remain_rejected(self):
        target,digest=io.stage_relay();foreign=self.base/'foreign-file';target.rename(foreign);target.symlink_to(foreign)
        with self.assertRaises(OSError):io.stage_relay()
        self.assertTrue(target.is_symlink());self.assertEqual(foreign.read_bytes(),self.source.read_bytes())
        target.unlink();os.link(foreign,target)
        with self.assertRaisesRegex(ValueError,'collision'):io.stage_relay()
        self.assertEqual(target.stat().st_nlink,2);self.assertEqual(foreign.read_bytes(),self.source.read_bytes())


if __name__=='__main__':unittest.main()
