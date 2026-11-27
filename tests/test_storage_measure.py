"""Real allocated-block GNUdu differential; descriptor and caller failures closed."""
from contextlib import redirect_stdout
import ctypes
import errno
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, Mock, call, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import storage_measure as worker
import fedora_ci as ci
from test_fedora_ci import worker_result

class MeasurementTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def expected(self):return worker.identity(self.root.stat())
    def oracle(self):
        p=subprocess.run(['/usr/bin/du','--summarize','--block-size=1','--one-file-system','--exclude=guest.qcow2',str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
        self.assertEqual(p.returncode,0,p.stderr.decode());return int(p.stdout.split()[0])
    def test_actual_sparse_allocated_hardlink_symlink_directories_and_exact_exclusion(self):
        (self.root/'empty').touch();(self.root/'sparse').touch()
        with open(self.root/'sparse','r+b') as f:f.truncate(8*1024**2)
        (self.root/'allocated').write_bytes(b'x'*131072);os.link(self.root/'allocated',self.root/'hardlink')
        (self.root/'link').symlink_to('/dev/shm');(self.root/'dangling').symlink_to('/not-followed-synthetic')
        deep=self.root
        for i in range(8):deep=deep/('deep-'+str(i));deep.mkdir()
        (deep/'data').write_bytes(b'x'*123);(deep/'guest.qcow2').write_bytes(b'x'*65536);(self.root/'guest.qcow2').write_bytes(b'x'*65536)
        result=worker.scan(self.root,self.expected());self.assertEqual(result['status'],'complete');self.assertEqual(result['allocated_bytes'],self.oracle())
        actual=ci.measure_storage(self.root,sudo=False);self.assertFalse(actual['provisional']);self.assertEqual(actual['bytes'],self.oracle())

    def isolated_mount_scan(self, fixture, mounts, check, *, backing=None, remount=False):
        sandbox=shutil.which('bwrap')
        if sandbox is None:self.skipTest('bubblewrap is unavailable')
        base=[sandbox,'--unshare-user','--uid','0','--gid','0','--unshare-pid','--unshare-net','--ro-bind','/','/']
        if remount:base.extend(('--cap-add','CAP_SYS_ADMIN'))
        probe=subprocess.run([*base,'--','/usr/bin/true'],capture_output=True,text=True,timeout=5)
        if probe.returncode and ('namespace' in probe.stderr or 'Operation not permitted' in probe.stderr):
            self.skipTest('private mount namespace is unavailable')
        self.assertEqual(probe.returncode,0,probe.stderr)
        source=textwrap.dedent('''
            from contextlib import redirect_stdout
            from io import StringIO
            import os
            from pathlib import Path
            import subprocess
            import sys
            from unittest.mock import patch

            sys.path.insert(0,sys.argv[1])
            import storage_measure as worker
            import fedora_ci as ci

            root=Path(sys.argv[2])
            expected=worker.identity(root.stat())
            scandir=os.scandir

            def check_failure(reason):
                sha=ci.file_hash(Path(worker.__file__))
                argv=[worker.__file__,'--root',str(root),'--sha256',sha]
                for key,value in expected.items():
                    argv.extend(('--'+key,str(value)))
                output=StringIO()
                with patch.object(sys,'argv',argv),redirect_stdout(output):
                    code=worker.main()
                assert code==2, (code,output.getvalue())
                result=subprocess.CompletedProcess([],code,output.getvalue().encode(),b'')
                try:ci.parse_storage(root,result,expected,sha)
                except ci.StorageMeasurementBlocked as error:
                    projected=error.diagnostics['worker']
                    assert projected['status']=='failed' and projected['allocated_bytes'] is None, projected
                    assert projected['reason']==reason, projected
                else:raise AssertionError('mount failure yielded a usable sample')
        ''')+textwrap.dedent(check)
        argv=[*base,'--bind',str(backing or fixture),str(fixture),*map(str,mounts),'--proc','/proc','--dev','/dev','--',
              sys.executable,'-I','-c',source,str(Path(worker.__file__).resolve().parent),str(self.root)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def tmpfs_backing(self):
        if not Path('/dev/shm').is_dir():self.skipTest('tmpfs fixture is unavailable')
        fs_type=subprocess.check_output(['/usr/bin/stat','-f','-c','%t','/dev/shm'],timeout=3).strip()
        if fs_type!=b'1021994':self.skipTest('the fixture requires tmpfs at /dev/shm')
        backing=tempfile.TemporaryDirectory(dir='/dev/shm',prefix='dp-storage-selfbind-')
        self.addCleanup(backing.cleanup)
        return Path(backing.name)

    def test_actual_mount_namespace_matches_gnu_du_for_owned_alias_cycle_and_foreign_mounts(self):
        # Include both kernel-escaped and literal mountinfo path characters.
        source=self.root/'source space\\name\n\t\r\v\f'
        source.mkdir()
        (source/'single').write_bytes(b'x'*8192)
        hard=source/'hard';hard.write_bytes(b'x'*16384);os.link(hard,source/'hard-alias')
        (source/'payload-link').symlink_to('/dev/shm')
        alias=self.root/'sibling alias\r\v\f';alias.mkdir()
        single_alias=self.root/'single alias';single_alias.touch()
        cycle=self.root/'ancestor-cycle';cycle.mkdir()
        foreign=self.root/'foreign-dir';foreign.mkdir()
        foreign_file=self.root/'foreign-file';foreign_file.touch()
        if not Path('/dev/shm').is_dir():self.skipTest('a second filesystem is needed')
        with tempfile.TemporaryDirectory(dir='/dev/shm',prefix='dp-storage-oracle-') as foreign_fixture:
            file=Path(foreign_fixture)/'data';file.write_bytes(b'x'*32768)
            if file.stat().st_dev==self.root.stat().st_dev:self.skipTest('a second filesystem is needed')
            self.isolated_mount_scan(self.root,
                ['--bind',source,alias,'--bind',source/'single',single_alias,
                 '--bind',self.root,cycle,'--tmpfs',foreign,'--bind',file,foreign_file],
                '''
                (root/'foreign-dir'/'data').write_bytes(b'x'*32768)
                assert (root/'foreign-file').stat().st_dev != expected['device']
                assert (root/'sibling alias\\r\\v\\f').stat().st_ino == (root/'source space\\\\name\\n\\t\\r\\v\\f').stat().st_ino
                assert (root/'ancestor-cycle').stat().st_ino == expected['inode']
                def same_device_only(fd):
                    assert os.fstat(fd).st_dev == expected['device']
                    return scandir(fd)
                with patch.object(worker.os,'scandir',side_effect=same_device_only):
                    measured=worker.scan(root,expected)
                native=subprocess.run(['/usr/bin/du','--summarize','--block-size=1','--one-file-system',
                    '--exclude=guest.qcow2',root],capture_output=True,check=True,timeout=3)
                assert not native.stderr, native.stderr
                assert measured['status']=='complete', measured
                assert measured['allocated_bytes']==int(native.stdout.split()[0]), (measured,native.stdout)
                real_open=open
                def missing_mountinfo(path,*args,**kwargs):
                    if path=='/proc/self/mountinfo':raise FileNotFoundError(path)
                    return real_open(path,*args,**kwargs)
                with patch('builtins.open',side_effect=missing_mountinfo):
                    check_failure('mountinfo-unavailable')
                ''')

    def test_same_device_mount_source_must_remain_inside_owned_scratch(self):
        fixture=self.root
        self.root=fixture/'scratch';self.root.mkdir()
        mounted=self.root/'mounted';mounted.mkdir()
        external=fixture/'outside';external.mkdir()
        (external/'do-not-enumerate').write_bytes(b'x'*8192)
        self.isolated_mount_scan(fixture,['--bind',external,mounted],'''
            def owned_only(fd):
                assert os.fstat(fd).st_ino != (root/'mounted').stat().st_ino
                return scandir(fd)
            with patch.object(worker.os,'scandir',side_effect=owned_only):
                check_failure('bind-source-outside-root')
            ''')

    def test_actual_tmpfs_self_bind_and_alias_match_gnu_du_with_bounded_witnesses(self):
        backing=self.tmpfs_backing()
        source=backing/'internal';source.mkdir()
        (backing/'mounted').mkdir()
        (source/'single').write_bytes(b'x'*8192)
        hard=source/'hard';hard.write_bytes(b'x'*16384);os.link(hard,source/'hard-alias')
        (source/'guest.qcow2').write_bytes(b'x'*32768)
        self.isolated_mount_scan(self.root,
            ['--bind',source,self.root/'internal','--bind',source,self.root/'mounted'],'''
            from contextlib import contextmanager
            import ctypes
            import errno
            from types import SimpleNamespace

            root_fd=os.open(root,os.O_PATH)
            try:
                try:worker._node(root_fd,'internal')
                except OSError as error:assert error.errno==errno.EXDEV, error
                else:raise AssertionError('canonical source did not cross a mount')
            finally:os.close(root_fd)

            measured=worker.scan(root,expected)
            native=subprocess.run(['/usr/bin/du','--summarize','--block-size=1','--one-file-system',
                '--exclude=guest.qcow2',root],capture_output=True,check=True,timeout=3)
            assert not native.stderr, native.stderr
            assert measured['status']=='complete', measured
            assert measured['allocated_bytes']==int(native.stdout.split()[0])>0, (measured,native.stdout)
            sample=ci.measure_storage(root,sudo=False)
            assert not sample['provisional'] and sample['bytes']==measured['allocated_bytes'], sample

            try:worker.scan(root,expected,entry_limit=1)
            except worker.ScanError as error:
                assert str(error)=='entry-limit', error
                assert error.scan_counters=={'entries':2,'unique_inodes':1,'vanished':0}, error.scan_counters
            else:raise AssertionError('witness failed to consume an entry')

            calls=0
            def expire_on_witness(fd):
                global calls
                calls+=1
                if calls==2:
                    assert Path(os.readlink(f'/proc/self/fd/{fd}'))==root
                return scandir(fd)
            with patch.object(worker.os,'scandir',side_effect=expire_on_witness), \\
                 patch.object(worker.time,'monotonic',side_effect=lambda: 10 if calls>=2 else 1):
                try:worker.scan(root,expected,end=10)
                except worker.ScanError as error:assert str(error)=='deadline', error
                else:raise AssertionError('witness escaped the deadline')
            assert calls==2, calls

            @contextmanager
            def wrong_covered_inode(fd):
                with scandir(fd) as entries:
                    yield (SimpleNamespace(name=entry.name,inode=lambda: expected['inode'])
                           if entry.name=='internal' else entry for entry in entries)
            with patch.object(worker.os,'scandir',side_effect=wrong_covered_inode):
                check_failure('bind-source-before-identity')

            for magic,reason in ((0x794c7630,'bind-source-before-exdev-overlay'),
                                 (0x9123683e,'bind-source-before-exdev-filesystem')):
                def unsupported_parent(fd,buffer):
                    assert Path(os.readlink(f'/proc/self/fd/{fd}'))==root
                    ctypes.cast(buffer,ctypes.POINTER(ctypes.c_long))[0]=magic
                    return 0
                with patch.object(worker.LIBC,'fstatfs',side_effect=unsupported_parent):
                    check_failure(reason)
            ''',backing=backing)

    def test_actual_tmpfs_regular_file_self_bind_fails_with_regular_reason(self):
        backing=self.tmpfs_backing()
        source=backing/'regular';source.write_bytes(b'x'*8192)
        self.isolated_mount_scan(self.root,['--bind',source,self.root/'regular'],'''
            check_failure('bind-source-before-exdev-regular')
            ''',backing=backing)

    def test_actual_canonical_source_overbind_and_parent_mount_are_rejected(self):
        for overbind in (True,False):
            with self.subTest(overbind=overbind):
                backing=self.tmpfs_backing()
                (backing/'parent').mkdir();(backing/'parent'/'internal').mkdir()
                (backing/'mounted').mkdir();(backing/'replacement').mkdir()
                mounts=['--bind',backing/'parent'/'internal',self.root/'mounted']
                if overbind:
                    mounts+=['--bind',backing/'replacement',self.root/'parent'/'internal']
                    reason='bind-source-before-identity'
                else:
                    mounts+=['--bind',backing/'parent',self.root/'parent']
                    reason='bind-source-before-exdev-parent-open'
                self.isolated_mount_scan(self.root,mounts,'''
                    def never_enumerate_alias(fd):
                        assert Path(os.readlink(f'/proc/self/fd/{fd}'))!=root/'mounted'
                        return scandir(fd)
                    with patch.object(worker.os,'scandir',side_effect=never_enumerate_alias):
                        check_failure(REASON)
                    '''.replace('REASON',repr(reason)),backing=backing)

    def test_actual_canonical_self_bind_replaced_during_alias_enumeration_has_no_total(self):
        backing=self.tmpfs_backing()
        source=backing/'internal';source.mkdir();(source/'data').write_bytes(b'x'*8192)
        (backing/'mounted').mkdir()
        self.isolated_mount_scan(self.root,
            ['--bind',source,self.root/'internal','--bind',source,self.root/'mounted'],'''
            import ctypes

            libc=ctypes.CDLL(None,use_errno=True)
            exchanged=False
            def remount_source(fd):
                global exchanged
                if not exchanged and Path(os.readlink(f'/proc/self/fd/{fd}'))==root/'mounted':
                    source=root/'internal'
                    old_fd=os.open(source,os.O_PATH)
                    try:
                        assert libc.umount2(bytes(source),2)==0, ctypes.get_errno()  # MNT_DETACH
                        assert libc.mount(bytes(source),bytes(source),None,4096,None)==0, ctypes.get_errno()  # MS_BIND
                        new_fd=os.open(source,os.O_PATH)
                        try:
                            assert os.fstat(old_fd).st_ino==os.fstat(new_fd).st_ino
                            assert worker._mount_id(old_fd)!=worker._mount_id(new_fd)
                        finally:os.close(new_fd)
                    finally:os.close(old_fd)
                    exchanged=True
                return scandir(fd)
            with patch.object(worker.os,'scandir',side_effect=remount_source):
                check_failure('bind-source-after-identity')
                assert exchanged
            ''',backing=backing,remount=True)

    def test_bind_source_replacement_during_enumeration_invalidates_measurement(self):
        source=self.root/'internal';source.mkdir()
        (source/'data').write_bytes(b'x'*8192)
        alias=self.root/'mounted';alias.mkdir()
        self.isolated_mount_scan(self.root,['--bind',source,alias],'''
            exchanged=False
            def replace_source(fd):
                global exchanged
                if not exchanged and Path(os.readlink(f'/proc/self/fd/{fd}'))==root/'mounted':
                    (root/'internal').rename(root/'renamed')
                    (root/'internal').mkdir()
                    exchanged=True
                return scandir(fd)
            with patch.object(worker.os,'scandir',side_effect=replace_source):
                check_failure('bind-source-after-identity')
                assert exchanged
            ''')

    def test_bind_mountpoint_disappearance_at_final_reopen_denies_a_usable_sample(self):
        source=self.root/'internal';source.mkdir()
        (source/'data').write_bytes(b'x'*8192)
        alias=self.root/'mounted';alias.mkdir()
        self.isolated_mount_scan(self.root,['--bind',source,alias],'''
            import errno

            open_node=worker._node
            mounted_enumerated=False
            def observe_mount(fd):
                global mounted_enumerated
                if Path(os.readlink(f'/proc/self/fd/{fd}')) == root/'mounted':
                    mounted_enumerated=True
                return scandir(fd)
            def disappear_on_reopen(parent,name,*,same_mount=True):
                if mounted_enumerated and name=='mounted' and not same_mount:
                    raise FileNotFoundError(errno.ENOENT,'synthetic late mountpoint disappearance')
                return open_node(parent,name,same_mount=same_mount)
            with patch.object(worker.os,'scandir',side_effect=observe_mount), \\
                 patch.object(worker,'_node',side_effect=disappear_on_reopen):
                check_failure('entry-reopen-missing')
                assert mounted_enumerated
            ''')

    def test_controlled_file_churn_never_becomes_a_stable_final_claim(self):
        tree=self.root/'files';tree.mkdir()
        for i in range(1000):(tree/str(i)).touch()
        stop=threading.Event()
        def churn():
            while not stop.is_set():
                for p in tree.iterdir():
                    if stop.is_set():break
                    try:p.unlink();p.touch()
                    except FileNotFoundError:pass
        thread=threading.Thread(target=churn);thread.start()
        try:
            try:
                observed=ci.measure_storage(self.root,live=True,sudo=False);self.assertGreater(observed['bytes'],0)
            except ci.StorageMeasurementBlocked as error:self.assertIn(error.diagnostics.get('worker',{}).get('reason'),('identity-changed','enumeration-disappeared'))
        finally:stop.set();thread.join(timeout=3);self.assertFalse(thread.is_alive())
        self.assertEqual(ci.measure_storage(self.root,sudo=False)['bytes'],self.oracle())
    def test_root_replacement_and_every_guard_produce_no_accepted_total(self):
        expected=self.expected();(self.root/'file').write_bytes(b'x')
        for kwargs,reason in (({'entry_limit':0},'entry-limit'),({'inode_limit':0},'inode-limit'),({'end':time.monotonic()-1},'deadline')):
            with self.subTest(reason=reason),self.assertRaisesRegex(worker.ScanError,reason):worker.scan(self.root,expected,**kwargs)
        child=self.root/'directory';child.mkdir()
        with self.assertRaisesRegex(worker.ScanError,'depth-limit'):worker.scan(self.root,expected,depth_limit=0)
        with self.assertRaisesRegex(worker.ScanError,'root-identity'):worker.scan(self.root,{**expected,'inode':expected['inode']+1})
        original=worker.os.stat;changed=False
        def replaced(name,*args,**kwargs):
            nonlocal changed
            if name=='directory' and kwargs.get('dir_fd') is not None and not changed:changed=True;child.rename(self.root/'moved');child.mkdir()
            return original(name,*args,**kwargs)
        with patch.object(worker.os,'stat',side_effect=replaced),self.assertRaisesRegex(worker.ScanError,'identity-changed'):worker.scan(self.root,expected)
        child_ino=child.stat().st_ino
        scandir=os.scandir
        def replaced_after_open(fd):
            if os.fstat(fd).st_ino==child_ino:
                child.rename(self.root/'moved-again')
                child.mkdir()
            return scandir(fd)
        with patch.object(worker.os,'scandir',side_effect=replaced_after_open),self.assertRaisesRegex(worker.ScanError,'identity-changed'):
            worker.scan(self.root,expected)
    def test_only_descendant_enoent_allows_a_provisional_sample(self):
        (self.root/'file').touch()
        for number in (errno.EACCES,errno.EPERM,errno.EIO,errno.ELOOP):
            with patch.object(worker,'_node',side_effect=OSError(number,'synthetic')),self.assertRaises(OSError):worker.scan(self.root,self.expected())
        with patch.object(worker,'_node',side_effect=FileNotFoundError(errno.ENOENT,'synthetic')):
            result=worker.scan(self.root,self.expected());self.assertEqual(result['status'],'provisional');self.assertGreater(result['allocated_bytes'],0)

    def test_entry_resolution_and_reopen_exdev_report_distinct_failures(self):
        entry=self.root/'directory';entry.mkdir();(entry/'file').touch()
        expected=self.expected();sha=ci.file_hash(Path(worker.__file__))
        argv=[worker.__file__,'--root',str(self.root),'--sha256',sha]
        for key,value in expected.items():
            argv.extend(('--'+key,str(value)))
        open_node=worker._node
        cases=(
            ('entry-resolve-exdev',(1,2),[True,False],1),
            ('entry-reopen-exdev',(2,),[True,True],2),
        )
        for reason,reject_attempts,expected_attempts,entries in cases:
            attempts=[]
            def reject_entry(parent,name,*,same_mount=True):
                if name==entry.name:
                    attempts.append(same_mount)
                    if len(attempts) in reject_attempts:
                        raise OSError(errno.EXDEV,'synthetic entry boundary')
                return open_node(parent,name,same_mount=same_mount)

            with self.subTest(reason=reason):
                output=StringIO()
                with patch.object(worker,'_node',side_effect=reject_entry),patch.object(sys,'argv',argv),redirect_stdout(output):
                    code=worker.main()
                self.assertEqual(attempts,expected_attempts)
                self.assertEqual(code,2)
                result=subprocess.CompletedProcess([],code,output.getvalue().encode(),b'')
                with self.assertRaises(ci.StorageMeasurementBlocked) as caught:
                    ci.parse_storage(self.root,result,expected,sha)
                projected=caught.exception.diagnostics['worker']
                self.assertEqual(projected['status'],'failed')
                self.assertIsNone(projected['allocated_bytes'])
                self.assertEqual(projected['counters']['entries'],entries)
                self.assertEqual(projected['reason'],reason)

    def test_strict_source_exdev_classification_does_not_open_fallback(self):
        for kind,source,reason in (
            (stat.S_IFREG,Path('.'),'bind-source-before-exdev-regular'),
            (stat.S_IFLNK,Path('leaf'),'bind-source-before-exdev-nondirectory'),
            (stat.S_IFDIR,Path('.'),'bind-source-before-exdev-empty-name'),
            (stat.S_IFDIR,Path('leaf'),None),
        ):
            for after in (False,True) if reason is not None else (True,):
                with self.subTest(kind=kind,source=source,after=after):
                    exdev=OSError(errno.EXDEV,'synthetic strict open')
                    expected='bind-source-after-exdev' if after else reason
                    with (patch.object(worker,'_node',side_effect=exdev) as node,
                          patch.object(worker,'_open_source_self_bind') as fallback,
                          self.assertRaises(worker.ScanError) as failure):
                        worker._verify_bind_source(11,b'1',source,(1,2,kind),self.fail,self.fail,after=after)
                    self.assertEqual(str(failure.exception),expected)
                    node.assert_called_once_with(11,source)
                    fallback.assert_not_called()

    def test_self_bind_exdev_classification_preserves_operation_sequence(self):
        source=Path('parent/leaf')
        strict=[call.node(11,source),call.node(11,source.parent)]
        parent_stat=[call.fstat(12)]
        filesystem=[call.mount_id(12),call.fstatfs(12,ANY)]
        leaf_open=[call.node(12,source.name,same_mount=False)]
        parent_close=[call.close(12)]
        cases=(
            ('parent-open',strict),
            ('parent-identity',strict+parent_stat+parent_close),
            ('overlay',strict+parent_stat+filesystem+parent_close),
            ('leaf-open',strict+parent_stat+filesystem+leaf_open+parent_close),
            ('leaf-mount',strict+parent_stat+filesystem+leaf_open+
             [call.fstat(13),call.mount_id(13),call.close(13)]+parent_close),
            ('',strict+parent_stat+filesystem+parent_close),
        )
        for branch,operations in cases:
            for after in (False,True):
                with self.subTest(branch=branch,after=after):
                    exdev=OSError(errno.EXDEV,'synthetic fallback operation')
                    trace=Mock()
                    trace.node.side_effect=[exdev,exdev if branch=='parent-open' else 12,
                                            exdev if branch=='leaf-open' else 13]
                    parent=SimpleNamespace(st_dev=6 if branch=='parent-identity' else 1,st_mode=stat.S_IFDIR)
                    leaf=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFDIR)
                    trace.fstat.side_effect={12:parent,13:leaf}.__getitem__
                    trace.mount_id.return_value=b'1'

                    def fstatfs(fd,buffer):
                        if not branch:raise exdev
                        magic=0x794c7630 if branch=='overlay' else 0x01021994
                        ctypes.cast(buffer,ctypes.POINTER(ctypes.c_long))[0]=magic
                        return 0

                    trace.fstatfs.side_effect=fstatfs
                    reason='bind-source-after-exdev' if after else 'bind-source-before-exdev'
                    if not after and branch:reason+='-'+branch
                    with (patch.object(worker,'_node',trace.node),patch.object(worker.os,'fstat',trace.fstat),
                          patch.object(worker,'_mount_id',trace.mount_id),patch.object(worker.LIBC,'fstatfs',trace.fstatfs),
                          patch.object(worker.os,'close',trace.close),self.assertRaises(worker.ScanError) as failure):
                        worker._verify_bind_source(11,b'1',source,(1,2,stat.S_IFDIR),self.fail,self.fail,
                                                   after=after,source_pin=14 if after else None)
                    self.assertEqual(str(failure.exception),reason)
                    self.assertEqual(trace.mock_calls,operations)

    def test_parser_no_total_is_never_a_usable_integer_and_typed_failure_survives(self):
        expected=self.expected();sha=ci.file_hash(Path(worker.__file__))
        for kind in ('integer-no-total','wrong-root','wrong-source','extra','bool-size','signal','partial','unknown-failure'):
            value=json.loads(worker_result(self.root).stdout);code=0
            if kind=='integer-no-total':value.update(status='no-total',reason='none');code=1
            if kind=='wrong-root':value['root']['inode']+=1
            if kind=='wrong-source':value['worker_sha256']='0'*64
            if kind=='extra':value['PRIVATE']='sensitive'
            if kind=='bool-size':value['allocated_bytes']=False
            if kind=='signal':code=-6
            if kind=='partial':value={'schema':1}
            if kind=='unknown-failure':value.update(status='failed',reason='PRIVATE',allocated_bytes=None);code=2
            with self.subTest(kind=kind),self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.parse_storage(self.root,subprocess.CompletedProcess([],code,json.dumps(value).encode(),b''),expected,sha)
            self.assertNotIn('PRIVATE',json.dumps(seen.exception.diagnostics));self.assertNotIn('worker',seen.exception.diagnostics)
        value=json.loads(worker_result(self.root).stdout);value.update(status='failed',allocated_bytes=None)
        for reason in worker.REASONS:
            if reason=='none':continue
            value['reason']=reason
            result=subprocess.CompletedProcess([],2,json.dumps(value).encode(),b'')
            with self.subTest(reason=reason):
                with self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.parse_storage(self.root,result,expected,sha)
                self.assertEqual(seen.exception.diagnostics['worker'],value)
    def test_enumeration_disappearance_has_no_total_not_zero(self):
        class Missing:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __next__(self):raise FileNotFoundError(errno.ENOENT,'synthetic')
        with patch.object(worker.os,'scandir',return_value=Missing()):value=worker.scan(self.root,self.expected())
        self.assertIsNone(value['allocated_bytes']);self.assertEqual(value['status'],'no-total')
    def test_fixed_source_limits_and_measurement_cannot_clear_image_copy_latch(self):
        probe=ci.Probe('a'*40,self.root);probe.image_copy_active=True
        value=worker_result(self.root,ci.OVERHEAD_LIMIT-ci.fedora_oci.UNLINKED_RESERVE)
        with patch.object(ci,'capture_du',return_value=value):self.assertEqual(probe.storage_measurement()['unlinked_spool_reserve_bytes'],ci.fedora_oci.UNLINKED_RESERVE)
        self.assertTrue(probe.image_copy_active)
        with patch.object(ci,'capture_du',return_value=worker_result(self.root,ci.OVERHEAD_LIMIT-ci.fedora_oci.UNLINKED_RESERVE+512)),self.assertRaises(ci.Blocked):probe.storage_measurement()
        self.assertTrue(probe.image_copy_active)
        with patch.object(ci,'capture_du',return_value=subprocess.CompletedProcess([],-6,b'',b'PRIVATE')),self.assertRaises(ci.StorageMeasurementBlocked):probe.storage_measurement()
        self.assertTrue(probe.image_copy_active);self.assertNotIn('PRIVATE',json.dumps(probe.report))

    def test_root_disappearance_replacement_and_small_protocol_limit(self):
        expected=self.expected();(self.root/'entry').touch();original=worker._node;moved=self.root.with_name(self.root.name+'-held')
        def replace(fd,name):
            if self.root.exists():self.root.rename(moved);self.root.mkdir()
            return original(fd,name)
        try:
            with patch.object(worker,'_node',side_effect=replace),self.assertRaisesRegex(worker.ScanError,'root-identity'):worker.scan(self.root,expected)
        finally:self.root.rmdir();moved.rename(self.root)
        value=worker_result(self.root);value.stdout=b' '*2049+value.stdout
        with self.assertRaises(ci.StorageMeasurementBlocked):ci.parse_storage(self.root,value,expected,ci.file_hash(Path(worker.__file__)))
        absent=self.root/'absent'
        with self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.measure_storage(absent,sudo=False)
        self.assertEqual(seen.exception.diagnostics['availability'],'not-launched')
    def test_real_sigabrt_and_short_test_timeout_never_supply_a_total_or_core_file(self):
        for code,timeout in (('import os;os.abort()',None),('import time;time.sleep(3)',.1)):
            argv=['/usr/bin/prlimit','--core=0:0','--',sys.executable,'-I','-c',code]
            if timeout is not None:argv=['/usr/bin/timeout','--signal=TERM','--kill-after=1s',str(timeout)+'s',*argv]
            result=ci.capture_du(self.root,argv)
            self.assertNotEqual(result.returncode,0)
            with self.assertRaises(ci.StorageMeasurementBlocked) as seen:ci.parse_storage(self.root,result,self.expected(),ci.file_hash(Path(worker.__file__)))
            self.assertNotIn('worker',seen.exception.diagnostics)
        self.assertEqual(list(self.root.iterdir()),[])
    def test_no_read_of_fifo_and_file_symlink_swap_never_follows_target(self):
        os.mkfifo(self.root/'fifo');self.assertEqual(worker.scan(self.root,self.expected())['allocated_bytes'],self.oracle())
        file=self.root/'regular';file.write_bytes(b'x'*4096);original=worker.os.stat;changed=False
        def swapped(name,*args,**kwargs):
            nonlocal changed
            if name=='regular' and kwargs.get('dir_fd') is not None and not changed:changed=True;file.unlink();file.symlink_to('/dev/shm')
            return original(name,*args,**kwargs)
        with patch.object(worker.os,'stat',side_effect=swapped),self.assertRaisesRegex(worker.ScanError,'identity-changed'):worker.scan(self.root,self.expected())
