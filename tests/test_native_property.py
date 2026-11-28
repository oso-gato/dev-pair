"""Independent v259-readable property fixtures and actual local FD/process checks."""
import copy
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import io
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_relay as r

UNIT='dev-pair-initialize-prepare-12345678-90abcdef.service'
OBJECT='/org/freedesktop/systemd1/unit/dev_2dpair_2dtest_2eservice'
# Independently transcribed from the audited v259 readable vtables, not from
# expected_profile()/PROFILE_PROPERTIES. File setters deliberately do not exist.
UNIT_FIXTURE=[('Id','s',UNIT),('Transient','b',True),('LoadState','s','loaded'),('ActiveState','s','active'),
              ('FragmentPath','s','/run/systemd/transient/'+UNIT),('SourcePath','s',''),
              ('DropInPaths','as',['/run/systemd/system/'+UNIT+'.d/10-timeout-abort.conf'])]
SERVICE_FIXTURE=[('Type','s','exec'),('Restart','s','no'),('MainPID','u',1),('ControlGroup','s','/system.slice/'+UNIT),('Slice','s','system.slice'),
                 ('User','s',''),('Group','s',''),('TimeoutStartUSec','t',1000000),('TimeoutStopUSec','t',5000000),('RuntimeMaxUSec','t',5000000),
                 ('TimeoutStartFailureMode','s','kill'),('TimeoutStopFailureMode','s','kill'),('KillMode','s','control-group'),('SendSIGKILL','b',True),
                 ('FinalKillSignal','i',9),('LimitCORE','t',0),('MemoryMax','t',2147483648),('TasksMax','t',512),('CPUQuotaPerSecUSec','t',1000000),
                 ('StandardInput','s','null'),('StandardOutput','s','file'),('StandardError','s','file'),('SELinuxContext','(bs)',[False,'']),
                 ('RootDirectory','s',''),('RootImage','s',''),('PrivateUsers','b',False),('PrivateNetwork','b',False),('NoNewPrivileges','b',False)]


def encoded(rows):
    return b''.join(json.dumps({'type':signature,'data':value},separators=(',',':')).encode()+b'\n' for name,signature,value in rows)


class TypedProperty(unittest.TestCase):
    def test_audited_interfaces_signatures_and_message_vs_property_shapes(self):
        self.assertEqual(r.UNIT_SCHEMA,tuple((name,sig) for name,sig,value in UNIT_FIXTURE))
        self.assertEqual(r.SERVICE_SCHEMA,tuple((name,sig) for name,sig,value in SERVICE_FIXTURE))
        self.assertEqual(len(r.PROFILE_PROPERTIES),35)
        self.assertTrue({'StandardInputFile','StandardOutputFile','StandardErrorFile'}.isdisjoint(r.PROFILE_PROPERTIES))
        self.assertEqual(r.unit_object(json.dumps({'type':'o','data':[OBJECT]}).encode()),OBJECT)
        self.assertEqual(r.property_records(encoded(UNIT_FIXTURE),r.UNIT_SCHEMA)['DropInPaths'],UNIT_FIXTURE[-1][2])
        self.assertEqual(r.property_records(encoded(SERVICE_FIXTURE),r.SERVICE_SCHEMA)['SELinuxContext'],[False,''])
        for value in ({'type':'o','data':OBJECT},{'type':'o','data':[OBJECT,OBJECT]},{'type':'o','data':['/private/arbitrary']},{'type':'s','data':[OBJECT]}):
            with self.assertRaises(r.ProfileError):r.unit_object(json.dumps(value).encode())

    def test_strict_json_and_scalar_widths_do_not_coerce_boolean_or_strings(self):
        for name,sig,value in UNIT_FIXTURE+SERVICE_FIXTURE:
            raw=json.dumps({'type':sig,'data':value}).encode()
            self.assertEqual(r.typed_record(raw,sig,name),value)
            for altered in ({'type':'v','data':value},{'type':sig,'data':value,'extra':0},{'type':sig,'data':{'nested':value}}):
                with self.subTest(name=name),self.assertRaises(r.ProfileError):r.typed_record(json.dumps(altered).encode(),sig,name)
        for sig,value in (('t',False),('u',True),('i','9'),('b',0),('t',-1),('u',2**32),('i',2**31),('t',2**64),('as','path'),('as',['a','b']),('(bs)',''),('(bs)',[0,'']),('(bs)',[False,'','extra'])):
            with self.subTest(sig=sig,value=value),self.assertRaises(r.ProfileError):r.typed_record(json.dumps({'type':sig,'data':value}).encode(),sig,'Query')
        with self.assertRaises(r.ProfileError):r.typed_record(b'{"type":"t","type":"t","data":0}','t','LimitCORE')
        for raw in (encoded(UNIT_FIXTURE)[:-2],encoded(UNIT_FIXTURE)+encoded(UNIT_FIXTURE[:1]),encoded(UNIT_FIXTURE[:-1])):
            with self.assertRaises(r.ProfileError):r.property_records(raw,r.UNIT_SCHEMA)

    def test_independent_typed_values_match_all_three_effective_profiles(self):
        for family,uid,unit,stop in (('root',0,UNIT,5000000),('maintenance',1000,'dev-pair-gptbox-'+'a'*64+'.service',10000000),('observation',1000,'dev-pair-ci-observe-'+'b'*16+'.service',1000000)):
            values={name:copy.deepcopy(value) for name,sig,value in UNIT_FIXTURE+SERVICE_FIXTURE}
            values.update(Id=unit,FragmentPath='/run/systemd/transient/'+unit,DropInPaths=['/run/systemd/system/'+unit+'.d/10-timeout-abort.conf'],
                          MainPID=os.getpid(),ControlGroup='/system.slice/'+unit,User='' if uid==0 else 'dp-maint',Group='',TimeoutStopUSec=stop,StandardInput='null' if uid==0 else 'file')
            args=types.SimpleNamespace(unit=unit,key=unit,profile=family,uid=uid,stdin=0 if uid==0 else 1,start_us=1000000,runtime_us=5000000,deadline=time.monotonic()+2)
            def opened(path,*a,**kw):
                if path=='/proc/self/status':return io.StringIO('Uid: '+(' '.join([str(uid)]*4))+'\nGid: '+(' '.join([str(uid)]*4))+'\n')
                if path=='/proc/self/cgroup':return io.StringIO('0::/system.slice/'+unit+'\n')
                raise AssertionError('unexpected path')
            with patch.object(r,'profile_query',return_value=values),patch('builtins.open',side_effect=opened),patch('pwd.getpwuid',return_value=types.SimpleNamespace(pw_gid=uid)):
                r.verify_profile(args)
            for key in ('Transient','SendSIGKILL','PrivateUsers','PrivateNetwork','NoNewPrivileges','SELinuxContext','DropInPaths'):
                bad=copy.deepcopy(values);bad[key]=[True,''] if key=='SELinuxContext' else ('path' if key=='DropInPaths' else not values[key])
                with patch.object(r,'profile_query',return_value=bad),patch('builtins.open',side_effect=opened),self.assertRaises(r.ProfileError):r.verify_profile(args)

    def fixture_spawn(self,records,delay=0,extra=b''):
        original=subprocess.Popen
        def spawn(argv,**kwargs):
            records.append(argv)
            if 'GetUnit' in argv:data=json.dumps({'type':'o','data':[OBJECT]}).encode()+b'\n'
            elif 'org.freedesktop.systemd1.Unit' in argv:data=encoded(UNIT_FIXTURE)
            else:data=encoded(SERVICE_FIXTURE)
            return original([sys.executable,'-c','import sys,time;time.sleep(float(sys.argv[1]));sys.stdout.buffer.write(bytes.fromhex(sys.argv[2]))',str(delay),(data+extra).hex()],**kwargs)
        return spawn

    def test_three_actual_processes_use_only_fixed_exact_gets_and_one_budget(self):
        calls=[]
        with patch.object(r.subprocess,'Popen',side_effect=self.fixture_spawn(calls)):
            values=r.profile_query(UNIT,time.monotonic()+2)
        self.assertEqual(len(values),35);self.assertEqual(len(calls),3)
        self.assertEqual(calls[0],['/usr/bin/busctl','--system','--json=short','--no-pager','call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',UNIT])
        self.assertEqual(calls[1][-7:],list(name for name,sig,value in UNIT_FIXTURE))
        self.assertEqual(calls[2][-28:],list(name for name,sig,value in SERVICE_FIXTURE))
        self.assertTrue(all('GetAll' not in argv and 'show' not in argv and 'Environment' not in argv and 'ExecStart' not in argv for argv in calls))
        self.assertEqual(r.QUERY_SECONDS,5)
        calls=[];started=time.monotonic()
        with patch.object(r,'QUERY_SECONDS',.15),patch.object(r.subprocess,'Popen',side_effect=self.fixture_spawn(calls,delay=.06)),self.assertRaises(r.ProfileError) as caught:
            r.profile_query(UNIT,time.monotonic()+2)
        self.assertEqual(caught.exception.value,'timeout');self.assertLess(time.monotonic()-started,.4)
        self.assertGreaterEqual(len(calls),2)

    def test_byte_cap_is_shared_across_sequential_processes_including_stderr(self):
        original=subprocess.Popen;calls=[]
        def padded(rows,width):
            return b''.join(line.ljust(width,b' ')+b'\n' for line in encoded(rows).splitlines())
        def spawn(argv,**kwargs):
            calls.append(argv)
            if len(calls)==1:data=json.dumps({'type':'o','data':[OBJECT]}).encode()
            elif len(calls)==2:data=padded(UNIT_FIXTURE,460)
            else:data=padded(SERVICE_FIXTURE,200)
            return original([sys.executable,'-c','import sys;sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))',data.hex()],**kwargs)
        with patch.object(r.subprocess,'Popen',side_effect=spawn),self.assertRaises(r.ProfileError) as caught:
            r.profile_query(UNIT,time.monotonic()+2)
        self.assertEqual(len(calls),3);self.assertEqual(caught.exception.value,'output-limit')
        used=[8000]
        def stderr(argv,**kwargs):return original([sys.executable,'-c','import os;os.write(2,b"x"*193)'],**kwargs)
        with patch.object(r.subprocess,'Popen',side_effect=stderr),self.assertRaises(r.ProfileError) as caught:
            r.query_process(['/fixed-test'],time.monotonic()+1,used)
        self.assertEqual(caught.exception.value,'output-limit')


class DescriptorBinding(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.fds=[]
        self.pairs=[]
        for name in ('stdout','stderr'):
            path=self.root/name;os.mkfifo(path,0o600)
            reader=os.open(path,os.O_RDONLY|os.O_NONBLOCK);writer=os.open(path,os.O_WRONLY|os.O_NONBLOCK)
            self.fds.extend((reader,writer));fcntl.fcntl(reader,fcntl.F_SETPIPE_SZ,4096)
            self.pairs.append((reader,writer))
        path=self.root/'stdin';path.write_bytes(b'NONCREDENTIAL');path.chmod(0o600)
        self.input=os.open(path,os.O_RDONLY);self.fds.append(self.input)
        self.nodes={'stdout_node':self.identity(self.pairs[0][1]),'stderr_node':self.identity(self.pairs[1][1]),'stdin_node':self.identity(self.input),'stdin':1}
        self.addCleanup(self.close)

    def close(self):
        self.root.chmod(0o700)
        for fd in self.fds:
            with __import__('contextlib').suppress(OSError):os.close(fd)

    def identity(self,fd):
        info=os.fstat(fd);return [info.st_dev,info.st_ino]

    def run_fd(self,stdin=None,stdout=None,stderr=None,nodes=None,bad_owner=None,hide=False):
        report=self.root/('report-'+str(time.monotonic_ns()))
        result=os.open(report,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        argv=nodes or self.nodes
        code=r'''
import sys,os,json,types
sys.path.insert(0,sys.argv[1]);import native_relay as r
args=types.SimpleNamespace(**json.loads(sys.argv[2]));args.stdout_node=tuple(args.stdout_node);args.stderr_node=tuple(args.stderr_node)
if args.stdin_node is not None:args.stdin_node=tuple(args.stdin_node)
actual=r.os.fstat
bad=int(sys.argv[4])
if sys.argv[5]:
 try:os.open(sys.argv[5]+'/stdout',os.O_RDONLY|os.O_NONBLOCK);raise AssertionError('hidden path was traversable')
 except PermissionError:pass
def owned(fd):
 s=actual(fd)
 return types.SimpleNamespace(**{key:getattr(s,key) for key in ('st_mode','st_dev','st_ino','st_nlink','st_size','st_rdev')},st_uid=55 if fd==bad else 0)
r.os.fstat=owned
r.os.open=lambda *a,**kw:(_ for _ in ()).throw(AssertionError('descriptor verification traversed a path'))
r.os.read=lambda *a:(_ for _ in ()).throw(AssertionError('descriptor verification consumed input'))
try:r.verify_fds(args);value={'pass':True,'ready':args.diagnostic_ready}
except (ValueError,OSError) as e:value={'pass':False,'key':getattr(e,'key','unavailable'),'ready':getattr(args,'diagnostic_ready',False)}
os.write(int(sys.argv[3]),json.dumps(value).encode())
'''
        if hide:self.root.chmod(0)
        try:
            process=subprocess.Popen([sys.executable,'-c',code,str(Path(r.__file__).parent),json.dumps(argv),str(result),str(bad_owner if bad_owner is not None else -1),str(self.root) if hide else ''],
                                     stdin=self.input if stdin is None else stdin,stdout=self.pairs[0][1] if stdout is None else stdout,
                                     stderr=self.pairs[1][1] if stderr is None else stderr,pass_fds=(result,),close_fds=True,start_new_session=True)
            self.assertEqual(process.wait(timeout=2),0)
        finally:
            self.root.chmod(0o700)
            os.close(result)
        return json.loads(report.read_bytes())

    def test_exact_real_fifo_and_regular_input_bindings_need_no_path_or_input_read(self):
        self.assertTrue(self.run_fd()['pass'])
        self.assertEqual(os.lseek(self.input,0,os.SEEK_CUR),0)
        null=os.open('/dev/null',os.O_RDONLY);self.fds.append(null)
        no_input=dict(self.nodes,stdin=0,stdin_node=None)
        self.assertTrue(self.run_fd(stdin=null,nodes=no_input)['pass'])
        # Kernel path lookup fails while these already-open objects remain valid.
        self.assertTrue(self.run_fd(hide=True)['pass'])

    def test_swapped_replaced_duplicated_and_anonymous_outputs_are_rejected(self):
        self.assertFalse(self.run_fd(stdout=self.pairs[1][1],stderr=self.pairs[0][1])['pass'])
        same=self.run_fd(stderr=self.pairs[0][1]);self.assertFalse(same['pass']);self.assertFalse(same['ready'])
        duplicate=dict(self.nodes,stderr_node=self.nodes['stdout_node'])
        self.assertFalse(self.run_fd(nodes=duplicate)['pass'])
        reader,writer=os.pipe();self.fds.extend((reader,writer));fcntl.fcntl(reader,fcntl.F_SETPIPE_SZ,4096)
        self.assertFalse(self.run_fd(stdout=writer)['pass'])
        path=self.root/'stdout';path.unlink();os.mkfifo(path,0o600)
        replacement=os.open(path,os.O_RDWR|os.O_NONBLOCK);self.fds.append(replacement);fcntl.fcntl(replacement,fcntl.F_SETPIPE_SZ,4096)
        self.assertFalse(self.run_fd(stdout=replacement)['pass'])

    def test_input_offset_access_size_identity_and_null_are_not_interchangeable(self):
        os.lseek(self.input,1,os.SEEK_SET)
        self.assertEqual(self.run_fd()['key'],'FD0');os.lseek(self.input,0,os.SEEK_SET)
        wrong=os.open(self.root/'stdin',os.O_RDWR);self.fds.append(wrong)
        self.assertEqual(self.run_fd(stdin=wrong)['key'],'FD0')
        replacement=self.root/'replacement';replacement.write_bytes(b'x');fd=os.open(replacement,os.O_RDONLY);self.fds.append(fd)
        self.assertEqual(self.run_fd(stdin=fd)['key'],'FD0')
        (self.root/'stdin').write_bytes(b'x'*16385)
        self.assertEqual(self.run_fd()['key'],'FD0')
        no_input=dict(self.nodes,stdin=0,stdin_node=None)
        self.assertEqual(self.run_fd(nodes=no_input)['key'],'FD0')
        wrong_arg=dict(self.nodes,stdin_node=None)
        self.assertEqual(self.run_fd(nodes=wrong_arg)['key'],'FD0')

    def test_owner_modes_links_capacity_and_access_still_fail_closed(self):
        self.assertEqual(self.run_fd(bad_owner=1)['key'],'FD1')
        path=self.root/'stdout';path.chmod(0o666)
        self.assertEqual(self.run_fd()['key'],'FD1');path.chmod(0o600)
        os.link(path,self.root/'hardlink')
        self.assertEqual(self.run_fd()['key'],'FD1');(self.root/'hardlink').unlink()
        fd=os.open(path,os.O_RDWR|os.O_NONBLOCK);self.fds.append(fd)
        self.assertEqual(self.run_fd(stdout=fd)['key'],'FD1')
        # The allocator may deny increasing a pipe; binding never relaxes it.
        try:fcntl.fcntl(self.pairs[0][0],fcntl.F_SETPIPE_SZ,8192)
        except PermissionError:pass
        else:self.assertEqual(self.run_fd()['key'],'FD1')

    def test_argument_aliases_and_mixed_duplicate_forms_never_reach_input_or_query(self):
        import hashlib
        base=['relay','--unit',UNIT,'--key',UNIT,'--profile','root','--start-us','1000000','--runtime-us','1000000',
              '--uid','0','--stdin','0','--maximum','262144','--deadline',str(time.monotonic()+1),'--helper',hashlib.sha256(Path(r.__file__).read_bytes()).hexdigest(),
              '--stdout-node','0:1','--stderr-node','0:2']
        for extra in (['--stdout-node=0:3'],['--stdou','0:1'],['--stdin-node','0:4','--stdin-node=0:5']):
            with patch.object(sys,'argv',base+extra+['--','/usr/bin/true']),patch.object(r,'privacy'),patch.object(r,'verify_process') as process,patch.object(r.os,'read') as read:
                self.assertEqual(r.main(),250)
                process.assert_not_called();read.assert_not_called()

    def test_numeric_metadata_is_closed_and_bounded(self):
        for value in ('-1:1','1:0','1:2:3','01:2','1:+2',str(2**64)+':1','1:'+str(2**64),'1:1 '*100):
            with self.assertRaises(ValueError):r.node_identity(value)
        self.assertEqual(r.node_identity('0:1'),(0,1))
