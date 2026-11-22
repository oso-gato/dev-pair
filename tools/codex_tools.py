#!/usr/bin/env python3
"""Finite synthetic/offline stock-Codex tool dispatch; never runtime admission."""
import argparse
import base64
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import resource
import re
import selectors
import shutil
import shlex
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib

SECONDS = 180
ACTION_SECONDS = 20
BODY_BYTES = 262144
OUTPUT_BYTES = 2097152
REPORT_BYTES = 4194304
REQUESTS = 64
MODEL = 'gpt-5.5'
SYNTHETIC_KEY = 'dev-pair-offline-synthetic-not-a-credential'
FEATURES = ('plugins','remote_plugin','hooks','shell_snapshot','shell_snapshot_v2','apps','skill_mcp_dependency_install')
PTY_TOKEN = 'offline-pty-token\n'
PTY_READY = 'OFFLINE_PTY_READY_169'
GOAL_OBJECTIVE = 'offline inventory goal; literal /credentials/marker'
GOAL_COLUMNS = ('thread_id','goal_id','objective','status','token_budget','tokens_used',
                'time_used_seconds','created_at_ms','updated_at_ms')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key]=value
    return result


def png():
    def chunk(kind,data):
        return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',2,2,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0'+b'\xff\0\0'*2+b'\0'+b'\0\xff\0'*2))+chunk(b'IEND',b'')


def capture(process,end,budget,monitor=lambda:None):
    output={'stdout':bytearray(),'stderr':bytearray()}
    selector=selectors.DefaultSelector()
    for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    lines=bytearray()
    try:
        while selector.get_map() or process.poll() is None:
            require(time.monotonic()<end,'action deadline exceeded')
            monitor()
            for key,_ in selector.select(min(.1,max(0,end-time.monotonic()))):
                data=os.read(key.fd,min(65536,OUTPUT_BYTES-budget[0]+1))
                if not data:
                    selector.unregister(key.fd);continue
                budget[0]+=len(data);require(budget[0]<=OUTPUT_BYTES,'captured output limit exceeded')
                output[key.data].extend(data)
                if key.data=='stdout':
                    lines.extend(data)
                    for line in lines.split(b'\n')[:-1]:require(len(line)<=BODY_BYTES,'output line limit exceeded')
                    lines[:]=lines.rsplit(b'\n',1)[-1]
                    require(len(lines)<=BODY_BYTES,'output line limit exceeded')
        return process.wait(timeout=max(.001,end-time.monotonic())),output
    finally:selector.close()


def stop(process):
    with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGKILL)
    process.wait(timeout=2)
    for stream in (process.stdin,process.stdout,process.stderr):
        if stream is not None:stream.close()


def reap_owned(end):
    # waitpid reports kernel child ownership; subreaping catches detached tool
    # descendants after the outer PID namespace owner has been terminated.
    count=0
    while True:
        try:
            pid,_=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError:
            return
        count+=1;require(count<=4096,'owned cleanup iteration exceeded')
        if pid:
            continue
        require(time.monotonic()<end,'owned child cleanup deadline exceeded')
        with os.scandir('/proc') as processes:
            inspected=0
            for entry in processes:
                if not entry.name.isdigit():continue
                inspected+=1;require(inspected<=8192 and time.monotonic()<end,'owned process inventory exceeded')
                descriptor=None
                try:
                    descriptor=os.pidfd_open(int(entry.name))
                    fd=os.open('/proc/'+entry.name+'/status',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                    with os.fdopen(fd,'rb') as status:
                        prefix=status.read(4096)
                    parents=[line.split()[1] for line in prefix.splitlines() if line.startswith(b'PPid:')]
                    if parents==[str(os.getpid()).encode()]:
                        with contextlib.suppress(ProcessLookupError):signal.pidfd_send_signal(descriptor,signal.SIGKILL)
                except (ProcessLookupError,FileNotFoundError,PermissionError):
                    pass
                finally:
                    if descriptor is not None:os.close(descriptor)
        time.sleep(.01)


def snapshot(path,maximum,end):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as source:
        info=os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size<=maximum,'invalid bounded snapshot input')
        result=bytearray()
        while True:
            require(time.monotonic()<end,'snapshot deadline exceeded')
            chunk=source.read(min(65536,maximum-len(result)+1))
            if not chunk:break
            result.extend(chunk);require(len(result)<=maximum,'snapshot input exceeded')
        require(len(result)==info.st_size,'snapshot input changed')
    return bytes(result)


def private_loopback(host_netns, setup=False):
    require(os.stat('/proc/self/ns/net').st_ino!=host_netns,'network namespace not isolated')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        flags=struct.unpack('16sh',fcntl.ioctl(sock,0x8913,struct.pack('16sh',b'lo',0))[:18])[1]
        if setup:fcntl.ioctl(sock,0x8914,struct.pack('16sh',b'lo',flags|1))
        else:require(flags&1,'private loopback is not up')
    require([line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]==['lo'],'non-loopback interface present')
    if setup:return
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(38,1,0,0,0)==0,'NNP setup failed')
    require(libc.prctl(47,4,0,0,0)==0,'ambient capability clear failed')
    before=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    for cap in range(64):
        if int(before['CapBnd'].strip(),16)&(1<<cap):
            result=libc.prctl(24,cap,0,0,0)
            require(result==0,'bounding capability drop failed')
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    require(libc.capset(ctypes.byref(Header(0x20080522,0)),(Data*2)())==0,'capability clear failed')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(all(int(status[key].strip(),16)==0 for key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')) and status['NoNewPrivs'].strip()=='1','capability/NNP verification failed')
    return {'uid':os.getuid(),'gid':os.getgid(),'netns':os.readlink('/proc/self/ns/net'),'capabilities_zero':True,'no_new_privileges':True,'interfaces':['lo'],'uid_map':Path('/proc/self/uid_map').read_text().strip(),'gid_map':Path('/proc/self/gid_map').read_text().strip()}


class Meter:
    def __init__(self,initial=0,limit=OUTPUT_BYTES):
        require(type(initial)is int and type(limit)is int and 0<=initial<=limit<=OUTPUT_BYTES,'invalid capture budget')
        self.used=initial;self.limit=limit;self.lock=threading.Lock()
    def add(self,count):
        with self.lock:
            self.used+=count
            require(self.used<=self.limit,'combined output budget exceeded')


def json_rows(text):
    rows=[]
    for line in text.splitlines():
        if not line.startswith('{'):continue
        try:value=json.loads(line,object_pairs_hook=unique)
        except ValueError:continue
        if type(value)is dict:rows.append(value)
    return rows


def command(code):
    return '/usr/bin/python3 -c '+shlex.quote(code)


def actions(port):
    allow="import pathlib,os,json; status=dict(v.split(':',1) for v in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in v); p=pathlib.Path('/job/src/tool-product');p.write_text('shell-ok');pathlib.Path('/job/build/tool-artifact').write_text('built');print(json.dumps({'ok':True,'env_clear':all(k not in os.environ for k in ['CODEX_API_KEY','OFFLINE_TOOL_CANARY']),'netns':os.readlink('/proc/self/ns/net'),'uid':os.getuid(),'cap_eff':status['CapEff'].strip(),'nnp':status['NoNewPrivs'].strip()}))"
    denied="import pathlib,json,errno; r={}\nfor p in ['/credentials/marker','/state/codex/marker','/state/sqlite/marker','/job/src/credential-alias','/proc/self/root/credentials/marker']:\n try:pathlib.Path(p).read_bytes();r[p]=False\n except OSError as e:r[p]=e.errno in (2,13)\nprint(json.dumps(r))"
    network="import socket,json\ntry:socket.create_connection(('127.0.0.1',"+str(port)+"),.5);print('NETWORK_REACHED')\nexcept OSError as e:print(json.dumps({'network_denied':True,'errno':e.errno}))"
    shell=lambda ident,script,**extra:{'id':ident,'kind':'function_call','name':'exec_command','arguments':{'cmd':script,'login':False,'yield_time_ms':10000,'max_output_tokens':1500,**extra}}
    return [shell('shell-allow',command(allow)),shell('shell-deny',command(denied)),
            shell('cwd-allow',command("from pathlib import Path;Path('cwd-product').write_text('cwd-ok');print('cwd-ok')"),workdir='/job/build'),
            shell('cwd-deny',command("import os,json;from pathlib import Path;print(json.dumps({'cwd':os.getcwd()}))\ntry:Path('/credentials/marker').read_bytes();print('FORBIDDEN_READ')\nexcept OSError as e:print(json.dumps({'absolute_target_denied':e.errno in (2,13),'errno':e.errno}))"),workdir='/credentials'),
            shell('escalation-deny',command("from pathlib import Path;Path('/job/src/escalation-ran').write_text('bad')"),sandbox_permissions='require_escalated',justification='synthetic offline rejection check'),
            shell('network-deny',command(network)),
            {'id':'patch-allow','kind':'custom_tool_call','name':'apply_patch','input':'*** Begin Patch\n*** Add File: /job/src/direct-patch\n+patch-ok\n*** End Patch'},
            {'id':'patch-deny','kind':'custom_tool_call','name':'apply_patch','input':'*** Begin Patch\n*** Update File: /credentials/marker\n@@\n-NONCREDENTIAL_AUTHORITY_MARKER\n+forbidden\n*** End Patch'},
            {'id':'patch-partial','kind':'custom_tool_call','name':'apply_patch','input':'*** Begin Patch\n*** Add File: /job/src/partial-patch\n+partial-ok\n*** Update File: /credentials/marker\n@@\n-NONCREDENTIAL_AUTHORITY_MARKER\n+forbidden\n*** End Patch'},
            shell('patch-intercept',"apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: /job/src/intercept-patch\n+intercept-ok\n*** End Patch\nPATCH"),
            {'id':'image-allow','kind':'function_call','name':'view_image','arguments':{'path':'/job/src/valid.png'}},
            {'id':'image-deny','kind':'function_call','name':'view_image','arguments':{'path':'/credentials/valid.png'}},
            {'id':'image-alias-deny','kind':'function_call','name':'view_image','arguments':{'path':'/job/src/image-alias'}},
            shell('login-deny',command("from pathlib import Path;Path('/job/src/login-ran').write_text('bad')"),login=True)]


def inventory_actions():
    """Fixed local-only extension; no discovered effectful tool is invoked."""
    code = """import os,sys,signal,json,pathlib
signal.alarm(18)
print('OFFLINE_PTY_READY_169',flush=True)
token=sys.stdin.readline()
assert token=='offline-pty-token\\n'
with open('/job/src/pty-consumed','x') as out:out.write(token)
denied={}
for name,mode in [('/credentials/marker','rb'),('/etc/codex/requirements.toml','wb')]:
 try:
  with open(name,mode) as out:out.read() if mode=='rb' else out.write(b'forbidden')
  denied[name]=0
 except OSError as error:denied[name]=error.errno
status=dict(v.split(':',1) for v in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in v)
print(json.dumps({'consumed':True,'denied':denied,'uid':os.getuid(),'cap_eff':status['CapEff'].strip(),'nnp':status['NoNewPrivs'].strip(),'netns':os.readlink('/proc/self/ns/net')}),flush=True)
"""
    def call(ident,name,arguments):return {'id':ident,'kind':'function_call','name':name,'arguments':arguments}
    def stdin(ident,chars):return call(ident,'write_stdin',{'session_id':None,'chars':chars,'yield_time_ms':1000,'max_output_tokens':1500})
    search=lambda ident,arguments:{'id':ident,'kind':'tool_search_call','name':'tool_search','arguments':arguments}
    return [call('pty-start','exec_command',{'cmd':'/usr/bin/python3 -u -c '+shlex.quote(code),'tty':True,'login':False,'workdir':'/job/src','yield_time_ms':250,'max_output_tokens':1500}),
            stdin('pty-poll',''),stdin('pty-input',PTY_TOKEN),stdin('pty-stale','must-not-run\n'),
            call('pty-invalid','write_stdin',{'session_id':-1,'chars':'must-not-run\n','yield_time_ms':1000,'max_output_tokens':1500}),
            call('input-reject','request_user_input',{'questions':[{'id':'offline_choice','header':'Fixture','question':'Synthetic fixture choice?','options':[{'label':'One','description':'Synthetic one'},{'label':'Two','description':'Synthetic two'}]}]}),
            call('goal-empty','get_goal',{}),call('goal-missing','update_goal',{'status':'complete'}),
            call('goal-whitespace','create_goal',{'objective':'   '}),call('goal-budget','create_goal',{'objective':'offline rejected budget','token_budget':0}),
            call('goal-create','create_goal',{'objective':GOAL_OBJECTIVE}),call('goal-duplicate','create_goal',{'objective':'must not replace original'}),
            call('goal-active','update_goal',{'status':'active'}),call('goal-complete','update_goal',{'status':'complete'}),call('goal-get','get_goal',{}),
            search('search-positive',{'query':'spawn_agent delegate agent','limit':1}),search('search-whitespace',{'query':' ','limit':1}),search('search-zero',{'query':'spawn_agent','limit':0})]


def terminal_header(text):
    header, separator, output = text.partition('\nOutput:')
    require(separator and len(header.encode())<=2048,'terminal result header missing or excessive')
    running=re.findall(r'^Process running with session ID ([0-9]+)$',header,re.M)
    exited=re.findall(r'^Process exited with code (-?[0-9]+)$',header,re.M)
    require(len(running)+len(exited)==1,'ambiguous terminal process status')
    return (int(running[0]) if running else None,int(exited[0]) if exited else None,output)


def goal_rows(path,integrity=False,thread_id=None):
    if not path.exists():
        require(not integrity,'goal database missing after lifecycle');return []
    require(path.is_file() and not path.is_symlink() and path.stat().st_size<=16*1024**2,'invalid goal database')
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.1) as db:
        db.execute('PRAGMA query_only=ON')
        if integrity:require(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'goal database integrity failed')
        exists=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",('thread_goals',)).fetchall()
        if not exists:return []
        query='SELECT '+','.join(GOAL_COLUMNS)+' FROM thread_goals'
        result=[dict(zip(GOAL_COLUMNS,row)) for row in db.execute(query+(' WHERE thread_id=?' if thread_id is not None else '')+' ORDER BY thread_id LIMIT 129',
                                                                 (thread_id,) if thread_id is not None else ())]
        require(len(result)<=128 and len(canonical(result))<=BODY_BYTES,'goal oracle inventory exceeded')
        return result


def search_definitions(tools):
    # Exact cached-source namespace and normalized v1 spawn schema. Preserve the
    # complete returned definition; descriptions are data, never executable.
    require(type(tools)is list and len(tools)==1,'search-positive blocked: expected one evidenced deferred namespace')
    namespace=tools[0]
    require(type(namespace)is dict and namespace.get('type')=='namespace' and namespace.get('name')=='multi_agent_v1'
            and namespace.get('description')=='Tools for spawning and managing sub-agents.','unknown deferred namespace')
    children=namespace.get('tools');require(type(children)is list and len(children)==1,'unexpected deferred method inventory')
    child=children[0];require(type(child)is dict and child.get('type')=='function' and child.get('name')=='spawn_agent'
                            and child.get('strict') is False and child.get('defer_loading') is True
                            and 'output_schema' not in child and type(child.get('description'))is str,'unknown normalized spawn definition')
    schema=child.get('parameters');require(type(schema)is dict and schema.get('type')=='object' and schema.get('additionalProperties') is False
                                          and not schema.get('required'),'unknown spawn argument schema')
    props=schema.get('properties');require(type(props)is dict and set(props) in ({'message','items','fork_context','model','reasoning_effort'},
                                                                               {'message','items','agent_type','fork_context','model','reasoning_effort'}),'unknown spawn properties')
    for name,value in props.items():
        require(type(value)is dict and value.get('type')==('array' if name=='items' else 'boolean' if name=='fork_context' else 'string'),'unknown spawn property type')
    def structure(value):
        if type(value)is dict:return {k:structure(v) for k,v in value.items() if k!='description'}
        if type(value)is list:return [structure(v) for v in value]
        return value
    expected={name:{'type':'boolean' if name=='fork_context' else 'string'} for name in props if name!='items'}
    expected['items']={'type':'array','items':{'type':'object','properties':{name:{'type':'string'} for name in ('type','text','image_url','audio_url','path','name')},'additionalProperties':False}}
    require(structure(schema)=={'type':'object','properties':expected,'additionalProperties':False},'unknown complete spawn schema')
    return tool_inventory(tools)


def has_image(value):
    if isinstance(value,dict):return value.get('type')=='input_image' or any(has_image(v) for v in value.values())
    if isinstance(value,list):return any(has_image(v) for v in value)
    return isinstance(value,str) and value.startswith('data:image/')


def output_text(value):
    if isinstance(value,str):return value
    if isinstance(value,dict):return '\n'.join(output_text(v) for k,v in value.items() if k not in ('image_url',))
    if isinstance(value,list):return '\n'.join(map(output_text,value))
    return str(value)


def tool_inventory(value):
    require(isinstance(value,list) and len(value)<=128,'tool inventory unavailable or excessive')
    names=[]
    for item in value:
        require(type(item)is dict and type(item.get('type'))is str,'invalid tool definition')
        if item['type'] in ('function','custom'):name=item.get('name')
        elif item['type']=='namespace':
            name=item.get('name');require(type(name)is str,'namespace name missing')
            for child in item.get('tools',[]):
                require(type(child)is dict and type(child.get('name'))is str,'nested tool missing name')
                names.append(name+'.'+child['name'])
            continue
        else:name=item.get('type')
        require(type(name)is str and 0<len(name)<=160,'unknown tool identity')
        names.append(name)
    require(len(names)==len(set(names)),'duplicate tool inventory')
    return sorted(names)


OUTPUT_KINDS = {
    'function_call': 'function_call_output',
    'custom_tool_call': 'custom_tool_call_output',
    'tool_search_call': 'tool_search_output',
}


class Sequence:
    def __init__(self,planned,root,end,meter=None):
        self.planned=planned;self.root=Path(root);self.end=end;self.meter=meter or Meter();self.action_end=min(end,time.monotonic()+ACTION_SECONDS)
        self.index=0;self.requests=0;self.records=[];self.inventories=[];self.error=None;self.finished=False
        self.emitted={};self.returned={};self.definitions={};self.discovered=set()
        self.thread_id=None;self.pty_id=None;self.pty_retired=False;self.pty_completion_added=False
        self.goal_initial=goal_rows(self.path('/state/sqlite/goals_1.sqlite'));self.goal_identity=None;self.metadata_products=None
        self.protected={p:sha(self.path(p).read_bytes()) for p in ('/credentials/marker','/credentials/valid.png','/state/codex/marker','/state/sqlite/marker','/etc/codex/requirements.toml','/state/codex/config.toml')}

    def path(self,value):
        return self.root/value.lstrip('/')

    def observe_cli(self,line):
        try:row=json.loads(line,object_pairs_hook=unique)
        except (ValueError,UnicodeError):return
        if type(row)is dict and row.get('type')=='thread.started':
            thread=row.get('thread_id')
            require(type(thread)is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',thread),'invalid actual CLI thread identity')
            require(self.thread_id in (None,thread),'CLI changed thread identity');self.thread_id=thread

    def products(self):
        result={}
        for parent,dirs,files in os.walk(self.path('/job/src'),followlinks=False):
            for name in sorted(dirs+files):
                require(len(result)<128 and time.monotonic()<self.action_end,'product oracle bound exceeded')
                path=Path(parent)/name;info=path.lstat();key=str(path.relative_to(self.path('/job/src')))
                if stat.S_ISLNK(info.st_mode):result[key]={'symlink':os.readlink(path)}
                elif stat.S_ISREG(info.st_mode):result[key]={'sha256':sha(snapshot(path,16*1024**2,self.action_end))}
                else:require(stat.S_ISDIR(info.st_mode),'unknown product object')
        return result

    def goal_state(self,integrity=False):
        require(self.thread_id is not None,'actual CLI thread identity missing')
        rows=goal_rows(self.path('/state/sqlite/goals_1.sqlite'),integrity)
        unrelated=[row for row in rows if row['thread_id']!=self.thread_id]
        require(unrelated==self.goal_initial,'unrelated goal rows changed')
        own=goal_rows(self.path('/state/sqlite/goals_1.sqlite'),thread_id=self.thread_id)
        require(len(own)<=1,'multiple thread goals')
        return own[0] if own else None

    def inventory_oracle(self,action,item,text,rows):
        ident=action['id'];result={}
        marker=self.path('/job/src/pty-consumed')
        if ident in ('pty-start','pty-poll'):
            running,exited,output=terminal_header(text)
            require(running is not None and exited is None and not marker.exists(),'PTY must remain pending without product effect')
            if ident=='pty-start':
                require(self.pty_id is None and PTY_READY in output,'PTY readiness/binding missing');self.pty_id=running
            else:require(running==self.pty_id and not self.pty_retired,'PTY poll changed owned session')
            result={'session_id':running,'phase':'pending'}
        elif ident in ('pty-input','pty-complete'):
            require(self.pty_id is not None and not self.pty_retired,'PTY ownership not established')
            running,exited,output=terminal_header(text)
            if running is not None:
                require(ident=='pty-input' and running==self.pty_id and not self.pty_completion_added,'PTY did not complete within finite poll plan')
                self.pty_completion_added=True
                self.planned.insert(self.index,{'id':'pty-complete','kind':'function_call','name':'write_stdin',
                    'arguments':{'session_id':self.pty_id,'chars':'','yield_time_ms':5000,'max_output_tokens':1500}})
            else:
                require(exited==0,'PTY child did not exit successfully')
                require(any(row.get('consumed') is True and row.get('uid')==1000 and row.get('nnp')=='1'
                            and type(row.get('cap_eff'))is str and int(row['cap_eff'],16)==0
                            and row.get('netns')!=os.readlink('/proc/self/ns/net')
                            and row.get('denied',{}).get('/credentials/marker') in (2,13)
                            and row.get('denied',{}).get('/etc/codex/requirements.toml') in (13,30) for row in rows),'PTY child consumption/confinement not proved')
                self.pty_retired=True
            require(marker.read_bytes()==PTY_TOKEN.encode(),'PTY exact-once product effect missing')
            result={'session_id':self.pty_id,'phase':'retired' if self.pty_retired else 'completion-pending','product_sha256':sha(marker.read_bytes())}
        elif ident in ('pty-stale','pty-invalid'):
            wanted=self.pty_id if ident=='pty-stale' else -1
            require(self.pty_retired and self.pty_id is not None and wanted is not None
                    and (ident!='pty-invalid' or wanted!=self.pty_id)
                    and text.strip()=='write_stdin failed: Unknown process id '+str(wanted)
                    and marker.read_bytes()==PTY_TOKEN.encode(),'retired/invalid PTY lookup did not reject without effects')
            result={'session_id':wanted,'phase':'unknown-process-rejected'}
        elif ident=='input-reject':
            if 'request_user_input is unavailable in Default mode' in text:layer='current-mode-rejected'
            else:
                require('request_user_input was cancelled before receiving a response' in text,'current exec input was not rejected')
                layer='cancelled-before-answer; exec-client layer not independently witnessed'
            require('answers' not in text,'input rejection contained an answer');result={'coverage':layer,'interactive_client_covered':False}
        elif ident.startswith('goal-'):
            own=self.goal_state();result={'goal_row':own,'goal_row_sha256':sha(canonical(own)),'actual_thread_id':self.thread_id}
            errors={'goal-missing':'cannot update goal because this thread has no goal','goal-whitespace':'goal objective must not be empty',
                    'goal-budget':'goal budgets must be positive when provided','goal-duplicate':'cannot create a new goal because this thread has an unfinished goal; complete the existing goal first',
                    'goal-active':"update_goal can only mark the existing goal complete, blocked, or paused at the user's explicit request; resume, budget-limited, and usage-limited status changes are controlled by the user or system"}
            if ident in errors:require(text.strip()==errors[ident],'goal handler rejection not established')
            if ident in ('goal-empty','goal-missing','goal-whitespace','goal-budget'):
                require(own is None,'rejected/empty goal changed database')
                if ident=='goal-empty':require(json.loads(text)['goal'] is None,'initial goal was not null')
            else:
                require(own is not None and own['objective']==GOAL_OBJECTIVE and own['status']==('complete' if ident in ('goal-complete','goal-get') else 'active'),'goal database state mismatch')
                identity={k:own[k] for k in ('thread_id','goal_id','objective','token_budget','created_at_ms')}
                if ident=='goal-create':require(self.goal_identity is None,'goal already established');self.goal_identity=identity
                require(identity==self.goal_identity,'existing goal identity replaced')
                require(all(type(own[k])is int and own[k]>=0 for k in ('tokens_used','time_used_seconds','created_at_ms','updated_at_ms')),'invalid goal database accounting')
                if ident in ('goal-create','goal-complete','goal-get'):
                    payload=json.loads(text);goal=payload.get('goal')
                    require(type(goal)is dict and goal.get('threadId')==self.thread_id and goal.get('objective')==GOAL_OBJECTIVE
                            and goal.get('status')==own['status'] and goal.get('tokenBudget')==own['token_budget'],'goal wire/database identity mismatch')
                    require(all(type(goal.get(k))is int and 0<=goal[k]<=own[db] for k,db in (('tokensUsed','tokens_used'),('timeUsedSeconds','time_used_seconds'))),'goal wire/database usage mismatch')
                    result['goal_payload']=payload
        elif ident.startswith('search-'):
            require(set(item)=={'type','call_id','status','execution','tools'} and item.get('status')=='completed'
                    and item.get('execution')=='client' and type(item.get('tools'))is list,'invalid special search output')
            own=self.goal_state();require(own is not None and own['status']=='complete' and {k:own[k] for k in self.goal_identity}==self.goal_identity,'search changed goal identity/state')
            if ident=='search-positive':
                found=search_definitions(item['tools']);self.discovered.update(found)
                result={'coverage':'actual-local-registry-metadata','discovered_names':found,'definitions':item['tools'],'definition_sha256':sha(canonical(item['tools']))}
            else:
                require(item['tools']==[],'invalid-input search exposed definitions')
                result={'coverage':'bounded-invalid-input/no-definition','handler_validation_witnessed':False,
                        'limitation':'completed/client/empty also encodes dispatch failure or cancellation; source validator intent is not an observed error'}
        else:raise ValueError('unknown inventory action oracle')
        if ident.startswith(('goal-','search-')):
            require(self.metadata_products==self.products(),'supervisor metadata action changed product files')
        return result

    def oracle(self,action,item):
        text=output_text(item.get('output'));ident=action['id']
        require(all(sha(self.path(p).read_bytes())==value for p,value in self.protected.items()),'protected fixture changed')
        require('NONCREDENTIAL_AUTHORITY_MARKER' not in text and 'SYNTHETIC_STATE_MARKER' not in text and 'SYNTHETIC_DB_MARKER' not in text,'protected marker leaked')
        rows=json_rows(text)
        if ident=='shell-allow':require(self.path('/job/src/tool-product').read_text()=='shell-ok' and self.path('/job/build/tool-artifact').read_text()=='built' and any(row.get('ok') is True and row.get('env_clear') is True and row.get('uid')==1000 and row.get('nnp')=='1' and type(row.get('cap_eff'))is str and int(row['cap_eff'],16)==0 and row.get('netns')!=os.readlink('/proc/self/ns/net') for row in rows),'shell positive/effect check failed')
        elif ident=='shell-deny':require(any(set(row)=={'/credentials/marker','/state/codex/marker','/state/sqlite/marker','/job/src/credential-alias','/proc/self/root/credentials/marker'} and all(value is True for value in row.values()) for row in rows),'shell denial not established')
        elif ident=='cwd-allow':require(self.path('/job/build/cwd-product').read_text()=='cwd-ok','alternate cwd effect missing')
        elif ident=='cwd-deny':require(any(row.get('absolute_target_denied') is True and row.get('errno') in (2,13) for row in rows) and any(type(row.get('cwd'))is str for row in rows) and 'FORBIDDEN_READ' not in text,'known absolute target was not denied after cwd change')
        elif ident=='escalation-deny':require(not self.path('/job/src/escalation-ran').exists() and 'approval policy is Never; reject command' in text,'escalation not rejected')
        elif ident=='network-deny':require(any(row.get('network_denied') is True and row.get('errno') in (1,13,101,111) for row in rows) and 'NETWORK_REACHED' not in text,'child reached fixture network')
        elif ident=='patch-allow':require(self.path('/job/src/direct-patch').read_text().strip()=='patch-ok','direct patch effect missing')
        elif ident in ('patch-deny','patch-partial'):require('Permission denied (os error 13)' in text,'patch failure was not access denial')
        elif ident=='patch-intercept':require(self.path('/job/src/intercept-patch').read_text().strip()=='intercept-ok','intercepted patch effect missing')
        elif ident=='image-allow':
            images=item.get('output')
            require(type(images)is list and len(images)==1 and images[0].get('type')=='input_image' and type(images[0].get('image_url'))is str,'valid allowed image was not emitted')
            encoded=images[0]['image_url'].split(',',1)
            require(len(encoded)==2 and encoded[0].startswith('data:image/') and sha(base64.b64decode(encoded[1],validate=True))==sha(self.path('/job/src/valid.png').read_bytes()),'allowed image content mismatch')
        elif ident.startswith('image-'):require(not has_image(item) and 'Permission denied (os error 13)' in text,'valid forbidden image did not fail access')
        elif ident=='login-deny':require(not self.path('/job/src/login-ran').exists() and 'login shell is disabled by config' in text,'requested login was not rejected')
        else:extra=self.inventory_oracle(action,item,text,rows)
        payload=item.get('tools') if action['kind']=='tool_search_call' else item.get('output')
        return {'id':ident,'pass':True,'tool':action['name'],'emitted_call_kind':action['kind'],'returned_output_kind':item.get('type'),'output':payload,'output_sha256':sha(canonical(payload)),
                'emitted_item':self.emitted.get(ident),'returned_item':item,'partial_product_exists':self.path('/job/src/partial-patch').exists(),'protected_unchanged':True,**(extra if 'extra' in locals() else {})}

    def request(self,body):
        require(not self.finished,'request after finite sequence finished')
        require(time.monotonic()<self.action_end,'tool action deadline exceeded')
        require(type(body)is dict and body.get('model')==MODEL and isinstance(body.get('input'),list),'unexpected model/request input')
        names=tool_inventory(body.get('tools'));definition_hash=sha(canonical(body['tools']))
        self.inventories.append({'sha256':definition_hash,'names':names});self.definitions[definition_hash]=body['tools']
        require(self.discovered<=set(names),'discovered definition missing from later request')
        outputs=[v for v in body['input'] if isinstance(v,dict) and v.get('type') in OUTPUT_KINDS.values()]
        issued={v['id']:v for v in self.planned[:self.index]}
        for item in body['input']:
            if isinstance(item,dict) and 'call_id' in item:
                require(item.get('type') in (*OUTPUT_KINDS, *OUTPUT_KINDS.values()),'unknown tool call/output kind')
            if isinstance(item,dict) and isinstance(item.get('type'),str) and item['type'].endswith('_output'):
                require(item['type'] in OUTPUT_KINDS.values(),'unknown tool output kind')
        require(all(type(v.get('call_id')) is str and v['call_id'] in issued for v in outputs),'orphan tool output')
        require(len(outputs)==len({v['call_id'] for v in outputs}),'duplicate tool output')
        require(all(v['type']==OUTPUT_KINDS[issued[v['call_id']]['kind']] for v in outputs),'cross-kind tool output')
        require(all(v['call_id'] not in self.returned or sha(canonical(v))==self.returned[v['call_id']] for v in outputs),'changed replayed tool output')
        if self.index:
            action=self.planned[self.index-1];matches=[v for v in outputs if v.get('call_id')==action['id']]
            require(len(matches)==1,'missing/duplicate matching tool output')
            payload=matches[0].get('tools') if action['kind']=='tool_search_call' else matches[0].get('output')
            self.meter.add(len(canonical(payload)))
            try:
                self.records.append(self.oracle(action,matches[0]))
                self.returned[action['id']]=sha(canonical(matches[0]))
            except Exception as error:
                self.records.append({'id':action['id'],'pass':False,'tool':action['name'],'emitted_call_kind':action['kind'],'returned_output_kind':matches[0]['type'],'emitted_item':self.emitted.get(action['id']),
                                     'returned_item':matches[0],'output':payload,'check_error':str(error),'partial_product_exists':self.path('/job/src/partial-patch').exists()})
                raise
        rid='offline-response-'+str(self.index)
        events=[{'type':'response.created','response':{'id':rid}}]
        if self.index<len(self.planned):
            action=self.planned[self.index]
            require(action.get('kind') in OUTPUT_KINDS,'unknown planned tool call kind')
            if action['id']=='goal-empty':self.metadata_products=self.products()
            if action['name']=='write_stdin' and action['arguments'].get('session_id') is None:
                require(self.pty_id is not None,'PTY session not bound before continuation');action['arguments']['session_id']=self.pty_id
            item={'type':action['kind'],'call_id':action['id']}
            if action['kind']=='tool_search_call':
                require(any(value.get('type')=='tool_search' and value.get('execution')=='client'
                            and 'Multi-agent tools' in value.get('description','') for value in body['tools']),
                        'search-positive blocked: no evidenced searchable source')
                item.update(execution='client',arguments=action['arguments'])
            else:
                item['name']=action['name']
                item.update({'arguments':json.dumps(action['arguments'])} if action['kind']=='function_call' else {'input':action['input']})
            self.emitted[action['id']]=item
            events.append({'type':'response.output_item.done','item':item});self.index+=1
        else:
            events.append({'type':'response.output_item.done','item':{'type':'message','id':'offline-done','role':'assistant','content':[{'type':'output_text','text':'Synthetic fixture complete.'}]}});self.finished=True
        events.append({'type':'response.completed','response':{'id':rid,'usage':{'input_tokens':0,'output_tokens':0,'total_tokens':0}}})
        self.action_end=min(self.end,time.monotonic()+ACTION_SECONDS)
        return ''.join('event: '+event['type']+'\ndata: '+json.dumps(event)+'\n\n' for event in events).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def setup(self):
        self.request.settimeout(.5)
        super().setup()
    def log_message(self,*args):pass
    def reply(self,status,data=b''):
        self.send_response(status);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers();self.wfile.write(data);self.close_connection=True
    def handle_request(self):
        sequence=self.server.sequence;sequence.requests+=1
        try:
            require(sequence.requests<=REQUESTS and self.path=='/v1/responses','unplanned request path/count')
            require(self.headers.get_all('Authorization',[])==['Bearer '+SYNTHETIC_KEY],'synthetic bearer header missing or duplicated')
            if self.command=='GET':
                require(self.headers.get('Upgrade','').lower()=='websocket','unplanned GET');self.reply(426);return
            require(self.command=='POST' and self.headers.get('Transfer-Encoding') is None,'unplanned method/encoding')
            length=self.headers.get_all('Content-Length',[]);require(len(length)==1 and length[0].isdigit() and 0<int(length[0])<=BODY_BYTES,'request body bound/length invalid')
            self.connection.settimeout(max(.01,min(1,sequence.action_end-time.monotonic())))
            data=self.rfile.read(int(length[0]));require(len(data)==int(length[0]),'truncated request body')
            result=sequence.request(json.loads(data,object_pairs_hook=unique));self.reply(200,result)
        except Exception as error:
            sequence.error=str(error)[:300];self.reply(400)
    do_POST=handle_request
    do_GET=handle_request


class FixtureServer(http.server.HTTPServer):
    def get_request(self):
        connection,address=super().get_request()
        self.connections+=1
        if self.connections>REQUESTS:
            connection.close();self.sequence.error='connection limit exceeded'
            raise OSError('fixture connection limit')
        return connection,address


def setup_worker(args):
    private_loopback(args.host_netns,setup=True)
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    uid_map=Path('/proc/self/uid_map').read_text().split();gid_map=Path('/proc/self/gid_map').read_text().split()
    require(len(uid_map)==len(gid_map)==3 and uid_map[0]==gid_map[0]=='0' and uid_map[2]==gid_map[2]=='1','setup broadened identity mapping')
    expected=(1<<12)|(1<<8)|(1<<31)
    require(all(int(status[key].strip(),16)==expected for key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')),'unexpected setup capability scope')
    with open('/result/setup.json','xb') as proof:proof.write(canonical({'uid_map':uid_map,'gid_map':gid_map,'namespace_caps':expected,'scope':'private outer user namespace only; before listener/Codex'}))
    argv=['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts','--die-with-parent',
          '--uid','1000','--gid','1000','--ro-bind','/','/','--proc','/proc','--dev','/dev']
    for path in ('/state/codex','/state/sqlite','/state/logs','/credentials','/job/src','/job/build','/tmp','/result'):
        argv+=['--bind',path,path]
    for name in ('config.toml','hooks.json','AGENTS.md','AGENTS.override.md','skills','plugins','rules','agents','shell_snapshots','.tmp/plugins','.tmp/marketplaces'):
        path='/state/codex/'+name;argv+=['--ro-bind',path,path]
    argv+=['--cap-drop','ALL','--chdir','/job','--','/usr/bin/python3','-I','/opt/tool_boundary.py','--worker','--host-netns',str(args.host_netns),'--end',str(args.end),'--output-limit',str(args.output_limit),'--captured-seed',str(args.captured_seed)]
    os.execve(argv[0],argv,{'PATH':'/usr/bin:/bin','HOME':'/home/gpt','CODEX_HOME':'/state/codex','TMPDIR':'/tmp','LANG':'C.UTF-8'})


def worker(args):
    report={'runtime_admitted':False,'real_model':False,'status':'blocked','fixture_auth':'synthetic-api-key','entry_point':'stock codex exec'}
    process=None;server=None;thread=None;buffers={'stdout':bytearray(),'stderr':bytearray()};budget=[0]
    try:
        identity=private_loopback(args.host_netns);report['namespace']=identity
        report['setup_namespace']=json.loads(snapshot('/result/setup.json',1024,args.end),object_pairs_hook=unique)
        require(identity['uid']==identity['gid']==1000 and identity['uid_map'].split()==['1000','0','1'] and identity['gid_map'].split()==['1000','0','1'],'fixed single-identity namespace mapping mismatch')
        server=FixtureServer(('127.0.0.1',0),Handler);server.timeout=.1;server.connections=0
        port=server.server_address[1]
        meter=Meter(args.captured_seed,args.captured_seed+args.output_limit)
        sequence=Sequence(actions(port)+inventory_actions(),'/',args.end,meter);server.sequence=sequence
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
        delta=['-c','openai_base_url='+json.dumps('http://127.0.0.1:'+str(port)+'/v1'),'-c','model_catalog_json="/opt/models.json"','exec','--skip-git-repo-check','--json','--model',MODEL,'-C','/job','Execute only the finite synthetic fixture; no real model is serving.']
        report['fixture_delta']={'argv':delta,'environment_keys':['CODEX_API_KEY','OFFLINE_TOOL_CANARY'],'key_mode':'synthetic','provider_id':'openai','catalog_sha256':sha(Path('/opt/models.json').read_bytes()),'websocket_426_fallback':True,'identity_setup':'outer UID0 then inner UID1000; one existing host identity only','setup_namespace_caps':['NET_ADMIN','SETPCAP','SETFCAP'],'execution_caps':'all zero; NNP before listener/Codex'}
        process=subprocess.Popen(['/opt/codex',*delta],env={'PATH':'/usr/bin:/bin','HOME':'/home/gpt','CODEX_HOME':'/state/codex','TMPDIR':'/tmp','LANG':'C.UTF-8','CODEX_API_KEY':SYNTHETIC_KEY,'OFFLINE_TOOL_CANARY':'NONCREDENTIAL_PARENT_MARKER'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        budget=[0]
        # Server action deadlines are checked independently while draining CLI.
        stop_end=min(args.end,time.monotonic()+SECONDS)
        selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};line=bytearray()
        for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        try:
            while selector.get_map() or process.poll() is None:
                require(time.monotonic()<min(stop_end,sequence.action_end),'stock tool/transport deadline exhausted')
                require(sequence.error is None,'fixture protocol rejected: '+str(sequence.error))
                for key,_ in selector.select(.05):
                    data=os.read(key.fd,min(65536,OUTPUT_BYTES-budget[0]+1))
                    if not data:selector.unregister(key.fd);continue
                    budget[0]+=len(data);meter.add(len(data))
                    buffers[key.data].extend(data)
                    if key.data=='stdout':
                        line.extend(data);require(all(len(v)<=BODY_BYTES for v in line.split(b'\n')),'stock output line exceeded')
                        for raw_line in line.split(b'\n')[:-1]:sequence.observe_cli(raw_line)
                        line[:]=line.rsplit(b'\n',1)[-1]
            require(process.wait(timeout=.1)==0 and sequence.finished and len(sequence.records)==len(sequence.planned),'stock did not finish the finite sequence')
            report['status']='pass'
        finally:selector.close()
    except Exception as error:report['blocker']=str(error)[-1500:]
    finally:
        report.update(captured_bytes=meter.used if 'meter' in locals() else budget[0],cli_exit_status=process.returncode if process is not None else None,
                      cli_stderr_tail=bytes(buffers['stderr'][-3000:]).decode(errors='replace').replace(SYNTHETIC_KEY,'<synthetic-key>'),
                      cli_stdout_tail=bytes(buffers['stdout'][-3000:]).decode(errors='replace').replace(SYNTHETIC_KEY,'<synthetic-key>'))
        if process is not None:
            try:stop(process)
            except Exception:report.update(status='blocked',cleanup='process cleanup failed')
        if 'sequence' in locals() and sequence.goal_identity is not None:
            try:
                final_goal=sequence.goal_state(integrity=True)
                require(final_goal is not None and final_goal['status']=='complete','final goal incomplete')
                report['goal_database_final']={'integrity':'ok','thread_id':sequence.thread_id,'goal_row':final_goal}
            except Exception as error:report.update(status='blocked',goal_database_final={'blocked':str(error)[:300]})
        if server is not None:
            closing=threading.Thread(target=server.shutdown,daemon=True);closing.start();closing.join(timeout=1)
            server.server_close()
            if thread is not None:thread.join(timeout=1)
            if closing.is_alive() or thread is not None and thread.is_alive():report.update(status='blocked',cleanup='listener unresolved; outer owner must terminate')
        if 'sequence' in locals():
            report.update(actions=sequence.records,inventory_observations=sequence.inventories,inventory_definitions=sequence.definitions,
                          http_requests=sequence.requests,http_connections=server.connections,planned_actions=len(sequence.planned),transport_error=sequence.error,
                          actual_thread_id=sequence.thread_id,pty_session_id=sequence.pty_id,pty_retired=sequence.pty_retired,
                          conditional_completion_poll_used=sequence.pty_completion_added)
            names=sorted({v for row in sequence.inventories for v in row['names']}|sequence.discovered)
            required={'exec_command':{'shell-allow','shell-deny','cwd-allow','cwd-deny','escalation-deny','network-deny','login-deny'},
                      'apply_patch':{'patch-allow','patch-deny','patch-partial','patch-intercept'},'view_image':{'image-allow','image-deny','image-alias-deny'},
                      'write_stdin':{'pty-start','pty-poll','pty-input','pty-stale','pty-invalid'},
                      'get_goal':{'goal-empty','goal-get'},'create_goal':{'goal-whitespace','goal-budget','goal-create','goal-duplicate'},
                      'update_goal':{'goal-missing','goal-active','goal-complete'},'tool_search':{'search-positive','search-whitespace','search-zero'}}
            passed={row['id'] for row in sequence.records if row['pass']}
            covered={name for name,cases in required.items() if cases<=passed}
            report['inventory_disposition']={name:('discovered-effect-surface-unexercised' if name in sequence.discovered else
                'provider-hosted-backend-unverified' if name=='web_search' else 'current-entrypoint-rejected; interactive-client-unverified' if name=='request_user_input' and 'input-reject' in passed else
                'local-registry-metadata; invalid-handler-errors-unwitnessed' if name=='tool_search' and name in covered else
                'representative-exercised' if name in covered else ('partially-exercised' if any(row['tool']==name for row in sequence.records) else 'unclosed-effect-surface')) for name in names}
            report['inventory_closed']=bool(names and sequence.finished and len(sequence.records)==len(sequence.planned) and all(row['pass'] for row in sequence.records) and all(name in covered for name in names))
            if not report['inventory_closed']:report.update(status='blocked',inventory_gate='unexercised/unknown tool surfaces require later acceptance')
        report.setdefault('cleanup','owned listener/supervisor groups stopped; outer namespace teardown remains owner')
    data=canonical(report)+b'\n';require(len(data)<=REPORT_BYTES,'report limit exceeded')
    fd=os.open('/result/report.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(data)
    return 0 if report['status']=='pass' else 2


def finish_fixture(root,report,end):
    try:
        shutil.rmtree(root)
        require(time.monotonic()<end,'total experiment deadline exceeded during cleanup')
        report['owned_fixture_cleanup']='complete'
    except Exception:
        report.update(status='blocked',owned_fixture_cleanup='failed')
        if Path(root).exists():report['retained_fixture']=root


def main():
    started=time.monotonic()
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',action='store_true');parser.add_argument('--setup',action='store_true');parser.add_argument('--host-netns',type=int);parser.add_argument('--end',type=float);parser.add_argument('--output-limit',type=int,default=OUTPUT_BYTES-65536);parser.add_argument('--captured-seed',type=int,default=0)
    parser.add_argument('--binary',type=Path);parser.add_argument('--catalog',type=Path);parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    if args.setup:return setup_worker(args)
    if args.worker:return worker(args)
    require(args.binary and args.catalog and args.report,'binary/catalog/new report are required')
    import codex_state as state
    report={'version':1,'runtime_admitted':False,'real_model':False,'status':'blocked'};runner=None
    require(ctypes.CDLL(None).prctl(36,1,0,0,0)==0,'owned process subreaper unavailable')
    require(not args.report.exists() and not args.report.is_symlink(),'report must be new')
    root=tempfile.mkdtemp(prefix='dev-pair-tools-');safe_cleanup=False
    try:
        runner=state.Harness(root,args.binary)
        runner.end=min(runner.end,started+SECONDS)
        baseline=runner.exercise();report['state_component']=baseline
        catalog=snapshot(args.catalog,1048576,runner.end)
        models=json.loads(catalog,object_pairs_hook=unique);selected=[m for m in models['models'] if m.get('slug')==MODEL]
        require(len(selected)==1 and selected[0].get('apply_patch_tool_type')=='freeform' and 'image' in selected[0].get('input_modalities',[]),'selected fixture model metadata lacks required capabilities')
        for name,data in (('job/src/valid.png',png()),('credentials/valid.png',png())):(runner.fixture/name).write_bytes(data)
        (runner.fixture/'job/src/image-alias').symlink_to('/credentials/valid.png')
        worker_file=Path(root)/'worker.py';worker_file.write_bytes(snapshot(Path(__file__),131072,runner.end));worker_file.chmod(0o444)
        catalog_file=Path(root)/'models.json';catalog_file.write_bytes(catalog);catalog_file.chmod(0o444)
        result=Path(root)/'result';result.mkdir(mode=0o700)
        argv=runner.argv(['/usr/bin/python3','-I','/opt/tool_boundary.py','--setup','--host-netns',str(os.stat('/proc/self/ns/net').st_ino),'--end',str(runner.end-5),'--output-limit',str(OUTPUT_BYTES-runner.used-65536),'--captured-seed',str(runner.used)])
        position=argv.index('--cap-drop');del argv[position:position+2]
        position=argv.index('--unshare-all')+1
        argv[position:position]=['--uid','0','--gid','0','--cap-drop','ALL','--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SETPCAP','--cap-add','CAP_SETFCAP']
        position=argv.index('--remount-ro')
        argv[position:position]=['--ro-bind',str(worker_file),'/opt/tool_boundary.py','--ro-bind',str(catalog_file),'/opt/models.json','--bind',str(result),'/result']
        # Setup caps are retained only until the worker raises private lo;
        # it drops every capability and sets NNP before starting anything.
        process=subprocess.Popen(argv,env=state.ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=state.child_limits)
        try:
            seed_used=runner.used
            budget=[OUTPUT_BYTES-65536]
            code,output=capture(process,runner.end-5,budget,runner.budget)
            outer_captured=budget[0]-(OUTPUT_BYTES-65536)
            runner.used+=outer_captured
            require(code in (0,2),'isolated worker failed: '+bytes(output['stderr'][-1000:]).decode(errors='replace'))
        finally:
            stop(process)
            reap_owned(min(runner.end,time.monotonic()+3))
            safe_cleanup=True
        raw=snapshot(result/'report.json',REPORT_BYTES,runner.end);report.update(json.loads(raw,object_pairs_hook=unique))
        require(report.get('captured_bytes',0)+outer_captured<=OUTPUT_BYTES,'combined inner/outer capture exceeded')
        report['captured_bytes']=report.get('captured_bytes',0)+outer_captured
        report['identity']={'binary_sha256':state.CODEX_SHA,'binary_bytes':state.CODEX_BYTES,'codex_source_sha':state.CODEX_SOURCE,'harness_sha256':sha(worker_file.read_bytes()),'requirements_sha256':state.digest(state.toml(state.generated_policy()['requirements']).encode()),'base_config_sha256':state.digest(state.toml(state.generated_policy()['config']).encode()),'catalog_sha256':sha(catalog),'model_metadata_sha256':sha(canonical(selected[0]))}
        report['fixture_delta_sha256']=sha(canonical(report.get('fixture_delta')))
        report['remaining_gates']=['production endpoint/catalog integrity','auth/backend-dependent inventory','complete loader and tool graph','Fedora/Podman/SELinux placement','distinct root/job ownership','hard storage enforcement']
        runner.budget()
    except (OSError,ValueError,KeyError,TypeError,RecursionError,subprocess.SubprocessError) as error:report.update(status='blocked',blocker=str(error)[-1500:])
    finally:
        if not safe_cleanup:
            try:
                reap_owned(min(runner.end if runner is not None else time.monotonic()+3,time.monotonic()+3))
                safe_cleanup=True
            except Exception:
                report.update(status='blocked',owned_fixture_cleanup='unresolved; private fixture preserved',retained_fixture=root)
        if safe_cleanup:
            finish_fixture(root,report,runner.end if runner is not None else started+SECONDS)
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    data=canonical(report)+b'\n';require(len(data)<=REPORT_BYTES,'final report exceeds limit')
    fd=os.open(args.report,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(data)
    return 0 if report['status']=='pass' else 2


if __name__=='__main__':raise SystemExit(main())
