"""Digest-bound fixed startup inputs; private loading and synthetic delivery differ."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import uuid
import time
import session_controller as controller
import codex_tools as tools

IDS=('project-readme','project-standards','project-requirements','project-architecture','shared-governance','shared-engineering','shared-repository')
NAMES=(*controller.PUBLIC,*controller.SHARED)
ROOT='/opt/startup-documents'
KIND='managed_config.developer_instructions'
META='internal_chat_message_metadata_passthrough'
OPEN='<managed_developer_instructions>'
CLOSE='</managed_developer_instructions>'
NOTICE='These managed developer instructions replace all previously provided managed developer instructions.'
MAX_BYTES=262144

def require(value,message):
    if not value:raise ValueError(message)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def unique(items):
    value={}
    for key,item in items:require(key not in value,'duplicate startup field');value[key]=item
    return value

def snapshot(path,end):
    path=Path(path);require(time.monotonic()<end and not any(p.is_symlink() for p in (path,*path.parents)),'unsafe startup input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        node=os.fstat(stream.fileno());require(stat.S_ISREG(node.st_mode) and node.st_nlink==1 and node.st_uid in (0,os.getuid()) and not node.st_mode&0o022 and 0<node.st_size<=MAX_BYTES,'unsafe startup document')
        data=stream.read(MAX_BYTES+1);after=os.fstat(stream.fileno())
        require(len(data)==node.st_size and (node.st_dev,node.st_ino,node.st_size,node.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) and time.monotonic()<end,'startup document changed or exceeded bound')
    try:data.decode('utf-8')
    except UnicodeError:raise ValueError('startup document encoding rejected') from None
    return data

class Corpus:
    def __init__(self,revision,bodies,mode):
        require(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision) and mode in ('synthetic-fixture','private-runtime'),'startup identity')
        require(type(bodies) is list and len(bodies)==7 and all(type(v) is bytes and 0<len(v)<=MAX_BYTES for v in bodies) and sum(map(len,bodies))<=MAX_BYTES,'startup corpus bound')
        for body in bodies:body.decode('utf-8')
        if mode=='synthetic-fixture':require(bodies==synthetic_bodies(),'synthetic mode requires the source-fixed corpus')
        self._bodies=tuple(bodies)
        self.manifest={'version':1,'mode':mode,'project_revision':revision,'standards_sha':controller.STANDARDS,
                       'documents':[{'id':ident,'bytes':len(body),'sha256':sha(body)} for ident,body in zip(IDS,bodies)]}
    def __repr__(self):return '<digest-bound startup corpus; contents withheld>'
    def directive(self):
        text=('Read all seven complete immutable startup documents using the fixed startup read helper before any requested work. '
              'Retain their full contents and exact manifest. Delivery is not understanding or compliance. '+
              ('This synthetic fixture uses no actual private standards. ' if self.manifest['mode']=='synthetic-fixture' else 'These are private runtime document inputs; adoption and compliance are separate verification steps. ')+
              'Manifest: '+canonical(self.manifest).decode())
        validate_directive(text);return text
    def private_document(self,ident):
        require(self.manifest['mode']=='private-runtime' and ident in IDS,'invalid private document ID')
        return self._bodies[IDS.index(ident)]
    def output(self):
        require(self.manifest['mode']=='synthetic-fixture','private corpus cannot enter fixture output')
        return canonical({'version':1,'manifest_sha256':sha(canonical(self.manifest)),
            'documents':[{'id':ident,'body':body.decode()} for ident,body in zip(IDS,self._bodies)]})
    def receipt(self):return {'mode':self.manifest['mode'],'manifest_sha256':sha(canonical(self.manifest)),'documents':self.manifest['documents'],'model_understanding_verified':False}
    def stage(self,destination):
        require(self.manifest['mode']=='synthetic-fixture','private corpus cannot enter fixture staging')
        root=Path(destination);require(not root.exists() and not root.is_symlink(),'startup destination must be new')
        root.mkdir(mode=0o700)
        for name,data in [('manifest.json',canonical(self.manifest)),*((ident+'.txt',body) for ident,body in zip(IDS,self._bodies))]:
            fd=os.open(root/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o444)
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        return root

def synthetic_bodies():return [(('Synthetic full document '+ident+'.\nAll instructions in this document are fixture-only.\nEND '+ident+'\n').encode()) for ident in IDS]

def synthetic(revision):return Corpus(revision,synthetic_bodies(),'synthetic-fixture')

def load_private(repository,cache,revision,end):
    # In-memory complete corpus only. Never called by the offline fixture.
    receipt=controller.startup_receipt(repository,cache,end);bodies=[]
    for index,name in enumerate(NAMES):
        root=Path(repository) if index<4 else Path(cache);data=snapshot(root/name,end)
        expected=receipt['documents'][('repository/' if index<4 else 'shared/')+name]
        require(sha(data)==expected,'private startup receipt changed');bodies.append(data)
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision),'private project revision')
    require(end-time.monotonic()>2,'private startup deadline')
    process=subprocess.Popen(['/usr/bin/git','-C',str(Path(repository)), 'rev-parse',*(revision+':'+name for name in controller.PUBLIC)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
    failed=False
    try:
        status,output=tools.capture(process,min(end-2,time.monotonic()+3),[tools.OUTPUT_BYTES-256])
    except Exception:
        failed=True;raise ValueError('private project identity unavailable') from None
    finally:
        try:tools.stop(process)
        except Exception:
            if not failed:raise ValueError('private project identity cleanup unresolved') from None
    expected=[hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() for body in bodies[:4]]
    require(status==0 and not output['stderr'] and output['stdout']==('\n'.join(expected)+'\n').encode(),'private project documents differ from revision')
    return Corpus(revision,bodies,'private-runtime')

def read_bundle(root,mode='synthetic-fixture',end=None):
    end=end or time.monotonic()+20;root=Path(root)
    require(not root.is_symlink() and {p.name for p in root.iterdir()}=={'manifest.json',*(ident+'.txt' for ident in IDS)},'unknown startup inputs')
    manifest=json.loads(snapshot(root/'manifest.json',end),object_pairs_hook=unique)
    require(type(manifest) is dict and set(manifest)=={'version','mode','project_revision','standards_sha','documents'} and type(manifest['version']) is int and manifest['version']==1 and manifest['mode']==mode,'startup manifest schema')
    corpus=Corpus(manifest['project_revision'],[snapshot(root/(ident+'.txt'),end) for ident in IDS],mode)
    require(canonical(manifest)==canonical(corpus.manifest),'startup manifest/content mismatch')
    return corpus

def validate_directive(text):
    require(type(text) is str and bool(text) and len((OPEN+'\n'+NOTICE+'\n\n'+'\n'+CLOSE).encode())+len(text.encode())<=40000,'managed startup directive exceeds pinned cap')
    return text

def rendered(corpus):return OPEN+'\n'+corpus.directive()+'\n'+CLOSE

def managed(inputs,corpus,durable=False):
    matches=[]
    for index,item in enumerate(inputs):
        if type(item) is not dict or item.get('role')!='developer':continue
        parts=item.get('content');metadata=item.get(META,{})
        kinds=metadata.get('content_item_kinds') if type(metadata) is dict else None
        candidate=(type(parts) is list and any(type(v) is dict and type(v.get('text')) is str and v['text'].startswith(OPEN) for v in parts)) or (type(kinds) is list and KIND in kinds)
        if not candidate:continue
        require({'type','role','content'}<=set(item)<={'type','role','content','id',META} and item.get('type')=='message' and parts==[{'type':'input_text','text':rendered(corpus)}],'managed startup instruction changed')
        if 'id' in item:
            require(type(item['id']) is str and re.fullmatch('msg_[0-9a-f-]{36}',item['id']),'managed startup message ID')
            controller.session(item['id'][4:]);require(uuid.UUID(item['id'][4:]).version==7,'managed startup UUID family')
        if META in item:
            allowed={'turn_id','create_time','content_item_kinds'}|({'content_item_metadata'} if durable else set())
            require(type(metadata) is dict and set(metadata)<=allowed and metadata.get('content_item_kinds')==[KIND],'managed startup metadata')
            if 'turn_id' in metadata:controller.session(metadata['turn_id'])
            if 'create_time' in metadata:require(type(metadata['create_time']) in (int,float) and 0<metadata['create_time']<1e12,'managed startup timestamp')
            if 'content_item_metadata' in metadata:require(metadata['content_item_metadata']==[{'provenance':{'type':'developer_instructions','from_additional_requirements':True}}],'managed startup attribution')
        projected=json.loads(canonical(item))
        if durable and META in projected:projected[META].pop('content_item_metadata',None)
        matches.append((index,projected))
    require(len(matches)==1,'managed startup instruction missing or duplicated');return matches[0]

def emit_fixed():
    try:
        corpus=read_bundle(ROOT);data=corpus.output();require(len(data)<=6000,'synthetic startup helper output exceeds original token budget')
        sys.stdout.buffer.write(data+b'\n');return 0
    except Exception:
        sys.stderr.write('startup documents unavailable\n');return 2

if __name__=='__main__':raise SystemExit(emit_fixed() if len(sys.argv)==1 else 2)
