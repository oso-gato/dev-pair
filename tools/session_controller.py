"""Private fixed-turn owner and read-only observer; never production job admission.

The trusted same-UID controller supplies source-fixed adapters, not submitted argv.
A persisted PID is diagnostic only. Owner loss never authorizes adoption or replay.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

VERSION=3
ROWS=32
BYTES=1048576
ACTIVE=('reserved','launching','running')
STATES=(*ACTIVE,'completed-turn','failed','uncertain','deferred')
STANDARDS='b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
SHARED={'GOVERNANCE.md':'3cc14e3b86a9920dcbc82a7b08a3a0270bab67bf6cad8262f584aafa0fce016d',
        'ENGINEERING-STANDARDS.md':'8b10a0a16647cb213863d9d7e5af7a20ab06b6a20f6964d9068b08f9f90eb195',
        'REPOSITORY-SETUP.md':'3014148494d56513a9b119bb3265420fb63b407b5f478dfb5197fc35bc1037d4'}
PUBLIC=('README.md','STANDARDS.md','REQUIREMENTS.md','ARCHITECTURE.md')
SQL_SCHEMA={'metadata':'CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)',
            'operations':'CREATE TABLE operations (id TEXT PRIMARY KEY,body TEXT NOT NULL)'}
def require(value,message):
    if not value:raise ValueError(message)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def sha(value):return hashlib.sha256(value).hexdigest()
def loads(value):
    def pairs(items):
        result={}
        for key,item in items:
            require(key not in result,'duplicate controller field');result[key]=item
        return result
    return json.loads(value,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite controller value')))
def token(value):require(type(value) is str and re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',value),'invalid controller ID')
def digest(value):require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'invalid controller digest')
def session(value):
    require(type(value) is str and str(uuid.UUID(value))==value,'invalid controller session UUID');return value

def private_file(path):
    node=path.lstat();require(stat.S_ISREG(node.st_mode) and node.st_uid==os.getuid() and node.st_nlink==1 and stat.S_IMODE(node.st_mode)==0o600,'unsafe controller file')

class DispatchFrozen(ValueError):
    pass

class ExistingOperation(ValueError):
    def __init__(self,row):
        self.observation=dict(row)
        super().__init__('operation already reserved; observe existing outcome')

def startup_receipt(repository,cache,end=None):
    """Read verified private cache only here; never deliver its text to CLI/history."""
    rows={}
    for root,names in ((Path(repository),PUBLIC),(Path(cache),SHARED)):
        for name in names:
            require(end is None or time.monotonic()<end,'startup deadline exhausted')
            path=root/name
            require(not any(p.is_symlink() for p in (path,*path.parents)),'unsafe startup source')
            try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            except OSError:raise ValueError('startup material unavailable') from None
            with os.fdopen(fd,'rb') as stream:
                node=os.fstat(stream.fileno());require(stat.S_ISREG(node.st_mode) and node.st_size<=1048576,'startup source bound')
                data=stream.read(1048577);require(len(data)<=1048576,'startup source bound')
            value=sha(data)
            if name in SHARED:require(value==SHARED[name],'startup standards cache mismatch')
            rows[('shared/' if name in SHARED else 'repository/')+name]=value
    return {'version':1,'standards_sha':STANDARDS,'documents':rows,'model_consumption_verified':False,'delivery':'controller-hash-receipt-only'}


def validate_startup(value):
    require(type(value) is dict and set(value)=={'version','standards_sha','documents','model_consumption_verified','delivery'} and type(value['version']) is int and value['version']==1 and value['standards_sha']==STANDARDS and value['model_consumption_verified'] is False and value['delivery']=='controller-hash-receipt-only','invalid controller startup receipt')
    names={*('repository/'+n for n in PUBLIC),*('shared/'+n for n in SHARED)}
    require(type(value['documents']) is dict and set(value['documents'])==names,'missing startup document receipt')
    for key,entry in value['documents'].items():
        digest(entry)
        if key.startswith('shared/'):require(entry==SHARED[key.split('/',1)[1]],'standards receipt mismatch')
    return value

BINDING_KEYS=set('controller_id job_id checkpoint_id checkpoint_sha256 source_sha256 runtime_sha256 binary_sha256 policy_sha256 layout_sha256 standards_sha agreement_sha256 job_sha256 source_revision provider model effort credential_ref startup_sha256'.split())
def validate_binding(value):
    require(type(value) is dict and set(value)==BINDING_KEYS,'invalid controller binding')
    for key in ('controller_id','job_id','checkpoint_id','credential_ref'):token(value[key])
    for key in BINDING_KEYS-set(('controller_id','job_id','checkpoint_id','credential_ref','provider','model','effort','standards_sha','source_revision')):digest(value[key])
    require(type(value['source_revision']) is str and re.fullmatch('[0-9a-f]{40}',value['source_revision']),'invalid controller source revision')
    require(value['standards_sha']==STANDARDS and value['provider']=='openai' and value['model']=='gpt-5.5' and value['effort']=='unconfigured-fixture','unsupported fixed fixture selection')
    return value

class Registry:
    def __init__(self,directory,binding=None,*,readonly=False):
        self.db=None;self.fd=None;self.ledger=None;self.control_fds={};self.control_nodes=None;self.owner_active=False;self.owner_token=None
        try:self._open(directory,binding,readonly=readonly)
        except BaseException:
            self.close();raise
    def _open(self,directory,binding=None,*,readonly=False):
        self.root=Path(directory).absolute();self.readonly=readonly;self.db=None;self.fd=None;self.ledger=None;self.control_fds={};self.control_nodes=None;self.owner_active=False
        for part in (self.root,*self.root.parents):
            require(not part.is_symlink(),'symlink controller state')
            if part.exists() and part!=self.root:
                node=part.stat();require(node.st_uid in (0,os.getuid()) and (not node.st_mode&0o022 or node.st_uid==0 and node.st_mode&stat.S_ISVTX),'unsafe controller ancestor')
        created=False
        if not readonly:
            try:self.root.mkdir(mode=0o700);created=True
            except FileExistsError:pass
        node=self.root.lstat();require(stat.S_ISDIR(node.st_mode) and node.st_uid==os.getuid() and stat.S_IMODE(node.st_mode)==0o700,'unsafe controller directory')
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.identity=(node.st_dev,node.st_ino)
        self.path=self.root/'registry.sqlite3'
        require(created or self.path.exists(),'incomplete controller state')
        if created:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
            fd=os.open(self.root/'owner.lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
        try:self.check_files()
        except Exception:
            self.close();raise
        for name in ('registry.sqlite3','owner.lock'):
            self.control_fds[name]=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
        self.control_nodes={name:{'device':os.fstat(fd).st_dev,'inode':os.fstat(fd).st_ino} for name,fd in self.control_fds.items()}
        self.check_files()
        uri='file:/proc/self/fd/'+str(self.fd)+'/registry.sqlite3'+('?mode=ro' if readonly else '?mode=rw')
        try:self.db=sqlite3.connect(uri,uri=True,timeout=.1,isolation_level=None)
        except sqlite3.Error:
            self.close();raise ValueError('controller registry rejected') from None
        self.check_files()
        if not readonly:self.db.execute('PRAGMA synchronous=FULL')
        if created:
            validate_binding(binding)
            self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA journal_mode=DELETE')
            self.initializing=True
            with self.transaction():
                for sql in SQL_SCHEMA.values():self.db.execute(sql)
                for key,value in (('version',VERSION),('registry_id','registry-'+uuid.uuid4().hex),('binding',binding),('generation',0),('control_identity',self.control_nodes),('dispatch',{'schema':1,'generation':0,'state':'open','identity':None,'snapshot':None})):
                    self.db.execute('INSERT INTO metadata VALUES (?,?)',(key,canonical(value)))
                self.db.execute('PRAGMA user_version='+str(VERSION))
            self.initializing=False
        try:
            self.validate_schema()
            rows=self.db.execute('SELECT key,value FROM metadata LIMIT 7').fetchall()
            require(len(rows)==6 and len({row[0] for row in rows})==6,'ambiguous controller metadata')
            self.meta={key:loads(value) for key,value in rows}
            require(set(self.meta)=={'version','registry_id','binding','generation','control_identity','dispatch'} and type(self.meta['version']) is int and self.meta['version']==VERSION,'invalid controller metadata')
            require(canonical(self.meta['control_identity'])==canonical(self.control_nodes),'controller control-file identity changed')
            validate_binding(self.meta['binding']);token(self.meta['registry_id'])
            require(type(self.meta['generation']) is int and self.meta['generation']>=0,'invalid controller generation')
            if binding is not None:require(canonical(binding)==canonical(self.meta['binding']),'controller binding changed')
            self.inventory()
        except Exception:
            self.close();raise ValueError('controller registry rejected') from None
    def validate_schema(self):
        require(self.db.execute('PRAGMA user_version').fetchone()[0]==VERSION,'unknown controller version')
        expected=sorted([('table',name,name,sql) for name,sql in SQL_SCHEMA.items()]+[('index','sqlite_autoindex_'+name+'_1',name,None) for name in SQL_SCHEMA],key=lambda row:row[1])
        require(self.db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name LIMIT 5').fetchall()==expected,'unsupported controller SQL schema')
        for name,key,value in (('metadata','key','value'),('operations','id','body')):
            require(self.db.execute('PRAGMA table_xinfo('+name+')').fetchall()==[(0,key,'TEXT',0,None,1,0),(1,value,'TEXT',1,None,0,0)],'unsupported controller columns')
            index='sqlite_autoindex_'+name+'_1'
            require(self.db.execute('PRAGMA index_list('+name+')').fetchall()==[(0,index,1,'pk',0)],'unsupported controller uniqueness')
            require(self.db.execute('PRAGMA index_xinfo('+index+')').fetchall()==[(0,0,key,0,'BINARY',1),(1,-1,None,0,'BINARY',0)],'unsupported controller primary key')
    def validate_metadata(self):
        stored=self.db.execute('SELECT key,value FROM metadata LIMIT 7').fetchall()
        require(len(stored)==6 and len({row[0] for row in stored})==6,'ambiguous controller metadata')
        current={key:loads(value) for key,value in stored}
        require(set(current)==set(self.meta),'unknown controller metadata')
        for key in ('version','registry_id','binding','control_identity'):
            require(canonical(current[key])==canonical(self.meta[key]),'controller metadata identity changed')
        require(canonical(current['control_identity'])==canonical(self.control_nodes),'controller control-file identity changed')
        generation=current['generation'];require(type(generation) is int and 0<=generation<=2147483647,'invalid controller generation')
        self.validate_dispatch(current['dispatch'])
        return generation
    def check_files(self):
        node=self.root.lstat();held=os.fstat(self.fd)
        require(stat.S_ISDIR(node.st_mode) and node.st_uid==os.getuid() and stat.S_IMODE(node.st_mode)==0o700 and (node.st_dev,node.st_ino)==self.identity and (held.st_dev,held.st_ino)==self.identity,'controller directory changed')
        allowed={'registry.sqlite3','owner.lock','registry.sqlite3-journal'}
        names=set(p.name for p in self.root.iterdir());require({'registry.sqlite3','owner.lock'}<=names<=allowed,'unknown or missing controller state file')
        total=0
        for path in self.root.iterdir():
            private_file(path);total+=path.stat().st_size
        require(total<=BYTES,'controller state byte bound')
        for name,fd in self.control_fds.items():
            held=os.fstat(fd);current=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            expected=self.control_nodes[name] if self.control_nodes is not None else {'device':held.st_dev,'inode':held.st_ino}
            require(stat.S_ISREG(current.st_mode) and (current.st_dev,current.st_ino)==(held.st_dev,held.st_ino)==(expected['device'],expected['inode']) and held.st_nlink==1,'controller control-file identity changed')
    def close(self):
        require(not self.owner_active,'cannot close an active controller owner')
        if self.db is not None:self.db.close();self.db=None
        for fd in self.control_fds.values():os.close(fd)
        self.control_fds={}
        if self.fd is not None:os.close(self.fd);self.fd=None
        if self.ledger is not None:self.ledger.close();self.ledger=None
    @contextlib.contextmanager
    def transaction(self):
        require(not self.readonly,'observer cannot mutate');self.check_files();self.db.execute('BEGIN IMMEDIATE')
        try:
            if not getattr(self,'initializing',False):
                self.validate_schema()
                if hasattr(self,'meta'):self.validate_metadata()
            yield
            self.check_files();self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
    @contextlib.contextmanager
    def owner(self):
        require(not self.readonly and not self.owner_active,'observer or nested owner denied');self.check_files()
        fd=self.control_fds['owner.lock']
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('controller owner busy') from None
            self.owner_active=True;self.owner_token=uuid.uuid4().hex;self.check_files()
            primary_pending=False
            try:yield
            except BaseException:
                primary_pending=True;raise
            finally:
                try:self.check_files()
                except Exception:
                    if not primary_pending:raise ValueError('controller control-file identity changed') from None
        finally:
            if self.owner_active:fcntl.flock(fd,fcntl.LOCK_UN);self.owner_active=False;self.owner_token=None
    def row(self,operation):
        token(operation)
        matches=[row for row in self.inventory()['operations'] if row['operation']==operation]
        require(len(matches)<=1,'ambiguous controller operation')
        return matches[0] if matches else None
    def validate_row(self,operation,body):
        require(type(body) is str and len(body.encode())<=4096,'controller row byte bound')
        value=loads(body);keys=set('operation request_sha256 logical_session mode expected_uuid uuid state sequence exit_code capture_complete owner_pid deadline reason checkpoint_id checkpoint_sha256 cleanup launch_handle_observed prompt_sha256 prompt_bytes owner_lease'.split())
        require(type(value) is dict and set(value)==keys and value['operation']==operation and value['state'] in STATES,'invalid controller operation')
        digest(value['request_sha256']);token(value['logical_session']);token(value['checkpoint_id']);digest(value['checkpoint_sha256']);digest(value['prompt_sha256'])
        require(type(value['prompt_bytes']) is int and 0<value['prompt_bytes']<=262144,'invalid stored prompt length')
        expected=self.request_identity(value['logical_session'],value['prompt_sha256'],value['prompt_bytes'],value['expected_uuid'],{key:value[key] for key in ('checkpoint_id','checkpoint_sha256')})
        require(value['request_sha256']==expected,'stored operation request binding changed')
        require(value['cleanup'] in ('not-observed','owned-child-reaped','unresolved','not-launched') and (value['launch_handle_observed'] is None or type(value['launch_handle_observed']) is bool),'invalid controller cleanup observation')
        require(value['mode'] in ('start','resume') and type(value['sequence']) is int and 0<=value['sequence']<=2097152 and value['reason'] in ('none','rejected','owner-loss','cleanup-unresolved','freeze-before-launch'),'invalid controller state')
        for key in ('expected_uuid','uuid'):
            if value[key] is not None:session(value[key])
        require(value['exit_code'] is None or type(value['exit_code']) is int and -255<=value['exit_code']<=255,'invalid controller exit')
        require((value['capture_complete'] is None or type(value['capture_complete']) is bool) and type(value['owner_pid']) is int and value['owner_pid']>0 and type(value['deadline']) in (int,float) and 0<value['deadline']<1e12,'invalid controller observation')
        require(value['state']!='completed-turn' or value['uuid'] is not None and value['exit_code']==0 and value['capture_complete'] is True and value['cleanup']=='owned-child-reaped' and value['launch_handle_observed'] is True,'corrupt terminal controller state')
        require((value['mode']=='start')==(value['expected_uuid'] is None),'controller mode/expected UUID mismatch')
        require(value['mode']!='resume' or value['uuid'] is None or value['uuid']==value['expected_uuid'],'controller resume UUID contradiction')
        state=value['state']
        require(state=='reserved' or value['sequence']>=1,'invalid controller state sequence')
        require(value['uuid'] is None or value['launch_handle_observed'] is True,'UUID without owned launcher observation')
        require(value['owner_lease'] is None or type(value['owner_lease']) is str and re.fullmatch('[0-9a-f]{32}',value['owner_lease']),'invalid operation owner lease')
        require((value['cleanup']=='not-launched')==(state=='deferred') and (value['launch_handle_observed'] is not False or state=='deferred'),'contradictory not-launched evidence')
        if state=='deferred':require(value['sequence']>=1 and value['owner_lease'] is not None and value['uuid'] is None and value['launch_handle_observed'] is False and value['cleanup']=='not-launched' and value['reason']=='freeze-before-launch' and value['exit_code'] is None and value['capture_complete'] is None,'invalid deferred controller state')
        if state in ('launching','running','completed-turn','failed'):require(value['owner_lease'] is not None,'missing operation owner lease')
        if state=='reserved':require(value['sequence']==0 and value['uuid'] is None and value['launch_handle_observed'] is None and value['cleanup']=='not-observed' and value['reason']=='none','invalid reserved controller state')
        if state=='launching':require(value['uuid'] is None and value['launch_handle_observed'] is None and value['cleanup']=='not-observed' and value['reason']=='none','invalid launching controller state')
        if state=='running':require(value['launch_handle_observed'] is True and value['reason']=='none','invalid running controller state')
        if state in ACTIVE or state=='uncertain':require(value['exit_code'] is None and value['capture_complete'] is None,'invalid incomplete controller result')
        if state=='uncertain':require(value['reason'] in ('owner-loss','rejected','cleanup-unresolved'),'invalid uncertain controller reason')
        if state=='failed':require(type(value['exit_code']) is int and value['exit_code']!=0 and value['capture_complete'] is True and value['cleanup']=='owned-child-reaped' and value['launch_handle_observed'] is True and value['reason']=='rejected','invalid failed controller result')
        if state=='completed-turn':require(value['reason']=='none','invalid completed controller reason')
        return value
    def validate_dispatch(self,value):
        require(type(value) is dict and set(value)=={'schema','generation','state','identity','snapshot'} and type(value['schema']) is int and value['schema']==1 and type(value['generation']) is int and 0<=value['generation']<=2147483647 and value['state'] in ('open','frozen'),'invalid dispatch metadata')
        ident=value['identity']
        if value['generation']==0:
            require(value['state']=='open' and ident is None and value['snapshot'] is None,'invalid initial dispatch state');return value
        require(type(ident) is dict and set(ident)=={'registry_id','attempt','token','generation','requested_generation','binding_sha256'},'invalid freeze identity')
        token(ident['attempt']);token(ident['registry_id']);digest(ident['binding_sha256'])
        require(ident['registry_id']==self.meta['registry_id'] and ident['binding_sha256']==sha(canonical(self.meta['binding']).encode()) and type(ident['token']) is str and re.fullmatch('[0-9a-f]{32}',ident['token']) and type(ident['generation']) is int and ident['generation']==value['generation'] and type(ident['requested_generation']) is int and ident['requested_generation']==ident['generation']-1,'freeze binding changed')
        snapshot=value['snapshot']
        if snapshot is not None:
            require(type(snapshot) is dict and set(snapshot)=={'schema','freeze','binding','registry_generation','operations','sessions','unbound_operations','quiescent','runtime_admitted'} and snapshot['schema']==1 and type(snapshot['schema']) is int and snapshot['freeze']==ident and snapshot['binding']==self.meta['binding'] and snapshot['quiescent'] is True and snapshot['runtime_admitted'] is False,'invalid freeze snapshot')
            require(type(snapshot['registry_generation']) is int and 0<=snapshot['registry_generation']<=2147483647 and type(snapshot['operations']) is list and len(snapshot['operations'])<=ROWS,'invalid snapshot bounds')
            rows=[self.validate_row(row['operation'],canonical(row)) for row in snapshot['operations']]
            require(len({row['operation'] for row in rows})==len(rows) and all(self.safe_drained(row) for row in rows),'invalid snapshot operations')
            require(snapshot['sessions']==[{'logical_session':a,'uuid':b} for a,b in sorted({(r['logical_session'],r['uuid']) for r in rows if r['uuid'] is not None})] and snapshot['unbound_operations']==[r['operation'] for r in rows if r['uuid'] is None],'incomplete freeze snapshot')
        return value
    def dispatch(self):
        rows=self.db.execute("SELECT value FROM metadata WHERE key='dispatch'").fetchall();require(len(rows)==1,'ambiguous dispatch metadata')
        return self.validate_dispatch(loads(rows[0][0]))
    def store_dispatch(self,value):
        self.validate_dispatch(value)
        self.db.execute("UPDATE metadata SET value=? WHERE key='dispatch'",(canonical(value),))
        self.db.execute("UPDATE metadata SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='generation'")
        self.validate_metadata() # Reject overflow inside the transaction, before acknowledgement.
    def freeze_binding(self,binding):
        validate_binding(binding);require(canonical(binding)==canonical(self.meta['binding']),'freeze caller binding changed')
    def request_freeze(self,attempt,generation,binding):
        token(attempt);require(type(generation) is int and 0<=generation<2147483647,'invalid freeze generation');self.freeze_binding(binding)
        with self.transaction():
            self.inventory();value=self.dispatch()
            if value['state']=='frozen':
                ident=value['identity'];require(ident['attempt']==attempt and ident['requested_generation']==generation,'freeze request collision');return ident
            require(value['generation']==generation,'stale freeze generation')
            ident={'registry_id':self.meta['registry_id'],'attempt':attempt,'token':uuid.uuid4().hex,'generation':generation+1,'requested_generation':generation,'binding_sha256':sha(canonical(binding).encode())}
            self.store_dispatch({'schema':1,'generation':generation+1,'state':'frozen','identity':ident,'snapshot':None})
            return ident
    def freeze_match(self,receipt,binding):
        self.freeze_binding(binding);value=self.dispatch()
        require(type(receipt) is dict and canonical(value['identity'])==canonical(receipt),'stale or forged freeze token');return value
    def abort_freeze(self,receipt,binding):
        with self.transaction():
            self.inventory();value=self.freeze_match(receipt,binding);self.current_checkpoint()
            if value['state']=='open':return value
            value['state']='open';value['snapshot']=None;self.store_dispatch(value);return value
    @staticmethod
    def safe_drained(row):
        return row['state']=='deferred' and row['launch_handle_observed'] is False and row['cleanup']=='not-launched' or row['state'] in ('completed-turn','failed') and row['launch_handle_observed'] is True and row['cleanup']=='owned-child-reaped'
    def seal_snapshot(self,receipt,binding):
        with self.owner():
            with self.transaction():
                inventory=self.inventory();value=self.freeze_match(receipt,binding)
                require(value['state']=='frozen','dispatch is not frozen')
                if value['snapshot'] is not None:return value['snapshot']
                require(all(self.safe_drained(row) for row in inventory['operations']),'controller draining or cleanup uncertain')
                snapshot={'schema':1,'freeze':value['identity'],'binding':self.meta['binding'],'registry_generation':inventory['generation']+1,'operations':inventory['operations'],'sessions':inventory['sessions'],'unbound_operations':[r['operation'] for r in inventory['operations'] if r['uuid'] is None],'quiescent':True,'runtime_admitted':False}
                require(len(canonical(snapshot).encode())<=BYTES,'freeze snapshot byte bound')
                value['snapshot']=snapshot;self.store_dispatch(value);self.inventory();return snapshot
    def admit_launch(self,operation):
        require(self.owner_active and self.owner_token is not None,'launch requires current owner lease')
        deferred=False
        with self.transaction():
            row=self.row(operation);require(row is not None and row['state']=='reserved' and row['owner_lease']==self.owner_token,'launch reservation owner mismatch')
            deferred=self.dispatch()['state']=='frozen'
            row.update(state='deferred' if deferred else 'launching');row['sequence']+=1
            if deferred:row.update(reason='freeze-before-launch',launch_handle_observed=False,cleanup='not-launched')
            self.write(row)
        if deferred:raise DispatchFrozen('dispatch frozen before launch; no child launched')
        return row
    def current_checkpoint(self):
        import job_protocol as p
        require(self.ledger is not None and self.ledger.controller_id==self.meta['binding']['controller_id'],'trusted ledger unavailable')
        job=self.ledger.record('job',self.meta['binding']['job_id']);p.validate(job,'job')
        binding=self.meta['binding']
        require(p.identity(job)==binding['job_sha256'] and job['standards_sha']==binding['standards_sha'] and job['agreement_sha256']==binding['agreement_sha256'] and job['selection']['model']==binding['model'] and job['selection']['runtime_sha256']==binding['runtime_sha256'],'job selection changed')
        row=self.ledger.db.execute('SELECT checkpoint FROM jobs WHERE id=?',(binding['job_id'],)).fetchone()
        require(row is not None and row['checkpoint'] is not None,'current checkpoint unavailable')
        cp=self.ledger.record('checkpoint',row['checkpoint']);p.validate(cp,'checkpoint')
        require(cp['job_id']==binding['job_id'] and cp['candidate']['artifact_sha256']==binding['binary_sha256'] and cp['candidate']['source_revision']==binding['source_revision'],'checkpoint target changed')
        return {'checkpoint_id':cp['checkpoint_id'],'checkpoint_sha256':p.identity(cp)}
    def inventory(self):
        self.check_files();owned=not self.db.in_transaction
        if owned:self.db.execute('BEGIN')
        try:
            self.validate_schema();generation=self.validate_metadata()
            stored=self.db.execute('SELECT id,body FROM operations ORDER BY id LIMIT 33').fetchall()
            ids=[row[0] for row in stored];require(len(ids)<=ROWS and len(set(ids))==len(ids),'controller row bound or duplicate IDs')
            rows=[]
            for operation,body in stored:token(operation);rows.append(self.validate_row(operation,body))
            identities={};active=set()
            for row in rows:
                if row['uuid'] is not None:
                    previous=identities.setdefault(row['uuid'],row['logical_session']);require(previous==row['logical_session'],'corrupt session ownership')
                if row['state'] in (*ACTIVE,'uncertain'):
                    require(row['logical_session'] not in active,'corrupt active session inventory');active.add(row['logical_session'])
            origins={}
            for row in rows:
                if row['mode']=='start':
                    require(row['logical_session'] not in origins,'duplicate logical session origin');origins[row['logical_session']]=row
            for row in rows:
                origin=origins.get(row['logical_session']);require(origin is not None,'missing logical session origin')
                if row['mode']=='resume':require(origin['state']=='completed-turn' and row['expected_uuid']==origin['uuid'],'conflicting logical session UUID')
                if row['uuid'] is not None:require(row['uuid']==origin['uuid'],'substituted logical session UUID')
            sessions=sorted({(r['logical_session'],r['uuid']) for r in rows if r['uuid'] is not None})
            dispatch=self.dispatch()
            if dispatch['state']=='frozen' and dispatch['snapshot'] is not None:
                require(dispatch['snapshot']['operations']==rows and dispatch['snapshot']['registry_generation']==generation,'sealed registry inventory changed')
            return {'dispatch':dispatch,'version':VERSION,'registry_id':self.meta['registry_id'],'controller_id':self.meta['binding']['controller_id'],'generation':generation,'operations':rows,'sessions':[{'logical_session':a,'uuid':b} for a,b in sessions],'scope':'all positive operations for this controller; negative fixture probe is separate','runtime_admitted':False}
        finally:
            if owned:self.db.execute('COMMIT')
    def write(self,row):
        self.validate_row(row['operation'],canonical(row))
        self.db.execute('INSERT OR REPLACE INTO operations VALUES (?,?)',(row['operation'],canonical(row)))
        self.db.execute("UPDATE metadata SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='generation'")
        self.inventory()
    def request_identity(self,logical_session,prompt_sha256,prompt_bytes,resume,checkpoint):
        return sha(canonical({'registry_id':self.meta['registry_id'],'binding':self.meta['binding'],'logical_session':logical_session,'prompt_sha256':prompt_sha256,'prompt_bytes':prompt_bytes,'resume':resume,**checkpoint}).encode())
    def reserve(self,operation,logical_session,prompt,deadline,resume=None):
        token(operation);token(logical_session);require(type(prompt) is str and 0<len(prompt.encode())<=262144,'invalid fixed prompt')
        if resume is not None:session(resume)
        with self.transaction():
            rows=self.inventory()['operations']
            prior=self.row(operation)
            checkpoint={key:prior[key] for key in ('checkpoint_id','checkpoint_sha256')} if prior is not None else self.current_checkpoint()
            request=self.request_identity(logical_session,sha(prompt.encode()),len(prompt.encode()),resume,checkpoint)
            if prior is not None:require(prior['request_sha256']==request,'operation request collision');return prior,False
            require(self.dispatch()['state']=='open','controller dispatch frozen')
            require(type(deadline) in (int,float) and time.monotonic()<deadline<=time.monotonic()+180,'invalid original controller deadline')
            require(len(rows)<ROWS,'controller row bound')
            require(not any(r['state'] in (*ACTIVE,'uncertain') and (r['logical_session']==logical_session or resume is not None and r['uuid']==resume) for r in rows),'session already active or uncertain')
            if resume is None:require(not any(r['logical_session']==logical_session for r in rows),'start identity already exists')
            else:require(any(r['logical_session']==logical_session and r['uuid']==resume and r['state']=='completed-turn' for r in rows),'resume not bound to completed owned session')
            row={'operation':operation,'request_sha256':request,'logical_session':logical_session,'mode':'resume' if resume else 'start','expected_uuid':resume,'uuid':None,'state':'reserved','sequence':0,'exit_code':None,'capture_complete':None,'owner_pid':os.getpid(),'deadline':deadline,'reason':'none','cleanup':'not-observed','launch_handle_observed':None,'prompt_sha256':sha(prompt.encode()),'prompt_bytes':len(prompt.encode()),'owner_lease':self.owner_token if self.owner_active else None,**checkpoint}
            self.write(row);return row,True
    def update(self,operation,**values):
        require(set(values)<= {'state','reason','exit_code','capture_complete','cleanup','launch_handle_observed','uuid'},'immutable controller operation binding')
        if values.get('state')=='launching':
            require(set(values)=={'state'},'invalid launch admission');return self.admit_launch(operation)
        with self.transaction():
            row=self.row(operation);require(row is not None,'unknown controller operation')
            require(row['state']!='deferred','deferred operation is observe-only')
            require(row['state']!='reserved' or values.get('state') in (None,'uncertain'),'reserved launch requires admission')
            row.update(values);row['sequence']+=1;self.write(row)
        return row
    def uncertain(self):
        with self.transaction():
            for row in self.inventory()['operations']:
                if row['state'] in ACTIVE:row.update(state='uncertain',reason='owner-loss');row['sequence']+=1;self.write(row)

class Observer:
    def __init__(self,directory):self.registry=Registry(directory,readonly=True)
    def owner_held(self):
        self.registry.check_files();fd=self.registry.control_fds['owner.lock']
        try:
            try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError:return True
            return False
        finally:fcntl.flock(fd,fcntl.LOCK_UN)
    def project(self,row,held):
        if not held and row['state'] in ACTIVE:row.update(state='uncertain',reason='owner-loss')
        return row
    def inventory(self):
        value=self.registry.inventory();held=self.owner_held()
        value['operations']=[self.project(row,held) for row in value['operations']]
        snapshot=value['dispatch']['snapshot']
        if snapshot is not None:
            value['dispatch']['snapshot']={'schema':1,'sha256':sha(canonical(snapshot).encode()),'registry_generation':snapshot['registry_generation'],'operation_count':len(snapshot['operations']),'quiescent':value['dispatch']['state']=='frozen'}
        value['owner_lease_observed']='held' if held else 'unheld'
        return value
    def reattach(self,operation):
        self.registry.check_files();row=self.registry.row(operation);require(row is not None,'unknown controller operation')
        return self.project(row,self.owner_held())
    def close(self):self.registry.close()

class TurnOwner:
    """Owns one source-fixed adapter invocation; observers never receive its handle."""
    def __init__(self,registry,operation):self.registry=registry;self.operation=operation;self.uuid=None;self.started=False;self.completed=False
    def launching(self):self.registry.admit_launch(self.operation)
    def child(self,process):
        require(process.pid>0,'child handle unavailable');self.registry.update(self.operation,state='running',launch_handle_observed=True)
    def cleanup(self,complete):
        self.registry.update(self.operation,cleanup='owned-child-reaped' if complete else 'unresolved')
    def event(self,raw):
        def pairs(items):
            row={}
            for k,v in items:require(k not in row,'duplicate controller event field');row[k]=v
            return row
        row=json.loads(raw,object_pairs_hook=pairs);require(type(row) is dict,'invalid controller CLI event');kind=row.get('type')
        if kind=='thread.started':
            require(set(row)=={'type','thread_id'} and self.uuid is None,'duplicate controller thread event');value=session(row['thread_id'])
            current=self.registry.row(self.operation);require(current['expected_uuid'] is None or current['expected_uuid']==value,'controller resume UUID mismatch')
            require(not any(r['operation']!=self.operation and r['logical_session']!=current['logical_session'] and r['uuid']==value for r in self.registry.inventory()['operations']),'controller session collision')
            self.uuid=value;self.registry.update(self.operation,uuid=value)
        elif kind=='turn.started':require(set(row)=={'type'} and self.uuid is not None and not self.started and not self.completed,'controller turn order');self.started=True
        elif kind=='turn.completed':
            keys={'input_tokens','cached_input_tokens','cache_write_input_tokens','output_tokens','reasoning_output_tokens'}
            require(set(row)=={'type','usage'} and self.started and not self.completed and type(row.get('usage')) is dict and set(row['usage'])==keys and all(type(v) is int and 0<=v<2**63 for v in row['usage'].values()),'controller terminal order/schema');self.completed=True
        else:
            require(kind in ('item.started','item.updated','item.completed') and set(row)=={'type','item'} and type(row['item']) is dict and type(row['item'].get('id')) is str and row['item']['id'] and type(row['item'].get('type')) is str and self.started and not self.completed,'controller event rejected')
            require(row['item']['type'] in ('agent_message','reasoning','command_execution'),'unplanned fixed fixture item')
            item=row['item']
            if item['type'] in ('agent_message','reasoning'):
                require(set(item)=={'id','type','text'} and type(item['text']) is str,'malformed fixed fixture text item')
            else:
                require(set(item)=={'id','type','command','aggregated_output','exit_code','status'} and type(item['command']) is str and type(item['aggregated_output']) is str and (item['exit_code'] is None or type(item['exit_code']) is int and -(2**31)<=item['exit_code']<2**31) and item['status'] in ('in_progress','completed'),'malformed or failed fixed command item')
            self.registry.update(self.operation,state='running')
    def finish(self,code,complete):
        if type(code) is int and code!=0 and complete:
            self.registry.update(self.operation,state='failed',reason='rejected',exit_code=code,capture_complete=True)
        require(code==0 and type(code) is int and complete and self.completed and self.registry.row(self.operation)['cleanup']=='owned-child-reaped','controller turn incomplete')
        return self.registry.update(self.operation,state='completed-turn',exit_code=code,capture_complete=True)
    def fail(self,uncertain=False):
        reason='cleanup-unresolved' if self.registry.row(self.operation)['cleanup']=='unresolved' else 'rejected'
        return self.registry.update(self.operation,state='uncertain' if uncertain else 'failed',reason=reason)


def main():
    import argparse
    parser=argparse.ArgumentParser(description='Read-only private fixed-turn observer; no dispatch or PID authority.')
    parser.add_argument('--registry',required=True,type=Path);parser.add_argument('--operation')
    args=parser.parse_args();observer=None
    try:
        observer=Observer(args.registry)
        value=observer.reattach(args.operation) if args.operation else observer.inventory()
        data=canonical(value).encode();require(len(data)<=65536,'observer projection bound')
        print(data.decode());return 0
    except Exception:
        print(canonical({'status':'unavailable','reason':'registry-rejected'}));return 2
    finally:
        if observer is not None:observer.close()

if __name__=='__main__':raise SystemExit(main())
