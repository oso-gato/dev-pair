"""Private offline fixture helper identity; never a production executor."""
import errno
import fcntl
import os
from pathlib import Path
import re
import stat
import time
from dataclasses import dataclass


def require(value):
    if not value:raise ValueError('owned CLI helper binding unavailable')


def identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size)


def bounded(fd,name,limit):
    handle=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
    try:
        data=os.read(handle,limit+1);require(len(data)<=limit);return data
    finally:os.close(handle)


def names(fd,limit,end=None):
    result=[]
    with os.scandir(fd) as entries:
        for entry in entries:
            require((end is None or time.monotonic()<end) and len(result)<limit);result.append(entry.name)
    return result


@dataclass(frozen=True)
class Evidence:
    owner: object
    path: str
    directory: tuple
    lock: tuple
    binary: tuple
    start: tuple
    def __getitem__(self,key):return getattr(self,key)


class OwnedChild:
    def __init__(self,process,end,binary='/opt/codex',helper_root='/state/codex/tmp/arg0-linux'):
        self.process=process;self.end=end;self.binary=Path(binary);self.root=Path(helper_root)
        self.proc=os.open('/proc/'+str(process.pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:self.start=self.live()
        except BaseException:self.close();raise

    def close(self):
        if self.proc is not None:os.close(self.proc);self.proc=None

    def live(self):
        require(time.monotonic()<self.end and self.process.poll() is None and self.proc is not None)
        raw=bounded(self.proc,'stat',4096).decode('ascii');right=raw.rfind(')');fields=raw[right+2:].split()
        require(raw.startswith(str(self.process.pid)+' (') and right>0 and len(fields)>=20 and fields[0] not in ('Z','X') and
            int(fields[1])==os.getpid() and os.fstat(self.proc).st_uid==os.getuid())
        value=(int(raw.split(' ',1)[0]),int(fields[19]))
        require(not hasattr(self,'start') or value==self.start)
        return value

    def capture(self):
        self.stage='ancestry';self.live();opened=[];chain=[];candidates=[]
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
        def directory(parent,name,private=False):
            fd=os.open(name,flags,dir_fd=parent);opened.append(fd);info=os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and not info.st_mode&0o022)
            if private:require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
            chain.append((parent,name,fd,identity(info)));return fd
        def unchanged():
            for parent,name,fd,known in chain:
                require(identity(os.fstat(fd))==known and identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==known)
        try:
            root=os.open('/',flags);opened.append(root)
            current=root
            for part in self.root.parts[1:]:current=directory(current,part,part==self.root.name)
            # Only fixed owned helper-root children and fixed .lock metadata.
            self.stage='helper-directory';locks={}
            for name in names(current,32,self.end):
                require(re.fullmatch(r'codex-arg0[A-Za-z0-9]{1,64}',name))
                fd=directory(current,name,True)
                info=os.stat('.lock',dir_fd=fd,follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and
                    info.st_size==0 and stat.S_IMODE(info.st_mode) in (0o600,0o644))
                key=(info.st_dev,info.st_ino);require(key not in locks);locks[key]=(name,fd,info)
            self.stage='owned-descriptor';fds=os.open('fd',flags,dir_fd=self.proc);opened.append(fds)
            infos=os.open('fdinfo',flags,dir_fd=self.proc);opened.append(infos)
            for number in names(fds,256,self.end):
                require(re.fullmatch(r'0|[1-9][0-9]{0,8}',number))
                try:info=os.stat(number,dir_fd=fds)
                except FileNotFoundError:continue  # Unrelated transient descriptors may close.
                key=(info.st_dev,info.st_ino)
                if key not in locks:continue
                self.stage='exclusive-lock';raw=bounded(infos,number,4096).decode('ascii')
                lines=raw.splitlines();keys=[line.split(':',1)[0] for line in lines]
                require(len(keys)==len(set(keys)) and set(keys)=={'pos','flags','mnt_id','ino','lock'})
                values=dict(line.split(':',1) for line in lines)
                require(values['pos'].strip()=='0' and int(values['ino'])==info.st_ino and int(values['flags'],8)&3==os.O_RDWR and int(values['mnt_id'])>0)
                match=re.fullmatch(r'\s*[0-9]+: FLOCK\s+ADVISORY\s+WRITE ([0-9]+) ([0-9a-f]+):([0-9a-f]+):([0-9]+) 0 EOF',values['lock'])
                require(match is not None and tuple(map(int,(match[1],match[4])))==(self.process.pid,info.st_ino) and
                    int(match[2],16)==os.major(info.st_dev) and int(match[3],16)==os.minor(info.st_dev))
                candidates.append((number,locks[key],raw))
            require(len(candidates)==1)
            number,(name,helper,lock_info),lock_record=candidates[0]
            self.stage='binary-alias'
            require(set(names(helper,5,self.end))=={'.lock','apply_patch','applypatch','codex-linux-sandbox'})
            binary=os.open(self.binary,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);opened.append(binary)
            binary_info=os.fstat(binary)
            require(stat.S_ISREG(binary_info.st_mode) and not binary_info.st_mode&0o222 and binary_info.st_nlink==1)
            require(os.readlink('exe',dir_fd=self.proc)==str(self.binary))
            exe=os.open('exe',os.O_RDONLY|os.O_CLOEXEC,dir_fd=self.proc);opened.append(exe)
            require(identity(os.fstat(exe))==identity(binary_info))
            alias_records=[]
            for alias in ('apply_patch','applypatch','codex-linux-sandbox'):
                info=os.stat(alias,dir_fd=helper,follow_symlinks=False)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and
                    os.readlink(alias,dir_fd=helper)==str(self.binary))
                alias_records.append((alias,identity(info)))
            lock=os.open('.lock',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=helper);opened.append(lock)
            require(identity(os.fstat(lock))==identity(lock_info))
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError as error:require(error.errno in (errno.EAGAIN,errno.EACCES))
            else:
                fcntl.flock(lock,fcntl.LOCK_UN);require(False)
            self.stage='recheck';unchanged()
            require(bounded(infos,number,4096).decode('ascii')==lock_record and
                identity(os.stat('exe',dir_fd=self.proc))==identity(binary_info) and os.readlink('exe',dir_fd=self.proc)==str(self.binary))
            for alias,known in alias_records:
                require(identity(os.stat(alias,dir_fd=helper,follow_symlinks=False))==known and os.readlink(alias,dir_fd=helper)==str(self.binary))
            require(identity(os.stat('.lock',dir_fd=helper,follow_symlinks=False))==identity(lock_info) and
                identity(os.stat(number,dir_fd=fds))==identity(lock_info) and
                identity(os.stat(self.binary,follow_symlinks=False))==identity(binary_info))
            self.live()
            return Evidence(self,str(self.root/name),identity(os.fstat(helper)),identity(lock_info),identity(binary_info),self.start)
        except (OSError,UnicodeError,ValueError,KeyError,IndexError):
            raise ValueError('owned CLI helper binding unavailable') from None
        finally:
            for fd in reversed(opened):os.close(fd)


def xml_text(value):
    return value.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&apos;')


def filesystem(content,parse):
    """One existing bounded environment parse, ephemeral frames and ordered tuples."""
    import json
    from hashlib import sha256
    model={'entries':[],'roots':[],'targets':[]};stack=[];active=False
    def visit(event,name,data,offset):
        nonlocal active
        if event=='start':
            if name=='filesystem':active=True
            if not active:return
            attrs=dict(zip(data[::2],data[1::2]));stack.append([name,attrs,offset,[]])
            if name=='permission_profile':
                require(attrs['type'] in ('managed','disabled','external'));model['profile']=attrs['type']
            if name=='file_system':
                require(attrs['type'] in ('restricted','unrestricted','external'))
                depth=attrs.get('glob_scan_max_depth');require(depth is None or re.fullmatch(r'0|[1-9][0-9]{0,9}',depth) and int(depth)<=2**32-1)
                require(depth is None or attrs['type']=='restricted');model['mode']=attrs['type'];model['depth']=depth
            if name=='entry':
                require(attrs['access'] in ('read','write','deny') and attrs.get('escalatable') in (None,'false','true'))
                require('escalatable' not in attrs or attrs['access']=='deny')
                model['pending']=[attrs['access'],attrs.get('escalatable')]
        elif active and event=='text':stack[-1][3].append(data)
        elif active and event=='end':
            node,attrs,start,text=stack.pop();value=''.join(text)
            if node=='root':model['roots'].append(value)
            if node in ('path','glob','special'):
                model['pending'] += [node,value];model['targets'].append((start,offset,node))
            if node=='entry':model['entries'].append(tuple(model.pop('pending')))
            if node=='filesystem':active=False
    try:
        parsed=parse(content,visit)
        require(parsed['status']=='parsed' and 'filesystem' in parsed['spans'] and 'pending' not in model)
        require((model['profile'],model['mode']) in (('managed','restricted'),('managed','unrestricted'),('disabled','unrestricted'),('external','external')))
        require(model['mode']=='restricted' or not model['entries'])
        raw=content[0]['text'].encode();model.update(raw=raw,parsed=parsed,span=parsed['spans']['filesystem'])
        return model
    except (ValueError,KeyError,TypeError,IndexError):return None


def transformed(original,current,old_helper,new_helper,parse):
    """Derive from audited old bytes and independently observed identities only."""
    try:
        require(isinstance(old_helper,Evidence) and isinstance(new_helper,Evidence) and old_helper.owner is not new_helper.owner and old_helper.path!=new_helper.path and old_helper.binary==new_helper.binary)
        old=filesystem(original,parse);new=filesystem(current,parse);require(old is not None and new is not None)
        require(old['profile']=='managed' and old['mode']=='restricted' and new['profile']=='managed' and new['mode']=='restricted')
        require(old['depth'] is None and new['depth'] is None and old['roots']==new['roots'])
        old_order=list(old['parsed']['spans']);new_order=list(new['parsed']['spans'])
        require(old_order==['cwd','shell','current_date','timezone','filesystem'] and new_order==['current_date','timezone','filesystem'])
        raw=old['raw'];spans=old['parsed']['spans']
        require(raw[spans['cwd'][0]:spans['cwd'][1]]==b'<cwd>/job</cwd>\n  ' and
                raw[spans['shell'][0]:spans['shell'][1]]==b'<shell>bash</shell>\n  ')
        matches=[i for i,value in enumerate(old['entries']) if value==('read',None,'path',old_helper['path'])]
        require(len(matches)==1 and sum(value[3]==old_helper['path'] for value in old['entries'])==1)
        index=matches[0];start,end,kind=old['targets'][index]
        require(kind=='path' and raw[start:start+6]==b'<path>' and raw[end:end+7]==b'</path>' and
            raw[start+6:end]==xml_text(old_helper['path']).encode())
        expected=raw[:start+6]+xml_text(new_helper['path']).encode()+raw[end:]
        # Target is after both omitted components, so their original offsets remain exact.
        for key in ('shell','cwd'):
            left,right=spans[key];expected=expected[:left]+expected[right:]
        require(current==[{'type':'input_text','text':expected.decode()}])
        return True
    except (ValueError,KeyError,TypeError,IndexError,UnicodeError):return False


def filesystem_witness(original,current,parse):
    import json
    from hashlib import sha256
    from collections import Counter
    def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    def digest(value):return sha256(canonical(value)).hexdigest()
    old=filesystem(original,parse);new=filesystem(current,parse)
    if old is None or new is None:return {'status':'unavailable'}
    before=old['entries'];after=new['entries'];left=Counter(before);right=Counter(after)
    header=lambda m:(m['profile'],m['mode'],m['depth'])
    raw=lambda m:m['raw'][m['span'][0]:m['span'][1]]
    static_expected=Counter([('read',None,'special' if p.startswith(':') else 'path',p) for p in (':minimal','/usr','/opt','/etc/codex','/home/gpt','/job')]+[('write',None,'path',p) for p in ('/job/src','/job/build','/tmp')]+[('deny','false','path',p) for p in ('/credentials','/state/sqlite','/state/logs')])
    def static(model):
        return Counter(v for v in model['entries'] if not (v[:3]==('read',None,'path') and re.fullmatch(r'/state/codex/tmp/arg0-linux/codex-arg0[A-Za-z0-9]{1,64}',v[3])))==static_expected
    eq=[raw(old)==raw(new),before==after,left==right,header(old)==header(new),old['roots']==new['roots'],static(old) and static(new)]
    def pair(a,b):return [digest(a)] if a==b else [digest(a),digest(b)]
    def role(target):
        constants=(':minimal','/usr','/opt','/etc/codex','/home/gpt','/job','/job/src','/job/build','/tmp','/credentials','/state/sqlite','/state/logs')
        if target in constants:return constants.index(target)+1
        return 13 if re.fullmatch(r'/state/codex/tmp/arg0-linux/codex-arg0[A-Za-z0-9]{1,64}',target) else 0
    def meta(entry):return (('read','write','deny').index(entry[0])+1)|(('path','glob','special').index(entry[2])+1)<<2|((None,'false','true').index(entry[1]))<<4|role(entry[3])<<6
    mismatches=[i for i in range(max(len(before),len(after))) if i>=len(before) or i>=len(after) or before[i]!=after[i]]
    mismatches.sort(key=lambda i:i>=len(before) or i>=len(after))
    details=[]
    for index in mismatches[:2]:
        a=before[index] if index<len(before) else None;b=after[index] if index<len(after) else None
        details.append([index,meta(a) if a else None,meta(b) if b else None,
            len(a[3].encode()) if a else None,len(b[3].encode()) if b else None,
            sha256(a[3].encode()).hexdigest() if a else None,sha256(b[3].encode()).hexdigest() if b else None])
    return {'status':'observed','checks':[63,sum(value<<i for i,value in enumerate(eq))],
        'counts':[len(old['roots']),len(new['roots']),len(before),len(after),sum((left-right).values()),sum((right-left).values()),len(mismatches)],
        'header':[[('managed','disabled','external').index(m['profile']),('restricted','unrestricted','external').index(m['mode']),m['depth']] for m in (old,new)],
        'ordered':pair(before,after),'multiset':pair(sorted(before,key=canonical),sorted(after,key=canonical)),
        'roots':pair(old['roots'],new['roots']),'details':details,'truncated':len(details)<len(mismatches)}
