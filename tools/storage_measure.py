#!/usr/bin/python3
"""Fixed read-only allocated-block scan for the CI controller's owned scratch."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import time

ENTRIES=524288
INODES=262144
DEPTH=64
ADDRESS_SPACE=256*1024**2
FDS=256
REASONS=(
    'none','root-identity','identity-changed','permission','io','unsupported','mount-boundary',
    'mount-id-missing','mount-id-equal','mountinfo-unavailable','mountinfo-row-shape','mountinfo-device',
    'mountinfo-root-missing','mountinfo-entry-missing','held-root-path-missing','held-entry-path-missing',
    'held-entry-path-mismatch','root-path-outside-mount','bind-source-outside-root',
    'bind-source-before-missing','bind-source-before-identity','bind-source-before-exdev',
    'bind-source-after-missing','bind-source-after-identity','bind-source-after-exdev',
    'entry-reopen-missing','entry-resolve-exdev','entry-reopen-exdev','entry-limit','inode-limit','depth-limit','deadline',
    'enumeration-disappeared',
)
class ScanError(ValueError):pass
class NoTotal(ScanError):pass

def require(ok,reason):
    if not ok:raise ScanError(reason)
def identity(node):return {'device':node.st_dev,'inode':node.st_ino,'owner':node.st_uid}
class How(ctypes.Structure):_fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
LIBC=ctypes.CDLL(None,use_errno=True)
def _node(parent,name,*,same_mount=True):
    require(platform.machine()=='x86_64','unsupported')
    resolve=0x04|0x08  # RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH
    if same_mount:resolve|=0x01  # RESOLVE_NO_XDEV
    how=How(os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,0,resolve)
    result=LIBC.syscall(437,parent,os.fsencode(name),ctypes.byref(how),ctypes.sizeof(how))
    if result<0:raise OSError(ctypes.get_errno(),'node open rejected')
    return result

def _open_entry(parent,name):
    try:return _node(parent,name),False
    except OSError as error:
        if error.errno!=errno.EXDEV:raise
    # Pin metadata only. A mounted tree is opened for enumeration only after
    # the same-device source is proven to be reachable inside the owned root.
    try:return _node(parent,name,same_mount=False),True
    except OSError as error:
        if error.errno==errno.EXDEV:raise ScanError('entry-resolve-exdev') from None
        raise

def _node_identity(node):
    return node.st_dev,node.st_ino,stat.S_IFMT(node.st_mode)

def _mount_id(fd):
    try:
        with open(f'/proc/self/fdinfo/{fd}','rb') as info:
            for line in info:
                if line.startswith(b'mnt_id:\t'):return line.split()[1]
    except FileNotFoundError:
        pass
    raise ScanError('mount-id-missing')

def _mount_path(field):
    return Path(os.fsdecode(re.sub(rb'\\([0-7]{3})',lambda match:bytes([int(match[1],8)]),field)))

def _bind_source(root_fd,root_id,mounted_fd,mount_id,device,bound):
    require(root_id!=mount_id,'mount-id-equal')
    mount_ids={root_id,mount_id}
    device_field=f'{os.major(device)}:{os.minor(device)}'.encode()
    paths={}
    try:
        with open('/proc/self/mountinfo','rb') as info:
            for line in info:
                bound()
                fields=line.split(b' ',5)  # Other whitespace can occur in path fields.
                if fields[0] in mount_ids:
                    require(len(fields)==6,'mountinfo-row-shape')
                    require(fields[2]==device_field,'mountinfo-device')
                    paths[fields[0]]=(_mount_path(fields[3]),_mount_path(fields[4]))
                    if paths.keys()==mount_ids:break
    except FileNotFoundError:
        raise ScanError('mountinfo-unavailable') from None
    try:root_path=Path(os.readlink(f'/proc/self/fd/{root_fd}'))
    except FileNotFoundError:raise ScanError('held-root-path-missing') from None
    try:mounted_path=Path(os.readlink(f'/proc/self/fd/{mounted_fd}'))
    except FileNotFoundError:raise ScanError('held-entry-path-missing') from None
    require(root_id in paths,'mountinfo-root-missing')
    require(mount_id in paths,'mountinfo-entry-missing')
    root_source,root_mountpoint=paths[root_id]
    mounted_source,mountpoint=paths[mount_id]
    require(mounted_path==mountpoint,'held-entry-path-mismatch')
    try:
        owned_source=root_source/root_path.relative_to(root_mountpoint)
    except ValueError:
        raise ScanError('root-path-outside-mount') from None
    try:return mounted_source.relative_to(owned_source)
    except ValueError:raise ScanError('bind-source-outside-root') from None

def _verify_bind_source(root_fd,source,expected,*,after=False):
    missing,identity_mismatch,resolve_exdev=(
        ('bind-source-after-missing','bind-source-after-identity','bind-source-after-exdev') if after else
        ('bind-source-before-missing','bind-source-before-identity','bind-source-before-exdev')
    )
    try:source_fd=_node(root_fd,source)
    except FileNotFoundError:raise ScanError(missing) from None
    except OSError as error:
        if error.errno==errno.EXDEV:raise ScanError(resolve_exdev) from None
        raise
    try:require(_node_identity(os.fstat(source_fd))==expected,identity_mismatch)
    finally:os.close(source_fd)

def scan(root,expected,*,entry_limit=ENTRIES,inode_limit=INODES,depth_limit=DEPTH,end=None):
    root=Path(root);end=time.monotonic()+4.5 if end is None else end
    counters={'entries':0,'unique_inodes':0,'vanished':0};seen={};active=set();total=0
    root_mount=None
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    def root_check():
        held=os.fstat(fd);current=os.stat(root,follow_symlinks=False)
        require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(current.st_mode) and identity(held)==identity(current)==expected,'root-identity')
        if root_mount is not None:
            current_fd=os.open(root,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                require(identity(os.fstat(current_fd))==expected and _mount_id(current_fd)==root_mount,'root-identity')
            finally:os.close(current_fd)
    def bound():require(time.monotonic()<end,'deadline')
    def account(node,through_bind):
        nonlocal total
        require(type(node.st_dev) is int and node.st_dev>=0 and type(node.st_ino) is int and node.st_ino>0,'unsupported')
        key=(node.st_dev,node.st_ino)
        kind=stat.S_IFMT(node.st_mode)
        if key in seen:
            prior_kind,prior_links,ordinary_seen=seen[key]
            require(kind==prior_kind,'identity-changed')
            if kind!=stat.S_IFDIR and prior_links>1 and node.st_nlink>1:return key
            require((through_bind or not ordinary_seen) and (prior_links>1)==(node.st_nlink>1),'identity-changed')
            seen[key]=(kind,prior_links,ordinary_seen or not through_bind)
        else:
            require(len(seen)<inode_limit,'inode-limit')
            seen[key]=(kind,node.st_nlink,not through_bind)
            counters['unique_inodes']+=1
        require(type(node.st_blocks) is int and 0<=node.st_blocks<2**54,'unsupported')
        total+=node.st_blocks*512;require(total<2**63,'unsupported')
        return key
    def visit(directory,name,depth,through_bind):
        nonlocal root_mount
        node_fd,crossed=_open_entry(directory,name)
        try:
            opened=os.fstat(node_fd)
            node_identity=_node_identity(opened)
            current=os.stat(name,dir_fd=directory,follow_symlinks=False)
            require(_node_identity(current)==node_identity,'identity-changed')
            # GNU du -x excludes both files and directories on other devices,
            # including their mount roots. It never enumerates those trees.
            same_device=opened.st_dev==expected['device']
            directory_node=same_device and stat.S_ISDIR(opened.st_mode)
            mount_id=_mount_id(node_fd) if crossed else None
            if crossed and root_mount is None:root_mount=_mount_id(fd)
            source=None
            if same_device:
                if crossed:
                    source=_bind_source(fd,root_mount,node_fd,mount_id,opened.st_dev,bound)
                    _verify_bind_source(fd,source,node_identity)
                if directory_node:
                    # An ancestor bind is a cycle; a sibling alias is a separate
                    # visit. GNU du counts single-link files again on that visit.
                    if (opened.st_dev,opened.st_ino) not in active:
                        child=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=node_fd)
                        try:
                            child_node=os.fstat(child)
                            require(_node_identity(child_node)==node_identity,'identity-changed')
                            walk(child,child_node,depth+1,through_bind or crossed)
                        finally:os.close(child)
                else:account(opened,through_bind or crossed)
            if directory_node or crossed:
                # Reopen via the original parent and check the mounted identity
                # again, including a replacement that reused the same inode.
                try:
                    after=_node(directory,name,same_mount=not crossed)
                except FileNotFoundError:
                    # A missing mountpoint prevents the final mount and source
                    # checks after its blocks may already have been counted.
                    if crossed:raise ScanError('entry-reopen-missing') from None
                    raise
                except OSError as error:
                    if error.errno==errno.EXDEV:raise ScanError('entry-reopen-exdev') from None
                    raise
                try:
                    require(_node_identity(os.fstat(after))==node_identity,'identity-changed')
                    if crossed:require(_mount_id(after)==mount_id,'identity-changed')
                    if source is not None:_verify_bind_source(fd,source,node_identity,after=True)
                finally:os.close(after)
        finally:os.close(node_fd)
    def walk(directory,node,depth,through_bind):
        bound();require(depth<=depth_limit,'depth-limit')
        key=account(node,through_bind)
        active.add(key)
        try:
            with os.scandir(directory) as entries:
                while True:
                    bound()
                    try:entry=next(entries)
                    except StopIteration:break
                    except FileNotFoundError:raise NoTotal('enumeration-disappeared') from None
                    counters['entries']+=1;require(counters['entries']<=entry_limit,'entry-limit')
                    if entry.name=='guest.qcow2':continue # Exact existing GNUdu basename exclusion.
                    try:visit(directory,entry.name,depth,through_bind)
                    except FileNotFoundError:counters['vanished']+=1
        except FileNotFoundError:raise NoTotal('enumeration-disappeared') from None
        finally:active.remove(key)
    try:
        root_check();walk(fd,os.fstat(fd),0,False);root_check()
        return {'status':'provisional' if counters['vanished'] else 'complete','allocated_bytes':total,'reason':'none','counters':counters}
    except NoTotal:
        root_check();return {'status':'no-total','allocated_bytes':None,'reason':'enumeration-disappeared','counters':counters}
    except (ScanError,OSError) as error:
        error.scan_counters=dict(counters);raise
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True,type=Path)
    for name in ('device','inode','owner'):parser.add_argument('--'+name,required=True,type=int)
    parser.add_argument('--sha256',required=True)
    args=parser.parse_args();expected={'device':args.device,'inode':args.inode,'owner':args.owner}
    source=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result={'schema':1,'worker_sha256':source,'root':expected,'status':'failed','allocated_bytes':None,'reason':'unsupported','counters':{'entries':0,'unique_inodes':0,'vanished':0}}
    try:
        require(source==args.sha256 and args.root.is_absolute() and all(type(value) is int and 0<=value<2**64 for value in expected.values()),'unsupported')
        result.update(scan(args.root,expected))
    except ScanError as error:
        result['reason']=str(error) if str(error) in REASONS else 'unsupported';result['counters']=getattr(error,'scan_counters',result['counters'])
    except OSError as error:
        result['counters']=getattr(error,'scan_counters',result['counters']);result['reason']={errno.ENOENT:'root-identity',errno.EXDEV:'mount-boundary',errno.EACCES:'permission',errno.EPERM:'permission',errno.EIO:'io'}.get(error.errno,'unsupported')
    except Exception:result['reason']='unsupported'
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0 if result['status'] in ('complete','provisional') else 1 if result['status']=='no-total' else 2
if __name__=='__main__':raise SystemExit(main())
