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
import stat
import time

ENTRIES=524288
INODES=262144
DEPTH=64
ADDRESS_SPACE=256*1024**2
FDS=256
REASONS=('none','root-identity','identity-changed','permission','io','unsupported','mount-boundary','entry-limit','inode-limit','depth-limit','deadline','enumeration-disappeared')
class ScanError(ValueError):pass
class NoTotal(ScanError):pass

def require(ok,reason):
    if not ok:raise ScanError(reason)
def identity(node):return {'device':node.st_dev,'inode':node.st_ino,'owner':node.st_uid}
class How(ctypes.Structure):_fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
LIBC=ctypes.CDLL(None,use_errno=True)
def _node(parent,name):
    require(platform.machine()=='x86_64','unsupported')
    how=How(os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,0,0x01|0x04|0x08)
    result=LIBC.syscall(437,parent,os.fsencode(name),ctypes.byref(how),ctypes.sizeof(how))
    if result<0:raise OSError(ctypes.get_errno(),'node open rejected')
    return result

def scan(root,expected,*,entry_limit=ENTRIES,inode_limit=INODES,depth_limit=DEPTH,end=None):
    root=Path(root);end=time.monotonic()+4.5 if end is None else end
    counters={'entries':0,'unique_inodes':0,'vanished':0};seen={};total=0
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    def root_check():
        held=os.fstat(fd);current=os.stat(root,follow_symlinks=False)
        require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(current.st_mode) and identity(held)==identity(current)==expected,'root-identity')
    def bound():require(time.monotonic()<end,'deadline')
    def account(node):
        nonlocal total
        require(type(node.st_dev) is int and node.st_dev>=0 and type(node.st_ino) is int and node.st_ino>0,'unsupported')
        key=(node.st_dev,node.st_ino)
        if key in seen:
            require(seen[key]>1 and node.st_nlink>1,'identity-changed')
            return False
        require(len(seen)<inode_limit,'inode-limit');seen[key]=node.st_nlink;counters['unique_inodes']+=1
        require(type(node.st_blocks) is int and 0<=node.st_blocks<2**54,'unsupported')
        total+=node.st_blocks*512;require(total<2**63,'unsupported');return True
    def walk(directory,node,depth):
        bound();require(depth<=depth_limit,'depth-limit')
        if not account(node):return
        try:
            with os.scandir(directory) as entries:
                while True:
                    bound()
                    try:entry=next(entries)
                    except StopIteration:break
                    except FileNotFoundError:raise NoTotal('enumeration-disappeared') from None
                    counters['entries']+=1;require(counters['entries']<=entry_limit,'entry-limit')
                    if entry.name=='guest.qcow2':continue # Exact existing GNUdu basename exclusion.
                    try:
                        nodefd=_node(directory,entry.name)
                        try:
                            opened=os.fstat(nodefd)
                            require(opened.st_dev==expected['device'],'mount-boundary')
                            # Pin before parent lookup: an unlinked inode cannot be recycled into a false identity match.
                            before=os.stat(entry.name,dir_fd=directory,follow_symlinks=False)
                            require((opened.st_dev,opened.st_ino,stat.S_IFMT(opened.st_mode))==(before.st_dev,before.st_ino,stat.S_IFMT(before.st_mode)),'identity-changed')
                            if stat.S_ISDIR(opened.st_mode):
                                child=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=nodefd)
                                try:walk(child,os.fstat(child),depth+1)
                                finally:os.close(child)
                                after=os.stat(entry.name,dir_fd=directory,follow_symlinks=False)
                                require((after.st_dev,after.st_ino)==(opened.st_dev,opened.st_ino),'identity-changed')
                            else:account(opened)
                        finally:os.close(nodefd)
                    except FileNotFoundError:counters['vanished']+=1
        except FileNotFoundError:raise NoTotal('enumeration-disappeared') from None
    try:
        root_check();walk(fd,os.fstat(fd),0);root_check()
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
