#!/usr/bin/python3
"""Fixed read-only allocated-block scan for the CI controller's owned scratch."""
import argparse
import array
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import time
from typing import NamedTuple

ENTRIES=524288
INODES=262144
DEPTH=64
ADDRESS_SPACE=256*1024**2
FDS=256
INODE_FILESYSTEMS={0xEF53:b'ext4',0x01021994:b'tmpfs'}
BACKING_FLAGS=os.ST_RDONLY|os.ST_NOSUID|os.ST_NODEV|os.ST_NOEXEC
REASONS=(
    'none','root-identity','identity-changed','ordinary-entry-changed','permission','io','unsupported','mount-boundary',
    'mount-id-missing','mount-id-equal','mountinfo-unavailable','mountinfo-row-shape','mountinfo-device',
    'mountinfo-root-missing','mountinfo-entry-missing','held-root-path-missing','held-entry-path-missing',
    'held-entry-path-mismatch','root-path-outside-mount','bind-source-outside-root',
    'bind-source-before-missing','bind-source-before-identity','bind-source-before-exdev',
    'bind-source-before-exdev-regular','bind-source-before-exdev-nondirectory','bind-source-before-exdev-empty-name',
    'bind-source-before-exdev-parent-open','bind-source-before-exdev-parent-identity',
    'bind-source-before-exdev-overlay','bind-source-before-exdev-filesystem',
    'bind-source-before-exdev-leaf-open','bind-source-before-exdev-leaf-mount',
    'bind-source-after-missing','bind-source-after-identity','bind-source-after-exdev',
    'entry-reopen-missing','entry-resolve-exdev','entry-reopen-exdev','entry-limit','inode-limit','depth-limit','deadline',
    'enumeration-disappeared',
)
class ScanError(ValueError):pass
class NoTotal(ScanError):pass
class SourceParentEXDEV(ScanError):pass
class OrdinaryChange(ScanError):pass

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

def _named_file(parent,name):
    # Bind the observation to a strict lookup, including its mount provenance.
    named=_node(parent,name)
    try:return os.fstat(named)
    finally:os.close(named)

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

def _bind_source(root_fd,root_id,mounted_fd,mount_id,device,bound,*,filesystem=None):
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
                    if filesystem is not None:
                        require(fields[5].partition(b' - ')[2].split(b' ',1)[0]==filesystem,'mount-boundary')
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

def _filesystem_type(fd):
    # The Linux x86_64 statfs buffer begins with a long f_type.
    result=(ctypes.c_long*16)()
    if LIBC.fstatfs(fd,ctypes.byref(result))!=0:
        raise OSError(ctypes.get_errno(),'filesystem check failed')
    return result[0]

def _open_source_self_bind(root_fd,root_id,source,expected,bound,charge_entry,reasons,*,after):
    missing,mismatch,exdev=reasons
    parent_fd=None
    try:
        try:parent_fd=_node(root_fd,source.parent)
        except OSError as error:
            if error.errno==errno.EXDEV:
                raise SourceParentEXDEV(exdev if after else 'bind-source-before-exdev-parent-open') from None
            raise
        parent=os.fstat(parent_fd)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_dev==expected[0] and _mount_id(parent_fd)==root_id,
                exdev if after else 'bind-source-before-exdev-parent-identity')
        filesystem_type=_filesystem_type(parent_fd)
        filesystem=INODE_FILESYSTEMS.get(filesystem_type)
        if filesystem is None:
            if after:raise ScanError(exdev)
            reason='bind-source-before-exdev-overlay' if filesystem_type==0x794c7630 else 'bind-source-before-exdev-filesystem'
            raise ScanError(reason)
        try:leaf_fd=_node(parent_fd,source.name,same_mount=False)
        except OSError as error:
            if not after and error.errno==errno.EXDEV:raise ScanError('bind-source-before-exdev-leaf-open') from None
            raise
        try:
            require(_node_identity(os.fstat(leaf_fd))==expected,mismatch)
            leaf_mount=_mount_id(leaf_fd)
            require(leaf_mount!=root_id,exdev if after else 'bind-source-before-exdev-leaf-mount')
            # Read a fresh cursor for the covered directory entry. Stat or open
            # on the name would resolve to the visible mount instead.
            witness_fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
            try:
                with os.scandir(witness_fd) as entries:
                    while True:
                        bound()
                        try:entry=next(entries)
                        except StopIteration:raise ScanError(missing) from None
                        charge_entry()
                        if entry.name==source.name:
                            covered_inode=entry.inode()
                            require(covered_inode>0 and covered_inode==expected[1],mismatch)
                            break
            finally:os.close(witness_fd)
            require(_bind_source(root_fd,root_id,leaf_fd,leaf_mount,expected[0],bound,filesystem=filesystem)==source,mismatch)
        except BaseException:
            os.close(leaf_fd)
            raise
        return leaf_fd
    except FileNotFoundError:raise ScanError(missing) from None
    except OSError as error:
        if error.errno==errno.EXDEV:raise ScanError(exdev) from None
        raise
    finally:
        if parent_fd is not None:os.close(parent_fd)

def _mount(source,target,flags):
    if LIBC.mount(source,target,None,ctypes.c_ulong(flags),None)!=0:
        raise OSError(ctypes.get_errno(),'private mount rejected')

def _send_backing_root(channel,root,expected,live_mount,worker_pid):
    if LIBC.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=worker_pid:  # PR_SET_PDEATHSIG
        raise ScanError('mount-boundary')
    if LIBC.unshare(0x20000)!=0:  # CLONE_NEWNS
        raise OSError(ctypes.get_errno(),'private namespace rejected')
    flags=os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    cloned=os.open(root,flags)
    try:
        clone_mount=_mount_id(cloned)
        require(identity(os.fstat(cloned))==expected and clone_mount!=live_mount,'root-identity')
        ms_private=1<<18
        ms_bind=1<<12
        _mount(None,b'/',ms_private|(1<<14))  # MS_PRIVATE | MS_REC comes before the bind.
        cloned_path=f'/proc/self/fd/{cloned}'.encode()
        _mount(cloned_path,cloned_path,ms_bind)
        backing=os.open(root,flags)
        try:
            require(identity(os.fstat(backing))==expected and _mount_id(backing) not in (clone_mount,live_mount),'root-identity')
            backing_path=f'/proc/self/fd/{backing}'.encode()
            _mount(None,backing_path,ms_private)
            # MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC.
            remount_flags=ms_bind|32|1|2|4|8
            if os.fstatvfs(backing).f_flag&8192:remount_flags|=256  # Preserve MS_NOSYMFOLLOW.
            _mount(None,backing_path,remount_flags)
            require(os.fstatvfs(backing).f_flag&BACKING_FLAGS==BACKING_FLAGS,'mount-boundary')
            rights=array.array('i',[backing])
            require(channel.sendmsg([b'B'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,rights)])==1,'mount-boundary')
        finally:os.close(backing)
    finally:os.close(cloned)

def _wait_backing_child(pid,end):
    while True:
        exited,status=os.waitpid(pid,os.WNOHANG)
        if exited:return status
        left=end-time.monotonic()
        if left<=0:return None
        time.sleep(min(.001,left))

def _open_backing_root(root,expected,live_mount,end):
    worker_pid=os.getpid()
    # Leave part of the single existing deadline available to kill and reap.
    left=end-time.monotonic()
    require(left>0,'deadline')
    response_end=end-min(.05,left/2)
    receiver,sender=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    with receiver,sender:
        status=None
        received=array.array('i')
        pid=os.fork()
        if pid==0:
            try:
                receiver.close()
                _send_backing_root(sender,root,expected,live_mount,worker_pid)
            except BaseException:os._exit(1)
            os._exit(0)
        try:
            sender.close()
            left=response_end-time.monotonic()
            require(left>0,'deadline')
            receiver.settimeout(left)
            size=received.itemsize
            try:
                payload,control,flags,_=receiver.recvmsg(1,socket.CMSG_SPACE(size),socket.MSG_CMSG_CLOEXEC)
            except TimeoutError:raise ScanError('deadline') from None
            for level,kind,data in control:
                if (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS):
                    received.frombytes(data[:len(data)//size*size])
            require(payload==b'B' and not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) and
                    len(control)==1 and len(control[0][2])==size and len(received)==1,'mount-boundary')
            status=_wait_backing_child(pid,response_end)
            require(status is not None,'deadline')
            require(status==0,'mount-boundary')
            backing=received[0]
            node=os.fstat(backing)
            require(stat.S_ISDIR(node.st_mode) and identity(node)==expected and _mount_id(backing)!=live_mount,'root-identity')
            require(fcntl.fcntl(backing,fcntl.F_GETFL)&os.O_PATH and not os.get_inheritable(backing) and
                    os.fstatvfs(backing).f_flag&BACKING_FLAGS==BACKING_FLAGS,'mount-boundary')
            return received.pop()
        finally:
            for received_fd in received:os.close(received_fd)
            if status is None:
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                require(_wait_backing_child(pid,end) is not None,'deadline')

class _BackingSource(NamedTuple):
    identities:tuple
    pins:tuple

    def close(self):
        for fd in self.pins:os.close(fd)

def _open_backing_source(root_fd,root_id,backing,filesystem,source,expected,bound,charge_entry,depth_limit,reasons):
    _,mismatch,exdev=reasons
    parts=source.parts
    require(len(parts)<=depth_limit,'depth-limit')
    require(parts and not source.is_absolute() and '..' not in parts,exdev)
    clean_parent,live_parent=backing,root_fd
    mount_id=root_id
    crossed_parent=False
    pins=[]
    identities=[]
    prefix=Path()
    try:
        for index,component in enumerate(parts):
            bound();charge_entry()
            clean_fd=_node(clean_parent,component)
            try:live_fd=_node(live_parent,component,same_mount=False)
            except BaseException:
                os.close(clean_fd)
                raise
            if clean_parent!=backing:os.close(clean_parent)
            if live_parent!=root_fd and live_parent not in pins:os.close(live_parent)
            clean_parent,live_parent=clean_fd,live_fd
            node=_node_identity(os.fstat(live_fd))
            require(node[0]==expected[0] and node[2]==stat.S_IFDIR and
                    node==_node_identity(os.fstat(clean_fd)),mismatch)
            prefix=prefix/component
            current_mount=_mount_id(live_fd)
            if current_mount!=mount_id:
                require(_bind_source(root_fd,root_id,live_fd,current_mount,expected[0],bound,filesystem=filesystem)==prefix,mismatch)
                pins.append(live_fd)
                if index<len(parts)-1:crossed_parent=True
            mount_id=current_mount
            identities.append((node,mount_id))
        require(crossed_parent and node==expected,mismatch)
        if live_parent not in pins:pins.append(live_parent)
        return _BackingSource(tuple(identities),tuple(pins))
    except BaseException:
        for pin in pins:os.close(pin)
        raise
    finally:
        if live_parent!=root_fd and live_parent not in pins:os.close(live_parent)
        if clean_parent!=backing:os.close(clean_parent)

def _verify_bind_source(root_fd,root_id,source,expected,bound,charge_entry,*,after=False,source_pin=None,backing_source=None):
    reasons=(
        ('bind-source-after-missing','bind-source-after-identity','bind-source-after-exdev') if after else
        ('bind-source-before-missing','bind-source-before-identity','bind-source-before-exdev')
    )
    missing,identity_mismatch,resolve_exdev=reasons
    try:source_fd=_node(root_fd,source)
    except FileNotFoundError:raise ScanError(missing) from None
    except OSError as error:
        if error.errno!=errno.EXDEV:raise
        if expected[2]!=stat.S_IFDIR:
            if not after:
                resolve_exdev=('bind-source-before-exdev-regular' if expected[2]==stat.S_IFREG
                               else 'bind-source-before-exdev-nondirectory')
            raise ScanError(resolve_exdev) from None
        if not source.name:
            raise ScanError(resolve_exdev if after else 'bind-source-before-exdev-empty-name') from None
        if after and source_pin is None:
            raise ScanError(resolve_exdev) from None
        try:leaf_fd=_open_source_self_bind(root_fd,root_id,source,expected,bound,charge_entry,reasons,after=after)
        except SourceParentEXDEV as parent_error:
            if backing_source is None or (after and not isinstance(source_pin,_BackingSource)):raise
            proven=backing_source(source,expected,reasons,str(parent_error))
            if not after:return proven
            try:require(proven.identities==source_pin.identities,identity_mismatch)
            finally:proven.close()
            return None
        if not after:return leaf_fd
        try:require(not isinstance(source_pin,_BackingSource) and _mount_id(leaf_fd)==_mount_id(source_pin),identity_mismatch)
        finally:os.close(leaf_fd)
        return None
    try:require(source_pin is None and _node_identity(os.fstat(source_fd))==expected,identity_mismatch)
    finally:os.close(source_fd)

def scan(root,expected,*,entry_limit=ENTRIES,inode_limit=INODES,depth_limit=DEPTH,end=None):
    root=Path(root);end=time.monotonic()+4.5 if end is None else end
    counters={'entries':0,'unique_inodes':0,'vanished':0};seen={};active=set();total=0
    root_mount=None
    backing_fd=backing_filesystem=None
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
    def require_ordinary_replacement(previous,current,crossed):
        require(not crossed and previous[0]==current[0]==expected['device'] and
                previous[1]>0 and current[1]>0 and previous[1]!=current[1] and
                previous[2]==current[2] and previous[2] in (stat.S_IFREG,stat.S_IFDIR),'identity-changed')
    def charge_entry():
        counters['entries']+=1
        require(counters['entries']<=entry_limit,'entry-limit')
    def backing_source(source,node_identity,reasons,rejection):
        nonlocal backing_fd,backing_filesystem
        require(len(source.parts)<=depth_limit,'depth-limit')
        if backing_fd is None:
            bound()
            try:root_check()
            except FileNotFoundError:raise ScanError('root-identity') from None
            try:
                backing_filesystem=INODE_FILESYSTEMS.get(_filesystem_type(fd))
                require(backing_filesystem is not None,rejection)
                backing_fd=_open_backing_root(root,expected,root_mount,end)
            except ScanError as error:
                if str(error)=='deadline':raise
                raise ScanError(rejection) from None
            except OSError:raise ScanError(rejection) from None
        try:
            return _open_backing_source(fd,root_mount,backing_fd,backing_filesystem,source,node_identity,
                                        bound,charge_entry,depth_limit,reasons)
        except FileNotFoundError:raise ScanError(reasons[0]) from None
        except OSError as error:
            if error.errno==errno.EXDEV:raise ScanError(rejection) from None
            raise
    def account(node,through_bind,*,link_witness=False):
        nonlocal total
        require(type(node.st_dev) is int and node.st_dev>=0 and type(node.st_ino) is int and node.st_ino>0,'unsupported')
        key=(node.st_dev,node.st_ino)
        kind=stat.S_IFMT(node.st_mode)
        if key in seen:
            prior_kind,prior_links,ordinary_seen,bind_seen,first_witness=seen[key]
            require(kind==prior_kind,'identity-changed')
            if kind==stat.S_IFREG and not through_bind:
                require(link_witness and (not ordinary_seen or first_witness),'identity-changed')
            if kind!=stat.S_IFDIR and prior_links>1 and node.st_nlink>1:return key
            if (kind==stat.S_IFREG and node.st_dev==expected['device'] and prior_links==node.st_nlink==1 and
                    ordinary_seen and not (through_bind or bind_seen)):
                raise OrdinaryChange('ordinary-entry-changed')
            require((through_bind or not ordinary_seen) and (prior_links>1)==(node.st_nlink>1),'identity-changed')
            witness=first_witness if ordinary_seen else link_witness
            seen[key]=(kind,prior_links,ordinary_seen or not through_bind,bind_seen or through_bind,witness)
        else:
            require(len(seen)<inode_limit,'inode-limit')
            # The first name can be gone by a repeated sighting. Keep the
            # proof from that encounter, including a failed confirmation.
            seen[key]=(kind,node.st_nlink,not through_bind,through_bind,link_witness)
            counters['unique_inodes']+=1
        require(type(node.st_blocks) is int and 0<=node.st_blocks<2**54,'unsupported')
        total+=node.st_blocks*512;require(total<2**63,'unsupported')
        return key
    def visit(directory,name,depth,through_bind):
        nonlocal root_mount
        node_fd,crossed=_open_entry(directory,name)
        source_pin=None
        change=None
        try:
            opened=os.fstat(node_fd)
            node_identity=_node_identity(opened)
            same_device=opened.st_dev==expected['device']
            ordinary_file=same_device and not crossed and stat.S_ISREG(opened.st_mode)
            repeated_file=ordinary_file and not through_bind and (opened.st_dev,opened.st_ino) in seen
            if ordinary_file:
                # Read named metadata from the strict descriptor itself. A
                # pathname stat could have crossed a transient same-inode bind.
                bound()
                try:current=_named_file(directory,name)
                except FileNotFoundError:
                    if repeated_file:raise ScanError('identity-changed') from None
                    raise
                except OSError as error:
                    if error.errno==errno.EXDEV:raise ScanError('identity-changed') from None
                    raise
            else:current=os.stat(name,dir_fd=directory,follow_symlinks=False)
            current_identity=_node_identity(current)
            if current_identity!=node_identity:
                require(not repeated_file,'identity-changed')
                require_ordinary_replacement(node_identity,current_identity,crossed)
                # The name must still resolve to the replacement under the
                # ordinary lookup restrictions. Loss during this proof is fatal.
                bound()
                try:
                    confirmed=_node(directory,name)
                    try:
                        confirmed_node=os.fstat(confirmed)
                        require(_node_identity(confirmed_node)==current_identity and confirmed_node.st_nlink==current.st_nlink,
                                'identity-changed')
                    finally:os.close(confirmed)
                except FileNotFoundError:raise ScanError('identity-changed') from None
                raise OrdinaryChange('ordinary-entry-changed')
            # GNU du -x excludes both files and directories on other devices,
            # including their mount roots. It never enumerates those trees.
            directory_node=same_device and stat.S_ISDIR(opened.st_mode)
            mount_id=_mount_id(node_fd) if crossed else None
            if crossed and root_mount is None:root_mount=_mount_id(fd)
            source=None
            if same_device:
                if crossed:
                    source=_bind_source(fd,root_mount,node_fd,mount_id,opened.st_dev,bound)
                    source_pin=_verify_bind_source(fd,root_mount,source,node_identity,bound,charge_entry,
                                                   backing_source=backing_source)
                if directory_node:
                    # An ancestor bind is a cycle; a sibling alias is a separate
                    # visit. GNU du counts single-link files again on that visit.
                    if (opened.st_dev,opened.st_ino) not in active:
                        child=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=node_fd)
                        try:
                            child_node=os.fstat(child)
                            require(_node_identity(child_node)==node_identity,'identity-changed')
                            try:walk(child,child_node,depth+1,through_bind or crossed)
                            except OrdinaryChange as error:change=error
                        finally:os.close(child)
                else:
                    link_witness=ordinary_file and not through_bind and opened.st_nlink==current.st_nlink>0
                    account(opened,through_bind or crossed,link_witness=link_witness)
            if directory_node or crossed:
                # Reopen via the original parent and check the mounted identity
                # again, even if a descendant already invalidated the total.
                try:
                    after=_node(directory,name,same_mount=not crossed)
                except FileNotFoundError:
                    # A missing mountpoint prevents the final mount and source
                    # checks after its blocks may already have been counted.
                    if crossed or change is not None:raise ScanError('entry-reopen-missing') from None
                    raise
                except OSError as error:
                    if error.errno==errno.EXDEV:raise ScanError('entry-reopen-exdev') from None
                    raise
                try:
                    after_identity=_node_identity(os.fstat(after))
                    if after_identity!=node_identity:
                        require(change is None,'identity-changed')
                        require_ordinary_replacement(node_identity,after_identity,crossed)
                        raise OrdinaryChange('ordinary-entry-changed')
                    if crossed:require(_mount_id(after)==mount_id,'identity-changed')
                    if source is not None:
                        _verify_bind_source(fd,root_mount,source,node_identity,bound,charge_entry,
                                            after=True,source_pin=source_pin,backing_source=backing_source)
                except FileNotFoundError:
                    if change is not None:raise ScanError('entry-reopen-missing') from None
                    raise
                finally:os.close(after)
            if change is not None:raise change
        finally:
            if isinstance(source_pin,_BackingSource):source_pin.close()
            elif source_pin is not None:os.close(source_pin)
            os.close(node_fd)
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
                    charge_entry()
                    if entry.name=='guest.qcow2':continue # Exact existing GNUdu basename exclusion.
                    try:visit(directory,entry.name,depth,through_bind)
                    except FileNotFoundError:counters['vanished']+=1
        except FileNotFoundError:raise NoTotal('enumeration-disappeared') from None
        finally:active.remove(key)
    try:
        root_check()
        try:walk(fd,os.fstat(fd),0,False)
        except OrdinaryChange:
            # The original root descriptor still pins its mount, even when
            # no entry crossed a mount during this scan.
            if root_mount is None:root_mount=_mount_id(fd)
            try:root_check()
            except FileNotFoundError:raise ScanError('root-identity') from None
            bound()
            raise
        root_check()
        return {'status':'provisional' if counters['vanished'] else 'complete','allocated_bytes':total,'reason':'none','counters':counters}
    except NoTotal:
        root_check();return {'status':'no-total','allocated_bytes':None,'reason':'enumeration-disappeared','counters':counters}
    except (ScanError,OSError) as error:
        error.scan_counters=dict(counters);raise
    finally:
        if backing_fd is not None:os.close(backing_fd)
        os.close(fd)

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
