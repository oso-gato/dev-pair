"""One disposable CI-only signed-load capsule. Never a plaintext logger."""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import signal
import stat
import subprocess
import time
import threading

RECIPIENT_SHA='020ad2bbd6c1f6ce7f2867b722f429fac7685351e362d6e24203ef3d7376962c'
FINGERPRINT='59CD9CD708EEB010F4A1BB6B83B33B576391877E'
RECIPIENT=Path('/run/dev-pair-payload/native35-recipient.asc')
HOME=Path('/run/dev-pair-payload/native35-gpg-home')
PLAIN_LIMIT=8192
CIPHER_LIMIT=16384
REASONS=('not-collected','not-selected','incomplete','too-large','no-budget','recipient-unavailable','home-unavailable','encryption-unavailable','encryption-cleanup-unresolved','report-budget','invalid')

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def unavailable(reason):return {'schema':1,'availability':'unavailable','reason':reason}
def digest(value):return hashlib.sha256(value).hexdigest()

# One live diagnostic owner at most. Never a PID-based adoption registry.
_PENDING=None

DIAGNOSTIC_ERRORS=(OSError,ValueError,subprocess.SubprocessError)

def _cleanup_owned(owner):
    process=owner['process']
    if process is None:return
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGKILL)
        process.wait(timeout=max(0,owner['end']-time.monotonic()))
    if process.returncode is None:raise ValueError('exit unconfirmed')
    for stream in (process.stdin,process.stdout,process.stderr):
        if stream is not None and not stream.closed:stream.close()

def reconcile_pending():
    """Live exact child only; original end is immutable, cancellation propagates."""
    global _PENDING
    if _PENDING is None:return True
    try:_cleanup_owned(_PENDING)
    except DIAGNOSTIC_ERRORS:return False
    _PENDING=None;return True

def _publish_child(owner,args,kwargs):
    # Main-thread handlers are deferred, not blocked/inherited across exec.
    if threading.current_thread() is not threading.main_thread():raise ValueError('main thread required')
    numbers=tuple(number for number in (signal.SIGALRM,signal.SIGINT,signal.SIGTERM,signal.SIGHUP)
        if number in (signal.SIGALRM,signal.SIGINT) or callable(signal.getsignal(number)))
    saved={number:signal.getsignal(number) for number in numbers}
    # This query changes nothing: an interrupt before assignment loses no mask.
    prior_mask=signal.pthread_sigmask(signal.SIG_BLOCK,())
    pending={};deferring=True
    def deliver(number,frame):
        handler=saved[number]
        if handler==signal.SIG_IGN:return
        if handler==signal.SIG_DFL:signal.raise_signal(number)
        else:handler(number,frame)
    def deferred(number,frame):
        if deferring:pending.setdefault(number,frame)
        else:deliver(number,frame) # Failed restoration cannot orphan deadlines.
    def drain():
        while pending:
            number=next(iter(pending));frame=pending.pop(number)
            deliver(number,frame)
    def restore_mask():
        try:signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
        except BaseException:
            # Retain the saved mask if a setter is interrupted before its effect.
            if signal.pthread_sigmask(signal.SIG_BLOCK,())!=prior_mask:
                signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
            raise
    def restore_handlers():
        nonlocal deferring
        failure=None
        try:
            try:signal.pthread_sigmask(signal.SIG_BLOCK,numbers)
            except BaseException as error:failure=error
            for number in reversed(numbers):
                # Restoration knowledge remains live until the setter succeeds.
                for attempt in range(2):
                    try:signal.signal(number,saved[number]);break
                    except BaseException as error:
                        if failure is None:failure=error
                        if signal.getsignal(number) is saved[number]:break
        finally:
            deferring=False
            restore_mask()
        if any(signal.getsignal(n) is not saved[n] for n in numbers):raise RuntimeError('signal restoration unavailable')
        if failure is not None:raise failure
    original_error=None
    try:
        # Only handler mutation is masked, never Popen or its exec handshake.
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK,numbers)
            for number in numbers:signal.signal(number,deferred)
        finally:restore_mask()
        drain() # Known setup cancellation must prevent a new child launch.
        process=subprocess.Popen(args,**kwargs)
        owner['process']=process
    except BaseException as error:
        original_error=error
        raise
    finally:
        restoration_error=None
        try:restore_handlers()
        except BaseException as error:restoration_error=error
        try:drain()
        except BaseException:
            if (original_error is None or isinstance(original_error,DIAGNOSTIC_ERRORS)) and (restoration_error is None or isinstance(restoration_error,DIAGNOSTIC_ERRORS)):raise
        if restoration_error is not None and (original_error is None or isinstance(original_error,DIAGNOSTIC_ERRORS)):
            raise restoration_error
    return process

def _encrypt(plain,end):
    """Owned stock GPG, no plaintext files/arguments/environment or ambient keys."""
    global _PENDING
    if len(plain)>PLAIN_LIMIT:raise ValueError('capsule size')
    owner={'process':None,'end':end}
    operation_end=end-.25
    process=None;original_error=None;selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};position=0
    try:
        _PENDING=owner
        if time.monotonic()>=operation_end:raise ValueError('capsule deadline')
        args=['/usr/bin/prlimit','--core=0:0','--','/usr/bin/gpg','--no-options','--batch','--no-tty','--homedir',str(HOME),
            '--no-autostart','--no-auto-key-retrieve','--no-default-keyring','--no-keyring','--no-auto-check-trustdb','--no-random-seed-file',
            '--trust-model','always','--recipient-file',str(RECIPIENT),'--compress-algo','none','--output','-','--encrypt']
        process=_publish_child(owner,args,dict(stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/bin','HOME':str(HOME),'LANG':'C','LC_ALL':'C'},start_new_session=True))
        for stream in (process.stdin,process.stdout,process.stderr):os.set_blocking(stream.fileno(),False)
        selector.register(process.stdin,selectors.EVENT_WRITE,'stdin');selector.register(process.stdout,selectors.EVENT_READ,'stdout');selector.register(process.stderr,selectors.EVENT_READ,'stderr')
        while selector.get_map():
            remaining=operation_end-time.monotonic()
            if remaining<=0:raise ValueError('capsule deadline')
            for event,_ in selector.select(min(.05,remaining)):
                if event.data=='stdin':
                    try:position+=os.write(event.fd,plain[position:])
                    except BrokenPipeError:position=len(plain)
                    if position==len(plain):selector.unregister(event.fileobj);event.fileobj.close()
                else:
                    data=os.read(event.fd,4096)
                    if not data:selector.unregister(event.fileobj)
                    else:
                        buffers[event.data].extend(data)
                        if len(buffers[event.data])>(CIPHER_LIMIT if event.data=='stdout' else 4096):raise ValueError('capsule capture')
        if process.wait(timeout=max(0,operation_end-time.monotonic()))!=0 or not buffers['stdout']:raise ValueError('capsule encryption')
        return bytes(buffers['stdout'])
    except BaseException as error:
        original_error=error
        raise
    finally:
        try:
            selector.close()
            _cleanup_owned(owner)
        except BaseException as error:
            _PENDING=owner
            if original_error is None or isinstance(original_error,DIAGNOSTIC_ERRORS) and not isinstance(error,DIAGNOSTIC_ERRORS):raise
            # Preserve the original cancellation/error; uncertainty stays separate.
        else:_PENDING=None

def _home():
    # The fixed authenticated payload ISO supplies an empty root-owned RO home.
    fd=os.open(HOME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o222 or os.listdir(fd) or not os.fstatvfs(fd).f_flag&os.ST_RDONLY:raise ValueError('immutable home')
    finally:os.close(fd)

def _recipient():
    fd=os.open(RECIPIENT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as file:
        info=os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o222 or info.st_size!=673:raise ValueError('recipient')
        key=file.read(674)
        if len(key)!=673 or digest(key)!=RECIPIENT_SHA:raise ValueError('recipient')
    return key

def seal(buffers,payload,identity,end):
    """Only internal checked selector/control evidence may supply these operands."""
    global _PENDING
    if _PENDING is not None:return unavailable('encryption-cleanup-unresolved')
    try:
        if type(identity) is not dict or set(identity)!={'source_sha','context_sha256','phase'} or not re.fullmatch('[0-9a-f]{40}',identity['source_sha']) or not re.fullmatch('[0-9a-f]{64}',identity['context_sha256']) or identity['phase']!='maintenance-gptbox':return unavailable('not-selected')
        if type(payload) is not dict or payload.get('context_sha256')!=identity['context_sha256'] or payload.get('suboperation')!='load' or payload.get('launch_handle_observed') is not True or payload.get('control_verified') is not True or type(payload.get('uid')) is not int or not 1000<=payload['uid']<2**32 or type(payload.get('status')) is not int or not 1<=payload['status']<=255:return unavailable('not-selected')
        if payload.get('availability')!='observed' or not all(s.get('complete') is True for s in payload['streams'].values()):return unavailable('incomplete')
        if set(payload['streams'])!={'stdout','stderr'}:return unavailable('invalid')
        if sum(len(buffers[name]) for name in ('stdout','stderr'))>PLAIN_LIMIT*3//4:return unavailable('too-large')
        streams={}
        for name in ('stdout','stderr'):
            raw=bytes(buffers[name]);record=payload['streams'][name]
            if record!={'bytes':len(raw),'sha256':digest(raw),'complete':True}:return unavailable('incomplete')
            streams[name]={**record,'base64':base64.b64encode(raw).decode()}
        attempt=secrets.token_hex(16)
        envelope={'schema':1,'attempt_id':attempt,'recipient_sha256':RECIPIENT_SHA,'fingerprint':FINGERPRINT,'identity':identity,'executor':{'uid':payload['uid'],'unit':'dev-pair-gptbox-'+identity['context_sha256']+'.service'},'suboperation':'load','status':payload['status'],'streams':streams}
        plain=canonical(envelope)
        if len(plain)>PLAIN_LIMIT:return unavailable('too-large')
        if end-time.monotonic()<=0:return unavailable('no-budget')
        try:_recipient()
        except FileNotFoundError:return unavailable('not-collected')
        except (OSError,ValueError):return unavailable('recipient-unavailable')
        try:_home()
        except (OSError,ValueError):return unavailable('home-unavailable')
        try:cipher=_encrypt(plain,min(end,time.monotonic()+5))
        except DIAGNOSTIC_ERRORS:
            return unavailable('encryption-cleanup-unresolved' if _PENDING is not None else 'encryption-unavailable')
        return {'schema':1,'availability':'sealed','attempt_id':attempt,'identity':identity,'uid':payload['uid'],'status':payload['status'],
            'recipient_sha256':RECIPIENT_SHA,'fingerprint':FINGERPRINT,'ciphertext_bytes':len(cipher),'ciphertext_sha256':digest(cipher),'ciphertext_base64':base64.b64encode(cipher).decode()}
    except (KeyError,TypeError,ValueError,AttributeError):return unavailable('invalid')

def project(value,expected,payload=None):
    try:
        if type(value) is not dict:return unavailable('invalid')
        if value.get('availability')=='unavailable':
            return value if set(value)=={'schema','availability','reason'} and type(value['schema']) is int and value['schema']==1 and value['reason'] in REASONS else unavailable('invalid')
        keys={'schema','availability','attempt_id','identity','uid','status','recipient_sha256','fingerprint','ciphertext_bytes','ciphertext_sha256','ciphertext_base64'}
        if not (set(value)==keys and type(value['schema']) is int and value['schema']==1 and value['availability']=='sealed'):raise ValueError("sealed schema")
        if not (type(value['attempt_id']) is str and re.fullmatch('[0-9a-f]{32}',value['attempt_id'])):raise ValueError('attempt')
        identity=value['identity']
        if not identity=={'source_sha':expected['source_sha'],'context_sha256':expected['context_sha256'],'phase':'maintenance-gptbox'}:raise ValueError('identity')
        if not (type(payload) is dict and payload.get('availability')=='observed' and payload.get('context_sha256')==expected['context_sha256'] and payload.get('suboperation')=='load' and payload.get('launch_handle_observed') is True and payload.get('control_verified') is True and type(payload.get('uid')) is int and type(payload.get('status')) is int and payload['uid']==value['uid'] and payload['status']==value['status'] and all(row.get('complete') is True for row in payload['streams'].values())):raise ValueError('payload binding')
        if not (value['recipient_sha256']==RECIPIENT_SHA and value['fingerprint']==FINGERPRINT):raise ValueError("sealed schema")
        if not (type(value['uid']) is int and 1000<=value['uid']<2**32 and type(value['status']) is int and 1<=value['status']<=255):raise ValueError("sealed schema")
        if not (type(value['ciphertext_base64']) is str and len(value['ciphertext_base64'])<=21848):raise ValueError("sealed schema")
        cipher=base64.b64decode(value['ciphertext_base64'],validate=True)
        if not (type(value['ciphertext_bytes']) is int and 0<len(cipher)<=CIPHER_LIMIT and len(cipher)==value['ciphertext_bytes'] and digest(cipher)==value['ciphertext_sha256']):raise ValueError("sealed schema")
        if not (len(canonical(value))<=24000):raise ValueError("sealed schema")
        return value
    except (AssertionError,KeyError,TypeError,ValueError):return unavailable('invalid')

def verify_plaintext(plain,value,expected,payload):
    """Private local post-decryption check; returns no decoded content or errors.

    Caller must first require successful authenticated stock-GPG decryption of
    the ciphertext whose public digest was checked. This does not decrypt.
    """
    try:
        if type(plain) is not bytes or not 0<len(plain)<=PLAIN_LIMIT or project(value,expected,payload)!=value or value.get('availability')!='sealed':return False
        def unique(pairs):
            result={}
            for key,item in pairs:
                if key in result:raise ValueError('duplicate')
                result[key]=item
            return result
        envelope=json.loads(plain,object_pairs_hook=unique)
        if canonical(envelope)!=plain or set(envelope)!={'schema','attempt_id','recipient_sha256','fingerprint','identity','executor','suboperation','status','streams'}:return False
        if type(envelope['schema']) is not int or envelope['schema']!=1 or envelope['suboperation']!='load':return False
        for key in ('attempt_id','recipient_sha256','fingerprint','identity','status'):
            if envelope[key]!=value[key]:return False
        if type(envelope['status']) is not int or envelope['executor']!={'uid':value['uid'],'unit':'dev-pair-gptbox-'+expected['context_sha256']+'.service'} or type(envelope['executor']['uid']) is not int:return False
        if type(envelope['streams']) is not dict or set(envelope['streams'])!={'stdout','stderr'}:return False
        for name,record in envelope['streams'].items():
            if type(record) is not dict or set(record)!={'bytes','sha256','complete','base64'} or type(record['bytes']) is not int or record['complete'] is not True or type(record['base64']) is not str:return False
            raw=base64.b64decode(record['base64'],validate=True)
            if len(raw)!=record['bytes'] or digest(raw)!=record['sha256'] or {key:record[key] for key in ('bytes','sha256','complete')}!=payload['streams'][name]:return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError):return False
