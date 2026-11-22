#!/usr/bin/python3
"""Explicit Fedora Cloud 44 host preparation; never launches submitted code or apps."""
import argparse
import base64
import contextlib
import contextvars
from dataclasses import dataclass
import fcntl
import hashlib
import http.client
import ipaddress
import importlib.util
import shutil
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

try:
    from native_io import NativeTransport, pipe_pair, expected_uid, stage_relay, verify_labels, relay, lookup_paths, configuration_snapshot, configuration_mismatch, verify_inactive_cgroup
except ModuleNotFoundError:
    _io_spec = importlib.util.spec_from_file_location('dev_pair_native_io', Path(__file__).with_name('native_io.py'))
    _io_module = importlib.util.module_from_spec(_io_spec)
    _io_spec.loader.exec_module(_io_module)
    NativeTransport, pipe_pair = _io_module.NativeTransport, _io_module.pipe_pair
    expected_uid, stage_relay, verify_labels, relay = _io_module.expected_uid, _io_module.stage_relay, _io_module.verify_labels, _io_module.relay
    lookup_paths, configuration_snapshot, verify_inactive_cgroup = _io_module.lookup_paths, _io_module.configuration_snapshot, _io_module.verify_inactive_cgroup
    configuration_mismatch = _io_module.configuration_mismatch

try:
    import selected_payload
except ModuleNotFoundError:
    _seal_spec=importlib.util.spec_from_file_location('selected_payload',Path(__file__).with_name('selected_payload.py'))
    selected_payload=importlib.util.module_from_spec(_seal_spec);_seal_spec.loader.exec_module(selected_payload)

STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
SOURCE_BASELINE = '4dcf92e256a49770ddd89e4420b105319885910f'
STATE = '/var/lib/dev-pair/bootstrap'
PACKAGES = ('podman', 'distrobox', 'passt', 'fuse-overlayfs', 'container-selinux',
            'policycoreutils', 'shadow-utils', 'sudo', 'openssh-server', 'nftables', 'git-core', 'util-linux',
            'mosh', 'tmux', 'chrony', 'slirp4netns', 'gnupg2')
REPO = '''[tailscale-stable]
name=Tailscale stable
baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=1
gpgkey=https://pkgs.tailscale.com/stable/fedora/repo.gpg
'''
GUARD = '''# dev-pair bootstrap v1; owns only this table, never flushes other rules
add table inet dev_pair_bootstrap
flush table inet dev_pair_bootstrap
add chain inet dev_pair_bootstrap input { type filter hook input priority -10; policy drop; }
add rule inet dev_pair_bootstrap input iifname != "tailscale0" udp dport 60000-61000 drop
add rule inet dev_pair_bootstrap input ct state established,related accept
add rule inet dev_pair_bootstrap input iifname "lo" accept
add rule inet dev_pair_bootstrap input iifname "tailscale0" tcp dport 22 accept
add rule inet dev_pair_bootstrap input iifname "tailscale0" udp dport 60000-61000 accept
{bootstrap_rules}
add rule inet dev_pair_bootstrap input udp dport 41641 accept
add rule inet dev_pair_bootstrap input meta l4proto { icmp, ipv6-icmp } accept
add rule inet dev_pair_bootstrap input udp sport 67 udp dport 68 accept
add rule inet dev_pair_bootstrap input udp sport 547 udp dport 546 accept
add chain inet dev_pair_bootstrap forward { type filter hook forward priority -10; policy drop; }
'''
UNIT = '''[Unit]
Description=Dev-pair temporary bootstrap ingress guard
Before=tailscaled.service sshd.service
After=local-fs.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/dev-pair/bootstrap.nft
[Install]
WantedBy=multi-user.target
'''
TAILSCALE_UNIT = '''[Unit]
Requires=dev-pair-bootstrap-guard.service
After=dev-pair-bootstrap-guard.service
'''

# Only Bash's interactive profile path enters tmux. Remote commands, scp/sftp and
# mosh's SSH startup run noninteractive shells and must retain their protocol.
OPERATOR_PROFILE = """# dev-pair core reconnect; installed by authorized bootstrap
case $- in
  *i*)
    if [ "$(/usr/bin/id -un)" = core ] && [ -z "${TMUX:-}" ] && [ -t 0 ] && [ -t 1 ]; then
        exec /usr/bin/tmux new-session -A -s dev-pair-core
    fi
    ;;
esac
"""
KEYS_URL = 'https://github.com/oso-gato.keys'
KEYS_MAX_BYTES = 262144
KEYS_FETCH_TIMEOUT = 25
KEYS_FETCH_ATTEMPTS = 3

class Blocked(Exception):
    pass

SUDO_PACKAGE_QUERY = ('/usr/bin/rpm', '-qf', '/usr/bin/sudo', '--queryformat',
                      '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n')
SUDO_ROLES = {'dp-maint': 'maintenance-sudo-denial', 'dp-dev': 'development-sudo-denial'}
ROLE_DIRECTORIES = {'dp-maint':'maintenance','dp-dev':'development'}
ROLE_CHILDREN = ('workspaces','checkpoints','evidence','deliverables','builds','cache','state')


@dataclass(frozen=True)
class _RoleIdentity:
    name: str
    uid: int
    gid: int


def _canonical_role_id(value):
    if type(value) is not str or len(value) > 11 or re.fullmatch(r'[1-9][0-9]{0,9}\n',value) is None:
        raise Blocked('managed role identity is not canonical')
    result = int(value[:-1])
    if not 1000 <= result <= 4294967294:
        raise Blocked('managed role identity is outside supported bounds')
    return result


def sudo_package_projection(stdout, stderr, complete, status):
    value = {'availability': 'unavailable', 'supported': False,
             'provenance': 'package-only', 'policy_plugin_verified': False}
    if complete is not True or type(status) is not int or status != 0 or stderr or len(stdout) > 512:
        return value
    try:
        text = stdout.decode('ascii')
    except UnicodeError:
        return value
    match = re.fullmatch(r'([A-Za-z0-9_.+-]{1,64})\t([A-Za-z0-9_.+-]{1,64})\t([A-Za-z0-9_.+-]{1,64})\t([A-Za-z0-9_+-]{1,32})\n', text)
    if match is None:
        return value
    value.update(availability='observed', **dict(zip(('name', 'version', 'release', 'arch'), match.groups())))
    value['supported'] = (value['name'] == 'sudo' and value['version'] == '1.9.17' and
                          re.fullmatch(r'[0-9]+\.p2\.fc44', value['release']) is not None and
                          value['arch'] in ('x86_64', 'aarch64'))
    return value


def sudo_denial_projection(role, stdout, stderr, *, complete, status, native_status,
                           relay_verified, host_verified, package, execution_kind='native'):
    if type(role) is not str or role not in SUDO_ROLES:
        raise Blocked('unsupported sudo denial role')
    expected = ('User ' + role + ' is not allowed to run sudo on erebus.\n').encode('ascii')
    exact = stdout == expected
    supported = (type(package) is dict and set(package) == {'availability', 'supported', 'provenance',
                 'policy_plugin_verified', 'name', 'version', 'release', 'arch'} and
                 package['availability'] == 'observed' and package['supported'] is True and
                 package['provenance'] == 'package-only' and package['policy_plugin_verified'] is False and
                 package['name'] == 'sudo' and package['version'] == '1.9.17' and
                 type(package['release']) is str and len(package['release']) <= 64 and
                 re.fullmatch(r'[0-9]+\.p2\.fc44', package['release']) is not None and
                 package['arch'] in ('x86_64', 'aarch64'))
    transport = ((execution_kind == 'native' and type(native_status) is int and native_status == 0 and relay_verified is True) or
                 (execution_kind == 'direct' and native_status is None and relay_verified is False))
    accepted = (complete is True and type(status) is int and status == 0 and transport and
                host_verified is True and supported and exact and not stderr)
    return {'operation_id': SUDO_ROLES[role], 'role': role, 'execution_kind': execution_kind,
            'relay_applicability': 'required' if execution_kind == 'native' else 'not-applicable',
            'payload_exit': status if type(status) is int else None,
            'native_exit': native_status if type(native_status) is int else None,
            'relay_verified': relay_verified is True, 'exact_denial': exact,
            'hostname_bound': host_verified is True, 'stderr_empty': not stderr,
            'complete_input': complete is True, 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
            'package_supported': supported, 'outcome': 'denied' if accepted else 'blocked'}

PREPARE_COST_STEPS=('pre-prepare','input-admission','host-preflight','context-content','context-source','git-prerequisite',
    'adapter-source-and-upstream','desired-state','resolved-discovery','packages','operator','host-identity-time',
    'sudo-package-provenance','dp-maint','maintenance-directories','dp-dev','development-directories','managed-limits',
    'ingress-guard','tailscale-package-config','tailscale-package','package-inventory','maintenance-gptbox-build',
    'preparation-completion','finalization','unattributed')
PREPARE_COST_COLUMNS=('visits','wall_seconds','command_count','accepted','rejected_with_launcher_handle',
                      'rejected_without_launcher_handle','command_elapsed_seconds')
PREPARE_COST_SCOPE='emitted-top-level-prepare-and-source-check-callbacks'


def cost_finite(value):
    return type(value) in (int,float) and 0<=value<=3300 and math.isfinite(value)


class PrepareCost:
    """Per-attempt diagnostics; parent elapsed already includes nested controls.

    An obtained launcher handle is not payload execution or cleanup proof. Wall
    and command durations are separate measurements and must never be added.
    """
    def __init__(self,source,context,attempt,started,phase='prepare'):
        self.phase=phase
        self.source,self.context,self.attempt=source,context,attempt
        self.started=self.last=started;self.active='pre-prepare';self.closed=False
        self.rows={'pre-prepare':[1,0.,0,0,0,0,0.]}
        self.wall_complete=self.commands_complete=True;self.overflow=False;self.unknown_records=0
        self.command_records=0;self.elapsed=None;self.outcome='interrupted'
        self.transition_pending=False;self.command_pending=False

    def tick(self):
        now=time.monotonic();delta=now-self.last
        if cost_finite(delta) and cost_finite(now-self.started):
            row=self.rows[self.active];row[1]=round(row[1]+delta,6);self.elapsed=round(now-self.started,6)
        else:self.wall_complete=False
        self.last=now

    def mark(self,step):
        if self.closed:return
        self.transition_pending=True
        self.tick()
        if step not in PREPARE_COST_STEPS:step='unattributed';self.wall_complete=False
        row=self.rows.setdefault(step,[0,0.,0,0,0,0,0.]);self.active=step
        if row[0]<4096:row[0]+=1
        else:self.overflow=True;self.wall_complete=False
        self.transition_pending=False

    def command(self,entry):
        if self.closed:return
        if self.command_records>=4096:self.overflow=True;self.commands_complete=False;return
        self.command_pending=True
        self.command_records+=1
        step=entry.get('step') if type(entry) is dict else None
        if (step not in PREPARE_COST_STEPS or type(entry.get('accepted_exit')) is not bool or
                type(entry.get('launcher_handle_observed')) is not bool or not cost_finite(entry.get('elapsed_seconds')) or
                entry['accepted_exit'] and not entry['launcher_handle_observed']):
            self.commands_complete=False;self.unknown_records+=1;self.command_pending=False;return
        row=self.rows.setdefault(step,[0,0.,0,0,0,0,0.]);row[2]+=1
        row[3 if entry['accepted_exit'] else 4 if entry['launcher_handle_observed'] else 5]+=1
        row[6]=round(row[6]+entry['elapsed_seconds'],6) if row[6] is not None else None
        if not cost_finite(row[6]):self.overflow=True;self.commands_complete=False;row[6]=None
        self.command_pending=False

    def finish(self,success):
        if not self.closed:
            self.tick();self.closed=True;self.outcome='complete' if success else 'interrupted'

    def snapshot(self,budget):
        if self.transition_pending or self.command_pending:
            return {'availability':'unavailable','reason':'interrupted-accounting-update'}
        result={'schema':1,'source_sha':self.source,'context_sha256':self.context,'attempt_id':self.attempt,'phase':self.phase,
            'phase_budget_sha256':hashlib.sha256(json.dumps(budget,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'status':'overflow' if self.overflow else 'incomplete' if not(self.wall_complete and self.commands_complete) else self.outcome,
            'wall_complete':self.wall_complete,'commands_complete':self.commands_complete,'elapsed_seconds':self.elapsed,
            'command_records':self.command_records,'unknown_records':self.unknown_records,
            'scope':('emitted-top-level-host-prerequisites-and-source-check-callbacks' if self.phase=='host-prerequisites' else PREPARE_COST_SCOPE),'nested_controls':'included-in-parent-elapsed-not-counted-again',
            'columns':list(PREPARE_COST_COLUMNS),'steps':self.rows}
        if len(json.dumps(result,separators=(',',':')).encode())>4096:
            return {'availability':'unavailable','reason':'projection-overflow'}
        return result

_PHASE_DEADLINE = contextvars.ContextVar('dev_pair_phase_deadline', default=None)


TAILSCALE_PACKAGE = ('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1', '--disablerepo=*',
    '--enablerepo=fedora', '--enablerepo=updates', '--enablerepo=tailscale-stable', 'install', 'tailscale')
LAUNCHER_RESULTS = frozenset(('success','resources','protocol','timeout','exit-code','signal','core-dump',
    'watchdog','start-limit-hit','oom-kill','exec-condition'))

def launcher_summary(raw, complete, expected_unit=None):
    """Closed C-locale systemd-run summary; never returns captured text."""
    unavailable = {'availability':'unavailable'}
    if not complete or len(raw)>8192 or any(c<32 and c!=10 or c>126 for c in raw):return unavailable
    try:
        fields={};seen=set()
        for line in raw.decode('ascii').splitlines():
            if not line:continue
            match=re.fullmatch(r' *([^:]+): (.+)',line)
            if not match:return unavailable
            key,value=match.groups()
            if key in seen:return unavailable
            seen.add(key)
            if key=='Finished with result':
                if value not in LAUNCHER_RESULTS:return unavailable
                fields['result']=value
            elif key=='Main processes terminated with':
                match=re.fullmatch(r'code=(exited|killed|dumped), status=([0-9]{1,3})/([A-Z0-9_-]+|n/a)',value)
                if not match:return unavailable
                code,number,label=match.groups();number=int(number)
                signals={'HUP':1,'INT':2,'QUIT':3,'ILL':4,'TRAP':5,'ABRT':6,'BUS':7,'FPE':8,'KILL':9,
                    'USR1':10,'SEGV':11,'USR2':12,'PIPE':13,'ALRM':14,'TERM':15,'CHLD':17,'CONT':18,'STOP':19,
                    'TSTP':20,'TTIN':21,'TTOU':22,'XCPU':24,'XFSZ':25,'VTALRM':26,'PROF':27,'WINCH':28,'SYS':31}
                exits={0:'SUCCESS',1:'FAILURE',2:'INVALIDARGUMENT',3:'NOTIMPLEMENTED',4:'NOPERMISSION',5:'NOTINSTALLED',6:'NOTCONFIGURED',7:'NOTRUNNING',
                    200:'CHDIR',203:'EXEC',204:'MEMORY',205:'LIMITS',216:'GROUP',217:'USER',218:'CAPABILITIES',226:'NAMESPACE'}
                if code=='exited':
                    if number>255 or label!=exits.get(number,'n/a'):return unavailable
                elif signals.get(label)!=number:return unavailable
                fields.update(code=code,status=number)
            elif key=='Running as unit':
                pattern=(re.escape(expected_unit) if expected_unit is not None else r'dev-pair-initialize-prepare-[0-9a-f]{8}-[0-9a-f]{8}\.service')
                if not re.fullmatch(pattern+r'(?:; invocation ID: [0-9a-f]{32})?',value):return unavailable
            elif key in ('Service runtime','CPU time consumed'):
                if not re.fullmatch(r'(?:[0-9]+(?:\.[0-9]+)?(?:us|ms|s|min|h|d|w|month|y) ?)+',value):return unavailable
            elif key=='Memory peak':
                if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?[BKMGTPE]?(?: \(swap: [0-9]+(?:\.[0-9]+)?[BKMGTPE]?\))?',value):return unavailable
            elif key in ('IP Traffic','IO Bytes'):
                if not re.fullmatch(r'(?:received|sent|read|written) [0-9]+(?:\.[0-9]+)?[BKMGTPE]?(?:, (?:sent|written) [0-9]+(?:\.[0-9]+)?[BKMGTPE]?)?',value):return unavailable
            else:return unavailable
        return {'availability':'observed',**fields} if 'result' in fields else unavailable
    except (ValueError,UnicodeError):return unavailable


SIGNED_LOAD_OWNER_ERROR = b'path "/usr/local/libexec/dev-pair-gptbox/home/.config" exists and it is not owned by the current user'
SIGNED_LOAD_ERRORS={'reported-owner':SIGNED_LOAD_OWNER_ERROR+b'\n',
    'reported-stat-enoent':b'stat /usr/local/libexec/dev-pair-gptbox/home/.config: no such file or directory\n',
    'reported-stat-eacces':b'stat /usr/local/libexec/dev-pair-gptbox/home/.config: permission denied\n'}


def signed_load_payload(buffers, selection, uid, *, launched, verified, status, complete):
    """Hash-only captured streams; matched forms are diagnostics, never causes."""
    if selection is None or selection.get('suboperation')!='load':return None
    streams={}
    for name in ('stdout','stderr'):
        data=bytes(buffers[name]);known=bool(data) or complete
        streams[name]={'bytes':len(data) if known else None,
                       'sha256':hashlib.sha256(data).hexdigest() if known else None,'complete':complete}
    family='unknown';role='none'
    if complete and status==1 and not buffers['stdout']:
        for name,form in SIGNED_LOAD_ERRORS.items():
            if bytes(buffers['stderr'])==form:family=name;role='old-home-config';break
    return {'schema':1,'availability':'observed' if complete else 'partial' if any(buffers.values()) else 'unavailable',
            'context_sha256':selection['context_sha256'],'uid':int(uid),'suboperation':'load',
            'launch_handle_observed':launched,'control_verified':verified,'status':status if verified else None,
            'streams':streams,'classification':{'family':family,'path_role':role}}


class Commands:
    """Bounded execution with secret-safe, explicitly public diagnostics."""
    deadline = None
    native_prefix = None
    diagnostic = None
    metadata_diagnostic = None
    native_register = None
    _cleanup_deadline = None
    current_step = 'unscoped'
    _maintenance_launcher_binding = None
    _adapter_image_binding = None

    @contextlib.contextmanager
    def maintenance_launcher(self, context, uid):
        # Diagnostic scope is entered only after build_gptbox source/context
        # validation and checked UID lookup. It grants no launch authority.
        previous=self._maintenance_launcher_binding
        self._maintenance_launcher_binding=(context,uid)
        try:yield
        finally:self._maintenance_launcher_binding=previous

    @contextlib.contextmanager
    def adapter_image_launcher(self,context,uid,identity=None):
        previous=self._adapter_image_binding;previous_identity=getattr(self,"_selected_payload_identity",None)
        self._adapter_image_binding=(context,uid);self._selected_payload_identity=identity
        try:yield
        finally:self._adapter_image_binding=previous;self._selected_payload_identity=previous_identity

    def adapter_image_selection(self,args,input_text):
        if self.current_step!='candidate-image' or input_text is not None:return None
        context,uid=self._adapter_image_binding
        if type(context) is not str or not re.fullmatch('[0-9a-f]{64}',context) or type(uid) is not str or not re.fullmatch('[1-9][0-9]{0,9}',uid):return None
        unit='dev-pair-gptbox-'+context+'.service';control='/usr/local/libexec/dev-pair-gptbox'
        fixed=('/usr/bin/systemd-run','--unit='+unit,'--description=dev-pair-owned-'+unit,'--quiet','--wait','--collect','--service-type=exec','--uid=dp-maint')
        if args[:8]!=fixed or len(args)<24 or not args[8].startswith('--property=RuntimeMaxSec='):return None
        try:
            duration=float(args[8].split('=',2)[2])
            if not math.isfinite(duration) or not 0<duration<=600:return None
        except ValueError:return None
        tail=('--property=TimeoutStopSec=10','--property=KillMode=control-group','--property=MemoryMax=2G','--property=TasksMax=512','--property=CPUQuota=100%',
            '/usr/bin/env','-i','PATH='+control+'/bin:/usr/bin:/usr/sbin:/bin','HOME='+control+'/home','USER=gpt','LOGNAME=gpt',
            'XDG_RUNTIME_DIR=/run/user/'+uid,'XDG_CONFIG_HOME='+control+'/xdg-config','CONTAINERS_CONF='+control+'/containers.conf','DBX_CONTAINER_MANAGER=podman')
        if args[9:24]!=tail:return None
        rest=args[24:];work='/var/lib/dev-pair/artifacts/gptbox-adapter/'+context+'/image-work';wrapper=control+'/bin/podman'
        temporary=('/usr/bin/env','TMPDIR='+work+'/image-copy',wrapper)
        copied=rest[:3]==temporary
        if copied:operation=rest[3:]
        elif rest[:1]==(wrapper,):operation=rest[1:]
        else:return None
        archive=re.escape(work+'/verification-work/')+r'dev-pair-fedora-[a-z0-9_]{8}/'
        image='sha256:9eaa56a730854ae53f57e58c16179d09c2fa1f4157a5d69ccb39647e33c6464d';selected=None
        if copied and len(operation)==3 and operation[:2]==('load','--input') and re.fullmatch(archive+r'base\.oci\.tar',operation[2]):selected='load'
        elif copied and len(operation)==5 and operation[:3]==('save','--format=oci-archive','--output') and operation[4]==image and re.fullmatch(archive+r'imported\.oci\.tar',operation[3]):selected='save'
        elif len(operation)==3 and operation[:2]==('image','inspect') and re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}',operation[2]):selected='inspect'
        elif copied and operation==('build','--quiet','--network=slirp4netns:allow_host_loopback=false','--pull=never','--http-proxy=false','--file',
                '/var/lib/dev-pair/artifacts/gptbox-adapter/'+context+'/build/Containerfile','/var/lib/dev-pair/artifacts/gptbox-adapter/'+context+'/build'):selected='build'
        return {'context_sha256':context,'unit':unit,'suboperation':selected} if selected else None

    def maintenance_launcher_selection(self,args,input_text,probe):
        binding=self._maintenance_launcher_binding
        if not all(type(value) is str for value in args):return None
        if self._adapter_image_binding is not None:return self.adapter_image_selection(args,input_text)
        if self.current_step!='maintenance-gptbox-build' or input_text is not None or probe or binding is None:return None
        context,uid=binding
        if (type(context) is not str or not re.fullmatch('[0-9a-f]{64}',context) or type(uid) is not str or
            not re.fullmatch('[1-9][0-9]{0,9}',uid) or not 1000<=int(uid)<=4294967294):return None
        unit='dev-pair-gptbox-'+context+'.service'
        base=('/usr/bin/systemd-run','--wait','--collect','--service-type=exec','--uid=dp-maint','--unit='+unit,
            '--description=dev-pair-owned-'+unit,'--property=RuntimeMaxSec=600','--property=TimeoutStopSec=10',
            '--property=KillMode=control-group','--property=MemoryMax=2G','--property=TasksMax=512','--property=CPUQuota=100%',
            '/usr/bin/env','-i','HOME=/home/dp-maint','USER=dp-maint','LOGNAME=dp-maint','PATH=/usr/sbin:/usr/bin',
            'XDG_RUNTIME_DIR=/run/user/'+uid)
        if args[:len(base)]!=base:return None
        rest=args[len(base):];work='/var/lib/dev-pair/artifacts/gptbox-image-work/'+context
        temporary=('TMPDIR='+work+'/image-copy',)
        limited=('/usr/bin/prlimit','--fsize=201326592:201326592')
        is_copy=rest[:1]==temporary
        if is_copy:rest=rest[1:]
        is_save=rest[:2]==limited
        if is_save:rest=rest[2:]
        engine=('/usr/bin/podman','--root','/var/lib/dev-pair/maintenance/images','--runroot',
            '/run/user/'+uid+'/dev-pair-gptbox-build','--storage-driver=vfs')
        if rest[:len(engine)]!=engine:return None
        operation=rest[len(engine):];stage='/var/lib/dev-pair/artifacts/gptbox/'+context
        archive=re.escape(work+'/verification-work/')+r'dev-pair-fedora-[a-z0-9_]{8}/'
        image='sha256:9eaa56a730854ae53f57e58c16179d09c2fa1f4157a5d69ccb39647e33c6464d'
        selected=None
        if is_copy and not is_save and len(operation)==3 and operation[:2]==('load','--input') and re.fullmatch(archive+r'base\.oci\.tar',operation[2]):selected='load'
        elif is_copy and is_save and len(operation)==5 and operation[:3]==('save','--format=oci-archive','--output') and operation[4]==image and re.fullmatch(archive+r'imported\.oci\.tar',operation[3]):selected='save'
        elif not is_save and len(operation)==3 and operation[:2]==('image','inspect') and re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}',operation[2]):selected='inspect'
        elif is_copy and not is_save and operation==('build','--quiet','--network=slirp4netns:allow_host_loopback=false','--pull=never','--format=oci',
            '--label','dev-pair.context='+context,'--tag','localhost/dev-pair/maintenance-gptbox:'+context,'--file',stage+'/Containerfile',stage):selected='build'
        return {'context_sha256':context,'unit':unit,'suboperation':selected} if selected is not None else None

    def execution_deadline(self):
        # Explicit cleanup controls are finite and may run after an execution
        # deadline; ordinary fresh runners always inherit the enclosing phase.
        if self._cleanup_deadline is not None:
            return self._cleanup_deadline
        return min((value for value in (self.deadline, _PHASE_DEADLINE.get()) if value is not None), default=None)

    def limit_timeout(self, timeout):
        deadline = self.execution_deadline()
        remaining = timeout if deadline is None else min(timeout, deadline - time.monotonic())
        if remaining <= 0:
            raise Blocked('phase execution budget exhausted')
        return remaining

    @contextlib.contextmanager
    def phase(self, seconds, prefix, native=True):
        self.phase_budget_witness = None
        previous = self.deadline, self.native_prefix
        started = time.monotonic()
        old_timer = signal.getitimer(signal.ITIMER_REAL)
        old_timer_deadline = started + old_timer[0] if old_timer[0] else None
        phase_deadline = min(started + seconds, self.execution_deadline() or float('inf'),
                             old_timer_deadline or float('inf'))
        remaining = phase_deadline - time.monotonic()
        if remaining <= 0:
            raise Blocked('phase execution budget exhausted')
        timer_fired = False
        def expired(signum, frame):
            nonlocal timer_fired
            timer_fired = True
            raise Blocked('phase execution budget exhausted')
        old_handler = signal.getsignal(signal.SIGALRM)
        token = None
        try:
            signal.signal(signal.SIGALRM, expired)
            token = _PHASE_DEADLINE.set(phase_deadline)
            self.deadline = phase_deadline
            self.native_prefix = prefix + '-' + uuid.uuid4().hex[:8] if native else None
            signal.setitimer(signal.ITIMER_REAL, remaining)
            yield
        finally:
            observed = time.monotonic()
            elapsed = observed >= phase_deadline
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.phase_budget_witness = {'configured_seconds':seconds,
                # Absolute-clock addition/subtraction may round slightly above
                # the configured duration. Bound only the reported observation;
                # the actual deadline, timer and expiry decision stay intact.
                'effective_seconds':min(seconds,max(0,phase_deadline-started)),
                'elapsed_seconds':max(0,observed-started),
                'deadline_reached_at_exit':elapsed,'timer_fired':timer_fired}
            self.deadline, self.native_prefix = previous
            if token is not None:
                _PHASE_DEADLINE.reset(token)
            signal.signal(signal.SIGALRM, old_handler)
            if old_timer_deadline is not None:
                # Restore the absolute deadline, never a fresh outer duration.
                signal.setitimer(signal.ITIMER_REAL, max(.000001, old_timer_deadline - time.monotonic()), old_timer[1])
            if elapsed:
                raise Blocked('phase execution budget exhausted')

    @staticmethod
    def public_operation(args):
        if args == ('/usr/sbin/getenforce',):
            return 'selinux-enforcement'
        if (len(args) == 7 and args[:2] == ('/usr/bin/systemctl', 'show') and args[-1] == 'systemd-resolved.service' and
                set(args[2:-1]) == {'--property=MainPID', '--property=User', '--property=ActiveState', '--property=LoadState'}):
            return 'resolved-service-identity'
        if args and args[0] == '/usr/bin/dnf':
            return 'signed-packages'
        if args and args[0] == '/usr/bin/systemd-run' and '/usr/bin/podman' in args:
            operation = args[args.index('/usr/bin/podman') + 1:]
            if 'pull' in operation or 'build' in operation:
                return 'candidate-image'
        return None

    @staticmethod
    def operation_id(args):
        # IDs are fixed enums; never echo argv, paths or environment.
        if len(args) == 3 and args[0] == '/usr/bin/id' and args[1] in ('-u','-g') and args[2] in ROLE_DIRECTORIES:
            return ROLE_DIRECTORIES[args[2]]+'-owner-'+('uid' if args[1]=='-u' else 'gid')
        if len(args) == 4 and args[:3] == ('/usr/bin/sudo', '-l', '-U') and args[3] in SUDO_ROLES:
            return SUDO_ROLES[args[3]]
        if args == SUDO_PACKAGE_QUERY:
            return 'sudo-package-provenance'
        if args == ('/usr/sbin/getenforce',):
            return 'selinux-enforcement'
        if (len(args) == 7 and args[:2] == ('/usr/bin/systemctl', 'show') and args[-1] == 'systemd-resolved.service' and
                set(args[2:-1]) == {'--property=MainPID', '--property=User', '--property=ActiveState', '--property=LoadState'}):
            return 'resolved-service-identity'
        fixed = {'/usr/bin/git': 'source-git-read', '/usr/bin/dnf': 'signed-packages',
                 '/usr/bin/ss': 'listener-inventory', '/usr/sbin/nft': 'firewall-control',
                 '/usr/bin/hostnamectl': 'host-identity', '/usr/bin/chronyc': 'time-status',
                 '/usr/bin/rpm': 'package-inventory', '/usr/sbin/chpasswd': 'operator-password'}
        if args and args[0] == '/usr/sbin/sshd':
            return 'sshd-effective' if '-T' in args else 'sshd-validation'
        if args and args[0] == '/usr/bin/systemctl':
            return {'is-active': 'service-active', 'show': 'service-properties', 'restart': 'service-restart',
                    'start': 'service-start', 'enable': 'service-enable', 'daemon-reload': 'service-reload',
                    'reload': 'service-reload', 'stop': 'service-stop'}.get(args[1] if len(args) > 1 else '', 'service-control')
        if args and args[0] == '/usr/bin/systemd-run':
            return 'candidate-native-executor'
        return fixed.get(args[0] if args else '', 'withheld-operation')

    @staticmethod
    def native_diagnostic(args):
        args = Commands.native_prefix_args(args)
        unit = next((value[7:] for value in args if value.startswith('--unit=')), None)
        description = next((value[14:] for value in args if value.startswith('--description=')), None)
        if not unit or description != 'dev-pair-owned-' + unit:
            return {'availability': 'not-controller-owned-or-not-native'}
        if not re.fullmatch(r'dev-pair-(?:initialize-(?:prepare|adapter|cleanup)-[0-9a-f]{8}-[0-9a-f]{8}|gptbox-[0-9a-f]{64}(?:\.service)?)', unit):
            return {'availability': 'unrecognized-controller-unit'}
        control = Commands()
        control._cleanup_deadline = time.monotonic() + 2
        properties = ('Description', 'LoadState', 'ActiveState', 'Result', 'ExecMainCode', 'ExecMainStatus', 'StatusErrno')
        try:
            text = control('/usr/bin/systemctl', 'show', *('--property=' + key for key in properties), unit,
                           ok=(0, 1, 4), timeout=2)
            values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
            if values.get('LoadState') == 'not-found':
                return {'availability': 'unavailable-collected-or-not-started', 'unit': unit}
            if values.get('Description') != description:
                return {'availability': 'ownership-unverified', 'unit': unit}
            return {'availability': 'observed', 'unit': unit, **{key: values.get(key, 'unavailable')[:80] for key in properties if key != 'Description'}}
        except (Blocked, OSError, ValueError, subprocess.SubprocessError):
            return {'availability': 'observation-failed', 'unit': unit}

    @staticmethod
    def native_prefix_args(args):
        if args and args[0] == '/usr/bin/systemd-run':
            end = next((index for index, value in enumerate(args[1:], 1) if not value.startswith('-')), len(args))
            return args[:end]
        return args

    @staticmethod
    def native_args(args, timeout):
        rewritten = []
        for value in args:
            if value.startswith('--property=RuntimeMaxSec='):
                current = value.rsplit('=', 1)[1].removesuffix('s')
                if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', current):
                    raise Blocked('invalid native lifetime')
                ceiling = min(float(current), timeout)
                if ceiling < .001:
                    raise Blocked('native execution budget exhausted; zero disables systemd lifetime')
                value = '--property=RuntimeMaxSec=%.3fs' % (int(ceiling * 1000) / 1000)
            rewritten.append(value)
        return tuple(rewritten)

    @staticmethod
    def reconcile_native(args, env):
        args = Commands.native_prefix_args(args)
        # Only fixed controller-created descriptions permit exact-unit cleanup.
        if args and args[0] != '/usr/bin/systemd-run' and not all(value.startswith(('--unit=', '--description=', '--uid=')) for value in args):
            return
        unit = next((v[7:] for v in args if v.startswith('--unit=')), None)
        description = next((v[14:] for v in args if v.startswith('--description=')), None)
        if not unit or description != 'dev-pair-owned-' + unit:
            return
        NativeTransport(unit)  # Validate fixed controller unit grammar before any manager effect.
        # A separate bounded runner has no phase/native wrapper or diagnostic
        # callback: cleanup observations cannot recursively launch more units.
        control = Commands()
        control._cleanup_deadline = time.monotonic() + 20
        observed = control('/usr/bin/systemctl', 'show', '--property=Description', '--property=ActiveState',
                           '--property=LoadState', '--property=User', unit, ok=(0, 1, 4), timeout=5)
        values = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
        expected_user = next((v[6:] for v in args if v.startswith('--uid=')), '')
        if values.get('LoadState') != 'not-found' and (values.get('Description') != description or values.get('User', '') not in ((expected_user,) if expected_user else ('', 'root'))):
            raise Blocked('native unit ownership mismatch; foreign unit preserved')
        if values.get('ActiveState') in ('active', 'activating', 'deactivating', 'reloading'):
            expected_user = next((v[6:] for v in args if v.startswith('--uid=')), '')
            if values.get('Description') != description or values.get('User', '') not in ((expected_user,) if expected_user else ('', 'root')):
                raise Blocked('native unit ownership mismatch; foreign unit preserved')
            control('/usr/bin/systemctl', 'stop', unit, timeout=10)
            after = control('/usr/bin/systemctl', 'show', '--property=ActiveState', '--property=LoadState',
                            unit, ok=(0, 1, 4), timeout=5)
            states = dict(line.split('=', 1) for line in after.splitlines() if '=' in line)
            if states.get('ActiveState') not in ('inactive', 'failed'):
                raise Blocked('native unit remains unresolved; no duplicate effects')
        elif values.get('ActiveState') not in ('inactive', 'failed'):
            raise Blocked('native unit observation failed; no duplicate effects')
        try:
            verify_inactive_cgroup(unit)
            NativeTransport.recover(unit, deadline=control._cleanup_deadline)
        except ValueError:
            raise Blocked('native transport cleanup unresolved; exact ownership records preserved') from None

    def interrupt(self, process, args, env):
        # A reaped/exited launcher still owns its session's process group, and
        # the exact native unit can outlive that launcher independently.
        failed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            failed = True
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            failed = True
        try:
            self.reconcile_native(args, env)
        except (Blocked, OSError, subprocess.SubprocessError):
            failed = True
        if failed:
            raise Blocked('native cleanup unresolved; retained ownership record and finite lifetime')

    def __call__(self, *args, ok=(0,), input_text=None, timeout=900, sudo_probe=None, sudo_package=False):
        return self._call(*args, ok=ok, input_text=input_text, timeout=timeout,
                          sudo_probe=sudo_probe, sudo_package=sudo_package)

    def _call(self, *args, ok=(0,), input_text=None, timeout=900, maximum=1048576, probe=False,
              sudo_probe=None, sudo_package=False):
        if sudo_probe is not None:
            if (type(sudo_probe) is not dict or set(sudo_probe) != {'role', 'host_verified', 'package'} or
                    type(sudo_probe['role']) is not str or sudo_probe['role'] not in SUDO_ROLES or
                    args != ('/usr/bin/sudo', '-l', '-U', sudo_probe['role']) or
                    ok != (0,) or input_text is not None or probe or sudo_package):
                raise Blocked('unsupported sudo denial operation')
        if sudo_package and (args != SUDO_PACKAGE_QUERY or ok != (0,) or input_text is not None or probe):
            raise Blocked('unsupported sudo package operation')
        timeout = self.limit_timeout(timeout)
        stdin_data = input_text.encode() if input_text is not None else None
        if stdin_data is not None and len(stdin_data) > 16384:
            raise Blocked('stdin byte budget exceeded; output withheld')
        original = args
        public = self.public_operation(args) if input_text is None else None
        unit = None
        description = None
        register_root_wrapper = False
        tailscale_launcher = (self.current_step == 'tailscale-package' and original == TAILSCALE_PACKAGE and
            input_text is None and not probe and bool(self.native_prefix) and
            re.fullmatch(r'dev-pair-initialize-prepare-[0-9a-f]{8}', self.native_prefix) is not None)
        maintenance_launcher=self.maintenance_launcher_selection(original,input_text,probe)
        signed_load_selected=(maintenance_launcher is not None and self._adapter_image_binding is not None and
                              maintenance_launcher['suboperation']=='load')
        launcher_selected=tailscale_launcher or maintenance_launcher is not None
        # Existing user transient units are already native executors. Tighten
        # their ceilings rather than putting them outside the phase budget.
        if args and args[0] == '/usr/bin/systemd-run':
            prefix = self.native_prefix_args(args)
            args = (*self.native_args(prefix, timeout), *args[len(prefix):])
        elif self.native_prefix:
            if timeout < .001:
                raise Blocked('native execution budget exhausted')
            register_root_wrapper = True
            unit = self.native_prefix + '-' + uuid.uuid4().hex[:8]
            description = 'dev-pair-owned-' + unit
            args = ('/usr/bin/systemd-run', '--unit=' + unit, '--description=' + description,
                    '--quiet', '--wait', '--collect', '--service-type=exec',
                    '--property=RuntimeMaxSec=%.3fs' % (int(timeout * 1000) / 1000), '--property=TimeoutStopSec=5',
                    '--property=KillMode=control-group', '--property=MemoryMax=2G',
                    '--property=TasksMax=512', '--property=CPUQuota=100%',
                    '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin', 'LANG=C', 'LC_ALL=C', 'HOME=/root', *args)
        env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
        # Frozen from the selected executor branch, never caller metadata or a
        # fallback following failed native admission/relay verification.
        native_execution = bool(args and args[0] == '/usr/bin/systemd-run')
        started = time.monotonic()
        command_end = min(started + timeout, self.execution_deadline() or float('inf'))
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        launcher_capture=bytearray();launcher_bytes=0;launcher_eof=set();launch_timing=None
        total = 0
        status = 'not-started'
        process = None
        completed = False
        capture_complete = False
        payload_eof=set()
        primary_pending = False
        special_result = None
        transport = None
        decoder = None
        relay_sha = None
        relay_uid = None
        relay_verified = False
        admission_stage = 'not-native'
        admission_reason = 'none'
        failure_point='not-reached';failure_category=None;failure_witness=None;cache_comparison=None
        def capture_failure(error):
            nonlocal failure_witness
            if failure_witness is not None or not native_execution:return
            category=failure_category or ('decoder-rejected' if isinstance(error,relay.DecoderRejected) else
                'wait-timeout' if isinstance(error,subprocess.TimeoutExpired) else 'io-error' if isinstance(error,OSError) else
                'text-decode' if isinstance(error,UnicodeError) else 'value-rejected' if isinstance(error,ValueError) else
                'subprocess-error' if isinstance(error,subprocess.SubprocessError) else 'blocked-or-interrupted')
            observed=None;sampled=False
            if process is not None:
                try:observed=process.poll();sampled=True
                except OSError:pass
            failure_witness={'point':failure_point,'category':category,'launcher_handle_observed':process is not None,
                'status_sampled_before_interrupt':sampled,'launcher_status_before_interrupt':observed,
                'decoder':decoder.witness() if decoder is not None else {'availability':'unavailable'}}
            if cache_comparison is not None:failure_witness['cache_comparison']=cache_comparison
            if launcher_selected:
                failure_witness['launcher']={'summary':launcher_summary(bytes(launcher_capture),len(launcher_eof)==2 and launcher_bytes<=8192,
                        maintenance_launcher['unit'] if maintenance_launcher is not None else None),
                    'bytes':min(launcher_bytes,maximum+1),'complete':len(launcher_eof)==2 and launcher_bytes<=8192,
                    'timing':launch_timing or {'availability':'unavailable'}}
                if maintenance_launcher is not None:failure_witness['launcher']['executor']=dict(maintenance_launcher)
        launcher_pairs = []
        selector = selectors.DefaultSelector()
        try:
            if args and args[0] == '/usr/bin/systemd-run':
                boundary = next((index for index, value in enumerate(args[1:], 1) if not value.startswith('-')), len(args))
                seen_options = set()
                for value in args[1:boundary]:
                    option = value.split('=', 2)[0] if not value.startswith('--property=') else '--property=' + value.split('=', 2)[1]
                    if option in seen_options:
                        raise Blocked('duplicate native launch option rejected')
                    seen_options.add(option)
                    if not value.startswith(('--unit=', '--description=', '--uid=', '--property=', '--service-type=')) and value not in ('--quiet', '--wait', '--collect', '--pipe', '--pty'):
                        raise Blocked('unknown native launch option rejected')
                unit = next((value[7:] for value in args[:boundary] if value.startswith('--unit=')), None)
                if next((value[14:] for value in args[:boundary] if value.startswith('--description=')), None) != 'dev-pair-owned-' + str(unit):
                    raise Blocked('native stream ownership unverified')
                if any(value.startswith(('--property=StandardInput=', '--property=StandardOutput=', '--property=StandardError=', '--property=TimeoutStartSec=')) for value in args[:boundary]):
                    raise Blocked('caller native transport/startup properties are forbidden')
                native_limits = [float(value.rsplit('=', 1)[1].removesuffix('s')) for value in args[:boundary]
                                 if value.startswith('--property=RuntimeMaxSec=')]
                if not native_limits:
                    raise Blocked('finite native lifetime is required')
                command_end = min(command_end, started + min(native_limits))
                transport = NativeTransport(unit, deadline=command_end)
                if maintenance_launcher is not None and transport.canonical!=maintenance_launcher['unit']:
                    maintenance_launcher=None;launcher_selected=tailscale_launcher
                # Observe before allocation/registration: an existing busy/foreign
                # unit is a collision, never this attempt's cleanup authority.
                control = Commands()
                control._cleanup_deadline = command_end
                admission_stage = 'manager-paths'
                paths = lookup_paths(control, self.limit_timeout(timeout))
                admission_stage = 'configuration-scan'
                snapshot = configuration_snapshot(paths, unit, end=command_end)
                observed = control._call('/usr/bin/systemctl', 'show', '--property=LoadState', '--property=ActiveState',
                                         '--property=Description', '--property=User', unit, ok=(0, 1, 4),
                                         timeout=self.limit_timeout(timeout), maximum=4096)
                values = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
                expected_user = next((value[6:] for value in args[:boundary] if value.startswith('--uid=')), '')
                if values.get('LoadState') != 'not-found' or values.get('ActiveState') != 'inactive':
                    raise Blocked('native unit is not pristine; existing resources preserved')
                # Initializer inventory contains only wrappers constructed here.
                # Explicit dp-maint context units have their own UID-bound retry
                # path and protected transport journal, not root-unit authority.
                admission_stage = 'mask-stage'
                transport.setup(stdin_data, self.native_register if register_root_wrapper else None)
                relay_path, relay_sha = stage_relay()
                relay_uid = expected_uid(args[:boundary])
                decoder = relay.Decoder(maximum)
                admission_stage = 'labels'
                # One fixed operation labels only owned objects, not shared parents.
                control._call('/usr/sbin/restorecon', '-F', str(transport.path.parent), str(transport.record.parent),
                              str(transport.record), str(transport.path), *(str(transport.path / name) for name in transport.state['nodes']),
                              str(relay_path.parent), str(relay_path), str(transport.profile_path), str(transport.profile_path / '10-timeout-abort.conf'),
                              timeout=self.limit_timeout(timeout), maximum=8192)
                verify_labels(transport, control, self.limit_timeout(timeout))
                admission_stage = 'cache-recheck'
                admission_reason = 'cache-snapshot'
                after = configuration_snapshot(paths, unit, owned_mask=True, end=command_end)
                root = str(transport.profile_path.parent)
                def normalized(rows):
                    return tuple((row[:5] + (None,)) if row[0] == root else row for row in rows
                                 if row[0] not in (str(transport.profile_path), str(transport.profile_path / '10-timeout-abort.conf')))
                admission_reason = 'cache-staging-comparison'
                if normalized(snapshot) != normalized(after):
                    raise Blocked('configuration changed during mask staging')
                admission_reason = 'cache-parent-lookup'
                before_root = next(row for row in snapshot if row[0] == root)
                after_root = next(row for row in after if row[0] == root)
                admission_reason = 'cache-before-mtime'
                if before_root[5] != transport.state['profile']['before_us']:
                    raise Blocked('lookup parent changed before mask staging')
                admission_reason = 'cache-after-mtime'
                if after_root[5] != transport.state['profile']['after_us']:
                    raise Blocked('lookup parent changed after mask staging')
                admission_reason = 'cache-state-query'
                observed = control._call('/usr/bin/systemctl', 'show', '--property=LoadState', '--property=ActiveState',
                                         transport.canonical, ok=(0, 1, 4), timeout=self.limit_timeout(timeout), maximum=4096)
                state = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
                admission_reason = 'cache-load-state'
                if state.get('LoadState') != 'not-found':
                    raise Blocked('native cache refresh is not pristine')
                admission_reason = 'cache-active-state'
                if state.get('ActiveState') != 'inactive':
                    raise Blocked('native cache refresh is not pristine')
                admission_reason = 'cache-manager-paths'
                if paths != lookup_paths(control, self.limit_timeout(timeout)):
                    raise Blocked('native cache refresh is not pristine')
                admission_reason = 'cache-final-snapshot'
                final = configuration_snapshot(paths, unit, owned_mask=True, end=command_end)
                admission_reason = 'cache-final-comparison'
                if after != final:
                    cache_comparison=configuration_mismatch(after,final,unit)
                    raise Blocked('configuration changed before native launch')
                admission_reason = 'cache-transport-verification'
                transport.verify()
                transport.open_streams()
                admission_reason = 'none'
                remaining = min(self.limit_timeout(timeout), command_end - time.monotonic())
                if remaining < .002:
                    raise Blocked('native startup budget exhausted')
                # Activation can block before exec while the manager opens a FIFO.
                # Reserve its independent finite timer inside the existing wall
                # budget, rather than relying on the later active-runtime timer.
                startup = min(5.0, remaining / 2)
                args = (*self.native_args(args[:boundary], remaining - startup), *args[boundary:])
                payload = next((index for index, value in enumerate(args[1:], 1) if not value.startswith('-')), len(args))
                family = 'root' if transport.canonical.startswith('dev-pair-initialize-') else ('maintenance' if transport.canonical.startswith('dev-pair-gptbox-') else 'observation')
                fixed = {'TimeoutStopSec': {'root': '5', 'maintenance': '10', 'observation': '1'}[family],
                         'KillMode': 'control-group', 'MemoryMax': '2G', 'TasksMax': '512', 'CPUQuota': '100%'}
                prefix = []
                for value in args[:payload]:
                    if value in ('--pipe', '--pty'):
                        continue
                    if value.startswith('--property='):
                        key, actual = value.removeprefix('--property=').split('=', 1)
                        if key in fixed:
                            if actual != fixed[key]:
                                raise Blocked('native fixed resource profile mismatch')
                            continue
                        if key != 'RuntimeMaxSec':
                            raise Blocked('unknown native property rejected')
                    if not ((tailscale_launcher or maintenance_launcher is not None and self._adapter_image_binding is not None) and value=='--quiet'):prefix.append(value)
                if not any(value == '--service-type=exec' for value in prefix):
                    if any(value.startswith('--service-type=') for value in prefix):
                        raise Blocked('native service type mismatch')
                    prefix.append('--service-type=exec')
                runtime = next(value.rsplit('=', 1)[1].removesuffix('s') for value in prefix if value.startswith('--property=RuntimeMaxSec='))
                start_us = int(startup * 1000) * 1000
                runtime_us = round(float(runtime) * 1000000)
                helper_end = command_end - min(.1, remaining / 2)
                admission_stage = 'effective-profile'
                failure_point='transport-verification'
                transport.verify()
                nodes = transport.state['nodes']
                node_args = tuple(value for name in ('stdout', 'stderr', 'stdin') if name in nodes
                                  for value in ('--'+name+'-node', str(nodes[name]['device'])+':'+str(nodes[name]['inode'])))
                args = (prefix[0], *transport.properties(), '--property=LimitCORE=0',
                        '--property=TimeoutStartSec=%.3fs' % (start_us / 1000000),
                        '--property=TimeoutStartFailureMode=kill', '--property=TimeoutStopFailureMode=kill',
                        '--property=SendSIGKILL=yes', '--property=FinalKillSignal=SIGKILL', '--property=Restart=no', '--property=Slice=system.slice',
                        *('--property=' + key + '=' + value for key, value in fixed.items()), *prefix[1:],
                        '/usr/bin/python3', '-I', str(relay_path), '--uid', str(relay_uid), '--stdin', str(int(stdin_data is not None)),
                        '--unit', transport.canonical, '--key', unit, '--profile', family, '--start-us', str(start_us), '--runtime-us', str(runtime_us),
                        *node_args, '--maximum', str(maximum), '--deadline', str(helper_end), '--helper', relay_sha, '--', *args[payload:])
                for _ in range(2):
                    launcher_pairs.append(pipe_pair())
                if launcher_selected:
                    observed=time.monotonic();phase_end=self.execution_deadline()
                    launch_timing={'availability':'observed','start_us':start_us,'runtime_us':runtime_us,
                        'command_remaining_us':max(0,int((command_end-observed)*1000000)),
                        'phase_remaining_us':None if phase_end is None else max(0,int((phase_end-observed)*1000000)),
                        'helper_margin_us':max(0,int((command_end-helper_end)*1000000))}
                failure_point='launcher-start'
                process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=launcher_pairs[0][1],
                                           stderr=launcher_pairs[1][1], start_new_session=True, close_fds=True)
                process.stdout = os.fdopen(launcher_pairs[0][0], 'rb', buffering=0)
                process.stderr = os.fdopen(launcher_pairs[1][0], 'rb', buffering=0)
                for reader, writer in launcher_pairs:
                    os.close(writer)
                launcher_pairs.clear()
                selector.register(process.stdout, selectors.EVENT_READ, 'launcher_stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'launcher_stderr')
                for name, fd in transport.readers.items():
                    selector.register(fd, selectors.EVENT_READ, name)
            else:
                process = subprocess.Popen(args, env=env, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
                stdin_offset = 0
                if input_text is not None:
                    if stdin_data:
                        os.set_blocking(process.stdin.fileno(), False)
                        selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
                    else:
                        process.stdin.close()
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            status = 'running'
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= command_end:
                    failure_category='deadline'
                    raise Blocked('command deadline exceeded; output withheld')
                if transport is not None and process.poll() is not None:
                    transport.release()
                for key, _ in selector.select(timeout=.1):
                    if key.data == 'stdin':
                        try:
                            stdin_offset += os.write(key.fileobj.fileno(), stdin_data[stdin_offset:stdin_offset + 4096])
                        except BlockingIOError:
                            continue
                        if stdin_offset == len(stdin_data):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                        continue
                    descriptor = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
                    failure_point='pipe-read'
                    block = os.read(descriptor, 8192 if decoder is not None and key.data == 'stderr' else min(8192, maximum - total + 1))
                    if not block:
                        if key.data in ('stdout','stderr'):payload_eof.add(key.data)
                        if launcher_selected and key.data.startswith('launcher_'):launcher_eof.add(key.data)
                        selector.unregister(key.fileobj)
                        continue
                    if decoder is not None and key.data=='stderr':failure_point='relay-feed'
                    chunks = decoder.feed(block) if decoder is not None and key.data == 'stderr' else (block,)
                    for chunk in chunks:
                        total += len(chunk)
                        if total > maximum:
                            failure_category='output-limit'
                            raise Blocked('command output byte budget exceeded; output withheld')
                        if input_text is None:
                            if launcher_selected and key.data.startswith('launcher_'):
                                launcher_bytes+=len(chunk)
                                launcher_capture.extend(chunk[:max(0,8192-len(launcher_capture))])
                            else:
                                name = 'stderr' if key.data.startswith('launcher_') else key.data
                                buffers[name].extend(chunk)
            failure_point='launcher-wait'
            status = process.wait(timeout=1)
            if time.monotonic() >= command_end:
                failure_category='deadline'
                raise Blocked('command deadline exceeded; output withheld')
            self.limit_timeout(timeout)
            if decoder is not None:
                failure_point='relay-finish'
                decoder.finish(status, relay_uid, relay_sha)
                relay_verified = True
            capture_complete = True
            if sudo_probe is not None:
                special_result = sudo_denial_projection(sudo_probe['role'], bytes(buffers['stdout']), bytes(buffers['stderr']),
                    complete=capture_complete, status=decoder.control['status'] if decoder is not None else status,
                    native_status=status if native_execution else None, relay_verified=relay_verified,
                    execution_kind='native' if native_execution else 'direct',
                    host_verified=sudo_probe['host_verified'], package=sudo_probe['package'])
                if special_result['outcome'] != 'denied':
                    raise Blocked('sudo denial predicate rejected; policy output withheld')
            elif sudo_package:
                special_result = sudo_package_projection(bytes(buffers['stdout']), bytes(buffers['stderr']),
                                                          capture_complete and (relay_verified or not native_execution), status)
                if not special_result['supported']:
                    raise Blocked('unsupported or unavailable guest sudo package provenance')
            failure_point='payload-status'
            if (decoder is not None and status == relay.ERROR_STATUS) or status not in ok:
                failure_category='status-rejected'
                raise Blocked('%s failed (exit %s; output withheld)' % (Path(original[0]).name, status))
            result = special_result if sudo_probe is not None or sudo_package else bytes(buffers['stdout']).decode() if input_text is None else ''
            completed = True
            return result
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            primary_pending=True
            capture_failure(error)
            known = {'Lookup directory timestamp did not advance': 'lookup-mtime-not-advanced', 'Unknown manager UnitPath': 'manager-paths-rejected',
                     'Unknown applicable drop-in': 'unknown-drop-in', 'Applicable dependency effects are forbidden': 'dependency-effects',
                     'Existing native fragment or alias': 'fragment-or-alias', 'Native manager stream context mismatch': 'label-mismatch',
                     'Runtime configuration parent unavailable': 'runtime-path-unavailable',
                     'Concurrent configuration mutation': 'directory-mutation',
                     'Configuration admission deadline exceeded': 'scan-deadline',
                     'Applicable configuration inventory bound exceeded': 'inventory-bound',
                     'Transport verification deadline exceeded': 'transport-deadline'}
            text = error.args[0] if error.args and type(error.args[0]) is str else ''
            if isinstance(error, OSError):
                category = {2: 'runtime-path-unavailable', 13: 'permission-denied', 17: 'owned-name-collision'}.get(error.errno, 'io-unavailable')
            else:
                category = known.get(text, 'rejected')
            if admission_stage == 'cache-recheck' and admission_reason.startswith('cache-'):
                # Both terms are fixed operation/categories, never error values.
                admission_reason += '-' + category
            else:
                admission_reason = known.get(text, 'admission-rejected') if not isinstance(error, OSError) else category
            status = 'failed-or-timed-out'
            raise Blocked('command failed or timed out; output withheld') from None
        except BaseException as error:
            primary_pending=True
            capture_failure(error)
            if admission_stage != 'cache-recheck' or not admission_reason.startswith('cache-'):
                admission_reason = 'blocked-or-interrupted'
            if status == 'running' or (not completed and status in ok):
                status = 'interrupted-or-failed'
            raise
        finally:
            callback_failed=False
            def notify(callback,*values):
                nonlocal callback_failed
                try:callback(*values)
                except Exception:
                    callback_failed=True  # No raw callback exception enters public diagnostics.
            cleanup_error = None
            if transport is not None:
                try:
                    transport.close()
                except OSError as exc:
                    cleanup_error, status, completed = exc, 'cleanup-unresolved', False
            for reader, writer in launcher_pairs:
                for fd in (reader, writer):
                    with contextlib.suppress(OSError):
                        os.close(fd)
            if process is not None and not completed:
                try:
                    self.interrupt(process, args, env)
                except (Blocked, OSError, subprocess.SubprocessError) as exc:
                    cleanup_error = exc
                    status = 'cleanup-unresolved'
            if transport is not None and transport.created_intent and cleanup_error is None:
                try:
                    if completed or process is None:
                        self.reconcile_native(args, env)
                    NativeTransport.recover(transport.unit)
                except (ValueError, Blocked, OSError, subprocess.SubprocessError) as exc:
                    cleanup_error = exc
                    status = 'cleanup-unresolved'
                    completed = False
            selector.close()
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                process.stdout.close()
                process.stderr.close()
            payload=None;sealed_payload=None
            if signed_load_selected:
                try:
                    verified=(relay_verified and decoder is not None and decoder.control is not None and
                              decoder.control['uid']==int(self._adapter_image_binding[1]))
                    payload=signed_load_payload(buffers,maintenance_launcher,self._adapter_image_binding[1],
                        launched=process is not None,verified=verified,
                        status=decoder.control['status'] if verified else None,
                        complete=bool(verified and capture_complete and cleanup_error is None and payload_eof=={'stdout','stderr'}))
                except Exception:
                    payload={'availability':'unavailable'};callback_failed=True
                # Optional sealed CI diagnostic cannot replace payload/cleanup failure.
                if payload is not None and not completed:
                    try:
                        sealed_payload=selected_payload.seal(buffers,payload,getattr(self,'_selected_payload_identity',None),
                            min(command_end,self.execution_deadline() or command_end))
                    except BaseException:
                        # A secondary diagnostic cannot replace an existing primary.
                        # Without that original primary, cancellation must propagate.
                        if not primary_pending:raise
                        sealed_payload={'schema':1,'availability':'unavailable','reason':
                            'encryption-cleanup-unresolved' if selected_payload._PENDING is not None else 'encryption-unavailable'}
            if probe and self.diagnostic:
                actual = process.returncode if process is not None else None
                notify(self.diagnostic,buffers,actual if actual is not None and actual not in ok else status)
            if (not probe and self.diagnostic) or self.metadata_diagnostic:
                record = {'operation': public or 'withheld', 'operation_id': self.operation_id(original),
                          'step': self.current_step, 'outcome': 'accepted' if completed else 'rejected',
                          'accepted_exit': completed, 'allowed_exit_statuses': list(ok), 'status': status,
                          'elapsed_seconds': round(time.monotonic() - started, 3), 'sensitive_stdin': input_text is not None,
                          'launcher_handle_observed':process is not None}
                if failure_witness is not None:record['native_failure']=failure_witness
                if payload is not None:record['signed_load_payload']=payload
                if sealed_payload is not None:record['sealed_signed_load']=sealed_payload
                if sudo_probe is not None:
                    record['sudo_denial'] = sudo_denial_projection(sudo_probe['role'], bytes(buffers['stdout']), bytes(buffers['stderr']),
                        complete=capture_complete and cleanup_error is None,
                        status=(decoder.control['status'] if decoder is not None and decoder.control is not None else
                                process.returncode if not native_execution and process is not None else None),
                        native_status=process.returncode if native_execution and process is not None else None,
                        execution_kind='native' if native_execution else 'direct',
                        relay_verified=relay_verified, host_verified=sudo_probe['host_verified'], package=sudo_probe['package'])
                if sudo_package:
                    record['sudo_package'] = sudo_package_projection(bytes(buffers['stdout']), bytes(buffers['stderr']),
                        capture_complete and (relay_verified or not native_execution) and cleanup_error is None,
                        process.returncode if process is not None else None)
                if unit is not None:
                    record['admission_stage'] = admission_stage
                    record['admission_outcome'] = 'accepted' if completed else 'blocked'
                    record['admission_reason'] = 'none' if completed else admission_reason
                if decoder is not None:
                    if decoder.failure is not None:
                        record['relay_failure'] = dict(decoder.failure)
                    record['relay_verified'] = relay_verified
                    record['native_exit_status'] = process.returncode if process is not None else None
                    if decoder.control is not None:
                        record['relay'] = dict(decoder.control)
                if not completed or type(status) is int and status != 0:
                    record['native'] = self.native_diagnostic(args)
                if self.metadata_diagnostic:
                    notify(self.metadata_diagnostic,dict(record))
                if public:
                    record.update(output_bytes=total, capture_limit_bytes=maximum,
                                  **{name + '_tail': bytes(data[-8192:]).decode(errors='replace') for name, data in buffers.items()},
                                  **{name + '_truncated': len(data) > 8192 for name, data in buffers.items()})
                if self.diagnostic and not probe:
                    notify(self.diagnostic,record)
            if cleanup_error is not None:
                raise Blocked('native cleanup unresolved; retained ownership record and finite lifetime') from None
            if callback_failed and not primary_pending:
                raise Blocked('required command diagnostics unavailable; output withheld') from None

def checked_file(path, *, secret=False):
    p = Path(path)
    if not p.is_absolute():
        raise Blocked('input file must be absolute')
    for parent in [p, *p.parents]:
        s = parent.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise Blocked('input path must be root-owned, without symlinks or group/world writes')
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_size > 16384:
        raise Blocked('input must be a small regular file')
    if secret and s.st_mode & 0o077:
        raise Blocked('secret file must have mode 0600 or stricter')
    return p

def validate_public_keys(payload):
    """Admit the complete GitHub response or nothing; no authorized_keys options."""
    try:
        if not payload or len(payload) > KEYS_MAX_BYTES:
            raise ValueError()
        text = payload.decode('ascii')
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines or len(lines) > 256:
            raise ValueError()
        admitted = []
        deadline = time.monotonic() + 20
        for line in lines:
            if time.monotonic() >= deadline:
                raise ValueError()
            if len(line) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in line):
                raise ValueError()
            fields = line.split()
            kind = fields[0]
            if (len(fields) < 2 or kind not in ('ssh-ed25519', 'ssh-rsa',
                    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                    'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com')):
                raise ValueError()
            blob = base64.b64decode(fields[1], validate=True)
            length = int.from_bytes(blob[:4], 'big')
            if length != len(kind) or blob[4:4 + length] != kind.encode():
                raise ValueError()
            # ssh-keygen checks the full public-key structure, beyond the type header.
            with tempfile.NamedTemporaryFile(mode='w') as key:
                key.write(line + '\n')
                key.flush()
                Commands()('/usr/bin/ssh-keygen', '-l', '-f', key.name, timeout=5)
            normalized = kind + ' ' + fields[1]
            if normalized not in admitted:
                admitted.append(normalized)
        return '\n'.join(admitted) + '\n'
    except (ValueError, UnicodeError, IndexError, Blocked):
        raise Blocked('GitHub keys response failed validation; existing keys preserved') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_github_response():
    """One bounded-body request, executed only inside the disposable fetch child."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        request = urllib.request.Request(KEYS_URL, headers={'User-Agent': 'dev-pair-bootstrap'})
        deadline = time.monotonic() + 20
        with opener.open(request, timeout=5) as response:
            if response.status != 200 or response.geturl() != KEYS_URL:
                raise ValueError()
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                chunk = response.read1(min(16384, KEYS_MAX_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > KEYS_MAX_BYTES:
                    raise ValueError()
        return b''.join(chunks)
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError):
        raise Blocked('GitHub HTTPS request failed; output withheld') from None


def github_keys():
    # A disposable process gives DNS/TLS/header/body work a wall-clock deadline.
    # Socket timeouts alone do not bound libc DNS resolution. No inherited auth,
    # Python startup hooks or proxy environment reaches the reviewed child.
    command = [sys.executable, '-I', str(Path(__file__).resolve()), '_fetch-github-keys']
    env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
    for attempt in range(KEYS_FETCH_ATTEMPTS):
        try:
            result = subprocess.run(command, env=env, capture_output=True, timeout=KEYS_FETCH_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode == 0:
            return validate_public_keys(result.stdout)
    raise Blocked('bounded GitHub HTTPS fetch failed; existing keys preserved')


def operator_password(path):
    password = checked_file(path, secret=True).read_bytes().decode('utf-8')
    # Exactly one line. Never accept chpasswd separators/control bytes or empty passwords.
    password = password.removesuffix('\n')
    if (not password or len(password) > 1024 or ':' in password
            or any(ord(c) < 32 or ord(c) == 127 for c in password)):
        raise Blocked('operator password file must contain one nonempty line without control characters or colon')
    return password


def validate_sources(sources):
    try:
        networks = sorted({str(ipaddress.ip_network(x, strict=True)) for x in sources})
    except ValueError:
        raise Blocked('bootstrap sources must be explicit canonical CIDRs') from None
    if not networks or any(ipaddress.ip_network(x).prefixlen == 0 for x in networks):
        raise Blocked('unrestricted bootstrap sources are not allowed')
    return networks

class Bootstrap:
    # Alternate roots/runners are internal unit-test boundaries, absent from CLI.
    def __init__(self, root=Path('/'), run=None):
        self.root, self.run = Path(root), run or Commands()
        self.state = self.path(STATE)
        self.hostname_verified = False
        self.role_directory_batches = {}

    def path(self, value):
        return self.root / value.lstrip('/')

    def text(self, value, default=''):
        p = self.path(value)
        return p.read_text() if p.exists() else default

    def atomic(self, path, content, mode=0o600, expected=None):
        p = self.path(path)
        for parent in [p, *p.parents]:
            if parent.exists() or parent.is_symlink():
                if parent.is_symlink():
                    raise Blocked('refusing symlink in managed path')
                info = parent.stat()
                if info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                    raise Blocked('managed configuration path must be root-owned and protected')
            if parent == self.root:
                break
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if p.exists():
            if p.read_text() == content:
                if stat.S_IMODE(p.stat().st_mode) != mode:
                    raise Blocked('managed file permissions conflict')
                return
            if expected is None or p.read_text() != expected:
                raise Blocked(f'conflicting managed file: {path}')
        fd, name = tempfile.mkstemp(prefix='.bootstrap-', dir=p.parent)
        try:
            with os.fdopen(fd, 'w') as f:
                os.fchmod(f.fileno(), mode)
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, p)
            d = os.open(p.parent, os.O_DIRECTORY)
            try:
                os.fsync(d)
            finally:
                os.close(d)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def preflight(self):
        if os.geteuid() != 0:
            raise Blocked('root is required')
        release = dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']*)', self.text('/etc/os-release'), re.M))
        if release.get('ID') != 'fedora' or release.get('VERSION_ID') != '44':
            raise Blocked('only Fedora 44 is supported; no changes made')
        if platform.machine() not in ('x86_64', 'aarch64'):
            raise Blocked('only x86_64/aarch64 supported')
        if self.text('/proc/1/comm').strip() != 'systemd':
            raise Blocked('host PID 1 must be systemd')
        if self.run('/usr/sbin/getenforce').strip() != 'Enforcing':
            raise Blocked('SELinux must be enforcing; run selinux_bootstrap.py initial convergence first')
        transition = self.path('/var/lib/dev-pair/selinux-bootstrap')
        if (transition / 'intent.json').exists():
            try:
                complete = json.loads((transition / 'complete.json').read_text())
                modes = re.findall(r'^\s*SELINUX\s*=\s*["\']?([^#\s"\']+)',
                                   self.text('/etc/selinux/config'), re.M)
                if not isinstance(complete, dict) or complete.get('phase') != 'enforcing' or modes != ['enforcing']:
                    raise ValueError()
            except (OSError, ValueError):
                raise Blocked('checked initial SELinux transition is incomplete; workloads remain blocked') from None
        repos = self.path('/etc/yum.repos.d')
        if repos.exists():
            for repo in repos.glob('*.repo'):
                if repo.name != 'dev-pair-tailscale.repo' and re.search(r'^\s*\[tailscale-stable\]\s*$', repo.read_text(), re.M):
                    raise Blocked('existing tailscale-stable repository conflicts with managed repo')
        self.run('/usr/sbin/sshd', '-t')
        settings = self.run('/usr/sbin/sshd', '-T')
        if re.findall(r'^port (\d+)$', settings, re.M) != ['22']:
            raise Blocked('bootstrap supports existing SSH port 22 only')
        for service in ('firewalld.service', 'nftables.service'):
            if self.run('/usr/bin/systemctl', 'is-active', service, ok=(0, 3, 4)).strip() == 'active':
                raise Blocked('competing firewall manager is active; inspect without disabling it')
        if self.path('/usr/sbin/nft').exists():
            tables = self.run('/usr/sbin/nft', 'list', 'tables').splitlines()
            if any(line.strip() != 'table inet dev_pair_bootstrap' for line in tables):
                raise Blocked('existing nftables rules conflict with vanilla bootstrap')
        # The identity batch is private to this already captured inventory.
        # It cannot survive a preflight call, retry, mutation or resolved restart.
        inventory = self.run('/usr/bin/ss', '-H', '-lntup').splitlines()
        discovery = [line for line in inventory if len(line.split())>=5 and line.split()[0] in ('tcp','udp')
            and line.split()[4].rpartition(':')[2]=='5355' and self.resolved_owner(line) is not None]
        batch = None
        if len(discovery)>=3 and not self.path(f'{STATE}/prepared').exists():
            try:
                batch = self.resolved_service(snapshot=True)
                if batch is None:raise ValueError()
            except (Blocked,OSError,ValueError):
                raise Blocked('unexpected listener: resolved identity unavailable') from None
        # Reject application listeners before creating users, installing packages or changing rules.
        for line in inventory:
            columns = line.split()
            if len(columns) < 5:
                raise Blocked('cannot parse listener inventory')
            proto, address = columns[0], columns[4]
            host, _, port = address.rpartition(':')
            try:
                local = ipaddress.ip_address(host.strip('[]').split('%')[0]).is_loopback
            except ValueError:
                local = False
            allowed = (proto == 'tcp' and port == '22') or (local and proto in ('tcp', 'udp') and port == '53') or (
                proto == 'udp' and (port in ('68', '546', '41641') or (local and port in ('53', '123', '323'))))
            if (not allowed and proto in ('tcp', 'udp') and port == '5355'
                    and not self.path(f'{STATE}/prepared').exists()):
                allowed = self.resolved_listener(line, batch)
            if not allowed and proto == 'tcp':
                allowed = self.peerapi_listener(line, host.strip('[]'))
            if not allowed and proto == 'udp' and port.isdigit() and 60000 <= int(port) <= 61000:
                allowed = self.mosh_listener(line)
            if not allowed:
                raise Blocked('unexpected listener: host is not vanilla; inspect inventory before proceeding')
        if batch is not None:
            try:
                if self.resolved_service(snapshot=True)!=batch:raise ValueError()
            except (Blocked,OSError,ValueError):
                raise Blocked('unexpected listener: resolved identity changed') from None
        return {'os': 'Fedora 44', 'arch': platform.machine(), 'selinux': 'Enforcing',
                'phase': 'temporary-bootstrap', 'ssh_cutover': 'not implemented'}

    def resolved_process_start(self,pid):
        # Bounded Linux proc stat: comm may contain spaces and parentheses.
        with self.path('/proc/'+pid+'/stat').open('rb') as stream:raw=stream.read(4097)
        if len(raw)>4096:raise Blocked('resolved process identity unavailable')
        try:
            text=raw.decode('ascii');end=text.rindex(') ')
            if not text.startswith(pid+' ('):raise ValueError()
            fields=text[end+2:].split();start=fields[19]
            if len(fields)<20 or not re.fullmatch(r'[1-9][0-9]{0,19}',start):raise ValueError()
            return int(start)
        except (ValueError,IndexError,UnicodeError):
            raise Blocked('resolved process identity unavailable') from None

    def resolved_service(self, *, snapshot=False):
        observed = self.run('/usr/bin/systemctl', 'show', '--property=MainPID', '--property=User',
                            '--property=ActiveState', '--property=LoadState', 'systemd-resolved.service', ok=(0, 1, 4))
        fields = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
        if snapshot and (len(observed.splitlines())!=4 or set(fields)!={'MainPID','User','ActiveState','LoadState'}):
            raise Blocked('resolved service identity incomplete')
        if fields.get('LoadState') == 'not-found' and fields.get('ActiveState') == 'inactive':
            return None
        if fields.get('LoadState') != 'loaded' or fields.get('ActiveState') != 'active' or fields.get('User') != 'systemd-resolve':
            raise Blocked('systemd-resolved service identity/state is not the supported Fedora baseline')
        pid = fields.get('MainPID', '')
        if not pid.isdigit() or int(pid) <= 1:
            raise Blocked('systemd-resolved has no valid main process')
        process_start=self.resolved_process_start(pid) if snapshot else None
        executable = '/usr/lib/systemd/systemd-resolved'
        if str(self.path('/proc/' + pid + '/exe').readlink()) != executable:
            raise Blocked('systemd-resolved executable mismatch')
        binary = self.path(executable)
        ancestry=[]
        for item in [binary, *binary.parents]:
            info = item.lstat()
            if snapshot:ancestry.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns))
            if item.is_symlink() or info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                raise Blocked('systemd-resolved executable path is not protected')
            if item == self.root:
                break
        if not stat.S_ISREG(binary.stat().st_mode):
            raise Blocked('systemd-resolved executable is not regular')
        account = self.run('/usr/bin/getent', 'passwd', 'systemd-resolve').strip().split(':')
        uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$', self.text('/proc/' + pid + '/status'), re.M)
        if (len(account) != 7 or account[0] != 'systemd-resolve' or not account[2].isdigit()
                or account[2] == '0' or not uid or any(value != account[2] for value in uid.groups())
                or self.text('/proc/' + pid + '/cgroup').strip() != '0::/system.slice/systemd-resolved.service'):
            raise Blocked('systemd-resolved process owner/cgroup mismatch')
        if snapshot:
            if self.resolved_process_start(pid)!=process_start:
                raise Blocked('resolved process identity changed')
            return {'pid':pid,'start':process_start,'uid':account[2],'ancestry':tuple(ancestry),
                'cgroup':'0::/system.slice/systemd-resolved.service','executable':executable}
        return pid

    @staticmethod
    def resolved_owner(line):
        owners=re.findall(r'\("([^"\n]+)",pid=(\d+),fd=\d+\)',line)
        return owners[0][1] if len(owners)==1 and owners[0][0]=='systemd-resolve' else None

    def resolved_listener(self, line, identity=None):
        # The observed Fedora discovery listener is temporary provisioning input,
        # never a general port allowance or post-prepare service policy.
        owner=self.resolved_owner(line)
        try:
            return owner is not None and owner == (identity['pid'] if identity is not None else self.resolved_service())
        except (Blocked, OSError, ValueError):
            return False

    @staticmethod
    def listener_endpoints(inventory):
        result = set()
        for line in inventory.splitlines():
            columns = line.split()
            if len(columns) < 5:
                raise Blocked('cannot parse listener inventory')
            result.add((columns[0], columns[4]))
        return result

    def resolved_ancestry(self):
        # Validate every existing public ancestor before directory() can create
        # or chmod its leaf. directory() alone checks only its final component.
        wanted = 0 if self.root == Path('/') else os.getuid()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in (None, 'etc', 'systemd'):
                if part is not None:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                info = os.fstat(fd)
                if info.st_uid != wanted or info.st_mode & 0o022 or (part is not None and not info.st_mode & 0o001):
                    raise Blocked('unprotected resolved configuration ancestry')
        finally:
            os.close(fd)

    def resolved_file_state(self, directory, target):
        wanted = 0 if self.root == Path('/') else os.getuid()
        info = self.path(directory).lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != wanted or stat.S_IMODE(info.st_mode) != 0o755:
            raise Blocked('resolved directory protection changed')
        fd = os.open(self.path(target), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            item = os.fstat(fd)
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != wanted or item.st_nlink != 1
                    or stat.S_IMODE(item.st_mode) != 0o644 or item.st_size > 64
                    or os.read(fd, 65) != b'[Resolve]\nLLMNR=no\nMulticastDNS=no\n'):
                raise Blocked('resolved managed file protection/content changed')
        finally:
            os.close(fd)
        return {'directory_mode': stat.S_IMODE(info.st_mode), 'file_mode': stat.S_IMODE(item.st_mode),
                'owner_and_type_verified': True,
                'identity': [(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size)
                             for value in (info,item)]}

    def configure_resolved(self):
        witness = {'version': 1, 'bootstrap_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'directory_mode': None, 'file_mode': None, 'owner_and_type_verified': False,
                   'stock_labels_match': False, 'runtime_discovery_disabled': False,
                   'status': 'blocked', 'reason': 'resolved-identity-rejected'}
        desired = json.loads(self.text(STATE + '/desired.json', '{}'))
        target = json.loads(self.text(STATE + '/initialize.json', '{}')).get('target', {})
        witness['context_sha256'] = desired.get('gptbox_context_sha256')
        witness['source_sha'] = target.get('source_sha')
        self.resolved_witness = witness
        def save_witness():
            if self.state.is_dir():
                path = STATE + '/resolved-discovery.json'
                self.atomic(path, json.dumps(witness, sort_keys=True) + '\n', expected=self.text(path) or None)
        reason = 'resolved-identity-rejected'
        try:
            before = self.listener_endpoints(self.run('/usr/bin/ss', '-H', '-lntup'))
            pid = self.resolved_service()
            reason = 'config-owner-or-type'
            self.resolved_ancestry()
            directory = '/etc/systemd/resolved.conf.d'
            target = directory + '/90-dev-pair-discovery.conf'
            reason = 'config-directory-mode'
            if self.path(directory).exists() or self.path(directory).is_symlink():
                info = self.path(directory).lstat()
                witness['directory_mode'] = stat.S_IMODE(info.st_mode)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != (0 if self.root == Path('/') else os.getuid()):
                    reason = 'config-owner-or-type'
                    raise Blocked('resolved configuration directory ownership/type conflict')
            self.directory(directory, mode=0o755)
            reason = 'config-file-conflict'
            if self.path(target).exists() or self.path(target).is_symlink():
                info = self.path(target).lstat()
                witness['file_mode'] = stat.S_IMODE(info.st_mode)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_nlink != 1:
                    reason = 'config-owner-or-type'
                    raise Blocked('resolved configuration file ownership/type conflict')
                if stat.S_IMODE(info.st_mode) != 0o644:
                    reason = 'config-file-mode'
                    raise Blocked('resolved configuration file mode conflict')
            self.atomic(target, '[Resolve]\nLLMNR=no\nMulticastDNS=no\n', mode=0o644)
            initial = self.resolved_file_state(directory, target)
            witness.update({key:initial[key] for key in ('directory_mode','file_mode','owner_and_type_verified')})
            reason = 'config-label-mismatch'
            self.run('/usr/sbin/restorecon', '-F', str(self.path(directory)), str(self.path(target)))
            expected = self.run('/usr/sbin/matchpathcon', '-n', directory, target).splitlines()
            actual = self.run('/usr/bin/stat', '--format=%C', str(self.path(directory)), str(self.path(target))).splitlines()
            if len(expected) != 2 or actual != expected or any(len(value)>200 or not re.fullmatch(r'[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:s[0-9]+(?::[A-Za-z0-9.,-]+)?', value) for value in expected):
                raise Blocked('resolved configuration stock label mismatch')
            witness['stock_labels_match'] = True
            self.resolved_ancestry()
            final = self.resolved_file_state(directory, target)
            if initial != final:
                raise Blocked('resolved configuration identity changed during labeling')
            reason = 'merged-config-conflict'
            merged = self.run('/usr/bin/systemd-analyze', 'cat-config', 'systemd/resolved.conf')
            section, values = '', {}
            for raw in merged.splitlines():
                line = raw.strip()
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1]
                elif section == 'Resolve' and '=' in line and not line.startswith(('#', ';')):
                    key, value = line.split('=', 1)
                    values[key.strip()] = value.strip()
            if any(values.get(key) != 'no' for key in ('LLMNR', 'MulticastDNS')):
                raise Blocked('effective resolved discovery configuration conflicts')
            witness['reason'] = 'resolved-identity-rejected'
            save_witness()  # Public staged-state evidence survives a later restart interruption.
            if pid is not None:
                reason = 'resolved-identity-rejected'
                self.run('/usr/bin/systemctl', 'restart', 'systemd-resolved.service')
                self.resolved_service()
                reason = 'runtime-properties-unavailable'
                raw = self.run('/usr/bin/busctl', '--system', '--json=short', '--no-pager', 'get-property',
                               'org.freedesktop.resolve1', '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager',
                               'LLMNR', 'MulticastDNS', timeout=5)
                reason = 'runtime-properties-malformed'
                if len(raw.encode()) > 512:
                    raise Blocked('resolved runtime property bound exceeded')
                try:
                    values = relay.property_records(raw.encode(), (('LLMNR','s'),('MulticastDNS','s')))
                except (ValueError, TypeError):
                    raise Blocked('resolved runtime property contract mismatch') from None
                reason = 'runtime-discovery-enabled'
                if values != {'LLMNR':'no','MulticastDNS':'no'}:
                    raise Blocked('resolved runtime discovery remains enabled')
                witness['runtime_discovery_disabled'] = True
            reason = 'discovery-listener-remains'
            after = self.listener_endpoints(self.run('/usr/bin/ss', '-H', '-lntup'))
            if any(address.rpartition(':')[2] in ('5353', '5355') for proto, address in after if proto in ('tcp', 'udp')):
                raise Blocked('discovery listener remains after persistent resolved configuration')
            def retained(endpoint):
                proto, address = endpoint
                host, _, port = address.rpartition(':')
                if proto == 'tcp' and port == '22':
                    return True
                try:
                    return port == '53' and ipaddress.ip_address(host.strip('[]').split('%')[0]).is_loopback
                except ValueError:
                    return False
            reason = 'retained-listener-missing'
            if not {value for value in before if retained(value)}.issubset(after):
                raise Blocked('SSH or loopback DNS listener disappeared after resolved configuration')
            witness.update(status='pass', reason='none')
        finally:
            if witness['status'] != 'pass': witness['reason'] = reason
            save_witness()

    def mosh_listener(self, line):
        match = re.search(r'users:\(\("mosh-server",pid=(\d+),', line)
        if not match or not self.path(f'{STATE}/identity-core.json').exists():
            return False
        pid = match.group(1)
        try:
            if str(self.path(f'/proc/{pid}/exe').readlink()) != '/usr/bin/mosh-server':
                return False
            wanted = self.run('/usr/bin/id', '-u', 'core').strip()
            uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$',
                            self.text(f'/proc/{pid}/status'), re.M)
            return bool(uid and wanted.isdigit() and int(wanted) >= 1000
                        and all(value == wanted for value in uid.groups()))
        except (OSError, Blocked):
            return False

    def peerapi_listener(self, line, host):
        # Permit only root's actual official tailscaled executable on this node's own IP.
        match = re.search(r'users:\(\("tailscaled",pid=(\d+),', line)
        if not match or not self.path('/usr/bin/tailscale').exists():
            return False
        pid = match.group(1)
        try:
            exe = self.path(f'/proc/{pid}/exe').readlink()
            if str(exe) != '/usr/sbin/tailscaled':
                return False
            uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$', self.text(f'/proc/{pid}/status'), re.M)
            if not uid or any(x != '0' for x in uid.groups()):
                return False
            live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json', ok=(0, 1)))
            return host in live.get('TailscaleIPs', []) and live.get('BackendState') == 'Running'
        except (OSError, ValueError, Blocked):
            return False

    @contextlib.contextmanager
    def lock(self, name='lock'):
        self.directory('/var/lib/dev-pair', mode=0o755)
        for parent in [self.state, *self.state.parents]:
            if parent.is_symlink():
                raise Blocked('symlink in bootstrap state path')
            if parent.exists():
                info = parent.stat()
                if info.st_uid != (0 if self.root == Path('/') else os.getuid()) or info.st_mode & 0o022:
                    raise Blocked('bootstrap state path must be root-owned and protected')
            if parent == self.root:
                break
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.state.is_symlink() or stat.S_IMODE(self.state.stat().st_mode) != 0o700:
            raise Blocked('bootstrap state directory must be private and not a symlink')
        fd = os.open(self.state / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocked('another bootstrap operation is running') from None
            yield
        finally:
            os.close(fd)

    def event(self, action, status):
        # Only fixed action names/status, never command output, credentials or argv.
        fd = os.open(self.state / 'journal.jsonl', os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps({'time': int(time.time()), 'action': action, 'status': status}) + '\n')
            f.flush()
            os.fsync(f.fileno())

    def mark_prepare_step(self, value):
        cost=getattr(self,'prepare_cost',None)
        if cost is not None:cost.mark(value)
        self.prepare_step = value
        if isinstance(self.run, Commands):
            self.run.current_step = value

    def step(self, action, callback):
        self.mark_prepare_step(action)
        self.event(action, 'begin')
        try:
            result = callback()
        except BaseException:
            self.event(action, 'interrupted-or-failed')
            raise
        self.event(action, 'complete')
        return result

    def directory(self, name, mode=0o700, owner=None):
        relative = Path(name)
        if not relative.is_absolute() or '..' in relative.parts:
            raise Blocked('invalid managed directory')
        uid = int(self.run('/usr/bin/id', '-u', owner).strip()) if owner else (0 if self.root == Path('/') else os.getuid())
        gid = int(self.run('/usr/bin/id', '-g', owner).strip()) if owner else os.getgid()
        return self._directory_as(name, mode, uid, gid, change_owner=bool(owner))

    def _directory_as(self, name, mode, uid, gid, *, change_owner, check_gid=False):
        # Private descriptor primitive, not a public arbitrary-owner interface.
        relative = Path(name)
        if not relative.is_absolute() or '..' in relative.parts:
            raise Blocked('invalid managed directory')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = relative.parts[1:]
            for index, part in enumerate(parts):
                leaf = index == len(parts) - 1
                created = False
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    os.mkdir(part, mode if leaf else 0o755, dir_fd=fd)
                    created = True
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                if leaf:
                    if created:
                        os.fchmod(fd, mode)
                        if change_owner:
                            os.fchown(fd, uid, gid)
                    info = os.fstat(fd)
                    if stat.S_IMODE(info.st_mode) != mode or info.st_uid != uid or check_gid and info.st_gid != gid:
                        raise Blocked(f'conflicting directory: {name}')
        except OSError:
            raise Blocked('unsafe or conflicting managed directory traversal') from None
        finally:
            os.close(fd)

    def _role_directories(self, verified):
        if type(verified) is not _RoleIdentity or verified.name not in ROLE_DIRECTORIES:
            raise Blocked('role directory batch requires verified fixed account')
        role = ROLE_DIRECTORIES[verified.name]
        evidence = {'role':role,'checked_lookups':0,'completed_directories':0,'outcome':'blocked'}
        try:
            uid = _canonical_role_id(self.run('/usr/bin/id','-u',verified.name))
            if type(verified.uid) is not int or uid != verified.uid:
                raise Blocked('managed role UID binding mismatch')
            evidence['checked_lookups'] = 1
            gid = _canonical_role_id(self.run('/usr/bin/id','-g',verified.name))
            if type(verified.gid) is not int or gid != verified.gid:
                raise Blocked('managed role GID binding mismatch')
            evidence['checked_lookups'] = 2
            base = '/var/lib/dev-pair/'+role
            for path in (base,*(base+'/'+name for name in ROLE_CHILDREN)):
                self._directory_as(path,0o700,uid,gid,change_owner=True,check_gid=True)
                evidence['completed_directories'] += 1
            evidence['outcome'] = 'complete'
        finally:
            # Counts only, never an owner pair reusable by a later call/retry.
            self.role_directory_batches[role] = dict(evidence)

    def identity(self, name, shell, substart=None):
        marker = f'{STATE}/identity-{name}.json'
        intent = json.dumps({'name': name, 'shell': shell, 'substart': substart}, sort_keys=True) + '\n'
        account = self.run('/usr/bin/getent', 'passwd', name, ok=(0, 2)).strip()
        if account and self.text(marker) != intent:
            raise Blocked('refusing to adopt an existing account')
        self.atomic(marker, intent)
        if not account:
            self.run('/usr/sbin/useradd', '--create-home', '--user-group', '--shell', shell,
                     '-K', 'SUB_UID_COUNT=0', '-K', 'SUB_GID_COUNT=0', name)
            account = self.run('/usr/bin/getent', 'passwd', name).strip()
        fields = account.split(':')
        if len(fields) != 7 or fields[5:] != [f'/home/{name}', shell] or int(fields[2]) < 1000:
            raise Blocked('account configuration conflicts')
        if name != 'core':
            self.run('/usr/sbin/usermod', '--lock', name)
        groups = self.run('/usr/bin/id', '-nG', name).split()
        if groups != [name]:
            raise Blocked('managed account must have only its private primary group')
        if substart is not None:
            for file in ('/etc/subuid', '/etc/subgid'):
                content = self.text(file)
                wanted = f'{name}:{substart}:65536'
                own = []
                for line in content.splitlines():
                    parts = line.split(':')
                    if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
                        raise Blocked('malformed subordinate ID configuration')
                    who, begin, count = parts[0], int(parts[1]), int(parts[2])
                    if who in (name, fields[2]):
                        own.append(line)
                    elif begin < substart + 65536 and substart < begin + count:
                        raise Blocked('subordinate ID range overlaps an existing account')
                if own and own != [wanted]:
                    raise Blocked('conflicting subordinate ID allocation')
                if not own:
                    self.atomic(file, content.rstrip('\n') + ('\n' if content else '') + wanted + '\n',
                                mode=0o644, expected=content)
            self.run('/usr/bin/loginctl', 'enable-linger', name)
        return {'name':fields[0],'uid':fields[2],'gid':fields[3]}

    def password_operator(self, password):
        marker = f'{STATE}/operator-password-set'
        if not self.path(marker).exists():
            # An interruption after chpasswd can safely reapply the same external input.
            self.run('/usr/sbin/chpasswd', input_text='core:' + password + '\n')
        observed = self.run('/usr/bin/passwd', '-S', 'core').split()
        # shadow-utils uses P; Fedora's historical passwd/libuser uses PS.
        # Both mean a set, unlocked password; L/LK/NP and absent output fail.
        if len(observed) < 2 or observed[0] != 'core' or observed[1] not in ('P', 'PS'):
            raise Blocked('core password is not usable; recovery required')
        self.atomic(marker, 'password configured; value remains external\n')

    def host_identity(self):
        # cloud-init must not restore a provider hostname on the next boot.
        self.atomic('/etc/cloud/cloud.cfg.d/99-dev-pair-hostname.cfg',
                    '#cloud-config\npreserve_hostname: true\n', mode=0o644)
        self.run('/usr/bin/hostnamectl', 'set-hostname', 'erebus')
        if self.run('/usr/bin/hostnamectl', '--static').strip() != 'erebus':
            raise Blocked('persistent hostname observation failed')
        self.hostname_verified = True
        self.run('/usr/bin/systemctl', 'enable', '--now', 'chronyd.service')
        self.run('/usr/bin/chronyc', 'tracking')
        self.reserve_mosh_ports()
        # Daemon observation is not proof of synchronized time; acceptance uses real host evidence.
        self.atomic('/etc/profile.d/90-dev-pair-core-tmux.sh', OPERATOR_PROFILE, mode=0o644)

    def restricted_identity(self, who, begin, package):
        if not self.hostname_verified or who not in SUDO_ROLES:
            raise Blocked('sudo denial requires verified host and fixed role')
        identity = self.identity(who, '/usr/sbin/nologin', begin)
        self.run('/usr/bin/sudo', '-l', '-U', who, timeout=10,
                 sudo_probe={'role': who, 'host_verified': self.hostname_verified, 'package': package})
        if type(identity) is not dict or identity.get('name') != who:
            raise Blocked('managed role account name binding mismatch')
        return _RoleIdentity(who,_canonical_role_id(identity['uid']+'\n'),_canonical_role_id(identity['gid']+'\n'))

    def reserve_mosh_ports(self):
        # The early public mosh drop also covers established UDP. Reserve its port
        # range so unrelated outbound clients do not receive replies in that range.
        ranges = []
        for entry in self.text('/proc/sys/net/ipv4/ip_local_reserved_ports').strip().split(','):
            if not entry:
                continue
            if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', entry):
                raise Blocked('invalid existing reserved port ranges')
            endpoints = [int(value) for value in entry.split('-')]
            low, high = endpoints[0], endpoints[-1]
            if not 1 <= low <= high <= 65535:
                raise Blocked('invalid existing reserved port ranges')
            ranges.append((low, high))
        ranges.append((60000, 61000))
        merged = []
        for low, high in sorted(ranges):
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        value = ','.join(str(low) if low == high else f'{low}-{high}' for low, high in merged)
        self.atomic('/etc/sysctl.d/90-dev-pair-mosh.conf',
                    'net.ipv4.ip_local_reserved_ports = ' + value + '\n', mode=0o644)
        self.run('/usr/sbin/sysctl', '-p', str(self.path('/etc/sysctl.d/90-dev-pair-mosh.conf')))

    def operator_keys(self, name, key):
        target = f'/etc/ssh/dev-pair-keys/{name}'
        marker = f'{STATE}/operator-keys.json'
        prior = self.text(marker)
        hashes = json.loads(prior) if prior else {}
        current = self.text(target)
        current_hash = hashlib.sha256(current.encode()).hexdigest() if current else None
        if current and current_hash not in (hashes.get('previous'), hashes.get('wanted')):
            raise Blocked('operator key file conflicts with protected import record')
        intent = json.dumps({'previous': current_hash, 'wanted': hashlib.sha256(key.encode()).hexdigest()}, sort_keys=True) + '\n'
        self.atomic(marker, intent, expected=prior or None)
        # Validation/fetch was completed before any of these files are touched. The intent
        # admits both sides of an interrupted rename, so retry can finish without key loss.
        self.atomic(target, key, mode=0o644, expected=current or None)

    def ssh_operator(self, name, key):
        self.directory('/etc/ssh/dev-pair-keys', mode=0o755)
        self.operator_keys(name, key)
        self.run('/usr/sbin/restorecon', '-RF', str(self.path('/etc/ssh/dev-pair-keys')))
        # This named human operator has explicit administration authority; runtime users do not.
        sudo = f'Defaults:{name} authenticate,!rootpw,!targetpw,!runaspw\n{name} ALL=(ALL) PASSWD: ALL\n'
        self.atomic('/etc/sudoers.d/dev-pair-operator', sudo, mode=0o440)
        self.run('/usr/sbin/visudo', '-cf', str(self.path('/etc/sudoers.d/dev-pair-operator')))
        self.run('/usr/sbin/visudo', '-c')
        effective_sudo = self.run('/usr/bin/sudo', '-l', '-U', name)
        if any(token in effective_sudo for token in ('NOPASSWD', '!authenticate')):
            raise Blocked('effective core sudo policy bypasses password authentication')
        ssh = (f'# dev-pair bootstrap: only the named operator; initial root route retained\n'
               'DenyUsers dp-maint dp-dev\n'
               f'Match User {name}\n    AuthorizedKeysFile /etc/ssh/dev-pair-keys/{name}\n'
               '    AuthenticationMethods publickey\n    PasswordAuthentication no\n'
               '    KbdInteractiveAuthentication no\n    PubkeyAuthentication yes\nMatch all\n')
        target = '/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'
        created = not self.path(target).exists()
        self.atomic(target, ssh, mode=0o600)
        try:
            self.run('/usr/sbin/sshd', '-t')
            effective = self.run('/usr/sbin/sshd', '-T', '-C', f'user={name},host=bootstrap,addr=100.64.0.1')
            required = ('authenticationmethods publickey', 'passwordauthentication no',
                        'kbdinteractiveauthentication no', 'pubkeyauthentication yes',
                        f'authorizedkeysfile /etc/ssh/dev-pair-keys/{name}')
            if not all(x in effective.splitlines() for x in required):
                raise Blocked('effective operator SSH settings conflict')
            self.run('/usr/bin/systemctl', 'reload', 'sshd.service')
        except BaseException:
            # Never leave a newly introduced invalid fragment active after a failed validation.
            if created:
                self.path(target).unlink(missing_ok=True)
            raise

    def prepare(self, name, key, sources, gptbox_context=None, expected_context=None, *, password=None, source_check=None):
        return self._converge_host(name,key,sources,gptbox_context,expected_context,password=password,source_check=source_check)

    def _host_prerequisites(self, name, key, sources, context, expected, *, password=None, source_check=None):
        # Caller holds the existing global bootstrap lock through image/assembly.
        return self._converge_host(name,key,sources,context,expected,password=password,source_check=source_check,host_only=True,locked=True)

    def _converge_host(self, name, key, sources, gptbox_context=None, expected_context=None, *, password=None, source_check=None,host_only=False,locked=False):
        self.mark_prepare_step('input-admission')
        if gptbox_context is not None and (not isinstance(expected_context, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_context)):
            raise Blocked('a separately trusted context SHA256 is required before preparation')
        sources = validate_sources(sources)
        connection = os.environ.get('SSH_CONNECTION')
        if connection:
            try:
                remote = ipaddress.ip_address(connection.split()[0])
            except ValueError:
                raise Blocked('invalid current SSH source') from None
            if not any(remote in ipaddress.ip_network(c) for c in sources):
                raise Blocked('current SSH source is outside declared bootstrap CIDRs')
        if name != 'core' or (password is None and not self.path(f'{STATE}/operator-password-set').exists()):
            raise Blocked('core operator and securely supplied password are required')
        self.mark_prepare_step('host-preflight')
        self.preflight()
        if gptbox_context is not None:
            self.mark_prepare_step('context-content')
            self.check_gptbox_inputs(gptbox_context, expected_context)
            if self.path('/usr/bin/git').exists():
                self.mark_prepare_step('context-source')
                _,_,host_manifest=self.validate_gptbox_context(gptbox_context, expected_context)
        with contextlib.nullcontext() if locked else self.lock():
            if gptbox_context is not None:
                if not self.path('/usr/bin/git').exists():
                    self.step('git-prerequisite', lambda: self.run('/usr/bin/dnf', '-y',
                              '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--disablerepo=*',
                              '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'))
                self.mark_prepare_step('context-source')
                # Full source verification precedes desired binding, accounts, ingress and normal packages.
                _,_,host_manifest=self.validate_gptbox_context(gptbox_context, expected_context)
                if source_check:
                    self.mark_prepare_step('adapter-source-and-upstream')
                    source_check()
            self.mark_prepare_step('desired-state')
            desired = json.dumps({'schema': 1, 'standards_sha': STANDARDS,
                                  'source_baseline': SOURCE_BASELINE,
                                  'bootstrap_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                  'gptbox_context_sha256': expected_context, 'operator': name,
                                  'keys_source': KEYS_URL, 'bootstrap_sources': sources}, sort_keys=True) + '\n'
            self.atomic(f'{STATE}/desired.json', desired)
            self.step('resolved-discovery', self.configure_resolved)
            self.step('packages', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                       '--setopt=localpkg_gpgcheck=1', '--disablerepo=*', '--enablerepo=fedora',
                       '--enablerepo=updates', 'install', *PACKAGES))
            self.step('operator', lambda: (self.identity(name, '/bin/bash'), self.ssh_operator(name, key),
                                         self.password_operator(password)))
            self.step('host-identity-time', self.host_identity)
            self.mark_prepare_step('sudo-package-provenance')
            sudo_package = self.run(*SUDO_PACKAGE_QUERY, timeout=10, sudo_package=True)
            for who, begin, role in [('dp-maint', 1000000, 'maintenance'), ('dp-dev', 1065536, 'development')]:
                verified = self.step(who, lambda who=who, begin=begin: self.restricted_identity(who, begin, sudo_package))
                self.step(role+'-directories',lambda verified=verified:self._role_directories(verified))
                del verified
            self.mark_prepare_step('managed-limits')
            self.atomic('/etc/dev-pair/limits.json', json.dumps({
                'jobs_enabled': False, 'per_role_memory_max': '2G', 'per_role_tasks_max': 512,
                'per_role_cpu_quota': '100%', 'storage_budget_bytes': 21474836480,
                'minimum_free_bytes': 8589934592, 'inactive_retention_days': 7,
                'note': 'No jobs admitted until storage enforcement and lifecycle validation exist.'}, indent=2) + '\n', mode=0o644)
            # Actual cgroup ceilings apply to the entire unprivileged user, not one container.
            for who in ('dp-maint', 'dp-dev'):
                uid = self.run('/usr/bin/id', '-u', who).strip()
                self.atomic(f'/etc/systemd/system/user-{uid}.slice.d/50-dev-pair.conf',
                            '[Slice]\nMemoryMax=2G\nTasksMax=512\nCPUQuota=100%\n', mode=0o644)
            self.step('ingress-guard', lambda: self.guard(sources))
            self.mark_prepare_step('tailscale-package-config')
            self.atomic('/etc/yum.repos.d/dev-pair-tailscale.repo', REPO, mode=0o644)
            self.step('tailscale-package', lambda: self.run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1',
                      '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates',
                      '--enablerepo=tailscale-stable', 'install', 'tailscale'))
            self.atomic('/etc/systemd/system/tailscaled.service.d/50-dev-pair-guard.conf', TAILSCALE_UNIT, mode=0o644)
            self.run('/usr/bin/systemctl', 'daemon-reload')
            self.run('/usr/bin/systemctl', 'enable', '--now', 'tailscaled.service')
            self.mark_prepare_step('package-inventory')
            versions = self.run('/usr/bin/rpm', '-q', *PACKAGES, 'tailscale')
            self.atomic(f'{STATE}/packages.txt', versions, expected=self.text(f'{STATE}/packages.txt') or None)
            if host_only:
                # Freshly reconverged evidence, never an admission/cache oracle.
                ready={'schema':1,'kind':'host-prerequisites','source_sha':host_manifest['source_sha'],
                    'context_sha256':expected_context,'standards_sha':STANDARDS,'bootstrap_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'desired_sha256':hashlib.sha256(desired.encode()).hexdigest(),'packages_sha256':hashlib.sha256(versions.encode()).hexdigest()}
                old_ready=self.text(STATE+'/host-ready.json')
                if old_ready:
                    previous=json.loads(old_ready,object_pairs_hook=relay.unique)
                    if type(previous) is not dict or set(previous)!=set(ready) or any(previous[k]!=v for k,v in ready.items() if k!='packages_sha256'):
                        raise Blocked('host prerequisite record target conflict')
                self.atomic(STATE+'/host-ready.json',json.dumps(ready,sort_keys=True)+'\n',expected=old_ready or None)
                return ready
            if gptbox_context is not None:
                self.step('maintenance-gptbox-build', lambda: self.build_gptbox(gptbox_context, expected_context))
            self.mark_prepare_step('preparation-completion')
            self.atomic(f'{STATE}/prepared', desired)
            self.event('prepare', 'complete')
        return self.status()

    def candidate_tool(self):
        path = Path(__file__).with_name('candidate.py')
        spec = importlib.util.spec_from_file_location('dev_pair_candidate', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def check_gptbox_inputs(self, context, expected):
        """Python-only input checks before any mutation; does not admit source or runtime."""
        if platform.machine() != 'x86_64':
            raise Blocked('current pinned Codex context supports x86_64 maintenance builds only')
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise Blocked('a separately trusted context SHA256 is required')
        tool = self.candidate_tool()
        source = Path(context)
        if not source.is_absolute():
            raise Blocked('gptbox context path must be absolute')
        # Protect transferred bytes before snapshot/verification; only root can race this source.
        if self.root == Path('/'):
            for entry in [source, *source.parents, *source.iterdir()]:
                info = entry.lstat()
                if entry.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise Blocked('gptbox context must be root-owned, protected and nonsymlink')
        try:
            _, manifest = tool._verify_content(source, expected)
            if manifest['role'] != 'maintenance':
                raise Blocked('first bootstrap accepts only maintenance-role gptbox contexts')
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Blocked('gptbox context/source verification failed; no host changes permitted') from None
        return tool, source, manifest

    def validate_gptbox_context(self, context, expected):
        tool, source, manifest = self.check_gptbox_inputs(context, expected)
        try:
            tool.verify(source, expected)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Blocked('gptbox context/source verification failed; no admission') from None
        return tool, source, manifest

    @staticmethod
    def storage_observer():
        spec=importlib.util.spec_from_file_location('dev_pair_storage_observation',Path(__file__).with_name('storage_observation.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

    def observe_storage(self,stage,source,context,prepared,sealed=None):
        observer=self.storage_observer()
        value=observer.record(stage,source,context,prepared.removeprefix('sha256:'),
            sealed.removeprefix('sha256:') if sealed else None,cleanup=stage=='assembled-postcleanup')
        location=(STATE+'/storage-prepared.json' if stage=='prepared-image' else
                  STATE+'/gptbox-adapter/'+context+'/storage-assembled-postcleanup.json')
        def save():self.atomic(location,json.dumps(value,sort_keys=True)+'\n',expected=self.text(location) or None)
        if not isinstance(self.run,Commands):value['reason']='bounded-runner-unavailable';save();return value
        end=self.run.execution_deadline()
        remaining=min(10,end-time.monotonic()) if end is not None else 10
        if remaining<2:value['reason']='no-budget';save();return value
        value['reason']='collector-lifecycle-failure';save()
        # _call deliberately bypasses ProbeCommands raw-buffer diagnostics. Native
        # lifecycle failures propagate unchanged; this is not a fallback executor.
        output=self.run._call('/usr/bin/python3','-I',str(Path(__file__).with_name('storage.py')),
            str(self.path(observer.ROOT)),'--seconds',str(min(9,remaining/2)),
            timeout=remaining,maximum=262144,ok=(0,2))
        try:
            inventory=observer.decode(output)
            if inventory is None:value['reason']='collector-unavailable'
            else:value.update(status='observed',reason='none',inventory=inventory)
        except (ValueError,TypeError):value['reason']='invalid-collector-output'
        save();return value

    def build_gptbox(self, context, expected):
        tool, source, manifest = self.validate_gptbox_context(context, expected)
        try:
            stage = f'/var/lib/dev-pair/artifacts/gptbox/{expected}'
            self.directory('/var/lib/dev-pair/artifacts', mode=0o755)
            self.directory('/var/lib/dev-pair/artifacts/gptbox', mode=0o755)
            self.directory(stage, mode=0o755)
            for name in ('inputs.json', 'codex', 'Containerfile', 'candidate.json', *tool.fedora_oci.FILES):
                data = (source / name).read_bytes()
                # All four files are public build inputs, never credentials or writable home state.
                target = self.path(stage) / name
                if target.exists() or target.is_symlink():
                    if target.is_symlink() or target.read_bytes() != data or target.stat().st_mode & 0o222:
                        raise Blocked('staged gptbox context conflicts')
                else:
                    temporary = target.with_name('.staging-' + name)
                    # A previous interrupted writer can leave only its private staging file.
                    if temporary.exists() or temporary.is_symlink():
                        info = temporary.lstat()
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                or info.st_nlink != 1):
                            raise Blocked('unsafe interrupted gptbox staging file')
                        temporary.unlink()
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
                    try:
                        with os.fdopen(fd, 'wb') as out:
                            os.fchmod(out.fileno(), 0o444)
                            out.write(data)
                            out.flush()
                            os.fsync(out.fileno())
                        os.replace(temporary, target)
                    finally:
                        temporary.unlink(missing_ok=True)
            tool.verify(self.path(stage), expected)
        except (ValueError, subprocess.SubprocessError):
            raise Blocked('gptbox context verification failed; no engine invoked') from None
        uid = self.run('/usr/bin/id', '-u', 'dp-maint').strip()
        if not uid.isdigit() or int(uid) < 1000:
            raise Blocked('invalid maintenance runtime UID')
        self.run('/usr/bin/systemctl', 'start', f'user@{uid}.service')
        storage = '/var/lib/dev-pair/maintenance/images'
        self.directory(storage, owner='dp-maint')
        base = ['/usr/bin/systemd-run', '--wait', '--collect', '--service-type=exec',
                '--uid=dp-maint', f'--unit=dev-pair-gptbox-{expected}.service',
                f'--description=dev-pair-owned-dev-pair-gptbox-{expected}.service',
                '--property=RuntimeMaxSec=600', '--property=TimeoutStopSec=10',
                '--property=KillMode=control-group', '--property=MemoryMax=2G',
                '--property=TasksMax=512', '--property=CPUQuota=100%', '/usr/bin/env', '-i',
                'HOME=/home/dp-maint', 'USER=dp-maint', 'LOGNAME=dp-maint',
                'PATH=/usr/sbin:/usr/bin', f'XDG_RUNTIME_DIR=/run/user/{uid}',
                '/usr/bin/podman', '--root', str(self.path(storage)),
                '--runroot', f'/run/user/{uid}/dev-pair-gptbox-build', '--storage-driver=vfs']
        def candidate_execute(*argv, **kwargs):
            scope=self.run.maintenance_launcher(expected,uid) if isinstance(self.run,Commands) else contextlib.nullcontext()
            with scope:return self.run(*argv,**kwargs)
        tag = f'localhost/dev-pair/maintenance-gptbox:{expected}'
        record_path = f'{STATE}/gptbox-image.json'
        intent = {'context_sha256': expected, 'local_tag': tag, 'source_sha': manifest['source_sha']}
        self.atomic(f'{STATE}/gptbox-build-intent.json', json.dumps(intent, sort_keys=True) + '\n')
        self.event('gptbox-build-intent', 'recorded')
        prior = json.loads(self.text(record_path)) if self.path(record_path).exists() else None
        if prior:
            if (prior.get('context_sha256') != expected or prior.get('source_sha') != manifest['source_sha']
                    or prior.get('base_image') != manifest['fedora']['image'] or prior.get('codex_sha256') != manifest['codex']['sha256']
                    or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', prior.get('image_id', ''))):
                raise Blocked('protected gptbox completion record conflicts')
            inspect = candidate_execute(*base, 'image', 'inspect', prior['image_id'], ok=(0, 125))
            if not inspect:
                raise Blocked('recorded gptbox artifact is missing; explicit recovery required')
        else:
            # A writable image-store label/tag is never a completion/provenance record.
            # Interrupted unrecorded builds are rebuilt from the same protected context.
            def reconcile_copy():
                if isinstance(self.run, Commands):
                    self.run.reconcile_native(('--unit=dev-pair-gptbox-'+expected+'.service','--description=dev-pair-owned-dev-pair-gptbox-'+expected+'.service','--uid=dp-maint'), {})
            work = '/var/lib/dev-pair/artifacts/gptbox-image-work/' + expected
            self.directory('/var/lib/dev-pair/artifacts/gptbox-image-work', mode=0o755)
            self.directory(work, mode=0o755)
            tool.fedora_oci.recover_workspaces(self.path(work),uid=int(uid),reconcile=reconcile_copy)
            if shutil.disk_usage(self.path(storage)).free < 8 * 1024 ** 3:
                raise Blocked('insufficient free storage reserve for gptbox build')
            with tool.fedora_oci.image_workspaces(self.path(work), uid=int(uid), reconcile=reconcile_copy, reserve=8*1024**3) as (copy_tmp, verification_root):
                with tool.fedora_oci.verified(self.path(stage), temporary_parent=verification_root, leased=True) as (plain, proof):
                    def local_image(*args, **kwargs):
                        prefix = list(base)
                        index = prefix.index('/usr/bin/podman')
                        prefix[index:index] = ['TMPDIR='+str(copy_tmp)]
                        if args[0] == 'save':
                            index = prefix.index('/usr/bin/podman')
                            prefix[index:index] = ['/usr/bin/prlimit', '--fsize=' + str(tool.fedora_oci.SAVE_FILE_LIMIT) + ':' + str(tool.fedora_oci.SAVE_FILE_LIMIT)]
                        return candidate_execute(*prefix, *args, **kwargs)
                    import_proof = tool.fedora_oci.import_image(local_image, plain, uid=int(uid))
                built_id = local_image('build', '--quiet', '--network=slirp4netns:allow_host_loopback=false', '--pull=never', '--format=oci',
                         '--label', f'dev-pair.context={expected}', '--tag', tag,
                         '--file', str(self.path(stage) / 'Containerfile'), str(self.path(stage))).strip()
            if not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', built_id):
                raise Blocked('gptbox build returned no unambiguous immutable image ID')
            inspect = candidate_execute(*base, 'image', 'inspect', built_id)
        try:
            images = json.loads(inspect)
            if not isinstance(images, list) or len(images) != 1:
                raise ValueError()
            image = images[0]
            image_id = image['Id']
            expected_id = prior['image_id'] if prior else built_id
            if image_id.removeprefix('sha256:') != expected_id.removeprefix('sha256:'):
                raise ValueError()
            if not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', image_id):
                raise ValueError()
            labels = image.get('Labels') or image.get('Config', {}).get('Labels', {})
            wanted = {'dev-pair.context': expected, 'dev-pair.role': 'maintenance',
                      'dev-pair.standards': STANDARDS,
                      'org.opencontainers.image.revision': manifest['source_sha'],
                      'dev-pair.codex.version': manifest['codex']['version']}
            if any(labels.get(key) != value for key, value in wanted.items()):
                raise ValueError()
            if image.get('Architecture') != 'amd64' or image.get('Os') != 'linux':
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise Blocked('gptbox artifact inspection identity mismatch') from None
        record = {'kind': 'host-maintenance-gptbox-oci-candidate', 'context_sha256': expected,
                  'source_sha': manifest['source_sha'], 'base_image': manifest['fedora']['image'],
                  'codex_sha256': manifest['codex']['sha256'], 'image_id': image_id,
                  'local_tag': tag, 'runtime_user': 'dp-maint', 'storage_driver': 'vfs',
                  'launch': 'blocked: stock Distrobox 1.8.2.5 adds privileged, label=disable and host mounts',
                  'distrobox_assembled': False, 'runtime_validated': False,
                  'fedora_base': import_proof if not prior else prior.get('fedora_base'),
                  'logical_storage':self.storage_observer().logical(image)}
        self.atomic(record_path, json.dumps(record, sort_keys=True, indent=2) + '\n')
        self.observe_storage('prepared-image',manifest['source_sha'],expected,image_id)
        return record

    def guard(self, sources):
        rules = '\n'.join(f'add rule inet dev_pair_bootstrap input {"ip6" if ":" in cidr else "ip"} saddr {cidr} tcp dport 22 accept' for cidr in sources)
        guard = GUARD.replace('{bootstrap_rules}', rules)
        config = '/etc/dev-pair/bootstrap.nft'
        if not self.path(config).exists():
            tables = self.run('/usr/sbin/nft', 'list', 'tables')
            if 'dev_pair_bootstrap' in tables:
                raise Blocked('existing bootstrap nft table has no managed configuration')
        self.atomic(config, guard, mode=0o600)
        self.atomic('/etc/systemd/system/dev-pair-bootstrap-guard.service', UNIT, mode=0o644)
        self.run('/usr/sbin/nft', '--check', '-f', str(self.path(config)))
        self.run('/usr/bin/systemctl', 'daemon-reload')
        self.run('/usr/bin/systemctl', 'enable', 'dev-pair-bootstrap-guard.service')
        # nft -f commits its own table transaction atomically. Reapply on resume to reconcile live drift.
        self.run('/usr/sbin/nft', '-f', str(self.path(config)))
        self.run('/usr/bin/systemctl', 'start', 'dev-pair-bootstrap-guard.service')

    def enroll(self, secret, tailnet):
        self.preflight()
        secret = checked_file(secret, secret=True)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.@-]{0,252}', tailnet):
            raise Blocked('invalid expected tailnet name')
        with self.lock():
            if not self.path(f'{STATE}/prepared').exists():
                raise Blocked('prepare must complete before enrollment')
            intent = f'{STATE}/enrollment-intent.json'
            expected = json.dumps({'tailnet': tailnet}, sort_keys=True) + '\n'
            same_intent = self.text(intent) == expected
            accepted = self.path(f'{STATE}/node.json').exists()
            try:
                live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json', ok=(0, 1)))
                if not isinstance(live, dict):
                    raise Blocked('invalid Tailscale status observation')
            except BaseException:
                if same_intent and not accepted:
                    self.disconnect_unverified()
                raise
            state = live.get('BackendState')
            if state == 'Running' and not same_intent:
                raise Blocked('refusing to adopt an already enrolled node')
            if accepted:
                if state != 'Running':
                    raise Blocked('previous node lost enrollment; explicit recovery required')
                self.check_node(live, tailnet)
                return self.status()
            try:
                if self.path(f'{STATE}/enrollment-recovery-required.json').exists():
                    raise Blocked('enrollment identity requires explicit recovery/new credentials; automatic retry denied')
                if state not in ('Running', 'NeedsLogin', 'NoState', 'Stopped'):
                    raise Blocked('unexpected Tailscale state; no automatic reauthentication')
                if state == 'Stopped' and not same_intent:
                    raise Blocked('stopped unowned enrollment requires explicit recovery')
                observed_tailnet, _ = self.identity_fields(live)
                if state != 'Running' and observed_tailnet and observed_tailnet != tailnet:
                    if same_intent:
                        self.require_enrollment_recovery(tailnet)
                    raise Blocked('stopped enrollment tailnet mismatch; explicit recovery/new credentials required')
                self.atomic(intent, expected)
                if state != 'Running':
                    self.step('enroll', lambda: self.run('/usr/bin/tailscale', 'up', '--auth-key=file:' + str(secret),
                             '--accept-routes=false', '--accept-dns=false', '--ssh=false',
                             '--advertise-exit-node=false', '--netfilter-mode=off', '--timeout=60s'))
                live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json'))
                if not isinstance(live, dict) or live.get('BackendState') != 'Running':
                    raise Blocked('enrollment did not reach Running; bootstrap access retained')
                self.check_node(live, tailnet, disconnect_on_mismatch=False)
                self.event('enrollment-observed', 'complete')
            except BaseException:
                # CLI success is insufficient: observation, decoding and persistence must also succeed.
                # Disconnect is attempted even if a full disk makes journaling fail.
                self.disconnect_unverified()
                # No prior accepted marker existed on this new-enrollment path.
                # A write may have become visible before its fsync/completion failed.
                self.path(f'{STATE}/node.json').unlink(missing_ok=True)
                raise
        return self.status()

    def require_enrollment_recovery(self, tailnet):
        self.atomic(f'{STATE}/enrollment-recovery-required.json',
                    json.dumps({'expected_tailnet': tailnet, 'reason': 'observed identity mismatch'}, sort_keys=True) + '\n')

    def disconnect_unverified(self):
        try:
            self.run('/usr/bin/tailscale', 'down')
        except BaseException:
            try:
                self.event('enrollment-failure-cleanup', 'failed')
            except OSError:
                pass
            raise Blocked('enrollment unverified and Tailscale disconnect failed; initial SSH retained, inspect/revoke externally') from None
        try:
            self.event('enrollment-failure-cleanup', 'complete')
        except OSError:
            pass

    @staticmethod
    def identity_fields(live):
        # Official Status uses nullable *TailnetStatus and *PeerStatus fields.
        current, own = live.get('CurrentTailnet'), live.get('Self')
        current = {} if current is None else current
        own = {} if own is None else own
        if not isinstance(current, dict) or not isinstance(own, dict):
            raise Blocked('invalid Tailscale identity schema')
        name, node_id = current.get('Name'), own.get('ID')
        if any(value is not None and not isinstance(value, str) for value in (name, node_id)):
            raise Blocked('invalid Tailscale identity fields')
        return name, node_id

    def check_node(self, live, tailnet, disconnect_on_mismatch=True):
        try:
            observed_tailnet, node_id = self.identity_fields(live)
        except Blocked:
            if disconnect_on_mismatch:
                self.disconnect_unverified()
            raise
        node = json.dumps({'tailnet': tailnet, 'node_id': node_id}, sort_keys=True) + '\n'
        previous = self.text(f'{STATE}/node.json')
        if (observed_tailnet != tailnet or not node_id
                or (previous and previous != node)):
            try:
                self.require_enrollment_recovery(tailnet)
            finally:
                if disconnect_on_mismatch:
                    self.disconnect_unverified()
            raise Blocked('tailnet identity mismatch: unverified node taken down; initial SSH retained, revoke key externally')
        self.atomic(f'{STATE}/node.json', node)

    def status(self):
        return {'prepared': self.path(f'{STATE}/prepared').exists(),
                'initialization': json.loads(self.text(f'{STATE}/initialize.json', '"not requested"')),
                'maintenance_gptbox': (json.loads(self.text(f'{STATE}/gptbox-image.json'))
                                       if self.path(f'{STATE}/gptbox-image.json').exists() else 'not built'),
                'enrollment_recorded': self.path(f'{STATE}/node.json').exists(),
                'phase': 'temporary-bootstrap', 'applications_started': False,
                'root_and_initial_ssh_retained': True, 'access_cutover': 'blocked pending external evidence',
                'runtime_acceptance': 'not verified', 'state': STATE,
                'note': 'Recorded state only; not proof of current external reachability or recovery'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='stage', required=True)
    sub.add_parser('inspect')
    sub.add_parser('_fetch-github-keys', help=argparse.SUPPRESS)
    init = sub.add_parser('initialize', help='prepare then genuine maintenance assembly; no jobs/authentication')
    init.add_argument('--source-sha', required=True)
    init.add_argument('--distrobox-source', required=True)
    init.add_argument('--retry', action='store_true')
    prep = sub.add_parser('prepare')
    for entry in (prep, init):
        entry.add_argument('--apply', action='store_true', help='perform host changes; absent means inspect only')
        entry.add_argument('--gptbox-context', required=True, help='real maintenance-role context; fixtures denied')
        entry.add_argument('--expected-context-sha256', required=True, help='trusted handoff digest outside context')
        entry.add_argument('--operator', choices=('core',), default='core')
        entry.add_argument('--password-file', help='protected root-owned core console/sudo password file; never an argv value')
        entry.add_argument('--bootstrap-source', action='append', required=True, help='explicit IPv4/IPv6 CIDR; repeatable')
    en = sub.add_parser('enroll')
    en.add_argument('--apply', action='store_true', help='enroll; absent means inspect only')
    en.add_argument('--auth-key-file', required=True)
    en.add_argument('--tailnet', required=True, help='exact expected CurrentTailnet.Name')
    sub.add_parser('status')
    sub.add_parser('finalize')
    args = p.parse_args()
    try:
        if args.stage == 'initialize':
            forwarded = [sys.executable, str(Path(__file__).with_name('gptbox.py')), 'initialize',
                         '--context', args.gptbox_context, '--expected-context-sha256', args.expected_context_sha256,
                         '--source-sha', args.source_sha, '--distrobox-source', args.distrobox_source]
            for source in args.bootstrap_source:
                forwarded.extend(['--bootstrap-source', source])
            if args.password_file:
                forwarded.extend(['--password-file', args.password_file])
            if args.apply:
                forwarded.append('--apply')
            if args.retry:
                forwarded.append('--retry')
            os.execv(sys.executable, forwarded)
        if args.stage == '_fetch-github-keys':
            sys.stdout.buffer.write(fetch_github_response())
            return 0
        b = Bootstrap()
        if args.stage == 'inspect':
            result = b.preflight()
        elif args.stage == 'prepare':
            if args.apply:
                password = operator_password(args.password_file) if args.password_file else None
                keys = github_keys()
                result = b.prepare(args.operator, keys, args.bootstrap_source,
                                   args.gptbox_context, args.expected_context_sha256, password=password)
            else:
                result = {**b.preflight(), 'preview': 'prepare', 'sources': validate_sources(args.bootstrap_source)}
                b.check_gptbox_inputs(args.gptbox_context, args.expected_context_sha256)
                if args.password_file:
                    operator_password(args.password_file)
                elif not b.path(f'{STATE}/operator-password-set').exists():
                    raise Blocked('first preparation requires --password-file')
                github_keys()
                result['operator'] = 'core; GitHub keys validated; console/sudo password supplied externally'
                if b.path('/usr/bin/git').exists():
                    b.validate_gptbox_context(args.gptbox_context, args.expected_context_sha256)
                    result['gptbox_context'] = 'content and source verified read-only; build not executed'
                else:
                    result['gptbox_context'] = 'content checked; Git source verification pending prerequisite install; not admitted'
        elif args.stage == 'enroll':
            result = b.enroll(args.auth_key_file, args.tailnet) if args.apply else {**b.preflight(), 'preview': 'enroll'}
        elif args.stage == 'finalize':
            raise Blocked('cutover is not implemented: preserve initial SSH/root until external named-admin tailnet access and independent recovery are proven')
        else:
            result = b.status()
        print(json.dumps(result, indent=2))
        return 0
    except (Blocked, OSError, ValueError) as e:
        # JSON/OS exceptions may contain external payloads/paths: do not echo them.
        print('bootstrap blocked: ' + (str(e) if isinstance(e, Blocked) else 'invalid input or local filesystem state'), file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
