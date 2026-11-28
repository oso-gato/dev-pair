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
import pwd
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
DEVELOPMENT_HOST_INTENT = STATE + '/prepare-development-host.json'
ACCESS_MODE = 'verified-provider-console'
ATTENDED_ACCESS = 'attended-local-recovery'
ATTENDED_RECEIPT = '/run/dev-pair-day0/recovery.json'
GUARD_PATH = '/etc/dev-pair/bootstrap.nft'
CUTOVER = STATE + '/access-cutover.json'
CORE_ACCESS_CUTOVER = 'core-access-cutover'
WORKLOAD_ACCESS_CUTOVER = 'workload-access-cutover'
TRUST_SIGNERS = '/etc/dev-pair/trust/allowed_signers'
SIGNER_TRUST_LOCK = 'signer-trust.lock'
AGENT_OBSERVER_PRINCIPAL = 'dev-pair-observer-authorized'
AGENT_OBSERVER_NAMESPACE = 'dev-pair-destination-observation'
AGENT_OBSERVER_PREFIX = f'{AGENT_OBSERVER_PRINCIPAL} namespaces="{AGENT_OBSERVER_NAMESPACE}" '
CHECKLIST_OWNER = 'dp-checklist'
CHECKLIST_HOME = '/var/lib/dev-pair/checklist-executor'
CHECKLIST_CONTROL = '/var/lib/dev-pair/checklist-release'
CHECKLIST_UNIT = 'dev-pair-checklist-executor@.service'
CHECKLIST_OVERRIDE = '/etc/systemd/system/' + CHECKLIST_UNIT + '.d/checklist-release.conf'
CHECKLIST_ENTRY = '/usr/libexec/dev-pair/renewal/checklist-entry'
CHECKLIST_PORTS = {'19425', '18279', '443'}
CHECKLIST_APP = 'dp-checklist-app'
CHECKLIST_ARGS = ('serve-host', '--state', CHECKLIST_HOME + '/ledger', '--tls', CHECKLIST_HOME + '/tls',
                  '--approval', '/etc/dev-pair/checklist/approval.json', '--port', '19425', '--lifetime', '600')
SSH_CUTOVER = '/etc/ssh/sshd_config.d/00-dev-pair-cutover.conf'
SSH_CUTOVER_CONFIG = '''# dev-pair tailnet administration
PermitRootLogin no
AllowUsers core
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
'''
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
SUDO_DENIAL_ROLES = {**SUDO_ROLES, 'dp-checklist': 'checklist-sudo-denial'}
ROLE_DIRECTORIES = {'dp-maint':'maintenance','dp-dev':'development'}
ROLE_CHILDREN = ('workspaces','checkpoints','evidence','deliverables','builds','cache','state')
BUILDER_ACCOUNT = 'dp-maint'


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


def role_subordinate_range(content, name, uid, start):
    """Use the same allocation and overlap predicate for provisioning and readback."""
    wanted = f'{name}:{start}:65536'
    own = []
    for line in content.splitlines():
        parts = line.split(':')
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            raise Blocked('malformed subordinate ID configuration')
        who, begin, count = parts[0], int(parts[1]), int(parts[2])
        if who in (name, uid):
            own.append(line)
        elif begin < start + 65536 and start < begin + count:
            raise Blocked('subordinate ID range overlaps an existing account')
    if own and own != [wanted]:
        raise Blocked('conflicting subordinate ID allocation')
    return bool(own)


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
    if type(role) is not str or role not in SUDO_DENIAL_ROLES:
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
    return {'operation_id': SUDO_DENIAL_ROLES[role], 'role': role, 'execution_kind': execution_kind,
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
    mask_staging_diagnostic = None
    native_register = None
    _cleanup_deadline = None
    current_step = 'unscoped'
    _maintenance_launcher_binding = None
    _adapter_image_binding = None
    _adapter_rpm_cache = False

    @contextlib.contextmanager
    def maintenance_launcher(self, context, uid):
        # Diagnostic scope is entered only after build_gptbox source/context
        # validation and checked UID lookup. It grants no launch authority.
        previous=self._maintenance_launcher_binding
        self._maintenance_launcher_binding=(context,uid)
        try:yield
        finally:self._maintenance_launcher_binding=previous

    @contextlib.contextmanager
    def adapter_image_launcher(self,context,uid,identity=None,*,rpm_cache=False):
        previous=self._adapter_image_binding;previous_identity=getattr(self,"_selected_payload_identity",None)
        previous_cache = self._adapter_rpm_cache
        self._adapter_image_binding=(context,uid);self._selected_payload_identity=identity
        self._adapter_rpm_cache = rpm_cache
        try:yield
        finally:
            self._adapter_image_binding=previous;self._selected_payload_identity=previous_identity
            self._adapter_rpm_cache = previous_cache

    def adapter_image_selection(self,args,input_text):
        if self.current_step!='candidate-image' or input_text is not None:return None
        context,uid=self._adapter_image_binding
        if type(context) is not str or not re.fullmatch('[0-9a-f]{64}',context) or type(uid) is not str or not re.fullmatch('[1-9][0-9]{0,9}',uid):return None
        unit='dev-pair-gptbox-'+context+'.service';control='/usr/local/libexec/dev-pair-gptbox'
        fixed=('/usr/bin/systemd-run','--unit='+unit,'--description=dev-pair-owned-'+unit,'--quiet','--wait','--collect','--service-type=exec','--uid='+BUILDER_ACCOUNT)
        if args[:8]!=fixed or len(args)<24 or not args[8].startswith('--property=RuntimeMaxSec='):return None
        try:
            duration=float(args[8].split('=',2)[2])
            if not math.isfinite(duration) or not 0<duration<=600:return None
        except ValueError:return None
        tail=('--property=TimeoutStopSec=10','--property=KillMode=control-group','--property=MemoryMax=2G','--property=TasksMax=512','--property=CPUQuota=100%',
            '/usr/bin/env','-i','PATH='+control+'/bin:/usr/bin:/usr/sbin:/bin','HOME='+control+'/home',
            'USER='+BUILDER_ACCOUNT,'LOGNAME='+BUILDER_ACCOUNT,
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
        elif copied:
            network = '--network=slirp4netns:allow_host_loopback=false'
            mounts = ()
            if self._adapter_rpm_cache:
                from fedora_rpm_cache import mount_args
                network, mounts = '--network=none', mount_args(Path(work) / 'verification-work/rpm-build')
            build = '/var/lib/dev-pair/artifacts/gptbox-adapter/' + context + '/build'
            if operation == ('build', '--quiet', network, '--pull=never', '--http-proxy=false', *mounts,
                             '--file', build + '/Containerfile', build):
                selected = 'build'
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
        if len(args) == 4 and args[:3] == ('/usr/bin/sudo', '-l', '-U') and args[3] in SUDO_DENIAL_ROLES:
            return SUDO_DENIAL_ROLES[args[3]]
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
                    type(sudo_probe['role']) is not str or sudo_probe['role'] not in SUDO_DENIAL_ROLES or
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
                    # The owned parent mtime is checked separately against the journal.
                    return tuple((row[:5] + (0,)) if row[0] == root else row for row in rows
                                 if row[0] not in (str(transport.profile_path), str(transport.profile_path / '10-timeout-abort.conf')))
                admission_reason = 'cache-staging-comparison'
                before_staging, after_staging = normalized(snapshot), normalized(after)
                if before_staging != after_staging:
                    cache_comparison = configuration_mismatch(before_staging, after_staging, unit, stage=admission_reason)
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
            if (self.mask_staging_diagnostic and register_root_wrapper and admission_reason == 'cache-staging-comparison'
                    and failure_witness is not None and cache_comparison is not None):
                notify(self.mask_staging_diagnostic, unit, failure_witness)
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
        networks = sorted({str(ipaddress.ip_network(x, strict=True)) for x in (sources or [])})
    except (TypeError, ValueError):
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

    def destination_identity(self):
        machine = self.text('/etc/machine-id').strip()
        boot = self.text('/proc/sys/kernel/random/boot_id').strip()
        if not re.fullmatch(r'[0-9a-f]{32}', machine) or not re.fullmatch(r'[0-9a-f-]{36}', boot):
            raise Blocked('destination machine or boot identity unavailable')
        return {'machine_id': machine, 'boot_id': str(uuid.UUID(boot))}

    def destination_source(self, expected, *, checkout=None):
        if type(expected) is not str or not re.fullmatch(r'[0-9a-f]{40}', expected):
            raise Blocked('exact independently admitted full source SHA required')
        script = Path(__file__).absolute()
        install = self.path('/usr/libexec/dev-pair')
        if checkout is None and self.destination_program_kind(script):
            try:
                return self.installed_destination_source(expected, script, install)
            except (OSError, ValueError, KeyError, TypeError) as error:
                raise Blocked('selected installed destination source evidence is unavailable') from error
        repo = script.parents[1] if checkout is None else Path(checkout)
        recorded_script = repo / 'tools/bootstrap.py'
        if not repo.is_absolute():
            raise Blocked('owner recovery checkout must be absolute')
        for path in (script, *script.parents, recorded_script, *recorded_script.parents, repo / '.git'):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Blocked('destination source path is not root protected')
        git = ('/usr/bin/git', '-C', str(repo))
        if (self.run(*git, 'rev-parse', '--verify', 'HEAD').strip() != expected
                or self.run(*git, 'status', '--porcelain=v1', '--untracked-files=all').strip()
                or self.run(*git, 'show', expected + ':tools/bootstrap.py') != script.read_text()
                or recorded_script.read_bytes() != script.read_bytes()):
            raise Blocked('destination source checkout differs from independent admission')
        return expected

    def signer_trust_file(self):
        path = checked_file(self.path(TRUST_SIGNERS))
        if path.lstat().st_nlink != 1:
            raise Blocked('the protected signer trust file must be singly linked')
        return path

    @staticmethod
    def observer_public_key(public):
        parts = public.split()
        if (not public.isascii() or len(public) > 1024 or len(parts) < 2 or
                parts[0] not in ('ssh-ed25519', 'sk-ssh-ed25519@openssh.com')):
            raise Blocked('enter the independent collector’s OpenSSH Ed25519 public key')
        return validate_public_keys((' '.join(parts[:2]) + '\n').encode()).strip()

    @staticmethod
    def signer_fingerprint(public):
        material = base64.b64decode(public.split()[1], validate=True)
        return 'SHA256:' + base64.b64encode(hashlib.sha256(material).digest()).decode().rstrip('=')

    @classmethod
    def agent_observer_entry(cls, raw):
        lines = raw.splitlines(keepends=True)
        entries = [line for line in lines if AGENT_OBSERVER_PRINCIPAL in line.split(None, 1)[:1]]
        if not entries:
            return None
        if len(entries) != 1 or not entries[0].startswith(AGENT_OBSERVER_PREFIX):
            raise Blocked('conflicting independent agent collector scope')
        line = entries[0]
        public = cls.observer_public_key(line.removeprefix(AGENT_OBSERVER_PREFIX))
        if line != AGENT_OBSERVER_PREFIX + public + '\n':
            raise Blocked('collector approval must name one exact principal and namespace')
        if any(public.split()[1] in other.split() for other in lines if other != line and not other.lstrip().startswith('#')):
            raise Blocked('the collector key is shared with another signing authority')
        return line, public

    def agent_observer_signers(self):
        """Select only the explicit collector approval, even if other entries use wildcard principals."""
        try:
            entry = self.agent_observer_entry(self.signer_trust_file().read_text(encoding='utf-8'))
        except FileNotFoundError:
            return None
        return entry[0].encode() if entry else None

    def update_agent_observer(self, fingerprint, *, public=None):
        """Enroll an independently confirmed collector, or withdraw its exact fingerprint."""
        if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
            raise Blocked('the collector’s separate OpenSSH SHA256 fingerprint is required')
        with self.lock(SIGNER_TRUST_LOCK):
            path = self.signer_trust_file()
            raw = path.read_bytes().decode('utf-8')
            previous = self.agent_observer_entry(raw)
            if public is None:
                if previous is None:
                    raise Blocked('no independent collector is enrolled')
                line, recorded = previous
                if self.signer_fingerprint(recorded) != fingerprint:
                    raise Blocked('the enrolled collector fingerprint differs from the withdrawal')
                updated = ''.join(record for record in raw.splitlines(keepends=True) if record != line)
            else:
                public = self.observer_public_key(public)
                if self.signer_fingerprint(public) != fingerprint:
                    raise Blocked('the collector fingerprint does not match the independently supplied key')
                if previous is not None:
                    if previous[1] == public:
                        return
                    raise Blocked('withdraw the existing collector fingerprint before enrolling another key')
                material = public.split()[1]
                for route in ('/etc/ssh/dev-pair-keys/core', '/etc/dev-pair/day0/access-exchange-known-hosts'):
                    route_keys = self.path(route)
                    if os.path.lexists(route_keys) and material in checked_file(route_keys).read_text().split():
                        raise Blocked('collector and named SSH or station transport require distinct keys')
                transport = self.path('/etc/dev-pair/day0/access-exchange-ed25519')
                if os.path.lexists(transport):
                    transport = checked_file(transport, secret=True)
                    public_transport = self.run('/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(transport), timeout=10)
                    if self.observer_public_key(public_transport).split()[1] == material:
                        raise Blocked('collector and destination-held transport require distinct keys')
                # Independent billing uses a separate active record on new sites.
                if os.path.lexists(self.path('/etc/dev-pair/provider-evidence/reviewer.json')):
                    from provider_billing import reviewer_state

                    billing = reviewer_state()
                    if billing and billing['key'] and billing['key'].split()[1] == material:
                        raise Blocked('collector and billing reviewers require distinct keys')
                updated = raw + ('\n' if raw and not raw.endswith('\n') else '') + AGENT_OBSERVER_PREFIX + public + '\n'
                self.agent_observer_entry(updated)  # Refuse materials already used by another principal.
            if len(updated.encode()) > 16384:
                raise Blocked('the protected signer trust file would exceed its bound')
            self.atomic(TRUST_SIGNERS, updated, mode=stat.S_IMODE(path.lstat().st_mode), expected=raw)

    def destination_program_kind(self, path):
        install = self.path('/usr/libexec/dev-pair')
        if path.parent == install / 'tools':
            return 'fixed'
        if (path.parent.name == 'tools' and path.parent.parent.parent == install / 'host-releases'
                and re.fullmatch(r'[0-9a-f]{64}', path.parent.parent.name)):
            return 'selected'
        return None

    @contextlib.contextmanager
    def destination_dispatch_gate(self):
        path = self.path('/var/lib/dev-pair/renewal-fence/owner.lock')
        self.runtime_protected_file(path)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            node = os.fstat(stream.fileno())
            if (node.st_uid != 0 or node.st_nlink != 1 or stat.S_IMODE(node.st_mode) != 0o644 or
                    not stat.S_ISREG(node.st_mode)):
                raise Blocked('checklist release lacks its protected host effect lock')
            try:
                fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise Blocked('checklist release is frozen by renewal') from error
            current = path.lstat()
            if (node.st_dev, node.st_ino) != (current.st_dev, current.st_ino):
                raise Blocked('checklist release host effect lock changed')
            if os.path.lexists(path.with_name('frozen')):
                raise Blocked('checklist release is frozen by renewal')
            yield

    def selected_destination_host(self):
        """Resolve settled, locally admitted current host authority under the shared effect fence."""
        import platform_release_install as platform_release
        import renewal

        boot = self.destination_identity()['boot_id']
        site, host, _ = self.runtime_selected_host(boot)
        controller = renewal.Renewal(self.path('/var/lib/dev-pair'), None)
        _, transition = controller.transition()
        if ((transition is not None and transition['phase'] not in renewal.TERMINAL)
                or self.runtime_record('/var/lib/dev-pair/renewal/current.json') != site):
            raise Blocked('checklist release is frozen by renewal')
        binding = self.runtime_record('/var/lib/dev-pair/renewal/platform-bindings/' + site + '.json')
        base = binding['base_platform_sha256']
        selected = binding['platform_sha256']
        if (set(binding) != {'schema', 'release_sha256', 'platform_sha256', 'base_platform_sha256', 'site_config_sha256',
                             'plan_sha256', 'intake_sha256'}
                or type(binding['schema']) is not int or binding['schema'] != 1 or binding['release_sha256'] != site
                or any(type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value) for value in (base, selected))):
            raise Blocked('installed destination source differs from the selected host release')
        _, selected_index, intake = platform_release.intake.retained_index(selected)
        if (binding['intake_sha256'] != intake or (selected_index['base_platform_sha256'] or selected) != base):
            raise Blocked('selected host release lacks its independently admitted portable binding')
        initial = selected_index if selected == base else platform_release.intake.retained_index(base)[1]
        component = initial['components']['host']
        if (initial['source_sha'], component['source_sha'], component['bundle_manifest_sha256']) != (
                host['source_revision'], host['source_revision'], host['artifact_sha256']):
            raise Blocked('installed destination source differs from independently admitted portable host code')
        store = self.path('/usr/libexec/dev-pair/host-releases') / host['artifact_sha256']
        platform_release.check_host_bundle(store, component, time.monotonic() + 15)
        manifest, _ = platform_release.protected_json(store / 'manifest.json', host['artifact_sha256'])
        if self.runtime_selected_host(boot)[:2] != (site, host):
            raise Blocked('destination host selection changed during source verification')
        return site, host['source_revision'], store, manifest

    def installed_destination_source(self, expected, script, install):
        from systemd_service_profile import protected

        _, source, store, manifest = self.selected_destination_host()
        if expected is not None and source != expected:
            raise Blocked('installed destination source differs from the selected host release')
        if script not in (install / 'tools/bootstrap.py', store / 'tools/bootstrap.py'):
            raise Blocked('installed destination verifier is outside the selected host release')
        for name in ('bootstrap.py', 'destination_release.py'):
            raw = protected(script.with_name(name), 0, 4 * 1024**2)
            if manifest['files'].get('tools/' + name) != hashlib.sha256(raw).hexdigest():
                raise Blocked('installed destination verifier differs from the selected signed host bundle')
        return source

    def dispatch_destination_program(self, script, operation, argv):
        """An immutable commissioning entry can hand fixed operations to the selected host bundle."""
        program = Path(script).absolute()
        operations = {'destination_observation.py': ('export-release',),
                      'destination_release.py': ('deploy', 'confirm', 'reject', 'rollback'),
                      'promotion_setup.py': ('enroll', 'import-proof'), 'product_release.py': ('advance', 'scan')}
        if self.destination_program_kind(program) != 'fixed' or operation not in operations.get(program.name, ()):
            return
        import platform_release_install as platform_release
        from systemd_service_profile import protected

        if os.getuid() != 0 or os.geteuid() != 0:
            raise Blocked('checklist dispatch requires the protected installed root entry')
        with self.destination_dispatch_gate():
            _, _, store, selected = self.selected_destination_host()
            intent = self.runtime_record('/var/lib/dev-pair/bootstrap/host-commissioning/intent.json')
            if type(intent['schema']) is not int or intent['schema'] != 1 or intent['machine_id'] != self.destination_identity()['machine_id']:
                raise Blocked('fixed checklist ingress lacks its same-machine commissioning authority')
            if not re.fullmatch(r'[0-9a-f]{64}', intent['platform_sha256']):
                raise Blocked('fixed checklist ingress lacks its exact installed package')
            _, platform, _ = platform_release.intake.retained_index(intent['platform_sha256'])
            fixed = platform['components']['host']
            if fixed['source_sha'] != intent['source_sha']:
                raise Blocked('fixed checklist ingress differs from its commissioned source')
            original = store.parent / fixed['bundle_manifest_sha256']
            manifest, _ = platform_release.protected_json(original / 'manifest.json', original.name)
            if manifest['source_revision'] != intent['source_sha']:
                raise Blocked('fixed checklist ingress manifest changes the approved commissioning source')
            for name in ('bootstrap.py', program.name):
                if hashlib.sha256(protected(program.with_name(name), 0, 4 << 20)).hexdigest() != manifest['files'].get('tools/' + name):
                    raise Blocked('fixed checklist ingress differs from its commissioned signed bundle')
            if original == store:
                return
            relative = 'tools/' + program.name
            target = store / relative
            if hashlib.sha256(protected(target, 0, 4 << 20, mode=0o444)).hexdigest() != selected['files'].get(relative):
                raise Blocked('selected checklist entry is missing or differs from its signed bundle')
        python = '/usr/bin/python3'
        os.execve(python, [python, '-EBs', str(target), *argv], {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8'})

    def signed_evidence(self, path, principal, namespace):
        if not path:
            raise Blocked('independently signed evidence is required')
        document = checked_file(path)
        signature = checked_file(document.with_name(document.name + '.sig'))
        signers = checked_file(self.path(TRUST_SIGNERS))
        raw = document.read_text(encoding='utf-8')
        self.run('/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', principal,
                 '-n', namespace, '-s', str(signature), input_text=raw, timeout=10)
        data = json.loads(raw, object_pairs_hook=relay.unique)
        if type(data) is not dict or type(data.get('version')) is not int or data['version'] != 1:
            raise Blocked('unsupported signed evidence')
        return data

    def recent_destination_evidence(self, path, principal, keys, *, lifetime, core_access=False):
        data = self.signed_evidence(path, principal, 'dev-pair-destination')
        if core_access and data.get('kind') == CORE_ACCESS_CUTOVER:
            keys = keys | {'kind', 'tailnet_addresses'}
        if core_access and data.get('kind') == WORKLOAD_ACCESS_CUTOVER:
            keys = keys | {'kind', 'tailnet_addresses', 'role_artifacts'}
        identity = self.destination_identity()
        if (set(data) != {'version', 'source_sha', 'issued_at', 'expires_at', *identity, *keys}
                or any(data.get(key) != value for key, value in identity.items())
                or type(data.get('issued_at')) is not int or type(data.get('expires_at')) is not int
                or not 0 <= time.time() - data['issued_at'] <= lifetime
                or not data['issued_at'] < data['expires_at'] <= data['issued_at'] + lifetime
                or data['expires_at'] <= time.time()):
            raise Blocked('destination evidence is stale or belongs to another machine/boot')
        self.destination_source(data['source_sha'])
        return data

    def validate_bootstrap_access(self, sources, console_receipt=None):
        self.attended_access = False
        if console_receipt is None:
            networks = validate_sources(sources)
            if self.root == Path('/'):
                peer = self.observed_ssh_peer()
                if peer and not any(peer['remote'] in ipaddress.ip_network(network) for network in networks):
                    raise Blocked('current live SSH source is outside declared bootstrap CIDRs')
            return networks
        if sources or os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_CLIENT') or self.ssh_ancestor():
            raise Blocked('console-based setup requires a separate out-of-band recovery route')
        if console_receipt == ATTENDED_RECEIPT:
            self.verify_attended_recovery(console_receipt)
            self.attended_access = True
            return []
        data = self.recent_destination_evidence(console_receipt, 'dev-pair-provider-console',
                                                {'provider', 'provider_vps_id', 'transport', 'reopened_root', 'public_ssh_denied'},
                                                lifetime=7200)
        if (data['provider'] != 'hostinger' or data['transport'] != 'out-of-band'
                or data['reopened_root'] is not True or data['public_ssh_denied'] is not True
                or type(data['provider_vps_id']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', data['provider_vps_id'])):
            raise Blocked('verified Hostinger out-of-band root recovery is required')
        return []

    def verify_attended_recovery(self, receipt):
        path = checked_file(receipt, secret=True)
        data = json.loads(path.read_bytes(), object_pairs_hook=relay.unique)
        identity = self.destination_identity()
        fields = {'schema', 'kind', 'source_sha', 'machine_id', 'boot_id', 'created_at', 'origin_session', 'confirmed_session', 'owner_checkout'}
        if (type(data) is not dict or set(data) != fields or type(data['schema']) is not int or data['schema'] != 1
                or data['kind'] != ATTENDED_ACCESS or any(data[key] != value for key, value in identity.items())
                or type(data['created_at']) is not int or not 0 <= time.time() - data['created_at'] <= 1800
                or any(type(data[key]) is not int or data[key] < 2 for key in ('origin_session', 'confirmed_session'))
                or data['origin_session'] == data['confirmed_session']):
            raise Blocked('separate current-boot attended recovery confirmation is required')
        self.destination_source(data['source_sha'], checkout=data['owner_checkout'])
        return data

    def ssh_ancestors(self, *, client_pid=None):
        pid = os.getppid() if client_pid is None else client_pid
        processes = []
        for _ in range(64):
            if pid < 2:
                return processes
            try:
                name = self.text(f'/proc/{pid}/comm').strip()
                if name.startswith(('sshd', 'dropbear')):
                    processes.append(pid)
                parent = re.search(r'^PPid:\s+([0-9]+)$', self.text(f'/proc/{pid}/status'), re.M)
                if parent is None:
                    break
                pid = int(parent[1])
            except OSError:
                break
        return None

    def ssh_ancestor(self):
        return self.ssh_ancestors() != []  # Unavailable ancestry is unresolved.

    def observed_ssh_peer(self, *, client_pid=None, transport=None):
        environment = os.environ if transport is None else transport
        connection = environment.get('SSH_CONNECTION')
        legacy = environment.get('SSH_CLIENT')
        if not connection:
            if legacy or client_pid is not None or self.ssh_ancestor():
                raise Blocked('SSH transport observed or unresolved; preserve full SSH_CONNECTION and retry')
            return None
        try:
            remote, remote_port, local, local_port = connection.split()
            remote, local = ipaddress.ip_address(remote), ipaddress.ip_address(local)
            if not all(re.fullmatch(r'[1-9][0-9]{0,4}', port) and int(port) <= 65535 for port in (remote_port, local_port)):
                raise ValueError()
            if legacy and legacy.split() != [str(remote), remote_port, local_port]:
                raise ValueError()
        except ValueError:
            raise Blocked('current SSH connection metadata is incomplete or inconsistent') from None
        ancestors = self.ssh_ancestors() if client_pid is None else self.ssh_ancestors(client_pid=client_pid)
        if not ancestors:
            raise Blocked('SSH connection is missing a verified live daemon ancestry')
        found = False
        for line in self.run('/usr/bin/ss', '-H', '-tnp', timeout=10).splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] != 'ESTAB':
                continue
            left, _, lport = fields[3].rpartition(':')
            right, _, rport = fields[4].rpartition(':')
            try:
                match = (ipaddress.ip_address(left.strip('[]')), lport, ipaddress.ip_address(right.strip('[]')), rport)
            except ValueError:
                continue
            pids = {int(pid) for pid in re.findall(r'pid=([1-9][0-9]*),', line)}
            if match == (local, local_port, remote, remote_port) and pids.intersection(ancestors):
                found = True
                break
        if not found:
            raise Blocked('current SSH metadata does not bind an established owned connection')
        route = json.loads(self.run('/usr/sbin/ip', '-j', 'route', 'get', str(remote), 'from', str(local), timeout=10))
        if len(route) != 1 or type(route[0].get('dev')) is not str or route[0]['dev'] == 'lo':
            raise Blocked('live SSH peer route is unavailable')
        authenticated_core = any(re.match(rb'^sshd(?:-session)?: core(?:[ @]|\x00)',
                                          self.path(f'/proc/{pid}/cmdline').read_bytes()[:2048])
                                 for pid in ancestors)
        return {'remote': remote, 'local': str(local), 'device': route[0]['dev'], 'core': authenticated_core}

    def console_inspect(self, source=None):
        if os.geteuid() != 0:
            raise Blocked('open the selected VPS root terminal for inspection')
        peer = os.environ.get('SSH_CONNECTION', '').split()
        ssh_observed = peer or os.environ.get('SSH_CLIENT') or self.ssh_ancestors()
        return {**self.destination_identity(), 'source_sha': self.destination_source(source) if source else None,
                'host': self.text('/proc/sys/kernel/hostname').strip(), 'arch': platform.machine(),
                'os_release': self.text('/etc/os-release'), 'pid1': self.text('/proc/1/comm').strip(),
                'transport': 'ssh-observed' if ssh_observed else 'requires-provider-verification',
                'ssh_peer': str(ipaddress.ip_address(peer[0])) if peer else None,
                'selinux': self.text('/sys/fs/selinux/enforce').strip() or 'not observed',
                'selinux_config': self.text('/etc/selinux/config'), 'kernel_cmdline': self.text('/proc/cmdline'),
                'block_devices': self.run('/usr/bin/lsblk', '--json', '-o', 'NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS'),
                'capacity': self.run('/usr/bin/df', '-hT', '/', '/var'),
                'inodes': self.run('/usr/bin/df', '-i', '/', '/var'),
                'addresses': self.run('/usr/sbin/ip', '-brief', 'address'),
                'listeners': self.run('/usr/bin/ss', '-lntu'),
                'failed_services': (self.run('/usr/bin/systemctl', 'list-units', '--state=failed', '--no-legend', '--no-pager')
                                    if self.text('/proc/1/comm').strip() == 'systemd' else None)}

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
        ancestors = []
        for parent in p.parents:
            if parent == self.root:
                break
            ancestors.append(parent)
        for parent in reversed(ancestors):
            try:
                parent.mkdir(mode=0o755)
            except FileExistsError:
                continue
            fd = os.open(parent, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd, 0o755)
            finally:
                os.close(fd)
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

    def preflight(self, *, require_enforcing=True, managed_runtime=False):
        if os.geteuid() != 0:
            raise Blocked('root is required')
        release = dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']*)', self.text('/etc/os-release'), re.M))
        if release.get('ID') != 'fedora' or release.get('VERSION_ID') != '44':
            raise Blocked('only Fedora 44 is supported; no changes made')
        if platform.machine() not in ('x86_64', 'aarch64'):
            raise Blocked('only x86_64/aarch64 supported')
        if self.text('/proc/1/comm').strip() != 'systemd':
            raise Blocked('host PID 1 must be systemd')
        selinux = self.run('/usr/sbin/getenforce').strip()
        if selinux not in ('Disabled', 'Permissive', 'Enforcing'):
            raise Blocked('unknown live SELinux state')
        if require_enforcing and selinux != 'Enforcing':
            raise Blocked('SELinux must be enforcing; run selinux_bootstrap.py initial convergence first')
        managed = self.path('/var/lib/dev-pair-managed-storage.json')
        if require_enforcing and managed.exists():
            ready = self.path('/var/lib/dev-pair/.managed-storage-ready')
            if not ready.is_file() or ready.is_symlink() or ready.read_bytes() != managed.read_bytes():
                raise Blocked('finish the admitted managed filesystem before bootstrap')
        transition = self.path('/var/lib/dev-pair/selinux-bootstrap')
        if require_enforcing and (transition / 'intent.json').exists():
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
        owned_candidates = []
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
            if managed_runtime and proto == 'tcp' and port in CHECKLIST_PORTS:
                owned_candidates.append(line)
                continue
            if not allowed and proto == 'tcp' and port not in CHECKLIST_PORTS:
                allowed = self.peerapi_listener(line, host.strip('[]'))
            if not allowed and proto == 'udp' and port.isdigit() and 60000 <= int(port) <= 61000:
                allowed = self.mosh_listener(line)
            if not allowed:
                raise Blocked('unexpected listener: host is not vanilla; inspect inventory before proceeding')
        checklist_ready = managed_runtime and any(os.path.lexists(self.path(CHECKLIST_CONTROL + '/' + name))
                                                  for name in ('ready.json', 'managed-listener.json'))
        if owned_candidates or checklist_ready:
            if selinux != 'Enforcing':
                raise Blocked('managed runtime listener requires enforcing SELinux')
            self.managed_runtime_listeners(owned_candidates)
        if batch is not None:
            try:
                if self.resolved_service(snapshot=True)!=batch:raise ValueError()
            except (Blocked,OSError,ValueError):
                raise Blocked('unexpected listener: resolved identity changed') from None
        return {'os': 'Fedora 44', 'arch': platform.machine(), 'selinux': selinux,
                'phase': 'bootstrap', 'ssh_cutover': 'independent evidence required'}

    def runtime_record(self, path, *, optional=False, private=True):
        try:
            file = checked_file(self.path(path), secret=private)
            if file.stat().st_nlink != 1:
                raise ValueError('managed runtime record has ambiguous ownership')
            raw = file.read_text()
        except FileNotFoundError:
            if optional and not os.path.lexists(self.path(path)):
                return None
            raise
        return json.loads(raw, object_pairs_hook=relay.unique)

    def runtime_account(self):
        account = pwd.getpwnam(CHECKLIST_OWNER)
        if (account.pw_uid != account.pw_gid or account.pw_uid < 1000
                or account.pw_dir != CHECKLIST_HOME or account.pw_shell != '/usr/sbin/nologin'
                or os.getgrouplist(CHECKLIST_OWNER, account.pw_gid) != [account.pw_gid]):
            raise ValueError('checklist runtime account changed')
        return account.pw_uid

    def runtime_user_command(self, uid, *args):
        run = f'/run/user/{uid}'
        return self.run('/usr/sbin/runuser', '-u', CHECKLIST_OWNER, '--', '/usr/bin/env', '-i',
                        'PATH=/usr/bin:/usr/sbin', 'HOME=' + CHECKLIST_HOME, 'LC_ALL=C.UTF-8',
                        'XDG_RUNTIME_DIR=' + run, 'DBUS_SESSION_BUS_ADDRESS=unix:path=' + run + '/bus',
                        *args, timeout=5)

    def runtime_unit(self, unit, properties, *, uid=None):
        from systemd_service_profile import manager_properties

        args = ('show', '--all', '--property=' + ','.join(properties), unit)
        command = ('/usr/bin/systemctl',)
        raw = (self.run(*command, *args, timeout=5) if uid is None else
               self.runtime_user_command(uid, *command, '--user', *args))
        facts = manager_properties(raw, properties)
        if (facts['Id'] != unit
                or facts['ActiveState'] != 'active' or not re.fullmatch(r'[1-9][0-9]{0,9}', facts['MainPID'])
                or int(facts['MainPID']) <= 1
                or not re.fullmatch(r'/(?:[A-Za-z0-9_@./-]|\\x[0-9a-f]{2})+', facts['ControlGroup'])
                or '..' in facts['ControlGroup'].split('/')):
            raise ValueError('managed runtime service identity is unavailable')
        return facts

    def runtime_process(self, pid, uid):
        start = self.resolved_process_start(pid)
        proc = self.path('/proc/' + pid)
        status = (proc / 'status').read_text()
        for field in ('Uid', 'Gid'):
            ids = [line.split()[1:] for line in status.splitlines() if line.startswith(field + ':')]
            if ids != [[str(uid)] * 4]:
                raise ValueError('managed socket process has a foreign identity')
        cgroup = (proc / 'cgroup').read_text().splitlines()
        exe = str((proc / 'exe').readlink())
        if len(cgroup) != 1 or not cgroup[0].startswith('0::/') or self.resolved_process_start(pid) != start:
            raise ValueError('managed socket process changed during observation')
        return exe, cgroup[0][3:], start

    def runtime_executable(self, actual, expected):
        trusted = [self.path(path).resolve(strict=True) for path in expected if self.path(path).exists()]
        observed = self.path(actual)
        if not actual.startswith('/') or observed not in trusted:
            raise ValueError('managed listener uses a foreign executable')
        self.runtime_protected_file(observed)

    @staticmethod
    def runtime_protected_file(script):
        for path in (script, *script.parents):
            node = path.lstat()
            if node.st_uid != 0 or node.st_mode & 0o022 or stat.S_ISLNK(node.st_mode):
                raise ValueError('managed launch code is mutable')
        node = script.lstat()
        if not stat.S_ISREG(node.st_mode) or node.st_nlink != 1:
            raise ValueError('managed launch file is ambiguous')

    def runtime_socket(self, line):
        fields = line.split(maxsplit=6)
        if len(fields) != 7 or fields[:2] != ['tcp', 'LISTEN']:
            raise ValueError('managed socket address is unavailable')
        match = re.fullmatch(r'users:\(\("[^"\n]+",pid=([1-9][0-9]{0,9}),fd=([0-9]{1,7})\)\)', fields[6])
        if match is None:
            raise ValueError('managed socket has ambiguous ownership')
        pid, fd = match.groups()
        target = str(self.path(f'/proc/{pid}/fd/{fd}').readlink())
        if not re.fullmatch(r'socket:\[[1-9][0-9]{0,19}\]', target):
            raise ValueError('managed listener descriptor changed')
        return fields[4], pid, fd, target

    def runtime_handoff(self, socket, uid, boot, managed):
        import systemd_service_profile as profile

        endpoint, pid, _, descriptor = socket
        unit = CHECKLIST_UNIT.replace('@.', f'@{uid}.')
        fragment = '/etc/systemd/system/' + CHECKLIST_UNIT
        profile.protected(self.path(fragment), 0, 8192, mode=0o644)
        properties = ('Id', 'LoadState', 'MainPID', 'ActiveState', 'ControlGroup', 'User', 'Group', 'FragmentPath',
                      'DropInPaths', 'ExecStart', 'ExecMainStartTimestampMonotonic', *profile.PROPERTIES)
        facts = self.runtime_unit(unit, properties)
        profile.observe(facts, (CHECKLIST_OVERRIDE,) if managed else (), self.path, self.run)
        if (endpoint != '127.0.0.1:19425' or facts['LoadState'] != 'loaded'
                or facts['MainPID'] != pid or facts['User'] != CHECKLIST_OWNER
                or facts['Group'] != CHECKLIST_OWNER or facts['FragmentPath'] != fragment
                or not facts['ControlGroup'].startswith('/system.slice/')
                or not facts['ControlGroup'].endswith('/' + unit)
                or not re.fullmatch(r'[1-9][0-9]{0,19}', facts['ExecMainStartTimestampMonotonic'])):
            raise ValueError('checklist handoff differs from its protected service')
        if managed:
            site, host, observed = self.runtime_selected_host(boot)
            artifact = host['artifact_sha256']
            profile.protected(self.path(CHECKLIST_OVERRIDE), 0, 8192, mode=0o644)
            profile.protected(self.path(CHECKLIST_ENTRY), 0, 65536, mode=0o755)
            command = json.loads(self.run(CHECKLIST_ENTRY, '--describe', timeout=5), object_pairs_hook=relay.unique)
            expected = ['/usr/bin/python3', '-EBs',
                        f'/usr/libexec/dev-pair/host-releases/{artifact}/tools/host_handoff.py', *CHECKLIST_ARGS]
            if command != expected or not profile.exec_start_matches(facts['ExecStart'], CHECKLIST_ENTRY):
                raise ValueError('managed handoff launch release changed')
            command_hash = hashlib.sha256(json.dumps(command, sort_keys=True, separators=(',', ':'),
                                                     ensure_ascii=False).encode()).hexdigest()
            actual = {'unit': unit, 'pid': int(pid), 'started': int(facts['ExecMainStartTimestampMonotonic']),
                      'command_sha256': command_hash, 'socket_inode': descriptor[8:-1]}
        else:
            command = ['/usr/bin/python3', '-EBs', '/usr/libexec/dev-pair/checklist/tools/host_handoff.py',
                       *CHECKLIST_ARGS]
            self.runtime_protected_file(self.path(command[2]))
            if not profile.exec_start_matches(facts['ExecStart'], ' '.join(command)):
                raise ValueError('direct handoff launch command changed')
        exe, cgroup, start = self.runtime_process(pid, uid)
        self.runtime_executable(exe, (command[0],))
        with self.path('/proc/' + pid + '/cmdline').open('rb') as stream:
            raw = stream.read(4097)
        if cgroup != facts['ControlGroup'] or raw != b'\0'.join(x.encode() for x in command) + b'\0':
            raise ValueError('checklist handoff listener differs from the selected process')
        if managed:
            self.runtime_handoff_observation(observed, actual, site)
        if (self.resolved_process_start(pid) != start or self.runtime_unit(unit, properties) != facts
                or managed and self.runtime_selected_host(boot) != (site, host, observed)):
            raise ValueError('checklist handoff listener differs from the selected process')

    def runtime_selected_host(self, boot):
        import systemd_service_profile as profile

        root = '/var/lib/dev-pair/renewal'
        site = self.runtime_record(root + '/site-current.json')
        if type(site) is not str or not re.fullmatch(r'[0-9a-f]{64}', site):
            raise ValueError('managed handoff current site selection is invalid')
        raw = profile.protected(self.path(root + '/releases/' + site + '.json'), 0, 65536, mode=0o600)
        release = json.loads(raw, object_pairs_hook=relay.unique)
        host = release['components']['host']
        if (hashlib.sha256(raw).hexdigest() != site or type(release['schema']) is not int or release['schema'] != 1
                or set(host) != {'source_revision', 'config_sha256', 'artifact_sha256'}
                or not re.fullmatch(r'[0-9a-f]{40}', host['source_revision'])
                or any(not re.fullmatch(r'[0-9a-f]{64}', host[key]) for key in ('config_sha256', 'artifact_sha256'))):
            raise ValueError('managed handoff site release is not the reviewed host component')
        selector_path = self.path('/var/lib/dev-pair/renewal-fence/selected-host.json')
        selector = json.loads(profile.protected(selector_path, 0, 4096, mode=0o644), object_pairs_hook=relay.unique)
        observed = self.runtime_record(root + '/host-observed.json')
        launch = '/usr/libexec/dev-pair/host-releases/' + host['artifact_sha256']
        if (selector != {'schema': 1, 'artifact_sha256': host['artifact_sha256']} or type(selector['schema']) is not int
                or self.runtime_record(root + '/host-selection.json') != host
                or set(observed) != {'schema', 'boot_id', 'component', 'launch_root', 'role_launch_seconds',
                                     'hostname', 'platform', 'selinux', 'handoff'}
                or type(observed['schema']) is not int or observed['schema'] != 2 or observed['boot_id'] != boot
                or observed['component'] != host or observed['launch_root'] != launch
                or observed['hostname'] != self.text('/proc/sys/kernel/hostname').strip()
                or observed['platform'] != 'fedora-44' or observed['selinux'] != 'enforcing'
                or type(observed['role_launch_seconds']) is not int or not 90 <= observed['role_launch_seconds'] <= 169):
            raise ValueError('managed handoff release differs from current site or boot observation')
        return site, host, observed

    def runtime_handoff_observation(self, observed, actual, site):
        import systemd_service_profile as profile

        previous = observed['handoff']
        if (type(previous) is not dict or set(previous) != set(actual)
                or previous['unit'] != actual['unit'] or previous['command_sha256'] != actual['command_sha256']
                or type(previous['pid']) is not int or previous['pid'] <= 1
                or type(previous['started']) is not int or previous['started'] <= 0
                or type(previous['socket_inode']) is not str
                or not re.fullmatch(r'[1-9][0-9]{0,19}', previous['socket_inode'])):
            raise ValueError('managed handoff lacks its exact authorized process observation')
        if previous == actual:
            return
        if actual['started'] <= previous['started']:
            raise ValueError('managed handoff process or inode changed without a later start')
        verifier = '/usr/libexec/dev-pair/renewal/host-release'
        profile.protected(self.path(verifier), 0, 65536, mode=0o755)
        # U measures the live endpoint again under its exact selected host. The
        # verify entry is read-only and never restarts or reselects a unit.
        fresh = json.loads(self.run(verifier, 'verify', site, timeout=20), object_pairs_hook=relay.unique)
        if fresh != {**observed, 'handoff': actual}:
            raise ValueError('new handoff process lacks a matching current site observation')

    def runtime_app(self, socket, uid, dns):
        state = self.runtime_record(CHECKLIST_CONTROL + '/release.json')
        active = state['active']
        subject = active['subject']
        if (state['version'] != 2 or state['pending'] is not None or state['route_pending'] is not False
                or active.get('quarantined') or active['compatibility'] != 'checklist-sqlite-v1'
                or active['dns_name'] != dns or not re.fullmatch(r'[0-9a-f]{64}', active['image_id'])
                or not re.fullmatch(r'ghcr\.io/oso-gato/dev-pair/checklist@sha256:[0-9a-f]{64}', subject)
                or socket[0] != '127.0.0.1:18279'):
            raise ValueError('checklist app lacks a settled authorized release')
        unit = CHECKLIST_APP + '.service'
        source = f'/etc/containers/systemd/users/{uid}/{CHECKLIST_APP}.container'
        data = checked_file(self.path(source)).read_bytes()
        if hashlib.sha256(data).hexdigest() != active['unit_sha256']:
            raise ValueError('protected checklist Quadlet differs from selected release')
        keys = ('Id', 'MainPID', 'ActiveState', 'ControlGroup', 'SourcePath', 'FragmentPath', 'DropInPaths', 'InvocationID')
        facts = self.runtime_unit(unit, keys, uid=uid)
        generators = {'generator', 'generator.early', 'generator.late'}
        manager = f'/user.slice/user-{uid}.slice/user@{uid}.service/'
        if (facts['SourcePath'] != source or facts['DropInPaths'] != ''
                or facts['FragmentPath'] not in {f'/run/user/{uid}/systemd/{where}/{unit}' for where in generators}
                or not re.fullmatch(r'[0-9a-f]{32}', facts['InvocationID'])
                or not facts['ControlGroup'].startswith(manager) or not facts['ControlGroup'].endswith('/' + unit)):
            raise ValueError('checklist app does not use the selected user-managed Quadlet')
        conmon, supervisor, _ = self.runtime_process(facts['MainPID'], uid)
        self.runtime_executable(conmon, ('/usr/bin/conmon',))
        if supervisor != facts['ControlGroup']:
            raise ValueError('checklist app supervisor is outside its named service')
        graph = '/var/lib/dev-pair/checklist-live/graph'
        runroot = f'/run/user/{uid}/dev-pair-checklist-live-runroot'
        config = '/etc/dev-pair/checklist/live-containers.conf'
        checked_file(self.path(config))

        def podman(*argv):
            return self.runtime_user_command(uid, '/usr/bin/env', 'CONTAINERS_CONF=' + config,
                'TMPDIR=/var/lib/dev-pair/checklist-live/image-copy', '/usr/bin/podman', '--remote=false', '--root', graph,
                '--runroot', runroot, *argv)

        container, = json.loads(podman('container', 'inspect', CHECKLIST_APP), object_pairs_hook=relay.unique)
        container_id = container['Id']
        if (not re.fullmatch(r'[0-9a-f]{64}', container_id) or container['Name'].removeprefix('/') != CHECKLIST_APP
                or container['Image'].removeprefix('sha256:') != active['image_id']
                or container['State']['Running'] is not True
                or podman('port', CHECKLIST_APP, '8000/tcp').strip() != socket[0]):
            raise ValueError('checklist rootless image or published port differs')
        exe, cgroup, start = self.runtime_process(socket[1], uid)
        self.runtime_executable(exe, ('/usr/libexec/podman/rootlessport', '/usr/bin/pasta'))
        path = cgroup.split('/')
        if (cgroup != facts['ControlGroup'] and not (cgroup.startswith(manager) and
                ({f'libpod-{container_id}.scope', f'libpod-conmon-{container_id}.scope'} & set(path)))):
            raise ValueError('checklist proxy socket does not belong to the selected app')
        route = json.loads(self.run('/usr/bin/tailscale', 'serve', 'status', '--json', timeout=5),
                           object_pairs_hook=relay.unique)
        if (route != {'TCP': {'443': {'HTTPS': True}}, 'Web': {f'{dns}:443': {
                'Handlers': {'/': {'Proxy': 'http://127.0.0.1:18279'}}}}}
                or self.resolved_process_start(socket[1]) != start):
            raise ValueError('Tailscale Serve differs from the exact checklist route')

    def runtime_serve(self, sockets):
        guard = self.verify_workload_access()
        live, dns = self.tailscale_state()
        if guard['target']['dns_name'] != dns:
            raise ValueError('checklist tailnet address differs from admitted cutover')
        unit = 'tailscaled.service'
        facts = self.runtime_unit(unit, ('Id', 'MainPID', 'ActiveState', 'ControlGroup'))
        exe, cgroup, start = self.runtime_process(facts['MainPID'], 0)
        self.runtime_executable(exe, ('/usr/sbin/tailscaled',))
        if cgroup != '/system.slice/' + unit or facts['ControlGroup'] != cgroup:
            raise ValueError('Serve does not use the managed tailscaled process')
        for endpoint, pid, _, _ in sockets:
            host = endpoint.rpartition(':')[0].strip('[]')
            if pid != facts['MainPID'] or host not in live.get('TailscaleIPs', ()):
                raise ValueError('Serve socket is outside the enrolled tailnet addresses')
        if self.resolved_process_start(facts['MainPID']) != start:
            raise ValueError('Serve process changed while observing')
        return dns

    def managed_runtime_listeners(self, lines):
        """Read only the installed checklist and Serve proofs for opt-in runtime callers."""
        try:
            boot = self.destination_identity()
            prepared = self.runtime_record(STATE + '/prepared')
            if (prepared != self.runtime_record(STATE + '/desired.json') or prepared['schema'] != 1
                    or prepared['standards_sha'] != STANDARDS or prepared['operator'] != 'core'
                    or not re.fullmatch(r'[0-9a-f]{64}', prepared['bootstrap_sha256'])):
                raise ValueError('protected host preparation is unavailable')
            setup = self.runtime_record(CHECKLIST_CONTROL + '/provision.json')
            uid = self.runtime_account()
            if (setup['version'] != 1 or setup['machine_id'] != boot['machine_id'] or setup['uid'] != uid
                    or not re.fullmatch(r'[0-9a-f]{40}', setup['platform_sha'])):
                raise ValueError('checklist provisioning does not match this host')
            ready = self.runtime_record(CHECKLIST_CONTROL + '/ready.json', optional=True)
            managed = os.path.lexists(self.path(CHECKLIST_OVERRIDE))
            commissioning = self.runtime_record(CHECKLIST_CONTROL + '/managed-listener.json', optional=True)
            if managed:
                checked_file(self.path(CHECKLIST_OVERRIDE))
                site = self.runtime_record('/var/lib/dev-pair/renewal/site-current.json')
                if commissioning['version'] != 2 or not re.fullmatch(r'[0-9a-f]{64}', site):
                    raise ValueError('managed checklist commissioning is unavailable')
            elif commissioning is not None:
                raise ValueError('managed checklist service cannot return to commissioning')
            if ready != setup or managed and commissioning['phase'] != 'ready':
                if (not managed or ready not in (None, setup) or commissioning['phase'] not in ('observe', 'queue-recovery', 'recovery')
                        or commissioning['boot'] != boot['boot_id'] or commissioning['site'] != site
                        or self.runtime_record('/var/lib/dev-pair/renewal-fence/frozen', private=False) != 'boot'):
                    raise ValueError('checklist runtime is outside protected commissioning')

            sockets = [self.runtime_socket(line) for line in lines]
            handoff = [row for row in sockets if row[0].endswith(':19425')]
            app = [row for row in sockets if row[0].endswith(':18279')]
            serve = [row for row in sockets if row[0].endswith(':443')]
            if len(handoff) > 1 or len(app) > 1 or len(serve) > 2 or len({row[0] for row in sockets}) != len(sockets):
                raise ValueError('multiple unexpected checklist listener addresses')
            if not handoff and (ready is not None or commissioning is not None):
                raise ValueError('the authorized checklist executor has no observed listener')
            if handoff:
                self.runtime_handoff(handoff[0], uid, boot['boot_id'], managed)
            if app or serve:
                if not managed or ready != setup or commissioning['phase'] != 'ready' or len(app) != 1:
                    raise ValueError('public release proof is unavailable for checklist app')
                dns = self.runtime_serve(serve)
                self.runtime_app(app[0], uid, dns)
            repeated = [line for line in self.run('/usr/bin/ss', '-H', '-lntup', timeout=5).splitlines()
                        if len(line.split()) >= 5 and line.split()[0] == 'tcp'
                        and line.split()[4].rpartition(':')[2] in CHECKLIST_PORTS]
            if sorted(self.runtime_socket(line) for line in repeated) != sorted(sockets) or self.destination_identity() != boot:
                raise ValueError('managed listener inventory changed during observation')
        except (OSError, ValueError, TypeError, KeyError, IndexError, Blocked, subprocess.SubprocessError):
            raise Blocked('unexpected listener: managed checklist or tailnet ownership is unverified') from None

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
        witness['source_sha'] = getattr(self, 'development_host_source', None) or target.get('source_sha')
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
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != (0 if self.root == Path('/') else os.getuid())):
                raise Blocked('bootstrap lock must be a protected regular file')
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
                if created:
                    os.fchmod(fd, mode if leaf else 0o755)
                if leaf:
                    if created:
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
                if not role_subordinate_range(content, name, fields[2], substart):
                    wanted = f'{name}:{substart}:65536'
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
        attended = getattr(self, 'attended_access', False)
        if attended:
            outside = '*,!100.64.0.0/10,!fd7a:115c:a1e0::/48'
            ssh += (f'Match User {name} Address {outside}\n    DenyUsers {name}\nMatch all\n'
                    f'Match User {name} LocalAddress {outside}\n    DenyUsers {name}\nMatch all\n')
        target = '/etc/ssh/sshd_config.d/00-dev-pair-operator.conf'
        created = not self.path(target).exists()
        self.atomic(target, ssh, mode=0o600)
        try:
            self.run('/usr/sbin/sshd', '-t')
            probe = f'user={name},host=bootstrap,addr=100.64.0.1'
            if attended:
                probe += ',laddr=100.64.0.2'
            effective = self.run('/usr/sbin/sshd', '-T', '-C', probe)
            required = ('authenticationmethods publickey', 'passwordauthentication no',
                        'kbdinteractiveauthentication no', 'pubkeyauthentication yes',
                        f'authorizedkeysfile /etc/ssh/dev-pair-keys/{name}')
            if not all(x in effective.splitlines() for x in required):
                raise Blocked('effective operator SSH settings conflict')
            if attended:
                def denied(config):
                    return any(line.split()[0] == 'denyusers' and name in line.split()[1:]
                               for line in config.splitlines() if line.strip())
                if denied(effective):
                    raise Blocked('attended core route is denied on the tailnet')
                for conditions in ('addr=192.0.2.1,laddr=100.64.0.2', 'addr=100.64.0.1,laddr=192.0.2.2',
                                   'addr=2001:db8::1,laddr=fd7a:115c:a1e0::2',
                                   'addr=fd7a:115c:a1e0::1,laddr=2001:db8::2'):
                    outside_config = self.run('/usr/sbin/sshd', '-T', '-C', f'user={name},host=bootstrap,{conditions}')
                    if not denied(outside_config):
                        raise Blocked('attended core account has an SSH route outside the tailnet')
            self.run('/usr/bin/systemctl', 'reload', 'sshd.service')
        except BaseException:
            # Never leave a newly introduced invalid fragment active after a failed validation.
            if created:
                self.path(target).unlink(missing_ok=True)
            raise

    def prepare(self, name, key, sources, gptbox_context=None, expected_context=None, *, password=None,
                source_check=None, console_receipt=None):
        return self._converge_host(name,key,sources,gptbox_context,expected_context,password=password,
                                   source_check=source_check,console_receipt=console_receipt)

    def _host_prerequisites(self, name, key, sources, context, expected, *, password=None, source_check=None,
                            development_host=False, console_receipt=None):
        # The caller holds the global bootstrap lock through readiness publication.
        return self._converge_host(name,key,sources,context,expected,password=password,source_check=source_check,
                                   host_only=True,locked=True,development_host=development_host,console_receipt=console_receipt)

    def _host_desired(self, name, sources, expected_context):
        desired = {'schema': 1, 'standards_sha': STANDARDS, 'source_baseline': SOURCE_BASELINE,
                           'bootstrap_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           'gptbox_context_sha256': expected_context, 'operator': name,
                           'keys_source': KEYS_URL, 'bootstrap_sources': sources}
        if not sources:
            desired['bootstrap_transport'] = ATTENDED_ACCESS if getattr(self, 'attended_access', False) else ACCESS_MODE
        return json.dumps(desired, sort_keys=True) + '\n'

    def _reject_development_host_intent(self):
        path = self.path(DEVELOPMENT_HOST_INTENT)
        if path.exists() or path.is_symlink():
            raise Blocked('bootstrap state belongs to the development host preparation')

    def _converge_host(self, name, key, sources, gptbox_context=None, expected_context=None, *, password=None,
                       source_check=None,host_only=False,locked=False,development_host=False,console_receipt=None):
        self.mark_prepare_step('input-admission')
        if development_host and (not host_only or not locked or gptbox_context is None
                                 or not callable(source_check) or not callable(key)):
            raise Blocked('development host prerequisites require locked exact-source admission')
        if gptbox_context is not None and (not isinstance(expected_context, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_context)):
            raise Blocked('a separately trusted context SHA256 is required before preparation')
        sources = self.validate_bootstrap_access(sources, console_receipt)
        connection = os.environ.get('SSH_CONNECTION')
        if connection:
            try:
                remote = ipaddress.ip_address(connection.split()[0])
            except (IndexError, ValueError):
                raise Blocked('invalid current SSH source') from None
            if not any(remote in ipaddress.ip_network(c) for c in sources):
                raise Blocked('current SSH source is outside declared bootstrap CIDRs')
        if name != 'core' or (password is None and not self.path(f'{STATE}/operator-password-set').exists()):
            raise Blocked('core operator and securely supplied password are required')
        self.mark_prepare_step('host-preflight')
        self.preflight()
        if gptbox_context is not None:
            self.mark_prepare_step('context-content')
            if development_host:
                self.check_gptbox_inputs(gptbox_context, expected_context, expected_role='development')
            else:
                self.check_gptbox_inputs(gptbox_context, expected_context)
            if not development_host and self.path('/usr/bin/git').exists():
                self.mark_prepare_step('context-source')
                _,_,host_manifest=self.validate_gptbox_context(gptbox_context, expected_context)
        with contextlib.nullcontext() if locked else self.lock():
            if not development_host:
                self._reject_development_host_intent()
            if json.loads(self.text(CUTOVER, '{}'), object_pairs_hook=relay.unique).get('phase') == 'applying':
                raise Blocked('access cutover interrupted; finish cutover before preparing the host again')
            if gptbox_context is not None:
                if not self.path('/usr/bin/git').exists():
                    self.step('git-prerequisite', lambda: self.run('/usr/bin/dnf', '-y',
                              '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--disablerepo=*',
                              '--enablerepo=fedora', '--enablerepo=updates', 'install', 'git-core'))
                self.mark_prepare_step('context-source')
                # Full source verification precedes desired binding, accounts, ingress and normal packages.
                if development_host:
                    self.mark_prepare_step('adapter-source-and-upstream')
                    host_manifest = source_check()
                    self.development_host_source = host_manifest['source_sha']
                    key = key()
                else:
                    _,_,host_manifest=self.validate_gptbox_context(gptbox_context, expected_context)
                    if source_check:
                        self.mark_prepare_step('adapter-source-and-upstream')
                        source_check()
            self.mark_prepare_step('desired-state')
            desired = self._host_desired(name, sources, expected_context)
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
                if development_host:
                    # The development caller publishes only after the native phase exits.
                    return ready
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

    def check_gptbox_inputs(self, context, expected, *, expected_role='maintenance'):
        """Python-only input checks before any mutation; does not admit source or runtime."""
        if expected_role not in ('maintenance', 'development'):
            raise Blocked('unsupported expected gptbox context role')
        if platform.machine() != 'x86_64':
            raise Blocked('current pinned Codex context supports x86_64 builds only')
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
            if manifest['role'] != expected_role:
                raise Blocked(f'this operation accepts only {expected_role}-role gptbox contexts')
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

    def _reject_unowned_bootstrap_table(self):
        tables = self.run('/usr/sbin/nft', 'list', 'tables')
        if 'dev_pair_bootstrap' in tables:
            raise Blocked('existing bootstrap nft table has no managed configuration')

    @staticmethod
    def guard_rules(sources, *, tailnet_only=False, retain_ssh=False):
        if tailnet_only and (sources or retain_ssh):
            raise Blocked('tailnet-only ingress cannot retain scoped temporary sources')
        scoped = [f'add rule inet dev_pair_bootstrap input {"ip6" if ":" in cidr else "ip"} saddr {cidr} tcp dport 22 accept'
                  for cidr in sources]
        before = 'add rule inet dev_pair_bootstrap input ct state established,related accept'
        drop = 'add rule inet dev_pair_bootstrap input iifname != "lo" iifname != "tailscale0" tcp dport '
        drop += ('{ 22, 443 }' if tailnet_only else '22') + ' drop'
        access = (['add rule inet dev_pair_bootstrap input tcp dport 22 accept'] if retain_ssh else [*scoped, drop])
        guard = GUARD.replace('{bootstrap_rules}\n', '').replace(before, '\n'.join([*access, before]))
        if tailnet_only:
            guard = guard.replace('"tailscale0" tcp dport 22 accept', '"tailscale0" tcp dport { 22, 443 } accept')
        return guard

    def guard(self, sources):
        if not self.path(GUARD_PATH).exists():
            self._reject_unowned_bootstrap_table()
        state = json.loads(self.text(CUTOVER, '{}'), object_pairs_hook=relay.unique)
        if state and state.get('phase') != 'complete':
            raise Blocked('access cutover interrupted; finish cutover before preparing the host again')
        guard = (self.guard_rules([], tailnet_only=True) if state else
                 self.guard_rules(sources, retain_ssh=getattr(self, 'attended_access', False)))
        self.atomic(GUARD_PATH, guard, mode=0o600)
        self.atomic('/etc/systemd/system/dev-pair-bootstrap-guard.service', UNIT, mode=0o644)
        self.run('/usr/sbin/nft', '--check', '-f', str(self.path(GUARD_PATH)))
        self.run('/usr/bin/systemctl', 'daemon-reload')
        self.run('/usr/bin/systemctl', 'enable', 'dev-pair-bootstrap-guard.service')
        # nft -f commits its own table transaction atomically. Reapply on resume to reconcile live drift.
        self.run('/usr/sbin/nft', '-f', str(self.path(GUARD_PATH)))
        self.run('/usr/bin/systemctl', 'start', 'dev-pair-bootstrap-guard.service')

    def enroll(self, secret, tailnet, *, browser=None):
        self.preflight()
        if (secret is None) == (browser is None) or browser is not None and not callable(browser):
            raise Blocked('choose exactly one protected key or interactive browser enrollment')
        if secret is not None:
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
                    command = ('/usr/bin/tailscale', 'up', '--accept-routes=false', '--accept-dns=false', '--ssh=false',
                               '--advertise-exit-node=false', '--netfilter-mode=off')
                    if browser is None:
                        self.step('enroll', lambda: self.run(*command, '--auth-key=file:' + str(secret), '--timeout=60s'))
                    else:
                        self.step('enroll', lambda: browser((*command, '--timeout=10m')))
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

    def tailscale_state(self):
        accepted = json.loads(checked_file(self.path(f'{STATE}/node.json')).read_text(), object_pairs_hook=relay.unique)
        live = json.loads(self.run('/usr/bin/tailscale', 'status', '--json'), object_pairs_hook=relay.unique)
        tailnet, node = self.identity_fields(live)
        own = live.get('Self') or {}
        dns = own.get('DNSName', '')
        if (accepted != {'tailnet': tailnet, 'node_id': node} or not tailnet or not node
                or live.get('BackendState') != 'Running' or own.get('Online') is not True
                or type(dns) is not str or not re.fullmatch(r'erebus\.[a-z0-9-]+\.ts\.net\.?', dns)):
            raise Blocked('live Tailscale identity differs from admitted erebus node')
        return live, dns.rstrip('.')

    def guard_hash(self):
        table = json.loads(self.run('/usr/sbin/nft', '-j', '-s', 'list', 'table', 'inet', 'dev_pair_bootstrap'),
                           object_pairs_hook=relay.unique)['nftables']
        normalized = []
        for entry in table:
            if 'metainfo' not in entry:
                normalized.append({kind: {key: value for key, value in data.items() if key != 'handle'}
                                   for kind, data in entry.items()})
        if not normalized:
            raise Blocked('live ingress guard unavailable')
        return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()

    def verify_final_guard(self):
        state = json.loads(checked_file(self.path(CUTOVER)).read_text(), object_pairs_hook=relay.unique)
        if (state.get('phase') != 'complete' or state.get('scope') not in (None, 'core')
                or state.get('guard_sha256') != self.guard_hash()
                or checked_file(self.path(GUARD_PATH)).read_text() != self.guard_rules([], tailnet_only=True)
                or checked_file(self.path(SSH_CUTOVER)).read_text() != SSH_CUTOVER_CONFIG):
            raise Blocked('tailnet-only destination firewall and SSH cutover are unverified')
        return state

    def verify_workload_access(self, *, recovery_release=None):
        from job_protocol import require_workload_access

        state = self.verify_final_guard()
        if state.get('scope') is not None:
            raise Blocked('independent workload access checks have not been admitted')
        roles = self.retained_workload_roles(state)
        if roles:
            fenced = recovery_release is not None and (self.own_workload_rollback(recovery_release) or
                                                       self.own_candidate_workload_activation(recovery_release))
            if fenced:
                selected = self.fenced_workload_placement(recovery_release)
            else:
                selected = self.access_workload_selection()
            if selected != roles:
                approved = self.admitted_candidate_workload(selected['release_sha256'], state)
                if approved is None or approved['role_artifacts'] != selected:
                    raise Blocked('independent workload access checks are required for the current role placement')
                state = {**state, **approved}
                roles = selected
        reference = roles['release_sha256'] if roles else None
        require_workload_access(self.path('/var/lib/dev-pair'), release=reference)
        return state

    def publish_workload_gate(self, phase, roles=None):
        from job_protocol import WORKLOAD_ACCESS

        path = '/var/lib/dev-pair/' + WORKLOAD_ACCESS
        before = checked_file(self.path(path)).read_text() if os.path.lexists(self.path(path)) else None
        try:
            self.prepare_workload_lease()
        except (Blocked, OSError, ValueError):
            held = json.dumps({'schema': 1, 'phase': 'held', 'release_sha256': None, 'images': None}, sort_keys=True) + '\n'
            self.atomic(path, held, mode=0o644, expected=before)
            raise
        images = {role: roles[role + '_image'] for role in ('maintenance', 'development', 'devbox')} if roles else None
        raw = json.dumps({'schema': 1, 'phase': phase, 'release_sha256': roles['release_sha256'] if roles else None,
                          'images': images}, sort_keys=True) + '\n'
        self.atomic(path, raw, mode=0o644, expected=before)

    def prepare_workload_lease(self):
        from job_protocol import WORKLOAD_LEASE

        public = '/var/lib/dev-pair/' + WORKLOAD_LEASE
        historical = '/var/lib/dev-pair/renewal/driver.lock'
        old, new = self.path(historical), self.path(public)
        if not os.path.lexists(old.parent):
            self.atomic(public, '', mode=0o644)
            return
        self.directory('/var/lib/dev-pair/renewal', mode=0o700)
        self.directory('/var/lib/dev-pair/renewal-fence', mode=0o755)
        if not os.path.lexists(old) and not os.path.lexists(new):
            self.atomic(historical, '', mode=0o600)
        existing = old if os.path.lexists(old) else new
        other = new if existing == old else old
        checked_file(existing)
        fd = os.open(existing, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            node = os.fstat(fd)
            if node.st_nlink not in (1, 2) or node.st_size or stat.S_IMODE(node.st_mode) not in (0o600, 0o644):
                raise Blocked('protected workload dispatch lease differs from its fixed scope')
            os.fchmod(fd, 0o644)
            os.fsync(fd)
            try:
                os.link(existing, other, follow_symlinks=False)
            except FileExistsError:
                pass
            for path in (old, new):
                live = checked_file(path).lstat()
                if ((live.st_dev, live.st_ino, live.st_nlink) != (node.st_dev, node.st_ino, 2)
                        or stat.S_IMODE(live.st_mode) != 0o644):
                    raise Blocked('historical and current workload dispatch leases differ')
                parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        finally:
            os.close(fd)

    def refresh_workload_gate(self):
        import renewal

        with self.lock():
            state = self.verify_final_guard()
            self.verify_final_ssh()
            roles = self.retained_workload_roles(state)
            if state.get('scope') == 'core':
                self.publish_workload_gate('held')
            elif roles is None:
                self.publish_legacy_workload_gate(state)
            else:
                with renewal.Renewal(self.path('/var/lib/dev-pair'), None).lock(shared=True):
                    try:
                        live = self.access_workload_selection()
                    except (Blocked, OSError, ValueError, KeyError, TypeError):
                        self.publish_workload_gate('held')
                        raise
                    if live == roles:
                        self.publish_workload_gate('admitted' if 'role_artifacts' in state else 'legacy', roles)
                    else:
                        try:
                            approved = self.admitted_candidate_workload(live['release_sha256'], state)
                        except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                            self.publish_workload_gate('held')
                            raise
                        if approved and approved['role_artifacts'] == live:
                            self.publish_workload_gate('admitted', live)
                        else:
                            self.publish_workload_gate('held')

    def hold_changed_workload_access(self, release, *, acquire_lease=False):
        from job_protocol import WORKLOAD_ACCESS, workload_access_lease

        path = self.path(CUTOVER)
        data = json.loads(checked_file(path).read_text(), object_pairs_hook=relay.unique) if os.path.lexists(path) else {}
        roles = self.retained_workload_roles(data)
        if data.get('scope') == 'core' or not roles or roles['release_sha256'] != release:
            if acquire_lease:
                flag = self.path('/var/lib/dev-pair/' + WORKLOAD_ACCESS)
                if os.path.lexists(flag) and json.loads(checked_file(flag).read_text(), object_pairs_hook=relay.unique) == {
                        'schema': 1, 'phase': 'held', 'release_sha256': None, 'images': None}:
                    return
                with workload_access_lease(self.path('/var/lib/dev-pair'), exclusive=True):
                    self.publish_workload_gate('held')
            else:
                self.publish_workload_gate('held')

    @staticmethod
    def retained_workload_roles(state):
        roles = state.get('role_artifacts')
        if roles is None and state.get('legacy_origin') == 'managed':
            roles = state.get('legacy_role_artifacts')
        return roles

    def managed_workload_present(self):
        paths = ('/var/lib/dev-pair/renewal', '/var/lib/dev-pair/renewal-fence/selected-host.json',
                 STATE + '/host-commissioning/intent.json')
        return any(os.path.lexists(self.path(path)) for path in paths)

    def original_legacy_origin(self, operations, boot):
        import renewal

        if not self.managed_workload_present():
            return {'legacy_origin': 'standalone'}
        try:
            operations.enter_context(renewal.Renewal(self.path('/var/lib/dev-pair'), None).lock(shared=True))
            roles = self.selected_workload_placement()
            site, _, _ = self.runtime_selected_host(boot)
            if site == roles['release_sha256']:
                return {'legacy_origin': 'managed', 'legacy_role_artifacts': roles}
        except (Blocked, OSError, ValueError, KeyError, TypeError):
            pass
        return {'legacy_origin': 'unverified'}

    def publish_legacy_workload_gate(self, state):
        roles = self.retained_workload_roles(state)
        if roles is not None:
            if self.access_workload_selection() == roles:
                self.publish_workload_gate('legacy', roles)
                return
        elif (state.get('legacy_origin') in (None, 'standalone') and 'legacy_role_artifacts' not in state
              and not self.managed_workload_present()):
            # Refresh the current admission without rewriting the original cutover.
            self.publish_workload_gate('legacy')
            return
        self.publish_workload_gate('held')

    def own_workload_rollback(self, release):
        import renewal

        attempt, state = renewal.Renewal(self.path('/var/lib/dev-pair'), None).transition()
        marker = self.path('/var/lib/dev-pair/renewal-fence/frozen')
        return (state is not None and state['phase'] in ('rolling-back', 'rollback-verifying', 'rollback-accepted')
                and state['request']['previous_sha256'] == release and os.path.lexists(marker)
                and renewal.read_json(marker) == attempt.name)

    def own_candidate_workload_activation(self, release):
        import renewal

        controller = renewal.Renewal(self.path('/var/lib/dev-pair'), None)
        attempt, state = controller.transition()
        marker = controller.root / 'renewal-fence/frozen'
        return (state is not None and state['phase'] in ('applying', 'verifying', 'accepted') and
                state['request']['scope'] in ('agent', 'stable') and state['request']['target_sha256'] == release and
                os.path.lexists(marker) and renewal.read_json(marker) == attempt.name)

    def fenced_workload_placement(self, reference):
        import renewal
        from renewal_site import role_artifacts

        controller = renewal.Renewal(self.path('/var/lib/dev-pair'), None)
        try:
            settled = self.access_workload_selection(allow_fenced=True)
        except Blocked:
            pass  # During a switch the execution selector advances before the committed selector.
        else:
            if settled['release_sha256'] != reference:
                raise Blocked('the fenced private placement selected another release')
            return settled
        if renewal.read_json(controller.control / 'site-current.json') != reference:
            raise Blocked('the fenced private placement has not been selected by its recovery executor')
        return role_artifacts(controller, reference)

    def admitted_candidate_workload(self, reference, state):
        import renewal
        from destination_observation import STABLE_CANDIDATE
        from renewal_site import CandidateAccess

        controller = renewal.Renewal(self.path('/var/lib/dev-pair'), None)
        stable = CandidateAccess(controller, self, kind=STABLE_CANDIDATE)
        observer = stable if os.path.lexists(stable.proof_path(reference)) else CandidateAccess(controller, self)
        return observer.admitted(reference, state)

    def restore_retained_workload_gate(self, reference):
        state = json.loads(self.text(CUTOVER, '{}'), object_pairs_hook=relay.unique)
        roles = self.retained_workload_roles(state)
        if roles is None or not (self.own_workload_rollback(reference) or self.own_candidate_workload_activation(reference)):
            return
        state = self.verify_final_guard()
        selected = self.fenced_workload_placement(reference)
        if selected == roles:
            phase = 'admitted' if 'role_artifacts' in state else 'legacy'
        else:
            approved = self.admitted_candidate_workload(reference, state)
            if approved is None or approved['role_artifacts'] != selected:
                return
            phase = 'admitted'
        self.verify_final_ssh()
        self.publish_workload_gate(phase, selected)

    def verify_final_ssh(self):
        self.run('/usr/sbin/sshd', '-t')
        required = {'permitrootlogin no', 'allowusers core', 'authenticationmethods publickey',
                    'passwordauthentication no', 'kbdinteractiveauthentication no'}
        transport = json.loads(self.text(STATE + '/desired.json', '{}'), object_pairs_hook=relay.unique).get('bootstrap_transport')
        for user in ('root', 'core', 'dp-maint', 'dp-dev', 'dp-checklist'):
            probe = f'user={user},host=erebus,addr=100.64.0.1'
            if transport == ATTENDED_ACCESS:
                probe += ',laddr=100.64.0.2'
            effective = self.run('/usr/sbin/sshd', '-T', '-C', probe).splitlines()
            if transport == ATTENDED_ACCESS and user == 'core' and any(
                    row.startswith('denyusers ') and 'core' in row.split()[1:] for row in effective):
                raise Blocked('effective tailnet OpenSSH denies the named core account')
            if (not required.issubset(effective) or [line for line in effective if line.startswith('allowusers ')] != ['allowusers core']
                    or user == 'core' and 'authorizedkeysfile /etc/ssh/dev-pair-keys/core' not in effective):
                raise Blocked('effective tailnet OpenSSH configuration conflicts')

    def verify_access_probes(self, data, expected):
        rows = data.get('probes')
        if type(rows) is not list or len(rows) != len(expected):
            raise Blocked('independent endpoint observations are incomplete')
        actors = {name: set() for name in ('authorized', 'denied', 'public', 'provider')}
        seen = set()
        for row in rows:
            if type(row) is not dict or set(row) != {'test', 'family', 'endpoint', 'vantage', 'client_id', 'outcome', 'observed_at', 'evidence_sha256'}:
                raise Blocked('invalid independent endpoint observation')
            key = (row['test'], row['family'])
            if (key in seen or expected.get(key) != (row['endpoint'], row['vantage'], row['outcome'])
                    or type(row['client_id']) is not str or not re.fullmatch(r'[A-Za-z0-9@._:+/-]{1,128}', row['client_id'])
                    or type(row['evidence_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['evidence_sha256'])
                    or type(row['observed_at']) is not int or not data['issued_at'] - 1800 <= row['observed_at'] <= data['issued_at']):
                raise Blocked('endpoint observation does not bind its expected test and identity')
            seen.add(key)
            actors[row['vantage']].add(row['client_id'])
        if any(actors[left] & actors[right] for left, right in (('authorized', 'denied'), ('authorized', 'public'), ('denied', 'public'))):
            raise Blocked('independent endpoint observations reused client access identity')

    @staticmethod
    def public_probe_host(value, family, recovery):
        if value is None:
            return recovery + '/no-public-' + family
        address = ipaddress.ip_address(value)
        if (type(value) is not str or str(address) != value or address.version != (4 if family == 'ipv4' else 6)
                or not address.is_global or address.is_multicast):
            raise Blocked('public observation does not bind a verified provider address')
        return value if family == 'ipv4' else f'[{value}]'

    @classmethod
    def access_probe_plan(cls, dns, recovery, public_addresses, *, core_only=False):
        if type(public_addresses) is not dict or set(public_addresses) != {'ipv4', 'ipv6'}:
            raise Blocked('both provider public address families must be recorded')
        ssh, mosh = f'ssh://core@{dns}:22', f'udp://{dns}:60000-61000'
        expected = {}
        for family in ('ipv4', 'ipv6'):
            public = cls.public_probe_host(public_addresses[family], family, recovery)
            public_ssh = public if public_addresses[family] is None else f'ssh://core@{public}:22'
            public_mosh = public if public_addresses[family] is None else f'udp://{public}:60000-61000'
            for name, endpoint, vantage, outcome in (
                ('named-key', ssh, 'authorized', 'allow'), ('invalid-key', ssh, 'authorized', 'deny'),
                ('password-login', ssh, 'authorized', 'deny'),
                ('password-gated-sudo', ssh, 'authorized', 'allow'), ('script-and-transfer', ssh, 'authorized', 'allow'),
                ('mosh-tmux-reconnect', mosh, 'authorized', 'allow'), ('denied-ssh', ssh, 'denied', 'deny'),
                ('denied-mosh', mosh, 'denied', 'deny'), ('public-ssh', public_ssh, 'public', 'deny'),
                ('public-mosh', public_mosh, 'public', 'deny'), ('lost-ssh', ssh, 'authorized', 'deny'),
                ('lost-mosh', mosh, 'authorized', 'deny'), ('restored-ssh', ssh, 'authorized', 'allow'),
            ):
                expected[name, family] = (endpoint, vantage, outcome)
            for role in (() if core_only else ('maintenance', 'development')):
                endpoint = f'{ssh}/{role}'
                for event, vantage, outcome in (('authorized', 'authorized', 'allow'), ('denied', 'denied', 'deny'),
                                                ('public', 'public', 'deny'), ('lost', 'authorized', 'deny'),
                                                ('restored', 'authorized', 'allow')):
                    target = public_ssh + '/' + role if event == 'public' else endpoint
                    expected[role + '-' + event, family] = (target, vantage, outcome)
        for step in ('reopened-recovery', 'recovery-during-loss'):
            expected[step, 'provider'] = (recovery, 'provider', 'allow')
        return expected

    @staticmethod
    def access_addresses(live):
        addresses = {}
        networks = {4: ipaddress.ip_network('100.64.0.0/10'), 6: ipaddress.ip_network('fd7a:115c:a1e0::/48')}
        for value in live['TailscaleIPs']:
            address = ipaddress.ip_address(value)
            family = 'ipv' + str(address.version)
            if str(address) != value or family in addresses or address not in networks[address.version]:
                raise Blocked('current Tailscale address identity differs')
            addresses[family] = value
        if set(addresses) != {'ipv4', 'ipv6'}:
            raise Blocked('both admitted Tailscale address families are required')
        return addresses

    def access_workload_selection(self, *, allow_fenced=False):
        self.verify_final_guard()
        return self.selected_workload_placement(allow_fenced=allow_fenced)

    def selected_workload_placement(self, *, allow_fenced=False):
        import renewal
        from renewal_site import role_artifacts

        control = self.path('/var/lib/dev-pair/renewal')
        chosen = renewal.read_json(control / 'current.json')
        if chosen != renewal.read_json(control / 'site-current.json') or not allow_fenced and os.path.lexists(
                self.path('/var/lib/dev-pair/renewal-fence/frozen')):
            raise Blocked('the selected private role placement is not settled')
        try:
            return role_artifacts(renewal.Renewal(self.path('/var/lib/dev-pair'), None), chosen)
        except ValueError as error:
            raise Blocked(str(error)) from error

    def access_cutover_binding(self, source, *, workload=False):
        self.destination_source(source)
        with self.lock():
            live, dns = self.tailscale_state()
            tailnet, node = self.identity_fields(live)
            if not self.path(STATE + '/prepared').is_file():
                raise Blocked('prepared maintenance host required for access review')
            result = {'version': 1, 'kind': CORE_ACCESS_CUTOVER, 'job_id': 'host-access', 'source_sha': source,
                      **self.destination_identity(), 'dns_name': dns, 'tailnet': tailnet, 'node_id': node,
                      'tailnet_addresses': self.access_addresses(live), 'keys_sha256': self.access_keys_digest()}
            if workload:
                result.update(kind=WORKLOAD_ACCESS_CUTOVER, role_artifacts=self.access_workload_selection())
            return result

    def access_keys_digest(self):
        return hashlib.sha256(checked_file(self.path('/etc/ssh/dev-pair-keys/core')).read_bytes()).hexdigest()

    def cutover_evidence(self, evidence):
        required = {'node_id', 'tailnet', 'dns_name', 'keys_sha256', 'acl_sha256', 'probes',
                    'execution_route', 'provider_recovery', 'public_addresses'}
        data = self.recent_destination_evidence(evidence, 'dev-pair-access-review', required, lifetime=1800, core_access=True)
        if (type(data['acl_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', data['acl_sha256'])
                or data['execution_route'] not in ('tailnet-core', 'provider-recovery')
                or type(data['provider_recovery']) is not str
                or not re.fullmatch(r'hostinger://[A-Za-z0-9_-]{1,100}/recovery', data['provider_recovery'])):
            raise Blocked('named access, independent recovery and ingress evidence is incomplete')
        live, dns = self.tailscale_state()
        core_only = data.get('kind') == CORE_ACCESS_CUTOVER
        scoped = core_only or data.get('kind') == WORKLOAD_ACCESS_CUTOVER
        if (self.identity_fields(live) != (data['tailnet'], data['node_id']) or dns != data['dns_name']
                or self.access_keys_digest() != data['keys_sha256']
                or scoped and self.access_addresses(live) != data['tailnet_addresses']):
            raise Blocked('cutover evidence does not bind current node, addresses and core keys')
        if data.get('kind') == WORKLOAD_ACCESS_CUTOVER and self.access_workload_selection() != data['role_artifacts']:
            raise Blocked('workload observations differ from the selected installed role placement')
        self.verify_access_probes(data, self.access_probe_plan(dns, data['provider_recovery'], data['public_addresses'],
                                                             core_only=core_only))
        return data, live, core_only

    def named_tailnet_peer(self, live, peer):
        if not peer or peer['local'] not in live.get('TailscaleIPs', []) or peer['device'] != 'tailscale0' or not peer['core']:
            raise Blocked('operation requires the live named core tailnet SSH route')

    def access_control_source(self, source, guard):
        prior = guard['target']['source_sha']
        if source == prior:
            return
        path = self.path('/var/lib/dev-pair-day0/continuation.json')
        if not os.path.lexists(path):
            raise Blocked('the access review source differs from the recorded host cutover')
        progress = json.loads(checked_file(path, secret=True).read_text(), object_pairs_hook=relay.unique)
        if (type(progress) is not dict or set(progress) != {'schema', 'machine_id', 'controller_source_sha',
                'maintenance_source_sha', 'image_id', 'context_sha256', 'initializer_sha256', 'desired_sha256'}
                or progress['schema'] != 1 or progress['machine_id'] != self.destination_identity()['machine_id']
                or progress['controller_source_sha'] != source or progress['maintenance_source_sha'] != prior
                or not all(type(progress[key]) is str and re.fullmatch(r'[0-9a-f]{64}', progress[key])
                           for key in ('image_id', 'context_sha256', 'initializer_sha256', 'desired_sha256'))):
            raise Blocked('the access review is not a verified continuation of the recorded host cutover')

    def initial_cutover_journal(self, data, target, prior, prior_raw, temporary, permanent, transport,
                                *, recover, previous_source, receipt_sha, legacy_origin):
        claims = {field: data[field] for field in ('boot_id', 'execution_route', 'keys_sha256', 'acl_sha256',
                                                   'provider_recovery', 'public_addresses')}
        if 'tailnet_addresses' in data:
            claims['tailnet_addresses'] = data['tailnet_addresses']
        intent = {'schema': 1, 'kind': data.get('kind', 'legacy-full'), 'bootstrap_transport': transport,
                  'temporary_guard_sha256': hashlib.sha256(temporary.encode()).hexdigest(),
                  'final_guard_sha256': hashlib.sha256(permanent.encode()).hexdigest(), 'claims': claims}
        pending = {'phase': 'applying', 'target': target, 'intent': intent, 'first_receipt_sha256': receipt_sha,
                   **legacy_origin}
        if not prior:
            if recover:
                raise Blocked('there is no interrupted access cutover to recover')
        elif prior.get('intent') == intent and prior['target'] == target and not recover:
            if not re.fullmatch(r'[0-9a-f]{64}', prior.get('first_receipt_sha256', '')):
                raise Blocked('saved access cutover receipt identity is invalid')
            return prior_raw
        else:
            prior_intent = prior.get('intent')
            earlier = {**target, 'source_sha': previous_source} if previous_source else target
            same_target = prior['target'] in (target, earlier)
            if prior_intent is None:
                compatible = data.get('kind') == CORE_ACCESS_CUTOVER and set(prior) == {'phase', 'target'}
            elif type(prior_intent) is dict and type(prior_intent.get('claims')) is dict:
                stable_claims = {key: value for key, value in claims.items() if key not in ('boot_id', 'execution_route')}
                recorded = prior_intent['claims']
                old = {**intent, 'claims': {**stable_claims, 'boot_id': recorded.get('boot_id'),
                                             'execution_route': recorded.get('execution_route')}}
                if prior_intent.get('kind') == 'legacy-full' and intent['kind'] == CORE_ACCESS_CUTOVER:
                    old['kind'] = 'legacy-full'
                    old['claims'].pop('tailnet_addresses', None)
                compatible = prior_intent == old
            else:
                compatible = False
            if not (recover and same_target and compatible and data['execution_route'] == 'provider-recovery'):
                raise Blocked('interrupted access cutover requires matching scoped evidence for its original boot and '
                              'route, or explicit recovery through a separately verified provider terminal')
            if os.path.lexists(self.path(SSH_CUTOVER)) and checked_file(self.path(SSH_CUTOVER)).read_text() != SSH_CUTOVER_CONFIG:
                raise Blocked('interrupted cutover has an unverified SSH configuration')
            predecessor = hashlib.sha256(prior_raw.encode()).hexdigest()
            self.atomic(STATE + '/cutover-recovery/' + predecessor + '.json', prior_raw)
            pending['recovery_predecessor_sha256'] = predecessor
            for field in ('legacy_origin', 'legacy_role_artifacts'):
                if field in prior:
                    pending[field] = prior[field]
        return json.dumps(pending, sort_keys=True) + '\n'

    def finalize(self, evidence, *, recover=False, previous_source=None):
        if os.geteuid() != 0:
            raise Blocked('root required for destination cutover')
        with contextlib.ExitStack() as operations:
            operations.enter_context(self.lock())
            if not self.path(f'{STATE}/prepared').exists():
                raise Blocked('prepare must complete before cutover')
            data, live, core_only = self.cutover_evidence(evidence)
            if data.get('kind') == WORKLOAD_ACCESS_CUTOVER:
                import renewal

                operations.enter_context(renewal.Renewal(self.path('/var/lib/dev-pair'), None).lock(shared=True))
                if self.access_workload_selection() != data['role_artifacts']:
                    raise Blocked('the selected role placement changed before signed workload activation')
            peer = self.observed_ssh_peer()
            if data['execution_route'] == 'tailnet-core':
                self.named_tailnet_peer(live, peer)
            elif peer:
                raise Blocked('cutover requires the admitted independent provider recovery terminal')
            desired = json.loads(checked_file(self.path(f'{STATE}/desired.json')).read_text(), object_pairs_hook=relay.unique)
            sources = desired.get('bootstrap_sources')
            transport = desired.get('bootstrap_transport')
            if sources != [] or transport not in (ACCESS_MODE, ATTENDED_ACCESS):
                sources = validate_sources(sources)
            temporary = self.guard_rules(sources, retain_ssh=transport == ATTENDED_ACCESS)
            permanent = self.guard_rules([], tailnet_only=True)
            current = checked_file(self.path(GUARD_PATH)).read_text()
            cutover_path = self.path(CUTOVER)
            prior_raw = checked_file(cutover_path).read_text() if os.path.lexists(cutover_path) else ''
            prior = json.loads(prior_raw or '{}', object_pairs_hook=relay.unique)
            if type(prior) is not dict:
                raise Blocked('protected access cutover history is invalid')
            target = {key: data[key] for key in ('source_sha', 'machine_id', 'tailnet', 'node_id', 'dns_name')}
            scoped_workload = data.get('kind') == WORKLOAD_ACCESS_CUTOVER
            continued = bool(prior.get('phase') == 'complete' and scoped_workload and previous_source and
                             previous_source != target['source_sha'])
            earlier = {**target, 'source_sha': previous_source} if (recover or continued) and previous_source else target
            if prior and (prior.get('target') not in (target, earlier) or prior.get('phase') not in ('applying', 'complete')):
                raise Blocked('cutover target conflict')
            if prior and prior['target'] != target:
                self.access_control_source(data['source_sha'], prior)
            if prior.get('phase') == 'complete':
                if recover:
                    raise Blocked('access cutover is already complete')
                self.verify_final_guard()
                self.verify_final_ssh()
                if prior.get('scope') == 'core' and not (core_only or scoped_workload):
                    raise Blocked('the named administrator stage requires a separate exact signed workload review')
                if scoped_workload:
                    if data['expires_at'] <= time.time():
                        raise Blocked('fresh workload observations required before activation')
                    accepted = {key: value for key, value in prior.items() if key != 'scope'}
                    if prior['target'] != target:
                        if (prior.get('core_keys_sha256') != data['keys_sha256'] or
                                any(prior.get(key) != data[key] for key in ('provider_recovery', 'public_addresses'))):
                            raise Blocked('continued workload evidence changes the original verified host access route or keys')
                        predecessor = hashlib.sha256(prior_raw.encode()).hexdigest()
                        self.atomic(STATE + '/cutover-history/' + predecessor + '.json', prior_raw)
                        accepted.update(target=target, predecessor_cutover_sha256=predecessor)
                    accepted.update(core_keys_sha256=data['keys_sha256'], acl_sha256=data['acl_sha256'],
                                    provider_recovery=data['provider_recovery'], public_addresses=data['public_addresses'],
                                    access_receipt_sha256=hashlib.sha256(checked_file(evidence).read_bytes()).hexdigest())
                    accepted['role_artifacts'] = data['role_artifacts']
                    self.atomic(CUTOVER, json.dumps(accepted, sort_keys=True) + '\n', expected=prior_raw)
                    self.publish_workload_gate('admitted', data['role_artifacts'])
                elif prior.get('scope') == 'core':
                    self.publish_workload_gate('held')
                elif 'role_artifacts' not in prior:
                    if self.retained_workload_roles(prior) is not None:
                        import renewal

                        operations.enter_context(renewal.Renewal(self.path('/var/lib/dev-pair'), None).lock(shared=True))
                    self.publish_legacy_workload_gate(prior)
                return self.status()
            if current not in (temporary, permanent) or (not prior and current != temporary):
                raise Blocked('bootstrap ingress configuration differs from protected intent')
            if not prior and (self.path(SSH_CUTOVER).exists() or self.path(SSH_CUTOVER).is_symlink()):
                raise Blocked('unowned OpenSSH cutover configuration')
            proposed = STATE + '/tailnet-only.nft'
            self.atomic(proposed, permanent)
            self.run('/usr/sbin/nft', '--check', '-f', str(self.path(proposed)))
            self.run('/usr/bin/systemctl', 'is-active', 'dev-pair-bootstrap-guard.service')
            if data['expires_at'] <= time.time():
                raise Blocked('fresh independent access observations required before cutover')
            receipt_sha = hashlib.sha256(checked_file(evidence).read_bytes()).hexdigest()
            legacy_origin = self.original_legacy_origin(operations, data['boot_id']) if not prior and not core_only else {}
            pending = self.initial_cutover_journal(data, target, prior, prior_raw, temporary, permanent, transport,
                                                  recover=recover, previous_source=previous_source, receipt_sha=receipt_sha,
                                                  legacy_origin=legacy_origin)
            self.atomic(CUTOVER, pending, expected=prior_raw)
            self.publish_workload_gate('held')
            # On retry only roll forward. The root-owned marker and external recovery permit
            # finishing after a crash without re-enabling temporary public SSH.
            ssh_file = self.path(SSH_CUTOVER)
            created = not ssh_file.exists()
            self.atomic(SSH_CUTOVER, SSH_CUTOVER_CONFIG)
            try:
                self.verify_final_ssh()
            except BaseException:
                if created:
                    ssh_file.unlink(missing_ok=True)
                raise
            for unit in ('sshd.service', 'sshd.socket'):
                self.atomic('/etc/systemd/system/' + unit + '.d/50-dev-pair-guard.conf', TAILSCALE_UNIT, mode=0o644)
            self.run('/usr/bin/systemctl', 'daemon-reload')
            self.run('/usr/bin/systemctl', 'reload', 'sshd.service')
            self.atomic(GUARD_PATH, permanent, expected=temporary)
            self.run('/usr/sbin/nft', '-f', str(self.path(GUARD_PATH)))
            self.run('/usr/bin/systemctl', 'is-active', 'dev-pair-bootstrap-guard.service')
            record = {'phase': 'complete', 'target': target, 'guard_sha256': self.guard_hash(),
                      'core_keys_sha256': data['keys_sha256'], 'acl_sha256': data['acl_sha256'],
                      'provider_recovery': data['provider_recovery'],
                      'public_addresses': data['public_addresses'],
                      'access_receipt_sha256': receipt_sha}
            finished_intent = json.loads(pending, object_pairs_hook=relay.unique)
            for field in ('first_receipt_sha256', 'recovery_predecessor_sha256', 'legacy_origin', 'legacy_role_artifacts'):
                if field in finished_intent:
                    record[field] = finished_intent[field]
            if core_only:
                record['scope'] = 'core'
            self.atomic(CUTOVER, json.dumps(record, sort_keys=True) + '\n', expected=pending)
            if not core_only:
                self.publish_legacy_workload_gate(record)
            self.event('access-cutover', 'complete')
            return self.status()

    def status(self):
        state = json.loads(self.text(CUTOVER, '{}'), object_pairs_hook=relay.unique)
        cutover = state.get('phase')
        access = json.loads(self.text(f'{STATE}/desired.json', '{}'), object_pairs_hook=relay.unique)
        return {'prepared': self.path(f'{STATE}/prepared').exists(),
                'initialization': json.loads(self.text(f'{STATE}/initialize.json', '"not requested"')),
                'maintenance_gptbox': (json.loads(self.text(f'{STATE}/gptbox-image.json'))
                                       if self.path(f'{STATE}/gptbox-image.json').exists() else 'not built'),
                'enrollment_recorded': self.path(f'{STATE}/node.json').exists(),
                'phase': 'tailnet-only' if cutover == 'complete' else 'temporary-bootstrap',
                'access_cutover': cutover or 'independent evidence required',
                'access_scope': ('core' if state.get('scope') == 'core' else 'full') if cutover == 'complete' else None,
                'root_and_initial_ssh_retained': cutover is None and (access.get('bootstrap_sources') != [] or
                                                                    access.get('bootstrap_transport') == ATTENDED_ACCESS),
                'runtime_acceptance': 'not verified', 'state': STATE,
                'note': 'Recorded state only; not proof of current external reachability or recovery'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='stage', required=True)
    sub.add_parser('inspect')
    console = sub.add_parser('console-inspect', help='read-only hPanel terminal inventory before setup')
    console.add_argument('--source-sha', help='verify the independently admitted staged Git checkout')
    sub.add_parser('_fetch-github-keys', help=argparse.SUPPRESS)
    init = sub.add_parser('initialize', help='prepare then genuine maintenance assembly; no jobs/authentication')
    init.add_argument('--source-sha', required=True)
    init.add_argument('--distrobox-source', required=True)
    init.add_argument('--retry', action='store_true')
    init.add_argument('--rpm-cache', help='protected Fedora construction cache transport')
    init.add_argument('--expected-rpm-cache-manifest-sha256', help='independently supplied construction cache manifest digest')
    prep = sub.add_parser('prepare')
    for entry in (prep, init):
        entry.add_argument('--apply', action='store_true', help='perform host changes; absent means inspect only')
        entry.add_argument('--gptbox-context', required=True, help='real maintenance-role context; fixtures denied')
        entry.add_argument('--expected-context-sha256', required=True, help='trusted handoff digest outside context')
        entry.add_argument('--operator', choices=('core',), default='core')
        entry.add_argument('--password-file', help='protected root-owned core console/sudo password file; never an argv value')
        access = entry.add_mutually_exclusive_group(required=True)
        access.add_argument('--bootstrap-source', action='append', help='explicit IPv4/IPv6 CIDR; repeatable')
        access.add_argument('--console-receipt', help='protected signed Hostinger out-of-band receipt')
        entry.add_argument('--provider-ssh', action='store_true', help='require the live SSH-backed hPanel transport')
    en = sub.add_parser('enroll')
    en.add_argument('--apply', action='store_true', help='enroll; absent means inspect only')
    en.add_argument('--auth-key-file', required=True)
    en.add_argument('--tailnet', required=True, help='exact expected CurrentTailnet.Name')
    sub.add_parser('status')
    finalize = sub.add_parser('finalize', help='apply tailnet-only SSH after independent access/recovery checks')
    finalize.add_argument('--evidence', help='protected signed current access evidence')
    finalize.add_argument('--apply', action='store_true')
    args = p.parse_args()
    try:
        if args.stage in ('prepare', 'initialize') and args.provider_ssh:
            if not args.bootstrap_source or not Bootstrap().observed_ssh_peer():
                raise Blocked('SSH-backed hPanel setup requires an observed SSH peer and scoped CIDRs')
        if args.stage == 'initialize':
            forwarded = [sys.executable, str(Path(__file__).with_name('gptbox.py')), 'initialize',
                         '--context', args.gptbox_context, '--expected-context-sha256', args.expected_context_sha256,
                         '--source-sha', args.source_sha, '--distrobox-source', args.distrobox_source]
            for source in args.bootstrap_source or []:
                forwarded.extend(['--bootstrap-source', source])
            if args.console_receipt:
                forwarded.extend(['--console-receipt', args.console_receipt])
            if args.password_file:
                forwarded.extend(['--password-file', args.password_file])
            if args.apply:
                forwarded.append('--apply')
            if args.retry:
                forwarded.append('--retry')
            if args.rpm_cache is not None:
                forwarded.extend(['--rpm-cache', args.rpm_cache])
            if args.expected_rpm_cache_manifest_sha256 is not None:
                forwarded.extend(['--expected-rpm-cache-manifest-sha256', args.expected_rpm_cache_manifest_sha256])
            os.execv(sys.executable, forwarded)
        if args.stage == '_fetch-github-keys':
            sys.stdout.buffer.write(fetch_github_response())
            return 0
        b = Bootstrap()
        if args.stage == 'inspect':
            result = b.preflight()
        elif args.stage == 'console-inspect':
            result = b.console_inspect(args.source_sha)
        elif args.stage == 'prepare':
            if args.apply:
                password = operator_password(args.password_file) if args.password_file else None
                keys = github_keys()
                result = b.prepare(args.operator, keys, args.bootstrap_source,
                                   args.gptbox_context, args.expected_context_sha256, password=password,
                                   console_receipt=args.console_receipt)
            else:
                result = {**b.preflight(), 'preview': 'prepare',
                          'sources': b.validate_bootstrap_access(args.bootstrap_source, args.console_receipt)}
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
            if not args.apply or not args.evidence:
                raise Blocked('cutover requires --apply and signed named-admin and independent recovery evidence')
            result = b.finalize(args.evidence)
        else:
            result = b.status()
        print(json.dumps(result, indent=2))
        return 0
    except (Blocked, OSError, ValueError, TypeError, KeyError) as e:
        # JSON/OS exceptions may contain external payloads/paths: do not echo them.
        print('bootstrap blocked: ' + (str(e) if isinstance(e, Blocked) else 'invalid input or local filesystem state'), file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
