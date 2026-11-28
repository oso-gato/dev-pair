#!/usr/bin/env python3
"""Finite private two-session stock resume fixture; no runtime/renewal admission."""
import argparse
import copy
import ctypes
import json
import math
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import codex_tools as t
import session_helper as helper
import session_controller as controller
import startup_delivery as startup

CATALOG_SHA = '1384625c0b6b3e67d3c60da29becea2b017f2c283fc1e2d05b8edafb4698eb10'
LABELS = ('alpha', 'beta')
UNKNOWN = '00000000-0000-4000-8000-000000000001'
UNCOMMITTED = b'private uncommitted source survives both explicit UUID resumes\n'
STOCK_SOURCE = 'd32063f96c2dff1dc96af839b3952abb6acfeda4'
METADATA = 'internal_chat_message_metadata_passthrough'
METADATA_KEYS = ('turn_id','create_time','content_token_count','content_item_kinds',
                 'content_item_metadata','cell_id','executed_tool_calls','tool_calls_complete')
require = t.require
canonical = t.canonical
sha = t.sha


# Fixed immutable worker dependency closure, shared by snapshots and mounts.
SESSION_MODULES=('codex_tools.py','session_helper.py','session_controller.py','job_protocol.py',
    'ledger_recovery.py','startup_delivery.py','codex_state.py','public_inputs.py','fedora_oci.py')

def session_sources():
    return (('worker.py',Path(__file__)),*((name,Path(__file__).with_name(name)) for name in SESSION_MODULES))

def stage_session_sources(root,end):
    files={}
    for name,source in session_sources():
        path=Path(root)/name;path.write_bytes(t.snapshot(source,131072,end));path.chmod(0o444);files[name]=path
    return files

def session_source_mounts(files):
    require(set(files)=={'worker.py',*SESSION_MODULES},'session source snapshot set mismatch')
    return ['--ro-bind',str(files['worker.py']),'/opt/tool_boundary.py',
        *sum((['--ro-bind',str(files[name]),'/opt/'+name] for name in SESSION_MODULES),[])]


class MetadataRejected(ValueError):
    def __init__(self, stage):
        require(stage in ('metadata-schema','metadata-turn-id','metadata-timestamp','pair-turn-mismatch'),
                'unsupported metadata rejection stage')
        self.stage = stage
        super().__init__('history metadata rejected: '+stage)


def valid_timestamp(value):
    return type(value) in (int,float) and 0 < value < 1e12 and math.isfinite(value)


def valid_uuid(value):
    try:session_uuid(value);return True
    except ValueError:return False


def json_type(value):
    return {dict:'object',list:'array',str:'string',int:'integer',float:'number',bool:'boolean',type(None):'null'}.get(type(value))


UNKNOWN_REASONS={prefix+'no rollout found for '+kind+' id '+UNKNOWN:
    ('terminal-' if prefix else '')+'bare-'+kind for prefix in ('','Error: ') for kind in ('thread','conversation')}
UNKNOWN_REASONS.update({prefix+'thread/resume: thread/resume failed: no rollout found for thread id '+UNKNOWN+' (code -32600)':
    ('terminal-' if prefix else '')+'typed-thread' for prefix in ('','Error: ')})


def unknown_reason_family(text):
    return UNKNOWN_REASONS.get(text,'none') if type(text) is str else 'none'


def unknown_reason(text):
    return unknown_reason_family(text)!='none'


def stderr_reason_family(raw,complete):
    if not complete:return None
    try:text=raw.decode('utf-8')
    except UnicodeError:return 'none'
    # A complete terminal line may have its one ordinary LF terminator.
    # No control stripping, substring, extra lines or partial-buffer proof.
    return unknown_reason_family(text[:-1] if text.endswith('\n') else text)


def session_uuid(value):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value)
            and str(uuid.UUID(value)) == value, 'malformed actual session UUID')
    return value


def prompt(label, phase, nonce):
    require(label in LABELS and phase in ('first', 'resume'), 'unplanned session phase')
    return 'OFFLINE_SESSION_' + label.upper() + '_' + phase.upper() + '_' + nonce


def progress(label, phase, nonce):
    return {'session': label, 'phase': phase, 'nonce': nonce}


def action(label, phase, nonce):
    first = canonical(progress(label, 'first', nonce)) + b'\n'
    current = canonical(progress(label, phase, nonce)) + b'\n'
    path = '/job/src/session-' + label + '.jsonl'
    code = ('import os,pathlib,stat; p=pathlib.Path(' + repr(path) + ');'
            + ("fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);" if phase == 'first' else
               'assert p.read_bytes()==' + repr(first) + ';fd=os.open(p,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW);')
            + 's=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;'
            + 'os.write(fd,' + repr(current) + ');os.fsync(fd);os.close(fd);print(' + repr(current.decode().strip()) + ')')
    return {'type': 'function_call', 'call_id': 'session-' + label + '-' + phase, 'name': 'exec_command',
            'arguments': json.dumps({'cmd': t.command(code), 'login': False, 'yield_time_ms': 10000,
                                     'max_output_tokens': 1500})}


def marker(root, label, phases, nonce):
    path = Path(root) / ('job/src/session-' + label + '.jsonl')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024, 'invalid progress marker')
    expected = b''.join(canonical(progress(label, phase, nonce)) + b'\n' for phase in phases)
    require(t.snapshot(path, 1024, time.monotonic() + 1) == expected, 'missing/duplicate/cross-session progress effect')
    return {'lines': len(phases), 'bytes': len(expected), 'sha256': sha(expected)}


def history_item(item, issued, kind):
    require(type(item) is dict and item.get('type') == kind and item.get('call_id') == issued['call_id'],
            'wrong history kind or call identity')
    base = {'type', 'call_id', 'name', 'arguments'} if kind == 'function_call' else {'type', 'call_id', 'output'}
    optional = {'id', 'internal_chat_message_metadata_passthrough'}
    if kind == 'function_call': optional |= {'status', 'namespace'}
    require(base <= set(item) <= base | optional, 'unknown/missing history fields')
    if kind == 'function_call':
        require(all(item[k] == issued[k] for k in base), 'history call does not match issued command')
        require('status' not in item or item['status'] == 'completed', 'unexpected historical call status')
        require('namespace' not in item or item['namespace'] == 'functions', 'unexpected function namespace')
    else:
        require(type(item['output']) is str, 'nontext exec result')
    if 'id' in item:
        require(type(item['id']) is str and re.fullmatch(r'(?:fc|fco)_[0-9a-f-]{36}', item['id']), 'invalid stamped history ID')
        session_uuid(item['id'].split('_', 1)[1])
    if METADATA in item:
        value = item[METADATA]
        expected = {'turn_id'} if kind == 'function_call' else {'turn_id','create_time'}
        if type(value) is not dict or set(value) != expected:raise MetadataRejected('metadata-schema')
        if not valid_uuid(value['turn_id']):raise MetadataRejected('metadata-turn-id')
        if kind == 'function_call_output' and not valid_timestamp(value['create_time']):
            raise MetadataRejected('metadata-timestamp')
    return item


def input_texts(inputs):
    result = []
    for index, item in enumerate(inputs):
        if type(item) is not dict or item.get('type') != 'message' or item.get('role') != 'user': continue
        content = item.get('content')
        require(type(content) is list, 'invalid user context content')
        for part in content:
            if type(part) is dict and part.get('type') == 'input_text' and type(part.get('text')) is str:
                result.append((index, part['text']))
    return result


def user_context(inputs):
    """Retain complete observed ordered messages; no metadata normalization."""
    result = []
    optional = {'id','status','phase','encrypted_content','internal_chat_message_metadata_passthrough'}
    for index,item in enumerate(inputs):
        if type(item) is not dict or item.get('role') != 'user':continue
        require(item.get('type') == 'message' and {'type','role','content'} <= set(item) <=
                {'type','role','content'} | optional, 'unknown user-context envelope')
        content = item['content']
        require(type(content) is list and 0 < len(content) <= 32 and all(type(part) is dict and
                set(part) == {'type','text'} and part['type'] == 'input_text' and type(part['text']) is str
                for part in content), 'unknown user-context content')
        result.append((index,copy.deepcopy(item)))
    require(result and len(canonical([item for _,item in result])) <= t.BODY_BYTES,
            'missing or excessive observed user context')
    return result


def exact_prompt_message(item, expected):
    return item['content'] == [{'type':'input_text','text':expected}]


def durable_user_to_wire(item):
    """Only the pinned non-RLite attribution removal; never used on wire input."""
    require(type(item) is dict and {'type','role','content',METADATA} <= set(item) <=
            {'type','role','content',METADATA,'id'} and item['type']=='message' and item['role']=='user',
            'unknown durable user envelope')
    if 'id' in item:
        value=item['id']
        require(type(value) is str and re.fullmatch(r'msg_(?:input_)?[0-9a-f-]{36}',value) and
                valid_uuid(value.removeprefix('msg_').removeprefix('input_')), 'unknown durable user ID')
    # Reuse only the strict text-content validator, not any wire normalization.
    user_context([item])
    metadata=item[METADATA]
    require(type(metadata) is dict and set(metadata)=={'turn_id','create_time','content_item_kinds','content_item_metadata'}
            and valid_uuid(metadata['turn_id']) and valid_timestamp(metadata['create_time']),
            'unknown durable user metadata')
    kinds=metadata['content_item_kinds'];attribution=metadata['content_item_metadata']
    require(type(kinds) is list and type(attribution) is list and
            len(kinds)==len(attribution)==len(item['content']), 'misaligned durable attribution')
    for kind,value in zip(kinds,attribution):
        require(type(kind) is str and kind in ('user.text','environments.environment_context'),
                'unknown durable user classification')
        expected={'provenance':{'type':'user'}} if kind=='user.text' else {'provenance':{'type':'harness','hook':False}}
        require(type(value) is dict and canonical(value)==canonical(expected), 'unknown durable user attribution')
    projected=copy.deepcopy(item)
    del projected[METADATA]['content_item_metadata']
    if not projected[METADATA]:del projected[METADATA]
    return projected


ENVIRONMENT_KIND='environments.environment_context'


def wire_fragment(item,kind,prefix):
    if (type(item) is not dict or set(item)!={'type','role','id','content',METADATA} or item.get('type')!='message' or
            item.get('role')!='user' or type(item.get('id')) is not str or not item['id'].startswith(prefix)):
        return False
    suffix=item['id'][len(prefix):]
    if not valid_uuid(suffix):return False
    if prefix=='msg_' and (uuid.UUID(suffix).version!=7 or uuid.UUID(suffix).variant!=uuid.RFC_4122):return False
    metadata=item[METADATA];content=item['content']
    return (type(content) is list and len(content)==1 and type(content[0]) is dict and set(content[0])=={'type','text'} and
        content[0]['type']=='input_text' and type(content[0]['text']) is str and type(metadata) is dict and
        set(metadata)=={'turn_id','create_time','content_item_kinds'} and metadata['content_item_kinds']==[kind] and
        valid_uuid(metadata['turn_id']) and valid_timestamp(metadata['create_time']))


def input_id_unique(inputs,index,candidate,retained_ids):
    """Only this physical position is excluded; equal dictionaries elsewhere count."""
    supported=(type(inputs) is list and type(index) is int and 0<=index<len(inputs) and
        type(candidate) is dict and type(candidate.get('id')) is str and
        all(type(item) is dict and type(item.get('type')) is str and bool(item['type']) and ('id' not in item or type(item['id']) is str and 0<len(item['id'])<=t.BODY_BYTES)
            for item in inputs))
    if not supported or canonical(inputs[index])!=canonical(candidate):return False,False
    value=candidate['id']
    return True,value not in retained_ids and all(item.get('id')!=value for position,item in enumerate(inputs) if position!=index)


def prompt_id_family(item):
    if type(item) is not dict or 'id' not in item:return 'missing'
    value=item.get('id') if type(item) is dict else None
    if type(value) is not str:return 'invalid'
    if value.startswith('msg_input_'):
        return 'msg-input-uuid' if valid_uuid(value[10:]) else 'invalid'
    if value.startswith('msg_'):
        suffix=value[4:]
        return 'msg-v7' if valid_uuid(suffix) and uuid.UUID(suffix).version==7 and uuid.UUID(suffix).variant==uuid.RFC_4122 else 'invalid'
    return 'other'


def prompt_diagnostic(item,expected):
    # Independent bits: envelope, identity, content, metadata, turn, time, kind.
    item=item if type(item) is dict else {};metadata=item.get(METADATA)
    content=item.get('content');text=(type(content) is list and len(content)==1 and type(content[0]) is dict and
        set(content[0])=={'type','text'} and content[0].get('type')=='input_text' and type(content[0].get('text')) is str)
    checks=(set(item)=={'type','role','id','content',METADATA} and item.get('type')=='message' and item.get('role')=='user',
        prompt_id_family(item)=='msg-v7',text,type(metadata) is dict and set(metadata)=={'turn_id','create_time','content_item_kinds'},
        type(metadata) is dict and valid_uuid(metadata.get('turn_id')),
        type(metadata) is dict and valid_timestamp(metadata.get('create_time')),
        type(metadata) is dict and metadata.get('content_item_kinds')==['user.text'])
    return {'envelope':shape_mask(item,RESUME_ENVELOPE),'metadata':shape_mask(metadata,RESUME_METADATA) if type(metadata) is dict else 0,
        'unknown':sum(k not in RESUME_ENVELOPE for k in item)+(sum(k not in RESUME_METADATA for k in metadata) if type(metadata) is dict else 0),
        'id_family':prompt_id_family(item),'failed':sum((not check)<<bit for bit,check in enumerate(checks)),
        'exact_text':content==[{'type':'input_text','text':expected}]}


ENV_COMPONENTS=('cwd','status','error','shell','environments','shell_version','current_date','timezone','network','filesystem','subagents')
ENV_CHILDREN={'environment_context':ENV_COMPONENTS,'environments':('environment',),'environment':('cwd','status','error','shell'),
    'network':('allowed','denied'),'filesystem':('workspace_roots','permission_profile'),'workspace_roots':('root',),
    'permission_profile':('file_system',),'file_system':('entry',),'entry':('path','glob','special')}
ENV_ATTRIBUTES={'environment':('id','primary','status'),'shell_version':('status',),'current_date':('status',),
    'network':('enabled',),'permission_profile':('type',),'file_system':('type','glob_scan_max_depth'),
    'entry':('access','escalatable')}
ENV_REPEATED=frozenset((('environments','environment'),('workspace_roots','root'),('file_system','entry')))
ENV_REQUIRED_ATTRIBUTES={'environment':frozenset(('id',)),'network':frozenset(('enabled',)),
    'permission_profile':frozenset(('type',)),'file_system':frozenset(('type',)),'entry':frozenset(('access',))}
ENV_REQUIRED_CHILDREN={'environments':frozenset(('environment',)),'workspace_roots':frozenset(('root',)),
    'filesystem':frozenset(('permission_profile',)),'permission_profile':frozenset(('file_system',))}


def environment_components(content,visitor=None):
    """Diagnostic-only bounded streaming parse; exact component bytes, never an acceptance oracle."""
    from xml.parsers import expat
    result={'status':'shape','presence':0,'order':1,'duplicates':0,'unknown':0,'parts':{},'spans':{},'prefix':None,'suffix':None}
    if not (type(content) is list and len(content)==1 and type(content[0]) is dict and
            set(content[0])=={'type','text'} and content[0].get('type')=='input_text' and type(content[0].get('text')) is str):return result
    if len(content[0]['text'])>16384:result['status']='bytes';return result
    try:raw=content[0]['text'].encode()
    except UnicodeError:result['status']='encoding';return result
    if len(raw)>16384:result['status']='bytes';return result
    if b'<!' in raw or b'<?' in raw:result['status']='declaration';return result
    parser=expat.ParserCreate();parser.ordered_attributes=True
    stack=[];children=[];forms=[];nodes=0;pending=None;start=None;first=None
    def fail(status):result['status']=status;raise ValueError('unsupported diagnostic structure')
    def finish(end):
        nonlocal pending,start
        if pending is not None:
            block=raw[start:end];result['parts'].setdefault(pending,[]).append((len(block),sha(block)));result['spans'][pending]=(start,end)
            pending=None;start=None
    def opened(name,attributes):
        nonlocal nodes,pending,start,first
        nodes+=1
        if nodes>128 or len(stack)>=8:fail('bounds')
        if len(attributes)>16:fail('bounds')
        unknown_attributes=sum(key not in ENV_ATTRIBUTES.get(name,()) for key in attributes[::2])
        if unknown_attributes:result['unknown']+=unknown_attributes;fail('shape')
        attribute_names=frozenset(attributes[::2])
        if not ENV_REQUIRED_ATTRIBUTES.get(name,frozenset())<=attribute_names:fail('shape')
        if name=='environment' and {'status','primary'}<=attribute_names:fail('shape')
        if not stack:
            if name!='environment_context' or attributes:fail('shape')
        elif name not in ENV_CHILDREN.get(stack[-1],()):
            result['unknown']+=1;fail('shape')
        if stack:
            if stack[-1]=='environment' and 'status' in forms[-1]:fail('shape')
            if name in children[-1] and (stack[-1],name) not in ENV_REPEATED:
                result['duplicates']+=1;fail('duplicate')
            # The renderer chooses exactly one entry path representation.
            if stack[-1]=='entry' and children[-1]:fail('shape')
            children[-1].add(name)
        if len(stack)==1:
            finish(parser.CurrentByteIndex)
            if first is None:first=parser.CurrentByteIndex;result['prefix']=sha(raw[:first])
            index=ENV_COMPONENTS.index(name);bit=1<<index
            result['presence']|=bit;result['order']=(result['order']<<4)|(index+1)
            pending=name;start=parser.CurrentByteIndex
        if visitor is not None:visitor('start',name,attributes,parser.CurrentByteIndex)
        stack.append(name);children.append(set());forms.append(attribute_names)
    def closed(name):
        if not ENV_REQUIRED_CHILDREN.get(name,frozenset())<=children[-1]:fail('shape')
        if name=='entry' and not children[-1]:fail('shape')
        if name=='environment' and 'status' not in forms[-1] and 'cwd' not in children[-1]:fail('shape')
        if len(stack)==1:
            finish(parser.CurrentByteIndex)
            if first is None:result['prefix']=sha(raw[:parser.CurrentByteIndex])
            result['suffix']=sha(raw[parser.CurrentByteIndex:])
        if visitor is not None:visitor('end',name,None,parser.CurrentByteIndex)
        stack.pop();children.pop();forms.pop()
    def text(value):
        if stack and stack[-1] in ENV_CHILDREN and any(char not in ' \t\r\n' for char in value):fail('shape')
        if stack and stack[-1] in ('shell_version','current_date') and 'status' in forms[-1] and value:fail('shape')
        if visitor is not None and stack:visitor('text',stack[-1],value,parser.CurrentByteIndex)
    parser.StartElementHandler=opened;parser.EndElementHandler=closed;parser.CharacterDataHandler=text
    parser.ExternalEntityRefHandler=lambda *args:0
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        for index in range(0,len(raw),512):parser.Parse(raw[index:index+512],False)
        parser.Parse(b'',True)
        result['status']='duplicate' if result['duplicates'] else 'parsed'
    except expat.ExpatError:result['status']='malformed'
    except ValueError:pass
    return result


def component_comparison(old,new):
    original=environment_components(old);current=environment_components(new)
    supported=original['status']==current['status']=='parsed'
    changed=[];equal=0
    if supported:
        for index,key in enumerate(ENV_COMPONENTS):
            before=original['parts'].get(key,[]);after=current['parts'].get(key,[])
            if before==after:equal|=1<<index
            else:changed.append([index,*(before[0] if before else (None,None)),*(after[0] if after else (None,None))])
    changed.sort(key=lambda item:item[1] is None or item[3] is None)
    return {'status':[original['status'],current['status']],'presence':[original['presence'],current['presence']],
        'order':[original['order'],current['order']],'duplicates':[original['duplicates'],current['duplicates']],
        'unknown':[original['unknown'],current['unknown']],'equal':equal if supported else None,
        'wrapper_equal':(original['prefix'],original['suffix'])==(current['prefix'],current['suffix']) if supported else None,'changed':changed[:2],
        'truncated':len(changed)>2,'complete':supported}


ENV_CHECKS=('original_pair_exact','causal_positions_valid','baseline_audited','baseline_schema','closed_environment_schema',
    'current_prompt_schema','new_message_id_valid','history_id_inventory_supported','new_message_id_unique',
    'current_prompt_id_unique','new_turn_valid','new_turn_differs_from_old','new_turn_matches_current_prompt','exact_environment_content_equal')


def compact_comparison(value):
    return {'checks':[sum((value[k] is not None)<<bit for bit,k in enumerate(ENV_CHECKS)),
                      sum((value[k] is True)<<bit for bit,k in enumerate(ENV_CHECKS))],
        'baseline_count':value['baseline_environment_count'],
        'body':[value['original_content_bytes'],value['new_content_bytes'],value['original_content_sha256'],value['new_content_sha256']],
        'prompt':value['prompt'],'components':value['components'],'filesystem':value['filesystem']}


def comparison_flag(value,key):
    index=ENV_CHECKS.index(key)
    return bool(value['checks'][1]&(1<<index)) if value['checks'][0]&(1<<index) else None


def environment_comparison(journey,contexts,observed,inputs,diagnostic_only=False):
    entry=journey.entries[journey.turn['label']];retained=entry['user_context']
    originals=[item for item in retained if type(item.get(METADATA)) is dict and
               item[METADATA].get('content_item_kinds')==[ENVIRONMENT_KIND]]
    baseline=originals[0] if len(originals)==1 else None
    new=contexts[-2] if len(contexts)==len(retained)+2 else None;current=contexts[-1]
    baseline_valid=wire_fragment(baseline,ENVIRONMENT_KIND,'msg_')
    new_valid=wire_fragment(new,ENVIRONMENT_KIND,'msg_');prompt_valid=wire_fragment(current,'user.text','msg_')
    original_ids={item['id'] for item in [*retained,entry['call'],entry['output']] if type(item.get('id')) is str}
    new_id_valid=type(new) is dict and type(new.get('id')) is str and new['id'].startswith('msg_') and valid_uuid(new['id'][4:])
    new_id_valid=bool(new_id_valid and uuid.UUID(new['id'][4:]).version==7 and uuid.UUID(new['id'][4:]).variant==uuid.RFC_4122)
    raw_metadata=new.get(METADATA) if type(new) is dict else None
    new_turn=raw_metadata.get('turn_id') if type(raw_metadata) is dict else None
    environment_ids_supported,environment_unique=input_id_unique(inputs,observed[-2][0],new,original_ids)
    prompt_ids_supported,prompt_unique=input_id_unique(inputs,observed[-1][0],current,original_ids)
    baseline_metadata=baseline.get(METADATA) if type(baseline) is dict else None
    old_turn=baseline_metadata.get('turn_id') if type(baseline_metadata) is dict else None
    current_metadata=current.get(METADATA) if type(current) is dict else None
    current_turn=current_metadata.get('turn_id') if type(current_metadata) is dict else None
    audited=journey.first_rollout_audits.get(journey.turn['label'])==sha(canonical(entry))
    def content(item):return item.get('content') if type(item) is dict else None
    calls=[i for i,item in enumerate(inputs) if type(item) is dict and item.get('type')=='function_call' and item.get('call_id')==entry['issued']['call_id']]
    outputs=[i for i,item in enumerate(inputs) if type(item) is dict and item.get('type')=='function_call_output' and item.get('call_id')==entry['issued']['call_id']]
    pair_exact=(len(calls)==len(outputs)==1 and calls[0]<outputs[0] and
        canonical(inputs[calls[0]])==canonical(entry['call']) and canonical(inputs[outputs[0]])==canonical(entry['output']))
    positions=bool(pair_exact and all(i<calls[0] for i,_ in observed[:len(retained)]) and
        outputs[0]<observed[-2][0]<observed[-1][0])
    comparison={'stage':'environment-binding' if positions else 'environment-position','original_pair_exact':pair_exact,'causal_positions_valid':positions,'baseline_environment_count':len(originals),'baseline_audited':audited,
        'baseline_schema':baseline_valid,'closed_environment_schema':new_valid,'current_prompt_schema':prompt_valid,
        'new_message_id_valid':new_id_valid,'history_id_inventory_supported':environment_ids_supported and prompt_ids_supported,
        'new_message_id_unique':environment_unique if new_id_valid and environment_ids_supported else None,
        'current_prompt_id_unique':prompt_unique if prompt_id_family(current)=='msg-v7' and prompt_ids_supported else None,
        'new_turn_valid':valid_uuid(new_turn),'new_turn_differs_from_old':new_turn!=old_turn if valid_uuid(new_turn) and valid_uuid(old_turn) else None,
        'new_turn_matches_current_prompt':new_turn==current_turn if valid_uuid(new_turn) and valid_uuid(current_turn) else None,
        'exact_environment_content_equal':canonical(content(new))==canonical(content(baseline)) if baseline_valid and new_valid else None,
        'original_content_bytes':len(canonical(content(baseline))) if baseline_valid else None,
        'new_content_bytes':len(canonical(content(new))) if new_valid else None,
        'original_content_sha256':sha(canonical(content(baseline))) if baseline_valid else None,
        'new_content_sha256':sha(canonical(content(new))) if new_valid else None}
    valid=(baseline_valid and new_valid and prompt_valid and audited and positions and comparison['new_message_id_unique'] and
           comparison['current_prompt_id_unique'] and comparison['new_turn_differs_from_old'] and
           comparison['new_turn_matches_current_prompt'] and comparison['exact_environment_content_equal'])
    if (not diagnostic_only and not valid and journey.helper_binary is not None and journey.owned_child is not None and journey.child_turn is journey.turn and
            isinstance(journey.turn_helper,helper.Evidence) and journey.turn_helper.owner is journey.owned_child and baseline_valid and new_valid and prompt_valid and audited and positions and
            all(comparison[k] is True for k in ('new_message_id_unique','current_prompt_id_unique','new_turn_differs_from_old','new_turn_matches_current_prompt'))):
        valid=helper.transformed(content(baseline),content(new),journey.helper_origins.get(journey.turn['label']),journey.turn_helper,environment_components)
    old_body=content(baseline);new_body=content(new)
    if diagnostic_only:
        def operand(value):
            return value if type(value) is list and len(value)==1 and type(value[0]) is dict and set(value[0])=={'type','text'} and value[0]['type']=='input_text' and type(value[0]['text']) is str else None
        old_body=operand(old_body) if audited else None;new_body=operand(new_body)
        comparison.update(original_content_bytes=len(canonical(old_body)) if old_body is not None else None,
            original_content_sha256=sha(canonical(old_body)) if old_body is not None else None,
            new_content_bytes=len(canonical(new_body)) if new_body is not None else None,
            new_content_sha256=sha(canonical(new_body)) if new_body is not None else None,
            exact_environment_content_equal=canonical(old_body)==canonical(new_body) if old_body is not None and new_body is not None else None)
        if not audited or baseline is None:
            comparison['baseline_schema']=None;comparison['new_turn_differs_from_old']=None
        if new is None:
            for key in ('causal_positions_valid','closed_environment_schema','new_message_id_valid','new_turn_valid'):
                comparison[key]=None
    comparison['filesystem']=helper.filesystem_witness(old_body,new_body,environment_components)
    comparison['prompt']=prompt_diagnostic(current,prompt(journey.turn['label'],'resume',journey.nonce))
    comparison['components']=component_comparison(old_body,new_body)
    if diagnostic_only:
        geometry=comparison['components']
        if old_body is None:geometry['status'][0]='unavailable'
        if new_body is None:geometry['status'][1]='unavailable'
        geometry['known']=sum((status=='parsed')<<bit for bit,status in enumerate(geometry['status']))
        for key in ('presence','order'):
            geometry[key]=[value if geometry['known']&(1<<bit) else None for bit,value in enumerate(geometry[key])]
    return bool(valid and not diagnostic_only),comparison


RESUME_FIELDS=('type','role','id','content','turn_id','create_time','content_item_kinds','metadata')
RESUME_ENVELOPE=('type','role','id','content',METADATA,'status','phase','encrypted_content')
RESUME_METADATA=('turn_id','create_time','content_item_kinds','content_item_metadata')
SHAPE_TYPES=(type(None),bool,int,float,str,list,dict)


def shape_mask(item,keys):
    # Three bits per fixed key: absent=0, otherwise SHAPE_TYPES index+1.
    return sum((SHAPE_TYPES.index(type(item[key]))+1 if key in item and type(item[key]) in SHAPE_TYPES else 0)
               <<(3*index) for index,key in enumerate(keys))


def context_fields(item):
    metadata=item.get(METADATA,{})
    return {**{key:[key in item,item.get(key)] for key in ('type','role','id','content')},
        **{key:[type(metadata) is dict and key in metadata,metadata.get(key) if type(metadata) is dict else None]
           for key in ('turn_id','create_time','content_item_kinds')},'metadata':[METADATA in item,item.get(METADATA)]}


def resume_rejection_witness(journey,observed,inputs,current):
    retained=journey.entries[journey.turn['label']]['user_context'];contexts=[item for _,item in observed];count=len(retained)
    prefix=contexts[:count];mismatch=next((i for i in range(count) if i>=len(contexts) or canonical(contexts[i])!=canonical(retained[i])),None)
    final=bool(contexts) and exact_prompt_message(contexts[-1],current)
    entry=journey.entries[journey.turn['label']];call_id=entry['issued']['call_id']
    calls=[i for i,v in enumerate(inputs) if type(v) is dict and v.get('type')=='function_call' and v.get('call_id')==call_id]
    outputs=[i for i,v in enumerate(inputs) if type(v) is dict and v.get('type')=='function_call_output' and v.get('call_id')==call_id]
    pair=(len(calls)==len(outputs)==1 and calls[0]<outputs[0] and
          canonical(inputs[calls[0]])==canonical(entry['call']) and canonical(inputs[outputs[0]])==canonical(entry['output']))
    allowed={call_id}
    if journey.turn['issued'] is not None:allowed.add(journey.turn['issued']['call_id'])
    pair=pair and all(type(item) is dict and (not ('call_id' in item or str(item.get('type','')).endswith(('_call','_output'))) or
        item.get('type') in ('function_call','function_call_output') and type(item.get('call_id')) is str and item['call_id'] in allowed) for item in inputs)
    candidates=[i for i in range(min(count,len(contexts))) if canonical(contexts[i])!=canonical(retained[i])]
    candidates += list(range(count,len(contexts)-(1 if final else 0)))
    witness={'stage':'resume-context','label':journey.turn['label'],'phase':'resume',
        'retained_count':count,'observed_count':len(contexts),'expected_count':count+1,
        'old_prefix_present':len(contexts)>=count,'exact_old_prefix_equal':canonical(prefix)==canonical(retained),
        'exact_final_continuation_prompt':final,'first_mismatching_original_index':mismatch,
        'retained_sha256':sha(canonical(retained)),'observed_sha256':sha(canonical(contexts)),
        'observed_prefix_sha256':sha(canonical(prefix)),'original_pair_exact':pair,
        'request':journey.last_request,'harness_sha256':journey.harness_sha256,'codex_source_sha':STOCK_SOURCE,
        'prompt':prompt_diagnostic(contexts[-1] if contexts else None,current),
        'summaries':[],'truncated_summary':False}
    for index in candidates[:4]:
        request_index,item=observed[index];metadata=item.get(METADATA,{})
        kinds=metadata.get('content_item_kinds') if type(metadata) is dict else None
        classification=('user.text' if kinds==['user.text'] else 'environments.environment_context' if
            kinds==['environments.environment_context'] else 'unknown')
        position='unresolved'
        if pair and final:
            position=('before-old-call' if request_index<calls[0] else 'between-old-call-output' if calls[0]<request_index<outputs[0] else
                'after-old-output-before-new-prompt' if outputs[0]<request_index<observed[-1][0] else
                'after-new-prompt' if request_index>observed[-1][0] else 'final-prompt')
        difference=None
        if index<count:
            actual=context_fields(item);expected=context_fields(retained[index])
            difference=sum((canonical(actual[key])!=canonical(expected[key]))<<bit for bit,key in enumerate(RESUME_FIELDS))
        summary={'request_index':request_index,'retained_index':index if index<count else None,
            'role':'user','type':'message','content_count':len(item['content']),'classification':classification,
            'envelope_shape':shape_mask(item,RESUME_ENVELOPE),'metadata_shape':shape_mask(metadata,RESUME_METADATA) if type(metadata) is dict else 0,
            'unknown_keys':sum(key not in RESUME_ENVELOPE for key in item)+(sum(key not in RESUME_METADATA for key in metadata) if type(metadata) is dict else 0),
            'difference_mask':difference,'position':position,'sha256':sha(canonical(item)),'bytes':len(canonical(item))}
        # Keep core counts, booleans and hashes even when summaries cannot fit.
        witness['summaries'].append(summary)
        if len(canonical(witness))>2048:witness['summaries'].pop();break
    witness['truncated_summary']=len(witness['summaries'])<len(candidates)
    if len(canonical(witness))>2048:
        witness['summaries']=[];witness['truncated_summary']=bool(candidates)
    return witness


def compact_helper_witness(witness):
    """Optional detail yields before the complete rejection/aggregate core."""
    fs=witness['filesystem']
    summaries=witness.get('summaries',[])
    while len(canonical(witness))>2048 and summaries:
        summaries.pop();witness['truncated_summary']=True
    if not summaries:witness.pop('summaries',None)
    if witness['exact_old_prefix_equal']:
        witness.pop('observed_prefix_sha256',None);witness.pop('old_prefix_present',None)
        witness.pop('first_mismatching_original_index',None)
    if fs['status']=='observed':
        while len(canonical(witness))>2048 and fs.get('details'):
            fs['details'].pop();fs['truncated']=True
        if not fs.get('details'):fs.pop('details',None)
    # These two facts are exactly reconstructible from the retained counters;
    # omission never discards a measured comparison or filesystem digest.
    if len(canonical(witness))>2048:
        for key in ('expected_count','old_prefix_present'):witness.pop(key,None)
    require(len(canonical(witness))<=2048,'helper rejection witness exceeded bound')


class Journey:
    """Evidence is retained from first turns, never supplied by a resume caller."""
    def __init__(self, root, end, meter, nonce, helper_binary=None, startup_corpus=None):
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'invalid synthetic nonce')
        self.root = Path(root); self.end = end; self.meter = meter; self.nonce = nonce
        require(startup_corpus is None or startup_corpus.manifest['mode']=='synthetic-fixture','private corpus forbidden in offline fixture')
        self.startup_corpus=startup_corpus;self.startup_records={}
        self.requests = 0; self.error = None; self.action_end = end
        self.helper_binary=helper_binary;self.owned_child=None;self.child_turn=None;self.child_ready=threading.Event();self.child_lock=threading.Lock()
        self.turn_helper=None;self.helper_origins={};self.helper_rejection=None
        self.entries = {}; self.turn = None; self.records = []; self.wall_started = time.time(); self.negative = False
        self.negative_reason_witnessed = False;self.negative_evidence=None
        self.cli_ready = threading.Event()
        self.last_request = None
        self.metadata_rejection = None
        self.rollout_rejection = None; self.continuations = {}; self.resume_context_rejection = None; self.first_rollout_audits = {}
        self.harness_sha256 = sha(Path(__file__).read_bytes());self.helper_sha256=sha(Path(helper.__file__).read_bytes())

    def begin(self, label, phase, expected_uuid=None):
        require(label in LABELS and phase in ('first','resume'), 'unplanned turn')
        if phase == 'first': require(label not in self.entries and expected_uuid is None, 'duplicate first session')
        else:
            require(label in self.entries and expected_uuid == self.entries[label]['uuid'], 'resume UUID not bound to retained checkpoint')
        self.turn = {'label': label, 'phase': phase, 'expected_uuid': expected_uuid, 'uuid': None,
                     'issued': None, 'returned': None, 'finished': False, 'started': 0, 'completed': 0,
                     'user_context':None,'resume_mode':None,'resume_environment':None}
        if self.startup_corpus is not None:self.turn.update(startup_issued=None,startup_managed=None,startup_managed_position=None)
        self.turn_helper=None;self.child_ready.clear()
        self.cli_ready.clear(); self.action_end = min(self.end, time.monotonic() + t.ACTION_SECONDS)

    def publish_child(self,process):
        if self.helper_binary is None or self.negative:return
        with self.child_lock:
            require(self.owned_child is None and self.turn is not None,'owned helper publication collision')
            try:self.owned_child=helper.OwnedChild(process,min(self.end,self.action_end),self.helper_binary)
            except (OSError,ValueError):
                self.child_ready.set();raise ValueError('owned CLI helper publication unavailable') from None
            self.child_turn=self.turn;self.child_ready.set()

    def clear_child(self):
        with self.child_lock:
            if self.owned_child is not None:self.owned_child.close()
            self.owned_child=None;self.child_turn=None;self.child_ready.set()

    def observe_helper(self):
        if self.helper_binary is None:return None
        try:
            require(self.child_ready.wait(max(0,min(self.end,self.action_end)-time.monotonic())),'owned helper not published')
            with self.child_lock:
                require(self.owned_child is not None and self.child_turn is self.turn,'owned helper turn unavailable')
                observed=self.owned_child.capture()
                require(self.turn_helper is None or observed==self.turn_helper,'owned helper changed within turn')
                return observed
        except (ValueError,OSError):
            if self.helper_rejection is None:self.helper_rejection={'availability':'unavailable','stage':getattr(self.owned_child,'stage','owned-child-helper'),
                'label':self.turn['label'],'phase':self.turn['phase'],'request':self.last_request,
                'harness_sha256':self.harness_sha256,'codex_source_sha':STOCK_SOURCE}
            raise ValueError('owned CLI helper binding unavailable') from None

    def observe_cli(self, raw):
        row = json.loads(raw, object_pairs_hook=t.unique)
        require(type(row) is dict and type(row.get('type')) is str, 'malformed stock CLI event')
        turn = self.turn
        if self.negative:
            witness=self.negative_evidence
            require(witness is None or witness.get('cli_rejection') is None,'unrecognized negative CLI error')
            kind=row['type'];allowed=kind in ('error','turn.failed')
            if witness is not None:
                key=kind if kind in ('error','turn.failed','thread.started') else 'other'
                witness['event_counts'][key]+=1
                witness['forbidden_thread_event'] |= not allowed
            require(allowed, 'unknown UUID started a real/fallback thread')
            if kind=='error':
                require(set(row)=={'type','message'} and type(row['message']) is str,'malformed negative CLI error')
                message=row['message']
            else:
                require(set(row)=={'type','error'} and type(row['error']) is dict and set(row['error'])=={'message'} and
                    type(row['error']['message']) is str,'malformed negative CLI failure')
                message=row['error']['message']
            family=unknown_reason_family(message)
            if family=='none':
                if witness is not None and witness.get('cli_rejection') is None:
                    encoded=raw.encode('utf-8','surrogatepass') if type(raw) is str else raw
                    witness['cli_rejection']={'classification':'unrecognized-error-message','event_type':kind,
                        'event_index':sum(witness['event_counts'].values())-1,'line_bytes':len(encoded),'line_sha256':sha(encoded),
                        'recognized_reason_before':self.negative_reason_witnessed}
                    witness['cli_event_reason']=self.negative_reason_witnessed
                raise ValueError('unrecognized negative CLI error')
            self.negative_reason_witnessed |= family!='none'
            if witness is not None:
                witness['cli_event_reason']=self.negative_reason_witnessed
                if family!='none':witness['cli_reason_family']=family
            return
        require(turn is not None, 'CLI event without planned process')
        if row['type'] == 'thread.started':
            require(set(row) == {'type','thread_id'} and turn['uuid'] is None, 'duplicate/malformed thread.started')
            actual = session_uuid(row['thread_id'])
            if turn['phase'] == 'resume': require(actual == turn['expected_uuid'], 'resume started wrong or fresh session UUID')
            else: require(actual not in {entry['uuid'] for entry in self.entries.values()}, 'same-cwd sessions are not distinct')
            turn['uuid'] = actual; self.cli_ready.set()
        elif row['type'] == 'turn.started':
            require(turn['uuid'] is not None and turn['started'] == 0, 'turn started before identity or duplicated')
            turn['started'] = 1
        elif row['type'] == 'turn.completed':
            require(turn['started'] == 1 and turn['completed'] == 0 and turn['finished'] and
                    turn['returned'] is not None and type(row.get('usage')) is dict,
                    'false/duplicate turn completion')
            turn['completed'] = 1
        elif row['type'] in ('error','turn.failed'):
            raise ValueError('stock turn failed; no restoration proof')
        else: require(row['type'] in ('item.started','item.updated','item.completed'), 'unknown CLI event kind')

    def pair(self, inputs, issued):
        calls = [(i,v) for i,v in enumerate(inputs) if type(v) is dict and v.get('type') == 'function_call' and v.get('call_id') == issued['call_id']]
        outputs = [(i,v) for i,v in enumerate(inputs) if type(v) is dict and v.get('type') == 'function_call_output' and v.get('call_id') == issued['call_id']]
        require(len(calls) == len(outputs) == 1 and calls[0][0] < outputs[0][0], 'missing/duplicate/reordered bound call/result')
        for index,item,kind in ((calls[0][0],calls[0][1],'function_call'),(outputs[0][0],outputs[0][1],'function_call_output')):
            try:history_item(item,issued,kind)
            except MetadataRejected as error:
                self.record_metadata_rejection(item,issued,kind,index,error.stage)
                raise
        if METADATA in calls[0][1] and METADATA in outputs[0][1]:
            if calls[0][1][METADATA]['turn_id'] != outputs[0][1][METADATA]['turn_id']:
                self.record_metadata_rejection(outputs[0][1],issued,'function_call_output',outputs[0][0],'pair-turn-mismatch')
                raise MetadataRejected('pair-turn-mismatch')
        return calls[0], outputs[0]

    def record_metadata_rejection(self,item,issued,kind,index,stage):
        if self.metadata_rejection is not None:return
        value=item.get(METADATA);is_object=type(value) is dict
        witness={'availability':'observed-shape','rejection_stage':stage,'expected_kind':kind,
            'item_index':index if type(index) is int and 0<=index<=t.BODY_BYTES else None,
            'issued_call_id_matches':item.get('call_id')==issued['call_id'],
            'metadata_present':METADATA in item,'metadata_type':json_type(value),
            'metadata_key_count':len(value) if is_object else None,
            'unknown_key_count':sum(key not in METADATA_KEYS for key in value) if is_object else 0,
            'recognized_keys':{key:{'present':is_object and key in value,
                'type':json_type(value[key]) if is_object and key in value else None} for key in METADATA_KEYS},
            'turn_id_valid':is_object and valid_uuid(value.get('turn_id')),
            'create_time_valid':is_object and valid_timestamp(value.get('create_time')),
            'request':dict(self.last_request) if self.last_request is not None else None,
            'harness_sha256':self.harness_sha256,'codex_source_sha':STOCK_SOURCE}
        if len(canonical(witness))>2048:
            witness={'availability':'witness-unavailable','rejection_stage':stage,
                     'harness_sha256':self.harness_sha256,'codex_source_sha':STOCK_SOURCE,
                     'request':dict(self.last_request) if self.last_request is not None else None}
        self.metadata_rejection=witness

    def record_unavailable_helper_context(self,inputs,observed):
        """Diagnostic-only input projection; never substitute for the failed binding."""
        if 'knownness' in self.helper_rejection:return  # Retain the first helper failure and its request binding.
        phase=self.turn['phase'];label=self.turn['label'];contexts=[item for _,item in observed]
        entry=self.entries.get(label) if phase=='resume' else None
        audited=bool(entry is not None and self.first_rollout_audits.get(label)==sha(canonical(entry)))
        original=[] if entry is None else [item for item in entry['user_context'] if type(item.get(METADATA)) is dict and
            item[METADATA].get('content_item_kinds')==[ENVIRONMENT_KIND]]
        old=original[0]['content'] if audited and len(original)==1 else None
        count=len(entry['user_context']) if entry is not None else 0
        if phase=='resume':current=contexts[count] if len(contexts)==count+2 else None
        else:
            available=[item for item in contexts if type(item.get(METADATA)) is dict and item[METADATA].get('content_item_kinds')==[ENVIRONMENT_KIND]]
            current=available[0] if len(available)==1 else None
        new=(current['content'] if type(current) is dict and type(current.get(METADATA)) is dict and
            current[METADATA].get('content_item_kinds')==[ENVIRONMENT_KIND] else None)
        known={'helper_available':False,'baseline_audited':audited,'old_body_available':old is not None,'new_body_available':new is not None}
        self.helper_rejection['knownness']=known
        if phase!='resume':
            self.helper_rejection['filesystem']={'status':'unavailable','reason':'missing-baseline'}
            return
        if self.resume_context_rejection is not None:return
        witness=resume_rejection_witness(self,observed,inputs,prompt(label,phase,self.nonce))
        witness['helper_binding']=known
        _,comparison=environment_comparison(self,contexts,observed,inputs,diagnostic_only=True)
        compact=compact_comparison(comparison)
        witness['environment_checks']=compact['checks'];witness['baseline_count']=compact['baseline_count']
        witness['body']=compact['body'];fs=compact['filesystem'];witness['filesystem']=fs
        geometry=compact['components']
        witness['components']={key:geometry[key] for key in ('status','known','presence','order','equal','wrapper_equal','complete')}
        witness['components']['truncated']=bool(geometry['changed']) or geometry['truncated']
        compact_helper_witness(witness)
        self.resume_context_rejection=witness

    def startup_action(self,label):
        return {'type':'function_call','call_id':'startup-'+label,'name':'exec_command',
            'arguments':json.dumps({'cmd':t.command("import sys;sys.path.insert(0,'/opt');import startup_delivery as d;raise SystemExit(d.emit_fixed())"),
                                   'login':False,'yield_time_ms':10000,'max_output_tokens':1500})}

    def startup_check(self,inputs,observed):
        if self.startup_corpus is None:return None,None,None
        turn=self.turn;label=turn['label'];position,message=startup.managed(inputs,self.startup_corpus)
        retained=self.startup_records.get(label)
        if retained is None and turn.get('startup_issued') is None:
            require(turn['phase']=='first','resume lacks original startup delivery')
            return 'issue',message,None
        issued=retained['issued'] if retained else turn['startup_issued']
        expected_managed=retained['managed'] if retained else turn['startup_managed']
        expected_position=retained['position'] if retained else turn['startup_managed_position']
        require(position==expected_position and canonical(message)==canonical(expected_managed),'managed startup wire changed or moved')
        call,output=self.pair(inputs,issued)
        original_context=observed[:len(self.entries[label]['user_context'])] if turn['phase']=='resume' else observed
        require(position<call[0]<output[0] and all(i<call[0] for i,_ in original_context),'startup delivery causal order')
        _,status,payload=t.terminal_header(output[1]['output'])
        require(status==0 and payload=='\n'+self.startup_corpus.output().decode()+'\n','complete startup document bodies not delivered')
        if retained:
            require(canonical(call[1])==canonical(retained['call']) and canonical(output[1])==canonical(retained['output']),'startup call/result replay changed')
            return 'retained',message,None
        return 'verified',message,{'issued':copy.deepcopy(issued),'call':copy.deepcopy(call[1]),'output':copy.deepcopy(output[1]),'managed':copy.deepcopy(message),'position':position}

    def request(self, body):
        turn = self.turn
        require(turn is not None and not turn['finished'] and time.monotonic() < self.action_end, 'request outside fixed turn')
        require(type(body) is dict and body.get('model') == t.MODEL and type(body.get('input')) is list,
                'unexpected model or request input')
        encoded = canonical(body); require(len(encoded) <= t.BODY_BYTES, 'request body exceeded')
        self.meter.add(len(encoded)); self.last_request = {'sha256': sha(encoded), 'bytes': len(encoded)}
        require(self.cli_ready.wait(max(0, min(t.ACTION_SECONDS, self.action_end-time.monotonic()))), 'request before actual CLI session identity')
        label, phase = turn['label'], turn['phase']; inputs = body['input']; observed = user_context(inputs)
        contexts = [item for _,item in observed]
        try:observed_helper=self.observe_helper()
        except ValueError:
            try:self.record_unavailable_helper_context(inputs,observed)
            except (ValueError,TypeError,KeyError,IndexError,OverflowError,AttributeError):
                # The original unavailable binding stays authoritative even if
                # the already-received input cannot support a comparison.
                if self.helper_rejection is not None:self.helper_rejection.setdefault('filesystem',{'status':'unavailable'})
            raise
        if observed_helper is not None:self.turn_helper=observed_helper
        own = prompt(label,'first',self.nonce); current = prompt(label,phase,self.nonce)
        own_positions = [i for i,item in observed if exact_prompt_message(item,own)]
        resume_mode=None;resume_environment=None
        if phase=='resume':
            retained=self.entries[label]['user_context'];count=len(retained)
            prefix_equal=canonical(contexts[:count])==canonical(retained)
            no_extra=len(contexts)==count+1 and prefix_equal
            one_extra=len(contexts)==count+2 and prefix_equal
            environment_valid=False;comparison=None
            if one_extra:environment_valid,comparison=environment_comparison(self,contexts,observed,inputs)
            if not (no_extra or environment_valid) or not exact_prompt_message(contexts[-1],current):
                if self.resume_context_rejection is None:
                    witness=resume_rejection_witness(self,observed,inputs,current)
                    if comparison is not None:
                        witness.pop('prompt')  # Same diagnostic is bound inside the compact environment comparison.
                        witness['environment_comparison']=compact_comparison(comparison)
                        # Prefer source/body/prompt bindings over redundant entry summaries.
                        while len(canonical(witness))>2048 and witness['summaries']:
                            witness['summaries'].pop();witness['truncated_summary']=True
                        fs=witness['environment_comparison']['filesystem']
                        if fs['status']=='observed':
                            # Equivalent prefix digests/true presence carry no additional evidence.
                            witness.pop('observed_prefix_sha256',None);witness.pop('old_prefix_present',None);witness.pop('first_mismatching_original_index',None)
                            witness['environment_comparison']['components']['changed']=[]
                            witness['environment_comparison']['components']['truncated']=True
                            while len(canonical(witness))>2048 and fs['details']:
                                fs['details'].pop();fs['truncated']=True
                            if len(canonical(witness))>2048:
                                witness['environment_comparison']['filesystem']={'status':'overflow','counts':fs['counts'],'checks':fs['checks'],'truncated':True}
                        changed=witness['environment_comparison']['components']['changed']
                        while len(canonical(witness))>2048 and changed:
                            changed.pop();witness['environment_comparison']['components']['truncated']=True
                        if len(canonical(witness))>2048:
                            witness['environment_comparison']['components']={'status':['unavailable','unavailable'],'changed':[], 'truncated':True}
                        if len(canonical(witness))>2048:
                            # Core hashes/counts and prompt checks always fit; never replace rejection with a witness exception.
                            witness['environment_comparison'].pop('components')
                            witness['environment_comparison']['component_status']='overflow'
                    self.resume_context_rejection=witness
            require(no_extra or environment_valid,'prior ordered user context changed/injected/removed')
            resume_mode='one-environment' if environment_valid else 'no-environment'
            resume_environment=contexts[-2] if environment_valid else None
        require(len(own_positions) == 1, 'exact prior prompt absent or duplicated')
        if phase == 'first':
            require(exact_prompt_message(contexts[-1],own), 'first prompt must be the exact final user message')
            if turn['user_context'] is not None:
                require(canonical(contexts) == canonical(turn['user_context']), 'first-result user context changed')
        else:
            retained = self.entries[label]['user_context']
            require(canonical(contexts[:len(retained)]) == canonical(retained),
                    'prior ordered user context changed/injected/removed')
            require(exact_prompt_message(contexts[-1],current), 'continuation prompt must be an exact new user message')
            if turn['user_context'] is not None:
                require(canonical(contexts) == canonical(turn['user_context']), 'continuation user context changed')
        other = next(value for value in LABELS if value != label)
        require(('OFFLINE_SESSION_' + other.upper() + '_') not in encoded.decode(), 'cross-session context present')
        startup_state,startup_message,startup_pending=self.startup_check(inputs,observed)
        allowed = {}
        startup_bound=self.startup_records.get(label)
        if startup_bound is not None:allowed[startup_bound['issued']['call_id']]=startup_bound['issued']
        elif turn.get('startup_issued') is not None:allowed[turn['startup_issued']['call_id']]=turn['startup_issued']
        if phase == 'resume':
            entry = self.entries[label]
            current_positions = [observed[-1][0]]
            first_call, first_output = self.pair(inputs, entry['issued'])
            if startup_bound is not None:
                startup_call,startup_output=self.pair(inputs,startup_bound['issued'])
                require(canonical(startup_bound)==canonical(entry.get('startup')) and
                        startup_call[0]<startup_output[0]<first_call[0]<first_output[0]<current_positions[0],
                        'startup delivery crossed original work or continuation')
            require(all(i < first_call[0] for i,_ in observed[:len(entry['user_context'])]) and
                    own_positions[0] < first_call[0] < first_output[0] < current_positions[0] and
                    canonical(first_call[1]) == canonical(entry['call']) and canonical(first_output[1]) == canonical(entry['output']),
                    'restored history not identical to independently observed first turn')
            if resume_mode=='one-environment':
                require(first_output[0]<observed[-2][0]<current_positions[0], 'new environment outside exact continuation position')
            allowed[entry['issued']['call_id']] = entry['issued']
        if turn['issued'] is not None: allowed[turn['issued']['call_id']] = turn['issued']
        for item in inputs:
            if type(item) is not dict: raise ValueError('nonobject history item')
            if 'call_id' in item or str(item.get('type','')).endswith(('_call','_output')):
                require(item.get('type') in ('function_call','function_call_output') and
                        type(item.get('call_id')) is str and item['call_id'] in allowed, 'orphan/cross-kind/unissued history')
        pending = None
        if turn['issued'] is not None:
            call, output = self.pair(inputs, turn['issued'])
            if startup_bound is not None:
                _,startup_output=self.pair(inputs,startup_bound['issued']);require(startup_output[0]<call[0],'work precedes startup documents')
            require(all(i < call[0] for i,_ in observed), 'user context moved across current action')
            require(call[0] > (current_positions[0] if phase == 'resume' else own_positions[0]), 'new action precedes current context')
            _, status, payload = t.terminal_header(output[1]['output'])
            require(status == 0 and payload == '\n'+canonical(progress(label,phase,self.nonce)).decode()+'\n',
                    'tool did not complete exact progress command')
            effect = marker(self.root,label,('first',) if phase == 'first' else ('first','resume'),self.nonce)
            pending = {'call': copy.deepcopy(call[1]), 'output': copy.deepcopy(output[1]), 'effect': effect}
        else:
            require(any(type(v) is dict and v.get('type') == 'function' and v.get('name') == 'exec_command'
                        for v in body.get('tools',[])), 'fixed child tool unavailable')
        if phase=='first' and observed_helper is not None:
            environments=[v for v in contexts if type(v.get(METADATA)) is dict and v[METADATA].get('content_item_kinds')==[ENVIRONMENT_KIND]]
            require(len(environments)==1,'original environment helper binding unavailable')
            model=helper.filesystem(environments[0]['content'],environment_components)
            require(model is not None and model['profile']=='managed' and model['mode']=='restricted' and
                    sum(v==('read',None,'path',observed_helper['path']) for v in model['entries'])==1 and
                    sum(v[3]==observed_helper['path'] for v in model['entries'])==1,
                    'original environment does not bind owned helper')
        # All incoming evidence is checked before acceptance bookkeeping changes.
        rid = 'session-fixture-' + label + '-' + phase + ('-startup' if startup_state=='issue' else '-final' if pending else '-action')
        events = [{'type':'response.created','response':{'id':rid}}]
        if turn['user_context'] is None:
            if phase=='first' and observed_helper is not None:self.helper_origins[label]=observed_helper
            turn['user_context'] = copy.deepcopy(contexts)
            if phase=='resume':
                turn['resume_mode']=resume_mode;turn['resume_environment']=copy.deepcopy(resume_environment)
        if startup_state=='issue':
            issued=self.startup_action(label);turn['startup_issued']=issued;turn['startup_managed']=copy.deepcopy(startup_message);turn['startup_managed_position']=startup.managed(inputs,self.startup_corpus)[0]
            events.append({'type':'response.output_item.done','item':issued})
        elif pending is None:
            if startup_pending is not None:self.startup_records[label]=startup_pending
            require(self.startup_corpus is None or label in self.startup_records,'work before complete startup delivery')
            issued = action(label,phase,self.nonce); turn['issued'] = issued
            events.append({'type':'response.output_item.done','item':issued})
        else:
            turn['returned'] = pending; turn['finished'] = True
            events.append({'type':'response.output_item.done','item':{'type':'message','id':'session-done-'+label+'-'+phase,
                'role':'assistant','content':[{'type':'output_text','text':'Finite offline session checkpoint complete.'}]}})
        events.append({'type':'response.completed','response':{'id':rid,'usage':{'input_tokens':0,'output_tokens':0,'total_tokens':0}}})
        result = ''.join('event: '+v['type']+'\ndata: '+json.dumps(v)+'\n\n' for v in events).encode()
        self.meter.add(len(result)); return result

    def finish(self, status):
        turn = self.turn
        require(status == 0 and turn is not None and turn['uuid'] is not None and turn['finished'] and
                turn['started'] == turn['completed'] == 1 and turn['returned'] is not None, 'process exited without complete bound progress')
        label, phase = turn['label'], turn['phase']
        if phase == 'first':
            self.entries[label] = {'uuid':turn['uuid'], 'expected_prompt':prompt(label,'first',self.nonce),
                                  'user_context':copy.deepcopy(turn['user_context']),
                                  'issued':copy.deepcopy(turn['issued']), **copy.deepcopy(turn['returned'])}
        else:
            self.continuations[label]={'user_context':copy.deepcopy(turn['user_context']),
                'resume_mode':turn['resume_mode'],'resume_environment':copy.deepcopy(turn['resume_environment']),
                'issued':copy.deepcopy(turn['issued']),**copy.deepcopy(turn['returned'])}
        if self.startup_corpus is not None:
            require(label in self.startup_records,'startup delivery not retained')
            if phase=='first':self.entries[label]['startup']=copy.deepcopy(self.startup_records[label])
        self.records.append({'label':label,'phase':phase,'uuid':turn['uuid'], 'context_sha256':sha(canonical(turn['user_context'])),
                             'user_context_count':len(turn['user_context']),
                             'resume_mode':turn['resume_mode'] if phase=='resume' else 'first-turn',
                             'resume_environment_sha256':sha(canonical(turn['resume_environment'])) if turn['resume_environment'] is not None else None,
                             'call_sha256':sha(canonical(turn['returned']['call'])), 'output_sha256':sha(canonical(turn['returned']['output'])),
                             'progress':turn['returned']['effect'], 'pass':True})

    def audit_first_rollout(self,row,label,checkpoint_sha256=None):
        entry=self.entries[label]
        proof=rollout_proof(self.root,row,entry,journey=self,checkpoint_sha256=checkpoint_sha256)
        self.first_rollout_audits[label]=sha(canonical(entry))
        return proof

    def checkpoint(self, path):
        require(set(self.entries) == set(LABELS), 'both first checkpoints are required')
        value = {'version':1,'entries':self.entries,'nonce':self.nonce}
        data = canonical(value); require(len(data) <= t.BODY_BYTES, 'checkpoint exceeds bound')
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
        return sha(data)

    def read_checkpoint(self, path):
        info = Path(path).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                'checkpoint is not private regular data')
        data = t.snapshot(path,t.BODY_BYTES,self.end)
        value = json.loads(data,object_pairs_hook=t.unique)
        require(canonical(value) == canonical({'version':1,'entries':self.entries,'nonce':self.nonce}),
                'checkpoint changed/missing independently retained evidence')
        return {label:session_uuid(value['entries'][label]['uuid']) for label in LABELS}


def database(root, expected=None, integrity=False):
    path = Path(root)/'state/sqlite/state_5.sqlite'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16*1024**2, 'stock state database missing or excessive')
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.1) as db:
        db.execute('PRAGMA query_only=ON')
        if integrity: require(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)], 'stock database integrity failed')
        rows = db.execute('SELECT id,cwd,rollout_path,model_provider FROM threads ORDER BY id LIMIT 129').fetchall()
    require(len(rows) <= 128, 'stock session inventory bound exceeded')
    result = {session_uuid(row[0]):row for row in rows}
    if expected is not None: require(set(result) == set(expected), 'session UUID set changed unexpectedly')
    return result


def rollout_mismatch(journey, stage, contexts, projected, expected, checkpoint_sha256):
    if journey is None or journey.rollout_rejection is not None:return
    index=next((i for i in range(max(len(projected),len(expected)))
                if i>=len(projected) or i>=len(expected) or canonical(projected[i])!=canonical(expected[i])),None)
    observed=contexts[index] if index is not None and index<len(contexts) else {}
    actual=projected[index] if index is not None and index<len(projected) else observed
    wanted=expected[index] if index is not None and index<len(expected) else {}
    known=('type','role','id','content','status','phase','encrypted_content')
    metadata=observed.get(METADATA) if type(observed) is dict else None
    left=actual.get(METADATA,{}) if type(actual) is dict else {};right=wanted.get(METADATA,{})
    witness={'stage':stage,'kind':'durable-rollout','expected_user_count':len(expected),
        'observed_user_count':len(contexts),'first_differing_index':index,
        'raw_context_sha256':sha(canonical(contexts)),'projected_context_sha256':sha(canonical(projected)),
        'wire_context_sha256':sha(canonical(expected)),'projection_applied':bool(projected),
        'field_difference':{key:actual.get(key)!=wanted.get(key) or (key in actual)!=(key in wanted) for key in known},
        'metadata_difference':{key:(left.get(key)!=right.get(key) or (key in left)!=(key in right))
            if type(left) is dict and type(right) is dict else True for key in ('turn_id','create_time','content_item_kinds','content_item_metadata')},
        'recognized_metadata':{key:{'present':type(metadata) is dict and key in metadata,
            'type':json_type(metadata[key]) if type(metadata) is dict and key in metadata else None}
            for key in ('turn_id','create_time','content_item_kinds','content_item_metadata')},
        'unknown_key_count':sum(key not in set(known)|{METADATA} for key in observed)+
            (sum(key not in ('turn_id','create_time','content_item_kinds','content_item_metadata') for key in metadata) if type(metadata) is dict else 0),
        'request':journey.last_request,'checkpoint_sha256':checkpoint_sha256,
        'harness_sha256':journey.harness_sha256,'codex_source_sha':STOCK_SOURCE}
    if len(canonical(witness))>2048:
        witness={'stage':stage,'kind':'durable-rollout','availability':'witness-unavailable',
            'raw_context_sha256':sha(canonical(contexts)),'wire_context_sha256':sha(canonical(expected)),
            'harness_sha256':journey.harness_sha256,'checkpoint_sha256':checkpoint_sha256}
    journey.rollout_rejection=witness


def rollout_proof(root, row, entry, continuation=None, journey=None, checkpoint_sha256=None):
    ident,cwd,raw,provider = row
    require(ident == entry['uuid'] and cwd == '/job' and provider == 'openai' and type(raw) is str,
            'actual thread database identity/cwd/provider mismatch')
    relative = Path(raw).relative_to('/state/codex/sessions')
    require(relative.parts and '..' not in relative.parts, 'rollout path not stock session state')
    path = Path(root)/'state/codex/sessions'/relative
    for parent in (path,*path.parents):
        require(not parent.is_symlink(), 'rollout symlink denied')
        if parent == Path(root):break
    data = t.snapshot(path,2*1024**2,time.monotonic()+1)
    lines=data.splitlines();require(lines and all(len(line)<=t.BODY_BYTES for line in lines), 'rollout line bound exceeded')
    rows=[json.loads(line,object_pairs_hook=t.unique) for line in lines]
    meta=rows[0];require(meta.get('type')=='session_meta' and meta.get('payload',{}).get('id')==ident and
                        meta['payload'].get('cwd')=='/job', 'rollout metadata is not actual bound session')
    items=[r.get('payload') for r in rows if r.get('type')=='response_item']
    contexts=[item for item in items if type(item) is dict and item.get('role')=='user']
    expected=entry['user_context'] if continuation is None else continuation['user_context']
    projected=[];stage='durable-context'
    try:
        for item in contexts:projected.append(durable_user_to_wire(item))
        stage='context-binding'
        require(canonical(projected)==canonical(expected), 'rollout complete observed user context changed')
        original_count=len(entry['user_context'])
        require(canonical(expected[:original_count])==canonical(entry['user_context']) and
                len(expected)==original_count+(2 if continuation is not None and continuation.get('resume_mode')=='one-environment' else 1 if continuation is not None else 0), 'unbound continuation context')
        allowed={entry['issued']['call_id']:entry}
        startup_bound=entry.get('startup')
        if startup_bound is not None:allowed[startup_bound['issued']['call_id']]=startup_bound
        if continuation is not None:allowed[continuation['issued']['call_id']]=continuation
        stage='orphan-history'
        for item in items:
            require(type(item) is dict, 'nonobject durable history')
            if 'call_id' in item or str(item.get('type','')).endswith(('_call','_output')):
                require(item.get('type') in ('function_call','function_call_output') and
                        type(item.get('call_id')) is str and item['call_id'] in allowed, 'unissued durable call/result')
        pairs={};stage='pair-binding'
        for call_id,bound in allowed.items():
            positions=[]
            for kind,key in (('function_call','call'),('function_call_output','output')):
                found=[(i,v) for i,v in enumerate(items) if v.get('type')==kind and v.get('call_id')==call_id]
                require(len(found)==1, 'missing/duplicate durable call/result')
                i,value=found[0];history_item(value,bound['issued'],kind)
                require(canonical(value)==canonical(bound[key]), 'durable call/result differs from retained wire')
                positions.append(i)
            require(positions[0]<positions[1], 'reordered durable call/result');pairs[call_id]=positions
        stage='causal-order'
        original_call,original_output=pairs[entry['issued']['call_id']]
        if startup_bound is not None:
            require(journey is not None and journey.startup_corpus is not None,'startup audit corpus unavailable')
            managed_index,managed=startup.managed(items,journey.startup_corpus,durable=True)
            require(canonical(managed)==canonical(startup_bound['managed']),'durable managed startup changed')
            start_call,start_output=pairs[startup_bound['issued']['call_id']]
            require(managed_index<start_call<start_output<original_call,'durable startup delivery moved')
        user_positions=[i for i,item in enumerate(items) if item.get('role')=='user']
        require(all(i<original_call for i in user_positions[:original_count]), 'prior context follows original call')
        if continuation is not None:
            mode=continuation.get('resume_mode')
            require(mode in ('no-environment','one-environment'),'unbound continuation mode')
            if mode=='one-environment':
                require(canonical(expected[-2])==canonical(continuation.get('resume_environment')) and
                    original_output<user_positions[-2]<user_positions[-1], 'durable environment moved/changed')
            else:require(continuation.get('resume_environment') is None,'unexpected durable environment mode')
            new_call,new_output=pairs[continuation['issued']['call_id']]
            require(original_output<user_positions[-1]<new_call<new_output, 'continuation crossed original causal pair')
    except ValueError:
        rollout_mismatch(journey,stage,contexts,projected,expected,checkpoint_sha256)
        raise
    return {'path_sha256':sha(raw.encode()),'bytes':len(data),'sha256':sha(data),'uuid':ident,'cwd':cwd,
            'raw_user_context_sha256':sha(canonical(contexts)),'projected_user_context_sha256':sha(canonical(projected)),
            'wire_user_context_sha256':sha(canonical(expected)),'projection_applied':True}


def cli_args(port, context, resume=None):
    args=['/opt/codex','-c','openai_base_url='+json.dumps('http://127.0.0.1:'+str(port)+'/v1'),
          '-c','model_catalog_json="/opt/models.json"','exec','--skip-git-repo-check','--json','--model',t.MODEL,'-C','/job']
    if resume is not None: args += ['resume',session_uuid(resume)]
    return args+[context]


def _run_turn(argv, journey, meter, end, monitor=lambda:None, popen=subprocess.Popen):
    negative=getattr(journey,'negative_evidence',None) if getattr(journey,'negative',False) else None
    if negative is not None:negative['launch_handle_observed']=False
    process=popen(argv,env={'PATH':'/usr/bin:/bin','HOME':'/home/gpt','CODEX_HOME':'/state/codex','TMPDIR':'/tmp',
                          'LANG':'C.UTF-8','CODEX_API_KEY':t.SYNTHETIC_KEY},stdin=subprocess.DEVNULL,
                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    if negative is not None:negative.update(stage='launched',launch_handle_observed=True)
    selector=None;line=bytearray();used=0;errors=bytearray();error_bytes=0;stderr_eof=False;stdout_eof=False;natural_exit=None
    try:
        if getattr(journey,'controller_turn',None) is not None:journey.controller_turn.child(process)
        if hasattr(journey,'publish_child'):journey.publish_child(process)
        selector=selectors.DefaultSelector()
        for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        while selector.get_map() or process.poll() is None:
            require(time.monotonic()<min(end,journey.action_end),'session action deadline exhausted')
            require(journey.error is None,'session transport rejected: '+str(journey.error))
            monitor()
            for key,_ in selector.select(.05):
                data=os.read(key.fd,min(65536,t.OUTPUT_BYTES-meter.used+1))
                if not data:
                    if key.data=='stderr':stderr_eof=True
                    if key.data=='stdout':stdout_eof=True
                    selector.unregister(key.fd);continue
                used+=len(data)
                if key.data=='stderr':
                    error_bytes+=len(data);errors.extend(data[:max(0,4096-len(errors))])
                meter.add(len(data))
                if key.data=='stdout':
                    line.extend(data);require(all(len(v)<=t.BODY_BYTES for v in line.split(b'\n')),'CLI line budget exceeded')
                    while b'\n' in line:
                        raw,_,rest=line.partition(b'\n');line[:]=rest;journey.observe_cli(raw)
                        if getattr(journey,'controller_turn',None) is not None:journey.controller_turn.event(raw)
        require(not line,'truncated CLI JSON line')
        family=stderr_reason_family(bytes(errors),stderr_eof and error_bytes<=4096)
        natural_exit=process.wait(timeout=max(.001,end-time.monotonic()))
        return natural_exit,{'captured_bytes':used,'stderr_bytes':error_bytes,
            'stderr_sha256':sha(errors) if error_bytes<=4096 else None,'stderr_capture_complete':stderr_eof and error_bytes<=4096,
            'unknown_uuid_reason_witnessed':family not in (None,'none'),'stderr_reason_family':family}
    finally:
        if negative is not None:
            family=stderr_reason_family(bytes(errors),stderr_eof and error_bytes<=4096)
            negative.update(captured_bytes=used,stderr_bytes=error_bytes,stderr_retained_bytes=len(errors),
                stderr_sha256=sha(errors) if error_bytes<=4096 else None,stderr_capture_complete=stderr_eof and error_bytes<=4096,
                stderr_reason=None if family is None else family!='none',stderr_reason_family=family,
                cli_stream_complete=stdout_eof and not line,natural_exit_observed=natural_exit is not None,natural_exit_code=natural_exit)
        if selector is not None:selector.close()
        owned=getattr(journey,'controller_turn',None);pending=sys.exc_info()[1]
        try:
            try:t.stop(process)
            except BaseException:
                if owned is not None:
                    try:owned.cleanup(False)
                    except Exception:pass
                if owned is None:raise
                if pending is None:raise ValueError('owned child cleanup unresolved; details withheld') from None
            else:
                if owned is not None:
                    try:owned.cleanup(True)
                    except Exception:
                        if pending is None:raise ValueError('controller cleanup observation unavailable') from None
        finally:
            if hasattr(journey,'clear_child'):journey.clear_child()



def run_turn(argv, journey, meter, end, monitor=lambda:None, popen=subprocess.Popen):
    registry=getattr(journey,'controller_registry',None)
    # Negative UUID diagnostic remains the actual pinned CLI oracle, outside the
    # positive-turn registry. It can never register an unknown UUID as a session.
    if registry is None or getattr(journey,'negative',False):
        return _run_turn(argv,journey,meter,end,monitor,popen)
    turn=journey.turn;label=turn['label'];phase=turn['phase'];resume=turn['expected_uuid']
    expected=cli_args(journey.controller_port,prompt(label,phase,journey.nonce),resume)
    require(argv==expected,'submitted CLI differs from fixed session adapter')
    operation='turn-'+label+'-'+phase
    with registry.owner():
        registry.uncertain()
        row,created=registry.reserve(operation,label,expected[-1],min(end,journey.action_end),resume)
        if not created:
            # Observation is not replayed into Journey as fresh CLI evidence.
            raise controller.ExistingOperation(row)
        owned=controller.TurnOwner(registry,operation);journey.controller_turn=owned
        try:
            owned.launching()
            code,details=_run_turn(expected,journey,meter,end,monitor,popen)
            try:owned.finish(code,True)
            except (OSError,sqlite3.Error):raise ValueError('controller terminal record unavailable') from None
            return code,details
        except BaseException:
            try:
                if registry.row(operation)['state'] in controller.ACTIVE:owned.fail(uncertain=True)
            except Exception:pass  # Registry diagnostics cannot mask the primary.
            raise
        finally:journey.controller_turn=None


def fixture_registry(root,receipt):
    """Link the finite adapter to real v1 ledger identities, without altering v1."""
    import job_protocol as protocol
    require(type(receipt) is dict and set(receipt)=={'startup','identity'},'invalid fixture controller receipt')
    controller.validate_startup(receipt['startup'])
    identity=receipt['identity'];require(type(identity) is dict and set(identity)=={'source_revision','source_sha256','runtime_sha256','binary_sha256','policy_sha256','layout_sha256'},'invalid fixture controller identity')
    ledger=protocol.Ledger(Path(root)/'job-ledger')
    identity=receipt['identity'];runtime=identity['runtime_sha256']
    agreement=sha(canonical({'scope':'finite-offline-session-fixture','real_model':False,'auth_verified':False}))
    job=protocol.envelope('job',job_id='offline-session-fixture',standards_sha=controller.STANDARDS,agreement_sha256=agreement,
        selection={'provider':'gptbox','model':t.MODEL,'effort':'medium','runtime_sha256':runtime,'verification':'unverified-record-only'},
        budgets={'seconds':t.ACTION_SECONDS,'artifact_bytes':65536,'spend_usd':0},max_requests=64)
    ledger.create_job(job)
    checkpoint=protocol.envelope('checkpoint',job_id=job['job_id'],checkpoint_id='fixed-session-inputs',
        candidate={'source_revision':identity['source_revision'],'artifact_sha256':identity['binary_sha256']},
        test=protocol.recipe_identity(),summary='Finite synthetic selection record; effort/model consumption are unverified.',evidence=[])
    ledger.checkpoint(checkpoint)
    binding={'controller_id':ledger.controller_id,'job_id':job['job_id'],'checkpoint_id':checkpoint['checkpoint_id'],
        'checkpoint_sha256':protocol.identity(checkpoint),'job_sha256':protocol.identity(job),'source_revision':identity['source_revision'],'source_sha256':identity['source_sha256'],'runtime_sha256':runtime,
        'binary_sha256':identity['binary_sha256'],'policy_sha256':identity['policy_sha256'],'layout_sha256':identity['layout_sha256'],
        'standards_sha':controller.STANDARDS,'agreement_sha256':agreement,'provider':'openai','model':t.MODEL,
        'effort':'unconfigured-fixture','credential_ref':'offline-synthetic-key','startup_sha256':sha(canonical(receipt['startup']))}
    try:registry=controller.Registry(Path(root)/'session-registry',binding)
    except BaseException:
        ledger.close();raise
    registry.ledger=ledger
    return registry

def check_unknown_uuid(report,journey,argv,meter,end,runner=run_turn):
    before=journey.requests
    witness={'stage':'attempted','harness_sha256':journey.harness_sha256,'codex_source_sha':STOCK_SOURCE,
        'helper_source_sha256':journey.helper_sha256,'launch_handle_observed':None,'exit_code':None,'exit_status_valid':None,'natural_exit_observed':None,'natural_exit_code':None,
        'requests_before':before,'requests_after':None,'request_delta':None,'captured_bytes':None,
        'stderr_bytes':None,'stderr_retained_bytes':None,'stderr_sha256':None,'stderr_capture_complete':None,
        'stderr_reason':None,'stderr_reason_family':None,'cli_event_reason':None,'cli_reason_family':None,'matched_reason_family':None,
        'cli_stream_complete':None,'cli_rejection':None,'event_counts':{'error':0,'turn.failed':0,'thread.started':0,'other':0},'forbidden_thread_event':False}
    report['unknown_uuid_evidence']=witness;journey.negative_evidence=witness
    journey.negative_reason_witnessed=False
    try:
        code,negative=runner(argv,journey,meter,end)
        witness.update(stage='returned',exit_code=code if type(code) is int and -255<=code<=255 else None,
            exit_status_valid=type(code) is int and -255<=code<=255,requests_after=journey.requests,request_delta=journey.requests-before,
            stderr_reason=negative['unknown_uuid_reason_witnessed'] if negative.get('stderr_capture_complete') is True else None,stderr_reason_family=negative.get('stderr_reason_family'),
            stderr_bytes=negative['stderr_bytes'],stderr_sha256=negative['stderr_sha256'],
            stderr_capture_complete=negative.get('stderr_capture_complete'),cli_event_reason=journey.negative_reason_witnessed)
        witness['matched_reason_family']=(witness['stderr_reason_family'] if witness['stderr_reason'] else
            witness['cli_reason_family'] if witness['cli_event_reason'] else 'none')
        require(type(code) is int and code==1 and journey.requests==before and not witness['forbidden_thread_event'] and witness['cli_rejection'] is None and
                (witness['stderr_reason'] or witness['cli_event_reason']),
                'unknown UUID rejection reason unproven or model dispatch occurred')
        report['unknown_uuid_rejected']=True
    finally:
        witness['requests_after']=journey.requests;witness['request_delta']=journey.requests-before
        if witness['stage']!='returned':witness['stage']='exception'


def final_session_audits(report,journey,initial,ids,source,root='/'):
    final=database(root,set(initial)|set(ids.values()),integrity=True)
    report['sessions']={label:{'uuid':ids[label],'progress':marker(root,label,('first','resume'),journey.nonce),
        'rollout':rollout_proof(root,final[ids[label]],journey.entries[label],continuation=journey.continuations[label],
            journey=journey,checkpoint_sha256=report['checkpoint_sha256'])} for label in LABELS}
    require(source.read_bytes()==UNCOMMITTED,'uncommitted source changed')
    report['uncommitted_source_sha256']=sha(UNCOMMITTED);report['database_integrity']='ok';report['uuid_set_unchanged']=True
    report['status']='pass'


def worker(args):
    report={'version':1,'status':'blocked','runtime_admitted':False,'real_model':False,'auth_verified':False,
            'replacement_verified':False,'interruption':'completed first-turn checkpoints; each stock process reaped before explicit UUID resume'}
    server=None;thread=None;journey=None;registry=None
    try:
        identity=t.private_loopback(args.host_netns);report['namespace']=identity
        report['setup_namespace']=json.loads(t.snapshot('/result/setup.json',1024,args.end),object_pairs_hook=t.unique)
        require(identity['uid']==identity['gid']==1000 and identity['uid_map'].split()==['1000','0','1'] and
                identity['gid_map'].split()==['1000','0','1'],'fixed single-identity namespace mismatch')
        meter=t.Meter(args.captured_seed,args.captured_seed+args.output_limit)
        corpus=startup.read_bundle(startup.ROOT)
        import codex_state as startup_state
        import tomllib
        actual_requirements=tomllib.loads(Path('/etc/codex/requirements.toml').read_text())
        expected_requirements=startup_state.generated_policy()['requirements'];expected_requirements['additional_developer_instructions']=corpus.directive()
        require(canonical(actual_requirements)==canonical(expected_requirements),'immutable startup requirements changed')
        journey=Journey('/',args.end,meter,uuid.uuid4().hex,helper_binary='/opt/codex',startup_corpus=corpus)
        source=Path('/job/src/uncommitted-session-source');source.write_bytes(UNCOMMITTED)
        initial=database('/',integrity=True)
        server=t.FixtureServer(('127.0.0.1',0),t.Handler);server.connections=0;server.sequence=journey
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
        port=server.server_address[1]
        receipt=json.loads(Path('/opt/session-startup.json').read_bytes(),object_pairs_hook=t.unique)
        session_policy=startup_state.generated_policy();session_policy['requirements']=expected_requirements
        session_layout={**startup_state.layout(),'immutable':[*startup_state.layout()['immutable'],startup.ROOT,'/opt/startup_delivery.py']}
        require(receipt['identity']['policy_sha256']==sha(canonical(session_policy)) and receipt['identity']['layout_sha256']==sha(canonical(session_layout)) and corpus.manifest['project_revision']==receipt['identity']['source_revision'],'startup policy/layout/source receipt mismatch')
        registry=fixture_registry('/result',receipt);journey.controller_registry=registry;journey.controller_port=port
        report['controller_startup']=receipt['startup']
        for label in LABELS:
            journey.begin(label,'first')
            code,_=run_turn(cli_args(port,prompt(label,'first',journey.nonce)),journey,meter,args.end)
            journey.finish(code)
            require(source.read_bytes()==UNCOMMITTED,'uncommitted source changed')
        report['checkpoint_sha256']=journey.checkpoint('/result/checkpoint.json')
        ids=journey.read_checkpoint('/result/checkpoint.json')
        rows=database('/',set(initial)|set(ids.values()),integrity=True)
        report['first_rollouts']={label:journey.audit_first_rollout(rows[ids[label]],label,report['checkpoint_sha256']) for label in LABELS}
        import job_protocol as protocol
        current=registry.ledger.record('checkpoint','fixed-session-inputs')
        current.update(checkpoint_id='verified-first-turns',summary='Both independent first-turn histories and progress retained; rollout audit remains required.',evidence=['sha256:'+report['checkpoint_sha256']])
        registry.ledger.checkpoint(current)
        for label in LABELS:
            require(journey.read_checkpoint('/result/checkpoint.json')==ids,'checkpoint identities changed')
            journey.begin(label,'resume',ids[label])
            code,_=run_turn(cli_args(port,prompt(label,'resume',journey.nonce),ids[label]),journey,meter,args.end)
            journey.finish(code)
            require(source.read_bytes()==UNCOMMITTED,'uncommitted source changed')
            database('/',set(initial)|set(ids.values()),integrity=True)
        require(UNKNOWN not in rows,'unknown UUID collides with actual session')
        # Pinned source resolves a UUID directly into thread/resume; an error is
        # propagated rather than selecting --last/name/cwd or starting a thread.
        requests=journey.requests;journey.turn=None;journey.negative=True;journey.action_end=min(args.end,time.monotonic()+t.ACTION_SECONDS)
        check_unknown_uuid(report,journey,cli_args(port,'Unknown UUID negative fixture only',UNKNOWN),meter,args.end)
        final_session_audits(report,journey,initial,ids,source)
    except Exception as error:report['blocker']=str(error)[:500]
    finally:
        if server is not None:
            closing=threading.Thread(target=server.shutdown,daemon=True);closing.start();closing.join(timeout=1)
            server.server_close();thread.join(timeout=1)
            if closing.is_alive() or thread.is_alive():report.update(status='blocked',listener_cleanup='unresolved')
            else:report['listener_cleanup']='complete'
        if journey is not None:
            report.update(turns=journey.records,http_requests=journey.requests,http_connections=server.connections if server else 0,
                          transport_error=journey.error,last_request=journey.last_request,captured_bytes=journey.meter.used,
                          observed_session_uuids={k:v['uuid'] for k,v in journey.entries.items()},
                          helper_source_sha256=journey.helper_sha256,helper_rejection=journey.helper_rejection,history_metadata_rejection=journey.metadata_rejection,rollout_rejection=journey.rollout_rejection,resume_context_rejection=journey.resume_context_rejection)
        if registry is not None:
            try:report['managed_inventory']=registry.inventory()
            except Exception:
                report.update(status='blocked',managed_inventory={'availability':'unavailable','reason':'registry-rejected'})
            finally:registry.close()
            report['managed_inventory_boundary']='positive fixed turns only; actual unknown-UUID diagnostic remains separately audited'
        if journey is not None and journey.startup_corpus is not None:
            report['startup_delivery']={**journey.startup_corpus.receipt(),'wire_delivery_sessions':sorted(journey.startup_records),'model_understanding_verified':False}
        data=canonical(report)+b'\n';require(len(data)<=t.REPORT_BYTES,'session report exceeded')
        fd=os.open('/result/report.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data)
    return 0 if report['status']=='pass' else 2


def main():
    started=time.monotonic();parser=argparse.ArgumentParser(description=__doc__)
    for name in ('worker','setup'):parser.add_argument('--'+name,action='store_true')
    parser.add_argument('--host-netns',type=int);parser.add_argument('--end',type=float)
    parser.add_argument('--output-limit',type=int,default=t.OUTPUT_BYTES-65536);parser.add_argument('--captured-seed',type=int,default=0)
    for name in ('binary','catalog','report'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--standards-cache',type=Path,default=Path('/workspace/standards'))
    args=parser.parse_args()
    if args.setup:return t.setup_worker(args)
    if args.worker:return worker(args)
    require(args.binary and args.catalog and args.report,'binary/catalog/new report required')
    require(not args.report.exists() and not args.report.is_symlink(),'report must be new')
    import codex_state as state
    report={'version':1,'status':'blocked','runtime_admitted':False,'real_model':False,'auth_verified':False,'replacement_verified':False}
    require(ctypes.CDLL(None).prctl(36,1,0,0,0)==0,'owned subreaper unavailable')
    root=tempfile.mkdtemp(prefix='dev-pair-sessions-');runner=None;safe=False
    try:
        startup_receipt=controller.startup_receipt(Path(__file__).resolve().parent.parent,args.standards_cache,started+t.SECONDS)
        runner=state.Harness(root,args.binary);runner.end=min(runner.end,started+t.SECONDS)
        report['state_component']=runner.exercise()
        revision=subprocess.check_output(['/usr/bin/git','-C',str(Path(__file__).resolve().parent.parent),'rev-parse','HEAD'],text=True).strip()
        corpus=startup.synthetic(revision);startup_documents=corpus.stage(Path(root)/'startup-documents')
        policy=state.generated_policy();policy['requirements']['additional_developer_instructions']=corpus.directive()
        requirements_path=runner.fixture/'etc/codex/requirements.toml';requirements_path.write_text(state.toml(policy['requirements']));requirements_path.chmod(0o444)
        report['managed_startup_inputs']=corpus.receipt()
        catalog=t.snapshot(args.catalog,1048576,runner.end);require(sha(catalog)==CATALOG_SHA,'unreviewed fixture catalog')
        selected=[m for m in json.loads(catalog,object_pairs_hook=t.unique)['models'] if m.get('slug')==t.MODEL]
        require(len(selected)==1,'fixture catalog model absent/ambiguous')
        files=stage_session_sources(root,runner.end)
        models=Path(root)/'models.json';models.write_bytes(catalog);models.chmod(0o444)
        receipt={'startup':startup_receipt,'identity':{'source_revision':subprocess.check_output(['/usr/bin/git','-C',str(Path(__file__).resolve().parent.parent),'rev-parse','HEAD'],text=True).strip(),'source_sha256':sha(canonical({name:sha(path.read_bytes()) for name,path in files.items()})),'runtime_sha256':sha(Path(__file__).with_name('gptbox_runtime.py').read_bytes()),'binary_sha256':state.CODEX_SHA,'policy_sha256':sha(canonical(policy)),'layout_sha256':sha(canonical({**state.layout(),'immutable':[*state.layout()['immutable'],startup.ROOT,'/opt/startup_delivery.py']}))}}
        startup_path=Path(root)/'session-startup.json';startup_path.write_bytes(canonical(receipt));startup_path.chmod(0o444)
        result=Path(root)/'result';result.mkdir(mode=0o700)
        argv=runner.argv(['/usr/bin/python3','-I','/opt/tool_boundary.py','--setup','--host-netns',str(os.stat('/proc/self/ns/net').st_ino),
                          '--end',str(runner.end-5),'--output-limit',str(t.OUTPUT_BYTES-runner.used-65536),'--captured-seed',str(runner.used)])
        index=argv.index('--cap-drop');del argv[index:index+2]
        index=argv.index('--unshare-all')+1
        argv[index:index]=['--uid','0','--gid','0','--cap-drop','ALL','--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SETPCAP','--cap-add','CAP_SETFCAP']
        index=argv.index('--remount-ro');argv[index:index]=[*session_source_mounts(files),'--ro-bind',str(startup_documents),startup.ROOT,'--ro-bind',str(startup_path),'/opt/session-startup.json','--ro-bind',str(models),'/opt/models.json','--bind',str(result),'/result']
        process=subprocess.Popen(argv,env=state.ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 start_new_session=True,preexec_fn=state.child_limits)
        try:
            budget=[t.OUTPUT_BYTES-65536];code,_=t.capture(process,runner.end-5,budget,runner.budget)
            outer=budget[0]-(t.OUTPUT_BYTES-65536);require(code in (0,2),'isolated session worker failed')
        finally:
            t.stop(process);t.reap_owned(min(runner.end,time.monotonic()+3));safe=True
        report.update(json.loads(t.snapshot(result/'report.json',t.REPORT_BYTES,runner.end),object_pairs_hook=t.unique))
        require(report.get('captured_bytes',0)+outer<=t.OUTPUT_BYTES,'combined capture exceeded')
        report['captured_bytes']=report.get('captured_bytes',0)+outer
        report['identity']={'binary_sha256':state.CODEX_SHA,'binary_bytes':state.CODEX_BYTES,'codex_source_sha':state.CODEX_SOURCE,
            'session_harness_sha256':sha(files['worker.py'].read_bytes()),'transport_harness_sha256':sha(files['codex_tools.py'].read_bytes()),
            'state_harness_sha256':sha(Path(state.__file__).read_bytes()),'catalog_sha256':sha(catalog),
            'requirements_sha256':sha(state.toml(state.generated_policy()['requirements']).encode()),
            'config_sha256':sha(state.toml(state.generated_policy()['config']).encode())}
        runner.budget()
    except Exception as error:report.update(status='blocked',blocker=str(error)[:500])
    finally:
        if not safe:
            try:t.reap_owned(min(runner.end if runner else started+t.SECONDS,time.monotonic()+3));safe=True
            except Exception:report.update(status='blocked',owned_fixture_cleanup='unresolved; fixture preserved',retained_fixture=root)
        if safe:t.finish_fixture(root,report,runner.end if runner else started+t.SECONDS)
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    report['remaining_gates']=(['actual stock proof after source review'] if report['status']!='pass' else [])+['Fedora/gptbox/authenticated session restoration',
        'in-flight operation recovery','image/version migration and replacement','all active sessions and renewal scheduling','hard storage and distinct-owner admission']
    data=canonical(report)+b'\n';require(len(data)<=t.REPORT_BYTES,'final report exceeded')
    fd=os.open(args.report,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data)
    return 0 if report['status']=='pass' else 2


if __name__=='__main__':raise SystemExit(main())
