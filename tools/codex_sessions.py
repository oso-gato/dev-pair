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


def unknown_reason(text):
    return type(text) is str and text in {prefix+'no rollout found for '+kind+' id '+UNKNOWN
        for prefix in ('','Error: ') for kind in ('thread','conversation')}


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


class Journey:
    """Evidence is retained from first turns, never supplied by a resume caller."""
    def __init__(self, root, end, meter, nonce):
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'invalid synthetic nonce')
        self.root = Path(root); self.end = end; self.meter = meter; self.nonce = nonce
        self.requests = 0; self.error = None; self.action_end = end
        self.entries = {}; self.turn = None; self.records = []; self.wall_started = time.time(); self.negative = False
        self.negative_reason_witnessed = False
        self.cli_ready = threading.Event()
        self.last_request = None
        self.metadata_rejection = None
        self.rollout_rejection = None; self.continuations = {}; self.resume_context_rejection = None
        self.harness_sha256 = sha(Path(__file__).read_bytes())

    def begin(self, label, phase, expected_uuid=None):
        require(label in LABELS and phase in ('first','resume'), 'unplanned turn')
        if phase == 'first': require(label not in self.entries and expected_uuid is None, 'duplicate first session')
        else:
            require(label in self.entries and expected_uuid == self.entries[label]['uuid'], 'resume UUID not bound to retained checkpoint')
        self.turn = {'label': label, 'phase': phase, 'expected_uuid': expected_uuid, 'uuid': None,
                     'issued': None, 'returned': None, 'finished': False, 'started': 0, 'completed': 0,
                     'user_context':None}
        self.cli_ready.clear(); self.action_end = min(self.end, time.monotonic() + t.ACTION_SECONDS)

    def observe_cli(self, raw):
        row = json.loads(raw, object_pairs_hook=t.unique)
        require(type(row) is dict and type(row.get('type')) is str, 'malformed stock CLI event')
        turn = self.turn
        if self.negative:
            require(row['type'] in ('error','turn.failed'), 'unknown UUID started a real/fallback thread')
            self.negative_reason_witnessed |= unknown_reason(row.get('message')) or unknown_reason(
                row.get('error',{}).get('message') if type(row.get('error')) is dict else None)
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
        own = prompt(label,'first',self.nonce); current = prompt(label,phase,self.nonce)
        own_positions = [i for i,item in observed if exact_prompt_message(item,own)]
        if phase=='resume' and self.resume_context_rejection is None:
            retained=self.entries[label]['user_context']
            if not (len(contexts)==len(retained)+1 and canonical(contexts[:-1])==canonical(retained) and
                    exact_prompt_message(contexts[-1],current)):
                self.resume_context_rejection=resume_rejection_witness(self,observed,inputs,current)
        require(len(own_positions) == 1, 'exact prior prompt absent or duplicated')
        if phase == 'first':
            require(exact_prompt_message(contexts[-1],own), 'first prompt must be the exact final user message')
            if turn['user_context'] is not None:
                require(canonical(contexts) == canonical(turn['user_context']), 'first-result user context changed')
        else:
            retained = self.entries[label]['user_context']
            require(len(contexts) == len(retained)+1 and canonical(contexts[:-1]) == canonical(retained),
                    'prior ordered user context changed/injected/removed')
            require(exact_prompt_message(contexts[-1],current), 'continuation prompt must be an exact new user message')
            if turn['user_context'] is not None:
                require(canonical(contexts) == canonical(turn['user_context']), 'continuation user context changed')
        other = next(value for value in LABELS if value != label)
        require(('OFFLINE_SESSION_' + other.upper() + '_') not in encoded.decode(), 'cross-session context present')
        allowed = {}
        if phase == 'resume':
            entry = self.entries[label]
            current_positions = [observed[-1][0]]
            first_call, first_output = self.pair(inputs, entry['issued'])
            require(all(i < first_call[0] for i,_ in observed[:-1]) and
                    own_positions[0] < first_call[0] < first_output[0] < current_positions[0] and
                    canonical(first_call[1]) == canonical(entry['call']) and canonical(first_output[1]) == canonical(entry['output']),
                    'restored history not identical to independently observed first turn')
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
        # All incoming evidence is checked before acceptance bookkeeping changes.
        rid = 'session-fixture-' + label + '-' + phase + ('-final' if pending else '-action')
        events = [{'type':'response.created','response':{'id':rid}}]
        if turn['user_context'] is None:turn['user_context'] = copy.deepcopy(contexts)
        if pending is None:
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
                'issued':copy.deepcopy(turn['issued']),**copy.deepcopy(turn['returned'])}
        self.records.append({'label':label,'phase':phase,'uuid':turn['uuid'], 'context_sha256':sha(canonical(turn['user_context'])),
                             'user_context_count':len(turn['user_context']),
                             'call_sha256':sha(canonical(turn['returned']['call'])), 'output_sha256':sha(canonical(turn['returned']['output'])),
                             'progress':turn['returned']['effect'], 'pass':True})

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
                len(expected)==original_count+(1 if continuation is not None else 0), 'unbound continuation context')
        allowed={entry['issued']['call_id']:entry}
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
        user_positions=[i for i,item in enumerate(items) if item.get('role')=='user']
        require(all(i<original_call for i in user_positions[:original_count]), 'prior context follows original call')
        if continuation is not None:
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


def run_turn(argv, journey, meter, end, monitor=lambda:None, popen=subprocess.Popen):
    process=popen(argv,env={'PATH':'/usr/bin:/bin','HOME':'/home/gpt','CODEX_HOME':'/state/codex','TMPDIR':'/tmp',
                          'LANG':'C.UTF-8','CODEX_API_KEY':t.SYNTHETIC_KEY},stdin=subprocess.DEVNULL,
                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    selector=None;line=bytearray();used=0;errors=bytearray();error_bytes=0
    try:
        selector=selectors.DefaultSelector()
        for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        while selector.get_map() or process.poll() is None:
            require(time.monotonic()<min(end,journey.action_end),'session action deadline exhausted')
            require(journey.error is None,'session transport rejected: '+str(journey.error))
            monitor()
            for key,_ in selector.select(.05):
                data=os.read(key.fd,min(65536,t.OUTPUT_BYTES-meter.used+1))
                if not data:selector.unregister(key.fd);continue
                meter.add(len(data));used+=len(data)
                if key.data=='stderr':
                    error_bytes+=len(data);errors.extend(data[:max(0,4096-len(errors))])
                if key.data=='stdout':
                    line.extend(data);require(all(len(v)<=t.BODY_BYTES for v in line.split(b'\n')),'CLI line budget exceeded')
                    while b'\n' in line:
                        raw,_,rest=line.partition(b'\n');line[:]=rest;journey.observe_cli(raw)
        require(not line,'truncated CLI JSON line')
        negative_witness = error_bytes <= 4096 and any(unknown_reason(line) for line in errors.decode('utf-8','replace').splitlines())
        return process.wait(timeout=max(.001,end-time.monotonic())),{'captured_bytes':used,'stderr_bytes':error_bytes,
            'stderr_sha256':sha(errors) if error_bytes<=4096 else None,'unknown_uuid_reason_witnessed':negative_witness}
    finally:
        if selector is not None:selector.close()
        t.stop(process)


def worker(args):
    report={'version':1,'status':'blocked','runtime_admitted':False,'real_model':False,'auth_verified':False,
            'replacement_verified':False,'interruption':'completed first-turn checkpoints; each stock process reaped before explicit UUID resume'}
    server=None;thread=None;journey=None
    try:
        identity=t.private_loopback(args.host_netns);report['namespace']=identity
        report['setup_namespace']=json.loads(t.snapshot('/result/setup.json',1024,args.end),object_pairs_hook=t.unique)
        require(identity['uid']==identity['gid']==1000 and identity['uid_map'].split()==['1000','0','1'] and
                identity['gid_map'].split()==['1000','0','1'],'fixed single-identity namespace mismatch')
        meter=t.Meter(args.captured_seed,args.captured_seed+args.output_limit)
        journey=Journey('/',args.end,meter,uuid.uuid4().hex)
        source=Path('/job/src/uncommitted-session-source');source.write_bytes(UNCOMMITTED)
        initial=database('/',integrity=True)
        server=t.FixtureServer(('127.0.0.1',0),t.Handler);server.connections=0;server.sequence=journey
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
        port=server.server_address[1]
        for label in LABELS:
            journey.begin(label,'first')
            code,_=run_turn(cli_args(port,prompt(label,'first',journey.nonce)),journey,meter,args.end)
            journey.finish(code)
            require(source.read_bytes()==UNCOMMITTED,'uncommitted source changed')
        report['checkpoint_sha256']=journey.checkpoint('/result/checkpoint.json')
        ids=journey.read_checkpoint('/result/checkpoint.json')
        rows=database('/',set(initial)|set(ids.values()),integrity=True)
        report['first_rollouts']={label:rollout_proof('/',rows[ids[label]],journey.entries[label],journey=journey,
            checkpoint_sha256=report['checkpoint_sha256']) for label in LABELS}
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
        code,negative=run_turn(cli_args(port,'Unknown UUID negative fixture only',UNKNOWN),journey,meter,args.end)
        require(code==1 and journey.requests==requests and (negative['unknown_uuid_reason_witnessed'] or journey.negative_reason_witnessed),
                'unknown UUID rejection reason unproven or model dispatch occurred')
        report['unknown_uuid_rejected']=True;report['unknown_uuid_evidence']=negative
        final=database('/',set(initial)|set(ids.values()),integrity=True)
        report['sessions']={label:{'uuid':ids[label],'progress':marker('/',label,('first','resume'),journey.nonce),
            'rollout':rollout_proof('/',final[ids[label]],journey.entries[label],continuation=journey.continuations[label],
                journey=journey,checkpoint_sha256=report['checkpoint_sha256'])} for label in LABELS}
        require(source.read_bytes()==UNCOMMITTED,'uncommitted source changed')
        report['uncommitted_source_sha256']=sha(UNCOMMITTED);report['database_integrity']='ok';report['uuid_set_unchanged']=True
        report['status']='pass'
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
                          history_metadata_rejection=journey.metadata_rejection,rollout_rejection=journey.rollout_rejection,resume_context_rejection=journey.resume_context_rejection)
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
        runner=state.Harness(root,args.binary);runner.end=min(runner.end,started+t.SECONDS)
        report['state_component']=runner.exercise()
        catalog=t.snapshot(args.catalog,1048576,runner.end);require(sha(catalog)==CATALOG_SHA,'unreviewed fixture catalog')
        selected=[m for m in json.loads(catalog,object_pairs_hook=t.unique)['models'] if m.get('slug')==t.MODEL]
        require(len(selected)==1,'fixture catalog model absent/ambiguous')
        files={}
        for name,source in (('worker.py',Path(__file__)),('codex_tools.py',Path(t.__file__))):
            path=Path(root)/name;path.write_bytes(t.snapshot(source,131072,runner.end));path.chmod(0o444);files[name]=path
        models=Path(root)/'models.json';models.write_bytes(catalog);models.chmod(0o444)
        result=Path(root)/'result';result.mkdir(mode=0o700)
        argv=runner.argv(['/usr/bin/python3','-I','/opt/tool_boundary.py','--setup','--host-netns',str(os.stat('/proc/self/ns/net').st_ino),
                          '--end',str(runner.end-5),'--output-limit',str(t.OUTPUT_BYTES-runner.used-65536),'--captured-seed',str(runner.used)])
        index=argv.index('--cap-drop');del argv[index:index+2]
        index=argv.index('--unshare-all')+1
        argv[index:index]=['--uid','0','--gid','0','--cap-drop','ALL','--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SETPCAP','--cap-add','CAP_SETFCAP']
        index=argv.index('--remount-ro');argv[index:index]=['--ro-bind',str(files['worker.py']),'/opt/tool_boundary.py',
            '--ro-bind',str(files['codex_tools.py']),'/opt/codex_tools.py','--ro-bind',str(models),'/opt/models.json','--bind',str(result),'/result']
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
