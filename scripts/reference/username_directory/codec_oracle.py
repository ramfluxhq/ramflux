#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent codec/size oracle: Python stdlib only, no product or crypto calls."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import unicodedata

HERE = Path(__file__).resolve().parent
M = 9007199254740991
T = M - 10000000
H = base64.urlsafe_b64encode(bytes(32)).decode().rstrip('=')
I = base64.urlsafe_b64encode(bytes([1]) * 32).decode().rstrip('=')
S = base64.urlsafe_b64encode(bytes(64)).decode().rstrip('=')
NODE = '.'.join(['a' * 63] * 3 + ['a' * 61])
NAME = 'm' * 32

def encode(value):
    """Separate encoder for the schema's restricted JCS vocabulary (no floats)."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if type(value) is int:
        if not 0 <= value <= M:
            raise ValueError('unsafe integer')
        return str(value)
    if isinstance(value, str):
        out = '"'
        for ch in value:
            n = ord(ch)
            if ch in ('"', '\\'):
                out += '\\' + ch
            elif n < 32:
                out += {8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r'}.get(n, '\\u%04x' % n)
            elif 0xD800 <= n <= 0xDFFF:
                raise ValueError('surrogate')
            else:
                out += ch
        return out + '"'
    if isinstance(value, list):
        return '[' + ','.join(encode(v) for v in value) + ']'
    if isinstance(value, dict):
        assert all(k.isascii() for k in value)
        return '{' + ','.join(encode(k) + ':' + encode(value[k]) for k in sorted(value)) + '}'
    raise ValueError('unsupported primitive')

def size(value):
    return len(encode(value).encode())

def ref(epoch=M-1):
    return dict(version=2, epoch=epoch, hash=H)

def signed(body):
    return dict(body=body, signature=S)

def binding(root=H, epoch=M-1):
    return signed(dict(name=NAME, node=NODE, principal_commitment=root, epoch=epoch))

def operation(root=H, oid=I):
    return signed(dict(action='profile_update', operation_id=oid, principal_commitment=root,
        expected_epoch=M-2, next_epoch=M-1, expected_profile=ref(M-2), profile=ref(),
        old_name=NAME, binding=binding(root), discoverable=False, issued_at=T-10, expires_at=T+290))

def receipt(state='committed'):
    epoch = M if state == 'reserved' else M-1
    return signed(dict(center_id=NODE, operation_id=I if state == 'reserved' else H,
        operation_hash=H, principal_commitment=H, epoch=epoch, state=state, binding_hash=H,
        profile=ref(epoch), discoverable=False, committed_at=T if state=='reserved' else T-86400,
        expires_at=T+120 if state=='reserved' else T+60))

def detail(root=H, oid=I):
    return dict(operation=operation(root, oid), operation_hash=H, state='committed', reserved_at=T,
        reservation_expires_at=T+120, finished_at=T+100, retain_until=T+86500)

def gc(n):
    rows=[]
    for num in range(1,n+1):
        root=base64.urlsafe_b64encode(num.to_bytes(32,'big')).decode().rstrip('=')
        oid=base64.urlsafe_b64encode((num+1000).to_bytes(32,'big')).decode().rstrip('=')
        rows += [dict(table='operation', key=dict(root=root,operation_id=oid),old=detail(root,oid),new=None),
            dict(table='op_owner',key=oid,old=dict(root=root,operation_hash=H),new=None),
            dict(table='due',key=dict(kind='operation',at=T+86500,root=root,operation_id=oid,phase='detail'),old=dict(count=1),new=None)]
    for scope in ('global','home'):
        key=dict(scope=scope,metric='operation_details')
        if scope=='home':
            key['home']=NODE
        rows.append(dict(table='counter',key=key,old=dict(value=n+1),new=dict(value=1)))
    rows.sort(key=lambda r:(r['table'],encode(r['key']).encode()))
    return dict(kind='gc',tx_id=H,writer_incarnation=I,clock_floor=T+86500,operation=None,rows=rows)

ALIASES = dict(UsernameBinding='UsernameBindingBody',SignedIdentityProfileV2='IdentityProfileV2Body',
    UsernameOperation='UsernameOperationBody',DirectoryReceipt='DirectoryReceiptBody',DirectoryResolve='DirectoryResolveBody')

def fixtures():
    profile=signed(dict(schema='ramflux.identity.profile.v2',principal_id='a'*256,
        principal_commitment=H,kind='headless_ai',display_name='中'+'\\'*85+'😀'*42,
        bio='😀'*140,avatar=dict(content_hash=H,media_type='image/jpeg',size=524288,relay_ref=H),epoch=M-1))
    root=dict(epoch=M-1,name=NAME,node=NODE,discoverable=False,deleted=False,profile=ref(),binding_hash=H,
        current_binding=binding(),receipt_decision=dict(committed_at=T-86400),last_operation_id=H,
        last_operation_hash=H,pending_operation_id=I,changes=[T-259200,T-172800,T-86400],
        hold_deadlines=[T+2332800,T+2419200,T+2505600])
    resolve=signed(dict(center_id=NODE,name=NAME,node=NODE,principal_commitment=H,epoch=M-1,
        binding_hash=H,profile=ref(),request_nonce=I,issued_at=T,expires_at=T+60))
    home=dict(root=H,nonce=I,current_binding=binding(),current_receipt=receipt(),pending_receipt=receipt('reserved'),lookup_allowed=False,issued_at=T,expires_at=T+10)
    values=dict(UsernameBinding=binding(),SignedIdentityProfileV2=profile,UsernameOperation=operation(),
        DirectoryReceipt=receipt(),DirectoryResolve=resolve,ProfileRef=ref(),AvatarRef=profile['body']['avatar'],
        RootRow=root,ReceiptDecision=root['receipt_decision'],NameRow=dict(root=H,state='reserved',operation_id=I),
        SkeletonRow=dict(name=NAME,root=H,state='reserved',operation_id=I),HoldKey=dict(name=NAME,skeleton='rn'*32),
        HoldRow=dict(release_at=T,hold_until=T+2592000),OperationKey=dict(root=H,operation_id=I),
        OperationRow=detail(),OperationOwnerRow=dict(root=H,operation_hash=H),DueRow=dict(count=400000),CounterRow=dict(value=8000000),
        HomeRevalidateRequest=dict(root=H,known_directory_epoch=M-1,operation_id=I,nonce=I),HomeRevalidateResult=home,
        DirectoryFailure=dict(code='rate_limited',retry_after_ms=60000),CheckpointDelta=gc(32))
    values['Checkpoint']=dict(center_id=NODE,generation=M,lsn=M,previous_digest=H,delta=values['CheckpointDelta'])
    for alias,body in ALIASES.items():
        values[body]=copy.deepcopy(values[alias]['body'])
    valid=[dict(name=k,type=k,wire=encode(v),bytes=size(v)) for k,v in values.items()]
    def add(name,kind,value):
        valid.append(dict(name=name,type=kind,wire=encode(value),bytes=size(value)))
    for table,key,kind in [('root',H,'RootRow'),('name',NAME,'NameRow'),('skeleton','rn'*32,'SkeletonRow'),
        ('hold',values['HoldKey'],'HoldRow'),('operation',values['OperationKey'],'OperationRow'),('op_owner',I,'OperationOwnerRow')]:
        add('replacement_'+table,'Replacement',dict(table=table,key=key,old=None,new=values[kind]))
    due_keys=[dict(kind='hold',at=T+2592000,name=NAME,skeleton='rn'*32),dict(kind='operation',at=T+120,root=H,operation_id=I,phase='reservation'),dict(kind='root_window',at=T+2332800,root=H),dict(kind='home_hold_credit',at=T+2592000,home=NODE)]
    for key in due_keys:
        add('due_'+key['kind'],'DueKey',key)
        add('replacement_due_'+key['kind'],'Replacement',dict(table='due',key=key,old=None,new=dict(count=400000 if key['kind']=='home_hold_credit' else 1)))
    for scope in ('global','home'):
        key=dict(scope=scope,metric='pending_operations')
        if scope=='home':key['home']=NODE
        add('counter_'+scope,'CounterKey',key)
        add('replacement_counter_'+scope,'Replacement',dict(table='counter',key=key,old=None,new=dict(value=100000 if scope=='home' else 1000000)))
    for kind,response in [('receipt',receipt()),('status',receipt()),('resolve',resolve),('refusal',values['DirectoryFailure'])]:
        add('serve_'+kind,'ServeCandidate',dict(kind=kind,generation=M,witness_boot=I,writer_incarnation=I,primary_lsn=M,primary_digest=H,call_id=I,response=response))
    for bio in ('中'*140,'"'*140,'\\'*140,''):
        p=copy.deepcopy(profile);p['body']['bio']=bio
        add('bio_'+str(len(valid)),'SignedIdentityProfileV2',p)
    p=copy.deepcopy(profile);p['body']['avatar']=None
    add('profile_no_avatar','SignedIdentityProfileV2',p)
    add('absent_profile','ProfileRef',dict(version=0,epoch=0,hash=None))
    add('legacy_profile_ref','ProfileRef',dict(version=1,epoch=1,hash=H))
    for action in ('claim','rename','release','delete','set_visibility','move_home'):
        v=operation();v['body']['action']=action;v['body']['profile']=copy.deepcopy(v['body']['expected_profile'])
        if action=='claim':v['body']['old_name']=None
        if action=='rename':v['body']['binding']['body']['name']='alice'
        if action in ('release','delete'):v['body']['binding']=None
        add('action_'+action,'UsernameOperation',v)
    v=operation();v['body'].update(action='claim',expected_epoch=0,next_epoch=1,expected_profile=dict(version=0,epoch=0,hash=None),profile=ref(1),old_name=None,discoverable=True);v['body']['binding']['body']['epoch']=1
    add('initial_claim','UsernameOperation',v)
    v=copy.deepcopy(v);v['body'].update(action='profile_update',binding=None,discoverable=False)
    add('initial_nameless_profile','UsernameOperation',v)
    for kind in ('human','bot'):
        v=copy.deepcopy(profile);v['body']['kind']=kind;add('kind_'+kind,'SignedIdentityProfileV2',v)
    v=copy.deepcopy(profile);v['body']['avatar']['media_type']='image/png';add('png','SignedIdentityProfileV2',v)
    schema=json.loads((HERE/'schema.json').read_text())
    for code in schema['enums']['DirectoryCode']:
        retry=code in ('rate_limited','capacity','directory_unavailable','operation_pending')
        add('error_'+code,'DirectoryFailure',dict(code=code,retry_after_ms=1000 if retry else None))
    v=copy.deepcopy(home);v.update(pending_receipt=None,lookup_allowed=True);v['current_receipt']['body']['discoverable']=True
    add('positive_home','HomeRevalidateResult',v)
    v=copy.deepcopy(values['Checkpoint']);v.update(lsn=0);v['delta'].update(kind='clock',rows=[],operation=None)
    add('genesis','Checkpoint',v)
    # Every nullable field is accepted in a coherent null-arm control, not omitted.
    zero=copy.deepcopy(root);zero.update(epoch=0,name=None,profile=dict(version=0,epoch=0,hash=None),binding_hash=None,current_binding=None,receipt_decision=None,last_operation_id=None,last_operation_hash=None,pending_operation_id=None,changes=[],hold_deadlines=[])
    add('unenrolled_root','RootRow',zero)
    deleted=copy.deepcopy(root);deleted.update(deleted=True,name=None,binding_hash=None,current_binding=None,pending_operation_id=None);deleted['hold_deadlines'].append(T+2592000)
    add('deleted_root','RootRow',deleted)
    reserved=detail();reserved.update(state='reserved',finished_at=None,retain_until=None)
    add('reserved_operation','OperationRow',reserved)
    aborted=detail();aborted['state']='aborted'
    add('aborted_operation','OperationRow',aborted)
    add('no_retry_failure','DirectoryFailure',dict(code='not_found',retry_after_ms=None))
    add('nameless_home','HomeRevalidateResult',dict(root=H,nonce=I,current_binding=None,current_receipt=None,pending_receipt=None,lookup_allowed=False,issued_at=T,expires_at=T+10))
    bad=[]
    def reject(name,kind,v,field=''):
        bad.append(dict(name=name,type=kind,wire=json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')),field=field))
    # One-field decoder mutations; expected fields are explicit for locally bound fields.
    for kind,value in values.items():
        if kind in ('Checkpoint','CheckpointDelta'):continue
        for field,v in value.items():
            if isinstance(v,str):
                changed=copy.deepcopy(value)
                if field in ('node','center_id','home'):changed[field]='A'*254;error='node'
                elif field in ('name','old_name'):changed[field]='UPPER';error='name'
                elif field=='principal_id':changed[field]='a'*257;error=field
                elif field=='bio':changed[field]='😀'*141;error=field
                elif field=='display_name':changed[field]='a'*257;error=field
                else:changed[field]='invalid!';error=field
                reject(kind+'_'+field,kind,changed,error if field not in ('action','state','kind','media_type','code') else '')
            elif type(v) is int:
                changed=copy.deepcopy(value);changed[field]=M+1
                reject(kind+'_'+field+'_unsafe',kind,changed,'!i_json')
        # Unknown and missing fields, including mandatory-null Option members.
        changed=copy.deepcopy(value);changed['unknown']=None;reject(kind+'_unknown',kind,changed)
        for field in value:
            changed=copy.deepcopy(value);del changed[field];reject(kind+'_missing_'+field,kind,changed)
    for kind in ('NameRow','SkeletonRow'):
        v=copy.deepcopy(values[kind]);v.update(state='active',operation_id=None);add('active_'+kind,kind,v)
    for scope in ('global','home'):
        for metric,maxval in [('root_slots',1000000),('active_names',1000000),('held_names',4000000),('pending_operations',1000000),('operation_details',8000000)]:
            key=dict(scope=scope,metric=metric)
            if scope=='home':key['home']=NODE;maxval//=10
            add('counter_max_'+scope+metric,'Replacement',dict(table='counter',key=key,old=None,new=dict(value=maxval)))
    for field,value in [('bio','Cafe\u0301'),('bio','ab\u200bcd'),('bio','ab\ue000cd')]:
        v=copy.deepcopy(values['IdentityProfileV2Body']);v[field]=value;reject('bio_nonnormal_'+str(len(bad)),'IdentityProfileV2Body',v,'bio')
    v=copy.deepcopy(values['IdentityProfileV2Body']);v['bio']='a'*2049;reject('parser_string_bound','IdentityProfileV2Body',v,'string')
    v=copy.deepcopy(values['RootRow']);deep=None
    for _ in range(13):deep=[deep]
    v['unknown']=deep;reject('parser_depth_bound','RootRow',v,'depth')
    v=copy.deepcopy(values['IdentityProfileV2Body']);v['bio']='中'
    bad.append(dict(name='nonminimal_bmp_escape',type='IdentityProfileV2Body',wire=encode(v).replace('"bio":"中"','"bio":"\\u4e2d"'),field=''))
    v=gc(1);v['rows'].append(copy.deepcopy(v['rows'][-1]));reject('duplicate_row','CheckpointDelta',v,'row_order')
    # Isolated length/range boundaries use otherwise valid grammar.
    boundary=[('UsernameBindingBody','name','a'*4,'name'),('UsernameBindingBody','name','a'*33,'name'),
        ('UsernameBindingBody','node','.'.join(['a'*63]*3+['a'*62]),'node'),('UsernameBindingBody','epoch',0,'epoch'),
        ('ProfileRef','epoch',0,'profile_ref'),('DueRow','count',0,'count'),('DueRow','count',400001,'count'),
        ('IdentityProfileV2Body','bio','中'*141,'bio'),('IdentityProfileV2Body','display_name','a'*129,'display_name'),('IdentityProfileV2Body','display_name','é'*127+'中','display_name'),
        ('DirectoryResolveBody','expires_at',T+61,'expires_at'),('HomeRevalidateResult','expires_at',T+11,'expires_at'),
        ('HoldRow','hold_until',T+2592001,'hold_until'),('OperationRow','retain_until',T+86501,'retain_until'),
        ('OperationRow','reservation_expires_at',T+121,'reservation_expires_at'),('DirectoryReceiptBody','epoch',0,'epoch')]
    for kind,field,value,error in boundary:
        changed=copy.deepcopy(values[kind]);changed[field]=value;reject(kind+'_'+field+'_isolated',kind,changed,error)
    for key in due_keys:
        changed=dict(table='due',key=key,old=None,new=dict(count=400001 if key['kind']=='home_hold_credit' else 2))
        reject('due_count_'+key['kind'],'Replacement',changed,'count')
    for scope in ('global','home'):
        for metric,maxval in [('root_slots',1000000),('active_names',1000000),('held_names',4000000),('pending_operations',1000000),('operation_details',8000000)]:
            key=dict(scope=scope,metric=metric)
            if scope=='home':key['home']=NODE;maxval//=10
            reject('counter_bound_'+scope+metric,'Replacement',dict(table='counter',key=key,old=None,new=dict(value=maxval+1)),'value')
    mutations=[('RootRow','changes',[T]*4,'changes'),('RootRow','hold_deadlines',[T]*4,'hold_deadlines'),
        ('ProfileRef','version',3,'version'),('ProfileRef','hash',None,'profile_ref'),
        ('AvatarRef','size',0,'size'),('AvatarRef','size',524289,'size'),
        ('DirectoryFailure','retry_after_ms',999,'retry_after_ms'),('DirectoryFailure','retry_after_ms',60001,'retry_after_ms'),
        ('DirectoryFailure','retry_after_ms',None,'retry_after_ms'),('HomeRevalidateResult','lookup_allowed',True,'lookup_allowed')]
    for kind,field,value,error in mutations:
        changed=copy.deepcopy(values[kind]);changed[field]=value;reject(kind+'_'+field+'_cross',kind,changed,error)
    for field,value,error in [('next_epoch',M,'next_epoch'),('old_name',None,'old_name'),('expires_at',T+291,'expires_at')]:
        changed=copy.deepcopy(operation()['body']);changed[field]=value;reject('operation_cross_'+field,'UsernameOperationBody',changed,error)
    bad.append(dict(name='overfull_delta',type='CheckpointDelta',wire=encode(gc(33)),field='frame_size'))
    for label,wire in [('whitespace',' '+encode(binding())),('trailing',encode(binding())+'x'),('duplicate',encode(binding()).replace('"signature":','"signature":"'+S+'","signature":',1)),('nonminimal_escape',encode(binding()).replace(NAME,'\\u006d'+NAME[1:],1))]:
        bad.append(dict(name=label,type='UsernameBinding',wire=wire,field=''))
    # r4f: independent byte-identity and exact-field vectors for the narrow codec delta.
    delete=operation();delete['body'].update(action='delete',binding=None,discoverable=False,profile=ref(M-2))
    request=dict(tx_id=H,operation=delete,expected_head=dict(lsn=M,digest=H),requested_time=M)
    result=dict(abort_digest=H,delete_digest=I,clock_floor=M-86400)
    batch=dict(batch_id=H,root=H,request_hash=H,abort_tx_id=I,lsn_n1=M-1,lsn_n2=M,retain_until=M,result=result)
    new_values=dict(ExpectedHead=request['expected_head'],DeletePreemptingPending=request,BatchResult=result,BatchRow=batch)
    for kind,value in new_values.items():
        add('batch_'+kind,kind,value)
        for field,v in value.items():
            if isinstance(v,str):
                changed=copy.deepcopy(value);changed[field]='invalid!';reject('batch_'+kind+'_'+field,kind,changed,field)
            elif type(v) is int:
                changed=copy.deepcopy(value);changed[field]=M+1;reject('batch_'+kind+'_'+field+'_unsafe',kind,changed,'!i_json')
    def negative(label,kind,value,field):reject('batch_'+label,kind,value,field)
    for field in ('lsn_n1','lsn_n2'):
        v=copy.deepcopy(batch);v[field]=0;negative(field+'_zero','BatchRow',v,field)
    v=copy.deepcopy(batch);v['abort_tx_id']=H;negative('same_ids','BatchRow',v,'abort_tx_id')
    v=copy.deepcopy(batch);v['lsn_n2']=M-1;negative('nonconsecutive','BatchRow',v,'lsn_n2')
    v=copy.deepcopy(batch);v['lsn_n1']=M;negative('lsn_exhaustion','BatchRow',v,'lsn_n2')
    v=copy.deepcopy(batch);v['retain_until']=M-1;negative('short_retention','BatchRow',v,'retain_until')
    v=copy.deepcopy(batch);v['result']['clock_floor']=M;negative('retention_exhaustion','BatchRow',v,'retain_until')
    v=copy.deepcopy(request);v['operation']=operation();negative('other_action','DeletePreemptingPending',v,'action')
    replacement=dict(table='batch',key=H,old=None,new=batch)
    add('batch_replacement','Replacement',replacement)
    v=copy.deepcopy(replacement);v['key']=I;negative('key_mismatch','Replacement',v,'batch_id')
    v=copy.deepcopy(replacement);v.update(key=I,old=batch,new=None);negative('old_key_mismatch','Replacement',v,'batch_id')
    add('batch_removal','Replacement',dict(table='batch',key=H,old=batch,new=None))
    for clock in (0,M):
        v=copy.deepcopy(result);v['clock_floor']=clock;add('batch_result_clock_'+str(clock),'BatchResult',v)
    v=copy.deepcopy(replacement);v['key']='invalid!';negative('key_grammar','Replacement',v,'batch_id')
    v=copy.deepcopy(replacement);v['old']=batch;negative('same_images','Replacement',v,'images')
    v=copy.deepcopy(replacement);v['new']=None;negative('empty_images','Replacement',v,'images')
    v=gc(1);v['rows']=[replacement];negative('caller_batch','CheckpointDelta',v,'batch')
    for lsn,clock in ((0,0),(M,M)):
        v=copy.deepcopy(request);v['expected_head']['lsn']=lsn;v['requested_time']=clock
        add('batch_request_boundary_'+str(lsn),'DeletePreemptingPending',v)
    v=copy.deepcopy(batch);v.update(lsn_n1=1,lsn_n2=2,retain_until=86400);v['result']['clock_floor']=0
    add('batch_row_min','BatchRow',v)
    v=copy.deepcopy(batch);v['result']['clock_floor']=0
    add('batch_retention_above_min','BatchRow',v)
    review_cases, review_controls = review_vectors(values, valid)
    bad.extend(review_cases)
    valid.extend(review_controls)
    old=dict(domain='ramflux.identity.profile.v1',principal_id='alice',principal_commitment=H,kind='human',display_name='Alice',epoch=1,signature=S)
    unsigned=dict(old);del unsigned['signature']
    native=dict(kind='human',display_name='Alice',custodian=None)
    maxima={k:size(values[k]) for k in ('RootRow','UsernameBinding','ReceiptDecision','UsernameOperation','OperationRow','HomeRevalidateResult','CheckpointDelta','Checkpoint','SignedIdentityProfileV2')}
    assert maxima['RootRow']==1449 and maxima['UsernameBinding']==510 and maxima['ReceiptDecision']==33
    assert maxima['UsernameOperation']==1191 and maxima['OperationRow']==1424 and maxima['HomeRevalidateResult']==2482
    assert maxima['CheckpointDelta']==65282 and maxima['Checkpoint']==65677 and size(gc(33))==67301
    assert len(profile['body']['display_name'].encode())==256 and len(encode(profile['body']['display_name']).encode())==343
    return dict(codec_only=True,valid=valid,invalid=bad,review_rules={case["name"]:case["field"] for case in review_cases},maxima=maxima,legacy=dict(profile=encode(old),signing=encode(unsigned),native=encode(native)),transcripts={kind:encode(dict(domain=domain,body=values[kind]['body'])) for kind,domain in [('UsernameBinding','ramflux.identity.username_binding.v1'),('SignedIdentityProfileV2','ramflux.identity.profile.v2'),('UsernameOperation','ramflux.identity.username_operation.v1'),('DirectoryReceipt','ramflux.identity.username_receipt.v1'),('DirectoryResolve','ramflux.identity.username_resolve.v1')]})

def review_vectors(values, valid):
    """One explicitly named stateless rejection per reviewed rule/arm."""
    cases=[]
    controls=[]
    def base(name):
        if name in values:
            return copy.deepcopy(values[name])
        return json.loads(next(case['wire'] for case in valid if case['name']==name))
    def reject(name, kind, value, field):
        name='review_'+name
        assert field and all(c['name']!=name for c in cases)
        cases.append(dict(name=name,type=kind,wire=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')),field=field))
    def control(name, kind, value):
        controls.append(dict(name='review_control_'+name,type=kind,wire=encode(value),bytes=size(value)))
    def changed(name, kind, field, value, error):
        v=base(kind);v[field]=value;reject(name,kind,v,error)
    # Policy probes include every literal and every available ASCII confusable arm.
    # root is also below the five-byte grammar minimum; the others isolate policy.
    literals=('admin','administrator','root','system','support','security','ramflux','official','moderator','notify','federation')
    aliases=('adrnin','adrninistrator','systern','rarnflux','ramf1ux','officia1','rnoderator')
    prefixes=('ramflux_user','system_user','rarnflux_user','ramf1ux_user','systern_user')
    for action in ('claim','rename'):
        for category,names in [('reserved',literals),('skeleton',aliases),('prefix',prefixes)]:
            for name in names:
                v=base('action_'+action)['body'];v['binding']['body']['name']=name
                reject(category+'_'+action+'_'+name,'UsernameOperationBody',v,'name')
    for action in ('rename','release','delete','set_visibility','move_home'):
        v=base('initial_claim')['body'];v['action']=action
        reject('initial_action_'+action,'UsernameOperationBody',v,'expected_epoch')
    v=base('initial_claim')['body'];v['expected_profile']=ref(1)
    reject('initial_expected_profile','UsernameOperationBody',v,'expected_epoch')
    v=base('initial_claim')['body'];v['binding']=None
    reject('initial_claim_binding','UsernameOperationBody',v,'expected_epoch')
    v=base('initial_nameless_profile')['body'];v['binding']=binding(epoch=1)
    reject('initial_nameless_binding','UsernameOperationBody',v,'expected_epoch')
    v=base('action_claim')['body'];v['old_name']=NAME
    reject('claim_old_name','UsernameOperationBody',v,'old_name')
    v=base('action_claim')['body'];v['binding']=None
    reject('claim_missing_binding','UsernameOperationBody',v,'old_name')
    v=base('action_rename')['body'];v['binding']['body']['name']=v['old_name']
    reject('rename_same_name','UsernameOperationBody',v,'name')
    v=base('action_rename')['body'];v['old_name']='mxxxx';v['binding']['body']['name']='rnxxxx'
    reject('rename_same_skeleton','UsernameOperationBody',v,'name')
    for field in ('old_name','binding'):
        v=base('action_rename')['body'];v[field]=None
        reject('rename_missing_'+field,'UsernameOperationBody',v,field)
    for action in ('release','delete'):
        v=base('action_'+action)['body'];v['binding']=binding()
        reject(action+'_binding','UsernameOperationBody',v,'binding')
        v=base('action_'+action)['body'];v['discoverable']=True
        reject(action+'_visible','UsernameOperationBody',v,'binding')
    v=base('action_release')['body'];v['old_name']=None
    reject('release_nameless','UsernameOperationBody',v,'old_name')
    for action in ('set_visibility','move_home','profile_update'):
        for old in ('alice',None):
            v=base('UsernameOperationBody') if action=='profile_update' else base('action_'+action)['body']
            v['old_name']=old
            reject(action+'_old_name_'+str(old),'UsernameOperationBody',v,'old_name')
    for field,value in [('epoch',M-2),('principal_commitment',I)]:
        v=base('UsernameOperationBody');v['binding']['body'][field]=value
        reject('operation_binding_'+field,'UsernameOperationBody',v,'binding')
    v=base('UsernameOperationBody');v['profile']['epoch']=v['expected_profile']['epoch']
    reject('profile_update_increment','UsernameOperationBody',v,'profile')
    v=base('UsernameOperationBody');v['profile']=dict(version=1,epoch=1,hash=H)
    reject('operation_profile_version','UsernameOperationBody',v,'profile')
    v=base('UsernameOperationBody');v['expected_profile']['version']=1
    reject('operation_expected_version','UsernameOperationBody',v,'expected_profile')
    for action in ('claim','rename','release','delete','set_visibility','move_home'):
        v=base('action_'+action)['body'];v['profile']['epoch']+=1
        reject(action+'_profile_preserved','UsernameOperationBody',v,'profile')
    # All six malformed null-together arms, and each member of the commit triple.
    fields=('name','binding_hash','current_binding')
    for bits in range(1,7):
        v=base('RootRow')
        for i,field in enumerate(fields):
            if not bits & (1<<i):v[field]=None
        reject('root_pair_'+str(bits),'RootRow',v,'current_binding')
    triple=('last_operation_id','last_operation_hash','receipt_decision')
    for field in triple:
        v=base('RootRow');v[field]=None
        reject('root_committed_'+field,'RootRow',v,'receipt_decision')
        v=base('unenrolled_root');v[field]=dict(committed_at=T) if field=='receipt_decision' else H
        reject('root_uncommitted_'+field,'RootRow',v,'receipt_decision')
    changed('root_profile_legacy','RootRow','profile',dict(version=1,epoch=1,hash=H),'profile')
    v=base('unenrolled_root');v['profile']=ref()
    reject('root_uncommitted_profile','RootRow',v,'profile')
    v=base('unenrolled_root');v['name']=NAME
    reject('root_uncommitted_name','RootRow',v,'profile')
    for field,value in [('name','alice'),('node','other.example'),('epoch',M-2)]:
        v=base('RootRow');v['current_binding']['body'][field]=value
        reject('root_binding_'+field,'RootRow',v,'current_binding')
    v=base('RootRow');v.update(deleted=True,pending_operation_id=None)
    reject('deleted_named','RootRow',v,'deleted')
    for field,value in [('pending_operation_id',I),('discoverable',True)]:
        v=base('deleted_root');v[field]=value
        reject('deleted_'+field,'RootRow',v,'deleted')
    v=base('unenrolled_root');v['deleted']=True
    reject('deleted_uncommitted','RootRow',v,'deleted')
    for label,times in [('spacing',[T,T+86399]),('decrease',[T,T-1]),('duplicate',[T,T])]:
        changed('changes_'+label,'RootRow','changes',times,'changes')
    changed('hold_unsorted','RootRow','hold_deadlines',[T+1,T],'hold_deadlines')
    v=base('deleted_root');v['hold_deadlines'].append(T+2592001)
    reject('deleted_hold_limit','RootRow',v,'hold_deadlines')
    changed('pending_reuses_last','RootRow','pending_operation_id',H,'pending_operation_id')
    for ttl in (119,121):
        v=receipt('reserved')['body'];v['expires_at']=T+ttl
        reject('receipt_reserved_ttl_'+str(ttl),'DirectoryReceiptBody',v,'expires_at')
    for state in ('committed','reserved','aborted'):
        v=receipt(state)['body'];v['expires_at']=v['committed_at']
        reject('receipt_expired_'+state,'DirectoryReceiptBody',v,'expires_at')
    changed('receipt_profile_version','DirectoryReceiptBody','profile',dict(version=1,epoch=1,hash=H),'profile')
    for field in ('finished_at','retain_until'):
        v=base('reserved_operation');v[field]=T
        reject('reserved_has_'+field,'OperationRow',v,'finished_at')
    changed('terminal_missing_time','OperationRow','finished_at',None,'finished_at')
    changed('terminal_missing_retention','OperationRow','retain_until',None,'retain_until')
    v=detail();v.update(finished_at=T-1,retain_until=T-1+86400)
    reject('terminal_before_reserve','OperationRow',v,'retain_until')
    for label,time in [('at',T+120),('past',T+121)]:
        v=detail();v.update(finished_at=time,retain_until=time+86400)
        reject('operation_reservation_expiry_'+label,'OperationRow',v,'finished_at')
    for label,time in [('at',T+50),('past',T+51)]:
        v=detail();v['operation']['body'].update(issued_at=T-250,expires_at=T+50)
        v.update(finished_at=time,retain_until=time+86400)
        reject('operation_signed_expiry_'+label,'OperationRow',v,'finished_at')
    v=detail();v.update(finished_at=T+119,retain_until=T+86519)
    control('commit_before_deadlines','OperationRow',v)
    def delta(kind,op=None,rows=None):
        return dict(kind=kind,tx_id=H,writer_incarnation=I,clock_floor=T+100,operation=op,rows=[] if rows is None else rows)
    counter=dict(table='counter',key=dict(scope='global',metric='pending_operations'),old=None,new=dict(value=1))
    for kind in ('abort','expire','gc','clock'):
        reject('delta_unexpected_operation_'+kind,'CheckpointDelta',delta(kind,operation()),'operation')
    for kind in ('reserve','commit'):
        row=detail()
        if kind=='reserve':row.update(state='reserved',finished_at=None,retain_until=None)
        replacement=dict(table='operation',key=dict(root=H,operation_id=I),old=None,new=row)
        d=delta(kind,operation(),[replacement]);control('delta_'+kind,'CheckpointDelta',d)
        v=copy.deepcopy(d);v['operation']=None
        reject('delta_missing_operation_'+kind,'CheckpointDelta',v,'operation')
        v=copy.deepcopy(d);v['operation']['body'].update(issued_at=T-9,expires_at=T+291)
        reject('delta_operation_new_mismatch_'+kind,'CheckpointDelta',v,'operation')
        v=copy.deepcopy(d);v['rows'][0]['old']=copy.deepcopy(row);v['rows'][0]['new']=None
        v['operation']['body'].update(issued_at=T-9,expires_at=T+291)
        reject('delta_operation_old_mismatch_'+kind,'CheckpointDelta',v,'operation')
    reject('clock_rows','CheckpointDelta',delta('clock',rows=[counter]),'rows')
    genesis=base('genesis')
    v=copy.deepcopy(genesis);v['previous_digest']=I
    reject('genesis_digest','Checkpoint',v,'lsn')
    v=copy.deepcopy(genesis);v['delta']=delta('gc')
    reject('genesis_kind','Checkpoint',v,'lsn')
    v=copy.deepcopy(genesis);v['delta']=delta('clock',rows=[counter])
    reject('genesis_rows','Checkpoint',v,'rows')
    v=copy.deepcopy(genesis);v['generation']=0
    reject('checkpoint_generation','Checkpoint',v,'generation')
    for name in ('replacement_root','replacement_name','replacement_skeleton','replacement_hold','replacement_operation','replacement_op_owner','replacement_due_hold','replacement_counter_global'):
        v=base(name);v['old']=copy.deepcopy(v['new'])
        reject('identical_'+name,'Replacement',v,'images')
    v=base('replacement_name');v.update(old=None,new=None)
    reject('empty_images','Replacement',v,'images')
    v=base('replacement_skeleton');v['key']='alice'
    reject('skeleton_key','Replacement',v,'skeleton')
    for field in ('root','operation_id'):
        v=base('replacement_operation');v['key'][field]=I if field=='root' else H
        reject('operation_key_'+field,'Replacement',v,'operation')
    v=base('replacement_root');v['key']=I
    reject('root_key','Replacement',v,'current_binding')
    v=base('replacement_root');v['old']=v['new'];v['new']=None
    reject('root_deletion','Replacement',v,'root')
    before=base('deleted_root');before['hold_deadlines']=before['hold_deadlines'][:3]
    after=copy.deepcopy(before);after['deleted']=False
    reject('root_resurrection','Replacement',dict(table='root',key=H,old=before,new=after),'deleted')
    before=base('RootRow');after=copy.deepcopy(before);after['epoch']-=1;after['current_binding']['body']['epoch']-=1
    reject('root_epoch_decrease','Replacement',dict(table='root',key=H,old=before,new=after),'epoch')
    # Equality and increasing revision are valid transition controls, not over-rejection.
    after=copy.deepcopy(before);after['pending_operation_id']=None
    control('root_same_epoch','Replacement',dict(table='root',key=H,old=before,new=after))
    after=copy.deepcopy(before);after['epoch']+=1;after['current_binding']['body']['epoch']+=1;after['pending_operation_id']=None
    control('root_epoch_increase','Replacement',dict(table='root',key=H,old=before,new=after))
    for kind in ('receipt','status','resolve','refusal'):
        v=base('serve_'+kind);v['generation']=0
        reject('serve_generation_'+kind,'ServeCandidate',v,'generation')
    changed('home_missing_receipt','HomeRevalidateResult','current_receipt',None,'current_receipt')
    v=base('HomeRevalidateResult');v['current_binding']['body']['principal_commitment']=I
    reject('home_binding_root','HomeRevalidateResult',v,'current_binding')
    v=base('HomeRevalidateResult');v['current_receipt']['body']['principal_commitment']=I
    reject('home_current_root','HomeRevalidateResult',v,'current_receipt')
    for state in ('reserved','aborted'):
        v=base('HomeRevalidateResult');v['current_receipt']=receipt(state)
        reject('home_current_state_'+state,'HomeRevalidateResult',v,'current_receipt')
    v=base('HomeRevalidateResult');v['current_receipt']['body']['binding_hash']=None
    reject('home_missing_binding_hash','HomeRevalidateResult',v,'current_binding')
    changed('home_missing_binding','HomeRevalidateResult','current_binding',None,'current_binding')
    v=base('HomeRevalidateResult');v['current_binding']['body']['epoch']-=1
    reject('home_binding_epoch','HomeRevalidateResult',v,'epoch')
    v=base('HomeRevalidateResult');v['pending_receipt']['body']['principal_commitment']=I
    reject('home_pending_root','HomeRevalidateResult',v,'pending_receipt')
    for state in ('committed','aborted'):
        v=base('HomeRevalidateResult');v['pending_receipt']=receipt(state)
        reject('home_pending_state_'+state,'HomeRevalidateResult',v,'pending_receipt')
    v=base('HomeRevalidateResult');v['pending_receipt']['body']['epoch']-=1
    reject('home_pending_epoch','HomeRevalidateResult',v,'pending_epoch')
    v=base('HomeRevalidateResult');v['current_binding']['body']['epoch']=M;v['current_receipt']['body']['epoch']=M
    reject('home_pending_exhaustion','HomeRevalidateResult',v,'pending_epoch')
    v=base('nameless_home');v['pending_receipt']=receipt('reserved')
    reject('home_initial_pending_epoch','HomeRevalidateResult',v,'pending_epoch')
    v['pending_receipt']['body']['epoch']=1;v['pending_receipt']['body']['profile']=ref(1)
    control('home_initial_pending','HomeRevalidateResult',v)
    v=base('HomeRevalidateResult');v['pending_receipt']['body']['center_id']='other.example'
    reject('home_center','HomeRevalidateResult',v,'center_id')
    v=base('positive_home');v['current_binding']=None;v['current_receipt']['body']['binding_hash']=None
    reject('home_lookup_nameless','HomeRevalidateResult',v,'lookup_allowed')
    v=base('positive_home');v['current_receipt']['body']['discoverable']=False
    reject('home_lookup_hidden','HomeRevalidateResult',v,'lookup_allowed')
    v=base('nameless_home');v['lookup_allowed']=True
    reject('home_lookup_unenrolled','HomeRevalidateResult',v,'lookup_allowed')
    for kind in ('NameRow','SkeletonRow'):
        v=base(kind);v['state']='active'
        reject('index_active_operation_'+kind,kind,v,'operation_id')
        v=base(kind);v['operation_id']=None
        reject('index_reserved_operation_'+kind,kind,v,'operation_id')
    v=base('HoldKey');v['skeleton']='alice'
    reject('hold_key_skeleton','HoldKey',v,'skeleton')
    for field,value in [('epoch',1),('hash',H)]:
        v=dict(version=0,epoch=0,hash=None);v[field]=value
        reject('absent_profile_'+field,'ProfileRef',v,'profile_ref')
    for kind in ('DirectoryResolveBody','DirectoryReceiptBody'):
        v=base(kind);v['profile']=dict(version=0,epoch=0,hash=None)
        reject('required_v2_'+kind,kind,v,'profile')
    changed('profile_v2_epoch_zero','IdentityProfileV2Body','epoch',0,'epoch')
    changed('resolve_epoch_zero','DirectoryResolveBody','epoch',0,'epoch')
    # Canonical but wrong-width encodings isolate length checks from alphabet checks.
    ordinary={'name','old_name','node','home','center_id','schema','principal_id','display_name','bio','skeleton','action','state','kind','media_type','code'}
    for kind,value in values.items():
        for field,old in value.items():
            if isinstance(old,str) and field not in ordinary:
                width=64 if field=='signature' else 32
                for count in (width-1,width+1):
                    v=copy.deepcopy(value);v[field]=base64.urlsafe_b64encode(bytes(count)).decode().rstrip('=')
                    reject('width_'+kind+'_'+field+'_'+str(count),kind,v,field)
            if kind in ('Checkpoint','CheckpointDelta') and type(old) is int:
                v=copy.deepcopy(value);v[field]=M+1
                reject('safe_'+kind+'_'+field,kind,v,'!i_json')
    for kind in ('HomeRevalidateResult','DirectoryResolveBody'):
        for label,offset in [('zero',0),('reverse',-1)]:
            v=base(kind);v['expires_at']=v['issued_at']+offset
            reject('duration_'+kind+'_'+label,kind,v,'expires_at')
    v=base('UsernameOperationBody');v['expires_at']=v['issued_at']+299
    reject('operation_short_lifetime','UsernameOperationBody',v,'expires_at')
    return cases,controls


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');parser.add_argument('--write',action='store_true');args=parser.parse_args()
    vectors=fixtures()
    if args.write:
        (HERE/'wire_vectors.json').write_text(json.dumps(vectors,ensure_ascii=False,indent=2)+'\n')
        sources=json.loads((HERE/'oracle_sources.json').read_text())
        sources['sha256']={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ('schema.json','wire_vectors.json','codec_oracle.py')}
        (HERE/'oracle_sources.json').write_text(json.dumps(sources,indent=2)+'\n')
    stored=json.loads((HERE/'wire_vectors.json').read_text());assert stored==vectors
    schema=json.loads((HERE/'schema.json').read_text())
    for case in stored['valid']:
        value=json.loads(case['wire'])
        kind=case['type']
        if kind in schema['records']:
            assert set(value)=={f.split(':')[0] for f in schema['records'][kind]['fields'].split(',')}
            assert case['bytes']<=schema['records'][kind]['limit']
        elif kind in ALIASES:
            assert set(value)=={'body','signature'}
            assert set(value['body'])=={f.split(':')[0] for f in schema['records'][ALIASES[kind]]['fields'].split(',')}
        assert encode(json.loads(case['wire']))==case['wire'] and len(case['wire'].encode())==case['bytes']
    assert stored['review_rules'] and all(stored['review_rules'].values())
    for name,field in stored['review_rules'].items():
        matches=[case for case in stored['invalid'] if case['name']==name]
        assert len(matches)==1 and matches[0]['field']==field
    for name,digest in json.loads((HERE/'oracle_sources.json').read_text())['sha256'].items():
        assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest
    assert encode({'q':'"\\😀中'})=='{"q":"\\"\\\\😀中"}'
    assert len({v for v in json.loads((HERE/'oracle_sources.json').read_text())['domains'].values()})==10
    print('codec oracle PASS:',len(stored['valid']),'valid,',len(stored['invalid']),'negative vectors; reachable r4c maxima; no crypto claim')

if __name__=='__main__':
    main()
