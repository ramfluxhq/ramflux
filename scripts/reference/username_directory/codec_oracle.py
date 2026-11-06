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
    old=dict(domain='ramflux.identity.profile.v1',principal_id='alice',principal_commitment=H,kind='human',display_name='Alice',epoch=1,signature=S)
    unsigned=dict(old);del unsigned['signature']
    native=dict(kind='human',display_name='Alice',custodian=None)
    maxima={k:size(values[k]) for k in ('RootRow','UsernameBinding','ReceiptDecision','UsernameOperation','OperationRow','HomeRevalidateResult','CheckpointDelta','Checkpoint','SignedIdentityProfileV2')}
    assert maxima['RootRow']==1449 and maxima['UsernameBinding']==510 and maxima['ReceiptDecision']==33
    assert maxima['UsernameOperation']==1191 and maxima['OperationRow']==1424 and maxima['HomeRevalidateResult']==2482
    assert maxima['CheckpointDelta']==65282 and maxima['Checkpoint']==65677 and size(gc(33))==67301
    assert len(profile['body']['display_name'].encode())==256 and len(encode(profile['body']['display_name']).encode())==343
    return dict(codec_only=True,valid=valid,invalid=bad,maxima=maxima,legacy=dict(profile=encode(old),signing=encode(unsigned),native=encode(native)),transcripts={kind:encode(dict(domain=domain,body=values[kind]['body'])) for kind,domain in [('UsernameBinding','ramflux.identity.username_binding.v1'),('SignedIdentityProfileV2','ramflux.identity.profile.v2'),('UsernameOperation','ramflux.identity.username_operation.v1'),('DirectoryReceipt','ramflux.identity.username_receipt.v1'),('DirectoryResolve','ramflux.identity.username_resolve.v1')]})

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
    for name,digest in json.loads((HERE/'oracle_sources.json').read_text())['sha256'].items():
        assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest
    assert encode({'q':'"\\😀中'})=='{"q":"\\"\\\\😀中"}'
    assert len({v for v in json.loads((HERE/'oracle_sources.json').read_text())['domains'].values()})==10
    print('codec oracle PASS:',len(stored['valid']),'valid,',len(stored['invalid']),'negative vectors; reachable r4c maxima; no crypto claim')

if __name__=='__main__':
    main()
