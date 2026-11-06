#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent P02 crypto goldens. Never invokes the product or Dalek.

Install: python -m pip install --require-hashes -r requirements.txt
Run: python oracle.py --check (or --write for intentional vector regeneration).
P01's stdlib-only oracle and artifacts remain independent and unchanged.
"""
import argparse
import base64
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
import codec_oracle as codec
from pure_blake3 import Hasher

HERE = Path(__file__).resolve().parent
D = json.loads((HERE / 'oracle_sources.json').read_text())['domains']
ROOT_DOMAIN = 'ramflux.identity.root_public_key.commitment.v1'
V1_DOMAIN = 'ramflux.identity.profile.v1'
SEED = bytes([17]) * 32
CENTER_SEED = bytes([29]) * 32

def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')

def raw(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

def j(value):
    return codec.encode(value).encode()

def digest(value):
    h = Hasher(); h.update(value); return b64(h.finalize())

def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def commitment(key):
    return digest(ROOT_DOMAIN.encode() + public(key))

def transcript(domain, body):
    return j(dict(domain=domain, body=body))

def signed(domain, body, key):
    preimage = transcript(domain, body)
    result = dict(body=body, signature=b64(key.sign(preimage)))
    key.public_key().verify(raw(result['signature']), preimage)
    return result

def framed(domain, value):
    return domain.encode() + b'\0' + j(value)

def leaves(value, path=()):
    """Every independently bound leaf, plus optional/container presence and array order."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, path + (key,))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from leaves(child, path + (i,))
        yield path, [] if value else [0]
    elif isinstance(value, bool):
        yield path, not value
    elif isinstance(value, int):
        yield path, value - 1 if value else 1
    elif value is None:
        yield path, False
    else:
        yield path, value + 'x'

def changed(value, path, replacement):
    value = json.loads(codec.encode(value))
    slot = value
    for component in path[:-1]:
        slot = slot[component]
    slot[path[-1]] = replacement
    return value

def pins():
    pin = json.loads((HERE / 'crypto_sources.json').read_text())
    for name in ['cryptography', 'cffi', 'pycparser']:
        assert importlib.metadata.version(name) == pin['sources'][name]['version']
    assert cryptography.__version__ == '46.0.3'
    assert backend.openssl_version_text() == pin['openssl']
    for filename, source, field in [('pure_blake3.py', 'pure_blake3', 'sha256'), ('pure_blake3.LICENSE', 'pure_blake3', 'license_sha256')]:
        assert hashlib.sha256((HERE / filename).read_bytes()).hexdigest() == pin['sources'][source][field]
    # RFC 8032 test 1: independent provider KAT, before generating any product golden.
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
    assert public(key).hex() == 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    assert key.sign(b'').hex() == ('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f' 'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    assert digest(b'') == b64(bytes.fromhex('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'))
    assert digest(b'abc') == b64(bytes.fromhex('6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'))

def fixtures():
    root = Ed25519PrivateKey.from_private_bytes(SEED)
    center = Ed25519PrivateKey.from_private_bytes(CENTER_SEED)
    alternate = Ed25519PrivateKey.from_private_bytes(bytes([31]) * 32)
    root_id = commitment(root)
    codec_cases = codec.fixtures()
    values = {c['name']:json.loads(c['wire']) for c in codec_cases['valid']}
    signatures = []
    hashes = []
    def add_sign(name, kind, tag, body, key=root):
        value = signed(tag, body, key)
        preimage = transcript(tag, body)
        tamper = []
        for path, replacement in leaves(body):
            try:
                key.public_key().verify(raw(value['signature']), transcript(tag, changed(body, path, replacement)))
            except InvalidSignature:
                pass
            else:
                raise AssertionError(('unbound field', name, path))
            tamper.append(dict(path=list(path), replacement=replacement, error='VerifyFailed'))
        # Container presence, unknown/missing fields, and the domain itself are bound too.
        for key_name, child in body.items():
            if isinstance(child, (dict, list)):
                tamper.append(dict(path=[key_name], replacement=None, error='VerifyFailed'))
        signatures.append(dict(name=name, type=kind, domain=tag, key=b64(public(key)), seed=b64(SEED if key is root else CENTER_SEED), wire=codec.encode(value), preimage=b64(preimage), tamper=tamper))
        return value
    def add_hash(name, tag, value, mode='framed'):
        preimage = framed(tag,value) if mode=='framed' else tag.encode()+value
        mutations=[]
        if mode=='framed':
            for path, replacement in leaves(value):
                mutated=changed(value,path,replacement)
                mutations.append(dict(path=list(path),replacement=replacement,hash=digest(framed(tag,mutated))))
        hashes.append(dict(name=name,domain=tag,mode=mode,wire=codec.encode(value) if mode=='framed' else None,raw=b64(value) if mode!='framed' else None,preimage=b64(preimage),hash=digest(preimage),mutations=mutations))
        return hashes[-1]['hash']
    add_hash('root_commitment',ROOT_DOMAIN,public(root),'raw')
    # Exercise the no-NUL avatar grammar at BLAKE3 block/chunk/tree and policy boundaries.
    for n in [0,1,63,64,65,1023,1024,1025,2048,2049,524288]:
        add_hash('avatar_'+str(n),D['AVATAR_CONTENT'],bytes(i%251 for i in range(n)),'raw')
    profile=copy.deepcopy(values['SignedIdentityProfileV2']['body']);profile['principal_commitment']=root_id
    for epoch in [codec.M-2,codec.M-1]:
        profile['epoch']=epoch
        p=add_sign('profile_'+str(epoch),'SignedIdentityProfileV2',D['IDENTITY_PROFILE_V2'],copy.deepcopy(profile))
        ph=add_hash('profile_'+str(epoch),D['USERNAME_PROFILE_HASH'],p)
        if epoch==codec.M-2:expected_profile=dict(version=2,epoch=epoch,hash=ph)
    profile_ref=dict(version=2,epoch=profile['epoch'],hash=ph)
    binding=values['UsernameBinding']['body'];binding['principal_commitment']=root_id
    b=add_sign('binding','UsernameBinding',D['USERNAME_BINDING'],binding)
    bh=add_hash('binding',D['USERNAME_BINDING_HASH'],b)
    op=values['UsernameOperation']['body'];op.update(principal_commitment=root_id,binding=b,profile=profile_ref,expected_profile=expected_profile)
    operation=add_sign('operation','UsernameOperation',D['USERNAME_OPERATION'],op)
    oh=add_hash('operation',D['USERNAME_OPERATION_HASH'],operation)
    receipt=values['DirectoryReceipt']['body'];receipt.update(principal_commitment=root_id,binding_hash=bh,operation_hash=oh,profile=profile_ref)
    r=add_sign('receipt','DirectoryReceipt',D['USERNAME_RECEIPT'],receipt,center)
    resolve=values['DirectoryResolve']['body'];resolve.update(principal_commitment=root_id,binding_hash=bh,profile=profile_ref)
    add_sign('resolve','DirectoryResolve',D['USERNAME_RESOLVE'],resolve,center)
    # Initial enrollment and nameless arms are real signatures, never codec placeholders.
    for action in ['claim','rename','release','set_visibility','delete','move_home','profile_update']:
        body=copy.deepcopy(op);body['action']=action
        if action=='profile_update':
            body.update(expected_epoch=0,next_epoch=1,expected_profile=dict(version=0,epoch=0,hash=None),profile=dict(version=2,epoch=1,hash=ph),old_name=None,binding=None)
        else:
            body['profile']=copy.deepcopy(expected_profile)
        if action=='claim':body['old_name']=None
        if action=='rename':body['old_name']='alice_old'
        if action in ['release','delete']:body.update(binding=None,discoverable=False)
        add_sign('action_'+action,'UsernameOperation',D['USERNAME_OPERATION'],body)
    # Root image commits retained r4c binding bytes and receipt decision on both sides.
    old=copy.deepcopy(values['RootRow']);old.update(current_binding=b,binding_hash=bh,profile=profile_ref,last_operation_hash=oh,pending_operation_id=None)
    new=copy.deepcopy(old);new['pending_operation_id']=codec.I
    checkpoint=dict(center_id=codec.NODE,generation=1,lsn=1,previous_digest=codec.H,delta=dict(kind='reserve',tx_id=codec.H,writer_incarnation=codec.I,clock_floor=codec.T,operation=operation,rows=[dict(table='root',key=root_id,old=old,new=new)]))
    add_hash('checkpoint_root_images',D['USERNAME_CHECKPOINT'],checkpoint)
    # Actual signatures and hashes at P01's 32-entry GC byte boundary. All bytes stay fixed-width.
    cp=copy.deepcopy(values['Checkpoint'])
    roots={}
    operations={}
    for row in cp['delta']['rows']:
        if row['table']=='operation':
            old_root=row['key']['root']
            owner=Ed25519PrivateKey.from_private_bytes(raw(old_root))
            roots[old_root]=commitment(owner)
            row['key']['root']=roots[old_root]
            o=row['old']['operation']
            o['body']['principal_commitment']=roots[old_root]
            o['body']['binding']['body']['principal_commitment']=roots[old_root]
            o['body']['binding']=signed(D['USERNAME_BINDING'],o['body']['binding']['body'],owner)
            for field in ['expected_profile','profile']:
                detached=copy.deepcopy(profile)
                detached.update(principal_commitment=roots[old_root],epoch=o['body'][field]['epoch'])
                document=signed(D['IDENTITY_PROFILE_V2'],detached,owner)
                o['body'][field]['hash']=digest(framed(D['USERNAME_PROFILE_HASH'],document))
            row['old']['operation']=signed(D['USERNAME_OPERATION'],o['body'],owner)
            row['old']['operation_hash']=digest(framed(D['USERNAME_OPERATION_HASH'],row['old']['operation']))
            operations[row['key']['operation_id']]=row['old']['operation_hash']
    for row in cp['delta']['rows']:
        if row['table']=='op_owner':
            row['old']['root']=roots[row['old']['root']]
            row['old']['operation_hash']=operations[row['key']]
        if row['table']=='due':
            row['key']['root']=roots[row['key']['root']]
    cp['delta']['rows'].sort(key=lambda r:(r['table'],codec.encode(r['key']).encode()))
    add_hash('checkpoint_max_gc',D['USERNAME_CHECKPOINT'],cp)
    legacy=dict(domain=V1_DOMAIN,principal_id='legacy',principal_commitment=root_id,kind='human',display_name='Legacy',epoch=1)
    legacy_preimage=j(legacy);legacy['signature']=b64(root.sign(legacy_preimage))
    add_hash('profile_v1',D['USERNAME_PROFILE_HASH'],legacy)
    v1=dict(wire=codec.encode(legacy),preimage=b64(legacy_preimage))
    domains=dict(D,ROOT_COMMITMENT=ROOT_DOMAIN,PROFILE_V1=V1_DOMAIN)
    return dict(domains=domains,root_key=b64(public(root)),alternate_key=b64(public(alternate)),root_commitment=root_id,center_id=codec.NODE,signatures=signatures,hashes=hashes,legacy=v1)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');parser.add_argument('--write',action='store_true');args=parser.parse_args()
    pins()  # Source/provider pins are checked BEFORE any vector emission.
    vectors=fixtures()
    path=HERE/'crypto_vectors.json'
    if args.write:
        path.write_text(json.dumps(vectors,ensure_ascii=False,indent=2)+'\n')
        pin=json.loads((HERE/'crypto_sources.json').read_text())
        pin['artifacts']={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ['oracle.py','pure_blake3.py','pure_blake3.LICENSE','requirements.txt','crypto_vectors.json']}
        (HERE/'crypto_sources.json').write_text(json.dumps(pin,indent=2)+'\n')
    assert json.loads(path.read_text())==vectors
    for name,sha in json.loads((HERE/'crypto_sources.json').read_text())['artifacts'].items():
        assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==sha
    print('crypto oracle PASS:',len(vectors['signatures']),'signed cases;',sum(len(c['tamper']) for c in vectors['signatures']),'field tamper negatives;',len(vectors['hashes']),'hash slots/boundaries')

if __name__=='__main__':main()
