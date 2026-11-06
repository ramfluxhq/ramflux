#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Check independent synthetic pairing vectors by default; --write regenerates.

Restricted fixtures contain strings and safe integers only: sorted compact UTF-8
JSON implements JCS for these values. SHA-256 uses the OpenSSL CLI; old custody
object/section/list controls use the pinned official C BLAKE3, never Rust/Python
blake3. No product modules are imported. Crypto adaptation is owned by later parts.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'crates/ramflux-protocol/fixtures/pairing_v2'
REF = ROOT / 'scripts/reference/pairing'

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()

def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def frame(domain, raw):
    return domain.encode() + b'\0' + raw

def run(args, data):
    return subprocess.run(args, input=data, check=True, capture_output=True).stdout

def generate():
    manifest = json.loads((FIX / 'manifest.json').read_text())
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == manifest['oracle_sha256']
    assert hashlib.sha256((REF/'hash.c').read_bytes()).hexdigest() == manifest['adapter_sha256']
    for name, digest in manifest['blake3_c']['files_sha256'].items():
        assert hashlib.sha256((REF / name).read_bytes()).hexdigest() == digest, name
    common = dict(schema='ramflux.pairing.Common.v2', version=2,
                  invitation_id=b64(bytes([1])*32), issuer_seq=1,
                  account_anchor=b64(bytes([2])*32), master_public_key=b64(bytes([3])*32),
                  record_hash=b64(bytes([4])*32), device_set_epoch=4294967297,
                  principal_kind='human', sas_suite='ramflux.identity.pairing.sas_emoji.v1',
                  hpke_suite=None, purpose='enroll', requested_role='secondary',
                  recipient_mode='new', destination_ref=None,
                  capabilities=['call','group','message','register','sync'],
                  lease_not_before=1700000000, lease_expires_at=1702592000,
                  expires_at=1700000300, transfer_id=None, data_selection=[])
    def role(name, n):
        return dict(schema='ramflux.pairing.RoleContext.v2',version=2,role=name,common=common,
                    device_ref=dict(account_anchor=common['account_anchor'],device_id=name,device_epoch=1),
                    branch_key=b64(bytes([n])*32),agreement_key=b64(bytes([n+1])*32),
                    sas_key=b64(bytes([n+2])*32),hpke_key=None,display_name='Vector '+name)
    initiator,responder=role('initiator',5),role('responder',8)
    transcript=dict(schema='ramflux.pairing.Transcript.v2',version=2,initiator=initiator,responder=responder)
    preimages={'transcript':frame('ramflux.identity.pairing_transcript.v2',jcs(transcript))}
    for n,ctx in enumerate([initiator,responder]):
        preimages[ctx['role']]=frame('ramflux.identity.pairing.context_commitment.v2',bytes([n])+bytes([11+n])*32+jcs(ctx))
    # Old v1 SAS grammar remains a control, never negotiated into v2.
    preimages['old_commitment']=frame('ramflux.identity.pairing.commitment.v1',b'\0'+bytes([11])*32+bytes([7])*32+bytes([1])*32)
    old_transcript={k:common[k] for k in ['invitation_id','account_anchor','master_public_key','record_hash','device_set_epoch','principal_kind','purpose','requested_role','capabilities','sas_suite','hpke_suite']}
    old_transcript.update(schema='ramflux.identity.pairing_transcript.v1',version=1,
                          initiator_sas_key=initiator['sas_key'],responder_sas_key=responder['sas_key'],
                          initiator_branch_key=initiator['branch_key'],responder_branch_key=responder['branch_key'],
                          responder_agreement_key=responder['agreement_key'],sender_hpke_key=None,recipient_hpke_key=None)
    preimages['old_transcript']=frame('ramflux.identity.pairing_transcript.v1',jcs(old_transcript))
    output={'transcript':transcript,'preimages_hex':{k:v.hex() for k,v in preimages.items()},
            'sha256':{k:run(['openssl','dgst','-sha256','-binary'],v).hex() for k,v in preimages.items()},
            'openssl':run(['openssl','version'],b'').decode().strip()}
    with tempfile.TemporaryDirectory(prefix='pairing-oracle-') as tmp:
        exe=str(Path(tmp)/'blake3-ref')
        subprocess.run(['cc','-O2','-DBLAKE3_NO_SSE2','-DBLAKE3_NO_SSE41','-DBLAKE3_NO_AVX2','-DBLAKE3_NO_AVX512','-DBLAKE3_USE_NEON=0','-I',str(REF),str(REF/'hash.c'),*[str(REF/n) for n in ['blake3.c','blake3_dispatch.c','blake3_portable.c']],'-o',exe],check=True)
        spec=dict(schema='ramflux.pairing.CreateSpec.v2',version=2,
                  account_anchor=common['account_anchor'],primary_ref=initiator['device_ref'],
                  base_record_hash=common['record_hash'],base_epoch=common['device_set_epoch'],
                  purpose='enroll',recipient_mode='new',destination_ref=None,
                  capabilities=common['capabilities'],lease_not_before=common['lease_not_before'],
                  lease_expires_at=common['lease_expires_at'],data_selection=[],ttl_seconds=300)
        spec_hash=b64(run([exe],frame('ramflux.identity.custody.object_hash.v1',jcs(spec))))
        ticket=dict(schema='ramflux.pairing.CreateTicket.v2',version=2,node_key=b64(bytes([3])*32),
                    boot_id=b64(bytes([5])*32),create_id=b64(bytes([2])*32),issuer_seq=1,
                    account_anchor=spec['account_anchor'],primary_ref=spec['primary_ref'],
                    spec_hash=spec_hash,issued_at=100,expires_at=400)
        invitation={k:v for k,v in spec.items() if k!='ttl_seconds'}
        invitation.update(schema='ramflux.pairing.Invitation.v2',invitation_id=b64(bytes([1])*32),
                          issuer_seq=1,request_id=b64(bytes([2])*32),node_key=b64(bytes([3])*32),
                          public_origin='https://relay.example:443',transfer_id=None,created_at=100,expires_at=400)
        commit=dict(schema='ramflux.pairing.Commit.v2',version=2,invitation_id=b64(bytes([1])*32),role='initiator',commitment=b64(bytes([1])*32))
        send=dict(schema='ramflux.pairing.Send.v2',version=2,invitation_id=b64(bytes([1])*32),issuer_seq=1,role='initiator',token=b64(bytes([4])*32),seq=0,frame=dict(kind='commit',value=commit))
        native_preimages={
            'ticket':jcs(dict(domain='ramflux.identity.pairing.create_ticket.v2',body=ticket)),
            'invitation':jcs(dict(domain='ramflux.identity.pairing.invitation.v2',body=invitation)),
            'old_ticket':jcs(dict(domain='ramflux.identity.pairing.create_ticket.v1',body=ticket)),
            'old_invitation':jcs(dict(domain='ramflux.identity.pairing.invitation.v1',body=invitation))}
        output['native_relay']=dict(spec=spec,spec_hash=spec_hash,ticket=ticket,invitation=invitation,send=send,
                                   send_digest=b64(run([exe],frame('ramflux.identity.custody.object_hash.v1',jcs(send)))),
                                   preimages_hex={k:v.hex() for k,v in native_preimages.items()},
                                   sha256={k:run(['openssl','dgst','-sha256','-binary'],v).hex() for k,v in native_preimages.items()})
        controls={}
        envelope={'body':{'schema':'control.v1','version':1,'nullable':None,'nested':{'body':{'n':1},'signature':b64(bytes([13])*64)}},'signature':b64(bytes([12])*64)}
        for name, domain, value in [('object','ramflux.identity.custody.object_hash.v1',envelope),('section','ramflux.identity.custody.section_hash.v1',{'section':'profile','value':{'kind':'human'}}),('list','ramflux.identity.revoked_devices.list.v1',[])]:
            raw=frame(domain,jcs(value))
            controls[name]={'domain':domain,'value':value,'preimage_hex':raw.hex(),'blake3':b64(run([exe],raw))}
        legacy_path=ROOT/'crates/ramflux-crypto/tests/fixtures/custody_v3.json'
        assert hashlib.sha256(legacy_path.read_bytes()).hexdigest() == manifest['custody_control_sha256']
        legacy=json.loads(legacy_path.read_bytes())
        assert b64(run([exe],frame('ramflux.identity.custody.object_hash.v1',jcs(legacy['record'])))) == legacy['record_hash']
        output['old_controls']=controls
        output['legacy_record_hash']=legacy['record_hash']
    return output

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); mode=parser.add_mutually_exclusive_group(); mode.add_argument('--check',action='store_true'); mode.add_argument('--write',action='store_true'); args=parser.parse_args()
    result=generate(); path=FIX/'vectors.json'
    if not args.write:
        expected=json.loads(path.read_text()); result['openssl']=expected['openssl']
        assert result == expected, 'independent pairing golden mismatch'
        print('pairing oracle: PASS (OpenSSL SHA-256, official BLAKE3 C, old controls)')
    else:
        path.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
        print('pairing vectors written')
