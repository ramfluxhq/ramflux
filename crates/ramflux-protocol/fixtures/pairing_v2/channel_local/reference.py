# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent D/E size witnesses: Python stdlib only, no product codec calls.

All material is synthetic. --write explicitly regenerates; default checks bytes.
The maxima are simultaneous field/collection maxima, not padding to body caps.
"""
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).parent
U = 9007199254740991
CAPS = ['call', 'group', 'message', 'register', 'sync']
def b(n, size=32):
    return base64.urlsafe_b64encode(bytes([n]) * size).decode().rstrip('=')
def obj(name, **fields):
    return dict(schema=f'ramflux.pairing.{name}.v2', version=2, **fields)
def escaped_id(index, size, bits=5):
    # Every character needs a JSON escape; the fixed-width prefix gives unique,
    # lexically sorted ids without replacing escapes with cheap ASCII digits.
    return ''.join('\\' if c == '1' else '"' for c in f'{index:0{bits}b}') + '\\'*(size-bits)
def ref(prefix='r', size=128):
    index = 0 if prefix == 'p' else 1 if prefix == 'r' else int(prefix)
    return dict(account_anchor=b(1), device_id=escaped_id(index,size,8), device_epoch=U)
def signed(body):
    return dict(body=body, signature=b(7, 64))
def canon(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

selection = [dict(key_id=escaped_id(i,128), purpose='attachment') for i in range(32)]
rights = dict(capabilities=CAPS, lease_not_before=U-300, lease_expires_at=U)
name = '\\"'*64
begin = obj('Begin', **rights, display_name=name)
transfer = obj('TransferBegin', **rights, display_name=name, recipient_mode='existing', destination_ref=ref(), data_selection=selection)
invitation = obj('Invitation', invitation_id=b(1), issuer_seq=U, request_id=b(2), node_key=b(3), public_origin='https://' + 'a'*63 + '.' + 'b'*63 + '.' + 'c'*63 + '.' + 'd'*56, account_anchor=b(1), primary_ref=ref('p'), base_record_hash=b(4), base_epoch=U, purpose='primary_transfer', recipient_mode='existing', destination_ref=ref(), **rights, data_selection=selection, transfer_id=b(5), created_at=U-300, expires_at=U)
token = obj('InviteToken', invitation=signed(invitation), recipient_token=b(6))
base = dict(operation_id=b(2), generation=U)
br = obj('BeginResult', **base, expires_at=U, invite_token=token)
update = obj('Update', **base, phase='mutually_confirmed', expires_at=U, transcript_hash=b(1), emoji_indices=[63]*7, peer_ref=ref(), peer_name=name, **rights, proposal_hash=None, record_hash=None, result='PublicationPending', cleanup='pending')
prepared = dict(update, phase='locally_installed', emoji_indices=None, proposal_hash=b(2), record_hash=b(3))
terminal = dict(prepared, phase='cancelled', result='PublicationPending')
objects = dict(Begin=begin, TransferBegin=transfer, Join=obj('Join', token=token, display_name=name), BeginResult=br, Update=update, LocalEvent=obj('LocalEvent', update=prepared), CredentialRequest=dict(local_account_id=escaped_id(0,128), reservation_id=b(1), frontend_generation=U, action='unlock'))
objects['Update_installed'] = prepared
objects['Update_terminal'] = terminal
objects['EnrollmentBodyMax'] = dict(schema='ramflux.identity.pairing.enrollment.v1', version=1,
    invitation_id=b(1), transcript_hash=b(2), base_record_hash=b(3), base_epoch=U,
    recipient_ref=ref(), branch_signing_key=b(4), agreement_key=b(5), requested_role='secondary',
    capabilities=CAPS, lease_expires_at=U, display_name=name)
objects['PreservationBodyMax'] = dict(schema='ramflux.identity.transfer.preserve.v1', version=1,
    transfer_id=b(1), transcript_hash=b(2), old_record_hash=b(3), new_record_hash=b(4),
    destination_ref=ref(), recipient_mode='existing', policy='preserve_all_existing', expires_at=U)
for typ, extra in [('Confirm',dict(transcript_hash=b(1), match=False)), ('Approve',dict(transcript_hash=b(1), proposal_hash=b(2), approved=False)), ('Prepare',dict(transcript_hash=b(1))), ('Cancel',{}), ('StatusRequest',{})]:
    objects[typ] = obj(typ, **base, **extra)
for tag, value in [('begin', br), ('update', prepared), ('error', obj('Failure', code='PublicationPending', retry_after_ms=None))]:
    objects['LocalResult_'+tag] = obj('LocalResult', outcome=dict(tag=tag, **{('error' if tag=='error' else 'value'):value}))
# Annex D uses wider 256-byte payload ids, 128-byte Ref ids and every collection full.
hashes = sorted(b(i) for i in range(8))
payload = dict(schema='ramflux.identity.transfer.payload.v1', version=1, transfer_id=b(1), transcript_hash=b(2), current_record_hash=b(3), device_set_epoch=U,
    pending_invitations=[dict(invitation_id=b(i), expires_at=U, proposal_hash=b(i)) for i in range(3)],
    journal=[dict(operation_id=b(i), intent_hash=b(i), state='acknowledged', acknowledgement_hash=b(i)) for i in range(64)], delegation_state=[],
    group_restriction_summary=[dict(group_id=escaped_id(i,256,6), group_genesis_hash=b(1), control_head_hash=b(2), restriction_hashes=hashes, revocation_hashes=hashes) for i in range(64)],
    pending_erasure=[ref(f'{i:03}') for i in range(256)],
    optional_data_keys=[dict(key_id=escaped_id(i,256), purpose='attachment', key=b(i)) for i in range(32)])
objects['TransferPayload'] = payload
for kind, total, count in [('hpke',819200,100), ('candidate',524288,64)]:
    objects['Channel_'+kind] = obj('Channel', invitation_id=b(1), transcript_hash=b(2), payload=dict(kind='artifact_chunk', object_kind=kind, object_id=b(1), index=count-1, count=count, total_bytes=total, bytes=b(1,8192)))
# Reach the complete HPKE envelope cap independently. Vary only a valid Ref id's
# JSON escaping to land on a base64 ciphertext length that exactly fills 819200.
for escaped in range(129):
    sender = ref('p')
    sender['device_id'] = '"'*escaped + 'x'*(128-escaped)
    binding = dict(schema='ramflux.identity.transfer_binding.v1', version=1, transfer_id=b(1), transcript_hash=b(2), current_record_hash=b(3), device_set_epoch=U, sender_device_ref=sender, sender_hpke_key=b(8), recipient_hpke_key=b(9), issued_at=U-300, expires_at=U)
    hpke = dict(schema='ramflux.identity.transfer.hpke.v1', version=1, transfer_id=b(1), transcript_hash=b(2), current_record_hash=b(3), device_set_epoch=U, sender_binding=signed(binding), enc=b(10), ciphertext='')
    cipher_chars = 819200 - len(canon(hpke).encode())
    residue = cipher_chars % 4
    if residue == 0:
        raw_size = cipher_chars // 4 * 3
    elif residue == 2:
        raw_size = cipher_chars // 4 * 3 + 1
    elif residue == 3:
        raw_size = cipher_chars // 4 * 3 + 2
    else:
        continue
    if 16 <= raw_size <= 1_048_592:
        hpke['ciphertext'] = b(0, raw_size)
        if len(canon(hpke).encode()) == 819200:
            objects['HpkeEnvelopeMax'] = hpke
            break
else:
    raise AssertionError('could not construct exact HPKE envelope maximum')
encoded = {key: dict(wire=canon(value), size=len(canon(value).encode())) for key,value in objects.items()}
result = json.dumps(encoded, ensure_ascii=False, indent=2, sort_keys=True) + '\n'
path = ROOT / 'maxima.json'
if sys.argv[1:] == ['--write']:
    path.write_text(result)
else:
    assert not sys.argv[1:]
    assert path.read_text() == result, 'independent size witnesses drifted'
print('D/E independent size witnesses: PASS (' + ', '.join(f'{k}={v["size"]}' for k,v in encoded.items()) + ')')
