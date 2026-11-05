#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent, test-only RFS1/primitive oracle. --check never rewrites goldens.

Install the hash-locked oracle_requirements.txt in an isolated environment.
Only public deterministic fixture seeds are used. No product module is imported.
"""
import argparse
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'crates/ramflux-protocol/fixtures/dm_fs_v3'
REFERENCE = ROOT / 'scripts/reference/dm_fs_v3/pure_blake3.py'
REFERENCE_HASH = '11735f50be9f369cc4148ae41f14ede97de850120e90176e862f8e0907abe139'
PROFILE = 'ramflux.dm.bootstrap.fs.v1'
PREFIX = 'ramflux.dm_bootstrap_fs.'


def load(name):
    return json.loads((FIXTURES / name).read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


# Check raw bytes BEFORE importing this third-party test-only implementation.
require(hashlib.sha256(REFERENCE.read_bytes()).hexdigest() == REFERENCE_HASH,
        'BLAKE3 reference source hash mismatch')
spec = importlib.util.spec_from_file_location('dm_fs_blake3_reference', REFERENCE)
reference = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reference
spec.loader.exec_module(reference)
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCHEMA = load('wire_schema.json')
TYPES = SCHEMA['types']


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def blake3(value):
    h = reference.Hasher()
    h.update(value)
    return h.finalize()


def domain(name):
    return (PREFIX + name + '.v1').encode()


def framed(name, value):
    return domain(name) + b'\0' + value


def jcs(value):
    """RFC 8785 for fixture domain: safe integers, Unicode strings, no floats.

    UTF-16 key ordering, no normalization, mandatory nulls, minimal JSON escapes.
    Reject values outside this domain rather than silently approximate JCS numbers.
    """
    if value is None:
        return b'null'
    if isinstance(value, bool):
        return b'true' if value else b'false'
    if isinstance(value, int):
        require(abs(value) <= 9007199254740991, 'unsafe JCS integer')
        return str(value).encode()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode('utf-8')
    if isinstance(value, list):
        return b'[' + b','.join(jcs(v) for v in value) + b']'
    require(isinstance(value, dict) and all(isinstance(k, str) for k in value),
            'unsupported JCS value')
    keys = sorted(value, key=lambda k: k.encode('utf-16be'))
    return b'{' + b','.join(jcs(k) + b':' + jcs(value[k]) for k in keys) + b'}'


def encode_value(kind, value):
    if kind.startswith('opt'):
        return b'\0' if value is None else b'\1' + encode_value(kind[3:].lstrip('_'), value)
    if kind.startswith('@'):
        return encode(kind[1:], value)
    if kind.startswith('list'):
        count, child = kind[4:].split('@')
        require(len(value) <= int(count), 'collection count exceeded')
        items = [encode(child, item) for item in value]
        return struct.pack('>H', len(items)) + b''.join(struct.pack('>I', len(v)) + v for v in items)
    if kind == 'u64':
        require(isinstance(value, int) and 0 <= value < 2**64, 'u64 out of range')
        return struct.pack('>Q', value)
    if kind == 'u32':
        require(isinstance(value, int) and 0 <= value < 2**32, 'u32 out of range')
        return struct.pack('>I', value)
    widths = {'key':32, 'hash':32, 'sig':64, 'id':32}
    if kind in widths or kind == 'bytes':
        result = bytes.fromhex(value)
        require(kind == 'bytes' or len(result) == widths[kind], 'fixed width mismatch')
        return result
    require(isinstance(value, str), 'expected string')
    result = value.encode('utf-8')
    if kind == 'text':
        require(0 < len(result) <= 256 and not any(unicodedata.category(c) == 'Cc' for c in value), 'invalid custody ID')
    if kind == 'profile':
        require(value == PROFILE, 'unknown profile')
    return result


def encode(name, values, unsigned=False):
    layout = TYPES[name]
    fields = [f for f in layout['fields'] if not (unsigned and f['name'] == 'signature')]
    require(set(values) == {f['name'] for f in fields}, 'unknown/missing field in ' + name)
    result = b'RFS1' + bytes([layout['code'], 1]) + struct.pack('>H', len(fields))
    for field in fields:
        value = encode_value(field['kind'], values[field['name']])
        require(len(value) <= field['max_bytes'], 'field ceiling exceeded')
        result += struct.pack('>HI', field['id'], len(value)) + value
    require(len(result) <= layout['ceiling'], 'type ceiling exceeded')
    return result


def scan(name, data, unsigned=False):
    """Separate bounded cursor scanner; does not decode/re-encode for acceptance."""
    layout = TYPES[name]
    require(len(data) <= layout['ceiling'] and len(data) >= 8, 'type size')
    fields = [f for f in layout['fields'] if not (unsigned and f['name'] == 'signature')]
    require(data[:6] == b'RFS1' + bytes([layout['code'],1]), 'magic/type/version')
    require(int.from_bytes(data[6:8], 'big') == len(fields), 'field count')
    pos = 8
    for field in fields:
        require(len(data)-pos >= 6, 'truncated field prefix')
        fid, size = struct.unpack_from('>HI', data, pos)
        pos += 6
        require(fid == field['id'] and size <= field['max_bytes'] and size <= len(data)-pos, 'field ID/length')
        value = data[pos:pos+size]
        pos += size
        check_value(field['kind'], value)
    require(pos == len(data), 'trailing bytes')


def check_value(kind, value):
    if kind.startswith('opt'):
        require(value and value[0] in (0,1), 'presence tag')
        if value[0] == 0:
            require(len(value) == 1, 'absent trailing data')
        else:
            check_value(kind[3:].lstrip('_'), value[1:])
    elif kind.startswith('@'):
        scan(kind[1:], value)
    elif kind.startswith('list'):
        cap, child = kind[4:].split('@')
        require(len(value) >= 2, 'collection prefix')
        count = int.from_bytes(value[:2], 'big')
        require(count <= int(cap), 'collection count')
        pos = 2
        for _ in range(count):
            require(len(value)-pos >= 4, 'element prefix')
            size = int.from_bytes(value[pos:pos+4], 'big')
            pos += 4
            require(size <= len(value)-pos, 'element length')
            scan(child, value[pos:pos+size])
            pos += size
        require(pos == len(value), 'collection trailing bytes')
    elif kind in ('u64','u32','key','hash','sig','id'):
        require(len(value) == {'u64':8,'u32':4,'key':32,'hash':32,'sig':64,'id':32}[kind], 'scalar width')
    elif kind != 'bytes':
        text = value.decode('utf-8', errors='strict')
        encode_value(kind, text)


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(seed, transcript):
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    signature = private.sign(transcript)
    private.public_key().verify(signature, transcript)
    return pub(private), signature


def mac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hkdf(ikm, salt, info, length=32):
    prk = mac(salt, ikm)
    blocks = []
    previous = b''
    for n in range(1, (length+31)//32 + 1):
        previous = mac(prk, previous + info + bytes([n]))
        blocks.append(previous)
    output = b''.join(blocks)[:length]
    require(output == HKDF(hashes.SHA256(), length, salt, info).derive(ikm), 'HKDF backend disagreement')
    return {'ikm':ikm.hex(), 'salt':salt.hex(), 'info':info.hex(), 'prk':prk.hex(),
            'blocks':[b.hex() for b in blocks], 'output':output.hex()}


def check_kats(kats):
    for item in kats['blake3']:
        require(blake3(bytes.fromhex(item['input'])).hex() == item['output'], 'BLAKE3 KAT')
    e = kats['ed25519']
    key, signature = sign(e['seed'], bytes.fromhex(e['message']))
    require(key.hex() == e['public'] and signature.hex() == e['signature'], 'Ed25519 KAT')
    x = kats['x25519']
    key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(x['secret']))
    require(pub(key).hex() == x['public'], 'X25519 public KAT')
    require(key.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(x['peer']))).hex() == x['shared'], 'X25519 shared KAT')
    try:
        key.exchange(x25519.X25519PublicKey.from_public_bytes(bytes(32)))
    except ValueError:
        pass
    else:
        raise ValueError('all-zero DH accepted')
    h = kats['hkdf']
    require(hkdf(bytes.fromhex(h['ikm']), bytes.fromhex(h['salt']), bytes.fromhex(h['info']),42)['output'] == h['output'], 'HKDF KAT')
    require(jcs({'\U0001f600':1,'\ufffd':2,'a':'\n"\\','nil':None}) == '{"a":"\\n\\"\\\\","nil":null,"😀":1,"�":2}'.encode(), 'JCS Unicode/escape control')


def check_wire(vectors):
    names = set()
    for vector in vectors['positive']:
        raw = bytes.fromhex(vector['bytes'])
        require(encode(vector['type'], vector['input']) == raw, 'golden bytes: ' + vector['name'])
        scan(vector['type'], raw)
        require(b64(raw) == vector['base64url'], 'carrier bytes')
        if vector['type'] in ('NativePrekeyLease','NativePrekeyPublish','NativePrekeyStatus','NativePrekeyResult'):
            label = {'NativePrekeyLease':'native_prekey_lease', 'NativePrekeyPublish':'native_prekey_publish',
                     'NativePrekeyStatus':'native_prekey_status', 'NativePrekeyResult':'native_prekey_result'}[vector['type']]
            require(vector['json_carrier'] == dict(frame_type=label,payload=b64(raw)), 'JSON carrier binding')
            require(jcs(vector['json_carrier']).hex() == vector['json_jcs'], 'JSON carrier JCS')
        names.add(vector['type'])
    require(names == set(TYPES), 'missing type vector coverage')
    for vector in vectors['invalid_inputs']:
        value = vector.get('input')
        if value is None:
            value = dict(vector['base_input'])
            value[vector['repeat_field']] = [vector['repeat_value']] * vector['count']
        try:
            encode(vector['type'], value)
        except (ValueError, UnicodeError):
            pass
        else:
            raise ValueError('invalid input accepted: ' + vector['name'])
    for vector in vectors['negative']:
        try:
            scan(vector['type'], bytes.fromhex(vector['bytes']))
        except (ValueError, UnicodeError):
            pass
        else:
            raise ValueError('negative accepted: ' + vector['name'])
    for vector in vectors['deadlines']:
        v = vector['input']
        try:
            t = 604800
            require(0 <= v['ttl'] <= t and v['validity'] <= 2*t, 'time policy')
            require(v['leased_at'] <= v['now']+300, 'future lease')
            start = v['leased_at'] if v['mode'] == 'opk' else v['issued_at']
            terms = (start+t, v['spk_expires_at']+t, v['created_at']+v['ttl'])
            require(all(0 <= n < 2**64 for n in terms), 'overflow')
            accepted = v['now'] < v['deadline'] <= min(terms)
        except ValueError:
            accepted = False
        require(accepted == vector['accepted'], 'deadline: ' + vector['name'])


def check_crypto(vectors):
    check_kats(vectors['known_answers'])
    seen = set()
    for vector in vectors['hashes']:
        require(blake3(bytes.fromhex(vector['preimage'])).hex() == vector['digest'], 'hash: ' + vector['name'])
        seen.add(vector['name'])
    require(seen == set(vectors['hash_inventory']), 'hash coverage mismatch')
    for vector in vectors['signatures']:
        public, signature = sign(vector['seed'], bytes.fromhex(vector['preimage']))
        require(public.hex() == vector['public'] and signature.hex() == vector['signature'], 'signature: ' + vector['name'])
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, bytes.fromhex(vector['preimage']) + b'!')
        except Exception as exc:
            from cryptography.exceptions import InvalidSignature
            require(isinstance(exc, InvalidSignature), 'unexpected signature failure')
        else:
            raise ValueError('tampered signature verified')
    require({v['mode'] for v in vectors['bootstrap']} == {'opk','spk_only'}, 'bootstrap coverage')
    for vector in vectors['bootstrap']:
        keys = {n:x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for n,s in vector['seeds'].items()}
        pairs = [('initiator_identity','spk'), ('ephemeral','recipient_identity'), ('ephemeral','spk')]
        if vector['mode'] == 'opk':
            pairs.append(('ephemeral','opk'))
        dhs = [keys[a].exchange(keys[b].public_key()) for a,b in pairs]
        reverse = [keys[b].exchange(keys[a].public_key()) for a,b in pairs]
        require(dhs == reverse and [d.hex() for d in dhs] == vector['dh'], 'X3DH DH ordering')
        require(pub(keys['ephemeral']) != pub(keys['ratchet']), 'E/R0 independence')
        require({n:pub(k).hex() for n,k in keys.items()} == vector['public_keys'], 'X25519 public keys')
        derived = hkdf(b'\xff'*32 + b''.join(dhs), bytes.fromhex(vector['kdf']['salt']), bytes.fromhex(vector['kdf']['info']))
        require(derived == vector['kdf'], 'X3DH KDF slots')


def check_custody(vectors):
    require({v['action']['operation'] for v in vectors} == {'register','prekey_status','register_update'}, 'custody coverage')
    for v in vectors:
        action = jcs(v['action'])
        preimage = b'ramflux.identity.custody_action.v1\0' + action
        digest = blake3(preimage)
        require(action.hex() == v['action_jcs'] and preimage.hex() == v['action_preimage'], 'custody JCS/preimage')
        require(digest.hex() == v['digest'] and b64(digest) == v['action_hash'], 'custody action hash')
        require(v['proof_body']['action_hash'] == b64(digest), 'proof action binding')
        transcript = jcs({'domain':'ramflux.identity.branch_proof.v3','body':v['proof_body']})
        public, signature = sign(v['branch_seed'], transcript)
        require(transcript.hex() == v['proof_transcript'] and public.hex() == v['branch_public'] and signature.hex() == v['proof_signature'], 'custody proof grammar')
        if v['action']['operation'] != 'register':
            label = 'query' if v['action']['operation'] == 'prekey_status' else 'update'
            require(v['action'][label] == b64(bytes.fromhex(v['embedded_rfs1'])), 'embedded custody payload')


def check_bindings(wire, crypto, custody):
    """Bind independent primitive slots to their actual canonical wire inputs."""
    by_name = {v['name']: v for v in wire['positive']}
    slots = {v['name']: v for v in crypto['hashes']}
    required = {
        'branch_binding', 'base_hash', 'retirement_digest', 'lease_operation_id',
        'request_argument', 'request_hash', 'status_request_hash', 'publish_argument', 'status_argument',
        'bundle_hash_opk', 'bundle_hash_spk_only', 'transcript_hash_opk',
        'transcript_hash_spk_only', 'custody_action_register',
        'custody_action_prekey_status', 'custody_action_register_update',
        'custody_object_register', 'custody_object_prekey_status',
        'custody_object_register_update',
    }
    require(set(slots) == required and len(slots) == len(crypto['hashes']), 'complete hash inventory')
    for v in slots.values():
        require(bytes.fromhex(v['preimage']) == v['domain'].encode() + b'\0' + bytes.fromhex(v['canonical']), 'hash framing: ' + v['name'])
    direct = {
        'branch_binding':'QualifiedBranch', 'base_hash':'SignedNativePrekeyBase',
        'retirement_digest':'RetirementRef', 'lease_operation_id':'PrekeyLeaseIntent',
        'request_argument':'PrekeyLeaseIntent', 'request_hash':'NativePrekeyRequest',
        'publish_argument':'OwnerPrekeyUpdate', 'status_argument':'OwnerStatusQuery',
        'bundle_hash_opk':'lease_opk', 'bundle_hash_spk_only':'lease_spk_only',
        'transcript_hash_opk':'transcript_opk', 'transcript_hash_spk_only':'transcript_spk_only',
    }
    require(slots['status_request_hash']['canonical'] == encode('NativePrekeyRequest', by_name['NativePrekeyStatus']['input']['request']).hex(), 'status request hash binding')
    for slot, name in direct.items():
        require(slots[slot]['canonical'] == by_name[name]['bytes'], 'hash wire binding: ' + slot)
    observed = set()
    def visit(name, value):
        layout = TYPES[name]
        if layout['domain'] and 'signature' in value:
            unsigned = {k:v for k,v in value.items() if k != 'signature'}
            transcript = framed(layout['domain'], encode(name, unsigned, unsigned=True))
            candidates = [v for v in crypto['signatures'] if v['signature'] == value['signature'] and v['preimage'] == transcript.hex()]
            require(len(candidates) == 1, 'native signature wire binding: ' + name)
            observed.add((transcript.hex(), value['signature']))
        for field in layout['fields']:
            kind, child = field['kind'], value[field['name']]
            if kind.startswith('opt@') and child is not None:
                visit(kind[4:], child)
            elif kind.startswith('@'):
                visit(kind[1:], child)
            elif kind.startswith('list'):
                for element in child:
                    visit(kind.split('@')[1], element)
    for vector in wire['positive']:
        visit(vector['type'], vector['input'])
    require(observed == {(v['preimage'],v['signature']) for v in crypto['signatures']}, 'signature coverage')
    for result_name, request_name in [('result_opk','NativePrekeyLease'), ('result_spk_only','NativePrekeyLease'), ('result_status','NativePrekeyStatus'), ('result_busy','NativePrekeyLease')]:
        result, request = by_name[result_name]['input'], by_name[request_name]['input']
        require(result['correlation_id'] == request['correlation_id'], 'result correlation binding')
        expected = blake3(framed('request_argument', encode('NativePrekeyRequest',request['request']))).hex()
        require(result['request_hash'] == expected, 'result request binding')
    for vector in crypto['bootstrap']:
        mode = vector['mode']
        header = by_name['header_'+mode]['input']
        require(header['bundle_hash'] == slots['bundle_hash_'+mode]['digest'], 'bundle binding')
        require(header['base_hash'] == slots['base_hash']['digest'], 'base binding')
        require(header['operation_id'] == slots['lease_operation_id']['digest'], 'operation binding')
        require(vector['kdf']['salt'] == header['bundle_hash'], 'KDF salt binding')
        require(vector['kdf']['info'] == (domain('x3dh_root') + bytes.fromhex(slots['transcript_hash_'+mode]['digest'])).hex(), 'KDF info binding')
        require(header['ephemeral_key'] == vector['public_keys']['ephemeral'] and header['ratchet_key'] == vector['public_keys']['ratchet'], 'E/R0 header binding')
    for v in custody:
        op = v['action']['operation']
        require(slots['custody_action_'+op]['digest'] == v['digest'], 'custody hash coverage')
        require(slots['custody_object_'+op]['canonical'] == jcs(v['proof_envelope']).hex(), 'custody object coverage')
        if op != 'register':
            name = 'OwnerStatusQuery' if op == 'prekey_status' else 'OwnerPrekeyUpdate'
            require(v['embedded_rfs1'] == by_name[name]['bytes'], 'custody native wire binding')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', required=True)
    parser.parse_args()
    manifest = load('oracle_sources.json')
    require(len({v['code'] for v in TYPES.values()}) == len(TYPES), 'duplicate type code')
    require(len(set(SCHEMA['domains'])) == 21, 'domain inventory')
    for layout in TYPES.values():
        require([f['id'] for f in layout['fields']] == list(range(1,len(layout['fields'])+1)), 'field ID ordering')
        require(all(f['required'] for f in layout['fields']), 'field presence grammar')
    for package, version in manifest['versions'].items():
        require(importlib.metadata.version(package) == version, 'oracle package version: ' + package)
    require(backend.openssl_version_text() == manifest['openssl_version'], 'OpenSSL version mismatch')
    require(manifest['reference']['sha256'] == REFERENCE_HASH, 'reference manifest pin')
    for name, digest in manifest['fixture_sha256'].items():
        require(hashlib.sha256((FIXTURES/name).read_bytes()).hexdigest() == digest, 'fixture integrity: ' + name)
    wire, crypto, custody = (load(n) for n in ('wire_vectors.json','crypto_vectors.json','custody_vectors.json'))
    check_wire(wire)
    check_crypto(crypto)
    check_custody(custody)
    check_bindings(wire, crypto, custody)
    actual_coverage = dict(wire_types=len(TYPES), positive_wire_cases=len(wire['positive']),
        negative_wire_cases=len(wire['negative']), invalid_inputs=len(wire['invalid_inputs']),
        deadline_cases=len(wire['deadlines']), hashes=len(crypto['hashes']),
        native_signatures=len(crypto['signatures']), custody_actions=len(custody),
        bootstrap_modes=sorted(v['mode'] for v in crypto['bootstrap']))
    require(actual_coverage == manifest['coverage'], 'manifest coverage mismatch')
    require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == manifest['oracle_source_sha256'], 'oracle source integrity')
    require(hashlib.sha256((ROOT / 'docs/design/dm_bootstrap_forward_secrecy_v3.md').read_bytes()).hexdigest() == manifest['design_copy']['sha256'], 'design copy integrity')
    print('ORACLE PASS: all wire, primitive, custody and deadline goldens verified')


if __name__ == '__main__':
    main()
