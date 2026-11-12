#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent complete signed group HistoryItem vectors, using PUBLIC fixture seeds only.

Run on QA with blake3 and cryptography. The custody fixture already pins its
master/branch certificates; this independently constructs group authority, the
native KDF/AEAD/commitments, original header, outer C/signature and protobuf wire.
Output is a public test artifact, never a tool for production inputs.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def un64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def lp(value):
    return len(value).to_bytes(4, "big") + value


def digest(domain, value):
    return blake3(domain + value).digest()


def hkdf(salt, ikm, info, size):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    previous = b""
    result = b""
    for counter in range(1, (size + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        result += previous
    return result[:size]


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def blob(tag, value):
    if isinstance(value, str):
        value = value.encode()
    return varint(tag * 8 + 2) + varint(len(value)) + value if value else b""


def integer(tag, value):
    return varint(tag * 8) + varint(value) if value else b""


repo = Path(__file__).resolve().parent.parent
fixture = json.loads((repo / "crates/ramflux-crypto/tests/fixtures/custody_v3.json").read_text())
record = fixture["record"]
body = record["body"]
now = body["issued_at"]
root = body["account_anchor"]
device = body["devices"][0]
primary = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture["self_signing_seed_hex"]))
branch = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture["branch_seed_hex"]))
identity = {"principal_id": body["principal_id"], "root_commitment": root,
            "device_id": device["device_id"],
            "signing_public_key": device["branch_certificate"]["body"]["branch_signing_public_key"],
            "target_delivery_id": "root~" + b64(canonical([root, device["device_id"]]))}
actor = {"identity": identity, "root_public_key": body["master_certificate"]["body"]["self_signing_public_key"],
         "root_signature": "", "native_authority": {"master_certificate": body["master_certificate"],
                                                        "branch_certificate": device["branch_certificate"]}}
group = "golden-native-group"
conversation = "golden-native-thread"
genesis = {"group_id": group, "conversation_id": conversation, "actor": actor,
           "issued_at": now, "max_members": 200, "new_member_history": "all_history"}
genesis["signature"] = b64(primary.sign(canonical(dict(genesis, domain="ramflux.group_state.genesis.v2"))))
state = {"group_id": group, "conversation_id": conversation, "epoch": 1, "max_members": 200,
         "new_member_history": "all_history", "name": None, "name_epoch": 0,
         "members": [{"identity": identity, "role": "owner", "joined_epoch": 1}], "excluded": [], "head_hash": ""}
core = {"domain": "ramflux.group_state.snapshot.v2", "genesis": genesis, "creator": actor,
        "transfers": [], "group_id": group, "epoch": 1, "previous_hash": None, "state": state, "issued_at": now}
head = b64(digest(b"ramflux.group_state.content.v2", canonical(core)))
snapshot = {"schema": "ramflux.group_state.snapshot.v2", "group_id": group, "epoch": 1,
            "state_hash": head, "previous_hash": None, "genesis": genesis, "creator": actor,
            "transfers": [], "state": dict(state, head_hash=head), "issued_at": now,
            "root_signature": b64(primary.sign(canonical({"domain": "ramflux.group_state.creator_signature.v2", "content": core, "state_hash": head}))),
            "issuer": actor}
snapshot["signature"] = b64(branch.sign(canonical(snapshot)))
author = blob(1, root) + blob(2, device["device_id"]) + integer(3, device["device_epoch"])
aad = canonical(["ramflux.shared_group.sender_key.v1", group, root, device["device_id"], 1, head])
root_domain = b"ramflux.dm_ratchet.root.v1"
chain_domain = b"ramflux.dm_ratchet.chain.v1"
message_domain = b"ramflux.dm_ratchet.message.v1"
aead_domain = b"ramflux.committing_aead.v1"
local, remote = bytes([2])*32, bytes([3])*32
session = b64(digest(root_domain, root_domain + local + remote + bytes([4])*32)).encode()
chain = hkdf(bytes([1])*32, bytes([1])*32, root_domain + session + local + remote + bytes(24) + b"initiator_send", 64)[32:]
manifest = {"publication": {"record": record, "compacted_ids": None}, "custodian_publication": None, "devices": []}
rows = []
for counter in range(2):
    n = counter.to_bytes(8, "big")
    native_id = session + b":" + str(counter).encode()
    fields = [session, local, remote, bytes(32), bytes(8), n, bytes(8), native_id]
    header = b"RFH1" + bytes([1, 1]) + (8).to_bytes(2, "big")
    header += b"".join(index.to_bytes(2, "big") + lp(value) for index, value in enumerate(fields, 1))
    direction = session + b"send" + bytes(32) + n + bytes(16)
    output = hkdf(digest(chain_domain, direction), chain, chain_domain + direction, 64)
    chain, secret = output[:32], output[32:]
    context = session + b"send" + n + digest(b"ramflux.committing_aead.header.v1", header) + digest(message_domain, aad)
    keys = hkdf(digest(message_domain, context), secret, message_domain + context, 108)
    aead_key, nonce, commitment_key, opening_key = keys[:32], keys[32:44], keys[44:76], keys[76:108]
    plaintext = blob(1, "independent signed group " + str(counter))
    ciphertext = ChaCha20Poly1305(aead_key).encrypt(nonce, plaintext, aad + header)
    hh = b64(digest(b"ramflux.committing_aead.header.v1", header))
    ah = b64(digest(b"ramflux.committing_aead.ad.v1", aad))
    ch = b64(digest(aead_domain, ciphertext))
    common = local + native_id + hh.encode() + ah.encode()
    kc = blake3(aead_domain + common + ch.encode(), key=commitment_key).digest()
    fc = blake3(b"ramflux.franking_opening.v1" + plaintext + common, key=opening_key).digest()
    final = digest(aead_domain, aead_domain + kc + fc)
    sealed = (blob(1, group) + blob(2, author) + integer(3, 1) + blob(4, un64(head)) + blob(5, un64(session.decode()))
              + integer(6, counter) + blob(7, nonce) + blob(8, ciphertext) + blob(11, header) + blob(12, kc)
              + blob(13, final) + blob(14, un64(ch)) + blob(16, local) + blob(17, remote) + blob(19, native_id)
              + blob(20, un64(hh)) + blob(21, fc) + blob(22, final))
    event_id = blake3(lp(b"ramflux.message.id.v1") + lp(root.encode()) + lp(device["device_id"].encode())
                      + device["device_epoch"].to_bytes(8, "big") + lp(conversation.encode()) + (counter+1).to_bytes(8, "big")).digest()
    event = blob(1, event_id) + blob(2, conversation) + blob(3, author) + integer(4, counter+1) + integer(5, 1000+counter) + blob(6, group) + integer(7, 1)
    exact_inner = integer(1, 2) + integer(2, 1) + blob(3, event) + blob(4, blob(16, sealed))
    group_binding = lp(group.encode()) + lp(author) + lp((1).to_bytes(8, "big")) + lp(un64(head))
    header_transcript = b"".join(lp(value) for value in [b"ramflux.message.original_header.v1", (2).to_bytes(4, "big"), (1).to_bytes(4, "big"), event,
                                                        now.to_bytes(8, "big"), (now+300).to_bytes(8, "big"), group_binding])
    outer = {"schema": "ramflux.envelope.v2", "version": 2, "domain": "ramflux.envelope.v2", "signing_key_id": "golden-device-key",
             "signature_alg": "ed25519", "envelope_id": "golden-group-"+str(counter), "source_principal_id": body["principal_id"],
             "source_device_id": device["device_id"], "target_delivery_id": "golden-recipient", "routing_set_id": "golden-route",
             "delivery_class": "message", "priority": "normal", "ttl": 300, "created_at": now, "delivery_mode": "durable",
             "collapse_tag": b64(bytes([34])*32), "payload_hash": b64(digest(b"ramflux.envelope.v1", b64(b"box").encode())),
             "ext": {"source_root_commitment": root, "message_metadata_commitment": b64(blake3(header_transcript).digest())}}
    a0 = {key: outer[key] for key in ["schema", "version", "domain", "envelope_id", "source_principal_id", "source_device_id", "target_delivery_id",
                                      "delivery_class", "priority", "created_at", "collapse_tag", "delivery_mode", "signing_key_id", "signature_alg"]}
    a0.update(ttl_seconds=300, source_authority=root)
    kf = bytes([31])*32
    outer["report_commitment"] = b64(blake3(lp(b"ramflux.message.report_opening.v1") + lp(exact_inner) + lp(canonical(a0)), key=kf).digest())
    outer["signature"] = b64(branch.sign(b"ramflux.envelope.sig.v2\0" + canonical(outer)))
    evidence = blob(1, canonical(outer)) + blob(2, blob(1, canonical(manifest))) + blob(3, blob(1, canonical(snapshot))) + blob(4, kf) + blob(5, plaintext) + blob(6, opening_key+commitment_key)
    item = blob(1, exact_inner) + blob(16, evidence)
    rows.append({"counter": counter, "history_item": b64(item), "history_item_hash": b64(blake3(item).digest()), "event_id": b64(event_id)})
print(json.dumps(rows, sort_keys=True))
