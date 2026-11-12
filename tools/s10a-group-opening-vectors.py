#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent public fixture commitments; requires Python blake3 on the QA host.

Preserves the existing native franking grammar, including its historical domain
framing. Prints commitments only, never opening material or production inputs.
"""
import base64
import json
from blake3 import blake3


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def native_hash(domain, data):
    return b64(blake3(domain + data).digest())


aead = b"ramflux.committing_aead.v1"
session = b64(bytes([9]) * 32)
native_event = session + b":1"
fields = [session, bytes([5]) * 32, bytes([6]) * 32, bytes(32),
          (0).to_bytes(8,"big"), (1).to_bytes(8,"big"), (1).to_bytes(8,"big"), native_event]
canonical = b"RFH1" + bytes([1,1]) + (8).to_bytes(2,"big")
canonical += b"".join(index.to_bytes(2,"big") + len(value).to_bytes(4,"big") + value
                      for index,value in enumerate(fields,1))
aad_bytes = json.dumps(["ramflux.shared_group.sender_key.v1", "fixture-group",
                       b64(bytes(32)).decode(), "alice", 7, b64(bytes([8])*32).decode()],
                      ensure_ascii=False,separators=(",",":")).encode()
header = native_hash(b"ramflux.committing_aead.header.v1", canonical)
aad = native_hash(b"ramflux.committing_aead.ad.v1", aad_bytes)
ciphertext = native_hash(aead, bytes([4]) * 32)
common = bytes([5]) * 32 + native_event + header + aad
key = blake3(aead + common + ciphertext, key=bytes([2]) * 32).digest()
franking = blake3(b"ramflux.franking_opening.v1" + b"\x0a\x05hello" + common,
                  key=bytes([1]) * 32).digest()
result = {
    "canonical_header": b64(canonical).decode(),
    "native_event_id": native_event.decode(),
    "native_aad": b64(aad_bytes).decode(),
    "header_hash": header.decode(),
    "ciphertext_hash": ciphertext.decode(),
    "key_commitment": b64(key).decode(),
    "franking_commitment": b64(franking).decode(),
    "commitment": native_hash(aead, aead + key + franking).decode(),
}
fields = [b"ramflux.message.friend.applied.v1", b"root/device", bytes([8, 2, 16, 8])]
result["friend_fingerprint"] = b64(blake3(b"".join(len(x).to_bytes(4, "big") + x for x in fields)).digest()).decode()
print(json.dumps(result, sort_keys=True))
