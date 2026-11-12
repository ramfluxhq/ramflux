#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent two-counter native KDF fixtures. All seeds are public test constants."""
import base64
import hashlib
import hmac
import json
from blake3 import blake3


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def digest(domain, value):
    return blake3(domain + value).digest()


def hkdf(salt, ikm, info, size):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    previous = b""
    output = b""
    for counter in range(1, (size + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
    return output[:size]


root_domain = b"ramflux.dm_ratchet.root.v1"
chain_domain = b"ramflux.dm_ratchet.chain.v1"
message_domain = b"ramflux.dm_ratchet.message.v1"
header_domain = b"ramflux.committing_aead.header.v1"
local = bytes([2])*32
remote = bytes([3])*32
session = b64(digest(root_domain, root_domain + local + remote + bytes([4])*32))
context = session + local + remote + bytes(24) + b"initiator_send"
chain = hkdf(bytes([1])*32, bytes([1])*32, root_domain + context, 64)[32:]
aad = json.dumps(["ramflux.shared_group.sender_key.v1", "fixture-group",
                  b64(bytes(32)).decode(), "alice", 7, b64(bytes([8])*32).decode()],
                 separators=(",", ":")).encode()
rows = []
for counter in range(2):
    number = counter.to_bytes(8, "big")
    native_id = session + b":" + str(counter).encode()
    fields = [session, local, remote, bytes(32), bytes(8), number, bytes(8), native_id]
    header = b"RFH1" + bytes([1, 1]) + (8).to_bytes(2, "big")
    header += b"".join(index.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
                       for index, value in enumerate(fields, 1))
    direction = session + b"send" + bytes(32) + number + bytes(16)
    output = hkdf(digest(chain_domain, direction), chain, chain_domain + direction, 64)
    chain, secret = output[:32], output[32:]
    context = session + b"send" + number + digest(header_domain, header) + digest(message_domain, aad)
    keys = hkdf(digest(message_domain, context), secret, message_domain + context, 108)
    # Pin the full 108-byte schedule by a public fingerprint without printing key material.
    rows.append({"counter": counter, "session": session.decode(), "native_id": native_id.decode(),
                 "header": b64(header).decode(), "aad": b64(aad).decode(),
                 "schedule_hash": b64(blake3(keys).digest()).decode(),
                 "opening_hash": b64(blake3(keys[76:108]+keys[44:76]).digest()).decode(),
                 "nonce": b64(keys[32:44]).decode()})
print(json.dumps(rows, sort_keys=True))
