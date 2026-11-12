#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent exact-content LP/BLAKE3 vectors; fixture entropy is public test data."""
import base64
import json
from blake3 import blake3


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def lp(value):
    return len(value).to_bytes(4, "big") + value


roots = sorted([b64(bytes([0])*32), b64(bytes([255])*32)])
dm = "dm:" + b64(blake3(lp(b"ramflux.message.dm_conversation.v1") + lp(roots[0].encode()) + lp(roots[1].encode())).digest())
rows = []
for conversation in [dm, "native-group-conversation"]:
    exact = b"\x0a\x03yes\x8a\x01\x20" + bytes(range(32))
    fields = [b"ramflux.message.edit.previous_content.v1", bytes([17])*32, conversation.encode(), roots[0].encode(), exact]
    transcript = b"".join(lp(field) for field in fields)
    rows.append({"conversation":conversation, "author":roots[0], "target":b64(bytes([17])*32),
                 "exact_message":b64(exact), "transcript":b64(transcript), "digest":b64(blake3(transcript).digest())})
print(json.dumps(rows, indent=2))
