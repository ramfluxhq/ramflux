# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent public consent vector using the existing nonproduction custody fixture.

Uses the Python cryptography/blake3 packages documented in custody_v3_reference.py.
ASCII strings and safe integers make this restricted sorted compact JSON exactly JCS.
No production credentials or network operations are used.
"""
import json
from pathlib import Path
import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from custody_v3_reference import b64, generate, jcs, sign


def generate_consent():
    fixture = generate()
    anchor = fixture["account_anchor"]
    nonce = b64(bytes([29]) * 32)
    body = {
        "schema": "ramflux.identity.contact_request.v2", "version": 2, "kind": "request",
        "request_id": b64(blake3.blake3(b"ramflux.contact_request.id.v1" + jcs([anchor, nonce])).digest()),
        "nonce": nonce, "requester_root": anchor, "target_root": b64(bytes([30]) * 32),
        "actor_root": anchor,
        "sending_device_ref": fixture["record"]["body"]["master_certificate"]["body"]["primary_device_ref"],
        "issued_at": 1700000000, "expires_at": 1700604800, "note": None,
        "actor_record_hash": fixture["record_hash"],
        "master_certificate_hash": fixture["master_certificate_hash"],
    }
    domain = "ramflux.identity.contact_request.v2"
    primary = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
    envelope = sign(primary, domain, body)
    return {"consent": envelope, "signing_bytes_hex": jcs({"domain": domain, "body": body}).hex(),
            "canonical_hex": jcs(envelope).hex()}


if __name__ == "__main__":
    output = Path(__file__).with_name("contact_consent_v2.json")
    output.write_text(json.dumps(generate_consent(), indent=2, sort_keys=True) + "\n")
    print("Wrote public nonproduction vector:", output)
