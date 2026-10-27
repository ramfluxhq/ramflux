# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent public vector: cryptography 50.0.2, blake3 1.0.11, mnemonic 0.21.

Run with the packages above installed; all object strings are ASCII and all numbers
are safe integers, so sorted compact JSON is exactly JCS for this restricted vector.
No production keys or network operations are used. The BIP39 entropy transcription
is the standard all-zero 256-bit vector; PBKDF2 is deliberately never invoked.
"""
import argparse
import base64
import json
from pathlib import Path
import blake3
from mnemonic import Mnemonic
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def framed(tag, value):
    return b64(blake3.blake3(tag.encode() + b"\0" + jcs(value)).digest())


def object_hash(value):
    return framed("ramflux.identity.custody.object_hash.v1", value)


def sign(key, tag, body):
    return {"body": body, "signature": b64(key.sign(jcs({"domain": tag, "body": body})))}


def generate():
    entropy = bytes(32)
    phrase = Mnemonic("english").to_mnemonic(entropy)
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32),
                info=b"ramflux.identity.master.v1").derive(entropy)
    master = Ed25519PrivateKey.from_private_bytes(seed)
    primary = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
    branch = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
    agreement = X25519PrivateKey.from_private_bytes(bytes([4]) * 32)
    anchor = b64(blake3.blake3(b"ramflux.identity.root_public_key.commitment.v1" + public(master)).digest())
    reference = {"account_anchor": anchor, "device_id": "primary", "device_epoch": 1}
    cert = sign(master, "ramflux.identity.master_certificate.v1", {
        "schema": "ramflux.identity.master_certificate.v1", "version": 1,
        "account_anchor": anchor, "principal_id": "vector.example", "principal_kind": "human",
        "master_public_key": b64(public(master)), "self_signing_public_key": b64(public(primary)),
        "primary_device_ref": reference, "custody_kind": "local_human",
        "scopes": ["branch_certify", "contact_consent", "delegate", "device_set", "profile"],
        "range_index": 1, "issued_at": 1700000000, "cert_id": b64(bytes([5]) * 32),
        "legacy_binding_hash": None, "previous_certificate_hash": None,
    })
    branch_cert = sign(primary, "ramflux.identity.branch_certificate.v1", {
        "schema": "ramflux.identity.branch_certificate.v1", "version": 1,
        "account_anchor": anchor, "master_certificate_hash": object_hash(cert),
        "device_id": "primary", "device_epoch": 1, "principal_kind": "human",
        "branch_signing_public_key": b64(public(branch)), "agreement_identity_public_key": b64(public(agreement)),
        "capabilities": ["call", "group", "message", "register", "sync"],
        "not_before": 1700000000, "expires_at": 1702592000, "cert_id": b64(bytes([6]) * 32),
    })
    sections = {
        "profile": {"kind": "human", "display_name": "Vector Human", "custodian": None},
        "devices": [{"device_id": "primary", "device_epoch": 1,
            "signing_key_commitment": b64(blake3.blake3(b"ramflux.identity.device_signing_key.v1" + public(branch)).digest()),
            "agreement_key_commitment": b64(blake3.blake3(b"ramflux.identity.device_agreement_key.v1" + public(agreement)).digest()),
            "status": "active", "revoked_at": None, "branch_certificate": branch_cert, "migration_state": "native"}],
        "delegations": [], "revoked_delegation_ids": [], "migration": None, "revoked_device_checkpoint": None,
    }
    body = {"schema": "ramflux.identity.signed_device_set.v3", "version": 3,
        "principal_id": "vector.example", "account_anchor": anchor, "principal_kind": "human",
        "origin": "new", "custody_mode": "v3", "device_set_epoch": 4294967297,
        "previous_record_hash": None, "issued_at": 1700000000, "master_certificate": cert,
        "legacy_binding": None, **sections,
        "section_hashes": {name: framed("ramflux.identity.custody.section_hash.v1", {"section": name, "value": value})
                           for name, value in sections.items()},
    }
    record = sign(primary, "ramflux.identity.signed_device_set.v3", body)
    return {"profile": "ramflux-recovery-v1", "entropy_hex": entropy.hex(),
        "phrase": phrase, "master_seed_hex": seed.hex(),
        "self_signing_seed_hex": (bytes([2]) * 32).hex(), "branch_seed_hex": (bytes([3]) * 32).hex(),
        "agreement_seed_hex": (bytes([4]) * 32).hex(), "master_public_key": b64(public(master)),
        "account_anchor": anchor, "master_certificate_hash": object_hash(cert),
        "branch_certificate_hash": object_hash(branch_cert), "record_hash": object_hash(record),
        "record_signing_bytes_hex": jcs({"domain": "ramflux.identity.signed_device_set.v3", "body": body}).hex(),
        "record_canonical_hex": jcs(record).hex(), "record": record}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Write a public custody v3 test vector")
    parser.add_argument("output", type=Path, help="new output path; existing files are refused")
    output = parser.parse_args().output
    with output.open("x", encoding="utf-8") as target:
        target.write(json.dumps(generate(), indent=2, sort_keys=True) + "\n")
    print("Wrote public nonproduction vector:", output)
