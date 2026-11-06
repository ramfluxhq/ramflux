#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Independent AP1 agent-profile hash goldens. Never invokes the product or any BLAKE3 FFI.

Hash primitive: pure-Python BLAKE3 vendored at scripts/reference/username_directory/pure_blake3.py
(oconnor663/pure_python_blake3 pinned commit, sha256 in ../username_directory/crypto_sources.json).
Ed25519/HKDF: PyCA cryptography pinned in ../username_directory/requirements.txt.
Canonical JSON (sorted, compact, UTF-8) and every record/envelope object are written here,
not produced by the Rust serializer. Manifest: manifest.json in this directory.

Install: python3 -m venv VENV && VENV/bin/pip install --require-hashes -r ../username_directory/requirements.txt
Run: VENV/bin/python -I oracle.py
"""
import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "username_directory"))

from pure_blake3 import Hasher  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

NOW = 1_700_000_000
ANCHOR_TAG = "ramflux.identity.root_public_key.commitment.v1"
MASTER_CERT_TAG = "ramflux.identity.master_certificate.v1"
BRANCH_CERT_TAG = "ramflux.identity.branch_certificate.v1"
DEVICE_SET_TAG = "ramflux.identity.signed_device_set.v3"
OBJECT_HASH_TAG = "ramflux.identity.custody.object_hash.v1"
SECTION_HASH_TAG = "ramflux.identity.custody.section_hash.v1"
AGENT_PROFILE_TAG = "ramflux.agent.profile.v1"
AGENT_PROFILE_HASH_TAG = "ramflux.agent.profile.hash.v1"
SCOPES = ["branch_certify", "contact_consent", "delegate", "device_set", "profile"]

# Pinned values; the Rust goldens in crypto/src/agent_profile.rs must equal these.
EXPECTED = {
    "native_head": "WS9hoFDbwEmVP2IXEfYQm3KzyPq6-KXSR1iLSiNZvJo",
    "signature": "oQtBtYep0hY2BRjGzrXj4DhG_6ZeIjHOnEjpCTdGrR-NzTadps8E3UNhkYUeE1T8olJm6sm-KboL9PTl26-MBQ",
    "sidecar_digest": "W3juonkTVGcnBDxemcO8yCohbpW35OPOHZ5PVj27U5g",
}


def blake(data: bytes) -> bytes:
    hasher = Hasher()
    hasher.update(data)
    return hasher.finalize()


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def jcs(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def framed(tag: str, value) -> str:
    return b64(blake(tag.encode() + b"\0" + jcs(value)))


def object_hash(envelope) -> str:
    return framed(OBJECT_HASH_TAG, envelope)


def raw_public(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(key, tag: str, body) -> dict:
    return {"body": body, "signature": b64(key.sign(jcs({"domain": tag, "body": body})))}


def commitment(tag: str, raw: bytes) -> str:
    return b64(blake(tag.encode() + raw))


def identity(seed_byte: int, kind: str, custodian):
    """Mirror of ramflux-crypto genesis(seed, kind, custodian) with the test's fixed seeds."""
    entropy = bytes([seed_byte]) * 32
    master_seed = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=b"ramflux.identity.master.v1"
    ).derive(entropy)
    master = Ed25519PrivateKey.from_private_bytes(master_seed)
    primary = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte + 2]) * 32)
    branch = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte + 3]) * 32)
    agreement = X25519PrivateKey.from_private_bytes(bytes([seed_byte + 4]) * 32)
    anchor = commitment(ANCHOR_TAG, raw_public(master))
    local = {"account_anchor": anchor, "device_id": "primary", "device_epoch": 1}
    human = kind == "human"
    cert = sign(master, MASTER_CERT_TAG, {
        "schema": MASTER_CERT_TAG, "version": 1, "account_anchor": anchor,
        "principal_id": "vector.example", "principal_kind": kind,
        "master_public_key": b64(raw_public(master)),
        "self_signing_public_key": b64(raw_public(primary)),
        "primary_device_ref": local if human else custodian,
        "custody_kind": "local_human" if human else "external_human",
        "scopes": SCOPES, "range_index": 1, "issued_at": NOW,
        "cert_id": b64(bytes([5]) * 32), "legacy_binding_hash": None,
        "previous_certificate_hash": None,
    })
    signing = b64(raw_public(branch))
    agreement_public = b64(raw_public(agreement))
    branch_cert = sign(primary, BRANCH_CERT_TAG, {
        "schema": BRANCH_CERT_TAG, "version": 1, "account_anchor": anchor,
        "master_certificate_hash": object_hash(cert), "device_id": "primary",
        "device_epoch": 1, "principal_kind": kind, "branch_signing_public_key": signing,
        "agreement_identity_public_key": agreement_public,
        "capabilities": ["call", "group", "message", "register", "sync"],
        "not_before": NOW, "expires_at": NOW + 2_592_000, "cert_id": b64(bytes([6]) * 32),
    })
    sections = {
        "profile": {"kind": kind, "display_name": "Vector Human",
                    "custodian": None if human else custodian},
        "devices": [{"device_id": "primary", "device_epoch": 1,
                     "signing_key_commitment": commitment(
                         "ramflux.identity.device_signing_key.v1", raw_public(branch)),
                     "agreement_key_commitment": commitment(
                         "ramflux.identity.device_agreement_key.v1", raw_public(agreement)),
                     "status": "active", "revoked_at": None,
                     "branch_certificate": branch_cert, "migration_state": "native"}],
        "delegations": [], "revoked_delegation_ids": [], "migration": None,
        "revoked_device_checkpoint": None,
    }
    body = {
        "schema": DEVICE_SET_TAG, "version": 3, "principal_id": "vector.example",
        "account_anchor": anchor, "principal_kind": kind, "origin": "new",
        "custody_mode": "v3", "device_set_epoch": 4294967297, "previous_record_hash": None,
        "issued_at": NOW, "master_certificate": cert, "legacy_binding": None, **sections,
        "section_hashes": {name: framed(SECTION_HASH_TAG, {"section": name, "value": value})
                           for name, value in sections.items()},
    }
    record = sign(primary, DEVICE_SET_TAG, body)
    return {"anchor": anchor, "primary": primary, "record": record}


def main() -> int:
    # Primitive self-check against the published empty-input BLAKE3 vector.
    assert blake(b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    human = identity(0, "human", None)
    custodian = {"account_anchor": human["anchor"], "device_id": "primary", "device_epoch": 1}
    agent = identity(10, "headless_ai", custodian)
    native_head = object_hash(agent["record"])
    body = {
        "schema": AGENT_PROFILE_TAG, "version": 1,
        "agent_anchor": agent["anchor"], "agent_custody_hash": native_head,
        "custodian_anchor": human["anchor"], "custodian_primary": custodian,
        "kind": "headless_ai", "profile_epoch": 1, "responsibility": "Research",
        "provider": "local", "model": "model", "persona_version": 1,
        "persona_hash": b64(bytes([7]) * 32),
    }
    signed = sign(agent["primary"], AGENT_PROFILE_TAG, body)
    result = {
        "native_head": native_head,
        "signature": signed["signature"],
        "sidecar_digest": framed(AGENT_PROFILE_HASH_TAG, signed),
    }
    for name, value in result.items():
        if value != EXPECTED[name]:
            print(f"MISMATCH {name}: got {value} expected {EXPECTED[name]}", file=sys.stderr)
            return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
