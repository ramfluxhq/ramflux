#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Create the demo node's signing seeds and the signed trust files the services load.

The discovery pin is the public key of the seed mounted at
certs/node-identity/node-signing.key. Federation signs client discovery with that
seed. The issuer certificate, provider keyring, and trust snapshot are separate
Ed25519 documents signed with seeds that stay in the private data directory.
"""

import base64
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

GATEWAY_ISSUER_CERTIFICATE_SCHEMA = "ramflux.gateway_issuer_certificate.v3"
PROVIDER_KEYRING_SCHEMA = "ramflux.federation_provider_keyring.v1"
TRUST_SNAPSHOT_SCHEMA = "ramflux.federated_issuer_trust_snapshot.v3"
TRUST_ENVELOPE_SCHEMA = "ramflux.federated_issuer_trust_snapshot_envelope.v4"
GATEWAY_INSTANCE_ID = "ramflux-gateway"
CERT_ID = "demo-gateway-issuer-1"
ATTESTATION_KEY_ID = "demo-gateway-attestation-1"
NODE_ROOT_KEY_ID = "demo-node-root-1"
PROVIDER_KEY_ID = "demo-provider-1"
TRUST_LIFETIME_SECONDS = 365 * 24 * 60 * 60
RENEWAL_FLOOR_SECONDS = 3600
NOT_BEFORE_SKEW_SECONDS = 60
PRIVATE_KEY_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PUBLIC_KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")
NODE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")
# An existing node keeps these. A missing metadata file must not replace them.
IDENTITY_ASSETS = (
    Path("identity.env"),
    Path("certs/node-identity/node-signing.key"),
    Path("secrets/gateway-v3/issuer-cert.json"),
    Path("secrets/federation/provider-keyring.json"),
    Path("secrets/federation/trust-snapshot.json"),
)


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value, label):
    if not isinstance(value, str) or not value or "=" in value:
        fail(f"demo trust {label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        fail(f"demo trust {label} is not valid base64url")
    encoded = b64url(decoded)
    if encoded != value:
        fail(f"demo trust {label} is not canonical base64url")
    return decoded


def canonical_json(value):
    """RFC 8785 for the ASCII objects these trust documents contain."""
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _openssl(args, input_bytes=None):
    result = subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail("openssl Ed25519 operation failed")
    return result.stdout


def ed25519_public_key(seed):
    if len(seed) != 32:
        fail("demo trust seed must be 32 bytes")
    with tempfile.TemporaryDirectory(prefix="ramflux-demo-trust-") as directory:
        key = Path(directory) / "key.der"
        key.write_bytes(PRIVATE_KEY_PREFIX + seed)
        raw = _openssl(
            ["pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER"]
        )
    if not raw.startswith(PUBLIC_KEY_PREFIX) or len(raw) != len(PUBLIC_KEY_PREFIX) + 32:
        fail("openssl Ed25519 public key has an unexpected encoding")
    return raw[len(PUBLIC_KEY_PREFIX):]


def ed25519_sign(seed, message):
    if len(seed) != 32:
        fail("demo trust seed must be 32 bytes")
    with tempfile.TemporaryDirectory(prefix="ramflux-demo-trust-") as directory:
        root = Path(directory)
        (root / "key.der").write_bytes(PRIVATE_KEY_PREFIX + seed)
        (root / "message.bin").write_bytes(message)
        signature = _openssl(
            [
                "pkeyutl", "-sign", "-rawin",
                "-inkey", str(root / "key.der"), "-keyform", "DER",
                "-in", str(root / "message.bin"),
            ]
        )
    if len(signature) != 64:
        fail("openssl Ed25519 signature has an unexpected length")
    return signature


def ed25519_verify(public_key, message, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    with tempfile.TemporaryDirectory(prefix="ramflux-demo-trust-") as directory:
        root = Path(directory)
        (root / "public.der").write_bytes(PUBLIC_KEY_PREFIX + public_key)
        (root / "signature.bin").write_bytes(signature)
        (root / "message.bin").write_bytes(message)
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                "-inkey", str(root / "public.der"), "-keyform", "DER",
                "-sigfile", str(root / "signature.bin"),
                "-in", str(root / "message.bin"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    return result.returncode == 0


def sign_field(document, field, seed):
    unsigned = dict(document)
    unsigned[field] = ""
    signed = dict(document)
    signed[field] = b64url(ed25519_sign(seed, canonical_json(unsigned)))
    return signed


def verify_field(document, field, public_key, label):
    signature = b64url_decode(document[field], label)
    unsigned = dict(document)
    unsigned[field] = ""
    if not ed25519_verify(public_key, canonical_json(unsigned), signature):
        fail(f"demo trust signature check failed: {label}")


def atomic_write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_identity(path, node_id, now):
    if path.is_file():
        try:
            identity = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"cannot read demo identity: {error}")
        if not isinstance(identity, dict):
            fail("demo identity is not a JSON object")
        if identity.get("node_id") != node_id:
            fail("demo identity node id does not match DEMO_NODE_ID")
        expires_at = identity.get("expires_at")
        if not isinstance(expires_at, int) or expires_at <= now + RENEWAL_FLOOR_SECONDS:
            fail("demo identity expires within one hour; create a fresh data directory")
        return identity
    issued_at = max(0, now - NOT_BEFORE_SKEW_SECONDS)
    return {
        "node_id": node_id,
        "issued_at": issued_at,
        "expires_at": now + TRUST_LIFETIME_SECONDS,
        "root_seed": b64url(secrets.token_bytes(32)),
        "attestation_seed": b64url(secrets.token_bytes(32)),
        "provider_seed": b64url(secrets.token_bytes(32)),
        "offline_seed": b64url(secrets.token_bytes(32)),
        "discovery_seed": b64url(secrets.token_bytes(32)),
        "service_seed": b64url(secrets.token_bytes(32)),
        "admin_token": b64url(secrets.token_bytes(32)),
    }


def seed_of(identity, name):
    raw = b64url_decode(identity.get(name), name)
    if len(raw) != 32:
        fail(f"demo trust {name} must decode to 32 bytes")
    return raw


def build_trust(identity, node_id):
    root = seed_of(identity, "root_seed")
    attestation = seed_of(identity, "attestation_seed")
    provider = seed_of(identity, "provider_seed")
    offline = seed_of(identity, "offline_seed")
    discovery = seed_of(identity, "discovery_seed")
    issued_at = identity["issued_at"]
    expires_at = identity["expires_at"]
    if not isinstance(issued_at, int) or issued_at < 0 or issued_at >= expires_at:
        fail("demo identity validity window is invalid")
    root_public = ed25519_public_key(root)
    attestation_public = ed25519_public_key(attestation)
    provider_public = ed25519_public_key(provider)
    offline_public = ed25519_public_key(offline)
    discovery_public = ed25519_public_key(discovery)
    certificate = sign_field(
        {
            "schema": GATEWAY_ISSUER_CERTIFICATE_SCHEMA,
            "version": 3,
            "cert_id": CERT_ID,
            "node_id": node_id,
            "gateway_instance_id": GATEWAY_INSTANCE_ID,
            "attestation_public_key": b64url(attestation_public),
            "attestation_key_id": ATTESTATION_KEY_ID,
            "not_before": issued_at,
            "not_after": expires_at,
            "issued_at": issued_at,
            "node_root_signing_key_id": NODE_ROOT_KEY_ID,
            "node_root_signature": "",
            "revoked_at": None,
        },
        "node_root_signature",
        root,
    )
    keyring = sign_field(
        {
            "schema": PROVIDER_KEYRING_SCHEMA,
            "version": 1,
            "issuer_node_id": node_id,
            "keyring_epoch": 1,
            "keys": [
                {
                    "key_id": PROVIDER_KEY_ID,
                    "public_key": b64url(provider_public),
                    "not_before": issued_at,
                    "not_after": expires_at,
                    "retired_at": None,
                    "authorized_provider_epoch": 1,
                }
            ],
            "keyring_signature": "",
        },
        "keyring_signature",
        offline,
    )
    envelope = sign_field(
        {
            "schema": TRUST_ENVELOPE_SCHEMA,
            "version": 4,
            "snapshot": {
                "schema": TRUST_SNAPSHOT_SCHEMA,
                "version": 3,
                "node_id": node_id,
                "generation": 1,
                "pin_epoch": 1,
                "trust_status": "active",
                "roots": [
                    {
                        "node_id": node_id,
                        "key_id": NODE_ROOT_KEY_ID,
                        "public_key": b64url(root_public),
                        "not_before": issued_at,
                        "not_after": expires_at,
                        "pin_epoch": 1,
                        "retired_at": None,
                    }
                ],
                "revoked_cert_ids": [],
                "hard_stale_at": expires_at,
            },
            "provider_signing_key_id": PROVIDER_KEY_ID,
            "provider_public_key": b64url(provider_public),
            "provider_epoch": 1,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature": "",
        },
        "signature",
        provider,
    )
    verify_field(certificate, "node_root_signature", root_public, "issuer certificate")
    verify_field(keyring, "keyring_signature", offline_public, "provider keyring")
    verify_field(envelope, "signature", provider_public, "trust snapshot")
    identity_env = "".join(
        f"{key}={value}\n"
        for key, value in (
            ("RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL", identity["service_seed"]),
            ("RAMFLUX_GATEWAY_V3_ISSUER_SEED", identity["attestation_seed"]),
            ("RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY", b64url(offline_public)),
            (
                "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE",
                "/etc/ramflux/node-identity/node-signing.key",
            ),
            ("RAMFLUX_ROUTER_ADMIN_TOKEN", identity["admin_token"]),
            ("RAMFLUX_FEDERATION_ADMIN_TOKEN", identity["admin_token"]),
            ("DEMO_EXPECTED_NODE_PUBLIC_KEY", b64url(discovery_public)),
        )
    )
    return {
        "certificate": certificate,
        "keyring": keyring,
        "envelope": envelope,
        "identity_env": identity_env,
        "discovery_seed": b64url(discovery),
    }


def pretty(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def existing_identity_assets(state):
    return [asset for asset in IDENTITY_ASSETS if (state / asset).exists()]


def init(state, node_id):
    if not isinstance(node_id, str) or NODE_ID_PATTERN.fullmatch(node_id) is None:
        fail("invalid DEMO_NODE_ID")
    state = Path(state)
    if not state.is_dir():
        fail("demo data directory does not exist")
    now = int(time.time())
    identity_path = state / "secrets" / "demo-identity.json"
    # Fresh seeds are only for an empty node. Do not import or replace an
    # existing key, pin, or trust document when the metadata file is gone.
    if not identity_path.is_file() and existing_identity_assets(state):
        fail("demo identity metadata is missing for an existing node")
    identity = load_identity(identity_path, node_id, now)
    material = build_trust(identity, node_id)
    atomic_write(identity_path, pretty(identity), 0o600)
    atomic_write(
        state / "secrets" / "gateway-v3" / "issuer-cert.json",
        pretty(material["certificate"]),
        0o644,
    )
    atomic_write(
        state / "secrets" / "federation" / "provider-keyring.json",
        pretty(material["keyring"]),
        0o644,
    )
    atomic_write(
        state / "secrets" / "federation" / "trust-snapshot.json",
        pretty(material["envelope"]),
        0o644,
    )
    atomic_write(state / "identity.env", material["identity_env"].encode("ascii"), 0o600)
    atomic_write(
        state / "certs" / "node-identity" / "node-signing.key",
        material["discovery_seed"].encode("ascii"),
        0o640,
    )


def main():
    if len(sys.argv) != 4 or sys.argv[1] != "init":
        fail("usage: demo-node-trust.py init STATE NODE_ID")
    init(sys.argv[2], sys.argv[3])


if __name__ == "__main__":
    main()
