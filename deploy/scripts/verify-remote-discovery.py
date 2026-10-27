#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Verify a downloaded Ramflux client discovery record without product binaries."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

DOMAIN = "ramflux.client_discovery.v1"
SCHEMA = "ramflux.well_known_client.v1"
CLOCK_SKEW_SECONDS = 300
PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
STRING_FIELDS = {
    "schema", "node_id", "node_public_key", "node_ca_cert_pem", "gateway_quic_addr",
    "gateway_tcp_addr", "gateway_server_name", "relay_quic_addr", "relay_server_name",
    "prekey_http_url", "signaling_turn_addr", "signature",
}
LIST_FIELDS = {"protocol_versions", "client_capabilities"}
INTEGER_FIELDS = {"updated_at", "expires_at"}
EXPECTED_FIELDS = STRING_FIELDS | LIST_FIELDS | INTEGER_FIELDS


def fail(message):
    raise SystemExit(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail(f"discovery JSON contains duplicate field {key}")
        value[key] = item
    return value


def decode_base64url(value, label, expected_size):
    if not isinstance(value, str) or not value or "=" in value:
        fail(f"discovery {label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        fail(f"discovery {label} is not valid base64url")
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != value or len(decoded) != expected_size:
        fail(f"discovery {label} has an invalid encoding or length")
    return decoded


def canonical_signing_bytes(record):
    unsigned = dict(record)
    unsigned.pop("signature", None)
    wrapped = {"domain": DOMAIN, "record": unsigned}
    return json.dumps(
        wrapped, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def verify(record_path, expected_key, now=None):
    version = subprocess.run(
        ["openssl", "version"], capture_output=True, text=True, check=False
    )
    if version.returncode != 0 or not version.stdout.startswith("OpenSSL 3."):
        fail("openssl lacks Ed25519 — install OpenSSL 3 or use demo-node-tool")
    try:
        record = json.loads(
            Path(record_path).read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read discovery record: {error}")
    if not isinstance(record, dict) or set(record) != EXPECTED_FIELDS:
        fail("discovery record has missing or unknown fields")
    if record.get("schema") != SCHEMA:
        fail("discovery record has an unsupported schema")
    if any(not isinstance(record[field], str) for field in STRING_FIELDS):
        fail("discovery record contains a non-string endpoint or identity field")
    if any(
        not isinstance(record[field], list)
        or any(not isinstance(item, str) for item in record[field])
        for field in LIST_FIELDS
    ):
        fail("discovery record contains an invalid capability list")
    if not isinstance(record.get("node_ca_cert_pem"), str) or not record["node_ca_cert_pem"].strip():
        fail("discovery record has no node CA certificate")
    if record.get("node_public_key") != expected_key:
        fail("discovery public key does not match operator pin")
    updated_at = record.get("updated_at")
    expires_at = record.get("expires_at")
    if not isinstance(updated_at, int) or isinstance(updated_at, bool) or updated_at < 0:
        fail("discovery updated_at is not an integer")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at < 0:
        fail("discovery expires_at is not an integer")
    timestamp = int(time.time()) if now is None else now
    if expires_at + CLOCK_SKEW_SECONDS < timestamp:
        fail("discovery record is expired")
    if updated_at > timestamp + CLOCK_SKEW_SECONDS:
        fail("discovery record is from the future")

    public_key = decode_base64url(record["node_public_key"], "public key", 32)
    signature = decode_base64url(record.get("signature"), "signature", 64)
    with tempfile.TemporaryDirectory(prefix="ramflux-discovery-") as directory:
        root = Path(directory)
        (root / "public.der").write_bytes(PUBLIC_KEY_DER_PREFIX + public_key)
        (root / "signature.bin").write_bytes(signature)
        (root / "signed.json").write_bytes(canonical_signing_bytes(record))
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                "-keyform", "DER", "-inkey", str(root / "public.der"),
                "-sigfile", str(root / "signature.bin"), "-in", str(root / "signed.json"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if result.returncode != 0:
        fail("discovery signature verification failed")
    node_id = record.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        fail("discovery record has no node id")
    print(f"discovery signature, freshness and operator pin: healthy ({node_id})")
    print(f"node public key: {expected_key}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        fail("usage: verify-remote-discovery.py RECORD EXPECTED_PUBLIC_KEY")
    verify(sys.argv[1], sys.argv[2])
