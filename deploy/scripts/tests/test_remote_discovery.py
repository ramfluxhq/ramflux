#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Exercise tool-free signed client discovery verification."""

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "verify-remote-discovery.py"
SPEC = importlib.util.spec_from_file_location("verify_remote_discovery", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class RemoteDiscoveryTests(unittest.TestCase):
    def test_libressl_reports_ed25519_tooling_gap(self):
        version = subprocess.CompletedProcess(
            ["openssl", "version"], 0, stdout="LibreSSL 3.3.6\n", stderr=""
        )
        with mock.patch.object(VERIFY.subprocess, "run", return_value=version):
            with self.assertRaisesRegex(
                SystemExit,
                "openssl lacks Ed25519 — install OpenSSL 3 or use demo-node-tool",
            ):
                VERIFY.verify(Path("unused"), "unused")

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_verifies_rust_signed_golden_record(self):
        fixture = Path(__file__).parent / "fixtures" / "rust-signed-discovery.json"
        record = json.loads(fixture.read_text())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            VERIFY.verify(fixture, record["node_public_key"], now=1500)
        self.assertIn("signature, freshness and operator pin: healthy", output.getvalue())

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_accepts_valid_ed25519_record_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory(prefix="ramflux-discovery-test-") as directory:
            root = Path(directory)
            private_key = root / "private.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key],
                check=True, capture_output=True,
            )
            public_der = subprocess.run(
                ["openssl", "pkey", "-in", private_key, "-pubout", "-outform", "DER"],
                check=True, capture_output=True,
            ).stdout
            public_key = base64.urlsafe_b64encode(public_der[-32:]).rstrip(b"=").decode()
            record = {
                "schema": VERIFY.SCHEMA,
                "node_id": "node.example.org",
                "node_public_key": public_key,
                "node_ca_cert_pem": "test CA",
                "gateway_quic_addr": "node.example.org:443",
                "gateway_tcp_addr": "node.example.org:443",
                "gateway_server_name": "ramflux-gateway",
                "relay_quic_addr": "node.example.org:17447",
                "relay_server_name": "ramflux-relay",
                "prekey_http_url": "https://node.example.org",
                "signaling_turn_addr": "node.example.org:3478",
                "protocol_versions": ["v1"],
                "client_capabilities": ["prekey"],
                "updated_at": 1000,
                "expires_at": 2000,
                "signature": "",
            }
            signed = root / "signed.json"
            signed.write_bytes(VERIFY.canonical_signing_bytes(record))
            signature = subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", private_key, "-in", signed],
                check=True, capture_output=True,
            ).stdout
            record["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
            record_path = root / "record.json"
            record_path.write_text(json.dumps(record))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                VERIFY.verify(record_path, public_key, now=1500)
            self.assertIn("signature, freshness and operator pin: healthy", output.getvalue())

            record["gateway_tcp_addr"] = "evil.example.org:443"
            record_path.write_text(json.dumps(record))
            with self.assertRaisesRegex(SystemExit, "signature verification failed"):
                VERIFY.verify(record_path, public_key, now=1500)


if __name__ == "__main__":
    unittest.main()
