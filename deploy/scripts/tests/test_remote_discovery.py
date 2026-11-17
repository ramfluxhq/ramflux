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
                "openssl lacks Ed25519 — install OpenSSL 3",
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
                "version": "0.2.0 (abcdef123456)",
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

    def test_refuses_a_record_without_a_node_version(self):
        fixture = Path(__file__).parent / "fixtures" / "rust-signed-discovery.json"
        record = json.loads(fixture.read_text())
        del record["version"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(SystemExit, "missing or unknown fields|openssl lacks"):
                VERIFY.verify(path, record["node_public_key"], now=1500)

    def write_deployment(
        self, state, capabilities, product_version, product_sha,
        image_tag="demo-v2", federation_capabilities=None,
    ):
        config = state / "config"
        config.mkdir(parents=True)
        router = self.capability_toml(capabilities)
        federation = self.capability_toml(
            capabilities if federation_capabilities is None else federation_capabilities
        )
        (config / "router.toml").write_text(router)
        (config / "federation.toml").write_text(federation)
        (state / "runtime.env").write_text(
            f"RAMFLUX_VERSION={image_tag}\n"
            f"RAMFLUX_EXPECTED_PRODUCT_VERSION={product_version}\n"
            f"RAMFLUX_EXPECTED_PRODUCT_SHA={product_sha}\n"
        )

    def capability_toml(self, capabilities):
        lines = ["gateway_client_capabilities = ["]
        lines.extend(f'  "{name}",' for name in capabilities)
        lines.append("]")
        return "\n".join(lines) + "\n"

    def sign_record(self, root, capabilities, version):
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
            "client_capabilities": capabilities,
            "version": version,
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
        return record_path, public_key

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_applied_deployment_accepts_gateway_names_and_rejects_mismatches(self):
        applied = ["gateway.session_push.v1", "gateway.ephemeral.v1"]
        product_version = "0.2.0"
        product_sha = "abcdef012345"
        signed = "0.2.0 (abcdef012345)"
        with tempfile.TemporaryDirectory(prefix="ramflux-discovery-deploy-") as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            self.write_deployment(state, applied, product_version, product_sha)
            runtime = (state / "runtime.env").read_text()
            self.assertIn("RAMFLUX_VERSION=demo-v2\n", runtime)
            self.assertNotIn(signed, runtime)
            advertised = [
                "opaque_delivery", "prekey", "object_relay", "device_pairing_v2", *applied,
            ]
            record_path, public_key = self.sign_record(root, advertised, signed)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                VERIFY.verify(record_path, public_key, now=1500, deploy_state=state)
            self.assertIn("signature, freshness and operator pin: healthy", output.getvalue())

            missing = root / "missing"
            missing.mkdir()
            missing_path, missing_key = self.sign_record(missing, ["prekey"], signed)
            with self.assertRaisesRegex(
                SystemExit, "discovery capabilities do not match the applied deployment"
            ):
                VERIFY.verify(missing_path, missing_key, now=1500, deploy_state=state)

            wrong_order = root / "order"
            wrong_order.mkdir()
            reversed_caps = [
                "opaque_delivery", "prekey", "object_relay",
                "gateway.ephemeral.v1", "gateway.session_push.v1",
            ]
            order_path, order_key = self.sign_record(wrong_order, reversed_caps, signed)
            with self.assertRaisesRegex(
                SystemExit, "discovery capabilities do not match the applied deployment"
            ):
                VERIFY.verify(order_path, order_key, now=1500, deploy_state=state)

            for wrong in ("demo-v2", "0.2.0 (0123456789ab)", "0.2.1 (abcdef012345)"):
                with self.subTest(wrong=wrong):
                    wrong_version = root / "version"
                    wrong_version.mkdir(exist_ok=True)
                    version_path, version_key = self.sign_record(wrong_version, advertised, wrong)
                    with self.assertRaisesRegex(
                        SystemExit, "discovery version does not match the applied deployment"
                    ):
                        VERIFY.verify(version_path, version_key, now=1500, deploy_state=state)

            unknown = root / "unknown"
            unknown.mkdir()
            self.write_deployment(unknown, applied, product_version, "unknown")
            unknown_path, unknown_key = self.sign_record(
                unknown, advertised, "0.2.0 (unknown)",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                VERIFY.verify(unknown_path, unknown_key, now=1500, deploy_state=unknown)

            self.write_deployment(
                root / "split",
                applied,
                product_version,
                product_sha,
                federation_capabilities=["gateway.session_push.v1"],
            )
            with self.assertRaisesRegex(
                SystemExit, "applied router and federation gateway capabilities disagree"
            ):
                VERIFY.verify(record_path, public_key, now=1500, deploy_state=root / "split")

            incomplete = root / "incomplete"
            incomplete.mkdir()
            (incomplete / "runtime.env").write_text("RAMFLUX_VERSION=demo-v2\n")
            with self.assertRaisesRegex(SystemExit, "applied deployment configuration is incomplete"):
                VERIFY.verify(record_path, public_key, now=1500, deploy_state=incomplete)

            malformed = root / "malformed"
            self.write_deployment(malformed, applied, "demo-v2", product_sha)
            with self.assertRaisesRegex(SystemExit, "applied deployment configuration is incomplete"):
                VERIFY.verify(record_path, public_key, now=1500, deploy_state=malformed)

            blank = root / "blank"
            blank.mkdir()
            (blank / "config").mkdir()
            (blank / "config" / "router.toml").write_text(
                'gateway_client_capabilities = [\n  "",\n]\n'
            )
            (blank / "config" / "federation.toml").write_text(
                'gateway_client_capabilities = [\n  "",\n]\n'
            )
            (blank / "runtime.env").write_text(
                "RAMFLUX_VERSION=demo-v2\n"
                "RAMFLUX_EXPECTED_PRODUCT_VERSION=0.2.0\n"
                "RAMFLUX_EXPECTED_PRODUCT_SHA=abcdef012345\n"
            )
            with self.assertRaisesRegex(
                SystemExit, "applied deployment has an empty gateway capability"
            ):
                VERIFY.verify(record_path, public_key, now=1500, deploy_state=blank)

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_rust_golden_capability_mismatch_is_a_signed_refusal(self):
        fixture = Path(__file__).parent / "fixtures" / "rust-signed-discovery.json"
        record = json.loads(fixture.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_deployment(
                state,
                ["gateway.session_push.v1", "gateway.ephemeral.v1"],
                "0.2.0",
                "abcdef123456",
            )
            with self.assertRaisesRegex(
                SystemExit, "discovery capabilities do not match the applied deployment"
            ):
                VERIFY.verify(fixture, record["node_public_key"], now=1500, deploy_state=state)


if __name__ == "__main__":
    unittest.main()
