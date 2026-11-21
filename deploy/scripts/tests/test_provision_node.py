#!/usr/bin/env python3
"""Generator coverage for gateway client capabilities and product demo trust."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
PROVISION = SCRIPTS / "provision-node.sh"
TRUST = SCRIPTS / "demo-node-trust.py"


class ProvisionNodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-provision-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ)
        self.env["RAMFLUX_DEPLOY_DIR"] = str(self.root)

    def provision(self, capabilities=None, check=False):
        env = dict(self.env)
        if capabilities is None:
            env.pop("DEMO_GATEWAY_CLIENT_CAPABILITIES", None)
        else:
            env["DEMO_GATEWAY_CLIENT_CAPABILITIES"] = capabilities
        args = ["sh", str(PROVISION)]
        if check:
            args.append("--check")
        return subprocess.run(args, env=env, text=True, capture_output=True, check=False)

    def toml(self, service):
        return (self.root / "config" / f"{service}.toml").read_text()

    def test_default_capabilities_are_emitted_for_router_and_federation_only(self):
        result = self.provision()
        self.assertEqual(result.returncode, 0, result.stderr)
        for service in ("router", "federation"):
            text = self.toml(service)
            self.assertIn("gateway_client_capabilities = [", text)
            self.assertLess(text.index('"gateway.session_push.v1"'), text.index('"gateway.ephemeral.v1"'))
        for service in ("gateway", "notify", "relay", "signaling", "retention"):
            self.assertNotIn("gateway_client_capabilities", self.toml(service))

    def test_input_order_is_normalized_and_session_push_alone_is_kept(self):
        result = self.provision("gateway.ephemeral.v1, gateway.session_push.v1")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.toml("router")
        self.assertLess(text.index('"gateway.session_push.v1"'), text.index('"gateway.ephemeral.v1"'))
        alone = self.provision("gateway.session_push.v1")
        self.assertEqual(alone.returncode, 0, alone.stderr)
        text = self.toml("federation")
        self.assertIn('"gateway.session_push.v1"', text)
        self.assertNotIn("gateway.ephemeral.v1", text)

    def test_unknown_empty_and_ephemeral_only_write_nothing(self):
        for value in ("gateway.session_push.v1,not-a-capability", "", "gateway.ephemeral.v1", ","):
            with self.subTest(value=value):
                result = self.provision(value)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("DEMO_GATEWAY_CLIENT_CAPABILITIES", result.stderr)
                self.assertFalse((self.root / "config").exists())
                checked = self.provision(value, check=True)
                self.assertNotEqual(checked.returncode, 0)
                self.assertFalse((self.root / "config").exists())


class DemoNodeTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-demo-trust-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "data"
        self.state.mkdir()

    def init(self, node_id="demo.invalid"):
        return subprocess.run(
            ["python3", str(TRUST), "init", str(self.state), node_id],
            text=True, capture_output=True, check=False,
        )

    def test_init_is_stable_and_pins_the_mounted_discovery_seed(self):
        self.assertTrue(shutil.which("openssl"), "openssl is required")
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        first = self.init()
        self.assertEqual(first.returncode, 0, first.stderr)
        identity = (self.state / "identity.env").read_bytes()
        key = (self.state / "certs/node-identity/node-signing.key").read_bytes()
        certificate = (self.state / "secrets/gateway-v3/issuer-cert.json").read_bytes()
        self.assertNotEqual(certificate.strip(), b"{}")
        second = self.init()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((self.state / "identity.env").read_bytes(), identity)
        self.assertEqual((self.state / "certs/node-identity/node-signing.key").read_bytes(), key)
        self.assertEqual((self.state / "secrets/gateway-v3/issuer-cert.json").read_bytes(), certificate)
        values = dict(line.split("=", 1) for line in identity.decode().splitlines())
        self.assertTrue(values["DEMO_EXPECTED_NODE_PUBLIC_KEY"])
        self.assertTrue(values["RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY"])
        self.assertEqual(values["RAMFLUX_ROUTER_ADMIN_TOKEN"], values["RAMFLUX_FEDERATION_ADMIN_TOKEN"])
        self.assertEqual(self.state.joinpath("certs/node-identity/node-signing.key").stat().st_mode & 0o777, 0o640)
        refused = self.init("other.invalid")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("node id", refused.stderr)
        self.assertEqual((self.state / "identity.env").read_bytes(), identity)
        document = json.loads(certificate)
        self.assertEqual(document["gateway_instance_id"], "ramflux-gateway")
        self.assertEqual(document["node_id"], "demo.invalid")
        self.assertIsNone(document["revoked_at"])

    def reset_state(self):
        for child in list(self.state.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    def test_missing_metadata_refuses_each_existing_identity_asset(self):
        assets = (
            Path("identity.env"),
            Path("certs/node-identity/node-signing.key"),
            Path("secrets/gateway-v3/issuer-cert.json"),
            Path("secrets/federation/provider-keyring.json"),
            Path("secrets/federation/trust-snapshot.json"),
        )
        payload = b"existing-node-bytes\n"
        for relative in assets:
            with self.subTest(asset=str(relative)):
                self.reset_state()
                target = self.state / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                result = self.init()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "demo identity metadata is missing for an existing node",
                    result.stderr,
                )
                self.assertEqual(target.read_bytes(), payload)
                self.assertFalse((self.state / "secrets" / "demo-identity.json").exists())
                for other in assets:
                    if other != relative:
                        self.assertFalse((self.state / other).exists())

    def test_first_init_of_an_empty_node_generates_identity(self):
        self.assertTrue(shutil.which("openssl"), "openssl is required")
        self.assertFalse((self.state / "secrets" / "demo-identity.json").exists())
        result = self.init()
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads((self.state / "secrets" / "demo-identity.json").read_text())
        self.assertEqual(metadata["node_id"], "demo.invalid")
        for field in (
            "root_seed", "attestation_seed", "provider_seed", "offline_seed",
            "discovery_seed", "service_seed",
        ):
            self.assertTrue(metadata[field])
        self.assertTrue((self.state / "certs/node-identity/node-signing.key").is_file())
        self.assertEqual(
            (self.state / "certs/node-identity/node-signing.key").read_text().strip(),
            metadata["discovery_seed"],
        )
