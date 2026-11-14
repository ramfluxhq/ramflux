#!/usr/bin/env python3
"""Run the real deploy scripts to check public origin and immutable host settings."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / "demo-node-config.py"
SCRIPT = HELPER.with_name("demo-node.sh")
REPO = HELPER.parents[2]


class DemoPublicOriginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-demo-origin-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "data"
        self.state.mkdir()
        self.settings = {
            "DEMO_DATA_DIR": str(self.state), "DEMO_PROJECT": "demo-origin-test",
            "DEMO_HOST": "node.example.org", "DEMO_NODE_ID": "demo.invalid",
            "DEMO_GATEWAY_PORT": "59443", "DEMO_RELAY_PORT": "59447",
            "DEMO_HTTP_PORT": "59482", "DEMO_TURN_PORT": "59478",
            "DEMO_MESH_PORT": "59453", "DEMO_BIND_ADDR": "0.0.0.0",
            "DEMO_VERSION": "v1", "DEMO_PUBLIC_ORIGIN": "",
        }
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("DEMO_", "RAMFLUX_"))}

    def run_helper(self, action, settings=None, *args):
        return subprocess.run(
            [sys.executable, str(HELPER), str(REPO), str(self.state), action, *args],
            env={**self.env, **(self.settings if settings is None else settings)},
            text=True, capture_output=True, timeout=15, check=False,
        )

    def test_real_client_config_ip_and_dns_with_and_without_public_origin(self):
        for host in ("192.0.2.10", "node.example.org"):
            for origin in (None, "", "https://public.example.org", "https://public.example.org:8443"):
                with self.subTest(host=host, origin=origin):
                    settings = {**self.settings, "DEMO_HOST": host}
                    if origin is None:
                        del settings["DEMO_PUBLIC_ORIGIN"]
                    else:
                        settings["DEMO_PUBLIC_ORIGIN"] = origin
                    result = self.run_helper("client-runtime", settings)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    values = dict(line.split("=", 1) for line in result.stdout.splitlines())
                    self.assertEqual(values["RAMFLUX_CLIENT_PREKEY_HTTP_URL"],
                                     origin or f"http://{host}:59482")
                    self.assertEqual(values["RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR"], f"{host}:59443")
                    self.assertEqual(values["RAMFLUX_CLIENT_GATEWAY_TCP_ADDR"], f"{host}:59443")
                    self.assertEqual(values["RAMFLUX_CLIENT_RELAY_QUIC_ADDR"], f"{host}:59447")
                    self.assertEqual(values["RAMFLUX_CLIENT_SIGNALING_TURN_ADDR"], f"{host}:59478")
                    self.assertEqual(values["RAMFLUX_CLIENT_GATEWAY_SERVER_NAME"], "ramflux-gateway")
                    self.assertEqual(values["RAMFLUX_CLIENT_RELAY_SERVER_NAME"], "ramflux-relay")

    def test_invalid_origins_refuse_before_managed_state_writes(self):
        for origin in (
            "http://node.example.org", "https://node.example.org/",
            "https://node.example.org/path", "https://user:secret@node.example.org",
            "https://node.example.org?", "https://node.example.org#",
            "https://node.example.org?query=1", "https://node.example.org#fragment",
            "https://node.example.org:", "https://node.example.org:0",
            "https://node.example.org:65536", "https://node.example.org:bad",
            "https://", "node.example.org", " https://node.example.org",
            "https://node.example.org\n", "https://node.example.org\\other",
            "https://-node.example.org", "https://node..example.org",
            "https://node.example.org\t", "https://[broken",
        ):
            with self.subTest(origin=origin):
                settings = {**self.settings, "DEMO_PUBLIC_ORIGIN": origin}
                for action, args in (("client-runtime", ()), ("prepare", ("up",))):
                    result = self.run_helper(action, settings, *args)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("DEMO_PUBLIC_ORIGIN_INVALID:", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(self.state.iterdir()), [])

    def test_shell_entrypoint_uses_typed_refusal_before_deployment(self):
        env_file = self.root / "demo.env"
        settings = {**self.settings, "DEMO_PUBLIC_ORIGIN": "http://node.example.org"}
        env_file.write_text("".join(f"{key}={shlex.quote(value)}\n" for key, value in settings.items()))
        result = subprocess.run(["sh", str(SCRIPT), "up", str(env_file)],
                                env=self.env, capture_output=True, text=True, timeout=15, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DEMO_PUBLIC_ORIGIN_INVALID:", result.stderr)
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertFalse(Path(str(self.state) + ".lock").exists())

    def test_fresh_settings_are_recorded_and_cannot_be_changed_in_place(self):
        self.settings["DEMO_PUBLIC_ORIGIN"] = "https://node.example.org"
        result = self.run_helper("prepare", self.settings, "up")
        self.assertEqual(result.returncode, 0, result.stderr)
        pending = self.state / "owner.json.pending"
        owner = json.loads(pending.read_bytes())
        self.assertEqual(owner["settings"]["DEMO_PUBLIC_ORIGIN"], self.settings["DEMO_PUBLIC_ORIGIN"])
        self.assertEqual(owner["settings"]["DEMO_HOST"], self.settings["DEMO_HOST"])
        # Finish only the ownership publication needed for subsequent read-only validation.
        pending.rename(self.state / "owner.json")
        (self.state / "transaction.pending").unlink()
        before = {path.relative_to(self.state): path.read_bytes()
                  for path in self.state.rglob("*") if path.is_file()}
        for changed in ({"DEMO_HOST": "other.example.org"},
                        {"DEMO_PUBLIC_ORIGIN": "https://other.example.org"},
                        {"DEMO_PUBLIC_ORIGIN": ""}):
            for command in ("up", "upgrade", "rollback"):
                with self.subTest(changed=changed, command=command):
                    result = self.run_helper("validate", {**self.settings, **changed}, command)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("demo settings changed", result.stderr)
                    self.assertEqual(before, {path.relative_to(self.state): path.read_bytes()
                                              for path in self.state.rglob("*") if path.is_file()})

    def test_old_owner_has_no_implicit_origin_migration(self):
        old = {key: value for key, value in self.settings.items()
               if key not in ("DEMO_DATA_DIR", "DEMO_PUBLIC_ORIGIN")}
        marker = self.state / "owner.json"
        marker.write_text(json.dumps({"settings": old, "directory": str(self.state),
                                      "token": "old-owner"}))
        before = marker.read_bytes()
        for command in ("up", "upgrade", "rollback"):
            with self.subTest(command=command):
                result = self.run_helper("validate", self.settings, command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("demo settings changed", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(marker.read_bytes(), before)
                self.assertEqual(list(self.state.iterdir()), [marker])


if __name__ == "__main__":
    unittest.main()
