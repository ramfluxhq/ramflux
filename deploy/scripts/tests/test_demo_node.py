#!/usr/bin/env python3
"""Exercise demo lifecycle and ownership safety with a fake Docker executable."""
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import tempfile
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "demo-node.sh"


class DemoNodeTests(unittest.TestCase):
    PROVIDER = "docker"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-demo-shell-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.state = self.root / "data"
        self.control = self.root / "control.json"
        self.control.write_text("{}")
        self.journal = self.root / "commands.jsonl"
        (self.root / "provider.txt").write_text(self.PROVIDER)
        (self.root / "clock").write_text("0")
        fixture = SCRIPT.parent / "tests/fake_demo_runtime.py"
        for name in ("docker", "podman", "podman-compose", "date", "sleep"):
            wrapper = "#!/bin/sh\nexec " + " ".join(shlex.quote(str(part)) for part in (
                sys.executable, fixture, "--fixture-root", self.root, "--name", name,
            )) + ' "$@"\n'
            self.executable(name, wrapper)
        self.cargo_journal = self.root / "cargo.jsonl"
        self.executable(
            "cargo",
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "
            + shlex.quote(str(self.cargo_journal))
            + "\nexit 0\n",
        )
        self.executable("rustup", "#!/bin/sh\nexit 1\n")
        tool = '''#!/usr/bin/env python3
from pathlib import Path
import sys
if sys.argv[1] == "init":
    root = Path(sys.argv[2])
    for name in ("gateway-v3", "federation"):
        directory = root / "secrets" / name
        directory.mkdir(parents=True, exist_ok=True)
        files = ("issuer-cert.json",) if name == "gateway-v3" else ("provider-keyring.json", "trust-snapshot.json")
        for filename in files:
            (directory / filename).write_text("{}")
    identity = {
        "DEMO_EXPECTED_NODE_PUBLIC_KEY": "test-public-pin",
        "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY": "test-offline-root",
        "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL": "test-service-seed",
        "RAMFLUX_GATEWAY_V3_ISSUER_SEED": "test-issuer-seed",
        "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL": "test-discovery-seed",
        "RAMFLUX_ROUTER_ADMIN_TOKEN": "test-admin-token",
        "RAMFLUX_FEDERATION_ADMIN_TOKEN": "test-admin-token",
    }
    (root / "identity.env").write_text("".join(f"{key}={value}\\n" for key, value in identity.items()))
else:
    assert sys.argv[3] == "test-public-pin"
    import json
    control = json.loads((Path(__file__).parent.parent / "control.json").read_text())
    root = Path(__file__).parent.parent / "data"
    runtime = root / "runtime.env"
    values = dict(line.split("=", 1) for line in runtime.read_text().splitlines()
                  if "=" in line) if runtime.exists() else {}
    with (Path(__file__).parent.parent / "public-probes.jsonl").open("a") as output:
        output.write(json.dumps({"origin": sys.argv[2], "version": values.get("RAMFLUX_VERSION"),
                                 "compose": (root / "compose.yml").read_text()
                                 if (root / "compose.yml").exists() else ""}) + "\\n")
    if values.get("RAMFLUX_VERSION") in control.get("public_unhealthy_versions", []):
        sys.exit("published discovery endpoint unhealthy")
    if control.get("relay_quic_unhealthy"):
        sys.exit("relay QUIC unhealthy")
    print("mock discovery and QUIC verification")
    print("node key fingerprint: test-public-fingerprint")
    print("gateway pre-account health: healthy (quic=ok tcp=not_attempted session=requires_account)")
    print("relay QUIC TLS/application health: healthy (demo.example.org:59447)")
'''
        self.tool = self.executable("demo-node-tool", tool)
        self.env_file = self.root / "demo.env"
        values = dict(DEMO_HOST="demo.example.org", DEMO_PROJECT="demo-test",
                      DEMO_DATA_DIR=str(self.state), DEMO_TOOL=str(self.tool),
                      DEMO_HEALTH_TIMEOUT_SECONDS="3", DEMO_HEALTH_POLL_SECONDS="1")
        self.env_file.write_text("".join(f"{key}={shlex.quote(value)}\n" for key, value in values.items()))
        self.environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", HOME=str(self.home))

    def executable(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)
        return path

    def run_script(self, command, *flags, success=True, env_file=None):
        result = subprocess.run(["sh", str(SCRIPT), command, str(env_file or self.env_file), *flags],
                                env=self.environment, text=True, capture_output=True, check=False)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def commands(self):
        if not self.journal.exists():
            return []
        return [json.loads(line) for line in self.journal.read_text().splitlines()]

    def compose_commands(self):
        return [args for args in self.commands() if args[0] == "compose" and args != ["compose", "version"]]

    def enable_prebuilt_images(self):
        with self.env_file.open("a") as output:
            output.write("DEMO_PREBUILT_IMAGES=1\n")

    def test_default_up_builds_locally_and_uses_compose_build(self):
        self.run_script("up")
        self.assertTrue(self.cargo_journal.is_file())
        compose_up = next(args for args in self.compose_commands() if "up" in args)
        self.assertIn("--build", compose_up)
        self.assertNotIn("--no-build", compose_up)
        self.assertFalse(any(args[:2] == ["image", "inspect"] for args in self.commands()))

    def test_prebuilt_up_skips_local_build_after_all_images_are_verified(self):
        self.enable_prebuilt_images()
        self.run_script("up")
        self.assertFalse(self.cargo_journal.exists())
        expected = {
            f"ghcr.io/ramfluxhq/ramflux-{service}:demo-test"
            for service in ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")
        }
        inspected = {args[2] for args in self.commands() if args[:2] == ["image", "inspect"]}
        self.assertEqual(inspected, expected)
        compose_up = next(args for args in self.compose_commands() if "up" in args)
        self.assertIn("--no-build", compose_up)
        self.assertNotIn("--build", compose_up)

    def test_prebuilt_up_fails_closed_with_every_missing_image(self):
        self.enable_prebuilt_images()
        missing = [
            "ghcr.io/ramfluxhq/ramflux-gateway:demo-test",
            "ghcr.io/ramfluxhq/ramflux-retention:demo-test",
        ]
        self.control.write_text(json.dumps({"missing_images": missing}))
        result = self.run_script("up", success=False)
        for image in missing:
            self.assertIn(image, result.stderr)
        self.assertIn("missing demo images for version demo-test", result.stderr)
        self.assertFalse(self.cargo_journal.exists())
        self.assertFalse(any("up" in args for args in self.compose_commands()))

    def current_snapshot(self):
        owner = json.loads((self.state / "owner.json").read_text())
        return self.state / "version-snapshots" / owner["current_snapshot"]

    def managed_state(self):
        names = ("compose.yml", "compose.voice.yml", "compose.admin.yml", "runtime.env",
                 "owner.json", "owner.token", "demo-override.json", "deploy-tree.version",
                 "identity.env", ".env")
        names += tuple(f"config/{service}.toml" for service in (
            "gateway", "router", "notify", "federation", "relay", "signaling", "retention"
        ))
        return {name: (self.state / name).read_bytes() if (self.state / name).exists() else None
                for name in names}

    def test_requires_env_and_refuses_unowned_data(self):
        self.run_script("up", env_file=self.root / "missing.env", success=False)
        self.state.mkdir()
        (self.state / "unrelated.txt").write_text("preserve")
        self.run_script("up", success=False)
        self.assertEqual((self.state / "unrelated.txt").read_text(), "preserve")
        self.assertEqual(self.commands(), [])

    def test_invalid_public_connection_limit_refuses_before_state_or_runtime_changes(self):
        for value in ("", "0", "4097", "invalid", "${UNRESOLVED}", "999999999999999999999999999"):
            with self.subTest(value=value):
                with self.env_file.open("a") as output:
                    output.write(f"RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS={shlex.quote(value)}\n")
                result = self.run_script("up", success=False)
                self.assertIn("public max connections", result.stderr)
                self.assertFalse(self.state.exists())
                self.assertEqual(self.commands(), [])

    def seed_pre_split_state(self):
        self.run_script("up")
        # Existing ownership, identity and volumes use the same pre-split schemas.
        old = SCRIPT.parent / "tests/fixtures/demo-pre-split-compose.yml"
        (self.state / "compose.yml").write_bytes(old.read_bytes())
        (self.state / "compose.voice.yml").write_text("# previous shipped voice overlay\nservices: {}\n")
        runtime = self.state / "runtime.env"
        runtime.write_text(runtime.read_text().replace("RAMFLUX_FEDERATION_PUBLIC_PORT=", "RAMFLUX_FEDERATION_ADMIN_PORT="))

    def test_up_refreshes_pre_split_frozen_compose_without_changing_identity_or_ownership(self):
        self.seed_pre_split_state()
        original_owner = json.loads((self.state / "owner.json").read_text())
        preserved = {name: (self.state / name).read_bytes() for name in
                     ("identity.env", "owner.token", "certs/ca.pem")}
        result = self.run_script("up")
        self.assertIn("demo configuration refreshed: compose.yml, compose.voice.yml", result.stdout)
        for name, value in preserved.items():
            self.assertEqual((self.state / name).read_bytes(), value)
        owner = json.loads((self.state / "owner.json").read_text())
        self.assertEqual(owner["settings"], original_owner["settings"])
        self.assertEqual(owner["token"], original_owner["token"])
        deploy = SCRIPT.parent.parent
        self.assertEqual((self.state / "compose.yml").read_bytes(), (deploy / "docker-compose.yml").read_bytes())
        self.assertEqual((self.state / "compose.voice.yml").read_bytes(), (deploy / "docker-compose.voice.yml").read_bytes())
        runtime = (self.state / "runtime.env").read_text()
        self.assertIn("RAMFLUX_FEDERATION_PUBLIC_PORT=0.0.0.0:59482", runtime)
        self.assertNotIn("RAMFLUX_FEDERATION_ADMIN_PORT=", runtime)
        self.assertFalse(any("down" in command or "rm" in command for command in self.commands()))

    def test_explicit_upgrade_and_rollback_preserve_identity_and_frozen_settings(self):
        self.run_script("up")
        identity = {name: (self.state / name).read_bytes() for name in (
            "identity.env", "owner.token", "certs/ca.pem",
        )}
        original_owner = json.loads((self.state / "owner.json").read_text())
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")

        refused = self.run_script("up", success=False)
        self.assertIn("use upgrade for DEMO_VERSION only", refused.stderr)
        self.assertEqual(json.loads((self.state / "owner.json").read_text()), original_owner)

        upgraded = self.run_script("upgrade")
        self.assertIn("rollback command:", upgraded.stdout)
        self.assertIn(f"{SCRIPT} rollback {self.env_file}", upgraded.stdout)
        owner = json.loads((self.state / "owner.json").read_text())
        self.assertEqual(owner["settings"]["DEMO_VERSION"], "demo-v2")
        self.assertEqual(owner["version_history"], ["demo-test", "demo-v2"])
        self.assertIn("RAMFLUX_VERSION=demo-v2", (self.state / "runtime.env").read_text())
        for name, value in identity.items():
            self.assertEqual((self.state / name).read_bytes(), value)

        with self.env_file.open("a") as output:
            output.write("DEMO_HOST=changed.example.org\n")
        refused = self.run_script("upgrade", success=False)
        self.assertIn("changed beyond DEMO_VERSION", refused.stderr)
        self.env_file.write_text(self.env_file.read_text().replace(
            "DEMO_HOST=changed.example.org\n", ""))

        rolled_back = self.run_script("rollback")
        self.assertIn("rolled back demo images to version demo-test", rolled_back.stdout)
        owner = json.loads((self.state / "owner.json").read_text())
        self.assertEqual(owner["settings"]["DEMO_VERSION"], "demo-test")
        self.assertEqual(owner["version_history"], ["demo-test"])
        self.assertIn("RAMFLUX_VERSION=demo-test", (self.state / "runtime.env").read_text())
        self.assertEqual(self.compose_commands()[-1][-3:], ["up", "-d", "--no-build"])
        for name, value in identity.items():
            self.assertEqual((self.state / name).read_bytes(), value)
        self.assertIn("use upgrade for DEMO_VERSION only",
                      self.run_script("status", success=False).stderr)
        self.env_file.write_text(self.env_file.read_text().replace(
            "DEMO_VERSION=demo-v2\n", "DEMO_VERSION=demo-test\n"))
        self.run_script("status")

    def test_successful_up_creates_an_immutable_complete_snapshot(self):
        self.run_script("up")
        owner = json.loads((self.state / "owner.json").read_text())
        self.assertEqual(owner["version_history"], ["demo-test"])
        self.assertEqual(owner["snapshot_history"], [owner["current_snapshot"]])
        snapshot = self.current_snapshot()
        manifest = json.loads((snapshot / "manifest.json").read_text())
        self.assertTrue({
            "compose.yml", "runtime.env", "owner.json", "demo-override.json",
            "deploy-tree.version", "identity.env", "owner.token", ".env",
            *(f"config/{service}.toml" for service in (
                "gateway", "router", "notify", "federation", "relay", "signaling", "retention"
            )),
        }.issubset(manifest["files"]))
        for name in manifest["files"]:
            self.assertEqual((snapshot / name).read_bytes(), (self.state / name).read_bytes())
            self.assertEqual((snapshot / name).stat().st_mode & 0o222, 0)

    def test_rollback_restores_configs_and_target_overlay_selection(self):
        self.run_script("up")
        original_snapshot = self.current_snapshot()
        original_snapshot.chmod(0o700)
        snapshot_config = original_snapshot / "config/gateway.toml"
        snapshot_config.chmod(0o600)
        expected_config = snapshot_config.read_bytes() + b"# version-one-template\n"
        snapshot_config.write_bytes(expected_config)
        snapshot_config.chmod(0o400)
        original_snapshot.chmod(0o500)
        (self.state / "config/gateway.toml").write_bytes(expected_config)

        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        self.run_script("upgrade")
        self.assertNotEqual((self.state / "config/gateway.toml").read_bytes(), expected_config)
        self.run_script("up", "--voice-udp-port", "59449")
        self.assertTrue((self.state / "compose.voice.yml").is_file())

        self.run_script("rollback")
        self.assertEqual((self.state / "config/gateway.toml").read_bytes(), expected_config)
        self.assertFalse((self.state / "compose.voice.yml").exists())
        self.assertNotIn(str(self.state / "compose.voice.yml"), self.compose_commands()[-1])

    def test_rollback_restores_pre_split_snapshot_bytes_and_public_probe(self):
        self.run_script("up")
        snapshot = self.current_snapshot()
        snapshot.chmod(0o700)
        old_compose = (SCRIPT.parent / "tests/fixtures/demo-pre-split-compose.yml").read_bytes()
        old_runtime = (self.state / "runtime.env").read_bytes().replace(
            b"RAMFLUX_FEDERATION_PUBLIC_PORT=", b"RAMFLUX_FEDERATION_ADMIN_PORT=")
        replacements = {
            "compose.yml": old_compose,
            "runtime.env": old_runtime,
            "deploy-tree.version": b"pre-split-tree\n",
        }
        for name, content in replacements.items():
            path = snapshot / name
            path.chmod(0o600)
            path.write_bytes(content)
            path.chmod(0o400)
            (self.state / name).write_bytes(content)
        snapshot.chmod(0o500)
        expected = {name: (snapshot / name).read_bytes()
                    for name in json.loads((snapshot / "manifest.json").read_text())["files"]}

        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        self.run_script("upgrade")
        self.assertNotEqual((self.state / "compose.yml").read_bytes(), old_compose)
        self.run_script("rollback")
        for name, content in expected.items():
            self.assertEqual((self.state / name).read_bytes(), content, name)
        probes = [json.loads(line) for line in (self.root / "public-probes.jsonl").read_text().splitlines()]
        self.assertEqual(probes[-1]["origin"], "http://demo.example.org:59482")
        self.assertEqual(probes[-1]["version"], "demo-test")
        self.assertEqual(probes[-1]["compose"].encode(), old_compose)

    def test_upgrade_refuses_missing_recorded_overlays_before_writes(self):
        with self.env_file.open("a") as output:
            output.write("DEMO_ADMIN_LOOPBACK_PORT=59487\n")
        self.run_script("up", "--voice-udp-port", "59449")
        before = self.managed_state()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")

        missing_voice = self.run_script("upgrade", success=False)
        self.assertIn("RAMFLUX_DEMO_VOICE_UDP_PORT", missing_voice.stderr)
        self.assertNotIn("59449", missing_voice.stderr)
        self.assertEqual(self.managed_state(), before)
        self.assertFalse((self.state / "transaction.pending").exists())

        with self.env_file.open("a") as output:
            output.write("RAMFLUX_DEMO_VOICE_UDP_PORT=59449\n")
        self.env_file.write_text(self.env_file.read_text().replace(
            "DEMO_ADMIN_LOOPBACK_PORT=59487\n", ""))
        missing_admin = self.run_script("upgrade", success=False)
        self.assertIn("DEMO_ADMIN_LOOPBACK_PORT", missing_admin.stderr)
        self.assertNotIn("59487", missing_admin.stderr)
        self.assertEqual(self.managed_state(), before)
        self.assertFalse((self.state / "transaction.pending").exists())

    def test_pending_transaction_refuses_maintenance_until_explicit_recovery(self):
        self.run_script("up")
        initial = self.managed_state()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        self.control.write_text(json.dumps({"fail_up_versions": ["demo-v2"]}))
        self.run_script("upgrade", success=False)
        marker = self.state / "transaction.pending"
        pending = marker.read_bytes()
        identifier = json.loads(pending)["target_snapshot"]
        failed_state = self.managed_state()
        probes = self.root / "public-probes.jsonl"
        old_probes = probes.read_bytes()
        # No file, engine or public-probe mutation is permitted on any refused command.
        for command, flags in (("status", ()), ("status", ("--remote",)),
                               ("down", ()), ("down", ("--purge",)), ("logs", ()),
                               ("up", ()), ("upgrade", ())):
            with self.subTest(command=command, flags=flags):
                self.journal.write_text("")
                refused = self.run_script(command, *flags, success=False)
                self.assertEqual(refused.returncode, 3)
                self.assertEqual(refused.stdout, "")
                self.assertEqual(refused.stderr, f"pending upgrade transaction {identifier}: "
                                 "run `demo-node.sh recover` (or `rollback`)\n")
                self.assertEqual(marker.read_bytes(), pending)
                self.assertEqual(self.managed_state(), failed_state)
                self.assertEqual(probes.read_bytes(), old_probes)
                self.assertEqual(self.commands(), [])
                self.assertFalse(Path(str(self.state) + ".lock").exists())

        self.control.write_text("{}")
        recovered = self.run_script("recover")
        self.assertIn("recovered demo version demo-test", recovered.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual(self.managed_state(), initial)
        self.assertEqual(self.compose_commands()[-1][-3:], ["up", "-d", "--no-build"])
        self.assertEqual(len(probes.read_text().splitlines()), len(old_probes.splitlines()) + 1)
        self.assertEqual(json.loads(probes.read_text().splitlines()[-1])["version"], "demo-test")

    def test_recovery_retains_marker_until_public_probes_succeed(self):
        self.run_script("up")
        initial = self.managed_state()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        self.control.write_text(json.dumps({"public_unhealthy_versions": ["demo-v2"]}))
        failed = self.run_script("upgrade", success=False)
        self.assertIn("published discovery endpoint unhealthy", failed.stderr)
        marker = self.state / "transaction.pending"
        pending = marker.read_bytes()
        self.control.write_text(json.dumps({"public_unhealthy_versions": ["demo-test"]}))
        failed_recovery = self.run_script("recover", success=False)
        self.assertIn("published discovery endpoint unhealthy", failed_recovery.stderr)
        self.assertEqual(marker.read_bytes(), pending)
        self.assertEqual(self.managed_state(), initial)
        self.assertEqual(self.compose_commands()[-1][-3:], ["up", "-d", "--no-build"])
        # With a marker, rollback retries last-good recovery, rather than another version step.
        self.control.write_text("{}")
        self.run_script("rollback")
        self.assertFalse(marker.exists())
        self.assertEqual(self.managed_state(), initial)
        self.assertEqual(self.compose_commands()[-1][-3:], ["up", "-d", "--no-build"])

    def test_missing_snapshot_recovery_refuses_manual_path_without_locking_commands(self):
        self.run_script("up")
        previous_snapshot = self.current_snapshot()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        old_image = "ghcr.io/ramfluxhq/ramflux-gateway:demo-test"
        self.control.write_text(json.dumps({
            "fail_up_versions": ["demo-v2"], "missing_images": [old_image],
        }))
        failed = self.run_script("upgrade", success=False)
        self.assertTrue((self.state / "transaction.pending").is_file())
        self.assertFalse(Path(str(self.state) + ".lock").exists())

        (previous_snapshot / "manifest.json").unlink()
        refused = self.run_script("recover", success=False)
        self.assertIn("manual recovery required: restore the complete demo data directory", refused.stderr)
        self.assertTrue((self.state / "transaction.pending").is_file())
        self.assertFalse(Path(str(self.state) + ".lock").exists())
        refused_down = self.run_script("down", success=False)
        self.assertIn("run `demo-node.sh recover`", refused_down.stderr)
        self.assertFalse(Path(str(self.state) + ".lock").exists())

    def test_recover_restores_config_after_interrupted_rewrite(self):
        self.run_script("up")
        config = self.state / "config/gateway.toml"
        expected = config.read_bytes()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        helper_environment = dict(self.environment, DEMO_PROJECT="demo-test",
                                  DEMO_HOST="demo.example.org", DEMO_NODE_ID="demo.invalid",
                                  DEMO_GATEWAY_PORT="59443", DEMO_RELAY_PORT="59447",
                                  DEMO_HTTP_PORT="59482", DEMO_TURN_PORT="59478",
                                  DEMO_MESH_PORT="59453", DEMO_BIND_ADDR="0.0.0.0",
                                  DEMO_VERSION="demo-v2")
        helper = SCRIPT.parent / "demo-node-config.py"
        prepared = subprocess.run([
            sys.executable, str(helper), str(SCRIPT.parents[2]), str(self.state),
            "prepare", "upgrade",
        ], env=helper_environment, text=True, capture_output=True, check=False)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        self.assertTrue((self.state / "transaction.pending").is_file())

        config.write_bytes(b"node_id = \"")
        recovered = self.run_script("recover")
        self.assertIn("recovered demo version demo-test", recovered.stdout)
        self.assertEqual(config.read_bytes(), expected)
        self.assertFalse((self.state / "transaction.pending").exists())

    def test_prebuilt_upgrade_requires_all_seven_versioned_images(self):
        self.run_script("up")
        owner = (self.state / "owner.json").read_bytes()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\nDEMO_PREBUILT_IMAGES=1\n")
        missing = "ghcr.io/ramfluxhq/ramflux-retention:demo-v2"
        self.control.write_text(json.dumps({"missing_images": [missing]}))
        self.journal.write_text("")
        result = self.run_script("upgrade", success=False)
        self.assertIn(missing, result.stderr)
        self.assertEqual((self.state / "owner.json").read_bytes(), owner)
        self.assertFalse(any("up" in args for args in self.compose_commands()))

        self.assertFalse((self.state / "transaction.pending").exists())
        self.control.write_text("{}")
        self.journal.write_text("")
        result = self.run_script("upgrade")
        self.assertIn("rollback command:", result.stdout)
        inspect_images = [args[2] for args in self.commands() if args[:2] == ["image", "inspect"]]
        self.assertEqual(len(inspect_images), 7)
        self.assertEqual(self.compose_commands()[-1][-3:], ["up", "-d", "--no-build"])

    def test_prebuilt_images_require_distinct_ids_and_matching_binaries_before_writes(self):
        services = ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")
        with self.env_file.open("a") as output:
            output.write("DEMO_PREBUILT_IMAGES=1\n")
        self.control.write_text(json.dumps({"image_ids": {service: "sha256:one" for service in services}}))
        refused = self.run_script("up", success=False)
        self.assertIn("demo images share an image ID", refused.stderr)
        for service in services:
            self.assertIn(service, refused.stderr)
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(self.compose_commands(), [])

        self.control.write_text("{}")
        self.run_script("up")
        initial = self.managed_state()
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\n")
        self.control.write_text(json.dumps({"image_bins": {"router": "ramflux-gateway"}}))
        self.journal.write_text("")
        refused = self.run_script("upgrade", success=False)
        self.assertIn("invalid demo image identity or RAMFLUX_BIN: router", refused.stderr)
        self.assertEqual(self.managed_state(), initial)
        self.assertFalse((self.state / "transaction.pending").exists())
        self.assertEqual(self.compose_commands(), [])
        self.control.write_text("{}")
        self.run_script("upgrade")
        self.assertEqual(self.compose_commands()[-1][-3:], ["up", "-d", "--no-build"])

    def test_rollback_and_recover_verify_target_image_identity_before_restoring(self):
        self.run_script("up")
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v2\nDEMO_PREBUILT_IMAGES=1\n")
        self.run_script("upgrade")
        initial = self.managed_state()
        self.control.write_text(json.dumps({"image_bins": {"retention": "ramflux-router"}}))
        self.journal.write_text("")
        self.run_script("rollback", success=False)
        self.assertEqual(self.managed_state(), initial)
        self.assertFalse((self.state / "transaction.pending").exists())
        self.assertEqual(self.compose_commands(), [])
        with self.env_file.open("a") as output:
            output.write("DEMO_VERSION=demo-v3\n")
        self.control.write_text(json.dumps({"fail_up_versions": ["demo-v3"]}))
        self.run_script("upgrade", success=False)
        failed_state = self.managed_state()
        pending = (self.state / "transaction.pending").read_bytes()
        self.control.write_text(json.dumps({"image_bins": {"retention": "ramflux-router"}}))
        self.journal.write_text("")
        self.run_script("recover", success=False)
        self.assertEqual(self.managed_state(), failed_state)
        self.assertEqual((self.state / "transaction.pending").read_bytes(), pending)
        self.assertEqual(self.compose_commands(), [])
        self.control.write_text("{}")
        self.run_script("recover")
        self.assertEqual(self.managed_state(), initial)
        self.assertFalse((self.state / "transaction.pending").exists())

    def test_admin_opt_in_uses_saved_overlay_and_refuses_conflicting_ports(self):
        with self.env_file.open("a") as output:
            output.write("DEMO_ADMIN_LOOPBACK_PORT=59487\n")
        self.run_script("up")
        calls = [json.loads(line) for line in (self.root / "cli.jsonl").read_text().splitlines()]
        up = next(call for call in calls if "up" in call["args"])
        self.assertIn(str(self.state / "compose.admin.yml"), up["args"])
        self.assertIn("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT=59487", (self.state / "runtime.env").read_text())
        with self.env_file.open("a") as output:
            output.write("DEMO_ADMIN_LOOPBACK_PORT=59482\n")
        self.assertIn("admin loopback port conflicts", self.run_script("up", success=False).stderr)

    def test_repeat_up_preserves_ca_and_named_volumes_until_explicit_purge(self):
        self.state.mkdir(mode=0o755)
        result = self.run_script("up")
        self.assertIn("demo URL: http://demo.example.org:59482", result.stdout)
        self.assertIn("all seven demo services are healthy", result.stdout)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        environment = (self.state / "runtime.env").read_text()
        self.assertIn("RAMFLUX_FEDERATION_PUBLIC_PORT=0.0.0.0:59482", environment)
        self.assertNotIn("RAMFLUX_FEDERATION_ADMIN_PORT=", environment)
        for advertised in ("59443", "59447", "59482", "59478", "59453"):
            self.assertIn(advertised, environment)
        calls = [json.loads(line) for line in (self.root / "cli.jsonl").read_text().splitlines()]
        compose_up = next(call for call in calls if "up" in call["args"])
        expected = "docker" if self.PROVIDER == "docker" else "podman-compose"
        self.assertEqual(compose_up["name"], expected)
        self.assertEqual(compose_up["cwd"], str(self.state))
        self.assertEqual(compose_up["args"][-3:], ["up", "-d", "--build"])
        ca = (self.state / "certs/ca.pem").read_bytes()
        owner = (self.state / "owner.token").read_text()
        self.run_script("up")
        self.assertEqual((self.state / "certs/ca.pem").read_bytes(), ca)
        self.assertEqual((self.state / "owner.token").read_text(), owner)
        self.run_script("status")
        self.run_script("logs")
        self.run_script("down")
        self.assertTrue((self.state / "identity.env").exists())
        down = [args for args in self.commands() if "down" in args]
        self.assertNotIn("--volumes", down[-1])
        self.run_script("down", "--purge")
        self.assertFalse(self.state.exists())
        down = [args for args in self.commands() if "down" in args]
        self.assertIn("--volumes", down[-1])
        self.assertFalse(any("prune" in args or "--rmi" in args for args in self.commands()))

    def test_runtime_env_supplies_production_relay_required_keys_and_mounted_paths(self):
        self.run_script("up")
        runtime = dict(line.split("=", 1) for line in (self.state / "runtime.env").read_text().splitlines())
        relay_sources = SCRIPT.parents[2] / "apps/ramflux-relay/src"
        config = (relay_sources / "config.rs").read_text()
        trust = (relay_sources / "trust_keyring.rs").read_text()
        # Follow the production validation inputs, so a new required lookup adds a test obligation.
        function = re.search(r"fn relay_keyring_provider_config\(\)[^{]+\{(.*?)^\}", trust, re.S | re.M)
        self.assertIsNotNone(function, "production provider validation function must be discoverable")
        inputs = re.findall(r"non_empty_env\((\w+)\)", function.group(1))
        self.assertTrue(inputs, "must derive required environment inputs from production validation")
        constants = dict(re.findall(r'const\s+(\w+):\s*&str\s*=\s*"(RAMFLUX_[A-Z0-9_]+)"', config + trust))
        for constant in inputs:
            self.assertIn(constant, constants, f"unresolved relay validation input: {constant}")
            key = constants[constant]
            self.assertIn(key, runtime, f"runtime.env missing production-required {key}")
            self.assertTrue(runtime[key].strip(), f"empty required {key}")
            self.assertNotIn("${", runtime[key], f"unresolved required {key}")
        self.assertEqual(runtime["RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE"],
                         "/etc/ramflux/federation/provider-keyring.json")
        self.assertEqual(runtime["RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE"],
                         "/var/lib/ramflux/relay/trust-snapshot.json")
        compose = (self.state / "compose.yml").read_text()
        relay = re.search(r"^  ramflux-relay:\n(.*?)(?=^  [a-z]|\Z)", compose, re.S | re.M).group(1)
        self.assertIn("- ./secrets/federation:/etc/ramflux/federation:ro", relay)
        self.assertIn("- relay-redb:/var/lib/ramflux/relay", relay)
        self.assertTrue((self.state / "secrets/federation/provider-keyring.json").is_file())
        self.assertTrue((self.state / "secrets/federation/trust-snapshot.json").is_file())
        # A repeated up must not delete the relay-owned anti-rollback cache volume.
        self.run_script("up")
        self.assertFalse(any("down" in args or "--volumes" in args for args in self.compose_commands()))

    def test_status_reports_relay_quic_health_and_propagates_probe_failure(self):
        self.run_script("up")
        result = self.run_script("status")
        self.assertIn("relay QUIC TLS/application health: healthy", result.stdout)
        self.assertIn("node key fingerprint: test-public-fingerprint", result.stdout)
        self.assertIn("gateway pre-account health: healthy", result.stdout)
        self.control.write_text('{"relay_quic_unhealthy": true}')
        result = self.run_script("status", success=False)
        self.assertIn("relay QUIC unhealthy", result.stderr)

    def test_refuses_foreign_containers_volumes_and_networks_even_on_purge(self):
        self.run_script("up")
        for kind in ("container", "volume", "network"):
            with self.subTest(kind=kind):
                self.control.write_text(json.dumps({"foreign": kind}))
                self.journal.write_text("")
                result = self.run_script("down", "--purge", success=False)
                self.assertIn("refusing foreign", result.stderr)
                self.assertTrue(self.state.exists())
                self.assertFalse(self.compose_commands())

    def test_refuses_unlabeled_volume_and_network_name_collisions(self):
        self.run_script("up")
        for kind in ("volume", "network"):
            with self.subTest(kind=kind):
                self.control.write_text(json.dumps({"unlabeled": kind}))
                self.journal.write_text("")
                refused = self.run_script("up", success=False)
                self.assertIn(f"refusing foreign {kind}", refused.stderr)
                self.assertFalse(self.compose_commands())
                self.control.write_text("{}")
                self.run_script("recover")

    def test_status_fails_for_stopped_or_unhealthy_services(self):
        self.run_script("up")
        self.control.write_text('{"stopped": true}')
        self.run_script("status", success=False)
        self.control.write_text('{"health": "unhealthy"}')
        self.run_script("status", success=False)

    def test_refuses_settings_change_and_concurrent_operation(self):
        self.run_script("up")
        with self.env_file.open("a") as output:
            output.write("DEMO_HOST=changed.example.org\n")
        self.journal.write_text("")
        self.run_script("down", "--purge", success=False)
        self.assertTrue(self.state.exists())
        self.assertEqual(self.commands(), [])
        lock = Path(f"{self.state}.lock")
        lock.mkdir()
        self.run_script("up", success=False)
        self.assertTrue(lock.exists())

    def test_remote_verification_requires_public_pin_and_needs_no_docker_or_state(self):
        self.run_script("status", "--remote", success=False)
        with self.env_file.open("a") as output:
            output.write("DEMO_EXPECTED_NODE_PUBLIC_KEY=test-public-pin\n")
        self.run_script("status", "--remote")
        self.assertFalse(self.state.exists())
        self.assertEqual(self.commands(), [])

    def test_health_wait_retries_starting_services_until_healthy(self):
        self.control.write_text('{"healthy_after": 2}')
        result = self.run_script("up")
        self.assertIn("waiting for demo health", result.stdout)
        sleeps = [args for args in self.commands() if args[0] == "1"]
        self.assertEqual(len(sleeps), 2)
        self.assertIn("all seven demo services are healthy", result.stdout)
        inspected = [args[-1] for args in self.commands() if args[0] == "inspect" and "--format" not in args]
        for service in ("gateway", "router", "notify", "federation", "relay", "signaling", "retention"):
            self.assertIn(f"id-ramflux-{service}", inspected)

    def test_health_wait_timeout_keeps_project_and_prints_diagnostics(self):
        self.control.write_text('{"health": "starting"}')
        result = self.run_script("up", success=False)
        self.assertIn("health wait failed", result.stderr)
        self.assertIn("mock project logs", result.stderr)
        self.assertEqual((self.root / "clock").read_text(), "3")
        self.assertTrue((self.state / "identity.env").exists())
        self.assertFalse(any("down" in args for args in self.compose_commands()))
        self.assertNotIn("demo URL:", result.stdout)

    def test_health_wait_fails_immediately_on_stopped_unhealthy_or_unchecked_services(self):
        for scenario in ({"container_state": "exited"}, {"health": "unhealthy"}, {"missing_health": True}, {"duplicate": True}):
            with self.subTest(scenario=scenario):
                fixture = self.__class__("test_requires_env_and_refuses_unowned_data")
                self.addCleanup(fixture.doCleanups)
                fixture.setUp()
                fixture.control.write_text(json.dumps(scenario))
                result = fixture.run_script("up", success=False)
                self.assertIn("health wait failed", result.stderr)
                self.assertEqual((fixture.root / "clock").read_text(), "0")
                self.assertTrue((fixture.state / "transaction.pending").exists())
                self.assertNotIn("demo URL:", result.stdout)

    def test_existing_explicit_ports_override_new_defaults(self):
        with self.env_file.open("a") as output:
            output.write("DEMO_HTTP_PORT=58482\n")
        self.run_script("up")
        self.run_script("up")
        self.assertIn("http://demo.example.org:58482", (self.state / "runtime.env").read_text())

    def test_every_maintenance_compose_call_refuses_conflicting_legacy_inputs(self):
        self.run_script("up")
        with (self.state / "runtime.env").open("a") as output:
            output.write("RF_COMPOSE_FEDERATION_ADMIN_TOKEN=DO_NOT_LOG\n")
        for command, flags in (("status", ()), ("logs", ()), ("down", ()),
                               ("down", ("--purge",))):
            with self.subTest(command=command, flags=flags):
                self.journal.write_text("")
                result = self.run_script(command, *flags, success=False)
                self.assertIn("RF_COMPOSE_FEDERATION_ADMIN_TOKEN", result.stderr)
                self.assertNotIn("DO_NOT_LOG", result.stderr)
                self.assertEqual(self.compose_commands(), [])

    def test_voice_port_refuses_the_mesh_udp_port_before_runtime_access(self):
        result = self.run_script("up", "--voice-udp-port", "59453", success=False)
        self.assertIn("conflicts with another demo UDP port", result.stderr)
        self.assertEqual(self.commands(), [])
        self.assertFalse(self.state.exists())

    def test_general_port_validation_precedes_voice_comparisons(self):
        original = self.env_file.read_text()
        for key in ("DEMO_GATEWAY_PORT", "DEMO_RELAY_PORT", "DEMO_HTTP_PORT",
                    "DEMO_TURN_PORT", "DEMO_MESH_PORT"):
            with self.subTest(key=key):
                self.env_file.write_text(original + f"{key}=not-a-number\n")
                result = self.run_script("up", "--voice-udp-port", "59449", success=False)
                self.assertIn("ports must be integers", result.stderr)
                self.assertNotIn("integer expression", result.stderr)
                self.assertNotIn("conflicts", result.stderr)
                self.assertEqual(self.commands(), [])
        self.assertFalse(self.state.exists())

    def test_new_voice_selection_gives_clear_maintenance_error_before_compose(self):
        self.run_script("up")
        marker = (self.state / "owner.json").read_bytes()
        runtime = (self.state / "runtime.env").read_bytes()
        with self.env_file.open("a") as output:
            output.write("RAMFLUX_DEMO_VOICE_UDP_PORT=59449\n")
        for command, flags in (("status", ()), ("logs", ()), ("down", ()),
                               ("down", ("--purge",))):
            with self.subTest(command=command, flags=flags):
                self.journal.write_text("")
                result = self.run_script(command, *flags, success=False)
                self.assertIn("run up first", result.stderr)
                self.assertNotIn("public voice host:port is required", result.stderr)
                self.assertEqual(self.commands(), [])
                self.assertTrue(self.state.exists())
                self.assertFalse((self.state / "compose.voice.yml").exists())
                self.assertEqual((self.state / "owner.json").read_bytes(), marker)
                self.assertEqual((self.state / "runtime.env").read_bytes(), runtime)
        self.env_file.write_text(self.env_file.read_text().replace(
            "RAMFLUX_DEMO_VOICE_UDP_PORT=59449\n", ""))
        self.run_script("logs")
        self.run_script("down", "--purge")
        self.assertFalse(self.state.exists())

    def test_applied_voice_selection_allows_maintenance_and_refuses_unapplied_changes(self):
        voice = ("--voice-udp-port", "59449")
        self.run_script("up", *voice)
        marker = (self.state / "owner.json").read_bytes()
        self.journal.write_text("")
        result = self.run_script("logs", "--voice-udp-port", "59459", success=False)
        self.assertIn("run up first", result.stderr)
        self.assertEqual(self.commands(), [])
        result = self.run_script("status", *voice)
        self.assertIn("voice UDP mapping: demo.example.org:59449", result.stdout)
        self.run_script("logs", *voice)
        self.run_script("down", *voice)
        self.assertEqual((self.state / "owner.json").read_bytes(), marker)
        for args in self.compose_commands():
            self.assertIn(str(self.state / "compose.voice.yml"), args)
        self.run_script("down", "--purge", *voice)
        self.assertFalse(self.state.exists())


class PodmanComposeDemoNodeTests(DemoNodeTests):
    PROVIDER = "podman"



if __name__ == "__main__":
    unittest.main()
