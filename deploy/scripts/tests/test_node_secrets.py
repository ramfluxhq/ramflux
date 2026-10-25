"""Native secret provisioning checks; no container runtime is started."""
import base64
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


class NodeSecretsTests(unittest.TestCase):
    def test_bootstrap_keys_are_private_stable_and_outside_database_volumes(self):
        with tempfile.TemporaryDirectory(prefix="rf-node-secrets-") as directory:
            root = Path(directory)
            env = dict(os.environ, RAMFLUX_DEPLOY_DIR=str(root))
            for script in ("bootstrap-ca.sh", "issue-certs.sh"):
                subprocess.run(["sh", str(SCRIPTS / script)], env=env, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            paths = [root / "certs" / "node-identity" / "node-signing.key",
                     root / "certs" / "notify" / "route.key"]
            original = [path.read_bytes() for path in paths]
            for path, encoded in zip(paths, original):
                # Group-readable for capability-dropped containers; never world-readable.
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
                self.assertEqual(len(base64.urlsafe_b64decode(encoded + b"=")), 32)
            subprocess.run(["sh", str(SCRIPTS / "issue-certs.sh")], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual([path.read_bytes() for path in paths], original)
            self.assertFalse((root / "certs" / "federation" / "node-signing.key").exists())

    def test_existing_identity_moves_out_of_the_mesh_directory(self):
        with tempfile.TemporaryDirectory(prefix="rf-node-secrets-") as directory:
            root = Path(directory)
            env = dict(os.environ, RAMFLUX_DEPLOY_DIR=str(root))
            subprocess.run(["sh", str(SCRIPTS / "bootstrap-ca.sh")], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            legacy = root / "certs" / "federation" / "node-signing.key"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
            legacy.chmod(0o600)
            subprocess.run(["sh", str(SCRIPTS / "issue-certs.sh")], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            moved = root / "certs" / "node-identity" / "node-signing.key"
            self.assertEqual(moved.read_text(), "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
            self.assertFalse(legacy.exists())

    def test_secret_group_defaults_to_the_operator_and_is_recorded_once(self):
        with tempfile.TemporaryDirectory(prefix="rf-node-secrets-") as directory:
            root = Path(directory)
            env = dict(os.environ, RAMFLUX_DEPLOY_DIR=str(root))
            env.pop("RAMFLUX_SECRET_GROUP", None)
            for script in ("bootstrap-ca.sh", "issue-certs.sh", "issue-certs.sh"):
                subprocess.run(["sh", str(SCRIPTS / script)], env=env, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            lines = (root / ".env").read_text().splitlines()
            self.assertEqual(lines, [f"RAMFLUX_SECRET_GID={os.getgid()}"])
            (root / ".env").write_text("RAMFLUX_SECRET_GID=4242\n")
            subprocess.run(["sh", str(SCRIPTS / "issue-certs.sh")], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual((root / ".env").read_text(), "RAMFLUX_SECRET_GID=4242\n")

    def test_conflicting_signing_seeds_fail_closed_and_keep_both(self):
        with tempfile.TemporaryDirectory(prefix="rf-node-secrets-") as directory:
            root = Path(directory)
            env = dict(os.environ, RAMFLUX_DEPLOY_DIR=str(root))
            for script in ("bootstrap-ca.sh", "issue-certs.sh"):
                subprocess.run(["sh", str(SCRIPTS / script)], env=env, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            current = root / "certs" / "node-identity" / "node-signing.key"
            legacy = root / "certs" / "federation" / "node-signing.key"
            legacy.write_text("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
            original = current.read_text()
            result = subprocess.run(["sh", str(SCRIPTS / "issue-certs.sh")], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("different node signing seeds", result.stderr)
            self.assertTrue(legacy.exists())
            self.assertEqual(current.read_text(), original)
            legacy.write_text(original)
            subprocess.run(["sh", str(SCRIPTS / "issue-certs.sh")], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertFalse(legacy.exists())

    def test_compose_uses_concrete_secret_paths(self):
        for filename in ("docker-compose.yml", "docker-compose.itest.yml"):
            contents = (SCRIPTS.parent / filename).read_text()
            self.assertNotIn("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL:", contents)
            self.assertIn('RAMFLUX_NOTIFY_ROUTE_KEY_FILE: "/etc/ramflux/mesh/route.key"', contents)
            self.assertIn(
                'RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE: "/etc/ramflux/node-identity/node-signing.key"',
                contents)
            self.assertNotIn("/federation:/etc/ramflux/node-identity", contents)

    def test_capability_dropped_secret_readers_join_the_secret_group(self):
        contents = (SCRIPTS.parent / "docker-compose.yml").read_text()
        for service in ("ramflux-notify", "ramflux-federation", "ramflux-retention"):
            block = contents.split(f"  {service}:\n", 1)[1].split("\n  ramflux-", 1)[0]
            self.assertIn('cap_drop: ["ALL"]', block)
            self.assertIn('group_add: ["${RAMFLUX_SECRET_GID:-0}"]', block)
        retention = contents.split("  ramflux-retention:\n", 1)[1]
        self.assertNotIn("./certs/federation:", retention.split("healthcheck:", 1)[0])


if __name__ == "__main__":
    unittest.main()
