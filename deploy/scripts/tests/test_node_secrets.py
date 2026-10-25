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
            paths = [root / "certs" / "federation" / "node-signing.key",
                     root / "certs" / "notify" / "route.key"]
            original = [path.read_bytes() for path in paths]
            for path, encoded in zip(paths, original):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(len(base64.urlsafe_b64decode(encoded + b"=")), 32)
            subprocess.run(["sh", str(SCRIPTS / "issue-certs.sh")], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual([path.read_bytes() for path in paths], original)

    def test_compose_uses_concrete_secret_paths(self):
        for filename in ("docker-compose.yml", "docker-compose.itest.yml"):
            contents = (SCRIPTS.parent / filename).read_text()
            self.assertNotIn("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL:", contents)
            self.assertIn('RAMFLUX_NOTIFY_ROUTE_KEY_FILE: "/etc/ramflux/mesh/route.key"', contents)
            self.assertIn('RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE: "/etc/ramflux/mesh/node-signing.key"', contents)


if __name__ == "__main__":
    unittest.main()
