#!/usr/bin/env python3
"""Exercise demo lifecycle and ownership safety with a fake Docker executable."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "demo-node.sh"


class DemoNodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-demo-shell-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.state = self.root / "data"
        self.control = self.root / "control.json"
        self.control.write_text("{}")
        self.journal = self.root / "commands.jsonl"
        docker = f'''#!/usr/bin/env python3
import json
from pathlib import Path
import sys
args = sys.argv[1:]
with Path({str(self.journal)!r}).open("a") as output:
    output.write(json.dumps(args) + "\\n")
control = json.loads(Path({str(self.control)!r}).read_text())
kind = None
if args[:2] == ["ps", "-aq"]: kind = "container"
if args[:3] == ["volume", "ls", "-q"]: kind = "volume"
if args[:3] == ["network", "ls", "-q"]: kind = "network"
if args == ["volume", "ls", "-q"] and control.get("unlabeled") == "volume":
    print("demo-test_gateway-redb")
elif args == ["network", "ls", "--format", "{{{{.Name}}}}"] and control.get("unlabeled") == "network":
    print("demo-test_default")
elif kind and control.get("foreign") == kind:
    print("foreign-resource")
elif args[0] == "inspect" or (len(args) > 1 and args[1] == "inspect"):
    if "Health.Status" in " ".join(args):
        print(control.get("health", "healthy"))
    else:
        print("foreign-owner")
elif args[0] == "compose" and "ps" in args and "-q" in args:
    if not control.get("stopped"):
        print("service-id")
'''
        self.executable("docker", docker)
        self.executable("cargo", "#!/bin/sh\nexit 0\n")
        self.executable("rustup", "#!/bin/sh\nexit 1\n")
        tool = '''#!/usr/bin/env python3
from pathlib import Path
import sys
if sys.argv[1] == "init":
    root = Path(sys.argv[2])
    for name in ("gateway-v3", "federation"):
        directory = root / "secrets" / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "test.json").write_text("{}")
    (root / "identity.env").write_text("DEMO_EXPECTED_NODE_PUBLIC_KEY=test-public-pin\\n")
else:
    assert sys.argv[3] == "test-public-pin"
    print("mock discovery and QUIC verification")
'''
        self.tool = self.executable("demo-node-tool", tool)
        self.env_file = self.root / "demo.env"
        values = dict(DEMO_HOST="demo.example.org", DEMO_PROJECT="demo-test",
                      DEMO_DATA_DIR=str(self.state), DEMO_TOOL=str(self.tool))
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

    def test_requires_env_and_refuses_unowned_data(self):
        self.run_script("up", env_file=self.root / "missing.env", success=False)
        self.state.mkdir()
        (self.state / "unrelated.txt").write_text("preserve")
        self.run_script("up", success=False)
        self.assertEqual((self.state / "unrelated.txt").read_text(), "preserve")
        self.assertEqual(self.commands(), [])

    def test_repeat_up_preserves_ca_and_named_volumes_until_explicit_purge(self):
        self.state.mkdir(mode=0o755)
        self.run_script("up")
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
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

    def test_refuses_foreign_containers_volumes_and_networks_even_on_purge(self):
        self.run_script("up")
        for kind in ("container", "volume", "network"):
            with self.subTest(kind=kind):
                self.control.write_text(json.dumps({"foreign": kind}))
                self.journal.write_text("")
                result = self.run_script("down", "--purge", success=False)
                self.assertIn("refusing foreign", result.stderr)
                self.assertTrue(self.state.exists())
                self.assertFalse(any(args[0] == "compose" for args in self.commands()))

    def test_refuses_unlabeled_volume_and_network_name_collisions(self):
        self.run_script("up")
        for kind in ("volume", "network"):
            with self.subTest(kind=kind):
                self.control.write_text(json.dumps({"unlabeled": kind}))
                self.journal.write_text("")
                self.run_script("up", success=False)
                self.assertFalse(any(args[0] == "compose" for args in self.commands()))

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


if __name__ == "__main__":
    unittest.main()
