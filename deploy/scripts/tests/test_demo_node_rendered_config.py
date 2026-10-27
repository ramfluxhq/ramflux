#!/usr/bin/env python3
"""Render the generated demo project with an installed Podman Compose CLI, without containers.

Set DEMO_TEST_PODMAN_COMPOSE to a command (for example: python /path/podman_compose.py).
The CLI's Python environment must provide PyYAML and python-dotenv. No runtime is needed.
"""
import os
import shlex
import shutil
import subprocess
import unittest

import test_demo_node as lifecycle


COMPOSE_CLI = os.environ.get("DEMO_TEST_PODMAN_COMPOSE") or shutil.which("podman-compose")


def unresolved_paths(value, path="config"):
    if isinstance(value, dict):
        return [found for key, item in value.items()
                for found in unresolved_paths(item, f"{path}.{key}")]
    if isinstance(value, list):
        return [found for index, item in enumerate(value)
                for found in unresolved_paths(item, f"{path}[{index}]")]
    return [path] if isinstance(value, str) and "${" in value else []


@unittest.skipUnless(COMPOSE_CLI, "set DEMO_TEST_PODMAN_COMPOSE to run the actual CLI config regression")
class DemoRenderedConfigTests(unittest.TestCase):
    def test_generated_project_has_no_unresolved_substitutions(self):
        import yaml  # Only required for the actual-provider regression.

        fixture = lifecycle.PodmanComposeDemoNodeTests("test_requires_env_and_refuses_unowned_data")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.run_script("up")
        # Reject every container operation, even if a provider unexpectedly issues one for config.
        forbidden = fixture.root / "forbidden-runtime-call"
        runtime = fixture.executable("config-only-podman", "#!/bin/sh\n"
            'if [ "$1" = --version ]; then echo "podman version 5.4.2"; exit 0; fi\n'
            f"touch {shlex.quote(str(forbidden))}\nexit 91\n")
        environment = {"PATH": os.environ["PATH"], "HOME": str(fixture.home)}
        command = shlex.split(COMPOSE_CLI) + ["--podman-path", str(runtime)]
        version = subprocess.run(command + ["version"], env=environment,
                                 capture_output=True, text=True, check=True)
        print(version.stdout.strip())
        result = subprocess.run(command + [
            "--env-file", str(fixture.state / "runtime.env"), "-p", "demo-test",
            "-f", str(fixture.state / "compose.yml"),
            "-f", str(fixture.state / "demo-override.json"), "config",
        ], cwd=fixture.state, env=environment, capture_output=True, text=True, check=True)
        self.assertFalse(forbidden.exists(), "config must not invoke container operations")
        config = yaml.safe_load(result.stdout)
        self.assertEqual(unresolved_paths(config), [], "provider preserved substitution expressions")
        runtime_env = dict(line.split("=", 1)
                           for line in (fixture.state / "runtime.env").read_text().splitlines())
        for key, value in config["services"]["ramflux-relay"]["environment"].items():
            self.assertIn(key, runtime_env, f"relay environment must be explicit: {key}")
            self.assertEqual(runtime_env[key], str(value), f"relay environment changed: {key}")
        # Ensure the frozen project and its ownership override were both used by the provider.
        owner = (fixture.state / "owner.token").read_text().strip()
        for service in config["services"].values():
            self.assertEqual(service["labels"]["org.ramflux.demo.owner"], owner)
        print("All seven services rendered without unresolved substitutions; every relay value is explicit.")


    def test_pre_split_upgrade_renders_public_only_and_private_router_forward(self):
        import yaml
        fixture = lifecycle.DemoNodeTests("test_requires_env_and_refuses_unowned_data")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.seed_pre_split_state()
        fixture.run_script("up")
        forbidden = fixture.root / "forbidden-upgrade-runtime"
        runtime = fixture.executable("upgrade-config-podman", '#!/bin/sh\nif [ "$1" = --version ]; then echo "podman version 5.4.2"; exit 0; fi\n' + f"touch {shlex.quote(str(forbidden))}\nexit 91\n")
        result = subprocess.run(shlex.split(COMPOSE_CLI) + ["--podman-path", str(runtime),
            "--env-file", str(fixture.state / "runtime.env"), "-p", "demo-test", "-f", str(fixture.state / "compose.yml"),
            "-f", str(fixture.state / "demo-override.json"), "config"], cwd=fixture.state,
            env={"PATH":os.environ["PATH"], "HOME":str(fixture.home)}, capture_output=True, text=True, check=True)
        config = yaml.safe_load(result.stdout)
        self.assertFalse(forbidden.exists())
        ports = config["services"]["ramflux-federation"]["ports"]
        def mapping(port):
            if isinstance(port, dict):
                return str(port.get("published")), str(port["target"])
            parts = str(port).split("/")[0].split(":")
            return parts[-2], parts[-1]
        mappings = [mapping(port) for port in ports]
        self.assertIn(("59482", "18082"), mappings)
        self.assertFalse(any(target == "18084" or published == "18082" for published, target in mappings), ports)
        self.assertEqual(config["services"]["ramflux-router"]["environment"]["RAMFLUX_ROUTER_FEDERATION_FORWARD_URL"],
                         "http://ramflux-federation:18084/internal/home-node-migration/forward")


if __name__ == "__main__":
    unittest.main()
