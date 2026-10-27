#!/usr/bin/env python3
"""Check Compose inputs and render configurations without a container engine."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_demo_node_rendered_config import unresolved_paths

DEPLOY = Path(__file__).resolve().parents[2]
MAPPING = json.loads((DEPLOY / "compose-inputs.json").read_text())
SELF_DEFAULT = re.compile(r'''^\s*(?:-\s+)?([A-Z_][A-Z0-9_]*)(?::\s*|=)["']?\$\{\1(?::-|-)[^}]*\}''')


class ComposeInputTests(unittest.TestCase):
    def test_all_compose_defaults_use_an_input_distinct_from_the_service_key(self):
        failures = []
        used = set()
        for path in DEPLOY.glob("docker-compose*.yml"):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if SELF_DEFAULT.match(line):
                    failures.append(f"{path.name}:{number}")
                used.update(re.findall(r"\$\{(RF_COMPOSE_[A-Z0-9_]+)", line))
        self.assertEqual(failures, [], "self-defaults break podman-compose 1.3.0")
        self.assertEqual(used, set(MAPPING.values()), "keep the operator migration map complete")
        for key, value in MAPPING.items():
            self.assertEqual(value, "RF_COMPOSE_" + key.removeprefix("RAMFLUX_"))

    def test_generated_demo_aliases_preserve_inputs_empty_values_permissions_and_repeatability(self):
        spec = importlib.util.spec_from_file_location("compose_env", DEPLOY / "scripts/compose-env.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.env"
            original = "RAMFLUX_NODE_ID=example.test\nRAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE=\nDEMO_EXPECTED_NODE_PUBLIC_KEY=public\n"
            path.write_text(original)
            path.chmod(0o600)
            module.append_inputs(path)
            first = path.read_text()
            module.append_inputs(path)
            self.assertEqual(path.read_text(), first)
            self.assertTrue(first.startswith(original))
            self.assertIn("RF_COMPOSE_NODE_ID=example.test\n", first)
            self.assertIn("RF_COMPOSE_NOTIFY_PROVIDER_CREDENTIALS_FILE=\n", first)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.write_text("RAMFLUX_NODE_ID=one\nRF_COMPOSE_NODE_ID=two\n")
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                module.append_inputs(path)
            self.assertEqual(path.read_bytes(), before)


class RenderedComposeInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-compose-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.forbidden = self.root / "forbidden-engine-call"
        runtime = self.root / "config-only-podman"
        runtime.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "podman version 5.4.2"; exit 0; fi\n'
                           f"touch {shlex.quote(str(self.forbidden))}\nexit 91\n")
        runtime.chmod(0o700)
        self.runtime = runtime

    def render(self, command, files, inputs):
        import yaml
        env_file = self.root / "compose.env"
        env_file.write_text("\n".join(f"{key}={value}" for key, value in inputs.items()) + "\n")
        args = command + ["--env-file", str(env_file), "-p", "config-only"]
        for path in files:
            args.extend(["-f", str(path)])
        output = subprocess.run(args + ["config"], cwd=DEPLOY,
                                env={"PATH": os.environ["PATH"], "HOME": str(self.root)},
                                text=True, capture_output=True, check=False)
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertFalse(self.forbidden.exists(), "configuration rendering must not contact an engine")
        config = yaml.safe_load(output.stdout)
        self.assertEqual(unresolved_paths(config), [], output.stderr)
        return config

    def check_provider(self, command):
        required = {
            "RAMFLUX_FEDERATION_TRUST_ENDPOINT": "federation.example:7443",
            "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID": "node.example",
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN": "generated-test-token",
            "RF_COMPOSE_ROUTER_ADMIN_TOKEN": "generated-test-token",
            "RF_COMPOSE_CLIENT_GATEWAY_QUIC_ADDR": "explicit-input",
            "RF_COMPOSE_CLIENT_GATEWAY_SERVER_NAME": "explicit-input",
            "RF_COMPOSE_CLIENT_GATEWAY_TCP_ADDR": "explicit-input",
            "RF_COMPOSE_CLIENT_PREKEY_HTTP_URL": "explicit-input",
            "RF_COMPOSE_CLIENT_RELAY_QUIC_ADDR": "explicit-input",
            "RF_COMPOSE_CLIENT_RELAY_SERVER_NAME": "explicit-input",
            "RF_COMPOSE_CLIENT_SIGNALING_TURN_ADDR": "explicit-input",
            "RF_COMPOSE_FEDERATION_NODE_ID": "explicit-input",
            "RF_COMPOSE_FEDERATION_PROVIDER_KEYRING_FILE": "explicit-input",
            "RF_COMPOSE_FEDERATION_PUBLIC_ENDPOINT": "explicit-input",
            "RF_COMPOSE_FEDERATION_TRUST_SNAPSHOT_FILE": "explicit-input",
            "RF_COMPOSE_GATEWAY_V3_ISSUER_CERT_FILE": "explicit-input",
            "RF_COMPOSE_GATEWAY_V3_ISSUER_SEED": "explicit-input",
            "RF_COMPOSE_NODE_SERVICE_SIGNING_SEED_B64URL": "explicit-input",
            "RF_COMPOSE_RELAY_TRUST_SNAPSHOT_CACHE_FILE": "explicit-input",

        }
        for path in sorted(DEPLOY.glob("docker-compose*.yml")):
            with self.subTest(compose=path.name):
                inputs = dict(required)
                files = [path]
                if path.name not in {"docker-compose.yml", "docker-compose.itest.yml"}:
                    base = "docker-compose.itest.yml" if ".itest." in path.name else "docker-compose.yml"
                    if path.name == "docker-compose.itest.admin.yml":
                        base = "docker-compose.yml"
                        inputs["RAMFLUX_ITEST_FEDERATION_ADMIN_PORT"] = "58484"
                    files.insert(0, DEPLOY / base)
                if path.name in {"docker-compose.itest.object-v3.yml", "docker-compose.itest.voice.yml"}:
                    files.insert(1, DEPLOY / "docker-compose.itest.cross-gateway.yml")
                if path.name == "docker-compose.voice.yml":
                    inputs["RF_COMPOSE_RELAY_VOICE_PUBLIC_ENDPOINT"] = "voice.example:17449"
                unset = self.render(command, files, inputs)
                empty = self.render(command, files, {**dict.fromkeys(MAPPING.values(), ""), **inputs})
                self.assertEqual(unset, empty, "empty inputs must retain :- default semantics")
        overridden = self.render(command, [DEPLOY / "docker-compose.itest.yml"], {
            **required, "RF_COMPOSE_NODE_ID": "override.example",
            "RF_COMPOSE_NOTIFY_PROVIDER_CREDENTIALS_FILE": "/run/provider.json",
            "RF_COMPOSE_MESH_QUIC_RECEIVE_WINDOW": "33554432",
        })
        for name in ["ramflux-gateway", "ramflux-router", "ramflux-notify"]:
            self.assertEqual(overridden["services"][name]["environment"]["RAMFLUX_NODE_ID"], "override.example")
        self.assertEqual(overridden["services"]["ramflux-notify"]["environment"]["RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE"], "/run/provider.json")
        self.assertEqual(str(overridden["services"]["ramflux-gateway"]["environment"]["RAMFLUX_MESH_QUIC_RECEIVE_WINDOW"]), "33554432")

    def test_every_compose_default_and_override_resolves_with_podman_compose(self):
        provider = os.environ.get("DEMO_TEST_PODMAN_COMPOSE") or shutil.which("podman-compose")
        if not provider:
            self.skipTest("set DEMO_TEST_PODMAN_COMPOSE for config-only provider testing")
        self.check_provider(shlex.split(provider) + ["--podman-path", str(self.runtime)])

    def test_every_compose_default_and_override_resolves_with_docker_compose_v2(self):
        provider = os.environ.get("COMPOSE_TEST_DOCKER_COMPOSE")
        if not provider:
            self.skipTest("set COMPOSE_TEST_DOCKER_COMPOSE for config-only Docker Compose v2 testing")
        self.check_provider(shlex.split(provider))

    def test_old_names_only_env_is_refused_before_required_production_config_can_start(self):
        provider = os.environ.get("COMPOSE_TEST_DOCKER_COMPOSE")
        if not provider:
            self.skipTest("set COMPOSE_TEST_DOCKER_COMPOSE for config-only testing")
        env_file = self.root / "legacy.env"
        env_file.write_text("".join(f"{old}=DO_NOT_LOG\n" for old in MAPPING)
            + "RAMFLUX_FEDERATION_TRUST_ENDPOINT=federation.example:7443\n"
            + "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY=fixture-root\n"
            + "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID=node.example\n")
        env = {"PATH": os.environ["PATH"], "HOME": str(self.root)}
        checked = subprocess.run([__import__('sys').executable,
            str(DEPLOY / "scripts/compose-preflight.py"), "--env-file", str(env_file)],
            env=env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(checked.returncode, 0)
        self.assertNotIn("DO_NOT_LOG", checked.stderr)
        rendered = subprocess.run(shlex.split(provider) + ["--env-file", str(env_file),
            "-f", str(DEPLOY / "docker-compose.yml"), "config"], env=env,
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(rendered.returncode, 0)
        self.assertIn("RF_COMPOSE_", rendered.stderr)
        self.assertNotIn("ramflux-local-admin-token", (DEPLOY / "docker-compose.yml").read_text())
