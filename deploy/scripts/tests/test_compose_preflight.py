#!/usr/bin/env python3
"""Preflight validates the provider's config-only render without leaking values."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "compose-preflight.py"
spec = importlib.util.spec_from_file_location("preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_legacy_names_are_best_effort_and_values_are_never_reported(self):
        env_file = self.root / "operator.env"
        env_file.write_text("RAMFLUX_NODE_ID=DO_NOT_LOG\n")
        with mock.patch.dict(os.environ, {}, clear=True):
            invalid = preflight.validate_legacy_inputs(["--env-file", str(env_file)])
        self.assertEqual(invalid, {"RAMFLUX_NODE_ID", "RF_COMPOSE_NODE_ID"})
        self.assertNotIn("DO_NOT_LOG", ",".join(invalid))

    def test_equal_legacy_and_new_names_are_accepted_with_process_precedence(self):
        env_file = self.root / "operator.env"
        env_file.write_text("RAMFLUX_NODE_ID=file\nRF_COMPOSE_NODE_ID=file\n")
        process = {"RAMFLUX_NODE_ID": "process", "RF_COMPOSE_NODE_ID": "process"}
        with mock.patch.dict(os.environ, process, clear=True):
            invalid = preflight.validate_legacy_inputs(["--env-file", str(env_file)])
        self.assertEqual(invalid, set())

    def test_implicit_dotenv_and_process_legacy_names_are_checked(self):
        (self.root / ".env").write_text("RAMFLUX_NODE_ID=DO_NOT_LOG\n")
        with mock.patch.object(preflight.Path, "cwd", return_value=self.root), \
                mock.patch.dict(os.environ, {}, clear=True):
            self.assertIn("RAMFLUX_NODE_ID", preflight.validate_legacy_inputs([]))
        with mock.patch.dict(os.environ, {"RAMFLUX_NODE_ID": "DO_NOT_LOG"}, clear=True):
            self.assertIn("RAMFLUX_NODE_ID", preflight.validate_legacy_inputs(["--env-file", str(self.root / ".env")]))

    def test_project_directory_selects_legacy_dotenv_candidate(self):
        project = self.root / "project"
        project.mkdir()
        (project / ".env").write_text("RAMFLUX_NODE_ID=DO_NOT_LOG\n")
        with mock.patch.object(preflight.Path, "cwd", return_value=self.root), \
                mock.patch.dict(os.environ, {}, clear=True):
            invalid = preflight.validate_legacy_inputs(["--project-directory", str(project)])
        self.assertIn("RAMFLUX_NODE_ID", invalid)

    def test_compose_env_files_are_checked_in_order_and_missing_files_fail_closed(self):
        first = self.root / "first.env"
        second = self.root / "second.env"
        first.write_text("RAMFLUX_NODE_ID=first\nRF_COMPOSE_NODE_ID=first\n")
        second.write_text("RAMFLUX_NODE_ID=second\n")
        process = {"COMPOSE_ENV_FILES": f"{first},{second}"}
        with mock.patch.object(preflight.Path, "cwd", return_value=self.root), \
                mock.patch.dict(os.environ, process, clear=True):
            invalid = preflight.validate_legacy_inputs([])
        self.assertIn("RAMFLUX_NODE_ID", invalid)
        with mock.patch.object(preflight.Path, "cwd", return_value=self.root), \
                mock.patch.dict(os.environ, {"COMPOSE_ENV_FILES": "missing.env"}, clear=True):
            with self.assertRaises(preflight.InputError):
                preflight.validate_legacy_inputs([])

    def test_explicit_env_file_takes_precedence_over_compose_env_files(self):
        explicit = self.root / "explicit.env"
        explicit.write_text("RAMFLUX_NODE_ID=same\nRF_COMPOSE_NODE_ID=same\n")
        with mock.patch.dict(os.environ, {"COMPOSE_ENV_FILES": "missing.env"}, clear=True):
            invalid = preflight.validate_legacy_inputs(["--env-file", str(explicit)])
        self.assertEqual(invalid, set())

    def test_dotenv_quotes_multiline_escapes_and_interpolation_remain_supported(self):
        env_file = self.root / "operator.env"
        env_file.write_text(
            "RF_COMPOSE_NODE_ID=${HOST_NAME:-fallback}\n"
            "MULTILINE=\"first\\nsecond\"\n"
            "LITERAL='${DO_NOT_EXPAND}'\n"
        )
        values = preflight.read_env(env_file, {}, {"HOST_NAME": "example.test"})
        self.assertEqual(values["RF_COMPOSE_NODE_ID"], "example.test")
        self.assertEqual(values["MULTILINE"], "first\nsecond")
        self.assertEqual(values["LITERAL"], "${DO_NOT_EXPAND}")

    def test_provider_render_uses_same_arguments_and_only_config(self):
        rendered = subprocess.CompletedProcess([], 0, '{"services": {}}', "")
        with mock.patch.object(preflight.subprocess, "run", return_value=rendered) as run:
            output = preflight.render_config(
                "docker", ["--env-file", "operator.env", "-p", "project", "-f", "compose.yml"]
            )
        self.assertEqual(output, rendered.stdout)
        self.assertEqual(
            run.call_args.args[0],
            ["docker", "compose", "--env-file", "operator.env", "-p", "project", "-f",
             "compose.yml", "config", "--format", "json"],
        )

    def test_docker_json_scans_public_unresolved_and_empty_security_values(self):
        rendered = json.dumps({"services": {"one": {"environment": {
            "RAMFLUX_FEDERATION_ADMIN_TOKEN": "  ramflux-local-admin-token  ",
            "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL": "",
            "RAMFLUX_PRIVATE_PATH": "/run/${UNRESOLVED}/key",
            "RAMFLUX_HARMLESS": "ready",
        }}}})
        invalid = preflight.validate_rendered(preflight.docker_environments(rendered))
        self.assertEqual(invalid, {
            "RAMFLUX_FEDERATION_ADMIN_TOKEN",
            "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL",
            "RAMFLUX_PRIVATE_PATH",
        })

    def test_podman_yaml_scans_mapping_and_list_environments_without_yaml_dependency(self):
        rendered = """services:
  one:
    environment:
      RAMFLUX_FEDERATION_ADMIN_TOKEN: ' ramflux-local-admin-token '
      RAMFLUX_GATEWAY_V3_ISSUER_SEED:
  two:
    environment:
      - RAMFLUX_PRIVATE_PATH=/run/${UNRESOLVED}/key
      - RAMFLUX_HARMLESS=ready
"""
        invalid = preflight.validate_rendered(preflight.podman_environments(rendered))
        self.assertEqual(invalid, {
            "RAMFLUX_FEDERATION_ADMIN_TOKEN",
            "RAMFLUX_GATEWAY_V3_ISSUER_SEED",
            "RAMFLUX_PRIVATE_PATH",
        })

    def test_podman_yaml_allows_services_without_environment(self):
        self.assertEqual(preflight.podman_environments("services:\n  probe:\n    image: scratch\n"), [])

    def test_render_failure_reports_only_a_stable_key(self):
        failed = subprocess.CompletedProcess([], 1, "DO_NOT_LOG", "DO_NOT_LOG")
        with mock.patch.object(preflight.subprocess, "run", return_value=failed):
            with self.assertRaises(preflight.InputError) as error:
                preflight.render_config("podman-compose", [])
        self.assertEqual(str(error.exception), "CONFIG_RENDER")


class ProviderBypassTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-compose-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def compose_file(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "compose.yaml"
        path.write_text("""services:
  probe:
    image: scratch
    environment:
      RAMFLUX_FEDERATION_ADMIN_TOKEN: ${RF_COMPOSE_FEDERATION_ADMIN_TOKEN:-safe-token}
""")
        return path

    def test_ci_has_at_least_one_config_provider(self):
        available = (os.environ.get("COMPOSE_TEST_DOCKER_COMPOSE")
                     or os.environ.get("DEMO_TEST_PODMAN_COMPOSE")
                     or shutil.which("podman-compose"))
        if not os.environ.get("CI") and not available:
            self.skipTest("config provider availability is required in CI")
        self.assertTrue(available, "CI must exercise at least one Compose config provider")

    def provider_environment(self, provider):
        environment = {"HOME": str(self.root), "PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}
        if provider == "docker":
            command = os.environ.get("COMPOSE_TEST_DOCKER_COMPOSE")
            if not command:
                self.skipTest("set COMPOSE_TEST_DOCKER_COMPOSE for Docker Compose config tests")
            parts = shlex.split(command)
            wrapper = self.bin / "docker"
            wrapper.write_text("#!/bin/sh\n[ \"$1\" = compose ] || exit 64\nshift\nexec "
                               + " ".join(shlex.quote(part) for part in parts) + " \"$@\"\n")
            wrapper.chmod(0o700)
        else:
            command = os.environ.get("DEMO_TEST_PODMAN_COMPOSE") or shutil.which("podman-compose")
            if not command:
                self.skipTest("podman-compose is unavailable")
            parts = shlex.split(command)
            wrapper = self.bin / "podman-compose"
            wrapper.write_text("#!/bin/sh\nexec "
                               + " ".join(shlex.quote(part) for part in parts) + " \"$@\"\n")
            wrapper.chmod(0o700)
        return environment

    def run_preflight(self, provider, cwd, arguments=(), environment=None, stdin=None):
        process = self.provider_environment(provider)
        process.update(environment or {})
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--provider", provider, *arguments],
            cwd=cwd,
            env=process,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("RAMFLUX_FEDERATION_ADMIN_TOKEN", result.stderr)
        self.assertNotIn(preflight.PUBLIC_SECRET, result.stderr)

    def test_docker_process_compose_file_cannot_hide_cwd_dotenv(self):
        self.compose_file(self.root / "project")
        (self.root / ".env").write_text(
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token\n")
        (self.root / "project" / ".env").write_text(
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=safe-token\n")
        self.run_preflight("docker", self.root,
                           environment={"COMPOSE_FILE": "project/compose.yaml"})

    def test_docker_upward_discovery_cannot_hide_subdirectory_dotenv(self):
        self.compose_file(self.root)
        (self.root / ".env").write_text("RF_COMPOSE_FEDERATION_ADMIN_TOKEN=safe-token\n")
        subdirectory = self.root / "sub"
        subdirectory.mkdir()
        (subdirectory / ".env").write_text(
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token\n")
        self.run_preflight("docker", subdirectory)

    def test_docker_stdin_file_cannot_hide_project_dotenv(self):
        compose = self.compose_file(self.root / "project")
        (self.root / ".env").write_text("RF_COMPOSE_FEDERATION_ADMIN_TOKEN=safe-token\n")
        (compose.parent / ".env").write_text(
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token\n")
        self.run_preflight("docker", self.root,
                           arguments=("-f", "-", "-f", str(compose)), stdin="services: {}\n")

    def test_podman_file_elsewhere_cannot_hide_cwd_dotenv(self):
        compose = self.compose_file(self.root / "project")
        (compose.parent / ".env").write_text("RF_COMPOSE_FEDERATION_ADMIN_TOKEN=safe-token\n")
        (self.root / ".env").write_text(
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token\n")
        self.run_preflight("podman-compose", self.root, arguments=("-f", str(compose)))

    def test_podman_disable_and_project_directory_cannot_hide_project_dotenv(self):
        self.compose_file(self.root / "project")
        (self.root / "project" / ".env").write_text(
            "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token\n")
        empty = self.root / "empty"
        empty.mkdir()
        self.run_preflight(
            "podman-compose",
            empty,
            environment={"COMPOSE_DISABLE_ENV_FILE": "1", "COMPOSE_PROJECT_DIR": str(self.root / "project")},
        )


if __name__ == "__main__":
    unittest.main()
