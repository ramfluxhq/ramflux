#!/usr/bin/env python3
"""Crash-safety tests for the demo snapshot transaction helper."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / "demo-node-config.py"
SPEC = importlib.util.spec_from_file_location("demo_node_config", HELPER)
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)


class DemoNodeConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ramflux-demo-config-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "data"
        self.state.mkdir()
        self.settings = {
            "DEMO_PROJECT": "demo-test",
            "DEMO_HOST": "demo.example.org",
            "DEMO_PUBLIC_ORIGIN": "",
            "DEMO_NODE_ID": "demo.invalid",
            "DEMO_GATEWAY_PORT": "59443",
            "DEMO_RELAY_PORT": "59447",
            "DEMO_HTTP_PORT": "59482",
            "DEMO_TURN_PORT": "59478",
            "DEMO_MESH_PORT": "59453",
            "DEMO_BIND_ADDR": "0.0.0.0",
            "DEMO_VERSION": "demo-v2",
        }
        owner = {
            "settings": {**self.settings, "DEMO_VERSION": "demo-v1"},
            "version_history": ["demo-v1"],
            "directory": str(self.state),
            "token": "owner-token",
        }
        (self.state / "owner.json").write_text(json.dumps(owner))
        for name in ("compose.yml", "runtime.env", "demo-override.json"):
            (self.state / name).write_text(f"legacy {name}\n")
        config = self.state / "config"
        config.mkdir()
        for service in CONFIG.SERVICES:
            (config / f"{service}.toml").write_text(f"service_id = 'ramflux-{service}'\n")

    def test_interrupted_initial_cleanup_retains_authority_without_pending_owner(self):
        pending = self.state / "owner.json.pending"
        owner = json.loads((self.state / "owner.json").read_text())
        pending.write_text(json.dumps(owner))
        marker = self.state / "transaction.pending"
        marker.write_text(json.dumps({"command": "up", "previous_snapshot": None,
                                      "target_snapshot": "demo-v1/initial"}))
        settings = owner["settings"]
        with mock.patch.dict(os.environ, settings, clear=False):
            with mock.patch.object(CONFIG.shutil, "rmtree", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    CONFIG.finish_initial_recovery(self.state)
            self.assertTrue(marker.exists())
            self.assertEqual(json.loads(marker.read_text())["initial_owner"], owner)
            pending.unlink(missing_ok=True)
            self.assertEqual(CONFIG.initial_recovery_owner(self.state), owner)
            CONFIG.finish_initial_recovery(self.state)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_owner_without_snapshot_history_is_refused_not_adopted(self):
        with mock.patch.dict(os.environ, self.settings, clear=False):
            with self.assertRaisesRegex(SystemExit, "obsolete data directory layout"):
                CONFIG.prepare(HELPER.parents[2], self.state, "upgrade")
        self.assertFalse((self.state / "version-snapshots").exists())
        self.assertFalse((self.state / "transaction.pending").exists())
        self.assertFalse((self.state / "owner.json.pending").exists())

    def test_symlinked_snapshot_root_is_refused_without_writing_outside_state(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.state / "version-snapshots").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(CONFIG.SnapshotError, "symlinked"):
            CONFIG.capture_snapshot(self.state, "demo-v1/current")
        self.assertEqual(list(outside.iterdir()), [])

    def test_snapshot_pruning_keeps_three_previous_snapshots_and_current(self):
        root = self.state / "version-snapshots"
        history = []
        for number in range(6):
            reference = f"v{number}/snapshot-{number}"
            history.append(reference)
            (root / reference).mkdir(parents=True)
        owner = {"snapshot_history": history, "current_snapshot": history[-1]}
        CONFIG.prune_snapshots(self.state, owner)
        retained = {
            f"{version.name}/{snapshot.name}"
            for version in root.iterdir()
            for snapshot in version.iterdir()
        }
        self.assertEqual(retained, set(history[-4:]))

    def test_product_identity_comes_from_the_build_input(self):
        repo = Path(__file__).resolve().parents[3]
        self.assertEqual(CONFIG.workspace_product_version(repo / "Cargo.toml"), "0.2.1")
        with mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "ABCDEF012345"}):
            with self.assertRaisesRegex(SystemExit, "lowercase hexadecimal"):
                CONFIG.product_sha(repo)
        with mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "abcdef0123456789"}):
            self.assertEqual(CONFIG.product_sha(repo), "abcdef012345")
        with mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": ""}):
            sha = CONFIG.product_sha(repo)
        self.assertRegex(sha, r"^(?:[0-9a-f]{12}|unknown)$")

    def test_selected_image_labels_supply_product_identity(self):
        def inspect(command, **_kwargs):
            self.assertEqual(command[:3], ["podman", "image", "inspect"])
            service = command[3].rsplit("/ramflux-", 1)[1].split(":", 1)[0]
            revision = "aaaaaaaaaaaa" if service != "relay" else "bbbbbbbbbbbb"
            payload = json.dumps([{
                "Config": {"Labels": {
                    "org.opencontainers.image.version": "0.1.9",
                    "org.opencontainers.image.revision": revision,
                }},
            }])
            return subprocess.CompletedProcess(command, 0, payload, "")

        with mock.patch.object(CONFIG.subprocess, "run", side_effect=inspect), \
                mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "cccccccccccccccc"}):
            with self.assertRaisesRegex(SystemExit, "DEMO_IMAGE_PRODUCT_MISMATCH"):
                CONFIG.image_product_identity("podman", "demo-v2")

        def uniform(command, **_kwargs):
            payload = json.dumps([{
                "Config": {"Labels": {
                    "org.opencontainers.image.version": "0.1.9",
                    "org.opencontainers.image.revision": "aaaaaaaaaaaa",
                }},
            }])
            return subprocess.CompletedProcess(command, 0, payload, "")

        with mock.patch.object(CONFIG.subprocess, "run", side_effect=uniform), \
                mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "bbbbbbbbbbbb"}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            CONFIG.image_product_identity("podman", "demo-v2")
        self.assertEqual(
            output.getvalue(),
            "RAMFLUX_EXPECTED_PRODUCT_VERSION=0.1.9\n"
            "RAMFLUX_EXPECTED_PRODUCT_SHA=aaaaaaaaaaaa\n",
        )

        def unlabeled(command, **_kwargs):
            payload = json.dumps([{"Config": {"Labels": {}}}])
            return subprocess.CompletedProcess(command, 0, payload, "")

        with mock.patch.object(CONFIG.subprocess, "run", side_effect=unlabeled), \
                mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "bbbbbbbbbbbb"}):
            with self.assertRaisesRegex(SystemExit, "DEMO_IMAGE_PRODUCT_UNLABELED"):
                CONFIG.image_product_identity("podman", "demo-v2")

    def test_release_labels_satisfy_the_image_reader_when_metadata_uses_the_tag(self):
        full_sha = "ab" * 20
        metadata = "\n".join([
            "org.opencontainers.image.created=2026-11-16T00:00:00.000Z",
            "org.opencontainers.image.version=v0.2.0",
            "org.opencontainers.image.title=ramflux-gateway",
            f"org.opencontainers.image.revision={full_sha}",
            "org.opencontainers.image.source=https://github.com/ramfluxhq/ramflux",
        ])
        raw = CONFIG.label_assignments(metadata)
        version = "0.2.1"
        revision = "abcdef012345"
        produced = CONFIG.release_image_labels(metadata, version, revision)
        labels = CONFIG.label_assignments(produced)
        lines = produced.splitlines()
        self.assertEqual(lines[-2], f"org.opencontainers.image.version={version}")
        self.assertEqual(lines[-1], f"org.opencontainers.image.revision={revision}")
        self.assertEqual(
            [line for line in lines if line.startswith("org.opencontainers.image.version=")],
            [lines[-2]],
        )
        self.assertEqual(
            [line for line in lines if line.startswith("org.opencontainers.image.revision=")],
            [lines[-1]],
        )
        self.assertEqual(labels["org.opencontainers.image.title"], "ramflux-gateway")
        self.assertEqual(
            labels["org.opencontainers.image.source"],
            "https://github.com/ramfluxhq/ramflux",
        )
        self.assertNotIn("v0.2.0", produced)
        self.assertNotIn(full_sha, produced)
        self.assertNotIn(full_sha[:12], produced)

        def inspect(mapping):
            def run(command, **_kwargs):
                payload = json.dumps([{"Config": {"Labels": mapping}}])
                return subprocess.CompletedProcess(command, 0, payload, "")
            return run

        with mock.patch.object(CONFIG.subprocess, "run", side_effect=inspect(raw)), \
                mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "bbbbbbbbbbbb"}):
            with self.assertRaisesRegex(SystemExit, "DEMO_IMAGE_PRODUCT_INVALID"):
                CONFIG.image_product_identity("podman", "v0.2.0")

        with mock.patch.object(CONFIG.subprocess, "run", side_effect=inspect(labels)), \
                mock.patch.dict(os.environ, {"RAMFLUX_GIT_SHA": "bbbbbbbbbbbb"}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            CONFIG.image_product_identity("podman", "v0.2.0")
        self.assertEqual(
            output.getvalue(),
            f"RAMFLUX_EXPECTED_PRODUCT_VERSION={version}\n"
            f"RAMFLUX_EXPECTED_PRODUCT_SHA={revision}\n",
        )

        sneaky = metadata.replace(
            "org.opencontainers.image.version=v0.2.0",
            "org.opencontainers.image.version=9.9.9",
        )
        replaced = CONFIG.label_assignments(
            CONFIG.release_image_labels(sneaky, version, revision)
        )
        self.assertEqual(replaced["org.opencontainers.image.version"], version)

        with self.assertRaisesRegex(SystemExit, "numeric X.Y.Z"):
            CONFIG.release_image_labels(metadata, "v0.2.0", revision)
        with self.assertRaisesRegex(SystemExit, "12 lowercase"):
            CONFIG.release_image_labels(metadata, version, full_sha)
        with self.assertRaisesRegex(SystemExit, "12 lowercase"):
            CONFIG.release_image_labels(metadata, version, "unknown")

        repo = Path(__file__).resolve().parents[3]
        cli = subprocess.run(
            [
                sys.executable, str(HELPER), str(repo), str(repo),
                "release-image-labels", version, revision,
            ],
            input=metadata + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(cli.stdout, produced + "\n")

        workflow = (repo / ".github/workflows/release.yml").read_text(encoding="utf-8")
        image = workflow.split("image-release:", 1)[1]
        self.assertLess(image.index("id: meta"), image.index("id: product"))
        self.assertLess(image.index("id: product"), image.index("id: build"))
        self.assertIn("release-image-labels", image)
        self.assertIn("RAMFLUX_PRODUCT_VERSION=${{ steps.product.outputs.version }}", image)
        self.assertIn("RAMFLUX_PRODUCT_REVISION=${{ steps.product.outputs.revision }}", image)
        self.assertIn("labels: ${{ steps.product.outputs.labels }}", image)
        self.assertNotIn("labels: ${{ steps.meta.outputs.labels }}", image)


if __name__ == "__main__":
    unittest.main()
