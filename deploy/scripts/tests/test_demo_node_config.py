#!/usr/bin/env python3
"""Crash-safety tests for the demo snapshot transaction helper."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
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
        self.assertEqual(CONFIG.workspace_product_version(repo / "Cargo.toml"), "0.2.0")
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


if __name__ == "__main__":
    unittest.main()
