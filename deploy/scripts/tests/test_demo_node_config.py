#!/usr/bin/env python3
"""Crash-safety tests for the demo snapshot transaction helper."""

import importlib.util
import json
import os
from pathlib import Path
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

    def test_legacy_snapshot_copy_failures_never_publish_the_transaction_marker(self):
        real_atomic = CONFIG.atomic_bytes
        for failure_at in range(1, 13):
            with self.subTest(failure_at=failure_at):
                snapshots = self.state / "version-snapshots"
                if snapshots.exists():
                    import shutil
                    shutil.rmtree(snapshots)
                (self.state / "owner.json.pending").unlink(missing_ok=True)
                (self.state / "transaction.pending").unlink(missing_ok=True)
                calls = 0

                def fail_copy(path, content, mode=0o600):
                    nonlocal calls
                    calls += 1
                    if calls == failure_at:
                        raise OSError("simulated disk full")
                    return real_atomic(path, content, mode)

                with mock.patch.dict(os.environ, self.settings, clear=False), \
                        mock.patch.object(CONFIG, "atomic_bytes", side_effect=fail_copy):
                    with self.assertRaises(OSError):
                        CONFIG.prepare(HELPER.parents[2], self.state, "upgrade")
                self.assertFalse((self.state / "transaction.pending").exists())
                self.assertFalse((self.state / "owner.json.pending").exists())

    def test_symlinked_snapshot_root_is_refused_without_writing_outside_state(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.state / "version-snapshots").symlink_to(outside, target_is_directory=True)
        with mock.patch.dict(os.environ, self.settings, clear=False):
            with self.assertRaisesRegex(CONFIG.SnapshotError, "symlinked"):
                CONFIG.prepare(HELPER.parents[2], self.state, "upgrade")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.state / "transaction.pending").exists())

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


if __name__ == "__main__":
    unittest.main()
