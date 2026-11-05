#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Exercise production-graph checking without dev feature unification."""
import importlib.util
from pathlib import Path
import unittest
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("production_features", Path(__file__).with_name("check-production-features.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ProductionFeatures(unittest.TestCase):
    def test_ordinary_graph(self):
        checker.check_tree("ramflux-node-core v0.1.0 (/src/core) default\nramflux-sdk v0.1.0 default")

    def graph_fixture(self, kind):
        with tempfile.TemporaryDirectory(prefix="production-feature-fixture-") as directory:
            root = Path(directory)
            (root / "core/src").mkdir(parents=True)
            (root / "app/src").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["core", "app"]\nresolver = "3"\n')
            (root / "core/Cargo.toml").write_text('[package]\nname = "ramflux-node-core"\nversion = "0.0.0"\nedition = "2024"\n[features]\ndurability-test-hooks = []\n')
            (root / "core/src/lib.rs").write_text("")
            dependency = 'ramflux-node-core = { path = "../core"' + (', features = ["durability-test-hooks"]' if kind == "normal" else '') + ' }\n'
            manifest = '[package]\nname = "fixture-app"\nversion = "0.0.0"\nedition = "2024"\n[dependencies]\n' + dependency
            if kind == "dev":
                manifest += '[dev-dependencies]\nramflux-node-core = { path = "../core", features = ["durability-test-hooks"] }\n'
            (root / "app/Cargo.toml").write_text(manifest)
            (root / "app/src/main.rs").write_text("fn main() {}")
            return subprocess.run(["perl", "-e", "alarm 900; exec @ARGV", "cargo", "tree", "--offline", "-p", "fixture-app", "-e", "normal,build", "--prefix", "none", "-f", "{p} {f}"], cwd=root, text=True, capture_output=True, check=True).stdout

    def test_dev_dependency_activation(self):
        checker.check_tree(self.graph_fixture("dev"))

    def test_normal_dependency_activation(self):
        with self.assertRaisesRegex(ValueError, "production graph enables forbidden ramflux-node-core durability-test-hooks"):
            checker.check_tree(self.graph_fixture("normal"))

    def test_ordinary_fixture(self):
        checker.check_tree(self.graph_fixture("ordinary"))

    def test_sdk_guard_remains(self):
        with self.assertRaisesRegex(ValueError, "itest-memory-vault"):
            checker.check_tree("ramflux-sdk v0.1.0 default,itest-memory-vault")


if __name__ == "__main__":
    unittest.main()
