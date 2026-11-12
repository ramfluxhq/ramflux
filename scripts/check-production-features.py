#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Refuse integration-only memory custody in the resolved production feature graph."""
import json
from pathlib import Path
import subprocess
import sys
import tomllib


def check(metadata):
    sdk_ids = {p["id"] for p in metadata["packages"] if p["name"] == "ramflux-sdk"}
    if not sdk_ids:
        raise ValueError("production graph has no SDK")
    nodes = [node for node in metadata["resolve"]["nodes"] if node["id"] in sdk_ids]
    if not nodes:
        raise ValueError("production graph has no resolved SDK node")
    for node in nodes:
        for feature in ("itest-memory-vault", "itest-legacy-accounts", "test-support"):
            if feature in node["features"]:
                raise ValueError(f"production graph enables forbidden SDK {feature}")


def check_tree(graph):
    for line in graph.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name = fields[0]
        # cargo tree puts optional source paths before the feature list.
        features = set(fields[-1].split(","))
        forbidden = {
            "ramflux-sdk": ("itest-memory-vault", "itest-legacy-accounts", "test-support"),
            "ramflux-node-core": ("durability-test-hooks",),
            "ramflux-storage": ("durability-test-hooks",),
        }.get(name, ())
        for feature in forbidden:
            if feature in features:
                raise ValueError(f"production graph enables forbidden {name} {feature}")


def main():
    root = Path(__file__).resolve().parent.parent
    # Each production binary gets its own normal/build graph. Dev feature
    # unification from cargo metadata is deliberately excluded here.
    for manifest in sorted((root / "apps").glob("*/Cargo.toml")):
        package = tomllib.loads(manifest.read_text())["package"]["name"]
        command = ["perl", "-e", "alarm 900; exec @ARGV", "cargo", "tree", "--locked",
                   "-p", package, "-e", "normal,build", "--prefix", "none", "-f", "{p} {f}"]
        if len(sys.argv) > 1:
            command += ["--features", sys.argv[1]]
        result = subprocess.run(command, cwd=root, check=True, capture_output=True, text=True)
        check_tree(result.stdout)
    for file in (root / ".github/workflows/release.yml", root / "deploy/Dockerfile"):
        text = file.read_text()
        if "RAMFLUX_PRODUCTION_BUILD=1 cargo build" not in text:
            raise ValueError(f"production build guard absent: {file}")
    sdk_root = (root / "crates/ramflux-sdk/src/lib.rs").read_text()
    for guard in (
        'all(feature = "itest-memory-vault", ramflux_production)',
        'all(feature = "itest-memory-vault", ramflux_release_profile)',
    ):
        if guard not in sdk_root:
            raise ValueError(f"memory-vault build guard absent: {guard}")
    for file in (
        root / "crates/ramflux-sdk/src/bus/dispatch/mod.rs",
        root / "crates/ramflux-sdk/src/bus/daemon.rs",
    ):
        dispatch = file.read_text()
        for guard in (
            'feature = "itest-memory-vault"',
            "ramflux_itest",
            "not(ramflux_release_profile)",
            "not(ramflux_production)",
        ):
            if guard not in dispatch:
                raise ValueError(f"migration approval dispatch guard absent in {file}: {guard}")
    print("production feature provenance: OK")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
