#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Refuse integration-only memory custody in the resolved production feature graph."""
import json
import re
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
            "ramflux-node-core": ("durability-test-hooks", "itest-http"),
            "ramflux-gateway": ("itest-http",),
            "ramflux-storage": ("durability-test-hooks",),
        }.get(name, ())
        for feature in forbidden:
            if feature in features:
                raise ValueError(f"production graph enables forbidden {name} {feature}")


def check_release_commands(text, file):
    # Fold shell continuations so feature flags on a following line are checked too.
    for command in text.replace("\\\n", " ").splitlines():
        if re.search(r"\b(?:cargo|cross)(?:\s+[^\s;]+)*?\s+(?:build|install|run)\b", command):
            if ("--release" in command or "--profile release" in command) and re.search(r"(?:-p|--package)\s+ramflux-sdk\b",command) and ("c-abi" in command or "card-runtime" in command) and "CARGO_PROFILE_RELEASE_PANIC=unwind" not in command:
                raise ValueError(f"SDK native C ABI release requires --profile ffi-release or CARGO_PROFILE_RELEASE_PANIC=unwind: {file}")
            if "itest-http" in command or "--all-features" in command:
                raise ValueError(f"test HTTP feature in release/deploy build command: {file}")


def self_test_release_commands():
    for command in (
        "cargo build --release -p ramflux-sdk --features c-abi",
        "cargo build --release --package ramflux-sdk --features card-runtime",
        "cargo build --release --features itest-http",
        "cargo install --path apps/ramflux-gateway --features itest-http",
        "cargo run --release --features ramflux-gateway/itest-http",
        "cross build --release --all-features",
        "cargo +stable build --release --all-features",
        "cargo $TC build --release " + "\\" + "\n --features ramflux-gateway/itest-http",
    ):
        try:
            check_release_commands(command, "fixture")
        except ValueError:
            continue
        raise ValueError("release command guard accepted a forbidden feature fixture")
    check_release_commands("cargo build --locked --release --workspace", "fixture")
    check_release_commands("cargo build --profile ffi-release -p ramflux-sdk --features c-abi", "fixture")
    check_release_commands("CARGO_PROFILE_RELEASE_PANIC=unwind cargo build --release -p ramflux-sdk --features card-runtime", "fixture")


def main():
    self_test_release_commands()
    if sys.argv[1:] == ["--self-test"]:
        print("release/deploy feature command guards: OK")
        return
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
        check_release_commands(text, file)
        if "RAMFLUX_PRODUCTION_BUILD=1 cargo build" not in text:
            raise ValueError(f"production build guard absent: {file}")
    check_release_commands((root / "deploy/scripts/build-prod-images.sh").read_text(), "production host build")
    core = (root / "crates/ramflux-node-core/src/lib.rs").read_text()
    if 'all(feature = "itest-http", any(ramflux_production, ramflux_release_profile))' not in core:
        raise ValueError("test HTTP release/production compile guard absent")
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
