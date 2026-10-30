#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Refuse integration-only memory custody in the resolved production feature graph."""
import json
from pathlib import Path
import subprocess
import sys


def check(metadata):
    sdk_ids = {p["id"] for p in metadata["packages"] if p["name"] == "ramflux-sdk"}
    if not sdk_ids:
        raise ValueError("production graph has no SDK")
    nodes = [node for node in metadata["resolve"]["nodes"] if node["id"] in sdk_ids]
    if not nodes:
        raise ValueError("production graph has no resolved SDK node")
    for node in nodes:
        for feature in ("itest-memory-vault", "itest-legacy-accounts"):
            if feature in node["features"]:
                raise ValueError(f"production graph enables forbidden SDK {feature}")


def main():
    root = Path(__file__).resolve().parent.parent
    command = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if len(sys.argv) > 1:
        command += ["--features", sys.argv[1]]
    result = subprocess.run(command, cwd=root, check=True, capture_output=True, text=True)
    check(json.loads(result.stdout))
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
