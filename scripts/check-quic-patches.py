#!/usr/bin/env python3
"""Verify pinned QUIC source inventory, reviewed deltas and resolved package identity."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "vendor/quic-provenance.json"
PINS = {"quinn": "0.11.11", "quinn-proto": "0.11.18"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(base):
    return {
        str(p.relative_to(base)): p
        for p in base.rglob("*")
        if p.is_file() and "target" not in p.relative_to(base).parts
    }


def check_sources(records):
    assert set(records) == set(PINS), "unexpected pinned package set"
    for name, version in PINS.items():
        record = records[name]
        assert record["version"] == version, f"{name}: pin changed"
        assert len(record["archive_sha256"]) == 64, "missing archive identity"
        assert record["source"] == (
            f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        ), "unexpected source archive"
        base = ROOT / "vendor" / name
        actual = inventory(base)
        assert set(actual) == set(record["files"]), f"{name}: file inventory drift"
        for rel, path in actual.items():
            expected = record["files"][rel]
            assert digest(path) == expected["patched_sha256"], f"{name}/{rel}: checksum drift"
            changed = expected.get("upstream_sha256") != expected["patched_sha256"]
            assert bool(expected.get("delta")) == changed, f"{name}/{rel}: undeclared delta"
            if path.suffix == ".rs":
                assert "SPDX-License-Identifier: MIT OR Apache-2.0" in (
                    "\n".join(path.read_text().splitlines()[:5])
                ), f"{name}/{rel}: upstream license missing"
                assert len(path.read_text().splitlines()) <= 5000, f"{rel}: file too long"
        for license_file in ("LICENSE-MIT", "LICENSE-APACHE"):
            expected = record["files"][license_file]
            assert digest(base / license_file) == expected["upstream_sha256"], (
                f"{name}: upstream license changed"
            )


def check_resolution():
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    metadata = json.loads(result.stdout)
    ids = {}
    for name, version in PINS.items():
        packages = [p for p in metadata["packages"] if p["name"] == name]
        assert len(packages) == 1, f"{name}: duplicate or absent package"
        package = packages[0]
        assert package["version"] == version and package["source"] is None, (
            f"{name}: unpatched source/version"
        )
        assert Path(package["manifest_path"]).resolve() == (
            ROOT / "vendor" / name / "Cargo.toml"
        ).resolve(), f"{name}: wrong path"
        ids[name] = package["id"]
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    # Includes the Linux optional graph even when this guard runs on another OS.
    consumers = [p for p in metadata["packages"] if p["name"] in ("quinn", "compio-quic")]
    assert {p["name"] for p in consumers} == {"quinn", "compio-quic"}
    for package in consumers:
        assert ids["quinn-proto"] in nodes[package["id"]]["dependencies"], (
            f"{package['name']}: proto patch bypassed"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources-only", action="store_true")
    args = parser.parse_args()
    check_sources(json.loads(RECORD.read_text()))
    if not args.sources_only:
        check_resolution()
    print("QUIC patch provenance and resolution: OK" if not args.sources_only
          else "QUIC patch source inventory: OK")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, subprocess.CalledProcessError) as error:
        print(f"QUIC patch check failed: {error}", file=sys.stderr)
        sys.exit(1)
