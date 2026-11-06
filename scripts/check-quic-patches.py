#!/usr/bin/env python3
"""Verify pinned QUIC source inventory, reviewed deltas and resolved package identity."""
import argparse
import hashlib
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "vendor/quic-provenance.json"
PINS = {
    "quinn": "0.11.11",
    "quinn-proto": "0.11.18",
    "bytes-1.12.0": "1.12.0",
    "bytes-1.11.1": "1.11.1",
}


def package_name(name):
    return "bytes" if name.startswith("bytes-") else name


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
            f"https://static.crates.io/crates/{package_name(name)}/{package_name(name)}-{version}.crate"
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
                license_id = "MIT" if package_name(name) == "bytes" else "MIT OR Apache-2.0"
                assert f"SPDX-License-Identifier: {license_id}" in (
                    "\n".join(path.read_text().splitlines()[:5])
                ), f"{name}/{rel}: upstream license missing"
                assert len(path.read_text().splitlines()) <= 5000, f"{rel}: file too long"
        for license_file in (("LICENSE",) if package_name(name) == "bytes" else ("LICENSE-MIT", "LICENSE-APACHE")):
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
    assert not any(
        p["id"] in metadata["workspace_members"] and p["name"] in {"bytes", "quinn", "quinn-proto"}
        for p in metadata["packages"]
    ), "vendored dependencies must not be workspace members"
    assert not any(p["name"] == "async-std" for p in metadata["packages"]), (
        "vendor-only dev dependencies leaked into product resolution"
    )
    ids = {}
    for name, version in (("quinn", PINS["quinn"]), ("quinn-proto", PINS["quinn-proto"]), ("bytes", "1.12.0")):
        packages = [p for p in metadata["packages"] if p["name"] == name]
        assert len(packages) == 1, f"{name}: duplicate or absent package"
        package = packages[0]
        assert package["version"] == version and package["source"] is None, (
            f"{name}: unpatched source/version"
        )
        assert Path(package["manifest_path"]).resolve() == (
            ROOT / "vendor" / ("bytes-1.12.0" if name == "bytes" else name) / "Cargo.toml"
        ).resolve(), f"{name}: wrong path"
        ids[name] = package["id"]
    for vendor in ("quinn", "quinn-proto"):
        graph = json.loads(subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path",
             str(ROOT / "vendor" / vendor / "Cargo.toml")],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout)
        packages = [p for p in graph["packages"] if p["name"] == "bytes"]
        assert len(packages) == 1 and packages[0]["version"] == "1.11.1", "vendor bytes pin drift"
        assert Path(packages[0]["manifest_path"]).resolve() == (ROOT / "vendor/bytes-1.11.1/Cargo.toml").resolve(), "vendor bytes patch bypassed"
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    assert "__control-test" not in nodes[ids["quinn-proto"]]["features"], (
        "dependency-test packet hooks leaked into product resolution"
    )
    # Includes the Linux optional graph even when this guard runs on another OS.
    consumers = [p for p in metadata["packages"] if p["name"] in ("quinn", "compio-quic")]
    assert {p["name"] for p in consumers} == {"quinn", "compio-quic"}
    for package in consumers:
        assert ids["quinn-proto"] in nodes[package["id"]]["dependencies"], (
            f"{package['name']}: proto patch bypassed"
        )


def verify_upstream(records, archive_dir=None):
    """Authenticate and extract registry archives, then check every original file."""
    cache = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/cache"
    for name, version in PINS.items():
        record = records[name]
        filename = f"{package_name(name)}-{version}.crate"
        if archive_dir is not None:
            archive = (archive_dir / filename).read_bytes()
        else:
            candidates = sorted(cache.glob(f"*/{filename}"))
            if candidates:
                archive = candidates[0].read_bytes()
            else:
                with urllib.request.urlopen(record["source"], timeout=30) as response:
                    archive = response.read(32 * 1024 * 1024 + 1)
        assert len(archive) <= 32 * 1024 * 1024, f"{name}: oversized archive"
        assert hashlib.sha256(archive).hexdigest() == record["archive_sha256"], (
            f"{name}: upstream archive checksum mismatch"
        )
        with tempfile.TemporaryDirectory(prefix="quic-upstream-") as directory:
            extracted = Path(directory)
            seen = set()
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
                for member in source.getmembers():
                    if member.isdir():
                        continue
                    assert member.isfile(), f"{name}: non-regular archive member"
                    rel = Path(member.name).relative_to(f"{package_name(name)}-{version}")
                    assert not rel.is_absolute() and ".." not in rel.parts, "unsafe archive path"
                    assert str(rel) not in seen, "duplicate archive file"
                    seen.add(str(rel))
                    target = extracted / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.extractfile(member).read())
            expected = {rel for rel, entry in record["files"].items() if "upstream_sha256" in entry}
            assert seen == expected, f"{name}: upstream inventory mismatch"
            for rel in sorted(seen):
                assert digest(extracted / rel) == record["files"][rel]["upstream_sha256"], (
                    f"{name}/{rel}: upstream file checksum mismatch"
                )
    print("QUIC upstream archives and original file hashes: OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources-only", action="store_true")
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--archive-dir", type=Path)
    args = parser.parse_args()
    records = json.loads(RECORD.read_text())
    check_sources(records)
    if args.verify_upstream:
        verify_upstream(records, args.archive_dir)
    if not args.sources_only:
        check_resolution()
    print("QUIC patch provenance and resolution: OK" if not args.sources_only
          else "QUIC patch source inventory: OK")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, OSError, ValueError, tarfile.TarError,
            subprocess.CalledProcessError) as error:
        print(f"QUIC patch check failed: {error}", file=sys.stderr)
        sys.exit(1)
