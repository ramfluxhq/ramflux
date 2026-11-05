#!/usr/bin/env python3
"""CI-only full library tests for patched dependencies, rejecting empty selections."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

for package in ("quinn", "quinn-proto"):
    command = [
        "cargo", "test", "--locked", "--manifest-path",
        str(ROOT / "vendor" / package / "Cargo.toml"), "--lib",
    ]
    listing = subprocess.run(
        command + ["--", "--list"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    )
    tests = [line[:-6] for line in listing.stdout.splitlines() if line.endswith(": test")]
    if not tests:
        raise SystemExit(f"{package}: zero library tests selected")
    print(f"{package}: {len(tests)} library tests selected", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)
