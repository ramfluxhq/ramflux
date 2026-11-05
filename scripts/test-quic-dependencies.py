#!/usr/bin/env python3
"""CI-only full library tests for patched dependencies, rejecting empty selections."""
from pathlib import Path
import json
import argparse
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--list-only", action="store_true")
args = parser.parse_args()

for package in ("quinn", "quinn-proto"):
    command = [
        "cargo", "test", "--locked", "--manifest-path",
        str(ROOT / "vendor" / package / "Cargo.toml"), "--lib",
    ]
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--manifest-path", command[4],
        "--format-version", "1",
    ], cwd=ROOT, text=True))
    for name in (("quinn", "quinn-proto") if package == "quinn" else ("quinn-proto",)):
        resolved = [p for p in metadata["packages"] if p["name"] == name]
        if len(resolved) != 1 or resolved[0]["source"] is not None:
            raise SystemExit(f"{package}: unpatched/duplicate {name} in dependency tests")
        if Path(resolved[0]["manifest_path"]).resolve() != (ROOT / "vendor" / name / "Cargo.toml").resolve():
            raise SystemExit(f"{package}: incorrect local {name} path")
    listing = subprocess.run(
        command + ["--", "--list"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    )
    tests = [line[:-6] for line in listing.stdout.splitlines() if line.endswith(": test")]
    if not tests:
        raise SystemExit(f"{package}: zero library tests selected")
    if package == "quinn":
        required = {
            "rawq_tests::packet_credit_covers_enqueue_processing_and_backing_release",
            "rawq_tests::control_credit_preserves_cid_close_and_drained",
            "rawq_tests::stateless_responses_bound_allocations_and_sender_tasks",
        }
        if missing := required.difference(tests):
            raise SystemExit(f"{package}: missing required raw/control/response tests: {sorted(missing)}")
    print(f"{package}: {len(tests)} library tests selected", flush=True)
    if not args.list_only:
        subprocess.run(command, cwd=ROOT, check=True)
