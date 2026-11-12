#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Prove that replacing recovered W0 with an enriched Resume copy breaks real CLI recovery."""
import argparse
import os
from pathlib import Path
import subprocess


def run(command, path):
    with path.open("w") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=False)
    return result.returncode, path.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", required=True, type=Path)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    os.chdir(Path(__file__).resolve().parents[4])
    source = Path("crates/ramflux-sdk/src/bus/connection_manager/receive_ledger.rs")
    original = source.read_bytes()
    anchor = b"let recovered = retries.remove(&entry_id(&entry));"
    if original.count(anchor) != 1:
        raise RuntimeError("recovered-input selection anchor is ambiguous")
    merge = Path("crates/ramflux-sdk/src/bus/sync_driver/source/w0.rs")
    merge_original = merge.read_bytes()
    merge_anchor = b"prepared.entry = entry;"
    if merge_original.count(merge_anchor) != 1:
        raise RuntimeError("durable packet merge anchor is ambiguous")
    build = ["cargo", "build", "-p", "ramflux-rf", "--features", "itest-memory-vault"]
    test = ["cargo", "nextest", "run", "--profile", "ci", "--no-tests=fail", "--retries", "0",
            "-p", "ramflux-rf", "--features", "itest-memory-vault", "--test", "e2e_resume",
            "-E", "test(b7_group_read_before_setup_ack_keeps_catchup_live)",
            "--run-ignored", "ignored-only", "--test-threads=1"]
    try:
        source.write_bytes(original.replace(anchor,
            b"let recovered = retries.remove(&entry_id(&entry)).filter(|_| false);"))
        merge.write_bytes(merge_original.replace(merge_anchor, b"let _ = (prepared, entry);"))
        code, _ = run(build, args.log_dir / "group-broken-build.log")
        if code:
            raise RuntimeError("broken receive path did not compile")
        code, log = run(test, args.log_dir / "group-broken-test.log")
        if not code or "receive stage conflict" not in log or "1 test run: 0 passed, 1 failed" not in log:
            raise RuntimeError("regression did not fail with the intended stage conflict")
        print("GROUP_RECOVERY_BTF_BROKEN: named regression failed with receive stage conflict", flush=True)
    finally:
        source.write_bytes(original)
        merge.write_bytes(merge_original)
        restored, _ = run(build, args.log_dir / "group-restored-build.log")
        if restored:
            raise RuntimeError("restored receive path failed to build")
    code, log = run(test, args.log_dir / "group-restored-test.log")
    if code or "1 test run: 1 passed" not in log:
        raise RuntimeError("restored regression did not pass in both storage modes")
    print("GROUP_RECOVERY_BTF_RESTORED: named regression passed in both storage modes", flush=True)


if __name__ == "__main__":
    main()
