#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Calibrate B1 against real gateway compatibility negotiation, then restore exactly."""
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
    source = Path("apps/ramflux-gateway/src/session_push.rs")
    original = source.read_bytes()
    anchor = b"    let capable = context.hub.readiness.supports()"
    if original.count(anchor) != 1:
        raise RuntimeError("production negotiation anchor is ambiguous")
    test = ["cargo", "test", "-p", "ramflux-rf", "--features", "itest-memory-vault",
            "--test", "e2e_boot_dm", "b1_same_node_bidirectional_dm_uses_deliver_without_resume",
            "--", "--ignored", "--nocapture"]
    build = ["cargo", "build", "-p", "ramflux-gateway"]
    code, _ = run(["cargo", "build", "-p", "ramflux-rf", "--no-default-features"],
                  args.log_dir / "default-build.log")
    if code:
        raise RuntimeError("default rf build failed")
    binary = Path(os.environ["CARGO_TARGET_DIR"]) / "debug/rf"
    if b"RAMFLUX_TEST_CRASH_AFTER_COMMITS" in binary.read_bytes():
        raise RuntimeError("test crash environment lookup leaked into the default binary")
    print("DEFAULT_CRASH_FAILPOINT_ABSENT", flush=True)
    try:
        source.write_bytes(original.replace(anchor, b"    let capable = false && context.hub.readiness.supports()"))
        code, _ = run(build, args.log_dir / "disabled-build.log")
        if code:
            raise RuntimeError("disabled gateway failed to compile; no behavioral proof")
        code, log = run(test, args.log_dir / "disabled-test.log")
        if not code or "B1 must receive Deliver frames" not in log or "running 1 test" not in log:
            raise RuntimeError("disabled push did not fail the intended real-process B1 assertion")
        print("BTF_PUSH_DISABLED: intended Deliver assertion failed (1 test executed)", flush=True)
    finally:
        source.write_bytes(original)
        restored, _ = run(build, args.log_dir / "restored-build.log")
        if restored:
            raise RuntimeError("restored gateway failed to compile")
    code, log = run(test, args.log_dir / "restored-test.log")
    if code or "test result: ok. 1 passed" not in log:
        raise RuntimeError("restored B1 did not pass with one executed test")
    print("BTF_PUSH_RESTORED: B1 passed (1 test executed)", flush=True)


if __name__ == "__main__":
    main()
