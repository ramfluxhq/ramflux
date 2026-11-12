#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""CI guard: default rf and release SDK artifacts must omit the receive crash seam."""
import argparse
import json
import mmap
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN = (b"RAMFLUX_TEST_CRASH_AFTER_COMMITS", b"RECEIVE_CRASH commits=")


def check_artifact(path):
    with path.open("rb") as artifact:
        if os.fstat(artifact.fileno()).st_size == 0:
            raise ValueError(f"empty artifact cannot prove crash seam absence: {path}")
        with mmap.mmap(artifact.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for marker in FORBIDDEN:
                if data.find(marker) != -1:
                    raise ValueError(f"receive crash seam leaked into {path}: {marker.decode()}")


def build_artifacts(arguments, target):
    env = os.environ.copy()
    env.pop("RAMFLUX_ITEST_BUILD", None)
    env["RAMFLUX_PRODUCTION_BUILD"] = "1"
    result = subprocess.run(
        ["cargo", "build", "--locked", "--message-format=json-render-diagnostics", *arguments],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True, check=True,
    )
    paths = set()
    for line in result.stdout.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") != "compiler-artifact" or artifact["target"]["name"] != target:
            continue
        if artifact["profile"]["test"] or "itest-memory-vault" in artifact["features"]:
            raise ValueError(f"expected a default production artifact for {target}")
        if target == "rf":
            if artifact.get("executable"):
                paths.add(Path(artifact["executable"]))
        else:
            paths.update(Path(name) for name in artifact["filenames"]
                         if Path(name).suffix in {".rlib", ".a", ".so", ".dylib", ".dll", ".lib"})
    if not paths:
        raise ValueError(f"cargo produced no {target} artifact to check")
    return sorted(paths)


class AbsenceGuardTests(unittest.TestCase):
    def test_accepts_clean_and_rejects_each_crash_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact"
            artifact.write_bytes(b"\x7fELF production receive counters")
            check_artifact(artifact)
            for marker in FORBIDDEN:
                with self.subTest(marker=marker):
                    artifact.write_bytes(b"\x7fELF\x00" + marker + b"\x00")
                    with self.assertRaisesRegex(ValueError, "receive crash seam leaked"):
                        check_artifact(artifact)

    def test_missing_artifact_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                check_artifact(Path(directory) / "missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(AbsenceGuardTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    # Cargo's selected artifact paths honor custom target directories and target triples.
    for arguments, target in [
        (["-p", "ramflux-rf"], "rf"),
        (["--release", "-p", "ramflux-sdk", "--lib"], "ramflux_sdk"),
    ]:
        for artifact in build_artifacts(arguments, target):
            check_artifact(artifact)
            print(f"RECEIVE_CRASH_ABSENT: {target} {artifact}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
