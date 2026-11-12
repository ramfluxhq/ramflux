#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Capture each nextest invocation's JUnit before the next one overwrites it."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


def run(command, junit, label, summary):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", label):
        raise ValueError("label must be a simple artifact name")
    # A failed build/test invocation must never reuse another invocation's results.
    junit.unlink(missing_ok=True)
    snapshot = junit.with_name("junit-" + label + ".xml")
    snapshot.unlink(missing_ok=True)
    try:
        return subprocess.run(command, check=False).returncode
    finally:
        try:
            if junit.exists():
                shutil.copyfile(junit, snapshot)
            reporter = Path(__file__).with_name("report-flakes.py")
            args = [sys.executable, "-B", str(reporter), "--junit", str(junit), "--label", label]
            if summary:
                with Path(summary).open("a") as output:
                    subprocess.run(args, stdout=output, check=False)
            else:
                subprocess.run(args, check=False)
        except OSError as error:
            print("FLAKE REPORT ERROR: " + str(error), file=sys.stderr)


class Tests(unittest.TestCase):
    def test_exit_status_stale_results_and_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            junit, summary = root / "junit.xml", root / "summary.md"
            junit.write_text("stale")
            rc = run([sys.executable, "-c", "raise SystemExit(7)"], junit, "first", summary)
            self.assertEqual(rc, 7)
            self.assertFalse(junit.exists())
            self.assertIn("NO JUNIT", summary.read_text())
            command = [sys.executable, "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('<testsuite/>')", str(junit)]
            self.assertEqual(run(command, junit, "second", summary), 0)
            self.assertEqual((root / "junit-second.xml").read_text(), "<testsuite/>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--junit", type=Path, default=Path("target/nextest/ci/junit.xml"))
    parser.add_argument("--label", default="nextest")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a nextest command is required after --")
    try:
        result = run(command, args.junit, args.label, os.environ.get("GITHUB_STEP_SUMMARY"))
        return result if result >= 0 else 128 - result
    except (OSError, ValueError) as error:
        print("run-nextest: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
