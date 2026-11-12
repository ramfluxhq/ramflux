#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Summarize cargo-mutants 27.x outcomes, including incomplete advisory runs."""
import argparse
import html
import json
from pathlib import Path
import sys
import unittest


def safe(value):
    return html.escape(str(value)).replace("\n", " ")


def report(data, status, has_diff):
    lines = ["### Mutation report (advisory)", "",
             "Baseline skipped; compare with required test results for the same revision.", ""]
    if has_diff == "false":
        return "\n".join(lines + ["Empty Rust diff: no mutation candidates requested.", ""])
    if has_diff != "true":
        lines.append("**INCOMPLETE: diff preparation failed or did not run.**")
    if status in ("124", "137"):
        lines.append("**INCOMPLETE: wall-clock mutation budget exhausted.**")
    elif status == "not-run":
        lines.append("**INCOMPLETE: mutation command did not run (check setup).**")
    elif status != "0":
        lines.append("Mutation command exit status: " + safe(status))
    if data is None:
        return "\n".join(lines + ["**No outcomes.json; no coverage or success claimed.**", ""])
    if not isinstance(data, dict):
        raise ValueError("outcomes.json must be an object")
    counts = {key: data.get(key, 0) for key in ("caught", "missed", "unviable", "timeout")}
    if any(not isinstance(n, int) or n < 0 for n in counts.values()):
        raise ValueError("invalid outcome counts")
    lines.append("; ".join(f"{key}={value}" for key, value in counts.items()))
    if not data.get("end_time"):
        lines.append("**INCOMPLETE: results have no end_time; pending mutants are unknown.**")
    for outcome in data.get("outcomes", []):
        if outcome.get("summary") != "MissedMutant":
            continue
        mutant = outcome["scenario"]["Mutant"]
        line = mutant["span"]["start"]["line"]
        lines.append("- MISSED {}:{} — {}".format(
            safe(mutant["file"]), line, safe(mutant["name"])))
    return "\n".join(lines + [""])


class Tests(unittest.TestCase):
    def test_empty_diff(self):
        self.assertIn("Empty Rust diff", report(None, "not-run", "false"))

    def test_timeout_and_missing_results(self):
        text = report(None, "124", "true")
        self.assertIn("budget exhausted", text)
        self.assertIn("No outcomes.json", text)

    def test_surviving_mutant_location(self):
        data = {"caught": 2, "missed": 1, "unviable": 3, "timeout": 4,
                "end_time": "2026-11-12T00:00:00Z", "outcomes": [{
                    "summary": "MissedMutant", "scenario": {"Mutant": {
                        "file": "src/lib.rs", "name": "replace < with <=",
                        "span": {"start": {"line": 17, "column": 4}}}}}]}
        text = report(data, "2", "true")
        for part in ("caught=2", "missed=1", "unviable=3", "timeout=4", "src/lib.rs:17", "&lt;"):
            self.assertIn(part, text)

    def test_partial_results_and_setup_failure(self):
        self.assertIn("pending mutants are unknown", report({}, "124", "true"))
        self.assertIn("diff preparation failed", report(None, "not-run", "unknown"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--outcomes", type=Path, default=Path("mutants.out/outcomes.json"))
    parser.add_argument("--status", default="not-run")
    parser.add_argument("--has-diff", choices=("true", "false", "unknown"), default="unknown")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        data = json.loads(args.outcomes.read_text()) if args.outcomes.exists() else None
        print(report(data, args.status, args.has_diff))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("**MUTATION REPORT ERROR (incomplete): " + safe(error) + "**")
    return 0


if __name__ == "__main__":
    sys.exit(main())
