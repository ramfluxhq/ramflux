#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Report nextest JUnit retries without changing the test command's result."""
import argparse
from datetime import date, datetime, timezone
import html
from pathlib import Path
import sys
import tomllib
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]


def safe(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ")


def watch_entries(data, today):
    entries, warnings = {}, []
    for row in data.get("test", []):
        key = (row["package"], row["name"])
        if key in entries:
            raise ValueError("duplicate watch entry: " + repr(key))
        for field in ("package", "name", "owner", "expires", "evidence"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise ValueError("watch entry requires " + field)
        expiry = date.fromisoformat(row["expires"])
        entries[key] = row
        if expiry < today:
            warnings.append("EXPIRED WATCH: {} / {} (owner {}, expired {})".format(
                *key, row["owner"], expiry))
    return entries, warnings


def report(xml, watch, today, label):
    entries, warnings = watch_entries(watch, today)
    lines = ["### Test retries: " + safe(label), "",
             "Advisory watch list only; persistent failures remain test failures.", ""]
    lines += ["**" + safe(warning) + "**" for warning in warnings]
    root = ET.fromstring(xml)
    flaky = failed = 0
    for case in root.iter("testcase"):
        children = list(case)
        retries = [e for e in children if e.tag in (
            "flakyFailure", "flakyError", "rerunFailure", "rerunError")]
        terminal = [e for e in children if e.tag in ("failure", "error")]
        if not retries and not terminal:
            continue
        identity = case.get("classname", "unknown")
        # nextest uses package or package::binary as classname.
        package = identity.split("::", 1)[0]
        name = case.get("name", "unknown")
        entry = entries.get((package, name))
        if terminal:
            status = "PERSISTENT FAILURE"
            failed += 1
        else:
            flaky += 1
            status = "FLAKY — WATCHED" if entry else "FLAKY — UNWATCHED"
        if entry and date.fromisoformat(entry["expires"]) < today:
            status += " — EXPIRED WATCH"
        attempts = 1 + len(retries)
        failure = (terminal + retries)[0]
        head = " ".join("".join(failure.itertext()).split())[:300]
        lines.append("- **{}**: {} / {}; attempts={}; {}".format(
            safe(status), safe(identity), safe(name), attempts, safe(head)))
    lines += ["", f"Recovered flaky tests: {flaky}; persistent failures: {failed}.", ""]
    return "\n".join(lines)


class Tests(unittest.TestCase):
    def setUp(self):
        self.today = date(2026, 11, 12)
        self.watch = {"test": [{"package": "sdk", "name": "test", "owner": "sdk",
                                "expires": "2026-11-26", "evidence": "run/1"}]}

    def test_flaky_junit_identity_attempts_and_text(self):
        xml = '<testsuites><testsuite><testcase classname="sdk::unit" name="test"><flakyFailure>first failure</flakyFailure></testcase></testsuite></testsuites>'
        output = report(xml, self.watch, self.today, "fixture")
        for text in ("FLAKY — WATCHED", "sdk::unit / test", "attempts=2", "first failure"):
            self.assertIn(text, output)

    def test_unwatched_and_expired_are_loud(self):
        self.watch["test"][0]["expires"] = "2026-11-11"
        xml = '<testsuite><testcase classname="other" name="test"><flakyError>oops</flakyError></testcase></testsuite>'
        output = report(xml, self.watch, self.today, "fixture")
        self.assertIn("EXPIRED WATCH", output)
        self.assertIn("UNWATCHED", output)

    def test_rerun_failure_is_not_recovered(self):
        xml = '<testsuite><testcase classname="sdk" name="test"><failure>bad</failure><rerunFailure>still bad</rerunFailure></testcase></testsuite>'
        output = report(xml, self.watch, self.today, "fixture")
        self.assertIn("PERSISTENT FAILURE", output)
        self.assertIn("attempts=2", output)
        self.assertIn("Recovered flaky tests: 0", output)

    def test_missing_metadata_and_escaping(self):
        self.watch["test"][0]["owner"] = ""
        with self.assertRaises(ValueError):
            watch_entries(self.watch, self.today)
        self.assertNotIn("<script>", safe("<script>|\n"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--label", default="nextest")
    parser.add_argument("--watch", type=Path, default=ROOT / ".config/test-quarantine.toml")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.junit is None:
        parser.error("--junit is required")
    # Reporting errors are visible, but never replace the nextest exit status.
    try:
        watch = tomllib.loads(args.watch.read_text())
        today = datetime.now(timezone.utc).date()
        if not args.junit.is_file():
            _, warnings = watch_entries(watch, today)
            print("### Test retries: " + safe(args.label))
            print("**NO JUNIT: invocation did not produce results; not a passing test run.**")
            for warning in warnings:
                print("**" + safe(warning) + "**")
        else:
            print(report(args.junit.read_text(), watch, today, args.label))
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print("**FLAKE REPORT ERROR: " + safe(error) + "**")
    return 0


if __name__ == "__main__":
    sys.exit(main())
