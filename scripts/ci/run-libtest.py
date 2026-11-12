#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Run existing serial libtest commands and capture their results as JUnit."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


def junit(output, status):
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
    cases = re.findall(r"(?:^|\n)test (\S+) \.\.\. (ok|FAILED|ignored)\b", clean)
    summaries = re.findall(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", clean
    )
    totals = tuple(sum(int(row[i]) for row in summaries) for i in range(3))
    observed = tuple(sum(state == value for _, state in cases) for value in ("ok", "FAILED", "ignored"))
    suite = ET.Element("testsuite", name="vault-secret-service")
    for name, state in cases:
        case = ET.SubElement(suite, "testcase", classname="libtest", name=name)
        if state == "FAILED":
            ET.SubElement(case, "failure").text = clean
        elif state == "ignored":
            ET.SubElement(case, "skipped")
    valid = bool(cases) and bool(summaries) and totals == observed
    if not valid or (status and not observed[1]):
        case = ET.SubElement(suite, "testcase", classname="capture", name="command-completed")
        ET.SubElement(case, "failure").text = f"exit={status}, summary={totals}, captured={observed}\n{clean}"
    suite.set("tests", str(len(suite)))
    suite.set("failures", str(sum(case.find("failure") is not None for case in suite)))
    suite.set("skipped", str(observed[2]))
    return suite, valid


def run(command, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    output = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as child:
        for line in child.stdout:
            print(line, end="", flush=True)
            output.append(line)
        status = child.wait()
    suite, valid = junit("".join(output), status)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
    return (status if status >= 0 else 128 - status) or (0 if valid else 1)


class Tests(unittest.TestCase):
    def test_multiple_binaries_and_repeated_names(self):
        text = "test a::one ... ok\ntest b ... ignored\ntest result: ok. 1 passed; 0 failed; 1 ignored;\n"
        suite, valid = junit(text + text, 0)
        self.assertTrue(valid)
        self.assertEqual(suite.get("tests"), "4")

    def test_missing_partial_and_command_failure(self):
        for text in ("", "test a ... ok\n", "test a ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored;"):
            suite, valid = junit(text, 0)
            self.assertFalse(valid)
            self.assertEqual(suite.get("failures"), "1")
        suite, valid = junit("test a ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;", 7)
        self.assertTrue(valid)
        self.assertEqual(suite.get("failures"), "1")

    def test_failed_test(self):
        suite, valid = junit("test a ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;", 101)
        self.assertTrue(valid)
        self.assertEqual(suite.get("failures"), "1")

    def test_process_status_and_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "junit.xml"
            path.write_text("stale")
            self.assertEqual(run([sys.executable, "-c", "raise SystemExit(7)"], path), 7)
            self.assertEqual(ET.parse(path).getroot().get("failures"), "1")
            self.assertEqual(run([sys.executable, "-c", "print('no tests')"], path), 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--junit", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        return 0 if result.wasSuccessful() else 1
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.junit is None or not command:
        parser.error("--junit and a command after -- are required")
    return run(command, args.junit)


if __name__ == "__main__":
    sys.exit(main())
