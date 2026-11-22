#!/usr/bin/env python3
"""Run isolated deploy-tool regressions with bounded, independent workers."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

TESTS = Path(__file__).resolve().parent / "tests"
MODULES = ("test_demo_node", "test_demo_node_config", "test_demo_node_rendered_config",
           "test_provision_node")
WORKERS = 4
CASE_TIMEOUT_SECONDS = 300


def case_ids(suite):
    for entry in suite:
        if isinstance(entry, unittest.TestSuite):
            yield from case_ids(entry)
        else:
            yield entry.id()


def execute(case):
    try:
        result = subprocess.run([sys.executable, "-B", "-m", "unittest", case, "-v"],
                                cwd=TESTS, capture_output=True, text=True,
                                timeout=CASE_TIMEOUT_SECONDS)
        return case, result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return case, 1, f"case exceeded {CASE_TIMEOUT_SECONDS}s deadline"


def main():
    if not os.environ.get("DEMO_TEST_PODMAN_COMPOSE"):
        sys.exit("DEMO_TEST_PODMAN_COMPOSE must name the installed config renderer")
    sys.path.insert(0, str(TESTS))
    cases = list(case_ids(unittest.TestLoader().loadTestsFromNames(MODULES)))
    if not cases or len(cases) != len(set(cases)):
        sys.exit("deployment lifecycle discovery returned empty or duplicate cases")
    started = time.monotonic()
    failures = 0
    print(f"DEPLOY_LIFECYCLE_START cases={len(cases)} workers={WORKERS}", flush=True)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for done in as_completed([pool.submit(execute, case) for case in cases]):
            case, code, output = done.result()
            failures += bool(code)
            print(f'{"FAIL" if code else "PASS"} {case}', flush=True)
            if code:
                print(output, flush=True)
    print(f"DEPLOY_LIFECYCLE cases={len(cases)} passed={len(cases) - failures} "
          f"failed={failures} elapsed={time.monotonic() - started:.3f}s", flush=True)
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
