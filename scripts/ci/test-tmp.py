#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Give a CI test job its own temporary directory and reject leaked test roots."""
import argparse
import contextlib
import io
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


def leftovers(root):
    return sorted(p.name for p in root.iterdir() if p.name.startswith(("ramflux-", "rf-", "ramflux_")))


def initialize():
    base = os.environ.get("RF_CI_TMPBASE") or os.environ["RUNNER_TEMP"]
    root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=base))
    root = root.resolve()
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
        output.write(f"RF_TEST_TMPBASE={root.parent}\n")
        for key in ("TMPDIR", "TMP", "TEMP", "RF_TEST_TMPDIR"):
            output.write(f"{key}={root}\n")


def check():
    root = Path(os.environ["RF_TEST_TMPDIR"])
    leaked = leftovers(root)
    for name in leaked:
        print(f"::error::test temporary entry leaked: {name}")
    print(f"TEST_TMP_LEAKS={len(leaked)}")
    # Only remove the dedicated directory created by init, never arbitrary TMPDIR.
    if root.parent.resolve() != Path(os.environ["RF_TEST_TMPBASE"]).resolve() or not root.name.startswith("rf-tests-"):
        raise ValueError("refusing cleanup outside the private CI test directory")
    shutil.rmtree(root)
    return int(bool(leaked))


class Tests(unittest.TestCase):
    def test_files_directories_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ramflux-file").touch()
            (root / "rf-directory").mkdir()
            (root / "ramflux_transport_ca").mkdir()
            (root / "compiler-scratch").touch()
            self.assertEqual(leftovers(root), ["ramflux-file", "ramflux_transport_ca", "rf-directory"])
            if os.name != "nt":
                (root / "rf-link").symlink_to(root / "missing")
                self.assertIn("rf-link", leftovers(root))

    def test_guard_reports_leak_and_cleans_private_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for leaked in (False, True):
                root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=parent))
                if leaked:
                    (root / "ramflux-leaked").mkdir()
                with patch.dict(os.environ, {"RF_TEST_TMPBASE": str(parent), "RF_TEST_TMPDIR": str(root)}):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(check(), int(leaked))
                    self.assertIn(f"TEST_TMP_LEAKS={int(leaked)}", output.getvalue())
                self.assertFalse(root.exists(), "CI scratch must be removed after recording the verdict")

    def test_owned_directory_cleans_up_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                with tempfile.TemporaryDirectory(prefix="ramflux-", dir=root):
                    self.assertEqual(len(leftovers(root)), 1)
                    raise RuntimeError("test failure")
            except RuntimeError:
                pass
            self.assertEqual(leftovers(root), [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("init", "check", "self-test"))
    mode = parser.parse_args().mode
    if mode == "self-test":
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        return int(not result.wasSuccessful())
    if mode == "init":
        initialize()
        return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
