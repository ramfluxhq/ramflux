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
    (root / ".test-owners").touch(mode=0o600)
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
        output.write(f"RF_CI_TMPBASE={Path(base).resolve()}\n")
        for key in ("TMPDIR", "TMP", "TEMP", "RF_TEST_TMPDIR"):
            output.write(f"{key}={root}\n")


def restore_environment():
    # Restore before inspection/cleanup: privileged leftovers must not break post-job actions.
    if env_file := os.environ.get("GITHUB_ENV"):
        with Path(env_file).open("a", encoding="utf-8") as output:
            for key in ("TMPDIR", "TMP", "TEMP"):
                output.write(f"{key}={os.environ['RUNNER_TEMP']}\n")
            output.write("RF_TEST_TMPDIR=\n")


def owner_context(root, names):
    """Read bounded diagnostic records; ownership never changes the leak verdict."""
    found = {}
    try:
        with (root / ".test-owners").open("rb") as journal:
            remaining = 16 * 1024 * 1024
            for _ in range(100_000):
                if remaining <= 0:
                    break
                line = journal.readline(min(16 * 1024, remaining))
                if not line:
                    break
                remaining -= len(line)
                name, separator, owner = line.partition(b"\t")
                if separator and name.decode("utf-8", errors="replace") in names:
                    found[name.decode("utf-8", errors="replace")] = owner.decode("utf-8", errors="replace").strip()
    except FileNotFoundError:
        pass
    except OSError as error:
        print(f"::warning::test ownership diagnostics unavailable: {error}")
    return found


def check():
    root = Path(os.environ["RF_TEST_TMPDIR"])
    restore_environment()
    expected = Path(os.environ.get("RF_CI_TMPBASE") or os.environ["RUNNER_TEMP"]).resolve()
    if root.is_symlink() or root.parent.resolve() != expected or not root.name.startswith("rf-tests-"):
        print("::error::refusing cleanup outside the configured CI temporary base")
        return 1
    errors = []
    try:
        leaked = leftovers(root)
    except OSError as error:
        leaked = []
        errors.append((root, error))
    owners = owner_context(root, set(leaked)) if leaked else {}
    for name in leaked:
        print(f"::error::test temporary entry leaked: {name}")
        if name in owners:
            print(f"test allocation owner: {owners[name]}")
    print(f"TEST_TMP_LEAKS={len(leaked)}")

    def failed(_operation, path, exception):
        errors.append((Path(path), exception[1]))

    try:
        shutil.rmtree(root, onerror=failed)
    except OSError as error:
        errors.append((root, error))
    for path, error in errors:
        print(f"::error::temporary entry could not be inspected/removed: {path}: {error}")
    print(f"TEST_TMP_CLEANUP_ERRORS={len(errors)}")
    return int(bool(leaked or errors))


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
                with patch.dict(os.environ, {"RUNNER_TEMP": str(parent), "RF_CI_TMPBASE": "", "RF_TEST_TMPDIR": str(root), "GITHUB_ENV": ""}):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(check(), int(leaked))
                    self.assertIn(f"TEST_TMP_LEAKS={int(leaked)}", output.getvalue())
                self.assertFalse(root.exists(), "CI scratch must be removed after recording the verdict")

    def test_leak_owner_diagnostics_preserve_failure_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=parent))
            (root / "rf-leaked").mkdir()
            (root / ".test-owners").write_text('rf-leaked\t"tests::leaking_case" at fixture.rs:12:3\n')
            with patch.dict(os.environ, {"RUNNER_TEMP": str(parent), "RF_CI_TMPBASE": "", "RF_TEST_TMPDIR": str(root), "GITHUB_ENV": ""}):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(check(), 1)
            self.assertIn("tests::leaking_case", output.getvalue())
            self.assertIn("TEST_TMP_LEAKS=1", output.getvalue())
            self.assertFalse(root.exists(), "diagnostics must not bypass scratch cleanup")

    def test_initialize_assigns_all_platform_temp_variables(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            env_file = parent / "github-env"
            with patch.dict(os.environ, {"RUNNER_TEMP": str(parent), "GITHUB_ENV": str(env_file), "RF_CI_TMPBASE": ""}):
                initialize()
            assigned = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines())
            root = Path(assigned["RF_TEST_TMPDIR"])
            self.assertTrue(root.is_dir())
            self.assertEqual(root.parent, parent)
            for key in ("TMPDIR", "TMP", "TEMP"):
                self.assertEqual(assigned[key], str(root))
            assigned.update(RUNNER_TEMP=str(parent), GITHUB_ENV=str(env_file))
            with patch.dict(os.environ, assigned), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(check(), 0)
            self.assertFalse(root.exists())
            restored = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines())
            for key in ("TMPDIR", "TMP", "TEMP"):
                self.assertEqual(restored[key], str(parent), "post-job actions need an existing temp directory")
            self.assertEqual(restored["RF_TEST_TMPDIR"], "")

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "requires unprivileged POSIX permissions")
    def test_permission_failure_restores_environment_and_removes_accessible_files(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=parent))
            blocked = root / "ramflux-privileged"
            blocked.mkdir()
            (blocked / "owned-file").touch()
            (root / "rf-accessible").touch()
            env_file = parent / "github-env"
            blocked.chmod(0)
            try:
                with patch.dict(os.environ, {"RUNNER_TEMP": str(parent), "RF_CI_TMPBASE": "", "RF_TEST_TMPDIR": str(root), "GITHUB_ENV": str(env_file)}):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(check(), 1)
                self.assertIn("could not be inspected/removed", output.getvalue())
                self.assertFalse((root / "rf-accessible").exists())
                restored = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
                self.assertEqual(restored["TMPDIR"], str(parent))
                self.assertEqual(restored["RF_TEST_TMPDIR"], "")
            finally:
                blocked.chmod(0o700)

    def test_forged_recorded_parent_does_not_authorize_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=parent))
            with patch.dict(os.environ, {"RUNNER_TEMP": str(parent / "configured"), "RF_CI_TMPBASE": "", "RF_TEST_TMPBASE": str(parent), "RF_TEST_TMPDIR": str(root), "GITHUB_ENV": ""}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(check(), 1)
            self.assertTrue(root.exists(), "a recorded parent must not override the configured base")


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
