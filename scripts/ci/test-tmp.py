#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Give a CI test job its own temporary directory and reject leaked test roots."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def leftovers(root):
    return sorted(p.name for p in root.iterdir() if p.name.startswith(("ramflux-", "rf-", "ramflux_")))


def run_attempt(command):
    """Keep retries separate; a killed wrapper cannot write the completion marker."""
    if not os.environ.get("RF_TEST_TMPDIR"):
        os.execvpe(command[0], command, os.environ)
    # Keep paths short: Unix-domain socket fixtures have a small pathname budget.
    attempts = Path(os.environ["RF_TEST_TMPDIR"]) / ".a"
    attempts.mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="a-", dir=attempts)).resolve()
    identity = {key: os.environ[key] for key in (
        "NEXTEST_RUN_ID", "NEXTEST_BINARY_ID", "NEXTEST_TEST_NAME", "NEXTEST_ATTEMPT",
        "NEXTEST_ATTEMPT_ID")}
    (root / ".identity").write_text(json.dumps(identity), encoding="utf-8")
    (root / ".test-owners").touch(mode=0o600)
    environment = dict(os.environ)
    for key in ("TMPDIR", "TMP", "TEMP", "RF_TEST_TMPDIR"):
        environment[key] = str(root)
    result = subprocess.run(command, env=environment, check=False).returncode
    # Persist before inspecting/cleaning: even a failed attempt that returned normally
    # must retain its real leaks if nextest subsequently retries it successfully.
    (root / ".completed").write_text(str(result), encoding="ascii")
    if not leftovers(root):
        shutil.rmtree(root)
    return result if result >= 0 else 128 - result


def attempt_leaks(root):
    """Incomplete attempt roots are interrupted, not evidence of failed TempDir drops."""
    attempts = root / ".a"
    if not attempts.exists() and not attempts.is_symlink():
        return [], 0
    if attempts.is_symlink() or not attempts.is_dir():
        raise ValueError("invalid attempt directory")
    leaked, interrupted = [], 0
    for attempt in sorted(attempts.iterdir()):
        if attempt.is_symlink() or not attempt.is_dir() or not attempt.name.startswith("a-"):
            raise ValueError("invalid attempt root: " + str(attempt))
        # Read only bounded metadata. Missing/corrupt identity is a guard error.
        with (attempt / ".identity").open("rb") as source:
            raw = source.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise ValueError("oversized attempt identity")
        identity = json.loads(raw)
        owner = "{} / {}; attempt={}; id={}".format(
            identity["NEXTEST_BINARY_ID"], identity["NEXTEST_TEST_NAME"],
            identity["NEXTEST_ATTEMPT"], identity["NEXTEST_ATTEMPT_ID"])
        names = leftovers(attempt)
        if not (attempt / ".completed").is_file():
            interrupted += 1
            print(f"::warning::interrupted test attempt temporary entries: {len(names)}; {owner}")
            for name in names:
                print(f"interrupted attempt temporary entry: {name}")
            continue
        owners = owner_context(attempt, set(names)) if names else {}
        for name in names:
            leaked.append(f"{attempt.name}/{name}")
            print(f"::error::test temporary entry leaked: {name}; {owner}")
            if name in owners:
                print(f"test allocation owner: {owners[name]}")
    return leaked, interrupted


def initialize():
    base = os.environ.get("RF_CI_TMPBASE") or os.environ["RUNNER_TEMP"]
    root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=base))
    root = root.resolve()
    (root / ".test-owners").touch(mode=0o600)
    (root / ".a").mkdir()
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
    try:
        attempt_entries, interrupted = attempt_leaks(root)
        leaked += attempt_entries
    except (OSError, ValueError, KeyError, TypeError) as error:
        interrupted = 0
        errors.append((root / ".a", error))
    print(f"TEST_TMP_INTERRUPTED_ATTEMPTS={interrupted}")
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
    def attempt(self, root, code, attempt=1, name="tests::same_name"):
        environment = dict(os.environ, RF_TEST_TMPDIR=str(root), NEXTEST_RUN_ID="run-1",
                           NEXTEST_BINARY_ID="sdk::unit", NEXTEST_TEST_NAME=name,
                           NEXTEST_ATTEMPT=str(attempt), NEXTEST_ATTEMPT_ID=f"run-1${name}${attempt}")
        return subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "attempt", "--",
                               sys.executable, "-c", code], env=environment, check=False,
                              capture_output=True, text=True, timeout=10)

    def verdict(self, root):
        with patch.dict(os.environ, {"RUNNER_TEMP": str(root.parent), "RF_CI_TMPBASE": "",
                                     "RF_TEST_TMPDIR": str(root), "GITHUB_ENV": ""}):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                result = check()
        return result, output.getvalue()

    def test_attempt_passes_exact_arguments_and_isolates_all_temp_variables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=directory))
            code = ("import os, pathlib; "
                    "values = [os.environ[k] for k in ('TMPDIR', 'TMP', 'TEMP', 'RF_TEST_TMPDIR')]; "
                    "assert len(set(values)) == 1; "
                    "assert pathlib.Path(values[0]).parent.name == '.a'; "
                    "print('child actually ran')")
            result = self.attempt(root, code)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("child actually ran", result.stdout)
            self.assertEqual(list((root / ".a").iterdir()), [])
            self.assertEqual(self.verdict(root)[0], 0)

    def test_completed_attempt_leaks_fail_even_after_clean_retry(self):
        for first_status in (0, 7):
            with self.subTest(first_status=first_status), tempfile.TemporaryDirectory() as directory:
                root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=directory))
                result = self.attempt(root, "import os, pathlib; "
                                      "(pathlib.Path(os.environ['TMPDIR']) / 'rf-leaked').mkdir(); "
                                      f"raise SystemExit({first_status})")
                self.assertEqual(result.returncode, first_status, result.stderr)
                self.assertEqual(self.attempt(root, "pass", attempt=2).returncode, 0)
                rc, output = self.verdict(root)
                self.assertEqual(rc, 1, output)
                self.assertIn("TEST_TMP_LEAKS=1", output)
                self.assertIn("attempt=1", output)
                self.assertIn("sdk::unit / tests::same_name", output)
                self.assertFalse(root.exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX signals")
    def test_killed_wrapper_then_clean_retry_warns_without_false_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=directory))
            # The child kills only its own wrapper after allocating scratch, then exits.
            # This exercises the same missing-completion path as nextest group termination.
            result = self.attempt(root, "import os, pathlib, signal; "
                                  "(pathlib.Path(os.environ['TMPDIR']) / 'rf-killed').mkdir(); "
                                  "os.kill(os.getppid(), signal.SIGKILL)")
            self.assertEqual(result.returncode, -9, result.stderr)
            self.assertEqual(self.attempt(root, "pass", attempt=2).returncode, 0)
            rc, output = self.verdict(root)
            self.assertEqual(rc, 0, output)
            self.assertIn("::warning::interrupted test attempt", output)
            self.assertIn("rf-killed", output)
            self.assertIn("TEST_TMP_INTERRUPTED_ATTEMPTS=1", output)
            self.assertIn("TEST_TMP_LEAKS=0", output)
            self.assertFalse(root.exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX signals")
    def test_killed_attempt_does_not_hide_leaking_successful_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=directory))
            result = self.attempt(root, "import os, signal; os.kill(os.getppid(), signal.SIGKILL)")
            self.assertEqual(result.returncode, -9, result.stderr)
            self.assertEqual(self.attempt(root, "import os, pathlib; "
                                         "(pathlib.Path(os.environ['TMPDIR']) / 'rf-real-leak').touch()",
                                         attempt=2).returncode, 0)
            rc, output = self.verdict(root)
            self.assertEqual(rc, 1, output)
            self.assertIn("TEST_TMP_INTERRUPTED_ATTEMPTS=1", output)
            self.assertIn("TEST_TMP_LEAKS=1", output)
            self.assertIn("attempt=2", output)

    def test_unmanaged_leak_still_fails_beside_interrupted_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=directory))
            self.assertEqual(self.attempt(root, "pass").returncode, 0)
            (root / "rf-unmanaged").touch()
            rc, output = self.verdict(root)
            self.assertEqual(rc, 1, output)
            self.assertIn("test temporary entry leaked: rf-unmanaged", output)

    def test_without_ci_temp_root_executes_child_and_preserves_exit(self):
        environment = dict(os.environ)
        environment.pop("RF_TEST_TMPDIR", None)
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "attempt", "--",
                                 sys.executable, "-c", "import sys; print(sys.argv[1]); sys.exit(7)",
                                 "an argument with spaces"], env=environment, check=False,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout.strip(), "an argument with spaces")

    def test_corrupt_attempt_identity_fails_and_still_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=directory))
            self.assertEqual(self.attempt(root, "import os, pathlib; "
                                         "(pathlib.Path(os.environ['TMPDIR']) / 'rf-leak').touch()").returncode, 0)
            attempt = next((root / ".a").iterdir())
            (attempt / ".identity").write_text("invalid json")
            rc, output = self.verdict(root)
            self.assertEqual(rc, 1, output)
            self.assertIn("TEST_TMP_CLEANUP_ERRORS=1", output)
            self.assertFalse(root.exists())

    def test_attempts_symlink_is_rejected_without_following_it(self):
        if os.name == "nt":
            self.skipTest("requires symlink privileges")
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = Path(tempfile.mkdtemp(prefix="rf-tests-", dir=parent))
            outside = parent / "outside"
            outside.mkdir()
            (outside / "rf-preserved").touch()
            (root / ".a").symlink_to(outside, target_is_directory=True)
            rc, output = self.verdict(root)
            self.assertEqual(rc, 1, output)
            self.assertIn("invalid attempt directory", output)
            self.assertTrue((outside / "rf-preserved").exists())

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
    parser.add_argument("mode", choices=("init", "check", "self-test", "attempt"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    mode = args.mode
    if mode == "attempt":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            parser.error("attempt requires a test command after --")
        return run_attempt(command)
    if mode == "self-test":
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        return int(not result.wasSuccessful())
    if mode == "init":
        initialize()
        return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
