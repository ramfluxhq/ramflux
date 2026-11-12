<!-- SPDX-License-Identifier: BSD-3-Clause -->
# CI verification tooling

These checks run in GitHub Actions. They add no developer build or local gate.
The workflow keeps existing feature variants, ignored-test selections, archive
shards, and required test failures. Tooling self-tests run in Provenance.

## Existing guards

Provenance runs the envelope TTL constructor inventory and the production feature
guard's self-tests. Unclassified TTL constructors fail. The feature self-tests
exercise normal versus development dependency activation using small offline
Cargo dependency graphs, without compiling them.

## Retries and the watch list

The nextest `ci` profile retries once and prints flaky results. Its `heavy` group
allows one matching test at a time **per nextest invocation**, not across jobs or
shards. CLI e2e uses nextest with the original feature and ignored-test selection.
The shutdown profile inherits CI retry settings and keeps its timeout override.

`scripts/ci/run-nextest.py` removes stale JUnit, runs the command, immediately
reports retries, and copies JUnit to `junit-<label>.xml` before the next invocation.
It preserves the command's exit status. Each invocation writes to the job summary;
artifacts preserve individual variant results. The vault's private-user archive
invocations are reported by the parent process; direct libtest fixtures remain
libtest and do not acquire retries.

`.config/test-quarantine.toml` is a **watch list**, never a skip list. Entries need
`package`, exact nextest `name`, `owner`, `expires` (YYYY-MM-DD), and an `evidence`
link. Recovered tests show identity, attempt count, and the beginning of their
failure text. Unwatched flakes and expired entries are prominent, advisory
warnings. A persistent failure still fails the original required test job.

To renew a watch entry, investigate the failure, add current evidence, and review
a new expiry date. Remove it after the fix has demonstrated stable CI behavior.
Do not delete an entry to conceal a recurring flake. Expiry is inclusive through
that date in UTC. Missing/malformed JUnit is reported as missing evidence, not as
success. Hard job cancellation can prevent summary publication.

## Blocking timing guard

The independent hosted **Test timing guard** runs
`python3 -B scripts/ci/test-timing.py --check`. It reads first-party Rust under
`apps/` and `crates/`, including test directories, test functions, and external
modules reached through test cfg declarations. Other conditional test paths are
included conservatively; it does not evaluate target features or expand macros.

The scanner removes comments/literals, follows grouped/module/function-value
aliases in each source file, and recognizes sleep/timeout call syntax across
line breaks. It hashes normalized complete call expressions, including referenced
local constant initializers. `tokio::time` calls directly inside a
`#[tokio::test(start_paused = true)]` function are counted separately and allowed;
thread sleeps and unresolved timing calls in that function are not virtual time.
Helpers do not inherit a caller's paused-time exemption.

`.config/test-timing-allowlist.toml` temporarily covers existing sites, expiring
on 2026-12-12. Each entry binds `path`, enclosing `item`, expression SHA-256,
occurrence `count`, `owner`, `reason`, and `expires`. Added copies, renamed items,
changed expressions, missing exceptions, or expired entries fail CI. Deleting a
site is allowed; remove its obsolete exception too. Formatting alone is stable.

Prefer replacing wall-clock waits with explicit events or virtual time. For an
unavoidable real-process watchdog, review a narrow exception and expiry. The
`--seed` mode prints candidate TOML for comparison only: do not replace the entire
allow-list or extend every expiry to make a failing PR green. To renew, change the
individual entry with a concrete reason and owner; to remove, delete its row.

This is a bounded lexical guard, not a proof that all timing is virtual. Renamed
cross-file re-exports, arbitrary wrapper APIs, runtime duration calculations, and
macro expansions still require review. Because the full call is fingerprinted,
changes to a protected future may also need an exception update. Do not interpret
the allow-list as approval of every existing test design.

## Advisory mutation report

On PRs and manual dispatch, a separate hosted job runs pinned cargo-mutants on the
Rust merge-base diff, excluding vendor code. PRs check out the PR head; dispatch
uses the selected revision and `mutants_base`. The job has read-only permissions,
no stored checkout credentials, and never posts PR comments.

The job is non-blocking. Setup and mutation share an eight-minute budget inside
the ten-minute job, reserving time for reporting. Each mutant has a 120-second
timeout. The baseline is skipped, so read results alongside required tests for
the same revision; a partial run is not mutation coverage acceptance.
The job summary lists caught, missed, unviable, and timed-out counts plus missed
mutant file/line locations; `mutants-out` retains details. Empty diffs, setup
failures, missing results, and exhausted budgets are explicit. Do not turn this
job into a required check or treat its green conclusion as proof all mutants ran.
