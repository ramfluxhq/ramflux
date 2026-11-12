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
CLI `e2e_*` binaries, `linux_vault_*` proofs and the Linux vault writer test module
have `retries = 0`: a second attempt must not inherit leaked processes, ports or
provider state. Heavy-group scheduling still applies to these tests.

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
`apps/`, `crates/`, root `tests/`, and `tools/`. Test directories, test functions,
and modules gated by `cfg(test)` or positive `cfg(all(test, ...))` are test scope.
`cfg(any(..., test))`, `cfg(not(test))` and `cfg_attr` do not establish test-only
scope. External module declarations propagate only positive test-only scope.

The scanner resolves explicit, grouped, aliased and glob imports in lexical
scope, including `super::*` through declared inline and external modules. Local
functions/constructors shadow imported names. It recognizes calls to Tokio's
`sleep`, `sleep_until`, `timeout`, `timeout_at`; std thread `sleep`/`park_timeout`;
std `TcpStream::connect_timeout` and qualified receiver/Condvar timeout APIs.
The exact `.recv_timeout`, `.wait_timeout` and `.wait_timeout_while` method forms
are also covered without receiver-type inference. Project helpers ending in
`_timeout`, local `timeout()` constructors, and socket timeout setters are not
sites. Multiline and turbofish calls are supported.

Tokio timing calls in `#[tokio::test(start_paused = true)]` functions, or after a
resolved `tokio::time::pause()` in the same/enclosing lexical block, are counted
separately and allowed. A resolved `resume()` ends that exemption. Pausing inside
another branch/block does not exempt calls outside it; helper functions do not
inherit their caller's state. std thread/channel waits remain wall-clock calls.

Each allow-list identity is **path + resolved call kind + normalized duration or
deadline expression**, with a per-file occurrence count. The protected future,
receiver name and enclosing function/module/impl names are not part of the key.
Duration imports and referenced constants are normalized; formatting, moving a
call within a file, and renaming its function do not require exception changes.
Adding a call or changing its duration does. Receiver/Condvar APIs select their
actual duration argument, not the receiver/guard or predicate.

`.config/test-timing-allowlist.toml` binds each identity to an `owner`, `reason`
and inclusive UTC expiry. Initial top-level crate/app groups are staggered over
2026-12-12, 2026-12-19, 2026-12-26 and 2027-01-02; root tests form their own group.
CI rejects new/changed sites, expired entries, **stale rows** and excess counts.
When a site is removed, delete its row or reduce its count in the same PR.

Prefer explicit events or virtual time. For an unavoidable real-process
watchdog, review a narrow exception. Renew only the affected row with current
justification, owner and expiry; do not extend a whole weekly group. `--seed`
prints candidate TOML for review, not an instruction to overwrite the allow-list.
An explicit `--expires` changes candidate dates; it does not bypass validation.

This is a bounded source guard, not a Rust compiler or a proof of virtual time.
Function values (including passing `sleep` to another function or assigning a
timer to a variable), interval/interval_at-driven polling, `Instant::elapsed`
polling, arbitrary wrappers, generated code and macro expansion remain known
limits requiring review; no name-based heuristic attempts to infer them.
Runtime duration calculations are fingerprinted as expressions, not evaluated.
Unresolvable cross-crate re-exports and receiver types likewise need review.
The initial exception list does not endorse every existing test design.

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
