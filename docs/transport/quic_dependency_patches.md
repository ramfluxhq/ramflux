# QUIC dependency patches

The product resolves exactly one local Quinn 0.11.11 and quinn-proto 0.11.18
through its root crates.io patch table. compio-quic uses the same proto patch.
Both vendor packages are excluded from product workspace membership with
`exclude = ["vendor/*"]`. They therefore retain the product's dependency
`opt-level = 3`; workspace clippy, doctests and nextest archives do not select
their own libraries/examples/dev dependencies. The mutants diff excludes
`vendor/**`. Dedicated dependency CI owns their library suites.

Each vendor manifest declares an isolated test workspace and carries a checked-in
lockfile. Quinn's standalone test workspace explicitly patches its sibling proto;
root patch tables would otherwise be ignored by a standalone manifest. The test
CI driver verifies the resolved local identities before listing a nonzero test
set and running the libraries. Root consumers and standalone tests are separate
Cargo graphs. Transport declares Tokio macros in its normal features because
production code uses `tokio::select!`, independently of test feature unification. The product lock/graph contains no async-std. Upstream async-std
remains only in Quinn's optional/test-workspace graph, so RUSTSEC-2025-0052 does
not require a product audit ignore; `.cargo/audit.toml` remains unchanged. These
dev-only graphs are not shipped in product artifacts.

`vendor/quic-provenance.json` records the registry archive URL/SHA-256, every
original file SHA-256, checked-in file SHA-256 and local delta reason. Added
files have no upstream hash. MIT and Apache-2.0 license texts and copyrights
remain unchanged. Rust files carry upstream SPDX. r2 restores upstream Rust
formatting/import ordering instead of applying product formatting to ~70 files.
Only the declared SPDX, idle-timeout extraction/no-growth and two strict-lint
adaptations remain. No protocol behavior changes or runtime certificates follow.

## Verification and maintenance

Run `python3 -B scripts/check-quic-patches.py --verify-upstream` to verify the
checked-in source inventory/deltas, locked unique resolution and original
archives. It reads Cargo's registry cache when available, otherwise downloads
the exact recorded crates.io URL; it verifies the archive SHA-256, extracts
regular files into a temporary directory and checks the complete original file
inventory and every `upstream_sha256`. `--archive-dir PATH` selects explicit
registry `.crate` files, including offline/corruption checks. `--sources-only`
skips Cargo graph resolution; it can be combined with `--verify-upstream`.
The dedicated PR CI job runs archive verification and the dependency libraries.

Product formatting command: `cargo +1.99.0 fmt --all`, with pinned toolchain
1.99.0 and `rustfmt 1.10.0-stable (b940084d7e 2026-09-28)`. Excluded vendor
sources are not bulk formatted. To reproduce r2 vendor source, extract the
verified upstream archive, prepend `// SPDX-License-Identifier: MIT OR Apache-2.0`
to Rust sources, then apply each declared semantic-free delta. There is no
vendor rustfmt command in r2. The provenance record also retains r1's exact
`cargo fmt --all` (pinned toolchain 1.99.0) command/config history, superseded by this restoration.
For newly changed vendor modules use the recorded pinned rustfmt version with
`rustfmt +1.99.0 --edition 2021 --config-path vendor/rustfmt.toml PATH`; record
that command and changed hashes rather than reformatting the whole dependency.

When updating the patch, verify the base archive and all original hashes first,
then review/reapply every declared delta by responsibility. Never replace base
hashes with modified hashes. Preserve versions, licenses and code-size bounds;
run source/resolution/archive guards, scoped checks and named tests. Full
dependency suites run in PR CI. Invalidate affected source/config/layout
certificates. Census line citations refer to immutable upstream source, before
SPDX/extraction shifts. Missing runtime bounds continue to refuse activation.
The controller owns upstream reproducer/benchmark/issues/PR publication and
removes patches only after an audited upstream version reproduces all bounds.
