# QUIC dependency patches

The workspace resolves exactly one local Quinn 0.11.11 and quinn-proto 0.11.18
through its root crates.io patch table. compio-quic retains its registry source
and uses the same patched proto. Default constructors preserve upstream behavior;
bounded policies remain dormant until their allocation certificates are complete.

`vendor/quic-provenance.json` records the immutable registry archive URL/SHA-256,
every original file SHA-256, each checked-in file SHA-256 and a reason for every
local delta. Newly added files have no upstream hash. The MIT and Apache-2.0
license texts and original copyright notices are retained verbatim. Rust files
carry the upstream SPDX license. Vendor formatting uses Rust 2021 conventions.

Run `python3 -B scripts/check-quic-patches.py` to check the exact file inventory,
checksums/delta declarations, licenses and resolved Cargo graph, including the
optional compio dependency. `--sources-only` performs no Cargo operation.
The guard rejects another registry/git copy even if its version matches.

Dependency library tests run explicitly in PR CI using each vendored manifest;
workspace consumer tests alone do not establish that dependency tests executed.
Named regression selections must list at least one test before execution.

## Updating the patch

1. Download the exact archive URL and verify its SHA-256 before extracting to
   a temporary directory. Compare original per-file hashes to the recorded base.
2. Reapply each declared delta and review the resulting source diff by
   responsibility, preserving upstream licenses and version identity. Regenerate
   only affected patched hashes/delta reasons; do not replace upstream hashes
   with modified source hashes. New upstream versions require an explicit pin
   and census/certificate review, rather than silently changing the baseline.
3. Run the source/locked-resolution guard, scoped changed-crate checks and owned
   named tests. PR CI runs full dependency library tests and consumer gates.
   Invalidate certificates whenever source/config/layout identity changes.
4. The controller owns upstream issues/PRs, reproducer and benchmark publication.
   Remove local patches only after an audited upstream version reproduces every
   allocation, queue, error propagation and destruction bound/test.

No runtime allocation certificate follows from importing the source or passing
the checksum guard. Missing bounds continue to refuse candidate startup.

Pinned line citations in the allocation census refer to the immutable upstream
archive, before SPDX/formatting or module extraction shifts lines. The delta
record identifies the checked-in locations. The idle-timeout extraction preserves
its existing tests; the build script emits the same `wasm_browser` condition
without the upstream macro's Rust 1.99 lint failure. Vendor clippy uses its
unchanged upstream MSRV (1.85), separate from the product workspace's MSRV.
