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
The initial import changed only SPDX, idle-timeout extraction/no-growth and strict
lint adaptations. The subsequent opt-in packet/control changes are listed below;
no runtime certificate or activation follows.

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
to Rust sources, then apply each declared delta. Scoped later formatting commands and upstream
import/whitespace restoration are recorded in the provenance file. The provenance record also retains r1's exact
`cargo fmt --all` (pinned toolchain 1.99.0) command/config history, superseded by this restoration.
Do not run rustfmt on vendor sources. `vendor/rustfmt.toml` was removed because
its edition setting reintroduced import churn. Root `cargo fmt --all` excludes
these packages. Preserve pinned upstream formatting by hand; historical formatter
commands in provenance describe earlier states and are not current instructions.

When updating the patch, verify the base archive and all original hashes first,
then review/reapply every declared delta by responsibility. Never replace base
hashes with modified hashes. Preserve versions, licenses and code-size bounds;
run source/resolution/archive guards, scoped checks and named tests. Full
dependency suites run in PR CI. Invalidate affected source/config/layout
certificates. Census line citations refer to immutable upstream source, before
SPDX/extraction shifts. Missing runtime bounds continue to refuse activation.
The controller owns upstream reproducer/benchmark/issues/PR publication and
removes patches only after an audited upstream version reproduces all bounds.


## Dormant packet-control hooks

The opt-in endpoint reserves raw owner/source/global bytes and items from borrowed
socket scratch, before copying or enqueueing. The original invariant parser and
routing precedence are shared by the borrowed and owning paths. Incoming and
buffered Initial owners retain admission credit through acceptance and backing
release, including header/token backing. Ordinary controls have a separate lane;
local Close and latest rebind use fixed coalesced slots, with bounded close reasons.
Packet preflight reserves both ordinary directions before dedup/ACK/effects;
parked remainders keep the datagram owner and retry without replaying heads.
Metadata failure has a terminal RESOURCE_LIMIT adapter; the exhaustive allocation
hooks and certificates remain the later metadata work. Services enable none of
this before the remaining runtime/certificate/activation prerequisites.

The named dependency tests run real Quinn endpoint/connection drivers over a
bounded deterministic datagram socket, with driver and consumer barriers. They
cover independent owner/source/endpoint byte and item ceilings, pool-independent
copy/delivery counts, retained backing, sparse handle mapping and typed capacity
refusal. The card-named control test also runs the complete real-driver matrix
with binding 4096-byte/4-item limits: discarded head/valid tail, committed heads
with one parked tail and one credit wake, independent directional drain, full
forward/reverse credit, raw-input pause, duplicate/later retransmission, concurrent
CID timer, repeated-RETIRE oversize and terminal metadata-adapter propagation.
The proto packet tests cover the three packet outcomes across actual coalesced
TLS flights, aggregate directional ceilings and metadata terminal delivery.

Bounded admission maps protocol handles into a fixed owner-slot table; incoming
traffic has a separate owner. Exhausted owner/source arenas return typed refusal
classes. Credits surviving Drained prevent premature slot reuse. Control resume
reads credit generations, counts emitted versus reserved controls and uses current
runtime time. Receive bytes count each complete datagram once across head/tail
parking. Accounting follows `handle_decode` so a migrating datagram credits the
new path; an already-pending/closed early return credits the current path once. Eight-packet yield, control-first ordering, Close/Rebind coalescing and
idempotent endpoint close apply only with bounded admission enabled. Default
mode retains its FIFO event semantics; channel/bookkeeping layout still differs
from upstream and must be included in any later layout certificate.

The dependency-test matrix uses actual Tokio endpoint/connection futures and
socket ingress. Its non-default proto `__control-test` feature constructs encrypted
adversarial wire packets from negotiated keys and observes dedup/ACK membership,
frame counters and directional usage. Quinn's barriers and dequeue/waker witnesses
are `cfg(test)`. Synthetic packet numbers are not in the sending peer's sent map;
those cases retain receiver transmissions in bounded wire history while suppressing
delivery to that peer. Handshake recovery uses normal generated packets. The root
resolution guard rejects this feature in the product graph. Metadata coverage here
exercises the terminal adapter; exhaustive allocation-class hooks remain later work.
The single-wake test exposed a stale waiter on successful retry; consumed waiters
are disarmed, failed retries re-arm under the credit mutex and generation races
schedule a new poll after releasing that mutex.

The r3 review set adds the upstream migration and oversized-datagram path-change
tests. An unbound routed handle is an `InvalidOwner` invariant refusal, distinct
from an exhausted owner-slot arena. RETIRE retransmission/duplicate checks wait
for consumer drain and assert that local CID issuance remains unchanged.


## Dormant stateless response construction and ownership

`set_stateless_response_limits` freezes a separate endpoint pool and starts exactly
one retained sender. Where raw owner capacity is configured, neither configuration
order permits an effective response capacity above that owner limit. Response
builders reserve an item, a 65536-byte slab and 512 bytes of metadata allowance
before negotiation, Retry, reset, refusal or accept-failure output grows. Byte
limits may lower the item-derived ceiling; oversize/full output is suppressed with
fixed counters and no connection/control credit borrowing. Legacy constructors
and response paths keep their direct-send behavior until explicitly configured.

A pre-sized ring and one active datagram retain typed proto permits through socket
completion, send error or cancellation plus buffer drop. There is no response
spawn or unbounded completion list. The exported sender handle supports cancel,
join and queued/active/task diagnostics; endpoint close/destruction cancels it.
Join witnesses destruction of sender-owned responses. R4 still owns the enclosing
service scope and racing synchronous producers; no full teardown certificate or
activation is supplied here.

The exact stateless response test blocks the real socket write/poller with zero
accepted connections, separately floods negotiation, Retry and refusal, and binds
item and byte ceilings independently. It checks actual runtime spawn counts, full
slab/metadata ownership, fixed drop labels, zero-allocation oversize negotiation,
unblock/recovery and healthy TLS admission. It also fills the protocol owner arena
and exercises response refusal there without closing admitted peers, plus blocked
cancel/join and endpoint-drop destruction. CI requires all three exact raw/control/
response test names to be present in its standalone Quinn listing.

A parked migrating head now carries its uncredited datagram length in PendingPacket.
Only resume after path selection charges those bytes; repeated shortage transfers
the length without accounting, and already-counted tails carry zero. The bounded
migration regression asserts new-path anti-amplification credit and exactly-once
accounting. The final requested upstream blank line in tests/mod.rs is restored;
its sole added line over upstream is the mandatory SPDX header.
