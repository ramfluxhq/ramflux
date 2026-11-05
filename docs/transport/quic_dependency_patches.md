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


Sender cancellation seals response construction. Requests received during endpoint
drain are counted as `stateless_response_closed`, separately from capacity-full
drops. Whether teardown should suppress responses or retain drain-time refusals
is an R4 service-scope policy decision; this hook exposes the distinction without
changing that policy. The response test also counts actual delivered wire datagrams
independently of response permits and requires exactly the reserved capacity after
unblocking each negotiation/Retry/refusal case.


## Partial metadata hooks: no activation or certificate

The shared metadata ledger reserves `align_up(capacity,64)+64` before actual backing
growth; old and new allocations overlap until the old backing is destroyed. The
ledger is not doubled again and has no per-class item caps. Nine send-side allocation
classes now have dormant hooks: send-segment deque backing, STREAM frame metadata,
packet record tables/builders, boxed retransmit owners and their eight child
collections, pending retransmit storage/transfers, both send range sets, PendingAcks
and ACK/loss scratch.
Unique leases follow backing through packet retirement and owned iteration; empty
retained capacity stays charged. Default mode retains the upstream tree containers.

Bounded sent records use an ordered allocation-visible table with tombstone reuse.
Packet builders reserve table backing before header/packet-number effects. PendingAcks
preflights growth before dedup/ACK/effects, including transient insertion of the 65th
range and its retained spare capacity. ACK/loss scratch propagates fallible growth;
metadata terminal close emits no ACK for refused processing. Bounded send deques
retain charged backing instead of invoking an untracked shrink allocation. Bounded
send ACK/retransmit ranges use allocation-visible arrays; refused growth returns
through ACK/loss processing to terminal close before later frames are processed.

Dependency tests use real Tokio drivers, actual capacities/packet numbers/source/
payload/wire observations and peer RESOURCE_LIMIT errors. Test-only ceiling freezes
at actual live charges force specific allocation attempts without fake allocation
owners or class item caps. The send-ACK range case injects encrypted ACKs for actual
STREAM packet numbers, observes two disjoint committed ranges and refusal of the
third, then Close/Drained and retained-owner release. Range units compare the upstream
tree's union/order and check both range sets sharing one credit and actual capacity.

Three receive classes remain unimplemented: STREAM receive assemblers, CRYPTO
receive assemblers and unordered receive history. Full receive per-packet preflight,
mixed exhaustion/waiter matrix, production writer, supported envelope and allocation
certificates belong to the next PR. Production metadata configuration remains absent;
only the rejected-from-product `__control-test` feature instantiates these dormant
hooks. No startup certificate, activation or profile arithmetic changes.

The send-only dependency oracle is
`rawq_tests::send_metadata_credit_covers_allocation_families`. The optional
retransmit owner remains one thin pointer in a packet record. Its actual box and
all eight allocating child collections are reserved before growth. Bounded set
storage uses an allocation-visible vector with duplicate suppression; default mode
retains the upstream hash set. Destination transfer capacity is reserved while the
source box and child allocations remain charged. Owned iterators retain backing
credit after dequeue; destroying the actual allocation returns its lease. Fallible
producers/builders/loss/PTO/Retry and public/drop reset/stop paths stop on failure.

The real Tokio oracle covers box/child refusal before RESET reaches the peer,
pending-producer and receiver-drop refusal, and refused plus healthy PTO transfers
with actual capacity, wire counts, ACK and destruction observations. Dependency units
exercise all eight children in both owner/pending roles, exact-full/refused growth,
box layout, source/destination overlap and owned iterator release. Protocol tests
cover all three packet-space builder boundaries and transfers, key discard, a real
Retry handshake and peer APPLICATION_ERROR conversion without ordinary CRYPTO.
The original `metadata_credit_exhaustion_propagates_resource_limit` remains the
next PR's complete twelve-class receive/mixed/handshake/waiter matrix ownership.


### Send-metadata fixture ordering and committed ownership

The disjoint send-ACK range fixture discards ordinary peer transmissions at the
in-memory socket send boundary while admitting its controlled ACK injections.
Clearing queued datagrams alone did not exclude a later cumulative ACK from the
peer driver. A regression explicitly schedules that late ordinary ACK after each
controlled ACK and checks actual wire delivery remains unchanged. Wait failures
report the originating condition location; wait durations and protocol recovery
parameters are unchanged.

PTO transfer now reserves from a borrowed sent owner before taking it, so refusal
retains the committed box and children. Packet-populate refusal truncates only the
current unfinished packet, returns any completed datagram prefix with the correct
GSO count, and sends terminal close on the next poll. Focused protocol tests assert
actual retained owners and completed prefix bytes/records independently of credit
counters. The earlier loss/retransmit module relocations are cohesive responsibility
extractions; their upstream source/deltas remain explicitly recorded.
