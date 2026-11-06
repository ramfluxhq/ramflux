# QUIC dependency patches

The product resolves exactly one local Quinn 0.11.11 and quinn-proto 0.11.18
through its root crates.io patch table. compio-quic uses the same proto patch.
The Quinn vendor packages are excluded from product workspace membership with
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
to Quinn Rust sources (MIT alone for Bytes), then apply each declared delta. Scoped later formatting commands and upstream
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

### Partial receive payload backing (PR1B-2a)

Dormant metadata mode admits an exact-capacity copy of decrypted packet payload
before allocating it. Only packets with nonempty STREAM or CRYPTO data use this
copy. All retained frame views, returned chunks, slices and Bytes clones share
that allocation and its raw-owner reference. Payload storage is destroyed before
its allocation charge returns; two STREAM frames in one packet do not pay twice.
Refused admission returns through the existing resource-close path before STREAM
frame effects. Default mode takes the unchanged raw-backed plaintext path.

This is the payload component only, not complete receive metadata enforcement.
The separately allocated Bytes owner/refcount envelope now uses the guarded
constructor described below; its allocation has separate admission and lifetime.
The partial receive classes remain uncertified.
Heap/descriptors and compaction copies have the separate hooks below. Unordered
history and whole-packet metadata transactions remain subsequent parts. No receipt of data, test counter or payload
lease is a certificate for those allocations, TLS residuals or a runtime profile.
The existing product-resolution guard is unchanged and metadata construction
remains test-only. Transport dependency probes will use an isolated dedicated
test crate; they will never enable diagnostic features in the product graph.

The real-driver test `rawq_tests::receive_backing_credit_follows_last_bytes_owner`
compares physical copy capacity with decrypted payload length observed at admission
before reservation/allocation. It checks exact peer data, two views retaining one
raw packet permit, held slices/clones across STOP_SENDING and received RESET_STREAM,
then Drained/public-handle destruction and final permit/charge release. A refused
input records its payload length but reaches no copy allocation or STREAM effect.
Allocation-site units exercise exact-full/refused capacity, split/cloned payloads
in both diagnostic families, and a real CRYPTO handshake through the same copy path.
Complete receive-class and whole-packet atomicity proofs remain unissued. The
component owner/assembler oracles below add no profile certificate or activation.


### Pinned Bytes after-free prerequisite

The product graph uses patched Bytes 1.12.0; the isolated Quinn library-test graphs
retain patched Bytes 1.11.1. Their registry archive and per-file original/patched
hashes use the same `vendor/quic-provenance.json` format as Quinn. The existing
provenance script verifies both identities and keeps diagnostic packet features
out of the ordinary product graph. Original MIT license files remain unchanged.

`Bytes::try_from_owner_with_guard` asks the caller to reserve the compiler's actual
wrapper Layout before its fallible allocation. Refusal preserves the input owner;
allocation failure releases the unused reservation. The unique guard lives outside
the Box during final destruction: payload owner destruction and actual wrapper
free complete before the guard returns credit, including constructor and owner
Drop unwinding. Existing `Bytes::from_owner` and its default behavior are unchanged.
Clones and slices share this allocation; `try_into_mut` preserves Err(self).
Forced Vec/BytesMut conversions copy before releasing the owner. Managed receive
paths must exclude them unless their copy overlap has separate admission.

The test-only counting allocator queries actual usable allocation sizes on Mac
System malloc and Linux System malloc, then pauses immediately before actual free.
A competing credit attempt must fail while that physical allocation is live. The
oracle also checks refusal, failed allocation, final clone/slice, constructor and
owner Drop panics, and conversions. Returning the guard before free fails it.
Those observations cover these test identities; they do not certify every allocator
or the eventual production owner layout. This prerequisite is not integrated into
receive backing and issues no receive/envelope certificate or activation.

A certified non-spendable per-connection allowance D must include any remaining
allocator excess. Checked profile arithmetic must rederive
`N = (b - E) / (2 * Unit_base + M_conn + D)`, require N >= 2, and independently check
`E + N * (2 * Unit_base + M_conn + D) <= b` plus aggregate slices within B. The hook
removes early-refund retirement overlap; this does not establish zero allocator
excess. Unknown source/layout/runtime/target/allocator identities refuse certificates.


### Partial receive owner envelope (PR1B-2b)

Dormant payload copies use `Bytes::try_from_owner_with_guard` with a separately
reserved AllocationCharge for the constructor's actual wrapper Layout. The guard
is outside the owner allocation during final destruction and returns only after
payload destruction and wrapper deallocation. Payload storage keeps its own charge;
raw ownership is additionally held by the after-free guard, so its permit also
survives wrapper deallocation. Clones, slices and Chunks
share one wrapper. No fixed wrapper-size estimate enters production admission.
Reservation/allocation refusal maps to the existing ResourceExhausted/terminal
adapter before STREAM effects; a refused wrapper destroys the temporary admitted
payload copy. Whole-packet class preflight remains a subsequent part.

The production-owner allocation-site test measures System allocator usable extents
for both actual payload and actual wrapper, retains them through completed free,
and blocks the final wrapper deallocator after payload destruction. Its concurrent
replacement reservation remains refused while the wrapper's credit is held. The
real-driver `receive_owner_metadata_survives_final_payload_drop` adds a limit one
byte short of payload+wrapper admission, independent pre-encryption payload length,
zero admitted STREAM effects and zero wrapper allocations; its positive case holds
shared Chunks/slices/clones across STOP_SENDING, RESET_STREAM and Drained. This is
owner-component evidence; it is not a receive-class,
allocator-profile or envelope certificate, and enables no production capability.


### Partial receive assembler allocation hooks (PR1B-2c)

Dormant STREAM and all three CRYPTO packet-space assemblers reserve actual receive
heap capacity before fallible allocation/growth. Replacement heaps retain old and
new leases together; converting the old heap to a sorted Vec reuses its allocation
and keeps its lease until that storage is destroyed. Clear/reinit preserve both
retained heap capacity and its charge, including reused receive owners.

Bounded compaction plans unique fragments without modifying the original buffers,
reserves a replacement heap, and fills one exact-capacity guarded payload copy
directly. Large well-utilized chunks keep their existing backing; small contiguous
fragments share slices of the copy. It creates no uncharged BytesMut split/header
or scratch copy. Original descriptors and payload owners remain live through all
replacement admission. Refusal restores the old heap, exact bytes and removed read
owner before the real Quinn adapter propagates terminal resource-close. The default
path keeps its upstream compaction behavior and thresholds.

`rawq_tests::receive_assemblers_charge_compaction_peaks` exercises actual unordered
read compaction, separately binding heap and copy limits, exact returned bytes and
physical descriptor capacities, plus held copied views through Drained. Units cover
both receive classes, three actual packet-space owners, replacement/copy/owner
refusal, retained reinit capacity, and mixed kept/copied/gapped/duplicate fragments.
Bypassing actual heap admission fails the named driver oracle. Unordered-history
allocations, whole-packet metadata preflight, complete waiter/exhaustion coverage,
executable profiles and allocator certificates remain later obligations. This
component enables no production profile or activation.


### Partial unordered receipt history hooks (PR1B-2d)

Dormant unordered receive history uses the existing fallible charged ArrayRangeSet;
the default path keeps the upstream B-tree and its intersection iterator. Storage
beyond the two inline ranges reserves actual replacement capacity before growth,
with old/new overlap and no independent item cap. Application chunk consumption
does not remove receipt ranges or refund their retained backing. Union/split and
empty-but-retained capacity keep the same actual storage charge until free/reinit.

The complete history transition is admitted before compaction or mode change; a
refused conversion preserves the ordered heap and removed receive owner. Incoming
deduplication reserves union growth before exposing intersections. The bounded
iterator reads those intersections without allocating a scratch list; its final
union uses the already admitted slot. Partial iterator Drop still commits the whole
union. Late conversion keeps the original tree until its successor is admitted.

`rawq_tests::unordered_history_credit_survives_chunk_consumption` observes actual
retained range capacity after chunks are consumed, refuses a third disjoint receipt
while admitting only its packet payload/wrapper, and checks consumed-byte duplicate
suppression under a fresh packet number plus later new data. It also verifies
transition refusal preserves the receive owner and ordered descriptors, then final
held-view lifetime through Drained. Test-only packet construction advances the peer
packet number so normal ACK validation remains valid. Units compare intersections
against the original tree and cover union/split, failed split/conversion, partial
iterator destruction, clear/reinit and fresh fragments between consumed ranges.

This completes the unordered-history hook component, not whole-packet transaction
or exhaustive cross-class/waiter proof. Those remain separate parts, as do runtime
profile enforcement, allocator certificates and activation/security gates.


The compaction driver oracle observes successful System allocator calls matching
the replacement heap's actual layout, outside metadata accounting. Its buffered
read is polled synchronously while the driver is gated, so unrelated tasks cannot
contribute observations. It checks zero actual replacement allocations on heap
refusal and one on copy refusal/success; the metadata allocation counter is not
its heap oracle. Actual descriptor capacity and returned bytes remain separate
observations. This test allocator is confined to the Quinn unit-test target.

Default-mode IllegalOrderedRead retains upstream behavior: the removed receive
owner is restored only when metadata admission is configured. A mode-paired unit
checks default closure and bounded-owner preservation independently.

Descriptor free-before-refund barrier tests for the old sorted compaction Vec and
old heap growth backing remain mandatory finite-evidence work. The source retains
those leases until destruction, but allocation-count/capacity tests alone do not
certify that temporal boundary. Production allocator certificates remain unissued
until independent real-deallocator/concurrent-refund oracles and their bypass
mutations pass alongside the complete runtime identity evidence.

Bounded receipt-range insertion and replacement seek their first relevant range
with `partition_point`. Insertions include an adjacent predecessor; replacement
intersections exclude it. Ascending gapped frames no longer scan the full prefix
on every frame. Middle insertions still shift contiguous storage, and overlapping
merges still compact it. The supported-envelope CPU proof must include reverse
and random gapped insertion and merge-heavy traffic at the full frozen window;
binary search alone does not certify those remaining costs.

Receive-history driver guards are at least ten seconds, including readiness,
injection, chunk reads, and final credit drain. Causal events and independent
assertions remain the completion oracle; these guards only bound hangs.


Dormant packet-private stage core validates exact connection/credit/configuration/
layout, packet-space/number/generation/phase, allocation and owner identities,
physical layouts, charged-byte equations and reservation lifecycle transitions.
Metadata and slice admission are atomic across the entire inline batch; key
suballocations consume only the existing fixed base grant. The move-only batch
lease survives every prepared backing and transfers without refund/recharge.
Allocator refusal discards the packet-private allocations before returning credit.
No packet processing or ordinary constructor selects this core. Its ledger and
inline plan require existing precharged storage; this patch issues no finite
allocator/TLS evidence and does not resolve the later publication/activation gates.
The E1 oracle uses independent wide arithmetic and causal deallocation gates;
the E0 positive boundary case reaches exactly one Session call with every cap
at equality.
