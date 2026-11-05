# Dormant QUIC allocation policy and certificate inventory

This prerequisite provides configuration and reservation accounting only. No
production call site selects this policy. Existing upstream runtimes remain
uncertified. There is no activation API and no total-process RSS claim.

The lockfile pins quinn 0.11.11, quinn-proto 0.11.18, compio-quic 0.8.0 and
rustls 0.23.46. `rawq_budget::CENSUS` assigns every allocation family to a
component and an implementation proof owner. R numbers denote subsequent bounded
integration stages, not evidence already obtained. Known unbounded event queues
belong to the R1/R7 pre-allocation hooks; compio stateless sends belong to R6.
All other entries also require hooks or verified finite layouts. A missing
allocation family, an impossible minimum, or an unsupported allocator/platform
blocks integration and requires replanning. Residual pools cannot absorb unknown
allocations. Dependency or target changes invalidate certificates.

| Allocation family and reachable children | Pool and proof obligation |
| --- | --- |
| Receive/send scratch, UDP socket owners and effective OS buffers | E: 128 KiB scratch, 512 KiB receive, 512 KiB send; read back effective OS caps, including Linux doubling. GRO disabled. |
| Endpoint config, route/CID maps, reset-token associations, token log/cache, hash capacity, counters | E: 512 KiB route state, with fixed capacity; no capacity inferred from current length. |
| Endpoint queues/sender state, timer/task registries, runtime/driver/completion records, shared config/cert roots/session caches, listener identities and reservation records | E: 512 KiB bookkeeping, 1 MiB runtime and 896 KiB finite residual. Separately certify each reachable allocation; external shared owners cannot escape charging. |
| Initial/coalesced datagram backing, Incoming queue and route metadata | Incoming: 65535 + I + 1024; Q=N; count backing through final release. |
| Forward packet events, clones, popped/processing buffers, bytes reference/header allocations | Raw: z + 256*ir per owner; global N*z/N*ir; pre-enqueue credit remains live until last buffer owner. |
| CID/new/retired vectors, forward/reverse endpoint events, ACK/dedup preflight state, timer controls | Ctl: C + 512*ic; atomically reserve before mutation; vector backing separately charged; bounded producer backpressure. |
| Close, reset, Drained, bounded terminal reason and duplicate state | Two 1024-byte terminal slots per owner, independent of ordinary controls. |
| CRYPTO fragments, reassembly/backing, rustls QUIC handshake queue and transport parameters | C=z/4, plus I for retained Incoming; no double charge of shared backing. |
| TLS connection/session, certificate chains and identity copies, verifier/ring/webpki temporaries, key material and key updates | T=256 KiB owner slab; immutable global configuration in E, CRYPTO bytes in C. Require complete transitive provider layout bounds or pre-allocation hooks. |
| Stream send/receive backing, assembled and out-of-order fragments, frame retransmit payload | Independent 4*z send/receive pools; stream receive window z; metadata is additional, never implied by a byte window. |
| Stream state maps, wakers, read/write futures, handles and result records | S*4 KiB; S=min(64,z/32 KiB); uni streams, datagrams and 0-RTT disabled. Clone/waker multiplicity must be bounded. |
| Sent packet trees, ACK-range sets and frame retransmit metadata | Windows: ceil(Wsend/600)+6 records at 256 bytes each, plus three spaces of 65 transient ACK ranges at 32 bytes each; both receive the factor two. R1/R7 pre-allocation credit covers every record kind, including non-ACK tails/probes/PTO/MTU probes. Two ACK-only records are included in C_pkt; ACK-only/untracked close never block. PTO may exceed C_pkt by two records for three rounds (six charged above C_pkt). Payload vectors retain their payload credits. |
| Fixed loss/congestion clones, CID/path/MTU/timer state, packet-builder and decode temporaries | Finite 64 KiB owner residual; packet-count-dependent allocations are excluded. Verify fixed layouts and clone multiplicity; no small-allocation fallback. |
| Primary/alternative/idle source records, normalized addresses, per-source phase indexes | 4*N records at 512 bytes, partitioned N/2N/N; phase counts overlap final owners. |
| Handshake/driver/ready/preauth futures, JoinSet, channel cells, completed-unjoined outputs, retained final handles and lease metadata | Eight 4 KiB records per owner; final-owner count N. Retained buffers keep their original pool credits. |
| Retry/reset/version negotiation/refusal vector backing, sender queue and completion, including zero-connection producers | Response: 65536+512 each, N items; reserve before construction, exactly one endpoint sender; retain through completion. |
| Gateway raw/JSON/value/string/base64 conversion, auth parser, output and length prefix, task metadata | Preauth: 4*F+A+O+8+64 KiB per slot; backing maxima F=A=z; V=N; lower frame admission does not shrink backing allowance. |

Every variable allocation charges `align_up(actual_capacity,64)+64` before
allocation against its doubled component pool. Headers, alignment, allocator
layout/fragmentation and reference metadata require proof too. Allocation failure
must follow the owning component's drop/backpressure/resource-close policy.
Fixed E is fully charged once per listener/runtime endpoint. No shared clone,
result or timer registry may grow outside these components.

`AllocationCertificate` records allocation class/pool, runtime, target/allocator
and OS convention, dependency/patch digest, frozen config digest, per-allocation shapes/counts and actual/charged capacities, component ceiling and hook/layout evidence. Each separately
allocated child pays its own alignment and header before the checked sum;
aligning an aggregate allocation total is forbidden. Socket evidence
also records both effective caps. The future startup gate must require complete,
nonduplicated coverage and verify evidence against the resolved dependency
sources and effective profile. R0 creates no certificate and proves no runtime
bound. R1/R7 must finish their full runtime certificates before candidate use;
R2/R3/R4 and R6/R8/R9 additionally prove source, final-owner and runtime behavior.

`FrozenBudget::prepare` consumes a physical-RAM reader exactly once, validates B
and the full canonical listener list, checks every slice sum and freezes the
configuration digest before any runtime factory is available. Each enabled
runtime variant needs its own listener identity and slice. Frame admission may
be lowered; other scalar overrides are not exposed. Application allocations after
handoff require their own service quota before activation.

All product processes on a host must use one controller-provisioned, protected
local ledger path and the same RAM/B policy. The controller assigns disjoint
byte intervals; the library does not independently claim the full host B.
Transactions lock the stable file, verify its fixed-size checksum, then persist
and sync the complete ledger. Never unlink, replace, or use a private alternate
ledger while owners exist. A claim is retained through all cloned leases and is
removed only on clean final destruction. A crash, torn write, failed release,
unknown process state, unsupported locking or unverifiable ledger refuses reuse.
No PID-based automatic recovery exists. Offline controller recovery requires
proof that all affected owners are dead; budget changes require complete
shutdown and re-reservation. Ledger provisioning must finish before concurrent
startup; racing an incomplete initial creation may safely refuse startup.

## Controller r6 packet-state derivation

This supersedes r5 totals. Credits include all packet-number spaces and builder
reservations; discard, Retry/rejection and space discard release their own
reservations. ACK-only service never blocks on credit: two records inside C_pkt
are reserved for its pinned non-ACK-tail policy. Untracked CONNECTION_CLOSE and
previous-path challenges remain unblocked. PTO may exceed C_pkt by S_pto=2 records
for K_pto=3 consecutive rounds. T_np=max(3*PTO,10000 ms) starts at exhaustion;
only an ACK freeing at least one record resets it. PING/keepalive does not reset
it. Deadline expiry resource-closes with untracked Close, then ordinary
Drained/final-owner destruction. These are frozen policy fields, not runtime hooks.

Pinned quinn-proto 0.11.18 spaces.rs:794-803 prunes PendingAcks to64 after
insertion. Preserve that algorithm; charge65 entries per space to cover the
transient insertion. The record allowance excludes the variable metadata below.
All classes are assigned to Windows with R1/R7 growth hooks. Capacities are policy
slab ceilings, not certified upstream layouts; R1/R7 must implement/certify them
before candidate activation. Unknown or unhookable layouts refuse integration.

| Item-3 class | Item cap per connection | Capacity / charged item bytes | Exhaustion and lifetime policy |
| --- | --- | --- | --- |
| STREAM/retransmit frame descriptors | 32*(C_pkt+6), aggregate32 per packet | 64 / 128 | Stop adding frames before growth; payload vectors retain independent payload credit. |
| Boxed Retransmits collection owners | C_pkt+6 | 512 / 576 | Reserve before boxing; descriptor children charged separately; pause builders at record credit. |
| SendBuffer ACK/loss range nodes | 2*64*S | 32 / 128 | Coalesce each set to a covering range before growth; permit duplicate retransmission. |
| SendBuffer segment descriptors | 64*S | 64 / 128 | Backpressure writes before growth; adjacent merges require existing payload credit. |
| Receive reassembly/unordered range nodes | 64*S | 32 / 128 | Drop excess out-of-order STREAM data unacknowledged before growth; peer retransmits. |
| Receive heap/buffer descriptors | 64*S | 64 / 128 | Same independent descriptor cap; retained payload keeps its original charge. |
| Shared simultaneous ACK/loss scratch | C_pkt+6 | 32 / 128 | Reserve before growth; use bounded sequential chunks with no overflow allocation. |

Each shape pays align_up(capacity,64)+64 separately. D_meta is their checked
sum, retained through transfer and final destruction. Its charged-shape totals
still receive the common outer factor two; no aggregation before alignment.
Thus D_meta=(C_pkt+6)*(32*128+576+128)+S*(2*64*128+3*64*128).
C_pkt=ceil(Wsend/600); DeltaUnit=(C_pkt+6)*256+65*32*3+D_meta;
Unit'=Unit+DeltaUnit; N=min(role_cap,floor((b-E)/(2*Unit')));
Bderived=E+2*N*Unit'. Window pool=2*(Wrecv+Wsend+DeltaUnit).
ACK backing is constant6240 bytes before doubling; packet terms grow with z.
New ceilings, metadata shapes and T_np/S_pto/K_pto enter the configuration digest.

| RAM / role | z | C_pkt | Record bytes incl PTO | ACK bytes | D_meta | DeltaUnit | N | Bderived | Unallocated B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 GB / mesh | 262144 | 1748 | 449024 | 6240 | 8746880 | 9202144 | 9 | 226852270 | 23147730 |
| 1 GB / gateway | 262144 | 1748 | 449024 | 6240 | 8746880 | 9202144 | 8 | 225181296 | 24818704 |
| 2 GB / mesh | 524288 | 3496 | 896512 | 6240 | 17464960 | 18367712 | 10 | 487987564 | 12012436 |
| 2 GB / gateway | 524288 | 3496 | 896512 | 6240 | 17464960 | 18367712 | 9 | 489153598 | 10846402 |
| 8 GB / mesh | 1048576 | 6991 | 1791232 | 6240 | 34896320 | 36693792 | 20 | 1911917784 | 88082216 |
| 8 GB / gateway | 1048576 | 6991 | 1791232 | 6240 | 34896320 | 36693792 | 18 | 1914607996 | 85392004 |

| RAM / role | L/l | H/h | R/r | U/u | V/v | Primary/alternative/idle | Endpoint raw bytes/items | Endpoint control bytes/items | Response bytes/items |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 GB / mesh | 9/8 | 9/4 | 9/4 | 0/0 | 0/0 | 9/18/9 | 2359296/576 | 589824/1152 | 589824/9 |
| 1 GB / gateway | 8/8 | 8/4 | 8/4 | 8/4 | 8/4 | 8/16/8 | 2097152/512 | 524288/1024 | 524288/8 |
| 2 GB / mesh | 10/8 | 10/4 | 10/4 | 0/0 | 0/0 | 10/20/10 | 5242880/640 | 1310720/2560 | 655360/10 |
| 2 GB / gateway | 9/8 | 9/4 | 9/4 | 9/4 | 9/4 | 9/18/9 | 4718592/576 | 1179648/2304 | 589824/9 |
| 8 GB / mesh | 20/8 | 20/4 | 16/4 | 0/0 | 0/0 | 20/40/20 | 20971520/1280 | 5242880/5120 | 1310720/20 |
| 8 GB / gateway | 18/8 | 18/4 | 16/4 | 18/4 | 18/4 | 18/36/18 | 18874368/1152 | 4718592/4608 | 1179648/18 |

The 1 GB split retains b=125000000 per listener and z=131072.
C_pkt=874; record bytes=225280; ACK bytes=6240; D_meta=4387840;
DeltaUnit=4619360. Mesh N=9, Bderived=120326830;
gateway N=8, Bderived=119481968; combined=239808798 <=250000000.
Every profile has N>=2; complete scalar, metadata, phase, source and queue
fixtures are tested via FrozenBudget::prepare. No runtime certificate is issued.
