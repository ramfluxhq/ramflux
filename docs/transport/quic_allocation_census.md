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
| Sent packet trees, ACK/range sets, frame metadata, loss/congestion clones, CID/path/MTU/timer state, packet-builder and decode temporaries | Finite 64 KiB owner residual; stream-specific state remains in stream pool and payload in windows. Verify capacities under worst legal input; no small-allocation fallback. |
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
