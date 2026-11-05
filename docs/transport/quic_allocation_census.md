# Dormant QUIC resource policy and allocation certificates

This module plans immutable listener/host reservations. No production call site
activates it, constructs a listener or enforces runtime allocation credit. The
lockfile pins quinn 0.11.11 (q), quinn-proto 0.11.18 (p), compio-quic 0.8.0 (c)
and rustls 0.23.46. All runtime integration remains contingent on complete
allocation certificates, supported-platform layouts and the tests below.

## Checked metadata sizing and exact profiles

Read physical RAM once; B defaults to floor(RAM/4). Canonical listener identities
share this single host limit, with positive disjoint slices b whose checked sum
is at most B. Each enabled runtime variant requires its own listener/slice.
Existing scalar derivation is in Profile::derive: E=4194304, z is the capped
power-of-two slab, Wsend=Wrecv_conn=4*z, and all original payload, TLS, stream,
raw/control, terminal, source, task, response and fixed residual terms remain.
Owner_base and Unit_base exclude the separate metadata contribution.

```
M_base = ceil((Wsend + Wrecv_conn)/1200)*512 + 65536
M_conn = 2*M_base
Unit_r8 = Unit_base + M_base
N = min(role_cap, floor((b-E)/(2*Unit_r8)))
Bderived = E + 2*N*Unit_r8 = E + N*(2*Unit_base + M_conn)
require N >= 2 and Bderived <= b
```

The 1200-byte reference sizes the policy; it is not a legal packet minimum or
an inferred packet-count bound. M_conn is already doubled and appears exactly
once in the complete per-owner envelope. The frozen digest includes the sizing
constants and all effective scalar ceilings. Lower frame admission does not
reduce backing allowances. Arithmetic/target conversion failures refuse planning.

Indicative arithmetic, not measured allocation certification or runtime support:

| RAM / role | z | Unit_base | M_base | M_conn | Unit_r8 | N | Bderived | Unallocated slice |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 GB / mesh | 262144 | 3167743 | 960512 | 1921024 | 4128255 | 29 | 243633094 | 6366906 |
| 1 GB / gateway | 262144 | 4609543 | 960512 | 1921024 | 5570055 | 22 | 249276724 | 723276 |
| 2 GB / mesh | 524288 | 5821951 | 1855488 | 3710976 | 7677439 | 32 | 495550400 | 4449600 |
| 2 GB / gateway | 524288 | 8574471 | 1855488 | 3710976 | 10429959 | 23 | 483972418 | 16027582 |
| 8 GB / mesh | 1048576 | 10999295 | 3644928 | 7289856 | 14644223 | 64 | 1878654848 | 121345152 |
| 8 GB / gateway | 1048576 | 16373255 | 3644928 | 7289856 | 20018183 | 49 | 1965976238 | 34023762 |

| RAM / role | L/l | H/h | R/r | U/u | V/v | Primary/alternative/idle records |
| --- | --- | --- | --- | --- | --- | --- |
| 1 GB / mesh | 29/8 | 29/4 | 16/4 | 0/0 | 0/0 | 29/58/29 |
| 1 GB / gateway | 22/8 | 22/4 | 16/4 | 22/4 | 22/4 | 22/44/22 |
| 2 GB / mesh | 32/8 | 32/4 | 16/4 | 0/0 | 0/0 | 32/64/32 |
| 2 GB / gateway | 23/8 | 23/4 | 16/4 | 23/4 | 23/4 | 23/46/23 |
| 8 GB / mesh | 64/8 | 64/4 | 16/4 | 0/0 | 0/0 | 64/128/64 |
| 8 GB / gateway | 49/8 | 49/4 | 16/4 | 49/4 | 49/4 | 49/98/49 |

The 1 GB split uses b=125000000 each and z=131072; M_base=513024,
M_conn=1026048. Mesh N=25/Bderived=121467854 and gateway
N=19/Bderived=121961738 sum to243429592<=250000000. Exact tests compare
complete literal Profile fixtures for all six defaults and both split roles,
including phases, source/queue counts and credit terms.

## Shared metadata allocation census

All twelve classes below debit the same Pool::Metadata M_conn per final owner.
CENSUS assigns the Tokio proof owner1 and compio proof owner7. The other census
rows retain their own endpoint, Incoming, payload/CRYPTO admission, TLS, stream,
raw/control/terminal/source/task/response/preauth and finite residual pools.
Metadata is never absorbed by residual storage. There are no separate per-class
item caps, ACK/PTO exemptions, overshoot allowances or no-progress deadlines.
Multiplicities describe reachable owners, not inferred bounds on item count.

Every actual allocation/growth reserves align_up(capacity,64)+64 before mutation.
Charge capacity rather than current length; growing/replacing a collection must
charge old and new backing simultaneously, including spare capacity, tree nodes,
allocator headers, temporary copies and compaction peaks. Transfer retains the
charge with the allocation until final destruction. Shared backing pays once;
separately allocated clone/reference state pays separately. Inline fields already
charged with an enclosing allocation are not double charged. Payload/CRYPTO
admission quotas remain independently required and do not replace this debit.

| Class | Reachability | Exact pinned allocation/transfer evidence |
| --- | --- | --- |
| SentRecords | Three packet spaces per owner, sharing the same byte credit | p 0.11.18 src/connection/spaces.rs:20-54,218-255,283-305; src/connection/packet_builder.rs:32-44,184-216; all tracked packets and outstanding builders |
| SentFrameMetadata | Every retained packet and outstanding builder capacity | p 0.11.18 src/frame.rs:468-509; src/connection/spaces.rs:283-305; variable StreamMetaVec capacity per retained packet/builder |
| RetransmitOwners | Every retained/pending owner and separately allocated child, including overlap | p 0.11.18 src/connection/spaces.rs:309-338,383-408,428-454; boxed owners and all vector/set/deque children including transfer overlap |
| SendSegments | Up to S send halves under the aggregate stream limit | p 0.11.18 src/connection/send_buffer.rs:9-40,43-77,147-174; every retained deque cell/backing capacity across S send halves |
| SendRanges | Two independent range trees per send half, up to 2*S sets | p 0.11.18 src/connection/send_buffer.rs:21-27,43-77,171-174; src/range_set/btree_range_set.rs:13-15,26-38; ACK/retransmit nodes survive record removal |
| StreamAssemblers | Up to S receive halves; old/new compaction backing remains live | p 0.11.18 src/connection/streams/recv.rs:15-27,274-300; src/connection/assembler.rs:13-23,105-147,153-219,255-280; chunks, descriptors, backing and compaction peaks |
| CryptoAssemblers | Three packet spaces per owner, sharing the same byte credit | p 0.11.18 src/connection/spaces.rs:20-54,80-91; src/connection/mod.rs:2128-2137; src/connection/assembler.rs:13-23,105-147,153-219,255-280; three additional CRYPTO assemblers |
| UnorderedHistory | One persistent received-history tree per unordered assembler | p 0.11.18 src/connection/assembler.rs:40-55,85-97,166-182,332-340; q 0.11.11 src/recv_stream.rs:163-180; c 0.8.0 src/recv_stream.rs:279-296; recvd trees persist after chunk consumption |
| PendingRetransmits | Three packet spaces per owner, sharing the same byte credit | p 0.11.18 src/connection/spaces.rs:20-28,383-408; src/connection/mod.rs:1779-1793; pending collections plus transferred backing until actual free |
| PendingAcks | Three packet spaces per owner, sharing the same byte credit | p 0.11.18 src/connection/spaces.rs:610-654,794-803,924; src/range_set/array_range_set.rs:20-38; preserve steady64/transient65 pruning, charge actual capacity |
| AckScratch | All simultaneous scratch allocations and replacement backing | p 0.11.18 src/connection/mod.rs:1493-1501; src/range_set/array_range_set.rs:20-38; every simultaneous ACK allocation and replacement backing |
| LossScratch | All simultaneous scratch allocations and replacement backing | p 0.11.18 src/connection/mod.rs:1695-1696,1730-1735,1779-1793; lost_packets capacity plus simultaneous pending transfers |

The scope includes all tracked ACK-only/PTO/MTU/ordinary packets and builders;
Retry/rejection/packet-space discard returns only destroyed reservations. Stream
and CRYPTO assembler backing are both included, as is unordered received history
after chunks have been consumed. PendingAcks preserves pinned steady64/transient65
pruning, charging its actual backing capacity rather than an assumed node size.
Pending loss transfers and ACK/loss scratch retain simultaneous charges.

## Required runtime exhaustion and operating-envelope proofs

Exhaustion is an attempted charge for which used+charge exceeds M_conn; equality
alone is permitted. Hooks return ResourceExhausted before growth and abort current
frame, coalesced-packet and packet-build processing by early return. Existing
committed data and owners stay charged; do not fabricate ACK knowledge, discard
already-ACKed data or refund transferred storage. No overflowing allocation or
metadata exemption is used to close: fixed terminal reservations remain available.

The local-close adapter must set the connection error exactly once as well as
entering Closed. Pinned p src/connection/mod.rs:396-406 emits ConnectionLost from
error; :1269-1283 alone changes close state. Data uses application RESOURCE_LIMIT;
Initial/Handshake preserve transport APPLICATION_ERROR conversion (:819-829).
Preserve the Close timer to Drained (:1193-1203,3490-3499) and endpoint ordering.
Both wrappers terminate/wake handshake, connection and stream/read/write waiters:
q src/connection.rs:1231-1234; c src/connection.rs:84-87. q :262-273 must never see
Drained without an error. Final buffers/handles and lifetime leases remain held
until actual joined destruction. These are future integration obligations.

Supported-envelope tests must use the actual coalescing writer (flush >=1200 bytes
or end-of-frame), including 1 KiB application writes, full send/connection receive
windows, reordering/loss up to one window, ACK-only/PTO interleaving and a bounded
consumer barrier until the receive window fills. Require reliable payload/hole
recovery, FIN completion and credit recovery after release. Include a lost leading
packet then at least65 full-size packets, and257 separate1KiB writes wherever the
profile permits (otherwise use a full window of1KiB writes), ordered/unordered
reads, mixed/coalesced frames and handshake/Data transitions. Recovery is unchanged.

Traffic outside that envelope, such as sustained tiny fragments, may resource-close.
There is no universal never-exhausts claim. Independent class exhaustion probes
must cover exact-full versus attempted-overflow, consumed-chunk unordered history,
CRYPTO, pending-loss transfers and compaction peaks, with one local error, all
waiters notified, correct wire close, Drained and held-owner destruction. A required
healthy case that cannot fit needs policy replanning before activation.

## Certificates and host-ledger lifetime

AllocationCertificate binds class/pool, runtime, target/allocator/socket convention,
dependency/patch digest, frozen configuration digest, exhaustive per-allocation
shapes/counts and actual/charged capacities. Separately allocated children each pay
alignment/header before the sum; aggregate-first alignment is forbidden. Socket
certificates include effective OS receive/send caps, including Linux doubling.
Uncovered allocation families and unsupported layouts refuse candidate startup.
The planner issues no runtime certificates and claims no total-process RSS bound.

All product processes on a host use one protected controller-provisioned local
ledger path and the same physical-RAM/B policy. Transactions lock its stable file,
verify fixed size, magic, checksum and policy, then persist/sync the complete ledger.
Do not unlink/replace a live ledger or select private alternate ledgers. Disjoint
claims remain held by every lease clone until final destruction. Release matches
digest, interval start/end and PID; altered identity leaves the claim intact.
Crash, torn write, failed release or unproved stale ownership refuses reuse. There
is no PID-based automatic recovery; offline recovery requires proof of death.
Changing budget/configuration requires complete shutdown and re-reservation.
