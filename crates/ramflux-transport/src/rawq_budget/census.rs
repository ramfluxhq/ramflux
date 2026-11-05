// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Allocation inventory and certificate schema, not certificates for upstream runtimes.
//! Every entry needs per-runtime, per-platform evidence before candidate construction.

/// Non-overlapping component pool. Every variable pool has the factor-two allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// E scratch, kernel buffers, route state, runtime, bookkeeping and fixed residual.
    Endpoint,
    /// Initial datagram backing plus I and route metadata.
    Incoming,
    /// C retained handshake/crypto data.
    Crypto,
    /// Independent receive and send payload window allowances.
    Windows,
    /// Shared metadata byte credit, already doubled once in `MetadataBudget`.
    Metadata,
    /// T fixed TLS/protocol owner slab.
    TlsOwner,
    /// S stream state slabs.
    Streams,
    /// Raw backing plus item/reference metadata.
    Raw,
    /// Control payload, vector capacities and item metadata.
    Control,
    /// Two terminal records, including bounded reason text.
    Terminal,
    /// Four source records amortized per owner.
    Sources,
    /// Eight task/handle/result records per owner.
    Tasks,
    /// 64 KiB finite residual per owner; never an unknown-allocation escape hatch.
    Residual,
    /// Stateless slab plus queue/completion record.
    Response,
    /// Gateway raw/JSON/conversion/output/length/parser capacities.
    Preauth,
}
/// Exhaustive allocation families in the pinned transport dependency graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationClass {
    /// Fixed socket scratch and effective OS buffers.
    Socket,
    /// Endpoint configuration, route, CID and token state.
    EndpointState,
    /// Runtime scheduling, driver and timer registries.
    Runtime,
    /// Initial datagram backing and admission queue state.
    Incoming,
    /// Raw packet queues, shared backing and retained references.
    RawEvents,
    /// Both control directions, vectors and atomic preflight state.
    Controls,
    /// Bounded close, reset and drained records.
    Terminal,
    /// Retained handshake payload admission; metadata has its own shared credit.
    Crypto,
    /// TLS session and transitive verification/provider allocations.
    Tls,
    /// Finite fixed loss, congestion, path, MTU and timer state.
    ProtocolFixed,
    /// Stream payload admission and backing allowances.
    StreamPayload,
    /// Bounded stream maps, handles and wakers.
    StreamState,
    /// Primary, migration and idle source records.
    Sources,
    /// Retained driver, handshake, ready and result owners.
    Tasks,
    /// Stateless response backing through socket completion.
    Responses,
    /// Gateway framing, authentication and conversion allocations.
    Preauth,
    /// Shared identities, trust roots and immutable configuration.
    SharedConfig,
    /// Sent map records and outstanding packet builder reservations.
    SentRecords,
    /// Variable stream frame metadata and vector capacity per retained packet.
    SentFrameMetadata,
    /// Boxed retransmit owners and all separately allocated children.
    RetransmitOwners,
    /// Retained send-buffer segment deque descriptors and capacity.
    SendSegments,
    /// Send ACK and retransmit range trees beyond packet retirement.
    SendRanges,
    /// Stream receive chunks, descriptors, backing and compaction peaks.
    StreamAssemblers,
    /// Three additional packet-space CRYPTO assemblers and backing.
    CryptoAssemblers,
    /// Persistent unordered received-range history after chunk consumption.
    UnorderedHistory,
    /// Pending loss collections and transferred backing until actual free.
    PendingRetransmits,
    /// Pending acknowledgement backing, including transient insertion.
    PendingAcks,
    /// Simultaneous ACK-processing scratch and replacement backing.
    AckScratch,
    /// Loss-detection scratch and overlapping pending transfers.
    LossScratch,
}
/// Multiplicities describe reachability, not independent item caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataMultiplicity {
    /// This many packet spaces per final connection owner.
    PacketSpaces(u8),
    /// All retained packet and in-progress builder vector capacities.
    RetainedPacketsAndBuilders,
    /// Every retained/pending owner and each allocated child, including overlaps.
    RetainedPacketAndPendingChildren,
    /// Up to S send halves under the aggregate stream limit.
    SendHalves,
    /// This many independent sets per send half, up to S halves.
    SendRangeSets(u8),
    /// Up to S receive halves under the aggregate stream limit.
    ReceiveHalves,
    /// One persistent history tree for each unordered assembler state.
    UnorderedAssemblers,
    /// All simultaneous scratch allocations and old/new backing.
    ConcurrentScratch,
}
/// A required bounded hook or finite-layout verification, owned by one implementation PR.
#[derive(Clone, Copy, Debug)]
pub struct CensusEntry {
    /// Allocation family.
    pub class: AllocationClass,
    /// Charged component pool.
    pub pool: Pool,
    /// Tokio implementation proof owner (RAWQ R number).
    pub tokio_owner: u8,
    /// Compio implementation proof owner (RAWQ R number).
    pub compio_owner: u8,
    /// Pinned source scope to inventory, including transitive provider allocations.
    pub source: &'static str,
    /// Required bounded exhaustion behavior; later runtime owners implement it.
    pub exhaustion: &'static str,
    /// Shared metadata reachability; absent for baseline pools.
    pub metadata_multiplicity: Option<MetadataMultiplicity>,
}
use AllocationClass as A;
use Pool as P;
const METADATA_EXHAUSTION: &str = "ResourceExhausted before growth; abort frame/coalesced/build processing; one local error; Data RESOURCE_LIMIT or handshake APPLICATION_ERROR; q/c terminate and wake waiters; Close timer to Drained; retain charges until final destruction";
const fn metadata_entry(
    class: AllocationClass,
    multiplicity: MetadataMultiplicity,
    source: &'static str,
) -> CensusEntry {
    CensusEntry {
        class,
        pool: P::Metadata,
        tokio_owner: 1,
        compio_owner: 7,
        source,
        exhaustion: METADATA_EXHAUSTION,
        metadata_multiplicity: Some(multiplicity),
    }
}
/// Complete pending inventory; none of these entries certifies an unpatched runtime.
pub const CENSUS: &[CensusEntry] = &[
    CensusEntry {
        class: A::Socket,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "q runtime.rs/endpoint.rs; c socket.rs; quinn-udp; OS effective SO_RCVBUF/SO_SNDBUF",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::EndpointState,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p endpoint.rs/config/token_memory_cache/bloom_token_log; q endpoint.rs; c endpoint.rs/builder.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Runtime,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "q runtime.rs; tokio runtime/time/task; c endpoint.rs; compio-runtime/driver/net/io completion registries",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Incoming,
        pool: P::Incoming,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p endpoint.rs Incoming; q incoming.rs/endpoint.rs; c incoming.rs/endpoint.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::RawEvents,
        pool: P::Raw,
        tokio_owner: 1,
        compio_owner: 7,
        source: "q endpoint.rs/connection.rs; p shared.rs; c endpoint.rs/connection.rs; bytes backing/reference headers",
        exhaustion: "Drop newest before allocation on raw byte/item exhaustion",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Controls,
        pool: P::Control,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p shared.rs/connection/cid_state.rs/cid_queue.rs; q connection.rs; c connection.rs",
        exhaustion: "Atomic preflight; pause on temporary shortage; resource-close oversize via reserved terminal",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Terminal,
        pool: P::Terminal,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/mod.rs/token.rs; q connection.rs; c connection.rs",
        exhaustion: "Coalesce first cause and final Drained in independent reserved slots",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Crypto,
        pool: P::Crypto,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p crypto/rustls.rs/connection/spaces.rs/assembler.rs; rustls quic.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Tls,
        pool: P::TlsOwner,
        tokio_owner: 1,
        compio_owner: 7,
        source: "rustls 0.23.46 common_state/conn/msgs/client/server/verify; webpki/ring certificate verification and keys",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::ProtocolFixed,
        pool: P::Residual,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/{mod,paths,timer,ack_frequency,mtud}/congestion; finite fixed loss/congestion/path/MTU/timer state only",
        exhaustion: "Resource-close on impossible fixed layout; no borrowing from count-dependent pools",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::StreamPayload,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/streams/{send,recv,state,mod}; q/c send_stream.rs/recv_stream.rs; payload admission quotas do not replace shared metadata/backing credit",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::StreamState,
        pool: P::Streams,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/streams/state.rs; q/c connection.rs stream wakers/maps, handle clones",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Sources,
        pool: P::Sources,
        tokio_owner: 1,
        compio_owner: 7,
        source: "mesh_quic_admission.rs; candidate primary/alternative/idle map hooks and normalized keys",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Tasks,
        pool: P::Tasks,
        tokio_owner: 1,
        compio_owner: 7,
        source: "mesh_quic_admission.rs; q/c connection driver futures; ready/channel/JoinSet/results/handshake and final handles",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Responses,
        pool: P::Response,
        tokio_owner: 1,
        compio_owner: 6,
        source: "p endpoint.rs response vectors; q/c endpoint.rs stateless send; c socket.rs completion buffers",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::Preauth,
        pool: P::Preauth,
        tokio_owner: 1,
        compio_owner: 7,
        source: "gateway_frame_reader.rs/quic_gateway.rs/types.rs; serde_json/postcard/base64 conversion temporaries",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    CensusEntry {
        class: A::SharedConfig,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "tls_config.rs/mesh_quic_admission.rs; rustls trust roots/session caches/config Arc; frozen config identities/digest/reservation records; fixed-label diagnostics",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
        metadata_multiplicity: None,
    },
    metadata_entry(
        A::SentRecords,
        MetadataMultiplicity::PacketSpaces(3),
        "p 0.11.18 src/connection/spaces.rs:20-54,218-255,283-305; src/connection/packet_builder.rs:32-44,184-216; all tracked packets and outstanding builders",
    ),
    metadata_entry(
        A::SentFrameMetadata,
        MetadataMultiplicity::RetainedPacketsAndBuilders,
        "p 0.11.18 src/frame.rs:468-509; src/connection/spaces.rs:283-305; variable StreamMetaVec capacity per retained packet/builder",
    ),
    metadata_entry(
        A::RetransmitOwners,
        MetadataMultiplicity::RetainedPacketAndPendingChildren,
        "p 0.11.18 src/connection/spaces.rs:309-338,383-408,428-454; boxed owners and all vector/set/deque children including transfer overlap",
    ),
    metadata_entry(
        A::SendSegments,
        MetadataMultiplicity::SendHalves,
        "p 0.11.18 src/connection/send_buffer.rs:9-40,43-77,147-174; every retained deque cell/backing capacity across S send halves",
    ),
    metadata_entry(
        A::SendRanges,
        MetadataMultiplicity::SendRangeSets(2),
        "p 0.11.18 src/connection/send_buffer.rs:21-27,43-77,171-174; src/range_set/btree_range_set.rs:13-15,26-38; ACK/retransmit nodes survive record removal",
    ),
    metadata_entry(
        A::StreamAssemblers,
        MetadataMultiplicity::ReceiveHalves,
        "p 0.11.18 src/connection/streams/recv.rs:15-27,274-300; src/connection/assembler.rs:13-23,105-147,153-219,255-280; chunks, descriptors, backing and compaction peaks",
    ),
    metadata_entry(
        A::CryptoAssemblers,
        MetadataMultiplicity::PacketSpaces(3),
        "p 0.11.18 src/connection/spaces.rs:20-54,80-91; src/connection/mod.rs:2128-2137; src/connection/assembler.rs:105-219; three additional CRYPTO assemblers",
    ),
    metadata_entry(
        A::UnorderedHistory,
        MetadataMultiplicity::UnorderedAssemblers,
        "p 0.11.18 src/connection/assembler.rs:40-55,85-97,166-182,332-340; q 0.11.11 src/recv_stream.rs:163-180; c 0.8.0 src/recv_stream.rs:279-296; recvd trees persist after chunk consumption",
    ),
    metadata_entry(
        A::PendingRetransmits,
        MetadataMultiplicity::PacketSpaces(3),
        "p 0.11.18 src/connection/spaces.rs:20-28,383-408; src/connection/mod.rs:1779-1793; pending collections plus transferred backing until actual free",
    ),
    metadata_entry(
        A::PendingAcks,
        MetadataMultiplicity::PacketSpaces(3),
        "p 0.11.18 src/connection/spaces.rs:610-654,794-803,924; src/range_set/array_range_set.rs:20-38; preserve steady64/transient65 pruning, charge actual capacity",
    ),
    metadata_entry(
        A::AckScratch,
        MetadataMultiplicity::ConcurrentScratch,
        "p 0.11.18 src/connection/mod.rs:1493-1501; src/range_set/array_range_set.rs:20-38; every simultaneous ACK allocation and replacement backing",
    ),
    metadata_entry(
        A::LossScratch,
        MetadataMultiplicity::ConcurrentScratch,
        "p 0.11.18 src/connection/mod.rs:1695-1696,1730-1735,1779-1793; lost_packets capacity plus simultaneous pending transfers",
    ),
];

/// One allocation shape; each object pays its own alignment and allocator header.
#[derive(Clone, Debug)]
pub struct AllocationLayout {
    /// Actual capacity of one backing allocation, including reachable inline metadata.
    pub capacity: u64,
    /// Maximum simultaneous allocations of this shape, including retained clones/results.
    pub count: u64,
}

/// Evidence format required from later bounded integration; R0 issues none.
#[derive(Clone, Debug)]
pub struct AllocationCertificate {
    /// Exact inventory class and charging pool.
    pub class: AllocationClass,
    /// Non-overlapping charging component.
    pub pool: Pool,
    /// Runtime whose allocation sites are covered (quinn or compio).
    pub runtime: String,
    /// Doubled variable component ceiling, or the fixed endpoint slab.
    pub pool_ceiling: u64,
    /// Dependency lock and patch digest.
    pub dependency_digest: [u8; 32],
    /// Frozen effective configuration digest.
    pub config_digest: [u8; 32],
    /// Target triple, allocator and socket accounting convention.
    pub platform: String,
    /// Pre-allocation hook or finite-layout bound evidence identifier.
    pub evidence: String,
    /// Exhaustive allocation shapes; separately allocated children need their own row.
    pub layouts: Vec<AllocationLayout>,
    /// Checked sum of capacity*count over all layouts.
    pub actual_capacity: u64,
    /// Checked sum of `count*(align_up(capacity,64)+64)` over all layouts;
    /// aggregate first then align is forbidden. Must fit the component ceiling.
    pub charged_bytes: u64,
    /// Effective socket receive/send caps read back from OS; required for Socket.
    pub effective_socket_bytes: Option<[u64; 2]>,
}
