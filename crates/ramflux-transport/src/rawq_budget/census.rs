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
    /// Independent receive and send windows, including packet/reassembly metadata.
    Windows,
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
    /// Fixed socket scratch and OS buffers.
    Socket,
    /// Endpoint/config/routes/CID lookup/token-cache state.
    EndpointState,
    /// Runtime scheduler/driver/timer registry and socket owners.
    Runtime,
    /// Initial packet, coalesced backing and Incoming admission queues.
    Incoming,
    /// Forward raw event queues, shared backing, clones and popped buffers.
    RawEvents,
    /// Both control directions, CID vectors, timer controls and dedup preflight.
    Controls,
    /// Close/reset/drained reason and terminal delivery.
    Terminal,
    /// TLS CRYPTO reassembly and retained handshake bytes.
    Crypto,
    /// TLS session, certificate chains, verification temporaries and crypto provider.
    Tls,
    /// Sent-record and ACK-range credits, with payload vectors charged separately.
    Protocol,
    /// Fixed loss/congestion/path/MTU/timer state; never packet-count-dependent.
    ProtocolFixed,
    /// Aggregate bounded STREAM/retransmit descriptors per tracked packet.
    SentFrameMetadata,
    /// Boxed retransmit collection owner/header per tracked packet.
    RetransmitOwner,
    /// Per-stream ACK and loss range nodes retained beyond sent-record retirement.
    SendRanges,
    /// Retained send-buffer segment descriptors.
    SendSegments,
    /// Receive reassembly and unordered-read range nodes.
    ReceiveRanges,
    /// Receive reassembly heap/buffer descriptors.
    ReceiveSegments,
    /// Shared simultaneous ACK/loss scratch entries.
    AckLossScratch,
    /// Stream send/receive payload, frame vectors and assembler segments.
    StreamPayload,
    /// Stream maps, wakers, handles and stream-local state.
    StreamState,
    /// Authenticated primary/migration/idle source records and normalization keys.
    Sources,
    /// Handshake/ready/driver tasks, `JoinSet`, channel and completed-unjoined results.
    Tasks,
    /// Stateless Retry/reset/negotiation/refusal allocation through send completion.
    Responses,
    /// Gateway frame/JSON/value/String/base64/conversion/output/parser state.
    Preauth,
    /// Identity/config/certificate shared owners and bounded diagnostics.
    SharedConfig,
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
}
use AllocationClass as A;
use Pool as P;
/// Pending inventory: no entry is certified by merely appearing in this list.
pub const CENSUS: &[CensusEntry] = &[
    CensusEntry {
        class: A::Socket,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "q runtime.rs/endpoint.rs; c socket.rs; quinn-udp; OS effective SO_RCVBUF/SO_SNDBUF",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::EndpointState,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p endpoint.rs/config/token_memory_cache/bloom_token_log; q endpoint.rs; c endpoint.rs/builder.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Runtime,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "q runtime.rs; tokio runtime/time/task; c endpoint.rs; compio-runtime/driver/net/io completion registries",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Incoming,
        pool: P::Incoming,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p endpoint.rs Incoming; q incoming.rs/endpoint.rs; c incoming.rs/endpoint.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::RawEvents,
        pool: P::Raw,
        tokio_owner: 1,
        compio_owner: 7,
        source: "q endpoint.rs/connection.rs; p shared.rs; c endpoint.rs/connection.rs; bytes backing/reference headers",
        exhaustion: "Drop newest before allocation on raw byte/item exhaustion",
    },
    CensusEntry {
        class: A::Controls,
        pool: P::Control,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p shared.rs/connection/cid_state.rs/cid_queue.rs; q connection.rs; c connection.rs",
        exhaustion: "Atomic preflight; pause on temporary shortage; resource-close oversize via reserved terminal",
    },
    CensusEntry {
        class: A::Terminal,
        pool: P::Terminal,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/mod.rs/token.rs; q connection.rs; c connection.rs",
        exhaustion: "Coalesce first cause and final Drained in independent reserved slots",
    },
    CensusEntry {
        class: A::Crypto,
        pool: P::Crypto,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p crypto/rustls.rs/connection/spaces.rs/assembler.rs; rustls quic.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Tls,
        pool: P::TlsOwner,
        tokio_owner: 1,
        compio_owner: 7,
        source: "rustls 0.23.46 common_state/conn/msgs/client/server/verify; webpki/ring certificate verification and keys",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Protocol,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/spaces.rs sent_packets/PendingAcks; packet_builder.rs; R1/R7 shared builder/sent credit, ACK-only allowance inside C_pkt, PTO overshoot6 outside; 64 ACK ranges per space with65 transient entries; payload vectors retain payload credit",
        exhaustion: "Ordinary ack-eliciting builders pause at C_pkt; ACK-only/untracked close continue; PTO overshoot <=2 per round for3 rounds; T_np closes without ACK progress; PendingAcks prunes oldest after transient65",
    },
    CensusEntry {
        class: A::ProtocolFixed,
        pool: P::Residual,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/{mod,paths,timer,ack_frequency,mtud}/congestion; finite fixed loss/congestion/path/MTU/timer state only",
        exhaustion: "Resource-close on impossible fixed layout; no borrowing from count-dependent pools",
    },
    CensusEntry {
        class: A::SentFrameMetadata,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p frame.rs StreamMetaVec; spaces.rs boxed Retransmits children: aggregate <=32 descriptors per tracked packet",
        exhaustion: "Stop adding frames before descriptor growth; unused builder reservations release on discard",
    },
    CensusEntry {
        class: A::RetransmitOwner,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p spaces.rs ThinRetransmits/boxed Retransmits: <=C_pkt+6 owners, 512-byte owner shape; children charged separately",
        exhaustion: "Reserve before boxing; stop packet building at record credit; retain through retransmit transfer/final destruction",
    },
    CensusEntry {
        class: A::SendRanges,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/send_buffer.rs acks/retransmits: each <=64 ranges per stream",
        exhaustion: "Coalesce to covering range before growth; resend covered acknowledged bytes if needed; retain transferred charges",
    },
    CensusEntry {
        class: A::SendSegments,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/send_buffer.rs unacked_segments: <=64 descriptors per stream",
        exhaustion: "Backpressure application writes before descriptor growth; merge adjacent segments only with existing payload credit",
    },
    CensusEntry {
        class: A::ReceiveRanges,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/assembler.rs unordered recvd/ranges: <=64 per stream",
        exhaustion: "Drop excess out-of-order STREAM data unacknowledged before growth; peer retransmits",
    },
    CensusEntry {
        class: A::ReceiveSegments,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/assembler.rs BinaryHeap<Buffer>: <=64 descriptors per stream",
        exhaustion: "Drop excess out-of-order STREAM data unacknowledged before descriptor growth; preserve retained payload credit",
    },
    CensusEntry {
        class: A::AckLossScratch,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/mod.rs ACK processing/loss detection scratch: shared <=C_pkt+6 simultaneous entries",
        exhaustion: "Reserve shared scratch before growth; process bounded chunks sequentially, never allocate overflow scratch",
    },
    CensusEntry {
        class: A::StreamPayload,
        pool: P::Windows,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/streams/{send,recv,state,mod}/send_buffer/assembler; q/c send_stream.rs/recv_stream.rs",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::StreamState,
        pool: P::Streams,
        tokio_owner: 1,
        compio_owner: 7,
        source: "p connection/streams/state.rs; q/c connection.rs stream wakers/maps, handle clones",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Sources,
        pool: P::Sources,
        tokio_owner: 1,
        compio_owner: 7,
        source: "mesh_quic_admission.rs; candidate primary/alternative/idle map hooks and normalized keys",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Tasks,
        pool: P::Tasks,
        tokio_owner: 1,
        compio_owner: 7,
        source: "mesh_quic_admission.rs; q/c connection driver futures; ready/channel/JoinSet/results/handshake and final handles",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Responses,
        pool: P::Response,
        tokio_owner: 1,
        compio_owner: 6,
        source: "p endpoint.rs response vectors; q/c endpoint.rs stateless send; c socket.rs completion buffers",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::Preauth,
        pool: P::Preauth,
        tokio_owner: 1,
        compio_owner: 7,
        source: "gateway_frame_reader.rs/quic_gateway.rs/types.rs; serde_json/postcard/base64 conversion temporaries",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
    CensusEntry {
        class: A::SharedConfig,
        pool: P::Endpoint,
        tokio_owner: 1,
        compio_owner: 7,
        source: "tls_config.rs/mesh_quic_admission.rs; rustls trust roots/session caches/config Arc; frozen config identities/digest/reservation records; fixed-label diagnostics",
        exhaustion: "Refuse growth before allocation; owning pool applies bounded backpressure/drop/resource-close; no uncharged fallback",
    },
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
