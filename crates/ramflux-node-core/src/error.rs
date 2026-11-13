// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[derive(Debug, thiserror::Error)]
pub enum NodeCoreError {
    #[error("gateway_state_reserved_path: database path overlaps the private staging namespace")]
    GatewayStateReservedPath,
    #[error("itest_listener_non_loopback: test HTTP listeners require a loopback address")]
    ItestListenerNonLoopback,
    #[error("gateway_writer_busy: retryable")]
    GatewayWriterBusy,
    #[error(
        "gateway_replay_budget_unfunded: effective R={root_budget} S={per_root_share}, required budget={required_bytes} bytes, available={available_bytes} bytes; configure gateway.replay.root_budget, gateway.replay.per_root_share, gateway.replay.storage_budget_bytes and provision storage; existing live shares must not be reduced"
    )]
    GatewayReplayUnfunded {
        root_budget: u64,
        per_root_share: u64,
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error("gateway_replay_capacity")]
    GatewayReplayCapacity,
    #[error(
        "unsupported gateway state format; stop the gateway, back up then remove its gateway redb file and sidecars, and restart to create format v3 (do not remove account or other service stores)"
    )]
    GatewayStateResetRequired,
    #[error("checkpoint_unavailable")]
    PreAuthCheckpointUnavailable,
    #[error("stale admission checkpoint")]
    PreAuthCheckpointStale,
    #[error(
        "unsupported persisted format: {0}; stop the owning service, back up and inspect affected state before a scoped reset"
    )]
    UnsupportedPersistedFormat(&'static str),
    #[error("clock_invalid")]
    PreAuthClockInvalid,
    #[error("clock_rollback")]
    PreAuthClockRollback,
    #[error("pre-auth source capacity reached")]
    PreAuthCapacity,
    #[error("invalid pre-auth configuration")]
    PreAuthConfigInvalid,
    #[error("invalid pre-auth admission snapshot")]
    PreAuthSnapshotInvalid,
    #[error("attachment authority history is full")]
    AttachmentAuthorityHistoryCapacity,
    #[error("payload_too_large")]
    PayloadTooLarge,
    #[error("invalid ACK batch: {0}")]
    InvalidAckBatch(&'static str),
    #[error("ack_backpressure_retry")]
    AckBackpressureRetry,
    #[error(transparent)]
    SenderRetry(#[from] crate::sender_retry::SenderRetryRefusal),
    #[error(transparent)]
    Publication(#[from] crate::publication::PublicationRefusal),
    #[error(
        "{path}: {cause}; stop every gateway, stop the router, then run ramflux-router --config <path> --rotate-inbox-incarnations --quarantine-wal-segment {path} (never move or delete WAL segments by hand)"
    )]
    WalSegmentRequiresQuarantine { path: std::path::PathBuf, cause: String },
    #[error("forward {phase} deadline expired")]
    ForwardTimeout { phase: &'static str },
    #[error("home migration refused: {0:?}")]
    HomeMigration(ramflux_protocol::home_migration::Refusal),
    #[error("custody authority conflict fenced: {alert:?}")]
    CustodyConflict { alert: Box<ramflux_crypto::custody::CustodyConflictAlert> },
    #[error("source authority refused: {reason_code:?}")]
    SourceAuthorityRefused { reason_code: crate::EnvelopeAuthorityReason },
    #[error("capacity: {resource}")]
    Capacity { resource: &'static str },
    #[error("capacity: new custody principals")]
    CustodyDailyCapacity(ramflux_protocol::custody::CapacityHint),
    #[error("principal_id_taken")]
    PrincipalIdTaken,
    #[error("device_id_taken")]
    DeviceIdTaken,
    #[error("--config requires a path")]
    MissingConfigPath,
    #[error("cannot read config {path}: {source}")]
    ConfigRead { path: std::path::PathBuf, source: std::io::Error },
    #[error("cannot parse config {path}: {source}")]
    ConfigParse { path: std::path::PathBuf, source: toml::de::Error },
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("cannot create node store directory {path}: {source}")]
    StoreDirectory { path: std::path::PathBuf, source: std::io::Error },
    #[error("node store does not exist: {path}")]
    StoreDoesNotExist { path: std::path::PathBuf },
    #[error("redb operation failed: {0}")]
    Redb(String),
    #[error("inbox_incarnation_missing")]
    InboxIncarnationMissing,
    #[error("corrupt migration drain row: {0}")]
    MigrationDrainCorrupt(String),
    #[error(
        "identity admission journal base mismatch: snapshot={snapshot_hash} journal={journal_hash}; stop the router and run --discard-stale-identity-journal against this store; restoring a pre-downgrade backup can roll back authority changes"
    )]
    IdentityAdmissionJournalBaseMismatch { snapshot_hash: String, journal_hash: String },
    #[error("identity admission journal has no stale rows to discard")]
    IdentityAdmissionJournalNotStale,
    #[error("router snapshot serialization failed: {0}")]
    SnapshotSerialization(String),
    #[error("config service_id {actual} does not match expected {expected}")]
    ServiceIdMismatch { expected: String, actual: String },
    #[error("config mesh.allowed_service_ids does not include {0}")]
    MissingAllowedServiceId(String),
    #[error("mesh peer {peer_spiffe_uri} is not authorized for local service {local_service_id}")]
    MeshPeerUnauthorized { local_service_id: String, peer_spiffe_uri: String },
    #[error("config mesh.endpoints is empty")]
    EmptyMeshEndpoints,
    #[error("stale session update for {target_delivery_id}")]
    StaleSessionUpdate { target_delivery_id: String },
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("envelope not found: {0}")]
    EnvelopeNotFound(String),
    #[error("ambiguous envelope id {0}; an inbox sequence is required")]
    AmbiguousEnvelopeId(String),
    #[error(
        "envelope target mismatch for {envelope_id}: expected {expected_target_delivery_id}, actual {actual_target_delivery_id}"
    )]
    EnvelopeTargetMismatch {
        envelope_id: String,
        expected_target_delivery_id: String,
        actual_target_delivery_id: String,
    },
    #[error("node replay guard rejected request: {0}")]
    ReplayGuard(String),
    #[error("envelope TTL expired: {envelope_id}")]
    TtlExpired { envelope_id: String },
    #[error("HTTP request rejected: {status}")]
    HttpRequestRejected { status: &'static str },
    #[error("missing inbox_seq for delivery target {target}, envelope {envelope_id}")]
    MissingInboxSequence { target: String, envelope_id: String },
    #[error("invalid inbox_seq for delivery target {target}, envelope {envelope_id}")]
    InvalidInboxSequence { target: String, envelope_id: String },
    #[error("itest HTTP operation failed: {0}")]
    ItestHttp(String),
    #[error("itest HTTP JSON failed: {0}")]
    ItestJson(String),
    #[error("service shutdown failed: {0}")]
    ServiceShutdown(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The caller is verifiably not the device bound as the push routes' owner.
    #[error("push route owner mismatch")]
    PushRouteOwnerMismatch,
    #[error("delivery_mode_refused")]
    DeliveryModeRefused,
}

impl From<ramflux_protocol::ephemeral::EphemeralModeError> for NodeCoreError {
    fn from(error: ramflux_protocol::ephemeral::EphemeralModeError) -> Self {
        use ramflux_protocol::ephemeral::EphemeralModeError as ModeError;
        match error {
            ModeError::EphemeralAtDurableSink
            | ModeError::InvalidDeliveryMode
            | ModeError::NotEphemeral
            | ModeError::InvalidPriority
            | ModeError::InvalidTtl
            | ModeError::CreatedAtTtlOverflow
            | ModeError::NegativeDeadline
            | ModeError::DeadlineMillisecondsOverflow
            | ModeError::ClockToleranceOverflow
            | ModeError::CreatedAtTooFarInFuture
            | ModeError::Expired => Self::DeliveryModeRefused,
        }
    }
}
