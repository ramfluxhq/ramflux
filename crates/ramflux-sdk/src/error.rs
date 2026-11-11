// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) const ATTACHMENT_DELETED: &str = "attachment deleted";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupOperation {
    Create,
    MemberAdd,
    Send,
    Rename,
    MemberRemove,
}

impl GroupOperation {
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::Create => "GroupCreateRefused",
            Self::MemberAdd => "GroupMemberAddRefused",
            Self::Send => "GroupSendRefused",
            Self::Rename => "GroupRenameRefused",
            Self::MemberRemove => "GroupMemberRemoveRefused",
        }
    }

    pub(crate) fn for_method(method: &str) -> Option<Self> {
        match method {
            "group.create" => Some(Self::Create),
            "group.member.add" => Some(Self::MemberAdd),
            "group.send" => Some(Self::Send),
            "group.name.set" => Some(Self::Rename),
            "group.member.remove" => Some(Self::MemberRemove),
            _ => None,
        }
    }
}

/// Why a verified Push session could not reconcile its durable receive epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceiveEpochReconcileFailure {
    #[error("retired incarnation fence is full")]
    PausedFence,
    #[error("old incarnation loss publication is pending")]
    PausedLoss,
    #[error("receive generation, epoch, cursor or erasure fence changed")]
    StaleFence,
}

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("receive epoch reconciliation refused: {0}")]
    ReceiveEpochReconcile(#[from] ReceiveEpochReconcileFailure),
    #[error("offline retention {0} is outside 3600..=604800 seconds")]
    InvalidOfflineRetention(u64),
    #[error(transparent)]
    LifecycleShared(std::sync::Arc<SdkError>),
    #[error("operation requires reconciliation: {0}")]
    OperationReconciliationRequired(String),
    #[error("data root is in use by another daemon")]
    DataRootInUse,
    #[error("custody authority is durably fork fenced")]
    CustodyForkFenced,
    #[error("object erased")]
    ObjectErased,
    #[error("legacy A2I binding changed during receive; redrive the entry")]
    LegacyBindingChanged,
    #[error("{}", ATTACHMENT_DELETED)]
    AttachmentDeleted,
    #[error("home migration refused: {0:?}")]
    HomeMigrationRefused(ramflux_protocol::home_migration::Refusal),
    #[error("custody networking refused: {0}")]
    CustodyNetwork(#[from] ramflux_protocol::custody::CustodyRefusal),
    #[error("custody networking refused: Capacity; {}", crate::custody::capacity_hint::message(.capacity))]
    CustodyCapacity { capacity: ramflux_protocol::custody::CapacityHint },
    #[error("custody networking refused: {code}; retry after {}ms", .retry.clamped().retry_after_ms)]
    CustodyAdmission {
        code: ramflux_protocol::custody::CustodyRefusal,
        retry: ramflux_protocol::custody::RetryHint,
    },
    #[error("born-v3 network registration is pending; legacy proofs are forbidden")]
    NetworkingPending,
    #[error("account networking is pending")]
    NetworkingPendingContext { networking: Box<serde_json::Value>, retry_after_ms: Option<u64> },
    #[error(
        "restore_setup_required: fresh restore requires an independent local data passphrase via --new-passphrase-env"
    )]
    RestoreSetupRequired,
    #[error("no confirmed home node is selected")]
    NoNodeSelected,
    #[error("node is unreachable; retry after {retry_after_ms}ms: {source}")]
    NodeUnreachable {
        retry_after_ms: u64,
        #[source]
        source: Box<SdkError>,
    },
    #[error("node operation timed out; retry after {retry_after_ms}ms")]
    NodeTimeout { retry_after_ms: u64 },
    #[error("born-v3 cannot accept legacy authority")]
    CustodyModeDowngrade,
    #[error("invalid custody setup")]
    CustodySetupInvalid,
    #[error("custody setup expired")]
    CustodyExpired,
    #[error("account id was claimed by another creation flow")]
    CustodyAccountConflict,
    #[error("recovery confirmation failed; setup cancelled")]
    CustodyConfirmationFailed,
    #[error("non-synchronizing primary vault unavailable; no file fallback")]
    CustodyVaultUnavailable,
    #[error("{0}")]
    CustodyVault(crate::custody::CustodyVaultReason),
    #[error("custody randomness unavailable")]
    CustodyRandomUnavailable,
    #[error("account not open: {0}")]
    AccountNotOpen(String),
    #[error("account restore is pending: {0}")]
    AccountRestorePending(String),
    #[error("account restore failed for {account_id}: {reason}")]
    AccountRestoreFailed { account_id: String, reason: String },
    #[error("account manifest is unreadable")]
    AccountManifestUnreadable,
    #[error("{code}: {message}")]
    LocalBusRefused { code: String, message: String, body: Box<serde_json::Value> },
    #[error("{message}")]
    TaskRefused { reason: crate::TaskRefusalCode, message: String },
    #[error("task delivery payload is too large: {bytes} bytes (limit {limit})")]
    TaskDeliveryTooLarge { bytes: usize, limit: usize },
    #[error("{message}")]
    SurfaceRefused { reason: crate::SurfaceRefusalCode, message: String },
    #[error("{operation:?} refused: {source}")]
    GroupRefused {
        operation: GroupOperation,
        #[source]
        source: Box<SdkError>,
    },
    #[error("surface delivery too large: {bytes} bytes exceeds {limit}")]
    SurfaceDeliveryTooLarge { bytes: usize, limit: usize },
    #[error("surface checkpoint does not match its owning row")]
    SurfaceCheckpointMismatch,
    #[error("contact root replacement requires confirmation")]
    ContactConfirmationRequired(Box<crate::ContactRootChange>),
    #[error(
        "contact card names a different home node; automatic cross-node contact routing is unavailable"
    )]
    ContactHomeNodeUnsupported,
    #[error("contact lookup unavailable: {0}")]
    ContactUnavailable(#[source] Box<SdkError>),
    #[error(transparent)]
    ContactInput(#[from] crate::ContactReason),
    #[error("authenticated device pair requires a fresh bootstrap")]
    PairRecoveryRequired,
    #[error("inbound envelope rejected: {0}")]
    InboundRejected(String),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("authenticated envelope replay payload mismatch")]
    ReplayMismatch,
    #[error("inbound state not ready: {0}")]
    InboundPending(String),
    #[error("inbound state not ready: sender manifest must be prepared")]
    SenderManifestRequired { root: String },
    #[error("inbound state not ready: native current-head freshness expired; refresh directory")]
    FreshHeadRequired { root: String },
    #[error("{source}")]
    DirectoryAuthorityUnavailable {
        root: String,
        #[source]
        source: Box<SdkError>,
    },
    #[error("contact admission waits for capacity: {0}")]
    ContactRequestCapacity(String),
    #[error("voice call control receipt capacity exhausted at {limit} receipts")]
    CallControlReceiptCapacity { limit: u64 },
    #[error("task manifest worker capacity is full")]
    TaskManifestWorkerCapacity,
    #[error("task federation forward deadline exceeded")]
    TaskDeliveryTimeout,
    #[error("task federation forward worker capacity is full")]
    TaskForwardWorkerCapacity,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid pairing field: {0}")]
    PairingField(&'static str),
    #[error("pairing {0}")]
    PairingCode(&'static str),
    #[error("storage error: {0}")]
    Storage(#[source] StorageError),
    #[error("sync error: {0}")]
    Sync(#[source] SyncError),
    #[error("transport error: {0}")]
    Transport(#[from] ramflux_transport::TransportError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ramflux_protocol::ProtocolError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("account index is not open")]
    AccountIndexNotOpen,
    #[error("account database is not unlocked")]
    AccountDbNotUnlocked,
    #[error("identity root is not initialized")]
    IdentityRootMissing,
    #[error("gateway session rejected: {0}")]
    GatewaySessionRejected(String),
    #[error("own-device authorization refresh failed: {0}")]
    OwnDeviceAuthorizationRefreshFailed(String),
    #[error("gateway session is not established")]
    GatewaySessionNotEstablished,
    #[error("invalid gateway cursor checkpoint: {0}")]
    InvalidGatewayCursor(String),
    #[error("local bus error: {0}")]
    LocalBus(String),
    #[error("local bus peer credential check failed")]
    LocalBusPermissionDenied,
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    #[error("grant invalidated")]
    GrantInvalidated,
    #[error("signature verification failed for mcp.approval.granted: {0}")]
    SignatureVerificationFailed(String),
    #[error("remote_app approval requires an App-signed mcp.approval.granted")]
    RemoteAppApprovalRequired,
}

impl SdkError {
    pub(crate) fn without_directory_context(self) -> Self {
        match self {
            Self::DirectoryAuthorityUnavailable { source, .. } => {
                (*source).without_directory_context()
            }
            other => other,
        }
    }

    pub(crate) fn directory_source(&self) -> &Self {
        match self {
            Self::DirectoryAuthorityUnavailable { source, .. } => source.directory_source(),
            other => other,
        }
    }

    /// Typed custody refusal category, including a server-supplied daily capacity hint.
    #[must_use]
    pub fn custody_refusal(&self) -> Option<ramflux_protocol::custody::CustodyRefusal> {
        match self {
            Self::CustodyNetwork(code) | Self::CustodyAdmission { code, .. } => Some(code.clone()),
            Self::CustodyCapacity { .. } => {
                Some(ramflux_protocol::custody::CustodyRefusal::Capacity)
            }
            _ => None,
        }
    }

    /// Server admission interval, clamped before exposing it to callers or scheduling.
    #[must_use]
    pub const fn retry_hint(&self) -> Option<ramflux_protocol::custody::RetryHint> {
        if let Self::CustodyAdmission { retry, .. } = self { Some(retry.clamped()) } else { None }
    }

    /// Daily reset metadata supplied by the receiving node, if present.
    #[must_use]
    pub const fn capacity_hint(&self) -> Option<ramflux_protocol::custody::CapacityHint> {
        if let Self::CustodyCapacity { capacity } = self { Some(*capacity) } else { None }
    }
}

impl From<StorageError> for SdkError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::ObjectErased => Self::ObjectErased,
            StorageError::PairingField(name) => Self::PairingField(name),
            other => Self::Storage(other),
        }
    }
}
impl From<SyncError> for SdkError {
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::ObjectErased => Self::ObjectErased,
            other => Self::Sync(other),
        }
    }
}
