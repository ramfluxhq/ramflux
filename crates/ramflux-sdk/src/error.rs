// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

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

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("home migration refused: {0:?}")]
    HomeMigrationRefused(ramflux_protocol::home_migration::Refusal),
    #[error("custody networking refused: {0}")]
    CustodyNetwork(#[from] ramflux_protocol::custody::CustodyRefusal),
    #[error("born-v3 network registration is pending; legacy proofs are forbidden")]
    NetworkingPending,
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
    #[error("recovery confirmation failed; setup cancelled")]
    CustodyConfirmationFailed,
    #[error("non-synchronizing primary vault unavailable; no file fallback")]
    CustodyVaultUnavailable,
    #[error("custody randomness unavailable")]
    CustodyRandomUnavailable,
    #[error("account not open: {0}")]
    AccountNotOpen(String),
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
    #[error("authenticated envelope replay payload mismatch")]
    ReplayMismatch,
    #[error("inbound state not ready: {0}")]
    InboundPending(String),
    #[error("contact admission waits for capacity: {0}")]
    ContactRequestCapacity(String),
    #[error("voice call control receipt capacity exhausted at {limit} receipts")]
    CallControlReceiptCapacity { limit: u64 },
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
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
