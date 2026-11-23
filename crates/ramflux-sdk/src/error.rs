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

/// Stable durable generated-message refusal class, shared with receive admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GeneratedRefusalCode {
    Identity,
    Authority,
    Content,
    TypingDurable,
    OriginEvidenceMissing,
    OriginCommitmentMismatch,
}
impl GeneratedRefusalCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "generated_identity",
            Self::Authority => "generated_authority",
            Self::Content => "generated_content",
            Self::TypingDurable => "typing_durable",
            Self::OriginEvidenceMissing => "generated_origin_evidence_missing",
            Self::OriginCommitmentMismatch => "generated_origin_commitment_mismatch",
        }
    }
}
impl std::fmt::Display for GeneratedRefusalCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which confirm check failed. Tokens are static and contain no secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyConfirmReason {
    PassphraseEmpty,
    PassphraseTooLong,
    PassphraseNotUtf8,
    /// The new account code is not exactly six ASCII digits.
    PassphraseNotSixDigits,
    /// The new account code is on the closed trivial list.
    PassphraseTrivialCode,
    /// 1-based recovery-phrase position. The expected word is not part of the reason.
    WordMismatch {
        position: u8,
    },
    DisplayName,
    OperationId,
}

impl CustodyConfirmReason {
    /// Bus status family this check belongs to.
    #[must_use]
    pub const fn family(self) -> &'static str {
        match self {
            Self::WordMismatch { .. } => "CustodyConfirmationFailed",
            Self::PassphraseEmpty
            | Self::PassphraseTooLong
            | Self::PassphraseNotUtf8
            | Self::PassphraseNotSixDigits
            | Self::PassphraseTrivialCode
            | Self::DisplayName
            | Self::OperationId => "CustodySetupInvalid",
        }
    }

    /// Stable `reason_code`. `word_N` is the 1-based position, never the word.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::PassphraseEmpty => "passphrase_empty",
            Self::PassphraseTooLong => "passphrase_too_long",
            Self::PassphraseNotUtf8 => "passphrase_not_utf8",
            Self::PassphraseNotSixDigits => "not_six_digits",
            Self::PassphraseTrivialCode => "trivial_code",
            Self::DisplayName => "display_name",
            Self::OperationId => "operation_id",
            Self::WordMismatch { position } => word_reason(position),
        }
    }

    /// Inverse of [`Self::token`]. Unknown or mismatched text is refused.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "passphrase_empty" => Self::PassphraseEmpty,
            "passphrase_too_long" => Self::PassphraseTooLong,
            "passphrase_not_utf8" => Self::PassphraseNotUtf8,
            "not_six_digits" => Self::PassphraseNotSixDigits,
            "trivial_code" => Self::PassphraseTrivialCode,
            "display_name" => Self::DisplayName,
            "operation_id" => Self::OperationId,
            _ => return word_from_token(token),
        })
    }

    /// Restore the typed check when the status family matches the token.
    #[must_use]
    pub fn decode(code: &str, reason_code: Option<&str>) -> Option<SdkError> {
        let reason = Self::from_token(reason_code?)?;
        (reason.family() == code).then_some(SdkError::CustodyConfirmRejected(reason))
    }
}

const WORD_REASONS: [&str; 24] = [
    "word_1", "word_2", "word_3", "word_4", "word_5", "word_6", "word_7", "word_8", "word_9",
    "word_10", "word_11", "word_12", "word_13", "word_14", "word_15", "word_16", "word_17",
    "word_18", "word_19", "word_20", "word_21", "word_22", "word_23", "word_24",
];

fn word_reason(position: u8) -> &'static str {
    match usize::from(position).checked_sub(1) {
        Some(index) => WORD_REASONS.get(index).copied().unwrap_or("word_rejected"),
        None => "word_rejected",
    }
}

fn word_from_token(token: &str) -> Option<CustodyConfirmReason> {
    let index = WORD_REASONS.iter().position(|candidate| *candidate == token)?;
    let position = u8::try_from(index.checked_add(1)?).ok()?;
    Some(CustodyConfirmReason::WordMismatch { position })
}

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error(transparent)]
    Search(#[from] ramflux_storage::local_search::SearchError),
    #[error(transparent)]
    SurfaceProtocol(#[from] ramflux_protocol::a2ui::Reject),
    #[error("priority session calls cannot await account writer checkpoints")]
    PriorityWriterAccess,
    #[error("gateway_writer_busy: retryable")]
    GatewayWriterBusy,
    #[error(transparent)]
    GeneratedApi(#[from] Box<crate::bindings::AdapterError>),
    #[error("receive epoch reconciliation refused: {0}")]
    ReceiveEpochReconcile(#[from] ReceiveEpochReconcileFailure),
    #[error(transparent)]
    HistoryEvidence(#[from] ramflux_protocol::message::original_header::EvidenceError),
    #[error("raw storage capacity for {source_anchor} ({scope:?})")]
    StorageCapacity { source_anchor: String, scope: ramflux_storage::RawInnerQuotaScope },
    #[error("{code}: {reason}")]
    GeneratedRefused { code: GeneratedRefusalCode, reason: String },
    #[error("self sync pin limit reached (100 active pins per conversation)")]
    PinLimitReached,
    #[error("edit conflict for {target}: expected revision {expected}, received {received}")]
    EditConflict { target: String, expected: u64, received: u64 },
    #[error("offline retention {0} is outside 3600..=604800 seconds")]
    InvalidOfflineRetention(u64),
    #[error(transparent)]
    PassphrasePolicy(#[from] crate::passphrase::PassphrasePolicyError),
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
    #[error("username directory refused: {}", .0.as_str())]
    UsernameDirectoryRefused(ramflux_protocol::username_directory::DirectoryCode),
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
    /// The home node does not advertise `agent_custody_authorization_v1`. Refused before any
    /// agent key, reservation or account write.
    #[error("the home node does not advertise agent custody authorization")]
    AgentCustodyUnsupported,
    /// An agent creation request refused before any effect. The token is a closed wire reason
    /// (for example `desktop_required` or `creation_pairing_required`), never prose.
    #[error("agent creation refused: {0}")]
    AgentCreationRefused(&'static str),
    #[error("invalid custody setup")]
    CustodySetupInvalid,
    /// A confirm check failed. The reason token names the check and never a secret.
    #[error("custody confirm rejected")]
    CustodyConfirmRejected(CustodyConfirmReason),
    #[error("custody setup expired")]
    CustodyExpired,
    #[error("account id was claimed by another creation flow")]
    CustodyAccountConflict,
    #[error("recovery confirmation failed; setup cancelled")]
    CustodyConfirmationFailed,
    #[error("custody authority publication failed")]
    CustodyPublicationFailed,
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
    /// Classifies a captured NACK using the same strict mapper as live gateway operations.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn gateway_nack_for_test(reason: String) -> Self {
        Self::gateway_nack(reason)
    }

    pub(crate) fn gateway_nack(reason: String) -> Self {
        if reason == "gateway_writer_busy: retryable" {
            Self::GatewayWriterBusy
        } else {
            Self::GatewaySessionRejected(reason)
        }
    }
    pub(crate) fn gateway_writer_busy(&self) -> bool {
        match self {
            Self::GatewayWriterBusy => true,
            Self::LifecycleShared(error) => error.gateway_writer_busy(),
            _ => false,
        }
    }

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

impl From<crate::bindings::AdapterError> for SdkError {
    fn from(error: crate::bindings::AdapterError) -> Self {
        Self::GeneratedApi(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::SdkError;
    #[test]
    fn writer_busy_discriminator_requires_exact_wire_reason() {
        assert!(matches!(
            SdkError::gateway_nack("gateway_writer_busy: retryable".into()),
            SdkError::GatewayWriterBusy
        ));
        for reason in [
            "relay v3 token issue rejected: gateway_writer_busy: retryable",
            "submit source rejected: gateway_writer_busy: retryable",
            "gateway_writer_busy: retryable extra",
        ] {
            assert!(matches!(
                SdkError::gateway_nack(reason.into()),
                SdkError::GatewaySessionRejected(_)
            ));
        }
    }
}
