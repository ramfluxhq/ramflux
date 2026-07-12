// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::EncryptionMode;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("core error: {0}")]
    Core(#[from] ramflux_core::CoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] ramflux_crypto::CryptoError),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("account key mismatch")]
    AccountKeyMismatch,
    #[error("account database encryption unavailable: {mode:?}")]
    EncryptionUnavailable { mode: EncryptionMode },
    #[error(
        "migration checksum mismatch for version {schema_version}: expected {expected}, got {actual}"
    )]
    MigrationChecksumMismatch { schema_version: i64, expected: String, actual: String },
    #[error("key wrapping failed: {0}")]
    KeyWrappingFailed(String),
    #[error("rekey rollback failed: {0}")]
    RekeyRollbackFailed(String),
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("history bundle hash mismatch")]
    HistoryBundleHashMismatch,
    #[error("authorization rejected")]
    AuthorizationRejected,
    #[error("group member limit exceeded")]
    GroupMemberLimitExceeded,
    #[error("invalid group role: {0}")]
    InvalidGroupRole(String),
    #[error("group permission denied")]
    GroupPermissionDenied,
    #[error("group control event replayed: {0}")]
    GroupControlReplay(String),
    #[error("group control event epoch mismatch: expected {expected}, got {actual}")]
    GroupControlEpochMismatch { expected: u64, actual: u64 },
    #[error("group control signing key missing for {0}")]
    GroupControlSigningKeyMissing(String),
    #[error("group invite missing: {0}")]
    GroupInviteMissing(String),
    #[error("group invite invalid state for {invite_id}: expected {expected}, got {actual}")]
    GroupInviteInvalidState { invite_id: String, expected: String, actual: String },
    #[error("group invite expired: {0}")]
    GroupInviteExpired(String),
    #[error("group invite acceptor mismatch for {0}")]
    GroupInviteAcceptorMismatch(String),
    #[error("group sender key is not distributed")]
    SenderKeyNotDistributed,
    #[error("group member cannot decrypt epoch")]
    GroupEpochAccessDenied,
    #[error("message not found: {0}")]
    MessageNotFound(String),
    #[error("message id conflict: {0}")]
    MessageIdConflict(String),
    #[error("event id conflict: {0}")]
    EventIdConflict(String),
    #[error("identity lifecycle blocks operation: {0}")]
    IdentityLifecycleBlocked(String),
    #[error("pending recovery {recovery_id} is not in expected state: {expected}")]
    InvalidRecoveryState { recovery_id: String, expected: String },
}
