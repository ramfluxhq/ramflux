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
    #[error("group sender key is not distributed")]
    SenderKeyNotDistributed,
    #[error("group member cannot decrypt epoch")]
    GroupEpochAccessDenied,
    #[error("message not found: {0}")]
    MessageNotFound(String),
    #[error("identity lifecycle blocks operation: {0}")]
    IdentityLifecycleBlocked(String),
}
