#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
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
