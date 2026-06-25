// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("core error: {0}")]
    Core(#[from] ramflux_core::CoreError),
    #[error("object not found")]
    ObjectNotFound,
    #[error("object tombstoned")]
    ObjectTombstoned,
    #[error("object key is missing")]
    ObjectKeyMissing,
    #[error("capability denied")]
    CapabilityDenied,
    #[error("invalid MCP capability: {0}")]
    InvalidMcpCapability(String),
    #[error("grant invalidated")]
    GrantInvalidated,
    #[error("A2UI render rejected")]
    A2uiRejected,
    #[error("bot manifest rejected")]
    BotManifestRejected,
    #[error("bot install grant rejected")]
    BotInstallGrantRejected,
    #[error("bot revoked")]
    BotRevoked,
    #[error("WebRTC relay must not hold media key")]
    MediaKeyLeak,
    #[error("franking verification failed")]
    FrankingVerificationFailed,
    #[error("node trust rejected")]
    NodeTrustRejected,
    #[error("federation route not found")]
    RouteNotFound,
    #[error("object chunk index is out of range")]
    ChunkOutOfRange,
    #[error("object chunk hash mismatch")]
    ChunkHashMismatch,
    #[error("object chunk AEAD verification failed")]
    ChunkAeadFailed,
    #[error("backup manifest signature invalid")]
    BackupManifestSignatureInvalid,
    #[error("LAN announce signature invalid")]
    LanAnnounceSignatureInvalid,
    #[error("LAN announce device epoch rollback")]
    LanAnnounceEpochRollback,
    #[error("LAN peer principal mismatch")]
    LanPeerPrincipalMismatch,
    #[error("LAN peer pairing is pending")]
    LanPeerPending,
    #[error("peer proof signature invalid")]
    PeerProofInvalid,
    #[error("peer proof nonce replayed")]
    PeerProofNonceReplay,
    #[error("resume token signature invalid")]
    ResumeTokenInvalid,
    #[error("object tombstone signature invalid")]
    ObjectTombstoneInvalid,
    #[error("contact gossip reported conflicting identity checkpoint")]
    ContactGossipFork,
    #[error("crypto error: {0}")]
    Crypto(#[from] ramflux_crypto::CryptoError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ramflux_protocol::ProtocolError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
