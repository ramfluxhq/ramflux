// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ramflux_protocol::ProtocolError;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("base64url decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid ed25519 signature length: {0}")]
    InvalidSignatureLength(usize),
    #[error("invalid ed25519 public key length: {0}")]
    InvalidPublicKeyLength(usize),
    #[error("ed25519 verification failed")]
    VerifyFailed,
    #[error("aead operation failed")]
    AeadFailed,
    #[error("hkdf output expansion failed")]
    HkdfFailed,
    #[error("hmac initialization failed")]
    HmacFailed,
    #[error("random bytes unavailable: {0}")]
    RandomUnavailable(String),
    #[error("argon2id derivation failed: {0}")]
    Argon2(String),
    #[error("recovery secret must contain at least 128 bits of input material")]
    WeakRecoverySecret,
    #[error("committing aead key commitment mismatch")]
    KeyCommitmentMismatch,
    #[error("committing aead commitment mismatch")]
    CommitmentMismatch,
    #[error("message skip limit exceeded")]
    MaxSkipExceeded,
    #[error("unsupported dm session snapshot")]
    UnsupportedDmSessionSnapshot,
    #[error("group sender key is missing or revoked")]
    GroupSenderKeyUnavailable,
    #[error("group membership commitment mismatch")]
    MembershipCommitmentMismatch,
    #[error("recovery quorum has invalid parameters")]
    RecoveryQuorumInvalidParameters,
    #[error("recovery quorum does not contain enough unique shares")]
    RecoveryQuorumInsufficient,
    #[error("device branch is revoked")]
    DeviceRevoked,
    #[error("branch proof replay detected")]
    BranchProofReplay,
    #[error("transparency proof failed")]
    TransparencyProofFailed,
    #[error("invalid home node migration proof: {0}")]
    InvalidHomeNodeMigrationProof(&'static str),
}
