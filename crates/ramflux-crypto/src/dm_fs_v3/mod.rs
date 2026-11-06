// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native bootstrap cryptography over bounded canonical public documents.
//! Signature validity does not establish current authority, freshness or admission.
mod signing;
pub use signing::{
    NativePrekeySigner, NativeSignatureDomain, sign_base, sign_lease_result, sign_opk,
    sign_owner_status, sign_owner_update, sign_request, verify_base, verify_lease_result,
    verify_opk, verify_owner_status, verify_owner_update, verify_request,
};
mod hashes;
pub use hashes::{
    NATIVE_HASH_RULES, NativeHashRule, NativePrekeyArgument, base_hash, branch_binding,
    bundle_hash, frame_result_hash, lease_operation_id, publication_snapshot_hash,
    request_argument_hash, request_hash, retirement_digest, transcript_hash,
};
mod transcript;
pub use transcript::{bootstrap_transcript, verify_bootstrap_transcript};

/// Public validation failure, containing no credential or untrusted input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativePrekeyError {
    /// Canonical framing or bounds failed.
    #[error(transparent)]
    Decode(#[from] ramflux_protocol::dm_fs_v3::DecodeError),
    /// Signature or public key failed strict verification.
    #[error("native prekey signature rejected")]
    Signature,
    /// A supplied signer does not own the named public key.
    #[error("native prekey signer mismatch")]
    SignerMismatch,
    /// A public commitment or cross-document binding disagrees.
    #[error("native prekey binding mismatch")]
    Binding,
}
#[cfg(test)]
mod signature_tests;
