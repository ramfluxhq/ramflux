// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Minimal MVP-0 cryptographic helpers for protocol fixtures.

mod double_ratchet;
mod error;
mod franking;
mod group_sender;
mod identity;
mod kdf;
mod key_verification;
mod prekey;
mod recovery;
mod signing;
mod x3dh;
#[cfg(test)]
mod zeroize_tests;

pub use double_ratchet::{DmCiphertext, DmSession, DmSessionSnapshot};
pub use error::CryptoError;
pub use franking::{
    FrankingCommitment, FrankingCommitmentInput, franking_commitment, franking_node_tag,
    franking_node_tag_preimage, sign_franking_node_tag, verify_franking_node_tag,
};
pub use group_sender::{
    GroupCiphertext, GroupMemberCommitment, GroupSenderKeyDistribution, GroupSenderKeyState,
    MAX_GROUP_SKIP, create_group_sender_key_distribution, membership_commitment_hash,
};
pub use identity::{
    BranchProofDocument, DeviceBranch, DeviceRevocationReplayGuard, IdentityRoot,
    authorize_device_branch, create_device_branch, create_identity_root, verify_branch_proof,
    verifying_key_from_base64url,
};
pub use kdf::{
    MIN_RECOVERY_SECRET_BYTES, RecoverySecret, blake3_256, blake3_256_base64url,
    blake3_keyed_derive, derive_recovery_secret, derive_recovery_secret_secret, event_id,
    random_32,
};
pub(crate) use kdf::{hkdf_sha256, write_len_prefixed};
pub use key_verification::{
    ContactSafetyMaterial, DeviceSafetyMaterial, KtConsistencyProof, KtInclusionProof, KtLeaf,
    KtLeafInput, KtSignedTreeHead, device_set_hash, kt_inclusion_proof, kt_leaf_canonical_hash,
    kt_leaf_hash, kt_merkle_root, kt_parent_hash, registration_pow_digest,
    registration_pow_meets_difficulty, safety_fingerprint, safety_number, sign_kt_leaf,
    sign_kt_tree_head, solve_registration_pow, verify_kt_consistency_prefix,
    verify_kt_consistency_proof, verify_kt_inclusion, verify_kt_inclusion_proof,
    verify_kt_leaf_signature, verify_kt_tree_head,
};
pub use prekey::{
    PrekeyBundle, X25519KeyPair, create_prekey_bundle, create_prekey_bundle_with_lineage,
    verify_prekey_bundle, verify_prekey_bundle_with_lineage,
};
pub use recovery::{
    RecoveryQuorumMemberKind, RecoveryShare, create_recovery_quorum, recover_secret_from_quorum,
};
pub use signing::{
    CanonicalSignatureBatchItem, CanonicalSignatureSingleKeyBatchItem,
    CanonicalSignatureVerifyTimings, fixture_public_key_base64url, fixture_signing_key,
    fixture_verifying_key, public_key_base64url_from_seed, public_key_bytes_from_seed,
    sign_canonical_bytes, sign_canonical_bytes_with_seed, sign_protocol_object,
    sign_protocol_object_with_device_branch, sign_protocol_object_with_seed,
    sign_with_device_branch, verify_canonical_signature, verify_canonical_signature_with_timings,
    verify_canonical_signatures_batch, verify_canonical_signatures_batch_single_key,
    verify_device_branch_signature, verify_fixture_signature,
};
pub use x3dh::{
    BootstrapTranscriptInput, X3dhInitiatorInput, X3dhOutput, X3dhRecipientInput,
    bootstrap_transcript_hash, x3dh_initiator, x3dh_recipient,
};

pub const CRATE_NAME: &str = "ramflux-crypto";
pub const FIXTURE_SIGNING_KEY_ID: &str = "fixture-ed25519-01";
pub const FIXTURE_SIGNING_KEY_BYTES: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}
