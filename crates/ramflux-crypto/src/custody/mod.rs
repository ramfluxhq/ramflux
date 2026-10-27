// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 account authority. Legacy v1/v2 signing functions remain separate.
mod genesis;
mod keys;
mod management;
pub use genesis::{GenesisInput, create_genesis};
mod phrase;
mod pins;
pub use pins::{AuthorityPins, PinOutcome};
mod validate;
mod verify;
pub use keys::{MasterKey, SelfSigningKey};
pub use phrase::RecoveryPhrase;
pub use verify::{
    CapacityLimit, CapacityPressure, VerifiedRecord, verify_publication, verify_record,
};

#[cfg(test)]
mod tests;

fn random_secret() -> Result<zeroize::Zeroizing<[u8; 32]>, crate::CryptoError> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| crate::CryptoError::RandomUnavailable(error.to_string()))?;
    Ok(bytes)
}

mod branch_proof;
mod node_identity;
pub use branch_proof::{
    MAX_BRANCH_PROOF_BYTES, ProofChannel, branch_exporter_hash, sign_branch_proof_v3,
    sign_proxy_acceptance, verify_branch_proof_v3,
};
pub use node_identity::{
    NodeKeyBinding, VerifiedNodeRecord, sign_node_identity_record, verify_node_identity_record,
};

#[cfg(test)]
mod network_tests;

mod safety;
pub use safety::{safety_fingerprint, safety_number};

mod contact;
pub use contact::verify_contact_consent;
