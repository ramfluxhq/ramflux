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
pub use verify::{CapacityLimit, CapacityPressure, VerifiedRecord, verify_record};

#[cfg(test)]
mod tests;

fn random_secret() -> Result<zeroize::Zeroizing<[u8; 32]>, crate::CryptoError> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| crate::CryptoError::RandomUnavailable(error.to_string()))?;
    Ok(bytes)
}
