use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use ramflux_core::DomainTag;
use secrecy::Secret;
use sha2::Sha256;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

pub const MIN_RECOVERY_SECRET_BYTES: usize = 16;
const RECOVERY_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const RECOVERY_ARGON2_TIME_COST: u32 = 3;
const RECOVERY_ARGON2_PARALLELISM: u32 = 1;

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RecoverySecret([u8; 32]);

impl RecoverySecret {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RecoverySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RecoverySecret").field(&"<redacted>").finish()
    }
}

#[must_use]
pub fn blake3_256(domain_tag: &str, bytes: &[u8]) -> [u8; 32] {
    with_core_domain_tag(domain_tag, |domain_tag| {
        ramflux_protocol::blake3_hash_bytes(domain_tag, bytes)
    })
}

#[must_use]
pub fn blake3_256_base64url(domain_tag: &str, bytes: &[u8]) -> String {
    with_core_domain_tag(domain_tag, |domain_tag| {
        ramflux_protocol::hash_base64url(domain_tag, bytes)
    })
}

#[must_use]
pub fn blake3_keyed_derive(key: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(context);
    hasher.finalize().into()
}

fn with_core_domain_tag<R>(domain_tag: &str, hash: impl FnOnce(&str) -> R) -> R {
    let typed = DomainTag::new(domain_tag);
    match typed.as_ref() {
        Ok(domain_tag) => hash(domain_tag.as_str()),
        Err(_err) => hash(domain_tag),
    }
}

/// # Errors
/// Returns an error when the operating system CSPRNG cannot provide fresh key material.
pub fn random_32() -> Result<[u8; 32], CryptoError> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| CryptoError::RandomUnavailable(error.to_string()))?;
    Ok(seed)
}

#[must_use]
pub fn event_id(actor_device_id: &str, device_counter: u64, random_nonce: &[u8]) -> String {
    ramflux_protocol::event_id(actor_device_id, device_counter, random_nonce)
}

pub(crate) fn write_len_prefixed(output: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(&bytes[..usize::from(len)]);
}

/// Derives a recovery secret using Argon2id, not a fast hash.
///
/// The input must be a client-generated CSPRNG recovery secret. Human memorable
/// passwords or passphrases are not valid root recovery factors for this API;
/// callers that accept user-entered text must first transform it through a
/// separate audited password-to-secret enrollment flow.
///
/// # Errors
/// Returns an error if the input secret is shorter than 128 bits, or if the
/// Argon2id parameter set or KDF invocation fails.
pub fn derive_recovery_secret(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<RecoverySecret, CryptoError> {
    Ok(RecoverySecret::new(derive_recovery_secret_bytes(passphrase, salt)?))
}

fn derive_recovery_secret_bytes(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    // This is the minimum byte-length floor required by the offline vault and identity-lineage
    // designs. Stronger entropy estimation is a separate policy layer.
    if passphrase.len() < MIN_RECOVERY_SECRET_BYTES {
        return Err(CryptoError::WeakRecoverySecret);
    }
    // Recovery protects offline root restoration, so prefer a memory-hard cost over fast UX.
    // 256 MiB keeps local recovery practical while materially raising brute-force cost.
    let params = Params::new(
        RECOVERY_ARGON2_MEMORY_KIB,
        RECOVERY_ARGON2_TIME_COST,
        RECOVERY_ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|err| CryptoError::Argon2(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|err| CryptoError::Argon2(err.to_string()))?;
    Ok(output)
}

/// Derives an Argon2id recovery secret wrapped in `secrecy`.
///
/// The input must be a client-generated CSPRNG recovery secret, not a human
/// memorable password or passphrase.
///
/// # Errors
/// Returns an error if the input secret is shorter than 128 bits, or if Argon2id derivation fails.
pub fn derive_recovery_secret_secret(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Secret<[u8; 32]>, CryptoError> {
    Ok(Secret::new(derive_recovery_secret_bytes(passphrase, salt)?))
}

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(salt).map_err(|_err| CryptoError::HmacFailed)?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    let mut previous = Vec::new();
    let mut offset = 0usize;
    let mut counter = 1u8;
    while offset < output.len() {
        let mut expand =
            <HmacSha256 as Mac>::new_from_slice(&prk).map_err(|_err| CryptoError::HmacFailed)?;
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        previous = expand.finalize().into_bytes().to_vec();
        let remaining = output.len() - offset;
        let take = remaining.min(previous.len());
        output[offset..offset + take].copy_from_slice(&previous[..take]);
        offset += take;
        counter = counter.checked_add(1).ok_or(CryptoError::HkdfFailed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"ramflux-recovery-test-salt";

    #[test]
    fn recovery_secret_rejects_less_than_128_bits() {
        let weak = [0x41_u8; MIN_RECOVERY_SECRET_BYTES - 1];

        assert!(matches!(
            derive_recovery_secret(&weak, SALT),
            Err(CryptoError::WeakRecoverySecret)
        ));
        assert!(matches!(
            derive_recovery_secret_secret(&weak, SALT),
            Err(CryptoError::WeakRecoverySecret)
        ));
    }

    #[test]
    fn recovery_secret_accepts_at_least_128_bits() -> Result<(), CryptoError> {
        let strong = [0x42_u8; MIN_RECOVERY_SECRET_BYTES];

        let derived = derive_recovery_secret(&strong, SALT)?;
        let _secrecy_derived = derive_recovery_secret_secret(&strong, SALT)?;

        assert_ne!(derived.expose(), &[0_u8; 32]);
        Ok(())
    }
}
