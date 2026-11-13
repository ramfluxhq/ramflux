// SPDX-License-Identifier: BSD-3-Clause
use crate::CardError;
use ed25519_dalek::{Signature, VerifyingKey};

/// Engine + bytecode format + host catalog identity; engine upgrades regenerate packages.
pub const ENGINE_ID: &str = "ramflux-card/v1;rquickjs=0.14.0;quickjs-ng=0.16.2;host=1";
pub(crate) const MAX_PACKAGE: usize = 64 * 1024;
const DOMAIN: &[u8] = b"ramflux-card-signed-bytecode-v1\0";
/// Bytes are private so unsigned packages cannot reach the bytecode loader.
#[derive(Clone)]
pub struct SignedPackage {
    pub(crate) bytecode: Vec<u8>,
}
impl SignedPackage {
    /// Verify a project-built package using an application-pinned trust key.
    /// The key MUST come from the host release, never a peer or package payload.
    /// # Errors
    /// Rejects oversized/empty packages and signatures for a different engine or payload.
    pub fn verify(
        bytecode: &[u8],
        signature: &[u8; 64],
        trusted_key: &[u8; 32],
    ) -> Result<Self, CardError> {
        if bytecode.is_empty() || bytecode.len() > MAX_PACKAGE {
            return Err(CardError::Limit("package"));
        }
        let key = VerifyingKey::from_bytes(trusted_key).map_err(|_| CardError::Signature)?;
        key.verify_strict(&signing_message(bytecode), &Signature::from_bytes(signature))
            .map_err(|_| CardError::Signature)?;
        Ok(Self { bytecode: bytecode.to_vec() })
    }
}
pub(crate) fn signing_message(bytecode: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(ENGINE_ID.as_bytes());
    message.push(0);
    message.extend_from_slice(bytecode);
    message
}
