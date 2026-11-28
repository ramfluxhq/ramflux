// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The leaf signature key: a fresh Ed25519 key per KeyPackage/leaf, never the device key.

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use zeroize::Zeroizing;

use crate::MlsError;

/// Secret key length of Ed25519.
const SECRET_BYTES: usize = 32;

/// Leaf signing key. Not `Clone`, not `Debug`; the secret is zeroized on drop.
pub struct LeafSigner {
    secret: Zeroizing<[u8; SECRET_BYTES]>,
    public: [u8; 32],
}

impl LeafSigner {
    /// Generate a fresh key from the process crypto provider.
    ///
    /// # Errors
    /// Provider failure.
    pub fn generate(crypto: &RustCrypto) -> Result<Self, MlsError> {
        let (secret, _public) = crypto
            .signature_key_gen(SignatureScheme::ED25519)
            .map_err(|error| MlsError::Mls(format!("leaf key generation: {error:?}")))?;
        let secret = Zeroizing::new(secret);
        Self::from_secret(&secret)
    }

    /// Rebuild from stored secret bytes.
    ///
    /// # Errors
    /// The slice is not a 32-byte Ed25519 secret.
    pub fn from_secret(secret: &[u8]) -> Result<Self, MlsError> {
        let bytes: [u8; SECRET_BYTES] = secret
            .try_into()
            .map_err(|_| MlsError::internal("leaf secret has the wrong length"))?;
        let public = SigningKey::from_bytes(&bytes).verifying_key().to_bytes();
        Ok(Self { secret: Zeroizing::new(bytes), public })
    }

    /// The public key.
    #[must_use]
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The secret bytes (for storage only).
    #[must_use]
    pub fn secret(&self) -> &[u8; SECRET_BYTES] {
        &self.secret
    }
}

impl Signer for LeafSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key = SigningKey::from_bytes(&self.secret);
        Ok(DalekSigner::sign(&key, payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
