// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-identity signing key input for operator-enabled device pairing.
//!
//! Pairing tickets and invitations are bound to the pinned node identity, so the router reads
//! that key from its own single mounted file. There is no fallback to the service-signing seed.
use ramflux_node_core::NodeSecret;

/// Path of the mounted node-identity signing seed, required when pairing is enabled.
pub(crate) const PAIRING_KEY_FILE_ENV: &str = "RAMFLUX_ROUTER_PAIRING_NODE_SIGNING_SEED_FILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairingKeyError {
    /// The setting is unset or empty.
    Missing,
    /// The file is unreadable, has a refused mode, is oversized or is not a 32-byte base64url key.
    Malformed,
    /// The key does not match the verified node identity record.
    Mismatch,
}

impl std::fmt::Display for PairingKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => {
                write!(
                    f,
                    "pairing requires {PAIRING_KEY_FILE_ENV} (node identity signing key file)"
                )
            }
            Self::Malformed => {
                write!(
                    f,
                    "pairing node identity signing key file ({PAIRING_KEY_FILE_ENV}) is invalid"
                )
            }
            Self::Mismatch => {
                f.write_str("pairing ticket signing key does not match node identity")
            }
        }
    }
}

impl std::error::Error for PairingKeyError {}

/// Loads the mounted key and verifies it against the trusted node identity public key.
pub(crate) fn load(node_public_key: &str) -> Result<[u8; 32], PairingKeyError> {
    let path = ramflux_node_core::environment::var_os(PAIRING_KEY_FILE_ENV)
        .filter(|value| !value.is_empty())
        .ok_or(PairingKeyError::Missing)?;
    let secret = NodeSecret::from_file(path).map_err(|_| PairingKeyError::Malformed)?;
    let seed = secret.with_bytes(|bytes| *bytes);
    if ramflux_crypto::public_key_base64url_from_seed(seed) != node_public_key {
        return Err(PairingKeyError::Mismatch);
    }
    Ok(seed)
}
