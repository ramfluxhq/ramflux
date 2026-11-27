// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device authority: the directory path (rule V, local knowledge only).
//!
//! The directory path ([`DeviceAuthority`]) lets the SDK's custody directory answer "what is the
//! current verified record of this anchor". It is used where rule V allows local freshness
//! knowledge: the adding device's own `KeyPackage` check, the sender's pre-seal check, the
//! receiver's application-message check, and display. It never decides the validity of a received
//! commit or Welcome; those use the pure device-chain check (`ramflux_crypto::custody::
//! verify_device_chain`) only.

pub use ramflux_crypto::custody::VerifiedRecord;

/// The directory path: the current verified record of an account anchor, if the directory has one.
///
/// `anchor` is the UTF-8 of the canonical base64url account anchor.
pub trait DeviceAuthority: Send + Sync {
    /// The current verified head record of `anchor`, or `None` when it is unknown.
    fn current(&self, anchor: &[u8]) -> Option<VerifiedRecord>;
}

/// The default authority: knows nothing, so every device credential answers `authority_needed`.
pub struct NoAuthority;

impl DeviceAuthority for NoAuthority {
    fn current(&self, _anchor: &[u8]) -> Option<VerifiedRecord> {
        None
    }
}
