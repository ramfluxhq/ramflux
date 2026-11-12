// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One error type for the platform-neutral web core.

/// Failures of the web host. No variant carries key material or a frame body.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum WebError {
    /// The WebSocket did not negotiate exactly the contract (subprotocol, extensions).
    #[error("web transport refused: {0}")]
    Transport(&'static str),
    /// A server frame was malformed, oversized or illegal in the current state.
    #[error("web session protocol violation: {0}")]
    Protocol(&'static str),
    /// A check that must pass before the branch proof is signed failed. Nothing was signed.
    #[error("web origin binding refused: {0}")]
    Binding(&'static str),
    /// The local clock is more than five minutes from the node's. Shown as a clock message.
    #[error("local clock differs from the node clock")]
    Clock,
    /// The node refused the custody exchange.
    #[error("node refused the web session")]
    Refused,
    /// The requested ceremony does not exist in a browser build.
    #[error("custody vault unavailable on web: {0}")]
    CustodyVaultUnavailable(&'static str),
    /// A tab-carrier frame failed admission.
    #[error("carrier frame refused: {0}")]
    Carrier(&'static str),
    /// Encrypted storage is unavailable; the store stays closed.
    #[error("web store unavailable: {0}")]
    StoreUnavailable(&'static str),
    /// The browser vault could not wrap or unwrap.
    #[error("web vault unavailable: {0}")]
    VaultUnavailable(&'static str),
    /// The enrolment bundle is not acceptable for this browser.
    #[error("web link refused: {0}")]
    Link(&'static str),
    /// A browser API is missing or failed.
    #[error("browser API unavailable: {0}")]
    Browser(&'static str),
    /// Canonical encoding failed.
    #[error("encoding failed")]
    Encoding,
}

impl From<ramflux_protocol::ProtocolError> for WebError {
    fn from(_: ramflux_protocol::ProtocolError) -> Self {
        Self::Encoding
    }
}

impl From<serde_json::Error> for WebError {
    fn from(_: serde_json::Error) -> Self {
        Self::Protocol("frame is not valid JSON for this state")
    }
}
