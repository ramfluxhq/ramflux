// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiving-home reach state and bounded admission, shared by local and foreign routes.
mod cost;
mod profile;
mod service;
mod snapshots;
pub use service::ReachService;
mod ingress;
mod state;
mod store;
use crate::NodeCoreError;
pub use ingress::{ReachIngress, ReachPending};
use ramflux_protocol::contact_reach::Reason;
pub use state::{AccountReach, ReachClass};
pub use store::ReachOwner;

#[derive(Debug, thiserror::Error)]
pub enum ReachError {
    #[error("contact reach refused: {0:?}")]
    Refused(Reason),
    #[error("reach revision conflict: current {0}")]
    Revision(u64),
    #[error(transparent)]
    Protocol(#[from] ramflux_protocol::ProtocolError),
    #[error(transparent)]
    Crypto(#[from] ramflux_crypto::CryptoError),
    #[error(transparent)]
    Storage(#[from] NodeCoreError),
}
pub(super) fn storage(error: impl std::fmt::Display) -> ReachError {
    NodeCoreError::Redb(error.to_string()).into()
}
pub(super) fn refuse(reason: Reason) -> ReachError {
    ReachError::Refused(reason)
}
pub type Result<T> = std::result::Result<T, ReachError>;

/// Read the initial default-off whole-profile activation switch.
/// # Errors
/// Refuses invalid values instead of partially activating a carrier.
pub fn enabled() -> std::result::Result<bool, NodeCoreError> {
    match std::env::var("RAMFLUX_CONTACT_REACH_ENABLED") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(value) if value == "0" => Ok(false),
        _ => Err(NodeCoreError::InvalidConfiguration(
            "invalid contact reach activation switch".into(),
        )),
    }
}
