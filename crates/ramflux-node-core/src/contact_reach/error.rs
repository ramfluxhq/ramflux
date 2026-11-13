// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed reach refusals and storage propagation without protocol detail leaks.
use crate::NodeCoreError;
use ramflux_protocol::contact_reach::Reason;
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
pub(crate) fn storage(error: impl std::fmt::Display) -> ReachError {
    NodeCoreError::Redb(error.to_string()).into()
}
pub(crate) fn refuse(reason: Reason) -> ReachError {
    ReachError::Refused(reason)
}
pub type Result<T> = std::result::Result<T, ReachError>;
