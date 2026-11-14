// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unified recipient-owned reach policy, independent of friendship and discovery.
mod deferred;
pub use deferred::{ephemeral_frame, unavailable};
mod groups;
pub use groups::*;
mod admission;
mod continuity;
pub mod group_profile;
pub use continuity::{NodeContinuityDocument, NodeContinuityKind, NodeKeyRotation};
pub mod directory;
mod foreign;
pub use foreign::*;
mod policy;
mod provenance;
mod route;
mod state;
pub use provenance::*;
#[cfg(test)]
mod tests;
pub use admission::*;
pub use policy::*;
pub use route::*;
pub use state::*;

mod codec;
mod domains;
pub(crate) use codec::{actor, digest, invalid, lifetime, node, safe, text};
pub use codec::{check_submission_time, decode, original_document, validate_node_selector};
pub use domains::*;
