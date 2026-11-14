// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiving-home reach state and bounded admission, shared by local and foreign routes.
mod cost;
mod cost_owner;
pub use cost_owner::ReachCostTransport;
mod forward;
mod public_prekeys;
pub use forward::{ReachCapability, ReachDeliveryClass, ReachForward};
mod ephemeral;
mod profile;
pub use ephemeral::{ReachEphemeralAdmission, ReachEphemeralContext};
mod resolver;
pub use resolver::ReachPeerResolver;
mod service;
mod submit;
pub use submit::ReachSourceSubmitter;
mod source;
pub use source::{ReachSnapshotContext, ReachSourceDocuments};
mod snapshots;
pub use service::{ReachService, ReachSession};
mod ingress;
mod report_receipt;
mod state;
mod store;
pub use cost::CostIssuerPeer;
pub use ingress::{ReachIngress, ReachPending};
pub use state::{AccountReach, ReachClass};
pub use store::ReachOwner;
pub(crate) use store::require_empty_reach_activation;

mod error;
pub(crate) use error::owner_error;
pub use error::{ReachError, Result};
pub(super) use error::{refuse, storage};
pub use ramflux_protocol::contact_reach::enabled;

mod carrier;
pub(crate) use carrier::{require_legacy_durable, require_submission_carrier};
