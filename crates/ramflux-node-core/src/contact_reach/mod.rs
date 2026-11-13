// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiving-home reach state and bounded admission, shared by local and foreign routes.
mod cost;
mod ephemeral;
mod profile;
pub use ephemeral::{ReachEphemeralAdmission, ReachEphemeralContext};
mod service;
mod snapshots;
pub use service::{ReachService, ReachSession};
mod ingress;
mod state;
mod store;
pub use cost::CostIssuerPeer;
pub use ingress::{ReachIngress, ReachPending};
pub use state::{AccountReach, ReachClass};
pub use store::ReachOwner;

mod error;
pub use error::{ReachError, Result};
pub(super) use error::{refuse, storage};
pub use ramflux_protocol::contact_reach::enabled;
