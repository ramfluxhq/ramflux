// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! UniFFI projection of the ramflux core API for Swift and Kotlin hosts.
//!
//! Two operations, on every language: `execute(request) -> outcome` with a deadline and a
//! cancel handle, and `subscribe(filter, listener) -> subscription` with credit back-pressure
//! and an explicit cancel. The interface is defined by proc-macros in this crate:
//!
//! - `types.rs`    records and enums
//! - `error.rs`    the error enum (stable numeric codes)
//! - `listener.rs` the host-implemented update listener
//! - `ramflux_core.rs` the `RamfluxCore` object
//! - `wait.rs`     the `CancelHandle` object
//! - `subscription.rs` the `Subscription` object
//! - `version.rs`  version functions
//!
//! Nothing in this crate executes account logic. Every call goes through one [`CorePort`].

#[cfg(feature = "embedded")]
mod embedded;
mod error;
mod listener;
mod port;
mod ramflux_core;
mod subscription;
mod types;
mod version;
mod wait;

#[cfg(test)]
mod tests;

pub use crate::ramflux_core::RamfluxCore;
pub use crate::error::{CoreError, ErrorDetail, code};
pub use crate::listener::UpdateListener;
pub use crate::port::{CorePort, PortRequest, PortSubscription, UpdateSink};
pub use crate::subscription::Subscription;
pub use crate::types::{
    ApiVersion, CoreConfig, CoreRequest, CoreResponse, CoreState, ExecuteOutcome, HostHandshake,
    Negotiated, NetworkChange, SubscribeFilter, SubscriptionEnd, SuspendEvidence, UpdateRow,
    UpdateState, WaiterEnd,
};
pub use crate::version::{
    BINDING_API_MAJOR, BINDING_API_MINOR, CAPABILITIES, binding_api_version,
    descriptor_fingerprint, negotiate, negotiate_with,
};
pub use crate::wait::{CancelHandle, ClaimGate, ClaimKind, ReplySender};

uniffi::setup_scaffolding!();

/// The port `RamfluxCore::open` uses.
#[cfg(feature = "embedded")]
fn embedded_port(config: &CoreConfig) -> Result<std::sync::Arc<dyn CorePort>, CoreError> {
    embedded::port(config)
}

/// Without the `embedded` feature there is no core to open; `with_port` still works.
#[cfg(not(feature = "embedded"))]
fn embedded_port(_config: &CoreConfig) -> Result<std::sync::Arc<dyn CorePort>, CoreError> {
    Err(CoreError::plain(
        code::CAPABILITY_REJECTED,
        "this library was built without the embedded core (feature `embedded`)",
    ))
}
