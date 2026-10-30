// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A bounded deterministic participant; rfd owns credentials, authorization and signed delivery.
mod bus;
mod checkpoint;
mod config;
mod engine;
mod participant;
mod provisioning;
mod runner;
mod runner_deferred;
mod runner_output;
mod runner_policy;
mod runner_refusal;
mod runner_surface;
mod surface_plan;
pub use bus::{AgentBus, RfdBus};
pub use checkpoint::{Checkpoint, CheckpointStore, GroupRefusal, OutputRefusal};
pub use config::{Choice, Config, Rule, SurfaceRule};
pub use engine::{ActionInput, ConversationInput, EngineProvider, Intent, RuleEngine};
pub use provisioning::{CredentialVault, import_provisioning_bundle, unlock_provisioned_account};
pub use runner::AgentHost;

pub type Result<T> = std::result::Result<T, Error>;
/// Errors intentionally omit rfd bodies, message text, paths and credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("group output requires refreshed branch authority")]
    GroupLeaseUnavailable,
    #[error("surface output refused: {0:?}")]
    SurfaceRefused(ramflux_sdk::SurfaceRefusalCode),
    #[error("host identity is unavailable or revoked")]
    IdentityLost,
    #[error("durable host storage is unavailable")]
    Storage,
    #[error("malformed local row field: {0}")]
    MalformedField(&'static str),
    #[error("invalid host configuration")]
    Config,
    #[error("host state could not be read or persisted")]
    State,
    #[error("rfd request or connection failed")]
    Bus,
    #[error("headless participant identity or membership unavailable")]
    Unauthorized,
    #[error("bounded host resource exhausted")]
    Limit,
    #[error("event stream requires reconnect and snapshot reload")]
    Resync,
}

impl Error {
    /// Only local identity loss and unrecoverable durable storage stop the running process.
    #[must_use]
    pub const fn stops_host(&self) -> bool {
        matches!(self, Self::IdentityLost | Self::Storage)
    }
}
