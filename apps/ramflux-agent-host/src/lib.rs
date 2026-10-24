// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A bounded deterministic participant; rfd owns credentials, authorization and signed delivery.
mod bus;
mod checkpoint;
mod config;
mod engine;
mod participant;
mod runner;
mod runner_output;
mod runner_surface;
pub use bus::{AgentBus, RfdBus};
pub use checkpoint::{Checkpoint, CheckpointStore};
pub use config::{Choice, Config, Rule, SurfaceRule};
pub use engine::{ActionInput, ConversationInput, EngineProvider, Intent, RuleEngine};
pub use runner::AgentHost;

pub type Result<T> = std::result::Result<T, Error>;
/// Errors intentionally omit rfd bodies, message text, paths and credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
