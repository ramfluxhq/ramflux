// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed client for the PRX management API.
//!
//! The client talks to a PRX daemon on loopback with a bearer token. It knows
//! nothing about ramflux accounts, custody or the bus. Every route is
//! documented in PRX's token document (`docs/rf-contract/capability-tokens.md`
//! at the pinned commit); unknown 2xx fields and malformed bodies fail closed.

mod agent;
mod apply;
mod autonomy;
mod capabilities;
mod catalog;
mod client;
mod error;
mod name;
mod revision;
mod targeted;
#[cfg(test)]
mod test_support;
mod transport;

pub use agent::{
    AgentConfig, AgentList, AgentReadback, AgentStatus, MainReadback, PROMPT_MAX_BYTES, PutKind, PutOutcome, Retired,
    Tools,
};
pub use apply::ApplyOutcome;
pub use autonomy::Autonomy;
pub use capabilities::{
    AGENT_CATALOG_V1, AGENT_CRUD_V1, AGENT_MAIN_READBACK_V1, BuildCommit, CAPABILITIES_V1, Capabilities, require,
};
pub use catalog::{Catalog, CatalogModel, CatalogTool};
pub use client::PrxClient;
pub use error::{ApiCode, PrxError};
pub use name::AgentName;
pub use revision::{CatalogRevision, ConfigRevision};
pub use targeted::{ReloadReport, TargetedAgents};
pub use transport::{ClientConfig, DEFAULT_MAX_BODY_BYTES, DEFAULT_REQUEST_TIMEOUT};
