// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private server-hop DTOs are separate from the token-free custody client protocol.
use crate::{MigrationPeerCall, MigrationPeerReply, NodeCoreError};
use ramflux_protocol::home_migration::Refusal;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
pub const MIGRATION_PEER_PATH: &str = "/v3/home-migration/peer";
pub const MIGRATION_LOCAL_PATH: &str = "/internal/home-migration/peer";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalMigrationRequest {
    pub admin_token: String,
    pub budget_ms: u64,
    pub action: LocalMigrationAction,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalMigrationAction {
    PeerKey { node_id: String },
    Exchange { call: Box<MigrationPeerCall> },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalMigrationReply {
    PeerKey { node_id: String, public_key: String },
    Peer { reply: Box<MigrationPeerReply> },
    Refused { reason: Refusal },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPeerRequest {
    pub budget_ms: u64,
    pub call: MigrationPeerCall,
}
/// Translate a remaining caller budget without accepting a renewable or excessive timeout.
/// # Errors
/// Rejects zero or more than ten seconds.
pub fn migration_hop_deadline(budget_ms: u64, received: Instant) -> Result<Instant, NodeCoreError> {
    if budget_ms == 0 || budget_ms > 10_000 {
        return Err(NodeCoreError::HomeMigration(Refusal::PeeringUnavailable));
    }
    received
        .checked_add(Duration::from_millis(budget_ms))
        .ok_or(NodeCoreError::HomeMigration(Refusal::PeeringUnavailable))
}
/// Carry only the remainder through every internal and admitted-peer hop.
/// # Errors
/// Rejects expired deadlines and budgets outside the protocol's ten-second ceiling.
pub fn migration_hop_budget(deadline: Instant) -> Result<u64, NodeCoreError> {
    let duration = deadline
        .checked_duration_since(Instant::now())
        .ok_or(NodeCoreError::HomeMigration(Refusal::PeeringUnavailable))?;
    let millis = u64::try_from(duration.as_millis().min(10_000))
        .map_err(|_| NodeCoreError::HomeMigration(Refusal::PeeringUnavailable))?;
    if millis == 0 {
        return Err(NodeCoreError::HomeMigration(Refusal::PeeringUnavailable));
    }
    Ok(millis)
}
