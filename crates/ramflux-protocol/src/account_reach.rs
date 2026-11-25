// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary-authorized reach policy; contact consent and discovery remain independent.
use crate::custody::Envelope;
use serde::{Deserialize, Serialize};

pub const REACH_POLICY_DOMAIN: &str = "ramflux.account.reach.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachMode {
    ContactsOnly,
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachPolicyBody {
    pub version: u8,
    pub account_anchor: String,
    pub home_head_hash: String,
    pub authority_head_hash: String,
    pub operation_id: String,
    pub expected_revision: u64,
    pub revision: u64,
    pub mode: ReachMode,
}

pub type ReachPolicy = Envelope<ReachPolicyBody>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachChange {
    pub mode: ReachMode,
    pub expected_revision: u64,
    pub operation_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachState {
    pub policy: Option<ReachPolicy>,
    pub history: Box<crate::home_migration::ResolveResult>,
    pub authority: Box<Envelope<crate::custody::DeviceSet>>,
    pub conflict: bool,
}

/// Historical signing authority accompanies the policy across transfers and restores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachRecord {
    pub policy: ReachPolicy,
    pub authority: Envelope<crate::custody::DeviceSet>,
}

/// A home-committed permission grants only this peer and conversation, never friendship.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyPermission {
    pub owner_root: String,
    pub peer_root: String,
    pub conversation_id: String,
    pub operation_id: String,
    pub revision: u64,
}
