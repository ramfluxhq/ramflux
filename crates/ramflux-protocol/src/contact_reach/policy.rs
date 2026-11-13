// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed receiving policy; username discoverability does not grant reach permission.
use super::{COMMAND_LIFETIME, actor, digest, invalid, lifetime, safe};
use crate::{ProtocolError, custody::DeviceRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachMode {
    ContactsOnly,
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachPolicy {
    pub version: u32,
    pub operation_id: String,
    pub account_anchor: String,
    pub home_head_hash: String,
    pub expected_revision: u64,
    pub revision: u64,
    pub mode: ReachMode,
    pub authority_head_hash: String,
    pub master_certificate_hash: String,
    pub actor: DeviceRef,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ReachPolicy {
    /// Validate the closed policy body without treating it as authenticated.
    /// # Errors
    /// Refuses invalid hashes, versions, revisions and submission lifetimes.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for value in [
            &self.operation_id,
            &self.account_anchor,
            &self.home_head_hash,
            &self.authority_head_hash,
            &self.master_certificate_hash,
        ] {
            digest(value)?;
        }
        actor(&self.actor)?;
        safe(self.expected_revision)?;
        safe(self.revision)?;
        if self.version != 1 || self.expected_revision.checked_add(1) != Some(self.revision) {
            return Err(invalid("reach policy version or revision"));
        }
        lifetime(self.issued_at, self.expires_at, COMMAND_LIFETIME)
    }
}
