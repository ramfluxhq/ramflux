// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Renderer authority comes from the local creator registry, never a peer actor-kind claim.
use crate::{RamfluxClient, SdkError};
impl RamfluxClient {
    /// Whether the local user's verified creator registry owns this agent principal.
    /// # Errors
    /// Returns storage or custody verification errors. Missing authority fails closed.
    pub fn surface_author_is_own_agent(&self, author: &str) -> Result<bool, SdkError> {
        let Some(owner) = &self.born_v3_account else {
            return Ok(false);
        };
        let Some(identity) = self.account_db()?.client_record("identity", author)? else {
            return Ok(false);
        };
        let Some(anchor) =
            identity.get("contact_identity_commitment").and_then(serde_json::Value::as_str)
        else {
            return Ok(false);
        };
        owner.owns_surface_agent(author, anchor, crate::custody::network_now()?)
    }
}
