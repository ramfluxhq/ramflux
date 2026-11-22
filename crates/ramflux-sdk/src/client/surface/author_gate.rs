// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Renderer authority is a pinned current publication bound to the local record.
//! A cached identity supplies the author's anchor and is not authority by itself.
use crate::{RamfluxClient, SdkError};
impl RamfluxClient {
    /// Whether this owner currently publishes `author` as its own headless agent.
    ///
    /// # Errors
    /// Returns storage or clock errors. Missing or stale authority fails closed.
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
        let now = crate::custody::network_now()?;
        let publication_bound = self.verified_own_agent(anchor, author, now)?;
        owner.owns_surface_agent(author, anchor, now, publication_bound)
    }
}
