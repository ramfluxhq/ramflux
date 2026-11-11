// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free diagnostics for raw quota holds; ledger/native bounds own retained work.
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use crate::client::identity_authority::HeadUse;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Diagnostic {
    source_anchor: String, envelope_id: String, payload_hash: String,
    expires_at: i64, first_seen: i64, local_retention_deadline_elapsed: bool,
}
impl RamfluxClient {
    pub(crate) fn record_generated_capacity(&self, entry: &GatewayInboxEntry, source: &str, now: i64) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let id = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
        let key = format!("raw-capacity/diagnostic/{id}");
        let old = db.load_actor_state::<Diagnostic>(&key)?;
        let expires_at = entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl));
        db.persist_actor_state(&key, &Diagnostic {
            source_anchor: source.into(), envelope_id: entry.envelope.envelope_id.clone(), payload_hash: entry.envelope.payload_hash.clone(),
            expires_at, first_seen: old.map_or(now, |old| old.first_seen), local_retention_deadline_elapsed: now >= expires_at,
        })?;
        db.persist_actor_state(&format!("raw-capacity/held/{id}"), &true)?;
        let keys = db.actor_state_keys("raw-capacity/diagnostic/")?;
        let excess = keys.len().saturating_sub(64);
        for old in keys.into_iter().filter(|old| old != &key).take(excess) { db.remove_actor_state(&old)?; }
        Ok(())
    }

    pub(crate) fn generated_capacity_held(&self, entry: &GatewayInboxEntry) -> Result<bool, SdkError> {
        let id = match self.authenticated_committed_key(HeadUse::NewAuthorization, entry) {
            Ok(id) => id,
            Err(SdkError::Storage(error)) => return Err(SdkError::Storage(error)),
            Err(_) => return Ok(false),
        };
        Ok(self.account_db()?.load_actor_state::<bool>(&format!("raw-capacity/held/{id}"))?.unwrap_or(false))
    }

    pub(crate) fn clear_generated_capacity(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        let id = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
        self.account_db()?.remove_actor_state(&format!("raw-capacity/held/{id}"))?;
        self.account_db()?.remove_actor_state(&format!("raw-capacity/diagnostic/{id}"))?;
        Ok(())
    }
}
