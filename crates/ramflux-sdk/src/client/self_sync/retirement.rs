// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Superseded drafts/read publications cannot survive in retry bodies or repair fingerprints.
use super::{RamfluxClient, SdkError};

impl RamfluxClient {
    pub(super) fn retire_self_sync_publications(&self, scope: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for prefix in ["self-sync/pending/", "self-sync/repair/", "self-sync/repair-sent/"] {
            for key in db.actor_state_keys(prefix)? {
                if db
                    .load_actor_state::<serde_json::Value>(&key)?
                    .is_some_and(|value| value["scope"].as_str() == Some(scope))
                {
                    db.retire_self_sync_actor(&key)?;
                }
            }
        }
        db.retire_self_sync_actor(scope)?;
        Ok(())
    }

    pub(super) fn persist_self_sync_owned_state(
        &self,
        key: &str,
        value: &serde_json::Value,
        references: &[super::Reference],
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.persist_actor_state(key, value)?;
        for reference in references {
            db.persist_message_actor_state(&reference.message_id, key, value)?;
        }
        Ok(())
    }
}
