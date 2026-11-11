// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free revision floors survive message and conversation erasure.
use super::{Deserialize, RamfluxClient, SdkError, Serialize, State};

#[derive(Serialize, Deserialize)]
struct Floor {
    conversation_id: String,
    revision: String,
}
#[derive(Serialize, Deserialize)]
struct Fence {
    conversation_id: String,
    erased: bool,
}

fn floor_key(scope: &str) -> String {
    scope.replacen("self-sync/state/", "self-sync/revision/", 1)
}
fn fence_key(root: &str, conversation: &str) -> Result<String, SdkError> {
    Ok(format!(
        "self-sync/erase/{}",
        ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&(
            root,
            conversation
        ))?)
    ))
}

impl RamfluxClient {
    pub(super) fn self_sync_revision_floor(&self, scope: &str) -> Result<u64, SdkError> {
        self.account_db()?.load_actor_state::<Floor>(&floor_key(scope))?.map_or(Ok(0), |floor| {
            floor.revision.parse().map_err(|_| {
                SdkError::InboundRejected("self sync: invalid stored revision floor".into())
            })
        })
    }
    pub(super) fn remember_self_sync_revision(
        &self,
        conversation: &str,
        scope: &str,
        revision: u64,
    ) -> Result<(), SdkError> {
        let revision = revision.max(self.self_sync_revision_floor(scope)?);
        self.account_db()?.persist_actor_state(
            &floor_key(scope),
            &Floor { conversation_id: conversation.into(), revision: format!("{revision:020}") },
        )?;
        Ok(())
    }
    pub(super) fn self_sync_conversation_erased(
        &self,
        root: &str,
        conversation: &str,
    ) -> Result<bool, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Fence>(&fence_key(root, conversation)?)?
            .is_some_and(|fence| fence.erased))
    }
    /// Erase own replicated values and pending deliveries while retaining revision floors.
    /// # Errors
    /// Returns authority and storage failures; the erase is atomic.
    pub fn erase_self_sync_conversation(&self, conversation: &str) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        self.authorize_self_sync(&own, conversation)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            for key in db.actor_state_keys("self-sync/state/")? {
                let Some(state) = db.load_actor_state::<State>(&key)? else {
                    continue;
                };
                if state.conversation_id != conversation {
                    continue;
                }
                self.remember_self_sync_revision(conversation, &key, state.value.revision)?;
                db.remove_actor_state(&key)?;
            }
            for prefix in ["self-sync/pending/", "self-sync/repair/"] {
                for key in db.actor_state_keys(prefix)? {
                    if db.load_actor_state::<serde_json::Value>(&key)?.is_some_and(|value| {
                        value["conversation_id"].as_str() == Some(conversation)
                    }) {
                        db.remove_actor_state(&key)?;
                    }
                }
            }
            db.persist_actor_state(
                &fence_key(own.root_commitment(), conversation)?,
                &Fence { conversation_id: conversation.into(), erased: true },
            )?;
            Ok(())
        })
    }
    /// Explicit local re-creation releases the conversation fence, preserving every floor.
    /// # Errors
    /// Returns authority and storage failures.
    pub fn recreate_self_sync_conversation(&self, conversation: &str) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        self.authorize_self_sync(&own, conversation)?;
        self.account_db()?.persist_actor_state(
            &fence_key(own.root_commitment(), conversation)?,
            &Fence { conversation_id: conversation.into(), erased: false },
        )?;
        Ok(())
    }
}
