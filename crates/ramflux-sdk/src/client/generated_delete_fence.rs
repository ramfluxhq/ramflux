// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free author-qualified pending Delete fences and committed tombstone metadata.
use crate::client::identity_authority::HeadUse;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_PENDING_DELETES_PER_ROOT: usize = 4096;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Moderator {
    pub group: String,
    pub epoch: u64,
    pub device: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Fence {
    pub conversation: String,
    pub target: g::MessageRef,
    pub source_root: String,
    pub source_device: String,
    pub scope: i32,
    pub tombstone_id: Vec<u8>,
    pub matched: bool,
    pub identity: Option<g::EventIdentity>,
    pub moderator: Option<Moderator>,
}
fn pending_prefix(id: &[u8]) -> String {
    format!("message-delete-fence/{}/", ramflux_protocol::encode_base64url(id))
}
fn committed_key(id: &[u8]) -> String {
    format!("message-delete-tombstone/{}", ramflux_protocol::encode_base64url(id))
}
impl RamfluxClient {
    pub(crate) fn install_generated_delete_fence(&self, fence: &Fence) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = if fence.matched {
            committed_key(&fence.target.id)
        } else {
            let authority = ramflux_protocol::canonical_json_bytes(&(
                &fence.source_root,
                fence.scope,
                &fence.moderator,
            ))?;
            format!(
                "{}{}",
                pending_prefix(&fence.target.id),
                ramflux_protocol::encode_base64url(authority)
            )
        };
        if let Some(mut old) = db.load_actor_state::<Fence>(&key)? {
            if fence.scope == g::DeleteScope::Everyone as i32
                && old.scope == g::DeleteScope::Local as i32
            {
                old.scope = fence.scope;
                db.persist_actor_state(&key, &old)?;
            }
            return Ok(());
        }
        if !fence.matched {
            let mut count = 0;
            for scope in db.actor_state_keys("message-delete-fence/")? {
                if db
                    .load_actor_state::<Fence>(&scope)?
                    .is_some_and(|old| old.source_root == fence.source_root)
                {
                    count += 1;
                }
            }
            if count >= MAX_PENDING_DELETES_PER_ROOT {
                return Err(SdkError::GeneratedRefused {
                    code: crate::GeneratedRefusalCode::Authority,
                    reason: "pending Delete fence limit".into(),
                });
            }
        }
        db.persist_actor_state(&key, fence)?;
        Ok(())
    }

    fn pending_delete_authority(
        &self,
        fence: &Fence,
        identity: &g::EventIdentity,
    ) -> Result<bool, SdkError> {
        if fence.conversation != identity.conversation_id {
            return Ok(false);
        }
        if let Some(moderator) = &fence.moderator {
            if identity.group_id.as_ref() != Some(&moderator.group) {
                return Ok(false);
            }
            let source = self.device_identity(&moderator.device)?;
            self.require_cached_root_authority(HeadUse::NewAuthorization, &source)?;
            self.require_native_operation(
                &source,
                crate::client::identity_authority::NativeOperation::Group,
            )?;
            self.require_generated_group_epoch(&moderator.group, &source, moderator.epoch, true)?;
            return Ok(true);
        }
        if fence.scope == g::DeleteScope::Local as i32 {
            if fence.source_root != self.own_account_anchor()? {
                return Ok(false);
            }
            let source = self.device_identity(&fence.source_device)?;
            self.require_cached_root_authority(HeadUse::NewAuthorization, &source)?;
            self.require_native_operation(
                &source,
                crate::client::identity_authority::NativeOperation::Sync,
            )?;
            self.require_native_operation(
                &self.owned_device_identity()?,
                crate::client::identity_authority::NativeOperation::Sync,
            )?;
            return Ok(true);
        }
        Ok(identity
            .author
            .as_ref()
            .is_some_and(|author| author.account_anchor == fence.source_root))
    }

    pub(crate) fn apply_generated_delete_fence(
        &self,
        identity: &g::EventIdentity,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let keys = db.actor_state_keys(&pending_prefix(&identity.id))?;
        let mut selected = None;
        let mut unresolved = std::collections::BTreeSet::new();
        for key in &keys {
            let Some(fence) = db.load_actor_state::<Fence>(key)? else {
                continue;
            };
            match self.pending_delete_authority(&fence, identity) {
                Ok(true) => {
                    selected = Some(fence);
                    break;
                }
                Ok(false)
                | Err(
                    SdkError::InboundRejected(_)
                    | SdkError::GeneratedRefused { .. }
                    | SdkError::Storage(ramflux_storage::StorageError::GroupPermissionDenied),
                ) => (),
                Err(
                    SdkError::InboundPending(_) | SdkError::DirectoryAuthorityUnavailable { .. },
                ) => {
                    unresolved.insert(key.clone());
                }
                Err(error) if crate::client::inbox_failure::deterministic(&error).is_some() => (),
                Err(error) => return Err(error),
            }
        }
        let Some(mut fence) = selected else {
            for key in keys {
                if !unresolved.contains(&key) {
                    db.remove_actor_state(&key)?;
                }
            }
            return Ok(false);
        };
        let id = ramflux_protocol::encode_base64url(&identity.id);
        if !db.message_is_deleted(&id)? {
            if self.direct_message_by_id(&id)?.is_none() {
                db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
                    conversation_id: &identity.conversation_id,
                    message_id: &id,
                    sender_id: "",
                    encrypted_body: &[],
                    metadata: &ramflux_storage::MessageMetadata::default(),
                    created_at: 0,
                })?;
            }
            db.delete_direct_message(
                &identity.conversation_id,
                &id,
                if fence.scope == g::DeleteScope::Local as i32 { "local" } else { "everyone" },
                &ramflux_protocol::encode_base64url(&fence.tombstone_id),
            )?;
        }
        fence.matched = true;
        fence.identity = Some(identity.clone());
        self.install_generated_delete_fence(&fence)?;
        for key in keys {
            db.remove_actor_state(&key)?;
        }
        Ok(true)
    }
}
