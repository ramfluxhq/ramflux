// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Greatest-pair early Edit retention, charged to the authenticated source's raw quota.
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use crate::client::identity_authority::HeadUse;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Pending { revision: u64, event_id: Vec<u8>, copy_id: String, committed_key: String }
fn key(target: &str) -> String { format!("routed/pending-edit/{target}") }
impl RamfluxClient {
    pub(crate) fn park_generated_edit(&self, entry: &GatewayInboxEntry, identity: &g::EventIdentity, edit: &g::Edit, bytes: &[u8]) -> Result<(), SdkError> {
        let target = edit.target.as_ref().ok_or_else(|| SdkError::InboundRejected("edit target missing".into()))?;
        let target_id = ramflux_protocol::encode_base64url(&target.id);
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let db = self.account_db()?;
        let key = key(&target_id);
        if let Some(old) = db.load_actor_state::<Pending>(&key)? {
            if (edit.revision, identity.id.as_slice()) <= (old.revision, old.event_id.as_slice()) { return Ok(()); }
            db.finish_raw_inner_reparse(&old.copy_id)?;
        }
        let pending = Pending {
            revision: edit.revision, event_id: identity.id.clone(),
            copy_id: format!("early-edit/{target_id}/{}", ramflux_protocol::encode_base64url(&identity.id)),
            committed_key: self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?,
        };
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: &ramflux_protocol::encode_base64url(&identity.id), verified_source_anchor: source.root_commitment(), copy_id: &pending.copy_id,
            kind: ramflux_storage::RawInnerCopyKind::OuterInner, bytes, bounded_metadata: &serde_json::to_vec(&pending)?,
        })?;
        db.bind_raw_inner_copy(&pending.copy_id, &target_id)?;
        db.persist_message_actor_state(&target_id, &key, &pending)?;
        Ok(())
    }

    pub(crate) fn resolve_generated_pending_edit(&self, conversation: &str, target_id: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = key(target_id);
        let Some(pending) = db.load_actor_state::<Pending>(&key)? else { return Ok(()); };
        let Some(raw) = db.raw_inner_copy(&pending.copy_id)? else { db.remove_actor_state(&key)?; return Ok(()); };
        let Some(committed) = db.load_actor_state::<crate::client::routed::Committed>(&pending.committed_key)? else { return Ok(()); };
        match self.apply_generated_edit_entry(&committed.entry, conversation, &raw.bytes) {
            Ok(_) | Err(SdkError::InboundRejected(_) | SdkError::GeneratedRefused { .. }) => {
                db.finish_raw_inner_reparse(&pending.copy_id)?;
                db.remove_actor_state(&key)?;
            }
            Err(SdkError::InboundPending(_)) => (),
            Err(error) => return Err(error),
        }
        Ok(())
    }
}
