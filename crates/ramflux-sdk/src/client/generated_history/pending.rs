// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{EvidenceError, RamfluxClient, SdkError, g};
use crate::client::identity_authority::HeadUse;
use prost::Message as _;
#[derive(serde::Serialize, serde::Deserialize)]
struct Pending {
    revision: u64,
    event_id: Vec<u8>,
    copy: String,
    receipt: String,
}
impl RamfluxClient {
    pub(crate) fn park_generated_history_edit(
        &self,
        entry: &crate::GatewayInboxEntry,
        item: &g::HistoryItem,
        identity: &g::EventIdentity,
        edit: &g::Edit,
        source_root: &str,
    ) -> Result<(), SdkError> {
        let target = edit.target.as_ref().ok_or(EvidenceError::EditTargetMismatch)?;
        let id = ramflux_protocol::encode_base64url(&target.id);
        let db = self.account_db()?;
        let key = format!("routed/pending-history-edit/{id}");
        if let Some(previous) = db.load_actor_state::<Pending>(&key)? {
            if (edit.revision, identity.id.as_slice())
                <= (previous.revision, previous.event_id.as_slice())
            {
                return Ok(());
            }
            db.finish_raw_inner_reparse(&previous.copy)?;
        }
        let copy = format!("history/early-edit/{id}");
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: &ramflux_protocol::encode_base64url(&identity.id),
            verified_source_anchor: source_root,
            copy_id: &copy,
            kind: ramflux_storage::RawInnerCopyKind::HistoryContainer,
            bytes: &item.encode_to_vec(),
            bounded_metadata: &[],
        })?;
        db.bind_raw_inner_copy(&copy, &id)?;
        // The enclosing authenticated own-copy receive writes this receipt in its W1 transaction.
        let receipt = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
        db.bind_message_container_reference(&id, &receipt)?;
        db.persist_message_actor_state(
            &id,
            &key,
            &Pending { revision: edit.revision, event_id: identity.id.clone(), copy, receipt },
        )?;
        Ok(())
    }

    pub(crate) fn resolve_generated_pending_history_edit(
        &self,
        target: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        // A known header/placeholder does not mean Message content is available.
        // Keep the parked edit until its target can actually be edited.
        if db.message_content(target)?.is_none() {
            return Ok(());
        }
        let key = format!("routed/pending-history-edit/{target}");
        let Some(pending) = db.load_actor_state::<Pending>(&key)? else {
            return Ok(());
        };
        let Some(raw) = db.raw_inner_copy(&pending.copy)? else {
            db.remove_actor_state(&key)?;
            return Ok(());
        };
        let Some(receipt) =
            db.load_actor_state::<crate::client::routed::Committed>(&pending.receipt)?
        else {
            return Ok(());
        };
        let item = g::HistoryItem::decode(raw.bytes.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        self.authenticated_device_identity(HeadUse::NewAuthorization, &receipt.entry)?;
        match self.apply_generated_history_edit(&receipt.entry, &item) {
            Ok(_)
            | Err(
                SdkError::HistoryEvidence(_)
                | SdkError::GeneratedRefused { .. }
                | SdkError::InboundRejected(_),
            ) => {
                db.finish_raw_inner_reparse(&pending.copy)?;
                db.remove_actor_state(&key)?;
            }
            Err(SdkError::InboundPending(_) | SdkError::DirectoryAuthorityUnavailable { .. }) => (),
            Err(error) => return Err(error),
        }
        Ok(())
    }
}
