// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keep content-free attribution and replay state while retiring every indexed old payload copy.
use super::routed::Committed;
use crate::{RamfluxClient, SdkError};

impl RamfluxClient {
    pub(crate) fn retire_generated_edit_payloads(
        &self,
        conversation: &str,
        target: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let origin = super::delivery_receipts::origin_key(conversation, target)?;
        let exact = [
            format!("routed/original-header/{target}"),
            format!("routed/generated-identity/{target}"),
            format!("routed/generated-order/{target}"),
            format!("routed/generated-display-hlc/{target}"),
            format!("routed/message-metadata/{target}"),
            format!("routed/edit-revision/{target}"),
            origin,
        ];
        let mut keep = exact.to_vec();
        // Receipts keep only authenticated attribution/hash; a retry cannot recover old ciphertext.
        for (key, mut receipt) in
            db.message_actor_entries::<Committed>(target, "routed/committed/")?
        {
            receipt.entry.envelope.encrypted_payload.clear();
            db.persist_message_actor_state(target, &key, &receipt)?;
            keep.push(key);
        }
        for prefix in [
            "routed/reaction/",
            "routed/reaction-operation/",
            "message-delete-fence/",
            "message-delete-tombstone/",
        ] {
            keep.extend(db.message_actor_keys(target, prefix)?);
        }
        db.retire_message_payload_copies(target, &keep)?;
        if let Some(original) = db.load_actor_state::<super::generated_history::OriginalHeader>(
            &format!("routed/original-header/{target}"),
        )? {
            let identity = ramflux_protocol::message::original_header::decode_identity(
                &original.exact_identity,
            )?;
            let author = identity.author.as_ref().ok_or(
                ramflux_protocol::message::original_header::EvidenceError::OriginEvidenceMissing,
            )?;
            db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
                owner_id: target,
                verified_source_anchor: &author.account_anchor,
                copy_id: &format!("history/original-header/{target}"),
                kind: ramflux_storage::RawInnerCopyKind::HistoryContainer,
                bytes: &serde_json::to_vec(&original)?,
                bounded_metadata: &[],
            })?;
        }
        db.persist_message_actor_state(
            target,
            &format!("routed/report-opening-retired/{target}"),
            &true,
        )?;
        Ok(())
    }
}
