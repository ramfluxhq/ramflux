// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Edited history can establish a body-free original, never reconstruct its erased content.
use super::{OriginalHeader, authority};
use crate::client::raw_inner_origin::VerifiedOrigin;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
use serde_json::Value;

impl RamfluxClient {
    /// Called inside the import writer after original and Edit evidence verification.
    pub(super) fn bootstrap_generated_edited_target(
        &self,
        item: &g::HistoryItem,
        original: &g::EventIdentity,
    ) -> Result<bool, SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let db = self.account_db()?;
        let id = ramflux_protocol::encode_base64url(&original.id);
        if db.message_is_deleted(&id)? || self.apply_generated_delete_fence(original)? {
            return Ok(false);
        }
        if self.direct_message_by_id(&id)?.is_some() {
            return Ok(true);
        }
        let evidence =
            item.original_metadata_evidence.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?;
        let outer: Value = ramflux_protocol::parse_i_json(&evidence.canonical_sender_envelope)?;
        let author = authority(
            &outer,
            evidence.source_authority.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?,
            original,
        )?;
        // This placeholder supplies signed routing/time only; signature verification above
        // uses the exact retained outer, which has no ciphertext or retired report opening.
        let mut placeholder = outer;
        placeholder["encrypted_payload"] = Value::String(String::new());
        let verified =
            VerifiedOrigin { author, outer: serde_json::from_value(placeholder).map_err(|_| bad)? };
        self.bind_history_message_conversation(original, &verified)?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: &original.conversation_id,
            message_id: &id,
            sender_id: &verified.outer.source_principal_id,
            encrypted_body: &[],
            metadata: &ramflux_storage::MessageMetadata::default(),
            created_at: verified.outer.created_at,
        })?;
        db.persist_message_actor_state(&id, &format!("routed/generated-identity/{id}"), original)?;
        db.persist_message_actor_state(
            &id,
            &crate::client::delivery_receipts::origin_key(&original.conversation_id, &id)?,
            &serde_json::json!({
                "sender_device_id": verified.author.device.device_id(),
                "sender_root_commitment": verified.author.root,
                "sender_device_display": verified.author.device.storage_key(),
                "direction": if verified.author.root == self.own_account_anchor()? { "outgoing" } else { "incoming" },
            }),
        )?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-order/{id}"),
            &original.hlc,
        )?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-display-hlc/{id}"),
            &crate::client::generated_identity::order_hlc(
                original.hlc,
                crate::client::generated_identity::now_ms(),
            ),
        )?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/original-header/{id}"),
            &OriginalHeader {
                exact_identity: item.exact_original_identity.clone(),
                evidence: evidence.clone(),
            },
        )?;
        Ok(true)
    }
}
