// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary history keeps the original signer and never promotes a forwarding envelope.
use super::*;
use crate::client::raw_inner_origin::{RetainedOrigin, VerifiedOrigin};
use crate::client::routed::{Kind, Routing};

impl RamfluxClient {
    pub(crate) fn verify_history_message_origin(
        item: &g::HistoryItem,
    ) -> Result<(g::EventIdentity, RetainedOrigin, VerifiedOrigin), SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let scanned = g::validation::scan_inner(&item.exact_inner).map_err(|_| bad)?;
        if scanned.kind != 1
            || item.tombstone.is_some()
            || item.original_metadata_evidence.is_some()
            || !item.exact_original_identity.is_empty()
        {
            return Err(bad.into());
        }
        let inner = g::Inner::decode(item.exact_inner.as_slice()).map_err(|_| bad)?;
        let identity = inner.identity.ok_or(bad)?;
        let origin = RetainedOrigin {
            evidence: item.source_evidence.clone().ok_or(EvidenceError::OriginEvidenceMissing)?,
            reported_inner: Vec::new(),
            routing: Routing {
                kind: if identity.group_id.is_some() { Kind::GroupMessage } else { Kind::Direct },
                conversation_id: identity.conversation_id.clone(),
                message_id: ramflux_protocol::encode_base64url(&identity.id),
                group_id: identity.group_id.clone(),
                group_message_id: None,
                attachments: false,
            },
        };
        let verified = origin.verify(&identity, &item.exact_inner)?;
        if verified.outer.delivery_mode.as_deref() != Some("durable")
            || verified.outer.delivery_class != ramflux_protocol::DeliveryClass::Message
        {
            return Err(bad.into());
        }
        Ok((identity, origin, verified))
    }
}

impl RamfluxClient {
    /// Export the current exact Message/Edit with its original private signed evidence.
    /// Retired bodies and openings are never reconstructed from a replacement.
    /// # Errors
    /// Refuses deleted/missing content, absent origins and invalid original proofs.
    pub fn export_generated_history_item(
        &self,
        message_id: &[u8],
    ) -> Result<g::HistoryItem, SdkError> {
        if message_id.len() != 32 {
            return Err(EvidenceError::OriginEvidenceMissing.into());
        }
        let id = ramflux_protocol::encode_base64url(message_id);
        let db = self.account_db()?;
        if db.message_is_deleted(&id)? {
            return Err(EvidenceError::ReportOpeningRetired.into());
        }
        let exact_inner = db.message_content(&id)?.ok_or(EvidenceError::OriginEvidenceMissing)?;
        let inner = g::Inner::decode(exact_inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        if inner.kind == 3 {
            let original = db
                .load_actor_state::<OriginalHeader>(&format!("routed/original-header/{id}"))?
                .ok_or(EvidenceError::OriginEvidenceMissing)?;
            let source_evidence = db
                .load_actor_state::<Option<g::HistoryOriginEvidence>>(&format!(
                    "routed/current-edit-proof/{id}"
                ))?
                .flatten()
                .ok_or(EvidenceError::OriginEvidenceMissing)?;
            let item = g::HistoryItem {
                exact_inner,
                source_evidence: Some(source_evidence),
                exact_original_identity: original.exact_identity,
                original_metadata_evidence: Some(original.evidence),
                tombstone: None,
            };
            if self.verify_generated_edited_history_item(&item)?.id != message_id {
                return Err(EvidenceError::EditTargetMismatch.into());
            }
            return Ok(item);
        }
        let origin = db
            .load_actor_state::<RetainedOrigin>(&format!("routed/origin-evidence/{id}"))?
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        // Only raw-I origins are legal on the activated history wire; no legacy carrier fallback.
        if !origin.reported_inner.is_empty() {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        let item = g::HistoryItem {
            exact_inner,
            source_evidence: Some(origin.evidence.clone()),
            ..Default::default()
        };
        let (identity, _, _) = Self::verify_history_message_origin(&item)?;
        if identity.id != message_id {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        Ok(item)
    }
}
