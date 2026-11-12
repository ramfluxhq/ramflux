// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root transport authority and original Message evidence remain separate.
use super::*;
use crate::client::identity_authority::NativeOperation;
use crate::client::raw_inner_origin::{RetainedOrigin, VerifiedOrigin};

impl RamfluxClient {
    pub(crate) fn import_generated_history_message(
        &self,
        sibling: &ramflux_crypto::RootQualifiedDeviceRef,
        item: &g::HistoryItem,
    ) -> Result<bool, SdkError> {
        if sibling.root_commitment() != self.own_account_anchor()? {
            return Err(EvidenceError::EditAuthorMismatch.into());
        }
        self.require_native_operation(sibling, NativeOperation::Sync)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        let (identity, origin, verified) = Self::verify_history_message_origin(item)?;
        if identity.device_sequence & (1 << 63) != 0 {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            self.authorize_history_message_scope(&identity)?;
            let id = ramflux_protocol::encode_base64url(&identity.id);
            if db.message_is_deleted(&id)? || self.apply_generated_delete_fence(&identity)? {
                return Ok(false);
            }
            if db
                .load_actor_state::<bool>(&format!("routed/report-opening-retired/{id}"))?
                .unwrap_or(false)
            {
                // A copy of the replaced original cannot reopen its body or report oracle.
                return Ok(false);
            }
            if let Some(stored) = db.message_content(&id)? {
                return if stored == item.exact_inner {
                    Ok(false)
                } else {
                    Err(SdkError::ReplayMismatch)
                };
            }
            self.install_history_message(item, &identity, &origin, &verified)
        })
    }

    pub(crate) fn authorize_history_message_scope(
        &self,
        identity: &g::EventIdentity,
    ) -> Result<(), SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let db = self.account_db()?;
        if let Some(group) = identity.group_id.as_ref() {
            g::dm_scope::validate_group(&identity.conversation_id).map_err(|_| bad)?;
            let local = self.owned_device_identity()?;
            let state = db.shared_group_state(group)?.ok_or_else(|| {
                SdkError::InboundPending("history group state is not available".into())
            })?;
            let joined = db.group_member_joined_epoch(group, &local)?.ok_or(bad)?;
            if state.snapshot().genesis.conversation_id != identity.conversation_id
                || state.view().effective_role(local.root_commitment(), local.device_id()).is_none()
                || identity.group_epoch.is_none_or(|epoch| epoch < joined)
            {
                return Err(bad.into());
            }
            if let Some(thread) = db.client_record("conversation", &identity.conversation_id)?
                && (thread["kind"] != "group"
                    || thread["group_id"].as_str() != Some(group.as_str()))
            {
                return Err(bad.into());
            }
        } else {
            let author = identity.author.as_ref().ok_or(bad)?;
            g::dm_scope::validate_direct(
                &identity.conversation_id,
                &self.own_account_anchor()?,
                &author.account_anchor,
            )
            .map_err(|_| bad)?;
            if let Some(thread) = db.client_record("conversation", &identity.conversation_id)? {
                let expected = std::collections::BTreeSet::from([
                    self.own_account_anchor()?,
                    author.account_anchor.clone(),
                ]);
                let roots = thread["participant_roots"]
                    .as_array()
                    .filter(|roots| roots.len() == 2)
                    .map(|roots| {
                        roots
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect::<std::collections::BTreeSet<_>>()
                    });
                if thread["kind"] != "direct"
                    || !thread["group_id"].is_null()
                    || roots.as_ref() != Some(&expected)
                {
                    return Err(bad.into());
                }
            }
        }
        Ok(())
    }

    fn install_history_message(
        &self,
        item: &g::HistoryItem,
        identity: &g::EventIdentity,
        origin: &RetainedOrigin,
        verified: &VerifiedOrigin,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let scanned = g::validation::scan_inner(&item.exact_inner)
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        let supported = scanned.outcome == g::validation::ScanOutcome::Supported
            && (identity.group_id.is_none()
                || g::validation::scan_message(
                    "Message",
                    &origin.evidence.group_plaintext,
                    scanned.layer,
                ) == Ok(g::validation::ScanOutcome::Supported));
        self.bind_history_message_conversation(identity, verified)?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: &identity.conversation_id,
            message_id: &id,
            sender_id: &verified.outer.source_principal_id,
            encrypted_body: &[],
            metadata: &ramflux_storage::MessageMetadata::default(),
            created_at: verified.outer.created_at,
        })?;
        db.persist_message_actor_state(&id, &format!("routed/generated-identity/{id}"), identity)?;
        db.persist_message_actor_state(&id, &crate::client::delivery_receipts::origin_key(&identity.conversation_id, &id)?, &serde_json::json!({
            "sender_device_id": verified.author.device.device_id(), "sender_root_commitment": verified.author.root,
            "sender_device_display": verified.author.device.storage_key(), "direction": "incoming",
        }))?;
        self.install_history_original_header(&id, &item.exact_inner, origin)?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-order/{id}"),
            &identity.hlc,
        )?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-display-hlc/{id}"),
            &crate::client::generated_identity::order_hlc(
                identity.hlc,
                crate::client::generated_identity::now_ms(),
            ),
        )?;
        if supported {
            db.replace_generated_message_content(
                &identity.conversation_id,
                &id,
                &item.exact_inner,
                &ramflux_storage::MessageMetadata::default(),
            )?;
            self.persist_known_origin(&id, origin)?;
            if identity.group_id.is_some() {
                let message = g::Message::decode(origin.evidence.group_plaintext.as_slice())
                    .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
                db.persist_message_actor_state(
                    &id,
                    &format!("routed/group-projection/{id}"),
                    &message,
                )?;
                db.persist_message_actor_state(
                    &id,
                    &format!("routed/group-content/{id}"),
                    &origin.evidence.group_plaintext,
                )?;
            }
            self.resolve_generated_pending_edit(&identity.conversation_id, &id)?;
            self.resolve_generated_pending_history_edit(&id)?;
        } else {
            self.retain_history_unsupported(item, identity, origin, verified)?;
        }
        let row = self.direct_message_by_id(&id)?.ok_or(EvidenceError::OriginCommitmentMismatch)?;
        let update = self.generated_message_update(&row, &identity.conversation_id, 0)?;
        db.append_message_update(
            &format!("history/item/{id}"),
            "message.received",
            &update,
            crate::time::now_unix_timestamp(),
        )?;
        Ok(true)
    }
}

impl RamfluxClient {
    fn bind_history_message_conversation(
        &self,
        identity: &g::EventIdentity,
        verified: &VerifiedOrigin,
    ) -> Result<(), SdkError> {
        if let Some(group) = identity.group_id.as_ref() {
            return self.merge_routed_group_link(group, &identity.conversation_id);
        }
        let db = self.account_db()?;
        if db.client_record("conversation", &identity.conversation_id)?.is_none() {
            let own = self.own_account_anchor()?;
            let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            db.persist_client_record("conversation", &identity.conversation_id, &serde_json::json!({
                "kind": "direct", "group_id": null, "title": null, "direct_route": null,
                "participants": [local.principal_id, verified.outer.source_principal_id],
                "participant_roots": std::collections::BTreeSet::from([own, verified.author.root.clone()]),
            }))?;
        }
        Ok(())
    }

    fn install_history_original_header(
        &self,
        id: &str,
        bytes: &[u8],
        origin: &RetainedOrigin,
    ) -> Result<(), SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let scanned = g::validation::scan_inner(bytes).map_err(|_| bad)?;
        let message = g::Message::decode(scanned.body).map_err(|_| bad)?;
        let original = OriginalHeader {
            exact_identity: g::original_header::exact_identity(bytes)?.to_vec(),
            evidence: g::HistoryOriginalMetadataEvidence {
                canonical_sender_envelope: origin.evidence.canonical_sender_envelope.clone(),
                source_authority: origin.evidence.source_authority.clone(),
                group_membership: origin.evidence.group_membership.clone(),
                group_binding: message.sealed_group.as_ref().map(g::original_header::group_binding),
                layer: scanned.layer,
            },
        };
        let db = self.account_db()?;
        let key = format!("routed/original-header/{id}");
        if let Some(previous) = db.load_actor_state::<OriginalHeader>(&key)? {
            if !previous.matches(&original)? {
                return Err(bad.into());
            }
        } else {
            db.persist_message_actor_state(id, &key, &original)?;
        }
        Ok(())
    }

    fn retain_history_unsupported(
        &self,
        item: &g::HistoryItem,
        identity: &g::EventIdentity,
        origin: &RetainedOrigin,
        verified: &VerifiedOrigin,
    ) -> Result<(), SdkError> {
        use crate::client::routed::generated_receive::Provenance;
        use ramflux_storage::{RawInnerCopyKind, RawInnerCopyWrite};
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let proof_id = origin.copy_id()?;
        let copy_id = format!("{proof_id}/inner");
        let db = self.account_db()?;
        let provenance = Provenance {
            source: verified.author.device.storage_key().into(),
            conversation: identity.conversation_id.clone(),
            message: id.clone(),
            envelope_id: verified.outer.envelope_id.clone(),
            payload_hash: verified.outer.payload_hash.clone(),
            expires_at: verified.outer.created_at.saturating_add(i64::from(verified.outer.ttl)),
            original_mode: "durable".into(),
            source_epoch: identity
                .author
                .as_ref()
                .ok_or(EvidenceError::OriginCommitmentMismatch)?
                .device_epoch,
            original_route: serde_json::to_string(&origin.routing)?,
            outer_receipt_key: copy_id.clone(),
            source_evidence_copy: Some(proof_id.clone()),
            received_erasure_generation: db.privacy_erasure_generation()?,
        };
        self.retain_raw_origin_copy(&id, &verified.author.root, &proof_id, origin, None)?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &id,
            verified_source_anchor: &verified.author.root,
            copy_id: &copy_id,
            kind: RawInnerCopyKind::OuterInner,
            bytes: &item.exact_inner,
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        let scanned = g::validation::scan_inner(&item.exact_inner)
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        self.persist_generated_unsupported_view(&id, &copy_id, &scanned)?;
        Ok(())
    }
}
