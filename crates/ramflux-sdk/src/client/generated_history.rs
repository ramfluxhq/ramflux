// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-hand origin authority for edited history; forwarders grant no author authority.
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
use serde_json::Value;
mod bootstrap;
mod import;
mod ordinary;
mod pending;

pub(crate) struct Author {
    pub(crate) root: String,
    pub(crate) device: ramflux_crypto::RootQualifiedDeviceRef,
}

pub(crate) fn authority(
    outer: &Value,
    manifest: &g::NativeCustodyManifest,
    identity: &g::EventIdentity,
) -> Result<Author, SdkError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    let manifest: ramflux_protocol::custody::CustodyManifest =
        ramflux_protocol::custody::decode(&manifest.canonical, 5 * 1024 * 1024).map_err(|_| bad)?;
    let issued = outer["created_at"].as_u64().ok_or(bad)?;
    let verified = crate::custody::verify_public_authority(
        &manifest.publication,
        manifest.custodian_publication.as_ref(),
        issued,
    )
    .map_err(|_| bad)?;
    let root = &verified.envelope().body.account_anchor;
    let author = identity.author.as_ref().ok_or(bad)?;
    if author.account_anchor != *root
        || outer["source_device_id"].as_str() != Some(author.device_id.as_str())
        || outer["source_principal_id"].as_str()
            != Some(verified.envelope().body.principal_id.as_str())
        || outer["ext"]["source_root_commitment"].as_str() != Some(root.as_str())
    {
        return Err(bad.into());
    }
    let device = ramflux_protocol::custody::DeviceRef {
        account_anchor: root.clone(),
        device_id: author.device_id.clone(),
        device_epoch: author.device_epoch,
    };
    let certified = verified.authorize(&device, "message", issued).map_err(|_| bad)?;
    if identity.group_id.is_some() {
        verified.authorize(&device, "group", issued).map_err(|_| bad)?;
    }
    ramflux_protocol::verify_sender_signature(
        outer,
        ramflux_protocol::SenderTranscriptMode::Evidence,
        &certified.branch_signing_public_key,
    )
    .map_err(|_| bad)?;
    Ok(Author {
        root: root.clone(),
        device: ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
            &verified,
            &author.device_id,
        )
        .map_err(|_| bad)?,
    })
}

fn verify_edit_origin(
    item: &g::HistoryItem,
    identity: &g::EventIdentity,
) -> Result<Author, SdkError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    let evidence = item.source_evidence.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?;
    if evidence.canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES
        || !evidence.group_plaintext.is_empty()
        || !evidence.group_opening.is_empty()
    {
        return Err(bad.into());
    }
    let outer: Value =
        ramflux_protocol::parse_i_json(&evidence.canonical_sender_envelope).map_err(|_| bad)?;
    if ramflux_protocol::canonical_json_bytes(&outer)? != evidence.canonical_sender_envelope {
        return Err(bad.into());
    }
    if outer["delivery_mode"].as_str() != Some("durable")
        || outer["delivery_class"].as_str() != Some("message")
    {
        return Err(bad.into());
    }
    let author = authority(
        &outer,
        evidence.source_authority.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?,
        identity,
    )?;
    // Only reconstruct an Envelope for A0; never use this placeholder for signature verification.
    let mut a0_outer = outer.clone();
    a0_outer["encrypted_payload"] = Value::String(String::new());
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(a0_outer).map_err(|_| bad)?;
    let a0 = g::outer::encode_candidate_report_a0(&g::outer::candidate_report_a0_from_envelope(
        &envelope,
    )?)?;
    let opening: [u8; 32] = evidence.report_opening.as_slice().try_into().map_err(|_| bad)?;
    let commitment: [u8; 32] =
        ramflux_protocol::decode_base64url(outer["report_commitment"].as_str().ok_or(bad)?)
            .map_err(|_| bad)?
            .try_into()
            .map_err(|_| bad)?;
    ramflux_crypto::verify_report_opening(&opening, &item.exact_inner, &a0, &commitment)
        .map_err(|_| bad)?;
    if outer["ext"].get(g::original_header::EXT_KEY).is_some() {
        return Err(bad.into());
    }
    Ok(author)
}

impl RamfluxClient {
    /// Verify both independently signed origins of an edited history claim, without importing it.
    /// The returned identity proves the original header, never the retired Message body.
    /// # Errors
    /// Refuses missing/invalid origin proofs, cross-author/target claims and native group-policy failures.
    pub fn verify_generated_edited_history_item(
        &self,
        item: &g::HistoryItem,
    ) -> Result<g::EventIdentity, SdkError> {
        let checked = g::original_header::edited::check(item)?;
        if checked.identity.device_sequence & (1 << 63) != 0
            || checked.edit_identity.device_sequence & (1 << 63) != 0
        {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        let original_evidence =
            item.original_metadata_evidence.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?;
        let original = authority(
            &checked.original_outer,
            original_evidence
                .source_authority
                .as_ref()
                .ok_or(EvidenceError::OriginEvidenceMissing)?,
            &checked.identity,
        )?;
        let edit_author = verify_edit_origin(item, &checked.edit_identity)?;
        if original.root != edit_author.root {
            return Err(EvidenceError::EditAuthorMismatch.into());
        }
        let target = checked.edit.target.as_ref().ok_or(EvidenceError::EditTargetMismatch)?;
        if target.id != checked.identity.id
            || target.conversation_id != checked.identity.conversation_id
            || checked.edit_identity.conversation_id != checked.identity.conversation_id
            || target.author_anchor != original.root
            || checked.edit_identity.group_id != checked.identity.group_id
        {
            return Err(EvidenceError::EditTargetMismatch.into());
        }
        self.verify_edited_history_group(
            original_evidence,
            &checked.identity,
            &original,
            &checked.edit_identity,
            &edit_author,
        )?;
        Ok(checked.identity)
    }

    fn verify_edited_history_group(
        &self,
        evidence: &g::HistoryOriginalMetadataEvidence,
        original: &g::EventIdentity,
        original_author: &Author,
        edit: &g::EventIdentity,
        edit_author: &Author,
    ) -> Result<(), SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        if let Some(group) = evidence.group_binding.as_ref() {
            let snapshot = evidence.group_membership.as_ref().ok_or(bad)?;
            let snapshot = ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(
                &snapshot.canonical,
            )
            .map_err(|_| bad)?;
            let verified =
                ramflux_crypto::verify_group_state_snapshot(snapshot).map_err(|_| bad)?;
            let state = verified.snapshot();
            if state.group_id != group.group_id
                || state.epoch != group.key_epoch
                || state.genesis.conversation_id != original.conversation_id
                || ramflux_protocol::decode_base64url(&state.state_hash).map_err(|_| bad)?
                    != group.group_state_hash
                || verified
                    .view()
                    .effective_role(&original_author.root, original_author.device.device_id())
                    .is_none()
            {
                return Err(bad.into());
            }
            self.require_generated_group_epoch(
                &group.group_id,
                &original_author.device,
                group.key_epoch,
                false,
            )?;
            self.require_generated_group_epoch(
                &group.group_id,
                &edit_author.device,
                edit.group_epoch.ok_or(bad)?,
                false,
            )?;
        } else if evidence.group_membership.is_some()
            || original.group_id.is_some()
            || edit.group_id.is_some()
        {
            return Err(bad.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct OriginalHeader {
    pub exact_identity: Vec<u8>,
    pub evidence: g::HistoryOriginalMetadataEvidence,
}

impl RamfluxClient {
    pub(crate) fn capture_generated_original_header(
        &self,
        entry: &crate::GatewayInboxEntry,
        exact_inner: &[u8],
    ) -> Result<(), SdkError> {
        // Before activation the test gate also carries native v1 fixtures; those are never evidence.
        if entry.envelope.schema != g::outer::CANDIDATE_ENVELOPE_SCHEMA {
            return Ok(());
        }
        let scanned = g::validation::scan_inner(exact_inner)
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        if scanned.kind != 1 {
            return Ok(());
        }
        let exact_identity = g::original_header::exact_identity(exact_inner)?.to_vec();
        let identity = g::original_header::decode_identity(&exact_identity)?;
        let author = identity.author.as_ref().ok_or(EvidenceError::OriginCommitmentMismatch)?;
        let authority = self
            .current_custody_evidence(&author.account_anchor, crate::custody::network_now()?)?
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        let manifest = ramflux_protocol::custody::CustodyManifest {
            publication: authority.publication,
            custodian_publication: authority.custodian_publication,
            devices: Vec::new(),
        };
        let message = g::Message::decode(scanned.body)
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        let group_binding = message.sealed_group.as_ref().map(g::original_header::group_binding);
        let group_membership = group_binding
            .as_ref()
            .map(|group| {
                let state = self
                    .account_db()?
                    .shared_group_state_at_epoch(&group.group_id, group.key_epoch)?
                    .ok_or(EvidenceError::OriginEvidenceMissing)?;
                Ok::<_, SdkError>(g::NativeGroupSnapshot {
                    canonical: ramflux_protocol::canonical_json_bytes(state.snapshot())?,
                })
            })
            .transpose()?;
        let canonical_sender_envelope = ramflux_protocol::sender_origin_evidence(&entry.envelope)?;
        if canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        let retained = OriginalHeader {
            exact_identity,
            evidence: g::HistoryOriginalMetadataEvidence {
                canonical_sender_envelope,
                source_authority: Some(g::NativeCustodyManifest {
                    canonical: ramflux_protocol::canonical_json_bytes(&manifest)?,
                }),
                group_membership,
                group_binding,
                layer: scanned.layer,
            },
        };
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let key = format!("routed/original-header/{id}");
        let db = self.account_db()?;
        if let Some(previous) = db.load_actor_state::<OriginalHeader>(&key)? {
            if !previous.matches(&retained)? {
                return Err(EvidenceError::OriginCommitmentMismatch.into());
            }
        } else {
            db.persist_message_actor_state(&id, &key, &retained)?;
        }
        Ok(())
    }
}

impl RamfluxClient {
    pub(crate) fn apply_generated_history_edit(
        &self,
        entry: &crate::GatewayInboxEntry,
        item: &g::HistoryItem,
    ) -> Result<bool, SdkError> {
        use super::identity_authority::{HeadUse, NativeOperation};
        let sibling = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if sibling.root_commitment() != self.own_account_anchor()? {
            return Err(EvidenceError::EditAuthorMismatch.into());
        }
        self.require_native_operation(&sibling, NativeOperation::Sync)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        let original = self.verify_generated_edited_history_item(item)?;
        let inner: g::Inner = prost::Message::decode(item.exact_inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        let edit_author = verify_edit_origin(
            item,
            inner.identity.as_ref().ok_or(EvidenceError::OriginCommitmentMismatch)?,
        )?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            self.authorize_history_message_scope(&original)?;
            if !self.bootstrap_generated_edited_target(item, &original)? {
                return Ok(false);
            }
            self.apply_generated_edit_authorized(
                super::message_mutations::EditContext {
                    entry,
                    source: &edit_author.device,
                    imported: Some(item),
                    own_sent: false,
                },
                &original.conversation_id,
                &item.exact_inner,
                None,
            )
        })
    }

    pub(crate) fn store_generated_edited_evidence(
        &self,
        target: &str,
        item: &g::HistoryItem,
    ) -> Result<(), SdkError> {
        let original = OriginalHeader {
            exact_identity: item.exact_original_identity.clone(),
            evidence: item
                .original_metadata_evidence
                .clone()
                .ok_or(EvidenceError::OriginEvidenceMissing)?,
        };
        let db = self.account_db()?;
        let key = format!("routed/original-header/{target}");
        if let Some(previous) = db.load_actor_state::<OriginalHeader>(&key)? {
            if !previous.matches(&original)? {
                return Err(EvidenceError::EditTargetMismatch.into());
            }
        } else {
            db.persist_message_actor_state(target, &key, &original)?;
        }
        let identity = g::original_header::decode_identity(&original.exact_identity)?;
        let source = &identity
            .author
            .as_ref()
            .ok_or(EvidenceError::OriginCommitmentMismatch)?
            .account_anchor;
        let copy_id = format!("history/current-edit/{target}");
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: target,
            verified_source_anchor: source,
            copy_id: &copy_id,
            kind: ramflux_storage::RawInnerCopyKind::HistoryContainer,
            bytes: &item.encode_to_vec(),
            bounded_metadata: &[],
        })?;
        db.persist_message_actor_state(
            target,
            &format!("routed/current-edit-proof/{target}"),
            &item.source_evidence,
        )?;
        let current = g::Inner::decode(item.exact_inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        let event = current.identity.ok_or(EvidenceError::OriginCommitmentMismatch)?;
        db.persist_message_actor_state(
            target,
            &format!("routed/report-event/{}", ramflux_protocol::encode_base64url(&event.id)),
            &target,
        )?;
        Ok(())
    }
}

impl OriginalHeader {
    fn matches(&self, other: &Self) -> Result<bool, SdkError> {
        let left: Value = ramflux_protocol::parse_i_json(&self.evidence.canonical_sender_envelope)?;
        let right: Value =
            ramflux_protocol::parse_i_json(&other.evidence.canonical_sender_envelope)?;
        Ok(self.exact_identity == other.exact_identity
            && self.evidence.layer == other.evidence.layer
            && left["ext"][g::original_header::EXT_KEY]
                == right["ext"][g::original_header::EXT_KEY])
    }
}

impl RamfluxClient {
    /// Select the current generated Message/Edit's own C/opening for an explicit report.
    /// Replaced originals and superseded events are non-reportable; no erased body is reconstructed.
    /// # Errors
    /// Refuses retired/missing evidence or an index that does not name the exact current event.
    pub fn selected_generated_report_evidence(
        &self,
        event_id: &[u8],
    ) -> Result<(Vec<u8>, g::HistoryOriginEvidence), SdkError> {
        if event_id.len() != 32 {
            return Err(EvidenceError::OriginEvidenceMissing.into());
        }
        let db = self.account_db()?;
        let id = ramflux_protocol::encode_base64url(event_id);
        let Some(target) = db.load_actor_state::<String>(&format!("routed/report-event/{id}"))?
        else {
            if db.message_content(&id)?.is_none()
                || db
                    .load_actor_state::<bool>(&format!("routed/report-opening-retired/{id}"))?
                    .unwrap_or(false)
            {
                return Err(EvidenceError::ReportOpeningRetired.into());
            }
            let item = self.export_generated_history_item(event_id)?;
            let proof = item.source_evidence.ok_or(EvidenceError::OriginEvidenceMissing)?;
            return Ok((item.exact_inner, proof));
        };
        let inner = db.message_content(&target)?.ok_or(EvidenceError::ReportOpeningRetired)?;
        let event = g::Inner::decode(inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        if event.identity.as_ref().is_none_or(|identity| identity.id != event_id) {
            return Err(EvidenceError::ReportOpeningRetired.into());
        }
        let proof = db
            .load_actor_state::<Option<g::HistoryOriginEvidence>>(&format!(
                "routed/current-edit-proof/{target}"
            ))?
            .flatten()
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        Ok((inner, proof))
    }
}
