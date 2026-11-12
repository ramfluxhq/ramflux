// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded account worker. Decoder attempts and projection share the writer commit.
use crate::client::identity_authority::HeadUse;
use crate::client::routed::{Committed, Kind, Routing, generated_receive::Provenance};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message::{
    self as g,
    validation::{self, ScanOutcome},
};
use ramflux_storage::RawInnerReparseRow;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReparseProgress {
    pub examined: usize,
    pub projected: usize,
    pub erased_or_changed: usize,
}
struct Prepared {
    identity: g::EventIdentity,
    content: g::Content,
    provenance: Provenance,
    source: ramflux_crypto::RootQualifiedDeviceRef,
    origin: Option<(ramflux_storage::RawInnerCopy, super::raw_inner_origin::RetainedOrigin)>,
}
// Bump when executable reparse policy changes without a descriptor change.
const REPARSE_POLICY: &str = "original-channel-3";
fn decoder_marker() -> String {
    format!(
        "{}/{}/{}",
        REPARSE_POLICY,
        g::registry::COMPILED_LAYER,
        ramflux_protocol::encode_base64url(blake3::hash(g::FILE_DESCRIPTOR_SET).as_bytes())
    )
}
impl RamfluxClient {
    /// Reparse one fair 32-row / 4-MiB page. Attempts survive restart and decoder upgrades.
    /// No network requests, historical operations, lifetime renewal or raw reconstruction.
    /// # Errors
    /// Returns local storage failures; malformed or unauthorized retained copies are skipped.
    pub fn reparse_raw_inner_page(&mut self) -> Result<ReparseProgress, SdkError> {
        let decoder = decoder_marker();
        let page = self.account_db()?.raw_inner_reparse_page(&decoder)?;
        let mut progress = ReparseProgress::default();
        for snapshot in page {
            progress.examined += 1;
            let prepared = self.prepare_raw_reparse(&snapshot)?;
            let db = self.account_db()?;
            let projected = db.write_transaction(|| -> Result<bool, SdkError> {
                if !db.mark_raw_inner_reparse_attempted(&snapshot, &decoder)? {
                    return Ok(false);
                }
                if matches!(
                    snapshot.copy.kind,
                    ramflux_storage::RawInnerCopyKind::OuterInner
                        | ramflux_storage::RawInnerCopyKind::SourceEvidence
                ) && !db
                    .actor_state_exists(&format!("routed/unsupported/{}", snapshot.copy.owner_id))?
                    && db.message_content(&snapshot.copy.owner_id)?.is_some()
                {
                    // A later copy cannot replace known content or an Edit. Retire redundant
                    // raw/opening copies without a second schema event; body-free headers stay.
                    db.finish_raw_inner_reparse(&snapshot.copy.copy_id)?;
                    return Ok(false);
                }
                let Some(prepared) = prepared else {
                    return Ok(false);
                };
                self.install_raw_reparse(&snapshot, prepared, &decoder)
            })?;
            if projected {
                progress.projected += 1;
            } else {
                progress.erased_or_changed += 1;
            }
        }
        Ok(progress)
    }
    fn install_raw_reparse(
        &self,
        snapshot: &RawInnerReparseRow,
        prepared: Prepared,
        decoder: &str,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if let Some((copy, origin)) = prepared.origin.as_ref() {
            if db.raw_inner_copy(&copy.copy_id)?.as_ref() != Some(copy) {
                return Ok(false);
            }
            if origin.verify(&prepared.identity, &snapshot.copy.bytes).is_err() {
                return Ok(false);
            }
        } else {
            self.require_cached_root_authority(HeadUse::HistoricalRead, &prepared.source)?;
        }
        if !self.raw_reparse_scope_allowed(&prepared.source, &prepared.provenance.conversation)? {
            return Ok(false);
        }
        if !self.raw_reparse_policy(snapshot, &prepared)? {
            return Ok(false);
        }
        self.project_raw_reparse(snapshot, prepared, decoder)
    }

    fn raw_reparse_policy(
        &self,
        snapshot: &RawInnerReparseRow,
        prepared: &Prepared,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if prepared.provenance.original_mode == "ephemeral" {
            self.discard_raw_reparse(snapshot, prepared)?;
            return Ok(false);
        }
        match prepared.content.value.as_ref() {
            Some(g::content::Value::Message(message)) if message.sealed_group.is_none() => (),
            Some(g::content::Value::Delete(delete)) if prepared.origin.is_some() => {
                // A failed peer authorization rolls back only this copy's effects,
                // preserving its attempted marker and progress for other sources.
                let applied = db.write_transaction(|| {
                    self.apply_generated_delete_authorized(
                        &prepared.source,
                        &prepared.identity,
                        &prepared.provenance.conversation,
                        delete,
                    )
                });
                if let Err(error) = applied {
                    return match error {
                        SdkError::Storage(_) => Err(error),
                        _ => Ok(false),
                    };
                }
            }
            // Service has no v1 native pin executor. Cosmetic data cannot create
            // that authority. Other native kinds never execute retroactively.
            Some(
                g::content::Value::Service(_)
                | g::content::Value::Typing(_)
                | g::content::Value::Control(_)
                | g::content::Value::Call(_)
                | g::content::Value::Task(_)
                | g::content::Value::Surface(_),
            ) => {
                self.discard_raw_reparse(snapshot, prepared)?;
                return Ok(false);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn project_raw_reparse(
        &self,
        snapshot: &RawInnerReparseRow,
        prepared: Prepared,
        decoder: &str,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let Prepared { identity, content, provenance, origin, .. } = prepared;
        let metadata = db.message_metadata(&provenance.conversation, &provenance.message)?;
        db.bind_raw_inner_copy(&snapshot.copy.copy_id, &provenance.message)?;
        db.replace_generated_message_content(
            &provenance.conversation,
            &provenance.message,
            &snapshot.copy.bytes,
            &metadata,
        )?;
        db.put_known_content_evidence(
            &provenance.message,
            &provenance.conversation,
            &snapshot.copy.bytes,
            &snapshot.metadata,
            &[],
        )?;
        db.persist_message_actor_state(
            &provenance.message,
            &format!("routed/generated-identity/{}", provenance.message),
            &identity,
        )?;
        if let Some((copy, origin)) = origin.as_ref() {
            db.persist_message_actor_state(
                &provenance.message,
                &format!("routed/origin-evidence/{}", provenance.message),
                origin,
            )?;
            db.finish_raw_inner_reparse(&copy.copy_id)?;
        }
        self.remove_generated_unsupported_view(&provenance.message)?;
        let update = if matches!(content.value, Some(g::content::Value::Message(_))) {
            self.resolve_generated_pending_edit(&provenance.conversation, &provenance.message)?;
            self.resolve_generated_pending_history_edit(&provenance.message)?;
            let row = self.direct_message_by_id(&provenance.message)?.ok_or_else(|| {
                SdkError::InboundRejected("reparsed Message projection missing".into())
            })?;
            // A winning parked Edit may already have retired the original body/opening.
            // Publish the content in force, never the just-erased original preview.
            self.generated_message_update(&row, &provenance.conversation, 0)?
        } else {
            g::MessageUpdate {
                account_id: db.local_account_id.clone(),
                identity: Some(identity),
                journal_sequence: 0,
                state: Some(g::message_update::State::Content(content)),
            }
        };
        let marker = format!(
            "routed/reparse/{}/{}/{}",
            snapshot.copy.copy_id,
            ramflux_protocol::encode_base64url(snapshot.copy.digest),
            decoder
        );
        db.append_message_update(
            &marker,
            "message.schema.updated",
            &update,
            crate::time::now_unix_timestamp(),
        )?;
        db.finish_raw_inner_reparse(&snapshot.copy.copy_id)?;
        Ok(true)
    }

    fn discard_raw_reparse(
        &self,
        snapshot: &RawInnerReparseRow,
        prepared: &Prepared,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if let Some((copy, _)) = &prepared.origin {
            db.finish_raw_inner_reparse(&copy.copy_id)?;
        }
        db.finish_raw_inner_reparse(&snapshot.copy.copy_id)?;
        self.disarm_generated_unsupported_view(&snapshot.copy.owner_id, &snapshot.copy.copy_id)?;
        Ok(())
    }

    fn prepare_raw_reparse(
        &self,
        snapshot: &RawInnerReparseRow,
    ) -> Result<Option<Prepared>, SdkError> {
        let Ok(scanned) = validation::scan_inner(&snapshot.copy.bytes) else {
            return Ok(None);
        };
        if scanned.outcome != ScanOutcome::Supported {
            return Ok(None);
        }
        let Ok((identity, content)) = Self::decode_generated_inner(&snapshot.copy.bytes) else {
            return Ok(None);
        };
        let Ok(provenance) = serde_json::from_slice::<Provenance>(&snapshot.metadata) else {
            return Ok(None);
        };
        if !matches!(provenance.original_mode.as_str(), "durable" | "ephemeral")
            || snapshot.copy.kind != ramflux_storage::RawInnerCopyKind::OuterInner
            || snapshot.copy.copy_id != provenance.outer_receipt_key
            || identity.group_id.is_some()
            || identity.group_epoch.is_some()
            || (scanned.kind != 7 && g::identity::verify(&identity).is_err())
            || provenance.message != snapshot.copy.owner_id
            || provenance.message != ramflux_protocol::encode_base64url(&identity.id)
            || identity.conversation_id != provenance.conversation
        {
            return Ok(None);
        }
        let (source, origin) = if let Some(copy_id) = provenance.source_evidence_copy.as_ref() {
            let Some(copy) = self.account_db()?.raw_inner_copy(copy_id)? else {
                return Ok(None);
            };
            if copy.owner_id != snapshot.copy.owner_id
                || copy.kind != ramflux_storage::RawInnerCopyKind::SourceEvidence
            {
                return Ok(None);
            }
            let Ok(origin) =
                serde_json::from_slice::<super::raw_inner_origin::RetainedOrigin>(&copy.bytes)
            else {
                return Ok(None);
            };
            let Ok(verified) = origin.verify(&identity, &snapshot.copy.bytes) else {
                return Ok(None);
            };
            let Ok(route) = serde_json::from_str::<Routing>(&provenance.original_route) else {
                return Ok(None);
            };
            let envelope = &verified.outer;
            if route.kind != Kind::Direct
                || (scanned.kind == 1
                    && envelope.delivery_class != ramflux_protocol::DeliveryClass::Message)
                || origin.routing != route
                || route.message_id != provenance.message
                || envelope.envelope_id != provenance.envelope_id
                || envelope.payload_hash != provenance.payload_hash
                || envelope.delivery_mode.as_deref().unwrap_or("durable")
                    != provenance.original_mode
                || envelope.created_at.checked_add(i64::from(envelope.ttl))
                    != Some(provenance.expires_at)
                || verified.author.root != snapshot.source_anchor
                || verified.author.device.storage_key() != provenance.source
                || identity
                    .author
                    .as_ref()
                    .is_none_or(|author| author.device_epoch != provenance.source_epoch)
            {
                return Ok(None);
            }
            (verified.author.device, Some((copy, origin)))
        } else {
            if ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION >= 1 {
                return Ok(None);
            }
            let Some(source) = self.legacy_raw_reparse_source(snapshot, &identity, &provenance)?
            else {
                return Ok(None);
            };
            (source, None)
        };
        if !self.raw_reparse_scope_allowed(&source, &provenance.conversation)? {
            return Ok(None);
        }
        Ok(Some(Prepared { identity, content, provenance, source, origin }))
    }
    fn legacy_raw_reparse_source(
        &self,
        snapshot: &RawInnerReparseRow,
        identity: &g::EventIdentity,
        provenance: &Provenance,
    ) -> Result<Option<ramflux_crypto::RootQualifiedDeviceRef>, SdkError> {
        let receipt =
            match self.account_db()?.load_actor_state::<Committed>(&provenance.outer_receipt_key) {
                Ok(Some(receipt)) => receipt,
                Ok(None) | Err(ramflux_storage::StorageError::Serde(_)) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
        let Ok(route) = serde_json::from_str::<Routing>(&provenance.original_route) else {
            return Ok(None);
        };
        let envelope = &receipt.entry.envelope;
        if !receipt.projected
            || route != receipt.routing
            || route.kind != Kind::Direct
            || route.conversation_id != provenance.conversation
            || route.message_id != provenance.message
            || envelope.envelope_id != provenance.envelope_id
            || envelope.payload_hash != provenance.payload_hash
            || envelope.delivery_mode.as_deref().unwrap_or("durable") != provenance.original_mode
            || envelope.created_at.checked_add(i64::from(envelope.ttl))
                != Some(provenance.expires_at)
        {
            return Ok(None);
        }
        let source =
            match self.authenticated_device_identity(HeadUse::HistoricalRead, &receipt.entry) {
                Ok(source) => source,
                Err(SdkError::Storage(error)) => return Err(error.into()),
                Err(_) => return Ok(None),
            };
        let epoch = self
            .account_db()?
            .client_device_record(&source)?
            .and_then(|record| record["device_epoch"].as_u64());
        if source.storage_key() != provenance.source
            || source.root_commitment() != snapshot.source_anchor
            || epoch != Some(provenance.source_epoch)
            || identity.author.as_ref().is_none_or(|author| {
                author.account_anchor != source.root_commitment()
                    || author.device_id != source.device_id()
                    || author.device_epoch != provenance.source_epoch
            })
        {
            return Ok(None);
        }
        if Self::verify_generated_message_header(&receipt.entry, &snapshot.copy.bytes).is_err() {
            return Ok(None);
        }
        Ok(Some(source))
    }
    pub(crate) fn raw_reparse_scope_allowed(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
    ) -> Result<bool, SdkError> {
        let own = self.own_account_anchor()?;
        if g::dm_scope::validate_direct(conversation, &own, source.root_commitment()).is_err() {
            return Ok(false);
        }
        let Some(thread) = self.account_db()?.client_record("conversation", conversation)? else {
            return Ok(false);
        };
        if thread["kind"] != "direct" || !thread["group_id"].is_null() {
            return Ok(false);
        }
        let roots = thread["participant_roots"].as_array();
        if roots.is_none_or(|roots| {
            roots.len() != 2
                || roots
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    != std::collections::BTreeSet::from([own.as_str(), source.root_commitment()])
        }) {
            return Ok(false);
        }
        Ok(true)
    }
    pub(crate) fn maintain_raw_inner_reparse(&mut self) -> Result<usize, SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(0);
        }
        let decoder = decoder_marker();
        let key = "message/reparse/decoder";
        if self.account_db()?.load_actor_state::<String>(key)?.as_deref() == Some(decoder.as_str())
            && !self.account_db()?.raw_inner_reparse_pending(&decoder)?
        {
            return Ok(0);
        }
        let page = self.reparse_raw_inner_page()?;
        if page.examined == 0 {
            let db = self.account_db()?;
            db.write_transaction(|| -> Result<(), SdkError> {
                if !db.raw_inner_reparse_pending(&decoder)? {
                    db.persist_actor_state(key, &decoder)?;
                }
                Ok(())
            })?;
        }
        Ok(page.projected)
    }
}
