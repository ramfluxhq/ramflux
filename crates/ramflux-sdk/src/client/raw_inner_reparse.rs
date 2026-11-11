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
}
fn decoder_marker() -> String {
    format!(
        "{}/{}",
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
                let Some(prepared) = prepared else {
                    return Ok(false);
                };
                self.require_cached_root_authority(HeadUse::HistoricalRead, &prepared.source)?;
                let Prepared { identity, content, provenance, .. } = prepared;
                let metadata =
                    db.message_metadata(&provenance.conversation, &provenance.message)?;
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
                db.remove_actor_state(&format!("routed/unsupported/{}", provenance.message))?;
                let update = g::MessageUpdate {
                    account_id: db.local_account_id.clone(),
                    identity: Some(identity),
                    journal_sequence: 0,
                    state: Some(g::message_update::State::Content(content)),
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
            })?;
            if projected {
                progress.projected += 1;
            } else {
                progress.erased_or_changed += 1;
            }
        }
        Ok(progress)
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
        match content.value.as_ref() {
            Some(g::content::Value::Message(message)) if message.sealed_group.is_none() => (),
            _ => return Ok(None),
        }
        let Ok(provenance) = serde_json::from_slice::<Provenance>(&snapshot.metadata) else {
            return Ok(None);
        };
        if provenance.original_mode != "durable"
            || snapshot.copy.kind != ramflux_storage::RawInnerCopyKind::OuterInner
            || snapshot.copy.copy_id != provenance.outer_receipt_key
            || identity.group_id.is_some()
            || identity.group_epoch.is_some()
            || g::identity::verify(&identity).is_err()
            || provenance.message != snapshot.copy.owner_id
            || provenance.message != ramflux_protocol::encode_base64url(&identity.id)
            || identity.conversation_id != provenance.conversation
        {
            return Ok(None);
        }
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
        if !self.raw_reparse_scope_allowed(&source, &provenance.conversation)? {
            return Ok(None);
        }
        if Self::verify_generated_message_header(&receipt.entry, &snapshot.copy.bytes).is_err() {
            return Ok(None);
        }
        Ok(Some(Prepared { identity, content, provenance, source }))
    }
    fn raw_reparse_scope_allowed(
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
