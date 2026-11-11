// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded account worker; decoding is outside the writer, admission is repeated within it.
use crate::client::identity_authority::HeadUse;
use crate::client::routed::generated_receive::Provenance;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message::{
    self as g,
    validation::{self, ScanOutcome},
};

/// Results of one 32-row / 4-MiB reparse page.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReparseProgress {
    pub examined: usize,
    pub projected: usize,
    pub erased_or_changed: usize,
}

impl RamfluxClient {
    /// Reparse retained direct Message bytes after an upgrade. Never fetches raw from a server.
    /// The actor owns `&mut self`, so two account reparse workers cannot overlap.
    /// Pass examined handles through `visited` until the bounded sweep completes.
    /// # Errors
    /// Refuses changed/untrusted provenance or returns decoder/storage errors.
    pub fn reparse_raw_inner_page(
        &mut self,
        visited: &mut Vec<String>,
    ) -> Result<ReparseProgress, SdkError> {
        let page = self.account_db()?.raw_inner_reparse_page(visited)?;
        let mut progress = ReparseProgress::default();
        for snapshot in page {
            if visited.len() >= 64 {
                break;
            }
            visited.push(snapshot.copy.copy_id.clone());
            progress.examined += 1;
            let Ok(scanned) = validation::scan_inner(&snapshot.copy.bytes) else { continue };
            if scanned.outcome != ScanOutcome::Supported {
                continue;
            }
            let Ok((identity, content)) = Self::decode_generated_inner(&snapshot.copy.bytes) else {
                continue;
            };
            let Some(g::content::Value::Message(message)) = content.value.as_ref() else {
                continue;
            };
            if message.sealed_group.is_some() {
                continue;
            }
            let Ok(provenance) = serde_json::from_slice::<Provenance>(&snapshot.metadata) else {
                continue;
            };
            // Channel policy is immutable receive provenance, never inferred from the new decoder.
            if provenance.original_mode != "durable" {
                continue;
            }
            let Ok(source) = self.device_identity(&provenance.source) else {
                continue;
            };
            if source.root_commitment() != snapshot.source_anchor
                || identity.conversation_id != provenance.conversation
                || provenance.message != snapshot.copy.owner_id
                || identity.author.as_ref().is_none_or(|author| {
                    author.account_anchor != source.root_commitment()
                        || author.device_id != source.device_id()
                })
            {
                continue;
            }
            if self.require_cached_root_authority(HeadUse::HistoricalRead, &source).is_err() {
                continue;
            }
            let account_id = self.account_db()?.local_account_id.clone();
            let db = self.account_db()?;
            let projected = db.write_transaction(|| -> Result<bool, SdkError> {
                if !db.raw_inner_reparse_is_current(&snapshot, &provenance.message)? {
                    return Ok(false);
                }
                self.require_cached_root_authority(HeadUse::HistoricalRead, &source)?;
                db.bind_raw_inner_copy(&snapshot.copy.copy_id, &provenance.message)?;
                db.put_known_content_evidence(
                    &provenance.message,
                    &provenance.conversation,
                    &snapshot.copy.bytes,
                    &snapshot.metadata,
                    &[],
                )?;
                db.remove_actor_state(&format!("routed/unsupported/{}", provenance.message))?;
                let update = g::MessageUpdate {
                    account_id,
                    identity: Some(identity),
                    journal_sequence: 0,
                    state: Some(g::message_update::State::Content(content)),
                };
                let marker = format!(
                    "routed/reparse/{}/{}/{}",
                    snapshot.copy.copy_id,
                    ramflux_protocol::encode_base64url(snapshot.copy.digest),
                    g::registry::COMPILED_LAYER
                );
                db.append_journal(
                    &marker,
                    "message.schema.updated",
                    &serde_json::json!({
                        "message_id": provenance.message, "update": update,
                    }),
                    crate::time::now_unix_timestamp(),
                    Some(&provenance.conversation),
                )?;
                db.persist_message_actor_state(
                    &provenance.message,
                    &marker,
                    &g::registry::COMPILED_LAYER,
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
}
