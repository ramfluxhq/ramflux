// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native private-generation projection. Contribution/DV and journal owners remain separate.
use super::{FullDirectHistory, direct_source, native_selection::Selected};
use crate::{BackupDatabase, DirectMessageRecord, MessageMetadata, StorageError};
use ramflux_crypto::native_origin::{Kind, OwnAuthoredCapture, RetainedOrigin, Routing};
use ramflux_protocol::{custody::DeviceRef, message as g};
use rusqlite::{Connection, params};
use serde::Serialize;
use zeroize::Zeroizing;

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

impl BackupDatabase {
    /// Merge one verified native history version in a PRIVATE generation. Projection and
    /// authored capture are actual contributor values, never synthesized transport evidence.
    /// The caller authenticates the contributor and owns the whole-input transaction.
    /// No receipt, journal
    /// cursor, live selection or current authority is granted by this projection alone.
    /// # Errors
    /// Refuses foreign accounts, incomplete native context/capture, unsupported metadata,
    /// equivocation and SQL failures. The caller must roll back the complete input on error.
    pub fn merge_full_direct_history(
        &mut self,
        source: &DeviceRef,
        history: &FullDirectHistory,
        projection: &DirectMessageRecord,
        authored: Option<&OwnAuthoredCapture>,
    ) -> Result<bool, StorageError> {
        if self.db.is_autocommit() {
            return Err(StorageError::PairingField("WrongContext"));
        }
        merge(&self.db, source, history, projection, authored)
    }
}

#[cfg(any(test, feature = "test-instrumentation"))]
impl crate::AccountDb {
    /// Exercise the same native projection under the managed writer in SDK fixtures.
    /// This is component instrumentation, never a full-transfer admission or installation gate.
    /// # Errors
    /// Refuses invalid history or generation and rolls back the complete managed callback.
    pub fn project_full_direct_history_for_test(
        &self,
        source: DeviceRef,
        history: FullDirectHistory,
        projection: DirectMessageRecord,
        authored: Option<OwnAuthoredCapture>,
    ) -> Result<bool, StorageError> {
        self.connection.call_immediate_result(move |tx| {
            merge(tx, &source, &history, &projection, authored.as_ref())
        })?
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Selection {
    Merge,
    OriginalContributions,
}
fn merge(
    db: &Connection,
    source: &DeviceRef,
    incoming: &FullDirectHistory,
    projection: &DirectMessageRecord,
    authored: Option<&OwnAuthoredCapture>,
) -> Result<bool, StorageError> {
    project(db, source, incoming, projection, authored, Selection::Merge)
}

/// The caller resolved retained ORIGINAL A/B rows, not the previous normalized maximum.
/// This replaces only the private content selection; no source is relabeled as original B.
pub(super) fn project_original_contributions(
    db: &Connection,
    source: &DeviceRef,
    incoming: &FullDirectHistory,
    projection: &DirectMessageRecord,
    authored: Option<&OwnAuthoredCapture>,
) -> Result<bool, StorageError> {
    if db.is_autocommit() {
        return Err(StorageError::PairingField("WrongContext"));
    }
    project(db, source, incoming, projection, authored, Selection::OriginalContributions)
}
fn project(
    db: &Connection,
    source: &DeviceRef,
    incoming: &FullDirectHistory,
    projection: &DirectMessageRecord,
    authored: Option<&OwnAuthoredCapture>,
    selection: Selection,
) -> Result<bool, StorageError> {
    super::super::mac_subkeys::full::source_key(source)?;
    let own: String = db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if source.account_anchor != own {
        return Err(invalid());
    }
    let version = incoming.verify(&own)?;
    let id = ramflux_protocol::encode_base64url(&version.original().id);
    require_projection(incoming, projection, &id, version.original())?;
    require_capture(incoming, authored, &own)?;
    if super::super::deleted_messages::message_is_deleted_on(db, &id)? {
        return Ok(false);
    }
    // Existing directory context must be admitted by its own owner before content.
    // Reuse its ordinary exact root-pair check, without importing contact authority.
    direct_source::require_peer(db, &own, &projection.conversation_id, incoming.peer_root())?;
    let previous = direct_source::read(db, &own, &id)?;
    let resolved = previous.as_ref().map_or(Ok(incoming), |old| old.merge(incoming, &own))?;
    let chosen = if selection == Selection::OriginalContributions { incoming } else { resolved };
    let changed = previous.as_ref().is_none_or(|old| old.exact_inner() != chosen.exact_inner());
    let old_capture =
        direct_source::actor::<OwnAuthoredCapture>(db, &format!("own-history/capture/{id}"))?;
    let capture = if selection == Selection::OriginalContributions {
        authored.filter(|capture| capture.sent.exact_inner == chosen.exact_inner())
    } else {
        old_capture
            .as_ref()
            .filter(|capture| capture.sent.exact_inner == chosen.exact_inner())
            .or_else(|| authored.filter(|capture| capture.sent.exact_inner == chosen.exact_inner()))
    };
    require_capture(chosen, capture, &own)?;
    if changed && previous.is_some() {
        let default = serde_json::to_vec(&MessageMetadata::default())?;
        if !db.query_row(
            "SELECT metadata_json=?2 FROM direct_message_projection WHERE message_id=?1",
            params![id, default],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(invalid());
        }
        retire(db, &id)?;
    }
    write_projection(db, chosen, projection, &own, &id)?;
    if selection == Selection::OriginalContributions {
        db.execute(
            "UPDATE direct_message_projection SET sender_id=?2,created_at=?3 WHERE message_id=?1 AND deleted=0",
            params![id, projection.sender_id, projection.created_at],
        )?;
        if capture.is_none() {
            let key = format!("own-history/capture/{id}");
            super::super::message_edit_retirement::retire_actor_for_restore(db, &key)?;
            db.execute("DELETE FROM message_footprint WHERE kind='actor' AND locator=?1", [&key])?;
            db.execute(
                "DELETE FROM message_copy_binding WHERE copy_id=?1",
                [format!("actor:{key}")],
            )?;
        }
    }
    write_evidence(db, chosen, capture, &own, &id)?;
    let actual = direct_source::read(db, &own, &id)?.ok_or_else(invalid)?;
    let mut expected = Zeroizing::new(Vec::new());
    let mut observed = Zeroizing::new(Vec::new());
    chosen.write(&mut *expected)?;
    actual.write(&mut *observed)?;
    if expected.as_slice() != observed.as_slice() {
        return Err(StorageError::PairingField("ManifestMismatch"));
    }
    Ok(changed)
}

fn require_projection(
    history: &FullDirectHistory,
    row: &DirectMessageRecord,
    id: &str,
    original: &g::EventIdentity,
) -> Result<(), StorageError> {
    if row.message_id != id
        || row.conversation_id != original.conversation_id
        || row.deleted
        || row.created_at < 0
        || row.sender_id.len() > 4096
        || (!row.encrypted_body.is_empty() && row.encrypted_body != history.exact_inner())
        || row.metadata != MessageMetadata::default()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn require_capture(
    history: &FullDirectHistory,
    capture: Option<&OwnAuthoredCapture>,
    own: &str,
) -> Result<(), StorageError> {
    if matches!(history.evidence_class(), Selected::Authored) && capture.is_none() {
        return Err(invalid());
    }
    if let Some(capture) = capture {
        let version = history.verify(own)?;
        if capture.check_direct(own).map_err(|_| invalid())? != *version.current()
            || capture.original != *version.original()
            || capture.sent.exact_inner != history.exact_inner()
        {
            return Err(invalid());
        }
        drop(super::direct_history::encode_state(capture)?);
    }
    Ok(())
}

fn retire(db: &Connection, id: &str) -> Result<(), StorageError> {
    // Existing B replay receipts need their typed sanitizer before a replacement.
    // Never discard that independent restriction merely to accept a newer body.
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM message_footprint WHERE message_id=?1 AND kind='actor' AND substr(locator,1,17)='routed/committed/')",
        [id], |row| row.get::<_, bool>(0),
    )? {
        return Err(invalid());
    }
    let mut statement =
        db.prepare("SELECT locator FROM message_footprint WHERE message_id=?1 AND kind='actor'")?;
    let mut rows = statement.query([id])?;
    let mut keep = Vec::new();
    while let Some(row) = rows.next()? {
        let key: String = row.get(0)?;
        if super::super::backup_edit_register::KEEP.iter().any(|prefix| key.starts_with(prefix))
            || key.starts_with("message/origin/")
        {
            if keep.len() == 4096 {
                return Err(invalid());
            }
            keep.push(key);
        }
    }
    super::super::message_edit_retirement::retire_for_restore(db, id, &keep)?;
    Ok(())
}

fn write_projection(
    db: &Connection,
    history: &FullDirectHistory,
    row: &DirectMessageRecord,
    own: &str,
    id: &str,
) -> Result<(), StorageError> {
    let version = history.verify(own)?;
    let is_own =
        version.original().author.as_ref().is_some_and(|author| author.account_anchor == own);
    db.execute("INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at) VALUES(?1,?2,?3,?4,?5,0,?6,?7) ON CONFLICT(message_id) DO UPDATE SET encrypted_body=excluded.encrypted_body,is_own=excluded.is_own WHERE direct_message_projection.conversation_id=excluded.conversation_id AND direct_message_projection.deleted=0",params![row.conversation_id,id,row.sender_id,history.exact_inner(),serde_json::to_vec(&row.metadata)?,i64::from(is_own),row.created_at])?;
    db.execute("INSERT INTO runtime_message_content(message_id,conversation_id,body) VALUES(?1,?2,?3) ON CONFLICT(message_id) DO UPDATE SET body=excluded.body WHERE runtime_message_content.conversation_id=excluded.conversation_id",params![id,row.conversation_id,history.exact_inner()])?;
    Ok(())
}

fn write_evidence(
    db: &Connection,
    history: &FullDirectHistory,
    capture: Option<&OwnAuthoredCapture>,
    own: &str,
    id: &str,
) -> Result<(), StorageError> {
    let version = history.verify(own)?;
    actor(db, id, &format!("routed/generated-identity/{id}"), version.original())?;
    actor(db, id, &format!("routed/generated-order/{id}"), &version.original().hlc)?;
    if version.current().id == version.original().id {
        let key = format!("routed/edit-revision/{id}");
        super::super::message_edit_retirement::retire_actor_for_restore(db, &key)?;
        db.execute("DELETE FROM message_footprint WHERE kind='actor' AND locator=?1", [&key])?;
        db.execute("DELETE FROM message_copy_binding WHERE copy_id=?1", [format!("actor:{key}")])?;
    } else {
        #[derive(Serialize)]
        struct Revision<'a> {
            revision: u64,
            event_id: &'a [u8],
        }
        actor(
            db,
            id,
            &format!("routed/edit-revision/{id}"),
            &Revision { revision: version.revision(), event_id: &version.current().id },
        )?;
    }
    if let Some(capture) = capture {
        actor(db, id, &format!("own-history/capture/{id}"), capture)?;
    }
    let class = match history.evidence_class() {
        Selected::Authored => "authored",
        Selected::OwnCopy => {
            actor(
                db,
                id,
                &format!(
                    "routed/own-sent-attestation/{id}/{}",
                    ramflux_protocol::encode_base64url(&version.current().id)
                ),
                history.own_attestation().ok_or_else(invalid)?,
            )?;
            "own_copy"
        }
        Selected::Received => {
            received(db, history, id, version.current())?;
            "received"
        }
    };
    db.execute("INSERT INTO runtime_native_history_selection(message_id,evidence_class,current_id,body_hash) SELECT message_id,?2,?3,?4 FROM runtime_message_content WHERE message_id=?1 AND body=?5 ON CONFLICT(message_id) DO UPDATE SET evidence_class=excluded.evidence_class,current_id=excluded.current_id,body_hash=excluded.body_hash",params![id,class,version.current().id,blake3::hash(history.exact_inner()).as_bytes().as_slice(),history.exact_inner()])?;
    Ok(())
}

fn received(
    db: &Connection,
    history: &FullDirectHistory,
    id: &str,
    current: &g::EventIdentity,
) -> Result<(), StorageError> {
    let item = history.history_item();
    if item.original_metadata_evidence.is_some() {
        actor(db, id, &format!("routed/current-edit-proof/{id}"), &item.source_evidence)?;
        actor(db, id, &format!("routed/report-opening-retired/{id}"), &true)?;
    } else {
        let origin = RetainedOrigin {
            evidence: item.source_evidence.clone().ok_or_else(invalid)?,
            reported_inner: Vec::new(),
            routing: Routing {
                kind: Kind::Direct,
                conversation_id: current.conversation_id.clone(),
                message_id: ramflux_protocol::encode_base64url(&current.id),
                group_id: None,
                group_message_id: None,
                attachments: false,
            },
        };
        actor(db, id, &format!("routed/origin-evidence/{id}"), &origin)?;
    }
    actor(
        db,
        id,
        &format!("routed/original-header/{id}"),
        &history.original_header()?.ok_or_else(invalid)?,
    )?;
    Ok(())
}

fn actor(db: &Connection, id: &str, key: &str, value: &impl Serialize) -> Result<(), StorageError> {
    let bytes = super::direct_history::encode_state(value)?;
    db.execute(
        "DELETE FROM message_copy_binding WHERE copy_id=?1",
        params![format!("actor:{key}")],
    )?;
    db.execute("DELETE FROM message_footprint WHERE kind='actor' AND locator=?1", [key])?;
    db.execute(
        "INSERT INTO message_copy_binding(copy_id,message_id) VALUES(?1,?2)",
        params![format!("actor:{key}"), id],
    )?;
    db.execute(
        "INSERT INTO message_footprint(message_id,kind,locator) VALUES(?1,'actor',?2)",
        params![id, key],
    )?;
    db.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",params![key,bytes.as_slice()])?;
    Ok(())
}

#[cfg(test)]
mod tests;
