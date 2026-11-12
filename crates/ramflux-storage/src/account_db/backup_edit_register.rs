// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore merge of per-message Edit registers: greatest pair, erasure dominance, opening union.
//!
//! [`merge`] is the single join used by every restore and copy merge. It is commutative,
//! associative and idempotent: erasure is the top element, live states order by the exact
//! `(revision, raw Edit event id)` pair, and only copies of the same winning pair union their
//! retained openings. A losing revision contributes no body, ciphertext, evidence or opening.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Local marker: a merge touched parked Edits, so the client must re-run its parked-Edit resolver.
pub const PARKED_EDIT_REVIEW: &str = "backup/parked-edit-review";
const REGISTER: &str = "routed/edit-revision/";
const PENDING: [&str; 2] = ["routed/pending-edit/", "routed/pending-history-edit/"];
/// Content-free attribution and replay state that survives retirement of a losing revision.
pub(super) const KEEP: [&str; 10] = [
    "routed/original-header/",
    "routed/generated-identity/",
    "routed/generated-order/",
    "routed/generated-display-hlc/",
    "routed/message-metadata/",
    REGISTER,
    "routed/reaction/",
    "routed/reaction-operation/",
    "message-delete-fence/",
    "message-delete-tombstone/",
];
/// Per-revision private evidence addressed by the target id rather than by an index row.
const REVISION_ACTORS: [&str; 5] = [
    "routed/current-edit-proof/",
    "routed/origin-evidence/",
    "routed/group-content/",
    "routed/group-projection/",
    "routed/report-opening-retired/",
];
const REVISION_RAW: &str = "history/current-edit/";
const ORIGINAL_RAW: &str = "history/original-header/";
const ERASED_COPY: &str = "CREATE TEMP TABLE IF NOT EXISTS backup_erased_copy(database_name TEXT NOT NULL,table_name TEXT NOT NULL,row_id INTEGER NOT NULL,PRIMARY KEY(database_name,table_name,row_id));";

/// Exact ordering key of one Edit: revision first, then raw event id bytes.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EditPair {
    pub(crate) revision: u64,
    pub(crate) event_id: Vec<u8>,
}

/// One retained private copy: `(stable index kind, stable locator)`.
pub(crate) type RetainedCopy = (String, String);

/// Restore-relevant state of one logical message in one copy of a conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RestoreMessage {
    /// Content in force: the unedited original (`None`) or the greatest applied Edit.
    Live { edit: Option<EditPair>, openings: BTreeSet<RetainedCopy> },
    /// Deleted: no content, evidence, opening or register survives.
    Erased,
}

/// Deterministic join of two copies of the same logical message.
#[must_use]
pub(crate) fn merge(left: &RestoreMessage, right: &RestoreMessage) -> RestoreMessage {
    match (left, right) {
        (RestoreMessage::Erased, _) | (_, RestoreMessage::Erased) => RestoreMessage::Erased,
        (
            RestoreMessage::Live { edit: first, openings: first_openings },
            RestoreMessage::Live { edit: second, openings: second_openings },
        ) => match first.cmp(second) {
            Ordering::Greater => left.clone(),
            Ordering::Less => right.clone(),
            Ordering::Equal => RestoreMessage::Live {
                edit: first.clone(),
                openings: first_openings.union(second_openings).cloned().collect(),
            },
        },
    }
}

#[derive(Deserialize)]
struct Pending {
    revision: u64,
    event_id: Vec<u8>,
    #[serde(alias = "copy_id")]
    copy: String,
}

fn incoming_table(db: &rusqlite::Connection, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )
}

fn has_table(db: &rusqlite::Connection, database: &str, table: &str) -> rusqlite::Result<bool> {
    if database == "incoming" {
        incoming_table(db, table)
    } else {
        super::message_footprint::table_exists(db, table)
    }
}

fn registers(
    db: &rusqlite::Connection,
    database: &str,
) -> Result<BTreeMap<String, EditPair>, StorageError> {
    let fence = if database == "incoming" {
        " AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid)"
    } else {
        ""
    };
    let mut query = db.prepare(&format!(
        "SELECT substr(r.state_kind,length(?1)+1),r.state_json FROM {database}.runtime_actor_state r WHERE substr(r.state_kind,1,length(?1))=?1{fence}"
    ))?;
    let rows = query
        .query_map([REGISTER], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(target, bytes)| Ok((target, serde_json::from_slice(&bytes)?))).collect()
}

fn erased_on(db: &rusqlite::Connection, database: &str, target: &str) -> Result<bool, StorageError> {
    if database == "main" && super::deleted_messages::message_is_deleted_on(db, target)? {
        return Ok(true);
    }
    for (table, condition) in
        [("direct_message_projection", "deleted=1"), ("message_tombstone_projection", "1")]
    {
        if has_table(db, database, table)?
            && db.query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM {database}.{table} WHERE message_id=?1 AND {condition})"
                ),
                [target],
                |row| row.get(0),
            )?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Stable-named private copies owned by one revision of `target` in one database.
fn revision_copies(
    db: &rusqlite::Connection,
    database: &str,
    target: &str,
) -> Result<BTreeSet<RetainedCopy>, StorageError> {
    let mut copies = BTreeSet::new();
    if has_table(db, database, "message_footprint")? {
        let mut query = db.prepare(&format!(
            "SELECT kind,locator FROM {database}.message_footprint WHERE message_id=?1 AND kind IN ('actor','prepared','history_container','event','raw_inner')"
        ))?;
        let rows = query
            .query_map([target], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (kind, locator) in rows {
            let kept = kind != "event"
                && kind != "raw_inner"
                && (KEEP.iter().any(|prefix| locator.starts_with(prefix))
                    || locator.starts_with("message/origin/"));
            let original = kind == "raw_inner" && locator == format!("{ORIGINAL_RAW}{target}");
            if !kept && !original {
                copies.insert((kind, locator));
            }
        }
    }
    for prefix in REVISION_ACTORS {
        let key = format!("{prefix}{target}");
        if db.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {database}.runtime_actor_state WHERE state_kind=?1)"
            ),
            [&key],
            |row| row.get(0),
        )? {
            copies.insert(("actor".into(), key));
        }
    }
    if has_table(db, database, "raw_inner_copy")? {
        let key = format!("{REVISION_RAW}{target}");
        if db.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {database}.raw_inner_copy WHERE copy_id=?1)"),
            [&key],
            |row| row.get(0),
        )? {
            copies.insert(("raw_inner".into(), key));
        }
    }
    Ok(copies)
}

fn exclude(db: &rusqlite::Connection, table: &str, column: &str, value: &str) -> rusqlite::Result<()> {
    if incoming_table(db, table)? {
        db.execute(
            &format!(
                "INSERT OR IGNORE INTO backup_erased_copy SELECT 'incoming',?1,r.rowid FROM incoming.{table} r WHERE r.{column}=?2"
            ),
            params![table, value],
        )?;
    }
    Ok(())
}

fn exclude_copy(db: &rusqlite::Connection, copy: &RetainedCopy) -> rusqlite::Result<()> {
    match copy.0.as_str() {
        "event" => exclude(db, "local_event_log", "event_id", &copy.1),
        "raw_inner" => exclude(db, "raw_inner_copy", "copy_id", &copy.1),
        _ => exclude(db, "runtime_actor_state", "state_kind", &copy.1),
    }
}

/// Fence every body-bearing incoming row of a losing or erased copy out of the row merge.
fn exclude_incoming_content(
    db: &rusqlite::Connection,
    target: &str,
    copies: &BTreeSet<RetainedCopy>,
) -> rusqlite::Result<()> {
    for copy in copies {
        exclude_copy(db, copy)?;
    }
    for table in ["runtime_message_content", "message_projection", "raw_inner_evidence"] {
        exclude(db, table, "message_id", target)?;
    }
    Ok(())
}

fn drop_local_raw(db: &rusqlite::Connection, copy_id: &str) -> rusqlite::Result<()> {
    if super::message_footprint::table_exists(db, "raw_inner_copy")? {
        db.execute("DELETE FROM main.raw_inner_copy WHERE copy_id=?1", [copy_id])?;
    }
    Ok(())
}

fn keep_keys(db: &rusqlite::Connection, target: &str) -> Result<Vec<String>, StorageError> {
    if !super::message_footprint::table_exists(db, "message_footprint")? {
        return Ok(Vec::new());
    }
    let mut query = db.prepare(
        "SELECT locator FROM main.message_footprint WHERE message_id=?1 AND kind='actor'",
    )?;
    let mut keep = query
        .query_map([target], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    keep.retain(|key| KEEP.iter().any(|prefix| key.starts_with(prefix)));
    let conversation = db
        .query_row(
            "SELECT conversation_id FROM main.direct_message_projection WHERE message_id=?1",
            [target],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(conversation) = conversation {
        keep.push(super::runtime::message_origin::message_origin_key(&conversation, target)?);
    }
    Ok(keep)
}

/// Replace the local losing revision by the incoming winner; the row merge then inserts its copies.
fn install_incoming_winner(db: &rusqlite::Connection, target: &str) -> Result<(), StorageError> {
    let keep = keep_keys(db, target)?;
    super::message_edit_retirement::retire_for_restore(db, target, &keep)?;
    for prefix in REVISION_ACTORS {
        super::message_edit_retirement::retire_actor_for_restore(
            db,
            &format!("{prefix}{target}"),
        )?;
    }
    drop_local_raw(db, &format!("{REVISION_RAW}{target}"))?;
    db.execute("DELETE FROM main.runtime_message_content WHERE message_id=?1", [target])?;
    db.execute(
        "UPDATE main.direct_message_projection SET (encrypted_body,metadata_json)=(SELECT r.encrypted_body,r.metadata_json FROM incoming.direct_message_projection r WHERE r.message_id=direct_message_projection.message_id AND r.conversation_id=direct_message_projection.conversation_id) WHERE message_id=?1 AND deleted=0 AND EXISTS(SELECT 1 FROM incoming.direct_message_projection r WHERE r.message_id=direct_message_projection.message_id AND r.conversation_id=direct_message_projection.conversation_id AND r.deleted=0)",
        [target],
    )?;
    db.execute(
        "UPDATE main.runtime_actor_state SET state_json=(SELECT r.state_json FROM incoming.runtime_actor_state r WHERE r.state_kind=?1) WHERE state_kind=?1 AND EXISTS(SELECT 1 FROM incoming.runtime_actor_state r WHERE r.state_kind=?1)",
        [format!("{REGISTER}{target}")],
    )?;
    Ok(())
}

/// Deletion leaves only content-free tombstones and fences on both sides.
fn erase_both(db: &rusqlite::Connection, target: &str) -> Result<(), StorageError> {
    for prefix in REVISION_ACTORS.iter().chain([REGISTER, "routed/original-header/"].iter()) {
        let key = format!("{prefix}{target}");
        exclude(db, "runtime_actor_state", "state_kind", &key)?;
        super::message_edit_retirement::retire_actor_for_restore(db, &key)?;
    }
    for prefix in [REVISION_RAW, ORIGINAL_RAW] {
        let key = format!("{prefix}{target}");
        exclude(db, "raw_inner_copy", "copy_id", &key)?;
        drop_local_raw(db, &key)?;
    }
    Ok(())
}

impl BackupDatabase {
    /// Apply [`merge`] to every message carrying an Edit register in either copy, before the
    /// generic row merge and before incoming rows are archived.
    pub(super) fn merge_edit_registers(&self) -> Result<(), StorageError> {
        let db = &self.db;
        db.execute_batch(ERASED_COPY)?;
        let local = registers(db, "main")?;
        let incoming = registers(db, "incoming")?;
        let targets = local.keys().chain(incoming.keys()).cloned().collect::<BTreeSet<_>>();
        for target in targets {
            let side = |database: &str,
                        edit: Option<&EditPair>|
             -> Result<RestoreMessage, StorageError> {
                if erased_on(db, database, &target)? {
                    return Ok(RestoreMessage::Erased);
                }
                Ok(RestoreMessage::Live {
                    edit: edit.cloned(),
                    openings: revision_copies(db, database, &target)?,
                })
            };
            let ours = side("main", local.get(&target))?;
            let theirs = side("incoming", incoming.get(&target))?;
            let incoming_copies = match &theirs {
                RestoreMessage::Live { openings, .. } => openings.clone(),
                RestoreMessage::Erased => revision_copies(db, "incoming", &target)?,
            };
            match merge(&ours, &theirs) {
                RestoreMessage::Erased => {
                    exclude_incoming_content(db, &target, &incoming_copies)?;
                    erase_both(db, &target)?;
                }
                RestoreMessage::Live { edit, openings } => {
                    let lost: BTreeSet<RetainedCopy> =
                        incoming_copies.difference(&openings).cloned().collect();
                    if edit.as_ref() == incoming.get(&target) && edit.as_ref() != local.get(&target)
                    {
                        let known: bool = db.query_row(
                            "SELECT EXISTS(SELECT 1 FROM main.direct_message_projection WHERE message_id=?1) OR EXISTS(SELECT 1 FROM main.runtime_actor_state WHERE state_kind=?2)",
                            params![target, format!("{REGISTER}{target}")],
                            |row| row.get(0),
                        )?;
                        if known {
                            install_incoming_winner(db, &target)?;
                        }
                    } else if edit.as_ref() != incoming.get(&target) {
                        exclude_incoming_content(db, &target, &lost)?;
                        exclude(db, "runtime_actor_state", "state_kind", &format!("{REGISTER}{target}"))?;
                        db.execute(
                            "INSERT OR IGNORE INTO backup_erased_copy SELECT 'incoming','direct_message_projection',r.rowid FROM incoming.direct_message_projection r JOIN main.direct_message_projection l ON l.message_id=r.message_id AND l.conversation_id=r.conversation_id WHERE r.message_id=?1 AND r.deleted=0",
                            [&target],
                        )?;
                    }
                }
            }
            self.exclude_divergent_named_copies(&target)?;
        }
        self.merge_pending_edit_registers()?;
        let parked: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 OR substr(state_kind,1,length(?2))=?2) OR EXISTS(SELECT 1 FROM incoming.runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 OR substr(state_kind,1,length(?2))=?2)",
            params![PENDING[0], PENDING[1]],
            |row| row.get(0),
        )?;
        if parked {
            // A target may now exist beside an Edit that was parked in the other copy.
            db.execute(
                "INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",
                params![PARKED_EDIT_REVIEW, b"true".as_slice()],
            )?;
        }
        Ok(())
    }

    /// The same winning Edit may be retained under one copy id with recipient-specific bytes.
    /// The local copy stays; the incoming duplicate is fenced instead of failing the restore.
    fn exclude_divergent_named_copies(&self, target: &str) -> Result<(), StorageError> {
        if !incoming_table(&self.db, "raw_inner_copy")?
            || !super::message_footprint::table_exists(&self.db, "raw_inner_copy")?
        {
            return Ok(());
        }
        for prefix in [REVISION_RAW, ORIGINAL_RAW] {
            self.db.execute(
                "INSERT OR IGNORE INTO backup_erased_copy SELECT 'incoming','raw_inner_copy',i.rowid FROM incoming.raw_inner_copy i JOIN main.raw_inner_copy l USING(copy_id) WHERE i.copy_id=?1 AND (i.raw_digest<>l.raw_digest OR i.raw_bytes<>l.raw_bytes)",
                [format!("{prefix}{target}")],
            )?;
        }
        Ok(())
    }

    /// Parked Edits keep only the greatest pair per register, with its own retained copy.
    fn merge_pending_edit_registers(&self) -> Result<(), StorageError> {
        let db = &self.db;
        for prefix in PENDING {
            let rows = {
                let mut query = db.prepare(
                    "SELECT r.state_kind,r.state_json,l.state_json FROM incoming.runtime_actor_state r JOIN main.runtime_actor_state l ON l.state_kind=r.state_kind WHERE substr(r.state_kind,1,length(?1))=?1 AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid)",
                )?;
                query
                    .query_map([prefix], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (key, theirs, ours) in rows {
                let theirs: Pending = serde_json::from_slice(&theirs)?;
                let ours: Pending = serde_json::from_slice(&ours)?;
                match (theirs.revision, &theirs.event_id).cmp(&(ours.revision, &ours.event_id)) {
                    Ordering::Greater => {
                        super::message_edit_retirement::retire_actor_for_restore(db, &key)?;
                        drop_local_raw(db, &ours.copy)?;
                    }
                    Ordering::Less => {
                        exclude(db, "runtime_actor_state", "state_kind", &key)?;
                        exclude(db, "raw_inner_copy", "copy_id", &theirs.copy)?;
                    }
                    Ordering::Equal => {
                        exclude(db, "runtime_actor_state", "state_kind", &key)?;
                        if incoming_table(db, "raw_inner_copy")?
                            && super::message_footprint::table_exists(db, "raw_inner_copy")?
                        {
                            db.execute(
                                "INSERT OR IGNORE INTO backup_erased_copy SELECT 'incoming','raw_inner_copy',i.rowid FROM incoming.raw_inner_copy i JOIN main.raw_inner_copy l USING(copy_id) WHERE i.copy_id=?1",
                                [&theirs.copy],
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
