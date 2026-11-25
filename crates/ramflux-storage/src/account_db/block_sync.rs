// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Block decisions replicated between the account's own devices (BLOCK-PERSIST-01).
//!
//! Order key: `(counter, device_id, state rank)`. `counter` is a Lamport value: a local decision
//! takes one above the largest counter in the decision tables, and an applied remote decision
//! is stored with its own counter, so the maximum seen always advances. `decided_at` is kept for
//! display only. Rows without a counter (counter 0) rank below every live decision.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};

/// Decision kind for a contact-request root (the root is the contact identity commitment).
pub const KIND_CONTACT_REQUEST: &str = "contact_request";
/// Decision kind for a friend link (the root is the link id).
pub const KIND_FRIEND_LINK: &str = "friend_link";
/// Runtime state key set by an archive restore; cleared by a sibling sync or when it expires.
pub const BLOCK_SYNC_PENDING_KEY: &str = "block_sync/pending";
/// Bounded wait for a live sibling to answer after a restore (seconds).
pub const BLOCK_SYNC_WINDOW_SECS: i64 = 3600;

/// One replicated block or unblock decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockDecisionRecord {
    pub kind: String,
    pub root: String,
    pub state: String,
    pub counter: i64,
    pub device_id: String,
    pub decided_at: i64,
}

/// Ordering tuple: a larger tuple supersedes a smaller one.
fn order_key(counter: i64, device_id: &str, state: &str) -> (i64, String, u8) {
    let rank = match state {
        "blocked" => 2,
        "declined" => 1,
        _ => 0,
    };
    (counter, device_id.to_owned(), rank)
}

/// True when `new` supersedes `old` under `(counter, device_id, state rank)`.
#[must_use]
pub fn block_decision_supersedes(new: &BlockDecisionRecord, old: (i64, &str, &str)) -> bool {
    order_key(new.counter, &new.device_id, &new.state) > order_key(old.0, old.1, old.2)
}

/// Next local counter: one above every counter in the decision tables (Lamport).
pub(super) fn next_block_counter(db: &Connection) -> rusqlite::Result<i64> {
    let max: i64 = db.query_row(
        "SELECT max(coalesce((SELECT max(counter) FROM contact_request_decision),0),coalesce((SELECT max(counter) FROM contact_link_decision),0))",
        [],
        |row| row.get(0),
    )?;
    max.checked_add(1).ok_or(rusqlite::Error::InvalidQuery)
}

fn valid_record(record: &BlockDecisionRecord) -> bool {
    matches!(record.kind.as_str(), KIND_CONTACT_REQUEST | KIND_FRIEND_LINK)
        && matches!(record.state.as_str(), "blocked" | "lifted")
        && record.counter >= 0
        && !record.root.is_empty()
}

impl AccountDb {
    /// Device id stamped on local decisions. Empty when no device signer is attached.
    pub(crate) fn local_block_device_id(&self) -> String {
        self.device_signer().map_or_else(String::new, |device| device.device_id.clone())
    }

    /// All block and unblock decisions this account holds, for fan-out and pairing backfill.
    ///
    /// # Errors
    /// Returns storage errors while reading the decision tables.
    pub fn block_decision_records(&self) -> Result<Vec<BlockDecisionRecord>, StorageError> {
        Ok(self.connection.call(|db| {
            let mut records = Vec::new();
            let mut requests = db.prepare(
                "SELECT root,state,counter,device_id,decided_at FROM contact_request_decision WHERE state IN ('blocked','lifted') ORDER BY root",
            )?;
            for row in requests.query_map([], |r| {
                Ok(BlockDecisionRecord {
                    kind: KIND_CONTACT_REQUEST.to_owned(),
                    root: r.get(0)?,
                    state: r.get(1)?,
                    counter: r.get(2)?,
                    device_id: r.get(3)?,
                    decided_at: r.get(4)?,
                })
            })? {
                records.push(row?);
            }
            let mut links = db.prepare(
                "SELECT link_id,state,counter,device_id,decided_at FROM contact_link_decision WHERE state IN ('blocked','lifted') ORDER BY link_id",
            )?;
            for row in links.query_map([], |r| {
                Ok(BlockDecisionRecord {
                    kind: KIND_FRIEND_LINK.to_owned(),
                    root: r.get(0)?,
                    state: r.get(1)?,
                    counter: r.get(2)?,
                    device_id: r.get(3)?,
                    decided_at: r.get(4)?,
                })
            })? {
                records.push(row?);
            }
            Ok(records)
        })?)
    }

    /// Applies one decision received from an own device. Returns true when it superseded the
    /// local decision (or created it). A superseded or equal decision changes nothing.
    ///
    /// # Errors
    /// Refuses an unknown kind or state, or a negative counter; returns storage errors.
    pub fn apply_block_decision(&self, record: &BlockDecisionRecord) -> Result<bool, StorageError> {
        if !valid_record(record) {
            return Err(StorageError::AuthorizationRejected);
        }
        let record = record.clone();
        self.write_transaction(|| {
            self.connection.call(move |db| {
                let existing: Option<(String, i64, String)> = if record.kind == KIND_CONTACT_REQUEST {
                    db.query_row(
                        "SELECT state,counter,device_id FROM contact_request_decision WHERE root=?1",
                        [&record.root],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?
                } else {
                    db.query_row(
                        "SELECT state,counter,device_id FROM contact_link_decision WHERE link_id=?1",
                        [&record.root],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?
                };
                if existing.as_ref().is_some_and(|(state, counter, device)| {
                    !block_decision_supersedes(&record, (*counter, device, state))
                }) {
                    return Ok(false);
                }
                if record.kind == KIND_CONTACT_REQUEST {
                    apply_request_decision(db, &record)?;
                } else {
                    apply_link_decision(db, &record)?;
                }
                Ok(true)
            })
            .map_err(StorageError::from)
        })
    }

    /// True while a restored device is still waiting for a sibling's block set and the bounded
    /// window has not elapsed. Inbound stranger requests are refused meanwhile.
    ///
    /// # Errors
    /// Returns storage errors while reading the marker.
    pub fn block_sync_pending(&self, now: i64) -> Result<bool, StorageError> {
        let until: Option<String> = self
            .connection
            .query_row(
                "SELECT CAST(state_json AS TEXT) FROM runtime_actor_state WHERE state_kind=?1",
                params![BLOCK_SYNC_PENDING_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match until {
            Some(text) => text.trim().parse::<i64>().is_ok_and(|until| now < until),
            None => false,
        })
    }

    /// Clears the restore marker after a sibling answered with its block set.
    ///
    /// # Errors
    /// Returns storage errors while deleting the marker.
    pub fn clear_block_sync_pending(&self) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind=?1",
            params![BLOCK_SYNC_PENDING_KEY],
        )?;
        Ok(())
    }
}

fn apply_request_decision(db: &Connection, record: &BlockDecisionRecord) -> rusqlite::Result<()> {
    if record.state == "blocked" {
        db.execute(
            "INSERT INTO contact_request_fence(root,state,until) VALUES(?1,'blocked',0) ON CONFLICT(root) DO UPDATE SET state=excluded.state,until=excluded.until",
            params![record.root],
        )?;
    } else {
        db.execute("DELETE FROM contact_request_fence WHERE root=?1", params![record.root])?;
    }
    db.execute(
        "INSERT INTO contact_request_decision(root,state,decided_at,counter,device_id) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(root) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at,counter=excluded.counter,device_id=excluded.device_id",
        params![record.root, record.state, record.decided_at, record.counter, record.device_id],
    )?;
    Ok(())
}

fn apply_link_decision(db: &Connection, record: &BlockDecisionRecord) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO contact_link_decision(link_id,state,decided_at,counter,device_id) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(link_id) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at,counter=excluded.counter,device_id=excluded.device_id",
        params![record.root, record.state, record.decided_at, record.counter, record.device_id],
    )?;
    // Projection effects only; the sibling does not re-run local cascades (object-share
    // revocation, pair retirement) for a replicated decision.
    if record.state == "blocked" {
        db.execute(
            "UPDATE friend_link_projection SET state='blocked',blocked=1,capability_revoked_at=coalesce(capability_revoked_at,?2),updated_at=?2 WHERE link_id=?1 AND state<>'removed'",
            params![record.root, record.decided_at / 1_000],
        )?;
    } else {
        db.execute(
            "UPDATE friend_link_projection SET state='accepted',blocked=0,capability_revoked_at=NULL,updated_at=?2 WHERE link_id=?1 AND state='blocked'",
            params![record.root, record.decided_at / 1_000],
        )?;
    }
    Ok(())
}
