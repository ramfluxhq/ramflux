// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact denial decisions close over both public projections without lifting consent.
use super::fixed_union::Cells;
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::CellType;
use rusqlite::{Connection, OptionalExtension as _, params};

struct Shape {
    family: &'static str,
    table: &'static str,
    state_name: &'static str,
    state_index: usize,
    denial_name: &'static str,
    denial_index: usize,
    blocked_index: Option<usize>,
}
const SHAPES: &[Shape] = &[
    Shape {
        family: "sql/friend_link_projection",
        table: "friend_link_projection",
        state_name: "state",
        state_index: 3,
        denial_name: "capability_revoked_at",
        denial_index: 6,
        blocked_index: Some(5),
    },
    Shape {
        family: "sql/friend_projection",
        table: "friend_projection",
        state_name: "link_state",
        state_index: 2,
        denial_name: "blocked_at",
        denial_index: 4,
        blocked_index: None,
    },
];
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn denied_state<'a>(current: &'a str, decision: &'a str) -> &'a str {
    if current == "removed" {
        current
    } else if decision == "blocked" {
        "blocked"
    } else if matches!(current, "pending" | "accepted") {
        "rejected"
    } else {
        current
    }
}
pub(super) fn derive(db: &Connection, family: &str, value: &mut Cells) -> Result<(), StorageError> {
    let Some(shape) = SHAPES.iter().find(|shape| shape.family == family) else {
        return Ok(());
    };
    let decision = db
        .query_row(
            "SELECT state,decided_at FROM contact_link_decision WHERE link_id=?1",
            [value.text(0)?],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((state, stamp)) = decision else {
        return Ok(());
    };
    if state == "lifted" {
        return Ok(());
    }
    if !matches!(state.as_str(), "blocked" | "declined") || stamp < 0 {
        return Err(invalid());
    }
    let next = denied_state(value.text(shape.state_index)?, &state).to_owned();
    value.set_text(shape.state_index, &next)?;
    if state == "blocked" {
        if let Some(index) = shape.blocked_index {
            value.set_integer(index, 1)?;
        }
        let stamp = stamp / 1000;
        let old = if value.kind(shape.denial_index)? == CellType::Null {
            stamp
        } else {
            value.integer(shape.denial_index)?.min(stamp)
        };
        value.set_integer(shape.denial_index, old)?;
    }
    Ok(())
}
pub(super) fn apply_decision(db: &Connection, decision: &Cells) -> Result<(), StorageError> {
    let state = decision.text(1)?;
    if state == "lifted" {
        return Ok(());
    }
    let stamp = decision.integer(2)?;
    if !matches!(state, "blocked" | "declined") || stamp < 0 {
        return Err(invalid());
    }
    for shape in SHAPES {
        let blocked = if shape.blocked_index.is_some() {
            ",blocked=CASE WHEN ?2='blocked' THEN 1 ELSE blocked END"
        } else {
            ""
        };
        // Every identifier is a compiled Shape field, never an input selector or SQL.
        db.execute(&format!("UPDATE \"{table}\" SET \"{column}\"=CASE WHEN \"{column}\"='removed' THEN 'removed' WHEN ?2='blocked' THEN 'blocked' WHEN \"{column}\" IN('pending','accepted') THEN 'rejected' ELSE \"{column}\" END,\"{denial}\"=CASE WHEN ?2='blocked' THEN min(coalesce(\"{denial}\",?3),?3) ELSE \"{denial}\" END{blocked} WHERE link_id=?1",table=shape.table,column=shape.state_name,denial=shape.denial_name),params![decision.text(0)?,state,stamp/1000])?;
    }
    Ok(())
}

pub(super) fn retain_absent(family: &str, value: &Cells) -> Result<bool, StorageError> {
    let Some(shape) = SHAPES.iter().find(|shape| shape.family == family) else {
        return Ok(false);
    };
    Ok(matches!(value.text(shape.state_index)?, "blocked" | "removed" | "rejected")
        || value.kind(shape.denial_index)? != CellType::Null
        || match shape.blocked_index {
            Some(index) => value.integer(index)? != 0,
            None => value.kind(5)? != CellType::Null,
        })
}
