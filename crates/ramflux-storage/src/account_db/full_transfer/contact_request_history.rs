// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public request history binds its original nonce/context; it never restores reply approval.
use super::{FamilyRule, fixed_union::Cells, sql_projection};
use crate::{StorageError, database::Connection as Managed};
use rusqlite::{Connection, OptionalExtension as _};
pub(super) const FAMILY: &str = "sql/contact_request_projection";
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn check_binding(
    own: &str,
    peer: &str,
    direction: &str,
    id: &str,
    metadata: &[u8],
    expires: i64,
) -> Result<(), StorageError> {
    let public = sql_projection::read_contact_metadata(metadata)?;
    let requester = match direction {
        "inbound" => peer,
        "outbound" => own,
        _ => return Err(invalid()),
    };
    if peer == own
        || public.issued_at.checked_add(604_800) != Some(expires)
        || id
            != ramflux_protocol::hash_base64url(
                "ramflux.contact_request.id.v1",
                &ramflux_protocol::canonical_json_bytes(&(requester, &public.nonce))?,
            )
    {
        return Err(invalid());
    }
    Ok(())
}
fn own_root(db: &Connection) -> Result<String, StorageError> {
    Ok(db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
}
pub(super) fn require_cells(db: &Connection, value: &Cells) -> Result<(), StorageError> {
    check_binding(
        &own_root(db)?,
        value.text(0)?,
        value.text(1)?,
        value.text(2)?,
        value.bytes(6)?,
        value.integer(7)?,
    )
}
pub(super) fn require_source(db: &Managed, rules: &[FamilyRule]) -> Result<(), StorageError> {
    let enabled = rules.iter().any(|rule| {
        rule.id == FAMILY
            && rule
                .codec
                .iter()
                .any(|field| matches!(field.codec, super::CodecRule::SqlJsonProjection { .. }))
    });
    if !enabled {
        return Ok(());
    }
    db.call(|db| Ok(require_rows(db)))?
}
fn require_rows(db: &Connection) -> Result<(), StorageError> {
    if !db.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_projection)", [], |row| {
        row.get::<_, bool>(0)
    })? {
        return Ok(());
    }
    let own = own_root(db)?;
    let mut query = db.prepare("SELECT CASE WHEN length(contact_identity_commitment)=43 THEN contact_identity_commitment END,direction,CASE WHEN length(request_id)=43 THEN request_id END,CASE WHEN length(request_json)<=1024 THEN request_json END,expires_at FROM contact_request_projection")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let public = super::catalog::SqlProjection::ContactRequestMetadataV1
            .source(row.get_ref(3)?.as_blob().map_err(|_| invalid())?)?;
        check_binding(
            &own,
            row.get_ref(0)?.as_str().map_err(|_| invalid())?,
            row.get_ref(1)?.as_str().map_err(|_| invalid())?,
            row.get_ref(2)?.as_str().map_err(|_| invalid())?,
            &public,
            row.get(4)?,
        )?;
    }
    Ok(())
}

pub(super) fn derive(db: &Connection, family: &str, value: &mut Cells) -> Result<(), StorageError> {
    if family != FAMILY {
        return Ok(());
    }
    require_cells(db, value)?;
    for (query, key) in [
        (
            "SELECT state,decided_at FROM contact_request_decision WHERE root=?1",
            value.text(0)?.to_owned(),
        ),
        (
            "SELECT state,decided_at FROM contact_link_decision WHERE link_id=?1",
            value.text(4)?.to_owned(),
        ),
    ] {
        let decision = db
            .query_row(query, [key], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
            .optional()?;
        let Some((state, stamp)) = decision else {
            continue;
        };
        if stamp < 0 || !matches!(state.as_str(), "blocked" | "declined" | "lifted") {
            return Err(invalid());
        }
        let stronger = state == "blocked" && value.text(5)? != "blocked"
            || state == "declined" && !matches!(value.text(5)?, "blocked" | "declined");
        if stronger {
            value.set_text(5, &state)?;
            value.set_integer(8, stamp / 1000)?;
        }
    }
    Ok(())
}
pub(super) fn retain_absent(family: &str, value: &Cells) -> Result<bool, StorageError> {
    Ok(family == FAMILY && matches!(value.text(5)?, "blocked" | "declined" | "expired"))
}

#[cfg(test)]
mod tests;
