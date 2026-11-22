// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary transfer by canonical positive export (design r3 with audit amendments A1–A7).
//! A builds one canonical export file from its pinned cut through the shared builder; B
//! opens it only through `open_verified` and installs only a clean copy it rebuilt itself.
mod bodies;
pub(super) mod builder;
mod classification;
mod contract;
pub(super) mod digest;
pub(super) mod open_verified;
#[cfg(feature = "itest-transfer-probe")]
pub mod probe;
mod tables;

use crate::{AccountDb, StorageError};
pub(crate) use classification::table_excluded;
use contract::RowFilter;
pub use contract::export_contract_digest;

/// Framing in front of the file in a transfer stream: domain tag, 32-byte file key, u64 length.
pub(crate) const FRAME_HEADER_BYTES: u64 = 28 + 32 + 8;

/// Per-cut size limit (A5): the framed total of one cut (header, file and any trailing
/// section) must not exceed the pre-publication delta stop, so the first delta is the last
/// under the signed rule. Returns the framed total.
/// # Errors
/// `PairingField("NoSpace")` over the limit.
pub(crate) fn require_cut_size(file_bytes: u64, trailing_bytes: u64) -> Result<u64, StorageError> {
    let framed = FRAME_HEADER_BYTES.saturating_add(file_bytes).saturating_add(trailing_bytes);
    if framed > ramflux_protocol::custody::pairing::full_transfer::PREPUBLICATION_DELTA_STOP_BYTES {
        tracing::warn!(framed, "transfer export exceeds the per-cut size limit");
        return Err(StorageError::PairingField("NoSpace"));
    }
    Ok(framed)
}

/// Tables a recipient's own join writes before the transfer streams (its account root).
const JOIN_CREATED: &[&str] = &["runtime_account_identity"];

impl AccountDb {
    /// A4: a transfer installs only into a FRESH recipient. B checks this itself and does not
    /// trust A's flag: no exported table may hold a carried row besides what its join wrote.
    /// Account creation writes one `directory/identity/` row for the owner; that row is bootstrap.
    /// # Errors
    /// `PairingField("RecipientNotFresh")` when carried rows exist; SQL errors.
    pub fn require_fresh_transfer_target(&self) -> Result<(), StorageError> {
        let carried = self.connection.call(|db| {
            let mut total = 0_u64;
            for table in tables::EXPORT_TABLES {
                if JOIN_CREATED.contains(&table.name) {
                    continue;
                }
                let exists: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                    [table.name],
                    |row| row.get(0),
                )?;
                if !exists {
                    continue;
                }
                total += match table.filter {
                    RowFilter::All => db.query_row(
                        &format!("SELECT count(*) FROM \"{}\"", table.name),
                        [],
                        |row| row.get::<_, u64>(0),
                    )?,
                    RowFilter::ActorNamespaces => carried_actor_rows(db)?,
                };
            }
            Ok(total)
        })?;
        if carried != 0 {
            tracing::warn!(
                carried,
                "transfer recipient holds account data; only a fresh device may receive"
            );
            return Err(StorageError::PairingField("RecipientNotFresh"));
        }
        Ok(())
    }
}

fn glob_pattern(prefix: &str) -> String {
    format!("{}*", prefix.replace('[', "[[]").replace('*', "[*]").replace('?', "[?]"))
}

fn glob_count(db: &rusqlite::Connection, prefix: &str) -> rusqlite::Result<u64> {
    db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB ?1",
        [glob_pattern(prefix)],
        |row| row.get(0),
    )
}

/// Identity rows other than the single account-creation row. That row's root commitment is
/// the account root (`capture::initialize_own_identity`); a contact row carries a different one.
fn identity_rows_beyond_owner(
    db: &rusqlite::Connection,
    prefix: &str,
    own: &str,
) -> rusqlite::Result<u64> {
    let pattern = glob_pattern(prefix);
    let others: u64 = db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB ?1 AND COALESCE(json_extract(CAST(state_json AS TEXT), '$.contact_identity_commitment'), '') != ?2",
        (pattern.clone(), own),
        |row| row.get(0),
    )?;
    let own_rows: u64 = db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB ?1 AND json_extract(CAST(state_json AS TEXT), '$.contact_identity_commitment') = ?2",
        (pattern, own),
        |row| row.get(0),
    )?;
    Ok(others + own_rows.saturating_sub(1))
}

fn carried_actor_rows(db: &rusqlite::Connection) -> rusqlite::Result<u64> {
    let own: String = db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let mut total = 0_u64;
    for namespace in classification::ACTOR_EXPORTED {
        total += if namespace.prefix == "directory/identity/" {
            identity_rows_beyond_owner(db, namespace.prefix, &own)?
        } else {
            glob_count(db, namespace.prefix)?
        };
    }
    Ok(total)
}
