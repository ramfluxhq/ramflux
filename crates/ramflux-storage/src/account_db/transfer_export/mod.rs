// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary transfer by canonical positive export (design r3 with audit amendments A1–A7).
//! A builds one canonical export file from its pinned cut through the shared builder; B
//! opens it only through `open_verified` and installs only a clean copy it rebuilt itself.
mod bodies;
mod builder;
mod classification;
mod contract;
mod open_verified;
#[cfg(feature = "itest-transfer-probe")]
pub mod probe;
mod tables;

use crate::{AccountDb, StorageError};
use contract::RowFilter;

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

fn carried_actor_rows(db: &rusqlite::Connection) -> rusqlite::Result<u64> {
    let mut total = 0_u64;
    for namespace in classification::ACTOR_EXPORTED {
        let pattern = format!(
            "{}*",
            namespace.prefix.replace('[', "[[]").replace('*', "[*]").replace('?', "[?]")
        );
        total += db.query_row(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB ?1",
            [pattern],
            |row| row.get::<_, u64>(0),
        )?;
    }
    Ok(total)
}
