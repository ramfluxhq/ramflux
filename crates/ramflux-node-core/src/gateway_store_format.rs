// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway format v3 is fresh-state-only; older stores fail before state publication.
use super::replay_journal;
use crate::{GATEWAY_STATE_TABLE, NodeCoreError};
use redb::{ReadableDatabase, ReadableTable};
use std::path::Path;

pub(super) const FORMAT: &str = "gateway_state_format";
pub(super) fn open(path: impl AsRef<Path>) -> Result<redb::Database, NodeCoreError> {
    let path = path.as_ref();
    let existed = path.try_exists().map_err(redb_error)?;
    let mut builder = redb::Database::builder();
    builder.set_cache_size(super::GATEWAY_REPLAY_PAGE_CACHE_BYTES);
    let db = if existed { builder.open(path) } else { builder.create(path) }.map_err(redb_error)?;
    if existed {
        let read = db.begin_read().map_err(redb_error)?;
        let table = read
            .open_table(GATEWAY_STATE_TABLE)
            .map_err(|_| NodeCoreError::GatewayStateResetRequired)?;
        if table.get(FORMAT).map_err(redb_error)?.is_none_or(|value| value.value() != b"3") {
            return Err(NodeCoreError::GatewayStateResetRequired);
        }
    } else {
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
            table.insert(FORMAT, &b"3"[..]).map_err(redb_error)?;
        }
        replay_journal::initialize_tables(&write)?;
        super::session_overlay::initialize_tables(&write)?;
        write.commit().map_err(redb_error)?;
    }
    Ok(db)
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableTableMetadata;

    #[test]
    fn old_gateway_format_is_refused_without_partial_open() -> Result<(), Box<dyn std::error::Error>>
    {
        for (with_data, old_marker) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let path = ramflux_test_support::TestPath::new()
                .expect("test: allocate fixture directory")
                .child(format!(
                    "gateway-old-format-{}.redb",
                    ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
                ));
            {
                let db = redb::Database::create(&path)?;
                let write = db.begin_write()?;
                {
                    let mut table = write.open_table(GATEWAY_STATE_TABLE)?;
                    if old_marker {
                        table.insert(FORMAT, &b"2"[..])?;
                    }
                    if with_data {
                        table.insert(
                            "replay_guard_state",
                            br#"{"accepted_by_key":{}}"#.as_slice(),
                        )?;
                    }
                }
                write.commit()?;
            }
            assert!(matches!(
                crate::GatewayRedbStore::open(&path),
                Err(NodeCoreError::GatewayStateResetRequired)
            ));
            let db = redb::Database::open(&path)?;
            let read = db.begin_read()?;
            let table = read.open_table(GATEWAY_STATE_TABLE)?;
            assert_eq!(table.get(FORMAT)?.is_some(), old_marker);
            assert_eq!(table.len()?, u64::from(with_data) + u64::from(old_marker));
            drop(table);
            drop(read);
            drop(db);
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}
