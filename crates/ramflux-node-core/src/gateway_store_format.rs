// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway format v3 is fresh-state-only; older stores fail before state publication.
use super::replay_journal;
use crate::{GATEWAY_STATE_TABLE, NodeCoreError};
use redb::{ReadableDatabase, ReadableTable};
use std::path::Path;

pub(super) const FORMAT: &str = "gateway_state_format";
pub(super) fn open(path: impl AsRef<Path>) -> Result<redb::Database, NodeCoreError> {
    open_with(path.as_ref(), |_| {})
}

fn open_with(
    path: &Path,
    mut initialized: impl FnMut(bool),
) -> Result<redb::Database, NodeCoreError> {
    let mut builder = redb::Database::builder();
    builder.set_cache_size(super::GATEWAY_REPLAY_PAGE_CACHE_BYTES);
    if !path.try_exists().map_err(redb_error)? {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // Only a fully committed v3 database can acquire the public name. An interrupted
        // creator leaves an unpublished temporary file; old public files remain refused.
        let stage = tempfile::Builder::new()
            .prefix(".gateway-init-")
            .tempfile_in(directory)
            .map_err(redb_error)?;
        let db = builder.create(stage.path()).map_err(redb_error)?;
        initialized(false);
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write.open_table(GATEWAY_STATE_TABLE).map_err(redb_error)?;
            table.insert(FORMAT, b"3".as_slice()).map_err(redb_error)?;
        }
        replay_journal::initialize_tables(&write)?;
        super::session_overlay::initialize_tables(&write)?;
        write.commit().map_err(redb_error)?;
        drop(db);
        stage.as_file().sync_all().map_err(redb_error)?;
        initialized(true);
        match stage.persist_noclobber(path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(redb_error(error)),
        }
        #[cfg(unix)]
        std::fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(redb_error)?;
    }
    let db = builder.open(path).map_err(redb_error)?;
    {
        let read = db.begin_read().map_err(redb_error)?;
        let table = read
            .open_table(GATEWAY_STATE_TABLE)
            .map_err(|_| NodeCoreError::GatewayStateResetRequired)?;
        if table.get(FORMAT).map_err(redb_error)?.is_none_or(|value| value.value() != b"3") {
            return Err(NodeCoreError::GatewayStateResetRequired);
        }
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
            let directory = tempfile::TempDir::new()?;
            let path = directory.path().join("gateway.redb");
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
            assert!(
                matches!(
                    crate::GatewayRedbStore::open(&path),
                    Err(NodeCoreError::GatewayStateResetRequired)
                ),
                "old stores must fail closed before publication"
            );
            let db = redb::Database::open(&path)?;
            let read = db.begin_read()?;
            let table = read.open_table(GATEWAY_STATE_TABLE)?;
            assert_eq!(
                table.get(FORMAT)?.is_some(),
                old_marker,
                "refusal must not change the marker"
            );
            assert_eq!(
                table.len()?,
                u64::from(with_data) + u64::from(old_marker),
                "refusal must not rewrite old rows"
            );
            drop(table);
            drop(read);
            drop(db);
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn initial_creation_crash_never_publishes_unmarked_database()
    -> Result<(), Box<dyn std::error::Error>> {
        const CHILD_PATH: &str = "RAMFLUX_TEST_GATEWAY_INIT_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let after_commit = std::env::var("RAMFLUX_TEST_GATEWAY_INIT_COMMITTED")? == "true";
            open_with(Path::new(&path), |committed| {
                if committed == after_commit {
                    std::process::exit(91);
                }
            })?;
            return Err("initialization crash hook was not reached".into());
        }
        let directory = tempfile::TempDir::new()?;
        for committed in [false, true] {
            let path = directory.path().join(format!("gateway-{committed}.redb"));
            let mut command = tokio::process::Command::new(std::env::current_exe()?);
            command.args(["--exact", "gateway_state::store_format::tests::initial_creation_crash_never_publishes_unmarked_database"])
                .env(CHILD_PATH, &path)
                .env("RAMFLUX_TEST_GATEWAY_INIT_COMMITTED", committed.to_string())
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            let status = tokio::time::timeout(std::time::Duration::from_secs(10), command.status())
                .await??;
            assert_eq!(
                status.code(),
                Some(91),
                "child must crash at the selected initialization boundary"
            );
            assert!(
                !path.try_exists()?,
                "a crashed initializer must not publish a partial database"
            );
            let store = crate::GatewayRedbStore::open(&path)?;
            drop(store);
            let db = open(&path)?;
            let read = db.begin_read()?;
            let table = read.open_table(GATEWAY_STATE_TABLE)?;
            assert_eq!(
                table.get(FORMAT)?.map(|value| value.value().to_vec()),
                Some(b"3".to_vec()),
                "retry must publish a committed v3 marker"
            );
        }
        Ok(())
    }
}
