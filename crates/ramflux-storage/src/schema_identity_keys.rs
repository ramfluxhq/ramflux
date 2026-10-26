// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preserve unattributed historical retry buckets without granting live root authority.
use crate::{StorageError, database::Connection};
use rusqlite::params;

pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS root_identity_key_upgrade(singleton INTEGER PRIMARY KEY CHECK(singleton=1));")?;
    if connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM root_identity_key_upgrade)",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(());
    }
    let transaction = connection.immediate_transaction()?;
    let rows = {
        let mut query =
            connection.prepare("SELECT envelope_key,source FROM runtime_inbox_policy")?;
        query
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (key, source) in rows {
        connection.execute(
            "UPDATE runtime_inbox_policy SET source=?2,trusted=0 WHERE envelope_key=?1",
            params![key, format!("legacy/inbox/{}", ramflux_protocol::encode_base64url(source))],
        )?;
    }
    connection.execute("INSERT INTO root_identity_key_upgrade VALUES(1)", [])?;
    transaction.commit()?;
    Ok(())
}
