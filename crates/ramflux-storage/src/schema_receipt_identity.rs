// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retain mixed-format historical markers without interpreting a literal name as a scoped actor.
use crate::{StorageError, database::Connection};
pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS receipt_identity_upgrade(singleton INTEGER PRIMARY KEY CHECK(singleton=1));")?;
    if connection.query_row("SELECT EXISTS(SELECT 1 FROM receipt_identity_upgrade)", [], |row| {
        row.get::<_, bool>(0)
    })? {
        return Ok(());
    }
    let transaction = connection.unchecked_transaction()?;
    for table in [
        "receipt_projection",
        "conversation_delivery_state",
        "conversation_read_state",
        "conversation_unread_marker",
    ] {
        connection.execute_batch(&format!("CREATE TABLE IF NOT EXISTS legacy_{table} AS SELECT * FROM {table} WHERE 0; INSERT INTO legacy_{table} SELECT * FROM {table}; DELETE FROM {table};"))?;
    }
    connection.execute("INSERT INTO receipt_identity_upgrade VALUES(1)", [])?;
    transaction.commit()?;
    Ok(())
}
