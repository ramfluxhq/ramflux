// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

// Dormant extension: install only when the explicit segment-store API is opened.
// Transfer identity/progress stays in the existing owner. Segment rows describe
// physical files and their bounded (at most eight-chunk) integrity checkpoints.
pub(super) fn install(db: &AccountDb) -> Result<(), StorageError> {
    let tx = db.connection.immediate_transaction()?;
    let mut stmt = db.connection.prepare("PRAGMA table_info(object_transfer_state)")?;
    let columns =
        stmt.query_map([], |row| row.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
    for (name, definition) in [
        ("segment_generation", "segment_generation INTEGER"),
        ("segment_sequence", "segment_sequence INTEGER NOT NULL DEFAULT 0"),
        ("segment_manifest", "segment_manifest BLOB"),
    ] {
        if !columns.iter().any(|c| c == name) {
            db.connection.execute_batch(&format!(
                "ALTER TABLE object_transfer_state ADD COLUMN {definition}"
            ))?;
        }
    }
    db.connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS object_segment_file (
        transfer_id TEXT NOT NULL REFERENCES object_transfer_state(transfer_id) ON DELETE CASCADE,
        generation INTEGER NOT NULL CHECK(generation>0),
        segment_index INTEGER NOT NULL CHECK(segment_index>=0),
        expected_digest BLOB NOT NULL CHECK(length(expected_digest)=32),
        expected_length INTEGER NOT NULL CHECK(expected_length>=16 AND expected_length<=4194304),
        received_bitmap INTEGER NOT NULL DEFAULT 0 CHECK(received_bitmap BETWEEN 0 AND 255),
        chunk_digests BLOB NOT NULL CHECK(length(chunk_digests)=256),
        cipher_verified INTEGER NOT NULL DEFAULT 0 CHECK(cipher_verified IN (0,1)),
        authenticated INTEGER NOT NULL DEFAULT 0 CHECK(authenticated IN (0,1)),
        PRIMARY KEY(transfer_id,generation,segment_index)
    );",
    )?;
    db.connection.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_segment_transfer_identity
         ON object_transfer_state(object_id,manifest_hash,segment_generation,direction)
         WHERE segment_generation IS NOT NULL;",
    )?;
    tx.commit()?;
    Ok(())
}
