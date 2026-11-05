// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Additive physical segment metadata, installed with every account schema.
use crate::{StorageError, database::Connection};

pub(crate) fn install(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS object_segment_file (
        transfer_id TEXT NOT NULL REFERENCES object_transfer_state(transfer_id) ON DELETE CASCADE,
        generation INTEGER NOT NULL CHECK(generation>0),
        segment_index INTEGER NOT NULL CHECK(segment_index>=0),
        expected_digest BLOB NOT NULL CHECK(length(expected_digest)=32),
        expected_length INTEGER NOT NULL CHECK(expected_length>=16 AND expected_length<=4194304),
        received_bitmap INTEGER NOT NULL DEFAULT 0 CHECK(received_bitmap BETWEEN 0 AND 255),
        chunk_digests BLOB NOT NULL CHECK(length(chunk_digests)=256),
        cipher_verified INTEGER NOT NULL DEFAULT 0 CHECK(cipher_verified IN (0,1)),
        PRIMARY KEY(transfer_id,generation,segment_index)
    );",
    )?;
    connection.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_segment_transfer_identity
         ON object_transfer_state(object_id,manifest_hash,segment_generation,direction)
         WHERE segment_generation IS NOT NULL;",
    )?;
    Ok(())
}
