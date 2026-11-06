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

/// Portable floors are restrictions; resource rows are local cleanup debt/provenance.
pub(crate) const RETIREMENT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS object_segment_reference_veto(reference_id BLOB PRIMARY KEY CHECK(length(reference_id)=32));
CREATE TABLE IF NOT EXISTS object_segment_floor(directory TEXT PRIMARY KEY,generation INTEGER NOT NULL CHECK(generation>0));
CREATE TABLE IF NOT EXISTS object_segment_resource(directory TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),transfer_id TEXT,wire TEXT NOT NULL,manifest TEXT NOT NULL,commitment TEXT NOT NULL,selector TEXT,reference_hash TEXT,message_id TEXT,retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN(0,1)),PRIMARY KEY(directory,generation));
CREATE INDEX IF NOT EXISTS object_segment_resource_transfer ON object_segment_resource(transfer_id,generation);
CREATE INDEX IF NOT EXISTS object_segment_resource_retired ON object_segment_resource(retired,directory,generation);
CREATE INDEX IF NOT EXISTS object_segment_resource_reference ON object_segment_resource(reference_hash,message_id);
CREATE INDEX IF NOT EXISTS object_segment_resource_payload ON object_segment_resource(commitment);
CREATE TRIGGER IF NOT EXISTS segment_payload_erased AFTER INSERT ON object_erasure_fence BEGIN UPDATE object_segment_resource SET retired=1 WHERE commitment=NEW.commitment; END;
CREATE TRIGGER IF NOT EXISTS segment_reference_removed AFTER DELETE ON object_message_reference BEGIN
UPDATE object_segment_resource SET retired=1 WHERE reference_hash=OLD.reference_hash AND message_id=OLD.message_id; END;
CREATE TRIGGER IF NOT EXISTS segment_transfer_removed BEFORE DELETE ON object_transfer_state BEGIN
UPDATE object_segment_resource SET retired=1 WHERE transfer_id=OLD.transfer_id; END;
CREATE TRIGGER IF NOT EXISTS segment_resource_retired AFTER UPDATE OF retired ON object_segment_resource WHEN NEW.retired=1 BEGIN
INSERT INTO object_segment_floor VALUES(NEW.directory,NEW.generation) ON CONFLICT(directory) DO UPDATE SET generation=max(generation,excluded.generation); END;
CREATE TRIGGER IF NOT EXISTS segment_floor_added AFTER INSERT ON object_segment_floor BEGIN UPDATE object_segment_resource SET retired=1 WHERE directory=NEW.directory AND generation<=NEW.generation AND retired=0; END;
CREATE TRIGGER IF NOT EXISTS segment_floor_raised AFTER UPDATE ON object_segment_floor BEGIN UPDATE object_segment_resource SET retired=1 WHERE directory=NEW.directory AND generation<=NEW.generation AND retired=0; END;
CREATE TRIGGER IF NOT EXISTS segment_floor_no_delete BEFORE DELETE ON object_segment_floor BEGIN SELECT RAISE(ABORT,'segment retirement floors are append-only'); END;
CREATE TRIGGER IF NOT EXISTS segment_floor_no_lower BEFORE UPDATE ON object_segment_floor WHEN NEW.generation<OLD.generation BEGIN SELECT RAISE(ABORT,'segment retirement floor rollback'); END;
";
