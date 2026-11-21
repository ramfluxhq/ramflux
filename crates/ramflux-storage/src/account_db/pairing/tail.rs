// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local tail-cut identity. It is never restored or imported as another device's work.
pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pairing_full_tail(
 account_id TEXT NOT NULL PRIMARY KEY,
 operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
 stage_id TEXT NOT NULL CHECK(length(stage_id)=43),
 snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=43),
 record_hash TEXT NOT NULL CHECK(length(record_hash)=43),
 tail_status TEXT NOT NULL CHECK(tail_status IN ('pending','merged','abandoned')),
 cut_state TEXT NOT NULL CHECK(cut_state IN ('pinned','durable'))
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairing_source_cleanup(
 account_id TEXT NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
 operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
 record_hash TEXT NOT NULL CHECK(length(record_hash)=43),
 source_ref BLOB NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 4096),
 primary_ref TEXT NOT NULL CHECK(length(primary_ref)=43),
 old_self_key TEXT NOT NULL CHECK(length(old_self_key)=43),
 PRIMARY KEY(account_id,operation_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairing_full_tail_apply(
 operation_id TEXT NOT NULL PRIMARY KEY CHECK(length(operation_id)=43),
 generation_nonce TEXT NOT NULL UNIQUE CHECK(length(generation_nonce)=43),
 stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32),
 source_owner TEXT NOT NULL CHECK(length(source_owner) BETWEEN 1 AND 1024),
 tail_hash TEXT CHECK(tail_hash IS NULL OR length(tail_hash)=43),
 phase INTEGER NOT NULL DEFAULT 0 CHECK(phase BETWEEN 0 AND 2),
 next_record INTEGER NOT NULL DEFAULT 0 CHECK(next_record>=0),
 tail_status TEXT NOT NULL DEFAULT 'pending' CHECK(tail_status IN ('pending','merged','abandoned'))
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairing_full_tail_dependency(
 operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
 owner INTEGER NOT NULL CHECK(owner IN(0,1)),
 parent_commitment TEXT NOT NULL CHECK(length(parent_commitment)=43),
 child_commitment TEXT NOT NULL CHECK(length(child_commitment)=43),
 PRIMARY KEY(operation_id,owner,parent_commitment,child_commitment),
 FOREIGN KEY(operation_id) REFERENCES pairing_full_tail_apply(operation_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairing_full_completion(
 operation_id TEXT NOT NULL PRIMARY KEY CHECK(length(operation_id)=43),
 generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 role TEXT NOT NULL CHECK(role IN('initiator','responder')),
 stage_id TEXT NOT NULL CHECK(length(stage_id)=43),
 receipt BLOB NOT NULL CHECK(length(receipt) BETWEEN 1 AND 16384),
 finished_at INTEGER NOT NULL CHECK(finished_at BETWEEN 0 AND 9007199254740991),
 cleanup_state TEXT NOT NULL DEFAULT 'pending' CHECK(cleanup_state IN('pending','done'))
) WITHOUT ROWID;

";
