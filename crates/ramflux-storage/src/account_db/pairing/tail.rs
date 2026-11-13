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
) WITHOUT ROWID;";
