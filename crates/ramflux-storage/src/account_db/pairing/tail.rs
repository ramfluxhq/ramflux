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
) WITHOUT ROWID;";
