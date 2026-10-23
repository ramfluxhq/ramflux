// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{RelayCacheState, RelayChunkStatus};

use crate::relay::test_support::{
    V3_CHUNK, V3_OBJECT, V3_OWNER_SEED, V3_REQUESTER_SEED, t14d_tombstone_chunk,
    t14d_tombstone_request, v3_pk,
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn owner_session_tombstone_applies_and_replay_is_zero_mutation() -> Result<(), String> {
    let now = 1_000_000;
    let mut state = RelayCacheState::new();
    state.put_chunk(t14d_tombstone_chunk(v3_pk(V3_OWNER_SEED))).map_err(|e| e.to_string())?;

    // A missing owner binding fails closed.
    let mut missing = t14d_tombstone_request();
    missing.owner_public_key = String::new();
    assert!(state.apply_owner_session_tombstone(missing, now).is_err());

    // A valid owner-session tombstone marks the owned chunk and records the object tombstone.
    let mutation = state
        .apply_owner_session_tombstone(t14d_tombstone_request(), now)
        .map_err(|error| error.to_string())?;
    assert!(mutation.changed);
    assert_eq!(mutation.affected_chunks.len(), 1);
    assert_eq!(
        state.chunk_entry(V3_CHUNK).map(|chunk| chunk.status),
        Some(RelayChunkStatus::Tombstoned)
    );
    assert!(state.tombstone(V3_OBJECT).is_some());

    // A byte-identical replay is idempotent with zero mutation.
    let replay = state
        .apply_owner_session_tombstone(t14d_tombstone_request(), now)
        .map_err(|error| error.to_string())?;
    assert!(!replay.changed);
    assert_eq!(replay.affected_chunks.len(), 0);
    Ok(())
}

#[test]
fn owner_session_tombstone_rejects_empty_and_cross_owner_scope() {
    let now = 1_000_000;

    // Empty scope: no stored chunk proves ownership -> fail closed, nothing recorded.
    let mut empty = RelayCacheState::new();
    assert!(empty.apply_owner_session_tombstone(t14d_tombstone_request(), now).is_err());
    assert!(empty.tombstone(V3_OBJECT).is_none());

    // Cross-owner: a chunk in scope owned by a different device fails the whole request closed,
    // leaving that chunk untouched.
    let mut cross = RelayCacheState::new();
    assert!(cross.put_chunk(t14d_tombstone_chunk(v3_pk(V3_REQUESTER_SEED))).is_ok());
    assert!(cross.apply_owner_session_tombstone(t14d_tombstone_request(), now).is_err());
    assert_eq!(
        cross.chunk_entry(V3_CHUNK).map(|chunk| chunk.status),
        Some(RelayChunkStatus::Available)
    );
    assert!(cross.tombstone(V3_OBJECT).is_none());
}
