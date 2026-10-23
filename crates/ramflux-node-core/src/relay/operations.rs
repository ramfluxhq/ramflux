// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist-before-publish relay operations and reservation cleanup.

use super::{
    ObjectChunkFrame, ObjectRelayTombstoneMutation, RelayCacheState, RelayChunkEntry,
    RelayChunkMeta, RelayChunkStatus, RelayExpiryMutation, RelayPutPlan, RelayRedbStore,
    RelayStoreOpError, object_relay_chunk_cipher_hash,
};

pub(super) type RelayStateMutex = std::sync::Mutex<RelayCacheState>;

pub(super) fn lock_relay_state(
    state: &RelayStateMutex,
) -> std::sync::MutexGuard<'_, RelayCacheState> {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// RAII rollback for an in-flight reservation. Any early return, store error, or unwind between
/// `reserve_*` and a successful `publish` drops this guard, which re-locks the state and cancels the
/// reservation (releasing its locks + reserved budget). `into_id` marks it consumed so the successful
/// path suppresses the cancel and hands the EXACT token to `publish`.
pub(super) struct RelayReservationGuard<'a> {
    state: &'a RelayStateMutex,
    id: u64,
    consumed: bool,
}

impl Drop for RelayReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            lock_relay_state(self.state).cancel_reservation(self.id);
        }
    }
}

impl RelayReservationGuard<'_> {
    fn into_id(mut self) -> u64 {
        self.consumed = true;
        self.id
    }
}

/// Persist-before-publish PUT of a pre-built candidate entry (shared by v2 after frame validation and
/// by the pre-verified v3 owner-session path). Never holds the state lock across the redb commit.
///
/// Ordering:
/// 1. Plan AND reserve under ONE lock (atomic): tombstone-block/owner/content(meta)/resurrect checks;
///    on a fresh id take an exclusive chunk lock + shared object ref and admit the full meta charge.
///    A concurrent same-chunk or object-exclusive (pending tombstone) mutation returns `Conflict`.
/// 2. Existing id: point-read the stored ciphertext and require an EXACT byte match (not just the
///    cipher hash) for an idempotent replay; otherwise reject.
/// 3. New id: commit the payload to redb (fsync) FIRST, then infallibly publish the exact reservation
///    token. A persist failure/unwind drops the RAII guard, which cancels the reservation.
///
/// Returns the stored entry and whether it was newly inserted.
///
/// # Errors
/// Returns a [`RelayStoreOpError`] mapped by the caller to a status code.
pub fn relay_store_put_candidate(
    store: &RelayRedbStore,
    state: &RelayStateMutex,
    candidate: RelayChunkEntry,
    _now: u64,
) -> Result<(RelayChunkEntry, bool), RelayStoreOpError> {
    enum PutPhase {
        Existing(RelayChunkEntry),
        New(RelayChunkEntry, u64),
    }
    let meta = RelayChunkMeta::from(&candidate);
    let phase = {
        let mut guard = lock_relay_state(state);
        match guard.plan_put(candidate)? {
            RelayPutPlan::Existing { candidate, .. } => PutPhase::Existing(candidate),
            RelayPutPlan::New(candidate) => {
                let id = guard.reserve_put(meta)?;
                PutPhase::New(candidate, id)
            }
        }
    };
    match phase {
        PutPhase::Existing(candidate) => {
            // Exact byte-identity idempotency: read the stored ciphertext and compare bytes.
            let stored = store
                .relay_chunk_entry(&candidate.chunk_id)
                .map_err(|error| RelayStoreOpError::PayloadUnavailable(error.to_string()))?
                .ok_or(RelayStoreOpError::NotAvailable)?;
            if stored.encrypted_chunk != candidate.encrypted_chunk {
                return Err(RelayStoreOpError::Unauthorized(
                    "object relay put rejects chunk content overwrite".to_owned(),
                ));
            }
            Ok((stored, false))
        }
        PutPhase::New(candidate, id) => {
            let guard = RelayReservationGuard { state, id, consumed: false };
            // Persist FIRST (post-fsync). On failure the guard drops -> cancel (nothing published).
            store
                .record_relay_chunk_entry(&candidate)
                .map_err(|error| RelayStoreOpError::Persist(error.to_string()))?;
            let id = guard.into_id();
            lock_relay_state(state).publish(id);
            Ok((candidate, true))
        }
    }
}

/// Persist-before-publish v2 PUT: validates the frame, builds the candidate, then applies
/// [`relay_store_put_candidate`].
///
/// # Errors
/// Returns a [`RelayStoreOpError`].
pub fn relay_store_put_frame(
    store: &RelayRedbStore,
    state: &RelayStateMutex,
    frame: ObjectChunkFrame,
    relay_service_key: &[u8],
    now: u64,
) -> Result<(RelayChunkEntry, bool), RelayStoreOpError> {
    let candidate = RelayCacheState::build_put_entry_from_frame(frame, relay_service_key, now)?;
    relay_store_put_candidate(store, state, candidate, now)
}

/// Read-through GET: given a validated resident meta snapshot, point-read the ciphertext from redb
/// WITHOUT holding the state lock, verify the payload hash/owner/id, then re-acquire the lock and
/// recheck status/tombstone/expiry/hash before returning. Any TOCTOU change fails closed (a
/// tombstoned/expired payload is never served).
///
/// # Errors
/// Returns a [`RelayStoreOpError`].
pub fn relay_store_read_through(
    store: &RelayRedbStore,
    state: &RelayStateMutex,
    expected: &RelayChunkMeta,
    now: u64,
) -> Result<RelayChunkEntry, RelayStoreOpError> {
    let entry = store
        .relay_chunk_entry(&expected.chunk_id)
        .map_err(|error| RelayStoreOpError::PayloadUnavailable(error.to_string()))?
        .ok_or(RelayStoreOpError::NotAvailable)?;
    // Verify the read payload against the expected metadata: identity and integrity, fail-closed.
    if entry.chunk_id != expected.chunk_id
        || entry.chunk_cipher_hash != expected.chunk_cipher_hash
        || entry.owner_signing_key_id != expected.owner_signing_key_id
        || entry.owner_public_key != expected.owner_public_key
    {
        return Err(RelayStoreOpError::PayloadUnavailable(
            "stored chunk does not match resident metadata".to_owned(),
        ));
    }
    let recomputed = object_relay_chunk_cipher_hash(
        &entry.manifest_hash,
        entry.chunk_index,
        &entry.encrypted_chunk,
    );
    if recomputed != expected.chunk_cipher_hash {
        return Err(RelayStoreOpError::PayloadUnavailable(
            "stored chunk ciphertext hash mismatch".to_owned(),
        ));
    }
    // Re-acquire the lock and recheck the chunk is still serveable and unchanged.
    let guard = lock_relay_state(state);
    // A published tombstone on the object is terminal.
    if guard.tombstone(&expected.object_id).is_some() {
        return Err(RelayStoreOpError::Tombstoned);
    }
    // An in-flight mutation on this exact chunk (tombstone/expiry/ack-with-delete) may be mid-way
    // through clearing the redb payload; fail closed (retryable) rather than serve a stale/half-
    // deleted payload. This also covers a pending tombstone that locked the chunk but hasn't
    // published its object tombstone yet.
    if guard.chunk_is_locked(&expected.chunk_id) {
        return Err(RelayStoreOpError::NotAvailable);
    }
    let current =
        guard.available_meta(&expected.chunk_id, now).ok_or(RelayStoreOpError::NotAvailable)?;
    if current.chunk_cipher_hash != expected.chunk_cipher_hash {
        return Err(RelayStoreOpError::NotAvailable);
    }
    drop(guard);
    Ok(entry)
}

/// Persist-before-publish ACK. The `plan` closure runs under the SAME lock as the reservation, so the
/// updated-meta computation and the exclusive chunk reservation are atomic (no PUT/tombstone can slip
/// in between). Then: point-read the full entry to keep/clear the payload (delete-on-ack leaves an
/// empty redb payload), persist FIRST, then infallibly publish the exact token. A persist failure
/// drops the RAII guard, which cancels the reservation.
///
/// # Errors
/// Returns a [`RelayStoreOpError`].
pub fn relay_store_ack<F>(
    store: &RelayRedbStore,
    state: &RelayStateMutex,
    plan: F,
) -> Result<RelayChunkMeta, RelayStoreOpError>
where
    F: FnOnce(&RelayCacheState) -> Result<RelayChunkMeta, RelayStoreOpError>,
{
    let (updated, id) = {
        let mut guard = lock_relay_state(state);
        let updated = plan(&guard)?;
        let id = guard.reserve_ack(updated.clone())?;
        (updated, id)
    };
    let reservation = RelayReservationGuard { state, id, consumed: false };
    let stored = store
        .relay_chunk_entry(&updated.chunk_id)
        .map_err(|error| RelayStoreOpError::PayloadUnavailable(error.to_string()))?
        .ok_or(RelayStoreOpError::NotAvailable)?;
    // Keep the ciphertext unless the ack consumed the chunk (delete-on-ack / any non-Available end
    // state), in which case the redb payload is cleared.
    let payload = if updated.status == RelayChunkStatus::Available {
        stored.encrypted_chunk
    } else {
        Vec::new()
    };
    let entry = updated.to_entry(payload);
    store
        .record_relay_chunk_entry(&entry)
        .map_err(|error| RelayStoreOpError::Persist(error.to_string()))?;
    let id = reservation.into_id();
    lock_relay_state(state).publish(id);
    Ok(updated)
}

/// Persist-before-publish TOMBSTONE. The `plan` closure runs under the SAME lock as the reservation,
/// so the affected-chunk set reflects the current published state atomically and no concurrent PUT can
/// land an uncovered chunk (`reserve_tombstone` also rejects an object with a pending PUT/ACK). Then
/// commit the batch to redb FIRST and infallibly publish. An idempotent replay (`changed == false`)
/// neither reserves, persists, nor publishes.
///
/// # Errors
/// Returns a [`RelayStoreOpError`].
pub fn relay_store_tombstone<F>(
    store: &RelayRedbStore,
    state: &RelayStateMutex,
    plan: F,
) -> Result<ObjectRelayTombstoneMutation, RelayStoreOpError>
where
    F: FnOnce(&RelayCacheState) -> Result<ObjectRelayTombstoneMutation, RelayStoreOpError>,
{
    let (mutation, id) = {
        let mut guard = lock_relay_state(state);
        let mutation = plan(&guard)?;
        if !mutation.changed {
            return Ok(mutation);
        }
        let id = guard.reserve_tombstone(mutation.clone())?;
        (mutation, id)
    };
    let reservation = RelayReservationGuard { state, id, consumed: false };
    store
        .record_relay_tombstone_mutation(&mutation)
        .map_err(|error| RelayStoreOpError::Persist(error.to_string()))?;
    let id = reservation.into_id();
    lock_relay_state(state).publish(id);
    Ok(mutation)
}

/// Persist-before-publish EXPIRY: plan + atomically reserve (locking the to-delete ids, skipping any
/// locked by an in-flight PUT/ACK/tombstone), batch-delete from redb FIRST, then infallibly publish
/// the removal. On a persist failure the RAII guard cancels the reservation, so the resident entries
/// stay put — reads still reject them by `expires_at`, and a restart cannot resurrect a servable
/// payload (the redb rows were never deleted).
///
/// # Errors
/// Returns a [`RelayStoreOpError`].
pub fn relay_store_expire(
    store: &RelayRedbStore,
    state: &RelayStateMutex,
    now: u64,
) -> Result<RelayExpiryMutation, RelayStoreOpError> {
    let (id, applied) = {
        let mut guard = lock_relay_state(state);
        let planned = guard.plan_expiry(now);
        match guard.reserve_expiry(planned)? {
            Some(pair) => pair,
            None => return Ok(RelayExpiryMutation::default()),
        }
    };
    let reservation = RelayReservationGuard { state, id, consumed: false };
    store
        .record_relay_expiry_mutation(&applied)
        .map_err(|error| RelayStoreOpError::Persist(error.to_string()))?;
    let id = reservation.into_id();
    lock_relay_state(state).publish(id);
    Ok(applied)
}
