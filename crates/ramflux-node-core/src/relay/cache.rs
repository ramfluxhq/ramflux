// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Payload-free chunk index, reservations, and in-memory publication.

use super::{
    BTreeMap, BTreeSet, Deserialize, NodeCoreError, OBJECT_RELAY_TOKEN_VERSION,
    OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS, ObjectChunkFrame, ObjectPermissionEnvelope,
    ObjectRelayAck, ObjectRelayCapability, ObjectRelayTombstone, RELAY_METADATA_MAX_BYTES_DEFAULT,
    RelayChunkEntry, RelayChunkMeta, RelayChunkStatus, RelayInternalInvariant,
    RelayResidentBudgetExceeded, RelayStoreOpError, RelayToken, Serialize,
    clamp_relay_chunk_expires_at, existing_tombstone_matches_replay,
    permission_owner_matches_token, tombstone_resident_charge, validate_object_chunk_frame,
    validate_object_permission, validate_relay_token,
};

use super::relay_default_max_bytes;

/// The concrete mutation an in-flight reservation will publish once its redb commit succeeds. Stored
/// on the reservation so `publish(id)` is an infallible, self-contained consume of an exact token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RelayPendingMutation {
    /// A brand-new chunk meta (PUT).
    Put(RelayChunkMeta),
    /// An in-place chunk meta update (ACK).
    Ack(RelayChunkMeta),
    /// A tombstone plus its affected (payload-cleared) chunk metas.
    Tombstone(Box<ObjectRelayTombstoneMutation>),
    /// An expiry removal set (the exact ids being deleted this round).
    Expiry(RelayExpiryMutation),
}

/// An in-flight, persist-before-publish mutation reservation. It holds exclusive chunk-id locks and a
/// shared (PUT/ACK) or exclusive (Tombstone/Expiry) object lock, and pre-charges the positive
/// resident-budget delta into `reserved_bytes` so the budget stays a HARD bound across the redb
/// commit. `resident_add`/`resident_sub` are the exact deltas applied to `resident_bytes` at publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RelayReservation {
    chunk_ids: Vec<String>,
    shared_objects: Vec<String>,
    exclusive_objects: Vec<String>,
    reserved_charge: u64,
    resident_add: u64,
    resident_sub: u64,
    pending: RelayPendingMutation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayCacheState {
    /// Resident, payload-free chunk index. Ciphertext is never held here; it lives in redb.
    pub(super) chunks_by_id: BTreeMap<String, RelayChunkMeta>,
    pub(super) tombstones_by_object_id: BTreeMap<String, ObjectRelayTombstone>,
    /// In-flight persist-before-publish reservations, keyed by a monotonic reservation id.
    #[serde(skip)]
    reservations: BTreeMap<u64, RelayReservation>,
    /// Exclusive chunk-id locks: `chunk_id` -> owning reservation id. A locked chunk cannot be
    /// concurrently PUT/ACK/tombstoned/expired.
    #[serde(skip)]
    locked_chunk_ids: BTreeMap<String, u64>,
    /// Shared object references held by in-flight PUT/ACK reservations: `object_id` -> reservation ids.
    #[serde(skip)]
    object_shared_locks: BTreeMap<String, BTreeSet<u64>>,
    /// Exclusive object locks held by in-flight Tombstone/Expiry reservations: `object_id` -> id.
    #[serde(skip)]
    object_exclusive_locks: BTreeMap<String, u64>,
    #[serde(skip)]
    next_reservation_id: u64,
    /// True resident charge of the PUBLISHED index (chunk-meta + tombstone). Recomputed on hydrate.
    #[serde(skip)]
    resident_bytes: u64,
    /// Sum of the positive headroom held by in-flight reservations. `resident_bytes + reserved_bytes`
    /// is the hard bound checked against `max_bytes` at every admission.
    #[serde(skip)]
    reserved_bytes: u64,
    /// Resident metadata budget ceiling. Not serialized; set explicitly on construction/hydrate and
    /// defaults to 64 MiB so a deserialized legacy snapshot is never left with a zero (fail-open) cap.
    #[serde(skip, default = "relay_default_max_bytes")]
    max_bytes: u64,
}

impl Default for RelayCacheState {
    fn default() -> Self {
        Self {
            chunks_by_id: BTreeMap::new(),
            tombstones_by_object_id: BTreeMap::new(),
            reservations: BTreeMap::new(),
            locked_chunk_ids: BTreeMap::new(),
            object_shared_locks: BTreeMap::new(),
            object_exclusive_locks: BTreeMap::new(),
            next_reservation_id: 0,
            resident_bytes: 0,
            reserved_bytes: 0,
            max_bytes: RELAY_METADATA_MAX_BYTES_DEFAULT,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRelayTombstoneMutation {
    pub tombstone: ObjectRelayTombstone,
    /// The metadata of every chunk the tombstone marked. Payload-free by construction: the tombstone
    /// clears ciphertext, so the store persists these as payload-empty redb rows.
    pub affected_chunks: Vec<RelayChunkMeta>,
    /// `true` only when this mutation applied a durable change (the first tombstone for the object).
    /// A stable idempotent replay sets this to `false`, so `record_relay_tombstone_mutation` is a
    /// complete no-op and never rewrites the redb tombstone/chunk rows.
    pub changed: bool,
}

/// The already-verified inputs for an owner-session (v3) tombstone. The caller (relay client QUIC
/// ingress) must have verified the v3 invocation — owner authorization proof + requester `PoP` — and
/// pass the owner identity and tombstone metadata it bound. `manifest_hash` scopes the tombstone to a
/// single manifest (`Some`) or the whole object (`None`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSessionTombstoneRequest {
    pub object_id: String,
    pub manifest_hash: Option<String>,
    pub tombstone_hash: String,
    pub source_event_id: String,
    pub signed_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelayExpiryMutation {
    pub expired_chunk_ids: Vec<String>,
    pub expired_tombstone_object_ids: Vec<String>,
}

impl RelayExpiryMutation {
    #[must_use]
    pub fn expired_count(&self) -> usize {
        self.expired_chunk_ids.len() + self.expired_tombstone_object_ids.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expired_chunk_ids.is_empty() && self.expired_tombstone_object_ids.is_empty()
    }
}

/// Internal plan of a PUT against the resident meta index (no mutation, no persist).
pub(super) enum RelayPutPlan {
    /// Chunk id already present and all metadata-level checks passed. The caller must still
    /// byte-verify the candidate against the stored ciphertext (via a redb point-read) before
    /// treating it as an idempotent replay.
    Existing { existing: RelayChunkMeta, candidate: RelayChunkEntry },
    /// A fresh chunk id whose owner/tombstone checks passed; the candidate must be persisted.
    New(RelayChunkEntry),
}

impl RelayCacheState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs an empty state with an explicit resident metadata budget.
    #[must_use]
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        Self { max_bytes, ..Self::default() }
    }

    /// The configured resident metadata budget ceiling in bytes.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Test helper: lowers/raises the cap in place (does not re-check the current resident charge).
    #[cfg(test)]
    pub(crate) fn set_max_bytes_for_test(&mut self, max_bytes: u64) {
        self.max_bytes = max_bytes;
    }

    /// Test helper: forces the resident charge (to drive a publish arithmetic-underflow fail-stop).
    #[cfg(test)]
    pub(crate) fn set_resident_bytes_for_test(&mut self, resident_bytes: u64) {
        self.resident_bytes = resident_bytes;
    }

    /// Test helper: forces the next reservation id (to drive the id-exhaustion fail-stop).
    #[cfg(test)]
    pub(crate) fn set_next_reservation_id_for_test(&mut self, next: u64) {
        self.next_reservation_id = next;
    }

    /// Test helper: independently recomputes the resident charge from the PUBLISHED chunk metas and
    /// tombstones, used to assert exact conservation of `resident_bytes`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn recompute_resident_for_test(&self) -> u64 {
        let mut total: u64 = 0;
        for meta in self.chunks_by_id.values() {
            total = total.saturating_add(meta.resident_charge().unwrap_or(0));
        }
        for tombstone in self.tombstones_by_object_id.values() {
            total = total.saturating_add(tombstone_resident_charge(tombstone).unwrap_or(0));
        }
        total
    }

    /// The current resident metadata charge (chunk-meta + tombstone + in-flight reservations).
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    /// Sum of the positive headroom currently held by in-flight reservations.
    #[must_use]
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// Sets the resident metadata budget and recomputes the true published charge from the current
    /// maps (used after a legacy-snapshot deserialize whose skipped budget fields defaulted). All
    /// accounting is CHECKED; an overflow or an over-cap total fails closed.
    ///
    /// # Errors
    /// Returns [`RelayResidentBudgetExceeded`] on overflow or when the resident charge exceeds
    /// `max_bytes`.
    pub fn rehydrate_budget(&mut self, max_bytes: u64) -> Result<(), RelayResidentBudgetExceeded> {
        self.max_bytes = max_bytes;
        self.reservations.clear();
        self.locked_chunk_ids.clear();
        self.object_shared_locks.clear();
        self.object_exclusive_locks.clear();
        self.reserved_bytes = 0;
        let mut resident: u64 = 0;
        for meta in self.chunks_by_id.values() {
            let charge = meta.resident_charge().ok_or_else(|| self.overflow_error())?;
            resident = resident.checked_add(charge).ok_or_else(|| self.overflow_error())?;
        }
        for tombstone in self.tombstones_by_object_id.values() {
            let charge =
                tombstone_resident_charge(tombstone).ok_or_else(|| self.overflow_error())?;
            resident = resident.checked_add(charge).ok_or_else(|| self.overflow_error())?;
        }
        if resident > max_bytes {
            return Err(RelayResidentBudgetExceeded {
                requested_charge: 0,
                resident_bytes: resident,
                max_bytes,
            });
        }
        self.resident_bytes = resident;
        Ok(())
    }

    #[must_use]
    fn overflow_error(&self) -> RelayResidentBudgetExceeded {
        RelayResidentBudgetExceeded {
            requested_charge: u64::MAX,
            resident_bytes: self.resident_bytes,
            max_bytes: self.max_bytes,
        }
    }

    #[must_use]
    fn budget_exceeded(&self, charge: u64) -> RelayResidentBudgetExceeded {
        RelayResidentBudgetExceeded {
            requested_charge: charge,
            resident_bytes: self.resident_bytes,
            max_bytes: self.max_bytes,
        }
    }

    /// Hard-bound admission of a positive `charge` into `reserved_bytes`: CHECKED arithmetic, and
    /// `resident_bytes + reserved_bytes + charge` must stay within `max_bytes`. Nothing is charged on
    /// failure.
    ///
    /// # Errors
    /// Returns [`RelayResidentBudgetExceeded`] on overflow or over-cap.
    fn admit_reserved(&mut self, charge: u64) -> Result<(), RelayResidentBudgetExceeded> {
        let projected = self
            .resident_bytes
            .checked_add(self.reserved_bytes)
            .and_then(|used| used.checked_add(charge))
            .ok_or_else(|| self.budget_exceeded(charge))?;
        if projected > self.max_bytes {
            return Err(self.budget_exceeded(charge));
        }
        self.reserved_bytes =
            self.reserved_bytes.checked_add(charge).ok_or_else(|| self.budget_exceeded(charge))?;
        Ok(())
    }

    /// The resident charge of an already-published chunk meta. Absent chunk → `0` (correct: nothing to
    /// replace). A present-but-uncomputable charge is an invariant violation for a RESIDENT meta and
    /// fails closed (it was admitted, so it must always be computable).
    ///
    /// # Errors
    /// Returns [`RelayResidentBudgetExceeded`] when a present meta's charge cannot be computed.
    fn existing_meta_charge(&self, chunk_id: &str) -> Result<u64, RelayResidentBudgetExceeded> {
        match self.chunks_by_id.get(chunk_id) {
            None => Ok(0),
            Some(meta) => meta.resident_charge().ok_or_else(|| self.overflow_error()),
        }
    }

    /// Allocates a fresh reservation id (CHECKED). Fails closed on the (impossible) `u64` exhaustion or
    /// on a collision with a still-live token — both are internal invariant violations.
    pub(crate) fn try_alloc_reservation_id(&mut self) -> Result<u64, RelayInternalInvariant> {
        let id = self.next_reservation_id;
        let next = id
            .checked_add(1)
            .ok_or(RelayInternalInvariant("relay reservation id space exhausted"))?;
        if self.reservations.contains_key(&id) {
            return Err(RelayInternalInvariant("relay reservation id collided with a live token"));
        }
        self.next_reservation_id = next;
        Ok(id)
    }

    /// Fail-stop wrapper for [`Self::try_alloc_reservation_id`] used on the reserve path. Exhaustion /
    /// collision are impossible; a hard stop is the correct response to the invariant violation.
    #[allow(clippy::expect_used)] // fail-stop on an impossible internal invariant
    fn alloc_reservation_id(&mut self) -> u64 {
        self.try_alloc_reservation_id().expect("relay reservation id allocation invariant violated")
    }

    #[must_use]
    pub(super) fn chunk_is_locked(&self, chunk_id: &str) -> bool {
        self.locked_chunk_ids.contains_key(chunk_id)
    }

    #[must_use]
    fn object_has_exclusive(&self, object_id: &str) -> bool {
        self.object_exclusive_locks.contains_key(object_id)
    }

    #[must_use]
    fn object_has_any_lock(&self, object_id: &str) -> bool {
        self.object_exclusive_locks.contains_key(object_id)
            || self.object_shared_locks.get(object_id).is_some_and(|ids| !ids.is_empty())
    }

    /// `true` when the chunk id is present in the resident index or exclusively locked in flight.
    #[must_use]
    pub fn contains_chunk(&self, chunk_id: &str) -> bool {
        self.chunks_by_id.contains_key(chunk_id) || self.locked_chunk_ids.contains_key(chunk_id)
    }

    /// Reserves a new PUT: exclusive chunk lock + shared object ref + full-meta charge admission.
    ///
    /// # Errors
    /// [`RelayStoreOpError::Conflict`] when the chunk id is locked or the object has an exclusive
    /// (tombstone/expiry) lock; [`RelayStoreOpError::Capacity`] when the budget would be exceeded.
    pub(crate) fn reserve_put(&mut self, meta: RelayChunkMeta) -> Result<u64, RelayStoreOpError> {
        if self.chunk_is_locked(&meta.chunk_id) || self.object_has_exclusive(&meta.object_id) {
            return Err(RelayStoreOpError::Conflict(
                "object relay put conflicts with an in-flight relay mutation".to_owned(),
            ));
        }
        let charge = meta.resident_charge().ok_or_else(|| {
            RelayStoreOpError::Capacity("object relay chunk meta charge overflow".to_owned())
        })?;
        self.admit_reserved(charge)?;
        let id = self.alloc_reservation_id();
        self.locked_chunk_ids.insert(meta.chunk_id.clone(), id);
        self.object_shared_locks.entry(meta.object_id.clone()).or_default().insert(id);
        self.reservations.insert(
            id,
            RelayReservation {
                chunk_ids: vec![meta.chunk_id.clone()],
                shared_objects: vec![meta.object_id.clone()],
                exclusive_objects: Vec::new(),
                reserved_charge: charge,
                resident_add: charge,
                resident_sub: 0,
                pending: RelayPendingMutation::Put(meta),
            },
        );
        Ok(id)
    }

    /// Reserves an ACK: exclusive chunk lock + shared object ref; admits the POSITIVE meta delta only
    /// (a negative delta is released after publish). The chunk must currently exist (no resurrection).
    ///
    /// # Errors
    /// [`RelayStoreOpError::NotAvailable`] when the chunk is gone; [`RelayStoreOpError::Conflict`] on
    /// an in-flight conflicting mutation; [`RelayStoreOpError::Capacity`] on budget overflow.
    pub(crate) fn reserve_ack(
        &mut self,
        updated: RelayChunkMeta,
    ) -> Result<u64, RelayStoreOpError> {
        let Some(existing) = self.chunks_by_id.get(&updated.chunk_id) else {
            return Err(RelayStoreOpError::NotAvailable);
        };
        if self.chunk_is_locked(&updated.chunk_id) || self.object_has_exclusive(&updated.object_id)
        {
            return Err(RelayStoreOpError::Conflict(
                "object relay ack conflicts with an in-flight relay mutation".to_owned(),
            ));
        }
        let old_charge = existing.resident_charge().ok_or_else(|| {
            RelayStoreOpError::Capacity("object relay chunk meta charge overflow".to_owned())
        })?;
        let new_charge = updated.resident_charge().ok_or_else(|| {
            RelayStoreOpError::Capacity("object relay chunk meta charge overflow".to_owned())
        })?;
        let positive_delta = new_charge.saturating_sub(old_charge);
        self.admit_reserved(positive_delta)?;
        let id = self.alloc_reservation_id();
        self.locked_chunk_ids.insert(updated.chunk_id.clone(), id);
        self.object_shared_locks.entry(updated.object_id.clone()).or_default().insert(id);
        self.reservations.insert(
            id,
            RelayReservation {
                chunk_ids: vec![updated.chunk_id.clone()],
                shared_objects: vec![updated.object_id.clone()],
                exclusive_objects: Vec::new(),
                reserved_charge: positive_delta,
                resident_add: new_charge,
                resident_sub: old_charge,
                pending: RelayPendingMutation::Ack(updated),
            },
        );
        Ok(id)
    }

    /// Reserves a TOMBSTONE: EXCLUSIVE object lock + exclusive locks on every affected chunk id.
    /// Requires the object to have NO pending PUT/ACK/tombstone and no affected chunk to be locked, so
    /// a concurrent PUT can never slip a chunk past the tombstone. Admits the tombstone charge plus the
    /// positive Σ(new-old) affected-meta delta in ONE checked admission (before any redb write).
    ///
    /// # Errors
    /// [`RelayStoreOpError::Conflict`] / [`RelayStoreOpError::Capacity`].
    pub(crate) fn reserve_tombstone(
        &mut self,
        mutation: ObjectRelayTombstoneMutation,
    ) -> Result<u64, RelayStoreOpError> {
        let object_id = mutation.tombstone.object_id.clone();
        if self.object_has_any_lock(&object_id) {
            return Err(RelayStoreOpError::Conflict(
                "object relay tombstone conflicts with an in-flight relay mutation".to_owned(),
            ));
        }
        for meta in &mutation.affected_chunks {
            if self.chunk_is_locked(&meta.chunk_id) {
                return Err(RelayStoreOpError::Conflict(
                    "object relay tombstone conflicts with an in-flight chunk mutation".to_owned(),
                ));
            }
        }
        let tombstone_charge = tombstone_resident_charge(&mutation.tombstone).ok_or_else(|| {
            RelayStoreOpError::Capacity("object relay tombstone charge overflow".to_owned())
        })?;
        let mut resident_add = tombstone_charge;
        let mut resident_sub: u64 = 0;
        for meta in &mutation.affected_chunks {
            let new_charge = meta.resident_charge().ok_or_else(|| {
                RelayStoreOpError::Capacity("object relay chunk meta charge overflow".to_owned())
            })?;
            // Absent chunk → 0; present-but-uncomputable → fail-closed Capacity (invariant violation).
            let old_charge = self.existing_meta_charge(&meta.chunk_id)?;
            resident_add = resident_add.checked_add(new_charge).ok_or_else(|| {
                RelayStoreOpError::Capacity("object relay tombstone charge overflow".to_owned())
            })?;
            resident_sub = resident_sub.checked_add(old_charge).ok_or_else(|| {
                RelayStoreOpError::Capacity("object relay tombstone charge overflow".to_owned())
            })?;
        }
        let positive_delta = resident_add.saturating_sub(resident_sub);
        self.admit_reserved(positive_delta)?;
        let id = self.alloc_reservation_id();
        self.object_exclusive_locks.insert(object_id.clone(), id);
        let mut chunk_ids = Vec::with_capacity(mutation.affected_chunks.len());
        for meta in &mutation.affected_chunks {
            self.locked_chunk_ids.insert(meta.chunk_id.clone(), id);
            chunk_ids.push(meta.chunk_id.clone());
        }
        self.reservations.insert(
            id,
            RelayReservation {
                chunk_ids,
                shared_objects: Vec::new(),
                exclusive_objects: vec![object_id],
                reserved_charge: positive_delta,
                resident_add,
                resident_sub,
                pending: RelayPendingMutation::Tombstone(Box::new(mutation)),
            },
        );
        Ok(id)
    }

    /// Reserves an EXPIRY: atomically locks (exclusive) every to-delete chunk id / tombstone object
    /// that is not already locked, SKIPPING any locked id (deferred to the next round) so a row being
    /// PUT/ACK/tombstoned is never deleted. Returns the reservation id and the filtered mutation of
    /// what is actually being deleted, or `None` when nothing is deletable.
    ///
    /// # Errors
    /// PRE-persist fail-closed: a RESIDENT meta/tombstone whose charge is uncomputable (it was
    /// admitted, so it must always compute) or whose release sum overflows is an invariant violation →
    /// [`RelayStoreOpError::Capacity`], zero mutation (nothing locked/reserved).
    pub(crate) fn reserve_expiry(
        &mut self,
        mutation: RelayExpiryMutation,
    ) -> Result<Option<(u64, RelayExpiryMutation)>, RelayStoreOpError> {
        let mut chunk_ids = Vec::new();
        let mut resident_sub: u64 = 0;
        for chunk_id in mutation.expired_chunk_ids {
            if self.chunk_is_locked(&chunk_id) {
                continue;
            }
            if let Some(meta) = self.chunks_by_id.get(&chunk_id) {
                // A RESIDENT meta's charge must be computable; the release sum is CHECKED. Both are
                // invariant violations if they fail → fail-closed Capacity (zero mutation).
                let charge = meta.resident_charge().ok_or_else(|| {
                    RelayStoreOpError::Capacity(
                        "resident chunk meta charge uncomputable".to_owned(),
                    )
                })?;
                resident_sub = resident_sub.checked_add(charge).ok_or_else(|| {
                    RelayStoreOpError::Capacity("relay expiry release sum overflow".to_owned())
                })?;
                chunk_ids.push(chunk_id);
            }
        }
        let mut object_ids = Vec::new();
        for object_id in mutation.expired_tombstone_object_ids {
            if self.object_has_any_lock(&object_id) {
                continue;
            }
            if let Some(tombstone) = self.tombstones_by_object_id.get(&object_id) {
                let charge = tombstone_resident_charge(tombstone).ok_or_else(|| {
                    RelayStoreOpError::Capacity("resident tombstone charge uncomputable".to_owned())
                })?;
                resident_sub = resident_sub.checked_add(charge).ok_or_else(|| {
                    RelayStoreOpError::Capacity("relay expiry release sum overflow".to_owned())
                })?;
                object_ids.push(object_id);
            }
        }
        if chunk_ids.is_empty() && object_ids.is_empty() {
            return Ok(None);
        }
        let id = self.alloc_reservation_id();
        for chunk_id in &chunk_ids {
            self.locked_chunk_ids.insert(chunk_id.clone(), id);
        }
        for object_id in &object_ids {
            self.object_exclusive_locks.insert(object_id.clone(), id);
        }
        let filtered = RelayExpiryMutation {
            expired_chunk_ids: chunk_ids.clone(),
            expired_tombstone_object_ids: object_ids.clone(),
        };
        self.reservations.insert(
            id,
            RelayReservation {
                chunk_ids,
                shared_objects: Vec::new(),
                exclusive_objects: object_ids,
                reserved_charge: 0,
                resident_add: 0,
                resident_sub,
                pending: RelayPendingMutation::Expiry(filtered.clone()),
            },
        );
        Ok(Some((id, filtered)))
    }

    fn release_reservation_locks(&mut self, id: u64, reservation: &RelayReservation) {
        for chunk_id in &reservation.chunk_ids {
            if self.locked_chunk_ids.get(chunk_id) == Some(&id) {
                self.locked_chunk_ids.remove(chunk_id);
            }
        }
        for object_id in &reservation.shared_objects {
            if let Some(ids) = self.object_shared_locks.get_mut(object_id) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.object_shared_locks.remove(object_id);
                }
            }
        }
        for object_id in &reservation.exclusive_objects {
            if self.object_exclusive_locks.get(object_id) == Some(&id) {
                self.object_exclusive_locks.remove(object_id);
            }
        }
    }

    /// Consumes an EXACT reservation token after its redb commit succeeded. This is POST-persist, so
    /// every branch is FAIL-STOP: a missing token, a `reserved_bytes` underflow, or a `resident_bytes`
    /// arithmetic failure are all impossible invariants (the RAII guard cancels only on the un-consumed
    /// paths, and every delta was admitted), and silently continuing after redb committed would split
    /// redb from the live index. The fallible core is [`Self::try_publish`]; a violation aborts.
    #[allow(clippy::expect_used)] // fail-stop: redb is already committed, no silent divergence
    pub(crate) fn publish(&mut self, id: u64) {
        self.try_publish(id).expect("relay publish invariant violated after redb commit");
    }

    /// Fallible core of [`Self::publish`]. All accounting is CHECKED; the new values are computed and
    /// validated BEFORE any state mutation, so a violation returns `Err` with the live index and budget
    /// untouched. Exposed for tests that assert the fail-stop paths without aborting the process.
    ///
    /// # Errors
    /// Returns [`RelayInternalInvariant`] on a missing token, `reserved_bytes` underflow, or
    /// `resident_bytes` arithmetic failure — all internal invariant violations that cannot occur on a
    /// live publish.
    pub(crate) fn try_publish(&mut self, id: u64) -> Result<(), RelayInternalInvariant> {
        let reservation = self
            .reservations
            .get(&id)
            .ok_or(RelayInternalInvariant("publish on a missing reservation token"))?;
        // `reserved_charge` was added by `admit_reserved`, so this can never underflow.
        let new_reserved = self
            .reserved_bytes
            .checked_sub(reservation.reserved_charge)
            .ok_or(RelayInternalInvariant("reserved_bytes underflow at publish"))?;
        // `resident_sub` is the exact old published charge (bounded by `resident_bytes`); adding
        // `resident_add` stays within the admitted budget.
        let new_resident = self
            .resident_bytes
            .checked_sub(reservation.resident_sub)
            .and_then(|resident| resident.checked_add(reservation.resident_add))
            .ok_or(RelayInternalInvariant("resident_bytes arithmetic failure at publish"))?;
        // All checks passed; now commit atomically (no partial state on the impossible error paths).
        let reservation = self
            .reservations
            .remove(&id)
            .ok_or(RelayInternalInvariant("publish on a missing reservation token"))?;
        self.release_reservation_locks(id, &reservation);
        self.reserved_bytes = new_reserved;
        self.resident_bytes = new_resident;
        match reservation.pending {
            RelayPendingMutation::Put(meta) | RelayPendingMutation::Ack(meta) => {
                self.chunks_by_id.insert(meta.chunk_id.clone(), meta);
            }
            RelayPendingMutation::Tombstone(mutation) => {
                for meta in &mutation.affected_chunks {
                    self.chunks_by_id.insert(meta.chunk_id.clone(), meta.clone());
                }
                self.tombstones_by_object_id
                    .insert(mutation.tombstone.object_id.clone(), mutation.tombstone.clone());
            }
            RelayPendingMutation::Expiry(mutation) => {
                for chunk_id in &mutation.expired_chunk_ids {
                    self.chunks_by_id.remove(chunk_id);
                }
                for object_id in &mutation.expired_tombstone_object_ids {
                    self.tombstones_by_object_id.remove(object_id);
                }
            }
        }
        Ok(())
    }

    /// Cancels a reservation (RAII rollback on persist failure/abort/unwind): releases the locks and
    /// the reserved headroom. Nothing was published, so `resident_bytes` is untouched. This is
    /// PRE-publish, but the `reserved_charge` was added by `admit_reserved`, so the checked subtraction
    /// can never underflow — an underflow would be an internal invariant violation → fail-stop.
    #[allow(clippy::expect_used)] // fail-stop on an impossible reserved_bytes underflow
    pub(crate) fn cancel_reservation(&mut self, id: u64) {
        if let Some(reservation) = self.reservations.remove(&id) {
            self.release_reservation_locks(id, &reservation);
            self.reserved_bytes = self
                .reserved_bytes
                .checked_sub(reservation.reserved_charge)
                .expect("relay reserved_bytes underflow at cancel");
        }
    }

    /// Test/seed helper: installs a chunk's metadata directly (dropping any payload) with a CHECKED,
    /// hard-bound budget admission. Fails closed if it would exceed `max_bytes`; there is no
    /// best-effort over-cap entry point.
    ///
    /// # Errors
    /// Returns [`RelayResidentBudgetExceeded`] when admitting the chunk would exceed the budget.
    #[allow(clippy::needless_pass_by_value)] // ergonomic owned-entry seed API
    pub fn put_chunk(&mut self, entry: RelayChunkEntry) -> Result<(), RelayResidentBudgetExceeded> {
        let meta = RelayChunkMeta::from(&entry);
        let new_charge = meta.resident_charge().ok_or_else(|| self.overflow_error())?;
        // Absent → 0; present-but-uncomputable → fail-closed (invariant violation).
        let previous = self.existing_meta_charge(&meta.chunk_id)?;
        let positive_delta = new_charge.saturating_sub(previous);
        let projected = self
            .resident_bytes
            .checked_add(self.reserved_bytes)
            .and_then(|used| used.checked_add(positive_delta))
            .ok_or_else(|| self.budget_exceeded(positive_delta))?;
        if projected > self.max_bytes {
            return Err(self.budget_exceeded(positive_delta));
        }
        self.resident_bytes = self
            .resident_bytes
            .checked_sub(previous)
            .and_then(|resident| resident.checked_add(new_charge))
            .ok_or_else(|| self.overflow_error())?;
        self.chunks_by_id.insert(meta.chunk_id.clone(), meta);
        Ok(())
    }

    /// Validates a v2 PUT frame and builds the candidate [`RelayChunkEntry`] (with clamped expiry).
    /// No state access. Shared by the pure state method and the persist-before-publish orchestration.
    ///
    /// # Errors
    /// Returns an error when token/permission/TTL/size/ciphertext-hash validation fails or the owner
    /// binding is missing.
    pub fn build_put_entry_from_frame(
        frame: ObjectChunkFrame,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkEntry, NodeCoreError> {
        validate_object_chunk_frame(&frame, relay_service_key, ObjectRelayCapability::Put, now)?;
        let owner_signing_key_id = frame.relay_token.owner_signing_key_id.clone();
        let owner_public_key = frame.relay_token.owner_public_key.clone();
        if owner_signing_key_id.is_empty() || owner_public_key.is_empty() {
            return Err(NodeCoreError::Unauthorized(
                "object relay put missing owner binding".to_owned(),
            ));
        }
        let expires_at = clamp_relay_chunk_expires_at(now, frame.expires_at);
        Ok(RelayChunkEntry {
            chunk_id: frame.chunk_id,
            object_id: frame.object_id,
            manifest_hash: frame.manifest_hash,
            chunk_index: frame.chunk_index,
            chunk_cipher_hash: frame.chunk_cipher_hash,
            owner_signing_key_id,
            owner_public_key,
            encrypted_chunk: frame.encrypted_chunk,
            stored_at: now,
            expires_at,
            delete_after_ack: frame.delete_after_ack,
            acked_by: BTreeSet::new(),
            status: RelayChunkStatus::Available,
        })
    }

    /// Metadata-level PUT plan: tombstone-block, owner-binding, cross-owner, content (via
    /// `chunk_cipher_hash`), and resurrect checks against the resident index. No mutation.
    pub(super) fn plan_put(
        &self,
        candidate: RelayChunkEntry,
    ) -> Result<RelayPutPlan, RelayStoreOpError> {
        if self.tombstones_by_object_id.contains_key(&candidate.object_id) {
            return Err(RelayStoreOpError::Tombstoned);
        }
        if candidate.owner_signing_key_id.is_empty() || candidate.owner_public_key.is_empty() {
            return Err(RelayStoreOpError::Unauthorized(
                "object relay put missing owner binding".to_owned(),
            ));
        }
        if let Some(existing) = self.chunks_by_id.get(&candidate.chunk_id) {
            if !existing.has_owner_binding()
                || existing.owner_signing_key_id != candidate.owner_signing_key_id
                || existing.owner_public_key != candidate.owner_public_key
            {
                return Err(RelayStoreOpError::Unauthorized(
                    "object relay put rejects cross-owner chunk overwrite".to_owned(),
                ));
            }
            if existing.object_id != candidate.object_id
                || existing.manifest_hash != candidate.manifest_hash
                || existing.chunk_index != candidate.chunk_index
                || existing.chunk_cipher_hash != candidate.chunk_cipher_hash
            {
                return Err(RelayStoreOpError::Unauthorized(
                    "object relay put rejects chunk content overwrite".to_owned(),
                ));
            }
            if existing.status != RelayChunkStatus::Available {
                return Err(RelayStoreOpError::Unauthorized(
                    "object relay put cannot resurrect a consumed chunk".to_owned(),
                ));
            }
            return Ok(RelayPutPlan::Existing { existing: existing.clone(), candidate });
        }
        Ok(RelayPutPlan::New(candidate))
    }

    /// # Errors
    /// Returns an error when token, object permission, TTL, tombstone, size or ciphertext hash
    /// validation fails, or the resident metadata budget is exceeded.
    ///
    /// Pure (store-free) PUT used by tests and as the validation authority. It publishes metadata
    /// only (no ciphertext is retained). Content-overwrite is compared by `chunk_cipher_hash`; the
    /// exact byte-identity check is enforced by the store read-through orchestration.
    pub fn put_object_chunk_frame(
        &mut self,
        frame: ObjectChunkFrame,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkMeta, NodeCoreError> {
        let candidate = Self::build_put_entry_from_frame(frame, relay_service_key, now)?;
        match self.plan_put(candidate).map_err(RelayStoreOpError::into_node_core)? {
            RelayPutPlan::Existing { existing, .. } => Ok(existing),
            RelayPutPlan::New(candidate) => {
                let meta = RelayChunkMeta::from(&candidate);
                let id =
                    self.reserve_put(meta.clone()).map_err(RelayStoreOpError::into_node_core)?;
                self.publish(id);
                Ok(meta)
            }
        }
    }

    /// # Errors
    /// Returns an error when token or permission validation fails, the chunk is missing, or it is
    /// expired/tombstoned.
    ///
    /// Validates a v2 GET and returns the resident metadata snapshot (payload-free). The ciphertext
    /// must be obtained through the store read-through path.
    pub fn get_object_chunk(
        &self,
        chunk_id: &str,
        token: &RelayToken,
        permission: &ObjectPermissionEnvelope,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkMeta, NodeCoreError> {
        validate_relay_token(token, relay_service_key, ObjectRelayCapability::Get, now)?;
        validate_object_permission(permission, ObjectRelayCapability::Get, now)?;
        if token.chunk_id != chunk_id
            || permission.object_id != token.object_id
            || permission.manifest_hash != token.manifest_hash
            || permission.grantee_device_hash != token.recipient_device_hash
            || !permission_owner_matches_token(permission, token)
        {
            return Err(NodeCoreError::ItestHttp("object relay get binding mismatch".to_owned()));
        }
        let meta = self
            .available_meta(chunk_id, now)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(chunk_id.to_owned()))?;
        // NOTE (RQ-03 follow-up / finding "C"): binding the retrieved chunk's original owner to the
        // requester requires an uploader-signed Get/Ack grant, deferred until that grant model lands.
        if self.tombstones_by_object_id.contains_key(&meta.object_id) {
            return Err(NodeCoreError::ItestHttp(
                "object relay tombstone blocks chunk get".to_owned(),
            ));
        }
        Ok(meta.clone())
    }

    /// Validates a v2 ACK and computes the updated metadata (payload handling is the store layer's
    /// job). No mutation.
    ///
    /// # Errors
    /// Returns an error when token/permission validation fails or the chunk is missing.
    pub fn plan_ack(
        &self,
        ack: &ObjectRelayAck,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkMeta, NodeCoreError> {
        validate_relay_token(&ack.relay_token, relay_service_key, ObjectRelayCapability::Ack, now)?;
        validate_object_permission(
            &ack.object_permission_envelope,
            ObjectRelayCapability::Ack,
            now,
        )?;
        if ack.relay_token.object_id != ack.object_id
            || ack.relay_token.manifest_hash != ack.manifest_hash
            || ack.relay_token.chunk_id != ack.chunk_id
            || ack.relay_token.recipient_device_hash != ack.recipient_device_hash
            || ack.object_permission_envelope.object_id != ack.object_id
            || ack.object_permission_envelope.manifest_hash != ack.manifest_hash
            || ack.object_permission_envelope.grantee_device_hash != ack.recipient_device_hash
            || !permission_owner_matches_token(&ack.object_permission_envelope, &ack.relay_token)
        {
            return Err(NodeCoreError::ItestHttp("object relay ack binding mismatch".to_owned()));
        }
        let existing = self
            .chunks_by_id
            .get(&ack.chunk_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.chunk_id.clone()))?;
        if existing.object_id != ack.object_id || existing.manifest_hash != ack.manifest_hash {
            return Err(NodeCoreError::ItestHttp("object relay ack binding mismatch".to_owned()));
        }
        let mut updated = existing.clone();
        updated.acked_by.insert(ack.recipient_device_hash.clone());
        // Deletion on ack is governed solely by the owner's stored delete policy, never the token.
        if updated.delete_after_ack {
            updated.status = RelayChunkStatus::AckedDeleted;
        }
        Ok(updated)
    }

    /// # Errors
    /// Returns an error when token/permission validation fails or the chunk is missing.
    ///
    /// Pure (store-free) ACK used by tests: reserve the positive meta delta (checked, hard bound),
    /// then publish. Returns the updated metadata (payload-free).
    #[allow(clippy::needless_pass_by_value)] // mirrors the wire ACK ownership for test ergonomics
    pub fn ack_object_chunk(
        &mut self,
        ack: ObjectRelayAck,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkMeta, NodeCoreError> {
        let updated = self.plan_ack(&ack, relay_service_key, now)?;
        let id = self.reserve_ack(updated.clone()).map_err(RelayStoreOpError::into_node_core)?;
        self.publish(id);
        Ok(updated)
    }

    /// # Errors
    /// Returns an error when token/permission validation fails.
    pub fn apply_object_tombstone(
        &mut self,
        tombstone: ObjectRelayTombstone,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<ObjectRelayTombstone, NodeCoreError> {
        Ok(self.apply_object_tombstone_mutation(tombstone, relay_service_key, now)?.tombstone)
    }

    /// # Errors
    /// Returns an error when token/permission validation fails.
    ///
    /// Pure (store-free) v2 tombstone used by tests: plan, then reserve (exclusive object + affected
    /// chunk locks, one checked admission) and publish.
    pub fn apply_object_tombstone_mutation(
        &mut self,
        tombstone: ObjectRelayTombstone,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        let mutation = self.plan_object_tombstone_mutation(tombstone, relay_service_key, now)?;
        if mutation.changed {
            let id = self
                .reserve_tombstone(mutation.clone())
                .map_err(RelayStoreOpError::into_node_core)?;
            self.publish(id);
        }
        Ok(mutation)
    }

    /// Validates and computes a v2 tombstone mutation WITHOUT mutating state (persist-before-publish
    /// plan phase). The affected chunk metas are returned already marked `Tombstoned` (payload
    /// cleared by construction).
    ///
    /// # Errors
    /// Returns an error when token/permission validation fails or the shared core rejects it.
    pub fn plan_object_tombstone_mutation(
        &self,
        tombstone: ObjectRelayTombstone,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        validate_relay_token(
            &tombstone.relay_token,
            relay_service_key,
            ObjectRelayCapability::Tombstone,
            now,
        )?;
        validate_object_permission(
            &tombstone.object_permission_envelope,
            ObjectRelayCapability::Tombstone,
            now,
        )?;
        if tombstone.relay_token.object_id != tombstone.object_id
            || tombstone
                .manifest_hash
                .as_ref()
                .is_some_and(|manifest_hash| &tombstone.relay_token.manifest_hash != manifest_hash)
            || tombstone.object_permission_envelope.object_id != tombstone.object_id
            || tombstone.manifest_hash.as_ref().is_some_and(|manifest_hash| {
                &tombstone.object_permission_envelope.manifest_hash != manifest_hash
            })
            || !permission_owner_matches_token(
                &tombstone.object_permission_envelope,
                &tombstone.relay_token,
            )
        {
            return Err(NodeCoreError::ItestHttp(
                "object relay tombstone binding mismatch".to_owned(),
            ));
        }
        self.plan_object_tombstone_record(tombstone, now)
    }

    /// Post-validation tombstone plan core shared by the v2 and v3 owner-session paths. `retained`
    /// must already carry the verified owner identity. Computes (but does not apply) the mutation:
    /// fail-closed TTL, idempotent-replay (zero mutation), cross-owner scope, empty-scope, and
    /// tombstone-wins (affected chunk metas marked `Tombstoned`).
    fn plan_object_tombstone_record(
        &self,
        retained: ObjectRelayTombstone,
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        if retained.expires_at <= now
            || retained.expires_at > now.saturating_add(OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS)
        {
            return Err(NodeCoreError::TtlExpired { envelope_id: retained.object_id.clone() });
        }
        if let Some(existing) = self.tombstones_by_object_id.get(&retained.object_id) {
            if existing_tombstone_matches_replay(existing, &retained) {
                return Ok(ObjectRelayTombstoneMutation {
                    tombstone: existing.clone(),
                    affected_chunks: Vec::new(),
                    changed: false,
                });
            }
            return Err(NodeCoreError::Unauthorized(
                "object relay tombstone conflicts with existing record".to_owned(),
            ));
        }
        let matches_scope = |chunk: &RelayChunkMeta| {
            chunk.object_id == retained.object_id
                && retained
                    .manifest_hash
                    .as_ref()
                    .is_none_or(|manifest| manifest == &chunk.manifest_hash)
        };
        if self
            .chunks_by_id
            .values()
            .any(|chunk| matches_scope(chunk) && !chunk.owner_matches_token(&retained.relay_token))
        {
            return Err(NodeCoreError::Unauthorized(
                "object relay tombstone owner binding mismatch".to_owned(),
            ));
        }
        let mut affected_chunks = Vec::new();
        for chunk in self.chunks_by_id.values() {
            if matches_scope(chunk) {
                let mut marked = chunk.clone();
                marked.status = RelayChunkStatus::Tombstoned;
                affected_chunks.push(marked);
            }
        }
        if affected_chunks.is_empty() {
            return Err(NodeCoreError::Unauthorized(
                "object relay tombstone matches no owned chunk".to_owned(),
            ));
        }
        Ok(ObjectRelayTombstoneMutation { tombstone: retained, affected_chunks, changed: true })
    }

    /// # Errors
    /// Returns an error when the owner binding is missing, or when the shared core rejects it.
    ///
    /// Pure (store-free) v3 owner-session tombstone used by tests: plan, then reserve and publish.
    pub fn apply_owner_session_tombstone(
        &mut self,
        request: OwnerSessionTombstoneRequest,
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        let mutation = self.plan_owner_session_tombstone(request, now)?;
        if mutation.changed {
            let id = self
                .reserve_tombstone(mutation.clone())
                .map_err(RelayStoreOpError::into_node_core)?;
            self.publish(id);
        }
        Ok(mutation)
    }

    /// Validates and computes a v3 owner-session tombstone mutation WITHOUT mutating state.
    ///
    /// # Errors
    /// Returns an error when the owner binding is missing, or when the shared core rejects it.
    pub fn plan_owner_session_tombstone(
        &self,
        request: OwnerSessionTombstoneRequest,
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        if request.owner_signing_key_id.is_empty() || request.owner_public_key.is_empty() {
            return Err(NodeCoreError::Unauthorized(
                "owner-session tombstone missing owner binding".to_owned(),
            ));
        }
        let relay_token = RelayToken {
            token_version: OBJECT_RELAY_TOKEN_VERSION,
            token_id: String::new(),
            object_id: request.object_id.clone(),
            manifest_hash: request.manifest_hash.clone().unwrap_or_default(),
            chunk_id: String::new(),
            recipient_device_hash: String::new(),
            owner_signing_key_id: request.owner_signing_key_id.clone(),
            owner_public_key: request.owner_public_key.clone(),
            issuer_service: String::new(),
            audience_service: String::new(),
            capabilities: vec![ObjectRelayCapability::Tombstone],
            delete_after_ack: false,
            issued_at: request.signed_at,
            expires_at: request.expires_at,
            nonce: String::new(),
            mac: String::new(),
        };
        let object_permission_envelope = ObjectPermissionEnvelope {
            object_id: request.object_id.clone(),
            manifest_hash: request.manifest_hash.clone().unwrap_or_default(),
            grantee_device_hash: String::new(),
            capability: ObjectRelayCapability::Tombstone,
            issued_at: request.signed_at,
            expires_at: request.expires_at,
            owner_signing_key_id: request.owner_signing_key_id.clone(),
            owner_public_key: request.owner_public_key.clone(),
            owner_signature: String::new(),
        };
        let retained = ObjectRelayTombstone {
            object_id: request.object_id,
            manifest_hash: request.manifest_hash,
            tombstone_hash: request.tombstone_hash,
            source_event_id: request.source_event_id,
            signed_at: request.signed_at,
            expires_at: request.expires_at,
            relay_token,
            object_permission_envelope,
        };
        self.plan_object_tombstone_record(retained, now)
    }

    /// Returns the resident metadata of an available (not expired, `Available` status) chunk.
    #[must_use]
    pub fn available_meta(&self, chunk_id: &str, now: u64) -> Option<&RelayChunkMeta> {
        self.chunks_by_id
            .get(chunk_id)
            .filter(|meta| meta.status == RelayChunkStatus::Available && meta.expires_at > now)
    }

    /// Compatibility accessor: the resident metadata of an available chunk (payload-free).
    #[must_use]
    pub fn get_available_chunk(&self, chunk_id: &str, now: u64) -> Option<&RelayChunkMeta> {
        self.available_meta(chunk_id, now)
    }

    /// Returns the resident metadata for a chunk id regardless of status (payload-free).
    #[must_use]
    pub fn chunk_meta(&self, chunk_id: &str) -> Option<&RelayChunkMeta> {
        self.chunks_by_id.get(chunk_id)
    }

    /// Compatibility accessor for [`Self::chunk_meta`].
    #[must_use]
    pub fn chunk_entry(&self, chunk_id: &str) -> Option<&RelayChunkMeta> {
        self.chunks_by_id.get(chunk_id)
    }

    pub fn expire_chunks(&mut self, now: u64) -> usize {
        self.expire_chunks_mutation(now).expired_count()
    }

    /// Compatibility helper: plans expiry, reserves (locking the to-delete ids, skipping any locked),
    /// and publishes the removal (pure, store-free). Returns the mutation actually applied.
    pub fn expire_chunks_mutation(&mut self, now: u64) -> RelayExpiryMutation {
        let planned = self.plan_expiry(now);
        // Fail-closed: an uncomputable resident charge (invariant violation) defers deletion this
        // round rather than mutating; nothing is expired.
        match self.reserve_expiry(planned) {
            Ok(Some((id, applied))) => {
                self.publish(id);
                applied
            }
            Ok(None) | Err(_) => RelayExpiryMutation::default(),
        }
    }

    /// Computes (without applying) the set of chunk ids and tombstone object ids that have expired.
    #[must_use]
    pub fn plan_expiry(&self, now: u64) -> RelayExpiryMutation {
        let expired_chunk_ids = self
            .chunks_by_id
            .iter()
            .filter(|(_id, meta)| meta.expires_at <= now)
            .map(|(id, _meta)| id.clone())
            .collect();
        let expired_tombstone_object_ids = self
            .tombstones_by_object_id
            .iter()
            .filter(|(_id, tombstone)| tombstone.expires_at <= now)
            .map(|(id, _tombstone)| id.clone())
            .collect();
        RelayExpiryMutation { expired_chunk_ids, expired_tombstone_object_ids }
    }

    #[must_use]
    pub fn available_count(&self, now: u64) -> usize {
        self.chunks_by_id
            .values()
            .filter(|meta| meta.status == RelayChunkStatus::Available && meta.expires_at > now)
            .count()
    }

    #[must_use]
    pub fn tombstone(&self, object_id: &str) -> Option<&ObjectRelayTombstone> {
        self.tombstones_by_object_id.get(object_id)
    }
}
#[cfg(test)]
#[path = "tests/cache.rs"]
mod tests;
