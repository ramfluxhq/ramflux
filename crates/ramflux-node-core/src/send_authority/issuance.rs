// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Non-exportable wake eligibility, original monotonic budgets and local publication.

use super::{
    Arc, AuthorityCallState, AuthorityMutation, AuthorityPhase, AuthorityPin, AuthorityRecord,
    AuthorityScope, BTreeMap, CLOCK, MAX_MIRROR_BYTES, MAX_MIRRORS, MAX_SCOPE_BYTES, Mirror,
    NodeCoreError, ROWS, ReadableTable, SendAuthorityError, SendAuthorityStore, charge_scope,
    encode, read_scope, reservation, rpc, same_operation, storage,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) struct WakeMirror {
    digest: String,
    target: String,
    owner_epoch: u64,
    start: Option<String>,
    expiry: u64,
    monotonic: Instant,
    wanted: bool,
    claimed: bool,
}

#[derive(Default)]
pub(super) struct GateState {
    pub(super) scopes: BTreeMap<String, Mirror>,
    pub(super) wakes: BTreeMap<String, WakeMirror>,
    pub(super) loading: BTreeMap<String, String>,
    pub(super) utc_floor: u128,
    pub(super) voip_enabled: bool,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) test_clock: Option<(Option<u128>, Duration)>,
}
impl std::ops::Deref for GateState {
    type Target = BTreeMap<String, Mirror>;
    fn deref(&self) -> &Self::Target {
        &self.scopes
    }
}
impl std::ops::DerefMut for GateState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.scopes
    }
}

fn utc() -> Result<u128, SendAuthorityError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).map_err(storage)
}

/// Prepared identities are data; only the guarded handoff can grant one actual issuance.
#[derive(Clone, Copy)]
pub struct WakeIssuance<'a> {
    pub wake_id: &'a str,
    pub digest: &'a str,
    pub start: Option<&'a str>,
    pub target: &'a str,
    pub credential: &'a str,
    pub pins: &'a [AuthorityPin],
    pub valid_until: u64,
    pub voip: bool,
}

#[derive(Clone, Copy)]
pub struct WakeAdmission<'a> {
    pub wake_id: &'a str,
    pub digest: &'a str,
    pub target: &'a str,
    pub owner_epoch: u64,
    pub start: Option<&'a str>,
    pub expiry: u64,
}

/// Bounded preparation capacity only; this guard carries no sending authority.
pub struct ProviderPreparation {
    count: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for ProviderPreparation {
    fn drop(&mut self) {
        self.count.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn sample_clock(gate: &GateState) -> Result<(u128, Instant), SendAuthorityError> {
    let monotonic = Instant::now();
    #[cfg(any(test, feature = "test-support"))]
    if let Some((sample, advance)) = gate.test_clock {
        return Ok((
            sample.map_or_else(utc, Ok)?,
            monotonic.checked_add(advance).ok_or(SendAuthorityError::Invalid)?,
        ));
    }
    let _ = gate;
    Ok((utc()?, monotonic))
}

#[derive(Clone, Copy)]
pub(crate) struct WakeClock {
    utc: u128,
    monotonic: Instant,
    rollback: bool,
}

impl SendAuthorityStore {
    pub(crate) fn capture_wake_clock(&self) -> Result<WakeClock, SendAuthorityError> {
        let first_utc = utc()?;
        let first_monotonic = Instant::now();
        let mut gate = self.gate.lock().map_err(storage)?;
        let (utc, monotonic) = sample_clock(&gate)?;
        let rollback = utc < gate.utc_floor;
        let anchors = (first_utc.max(gate.utc_floor), first_monotonic);
        #[cfg(any(test, feature = "test-support"))]
        let anchors =
            if gate.test_clock.is_some() { (utc.max(gate.utc_floor), monotonic) } else { anchors };
        let _ = monotonic;
        gate.utc_floor = gate.utc_floor.max(utc);
        Ok(WakeClock { utc: anchors.0, monotonic: anchors.1, rollback })
    }

    pub(crate) fn retention_clock(&self, now: u64) -> Result<u64, SendAuthorityError> {
        let seconds = {
            let mut gate = self.gate.lock().map_err(storage)?;
            gate.utc_floor = gate.utc_floor.max(u128::from(now) * 1_000_000_000);
            let seconds = u64::try_from(gate.utc_floor / 1_000_000_000).map_err(storage)?;
            gate.wakes.retain(|_, row| row.expiry > seconds);
            seconds
        };
        let tx = self.db.begin_write().map_err(storage)?;
        self.persist_clock(&tx).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(seconds)
    }

    pub(crate) fn current_boot_call(
        &self,
        digest: &str,
    ) -> Result<AuthorityRecord, SendAuthorityError> {
        let scope = AuthorityScope::Call { start_digest: digest.into() };
        let row = self.load(&scope.key()?)?.ok_or(SendAuthorityError::Closed)?;
        if row.admitted_boot != self.boot
            || row.mutation.notify_boot != self.boot
            || row.mutation.phase != AuthorityPhase::Stable
        {
            return Err(SendAuthorityError::Closed);
        }
        Ok(row.desired)
    }

    pub(crate) fn discard_unfunded_wake(&self, id: &str) -> Result<(), SendAuthorityError> {
        let mut gate = self.gate.lock().map_err(storage)?;
        if gate.wakes.get(id).is_some_and(|row| !row.claimed && !row.wanted) {
            gate.wakes.remove(id);
        }
        Ok(())
    }
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn gate_is_held_for_test(&self) -> bool {
        matches!(self.gate.try_lock(), Err(std::sync::TryLockError::WouldBlock))
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Install a fixture-scoped clock sample without changing the original admitted budget.
    /// # Errors
    /// A poisoned gate refuses fixture clock changes.
    pub fn set_test_clock(
        &self,
        utc_nanoseconds: Option<u128>,
        monotonic_advance: Duration,
    ) -> Result<(), SendAuthorityError> {
        self.gate.lock().map_err(storage)?.test_clock = Some((utc_nanoseconds, monotonic_advance));
        Ok(())
    }

    /// # Errors
    /// Refuses a 129th preparation before OAuth, network setup or authority lookup.
    pub fn reserve_preparation(&self) -> Result<ProviderPreparation, SendAuthorityError> {
        self.preparations
            .try_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |count| if count < 128 { count.checked_add(1) } else { None },
            )
            .map_err(|_| SendAuthorityError::Busy)?;
        Ok(ProviderPreparation { count: Arc::clone(&self.preparations) })
    }

    /// # Errors
    /// A poisoned gate refuses policy acknowledgement.
    pub fn set_voip_enabled(&self, enabled: bool) -> Result<(), SendAuthorityError> {
        self.gate.lock().map_err(storage)?.voip_enabled = enabled;
        Ok(())
    }

    #[must_use]
    pub fn voip_enabled(&self) -> bool {
        self.gate.lock().is_ok_and(|gate| gate.voip_enabled)
    }

    /// Persist the sampled floor outside `SendGate` in the caller's existing transaction.
    /// # Errors
    /// Clock overflow or a durability error refuses publication.
    pub fn persist_clock(&self, tx: &redb::WriteTransaction) -> Result<(), SendAuthorityError> {
        let floor = {
            let gate = self.gate.lock().map_err(storage)?;
            u64::try_from(gate.utc_floor).map_err(storage)?
        };
        let mut table = tx.open_table(CLOCK).map_err(storage)?;
        let prior = table.get("utc_nanoseconds").map_err(storage)?.map_or(0, |v| v.value());
        table.insert("utc_nanoseconds", floor.max(prior)).map_err(storage)?;
        Ok(())
    }

    /// Retain the original budget at first verified admission, before any slow durable work.
    /// # Errors
    /// Refuses changed wake mappings, expired admission or exhausted bounded memory.
    pub fn admit_wake(&self, admission: WakeAdmission<'_>) -> Result<u64, SendAuthorityError> {
        self.admit_wake_at(admission, self.capture_wake_clock()?)
    }

    pub(crate) fn admit_wake_at(
        &self,
        admission: WakeAdmission<'_>,
        clock: WakeClock,
    ) -> Result<u64, SendAuthorityError> {
        let WakeAdmission { wake_id, digest, target, owner_epoch, start, expiry } = admission;
        let mut gate = self.gate.lock().map_err(storage)?;
        if let Some(row) = gate.wakes.get(wake_id) {
            if !(row.digest == digest
                && row.target == target
                && row.owner_epoch == owner_epoch
                && row.start.as_deref() == start)
            {
                return Err(SendAuthorityError::Conflict);
            }
            if clock.monotonic >= row.monotonic
                || gate.utc_floor.max(clock.utc) >= u128::from(row.expiry) * 1_000_000_000
                || (clock.rollback && start.is_some())
            {
                return Err(SendAuthorityError::Closed);
            }
            return Ok(row.expiry);
        }
        let WakeClock { utc: sample, monotonic: admitted_monotonic, rollback } = clock;
        let prior = start
            .and_then(|start| gate.wakes.values().find(|row| row.start.as_deref() == Some(start)));
        if prior.is_some_and(|row| {
            row.target != target
                || row.owner_epoch != owner_epoch
                || row.monotonic <= admitted_monotonic
        }) {
            return Err(SendAuthorityError::Closed);
        }
        let retained = prior.map(|row| (row.expiry, row.monotonic));
        let expiry = retained.map_or(expiry, |(old, _)| expiry.min(old));
        let expiry_ns = u128::from(expiry) * 1_000_000_000;
        if expiry_ns <= gate.utc_floor || (start.is_some() && rollback) {
            return Err(SendAuthorityError::Closed);
        }
        let due = gate
            .wakes
            .iter()
            .filter(|(_, row)| {
                row.expiry <= u64::try_from(gate.utc_floor / 1_000_000_000).unwrap_or(u64::MAX)
            })
            .take(128)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in due {
            gate.wakes.remove(&key);
        }
        cache_room(
            &mut gate,
            "",
            wake_id.len() + digest.len() + target.len() + start.map_or(0, str::len) + 80,
        )?;
        let budget = u64::try_from(expiry_ns - sample).map_err(storage)?;
        let monotonic = admitted_monotonic
            .checked_add(Duration::from_nanos(budget))
            .ok_or(SendAuthorityError::Invalid)?;
        let monotonic = retained.map_or(monotonic, |(_, old)| old.min(monotonic));
        gate.wakes.insert(
            wake_id.into(),
            WakeMirror {
                digest: digest.into(),
                target: target.into(),
                owner_epoch,
                start: start.map(str::to_owned),
                expiry,
                monotonic,
                wanted: false,
                claimed: false,
            },
        );
        Ok(expiry)
    }

    /// The original budget is data, not permission to issue or refresh it.
    /// # Errors
    /// Missing/terminal/pre-boot call memory and elapsed budgets refuse before slow work.
    pub fn wake_deadline(
        &self,
        wake_id: &str,
        digest: &str,
    ) -> Result<Instant, SendAuthorityError> {
        let gate = self.gate.lock().map_err(storage)?;
        let row = gate.wakes.get(wake_id).ok_or(SendAuthorityError::Closed)?;
        if row.digest != digest {
            return Err(SendAuthorityError::Conflict);
        }
        let (sample, now) = sample_clock(&gate)?;
        if now >= row.monotonic
            || gate.utc_floor.max(sample) >= u128::from(row.expiry) * 1_000_000_000
            || (row.start.is_some() && sample < gate.utc_floor)
        {
            return Err(SendAuthorityError::Closed);
        }
        Ok(row.monotonic)
    }

    pub(crate) fn wake_target(&self, wake_id: &str) -> Result<Option<String>, SendAuthorityError> {
        Ok(self.gate.lock().map_err(storage)?.wakes.get(wake_id).map(|row| row.target.clone()))
    }

    /// A failed/uncertain claim stays closed; cancellation cannot be undone by a late ACK.
    /// # Errors
    /// Returns missing-memory or storage errors without reminting a call budget.
    pub fn commit_wake_claim(
        &self,
        wake_id: &str,
        digest: &str,
        terminal: bool,
    ) -> Result<(), SendAuthorityError> {
        let mut gate = self.gate.lock().map_err(storage)?;
        let row = gate.wakes.get_mut(wake_id).ok_or(SendAuthorityError::Closed)?;
        if row.digest != digest {
            return Err(SendAuthorityError::Conflict);
        }
        if terminal {
            row.wanted = false;
            row.claimed = true;
        } else if !row.claimed {
            row.wanted = true;
        }
        Ok(())
    }

    /// Close under the same exclusive gate as the synchronous header/body handoff.
    /// # Errors
    /// A poisoned gate refuses mutation acknowledgement.
    pub fn close_wake(&self, wake_id: &str) -> Result<(), SendAuthorityError> {
        let mut gate = self.gate.lock().map_err(storage)?;
        if let Some(row) = gate.wakes.get_mut(wake_id) {
            row.wanted = false;
            row.claimed = true;
        }
        Ok(())
    }

    /// Mark the already durable attempt reservation eligible for its bounded retry loop.
    /// # Errors
    /// Refuses terminal or absent wake memory, including all pre-boot calls.
    pub fn claim_attempt(&self, wake_id: &str) -> Result<(), SendAuthorityError> {
        let mut gate = self.gate.lock().map_err(storage)?;
        let row = gate.wakes.get_mut(wake_id).ok_or(SendAuthorityError::Closed)?;
        if !row.wanted {
            return Err(SendAuthorityError::Closed);
        }
        row.claimed = true;
        Ok(())
    }

    /// Snapshot a committed mirror; the final handoff compares this complete pin again.
    /// # Errors
    /// Absent/closed mirrors confer no authority.
    pub fn pin(&self, scope: &AuthorityScope) -> Result<AuthorityPin, SendAuthorityError> {
        let key = scope.key()?;
        let nonce = rpc::random_id().map_err(storage)?;
        {
            let mut gate = self.gate.lock().map_err(storage)?;
            if let Some(row) = gate.get(&key) {
                return mirror_pin(scope, row, &self.boot);
            }
            if gate.loading.contains_key(&key) {
                return Err(SendAuthorityError::Busy);
            }
            cache_room(&mut gate, &key, MAX_SCOPE_BYTES)?;
            gate.loading.insert(key.clone(), nonce.clone());
        }
        let loaded = self.load(&key);
        let mut gate = self.gate.lock().map_err(storage)?;
        if gate.loading.get(&key) != Some(&nonce) {
            return Err(SendAuthorityError::Conflict);
        }
        gate.loading.remove(&key);
        let row = loaded?.ok_or(SendAuthorityError::Closed)?;
        if row.mutation.notify_boot != self.boot || row.mutation.phase != AuthorityPhase::Stable {
            return Err(SendAuthorityError::Closed);
        }
        let encoded_bytes = encode(&row)?.len();
        cache_room(&mut gate, &key, encoded_bytes)?;
        gate.insert(key.clone(), Mirror { scope: row, open: true, retiring: false, encoded_bytes });
        mirror_pin(scope, gate.get(&key).ok_or(SendAuthorityError::Closed)?, &self.boot)
    }

    /// Resume the exact saved encrypted delta before accepting a distinct local mutation.
    /// # Errors
    /// Missing receipt/history, failed persistence and stale completions stay closed.
    pub fn resume_local(
        &self,
        scope: &AuthorityScope,
        apply: impl FnOnce(&redb::WriteTransaction, &AuthorityRecord) -> Result<(), NodeCoreError>,
    ) -> Result<(), NodeCoreError> {
        let Some(pending) = self.load(&scope.key()?)? else { return Ok(()) };
        if !matches!(pending.desired, AuthorityRecord::LocalRows { .. }) {
            return Err(SendAuthorityError::Invalid.into());
        }
        if pending.mutation.phase == AuthorityPhase::Stable
            && pending.mutation.notify_boot == self.boot
        {
            return Ok(());
        }
        let identity = self.local_identity.lock().map_err(storage)?.clone();
        reservation::require_owner(
            &self.db,
            &identity,
            &pending.mutation.reservation_id,
            pending.mutation.reservation_generation,
        )?;
        let observed = self.state(scope)?;
        let mut mutation = pending.mutation;
        let resync = mutation.notify_boot != self.boot;
        if resync {
            if mutation.phase == AuthorityPhase::Stable {
                mutation.operation_id = rpc::random_id()?;
            }
            mutation.expected_generation = observed.generation;
            mutation.generation =
                observed.generation.checked_add(1).ok_or(SendAuthorityError::Invalid)?;
            mutation.notify_boot.clone_from(&self.boot);
            mutation.result = None;
        }
        let prior_phase = mutation.phase;
        mutation.phase = AuthorityPhase::Closing;
        self.fence(scope, &mutation, pending.desired.clone(), &observed, resync)?;
        if resync || prior_phase == AuthorityPhase::Closing {
            let tx = self.db.begin_write().map_err(storage)?;
            let mut table = tx.open_table(ROWS).map_err(storage)?;
            let mut row = read_scope(&table, &scope.key()?)?.ok_or(SendAuthorityError::Closed)?;
            if !same_operation(&row.mutation, &mutation) {
                return Err(SendAuthorityError::Conflict.into());
            }
            apply(&tx, &pending.desired)?;
            row.mutation.phase = AuthorityPhase::Committed;
            charge_scope(&tx, &scope.key()?, &row, encode(&row)?.len())?;
            table.insert(scope.key()?.as_str(), encode(&row)?.as_slice()).map_err(storage)?;
            drop(table);
            self.persist_clock(&tx)?;
            tx.commit().map_err(storage)?;
        }
        mutation.phase = AuthorityPhase::Committed;
        self.publish(scope, &mutation, &pending.desired)?;
        Ok(())
    }

    /// Publish local encrypted row changes with the same operation-owned fence/CAS as RPCs.
    /// # Errors
    /// Any failed persistence or stale completion leaves this scope closed.
    pub fn local_change<T>(
        &self,
        scope: &AuthorityScope,
        record: &AuthorityRecord,
        apply: impl FnOnce(&redb::WriteTransaction) -> Result<T, NodeCoreError>,
    ) -> Result<T, NodeCoreError> {
        let root = match scope {
            AuthorityScope::TargetRoutes { target_delivery_id } => {
                ramflux_protocol::parse_qualified_device_id(target_delivery_id)
                    .map_err(storage)?
                    .map_or_else(reservation::system_root, |(root, _)| root)
            }
            AuthorityScope::Credential { .. } => reservation::system_root(),
            _ => return Err(SendAuthorityError::Invalid.into()),
        };
        let receipt = self.ensure_local_root(&root)?;
        let observed = self.state(scope)?;
        let id = rpc::random_id()?;
        let mutation = AuthorityMutation {
            version: 1,
            operation_id: id.clone(),
            reservation_id: receipt.reservation_id.ok_or(SendAuthorityError::Closed)?,
            reservation_generation: receipt
                .reservation_generation
                .ok_or(SendAuthorityError::Closed)?,
            origin_incarnation: receipt.origin_incarnation,
            expected_generation: observed.generation,
            generation: observed.generation.checked_add(1).ok_or(SendAuthorityError::Invalid)?,
            notify_boot: self.boot.clone(),
            desired_record_hash: record.record_hash()?,
            phase: AuthorityPhase::Closing,
            result: None,
        };
        self.fence(scope, &mutation, record.clone(), &observed, false)?;
        let tx = self.db.begin_write().map_err(storage)?;
        let result = apply(&tx)?;
        let mut committed = mutation;
        committed.phase = AuthorityPhase::Committed;
        {
            let mut table = tx.open_table(ROWS).map_err(storage)?;
            let mut row = read_scope(&table, &scope.key()?)?.ok_or(SendAuthorityError::Closed)?;
            if !same_operation(&row.mutation, &committed) {
                return Err(SendAuthorityError::Conflict.into());
            }
            row.mutation.phase = AuthorityPhase::Committed;
            charge_scope(&tx, &scope.key()?, &row, encode(&row)?.len())?;
            table.insert(scope.key()?.as_str(), encode(&row)?.as_slice()).map_err(storage)?;
        }
        self.persist_clock(&tx)?;
        tx.commit().map_err(storage)?;
        self.publish(scope, &committed, record)?;
        Ok(result)
    }

    /// Final validation and the complete synchronous H2 issue are one indivisible operation.
    /// # Errors
    /// Refuses stale pins, changed mappings, cancellation, rollback and either original deadline.
    pub fn with_send_permit<T>(
        &self,
        prepared: WakeIssuance<'_>,
        issue: impl FnOnce() -> Result<T, NodeCoreError>,
    ) -> Result<T, NodeCoreError> {
        let WakeIssuance { wake_id, digest, start, target, credential, pins, valid_until, voip } =
            prepared;
        let mut expected = vec![
            AuthorityScope::Owner { target_delivery_id: target.into() },
            AuthorityScope::TargetRoutes { target_delivery_id: target.into() },
            AuthorityScope::Credential { credential_id: credential.into() },
        ];
        if let Some(start) = start {
            expected.push(AuthorityScope::Call { start_digest: start.into() });
        }
        if pins.len() != expected.len()
            || expected
                .iter()
                .any(|scope| pins.iter().filter(|pin| &pin.scope == scope).count() != 1)
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        let keys = pins.iter().map(|pin| pin.scope.key()).collect::<Result<Vec<_>, _>>()?;
        let mut gate = self.gate.lock().map_err(storage)?;
        let (sample, monotonic_now) = sample_clock(&gate)?;
        let rollback = sample < gate.utc_floor;
        gate.utc_floor = gate.utc_floor.max(sample);
        let row = gate.wakes.get(wake_id).ok_or(SendAuthorityError::Closed)?;
        if (voip && !gate.voip_enabled)
            || !row.wanted
            || !row.claimed
            || row.digest != digest
            || row.target != target
            || row.start.as_deref() != start
            || gate.utc_floor >= u128::from(row.expiry.min(valid_until)) * 1_000_000_000
            || (start.is_some() && (rollback || monotonic_now >= row.monotonic))
        {
            return Err(SendAuthorityError::Closed.into());
        }
        for (pin, key) in pins.iter().zip(&keys) {
            let authority = gate.get(key).ok_or(SendAuthorityError::Closed)?;
            if !authority.open
                || authority.scope.mutation.notify_boot != self.boot
                || authority.scope.mutation.generation != pin.generation
                || authority.scope.mutation.desired_record_hash != pin.record_hash
            {
                return Err(SendAuthorityError::Closed.into());
            }
            match &authority.scope.desired {
                AuthorityRecord::Owner {
                    owner: Some(owner),
                    custody_authority: Some(evidence),
                    revoked: false,
                    ..
                } if owner.device_epoch == row.owner_epoch => {
                    let branch = evidence
                        .publication
                        .record
                        .body
                        .devices
                        .iter()
                        .find(|device| device.device_id == owner.device_id)
                        .and_then(|device| device.branch_certificate.as_ref())
                        .ok_or(SendAuthorityError::Closed)?;
                    if gate.utc_floor >= u128::from(branch.body.expires_at) * 1_000_000_000 {
                        return Err(SendAuthorityError::Closed.into());
                    }
                }
                AuthorityRecord::Call {
                    state: AuthorityCallState::Ringing,
                    signed_start: Some(signed),
                    ..
                } if signed.body.target_delivery_id == target
                    && signed.body.target_epoch == row.owner_epoch
                    && gate.utc_floor < u128::from(signed.body.expires_at) * 1_000_000_000 => {}
                AuthorityRecord::LocalRows { .. } => {}
                _ => return Err(SendAuthorityError::Closed.into()),
            }
        }
        let result = issue();
        drop(gate);
        result
    }
}

fn mirror_pin(
    scope: &AuthorityScope,
    row: &Mirror,
    boot: &str,
) -> Result<AuthorityPin, SendAuthorityError> {
    if !row.open || row.scope.mutation.notify_boot != boot {
        return Err(SendAuthorityError::Closed);
    }
    Ok(AuthorityPin {
        scope: scope.clone(),
        generation: row.scope.mutation.generation,
        record_hash: row.scope.mutation.desired_record_hash.clone(),
    })
}

pub(super) fn cache_room(
    gate: &mut GateState,
    key: &str,
    bytes: usize,
) -> Result<(), SendAuthorityError> {
    loop {
        let used: usize = gate.values().map(|r| r.encoded_bytes).sum::<usize>()
            + gate.loading.keys().map(|key| key.len() + 64).sum::<usize>()
            + gate
                .wakes
                .iter()
                .map(|(key, row)| {
                    key.len()
                        + row.digest.len()
                        + row.target.len()
                        + row.start.as_ref().map_or(0, String::len)
                        + 80
                })
                .sum::<usize>();
        let prior = gate.get(key).map_or(0, |r| r.encoded_bytes);
        if (gate.contains_key(key)
            || gate.len() + gate.loading.len() + gate.wakes.len() < MAX_MIRRORS)
            && used.saturating_sub(prior).saturating_add(bytes) <= MAX_MIRROR_BYTES
        {
            return Ok(());
        }
        let victim = gate
            .iter()
            .find(|(candidate, row)| candidate.as_str() != key && row.open)
            .map(|(key, _)| key.clone())
            .ok_or(SendAuthorityError::Capacity)?;
        gate.remove(&victim);
    }
}
