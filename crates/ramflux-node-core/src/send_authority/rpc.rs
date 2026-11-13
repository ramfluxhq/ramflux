// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Origin coordinator transport contract and correlated bounded RPC helpers.

use super::{
    AuthorityBootReply, AuthorityBootRequest, AuthorityControlOutcome, AuthorityControlPhase,
    AuthorityControlReply, AuthorityControlRequest, AuthorityMutation, AuthorityOrigin,
    AuthorityPhase, AuthorityRecord, AuthorityScope, AuthorityState, AuthorityStateReply,
    AuthorityStateRequest, MAX_AUTHORITY_GENERATION, NodeCoreError, OriginIntent,
    SEND_AUTHORITY_BOOT_PATH, SEND_AUTHORITY_PATH, SEND_AUTHORITY_STATE_PATH, SendAuthorityError,
    reservation, storage, wire,
};
use serde::{Serialize, de::DeserializeOwned};
use std::time::{Duration, Instant};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

/// Implementations enforce mTLS service identity, original-byte parsing and one deadline.
pub trait AuthorityRpc: Send + Sync {
    /// # Errors
    /// Returns authentication, wire, deadline or transport failures without fallback.
    fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
        deadline: Instant,
    ) -> Result<serde_json::Value, NodeCoreError>;
}

/// One exclusive origin incarnation. A new process surveys all retained receipts first.
pub struct AuthorityClient {
    rpc: Arc<dyn AuthorityRpc>,
    incarnation: String,
    ready: Mutex<BTreeSet<String>>,
    known_boot: Mutex<Option<String>>,
    admission: Mutex<()>,
    survey_progress: Mutex<SurveyProgress>,
}

#[derive(Default)]
struct SurveyProgress {
    boot: Option<String>,
    after: Option<u64>,
    ready: bool,
}

#[derive(Clone, Copy)]
pub struct AuthorityUpdate<'a> {
    pub scope: &'a AuthorityScope,
    pub record: &'a AuthorityRecord,
    pub recipient_root: &'a str,
    pub slot_id: Option<&'a str>,
    pub desired_payload: &'a [u8],
    pub deadline: Instant,
}

pub struct PreparedAuthority {
    pub scope: AuthorityScope,
    pub mutation: AuthorityMutation,
    pub payload: Vec<u8>,
    deadline: Instant,
}

impl AuthorityClient {
    /// # Errors
    /// Returns OS randomness failure; there is no predictable incarnation fallback.
    pub fn new(rpc: Arc<dyn AuthorityRpc>) -> Result<Self, NodeCoreError> {
        Ok(Self {
            rpc,
            incarnation: random_id()?,
            ready: Mutex::new(BTreeSet::new()),
            known_boot: Mutex::new(None),
            admission: Mutex::new(()),
            survey_progress: Mutex::new(SurveyProgress::default()),
        })
    }

    #[must_use]
    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }

    #[must_use]
    pub fn known_boot(&self) -> Option<String> {
        self.known_boot.lock().ok().and_then(|boot| boot.clone())
    }

    /// Runtime readiness is never restored from an old process's stable disk row.
    #[must_use]
    pub fn scope_ready(&self, scope: &AuthorityScope) -> bool {
        scope.key().is_ok_and(|key| self.ready.lock().is_ok_and(|ready| ready.contains(&key)))
    }

    /// Fence, commit and publish one desired record, resuming only its retained operation.
    /// `apply` replaces the exact saved payload idempotently in the supplied transaction.
    /// # Errors
    /// Any failed phase stays durable/closed; a later call resumes that phase without a new ID.
    pub fn update(
        &self,
        db: &redb::Database,
        update: AuthorityUpdate<'_>,
        mut apply: impl FnMut(&redb::WriteTransaction, &[u8]) -> Result<(), NodeCoreError>,
    ) -> Result<(), NodeCoreError> {
        let mut prepared = self.prepare(db, update)?;
        if prepared.mutation.phase == AuthorityPhase::Closing {
            let committed =
                AuthorityOrigin::commit(db, &prepared.scope, &prepared.mutation, |tx| {
                    apply(tx, &prepared.payload)
                })?;
            prepared.mutation = committed;
        }
        self.finish(db, &prepared, &prepared.mutation)
    }

    /// Close the remote mirror before an external multi-scope authoritative transaction.
    /// # Errors
    /// Leaves an uncertain operation durable and closed for exact retry.
    pub fn prepare(
        &self,
        db: &redb::Database,
        update: AuthorityUpdate<'_>,
    ) -> Result<PreparedAuthority, NodeCoreError> {
        let AuthorityUpdate { scope, record, recipient_root, slot_id, desired_payload, deadline } =
            update;
        let admission = self.admission.try_lock().map_err(|_| SendAuthorityError::Busy)?;
        let boot = self.discover_boot(deadline)?;
        self.survey(db, &boot, deadline)?;
        let observed = self.state(scope, &boot, deadline)?;
        let pending = AuthorityOrigin::pending(db, scope)?;
        let hash = record.record_hash()?;
        let mut resync = false;
        let (mutation, payload) = if let Some(pending) = pending {
            if pending.mutation.phase != AuthorityPhase::Stable {
                if pending.mutation.desired_record_hash != hash
                    || pending.payload != desired_payload
                {
                    return Err(SendAuthorityError::Busy.into());
                }
                let mutation = if pending.mutation.notify_boot == boot {
                    pending.mutation
                } else {
                    resync = true;
                    AuthorityOrigin::recover(db, scope, &boot, &observed)?
                };
                (mutation, pending.payload)
            } else if (pending.mutation.notify_boot != boot || !self.scope_ready(scope))
                && pending.mutation.desired_record_hash == hash
                && pending.payload == desired_payload
            {
                resync = true;
                let mutation = AuthorityOrigin::recover(db, scope, &boot, &observed)?;
                (mutation, pending.payload)
            } else {
                if pending.mutation.notify_boot != boot || !observed.matches(&pending.mutation) {
                    return Err(SendAuthorityError::Busy.into());
                }
                let receipt = pending.reservation;
                let mutation = AuthorityOrigin::begin(
                    db,
                    OriginIntent {
                        scope,
                        desired: record.clone(),
                        notify_boot: &boot,
                        notify_state: &observed,
                        operation_id: &random_id()?,
                        reservation: &receipt,
                        desired_payload,
                    },
                )?;
                (mutation, desired_payload.to_vec())
            }
        } else {
            let receipt = match AuthorityOrigin::receipt(db, recipient_root, slot_id)? {
                Some(receipt) => receipt,
                None => self.reserve(recipient_root, slot_id, &random_id()?, deadline)?,
            };
            let mutation = AuthorityOrigin::begin(
                db,
                OriginIntent {
                    scope,
                    desired: record.clone(),
                    notify_boot: &boot,
                    notify_state: &observed,
                    operation_id: &random_id()?,
                    reservation: &receipt,
                    desired_payload,
                },
            )?;
            (mutation, desired_payload.to_vec())
        };
        drop(admission);
        if mutation.phase == AuthorityPhase::Closing {
            self.control(
                scope,
                &mutation,
                if resync {
                    AuthorityControlPhase::ResyncFence
                } else {
                    AuthorityControlPhase::Fence
                },
                deadline,
            )?;
        }
        Ok(PreparedAuthority { scope: scope.clone(), mutation, payload, deadline })
    }

    /// Publish an exact committed tuple after its authoritative transaction is durable.
    /// # Errors
    /// A failed or stale completion remains denied.
    pub fn finish(
        &self,
        db: &redb::Database,
        prepared: &PreparedAuthority,
        mutation: &AuthorityMutation,
    ) -> Result<(), NodeCoreError> {
        self.control(&prepared.scope, mutation, AuthorityControlPhase::Publish, prepared.deadline)?;
        AuthorityOrigin::published(db, &prepared.scope, mutation)?;
        let key = prepared.scope.key()?;
        let mut ready = self.ready.lock().map_err(storage)?;
        if ready.len() >= 4096
            && let Some(old) = ready.first().cloned()
        {
            ready.remove(&old);
        }
        ready.insert(key);
        Ok(())
    }

    /// Reopen an unchanged saved operation after either endpoint restarts.
    /// # Errors
    /// Missing history or an uncertain saved delta stays denied.
    pub fn ensure_current(
        &self,
        db: &redb::Database,
        scope: &AuthorityScope,
        apply: impl FnMut(&redb::WriteTransaction, &[u8]) -> Result<(), NodeCoreError>,
    ) -> Result<(), NodeCoreError> {
        let pending = AuthorityOrigin::pending(db, scope)?.ok_or(SendAuthorityError::Closed)?;
        self.update(
            db,
            AuthorityUpdate {
                scope,
                record: &pending.record,
                recipient_root: &pending.reservation.recipient_root,
                slot_id: pending.reservation.slot_id.as_deref(),
                desired_payload: &pending.payload,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            apply,
        )
    }

    /// # Errors
    /// Wrong correlation or malformed boot replies confer no authority.
    pub fn discover_boot(&self, deadline: Instant) -> Result<String, NodeCoreError> {
        let request = AuthorityBootRequest { version: 1, request_id: random_id()? };
        let reply: AuthorityBootReply =
            self.post(SEND_AUTHORITY_BOOT_PATH, &request, deadline, 8192)?;
        if reply.version != 1 || reply.request_id != request.request_id {
            return Err(SendAuthorityError::Invalid.into());
        }
        wire::validate_digest(&reply.notify_boot)?;
        let mut known = self.known_boot.lock().map_err(storage)?;
        if known.as_ref() != Some(&reply.notify_boot) {
            self.ready.lock().map_err(storage)?.clear();
            *self.survey_progress.lock().map_err(storage)? = SurveyProgress::default();
        }
        *known = Some(reply.notify_boot.clone());
        Ok(reply.notify_boot)
    }

    /// # Errors
    /// Refuses mismatched boot/scope/correlation or inconsistent zero history.
    pub fn state(
        &self,
        scope: &AuthorityScope,
        boot: &str,
        deadline: Instant,
    ) -> Result<AuthorityState, NodeCoreError> {
        let request = AuthorityStateRequest {
            version: 1,
            request_id: random_id()?,
            notify_boot: boot.to_owned(),
            scope: scope.clone(),
        };
        let reply: AuthorityStateReply =
            self.post(SEND_AUTHORITY_STATE_PATH, &request, deadline, 8192)?;
        let state = reply.state();
        if reply.version != 1
            || reply.request_id != request.request_id
            || reply.notify_boot != boot
            || reply.scope != *scope
            || (state.generation == 0 && !state.is_empty())
            || state.generation > MAX_AUTHORITY_GENERATION
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        Ok(state)
    }

    /// Survey under the exclusive database incarnation before new writes and during operation.
    /// Every page is bounded; an incomplete survey denies admission instead of skipping tuples.
    /// # Errors
    /// Any uncertain absence/ACK or deadline retains the coordinator charge.
    fn survey(
        &self,
        db: &redb::Database,
        boot: &str,
        deadline: Instant,
    ) -> Result<(), NodeCoreError> {
        let (online, mut cursor) = {
            let mut progress = self.survey_progress.lock().map_err(storage)?;
            if progress.boot.as_deref() != Some(boot) {
                *progress = SurveyProgress { boot: Some(boot.into()), after: None, ready: false };
            }
            (progress.ready, progress.after)
        };
        loop {
            let page = self.reservation_page(boot, cursor, deadline)?;
            for row in page.rows {
                if matches!(
                    row.phase,
                    reservation::ReservationPhase::Active | reservation::ReservationPhase::Retiring
                ) && !AuthorityOrigin::reservation_nonempty(db, &row.reservation_id)?
                {
                    let request = reservation::ReservationRequest {
                        version: 1,
                        request_id: random_id()?,
                        operation_id: row.operation_id,
                        recipient_root: row.recipient_root,
                        slot_id: row.slot_id,
                        reservation_id: Some(row.reservation_id),
                        reservation_generation: Some(row.reservation_generation),
                        origin_incarnation: row.origin_incarnation,
                        action: reservation::ReservationAction::Retire,
                    };
                    self.reservation(&request, deadline)?;
                }
            }
            let mut progress = self.survey_progress.lock().map_err(storage)?;
            if progress.boot.as_deref() != Some(boot) {
                return Err(SendAuthorityError::Conflict.into());
            }
            progress.after = page.next_generation;
            if page.next_generation.is_none() {
                progress.ready = true;
                return Ok(());
            }
            cursor = page.next_generation;
            // Startup completes the entire survey before business writes. Later operations
            // advance one page, so a full admitted root never depends on rescanning every slot.
            if online {
                return Ok(());
            }
        }
    }

    /// Enumerate at most four receipts per network call; the caller processes each page.
    /// # Errors
    /// Refuses stale boot, correlation, non-increasing generations and oversized pages.
    pub fn reservation_page(
        &self,
        boot: &str,
        after: Option<u64>,
        deadline: Instant,
    ) -> Result<reservation::ReservationListReply, NodeCoreError> {
        let request = reservation::ReservationListRequest {
            version: 1,
            request_id: random_id()?,
            notify_boot: boot.to_owned(),
            after_generation: after,
        };
        let reply: reservation::ReservationListReply =
            self.post(reservation::RESERVATIONS_PATH, &request, deadline, 8192)?;
        let mut previous = after.unwrap_or(0);
        for row in &reply.rows {
            if row.reservation_generation <= previous
                || row.phase == reservation::ReservationPhase::Refused
            {
                return Err(SendAuthorityError::Invalid.into());
            }
            previous = row.reservation_generation;
        }
        if reply.version != 1
            || reply.request_id != request.request_id
            || reply.notify_boot != boot
            || reply.rows.len() > 4
            || reply.next_generation.is_some_and(|next| next != previous)
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        Ok(reply)
    }

    /// # Errors
    /// Lost retirement ACKs stay discoverable in the coordinator's per-origin survey.
    pub fn retire_component(
        &self,
        receipt: &reservation::ReservationReply,
    ) -> Result<(), NodeCoreError> {
        let request = reservation::ReservationRequest {
            version: 1,
            request_id: random_id()?,
            operation_id: receipt.operation_id.clone(),
            recipient_root: receipt.recipient_root.clone(),
            slot_id: receipt.slot_id.clone(),
            reservation_id: receipt.reservation_id.clone(),
            reservation_generation: receipt.reservation_generation,
            origin_incarnation: receipt.origin_incarnation.clone(),
            action: reservation::ReservationAction::Retire,
        };
        self.reservation(&request, Instant::now() + Duration::from_secs(5))?;
        Ok(())
    }

    /// Obtain activation before any charged origin write. Retries preserve the request tuple.
    /// # Errors
    /// Capacity/busy/refusal, ACK uncertainty and correlation failure remain denied.
    pub fn reserve(
        &self,
        root: &str,
        slot: Option<&str>,
        operation_id: &str,
        deadline: Instant,
    ) -> Result<reservation::ReservationReply, NodeCoreError> {
        let mut request = reservation::ReservationRequest {
            version: 1,
            request_id: random_id()?,
            operation_id: operation_id.to_owned(),
            recipient_root: root.to_owned(),
            slot_id: slot.map(str::to_owned),
            reservation_id: None,
            reservation_generation: None,
            origin_incarnation: self.incarnation.clone(),
            action: reservation::ReservationAction::Acquire,
        };
        let reserved = self.reservation(&request, deadline)?;
        if reserved.phase != reservation::ReservationPhase::Reserved {
            if reserved.phase == reservation::ReservationPhase::Active {
                return Ok(reserved);
            }
            return Err(SendAuthorityError::Closed.into());
        }
        request.action = reservation::ReservationAction::Activate;
        request.request_id = random_id()?;
        request.reservation_id = reserved.reservation_id;
        request.reservation_generation = reserved.reservation_generation;
        let active = self.reservation(&request, deadline)?;
        if active.phase != reservation::ReservationPhase::Active {
            return Err(SendAuthorityError::Closed.into());
        }
        Ok(active)
    }

    /// # Errors
    /// Rejects any response that changes the owning tuple or is a typed refusal.
    pub fn reservation(
        &self,
        request: &reservation::ReservationRequest,
        deadline: Instant,
    ) -> Result<reservation::ReservationReply, NodeCoreError> {
        let reply: reservation::ReservationReply =
            self.post(reservation::RESERVATION_PATH, request, deadline, 8192)?;
        if reply.version != 1
            || reply.request_id != request.request_id
            || reply.operation_id != request.operation_id
            || reply.recipient_root != request.recipient_root
            || reply.slot_id != request.slot_id
            || reply.origin_incarnation != request.origin_incarnation
            || (request.action != reservation::ReservationAction::Acquire
                && (request.reservation_id != reply.reservation_id
                    || request.reservation_generation != reply.reservation_generation))
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        if let Some(reason) = reply.reason {
            return Err(match reason {
                reservation::ReservationRefusal::Capacity => SendAuthorityError::Capacity,
                reservation::ReservationRefusal::Busy => SendAuthorityError::Busy,
                reservation::ReservationRefusal::Conflict => SendAuthorityError::Conflict,
            }
            .into());
        }
        wire::validate_digest(reply.reservation_id.as_deref().ok_or(SendAuthorityError::Invalid)?)?;
        if reply.reservation_generation.is_none_or(|n| n == 0 || n > MAX_AUTHORITY_GENERATION) {
            return Err(SendAuthorityError::Invalid.into());
        }
        Ok(reply)
    }

    /// # Errors
    /// ACKs must match the entire owning operation, boot and generation.
    pub fn control(
        &self,
        scope: &AuthorityScope,
        mutation: &AuthorityMutation,
        phase: AuthorityControlPhase,
        deadline: Instant,
    ) -> Result<(), NodeCoreError> {
        let request = AuthorityControlRequest {
            version: 1,
            request_id: random_id()?,
            operation_id: mutation.operation_id.clone(),
            reservation_id: mutation.reservation_id.clone(),
            reservation_generation: mutation.reservation_generation,
            origin_incarnation: mutation.origin_incarnation.clone(),
            notify_boot: mutation.notify_boot.clone(),
            scope: scope.clone(),
            expected_generation: mutation.expected_generation,
            generation: mutation.generation,
            phase,
            record_hash: mutation.desired_record_hash.clone(),
        };
        let reply: AuthorityControlReply =
            self.post(SEND_AUTHORITY_PATH, &request, deadline, 8192)?;
        if reply.version != 1
            || reply.request_id != request.request_id
            || reply.operation_id != request.operation_id
            || reply.notify_boot != request.notify_boot
            || reply.generation != request.generation
            || reply.outcome == AuthorityControlOutcome::Refused
        {
            return Err(SendAuthorityError::Conflict.into());
        }
        Ok(())
    }

    fn post<Q: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &Q,
        deadline: Instant,
        cap: usize,
    ) -> Result<R, NodeCoreError> {
        let request = ramflux_protocol::canonical_json_bytes(request).map_err(storage)?;
        if request.len() > cap {
            return Err(SendAuthorityError::Capacity.into());
        }
        let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
        if deadline <= Instant::now() {
            return Err(SendAuthorityError::Closed.into());
        }
        let value = ramflux_protocol::parse_i_json(&request).map_err(storage)?;
        let reply = self.rpc.post(path, &value, deadline)?;
        let bytes = ramflux_protocol::canonical_json_bytes(&reply).map_err(storage)?;
        if bytes.len() > cap {
            return Err(SendAuthorityError::Capacity.into());
        }
        Ok(ramflux_protocol::parse_i_json(&bytes).map_err(storage)?)
    }
}

pub(crate) fn random_id() -> Result<String, NodeCoreError> {
    Ok(ramflux_protocol::encode_base64url(ramflux_crypto::random_32().map_err(storage)?))
}
