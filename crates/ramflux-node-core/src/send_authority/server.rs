// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Notify's authenticated control adapter. Origin reads finish before taking `SendGate`.

use super::{
    AuthorityBootReply, AuthorityBootRequest, AuthorityControlOutcome, AuthorityControlPhase,
    AuthorityControlReply, AuthorityControlRequest, AuthorityMutation, AuthorityPhase,
    AuthorityReadPurpose, AuthorityReadReply, AuthorityReadRequest, AuthorityReadResult,
    AuthorityScope, AuthorityStateReply, AuthorityStateRequest, NodeCoreError, SendAuthorityError,
    SendAuthorityStore, reservation, rpc, storage, validate_digest,
};

impl SendAuthorityStore {
    /// Configure the one global recipient ledger from canonical authenticated identities.
    /// # Errors
    /// Refuses unfunded, invalid or occupied-quota-reducing configuration.
    pub fn configure_origins(
        &self,
        root_budget: u64,
        origins: &[String],
    ) -> Result<(), SendAuthorityError> {
        reservation::initialize(&self.db, root_budget, origins)
    }

    /// # Errors
    /// Resolve only the durable coordinator-owned origin, never a caller-provided service hint.
    pub fn origin_for_scope(
        &self,
        scope: &AuthorityScope,
    ) -> Result<Option<String>, SendAuthorityError> {
        self.load(&scope.key()?)?
            .map(|row| reservation::owner(&self.db, &row.mutation.reservation_id))
            .transpose()
    }

    /// Set the authenticated local writer before any recipient or credential writes.
    /// # Errors
    /// Rejects a non-notify identity or a poisoned writer configuration.
    pub fn configure_local_writer(&self, identity: String) -> Result<(), SendAuthorityError> {
        let peer = crate::parse_mesh_spiffe_uri(&identity).map_err(storage)?;
        if peer.service_id != "ramflux-notify" {
            return Err(SendAuthorityError::Invalid);
        }
        *self.local_identity.lock().map_err(storage)? = identity;
        Ok(())
    }

    /// # Errors
    /// Only configured authenticated origins may discover the non-authorizing boot.
    pub fn boot_reply(
        &self,
        origin: &str,
        request: &AuthorityBootRequest,
    ) -> Result<AuthorityBootReply, SendAuthorityError> {
        reservation::require_origin(&self.db, origin)?;
        validate_digest(&request.request_id)?;
        if request.version != 1 {
            return Err(SendAuthorityError::Invalid);
        }
        Ok(AuthorityBootReply {
            version: 1,
            request_id: request.request_id.clone(),
            notify_boot: self.boot.clone(),
        })
    }

    /// # Errors
    /// Scope ownership, current boot and complete durable history must match.
    pub fn state_reply(
        &self,
        origin: &str,
        request: &AuthorityStateRequest,
    ) -> Result<AuthorityStateReply, SendAuthorityError> {
        self.require_remote_scope(origin, &request.scope)?;
        validate_digest(&request.request_id)?;
        if request.version != 1 || request.notify_boot != self.boot {
            return Err(SendAuthorityError::Invalid);
        }
        if let Some(row) = self.load(&request.scope.key()?)? {
            reservation::require_owner(
                &self.db,
                origin,
                &row.mutation.reservation_id,
                row.mutation.reservation_generation,
            )?;
        }
        let state = self.state(&request.scope)?;
        Ok(AuthorityStateReply {
            version: 1,
            request_id: request.request_id.clone(),
            notify_boot: self.boot.clone(),
            scope: request.scope.clone(),
            generation: state.generation,
            operation_id: state.operation_id,
            phase: state.phase,
            record_hash: state.record_hash,
        })
    }

    /// # Errors
    /// Receipts cannot cross configured origin/channel identities.
    pub fn reservation_reply(
        &self,
        origin: &str,
        request: &reservation::ReservationRequest,
        now: u64,
    ) -> Result<reservation::ReservationReply, SendAuthorityError> {
        reservation::require_origin(&self.db, origin)?;
        let peer = crate::parse_mesh_spiffe_uri(origin).map_err(storage)?;
        if request.recipient_root == reservation::system_root()
            || (peer.service_id == "ramflux-gateway") != request.slot_id.is_some()
        {
            return Err(SendAuthorityError::Invalid);
        }
        let now = self.retention_clock(now)?;
        let reply = reservation::apply(&self.db, origin, request, now)?;
        if request.action == reservation::ReservationAction::Retire
            && let Some(id) = reply.reservation_id.as_deref()
            && let Some(horizon) = self.retire_component_scopes(id, now, |_, _| Ok(()))?
        {
            let tx = self.db.begin_write().map_err(storage)?;
            reservation::notify_retired(
                &tx,
                id,
                reply.reservation_generation.ok_or(SendAuthorityError::Invalid)?,
                horizon,
            )?;
            tx.commit().map_err(storage)?;
        }
        reservation::prune(&self.db, now)?;
        Ok(reply)
    }

    /// # Errors
    /// Wrong boot, unknown origin, malformed cursor and over-limit replies refuse.
    pub fn reservations_reply(
        &self,
        origin: &str,
        request: &reservation::ReservationListRequest,
    ) -> Result<reservation::ReservationListReply, SendAuthorityError> {
        reservation::list(&self.db, origin, &self.boot, request)
    }

    /// `read_origin` uses the configured endpoint for the authenticated origin's exact identity.
    /// # Errors
    /// Failed origin lookup, proof, receipt or tuple validation never opens a gate.
    pub fn control_reply(
        &self,
        origin: &str,
        request: &AuthorityControlRequest,
        read_origin: impl FnOnce(&AuthorityReadRequest) -> Result<AuthorityReadReply, NodeCoreError>,
        now: u64,
    ) -> Result<AuthorityControlReply, NodeCoreError> {
        self.require_remote_scope(origin, &request.scope)?;
        validate_digest(&request.request_id)?;
        if request.version != 1 || request.notify_boot != self.boot {
            return Err(SendAuthorityError::Invalid.into());
        }
        let now = self.retention_clock(now)?;
        if let Some(reply) = self.duplicate_control(origin, request)? {
            return Ok(reply);
        }
        let read = AuthorityReadRequest {
            version: 1,
            request_id: rpc::random_id()?,
            notify_boot: self.boot.clone(),
            scope: request.scope.clone(),
            purpose: if request.phase == AuthorityControlPhase::Publish {
                AuthorityReadPurpose::PublishCheck
            } else {
                AuthorityReadPurpose::FenceCheck
            },
            operation_id: Some(request.operation_id.clone()),
        };
        let reply = read_origin(&read)?;
        if reply.version != 1
            || reply.request_id != read.request_id
            || reply.notify_boot != self.boot
            || reply.scope != request.scope
        {
            return Err(SendAuthorityError::Invalid.into());
        }
        let AuthorityReadResult::Record {
            reservation_id,
            reservation_generation,
            origin_incarnation,
            operation_id,
            phase,
            expected_generation,
            generation,
            record_hash,
            record,
        } = reply.result
        else {
            return Err(SendAuthorityError::Closed.into());
        };
        let mutation = AuthorityMutation {
            version: 1,
            reservation_id,
            reservation_generation,
            origin_incarnation,
            operation_id,
            phase,
            expected_generation,
            generation,
            notify_boot: self.boot.clone(),
            desired_record_hash: record_hash,
            result: None,
        };
        if mutation.operation_id != request.operation_id
            || mutation.generation != request.generation
            || mutation.expected_generation != request.expected_generation
            || mutation.desired_record_hash != request.record_hash
            || mutation.reservation_id != request.reservation_id
            || mutation.reservation_generation != request.reservation_generation
            || mutation.origin_incarnation != request.origin_incarnation
        {
            return Err(SendAuthorityError::Conflict.into());
        }
        record.verify_evidence(now)?;
        if request.phase == AuthorityControlPhase::Fence
            && self.state(&request.scope)?.is_empty()
            && matches!(record.as_ref(), super::AuthorityRecord::Call {
                state: super::AuthorityCallState::Ringing, signed_start: Some(start), ..
            } if now>=start.body.expires_at)
        {
            return Err(SendAuthorityError::Closed.into());
        }
        reservation::verify_active(&self.db, origin, &mutation, &record)?;
        match request.phase {
            AuthorityControlPhase::Fence | AuthorityControlPhase::ResyncFence => {
                let observed = self.state(&request.scope)?;
                self.fence(
                    &request.scope,
                    &mutation,
                    *record,
                    &observed,
                    request.phase == AuthorityControlPhase::ResyncFence,
                )?;
            }
            AuthorityControlPhase::Publish => self.publish(&request.scope, &mutation, &record)?,
        }
        Ok(AuthorityControlReply {
            version: 1,
            request_id: request.request_id.clone(),
            operation_id: request.operation_id.clone(),
            notify_boot: self.boot.clone(),
            generation: request.generation,
            outcome: AuthorityControlOutcome::Applied,
        })
    }

    fn duplicate_control(
        &self,
        origin: &str,
        request: &AuthorityControlRequest,
    ) -> Result<Option<AuthorityControlReply>, NodeCoreError> {
        if let Some(row) = self.load(&request.scope.key()?)? {
            let duplicate =
                std::iter::once(&row.mutation).chain(row.prior_result.as_ref()).any(|mutation| {
                    mutation.phase == AuthorityPhase::Stable
                        && mutation.result.is_some()
                        && mutation.notify_boot == request.notify_boot
                        && mutation.operation_id == request.operation_id
                        && mutation.reservation_id == request.reservation_id
                        && mutation.reservation_generation == request.reservation_generation
                        && mutation.origin_incarnation == request.origin_incarnation
                        && mutation.expected_generation == request.expected_generation
                        && mutation.generation == request.generation
                        && mutation.desired_record_hash == request.record_hash
                });
            if duplicate {
                reservation::require_owner(
                    &self.db,
                    origin,
                    &request.reservation_id,
                    request.reservation_generation,
                )?;
                return Ok(Some(AuthorityControlReply {
                    version: 1,
                    request_id: request.request_id.clone(),
                    operation_id: request.operation_id.clone(),
                    notify_boot: self.boot.clone(),
                    generation: request.generation,
                    outcome: AuthorityControlOutcome::Duplicate,
                }));
            }
        }
        Ok(None)
    }

    fn require_remote_scope(
        &self,
        identity: &str,
        scope: &AuthorityScope,
    ) -> Result<(), SendAuthorityError> {
        reservation::require_origin(&self.db, identity)?;
        let peer = crate::parse_mesh_spiffe_uri(identity).map_err(storage)?;
        if scope.origin_service() != Some(peer.service_id.as_str()) {
            return Err(SendAuthorityError::Invalid);
        }
        Ok(())
    }
}
