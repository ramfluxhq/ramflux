// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recover exact outbound business messages and release destination reservations.
use super::{HomeMigrationJournal, MigrationPhase, MigrationProgress, refused};
use crate::{
    SdkError,
    custody::{BornAccount, PrimaryVault},
};
use ramflux_crypto::{DeviceBranch, home_migration as crypto};
use ramflux_protocol::{
    custody::{DeviceRef, framed_hash, object_hash},
    home_migration as wire,
};

/// A durable outbound plan. Reading it never requests another management signature.
pub enum MigrationResumption {
    Prepare(Box<wire::Signed<wire::Prepare>>),
    Seal(Box<wire::Request>),
    AbortPrepared(Box<wire::Request>),
    Commit(Box<wire::Evidence>),
    Activate(Box<wire::Evidence>),
    Idle(Box<MigrationProgress>),
}

pub(super) fn sign_control(
    account: &BornAccount,
    branch: &DeviceBranch,
    action: wire::Action,
    audience: &str,
    operation: &str,
    payload_hash: String,
    now: u64,
) -> Result<wire::Signed<wire::Control>, SdkError> {
    Ok(crypto::sign_actor(
        wire::Control {
            version: 1,
            action,
            audience_node: audience.into(),
            migration_id: operation.into(),
            requester: DeviceRef {
                account_anchor: account.record().body.account_anchor.clone(),
                device_id: branch.device_id.clone(),
                device_epoch: branch.device_epoch,
            },
            authority_record_hash: object_hash(account.record())?,
            payload_hash,
            nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            issued_at: now,
            expires_at: now
                .checked_add(300)
                .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
                .ok_or_else(|| refused(wire::Refusal::AdmissionExpired))?,
        },
        branch,
        account.verified(),
        now,
    )?)
}

impl HomeMigrationJournal<'_> {
    /// Release an expired, unsealed Offer's local account lock. An uncertain seal is never expired locally.
    /// # Errors
    /// Refuses missing/corrupt jobs or conflicting persistence writes.
    pub fn expire_offer(&self, operation: &str, now: u64) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        let now = now.max(job.clock_floor);
        if !job.progress.phase.terminal()
            && !job.recovery_blocked
            && job.offer.as_ref().is_some_and(|offer| now > offer.body.accept_until)
        {
            let prior = job.progress.seq;
            job.progress.phase = MigrationPhase::Expired;
            job.progress.reason = Some(wire::Refusal::AdmissionExpired);
            job.clock_floor = now;
            self.advance(&mut job, prior)?;
        }
        Ok(job.progress)
    }

    /// Re-send the saved Prepare or Seal after save-before-send crashes, without re-signing or presence.
    /// A pending reservation Abort is actor-signed once and persisted before its first send.
    /// # Errors
    /// Refuses missing evidence, unavailable branch credentials or persistence failure.
    pub fn resume(
        &self,
        operation: &str,
        vault: &dyn PrimaryVault,
        now: u64,
    ) -> Result<MigrationResumption, SdkError> {
        self.expire_offer(operation, now)?;
        let mut job = self.load(operation)?;
        match job.progress.phase {
            MigrationPhase::PrepareSent => Ok(MigrationResumption::Prepare(Box::new(
                job.prepare.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?,
            ))),
            MigrationPhase::SealSent | MigrationPhase::NeedsAttention
                if !job.cancel_requested
                    && job.authorization.is_some()
                    && job.seal.is_none()
                    && job.fence.is_none() =>
            {
                let authorization =
                    job.authorization.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
                let control =
                    job.seal_control.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
                let payload = wire::ActionPayload::Seal(wire::SealPayload {
                    authorization_hash: wire::message_hash(&authorization)?,
                    offer_hash: authorization.body.offer_hash.clone(),
                });
                Ok(MigrationResumption::Seal(Box::new(wire::Request {
                    control,
                    payload,
                    evidence: wire::Evidence {
                        authority: Some(job.authority),
                        authorization: Some(authorization),
                        prepare: job.prepare,
                        offer: job.offer,
                        ..wire::Evidence::default()
                    },
                })))
            }
            MigrationPhase::AbortPending => {
                if let Some(request) = &job.abort_request
                    && request.control.body.expires_at >= now.max(job.clock_floor)
                {
                    return Ok(MigrationResumption::AbortPrepared(Box::new(request.clone())));
                }
                let target =
                    job.target.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
                let now = now.max(job.clock_floor);
                let (_, credentials) =
                    self.account.credentials(vault, &job.actor.device_id, now)?;
                let payload = wire::OperationPayload {
                    account_anchor: job.anchor.clone(),
                    migration_id: operation.into(),
                };
                let control = sign_control(
                    self.account,
                    &credentials.signing,
                    wire::Action::Abort,
                    &target.node_id,
                    operation,
                    framed_hash(ramflux_protocol::domain::HOME_CONTROL, &payload)?,
                    now,
                )?;
                let request = wire::Request {
                    control,
                    payload: wire::ActionPayload::Operation(payload),
                    evidence: wire::Evidence {
                        authority: Some(job.authority.clone()),
                        prepare: job.prepare.clone(),
                        offer: job.offer.clone(),
                        ..wire::Evidence::default()
                    },
                };
                let prior = job.progress.seq;
                job.abort_request = Some(request.clone());
                job.clock_floor = now;
                self.advance(&mut job, prior)?;
                Ok(MigrationResumption::AbortPrepared(Box::new(request)))
            }
            MigrationPhase::Sealed | MigrationPhase::CommitPending if job.commit.is_none() => {
                Ok(MigrationResumption::Commit(Box::new(self.commit_evidence(operation, now)?)))
            }
            MigrationPhase::CommitPending | MigrationPhase::ActivateSent => {
                Ok(MigrationResumption::Activate(Box::new(self.activation_evidence(operation)?)))
            }
            _ => Ok(MigrationResumption::Idle(Box::new(job.progress))),
        }
    }

    /// Finish a pre-seal cancellation only after B authenticates release of the reservation.
    /// # Errors
    /// Refuses substituted, stale, unsigned or incorrectly bound acknowledgments.
    pub fn reservation_aborted(
        &self,
        operation: &str,
        receipt: wire::Signed<wire::Receipt>,
        now: u64,
    ) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        if !job.cancel_requested || job.recovery_blocked || job.abort_request.is_none() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let target = job.target.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        crypto::verify_node(&receipt, &target.node_id, &target.node_public_key)?;
        let request =
            job.abort_request.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let r = &receipt.body;
        if r.version != 1
            || r.action != wire::Action::Abort
            || r.migration_id != operation
            || r.account_anchor != job.anchor
            || r.node_id != target.node_id
            || r.request_hash != wire::message_hash(&request.control)?
            || r.request_nonce != request.control.body.nonce
            || r.reason_code.is_some()
            || !matches!(r.phase, wire::Phase::Aborted | wire::Phase::Expired)
            || r.issued_at > now.max(job.clock_floor).saturating_add(wire::SKEW_SECONDS)
            || r.expires_at < r.issued_at
            || r.expires_at < now.max(job.clock_floor)
        {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        if job.progress.phase.terminal() {
            return Ok(job.progress);
        }
        if job.progress.phase != MigrationPhase::AbortPending {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let prior = job.progress.seq;
        job.progress.phase = MigrationPhase::Aborted;
        job.progress.reason = None;
        job.clock_floor = job.clock_floor.max(now);
        self.advance(&mut job, prior)?;
        Ok(job.progress)
    }
}
