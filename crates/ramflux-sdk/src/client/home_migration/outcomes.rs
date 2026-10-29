// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Only authenticated evidence can advance an uncertain business outcome.
use super::{HomeMigrationJournal, MigrationPhase, MigrationProgress, refused};
use crate::SdkError;
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::home_migration as wire;

impl HomeMigrationJournal<'_> {
    /// Retain B's fresh control-bound reply and durable seal hash, even after cancellation.
    /// # Errors
    /// Rejects another node, authorization, business nonce, phase or impossible seal bounds.
    pub fn sealed(
        &self,
        operation: &str,
        seal: wire::Signed<wire::Receipt>,
        now: u64,
    ) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        if job.seal.as_ref() == Some(&seal) {
            return Ok(job.progress);
        }
        if !job.recovery_blocked || job.commit.is_some() || job.fence.is_some() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let a =
            job.authorization.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let offer = job.offer.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        crypto::verify_node(&seal, &a.body.destination_node, &a.body.destination_key)?;
        let receipt = &seal.body;
        let hash = wire::message_hash(a)?;
        let control =
            job.seal_control.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        if receipt.version != 1
            || receipt.action != wire::Action::Seal
            || receipt.migration_id != job.intent.operation_id
            || receipt.account_anchor != job.anchor
            || receipt.node_id != a.body.destination_node
            || receipt.authorization_hash.as_deref() != Some(&hash)
            || receipt.request_hash != wire::message_hash(control)?
            || receipt.request_nonce != control.body.nonce
            || receipt.phase != wire::Phase::Sealed
            || receipt.reason_code.is_some()
            || job.seal_hash.as_ref().is_some_and(|prior| receipt.seal_hash.as_ref() != Some(prior))
            || receipt.state_version == 0
            || receipt.seal_hash.as_deref().is_none_or(|value| !super::digest(value))
            || receipt.issued_at > now.max(job.clock_floor).saturating_add(wire::SKEW_SECONDS)
            || receipt.expires_at < receipt.issued_at
            || receipt.expires_at < now.max(job.clock_floor)
        {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        let sealed_at =
            receipt.sealed_at.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        if sealed_at > now.max(job.clock_floor).saturating_add(wire::SKEW_SECONDS) {
            return Err(refused(wire::Refusal::CommitOutcomeUnknown));
        }
        crypto::commit_bounds(&a.body, &offer.body, receipt, sealed_at)?;
        let prior = job.progress.seq;
        job.progress.commit_deadline = receipt.commit_deadline;
        job.seal_hash.clone_from(&receipt.seal_hash);
        job.seal = Some(seal);
        if !job.cancel_requested {
            job.progress.phase = MigrationPhase::Sealed;
            job.progress.reason = None;
        }
        job.clock_floor = job.clock_floor.max(now);
        self.advance(&mut job, prior)?;
        Ok(job.progress)
    }
    /// Construct the commit payload using B's durable seal hash, independent of fresh receipt bytes.
    /// # Errors
    /// Refuses missing seal/authorization or cancelled/fenced jobs.
    pub fn commit_payload(&self, operation: &str) -> Result<wire::CommitPayload, SdkError> {
        let job = self.load(operation)?;
        if job.cancel_requested || job.fence.is_some() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let authorization =
            job.authorization.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        Ok(wire::CommitPayload {
            authorization_hash: wire::message_hash(authorization)?,
            offer_hash: authorization.body.offer_hash.clone(),
            seal_hash: job.seal_hash.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?,
        })
    }
    /// Persist `commit_pending` before handing the immutable signed evidence to transport.
    /// # Errors
    /// Refuses cancellation, absent seal, expired admission or a changed/terminal operation.
    pub fn commit_evidence(&self, operation: &str, now: u64) -> Result<wire::Evidence, SdkError> {
        let mut job = self.load(operation)?;
        if job.cancel_requested
            || job.commit.is_some()
            || job.fence.is_some()
            || !job.recovery_blocked
        {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let a =
            job.authorization.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let offer = job.offer.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let seal = job.seal.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let now = now.max(job.clock_floor);
        crypto::commit_bounds(&a.body, &offer.body, &seal.body, now)?;
        let evidence = wire::Evidence {
            authority: Some(job.authority.clone()),
            authorization: Some(a.clone()),
            offer: Some(offer.clone()),
            // B retains the original seal; this receipt authenticates only the fresh reply.
            seal_receipt: None,
            prepare: job.prepare.clone(),
            ..wire::Evidence::default()
        };
        let prior = job.progress.seq;
        job.progress.phase = MigrationPhase::CommitPending;
        job.progress.reason = None;
        job.clock_floor = now;
        self.advance(&mut job, prior)?;
        Ok(evidence)
    }
    /// Store A's authenticated successor before any activation or local file write.
    /// Duplicate accepted proofs are idempotent; cancellation and a noncommit fence refuse activation.
    /// # Errors
    /// Rejects another operation/base/authorization, wrong A pin and conflicting outcomes.
    pub fn committed(
        &self,
        operation: &str,
        home: &crypto::VerifiedHome,
        now: u64,
    ) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        let wire::HomeRecord::Committed { authorization, commit_proof } = &home.evidence().record
        else {
            return Err(refused(wire::Refusal::EvidenceRequired));
        };
        crypto::verify_node(commit_proof, &job.progress.source, &job.source_key)?;
        let a =
            job.authorization.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        if authorization.as_ref() != a
            || commit_proof.body.authorization_hash != wire::message_hash(a)?
            || commit_proof.body.migration_id != operation
            || commit_proof.body.account_anchor != job.anchor
            || commit_proof.body.destination_node != a.body.destination_node
            || commit_proof.body.destination_key != a.body.destination_key
            || home.epoch() != a.body.next_home_epoch
            || !home.extends(a.body.next_home_epoch.saturating_sub(1), &a.body.previous_home_hash)
        {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        if let Some(seal_hash) = &job.seal_hash
            && &commit_proof.body.seal_hash != seal_hash
        {
            return Err(refused(wire::Refusal::HomeFork));
        }
        if let Some(prior) = &job.commit {
            if prior != commit_proof.as_ref() {
                return Err(refused(wire::Refusal::IdempotencyConflict));
            }
            return Ok(job.progress);
        }
        if job.cancel_requested || job.fence.is_some() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let prior = job.progress.seq;
        job.commit = Some(commit_proof.as_ref().clone());
        job.new_home = Some(home.evidence().clone());
        job.progress.home_epoch = Some(home.epoch());
        job.progress.home_hash = Some(home.hash().into());
        job.progress.forward_until = Some(commit_proof.body.forward_until);
        job.progress.commit_deadline = Some(commit_proof.body.commit_deadline);
        job.progress.phase = MigrationPhase::CommitPending;
        job.progress.reason = None;
        job.recovery_blocked = true;
        job.clock_floor = job.clock_floor.max(now);
        self.advance(&mut job, prior)?;
        Ok(job.progress)
    }
    /// Persist `activate_sent` before returning the exact A proof; never activates on a timer.
    /// # Errors
    /// Refuses missing commit evidence, an incompatible fence or corrupt state.
    pub fn activation_evidence(&self, operation: &str) -> Result<wire::Evidence, SdkError> {
        let mut job = self.load(operation)?;
        if job.fence.is_some() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let commit =
            job.commit.clone().ok_or_else(|| refused(wire::Refusal::CommitOutcomeUnknown))?;
        let home = job.new_home.clone().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let evidence = wire::Evidence {
            authority: Some(job.authority.clone()),
            commit_proof: Some(commit),
            home_record: Some(home.record),
            authorization: job.authorization.clone(),
            offer: job.offer.clone(),
            seal_receipt: None,
            ..wire::Evidence::default()
        };
        let prior = job.progress.seq;
        job.progress.phase = MigrationPhase::ActivateSent;
        self.advance(&mut job, prior)?;
        Ok(evidence)
    }
    /// Only A's authorization-bound noncommit fence releases uncertainty.
    /// # Errors
    /// Rejects a wrong node/operation/authorization, future evidence and a conflicting commit.
    pub fn noncommit(
        &self,
        operation: &str,
        fence: wire::Signed<wire::NoncommitFence>,
        now: u64,
    ) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        crypto::verify_node(&fence, &job.progress.source, &job.source_key)?;
        let a =
            job.authorization.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        if fence.body.version != 1
            || fence.body.migration_id != operation
            || fence.body.authorization_hash != wire::message_hash(a)?
            || fence.body.fenced_at > now.max(job.clock_floor).saturating_add(wire::SKEW_SECONDS)
            || job.commit.is_some()
        {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        if let Some(prior) = &job.fence {
            if prior != &fence {
                return Err(refused(wire::Refusal::IdempotencyConflict));
            }
            return Ok(job.progress);
        }
        let prior = job.progress.seq;
        job.fence = Some(fence);
        job.recovery_blocked = false;
        job.progress.phase =
            if job.cancel_requested { MigrationPhase::Aborted } else { MigrationPhase::Expired };
        job.progress.reason = None;
        job.clock_floor = job.clock_floor.max(now);
        self.advance(&mut job, prior)?;
        Ok(job.progress)
    }
}
