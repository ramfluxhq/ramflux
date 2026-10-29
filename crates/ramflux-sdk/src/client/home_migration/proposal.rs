// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Proposal and signature plans cross the writer boundary without carrying a primary key.
use super::{HomeMigrationJournal, MigrationPhase, refused};
use crate::{
    SdkError,
    custody::{BornAccount, PrimaryVault},
};
use ramflux_protocol::{custody::object_hash, home_migration as wire};

/// Immutable, purpose-bound plan. Run `sign` outside the database writer and socket reader.
/// Successful presence is not installation: cancellation or changed authority invalidates it.
pub struct MigrationApprovalPlan {
    account: BornAccount,
    draft: wire::Authorization,
    digest: String,
    revision: u64,
}
/// Opaque result of the presence provider; only the journal may install it.
pub struct MigrationApprovalResult {
    authorization: wire::Signed<wire::Authorization>,
    control: wire::Signed<wire::Control>,
    digest: String,
    revision: u64,
}
impl MigrationApprovalPlan {
    #[must_use]
    pub fn proposal_digest(&self) -> &str {
        &self.digest
    }
    #[must_use]
    pub fn destination_fingerprint(&self) -> String {
        ramflux_protocol::hash_hex(
            ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
            self.draft.destination_key.as_bytes(),
        )
    }
    #[must_use]
    pub fn previous_home_hash(&self) -> &str {
        &self.draft.previous_home_hash
    }
    #[must_use]
    pub const fn next_home_epoch(&self) -> u64 {
        self.draft.next_home_epoch
    }
    /// # Errors
    /// Refuses missing presence, expired/stale authority and unavailable branch credentials.
    pub fn sign(
        self,
        vault: &dyn PrimaryVault,
        now: u64,
    ) -> Result<MigrationApprovalResult, SdkError> {
        let authorization =
            self.account.sign_migration_authorization(vault, &self.draft, &self.digest, now)?;
        let (_, credentials) = self.account.credentials(vault, &self.draft.actor.device_id, now)?;
        let payload = wire::SealPayload {
            authorization_hash: wire::message_hash(&authorization)?,
            offer_hash: self.draft.offer_hash.clone(),
        };
        let control = super::resume::sign_control(
            &self.account,
            &credentials.signing,
            super::resume::ControlPlan {
                action: wire::Action::Seal,
                audience: &self.draft.destination_node,
                operation: &self.draft.migration_id,
                payload_hash: ramflux_protocol::custody::framed_hash(
                    ramflux_protocol::domain::HOME_CONTROL,
                    &payload,
                )?,
                now,
            },
        )?;
        Ok(MigrationApprovalResult {
            authorization,
            control,
            digest: self.digest,
            revision: self.revision,
        })
    }
}
impl HomeMigrationJournal<'_> {
    /// Store the exact actor-signed Prepare before returning it for transmission.
    /// # Errors
    /// Rejects unsigned discovery, a different pinned node, stale actor/base or changed retry.
    pub fn prepare(
        &self,
        operation: &str,
        target: ramflux_protocol::WellKnownClientRecord,
        prepare: wire::Signed<wire::Prepare>,
        now: u64,
    ) -> Result<wire::Signed<wire::Prepare>, SdkError> {
        let mut job = self.load(operation)?;
        if let Some(prior) = &job.prepare {
            if prior == &prepare
                && job.target.as_ref() == Some(&target)
                && !job.cancel_requested
                && job.progress.phase == MigrationPhase::PrepareSent
            {
                return Ok(prior.clone());
            }
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        if job.progress.phase != MigrationPhase::Intent || job.cancel_requested {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let now = now.max(job.clock_floor);
        ramflux_protocol::verify_client_discovery_record(&target, now)?;
        if ramflux_protocol::hash_hex(
            ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
            target.node_public_key.as_bytes(),
        ) != job.intent.expected_node_fingerprint
        {
            return Err(refused(wire::Refusal::PinMismatch));
        }
        ramflux_crypto::home_migration::verify_actor(&prepare, self.account.verified(), now)?;
        let p = &prepare.body;
        let actor_certificate = self
            .account
            .record()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == job.actor.device_id)
            .and_then(|entry| entry.branch_certificate.as_ref())
            .ok_or_else(|| refused(wire::Refusal::ActorRevoked))?;
        if p.version != 1
            || p.migration_id != job.intent.operation_id
            || p.account_anchor != job.anchor
            || p.actor != job.actor
            || p.authority_record_hash != job.authority_hash
            || p.branch_certificate_hash != object_hash(actor_certificate)?
            || p.previous_home_hash
                != job
                    .progress
                    .home_hash
                    .clone()
                    .ok_or_else(|| refused(wire::Refusal::HomeGenesisRequired))?
            || Some(p.previous_home_epoch) != job.progress.home_epoch
            || p.old_node != job.progress.source
            || p.destination_node != target.node_id
            || p.destination_key != target.node_public_key
            || p.issued_at.abs_diff(now) > wire::SKEW_SECONDS
            || p.expires_at <= now
            || p.expires_at > p.issued_at.saturating_add(wire::MAX_SEAL_DELAY)
        {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        let prior = job.progress.seq;
        job.progress.target = Some(target.node_id.clone());
        job.target = Some(target);
        job.prepare = Some(prepare.clone());
        job.progress.phase = MigrationPhase::PrepareSent;
        job.clock_floor = now;
        self.advance(&mut job, prior)?;
        Ok(prepare)
    }
    /// Persist B's verified Offer and the exact unsigned proposal before any primary prompt.
    /// # Errors
    /// Rejects wrong destination, changed Prepare/base, expiry and unsupported offer policy.
    pub fn offer(
        &self,
        operation: &str,
        offer: wire::Signed<wire::Offer>,
        now: u64,
    ) -> Result<String, SdkError> {
        self.expire_offer(operation, now)?;
        let mut job = self.load(operation)?;
        if job.offer.as_ref() == Some(&offer)
            && !job.cancel_requested
            && job.progress.phase == MigrationPhase::AwaitingCustodyUnlock
        {
            return job.proposal_digest.ok_or_else(|| refused(wire::Refusal::StorageUnavailable));
        }
        if job.progress.phase != MigrationPhase::PrepareSent || job.cancel_requested {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        let now = now.max(job.clock_floor);
        let prepare =
            job.prepare.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        let target = job.target.as_ref().ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?;
        ramflux_crypto::home_migration::verify_node(
            &offer,
            &target.node_id,
            &target.node_public_key,
        )?;
        let expired = now > offer.body.accept_until;
        ramflux_crypto::home_migration::offer_bounds(
            &offer.body,
            if expired { offer.body.issued_at } else { now },
        )?;
        let o = &offer.body;
        let p = &prepare.body;
        if o.version != 1
            || o.migration_id != p.migration_id
            || o.account_anchor != p.account_anchor
            || o.prepare_hash != wire::message_hash(prepare)?
            || o.authority_record_hash != p.authority_record_hash
            || o.previous_home_hash != p.previous_home_hash
            || p.previous_home_epoch.checked_add(1) != Some(o.next_home_epoch)
            || o.old_node != p.old_node
            || o.destination_node != p.destination_node
            || o.destination_key != p.destination_key
            || o.discovery_hash != p.discovery_hash
            || o.delivery_map_hash != p.delivery_map_hash
            || o.gateway_tcp_addr != target.gateway_tcp_addr
        {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        if object_hash(self.account.record())? != job.authority_hash {
            return Err(refused(wire::Refusal::AuthorityUpdateRequired));
        }
        if expired {
            let prior = job.progress.seq;
            job.offer = Some(offer);
            job.progress.phase = MigrationPhase::Expired;
            job.progress.reason = Some(wire::Refusal::AdmissionExpired);
            job.clock_floor = now;
            self.advance(&mut job, prior)?;
            return Err(refused(wire::Refusal::AdmissionExpired));
        }
        let draft = wire::Authorization {
            version: 1,
            migration_id: p.migration_id.clone(),
            account_anchor: p.account_anchor.clone(),
            actor: p.actor.clone(),
            authority_record_hash: p.authority_record_hash.clone(),
            management_certificate_hash: object_hash(
                &self.account.record().body.master_certificate,
            )?,
            previous_home_hash: p.previous_home_hash.clone(),
            next_home_epoch: o.next_home_epoch,
            old_node: o.old_node.clone(),
            destination_node: o.destination_node.clone(),
            destination_key: o.destination_key.clone(),
            gateway_tcp_addr: o.gateway_tcp_addr.clone(),
            offer_hash: wire::message_hash(&offer)?,
            delivery_map_hash: o.delivery_map_hash.clone(),
            nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            issued_at: now,
            seal_until: o.accept_until.min(now.saturating_add(wire::MAX_SEAL_DELAY)),
            max_commit_delay: o.max_commit_delay,
            forward_seconds: o.forward_seconds,
        };
        let digest = crate::custody::home_authorization::proposal_digest(&draft)?;
        let prior = job.progress.seq;
        job.offer = Some(offer);
        job.draft = Some(draft);
        job.proposal_digest = Some(digest.clone());
        job.progress.phase = MigrationPhase::AwaitingCustodyUnlock;
        job.clock_floor = now;
        self.advance(&mut job, prior)?;
        Ok(digest)
    }
    /// Extract a non-clonable signing plan without holding a SQL transaction over OS presence.
    /// # Errors
    /// Refuses a changed digest, terminal/cancelled operation or another authority snapshot.
    pub fn approval_plan(
        &self,
        operation: &str,
        digest: &str,
    ) -> Result<MigrationApprovalPlan, SdkError> {
        let job = self.load(operation)?;
        if job.progress.phase != MigrationPhase::AwaitingCustodyUnlock
            || job.cancel_requested
            || job.proposal_digest.as_deref() != Some(digest)
            || object_hash(self.account.record())? != job.authority_hash
        {
            return Err(refused(wire::Refusal::CustodyApprovalRequired));
        }
        Ok(MigrationApprovalPlan {
            account: self.account.clone(),
            draft: job.draft.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))?,
            digest: digest.into(),
            revision: job.progress.seq,
        })
    }
    /// Revalidate the returned signature and persist `seal_sent` before handing it to transport.
    /// # Errors
    /// Rejects cancellation during the prompt, changed authority/proposal, stale or reused plans.
    pub fn authorize(
        &self,
        result: MigrationApprovalResult,
        now: u64,
    ) -> Result<wire::Signed<wire::Authorization>, SdkError> {
        let id = &result.authorization.body.migration_id;
        self.expire_offer(id, now)?;
        let mut job = self.load(id)?;
        let now = now.max(job.clock_floor);
        if job.progress.seq != result.revision
            || job.progress.phase != MigrationPhase::AwaitingCustodyUnlock
            || job.cancel_requested
            || job.proposal_digest.as_deref() != Some(&result.digest)
            || job.draft.as_ref() != Some(&result.authorization.body)
            || now > result.authorization.body.seal_until
        {
            return Err(refused(wire::Refusal::CustodyApprovalRequired));
        }
        ramflux_crypto::home_migration::verify_authorization(
            &result.authorization,
            self.account.verified(),
            now,
        )?;
        let prior = job.progress.seq;
        job.authorization = Some(result.authorization.clone());
        job.seal_control = Some(result.control);
        job.progress.phase = MigrationPhase::SealSent;
        job.recovery_blocked = true;
        job.clock_floor = now;
        job.next_attempt_at = now;
        self.advance(&mut job, prior)?;
        Ok(result.authorization)
    }
}
