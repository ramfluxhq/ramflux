// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Centre authority lives with the witness. The private daemon receives no publication permit.
use super::{
    CheckpointError, CheckpointHead, CheckpointWitness, MutationPhase, Result, ServingFence,
    VerifiedReporter, WriterIdentity,
    image::{ImagePlan, skeleton},
    transitions::{self, ensure},
};
use ramflux_crypto::username_directory as crypto;
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};

pub struct DirectoryAuthority {
    pub(super) witness: CheckpointWitness,
    pub(super) fence: ServingFence,
}

impl DirectoryAuthority {
    /// A storage handle must already have passed protected initialization/open checks.
    /// # Errors
    /// Refuses unavailable boot randomness. Every restart creates a new fenced boot identity.
    pub fn new(witness: CheckpointWitness) -> Result<Self> {
        Ok(Self { fence: ServingFence::new(witness.head().generation)?, witness })
    }

    #[must_use]
    pub fn head(&self) -> CheckpointHead {
        self.witness.head()
    }

    /// # Errors
    /// Refuses occupied leases and unsafe clock state.
    pub fn acquire(&mut self) -> Result<WriterIdentity> {
        self.fence.acquire(self.witness.sample_time()?)
    }

    /// # Errors
    /// Refuses retired/expired writer identities.
    pub fn renew(&mut self, writer: &WriterIdentity) -> Result<()> {
        self.fence.renew(writer, self.witness.sample_time()?)
    }

    pub fn disconnect(&mut self) {
        self.fence.disconnect();
    }

    /// Must be called after actual primary fsync by the current authenticated writer.
    /// # Errors
    /// Refuses callbacks from retired boots/writers and unmatched primary heads.
    pub fn primary_applied(
        &mut self,
        writer: &WriterIdentity,
        primary: &CheckpointHead,
    ) -> Result<()> {
        self.fence.primary_applied(
            writer,
            primary,
            &self.witness.head(),
            self.witness.sample_time()?,
        )
    }

    /// Generate and durably apply one operation transition. Success here is a private candidate,
    /// not a home/SDK ACK; the primary fsync and live publication gate are still mandatory.
    /// # Errors
    /// Refuses stale authority, signatures, profile substitutions, collisions, holds and quotas.
    pub fn mutate(
        &mut self,
        writer: &WriterIdentity,
        reporter: &VerifiedReporter,
        phase: MutationPhase,
        operation: &w::UsernameOperation,
        profile: Option<&w::SignedIdentityProfileV2>,
    ) -> Result<CheckpointHead> {
        let time = self.witness.sample_time()?;
        self.fence.check_ready(writer, &self.head(), time)?;
        ensure(time.wall < reporter.expires_at, Code::AuthenticationRequired)?;
        crypto::verify_operation(&reporter.master, operation)?;
        ensure(operation.body.principal_commitment == reporter.root, Code::OwnershipMismatch)?;
        if operation.body.action == w::Action::Delete
            && self.preempt_delete_if_needed(writer, reporter, phase, operation, profile)?
        {
            return Ok(self.head());
        }
        ensure(
            operation.body.issued_at <= time.wall && time.wall < operation.body.expires_at,
            Code::Replay,
        )?;
        let mut plan = ImagePlan::new(&self.witness.db);
        let key = transitions::operation_key(operation);
        let operation_hash = crypto::operation_hash(operation)?;
        if let Some(previous) = plan.operation(&key)? {
            ensure(
                previous.operation_hash == operation_hash && previous.operation == *operation,
                Code::Replay,
            )?;
            let complete = match phase {
                MutationPhase::Reserve => true,
                MutationPhase::Commit => previous.state == w::ReceiptState::Committed,
                MutationPhase::Abort => previous.state == w::ReceiptState::Aborted,
            };
            if complete {
                return Ok(self.witness.head());
            }
        } else if let Some(root) = plan.root(&reporter.root)?
            && root.last_operation_id.as_ref() == Some(&operation.body.operation_id)
        {
            ensure(root.last_operation_hash.as_ref() == Some(&operation_hash), Code::Replay)?;
            return Ok(self.witness.head());
        }
        let current_profile = plan.root(&reporter.root)?.map(|row| row.profile);
        verify_profile(reporter, operation, profile, current_profile.as_ref())?;
        let kind = match phase {
            MutationPhase::Reserve => {
                let details = plan.detail_count(&reporter.root)?;
                let held = operation
                    .body
                    .binding
                    .as_ref()
                    .map(|b| skeleton(&b.body.name))
                    .transpose()?
                    .map(|s| plan.held_skeleton(&s))
                    .transpose()?
                    .flatten();
                transitions::reserve(
                    &mut plan,
                    reporter,
                    operation,
                    time.wall,
                    details,
                    held.as_ref(),
                )?;
                w::DeltaKind::Reserve
            }
            MutationPhase::Commit => {
                transitions::commit(&mut plan, reporter, operation, time.wall)?;
                w::DeltaKind::Commit
            }
            MutationPhase::Abort => {
                transitions::abort(
                    &mut plan,
                    &reporter.root,
                    &operation.body.operation_id,
                    time.wall,
                )?;
                w::DeltaKind::Abort
            }
        };
        let tx_id = super::transport::digest(&(operation_hash, phase))?;
        let delta = w::CheckpointDelta {
            kind,
            tx_id,
            writer_incarnation: writer.incarnation.clone(),
            clock_floor: time.wall,
            operation: if phase == MutationPhase::Abort { None } else { Some(operation.clone()) },
            rows: plan.finish(),
        };
        let expected = self.witness.head();
        self.witness.append_at(
            &expected,
            delta,
            &reporter.root,
            operation.body.action == w::Action::Delete,
            time,
        )?;
        self.fence.advancing_head();
        Ok(self.witness.head())
    }

    /// Read current root state from the product authority image, not cached receipts or the caller.
    /// # Errors
    /// Refuses malformed roots and unavailable/corrupt image storage.
    pub fn current_root(&self, root: &str) -> Result<Option<w::RootRow>> {
        super::fixed(root)?;
        ImagePlan::new(&self.witness.db).root(root)
    }

    /// Current committed receipt facts survive latest-detail GC and redo compaction.
    /// The publication owner alone signs/finalizes their release expiry.
    /// # Errors
    /// Refuses an uncommitted root or missing retained decision/result fields.
    pub(crate) fn receipt_body(&self, root_key: &str, now: u64) -> Result<w::DirectoryReceiptBody> {
        let root =
            self.current_root(root_key)?.ok_or(CheckpointError::Directory(Code::NotFound))?;
        ensure(root.epoch > 0, Code::NotFound)?;
        Ok(w::DirectoryReceiptBody {
            center_id: self.head().center_id,
            principal_commitment: root_key.into(),
            operation_id: root
                .last_operation_id
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?,
            operation_hash: root
                .last_operation_hash
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?,
            epoch: root.epoch,
            state: w::ReceiptState::Committed,
            binding_hash: root.binding_hash,
            profile: root.profile,
            discoverable: root.discoverable,
            committed_at: root
                .receipt_decision
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?
                .committed_at,
            expires_at: transitions::after(now, 60)?,
        })
    }
}

pub(super) fn verify_profile(
    reporter: &VerifiedReporter,
    operation: &w::UsernameOperation,
    profile: Option<&w::SignedIdentityProfileV2>,
    current_profile: Option<&w::ProfileRef>,
) -> Result<()> {
    if let Some(profile) = profile {
        crypto::verify_profile(&reporter.master, profile)?;
        let native = &reporter.history.evidence().authority.record.body;
        ensure(
            profile.body.principal_id == native.principal_id
                && profile.body.display_name == native.profile.display_name
                && profile.body.kind == w::ProfileKind::from_principal_kind(native.principal_kind),
            Code::InvalidProfile,
        )?;
        ensure(profile.body.avatar.is_none(), Code::InvalidAvatar)?;
        ensure(
            profile.body.principal_commitment == reporter.root
                && operation.body.profile.version == 2
                && operation.body.profile.epoch == profile.body.epoch
                && operation.body.profile.hash.as_ref() == Some(&crypto::profile_hash_v2(profile)?),
            Code::InvalidProfile,
        )?;
    } else {
        ensure(current_profile == Some(&operation.body.profile), Code::InvalidProfile)?;
    }
    Ok(())
}
