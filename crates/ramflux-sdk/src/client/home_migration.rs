// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned migration journal. Persisted plans precede all external effects.
mod model;
mod outcomes;
mod proposal;
use crate::{SdkError, custody::BornAccount};
use model::Job;
pub use model::{MigrationIntent, MigrationPhase, MigrationProgress};
pub use proposal::{MigrationApprovalPlan, MigrationApprovalResult};
use ramflux_protocol::{
    custody::{CustodyKind, DeviceRef, object_hash},
    home_migration as wire,
};
use ramflux_storage::{AccountDb, HomeMigrationWrite};

fn refused(reason: wire::Refusal) -> SdkError {
    SdkError::HomeMigrationRefused(reason)
}
fn digest(value: &str) -> bool {
    ramflux_protocol::decode_base64url(value)
        .is_ok_and(|b| b.len() == 32 && ramflux_protocol::encode_base64url(b) == value)
}
fn intent_hash(intent: &MigrationIntent) -> Result<String, SdkError> {
    Ok(ramflux_protocol::custody::framed_hash("ramflux.sdk.home_migration.intent.v1", intent)?)
}
/// Uses the account's existing encrypted FULL-synchronous writer. No network or OS prompt
/// runs inside its transactions. The caller owns account serialization and reconnect work.
pub struct HomeMigrationJournal<'a> {
    db: &'a AccountDb,
    account: &'a BornAccount,
}
impl<'a> HomeMigrationJournal<'a> {
    /// # Errors
    /// Refuses nonhuman, legacy, mismatched or unbound account databases.
    pub fn new(
        db: &'a AccountDb,
        index: &ramflux_storage::AccountIndex,
        account: &'a BornAccount,
    ) -> Result<Self, SdkError> {
        let body = &account.record().body;
        let indexed = index.account(account.local_account_id())?;
        if indexed.principal_commitment != body.account_anchor
            || db.path.canonicalize()?
                != index.root().join(indexed.db_relative_path).canonicalize()?
        {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        if db.local_account_id != account.local_account_id()
            || body.principal_kind != ramflux_protocol::PrincipalKind::Human
            || body.master_certificate.body.custody_kind != CustodyKind::LocalHuman
        {
            return Err(refused(wire::Refusal::V3Required));
        }
        Ok(Self { db, account })
    }
    /// Start only from an independently authenticated source home; retries cannot change intent.
    /// # Errors
    /// Rejects changed business identity, missing source evidence, bad pins and concurrent jobs.
    pub fn begin(
        &self,
        intent: MigrationIntent,
        actor: DeviceRef,
        home: &ramflux_crypto::home_migration::VerifiedHome,
        now: u64,
    ) -> Result<MigrationProgress, SdkError> {
        let url = reqwest::Url::parse(&intent.target_discovery_url)
            .map_err(|_| refused(wire::Refusal::PinMismatch))?;
        if !digest(&intent.operation_id)
            || intent.target_discovery_url.len() > 2048
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || intent.expected_node_fingerprint.len() != 64
            || !intent
                .expected_node_fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || now > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        {
            return Err(refused(wire::Refusal::PinMismatch));
        }
        let anchor = &self.account.record().body.account_anchor;
        if &actor.account_anchor != anchor || home.evidence().record.account_anchor() != anchor {
            return Err(refused(wire::Refusal::BaseMismatch));
        }
        self.account.verified().authorize(&actor, "register", now)?;
        if let Some(old) = self.load_optional(&intent.operation_id)? {
            if old.intent != intent || old.actor != actor {
                return Err(refused(wire::Refusal::IdempotencyConflict));
            }
            return Ok(old.progress);
        }
        if self.db.active_home_migration()?.is_some() {
            return Err(refused(wire::Refusal::MigrationInProgress));
        }
        let progress = MigrationProgress {
            operation_id: intent.operation_id.clone(),
            seq: 1,
            phase: MigrationPhase::Intent,
            source: home.home().0.into(),
            target: None,
            home_epoch: Some(home.epoch()),
            home_hash: Some(home.hash().into()),
            commit_deadline: None,
            forward_until: None,
            backlog: wire::BacklogProgress::default(),
            reason: None,
        };
        let job = Job {
            version: 1,
            intent_hash: intent_hash(&intent)?,
            intent,
            anchor: anchor.clone(),
            authority_hash: object_hash(self.account.record())?,
            actor,
            source_key: home.home().1.into(),
            progress,
            recovery_blocked: false,
            cancel_requested: false,
            clock_floor: now,
            attempts: 0,
            next_attempt_at: now,
            target: None,
            prepare: None,
            offer: None,
            draft: None,
            proposal_digest: None,
            authorization: None,
            seal: None,
            commit: None,
            fence: None,
            new_home: None,
        };
        self.save(&job, None)?;
        Ok(job.progress)
    }
    /// # Errors
    /// Returns a typed refusal for a missing/corrupt operation or another account's job.
    pub fn status(&self, operation: &str) -> Result<MigrationProgress, SdkError> {
        Ok(self.load(operation)?.progress)
    }
    /// A post-seal cancellation is a durable request to A, never a local rollback.
    /// # Errors
    /// Refuses a committed operation; persistence failure leaves the prior state intact.
    pub fn cancel(&self, operation: &str, now: u64) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        if job.commit.is_some() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        if job.progress.phase.terminal() || job.cancel_requested {
            return Ok(job.progress);
        }
        let prior = job.progress.seq;
        job.cancel_requested = true;
        job.clock_floor = job.clock_floor.max(now);
        job.next_attempt_at = job.clock_floor;
        if job.recovery_blocked {
            job.progress.phase = MigrationPhase::NeedsAttention;
            job.progress.reason = Some(wire::Refusal::CommitOutcomeUnknown);
        } else {
            job.progress.phase = MigrationPhase::Aborted;
        }
        self.advance(&mut job, prior)?;
        Ok(job.progress)
    }
    /// A cancellation action includes the original Authorization even if B never replied.
    /// This only constructs a plan; the scoped control transport must authenticate it to A.
    /// # Errors
    /// Rejects calls before cancellation or with no uncertain seal attempt.
    pub fn cancellation_authorization(
        &self,
        operation: &str,
    ) -> Result<wire::Signed<wire::Authorization>, SdkError> {
        let job = self.load(operation)?;
        if !job.cancel_requested || !job.recovery_blocked || job.commit.is_some() {
            return Err(refused(wire::Refusal::IdempotencyConflict));
        }
        job.authorization.ok_or_else(|| refused(wire::Refusal::CustodyApprovalRequired))
    }
    /// Persist a bounded retry deadline. Timeouts never select a new home or release the guard.
    /// # Errors
    /// Rejects terminal/not-yet-due jobs, unsafe clocks and persistence conflicts.
    pub fn retry_later(&self, operation: &str, now: u64) -> Result<MigrationProgress, SdkError> {
        let mut job = self.load(operation)?;
        let now = now.max(job.clock_floor);
        if job.progress.phase.terminal() || now < job.next_attempt_at {
            return Err(refused(wire::Refusal::RateLimited));
        }
        let prior = job.progress.seq;
        job.attempts = job.attempts.saturating_add(1);
        job.clock_floor = now;
        job.next_attempt_at = now
            .checked_add((1_u64 << job.attempts.min(6)).min(60))
            .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| refused(wire::Refusal::StorageUnavailable))?;
        if job.recovery_blocked {
            job.progress.phase = MigrationPhase::NeedsAttention;
            job.progress.reason = Some(wire::Refusal::CommitOutcomeUnknown);
        }
        self.advance(&mut job, prior)?;
        Ok(job.progress)
    }
    /// # Errors
    /// Fails closed on a corrupt journal. Data unlock alone cannot override this guard.
    pub fn require_recovery_allowed(&self) -> Result<(), SdkError> {
        if let Some(row) = self.db.active_home_migration()? {
            let job = self.decode(&row)?;
            if job.recovery_blocked {
                return Err(refused(wire::Refusal::MigrationInProgress));
            }
        }
        Ok(())
    }
    fn load_optional(&self, id: &str) -> Result<Option<Job>, SdkError> {
        self.db.home_migration_job(id)?.map(|r| self.decode(&r)).transpose()
    }
    fn load(&self, id: &str) -> Result<Job, SdkError> {
        self.load_optional(id)?.ok_or_else(|| refused(wire::Refusal::EvidenceRequired))
    }
    fn decode(&self, row: &ramflux_storage::HomeMigrationStateRow) -> Result<Job, SdkError> {
        let job: Job = serde_json::from_slice(&row.state)?;
        if job.version != 1
            || row.operation_id != job.intent.operation_id
            || row.account_anchor != job.anchor
            || job.anchor != self.account.record().body.account_anchor
            || row.intent_hash != intent_hash(&job.intent)?
            || job.intent_hash != row.intent_hash
            || row.revision != job.progress.seq
            || row.active == job.progress.phase.terminal()
            || row.recovery_blocked != job.recovery_blocked
            || row.next_attempt_at != job.next_attempt_at
            || row.progress != serde_json::to_value(&job.progress)?
        {
            return Err(refused(wire::Refusal::StorageUnavailable));
        }
        Ok(job)
    }
    fn save(&self, job: &Job, expected: Option<u64>) -> Result<(), SdkError> {
        self.db.persist_home_migration(HomeMigrationWrite {
            operation_id: &job.intent.operation_id,
            account_anchor: &job.anchor,
            intent_hash: &job.intent_hash,
            expected_revision: expected,
            revision: job.progress.seq,
            active: !job.progress.phase.terminal(),
            recovery_blocked: job.recovery_blocked,
            next_attempt_at: job.next_attempt_at,
            state: &serde_json::to_vec(job)?,
            progress: &serde_json::to_value(&job.progress)?,
        })?;
        Ok(())
    }
    fn advance(&self, job: &mut Job, prior: u64) -> Result<(), SdkError> {
        job.progress.seq =
            prior.checked_add(1).ok_or_else(|| refused(wire::Refusal::StorageUnavailable))?;
        self.save(job, Some(prior))
    }
}

impl crate::RamfluxClient {
    /// Start a durable migration of the currently selected born-v3 account.
    /// # Errors
    /// Rejects legacy/locked accounts, unverified homes and conflicting durable intent.
    pub fn migrate_home_node(
        &self,
        intent: MigrationIntent,
        actor: DeviceRef,
        home: &ramflux_crypto::home_migration::VerifiedHome,
        now: u64,
    ) -> Result<MigrationProgress, SdkError> {
        let account =
            self.born_v3_account.as_deref().ok_or_else(|| refused(wire::Refusal::V3Required))?;
        HomeMigrationJournal::new(self.account_db()?, self.account_index()?, account)?
            .begin(intent, actor, home, now)
    }
}
#[cfg(test)]
mod tests;
