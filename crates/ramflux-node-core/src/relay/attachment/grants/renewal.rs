// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Source-side renewal challenges and the atomic renewal admission (P25 N3).
//! A challenge is single use and is consumed in the SAME write transaction that
//! consumes the requester's renewal nonce. Nothing here activates an endpoint.
use super::{
    AttachmentLedgerError, AttachmentOwner, AttachmentRegistrationReceipt, AttachmentReplayError,
    AttachmentReplayProof, AttachmentReservation, AttachmentReservationState, GRANTS,
    GrantPublicationLease, RECORDS, ReadableTable, RegisteredAttachmentGrant, ScopedGrantRegistry,
    ScopedGrantState, TableDefinition, VerifiedScopedGrant, clock, decode, encode, key, replay,
    store,
};
use ramflux_protocol::large_attachment::{
    AttachmentOperation, QualifiedOwner, ScopedAttachmentGrant, requester_digest,
};
use serde::{Deserialize, Serialize};

const CHALLENGES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_renewal_challenges_v1");
/// Challenge lifetime in seconds.
pub const CHALLENGE_TTL: u64 = 30;
/// Maximum age of a home verdict at the relay, in seconds.
pub const VERDICT_MAX_AGE: u64 = 60;
const GC_SKEW: u64 = 5;
const GC_PAGE: usize = 64;
const RENEW_RIGHT: u32 = 8;

/// Typed refusals shared by every hop. `Invalid` (malformed input) and `Storage`
/// (fail-closed ledger failure) are the only additions to the design list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RenewalRefusal {
    #[error("proof nonce already consumed")]
    Replay,
    #[error("expired")]
    Expired,
    #[error("challenge unknown")]
    ChallengeUnknown,
    #[error("challenge already consumed")]
    ChallengeConsumed,
    #[error("challenge does not match the request")]
    ChallengeMismatch,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("grant is not active")]
    GrantNotActive,
    #[error("payload generation mismatch")]
    PayloadGenerationMismatch,
    #[error("authority generation mismatch")]
    AuthorityGenerationMismatch,
    #[error("target invalid")]
    TargetInvalid,
    #[error("rights insufficient")]
    RightsInsufficient,
    #[error("home mismatch")]
    HomeMismatch,
    #[error("home trust unavailable")]
    HomeTrustUnavailable,
    #[error("capability unavailable")]
    CapabilityUnavailable,
    #[error("capability invalid")]
    CapabilityInvalid,
    #[error("source unknown")]
    SourceUnknown,
    #[error("replay protection capacity exceeded")]
    ReplayProtectionCapacity,
    #[error("clock uncertain")]
    ClockUncertain,
    #[error("busy")]
    Busy,
    #[error("malformed or invalid input")]
    Invalid,
    #[error("storage failure")]
    Storage,
}

impl From<AttachmentLedgerError> for RenewalRefusal {
    fn from(error: AttachmentLedgerError) -> Self {
        match error {
            AttachmentLedgerError::Capacity => Self::Busy,
            AttachmentLedgerError::Expired => Self::Expired,
            _ => Self::Storage,
        }
    }
}
impl From<AttachmentReplayError> for RenewalRefusal {
    fn from(error: AttachmentReplayError) -> Self {
        match error {
            AttachmentReplayError::Invalid => Self::Invalid,
            AttachmentReplayError::Expired => Self::Expired,
            AttachmentReplayError::Replay => Self::Replay,
            AttachmentReplayError::ReplayProtectionCapacity => Self::ReplayProtectionCapacity,
            AttachmentReplayError::ClockUncertain => Self::ClockUncertain,
            AttachmentReplayError::Ledger(e) => e.into(),
        }
    }
}
/// Classifies refusals raised before the admission transaction opens.
fn lease_error(error: AttachmentLedgerError) -> RenewalRefusal {
    match error {
        AttachmentLedgerError::Conflict => RenewalRefusal::RightsInsufficient,
        AttachmentLedgerError::State => RenewalRefusal::GrantNotActive,
        other => other.into(),
    }
}

/// Node-configured audiences. Both come from node configuration, never a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalPolicy {
    /// Relay origin that Otarget must name as its audience.
    pub relay_audience: String,
    /// Configured token issuer: `W.source_issuer`, `Orenew.audience` and `T.token_issuer`.
    pub token_issuer: String,
}

/// Current-home verdict computed by the source router (N5a owns the computation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeVerdict {
    pub account_anchor: String,
    pub home_node: String,
    pub home_node_key: [u8; 32],
    pub home_epoch: u64,
    pub home_record_hash: [u8; 32],
    pub checked_at: u64,
}

/// Challenge bootstrap input: no W exists yet, so nothing here is attested.
pub struct ChallengeMint<'a> {
    /// Complete registered capability, `RFC1 || LP(G) || LP(sig) || LP(receipt)`.
    pub capability: &'a [u8],
    pub target_operation: &'a [u8],
    pub requester: &'a QualifiedOwner,
    pub home_node: &'a str,
    pub peer_node: &'a str,
    pub verdict: &'a HomeVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalChallenge {
    pub challenge: [u8; 32],
    pub authority_generation: u64,
    pub expires_at: u64,
}

/// Everything the admission transaction compares against the challenge row.
pub struct RenewalAdmission<'a> {
    pub grant: &'a VerifiedScopedGrant,
    pub challenge: [u8; 32],
    /// Htarget, the hash of the parsed Otarget.
    pub target_hash: [u8; 32],
    pub requester: &'a QualifiedOwner,
    /// `W.home_issuer`, which the caller has already equated with the TLS peer.
    pub home_node: &'a str,
    pub home_epoch: u64,
    pub payload_generation: u64,
    pub authority_generation: u64,
    pub w_expires_at: u64,
    pub proof: &'a AttachmentReplayProof,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRow {
    grant_id: [u8; 32],
    grant_epoch: u64,
    grant_hash: [u8; 32],
    target_hash: [u8; 32],
    requester: [u8; 32],
    home_node: String,
    home_epoch: u64,
    authority_generation: u64,
    expires_at: u64,
    consumed: bool,
}

#[derive(Clone, Copy)]
pub(super) struct Caps {
    pub global: usize,
    pub per_home: usize,
    pub per_requester: usize,
}
impl Default for Caps {
    fn default() -> Self {
        Self { global: 4096, per_home: 64, per_requester: 4 }
    }
}

pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let _ = tx.open_table(CHALLENGES).map_err(store)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test fault: fail the admission after the challenge update, before the nonce.
    pub(super) static FAIL_AFTER_CHALLENGE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn target_right(op: u32) -> u32 {
    1 << (op - 1)
}

impl ScopedGrantRegistry {
    /// Core-side Otarget validation (r4 section 10): GET/HEAD/Missing only, the
    /// configured relay audience, exact grant binding, generation, rights and time.
    /// # Errors
    /// Returns the typed refusal for the first failed check.
    pub fn check_renewal_target(
        &self,
        policy: &RenewalPolicy,
        g: &ScopedAttachmentGrant,
        target: &AttachmentOperation,
        now: u64,
    ) -> Result<(), RenewalRefusal> {
        if !matches!(target.op, 1..=3)
            || target.audience != policy.relay_audience
            || target.object_id != g.object_id
            || target.manifest_hash != g.manifest_hash
            || target.grant_id != g.grant_id
            || target.grant_epoch != g.epoch
        {
            return Err(RenewalRefusal::TargetInvalid);
        }
        if target.authority_generation != self.authority.generation {
            return Err(RenewalRefusal::AuthorityGenerationMismatch);
        }
        let need = RENEW_RIGHT | target_right(target.op);
        if g.rights & need != need {
            return Err(RenewalRefusal::RightsInsufficient);
        }
        if now.saturating_add(5) < g.issued_at || now >= g.expires_at {
            return Err(RenewalRefusal::Expired);
        }
        Ok(())
    }

    /// Mints one single-use challenge bound to the exact grant, target, requester,
    /// home and authority generation. Inserts nothing on any refusal.
    /// # Errors
    /// Returns the typed refusal; capacity and clock failures insert nothing.
    pub fn mint_renewal_challenge(
        &self,
        policy: &RenewalPolicy,
        request: &ChallengeMint<'_>,
        now: u64,
    ) -> Result<RenewalChallenge, RenewalRefusal> {
        let challenge = ramflux_crypto::random_32().map_err(|_| RenewalRefusal::Storage)?;
        self.mint_with(policy, request, challenge, now, Caps::default())
    }

    pub(super) fn mint_with(
        &self,
        policy: &RenewalPolicy,
        request: &ChallengeMint<'_>,
        challenge: [u8; 32],
        now: u64,
        caps: Caps,
    ) -> Result<RenewalChallenge, RenewalRefusal> {
        let a = &self.authority;
        let (grant, _) = AttachmentRegistrationReceipt::decode_capability(
            request.capability,
            &a.source,
            a.generation,
            &a.signing_public_key,
            now,
        )
        .map_err(|_| RenewalRefusal::CapabilityInvalid)?;
        let g = grant.grant();
        let row = self.lookup(&g.grant_id)?.ok_or(RenewalRefusal::CapabilityInvalid)?;
        if row.state != ScopedGrantState::Active {
            return Err(RenewalRefusal::GrantNotActive);
        }
        if row.capability != ramflux_protocol::encode_base64url(request.capability) {
            return Err(RenewalRefusal::CapabilityInvalid);
        }
        self.current(&grant, now).map_err(lease_error)?;
        if request.requester != &g.grantee {
            return Err(RenewalRefusal::ChallengeMismatch);
        }
        let v = request.verdict;
        if request.home_node != request.peer_node
            || request.home_node != g.grantee.home_node_id
            || request.home_node != v.home_node
            || v.account_anchor != g.grantee.account_anchor
        {
            return Err(RenewalRefusal::HomeMismatch);
        }
        if now.saturating_sub(v.checked_at) > VERDICT_MAX_AGE
            || v.checked_at > now.saturating_add(5)
            || ed25519_dalek::VerifyingKey::from_bytes(&v.home_node_key).is_err()
        {
            return Err(RenewalRefusal::HomeTrustUnavailable);
        }
        let target = AttachmentOperation::decode(request.target_operation)
            .map_err(|_| RenewalRefusal::TargetInvalid)?;
        self.check_renewal_target(policy, g, &target, now)?;
        let digest = requester_digest(request.requester).map_err(|_| RenewalRefusal::Invalid)?;
        let target_hash = target.hash().map_err(|_| RenewalRefusal::TargetInvalid)?;
        let tx = self.ledger.db.begin_write().map_err(store)?;
        let effective = replay::fence_clock(&tx, now)?;
        clock(&tx, effective)?;
        if Self::committed_generation(&tx, g, &row, effective)? != Some(target.payload_generation) {
            return Err(RenewalRefusal::PayloadGenerationMismatch);
        }
        let expires_at = effective.checked_add(CHALLENGE_TTL).ok_or(RenewalRefusal::Invalid)?;
        {
            let mut table = tx.open_table(CHALLENGES).map_err(store)?;
            gc_rows(&mut table, effective, GC_PAGE)?;
            let (mut total, mut home, mut same) = (0_usize, 0_usize, 0_usize);
            for entry in table.iter().map_err(store)? {
                let (_, value) = entry.map_err(store)?;
                let old: ChallengeRow = decode(value.value())?;
                total += 1;
                home += usize::from(old.home_node == request.home_node);
                same += usize::from(old.requester == digest);
            }
            if total >= caps.global || home >= caps.per_home || same >= caps.per_requester {
                return Err(RenewalRefusal::ReplayProtectionCapacity);
            }
            if table.get(challenge.as_slice()).map_err(store)?.is_some() {
                return Err(RenewalRefusal::Busy);
            }
            let row = ChallengeRow {
                grant_id: g.grant_id,
                grant_epoch: g.epoch,
                grant_hash: g.hash().map_err(|_| RenewalRefusal::Invalid)?,
                target_hash,
                requester: digest,
                home_node: request.home_node.into(),
                home_epoch: v.home_epoch,
                authority_generation: a.generation,
                expires_at,
                consumed: false,
            };
            table.insert(challenge.as_slice(), encode(&row)?.as_slice()).map_err(store)?;
        }
        tx.commit().map_err(store)?;
        Ok(RenewalChallenge { challenge, authority_generation: a.generation, expires_at })
    }

    /// Reclaims at most 64 challenge rows whose expiry plus 5 s skew has passed.
    /// # Errors
    /// Refuses invalid page limits and clock rollback.
    pub fn gc_renewal_challenges(&self, now: u64, limit: usize) -> Result<usize, RenewalRefusal> {
        if limit == 0 || limit > GC_PAGE {
            return Err(RenewalRefusal::Invalid);
        }
        let tx = self.ledger.db.begin_write().map_err(store)?;
        let effective = replay::fence_clock(&tx, now)?;
        let count = {
            let mut table = tx.open_table(CHALLENGES).map_err(store)?;
            gc_rows(&mut table, effective, limit)?
        };
        tx.commit().map_err(store)?;
        Ok(count)
    }

    /// Reads the payload generation committed for the grant's upload, in `tx`.
    /// An expired, uncommitted or substituted payload is refused as `Expired`.
    fn committed_generation(
        tx: &redb::WriteTransaction,
        g: &ScopedAttachmentGrant,
        row: &RegisteredAttachmentGrant,
        now: u64,
    ) -> Result<Option<u64>, RenewalRefusal> {
        let owner = AttachmentOwner::from_authenticated_session(&g.owner.account_anchor)?;
        let table = tx.open_table(RECORDS).map_err(store)?;
        let value = table
            .get(key(&owner, &row.upload_id).as_slice())
            .map_err(store)?
            .ok_or(RenewalRefusal::GrantNotActive)?;
        let payload: AttachmentReservation = decode(value.value())?;
        if payload.state != AttachmentReservationState::Committed
            || payload.object_id != g.object_id
            || payload.manifest_hash != Some(g.manifest_hash)
            || payload.expires_at.is_none_or(|t| now >= t)
            || now >= row.expires_at
        {
            return Err(RenewalRefusal::Expired);
        }
        // Shared helper: a legacy-zero or unbound payload never admits (N-alpha r2).
        payload
            .require_bound_generation()
            .map_err(|_| RenewalRefusal::PayloadGenerationMismatch)?;
        Ok(payload.committed_generation)
    }

    /// One redb write transaction, in the section 5 order: nonce replay pre-check,
    /// grant re-read, payload join, generation check, challenge consume, nonce consume,
    /// commit. A refusal at any step leaves the challenge and the nonce untouched.
    /// P9 MUST first verify W, Prenew and the exact operation bytes; this is not authentication.
    /// # Errors
    /// Returns the typed refusal; storage, clock and capacity failures abort everything.
    pub fn admit_renewal_after_authentication(
        &self,
        admission: &RenewalAdmission<'_>,
        now: u64,
    ) -> Result<GrantPublicationLease, RenewalRefusal> {
        let g = admission.grant.grant();
        if admission.requester != &g.grantee {
            return Err(RenewalRefusal::ChallengeMismatch);
        }
        self.lease_with_admission(admission.grant, RENEW_RIGHT, now, lease_error, |tx| {
            if replay::nonce_consumed(
                tx,
                &self.authority.source,
                admission.requester,
                &admission.proof.nonce,
            )? {
                return Err(RenewalRefusal::Replay);
            }
            let effective = replay::fence_clock(tx, now)?;
            let row: RegisteredAttachmentGrant = {
                let table = tx.open_table(GRANTS).map_err(store)?;
                let value = table
                    .get(g.grant_id.as_slice())
                    .map_err(store)?
                    .ok_or(RenewalRefusal::GrantNotActive)?;
                decode(value.value())?
            };
            if row.state != ScopedGrantState::Active
                || self.stored_grant(&row)?.grant() != admission.grant.grant()
            {
                return Err(RenewalRefusal::GrantNotActive);
            }
            if effective >= row.expires_at {
                return Err(RenewalRefusal::Expired);
            }
            if Self::committed_generation(tx, g, &row, effective)?
                != Some(admission.payload_generation)
            {
                return Err(RenewalRefusal::PayloadGenerationMismatch);
            }
            if admission.authority_generation != self.authority.generation {
                return Err(RenewalRefusal::AuthorityGenerationMismatch);
            }
            self.claim_challenge(tx, admission, effective)?;
            #[cfg(test)]
            if FAIL_AFTER_CHALLENGE.with(|f| f.replace(false)) {
                return Err(RenewalRefusal::ReplayProtectionCapacity);
            }
            replay::consume_nonce(
                tx,
                &self.authority.source,
                admission.requester,
                admission.proof,
                effective,
            )?;
            Ok(effective)
        })
    }

    /// Marks the challenge consumed inside the caller's transaction.
    fn claim_challenge(
        &self,
        tx: &redb::WriteTransaction,
        admission: &RenewalAdmission<'_>,
        effective: u64,
    ) -> Result<(), RenewalRefusal> {
        let g = admission.grant.grant();
        let digest = requester_digest(admission.requester).map_err(|_| RenewalRefusal::Invalid)?;
        let mut table = tx.open_table(CHALLENGES).map_err(store)?;
        let mut row: ChallengeRow = {
            let value = table
                .get(admission.challenge.as_slice())
                .map_err(store)?
                .ok_or(RenewalRefusal::ChallengeUnknown)?;
            decode(value.value())?
        };
        if row.authority_generation != self.authority.generation {
            return Err(RenewalRefusal::AuthorityGenerationMismatch);
        }
        if row.grant_id != g.grant_id
            || row.grant_epoch != g.epoch
            || row.grant_hash != g.hash().map_err(|_| RenewalRefusal::Invalid)?
            || row.target_hash != admission.target_hash
            || row.requester != digest
            || row.home_node != admission.home_node
            || admission.home_epoch < row.home_epoch
            || admission.w_expires_at > row.expires_at
        {
            return Err(RenewalRefusal::ChallengeMismatch);
        }
        if row.consumed {
            return Err(RenewalRefusal::ChallengeConsumed);
        }
        if effective >= row.expires_at {
            return Err(RenewalRefusal::ChallengeExpired);
        }
        row.consumed = true;
        table.insert(admission.challenge.as_slice(), encode(&row)?.as_slice()).map_err(store)?;
        Ok(())
    }
}

fn gc_rows(
    table: &mut redb::Table<'_, &[u8], &[u8]>,
    now: u64,
    limit: usize,
) -> Result<usize, RenewalRefusal> {
    let mut stale = Vec::new();
    for entry in table.iter().map_err(store)? {
        let (k, v) = entry.map_err(store)?;
        let row: ChallengeRow = decode(v.value())?;
        if row.expires_at.saturating_add(GC_SKEW) <= now {
            stale.push(k.value().to_vec());
            if stale.len() == limit {
                break;
            }
        }
    }
    for k in &stale {
        table.remove(k.as_slice()).map_err(store)?;
    }
    Ok(stale.len())
}

#[cfg(test)]
mod tests;
