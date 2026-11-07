// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant source-issuer renewal admission (P25 N4). It validates a forwarded renewal
//! on its received bytes, admits it atomically through the shared registry, and signs
//! token T while holding the publication lease through the final token write.
//! No listener or caller exists; the owner device is never involved.
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ramflux_node_core::attachment::{
    AttachmentReplayProof, ChallengeMint, GrantPublicationLease, HomeVerdict, RenewalAdmission,
    RenewalChallenge, RenewalPolicy, RenewalRefusal, ScopedGrantRegistry,
};
use ramflux_protocol::large_attachment::{
    AttachmentOperation, AttachmentRegistrationReceipt, AttachmentToken, ForwardAttestation,
    RenewalRequest, RequesterPop, VerifiedScopedGrant, requester_digest,
};
use serde::{Deserialize, Serialize};
use std::{io, time::Duration};

/// Whole-request cap across all byte fields.
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// The single token write is at most this many bytes, with a 5 s deadline.
const MAX_TOKEN_WRITE: usize = 4096;
const TOKEN_WRITE_DEADLINE: Duration = Duration::from_secs(5);
const VERDICT_MAX_AGE: u64 = 60;
const TOKEN_LIFETIME: u64 = 300;

/// Seven forwarded byte fields plus the transport-derived peer and the router verdict.
/// `peer_node` is set only by the source federation hop, never by a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewAdmitRequest {
    pub operation: Vec<u8>,
    pub body: Vec<u8>,
    pub attestation: Vec<u8>,
    pub home_signature: Vec<u8>,
    pub proof: Vec<u8>,
    pub requester_signature: Vec<u8>,
    /// Complete registered capability: grant plus registration receipt.
    pub grant: Vec<u8>,
    pub peer_node: String,
    pub home_verdict: HomeVerdict,
}

/// `Issued.token` is `LP(T) || LP(signature)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenewAdmitResponse {
    Issued { token: Vec<u8> },
    Refused { code: RenewalRefusal },
}

/// Output stream for the single token write.
pub trait TokenSink {
    /// Writes the whole token, bounded by `deadline`.
    /// # Errors
    /// Returns the transport failure.
    fn write_token(&mut self, bytes: &[u8], deadline: Duration) -> io::Result<()>;
    /// Resets the stream without having written any token byte.
    fn reset(&mut self);
}

#[derive(Debug, Default)]
pub struct VecSink {
    pub bytes: Vec<u8>,
    pub reset: bool,
}
impl TokenSink for VecSink {
    fn write_token(&mut self, bytes: &[u8], _: Duration) -> io::Result<()> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    Refused(RenewalRefusal),
    /// The process stopped after the admission commit; nothing was emitted.
    Interrupted,
    /// Retirement cancelled the lease before any token byte; the stream was reset.
    Cancelled,
    Write(io::ErrorKind),
}
impl From<RenewalRefusal> for IssueError {
    fn from(code: RenewalRefusal) -> Self {
        Self::Refused(code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Issued,
    Refused(RenewalRefusal),
}

/// Named, test-hookable points. Production passes [`IssueHooks::none`].
pub struct IssueHooks<'a> {
    /// After validation, before the admission transaction.
    pub before_admission: &'a dyn Fn(),
    /// After the admission commit, before signing. Returning true simulates a crash.
    pub after_commit: &'a dyn Fn() -> bool,
    /// After T is signed with the lease held, immediately before the final check.
    pub before_final_token_check: &'a dyn Fn(),
}
impl IssueHooks<'static> {
    #[must_use]
    pub fn none() -> Self {
        Self { before_admission: &|| {}, after_commit: &|| false, before_final_token_check: &|| {} }
    }
}

struct Validated {
    grant: VerifiedScopedGrant,
    receipt_expires_at: u64,
    attestation: ForwardAttestation,
    target: AttachmentOperation,
    proof: RequesterPop,
    home_epoch: u64,
}

pub struct SourceIssuer {
    registry: ScopedGrantRegistry,
    signer: SigningKey,
    policy: RenewalPolicy,
}

impl SourceIssuer {
    /// # Errors
    /// `CapabilityUnavailable` unless `signer` is the registry's pinned source key;
    /// `Invalid` for an empty or oversized audience.
    pub fn new(
        registry: ScopedGrantRegistry,
        signer: SigningKey,
        policy: RenewalPolicy,
    ) -> Result<Self, RenewalRefusal> {
        if signer.verifying_key().to_bytes() != registry.authority().signing_public_key {
            return Err(RenewalRefusal::CapabilityUnavailable);
        }
        for s in [&policy.relay_audience, &policy.token_issuer] {
            if s.is_empty() || s.len() > 256 {
                return Err(RenewalRefusal::Invalid);
            }
        }
        Ok(Self { registry, signer, policy })
    }

    /// Mints a challenge for an already verified request (section 2, step 5).
    /// # Errors
    /// Returns the typed refusal; nothing is inserted on refusal.
    pub fn challenge(
        &self,
        request: &ChallengeMint<'_>,
        now: u64,
    ) -> Result<RenewalChallenge, RenewalRefusal> {
        self.registry.mint_renewal_challenge(&self.policy, request, now)
    }

    /// Wire adapter. The JSON response frame is built and written through the same
    /// lease-holding writer as the raw token: the lease is held until the transport
    /// write completes or is cancelled, never across a buffered return.
    /// # Errors
    /// `Cancelled`/`Interrupted`/`Write` as for [`Self::renew`]; typed refusals are
    /// written as `Refused` frames and reported as [`Outcome::Refused`].
    pub fn respond(
        &self,
        request: &RenewAdmitRequest,
        clock: &dyn Fn() -> u64,
        sink: &mut dyn TokenSink,
        hooks: &IssueHooks<'_>,
    ) -> Result<Outcome, IssueError> {
        match self.issue(request, clock, sink, hooks, true) {
            Ok(()) => Ok(Outcome::Issued),
            Err(IssueError::Refused(code)) => {
                let frame = serde_json::to_vec(&RenewAdmitResponse::Refused { code })
                    .map_err(|_| IssueError::Write(io::ErrorKind::InvalidData))?;
                sink.write_token(&frame, TOKEN_WRITE_DEADLINE).map_err(|e| {
                    sink.reset();
                    IssueError::Write(e.kind())
                })?;
                Ok(Outcome::Refused(code))
            }
            Err(other) => Err(other),
        }
    }

    /// Validates, admits atomically, signs T and writes it while the lease is held.
    /// # Errors
    /// `Refused` before any consumption; `Interrupted` and `Cancelled` leave the nonce
    /// and challenge consumed and emit no token byte; `Write` is a transport failure.
    pub fn renew(
        &self,
        request: &RenewAdmitRequest,
        clock: &dyn Fn() -> u64,
        sink: &mut dyn TokenSink,
        hooks: &IssueHooks<'_>,
    ) -> Result<(), IssueError> {
        self.issue(request, clock, sink, hooks, false)
    }

    fn issue(
        &self,
        request: &RenewAdmitRequest,
        clock: &dyn Fn() -> u64,
        sink: &mut dyn TokenSink,
        hooks: &IssueHooks<'_>,
        json: bool,
    ) -> Result<(), IssueError> {
        let now = clock();
        let v = self.validate(request, now)?;
        let g = v.grant.grant();
        let authority = self.registry.authority();
        let proof = AttachmentReplayProof {
            nonce: v.proof.nonce,
            issued_at: v.proof.issued_at,
            expires_at: v.proof.expires_at,
        };
        (hooks.before_admission)();
        let lease = self.registry.admit_renewal_after_authentication(
            &RenewalAdmission {
                grant: &v.grant,
                challenge: v.attestation.challenge,
                target_hash: v.target.hash().map_err(|_| RenewalRefusal::Invalid)?,
                requester: &g.grantee,
                home_node: &v.attestation.home_issuer,
                home_epoch: v.home_epoch,
                payload_generation: v.target.payload_generation,
                authority_generation: authority.generation,
                w_issued_at: v.attestation.issued_at,
                w_expires_at: v.attestation.expires_at,
                verdict_checked_at: request.home_verdict.checked_at,
                proof: &proof,
            },
            clock,
        )?;
        if (hooks.after_commit)() {
            return Err(IssueError::Interrupted);
        }
        // Retirement may have cancelled the lease after the commit: sign nothing.
        if lease.check_current(clock()).is_err() {
            sink.reset();
            return Err(IssueError::Cancelled);
        }
        // Issue time is re-read after admission, never reused from validation.
        let issued_at = clock();
        let expires_at =
            issued_at.saturating_add(TOKEN_LIFETIME).min(g.expires_at).min(v.receipt_expires_at);
        let token = AttachmentToken {
            target_hash: v.target.hash().map_err(|_| RenewalRefusal::Invalid)?,
            grant_hash: v.attestation.grant_hash,
            grant_epoch: g.epoch,
            source_authority: authority.source.clone(),
            authority_generation: authority.generation,
            requester_digest: requester_digest(&g.grantee).map_err(|_| RenewalRefusal::Invalid)?,
            rights: 1 << (v.target.op - 1),
            token_issuer: self.policy.token_issuer.clone(),
            issued_at,
            expires_at,
        };
        let signature = self
            .signer
            .sign(&token.signing_bytes().map_err(|_| RenewalRefusal::Invalid)?)
            .to_bytes();
        let bytes = token
            .signed_bytes(&self.signer.verifying_key().to_bytes(), &signature)
            .map_err(|_| RenewalRefusal::Expired)?;
        let frame = if json {
            serde_json::to_vec(&RenewAdmitResponse::Issued { token: bytes })
                .map_err(|_| IssueError::Write(io::ErrorKind::InvalidData))?
        } else {
            bytes
        };
        write_through_lease(&lease, sink, &frame, clock, hooks)
    }

    fn validate(&self, req: &RenewAdmitRequest, now: u64) -> Result<Validated, RenewalRefusal> {
        let total = [&req.operation, &req.body, &req.attestation, &req.home_signature, &req.proof]
            .iter()
            .map(|verdict| verdict.len())
            .sum::<usize>()
            + req.requester_signature.len()
            + req.grant.len();
        if total > MAX_REQUEST_BYTES {
            return Err(RenewalRefusal::Invalid);
        }
        let authority = self.registry.authority();
        let (grant, receipt) = AttachmentRegistrationReceipt::decode_capability(
            &req.grant,
            &authority.source,
            authority.generation,
            &authority.signing_public_key,
            now,
        )
        .map_err(|_| RenewalRefusal::CapabilityInvalid)?;
        let g = grant.grant();
        let row = self.registry.lookup(&g.grant_id)?.ok_or(RenewalRefusal::CapabilityInvalid)?;
        if row.capability != ramflux_protocol::encode_base64url(&req.grant) {
            return Err(RenewalRefusal::CapabilityInvalid);
        }
        let request = RenewalRequest { operation: req.operation.clone(), body: req.body.clone() };
        let (renew, target) = request.target().map_err(|_| RenewalRefusal::TargetInvalid)?;
        if renew.audience != self.policy.token_issuer {
            return Err(RenewalRefusal::TargetInvalid);
        }
        self.registry.check_renewal_target(&self.policy, g, &target, now)?;
        // Home attestation W: signed by the pinned current-home key from the verdict.
        let attest =
            ForwardAttestation::decode(&req.attestation).map_err(|_| RenewalRefusal::Invalid)?;
        let verdict = &req.home_verdict;
        if attest.home_issuer != req.peer_node
            || attest.home_issuer != verdict.home_node
            || attest.requester.home_node_id != verdict.home_node
            || g.grantee.home_node_id != verdict.home_node
            || attest.requester.account_anchor != verdict.account_anchor
        {
            return Err(RenewalRefusal::HomeMismatch);
        }
        if now.saturating_sub(verdict.checked_at) > VERDICT_MAX_AGE
            || verdict.checked_at > now.saturating_add(5)
            || VerifyingKey::from_bytes(&verdict.home_node_key).is_err()
        {
            return Err(RenewalRefusal::HomeTrustUnavailable);
        }
        let home_signature: [u8; 64] =
            req.home_signature.as_slice().try_into().map_err(|_| RenewalRefusal::Invalid)?;
        attest
            .verify(&verdict.home_node_key, &home_signature)
            .map_err(|_| RenewalRefusal::HomeMismatch)?;
        attest.validate(&request, &grant, &g.grantee, &attest.challenge, now).map_err(|err| {
            if err.0 == "forward time" {
                RenewalRefusal::Expired
            } else {
                RenewalRefusal::ChallengeMismatch
            }
        })?;
        // Requester proof Prenew: signed by the registered grantee device key.
        let pop = RequesterPop::decode(&req.proof).map_err(|_| RenewalRefusal::Invalid)?;
        pop.validate(&attest, now).map_err(|err| {
            if err.0 == "pop time" { RenewalRefusal::Expired } else { RenewalRefusal::Invalid }
        })?;
        let pop_signature: [u8; 64] =
            req.requester_signature.as_slice().try_into().map_err(|_| RenewalRefusal::Invalid)?;
        pop.verify(&g.grantee.signing_public_key, &pop_signature)
            .map_err(|_| RenewalRefusal::Invalid)?;
        Ok(Validated {
            grant,
            receipt_expires_at: receipt.expires_at,
            attestation: attest,
            target,
            proof: pop,
            home_epoch: verdict.home_epoch,
        })
    }
}

/// Lease-holding writer: the final check runs immediately before the single bounded
/// write, and the lease is dropped by the caller only after the write completes.
fn write_through_lease(
    lease: &GrantPublicationLease,
    sink: &mut dyn TokenSink,
    bytes: &[u8],
    clock: &dyn Fn() -> u64,
    hooks: &IssueHooks<'_>,
) -> Result<(), IssueError> {
    if bytes.len() > MAX_TOKEN_WRITE {
        sink.reset();
        return Err(IssueError::Write(io::ErrorKind::InvalidInput));
    }
    (hooks.before_final_token_check)();
    if lease.check_current(clock()).is_err() {
        sink.reset();
        return Err(IssueError::Cancelled);
    }
    sink.write_token(bytes, TOKEN_WRITE_DEADLINE).map_err(|e| {
        sink.reset();
        IssueError::Write(e.kind())
    })
}

pub mod listener;

#[cfg(test)]
mod tests;
