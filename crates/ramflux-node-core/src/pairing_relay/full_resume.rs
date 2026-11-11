// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh original-branch possession, data-only tokens and bounded reconnect ownership.
use super::limits::{constant_time_eq, wire};
use super::{
    ChargedFullBody, FullBodyBudget, FullBodyBudgetStats, FullBodyPermit, FullBodySlot,
    FullDirection, FullMetadataPermit, PairingAllocation, PairingAllocations, PairingClock,
    PairingRelayError,
};
use ramflux_crypto::custody::pairing::{
    verify_full_data_lease, verify_full_prepublication_authority, verify_full_resume_pair,
    verify_full_tail_authority,
};
use ramflux_crypto::custody::{VerifiedNodeRecord, VerifiedRecord};
use ramflux_crypto::{CryptoError, random_32, verify_canonical_signature};
use ramflux_protocol::custody::Envelope;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        lease::{BranchKeys, DataGrant, DataLease, ResumeProof},
        relay::{PollFullControl, SendFullControl},
    },
};
use ramflux_protocol::{canonical_json_bytes, decode_base64url, encode_base64url};
use std::sync::Arc;
use zeroize::Zeroizing;
mod admitted;
pub use admitted::FullAdmittedReply;
mod data;
mod discovery;
mod forward;
pub use data::{FullDataAccepted, FullDataFrame};
pub use forward::{
    FULL_MESH_ADMIT_PATH, FULL_MESH_FRAME_BYTES, FullArm, FullForwardClaim, FullMeshAdmit,
    FullMeshPermit, SecretAuthorization,
};

/// Supplied by the node's actual native owner, never deserialized from an HTTP request.
pub enum FullNativeAdmission<'a> {
    BeforePublication { node: &'a VerifiedNodeRecord, current: &'a VerifiedRecord },
    Tail { node: &'a VerifiedNodeRecord, current: &'a VerifiedRecord },
}
impl<'a> FullNativeAdmission<'a> {
    /// Derive the data-only arm from the node's own verified current head, never a client hint.
    /// Token-before-native ordering stays in authenticate; this selection exposes no refusal.
    #[must_use]
    pub fn for_current(
        node: &'a VerifiedNodeRecord,
        current: &'a VerifiedRecord,
        grant: &DataGrant,
    ) -> Self {
        if current.envelope().body.master_certificate.body.primary_device_ref == grant.source_ref {
            Self::BeforePublication { node, current }
        } else {
            Self::Tail { node, current }
        }
    }
    pub(super) fn node(&self) -> &VerifiedNodeRecord {
        match self {
            Self::BeforePublication { node, .. } | Self::Tail { node, .. } => node,
        }
    }
    fn verify(&self, grant: &DataGrant, now: u64) -> Result<(), PairingRelayError> {
        match self {
            Self::BeforePublication { current, .. } => {
                verify_full_prepublication_authority(grant, current, now)
            }
            Self::Tail { current, .. } => verify_full_tail_authority(grant, current, now),
        }
        .map_err(|error| crypto(&error))
    }
}
#[derive(Clone)]
pub struct FullResumeOffer {
    pub lease: Envelope<DataLease>,
    pub hpke_keys: BranchKeys,
    pub epoch: String,
}
#[derive(Clone)]
pub struct FullResumeChallenge {
    pub template: ResumeProof,
    pub expires_in_ms: u64,
}
pub struct FullResumeToken {
    pub peer_proof: Envelope<ResumeProof>,
    pub lease_id: String,
    pub epoch: String,
    pub role: String,
    pub token: Zeroizing<[u8; 32]>,
}
impl FullResumeToken {
    /// H1: return only the peer's exact signed proof, never its bearer token.
    /// # Errors
    /// Refuses an invalid or oversized complete token response.
    pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>, PairingRelayError> {
        ramflux_protocol::custody::pairing::full_transfer::relay::ResumeTokenFull {
            epoch: self.epoch.clone(),
            kind: "resume_token_full".into(),
            lease_id: self.lease_id.clone(),
            peer_proof: self.peer_proof.clone(),
            profile: ramflux_protocol::custody::pairing::full_transfer::PROFILE.into(),
            role: self.role.clone(),
            token: ramflux_protocol::custody::pairing::full_transfer::SecretBase64::from_bytes(
                self.token.as_ref(),
            ),
        }
        .encode_secret()
        .map_err(|error| wire(&error))
    }
}
pub enum FullResumeProgress {
    Pending,
    Ready(Box<FullResumeToken>),
}
#[derive(Clone, Copy, Debug)]
pub struct FullResumeStats {
    pub pending_challenges: usize,
    pub connections: usize,
    pub cooldown_accounts: usize,
    pub body_budget: FullBodyBudgetStats,
}
/// Authenticated full-data body reservation. It cannot admit an ordinary/native operation.
pub struct FullSendPermit {
    pub(super) arm: Option<FullArm>,
    pub(super) body: FullBodyPermit,
    pub(super) lease_id: String,
    pub(super) epoch: String,
    pub(super) role: String,
    pub(super) token: Zeroizing<[u8; 32]>,
    pub(super) _metadata: FullMetadataPermit,
}
impl FullSendPermit {
    /// Check the original full Send body against the already admitted A2 header scope.
    /// # Errors
    /// Refuses malformed bodies or a lease/epoch/role/token mismatch without echoing input.
    pub fn verify_body<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<
        ramflux_protocol::custody::pairing::full_transfer::relay::BorrowedSendFull<'a>,
        PairingRelayError,
    > {
        use ramflux_protocol::custody::pairing::full_transfer::relay::BorrowedSendFull;
        if input.len() != self.body.reserved_bytes()
            || self.arm.is_some_and(|arm| arm != FullArm::Send)
        {
            return Err(PairingRelayError::WrongContext);
        }
        let body = BorrowedSendFull::from_wire_bytes(input).map_err(|error| wire(&error))?;
        let token = Zeroizing::new(
            decode_base64url(body.token).map_err(|_| PairingRelayError::WrongContext)?,
        );
        let token_matches = constant_time_eq(self.token.as_ref(), token.as_slice());
        if body.packet.lease_id != self.lease_id
            || body.packet.epoch != self.epoch
            || body.packet.role != self.role
            || !token_matches
        {
            return Err(PairingRelayError::WrongContext);
        }
        Ok(body)
    }
}
pub struct FullRoute<'a> {
    pub lease_id: &'a str,
    pub epoch: &'a str,
    pub role: &'a str,
    pub token: &'a [u8; 32],
}
struct Pending {
    lease: Envelope<DataLease>,
    template: Option<ResumeProof>,
    source_key: String,
    destination_key: Option<String>,
    epoch: String,
    nonce: String,
    discovery_credit: [u64; 2],
    discovery_updated: [u64; 2],
    proofs: [Option<Envelope<ResumeProof>>; 2],
    deadline: u64,
    _metadata: FullMetadataPermit,
}
/// Shared retained inner control; no bearer token is forwarded or copied.
#[derive(Clone)]
pub struct FullControlFrame(Arc<ChargedFullBody>);
impl FullControlFrame {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
struct Ready {
    queues: [data::DirectionQueue; 2],
    data_poll_credit: [u64; 2],
    data_poll_updated: [u64; 2],
    control_sent: bool,
    control: Option<FullControlFrame>,
    poll_credit: u64,
    poll_updated: u64,
    lease: Envelope<DataLease>,
    template: ResumeProof,
    proof_hashes: [[u8; 32]; 2],
    proofs: [Envelope<ResumeProof>; 2],
    tokens: [Zeroizing<[u8; 32]>; 2],
    retrieval_deadline: u64,
    lease_deadline: u64,
    last_activity: [u64; 2],
    resources: FullBodySlot,
    _allocation: PairingAllocation,
    _metadata: FullMetadataPermit,
}
pub(super) struct FullResumeConfig {
    pub clock: Arc<dyn PairingClock>,
    pub node_id: String,
    pub node_key: String,
    pub boot_id: String,
    pub allocations: PairingAllocations,
}
struct Cooldown {
    account: [u8; 32],
    until: u64,
    penalty_ms: u64,
}
pub(super) struct FullResumeServer {
    clock: Arc<dyn PairingClock>,
    node_id: String,
    node_key: String,
    boot_id: String,
    allocations: PairingAllocations,
    budget: FullBodyBudget,
    pending: Vec<Pending>,
    cooldowns: [Option<Cooldown>; 64],
    forward: [Option<Box<forward::ForwardTicket>>; 8],
    ready: Vec<Ready>,
    _metadata: FullMetadataPermit,
}
pub(super) fn crypto(error: &CryptoError) -> PairingRelayError {
    match error {
        CryptoError::Pairing("HeadChanged") => PairingRelayError::HeadChanged,
        CryptoError::Pairing("LeaseExpired") => PairingRelayError::LeaseExpired,
        _ => PairingRelayError::WrongContext,
    }
}
fn role(value: &str) -> Result<usize, PairingRelayError> {
    match value {
        "initiator" => Ok(0),
        "responder" => Ok(1),
        _ => Err(PairingRelayError::WrongRole),
    }
}
fn b32(value: &str) -> Result<[u8; 32], PairingRelayError> {
    if value.len() != 43 {
        return Err(PairingRelayError::invalid("full_context"));
    }
    let bytes = decode_base64url(value).map_err(|_| PairingRelayError::invalid("full_context"))?;
    if encode_base64url(&bytes) != value {
        return Err(PairingRelayError::invalid("full_context"));
    }
    bytes.try_into().map_err(|_| PairingRelayError::invalid("full_context"))
}
fn proof_hash(value: &Envelope<ResumeProof>) -> Result<[u8; 32], PairingRelayError> {
    Ok(ramflux_crypto::blake3_256(
        "ramflux.pairing.full.resume_cache.v1",
        &canonical_json_bytes(value).map_err(|_| PairingRelayError::invalid("proof"))?,
    ))
}
impl FullResumeServer {
    pub(super) fn new(config: FullResumeConfig) -> Result<Self, PairingRelayError> {
        b32(&config.node_key)?;
        b32(&config.boot_id)?;
        if config.node_id.len() > 128 {
            return Err(PairingRelayError::invalid("node_id"));
        }
        let budget = FullBodyBudget::default();
        let base = std::mem::size_of::<Self>()
            + 4 * std::mem::size_of::<Pending>()
            + 2 * std::mem::size_of::<Ready>()
            + config.node_id.capacity()
            + config.node_key.capacity()
            + config.boot_id.capacity();
        let metadata = budget.reserve_metadata(base, config.clock.monotonic_ms())?;
        Ok(Self {
            clock: config.clock,
            node_id: config.node_id,
            node_key: config.node_key,
            boot_id: config.boot_id,
            allocations: config.allocations,
            budget,
            pending: Vec::with_capacity(4),
            cooldowns: std::array::from_fn(|_| None),
            forward: std::array::from_fn(|_| None),
            ready: Vec::with_capacity(2),
            _metadata: metadata,
        })
    }
    pub(super) fn verify_offer(
        offer: &FullResumeOffer,
        admission: &FullNativeAdmission<'_>,
        expected_node_key: &str,
        now: u64,
    ) -> Result<(), PairingRelayError> {
        if admission.node().envelope().body.node_signing_public_key != expected_node_key {
            return Err(PairingRelayError::WrongContext);
        }
        verify_full_data_lease(&offer.lease, &offer.lease.body.grant, admission.node(), now)
            .map_err(|error| crypto(&error))?;
        admission.verify(&offer.lease.body.grant, now)?;
        b32(&offer.epoch)?;
        offer.hpke_keys.validate().map_err(|error| wire(&error))
    }
    pub(super) fn stats(&self) -> Result<FullResumeStats, PairingRelayError> {
        Ok(FullResumeStats {
            pending_challenges: self.pending.len(),
            connections: self.ready.len(),
            cooldown_accounts: self.cooldowns.iter().flatten().count(),
            body_budget: self.budget.stats()?,
        })
    }
    pub(super) fn prune(&mut self) -> Result<(), PairingRelayError> {
        let wall = self.clock.wall_unix_secs()?;
        let mono = self.clock.monotonic_ms();
        self.prune_forward(mono);
        let mut expired = [None; 4];
        for (slot, item) in expired.iter_mut().zip(
            self.pending
                .iter()
                .filter(|item| mono >= item.deadline && item.proofs.iter().any(Option::is_none)),
        ) {
            *slot = Some((b32(&item.lease.body.grant.source_ref.account_anchor)?, item.deadline));
        }
        self.pending
            .retain(|item| mono < item.deadline && item.lease.body.require_live(wall).is_ok());
        for (account, at) in expired.into_iter().flatten() {
            self.record_expiry(account, at);
        }
        self.ready.retain(|item| {
            mono < item.lease_deadline
                && item.lease.body.require_live(wall).is_ok()
                && item.last_activity.iter().all(|activity| mono.saturating_sub(*activity) < 10_000)
        });
        Ok(())
    }
    fn record_expiry(&mut self, account: [u8; 32], at: u64) {
        if let Some(entry) =
            self.cooldowns.iter_mut().flatten().find(|entry| entry.account == account)
        {
            entry.penalty_ms = entry.penalty_ms.saturating_mul(2).min(300_000);
            entry.until = at.saturating_add(entry.penalty_ms);
        } else if let Some(slot) = self.cooldowns.iter_mut().find(|slot| slot.is_none()) {
            *slot =
                Some(Cooldown { account, until: at.saturating_add(10_000), penalty_ms: 10_000 });
        }
    }
    fn check_cooldown(&self, account: &str, mono: u64) -> Result<(), PairingRelayError> {
        let account = b32(account)?;
        if let Some(entry) = self
            .cooldowns
            .iter()
            .flatten()
            .find(|entry| entry.account == account && mono < entry.until)
        {
            return Err(PairingRelayError::Busy {
                retry_after_ms: entry.until.saturating_sub(mono).clamp(1000, 30_000),
            });
        }
        Ok(())
    }
    pub(super) fn begin(
        &mut self,
        offer: &FullResumeOffer,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullResumeChallenge, PairingRelayError> {
        self.prune()?;
        let wall = self.clock.wall_unix_secs()?;
        let mono = self.clock.monotonic_ms();
        Self::verify_offer(offer, admission, &self.node_key, wall)?;
        if admission.node().envelope().body.node_id != self.node_id {
            return Err(PairingRelayError::WrongContext);
        }
        if let Some(ready) =
            self.ready.iter().find(|item| item.lease.body.lease_id == offer.lease.body.lease_id)
        {
            if ready.template.epoch != offer.epoch || ready.template.hpke_keys != offer.hpke_keys {
                return Err(PairingRelayError::busy(mono));
            }
            return Err(PairingRelayError::Replay);
        }
        if let Some(pending) =
            self.pending.iter().find(|item| item.lease.body.lease_id == offer.lease.body.lease_id)
        {
            if pending.lease != offer.lease
                || pending.epoch != offer.epoch
                || pending.source_key != offer.hpke_keys.source
                || pending.destination_key.as_deref() != Some(offer.hpke_keys.destination.as_str())
            {
                return Err(PairingRelayError::WrongContext);
            }
            return Ok(FullResumeChallenge {
                template: pending.template.clone().ok_or(PairingRelayError::WrongContext)?,
                expires_in_ms: pending.deadline.saturating_sub(mono),
            });
        }
        self.check_cooldown(&offer.lease.body.grant.source_ref.account_anchor, mono)?;
        if self.pending.len() == 4
            || self.pending.iter().any(|item| {
                item.lease.body.grant.source_ref.account_anchor
                    == offer.lease.body.grant.source_ref.account_anchor
            })
        {
            return Err(PairingRelayError::busy(mono));
        }
        let metadata = self.budget.reserve_metadata(8192, mono)?;
        let template = ResumeProof {
            schema: "ramflux.pairing.full_transfer.resume_proof.v1".into(),
            version: 1,
            lease_id: offer.lease.body.lease_id.clone(),
            boot_id: self.boot_id.clone(),
            nonce: encode_base64url(
                random_32().map_err(|_| PairingRelayError::invalid("entropy"))?,
            ),
            role: "initiator".into(),
            hpke_keys: offer.hpke_keys.clone(),
            epoch: offer.epoch.clone(),
        };
        template.validate().map_err(|error| wire(&error))?;
        self.pending.push(Pending {
            lease: offer.lease.clone(),
            source_key: template.hpke_keys.source.clone(),
            destination_key: Some(template.hpke_keys.destination.clone()),
            epoch: template.epoch.clone(),
            nonce: template.nonce.clone(),
            template: Some(template.clone()),
            discovery_credit: [1000; 2],
            discovery_updated: [mono; 2],
            proofs: [None, None],
            deadline: mono.saturating_add(10_000),
            _metadata: metadata,
        });
        Ok(FullResumeChallenge { template, expires_in_ms: 10_000 })
    }
    fn verify_ready(
        &self,
        index: usize,
        admission: &FullNativeAdmission<'_>,
        wall: u64,
    ) -> Result<(), PairingRelayError> {
        let ready = &self.ready[index];
        if admission.node().envelope().body.node_id != self.node_id
            || admission.node().envelope().body.node_signing_public_key != self.node_key
        {
            return Err(PairingRelayError::WrongContext);
        }
        verify_full_data_lease(&ready.lease, &ready.lease.body.grant, admission.node(), wall)
            .map_err(|error| crypto(&error))?;
        admission.verify(&ready.lease.body.grant, wall)
    }
    pub(super) fn submit(
        &mut self,
        proof: &Envelope<ResumeProof>,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullResumeProgress, PairingRelayError> {
        self.prune()?;
        let wall = self.clock.wall_unix_secs()?;
        let mono = self.clock.monotonic_ms();
        let signer = role(&proof.body.role)?;
        proof.body.validate().map_err(|error| wire(&error))?;
        if proof.signature.len() != 86 {
            return Err(PairingRelayError::WrongContext);
        }
        let hash = proof_hash(proof)?;
        if let Some(index) =
            self.ready.iter().position(|item| item.lease.body.lease_id == proof.body.lease_id)
        {
            if let Err(error) = self.verify_ready(index, admission, wall) {
                self.ready.swap_remove(index);
                return Err(error);
            }
            let ready = &mut self.ready[index];
            if mono >= ready.retrieval_deadline || ready.proof_hashes[signer] != hash {
                return Err(PairingRelayError::Replay);
            }
            ready.last_activity[signer] = mono;
            return Ok(FullResumeProgress::Ready(Box::new(Self::token(ready, signer))));
        }
        let index = self
            .pending
            .iter()
            .position(|item| item.lease.body.lease_id == proof.body.lease_id)
            .ok_or(PairingRelayError::Replay)?;
        self.accept_proof(index, signer, proof, admission, wall)?;
        if self.pending[index].proofs.iter().any(Option::is_none) {
            return Ok(FullResumeProgress::Pending);
        }
        self.finish(index, signer, admission, wall, mono)
    }
    fn accept_proof(
        &mut self,
        index: usize,
        signer: usize,
        proof: &Envelope<ResumeProof>,
        admission: &FullNativeAdmission<'_>,
        wall: u64,
    ) -> Result<(), PairingRelayError> {
        let pending = &mut self.pending[index];
        verify_full_data_lease(&pending.lease, &pending.lease.body.grant, admission.node(), wall)
            .map_err(|error| crypto(&error))?;
        admission.verify(&pending.lease.body.grant, wall)?;
        if pending.proofs[signer].as_ref().is_some_and(|saved| saved != proof) {
            return Err(PairingRelayError::Replay);
        }
        let mut expected = pending.template.clone().ok_or(PairingRelayError::WrongContext)?;
        expected.role.clone_from(&proof.body.role);
        if proof.body != expected {
            return Err(PairingRelayError::WrongContext);
        }
        let key = if signer == 0 {
            &pending.lease.body.grant.branch_keys.source
        } else {
            &pending.lease.body.grant.branch_keys.destination
        };
        verify_canonical_signature(
            &proof.body.signing_bytes().map_err(|error| wire(&error))?,
            &proof.signature,
            key,
        )
        .map_err(|_| PairingRelayError::WrongContext)?;
        pending.proofs[signer] = Some(proof.clone());
        Ok(())
    }
    fn finish(
        &mut self,
        index: usize,
        signer: usize,
        admission: &FullNativeAdmission<'_>,
        wall: u64,
        mono: u64,
    ) -> Result<FullResumeProgress, PairingRelayError> {
        let pending = &self.pending[index];
        let source = pending.proofs[0].as_ref().ok_or(PairingRelayError::WrongContext)?;
        let destination = pending.proofs[1].as_ref().ok_or(PairingRelayError::WrongContext)?;
        verify_full_resume_pair(
            &pending.lease.body,
            source,
            destination,
            &self.boot_id,
            &pending.nonce,
            wall,
        )
        .map_err(|error| crypto(&error))?;
        admission.verify(&pending.lease.body.grant, wall)?;
        let hashes = [proof_hash(source)?, proof_hash(destination)?];
        let proofs = [source.clone(), destination.clone()];
        let account = b32(&pending.lease.body.grant.source_ref.account_anchor)?;
        for entry in &mut self.cooldowns {
            if entry.as_ref().is_some_and(|entry| entry.account == account) {
                *entry = None;
            }
        }
        if self.ready.len() == 2 {
            return Err(PairingRelayError::busy(mono));
        }
        let metadata = self.budget.reserve_metadata(8192, mono)?;
        let allocation = self.allocations.reserve(account, mono)?;
        let resources = self.budget.open_slot(account, mono)?;
        let mut tokens = [
            Zeroizing::new(random_32().map_err(|_| PairingRelayError::invalid("entropy"))?),
            Zeroizing::new(random_32().map_err(|_| PairingRelayError::invalid("entropy"))?),
        ];
        if constant_time_eq(tokens[0].as_ref(), tokens[1].as_ref()) {
            tokens[1][0] ^= 1;
        }
        let pending = self.pending.swap_remove(index);
        let lease_deadline = mono.saturating_add(
            pending.lease.body.expires_at.saturating_sub(wall).saturating_mul(1000),
        );
        let ready = Ready {
            queues: std::array::from_fn(|_| data::DirectionQueue::default()),
            data_poll_credit: [1000; 2],
            data_poll_updated: [mono; 2],
            control_sent: false,
            control: None,
            poll_credit: 1000,
            poll_updated: mono,
            lease: pending.lease,
            template: pending.template.ok_or(PairingRelayError::WrongContext)?,
            proof_hashes: hashes,
            proofs,
            tokens,
            retrieval_deadline: pending.deadline,
            lease_deadline,
            last_activity: [mono; 2],
            resources,
            _allocation: allocation,
            _metadata: metadata,
        };
        let token = Self::token(&ready, signer);
        self.ready.push(ready);
        Ok(FullResumeProgress::Ready(Box::new(token)))
    }
    fn token(ready: &Ready, signer: usize) -> FullResumeToken {
        FullResumeToken {
            peer_proof: ready.proofs[1 - signer].clone(),
            lease_id: ready.lease.body.lease_id.clone(),
            epoch: ready.template.epoch.clone(),
            role: if signer == 0 { "initiator" } else { "responder" }.into(),
            token: Zeroizing::new(*ready.tokens[signer]),
        }
    }
    pub(super) fn proof_grant(
        &mut self,
        proof: &Envelope<ResumeProof>,
    ) -> Result<DataGrant, PairingRelayError> {
        self.prune()?;
        proof.body.validate().map_err(|error| wire(&error))?;
        let signer = role(&proof.body.role)?;
        let grant = if let Some(pending) =
            self.pending.iter().find(|pending| pending.lease.body.lease_id == proof.body.lease_id)
        {
            &pending.lease.body.grant
        } else {
            &self
                .ready
                .iter()
                .find(|ready| {
                    ready.lease.body.lease_id == proof.body.lease_id
                        && self.clock.monotonic_ms() < ready.retrieval_deadline
                })
                .ok_or(PairingRelayError::WrongContext)?
                .lease
                .body
                .grant
        };
        let key =
            if signer == 0 { &grant.branch_keys.source } else { &grant.branch_keys.destination };
        verify_canonical_signature(
            &proof.body.signing_bytes().map_err(|error| wire(&error))?,
            &proof.signature,
            key,
        )
        .map_err(|_| PairingRelayError::WrongContext)?;
        Ok(grant.clone())
    }
    pub(super) fn authenticated_grant(
        &mut self,
        route: &FullRoute<'_>,
    ) -> Result<DataGrant, PairingRelayError> {
        self.prune()?;
        let ready = self
            .ready
            .iter()
            .find(|ready| ready.lease.body.lease_id == route.lease_id)
            .ok_or(PairingRelayError::WrongContext)?;
        let signer = role(route.role)?;
        let matches = constant_time_eq(ready.tokens[signer].as_ref(), route.token);
        if ready.template.epoch != route.epoch || !matches {
            return Err(PairingRelayError::WrongContext);
        }
        Ok(ready.lease.body.grant.clone())
    }
    fn authenticate(
        &mut self,
        route: &FullRoute<'_>,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<(usize, usize), PairingRelayError> {
        self.prune()?;
        let wall = self.clock.wall_unix_secs()?;
        let index = self
            .ready
            .iter()
            .position(|item| item.lease.body.lease_id == route.lease_id)
            .ok_or(PairingRelayError::WrongContext)?;
        let signer = role(route.role)?;
        let ready = &self.ready[index];
        let token_matches = constant_time_eq(ready.tokens[signer].as_ref(), route.token);
        if ready.template.epoch != route.epoch || !token_matches {
            return Err(PairingRelayError::WrongContext);
        }
        // No native-head/lease errors become visible until the role token authenticates.
        if let Err(error) = self.verify_ready(index, admission, wall) {
            self.ready.swap_remove(index);
            return Err(error);
        }
        Ok((index, signer))
    }
    pub(super) fn send_control(
        &mut self,
        request: &SendFullControl,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<(), PairingRelayError> {
        // Includes the complete wrapper's 8-KiB bound, never a Value token tree.
        let _encoded = request.encode_secret().map_err(|error| wire(&error))?;
        let token = request.token.decode(32).map_err(|error| wire(&error))?;
        let token: &[u8; 32] =
            token.as_slice().try_into().map_err(|_| PairingRelayError::WrongContext)?;
        let route = FullRoute {
            lease_id: &request.control.lease_id,
            epoch: &request.control.epoch,
            role: &request.control.role,
            token,
        };
        let (index, signer) = self.authenticate(&route, admission)?;
        if signer != 0 {
            return Err(PairingRelayError::WrongRole);
        }
        let ready = &mut self.ready[index];
        if ready.control_sent {
            return Err(PairingRelayError::Replay);
        }
        let mut bytes = request.control.to_wire_bytes().map_err(|error| wire(&error))?;
        bytes.shrink_to_fit();
        let mono = self.clock.monotonic_ms();
        let permit = ready.resources.reserve(FullDirection::Initiator, bytes.len(), mono)?;
        let retained = FullControlFrame(Arc::new(permit.attach(bytes)?));
        ready.control = Some(retained);
        ready.control_sent = true;
        ready.last_activity[0] = mono;
        Ok(())
    }
    pub(super) fn poll_control(
        &mut self,
        request: &PollFullControl,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<Option<FullControlFrame>, PairingRelayError> {
        let _encoded = request.encode_secret().map_err(|error| wire(&error))?;
        let token = request.token.decode(32).map_err(|error| wire(&error))?;
        let token: &[u8; 32] =
            token.as_slice().try_into().map_err(|_| PairingRelayError::WrongContext)?;
        let route = FullRoute {
            lease_id: &request.lease_id,
            epoch: &request.epoch,
            role: &request.role,
            token,
        };
        let (index, signer) = self.authenticate(&route, admission)?;
        if signer != 1 {
            return Err(PairingRelayError::WrongRole);
        }
        let mono = self.clock.monotonic_ms();
        let ready = &mut self.ready[index];
        let credit =
            ready.poll_credit.saturating_add(mono.saturating_sub(ready.poll_updated)).min(1000);
        if credit < 500 {
            return Err(PairingRelayError::busy(mono));
        }
        ready.poll_credit = credit - 500;
        ready.poll_updated = ready.poll_updated.max(mono);
        ready.last_activity[1] = mono;
        Ok(ready.control.clone())
    }
    pub(super) fn reserve_body(
        &mut self,
        route: &FullRoute<'_>,
        bytes: usize,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullSendPermit, PairingRelayError> {
        let (index, signer) = self.authenticate(route, admission)?;
        let mono = self.clock.monotonic_ms();
        let ready = &mut self.ready[index];
        let metadata = self.budget.reserve_metadata(
            std::mem::size_of::<FullSendPermit>()
                + route.lease_id.len()
                + route.epoch.len()
                + route.role.len(),
            mono,
        )?;
        let permit = ready.resources.reserve(
            if signer == 0 { FullDirection::Initiator } else { FullDirection::Responder },
            bytes,
            mono,
        )?;
        ready.last_activity[signer] = mono;
        Ok(FullSendPermit {
            arm: None,
            body: permit,
            lease_id: route.lease_id.into(),
            epoch: route.epoch.into(),
            role: route.role.into(),
            token: Zeroizing::new(*route.token),
            _metadata: metadata,
        })
    }
}
