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
mod data;
pub use data::{FullDataAccepted, FullDataFrame};

/// Supplied by the node's actual native owner, never deserialized from an HTTP request.
pub enum FullNativeAdmission<'a> {
    BeforePublication {
        node: &'a VerifiedNodeRecord,
        current: &'a VerifiedRecord,
    },
    Tail {
        node: &'a VerifiedNodeRecord,
        current: &'a VerifiedRecord,
        published: &'a VerifiedRecord,
        expected_candidate_hash: &'a str,
    },
}
impl FullNativeAdmission<'_> {
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
            Self::Tail { current, published, expected_candidate_hash, .. } => {
                verify_full_tail_authority(grant, published, expected_candidate_hash, current, now)
            }
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
    pub lease_id: String,
    pub epoch: String,
    pub role: String,
    pub token: Zeroizing<[u8; 32]>,
}
pub enum FullResumeProgress {
    Pending,
    Ready(FullResumeToken),
}
#[derive(Clone, Copy, Debug)]
pub struct FullResumeStats {
    pub pending_challenges: usize,
    pub connections: usize,
    pub body_budget: FullBodyBudgetStats,
}
/// Authenticated full-data body reservation. It cannot admit an ordinary/native operation.
pub struct FullSendPermit {
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
    template: ResumeProof,
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
pub(super) struct FullResumeServer {
    clock: Arc<dyn PairingClock>,
    node_id: String,
    node_key: String,
    boot_id: String,
    allocations: PairingAllocations,
    budget: FullBodyBudget,
    pending: Vec<Pending>,
    ready: Vec<Ready>,
    _metadata: FullMetadataPermit,
}
fn crypto(error: &CryptoError) -> PairingRelayError {
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
            body_budget: self.budget.stats()?,
        })
    }
    pub(super) fn prune(&mut self) -> Result<(), PairingRelayError> {
        let wall = self.clock.wall_unix_secs()?;
        let mono = self.clock.monotonic_ms();
        self.pending
            .retain(|item| mono < item.deadline && item.lease.body.require_live(wall).is_ok());
        self.ready.retain(|item| {
            mono < item.lease_deadline
                && item.lease.body.require_live(wall).is_ok()
                && item.last_activity.iter().all(|activity| mono.saturating_sub(*activity) < 10_000)
        });
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
                || pending.template.epoch != offer.epoch
                || pending.template.hpke_keys != offer.hpke_keys
            {
                return Err(PairingRelayError::WrongContext);
            }
            return Ok(FullResumeChallenge {
                template: pending.template.clone(),
                expires_in_ms: pending.deadline.saturating_sub(mono),
            });
        }
        if self.pending.len() == 4 {
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
            template: template.clone(),
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
            return Ok(FullResumeProgress::Ready(Self::token(ready, signer)));
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
        let mut expected = pending.template.clone();
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
        if pending.proofs[signer].as_ref().is_some_and(|saved| saved != proof) {
            return Err(PairingRelayError::Replay);
        }
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
        if self.ready.len() == 2 {
            return Err(PairingRelayError::busy(mono));
        }
        let pending = &self.pending[index];
        let source = pending.proofs[0].as_ref().ok_or(PairingRelayError::WrongContext)?;
        let destination = pending.proofs[1].as_ref().ok_or(PairingRelayError::WrongContext)?;
        verify_full_resume_pair(
            &pending.lease.body,
            source,
            destination,
            &self.boot_id,
            &pending.template.nonce,
            wall,
        )
        .map_err(|error| crypto(&error))?;
        admission.verify(&pending.lease.body.grant, wall)?;
        let hashes = [proof_hash(source)?, proof_hash(destination)?];
        let metadata = self.budget.reserve_metadata(8192, mono)?;
        let account = b32(&pending.lease.body.grant.source_ref.account_anchor)?;
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
            template: pending.template,
            proof_hashes: hashes,
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
        Ok(FullResumeProgress::Ready(token))
    }
    fn token(ready: &Ready, signer: usize) -> FullResumeToken {
        FullResumeToken {
            lease_id: ready.lease.body.lease_id.clone(),
            epoch: ready.template.epoch.clone(),
            role: if signer == 0 { "initiator" } else { "responder" }.into(),
            token: Zeroizing::new(*ready.tokens[signer]),
        }
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
            body: permit,
            lease_id: route.lease_id.into(),
            epoch: route.epoch.into(),
            role: route.role.into(),
            token: Zeroizing::new(*route.token),
            _metadata: metadata,
        })
    }
}
