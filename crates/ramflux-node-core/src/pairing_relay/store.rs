// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Boot-scoped in-memory pairing relay allocator. Dormant: no HTTP or native route.
use super::bytes::{
    claim_payload, closed_payload, direction_payload, frame_list_heap, hour_payload, slot_payload,
    table_bytes,
};
use super::limits::{
    AllocatorStats, CLAIM_GRACE_MS, HOUR_MS, INVITATION_LIFETIME_SECS, MAX_BACKING, MAX_CLAIMS,
    MAX_CLAIMS_PER_PREFIX, MAX_CLOSED, MAX_FRAME_BYTES, MAX_FRAMES_PER_DIRECTION, MAX_HOUR_ENTRIES,
    MAX_ISSUES_PER_HOUR, MAX_POLLS_PER_SEC, MAX_SLOTS, MAX_SLOTS_PER_ACCOUNT, PairingClock,
    PairingRelayError, claim_source_prefixes, constant_time_eq, token_hash, wire,
};
use crate::{InFlightGuard, begin_service_request};
use ramflux_crypto::{
    public_key_base64url_from_seed, random_32, sign_canonical_bytes_with_seed,
    verify_canonical_signature,
};
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::{
    Create, CreateSlot, CreateSpec, CreateTicket, Created, Invitation, Issued,
    invitation_signing_bytes, ticket_signing_bytes,
};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, QueuedFrame, RelayFrame, Send, Sent,
};
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::{decode_base64url, encode_base64url};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Injected clock, node identity seed and pinned HTTPS origin.
pub struct PairingRelayConfig {
    pub clock: Arc<dyn PairingClock>,
    pub node_seed: [u8; 32],
    pub public_origin: String,
}

#[derive(Clone, Copy)]
struct Now {
    wall: u64,
    mono: u64,
}

#[derive(Default)]
pub(super) struct Direction {
    pub(super) frames: Vec<(u64, RelayFrame)>,
    pub(super) next_send_seq: u64,
    pub(super) last_send: Option<(u64, String)>,
    pub(super) acked_seq: Option<u64>,
    pub(super) poll_times: VecDeque<u64>,
}

pub(super) struct IssuedSlot {
    pub(super) ticket: Envelope<CreateTicket>,
    pub(super) spec_hash: String,
    pub(super) primary_ref: DeviceRef,
}

pub(super) enum SlotBody {
    Issued(Box<IssuedSlot>),
    Live(Box<LiveSlot>),
}

pub(super) struct LeaseCache {
    pub(super) request_hash: [u8; 32],
    pub(super) lease: Envelope<ramflux_protocol::custody::pairing::full_transfer::lease::DataLease>,
}

pub(super) struct LiveSlot {
    pub(super) data_lease: Option<Box<LeaseCache>>,
    pub(super) ticket: Envelope<CreateTicket>,
    pub(super) descriptor: Envelope<Invitation>,
    pub(super) primary_token: Zeroizing<[u8; 32]>,
    pub(super) recipient_token: Zeroizing<[u8; 32]>,
    pub(super) claim_nonce: Option<[u8; 32]>,
    pub(super) initiator: Direction,
    pub(super) responder: Direction,
    pub(super) closed_reason: Option<String>,
    pub(super) last_activity_ms: u64,
}

pub(super) struct Slot {
    pub(super) account: [u8; 32],
    pub(super) expires_at: u64,
    pub(super) monotonic_deadline: u64,
    pub(super) body: SlotBody,
}

pub(super) struct ClosedSlot {
    pub(super) reason: String,
    pub(super) issuer_seq: u64,
    pub(super) primary_hash: [u8; 32],
    pub(super) recipient_hash: [u8; 32],
    pub(super) expires_at: u64,
    pub(super) monotonic_deadline: u64,
}

pub(super) struct ClaimEntry {
    pub(super) prefixes: Vec<String>,
    pub(super) expires_ms: u64,
}

/// Process-local issued+live pairing relay. Restored from nothing on restart.
pub struct PairingRelayStore {
    clock: Arc<dyn PairingClock>,
    seed: Zeroizing<[u8; 32]>,
    node_key: String,
    boot_id_b64: String,
    public_origin: String,
    issuer_seq: u64,
    slots: HashMap<[u8; 32], Slot>,
    invitations: HashMap<[u8; 32], [u8; 32]>,
    hour: HashMap<[u8; 32], VecDeque<u64>>,
    claims: HashMap<[u8; 32], ClaimEntry>,
    closed: HashMap<[u8; 32], ClosedSlot>,
    accounted: usize,
    high_water: usize,
    registry_mark: usize,
}

impl PairingRelayStore {
    /// Draw a fresh `boot_id`. Restores no slots.
    ///
    /// # Errors
    /// Refuses CSPRNG failure or a non-HTTPS origin.
    pub fn new(config: PairingRelayConfig) -> Result<Self, PairingRelayError> {
        let boot_id = random_32().map_err(|_| PairingRelayError::invalid("entropy"))?;
        let origin = config.public_origin;
        if !origin.starts_with("https://") || origin.len() > 256 {
            return Err(PairingRelayError::invalid("public_origin"));
        }
        let mut store = Self {
            clock: config.clock,
            node_key: public_key_base64url_from_seed(config.node_seed),
            seed: Zeroizing::new(config.node_seed),
            boot_id_b64: encode_base64url(boot_id),
            public_origin: origin,
            issuer_seq: 0,
            slots: HashMap::with_capacity(MAX_SLOTS),
            invitations: HashMap::with_capacity(MAX_SLOTS),
            hour: HashMap::with_capacity(MAX_HOUR_ENTRIES),
            claims: HashMap::with_capacity(MAX_CLAIMS),
            closed: HashMap::with_capacity(MAX_CLOSED),
            accounted: 0,
            high_water: 0,
            registry_mark: 0,
        };
        store.accounted = store.registry_bytes();
        store.high_water = store.accounted;
        store.registry_mark = store.accounted;
        Ok(store)
    }

    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id_b64
    }
    #[must_use]
    pub fn node_key(&self) -> &str {
        &self.node_key
    }
    #[must_use]
    pub fn stats(&self) -> AllocatorStats {
        let (issued, live, queued_bytes, queued_frames) = slot_counts(&self.slots);
        AllocatorStats {
            slots: self.slots.len(),
            issued,
            live,
            backing: self.accounted,
            high_water: self.high_water,
            queued_bytes,
            queued_frames,
            sockets: self.claims.len(),
            claims: self.claims.len(),
        }
    }
    #[must_use]
    pub fn accounted_bytes(&self) -> usize {
        self.accounted
    }
    /// Production walker: sums the same owned-buffer quantities the accountant charges.
    /// No allocation. Independent of the running total.
    #[must_use]
    pub fn measured_bytes(&self) -> usize {
        self.registry_bytes()
            .saturating_add(self.slots.values().map(slot_payload).sum())
            .saturating_add(self.hour.values().map(hour_payload).sum())
            .saturating_add(self.claims.values().map(claim_payload).sum())
            .saturating_add(self.closed.values().map(closed_payload).sum())
    }

    /// Account-scoped slot class. Unknown and foreign ids share one Retired result.
    ///
    /// # Errors
    /// `Retired` when the id is missing or belongs to a different account.
    pub fn lookup_create(
        &self,
        account_anchor: &str,
        create_id: &str,
    ) -> Result<CreateSlot, PairingRelayError> {
        let account = parse_id(account_anchor, "account_anchor")?;
        let id = parse_id(create_id, "create_id")?;
        match self.slots.get(&id) {
            Some(slot) if slot.account == account => Ok(match slot.body {
                SlotBody::Issued(_) => CreateSlot::Issued,
                SlotBody::Live(_) => CreateSlot::Live,
            }),
            _ => Err(PairingRelayError::Retired),
        }
    }

    /// Issue a data-only lease once from a saved live primary-transfer invitation.
    /// The native proof owner supplies fresh verified account and node authority.
    /// # Errors
    /// Refuses absent/expired invitations, changed original bindings, missing branch proofs,
    /// conflicting retries and the bounded two-lease/per-account allocation budget.
    pub fn issue_data_lease(
        &mut self,
        request: &ramflux_protocol::custody::pairing::full_transfer::lease::LeaseRequest,
        authority: &ramflux_crypto::custody::VerifiedRecord,
        node: &ramflux_crypto::custody::VerifiedNodeRecord,
    ) -> Result<
        Envelope<ramflux_protocol::custody::pairing::full_transfer::lease::DataLease>,
        PairingRelayError,
    > {
        let _guard = admit()?;
        self.prune()?;
        request.validate().map_err(|error| wire(&error))?;
        let now = self.now()?;
        if request.grant.node_id != node.envelope().body.node_id
            || self.node_key != node.envelope().body.node_signing_public_key
        {
            return Err(PairingRelayError::WrongContext);
        }
        let invitation = parse_id(&request.invitation_id, "invitation_id")?;
        let live = self.live(invitation)?;
        let original = &live.descriptor.body;
        if live.closed_reason.is_some()
            || original.purpose != "primary_transfer"
            || original.issuer_seq != request.issuer_seq
            || original.transfer_id.as_ref() != Some(&request.grant.transfer_id)
            || original.primary_ref != request.grant.source_ref
            || original
                .destination_ref
                .as_ref()
                .is_some_and(|reference| reference != &request.grant.destination_ref)
        {
            return Err(PairingRelayError::WrongContext);
        }
        ramflux_crypto::custody::pairing::verify_full_lease_request(request, authority, now.wall)
            .map_err(|error| match error {
            ramflux_crypto::CryptoError::Pairing("HeadChanged") => PairingRelayError::HeadChanged,
            ramflux_crypto::CryptoError::Pairing("LeaseExpired") => PairingRelayError::LeaseExpired,
            _ => PairingRelayError::WrongContext,
        })?;
        let request_hash = ramflux_crypto::blake3_256(
            "ramflux.pairing.full.lease_request_cache.v1",
            &request.to_wire_bytes().map_err(|error| wire(&error))?,
        );
        if let Some(saved) = &live.data_lease {
            return if saved.request_hash == request_hash {
                Ok(saved.lease.clone())
            } else {
                Err(PairingRelayError::Replay)
            };
        }
        let mut count = 0;
        for slot in self.slots.values() {
            if let SlotBody::Live(other) = &slot.body
                && other.data_lease.is_some()
            {
                count += 1;
                if other.descriptor.body.account_anchor == request.grant.source_ref.account_anchor {
                    return Err(self.busy());
                }
            }
        }
        if count >= 2 {
            return Err(self.busy());
        }
        let lease = self.sign_data_lease(request.grant.clone(), now.wall)?;
        let cached = Box::new(LeaseCache { request_hash, lease: lease.clone() });
        let bytes = super::bytes::lease_cache_heap(&cached);
        if bytes > 8192 {
            return Err(PairingRelayError::invalid("lease_size"));
        }
        self.charge(bytes)?;
        self.live_mut(invitation)?.data_lease = Some(cached);
        Ok(lease)
    }

    fn sign_data_lease(
        &self,
        grant: ramflux_protocol::custody::pairing::full_transfer::lease::DataGrant,
        now: u64,
    ) -> Result<
        Envelope<ramflux_protocol::custody::pairing::full_transfer::lease::DataLease>,
        PairingRelayError,
    > {
        let body =
            ramflux_protocol::custody::pairing::full_transfer::lease::DataLease {
                schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
                version: 1,
                lease_id: encode_base64url(
                    random_32().map_err(|_| PairingRelayError::invalid("entropy"))?,
                ),
                expires_at: grant.expires_at.min(now.saturating_add(
                    ramflux_protocol::custody::pairing::full_transfer::LEASE_SECONDS,
                )),
                grant,
                issued_at: now,
            };
        Ok(Envelope {
            signature: sign_canonical_bytes_with_seed(
                &body.signing_bytes().map_err(|error| wire(&error))?,
                *self.seed,
            ),
            body,
        })
    }

    /// # Errors
    /// Quota Busy, entropy, clock, or a malformed specification.
    pub fn issue(&mut self, spec: CreateSpec) -> Result<Issued, PairingRelayError> {
        let _guard = admit()?;
        self.prune()?;
        let mut spec = spec;
        spec.normalize();
        spec.validate().map_err(|e| wire(&e))?;
        let account = parse_id(&spec.account_anchor, "account_anchor")?;
        self.check_issue_quotas(account)?;
        let now = self.now()?;
        let create_id = random_32().map_err(|_| PairingRelayError::invalid("entropy"))?;
        self.issuer_seq =
            self.issuer_seq.checked_add(1).ok_or(PairingRelayError::invalid("issuer_seq"))?;
        let ticket = self.build_ticket(&spec, create_id, self.issuer_seq, now.wall)?;
        let envelope = sign_ticket(&self.seed, ticket)?;
        self.insert_issued(account, create_id, envelope.clone(), spec, now)?;
        Ok(Issued { schema: "ramflux.pairing.Issued.v2".into(), version: 2, ticket: envelope })
    }

    /// Consume an issued ticket, retry a live Create, or retire a missing/old id.
    ///
    /// # Errors
    /// Retired/Expired/Replay/WrongContext as specified; never allocates a missing slot.
    pub fn create(&mut self, create: Create) -> Result<Created, PairingRelayError> {
        let _guard = admit()?;
        self.prune()?;
        create.validate().map_err(|e| wire(&e))?;
        self.verify_ticket(&create)?;
        let now = self.now()?;
        if create.ticket.body.boot_id != self.boot_id_b64 {
            return Err(PairingRelayError::Retired);
        }
        let id = parse_id(&create.ticket.body.create_id, "create_id")?;
        let kind = match self.slots.get(&id) {
            None => return Err(PairingRelayError::Retired),
            Some(slot) if slot_expired(slot, &now) => {
                self.release_slot(id);
                return Err(PairingRelayError::Retired);
            }
            Some(slot) => match &slot.body {
                SlotBody::Live(live) => return replay_created(live.as_ref(), &create),
                SlotBody::Issued(issued) => {
                    if issued.primary_ref != create.spec.primary_ref {
                        return Err(PairingRelayError::WrongContext);
                    }
                    if issued.ticket.signature != create.ticket.signature
                        || issued.ticket.body.create_id != create.ticket.body.create_id
                    {
                        return Err(PairingRelayError::Replay);
                    }
                    issued.spec_hash.clone()
                }
            },
        };
        if kind != create.spec.spec_hash().map_err(|e| wire(&e))? {
            return Err(PairingRelayError::Replay);
        }
        self.promote_live(id, create, now)
    }

    /// # Errors
    /// Token, claim-budget Busy, Replay of a different nonce, or a missing invitation.
    pub fn claim(&mut self, source: IpAddr, claim: &Claim) -> Result<Claimed, PairingRelayError> {
        let _guard = admit()?;
        self.prune()?;
        let now = self.now()?;
        claim.validate().map_err(|e| wire(&e))?;
        let invitation = parse_id(&claim.invitation_id, "invitation_id")?;
        let expires_at = self.check_token(
            invitation,
            claim.issuer_seq,
            "responder",
            &claim.recipient_token,
            now.wall,
        )?;
        let nonce = parse_id(&claim.claim_nonce, "claim_nonce")?;
        match self.live(invitation)?.claim_nonce {
            Some(existing) if existing == nonce => {
                self.live_mut(invitation)?.last_activity_ms = now.mono;
                return Ok(claimed_reply(claim, expires_at));
            }
            Some(_) => return Err(PairingRelayError::Replay),
            None => {}
        }
        self.admit_claim_budget(source, invitation, now.mono)?;
        let live = self.live_mut(invitation)?;
        live.claim_nonce = Some(nonce);
        live.last_activity_ms = now.mono;
        Ok(claimed_reply(claim, expires_at))
    }

    /// # Errors
    /// Token, Replay of a different digest, Busy at two queued frames, or Expired.
    pub fn send(&mut self, send: &Send) -> Result<Sent, PairingRelayError> {
        let _guard = admit()?;
        self.prune()?;
        let now = self.now()?;
        send.validate().map_err(|e| wire(&e))?;
        let invitation = parse_id(&send.invitation_id, "invitation_id")?;
        let _ = self.check_token(invitation, send.issuer_seq, &send.role, &send.token, now.wall)?;
        self.require_responder_claim(invitation, &send.role)?;
        let digest = send.frame_digest().map_err(|e| wire(&e))?;
        send.frame.validate().map_err(|e| wire(&e))?;
        let (extra, snapshot) = {
            let live = self.live_mut(invitation)?;
            live.last_activity_ms = now.mono;
            let out = direction_mut(live, &send.role)?;
            enqueue_cost(out, send.seq, &digest)?;
            let before = direction_payload(out);
            let snapshot =
                (out.last_send.clone(), out.next_send_seq, out.frames.len(), out.frames.capacity());
            apply_enqueue(out, send.seq, send.frame.clone(), digest);
            (direction_payload(out).saturating_sub(before), snapshot)
        };
        if let Err(err) = self.charge(extra) {
            if let Ok(live) = self.live_mut(invitation)
                && let Ok(out) = direction_mut(live, &send.role)
            {
                out.frames.truncate(snapshot.2);
                // Inverse of first-send growth from `Direction::default` (`Vec::new()`).
                // Snapshot capacity, not length: shrink_to(len) is a no-op when len > 0.
                // Charge-Busy on Send is unreachable at annex F caps (remaining slack
                // after max fill exceeds one max frame); shrink_to stays as defense.
                out.frames.shrink_to(snapshot.3);
                out.last_send = snapshot.0;
                out.next_send_seq = snapshot.1;
            }
            return Err(err);
        }
        Ok(Sent {
            schema: "ramflux.pairing.Sent.v2".into(),
            version: 2,
            invitation_id: send.invitation_id.clone(),
            role: send.role.clone(),
            seq: send.seq,
        })
    }

    /// # Errors
    /// Token, poll-rate Busy, or a missing invitation.
    pub fn poll(&mut self, poll: &Poll) -> Result<Polled, PairingRelayError> {
        let _guard = admit()?;
        self.prune()?;
        let now = self.now()?;
        poll.validate().map_err(|e| wire(&e))?;
        let invitation = parse_id(&poll.invitation_id, "invitation_id")?;
        let _ = self.check_token(invitation, poll.issuer_seq, &poll.role, &poll.token, now.wall)?;
        if self.closed.contains_key(&invitation) {
            return Ok(Polled {
                schema: "ramflux.pairing.Polled.v2".into(),
                version: 2,
                invitation_id: poll.invitation_id.clone(),
                frames: Vec::new(),
                closed: true,
            });
        }
        self.require_responder_claim(invitation, &poll.role)?;
        let (closed, refund, extra, frames, undo) = {
            let live = self.live_mut(invitation)?;
            live.last_activity_ms = now.mono;
            let closed = live.closed_reason.is_some();
            let incoming = peer_mut(live, &poll.role)?;
            let before = direction_payload(incoming);
            let undo = (
                incoming.poll_times.clone(),
                incoming.poll_times.capacity(),
                incoming.frames.clone(),
                incoming.frames.capacity(),
            );
            record_poll(incoming, now.mono)?;
            if let Some(ack) = poll.after_seq {
                let _ = ack_frames(incoming, ack);
            }
            let after = direction_payload(incoming);
            let frames = take_polled_frames(incoming)?;
            let refund = before.saturating_sub(after);
            let extra = after.saturating_sub(before);
            (closed, refund, extra, frames, undo)
        };
        self.refund(refund);
        if let Err(err) = self.charge(extra) {
            if let Ok(live) = self.live_mut(invitation)
                && let Ok(incoming) = peer_mut(live, &poll.role)
            {
                incoming.poll_times = undo.0;
                incoming.poll_times.shrink_to(undo.1);
                incoming.frames = undo.2;
                incoming.frames.shrink_to(undo.3);
            }
            return Err(err);
        }
        Ok(Polled {
            schema: "ramflux.pairing.Polled.v2".into(),
            version: 2,
            invitation_id: poll.invitation_id.clone(),
            frames,
            closed,
        })
    }

    /// Releases the slot. Idempotent for the same invitation.
    ///
    /// # Errors
    /// Token or a missing invitation (Retired).
    pub fn close(&mut self, close: &Close) -> Result<Closed, PairingRelayError> {
        let _guard = admit()?;
        self.prune()?;
        let now = self.now()?;
        close.validate().map_err(|e| wire(&e))?;
        let invitation = parse_id(&close.invitation_id, "invitation_id")?;
        let _ =
            self.check_token(invitation, close.issuer_seq, &close.role, &close.token, now.wall)?;
        if let Some(closed) = self.closed.get(&invitation) {
            return Ok(closed_reply(&close.invitation_id, &closed.reason));
        }
        if self.closed.len() >= MAX_CLOSED {
            return Err(self.busy());
        }
        self.require_responder_claim(invitation, &close.role)?;
        let Some(create_id) = self.invitations.get(&invitation).copied() else {
            return Err(PairingRelayError::Retired);
        };
        self.remember_closed(create_id, invitation, close.reason.clone())?;
        self.release_slot(create_id);
        Ok(closed_reply(&close.invitation_id, &close.reason))
    }

    /// Zeroize tokens and drop every slot. A later `new` draws a different `boot_id`.
    pub fn shutdown(&mut self) {
        let ids: Vec<[u8; 32]> = self.slots.keys().copied().collect();
        for id in ids {
            self.release_slot(id);
        }
        let claim_refund: usize = self.claims.values().map(claim_payload).sum();
        self.claims.clear();
        self.refund(claim_refund);
        let hour_refund: usize = self.hour.values().map(hour_payload).sum();
        self.hour.clear();
        self.refund(hour_refund);
        let closed_refund: usize = self.closed.values().map(closed_payload).sum();
        for closed in self.closed.values_mut() {
            closed.primary_hash.fill(0);
            closed.recipient_hash.fill(0);
        }
        self.closed.clear();
        self.refund(closed_refund);
        self.issuer_seq = 0;
        self.accounted = self.registry_bytes();
        self.registry_mark = self.accounted;
    }

    /// Count issued+live slots whose `account_anchor` matches.
    #[must_use]
    pub fn account_slots(&self, account_anchor: &str) -> usize {
        parse_id(account_anchor, "account_anchor")
            .ok()
            .map_or(0, |account| self.slots.values().filter(|slot| slot.account == account).count())
    }
}

impl Drop for PairingRelayStore {
    fn drop(&mut self) {
        self.shutdown();
        self.seed.fill(0);
    }
}

fn admit() -> Result<InFlightGuard, PairingRelayError> {
    begin_service_request().ok_or_else(|| PairingRelayError::busy(0))
}

impl PairingRelayStore {
    fn now(&self) -> Result<Now, PairingRelayError> {
        Ok(Now { wall: self.clock.wall_unix_secs()?, mono: self.clock.monotonic_ms() })
    }

    fn check_issue_quotas(&self, account: [u8; 32]) -> Result<(), PairingRelayError> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(self.busy());
        }
        let owned = self.slots.values().filter(|slot| slot.account == account).count();
        if owned >= MAX_SLOTS_PER_ACCOUNT {
            return Err(self.busy());
        }
        let recent = self.hour.get(&account).map_or(0, VecDeque::len);
        if recent >= MAX_ISSUES_PER_HOUR {
            return Err(self.busy());
        }
        if !self.hour.contains_key(&account) && self.hour.len() >= MAX_HOUR_ENTRIES {
            return Err(self.busy());
        }
        Ok(())
    }

    fn busy(&self) -> PairingRelayError {
        PairingRelayError::busy(self.clock.monotonic_ms())
    }

    fn build_ticket(
        &self,
        spec: &CreateSpec,
        create_id: [u8; 32],
        issuer_seq: u64,
        wall: u64,
    ) -> Result<CreateTicket, PairingRelayError> {
        let ticket = CreateTicket {
            schema: "ramflux.pairing.CreateTicket.v2".into(),
            version: 2,
            node_key: self.node_key.clone(),
            boot_id: self.boot_id_b64.clone(),
            create_id: encode_base64url(create_id),
            issuer_seq,
            account_anchor: spec.account_anchor.clone(),
            primary_ref: spec.primary_ref.clone(),
            spec_hash: spec.spec_hash().map_err(|e| wire(&e))?,
            issued_at: wall,
            expires_at: wall
                .checked_add(INVITATION_LIFETIME_SECS)
                .ok_or(PairingRelayError::invalid("expires_at"))?,
        };
        ticket.validate().map_err(|e| wire(&e))?;
        Ok(ticket)
    }

    fn insert_issued(
        &mut self,
        account: [u8; 32],
        create_id: [u8; 32],
        ticket: Envelope<CreateTicket>,
        spec: CreateSpec,
        now: Now,
    ) -> Result<(), PairingRelayError> {
        if !self.hour.contains_key(&account) && self.hour.len() >= MAX_HOUR_ENTRIES {
            return Err(self.busy());
        }
        let slot = Slot {
            account,
            expires_at: ticket.body.expires_at,
            monotonic_deadline: now
                .mono
                .saturating_add(INVITATION_LIFETIME_SECS.saturating_mul(1_000)),
            body: SlotBody::Issued(Box::new(IssuedSlot {
                spec_hash: spec.spec_hash().map_err(|e| wire(&e))?,
                primary_ref: spec.primary_ref,
                ticket,
            })),
        };
        let payload = slot_payload(&slot);
        self.charge(payload)?;
        if let Err(err) = self.record_hour(account, now.mono) {
            self.refund(payload);
            return Err(err);
        }
        self.slots.insert(create_id, slot);
        self.sync_registry()
    }

    fn verify_ticket(&self, create: &Create) -> Result<(), PairingRelayError> {
        let body = &create.ticket.body;
        if body.node_key != self.node_key {
            return Err(PairingRelayError::WrongContext);
        }
        let bytes = ticket_signing_bytes(body).map_err(|e| wire(&e))?;
        verify_canonical_signature(&bytes, &create.ticket.signature, &self.node_key)
            .map_err(|_| PairingRelayError::WrongContext)
    }

    fn promote_live(
        &mut self,
        id: [u8; 32],
        create: Create,
        now: Now,
    ) -> Result<Created, PairingRelayError> {
        let invitation_id = random_32().map_err(|_| PairingRelayError::invalid("entropy"))?;
        let transfer_id = if create.spec.purpose == "primary_transfer" {
            Some(random_32().map_err(|_| PairingRelayError::invalid("entropy"))?)
        } else {
            None
        };
        let primary = random_32().map_err(|_| PairingRelayError::invalid("entropy"))?;
        let mut recipient = random_32().map_err(|_| PairingRelayError::invalid("entropy"))?;
        if recipient == primary {
            recipient[0] ^= 1;
        }
        let descriptor = self.build_invitation(&create, invitation_id, transfer_id)?;
        let created = created_reply(&descriptor, primary, recipient)?;
        let (account, expires_at, monotonic_deadline, before) = {
            let slot = self.slots.get(&id).ok_or(PairingRelayError::Retired)?;
            (slot.account, slot.expires_at, slot.monotonic_deadline, slot_payload(slot))
        };
        let live_slot = Slot {
            account,
            expires_at,
            monotonic_deadline,
            body: SlotBody::Live(Box::new(LiveSlot {
                data_lease: None,
                ticket: create.ticket,
                descriptor,
                primary_token: Zeroizing::new(primary),
                recipient_token: Zeroizing::new(recipient),
                claim_nonce: None,
                initiator: Direction::default(),
                responder: Direction::default(),
                closed_reason: None,
                last_activity_ms: now.mono,
            })),
        };
        let after = slot_payload(&live_slot);
        if after >= before {
            self.charge(after.saturating_sub(before))?;
        } else {
            self.refund(before.saturating_sub(after));
        }
        self.slots.insert(id, live_slot);
        self.invitations.insert(invitation_id, id);
        self.sync_registry()?;
        Ok(created)
    }

    fn build_invitation(
        &self,
        create: &Create,
        invitation_id: [u8; 32],
        transfer_id: Option<[u8; 32]>,
    ) -> Result<Envelope<Invitation>, PairingRelayError> {
        let ticket = &create.ticket.body;
        let spec = &create.spec;
        let mut invitation = Invitation {
            schema: "ramflux.pairing.Invitation.v2".into(),
            version: 2,
            invitation_id: encode_base64url(invitation_id),
            issuer_seq: ticket.issuer_seq,
            request_id: ticket.create_id.clone(),
            node_key: self.node_key.clone(),
            public_origin: self.public_origin.clone(),
            account_anchor: spec.account_anchor.clone(),
            primary_ref: spec.primary_ref.clone(),
            base_record_hash: spec.base_record_hash.clone(),
            base_epoch: spec.base_epoch,
            purpose: spec.purpose.clone(),
            recipient_mode: spec.recipient_mode.clone(),
            destination_ref: spec.destination_ref.clone(),
            capabilities: spec.capabilities.clone(),
            lease_not_before: spec.lease_not_before,
            lease_expires_at: spec.lease_expires_at,
            data_selection: spec.data_selection.clone(),
            transfer_id: transfer_id.map(encode_base64url),
            created_at: ticket.issued_at,
            expires_at: ticket.expires_at,
        };
        invitation.normalize();
        let bytes = invitation_signing_bytes(&invitation).map_err(|e| wire(&e))?;
        Ok(Envelope {
            body: invitation,
            signature: sign_canonical_bytes_with_seed(&bytes, *self.seed),
        })
    }

    fn check_live_token(
        &self,
        invitation: [u8; 32],
        issuer_seq: u64,
        role: &str,
        token: &str,
        wall: u64,
    ) -> Result<u64, PairingRelayError> {
        let create_id = self.invitations.get(&invitation).ok_or(PairingRelayError::Retired)?;
        let slot = self.slots.get(create_id).ok_or(PairingRelayError::Retired)?;
        let now = Now { wall, mono: self.clock.monotonic_ms() };
        if slot_expired(slot, &now) {
            return Err(PairingRelayError::Expired);
        }
        let SlotBody::Live(live) = &slot.body else {
            return Err(PairingRelayError::Retired);
        };
        if live.descriptor.body.invitation_id != encode_base64url(invitation)
            || live.descriptor.body.issuer_seq != issuer_seq
        {
            return Err(PairingRelayError::WrongContext);
        }
        role_token_ok(role, token, &live.primary_token, &live.recipient_token)?;
        Ok(live.descriptor.body.expires_at)
    }

    fn check_token(
        &self,
        invitation: [u8; 32],
        issuer_seq: u64,
        role: &str,
        token: &str,
        wall: u64,
    ) -> Result<u64, PairingRelayError> {
        if self.invitations.contains_key(&invitation) {
            return self.check_live_token(invitation, issuer_seq, role, token, wall);
        }
        let Some(closed) = self.closed.get(&invitation) else {
            return Err(PairingRelayError::Retired);
        };
        let now = Now { wall, mono: self.clock.monotonic_ms() };
        if now.wall >= closed.expires_at || now.mono >= closed.monotonic_deadline {
            return Err(PairingRelayError::Expired);
        }
        if closed.issuer_seq != issuer_seq {
            return Err(PairingRelayError::WrongContext);
        }
        role_token_hash_ok(role, token, &closed.primary_hash, &closed.recipient_hash)?;
        Ok(closed.expires_at)
    }

    fn require_responder_claim(
        &self,
        invitation: [u8; 32],
        role: &str,
    ) -> Result<(), PairingRelayError> {
        if role != "responder" {
            return Ok(());
        }
        match self.live(invitation) {
            Ok(live) if live.claim_nonce.is_some() => Ok(()),
            Ok(_) => Err(PairingRelayError::WrongContext),
            Err(err) => Err(err),
        }
    }

    fn remember_closed(
        &mut self,
        create_id: [u8; 32],
        invitation: [u8; 32],
        reason: String,
    ) -> Result<(), PairingRelayError> {
        let slot = self.slots.get(&create_id).ok_or(PairingRelayError::Retired)?;
        let SlotBody::Live(live) = &slot.body else {
            return Err(PairingRelayError::Retired);
        };
        let closed = ClosedSlot {
            reason,
            issuer_seq: live.descriptor.body.issuer_seq,
            primary_hash: token_hash(&live.primary_token),
            recipient_hash: token_hash(&live.recipient_token),
            expires_at: slot.expires_at,
            monotonic_deadline: slot.monotonic_deadline,
        };
        self.charge(closed_payload(&closed))?;
        self.closed.insert(invitation, closed);
        self.sync_registry()
    }

    fn live(&self, invitation: [u8; 32]) -> Result<&LiveSlot, PairingRelayError> {
        let create_id = self.invitations.get(&invitation).ok_or(PairingRelayError::Retired)?;
        match &self.slots.get(create_id).ok_or(PairingRelayError::Retired)?.body {
            SlotBody::Live(live) => Ok(live.as_ref()),
            SlotBody::Issued(_) => Err(PairingRelayError::Retired),
        }
    }

    fn live_mut(&mut self, invitation: [u8; 32]) -> Result<&mut LiveSlot, PairingRelayError> {
        let create_id = *self.invitations.get(&invitation).ok_or(PairingRelayError::Retired)?;
        match &mut self.slots.get_mut(&create_id).ok_or(PairingRelayError::Retired)?.body {
            SlotBody::Live(live) => Ok(live.as_mut()),
            SlotBody::Issued(_) => Err(PairingRelayError::Retired),
        }
    }

    fn admit_claim_budget(
        &mut self,
        source: IpAddr,
        invitation: [u8; 32],
        mono: u64,
    ) -> Result<(), PairingRelayError> {
        if self.claims.contains_key(&invitation) {
            return Ok(());
        }
        let prefixes = claim_source_prefixes(source);
        if prefixes.is_empty() {
            return Err(PairingRelayError::invalid("source"));
        }
        if self.claims.len() >= MAX_CLAIMS {
            return Err(self.busy());
        }
        for prefix in &prefixes {
            let used = self.claims.values().filter(|entry| entry.prefixes.contains(prefix)).count();
            if used >= MAX_CLAIMS_PER_PREFIX {
                return Err(self.busy());
            }
        }
        let entry = ClaimEntry { prefixes, expires_ms: mono.saturating_add(CLAIM_GRACE_MS) };
        self.charge(claim_payload(&entry))?;
        self.claims.insert(invitation, entry);
        self.sync_registry()
    }

    fn prune(&mut self) -> Result<(), PairingRelayError> {
        let now = self.now()?;
        let expired: Vec<[u8; 32]> = self
            .slots
            .iter()
            .filter(|(_, slot)| slot_expired(slot, &now))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.release_slot(id);
        }
        self.prune_claims(now.mono);
        self.prune_closed(&now);
        self.prune_stale_frames(now.mono);
        self.prune_hour(now.mono);
        Ok(())
    }

    fn charge(&mut self, extra: usize) -> Result<(), PairingRelayError> {
        if extra == 0 {
            return Ok(());
        }
        let next =
            self.accounted.checked_add(extra).ok_or(PairingRelayError::invalid("backing"))?;
        if next > MAX_BACKING {
            return Err(self.busy());
        }
        self.accounted = next;
        self.high_water = self.high_water.max(next);
        Ok(())
    }

    fn refund(&mut self, extra: usize) {
        self.accounted = self.accounted.saturating_sub(extra);
    }

    fn registry_bytes(&self) -> usize {
        table_bytes(&self.slots)
            .saturating_add(table_bytes(&self.invitations))
            .saturating_add(table_bytes(&self.hour))
            .saturating_add(table_bytes(&self.claims))
            .saturating_add(table_bytes(&self.closed))
            .saturating_add(self.node_key.capacity())
            .saturating_add(self.boot_id_b64.capacity())
            .saturating_add(self.public_origin.capacity())
            .saturating_add(32)
    }

    fn sync_registry(&mut self) -> Result<(), PairingRelayError> {
        let now = self.registry_bytes();
        if now > self.registry_mark {
            self.charge(now.saturating_sub(self.registry_mark))?;
        } else if now < self.registry_mark {
            self.refund(self.registry_mark.saturating_sub(now));
        }
        self.registry_mark = now;
        Ok(())
    }

    fn record_hour(&mut self, account: [u8; 32], mono: u64) -> Result<(), PairingRelayError> {
        if !self.hour.contains_key(&account) {
            let times = VecDeque::with_capacity(MAX_ISSUES_PER_HOUR);
            self.charge(hour_payload(&times))?;
            self.hour.insert(account, times);
            self.sync_registry()?;
        }
        let extra = {
            let times = self.hour.get_mut(&account).ok_or(PairingRelayError::invalid("hour"))?;
            let before = hour_payload(times);
            times.push_back(mono);
            hour_payload(times).saturating_sub(before)
        };
        self.charge(extra)
    }

    fn prune_claims(&mut self, mono: u64) {
        let mut refund = 0_usize;
        self.claims.retain(|_, entry| {
            if entry.expires_ms > mono {
                true
            } else {
                refund = refund.saturating_add(claim_payload(entry));
                false
            }
        });
        self.refund(refund);
        let _ = self.sync_registry();
    }

    fn prune_closed(&mut self, now: &Now) {
        let mut refund = 0_usize;
        self.closed.retain(|_, closed| {
            if now.wall < closed.expires_at && now.mono < closed.monotonic_deadline {
                true
            } else {
                refund = refund.saturating_add(closed_payload(closed));
                false
            }
        });
        self.refund(refund);
        let _ = self.sync_registry();
    }

    fn prune_stale_frames(&mut self, mono: u64) {
        let stale: Vec<[u8; 32]> = self
            .slots
            .iter()
            .filter_map(|(id, slot)| match &slot.body {
                SlotBody::Live(live)
                    if mono.saturating_sub(live.last_activity_ms) >= CLAIM_GRACE_MS =>
                {
                    Some(*id)
                }
                _ => None,
            })
            .collect();
        let mut refund = 0_usize;
        for id in stale {
            if let Some(Slot { body: SlotBody::Live(live), .. }) = self.slots.get_mut(&id) {
                refund = refund.saturating_add(frame_list_heap(&live.initiator.frames));
                refund = refund.saturating_add(frame_list_heap(&live.responder.frames));
                live.initiator.frames.clear();
                live.responder.frames.clear();
            }
        }
        self.refund(refund);
    }

    fn prune_hour(&mut self, mono: u64) {
        let cutoff = mono.saturating_sub(HOUR_MS);
        for times in self.hour.values_mut() {
            while times.front().is_some_and(|t| *t < cutoff) {
                times.pop_front();
            }
        }
        let mut refund = 0_usize;
        self.hour.retain(|_, times| {
            if times.is_empty() {
                refund = refund.saturating_add(hour_payload(times));
                false
            } else {
                true
            }
        });
        self.refund(refund);
        let _ = self.sync_registry();
    }

    fn release_slot(&mut self, id: [u8; 32]) {
        if let Some(slot) = self.slots.remove(&id) {
            self.refund(slot_payload(&slot));
            if let SlotBody::Live(mut live) = slot.body {
                live.primary_token.fill(0);
                live.recipient_token.fill(0);
                let invitation =
                    parse_id(&live.descriptor.body.invitation_id, "invitation_id").ok();
                if let Some(invitation) = invitation {
                    self.invitations.remove(&invitation);
                    if let Some(claim) = self.claims.remove(&invitation) {
                        self.refund(claim_payload(&claim));
                    }
                }
            }
            let _ = self.sync_registry();
        }
    }
}

fn sign_ticket(
    seed: &Zeroizing<[u8; 32]>,
    ticket: CreateTicket,
) -> Result<Envelope<CreateTicket>, PairingRelayError> {
    let bytes = ticket_signing_bytes(&ticket).map_err(|e| wire(&e))?;
    Ok(Envelope { body: ticket, signature: sign_canonical_bytes_with_seed(&bytes, **seed) })
}

fn replay_created(live: &LiveSlot, create: &Create) -> Result<Created, PairingRelayError> {
    if live.ticket.body.create_id != create.ticket.body.create_id {
        return Err(PairingRelayError::Replay);
    }
    let expected = create.spec.spec_hash().map_err(|e| wire(&e))?;
    if live.ticket.body.spec_hash != expected {
        return Err(PairingRelayError::Replay);
    }
    created_reply(&live.descriptor, *live.primary_token, *live.recipient_token)
}

fn created_reply(
    descriptor: &Envelope<Invitation>,
    primary: [u8; 32],
    recipient: [u8; 32],
) -> Result<Created, PairingRelayError> {
    let created = Created {
        schema: "ramflux.pairing.Created.v2".into(),
        version: 2,
        request_id: descriptor.body.request_id.clone(),
        invitation: descriptor.clone(),
        primary_token: encode_base64url(primary),
        recipient_token: encode_base64url(recipient),
    };
    created.validate().map_err(|e| wire(&e))?;
    Ok(created)
}

fn parse_id(value: &str, field: &'static str) -> Result<[u8; 32], PairingRelayError> {
    let bytes = decode_base64url(value).map_err(|_| PairingRelayError::invalid(field))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| PairingRelayError::invalid(field))
}

fn slot_expired(slot: &Slot, now: &Now) -> bool {
    now.wall >= slot.expires_at || now.mono >= slot.monotonic_deadline
}

fn slot_counts(slots: &HashMap<[u8; 32], Slot>) -> (usize, usize, usize, usize) {
    let mut issued = 0;
    let mut live = 0;
    let mut queued_bytes = 0;
    let mut queued_frames = 0;
    for slot in slots.values() {
        match &slot.body {
            SlotBody::Issued(_) => issued += 1,
            SlotBody::Live(body) => {
                live += 1;
                for direction in [&body.initiator, &body.responder] {
                    queued_frames += direction.frames.len();
                    queued_bytes += direction
                        .frames
                        .iter()
                        .map(|(_, frame)| frame_held_bytes(frame))
                        .sum::<usize>();
                }
            }
        }
    }
    (issued, live, queued_bytes, queued_frames)
}

fn direction_mut<'a>(
    live: &'a mut LiveSlot,
    role: &str,
) -> Result<&'a mut Direction, PairingRelayError> {
    match role {
        "initiator" => Ok(&mut live.initiator),
        "responder" => Ok(&mut live.responder),
        _ => Err(PairingRelayError::WrongRole),
    }
}

fn peer_mut<'a>(
    live: &'a mut LiveSlot,
    role: &str,
) -> Result<&'a mut Direction, PairingRelayError> {
    match role {
        "initiator" => Ok(&mut live.responder),
        "responder" => Ok(&mut live.initiator),
        _ => Err(PairingRelayError::WrongRole),
    }
}

fn enqueue_cost(out: &Direction, seq: u64, digest: &str) -> Result<(), PairingRelayError> {
    if let Some((last_seq, last_digest)) = &out.last_send
        && seq == *last_seq
    {
        if digest != last_digest {
            return Err(PairingRelayError::Replay);
        }
        if out.acked_seq.is_some_and(|ack| seq <= ack)
            || out.frames.iter().any(|(held, _)| *held == seq)
        {
            return Ok(());
        }
        if out.frames.len() >= MAX_FRAMES_PER_DIRECTION {
            return Err(PairingRelayError::busy(seq));
        }
        return Ok(());
    }
    if seq != out.next_send_seq {
        return Err(PairingRelayError::Replay);
    }
    if out.frames.len() >= MAX_FRAMES_PER_DIRECTION {
        return Err(PairingRelayError::busy(seq));
    }
    Ok(())
}

fn apply_enqueue(out: &mut Direction, seq: u64, frame: RelayFrame, digest: String) {
    if let Some((last_seq, _)) = &out.last_send
        && seq == *last_seq
    {
        if out.acked_seq.is_some_and(|ack| seq <= ack)
            || out.frames.iter().any(|(held, _)| *held == seq)
        {
            return;
        }
        out.frames.push((seq, frame));
        return;
    }
    out.frames.push((seq, frame));
    out.last_send = Some((seq, digest));
    out.next_send_seq = out.next_send_seq.saturating_add(1);
}

fn ack_frames(direction: &mut Direction, ack: u64) -> usize {
    let before = frame_list_heap(&direction.frames);
    direction.acked_seq = Some(direction.acked_seq.map_or(ack, |prev| prev.max(ack)));
    direction.frames.retain(|(seq, _)| *seq > ack);
    before.saturating_sub(frame_list_heap(&direction.frames))
}

fn record_poll(direction: &mut Direction, mono: u64) -> Result<(), PairingRelayError> {
    let window = mono.saturating_sub(1_000);
    while direction.poll_times.front().is_some_and(|t| *t < window) {
        direction.poll_times.pop_front();
    }
    if direction.poll_times.len() >= MAX_POLLS_PER_SEC {
        return Err(PairingRelayError::busy(mono));
    }
    direction.poll_times.push_back(mono);
    Ok(())
}

fn take_polled_frames(direction: &Direction) -> Result<Vec<QueuedFrame>, PairingRelayError> {
    let mut frames = Vec::new();
    for (seq, frame) in &direction.frames {
        let candidate = QueuedFrame { seq: *seq, frame: frame.clone() };
        let mut trial = frames.clone();
        trial.push(candidate.clone());
        let polled = Polled {
            schema: "ramflux.pairing.Polled.v2".into(),
            version: 2,
            invitation_id: encode_base64url([0; 32]),
            frames: trial,
            closed: false,
        };
        if ramflux_protocol::canonical_json_bytes(&polled)
            .map_err(|_| PairingRelayError::invalid("json"))?
            .len()
            > MAX_FRAME_BYTES
        {
            break;
        }
        frames.push(candidate);
        if frames.len() == MAX_FRAMES_PER_DIRECTION {
            break;
        }
    }
    Ok(frames)
}

fn closed_reply(invitation_id: &str, reason: &str) -> Closed {
    Closed {
        schema: "ramflux.pairing.Closed.v2".into(),
        version: 2,
        invitation_id: invitation_id.into(),
        reason: reason.into(),
    }
}

fn role_token_ok(
    role: &str,
    presented: &str,
    primary: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<(), PairingRelayError> {
    role_match(role, token_eq(primary, presented), token_eq(recipient, presented))
}

fn role_token_hash_ok(
    role: &str,
    presented: &str,
    primary_hash: &[u8; 32],
    recipient_hash: &[u8; 32],
) -> Result<(), PairingRelayError> {
    role_match(
        role,
        token_hash_eq(primary_hash, presented),
        token_hash_eq(recipient_hash, presented),
    )
}

fn role_match(role: &str, init_ok: bool, resp_ok: bool) -> Result<(), PairingRelayError> {
    match role {
        "initiator" if init_ok => Ok(()),
        "responder" if resp_ok => Ok(()),
        "initiator" | "responder" => Err(PairingRelayError::WrongContext),
        _ => Err(PairingRelayError::WrongRole),
    }
}

fn decode_token(presented: &str) -> (bool, [u8; 32]) {
    let decoded = decode_base64url(presented).ok();
    let mut buf = [0_u8; 32];
    let valid = match decoded {
        Some(bytes) if bytes.len() == 32 => {
            buf.copy_from_slice(&bytes);
            true
        }
        _ => false,
    };
    (valid, buf)
}

fn token_eq(expected: &[u8; 32], presented: &str) -> bool {
    let (valid, buf) = decode_token(presented);
    constant_time_eq(&buf, expected) && valid
}

fn token_hash_eq(expected_hash: &[u8; 32], presented: &str) -> bool {
    let (valid, buf) = decode_token(presented);
    constant_time_eq(&token_hash(&buf), expected_hash) && valid
}

fn frame_held_bytes(frame: &RelayFrame) -> usize {
    ramflux_protocol::canonical_json_bytes(frame).map_or(MAX_FRAME_BYTES, |bytes| bytes.len())
}

fn claimed_reply(claim: &Claim, expires_at: u64) -> Claimed {
    Claimed {
        schema: "ramflux.pairing.Claimed.v2".into(),
        version: 2,
        invitation_id: claim.invitation_id.clone(),
        issuer_seq: claim.issuer_seq,
        claim_nonce: claim.claim_nonce.clone(),
        role: "responder".into(),
        expires_at,
    }
}
