// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor-owned pairing coordinator. Two local confirmations precede approval.
//! Dormant and default-off; a peer `confirmed` flag never stands for the local user.
use super::transport::{
    HttpRelay, PairingNative, PreparedCreate, PreparedIssue, assemble_chunks, reveal_chunks, wire,
};
use crate::SdkError;
use crate::time::now_unix_timestamp;
use ramflux_crypto::custody::pairing::{EstablishedSas, PairingRole, PendingSas, commit};
use ramflux_crypto::{X25519KeyPair, random_32};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, BeginResult, Cancel, Confirm, Join, LocalResult, Outcome, StatusRequest, Update,
};
use ramflux_protocol::custody::pairing::native::{CreateSpec, Invitation, InviteToken};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Close, Poll, QueuedFrame, RelayFrame, Send,
};
use ramflux_protocol::custody::pairing::{Commit, Common, PairingWire, Reveal, RoleContext};
use ramflux_protocol::{decode_base64url, encode_base64url};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

const LIVE_CAP: usize = 3;
const _: () = assert!(LIVE_CAP >= 1);
const SYNC_STEPS: u32 = 64;

/// True when the default-off pairing opt-in is set.
#[must_use]
pub fn pairing_enabled() -> bool {
    matches!(std::env::var("RAMFLUX_DEVICE_PAIRING_ENABLED").as_deref(), Ok("1"))
}

/// Responder-only prepared→acknowledged. The publisher (local primary) must submit first.
/// # Errors
/// `submitted_required` when the publisher skips submitted; `responder_submitted` otherwise.
pub fn validate_head_advance(
    from: &str,
    to: &str,
    publisher_is_local_primary: bool,
) -> Result<(), SdkError> {
    match (from, to) {
        ("prepared", "submitted") | ("submitted", "acknowledged") if publisher_is_local_primary => {
            Ok(())
        }
        ("prepared", "submitted") | ("submitted", "acknowledged") => {
            Err(SdkError::PairingField("responder_submitted"))
        }
        ("prepared", "acknowledged") if publisher_is_local_primary => {
            Err(SdkError::PairingField("submitted_required"))
        }
        ("prepared", "acknowledged") => Ok(()),
        (same, next) if same == next => Ok(()),
        _ => Err(SdkError::PairingField("state")),
    }
}

/// Local device identity for one ceremony actor.
#[derive(Clone)]
pub struct PairingIdentity {
    pub account_id: String,
    pub local_ref: DeviceRef,
    pub master_public_key: String,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub is_primary: bool,
}

/// Actor-owned ceremony generation. One live run per actor.
pub struct PairingActor {
    identity: PairingIdentity,
    native: Arc<dyn PairingNative>,
    relay: HttpRelay,
    actor_generation: u64,
    frontend_generation: u64,
    ceremony: Option<Ceremony>,
    unsolicited: u32,
}

struct Ceremony {
    operation_id: String,
    generation: u64,
    role: PairingRole,
    phase: String,
    expires_at: u64,
    invitation: Invitation,
    issuer_seq: u64,
    token: Zeroizing<String>,
    next_send_seq: u64,
    last_poll_seq: Option<u64>,
    outbound: VecDeque<RelayFrame>,
    sas: SasHold,
    local_confirmed: bool,
    peer_mac_ok: bool,
    displayed_th: Option<[u8; 32]>,
    displayed_proposal: Option<String>,
    common: Common,
    peer_ref: Option<DeviceRef>,
    peer_name: Option<String>,
    result: Option<String>,
    cleanup: String,
    emoji: Option<Vec<u64>>,
    reveal_chunks: BTreeMap<u64, (String, u64, u64, String)>,
    reveal_sent: bool,
    frames_seen: u64,
    head_state: Option<String>,
}

enum SasHold {
    None,
    Pending(Box<PendingSas>),
    Established(Box<EstablishedSas>),
}

impl PairingActor {
    #[must_use]
    pub fn new(
        identity: PairingIdentity,
        native: Arc<dyn PairingNative>,
        relay: HttpRelay,
    ) -> Self {
        Self {
            identity,
            native,
            relay,
            actor_generation: 1,
            frontend_generation: 1,
            ceremony: None,
            unsolicited: 0,
        }
    }

    #[must_use]
    pub fn actor_generation(&self) -> u64 {
        self.actor_generation
    }

    #[must_use]
    pub fn frontend_generation(&self) -> u64 {
        self.frontend_generation
    }

    #[must_use]
    pub fn unsolicited_prompts(&self) -> u32 {
        self.unsolicited
    }

    #[must_use]
    pub fn frames_seen(&self) -> u64 {
        self.ceremony.as_ref().map_or(0, |c| c.frames_seen)
    }

    /// Primary begin: Prepare Issue/Create then Apply. One-shot recipient token in the result.
    /// # Errors
    /// `PrimaryRequired`, `Busy`, native refusal, or a live ceremony.
    pub fn begin(&mut self, begin: Begin) -> Result<LocalResult, SdkError> {
        begin.validate().map_err(|e| wire(&e))?;
        Self::require_open()?;
        if !self.identity.is_primary {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
        self.expire_live();
        if self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase)) {
            return Err(SdkError::PairingCode("Busy"));
        }
        let spec = spec_from_begin(&self.identity, &begin)?;
        let prepared = PreparedIssue::prepare(spec.clone())?;
        let issued = prepared.apply(self.native.as_ref())?;
        let created = PreparedCreate::prepare(issued.ticket, spec)?.apply(self.native.as_ref())?;
        let invitation = created.invitation.body.clone();
        let common = invitation
            .project_common(self.identity.master_public_key.clone())
            .map_err(|e| wire(&e))?;
        let generation = self.actor_generation;
        let mut ceremony = self.open_ceremony(CeremonyOpen {
            operation_id: created.request_id.clone(),
            generation,
            role: PairingRole::Initiator,
            invitation,
            token: created.primary_token.clone(),
            common,
            display_name: begin.display_name,
        })?;
        ceremony.phase = "invited".into();
        Self::queue_commit(&mut ceremony)?;
        self.ceremony = Some(ceremony);
        let result = BeginResult {
            schema: "ramflux.pairing.BeginResult.v2".into(),
            version: 2,
            operation_id: created.request_id.clone(),
            generation,
            expires_at: created.invitation.body.expires_at,
            invite_token: InviteToken {
                schema: "ramflux.pairing.InviteToken.v2".into(),
                version: 2,
                invitation: created.invitation.clone(),
                recipient_token: created.recipient_token.clone(),
            },
        };
        result.validate().map_err(|e| wire(&e))?;
        Ok(local_begin(result))
    }

    /// Recipient join: one claim then SAS commit. Token is consumed from the QR display.
    /// # Errors
    /// `Busy`, `Expired`, or a claim Failure.
    pub fn join(&mut self, join: Join) -> Result<LocalResult, SdkError> {
        join.validate().map_err(|e| wire(&e))?;
        Self::require_open()?;
        self.expire_live();
        if self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase)) {
            return Err(SdkError::PairingCode("Busy"));
        }
        let invitation = join.token.invitation.body.clone();
        invitation.validate().map_err(|e| wire(&e))?;
        let nonce = random_32()?;
        let claimed = self.relay.claim(&Claim {
            schema: "ramflux.pairing.Claim.v2".into(),
            version: 2,
            invitation_id: invitation.invitation_id.clone(),
            issuer_seq: invitation.issuer_seq,
            recipient_token: join.token.recipient_token.clone(),
            claim_nonce: encode_base64url(nonce),
        })?;
        let _ = claimed;
        let common = invitation
            .project_common(self.identity.master_public_key.clone())
            .map_err(|e| wire(&e))?;
        let generation = self.actor_generation;
        let mut ceremony = self.open_ceremony(CeremonyOpen {
            operation_id: invitation.request_id.clone(),
            generation,
            role: PairingRole::Responder,
            invitation,
            token: join.token.recipient_token.clone(),
            common,
            display_name: join.display_name,
        })?;
        ceremony.phase = "invited".into();
        Self::queue_commit(&mut ceremony)?;
        self.ceremony = Some(ceremony);
        self.sync_relay()
    }

    /// Local SAS match bound to the currently displayed transcript. Never a peer boolean.
    /// # Errors
    /// Generation mismatch, `SasMismatch`, or `already_confirmed`.
    pub fn confirm(&mut self, confirm: &Confirm) -> Result<LocalResult, SdkError> {
        confirm.validate().map_err(|e| wire(&e))?;
        Self::require_open()?;
        let th = self.with_ceremony(|c| {
            check_generation(c, confirm.generation)?;
            if c.phase != "sas_pending" {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let displayed = c.displayed_th.ok_or(SdkError::PairingCode("WrongContext"))?;
            let got = decode32(&confirm.transcript_hash)?;
            if got != displayed {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            Ok(displayed)
        })?;
        if !confirm.r#match {
            return self.fail("rejected", "SasMismatch");
        }
        let mac = self.with_ceremony_mut(|c| {
            let SasHold::Established(sas) = &mut c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            let mac = sas.confirm_local(&th, true)?;
            c.local_confirmed = true;
            Ok(mac)
        })?;
        self.with_ceremony_mut(|c| {
            c.outbound.push_back(RelayFrame::Confirm {
                role: c.role.as_str().into(),
                transcript_hash: encode_base64url(th),
                mac: encode_base64url(mac),
            });
            Ok(())
        })?;
        self.sync_relay()
    }

    /// Primary approval after TWO local confirmations and both direction MACs.
    /// # Errors
    /// `PrimaryRequired`, `WrongContext`, or a TH/proposal mismatch.
    pub fn approve(&mut self, approve: &Approve) -> Result<LocalResult, SdkError> {
        approve.validate().map_err(|e| wire(&e))?;
        Self::require_open()?;
        if !self.identity.is_primary {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
        self.with_ceremony(|c| {
            check_generation(c, approve.generation)?;
            if c.phase != "mutually_confirmed" {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            if !c.local_confirmed || !c.peer_mac_ok {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let th = c.displayed_th.ok_or(SdkError::PairingCode("WrongContext"))?;
            if decode32(&approve.transcript_hash)? != th {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let proposal =
                c.displayed_proposal.as_deref().ok_or(SdkError::PairingCode("WrongContext"))?;
            if proposal != approve.proposal_hash {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            Ok(())
        })?;
        if !approve.approved {
            return self.fail("rejected", "NotFound");
        }
        self.with_ceremony_mut(|c| {
            c.phase = "proposal_pending".into();
            c.emoji = None;
            Ok(())
        })?;
        self.status_update()
    }

    /// Cancel the current generation and wipe SAS secrets.
    /// # Errors
    /// Generation mismatch or no live ceremony.
    pub fn cancel(&mut self, cancel: &Cancel) -> Result<LocalResult, SdkError> {
        cancel.validate().map_err(|e| wire(&e))?;
        Self::require_open()?;
        self.with_ceremony(|c| check_generation(c, cancel.generation))?;
        self.fail("cancelled", "Retired")
    }

    /// Status never re-exports the invite token.
    /// # Errors
    /// Generation mismatch.
    pub fn status(&mut self, request: &StatusRequest) -> Result<LocalResult, SdkError> {
        request.validate().map_err(|e| wire(&e))?;
        self.expire_live();
        self.with_ceremony(|c| check_generation(c, request.generation))?;
        self.status_update()
    }

    /// Drive relay send/poll until a user wait or a bound is hit.
    /// # Errors
    /// Transport, `Busy`, or protocol failure.
    pub fn sync_relay(&mut self) -> Result<LocalResult, SdkError> {
        self.expire_live();
        for _ in 0..SYNC_STEPS {
            self.flush_send()?;
            let Some(operation) = self.ceremony.as_ref().map(|c| c.operation_id.clone()) else {
                break;
            };
            let _ = operation;
            let polled = match self.poll_once() {
                Ok(polled) => polled,
                Err(SdkError::PairingCode("Busy")) => break,
                Err(error) => return Err(error),
            };
            self.ingest(polled.frames)?;
            if polled.closed {
                return self.fail("cancelled", "Retired");
            }
            if self.waiting_for_user() {
                break;
            }
            let idle = self.ceremony.as_ref().is_some_and(|c| c.outbound.is_empty());
            if idle {
                break;
            }
        }
        self.status_update()
    }

    /// Close on lock. Frontend generation advances so a stale confirm cannot bind.
    /// # Errors
    /// No live ceremony.
    pub fn lock(&mut self) -> Result<LocalResult, SdkError> {
        self.frontend_generation = self.frontend_generation.saturating_add(1);
        self.actor_generation = self.actor_generation.saturating_add(1);
        self.fail("cancelled", "Retired")
    }

    /// App background after the deadline expires the run; never auto-confirms.
    /// # Errors
    /// No live ceremony.
    pub fn background(&mut self) -> Result<LocalResult, SdkError> {
        self.fail("expired", "Expired")
    }

    /// Higher/conflicting head invalidates the pending SAS.
    /// # Errors
    /// No live ceremony.
    pub fn note_head_change(&mut self) -> Result<LocalResult, SdkError> {
        self.fail("rejected", "HeadChanged")
    }

    /// Displayed proposal hash for the current SAS run.
    /// # Errors
    /// `WrongContext` before SAS is revealed.
    pub fn displayed_proposal(&self) -> Result<String, SdkError> {
        self.ceremony
            .as_ref()
            .and_then(|c| c.displayed_proposal.clone())
            .ok_or(SdkError::PairingCode("WrongContext"))
    }

    /// Displayed transcript hash.
    /// # Errors
    /// `WrongContext` before SAS is revealed.
    pub fn displayed_transcript(&self) -> Result<String, SdkError> {
        let th = self
            .ceremony
            .as_ref()
            .and_then(|c| c.displayed_th)
            .ok_or(SdkError::PairingCode("WrongContext"))?;
        Ok(encode_base64url(th))
    }

    /// Ingest a peer-supplied confirmed flag. Production ignores it.
    pub fn note_peer_confirmed_flag(&mut self, confirmed: bool) {
        if let Some(ceremony) = self.ceremony.as_mut() {
            apply_peer_confirmed_flag(ceremony, confirmed);
        }
        let _ = self.maybe_mutually_confirmed();
    }

    fn require_open() -> Result<(), SdkError> {
        if pairing_enabled() { Ok(()) } else { Err(SdkError::PairingCode("NotFound")) }
    }

    fn expire_live(&mut self) {
        let now = wall();
        let expired =
            self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase) && now >= c.expires_at);
        if expired {
            let _ = self.fail("expired", "Expired");
        }
    }

    fn waiting_for_user(&self) -> bool {
        self.ceremony.as_ref().is_some_and(|c| {
            matches!(c.phase.as_str(), "sas_pending" | "mutually_confirmed" | "proposal_pending")
                && c.outbound.is_empty()
        })
    }

    fn open_ceremony(&self, open: CeremonyOpen) -> Result<Ceremony, SdkError> {
        let mut sas_secret = random_32()?;
        let role = open.role;
        let (context, salt) = build_context(
            role,
            &open.common,
            self.device_ref(role, &open.invitation),
            open.display_name,
            &sas_secret,
        )?;
        let pending = commit(role, &context, &sas_secret, &salt)?;
        sas_secret.zeroize();
        Ok(Ceremony {
            operation_id: open.operation_id,
            generation: open.generation,
            role,
            phase: "invited".into(),
            expires_at: open.invitation.expires_at,
            issuer_seq: open.invitation.issuer_seq,
            invitation: open.invitation,
            token: Zeroizing::new(open.token),
            next_send_seq: 0,
            last_poll_seq: None,
            outbound: VecDeque::new(),
            sas: SasHold::Pending(Box::new(pending)),
            local_confirmed: false,
            peer_mac_ok: false,
            displayed_th: None,
            displayed_proposal: None,
            common: open.common,
            peer_ref: None,
            peer_name: None,
            result: None,
            cleanup: "none".into(),
            emoji: None,
            reveal_chunks: BTreeMap::new(),
            reveal_sent: false,
            frames_seen: 0,
            head_state: None,
        })
    }

    fn device_ref(&self, role: PairingRole, invitation: &Invitation) -> DeviceRef {
        match role {
            PairingRole::Initiator => invitation.primary_ref.clone(),
            PairingRole::Responder => self.identity.local_ref.clone(),
        }
    }

    fn queue_commit(ceremony: &mut Ceremony) -> Result<(), SdkError> {
        let SasHold::Pending(pending) = &ceremony.sas else {
            return Err(SdkError::PairingCode("WrongContext"));
        };
        let commit = Commit {
            schema: "ramflux.pairing.Commit.v2".into(),
            version: 2,
            invitation_id: ceremony.invitation.invitation_id.clone(),
            role: ceremony.role.as_str().into(),
            commitment: encode_base64url(pending.commitment()),
        };
        commit.validate().map_err(|e| wire(&e))?;
        ceremony.outbound.push_back(RelayFrame::Commit { value: commit });
        Ok(())
    }

    fn flush_send(&mut self) -> Result<(), SdkError> {
        loop {
            let (send, empty) = {
                let Some(c) = self.ceremony.as_mut() else { return Ok(()) };
                let Some(frame) = c.outbound.front().cloned() else { return Ok(()) };
                let send = Send {
                    schema: "ramflux.pairing.Send.v2".into(),
                    version: 2,
                    invitation_id: c.invitation.invitation_id.clone(),
                    issuer_seq: c.issuer_seq,
                    role: c.role.as_str().into(),
                    token: c.token.as_str().into(),
                    seq: c.next_send_seq,
                    frame,
                };
                (send, false)
            };
            let _ = empty;
            match self.relay.send(&send) {
                Ok(_) => {
                    if let Some(c) = self.ceremony.as_mut() {
                        c.outbound.pop_front();
                        c.next_send_seq = c.next_send_seq.saturating_add(1);
                    }
                }
                Err(SdkError::PairingCode("Busy")) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    fn poll_once(&mut self) -> Result<ramflux_protocol::custody::pairing::relay::Polled, SdkError> {
        let (poll, _id) = {
            let c = self.ceremony.as_ref().ok_or(SdkError::PairingCode("NotFound"))?;
            (
                Poll {
                    schema: "ramflux.pairing.Poll.v2".into(),
                    version: 2,
                    invitation_id: c.invitation.invitation_id.clone(),
                    issuer_seq: c.issuer_seq,
                    role: c.role.as_str().into(),
                    token: c.token.as_str().into(),
                    after_seq: c.last_poll_seq,
                },
                c.operation_id.clone(),
            )
        };
        self.relay.poll(&poll)
    }

    fn ingest(&mut self, frames: Vec<QueuedFrame>) -> Result<(), SdkError> {
        let mut rest = Vec::new();
        for queued in frames {
            self.with_ceremony_mut(|c| {
                c.frames_seen = c.frames_seen.saturating_add(1);
                c.last_poll_seq = Some(queued.seq);
                Ok(())
            })?;
            match queued.frame {
                RelayFrame::Commit { value } => self.ingest_commit(&value)?,
                other => rest.push(other),
            }
        }
        self.maybe_reveal()?;
        for frame in rest {
            match frame {
                RelayFrame::RevealChunk { object_id, index, count, total_bytes, bytes } => {
                    self.ingest_reveal_chunk(object_id, index, count, total_bytes, bytes)?;
                }
                RelayFrame::Confirm { role: _, transcript_hash: _, mac } => {
                    self.ingest_confirm_mac(&mac, false)?;
                }
                RelayFrame::OfferChunk { .. }
                | RelayFrame::Channel { .. }
                | RelayFrame::Commit { .. } => {}
            }
        }
        self.maybe_mutually_confirmed()?;
        Ok(())
    }

    fn ingest_commit(&mut self, value: &Commit) -> Result<(), SdkError> {
        value.validate().map_err(|e| wire(&e))?;
        let peer = match value.role.as_str() {
            "initiator" => PairingRole::Initiator,
            "responder" => PairingRole::Responder,
            _ => return Err(SdkError::PairingCode("WrongRole")),
        };
        let commitment = decode32(&value.commitment)?;
        self.with_ceremony_mut(|c| {
            let SasHold::Pending(pending) = &mut c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            pending.store_peer_commitment(peer, commitment)?;
            if c.phase == "invited" {
                c.phase = "commitments".into();
            }
            Ok(())
        })
    }

    fn ingest_reveal_chunk(
        &mut self,
        object_id: String,
        index: u64,
        count: u64,
        total_bytes: u64,
        bytes: String,
    ) -> Result<(), SdkError> {
        let complete = self.with_ceremony_mut(|c| {
            c.reveal_chunks.insert(index, (object_id, count, total_bytes, bytes));
            Ok(u64::try_from(c.reveal_chunks.len()).ok() == Some(count))
        })?;
        if complete {
            self.finish_reveal()?;
        }
        Ok(())
    }

    fn finish_reveal(&mut self) -> Result<(), SdkError> {
        let assembled = self.with_ceremony_mut(|c| {
            let chunks: Vec<(u64, String, u64, u64, String)> = c
                .reveal_chunks
                .iter()
                .map(|(i, (id, count, total, bytes))| {
                    (*i, id.clone(), *count, *total, bytes.clone())
                })
                .collect();
            c.reveal_chunks.clear();
            assemble_chunks(&chunks)
        })?;
        let reveal = Reveal::from_wire_bytes(&assembled).map_err(|e| wire(&e))?;
        let salt = decode32(&reveal.salt)?;
        let peer = reveal.context.clone();
        self.with_ceremony_mut(|c| {
            let pending = match std::mem::replace(&mut c.sas, SasHold::None) {
                SasHold::Pending(pending) => pending,
                other => {
                    c.sas = other;
                    return Err(SdkError::PairingCode("WrongContext"));
                }
            };
            let established = pending.establish(&peer, &salt)?;
            c.displayed_th = Some(established.transcript_hash());
            c.displayed_proposal = Some(proposal_hash(&c.common)?);
            c.emoji = Some(established.emoji_indices().iter().map(|i| u64::from(*i)).collect());
            c.peer_ref = Some(peer.device_ref.clone());
            c.peer_name = Some(peer.display_name.clone());
            c.phase = "sas_pending".into();
            c.sas = SasHold::Established(Box::new(established));
            c.cleanup = "none".into();
            Ok(())
        })
    }

    fn ingest_confirm_mac(&mut self, mac: &str, peer_confirmed_flag: bool) -> Result<(), SdkError> {
        ignore_peer_confirmed_flag(peer_confirmed_flag);
        let mac = decode32(mac)?;
        self.with_ceremony_mut(|c| {
            let SasHold::Established(sas) = &mut c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            sas.accept_peer_mac(&mac)?;
            c.peer_mac_ok = true;
            Ok(())
        })
    }

    fn maybe_reveal(&mut self) -> Result<(), SdkError> {
        let should = self.with_ceremony(|c| {
            Ok(!c.reveal_sent && matches!(&c.sas, SasHold::Pending(_)) && c.phase == "commitments")
        })?;
        if !should {
            return Ok(());
        }
        let ready = self.with_ceremony(|c| {
            let SasHold::Pending(pending) = &c.sas else { return Ok(false) };
            Ok(pending.reveal().is_ok())
        })?;
        if !ready {
            return Ok(());
        }
        let (bytes, object) = self.with_ceremony_mut(|c| {
            let SasHold::Pending(pending) = &c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            let (salt, context) = pending.reveal()?;
            let reveal = Reveal {
                schema: "ramflux.pairing.Reveal.v2".into(),
                version: 2,
                invitation_id: c.invitation.invitation_id.clone(),
                role: c.role.as_str().into(),
                salt: encode_base64url(salt),
                context: context.clone(),
            };
            reveal.validate().map_err(|e| wire(&e))?;
            c.reveal_sent = true;
            Ok((reveal.to_wire_bytes().map_err(|e| wire(&e))?, random_32()?))
        })?;
        for frame in reveal_chunks(object, &bytes)? {
            self.with_ceremony_mut(|c| {
                c.outbound.push_back(frame);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn maybe_mutually_confirmed(&mut self) -> Result<(), SdkError> {
        self.with_ceremony_mut(|c| {
            if c.local_confirmed && c.peer_mac_ok && c.phase == "sas_pending" {
                c.phase = "mutually_confirmed".into();
            }
            Ok(())
        })
    }

    fn fail(&mut self, phase: &str, code: &'static str) -> Result<LocalResult, SdkError> {
        let close = self.ceremony.as_mut().map(|c| {
            match &mut c.sas {
                SasHold::Pending(pending) => pending.cleanup(),
                SasHold::Established(sas) => sas.cleanup(),
                SasHold::None => {}
            }
            c.sas = SasHold::None;
            c.phase = phase.into();
            c.result = Some(code.into());
            c.cleanup = "done".into();
            c.emoji = None;
            c.outbound.clear();
            c.head_state = None;
            Close {
                schema: "ramflux.pairing.Close.v2".into(),
                version: 2,
                invitation_id: c.invitation.invitation_id.clone(),
                issuer_seq: c.issuer_seq,
                role: c.role.as_str().into(),
                token: c.token.as_str().into(),
                reason: close_reason(code),
            }
        });
        if let Some(close) = close {
            let _ = self.relay.close(&close);
            if let Some(c) = self.ceremony.as_mut() {
                c.token.zeroize();
            }
        }
        self.actor_generation = self.actor_generation.saturating_add(1);
        self.status_update()
    }

    fn status_update(&self) -> Result<LocalResult, SdkError> {
        let c = self.ceremony.as_ref().ok_or(SdkError::PairingCode("NotFound"))?;
        let update = build_update(c)?;
        Ok(local_update(update))
    }

    fn with_ceremony<T>(
        &self,
        f: impl FnOnce(&Ceremony) -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        f(self.ceremony.as_ref().ok_or(SdkError::PairingCode("NotFound"))?)
    }

    fn with_ceremony_mut<T>(
        &mut self,
        f: impl FnOnce(&mut Ceremony) -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        f(self.ceremony.as_mut().ok_or(SdkError::PairingCode("NotFound"))?)
    }
}

struct CeremonyOpen {
    operation_id: String,
    generation: u64,
    role: PairingRole,
    invitation: Invitation,
    token: String,
    common: Common,
    display_name: String,
}

/// A peer-provided `confirmed:true` is ignored. Local confirm is `confirm()` only.
fn apply_peer_confirmed_flag(ceremony: &mut Ceremony, confirmed: bool) {
    ignore_peer_confirmed_flag(confirmed);
    let _ = ceremony.local_confirmed;
}

fn ignore_peer_confirmed_flag(confirmed: bool) {
    let _ = confirmed;
}

fn wall() -> u64 {
    u64::try_from(now_unix_timestamp()).unwrap_or(0)
}

fn terminal(phase: &str) -> bool {
    matches!(phase, "cancelled" | "expired" | "rejected" | "completed")
}

fn check_generation(ceremony: &Ceremony, generation: u64) -> Result<(), SdkError> {
    if ceremony.generation == generation {
        Ok(())
    } else {
        Err(SdkError::PairingCode("WrongContext"))
    }
}

fn decode32(value: &str) -> Result<[u8; 32], SdkError> {
    let bytes = decode_base64url(value).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| SdkError::PairingCode("InvalidInput"))
}

fn spec_from_begin(identity: &PairingIdentity, begin: &Begin) -> Result<CreateSpec, SdkError> {
    let spec = CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: identity.local_ref.account_anchor.clone(),
        primary_ref: identity.local_ref.clone(),
        base_record_hash: identity.base_record_hash.clone(),
        base_epoch: identity.base_epoch,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: begin.capabilities.clone(),
        lease_not_before: begin.lease_not_before,
        lease_expires_at: begin.lease_expires_at,
        data_selection: vec![],
        ttl_seconds: 300,
    };
    spec.validate().map_err(|e| wire(&e))?;
    Ok(spec)
}

fn build_context(
    role: PairingRole,
    common: &Common,
    device_ref: DeviceRef,
    display_name: String,
    sas_secret: &[u8; 32],
) -> Result<(RoleContext, [u8; 32]), SdkError> {
    let mut branch = random_32()?;
    let mut agree = random_32()?;
    let salt = random_32()?;
    let context = RoleContext {
        schema: "ramflux.pairing.RoleContext.v2".into(),
        version: 2,
        role: role.as_str().into(),
        common: common.clone(),
        device_ref,
        branch_key: encode_base64url(
            ed25519_dalek::SigningKey::from_bytes(&branch).verifying_key().to_bytes(),
        ),
        agreement_key: encode_base64url(X25519KeyPair::from_seed(agree).public),
        sas_key: encode_base64url(X25519KeyPair::from_seed_ref(sas_secret).public),
        hpke_key: None,
        display_name,
    };
    branch.zeroize();
    agree.zeroize();
    context.validate().map_err(|e| wire(&e))?;
    Ok((context, salt))
}

fn proposal_hash(common: &Common) -> Result<String, SdkError> {
    let body = serde_json::json!({
        "capabilities": common.capabilities,
        "lease_not_before": common.lease_not_before,
        "lease_expires_at": common.lease_expires_at,
        "purpose": common.purpose,
    });
    let bytes = ramflux_protocol::canonical_json_bytes(&body)?;
    Ok(encode_base64url(*blake3::hash(&bytes).as_bytes()))
}

fn build_update(c: &Ceremony) -> Result<Update, SdkError> {
    let p = phase_index(&c.phase)?;
    let th = c.displayed_th.map(encode_base64url);
    let update = Update {
        schema: "ramflux.pairing.Update.v2".into(),
        version: 2,
        operation_id: c.operation_id.clone(),
        generation: c.generation,
        phase: c.phase.clone(),
        expires_at: c.expires_at,
        transcript_hash: if p >= 2 { th } else { None },
        emoji_indices: c.emoji.clone(),
        peer_ref: c.peer_ref.clone(),
        peer_name: c.peer_name.clone(),
        capabilities: c.common.capabilities.clone(),
        lease_not_before: c.common.lease_not_before,
        lease_expires_at: c.common.lease_expires_at,
        proposal_hash: if p >= 5 { c.displayed_proposal.clone() } else { None },
        record_hash: None,
        result: c.result.clone(),
        cleanup: c.cleanup.clone(),
    };
    update.validate().map_err(|e| wire(&e))?;
    Ok(update)
}

fn phase_index(phase: &str) -> Result<usize, SdkError> {
    ramflux_protocol::custody::pairing::local_dto::PHASES
        .iter()
        .position(|name| *name == phase)
        .ok_or(SdkError::PairingField("phase"))
}

fn close_reason(code: &str) -> String {
    match code {
        "SasMismatch" => "mismatch",
        "Expired" => "expired",
        "HeadChanged" | "WrongContext" => "protocol",
        _ => "cancel",
    }
    .into()
}

fn local_begin(value: BeginResult) -> LocalResult {
    LocalResult {
        schema: "ramflux.pairing.LocalResult.v2".into(),
        version: 2,
        outcome: Outcome::Begin { value: Box::new(value) },
    }
}

fn local_update(value: Update) -> LocalResult {
    LocalResult {
        schema: "ramflux.pairing.LocalResult.v2".into(),
        version: 2,
        outcome: Outcome::Update { value: Box::new(value) },
    }
}

fn actors() -> &'static Mutex<HashMap<String, PairingActor>> {
    static ACTORS: OnceLock<Mutex<HashMap<String, PairingActor>>> = OnceLock::new();
    ACTORS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install an actor for bus dispatch. Tests and the dormant opt-in share this map.
pub fn install_actor(account_id: String, actor: PairingActor) {
    let mut map = actors().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    map.insert(account_id, actor);
}

/// Dispatch a pairing bus method to the actor for `account_id`.
/// # Errors
/// `NotFound` when no actor is installed, or the method/ceremony error.
pub fn handle_bus(
    account_id: &str,
    method: &str,
    body: serde_json::Value,
) -> Result<LocalResult, SdkError> {
    let mut map = actors().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let actor = map.get_mut(account_id).ok_or(SdkError::PairingCode("NotFound"))?;
    match method {
        "device.pair.begin" => actor.begin(bus_body(body)?),
        "device.pair.join" => actor.join(bus_body(body)?),
        "device.pair.confirm" => actor.confirm(&bus_body(body)?),
        "device.pair.approve" => actor.approve(&bus_body(body)?),
        "device.pair.cancel" => actor.cancel(&bus_body(body)?),
        "device.pair.status" => actor.status(&bus_body(body)?),
        _ => Err(SdkError::LocalBus(format!("unsupported local bus method: {method}"))),
    }
}

fn bus_body<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> Result<T, SdkError> {
    serde_json::from_value(body).map_err(SdkError::from)
}

impl Drop for Ceremony {
    fn drop(&mut self) {
        self.token.zeroize();
        match &mut self.sas {
            SasHold::Pending(pending) => pending.cleanup(),
            SasHold::Established(sas) => sas.cleanup(),
            SasHold::None => {}
        }
    }
}
