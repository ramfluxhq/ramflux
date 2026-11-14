// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor-owned pairing coordinator. Two local confirmations precede approval.
//! Dormant and default-off; a peer `confirmed` flag never stands for the local user.
use super::transport::{
    PairingConfig, PairingNative, PairingTransport, PreparedCreate, PreparedIssue, assemble_chunks,
    offer_chunks, reveal_chunks, wire,
};
use crate::SdkError;
use crate::time::now_unix_timestamp;
use ramflux_crypto::custody::pairing::{EstablishedSas, PairingRole, PendingSas, commit};
use ramflux_crypto::{CryptoError, X25519KeyPair, random_32, verify_canonical_signature};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::Envelope;
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, BeginResult, Cancel, Confirm, Join, LocalResult, Outcome, StatusRequest, Update,
};
use ramflux_protocol::custody::pairing::native::{
    CreateSpec, Invitation, InviteToken, invitation_signing_bytes,
};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Close, Poll, QueuedFrame, RelayFrame, Send,
};
use ramflux_protocol::custody::pairing::{
    Commit, Common, ContextOffer, PairingWire, Reveal, RoleContext,
};
use ramflux_protocol::{decode_base64url, encode_base64url};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

mod full;
pub(super) use full::cancel::FullRuntimeCancel;
mod local_writer;
mod registry;
pub use local_writer::PairingLocalWriterService;
mod attended_join;
mod workflow;
#[cfg(test)]
pub(crate) use registry::settle_actor_data_for_test;
pub(crate) use registry::{
    PairingEventSubscription, install_actor_with_writer, pairing_event_stream, service_frontend,
    take_installed_recipient, work_signal,
};
pub use registry::{install_actor, remove_actor, remove_actor_and_drain};

const LIVE_CAP: usize = 3;
const _: () = assert!(LIVE_CAP >= 1);
const SYNC_STEPS: u32 = 64;

/// Read the strict default-off pairing opt-in from the process env.
/// Production builds [`PairingConfig::from_env`] once at startup; tests inject config.
/// # Errors
/// Refuses an invalid opt-in value before startup.
pub fn pairing_enabled() -> Result<bool, SdkError> {
    Ok(PairingConfig::from_env()?.enabled)
}

/// Responder-only prepared→acknowledged. The publisher (local primary) must submit first.
/// `publisher_ref` is the head's stored publisher; local current-primary may submit.
/// # Errors
/// `submitted_required` when the publisher skips submitted; `responder_submitted` otherwise.
pub fn validate_head_advance(
    from: &str,
    to: &str,
    publisher_ref: &DeviceRef,
    local_ref: &DeviceRef,
) -> Result<(), SdkError> {
    let publisher_is_local_primary = publisher_ref == local_ref;
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
    pub master_public_key: Option<String>,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub is_primary: bool,
}

/// Actor-owned ceremony generation. One live run per actor.
pub struct PairingActor {
    identity: PairingIdentity,
    participant: Option<Arc<super::LocalPairingParticipant>>,
    native: Option<Arc<dyn PairingNative>>,
    transport: Arc<dyn PairingTransport>,
    config: PairingConfig,
    full_node: Option<ramflux_crypto::custody::VerifiedNodeRecord>,
    full_runtime: Arc<full::cancel::FullRuntimeCancel>,
    actor_generation: u64,
    frontend_generation: u64,
    ceremony: Option<Ceremony>,
    recovered_installation: Option<full::install_recovery::RecoveredInstallation>,
    tail_jobs: BTreeMap<String, full::tail::TailJob>,
    recovered_tail_status: Option<ramflux_protocol::custody::pairing::local_dto::FullStatus>,
    unsolicited: u32,
    recipient_stage: Option<Arc<dyn super::recipient::RecipientKeyStaging>>,
    local_writer: Option<local_writer::LocalWriterPort>,
}

struct Ceremony {
    operation_id: String,
    generation: u64,
    role: PairingRole,
    phase: String,
    expires_at: u64,
    invitation: Invitation,
    origin: String,
    issuer_seq: u64,
    token: Zeroizing<String>,
    display_name: String,
    next_send_seq: u64,
    last_poll_seq: Option<u64>,
    outbound: VecDeque<RelayFrame>,
    sas: SasHold,
    local_confirmed: bool,
    peer_mac_ok: bool,
    displayed_th: Option<[u8; 32]>,
    displayed_proposal: Option<String>,
    common: Option<Common>,
    full: Option<full::FullCeremony>,
    full_error: Option<ramflux_protocol::custody::pairing::full_transfer::FullError>,
    full_terminal_status: Option<Box<ramflux_protocol::custody::pairing::local_dto::FullStatus>>,
    peer_ref: Option<DeviceRef>,
    peer_name: Option<String>,
    result: Option<String>,
    cleanup: String,
    emoji: Option<Vec<u64>>,
    reveal_chunks: BTreeMap<u64, (String, u64, u64, String)>,
    offer_chunks: BTreeMap<u64, (String, u64, u64, String)>,
    reveal_sent: bool,
    frames_seen: u64,
    sent_bytes: usize,
    received_bytes: usize,
    head_state: Option<String>,
    verified_invite: Option<Envelope<Invitation>>,
    commitment_ref: Option<DeviceRef>,
    transcript: Option<ramflux_protocol::custody::pairing::Transcript>,
    enrollment: Option<Envelope<ramflux_protocol::custody::pairing::channel::EnrollmentBody>>,
    record_hash: Option<String>,
    record_epoch: Option<u64>,
    channels: VecDeque<(u64, String)>,
}

enum SasHold {
    None,
    Pending(Box<PendingSas>),
    Established(Box<EstablishedSas>),
}

impl PairingActor {
    pub(super) fn note_background_error(&mut self, error: &SdkError) {
        let code = Self::background_error_code(error);
        self.schedule_full_data_retry(error);
        if let Some(c) = &mut self.ceremony {
            if c.full.is_some() {
                c.full_error = Some(
                    ramflux_protocol::custody::pairing::full_transfer::FullError::from_code(code)
                        .unwrap_or(
                        ramflux_protocol::custody::pairing::full_transfer::FullError::InvalidInput,
                    ),
                );
            }
            // Active v2 updates permit only PublicationPending. Keep full-profile
            // refusals separately instead of emitting an invalid phase/result pair.
            if code == "PublicationPending" {
                c.result = Some(code.into());
            } else if !terminal(&c.phase) {
                c.result = None;
            }
        }
    }
    /// Exact last full-profile background refusal, separate from legacy update fields.
    /// This is local progress information and confers no verification or publication right.
    #[must_use]
    pub fn full_background_error(
        &self,
    ) -> Option<ramflux_protocol::custody::pairing::full_transfer::FullError> {
        self.ceremony.as_ref().and_then(|c| c.full_error)
    }
    fn background_error_code(error: &SdkError) -> &'static str {
        match error {
            SdkError::PairingCode(code)
            | SdkError::PairingField(code)
            | SdkError::Crypto(CryptoError::Pairing(code))
            | SdkError::Storage(ramflux_storage::StorageError::PairingField(code)) => code,
            _ => "ResumeRequired",
        }
    }
    #[must_use]
    pub fn new(
        identity: PairingIdentity,
        native: Option<Arc<dyn PairingNative>>,
        transport: Arc<dyn PairingTransport>,
        config: PairingConfig,
    ) -> Self {
        Self {
            identity,
            participant: None,
            native,
            transport,
            config,
            full_node: None,
            full_runtime: Arc::new(full::cancel::FullRuntimeCancel::default()),
            actor_generation: 1,
            frontend_generation: 1,
            ceremony: None,
            recovered_installation: None,
            tail_jobs: BTreeMap::new(),
            recovered_tail_status: None,
            unsolicited: 0,
            recipient_stage: None,
            local_writer: None,
        }
    }

    /// Set the full-profile receiving-node record from the configured native pin owner.
    /// Never populate this port from an invitation or node-asserted key alone.
    pub fn set_full_node(&mut self, node: ramflux_crypto::custody::VerifiedNodeRecord) {
        self.full_node = Some(node);
    }

    /// Attach the device-local storage participant used by SDK, bus and CLI ceremonies.
    pub fn set_participant(&mut self, participant: Arc<super::LocalPairingParticipant>) {
        self.recipient_stage = Some(participant.clone());
        self.participant = Some(participant);
    }

    /// Inject recipient J0/J1 staging. Called before the recipient commitment.
    pub fn set_recipient_staging(
        &mut self,
        staging: Arc<dyn super::recipient::RecipientKeyStaging>,
    ) {
        self.recipient_stage = Some(staging);
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
    pub async fn begin(&mut self, begin: Begin) -> Result<LocalResult, SdkError> {
        begin.validate().map_err(|e| wire(&e))?;
        self.require_open()?;
        if !self.identity.is_primary {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
        let native = self.native.clone().ok_or(SdkError::PairingCode("PrimaryRequired"))?;
        let master = self
            .identity
            .master_public_key
            .clone()
            .ok_or(SdkError::PairingCode("PrimaryRequired"))?;
        self.expire_live().await;
        if self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase)) {
            return Err(SdkError::PairingCode("Busy"));
        }
        self.refresh_generation().await?;
        let spec = spec_from_begin(&self.identity, &begin)?;
        let prepared = PreparedIssue::prepare(spec.clone())?;
        let mut attempt = NativeAttempt { native: Arc::clone(&native), armed: true };
        let issued = prepared.apply(native.as_ref()).await?;
        let prepared_create = PreparedCreate::prepare(issued.ticket, spec)?;
        let mut created = prepared_create.apply(native.as_ref()).await?;
        created.validate_create(prepared_create.create()).map_err(|e| wire(&e))?;
        let invitation = created.invitation.body.clone();
        let origin = invitation.public_origin.clone();
        let common = invitation.project_common(master).map_err(|e| wire(&e))?;
        let generation = self.actor_generation;
        let primary_token = Zeroizing::new(std::mem::take(&mut created.primary_token));
        let recipient_token = std::mem::take(&mut created.recipient_token);
        let request_id = created.request_id.clone();
        let invite_envelope = created.invitation.clone();
        let expires_at = invitation.expires_at;
        let keys = self.load_public_keys(self.identity.local_ref.clone()).await?;
        self.record_local_invitation(invite_envelope.clone(), generation).await?;
        let mut ceremony = Self::open_ceremony(CeremonyOpen {
            operation_id: request_id.clone(),
            generation,
            role: PairingRole::Initiator,
            invitation,
            verified_invite: Some(invite_envelope.clone()),
            origin,
            token: primary_token,
            common: Some(common),
            display_name: begin.display_name,
        });
        Self::start_sas_with_ref(&mut ceremony, &self.identity.local_ref, keys)?;
        Self::queue_offer(&mut ceremony)?;
        Self::queue_commit(&mut ceremony)?;
        self.ceremony = Some(ceremony);
        let result = BeginResult {
            schema: "ramflux.pairing.BeginResult.v2".into(),
            version: 2,
            operation_id: request_id,
            generation,
            expires_at,
            invite_token: InviteToken {
                schema: "ramflux.pairing.InviteToken.v2".into(),
                version: 2,
                invitation: invite_envelope,
                recipient_token,
            },
        };
        result.validate().map_err(|e| wire(&e))?;
        attempt.armed = false;
        Ok(local_begin(result))
    }

    /// Recipient join: verify the invitation, claim, then wait for the account offer.
    /// # Errors
    /// `Busy`, `Expired`, signature failure, or a claim Failure.
    pub async fn join(&mut self, join: Join) -> Result<LocalResult, SdkError> {
        join.validate().map_err(|e| wire(&e))?;
        self.require_open()?;
        self.expire_live().await;
        if self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase)) {
            return Err(SdkError::PairingCode("Busy"));
        }
        self.refresh_generation().await?;
        verify_invitation(&join.token.invitation)?;
        let verified = join.token.invitation.clone();
        let invitation = verified.body.clone();
        let origin = invitation.public_origin.clone();
        let nonce = random_32()?;
        let claim = Claim {
            schema: "ramflux.pairing.Claim.v2".into(),
            version: 2,
            invitation_id: invitation.invitation_id.clone(),
            issuer_seq: invitation.issuer_seq,
            recipient_token: join.token.recipient_token.clone(),
            claim_nonce: encode_base64url(nonce),
        };
        let claimed = self.transport.claim(origin.clone(), claim.clone()).await?;
        if let Err(error) = consume_claimed(&claimed, &claim, &invitation) {
            let _ = self
                .transport
                .close(
                    origin.clone(),
                    Close {
                        schema: "ramflux.pairing.Close.v2".into(),
                        version: 2,
                        invitation_id: invitation.invitation_id.clone(),
                        issuer_seq: invitation.issuer_seq,
                        role: "responder".into(),
                        token: claim.recipient_token.clone(),
                        reason: "protocol".into(),
                    },
                )
                .await;
            return Err(error);
        }
        let generation = self.actor_generation;
        let ceremony = Self::open_ceremony(CeremonyOpen {
            operation_id: invitation.request_id.clone(),
            generation,
            role: PairingRole::Responder,
            invitation,
            verified_invite: Some(verified),
            origin,
            token: Zeroizing::new(join.token.recipient_token.clone()),
            common: None,
            display_name: join.display_name,
        });
        self.ceremony = Some(ceremony);
        Box::pin(self.sync_relay()).await
    }

    /// Local SAS match bound to the currently displayed transcript. Never a peer boolean.
    /// # Errors
    /// Generation mismatch, `SasMismatch`, or `already_confirmed`.
    pub async fn confirm(&mut self, confirm: &Confirm) -> Result<LocalResult, SdkError> {
        confirm.validate().map_err(|e| wire(&e))?;
        self.require_open()?;
        let th = self.with_ceremony(|c| {
            check_generation(c, &confirm.operation_id, confirm.generation)?;
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
            return self.fail("rejected", "SasMismatch").await;
        }
        let mac = match self.with_ceremony_mut(|c| {
            let SasHold::Established(sas) = &mut c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            if c.local_confirmed {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let mac = sas.confirm_local(&th, true)?;
            c.local_confirmed = true;
            Ok(mac)
        }) {
            Ok(mac) => mac,
            Err(error) => return self.terminal_protocol(error).await,
        };
        self.with_ceremony_mut(|c| {
            c.outbound.push_back(RelayFrame::Confirm {
                role: c.role.as_str().into(),
                transcript_hash: encode_base64url(th),
                mac: encode_base64url(mac),
            });
            Ok(())
        })?;
        self.sync_relay().await
    }

    /// Primary approval after TWO local confirmations and both direction MACs.
    /// # Errors
    /// `PrimaryRequired`, `WrongContext`, or a TH/proposal mismatch.
    pub fn approve<'a>(
        &'a mut self,
        approve: &'a Approve,
    ) -> impl std::future::Future<Output = Result<LocalResult, SdkError>> + std::marker::Send + 'a
    {
        Box::pin(self.approve_owned(approve))
    }
    async fn approve_owned(&mut self, approve: &Approve) -> Result<LocalResult, SdkError> {
        approve.validate().map_err(|e| wire(&e))?;
        self.require_open()?;
        if self.ceremony.as_ref().is_some_and(|c| c.full.is_some()) {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        if !self.identity.is_primary {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
        let real_workflow = self.participant.is_some();
        self.with_ceremony(|c| {
            check_generation(c, &approve.operation_id, approve.generation)?;
            if c.phase != "mutually_confirmed" && !(real_workflow && c.phase == "proposal_pending")
            {
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
            return self.fail("rejected", "NotFound").await;
        }
        self.with_ceremony_mut(|c| {
            c.phase = "proposal_pending".into();
            c.emoji = None;
            Ok(())
        })?;
        if real_workflow {
            self.publish_workflow().await?;
            self.sync_relay().await
        } else {
            self.status_update()
        }
    }

    /// Cancel the current generation and wipe SAS secrets.
    /// # Errors
    /// Generation mismatch or no live ceremony.
    pub async fn cancel(&mut self, cancel: &Cancel) -> Result<LocalResult, SdkError> {
        cancel.validate().map_err(|e| wire(&e))?;
        self.require_open()?;
        if self.tail_jobs.contains_key(&cancel.operation_id)
            || self.ceremony.as_ref().is_some_and(|c| {
                c.full.as_ref().is_some_and(full::FullCeremony::has_installed_tail)
            })
        {
            return Err(SdkError::PairingCode("InvalidInput"));
        }
        self.with_ceremony(|c| check_generation(c, &cancel.operation_id, cancel.generation))?;
        self.fail("cancelled", "Retired").await
    }

    /// Status never re-exports the invite token.
    /// # Errors
    /// Generation mismatch.
    pub async fn status(&mut self, request: &StatusRequest) -> Result<LocalResult, SdkError> {
        self.require_open()?;
        request.validate().map_err(|e| wire(&e))?;
        self.expire_live().await;
        self.with_ceremony(|c| check_generation(c, &request.operation_id, request.generation))?;
        self.status_update()
    }

    /// Drive relay send/poll until a user wait or a bound is hit.
    /// # Errors
    /// Transport, `Busy`, or protocol failure.
    pub async fn sync_relay(&mut self) -> Result<LocalResult, SdkError> {
        self.require_open()?;
        if self.ceremony.is_none()
            && self.tail_jobs.is_empty()
            && self.local_writer.is_some()
            && let Some(recovered) = &self.recovered_installation
        {
            let request = recovered.status_request();
            Box::pin(self.resume_full_tail(&request)).await?;
        }
        if let Err(error) = self.advance_full_tails().await {
            self.note_background_error(&error);
            return Err(error);
        }
        if self.ceremony.is_none() {
            if let Some((operation, job)) = self.tail_jobs.iter().next_back() {
                return job.result(&StatusRequest {
                    schema: "ramflux.pairing.StatusRequest.v2".into(),
                    version: 2,
                    operation_id: operation.clone(),
                    generation: job.generation(),
                });
            }
            if let Some(status) = &self.recovered_tail_status {
                return self
                    .recovered_tail_result(&StatusRequest {
                        schema: "ramflux.pairing.StatusRequest.v2".into(),
                        version: 2,
                        operation_id: status.operation_id.clone(),
                        generation: status.generation,
                    })?
                    .ok_or(SdkError::PairingCode("WrongContext"));
            }
        }
        if let Some(recovered) = &self.recovered_installation {
            return recovered.local_result();
        }
        self.expire_live().await;
        if self.ceremony.as_ref().is_some_and(|c| terminal(&c.phase)) {
            self.flush_send().await?;
            self.close_completed_relay().await;
            self.clear_completed_secrets();
            return self.status_update();
        }
        if self.retry_full_data_if_due().await? {
            return self.status_update();
        }
        match self.advance_full_epoch().await {
            Ok(true) => return self.status_update(),
            Ok(false) => {}
            Err(error) => {
                self.note_background_error(&error);
                self.reject_invalid_full_head(&error).await?;
                return Err(error);
            }
        }
        for _ in 0..SYNC_STEPS {
            self.flush_send().await?;
            let polled = match self.poll_once().await {
                Ok(polled) => polled,
                Err(SdkError::PairingCode("Busy")) => break,
                Err(error) => return Err(error),
            };
            self.ingest(polled.frames).await?;
            if self.ceremony.as_ref().is_some_and(|c| terminal(&c.phase)) {
                self.flush_send().await?;
                self.close_completed_relay().await;
                self.clear_completed_secrets();
                break;
            }
            if polled.closed {
                return self.fail("cancelled", "Retired").await;
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
    pub async fn lock(&mut self) -> Result<LocalResult, SdkError> {
        if let Some(status) = self.recovered_tail_status.take() {
            self.retire_owned_runtime().await;
            return Ok(LocalResult {
                schema: "ramflux.pairing.LocalResult.v2".into(),
                version: 2,
                outcome: Outcome::FullStatus { value: Box::new(status) },
            });
        }
        if self.ceremony.is_none()
            && let Some((operation, job)) = self.tail_jobs.iter().next_back()
        {
            let result = job.result(&StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: operation.clone(),
                generation: job.generation(),
            })?;
            self.retire_owned_runtime().await;
            return Ok(result);
        }
        if let Some(recovered) = self.recovered_installation.take() {
            self.retire_owned_runtime().await;
            return recovered.local_result();
        }
        if let Some(participant) = &self.participant {
            participant.provider.cancel();
        }
        self.frontend_generation = self.frontend_generation.saturating_add(1);
        self.actor_generation = self.actor_generation.saturating_add(1);
        // A previous cancel may already have dropped the full owner and returned the
        // frontend database. Lock still retires memory; it must not repeat that DB loan.
        if self.ceremony.as_ref().is_some_and(|c| c.full.is_some() || c.cleanup == "pending") {
            self.retire_owned_runtime().await;
            self.with_ceremony_mut(|c| {
                c.phase = "cancelled".into();
                c.result = Some("Retired".into());
                c.cleanup = "pending".into();
                Ok(())
            })?;
            return self.status_update();
        }
        self.fail("cancelled", "Retired").await
    }

    /// App background after the deadline expires the run; never auto-confirms.
    /// # Errors
    /// No live ceremony.
    pub async fn background(&mut self) -> Result<LocalResult, SdkError> {
        self.fail("expired", "Expired").await
    }

    /// Higher/conflicting head invalidates the pending SAS.
    /// # Errors
    /// No live ceremony.
    pub async fn note_head_change(&mut self) -> Result<LocalResult, SdkError> {
        self.fail("rejected", "HeadChanged").await
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

    fn require_open(&self) -> Result<(), SdkError> {
        self.full_runtime.require_live()?;
        if self.config.enabled { Ok(()) } else { Err(SdkError::PairingCode("NotFound")) }
    }

    async fn expire_live(&mut self) {
        let now = wall();
        let expired =
            self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase) && now >= c.expires_at);
        if expired {
            let _ = self.fail("expired", "Expired").await;
        }
    }

    fn waiting_for_user(&self) -> bool {
        self.ceremony.as_ref().is_some_and(|c| {
            matches!(c.phase.as_str(), "sas_pending" | "mutually_confirmed" | "proposal_pending")
                && c.outbound.is_empty()
        })
    }

    fn open_ceremony(open: CeremonyOpen) -> Ceremony {
        Ceremony {
            operation_id: open.operation_id,
            generation: open.generation,
            role: open.role,
            phase: "invited".into(),
            expires_at: open.invitation.expires_at,
            issuer_seq: open.invitation.issuer_seq,
            origin: open.origin,
            invitation: open.invitation,
            token: open.token,
            display_name: open.display_name,
            next_send_seq: 0,
            last_poll_seq: None,
            outbound: VecDeque::new(),
            sas: SasHold::None,
            local_confirmed: false,
            peer_mac_ok: false,
            displayed_th: None,
            displayed_proposal: None,
            common: open.common,
            full: None,
            full_error: None,
            full_terminal_status: None,
            peer_ref: None,
            peer_name: None,
            result: None,
            cleanup: "none".into(),
            emoji: None,
            reveal_chunks: BTreeMap::new(),
            offer_chunks: BTreeMap::new(),
            reveal_sent: false,
            frames_seen: 0,
            sent_bytes: 0,
            received_bytes: 0,
            head_state: None,
            verified_invite: open.verified_invite,
            commitment_ref: None,
            transcript: None,
            enrollment: None,
            record_hash: None,
            record_epoch: None,
            channels: VecDeque::new(),
        }
    }

    fn start_sas_with_ref(
        ceremony: &mut Ceremony,
        local_ref: &DeviceRef,
        keys: Option<(String, String)>,
    ) -> Result<(), SdkError> {
        if ceremony.full.is_some() {
            return Self::start_full_sas(ceremony, local_ref, keys);
        }
        if !matches!(ceremony.sas, SasHold::None) {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let common = ceremony.common.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
        let mut sas_secret = random_32()?;
        let device_ref = match ceremony.role {
            PairingRole::Initiator => ceremony.invitation.primary_ref.clone(),
            PairingRole::Responder => DeviceRef {
                account_anchor: common.account_anchor.clone(),
                device_id: local_ref.device_id.clone(),
                device_epoch: local_ref.device_epoch,
            },
        };
        let (context, salt) = build_context(
            ceremony.role,
            common,
            device_ref,
            ceremony.display_name.clone(),
            &sas_secret,
            keys,
        )?;
        let pending = commit(ceremony.role, &context, &sas_secret, &salt)?;
        sas_secret.zeroize();
        ceremony.sas = SasHold::Pending(Box::new(pending));
        Ok(())
    }

    fn queue_offer(ceremony: &mut Ceremony) -> Result<(), SdkError> {
        if ceremony.full.is_some() {
            return Self::queue_full_offer(ceremony);
        }
        let common = ceremony.common.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
        let offer = ContextOffer {
            schema: "ramflux.pairing.ContextOffer.v2".into(),
            version: 2,
            common: common.clone(),
        };
        offer.validate().map_err(|e| wire(&e))?;
        let bytes = offer.to_wire_bytes().map_err(|e| wire(&e))?;
        let object = random_32()?;
        for frame in offer_chunks(object, &bytes)? {
            ceremony.outbound.push_back(frame);
        }
        Ok(())
    }

    fn queue_commit(ceremony: &mut Ceremony) -> Result<(), SdkError> {
        if ceremony.full.is_some() {
            return Self::queue_full_commit(ceremony);
        }
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

    async fn flush_send(&mut self) -> Result<(), SdkError> {
        loop {
            let (origin, send, frame_bytes) = {
                let Some(c) = self.ceremony.as_mut() else { return Ok(()) };
                let Some(frame) = c.outbound.front().cloned() else { return Ok(()) };
                let frame_bytes = ramflux_protocol::canonical_json_bytes(&frame)?.len();
                check_direction_budget(c.next_send_seq, c.sent_bytes, frame_bytes)?;
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
                (c.origin.clone(), send, frame_bytes)
            };
            match self.transport.send(origin, send).await {
                Ok(_) => {
                    if let Some(c) = self.ceremony.as_mut() {
                        c.outbound.pop_front();
                        c.next_send_seq += 1;
                        c.sent_bytes += frame_bytes;
                    }
                }
                Err(SdkError::PairingCode("Busy")) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    async fn poll_once(
        &mut self,
    ) -> Result<ramflux_protocol::custody::pairing::relay::Polled, SdkError> {
        let (origin, poll) = {
            let c = self.ceremony.as_ref().ok_or(SdkError::PairingCode("NotFound"))?;
            (
                c.origin.clone(),
                Poll {
                    schema: "ramflux.pairing.Poll.v2".into(),
                    version: 2,
                    invitation_id: c.invitation.invitation_id.clone(),
                    issuer_seq: c.issuer_seq,
                    role: c.role.as_str().into(),
                    token: c.token.as_str().into(),
                    after_seq: c.last_poll_seq,
                },
            )
        };
        self.transport.poll(origin, poll).await
    }

    async fn ingest(&mut self, frames: Vec<QueuedFrame>) -> Result<(), SdkError> {
        let outcome = match self.ingest_inner(frames).await {
            Ok(()) => self.advance_workflow().await,
            Err(error) => match protocol_fail_code(&error) {
                Some(code) if self.ceremony.as_ref().is_some_and(|c| !terminal(&c.phase)) => {
                    let _ = self.fail("rejected", code).await;
                    Ok(())
                }
                _ => Err(error),
            },
        };
        match outcome {
            Err(error) if protocol_fail_code(&error).is_some() => {
                self.fail("rejected", protocol_fail_code(&error).unwrap_or("WrongContext")).await?;
                Ok(())
            }
            other => other,
        }
    }

    async fn ingest_inner(&mut self, frames: Vec<QueuedFrame>) -> Result<(), SdkError> {
        let mut rest = Vec::new();
        let mut commits = Vec::new();
        for queued in frames {
            self.with_ceremony_mut(|c| {
                let expected = c.last_poll_seq.map_or(0, |seq| seq + 1);
                if queued.seq != expected {
                    return Err(SdkError::PairingCode("Replay"));
                }
                queued.frame.validate().map_err(|error| wire(&error))?;
                let bytes = ramflux_protocol::canonical_json_bytes(&queued.frame)?.len();
                check_direction_budget(c.frames_seen, c.received_bytes, bytes)?;
                c.frames_seen += 1;
                c.received_bytes += bytes;
                c.last_poll_seq = Some(queued.seq);
                Ok(())
            })?;
            match queued.frame {
                RelayFrame::OfferChunk { object_id, index, count, total_bytes, bytes } => {
                    self.ingest_offer_chunk(object_id, index, count, total_bytes, bytes).await?;
                }
                RelayFrame::Commit { value } => commits.push(value),
                other => rest.push(other),
            }
        }
        for value in commits {
            self.ingest_commit(&value)?;
        }
        self.maybe_reveal()?;
        for frame in rest {
            match frame {
                RelayFrame::RevealChunk { object_id, index, count, total_bytes, bytes } => {
                    self.ingest_reveal_chunk(object_id, index, count, total_bytes, bytes)?;
                }
                RelayFrame::Confirm { role, transcript_hash, mac } => {
                    self.ingest_confirm_mac(&role, &transcript_hash, &mac)?;
                }
                RelayFrame::Channel { counter, ciphertext } => {
                    self.with_ceremony_mut(|c| {
                        c.channels.push_back((counter, ciphertext));
                        Ok(())
                    })?;
                }
                RelayFrame::OfferChunk { .. } | RelayFrame::Commit { .. } => {}
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
            if c.full.is_some() {
                return Self::ingest_full_commit(c, peer, commitment);
            }
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

    async fn ingest_offer_chunk(
        &mut self,
        object_id: String,
        index: u64,
        count: u64,
        total_bytes: u64,
        bytes: String,
    ) -> Result<(), SdkError> {
        let complete = self.with_ceremony_mut(|c| {
            if c.phase != "invited" {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            accept_chunk(&mut c.offer_chunks, object_id, index, count, total_bytes, bytes)
        })?;
        if complete {
            self.finish_offer().await?;
        }
        Ok(())
    }

    async fn finish_offer(&mut self) -> Result<(), SdkError> {
        let assembled = self.with_ceremony_mut(|c| {
            let chunks: Vec<(u64, String, u64, u64, String)> = c
                .offer_chunks
                .iter()
                .map(|(i, (id, count, total, bytes))| {
                    (*i, id.clone(), *count, *total, bytes.clone())
                })
                .collect();
            c.offer_chunks.clear();
            assemble_chunks(&chunks)
        })?;
        if self.ceremony.as_ref().is_some_and(|c| c.invitation.purpose == "primary_transfer") {
            return self.finish_full_offer(&assembled).await;
        }
        let offer = ContextOffer::from_wire_bytes(&assembled).map_err(|e| wire(&e))?;
        offer.validate().map_err(|e| wire(&e))?;
        let local_ref = self.identity.local_ref.clone();
        self.with_ceremony_mut(|c| {
            if c.role != PairingRole::Responder || c.common.is_some() {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let projected = c
                .invitation
                .project_common(offer.common.master_public_key.clone())
                .map_err(|e| wire(&e))?;
            if projected != offer.common {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            c.common = Some(offer.common);
            Ok(())
        })?;
        let staged = self.stage_recipient_before_commit().await?;
        let local_ref = staged.clone().unwrap_or(local_ref);
        let keys = self.load_public_keys(local_ref.clone()).await?;
        self.with_ceremony_mut(|c| {
            c.commitment_ref.clone_from(&staged);
            Self::start_sas_with_ref(c, &local_ref, keys)?;
            Self::queue_commit(c)
        })
    }

    fn stage_recipient_before_commit(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<DeviceRef>, SdkError>> + std::marker::Send + '_
    {
        Box::pin(self.stage_recipient_owned())
    }
    async fn stage_recipient_owned(&self) -> Result<Option<DeviceRef>, SdkError> {
        let Some(staging) = self.recipient_stage.as_ref() else {
            return Ok(None);
        };
        let invite = self.with_ceremony(|ceremony| {
            ceremony.verified_invite.clone().ok_or(SdkError::PairingCode("InvalidInput"))
        })?;
        if invite.body.recipient_mode == "existing"
            && let (Some(writer), Some(participant)) =
                (&self.local_writer, self.participant.clone())
        {
            let generation = self.frontend_generation;
            let ceremony_generation = self.actor_generation;
            let unlock = self
                .full_runtime
                .clone()
                .run_blocking(move || {
                    super::recipient::ExistingFrontendUnlock::acquire(
                        participant,
                        invite,
                        generation,
                        ceremony_generation,
                    )
                })
                .await?;
            return Ok(Some(writer.request_client(move |client| unlock.finish(client)).await?));
        }
        let staging = Arc::clone(staging);
        let generation = self.frontend_generation;
        let ceremony_generation = self.actor_generation;
        Ok(Some(
            self.full_runtime
                .clone()
                .run_blocking(move || {
                    staging.stage_with_generation(&invite, generation, ceremony_generation)
                })
                .await?,
        ))
    }

    #[cfg(test)]
    pub(super) fn set_enabled_for_test(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    #[cfg(test)]
    pub(crate) fn ordinary_peer_for_test(&self) -> Self {
        let mut peer = Self::new(
            self.identity.clone(),
            self.native.clone(),
            self.transport.clone(),
            self.config.clone(),
        );
        if let Some(participant) = &self.participant {
            peer.set_participant(participant.clone());
        }
        peer
    }

    #[cfg(test)]
    pub(crate) fn wrap_transport_for_test(
        &mut self,
        wrap: impl FnOnce(Arc<dyn PairingTransport>) -> Arc<dyn PairingTransport>,
    ) {
        self.transport = wrap(self.transport.clone());
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn commitment_device_id(&self) -> Option<String> {
        self.ceremony.as_ref().and_then(|ceremony| {
            ceremony.commitment_ref.as_ref().map(|device| device.device_id.clone())
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
            if c.phase != "commitments" {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            accept_chunk(&mut c.reveal_chunks, object_id, index, count, total_bytes, bytes)
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
        if self.ceremony.as_ref().is_some_and(|c| c.full.is_some()) {
            return self.with_ceremony_mut(|c| Self::finish_full_reveal(c, &assembled));
        }
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
            let local = pending.context()?.clone();
            c.transcript = Some(ramflux_protocol::custody::pairing::Transcript {
                schema: "ramflux.pairing.Transcript.v2".into(),
                version: 2,
                initiator: if c.role == PairingRole::Initiator {
                    local.clone()
                } else {
                    peer.clone()
                },
                responder: if c.role == PairingRole::Responder { local } else { peer.clone() },
            });
            let established = pending.establish(&peer, &salt)?;
            let th = established.transcript_hash();
            c.displayed_th = Some(th);
            c.peer_ref = Some(peer.device_ref.clone());
            c.peer_name = Some(peer.display_name.clone());
            let common = c.common.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
            c.displayed_proposal = Some(proposal_hash(common, th, &peer.device_ref)?);
            c.emoji = Some(established.emoji_indices().iter().map(|i| u64::from(*i)).collect());
            c.phase = "sas_pending".into();
            c.sas = SasHold::Established(Box::new(established));
            c.cleanup = "none".into();
            Ok(())
        })
    }

    fn ingest_confirm_mac(
        &mut self,
        role: &str,
        transcript_hash: &str,
        mac: &str,
    ) -> Result<(), SdkError> {
        ignore_peer_confirmed_flag(false);
        let mac = decode32(mac)?;
        let th = decode32(transcript_hash)?;
        self.with_ceremony_mut(|c| {
            let expected = match c.role {
                PairingRole::Initiator => "responder",
                PairingRole::Responder => "initiator",
            };
            if role != expected {
                return Err(SdkError::PairingCode("WrongRole"));
            }
            let displayed = c.displayed_th.ok_or(SdkError::PairingCode("WrongContext"))?;
            if th != displayed {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let SasHold::Established(sas) = &mut c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            sas.accept_peer_mac(&mac)?;
            c.peer_mac_ok = true;
            Ok(())
        })
    }

    fn maybe_reveal(&mut self) -> Result<(), SdkError> {
        if self.ceremony.as_ref().is_some_and(|c| c.full.is_some()) {
            return self.with_ceremony_mut(Self::maybe_full_reveal);
        }
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

    async fn terminal_protocol(&mut self, error: SdkError) -> Result<LocalResult, SdkError> {
        match protocol_fail_code(&error) {
            Some(code) => self.fail("rejected", code).await,
            None => Err(error),
        }
    }

    /// Root removal erases memory and joins owned work without turning an encrypted
    /// data-resume journal into approval or deleting uncertain publication operands.
    async fn retire_owned_runtime(&mut self) {
        if let Some(participant) = &self.participant {
            participant.provider.cancel();
        }
        self.full_runtime.stop();
        for (_, mut job) in std::mem::take(&mut self.tail_jobs) {
            if let Some(epoch) = job.epoch.take() {
                epoch.abort_and_drain().await;
            }
        }
        if let Some(native) = &self.native {
            native.close();
        }
        let epoch = self
            .ceremony
            .as_mut()
            .and_then(|c| c.full.as_mut())
            .and_then(full::FullCeremony::take_epoch_job);
        let stream = self
            .ceremony
            .as_mut()
            .and_then(|c| c.full.as_mut())
            .and_then(full::FullCeremony::take_stream_job);
        if let Some(c) = self.ceremony.as_mut() {
            c.full.take();
            match &mut c.sas {
                SasHold::Pending(sas) => sas.cleanup(),
                SasHold::Established(sas) => sas.cleanup(),
                SasHold::None => {}
            }
            c.sas = SasHold::None;
            c.token.zeroize();
            c.outbound.clear();
            c.channels.clear();
            c.emoji = None;
            c.displayed_th = None;
            c.displayed_proposal = None;
        }
        if let Some(epoch) = epoch {
            epoch.abort_and_drain().await;
        }
        if let Some(stream) = stream {
            stream.abort_and_drain().await;
        }
        self.full_runtime.drain_local_jobs().await;
        if let Some(participant) = &self.participant {
            participant.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        }
    }

    async fn fail(&mut self, phase: &str, code: &'static str) -> Result<LocalResult, SdkError> {
        self.capture_full_terminal_status(phase);
        let epoch = self
            .ceremony
            .as_mut()
            .and_then(|c| c.full.as_mut())
            .and_then(full::FullCeremony::take_epoch_job);
        let stream = self
            .ceremony
            .as_mut()
            .and_then(|c| c.full.as_mut())
            .and_then(full::FullCeremony::take_stream_job);
        if let Some(native) = &self.native {
            native.close();
        }
        let full_terminal = self
            .ceremony
            .as_ref()
            .filter(|c| c.full.is_some() || c.cleanup == "pending")
            .map(|c| (c.operation_id.clone(), c.generation));
        let close = self.ceremony.as_mut().map(|c| {
            match &mut c.sas {
                SasHold::Pending(pending) => pending.cleanup(),
                SasHold::Established(sas) => sas.cleanup(),
                SasHold::None => {}
            }
            c.sas = SasHold::None;
            c.phase = phase.into();
            c.result = Some(code.into());
            c.cleanup =
                if c.full.is_some() || c.cleanup == "pending" { "pending" } else { "done" }.into();
            c.full.take();
            c.emoji = None;
            c.displayed_th = None;
            c.displayed_proposal = None;
            c.outbound.clear();
            c.head_state = None;
            (
                c.origin.clone(),
                Close {
                    schema: "ramflux.pairing.Close.v2".into(),
                    version: 2,
                    invitation_id: c.invitation.invitation_id.clone(),
                    issuer_seq: c.issuer_seq,
                    role: c.role.as_str().into(),
                    token: c.token.as_str().into(),
                    reason: close_reason(code),
                },
            )
        });
        if let Some(epoch) = epoch {
            epoch.abort_and_drain().await;
        }
        if let Some(stream) = stream {
            stream.abort_and_drain().await;
        }
        self.full_runtime.drain_local_jobs().await;
        self.full_runtime.drain_local_work();
        // Full owners/caches/readers were cancelled above, before waiting for the DB loan.
        // Preserve candidate and stage metadata even when publication might have escaped.
        let durable_terminal = self.persist_full_data_terminal(full_terminal, phase).await;
        if let Some((origin, close)) = close {
            let _ = self.transport.close(origin, close).await;
            if let Some(c) = self.ceremony.as_mut() {
                c.token.zeroize();
            }
        }
        if durable_terminal? && let Some(c) = &mut self.ceremony {
            c.cleanup = "done".into();
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

struct NativeAttempt {
    native: Arc<dyn PairingNative>,
    armed: bool,
}

impl Drop for NativeAttempt {
    fn drop(&mut self) {
        if self.armed {
            self.native.close();
        }
    }
}

impl Drop for PairingActor {
    fn drop(&mut self) {
        if let Some(native) = &self.native {
            native.close();
        }
    }
}

struct CeremonyOpen {
    operation_id: String,
    generation: u64,
    role: PairingRole,
    invitation: Invitation,
    verified_invite: Option<Envelope<Invitation>>,
    origin: String,
    token: Zeroizing<String>,
    common: Option<Common>,
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

fn check_generation(
    ceremony: &Ceremony,
    operation_id: &str,
    generation: u64,
) -> Result<(), SdkError> {
    if ceremony.operation_id == operation_id && ceremony.generation == generation {
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
    keys: Option<(String, String)>,
) -> Result<(RoleContext, [u8; 32]), SdkError> {
    let mut branch = random_32()?;
    let mut agree = random_32()?;
    let salt = random_32()?;
    let mut context = RoleContext {
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
    if let Some((branch_key, agreement_key)) = keys {
        context.branch_key = branch_key;
        context.agreement_key = agreement_key;
    }
    branch.zeroize();
    agree.zeroize();
    context.validate().map_err(|e| wire(&e))?;
    Ok((context, salt))
}

fn proposal_hash(common: &Common, th: [u8; 32], peer_ref: &DeviceRef) -> Result<String, SdkError> {
    let body = serde_json::json!({
        "capabilities": common.capabilities,
        "lease_not_before": common.lease_not_before,
        "lease_expires_at": common.lease_expires_at,
        "purpose": common.purpose,
        "transcript_hash": encode_base64url(th),
        "peer_ref": peer_ref,
    });
    let bytes = ramflux_protocol::canonical_json_bytes(&body)?;
    Ok(encode_base64url(*blake3::hash(&bytes).as_bytes()))
}

fn build_update(c: &Ceremony) -> Result<Update, SdkError> {
    let p = phase_index(&c.phase)?;
    let th = c.displayed_th.map(encode_base64url);
    let (capabilities, lease_not_before, lease_expires_at) = match &c.common {
        Some(common) => {
            (common.capabilities.clone(), common.lease_not_before, common.lease_expires_at)
        }
        None => (
            c.invitation.capabilities.clone(),
            c.invitation.lease_not_before,
            c.invitation.lease_expires_at,
        ),
    };
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
        capabilities,
        lease_not_before,
        lease_expires_at,
        proposal_hash: if p >= 5 { c.displayed_proposal.clone() } else { None },
        record_hash: c.record_hash.clone(),
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

/// Dispatch a pairing bus method to the actor for `account_id`.
/// # Errors
/// `NotFound` when no actor is installed, or the method/ceremony error.
pub async fn handle_bus(
    root: &std::path::Path,
    account_id: &str,
    method: &str,
    body: serde_json::Value,
) -> Result<LocalResult, SdkError> {
    let entry = registry::find(root, account_id)?;
    let mut actor = entry.actor.lock().await;
    entry.require_live()?;
    let result = match method {
        "device.pair.begin" => Box::pin(actor.begin(bus_body(body)?)).await,
        "device.pair.join" | "device.transfer.join" => {
            Box::pin(actor.join_attended(bus_body(body)?)).await
        }
        "device.pair.confirm" | "device.transfer.confirm" => {
            Box::pin(actor.confirm(&bus_body(body)?)).await
        }
        "device.pair.approve" => Box::pin(actor.approve(&bus_body(body)?)).await,
        "device.pair.cancel" | "device.transfer.cancel" => {
            Box::pin(actor.cancel(&bus_body(body)?)).await
        }
        "device.pair.status" => Box::pin(actor.status(&bus_body(body)?)).await,
        "device.transfer.begin" => Box::pin(actor.begin_full(bus_body(body)?)).await,
        "device.transfer.tail_abandon" => Box::pin(actor.tail_abandon(&bus_body(body)?)).await,
        "device.transfer.prepare" => Box::pin(actor.prepare_full_transfer(&bus_body(body)?)).await,
        "device.transfer.affirm" => Box::pin(actor.affirm_full_transfer(&bus_body(body)?)).await,
        "device.transfer.status" => {
            let request = bus_body(body)?;
            if actor.ceremony.is_none() {
                if let Some(result) = Box::pin(actor.resume_full_tail(&request)).await? {
                    Ok(result)
                } else if let Some(result) =
                    Box::pin(actor.recover_full_installation(&request)).await?
                {
                    Ok(result)
                } else {
                    Box::pin(actor.resume_full_data(&request)).await
                }
            } else {
                Box::pin(actor.transfer_status(&request)).await
            }
        }
        _ => Err(SdkError::LocalBus(format!("unsupported local bus method: {method}"))),
    };
    if result.is_ok()
        && let Err(error) = entry.remember_display(&actor)
    {
        tracing::warn!(
            error_code = crate::bus::io::local_bus_error_code(&error),
            "pairing display publication deferred"
        );
    }
    if entry.require_live().is_err() {
        actor.retire_owned_runtime().await;
        return Err(SdkError::PairingCode("Retired"));
    }
    result
}

fn bus_body<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> Result<T, SdkError> {
    serde_json::from_value(body).map_err(SdkError::from)
}

pub(crate) fn verify_invitation(envelope: &Envelope<Invitation>) -> Result<(), SdkError> {
    envelope.body.validate().map_err(|e| wire(&e))?;
    let bytes = invitation_signing_bytes(&envelope.body).map_err(|e| wire(&e))?;
    verify_canonical_signature(&bytes, &envelope.signature, &envelope.body.node_key)
        .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    super::transport::require_https_origin(&envelope.body.public_origin)?;
    Ok(())
}

fn consume_claimed(
    claimed: &ramflux_protocol::custody::pairing::relay::Claimed,
    claim: &Claim,
    invitation: &Invitation,
) -> Result<(), SdkError> {
    claimed.validate().map_err(|e| wire(&e))?;
    if claimed.claim_nonce != claim.claim_nonce
        || claimed.invitation_id != claim.invitation_id
        || claimed.issuer_seq != claim.issuer_seq
        || claimed.role != "responder"
        || claimed.expires_at > invitation.expires_at
    {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    Ok(())
}

fn accept_chunk(
    chunks: &mut BTreeMap<u64, (String, u64, u64, String)>,
    object_id: String,
    index: u64,
    count: u64,
    total_bytes: u64,
    bytes: String,
) -> Result<bool, SdkError> {
    if let Some(existing) = chunks.get(&index) {
        if existing != &(object_id, count, total_bytes, bytes) {
            return Err(SdkError::PairingCode("Replay"));
        }
        return Ok(u64::try_from(chunks.len()).ok() == Some(count));
    }
    if let Some((id0, count0, total0, _)) = chunks.values().next()
        && (id0 != &object_id || *count0 != count || *total0 != total_bytes)
    {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    if index >= count || u64::try_from(chunks.len()).ok().is_none_or(|len| len >= count) {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    chunks.insert(index, (object_id, count, total_bytes, bytes));
    Ok(u64::try_from(chunks.len()).ok() == Some(count))
}

fn protocol_fail_code(error: &SdkError) -> Option<&'static str> {
    match error {
        SdkError::Crypto(CryptoError::Pairing("UpdateRequired"))
        | SdkError::PairingCode("UpdateRequired")
        | SdkError::PairingField("UpdateRequired") => Some("UpdateRequired"),
        SdkError::Crypto(CryptoError::Pairing("confirm_mac"))
        | SdkError::PairingCode("SasMismatch") => Some("SasMismatch"),
        SdkError::Crypto(CryptoError::Pairing(_))
        | SdkError::PairingCode("WrongContext" | "WrongRole" | "Replay" | "InvalidInput")
        | SdkError::PairingField(_) => Some("WrongContext"),
        _ => None,
    }
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

fn check_direction_budget(frames: u64, bytes: usize, next: usize) -> Result<(), SdkError> {
    if frames >= 272 || bytes.checked_add(next).is_none_or(|total| total > 4 * 1024 * 1024) {
        return Err(SdkError::PairingCode("TransferCapacity"));
    }
    Ok(())
}
