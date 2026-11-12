// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! V3 SAS inside the same actor/relay/generation owner; no v2 transfer fallback.
use super::{
    Arc, BeginResult, Ceremony, CeremonyOpen, Commit, DeviceRef, InviteToken, LocalResult,
    NativeAttempt, PairingActor, PairingRole, PairingWire, PendingSas, PreparedCreate,
    PreparedIssue, RelayFrame, SasHold, SdkError, X25519KeyPair, Zeroizing, commit, decode32,
    encode_base64url, local_begin, offer_chunks, proposal_hash, random_32, reveal_chunks, terminal,
    wire,
};
use ramflux_crypto::custody::pairing::HpkeSecrets;
use ramflux_protocol::custody::pairing::{
    context_v3::{
        CommonV3, ContextOfferV3, RevealV3, RoleContextV3, TranscriptV3, TransferProfile,
    },
    local_dto::FullTransferBegin,
};
use ramflux_storage::{FullSourcePreparationCancel, PreparedFullSource};
mod bootstrap;
pub(super) mod cancel;
mod epoch;
mod status;
mod stream;

pub(super) struct FullCeremony {
    pub(super) common: CommonV3,
    pub(super) node: Option<ramflux_crypto::custody::VerifiedNodeRecord>,
    pending: Option<PendingSas<RoleContextV3>>,
    pub(super) transcript: Option<TranscriptV3>,
    pub(super) sas_base: Option<ramflux_crypto::custody::VerifiedRecord>,
    pub(super) hpke: Option<HpkeSecrets>,
    pub(super) prepared: Option<PreparedFullSource>,
    cancelled: Option<FullSourcePreparationCancel>,
    bootstrap: Option<bootstrap::BootstrapState>,
}
impl FullCeremony {
    pub(super) fn take_epoch_job(&mut self) -> Option<epoch::FullEpochJob> {
        self.bootstrap.as_mut().and_then(|state| state.epoch_job.take())
    }
    pub(super) fn take_stream_job(&mut self) -> Option<stream::FullStreamJob> {
        self.bootstrap.as_mut().and_then(|state| state.stream.as_mut()).and_then(|s| s.job.take())
    }

    fn new(
        common: CommonV3,
        source: Option<(PreparedFullSource, FullSourcePreparationCancel)>,
    ) -> Self {
        let (prepared, cancelled) =
            source.map_or((None, None), |(prepared, cancel)| (Some(prepared), Some(cancel)));
        Self {
            common,
            node: None,
            pending: None,
            transcript: None,
            sas_base: None,
            hpke: None,
            prepared,
            cancelled,
            bootstrap: None,
        }
    }
}
impl Drop for FullCeremony {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancelled {
            cancel.cancel();
        }
        self.prepared.take();
        self.transcript.take();
        self.node.take();
        self.sas_base.take();
        self.bootstrap.take();
        if let Some(hpke) = &mut self.hpke {
            hpke.cleanup();
        }
        if let Some(pending) = &mut self.pending {
            pending.cleanup();
        }
    }
}
impl PairingActor {
    async fn load_full_sas_base(
        &self,
        common: &CommonV3,
        source: &DeviceRef,
        new_recipient: bool,
    ) -> Result<ramflux_crypto::custody::VerifiedRecord, SdkError> {
        let participant =
            self.participant.clone().ok_or(SdkError::PairingCode("UpdateRequired"))?;
        let common = common.clone();
        let source = source.clone();
        self.full_runtime
            .clone()
            .run_blocking(move || {
                if new_recipient {
                    participant.full_new_recipient_sas_base(&common, &source)
                } else {
                    participant.full_sas_base(&common, &source)
                }
            })
            .await
    }
    pub(super) fn start_full_sas(
        c: &mut Ceremony,
        local_ref: &DeviceRef,
        keys: Option<(String, String)>,
    ) -> Result<(), SdkError> {
        let full = c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?;
        if full.pending.is_some() || full.hpke.is_some() || !matches!(c.sas, SasHold::None) {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let (branch_key, agreement_key) = keys.ok_or(SdkError::PairingCode("VaultUnavailable"))?;
        let sas_secret = Zeroizing::new(random_32()?);
        let salt = random_32()?;
        let hpke = HpkeSecrets::new()?;
        let device_ref = match c.role {
            PairingRole::Initiator => c.invitation.primary_ref.clone(),
            PairingRole::Responder => DeviceRef {
                account_anchor: full.common.account_anchor.clone(),
                device_id: local_ref.device_id.clone(),
                device_epoch: local_ref.device_epoch,
            },
        };
        let context = RoleContextV3 {
            schema: "ramflux.pairing.RoleContext.v3".into(),
            version: 3,
            role: c.role.as_str().into(),
            common: full.common.clone(),
            device_ref,
            branch_key,
            agreement_key,
            sas_key: encode_base64url(X25519KeyPair::from_seed_ref(&sas_secret).public),
            hpke_key: Some(encode_base64url(hpke.public_key())),
            display_name: c.display_name.clone(),
            transfer_profile: Some(TransferProfile::FullAccountDataV1),
        };
        context.validate().map_err(|error| wire(&error))?;
        full.pending = Some(commit(c.role, &context, &sas_secret, &salt)?);
        full.hpke = Some(hpke);
        Ok(())
    }
    pub(super) fn queue_full_offer(c: &mut Ceremony) -> Result<(), SdkError> {
        let full = c.full.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
        let offer = ContextOfferV3 {
            schema: "ramflux.pairing.ContextOffer.v3".into(),
            version: 3,
            common: full.common.clone(),
        };
        for frame in
            offer_chunks(random_32()?, &offer.to_wire_bytes().map_err(|error| wire(&error))?)?
        {
            c.outbound.push_back(frame);
        }
        Ok(())
    }
    pub(super) fn queue_full_commit(c: &mut Ceremony) -> Result<(), SdkError> {
        let pending = c
            .full
            .as_ref()
            .and_then(|full| full.pending.as_ref())
            .ok_or(SdkError::PairingCode("WrongContext"))?;
        // The existing bounded Commit carrier is opaque; its hash commits RoleContext.v3.
        c.outbound.push_back(RelayFrame::Commit {
            value: Commit {
                schema: "ramflux.pairing.Commit.v2".into(),
                version: 2,
                invitation_id: c.invitation.invitation_id.clone(),
                role: c.role.as_str().into(),
                commitment: encode_base64url(pending.commitment()),
            },
        });
        Ok(())
    }
    pub(super) fn ingest_full_commit(
        c: &mut Ceremony,
        peer: PairingRole,
        commitment: [u8; 32],
    ) -> Result<(), SdkError> {
        let pending = c
            .full
            .as_mut()
            .and_then(|full| full.pending.as_mut())
            .ok_or(SdkError::PairingCode("WrongContext"))?;
        pending.store_peer_commitment(peer, commitment)?;
        if c.phase == "invited" {
            c.phase = "commitments".into();
        }
        Ok(())
    }
    pub(super) fn maybe_full_reveal(c: &mut Ceremony) -> Result<(), SdkError> {
        if c.reveal_sent || c.phase != "commitments" {
            return Ok(());
        }
        let pending = c
            .full
            .as_ref()
            .and_then(|full| full.pending.as_ref())
            .ok_or(SdkError::PairingCode("WrongContext"))?;
        let Ok((salt, context)) = pending.reveal() else { return Ok(()) };
        let reveal = RevealV3 {
            schema: "ramflux.pairing.Reveal.v3".into(),
            version: 3,
            invitation_id: c.invitation.invitation_id.clone(),
            role: c.role.as_str().into(),
            salt: encode_base64url(salt),
            context: context.clone(),
        };
        for frame in
            reveal_chunks(random_32()?, &reveal.to_wire_bytes().map_err(|error| wire(&error))?)?
        {
            c.outbound.push_back(frame);
        }
        c.reveal_sent = true;
        Ok(())
    }
    pub(super) async fn finish_full_offer(&mut self, bytes: &[u8]) -> Result<(), SdkError> {
        ramflux_protocol::custody::pairing::require_context_version(bytes, 3)
            .map_err(|error| wire(&error))?;
        let offer = ContextOfferV3::from_wire_bytes(bytes).map_err(|error| wire(&error))?;
        let source = self.with_ceremony(|c| {
            if c.role != PairingRole::Responder || c.common.is_some() || c.full.is_some() {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let expected = CommonV3::from_full_invitation(
                &c.invitation,
                offer.common.master_public_key.clone(),
            )
            .map_err(|error| wire(&error))?;
            if expected != offer.common {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            Ok(c.invitation.primary_ref.clone())
        })?;
        let base = self
            .load_full_sas_base(&offer.common, &source, offer.common.recipient_mode == "new")
            .await?;
        let node = self.full_node.clone();
        self.with_ceremony_mut(|c| {
            if c.role != PairingRole::Responder || c.common.is_some() || c.full.is_some() {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let expected = CommonV3::from_full_invitation(
                &c.invitation,
                offer.common.master_public_key.clone(),
            )
            .map_err(|error| wire(&error))?;
            if expected != offer.common {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            c.common = Some(
                c.invitation
                    .project_common(offer.common.master_public_key.clone())
                    .map_err(|error| wire(&error))?,
            );
            if node.as_ref().is_some_and(|node| {
                node.envelope().body.node_signing_public_key != c.invitation.node_key
            }) {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let mut full = FullCeremony::new(offer.common, None);
            full.node = node;
            full.sas_base = Some(base);
            c.full = Some(full);
            Ok(())
        })?;
        let staged = self.stage_recipient_before_commit().await?;
        let reference = staged.as_ref().unwrap_or(&self.identity.local_ref).clone();
        let keys = self.load_public_keys(reference.clone()).await?;
        self.with_ceremony_mut(|c| {
            c.commitment_ref = staged;
            Self::start_full_sas(c, &reference, keys)?;
            Self::queue_full_commit(c)
        })
    }
    pub(super) fn finish_full_reveal(c: &mut Ceremony, bytes: &[u8]) -> Result<(), SdkError> {
        ramflux_protocol::custody::pairing::require_context_version(bytes, 3)
            .map_err(|error| wire(&error))?;
        let reveal = RevealV3::from_wire_bytes(bytes).map_err(|error| wire(&error))?;
        if reveal.invitation_id != c.invitation.invitation_id {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let salt = decode32(&reveal.salt)?;
        let full = c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?;
        let pending = full.pending.take().ok_or(SdkError::PairingCode("WrongContext"))?;
        let local = pending.context()?.clone();
        let peer = reveal.context;
        let transcript = TranscriptV3 {
            schema: "ramflux.pairing.Transcript.v3".into(),
            version: 3,
            initiator: if c.role == PairingRole::Initiator { local.clone() } else { peer.clone() },
            responder: if c.role == PairingRole::Responder { local } else { peer.clone() },
        };
        transcript.validate().map_err(|error| wire(&error))?;
        let established = pending.establish(&peer, &salt)?;
        let th = established.transcript_hash();
        c.displayed_th = Some(th);
        c.peer_ref = Some(peer.device_ref.clone());
        c.peer_name = Some(peer.display_name);
        // Existing local proposal hash already commits the full v3 transcript hash.
        c.displayed_proposal = Some(proposal_hash(
            c.common.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?,
            th,
            &peer.device_ref,
        )?);
        c.emoji = Some(established.emoji_indices().iter().map(|n| u64::from(*n)).collect());
        c.phase = "sas_pending".into();
        c.sas = SasHold::Established(Box::new(established));
        c.cleanup = "none".into();
        full.transcript = Some(transcript);
        Ok(())
    }
}

impl PairingActor {
    async fn prepare_live_full_source(
        &self,
    ) -> Result<(PreparedFullSource, FullSourcePreparationCancel), SdkError> {
        let participant =
            self.participant.clone().ok_or(SdkError::PairingCode("UpdateRequired"))?;
        // Complete source census/typed encoding before any Issue/Create allocation.
        let runtime = self.full_runtime.clone();
        let source = self
            .full_runtime
            .clone()
            .run_blocking(move || {
                let _local = runtime.local_work()?;
                participant
                    .prepare_full_source_with_cancel(|cancel| runtime.register_preparation(cancel))
            })
            .await?;
        if let Err(error) = self.full_runtime.require_live() {
            source.1.cancel();
            return Err(error);
        }
        Ok(source)
    }
    /// Explicit full-transfer begin; typed source preflight completes before native Issue.
    /// # Errors
    /// Refuses default-off, non-primary, locked/unsupported source or native/SAS setup errors.
    pub async fn begin_full(&mut self, begin: FullTransferBegin) -> Result<LocalResult, SdkError> {
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
        let source = self.prepare_live_full_source().await?;
        let spec = begin
            .create_spec(
                self.identity.local_ref.clone(),
                self.identity.base_record_hash.clone(),
                self.identity.base_epoch,
            )
            .map_err(|error| wire(&error))?;
        let prepared = PreparedIssue::prepare(spec.clone())?;
        let mut attempt = NativeAttempt { native: Arc::clone(&native), armed: true };
        let issued = prepared.apply(native.as_ref()).await?;
        let prepared_create = PreparedCreate::prepare(issued.ticket, spec)?;
        let mut created = prepared_create.apply(native.as_ref()).await?;
        created.validate_create(prepared_create.create()).map_err(|e| wire(&e))?;
        let node = match &self.full_node {
            Some(node) => node.clone(),
            None => native.full_node().await?,
        };
        let invitation = created.invitation.body.clone();
        if node.envelope().body.node_signing_public_key != invitation.node_key {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let origin = invitation.public_origin.clone();
        let full_common = CommonV3::from_full_invitation(&invitation, master.clone())
            .map_err(|error| wire(&error))?;
        let common = invitation.project_common(master).map_err(|e| wire(&e))?;
        let base = self.load_full_sas_base(&full_common, &invitation.primary_ref, false).await?;
        let generation = self.actor_generation;
        let primary_token = Zeroizing::new(std::mem::take(&mut created.primary_token));
        let recipient_token = std::mem::take(&mut created.recipient_token);
        let request_id = created.request_id.clone();
        let invite_envelope = created.invitation.clone();
        let expires_at = invitation.expires_at;
        let keys = self.load_public_keys(self.identity.local_ref.clone()).await?;
        if let Some(participant) = self.participant.clone() {
            let invitation = invite_envelope.clone();
            let runtime = self.full_runtime.clone();
            self.full_runtime
                .clone()
                .run_blocking(move || {
                    let _local = runtime.local_work()?;
                    participant.record_invitation(&invitation, generation)
                })
                .await?;
        }
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
        let mut full = FullCeremony::new(full_common, Some(source));
        full.node = Some(node);
        full.sas_base = Some(base);
        ceremony.full = Some(full);
        Self::start_full_sas(&mut ceremony, &self.identity.local_ref, keys)?;
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
}

#[cfg(test)]
mod tests;

impl super::PairingActor {
    /// Obtain local data-only stage access after the durable SAS-bound bootstrap.
    /// Reopening metadata alone cannot construct this owner or restore SAS approval.
    /// # Errors
    /// Refuses retired actors, absent participants or unfinished durable bootstrap.
    pub fn full_transfer_local_io(
        &self,
        db: &ramflux_storage::AccountDb,
    ) -> Result<crate::custody::pairing::FullTransferLocalIo, SdkError> {
        let wrong = || SdkError::PairingCode("WrongContext");
        self.full_runtime.require_live()?;
        let participant = self.participant.as_ref().ok_or_else(wrong)?;
        let ceremony = self.ceremony.as_ref().ok_or_else(wrong)?;
        let state =
            ceremony.full.as_ref().and_then(|full| full.bootstrap.as_ref()).ok_or_else(wrong)?;
        let trust = state.trust.as_ref().ok_or_else(wrong)?;
        let cancelled = state.cancel.clone().ok_or_else(wrong)?;
        crate::custody::pairing::FullTransferLocalIo::new(
            participant,
            db,
            (ceremony.operation_id.clone(), ceremony.generation),
            trust,
            cancelled,
            self.full_runtime.clone(),
        )
    }
}
