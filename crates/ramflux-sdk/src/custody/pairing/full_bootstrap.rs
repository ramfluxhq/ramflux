// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-profile SAS bootstrap: local grant validation precedes the real branch signer.
use super::{PairingNative, transport::wire};
use crate::SdkError;
use ramflux_crypto::custody::{
    VerifiedNodeRecord,
    pairing::{
        EstablishedSas, FullResumeTrust, PairingRole, verify_full_data_lease,
        verify_full_grant_offer,
    },
};
use ramflux_crypto::verify_canonical_signature;
use ramflux_protocol::{
    custody::{
        Envelope,
        pairing::{
            context_v3::TranscriptV3,
            full_transfer::{
                PROFILE,
                lease::{DataGrant, DataLease, LeaseRequest},
                relay::{FullSasControl, GrantOfferFull, GrantSignedFull, LeaseFull, StartFull},
            },
        },
    },
    encode_base64url,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    Offer,
    Signed,
    NativeLease,
    Lease,
    Done,
    Dead,
}
/// A SAS-channel ciphertext; the ordinary bounded relay carrier transports it unchanged.
pub struct FullBootstrapFrame {
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}
/// Created only after the bootstrap owner verifies both SAS confirmations and all
/// local grant operands. It grants one signature over this data-only request.
pub struct FullGrantSigningRequest<'a> {
    request: &'a LeaseRequest,
    context: &'a TranscriptV3,
    role: &'a str,
}
impl FullGrantSigningRequest<'_> {
    #[must_use]
    pub fn request(&self) -> &LeaseRequest {
        self.request
    }
    #[must_use]
    pub fn context(&self) -> &TranscriptV3 {
        self.context
    }
    #[must_use]
    pub fn role(&self) -> &str {
        self.role
    }
}
/// The channel's own 16-controls-per-direction limit and original expiry remain authoritative.
/// This owner contains no signing key, credential or reusable signer grant.
pub struct FullBootstrap {
    role: PairingRole,
    channel: EstablishedSas,
    context: TranscriptV3,
    node: VerifiedNodeRecord,
    phase: Phase,
    deadline: std::time::Instant,
    start: Option<StartFull>,
    request: Option<LeaseRequest>,
}
impl FullBootstrap {
    /// # Errors
    /// Refuses an unconfirmed or foreign v3 context, role or expired original SAS window.
    pub fn new(
        role: PairingRole,
        mut channel: EstablishedSas,
        context: TranscriptV3,
        node: VerifiedNodeRecord,
        now: u64,
    ) -> Result<Self, SdkError> {
        channel.require_full_transcript(role, &context)?;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(
                context.initiator.common.expires_at.saturating_sub(now).min(300),
            );
        let mut owner = Self {
            role,
            channel,
            context,
            node,
            phase: Phase::Start,
            deadline,
            start: None,
            request: None,
        };
        owner.live(now)?;
        Ok(owner)
    }
    fn live(&mut self, now: u64) -> Result<(), SdkError> {
        if self.phase == Phase::Dead || self.phase == Phase::Done {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        if now >= self.context.initiator.common.expires_at
            || std::time::Instant::now() >= self.deadline
        {
            return self.fail("Expired");
        }
        Ok(())
    }
    fn fail<T>(&mut self, code: &'static str) -> Result<T, SdkError> {
        self.channel.cleanup();
        self.phase = Phase::Dead;
        Err(SdkError::PairingCode(code))
    }
    fn request(&self, grant: DataGrant) -> Result<LeaseRequest, SdkError> {
        let request = LeaseRequest {
            schema: "ramflux.pairing.full_transfer.lease_request.v1".into(),
            version: 1,
            invitation_id: self.context.initiator.common.invitation_id.clone(),
            issuer_seq: self.context.initiator.common.issuer_seq,
            transcript_hash: encode_base64url(self.channel.transcript_hash()),
            grant,
            source_signature: encode_base64url([0; 64]),
            destination_signature: encode_base64url([0; 64]),
        };
        request
            .bind_transcript(&self.context, &encode_base64url(self.channel.transcript_hash()))
            .map_err(|error| wire(&error))?;
        Ok(request)
    }
    fn seal(&mut self, control: &FullSasControl) -> Result<FullBootstrapFrame, SdkError> {
        let plaintext = control.encode_secret().map_err(|error| wire(&error))?;
        let (counter, ciphertext) = self.channel.seal(&plaintext)?;
        Ok(FullBootstrapFrame { counter, ciphertext })
    }
    /// Source emits `Start` then `GrantOffer` on the same mutually confirmed v3 channel.
    /// # Errors
    /// Refuses bad locally pinned grant operands before invoking the branch signer.
    pub fn begin_source(
        &mut self,
        start: StartFull,
        grant: &DataGrant,
        now: u64,
        sign: impl FnOnce(&FullGrantSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<[FullBootstrapFrame; 2], SdkError> {
        self.live(now)?;
        if self.role != PairingRole::Initiator || self.phase != Phase::Start {
            return self.fail("WrongContext");
        }
        let grant = verify_full_grant_offer(
            &self.context,
            &start,
            grant,
            &self.node.envelope().body.node_id,
            now,
        )?;
        let mut request = self.request(grant.clone())?;
        request.source_signature = sign(&FullGrantSigningRequest {
            request: &request,
            context: &self.context,
            role: "initiator",
        })?;
        verify_canonical_signature(
            &request.signing_bytes("initiator").map_err(|error| wire(&error))?,
            &request.source_signature,
            &self.context.initiator.branch_key,
        )?;
        let first = self.seal(&FullSasControl::Start(start.clone()))?;
        let second = self.seal(&FullSasControl::GrantOffer(GrantOfferFull {
            grant,
            kind: "grant_offer_full".into(),
            profile: PROFILE.into(),
        }))?;
        self.start = Some(start);
        self.request = Some(request);
        self.phase = Phase::Signed;
        Ok([first, second])
    }
    /// Apply one encrypted bootstrap control. B rebuilds the complete grant locally
    /// before the callback may load its original branch signer.
    /// # Errors
    /// Refuses reordered/foreign controls, invalid signatures, changed leases and expiry.
    pub fn receive(
        &mut self,
        frame: &FullBootstrapFrame,
        now: u64,
        sign: impl FnOnce(&FullGrantSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<Option<FullBootstrapFrame>, SdkError> {
        let result = self.receive_inner(frame, now, sign);
        if result.is_err() {
            self.channel.cleanup();
            self.phase = Phase::Dead;
        }
        result
    }
    fn receive_inner(
        &mut self,
        frame: &FullBootstrapFrame,
        now: u64,
        sign: impl FnOnce(&FullGrantSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<Option<FullBootstrapFrame>, SdkError> {
        self.live(now)?;
        let opened = self.channel.open(frame.counter, &frame.ciphertext)?;
        let control = FullSasControl::from_wire_bytes(&opened).map_err(|error| wire(&error))?;
        match (self.role, self.phase, control) {
            (PairingRole::Responder, Phase::Start, FullSasControl::Start(start)) => {
                if self.context.initiator.common.transfer_id.as_deref()
                    != Some(start.transfer_id.as_str())
                {
                    return self.fail("WrongContext");
                }
                self.start = Some(start);
                self.phase = Phase::Offer;
                Ok(None)
            }
            (PairingRole::Responder, Phase::Offer, FullSasControl::GrantOffer(offer)) => {
                let start = self.start.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
                let grant = verify_full_grant_offer(
                    &self.context,
                    start,
                    &offer.grant,
                    &self.node.envelope().body.node_id,
                    now,
                )?;
                let mut request = self.request(grant)?;
                request.destination_signature = sign(&FullGrantSigningRequest {
                    request: &request,
                    context: &self.context,
                    role: "responder",
                })?;
                verify_canonical_signature(
                    &request.signing_bytes("responder").map_err(|error| wire(&error))?,
                    &request.destination_signature,
                    &self.context.responder.branch_key,
                )?;
                let reply = self.seal(&FullSasControl::GrantSigned(GrantSignedFull {
                    destination_signature: request.destination_signature.clone(),
                    kind: "grant_signed_full".into(),
                    profile: PROFILE.into(),
                }))?;
                self.request = Some(request);
                self.phase = Phase::Lease;
                Ok(Some(reply))
            }
            (PairingRole::Initiator, Phase::Signed, FullSasControl::GrantSigned(signed)) => {
                let request = self.request.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?;
                verify_canonical_signature(
                    &request.signing_bytes("responder").map_err(|error| wire(&error))?,
                    &signed.destination_signature,
                    &self.context.responder.branch_key,
                )?;
                request.destination_signature = signed.destination_signature;
                self.phase = Phase::NativeLease;
                Ok(None)
            }
            // Lease acceptance and trust extraction are explicit to prevent accidentally
            // treating receipt of a node signature as completion of the peer proof gate.
            _ => self.fail("WrongContext"),
        }
    }
    /// Native issuance uses the ceremony's fresh proof connection, with no DB loan held.
    /// # Errors
    /// Refuses an incomplete exchange, native failure or a node-replaced lease.
    pub async fn issue_source_lease(
        &mut self,
        native: &dyn PairingNative,
        now: u64,
    ) -> Result<(FullBootstrapFrame, Envelope<DataLease>, FullResumeTrust), SdkError> {
        self.live(now)?;
        if self.role != PairingRole::Initiator || self.phase != Phase::NativeLease {
            return self.fail("WrongContext");
        }
        let request = self.request.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?.clone();
        let lease = native.data_lease(request.clone()).await?;
        let after = crate::custody::network_now()?;
        self.live(after)?;
        verify_full_data_lease(&lease, &request.grant, &self.node, after)?;
        let trust = self.channel.full_resume_trust(self.context.clone(), request.grant, &lease)?;
        let frame = self.seal(&FullSasControl::Lease(LeaseFull {
            kind: "lease_full".into(),
            lease: lease.clone(),
            profile: PROFILE.into(),
        }))?;
        self.channel.cleanup();
        self.phase = Phase::Done;
        Ok((frame, lease, trust))
    }
    /// B verifies the exact locally reconstructed grant and pinned node before saving resume trust.
    /// # Errors
    /// Refuses any other arm/phase, changed grant, forged lease or original-window expiry.
    pub fn accept_destination_lease(
        &mut self,
        frame: &FullBootstrapFrame,
        now: u64,
    ) -> Result<(Envelope<DataLease>, FullResumeTrust), SdkError> {
        self.live(now)?;
        if self.role != PairingRole::Responder || self.phase != Phase::Lease {
            return self.fail("WrongContext");
        }
        let opened = self.channel.open(frame.counter, &frame.ciphertext)?;
        let FullSasControl::Lease(lease) =
            FullSasControl::from_wire_bytes(&opened).map_err(|error| wire(&error))?
        else {
            return self.fail("WrongContext");
        };
        let grant = &self.request.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?.grant;
        verify_full_data_lease(&lease.lease, grant, &self.node, now)?;
        let trust =
            self.channel.full_resume_trust(self.context.clone(), grant.clone(), &lease.lease)?;
        self.channel.cleanup();
        self.phase = Phase::Done;
        Ok((lease.lease, trust))
    }
}

#[cfg(test)]
mod tests;
