// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Memory-only A3 driver. No SAS approval, native authority, database loan or persisted token.
use super::{FullPairingTransport, HttpRelay, transport::wire};
use crate::SdkError;
use ramflux_crypto::custody::pairing::{
    FullResumeAttempt, FullResumeKeyOwner, FullResumeTrust, HpkeSecrets, PairingRole,
    VerifiedFullResume,
};
use ramflux_protocol::{
    custody::{
        DeviceRef, Envelope,
        pairing::{
            PairingWire,
            full_transfer::{
                PROFILE, SecretBase64,
                lease::{DataLease, ResumeProof},
                relay::{FullDiscovery, FullProofReply, HelloFull, PollFullDiscovery, ProveFull},
            },
        },
    },
    decode_base64url, encode_base64url,
};
use tokio::time::{Duration, Instant};

/// Constructed only after matching the discovery template with both locally frozen keys.
pub struct FullResumeProofSigningRequest<'a> {
    proof: &'a ResumeProof,
    own_ref: &'a DeviceRef,
    own_branch_key: &'a str,
}
impl FullResumeProofSigningRequest<'_> {
    #[must_use]
    pub fn proof(&self) -> &ResumeProof {
        self.proof
    }
    #[must_use]
    pub fn own_ref(&self) -> &DeviceRef {
        self.own_ref
    }
    #[must_use]
    pub fn own_branch_key(&self) -> &str {
        self.own_branch_key
    }
}
/// Data-only proof-verified HPKE setup owner and this role's erasing bearer token.
/// No Debug/serde; neither this token nor the epoch is durable resume metadata.
pub struct FullEpoch {
    verified: VerifiedFullResume,
    token: SecretBase64,
    lease_id: String,
    epoch: String,
    role: PairingRole,
    binding: ramflux_protocol::custody::pairing::full_transfer::DataBinding,
    expires_at: u64,
    initial_epoch: bool,
}
impl FullEpoch {
    /// Poll B's control using only this original-proof-verified role token and local scope.
    /// The returned ciphertext is still opened against B's own frozen info/AAD.
    /// # Errors
    /// Refuses initiator scope, lease expiry, malformed control or transport failure.
    pub async fn poll_destination_control(
        &self,
        relay: &dyn FullPairingTransport,
        origin: &str,
    ) -> Result<
        Option<ramflux_protocol::custody::pairing::full_transfer::relay::HpkeConfirmFull>,
        SdkError,
    > {
        use ramflux_protocol::custody::pairing::full_transfer::relay::PollFullControl;
        if self.role != PairingRole::Responder {
            return Err(wrong());
        }
        if crate::custody::network_now()? >= self.expires_at {
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        let request = PollFullControl {
            epoch: self.epoch.clone(),
            kind: "poll_full_control".into(),
            lease_id: self.lease_id.clone(),
            profile: PROFILE.into(),
            role: self.role.as_str().into(),
            token: self.token.clone(),
        };
        let reply = relay.poll_full_control(origin, &request).await?;
        reply.validate().map_err(|error| wire(&error))?;
        if let Some(control) = &reply.control
            && (control.epoch != self.epoch
                || control.lease_id != self.lease_id
                || control.role != "initiator")
        {
            return Err(wrong());
        }
        Ok(reply.control)
    }
}

struct Negotiation<'a> {
    trust: &'a FullResumeTrust,
    lease: Envelope<DataLease>,
    role: PairingRole,
    own_ref: DeviceRef,
    own_branch_key: String,
    key: Option<HpkeSecrets>,
    hello: Option<HelloFull>,
    attempt: Option<FullResumeAttempt>,
    proof: Option<ProveFull>,
    deadline: Instant,
    discovered_source: Option<String>,
    initial_epoch: bool,
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
impl<'a> Negotiation<'a> {
    fn new(trust: &'a FullResumeTrust, keys: &mut FullResumeKeyOwner) -> Result<Self, SdkError> {
        let saved = trust.local_stage_record()?;
        let lease: Envelope<DataLease> =
            ramflux_protocol::parse_i_json_secret(&saved.lease).map_err(|_| wrong())?;
        let role = saved.role;
        let (own_ref, own_branch_key) = match role {
            PairingRole::Initiator => (saved.grant.source_ref, saved.grant.branch_keys.source),
            PairingRole::Responder => {
                (saved.grant.destination_ref, saved.grant.branch_keys.destination)
            }
        };
        let initial_epoch = keys.next_uses_sas_key();
        let key = keys.next_key()?;
        let hello = if role == PairingRole::Initiator {
            Some(HelloFull {
                epoch: encode_base64url(ramflux_crypto::random_32()?),
                hpke_key: encode_base64url(key.public_key()),
                kind: "hello_full".into(),
                lease: lease.clone(),
                profile: PROFILE.into(),
                role: role.as_str().into(),
            })
        } else {
            None
        };
        Ok(Self {
            trust,
            lease,
            role,
            own_ref,
            own_branch_key,
            key: Some(key),
            hello,
            attempt: None,
            proof: None,
            discovered_source: None,
            initial_epoch,
            deadline: Instant::now() + Duration::from_secs(10),
        })
    }
    fn live(&self) -> Result<(), SdkError> {
        if Instant::now() >= self.deadline {
            return Err(SdkError::PairingCode("ResumeRequired"));
        }
        if crate::custody::network_now()? >= self.trust.lease_expires_at() {
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        Ok(())
    }
    fn poll(&self) -> PollFullDiscovery {
        PollFullDiscovery {
            kind: "poll_full_discovery".into(),
            lease: self.lease.clone(),
            profile: PROFILE.into(),
            role: self.role.as_str().into(),
        }
    }
    fn discovery(
        &mut self,
        reply: &FullDiscovery,
        sign: &mut impl FnMut(&FullResumeProofSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<(), SdkError> {
        self.live()?;
        reply.validate().map_err(|error| wire(&error))?;
        if reply.lease_id != self.lease.body.lease_id {
            return Err(wrong());
        }
        if self.hello.is_none() {
            if self.role != PairingRole::Responder {
                return Err(wrong());
            }
            self.discovered_source = Some(reply.hpke_keys.source.clone());
            let key = self.key.as_ref().ok_or_else(wrong)?;
            self.hello = Some(HelloFull {
                epoch: reply.epoch.clone(),
                hpke_key: encode_base64url(key.public_key()),
                kind: "hello_full".into(),
                lease: self.lease.clone(),
                profile: PROFILE.into(),
                role: self.role.as_str().into(),
            });
        }
        if self.discovered_source.as_ref().is_some_and(|source| source != &reply.hpke_keys.source) {
            return Err(wrong());
        }
        let hello = self.hello.as_ref().ok_or_else(wrong)?;
        let own = match self.role {
            PairingRole::Initiator => Some(reply.hpke_keys.source.as_str()),
            PairingRole::Responder => reply.hpke_keys.destination.as_deref(),
        };
        if reply.epoch != hello.epoch || own.is_some_and(|value| value != hello.hpke_key) {
            return Err(wrong());
        }
        if reply.template.is_none() {
            return Ok(());
        }
        if self.proof.is_some() {
            return Err(wrong());
        }
        let peer = match self.role {
            PairingRole::Initiator => reply.hpke_keys.destination.as_deref().ok_or_else(wrong)?,
            PairingRole::Responder => reply.hpke_keys.source.as_str(),
        };
        let peer = decode_base64url(peer).map_err(|_| wrong())?;
        let peer = peer.as_slice().try_into().map_err(|_| wrong())?;
        let mut attempt = self.trust.begin(
            &self.lease,
            self.key.take().ok_or_else(wrong)?,
            peer,
            hello.epoch.clone(),
        )?;
        let body = attempt.discovery_proof_to_sign(reply)?;
        let signature = sign(&FullResumeProofSigningRequest {
            proof: &body,
            own_ref: &self.own_ref,
            own_branch_key: &self.own_branch_key,
        })?;
        let proof = ProveFull {
            kind: "prove_full".into(),
            profile: PROFILE.into(),
            proof: Envelope { body, signature },
        };
        proof.validate().map_err(|error| wire(&error))?;
        // Refuse a broken/private provider before giving the node any signing output.
        ramflux_crypto::verify_canonical_signature(
            &proof.proof.body.signing_bytes().map_err(|error| wire(&error))?,
            &proof.proof.signature,
            &self.own_branch_key,
        )?;
        self.attempt = Some(attempt);
        self.proof = Some(proof);
        Ok(())
    }
    fn token(&mut self, reply: FullProofReply) -> Result<Option<FullEpoch>, SdkError> {
        self.live()?;
        let epoch = &self.hello.as_ref().ok_or_else(wrong)?.epoch;
        match reply {
            FullProofReply::Pending(pending) => {
                pending.validate().map_err(|error| wire(&error))?;
                if pending.lease_id != self.lease.body.lease_id || &pending.epoch != epoch {
                    return Err(wrong());
                }
                Ok(None)
            }
            FullProofReply::Ready(token) => {
                // Original SAS peer key + exact locally retained lease/epoch/two-key proof.
                let verified = self.attempt.take().ok_or_else(wrong)?.verify_token(&token)?;
                let saved = self.trust.local_stage_record()?;
                let binding = ramflux_protocol::custody::pairing::full_transfer::DataBinding {
                    profile: PROFILE.into(),
                    transfer_id: saved.transfer_id,
                    manifest_hash: saved.base_manifest_hash,
                    epoch: token.epoch.clone(),
                    source_ref: saved.grant.source_ref,
                    destination_ref: saved.grant.destination_ref,
                    base_record_hash: saved.base_record_hash,
                };
                Ok(Some(FullEpoch {
                    verified,
                    token: token.token,
                    lease_id: token.lease_id,
                    epoch: token.epoch,
                    role: self.role,
                    binding,
                    expires_at: self.trust.lease_expires_at(),
                    initial_epoch: self.initial_epoch,
                }))
            }
        }
    }
}
impl dyn FullPairingTransport + '_ {
    /// Run A-first discovery and dual original-branch proofs, including the first epoch.
    /// `keys` preserves only the still-unused SAS private half in memory; every later key
    /// is fresh. The signer must bind its actual unlocked branch to the typed request.
    /// No DB/generation/authority lock may be held across this network operation.
    /// # Errors
    /// Refuses changed discovery operands, wrong/missing peer proof, deadline or lease expiry.
    /// A failed attempt drops its HPKE half and token; retry starts a fresh epoch.
    pub async fn negotiate_full_epoch(
        &self,
        origin: &str,
        trust: &FullResumeTrust,
        keys: &mut FullResumeKeyOwner,
        mut sign: impl FnMut(&FullResumeProofSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<FullEpoch, SdkError> {
        let mut run = Negotiation::new(trust, keys)?;
        let deadline = run.deadline;
        tokio::time::timeout_at(deadline, async {
            let mut sent_hello = false;
            loop {
                run.live()?;
                if let Some(proof) = &run.proof {
                    let reply = self.prove_full(origin, proof).await?;
                    if let Some(ready) = run.token(reply)? {
                        return Ok(ready);
                    }
                } else {
                    let reply = if !sent_hello && let Some(hello) = &run.hello {
                        let value = self.hello_full(origin, hello).await?;
                        sent_hello = true;
                        value
                    } else {
                        match self.discover_full(origin, &run.poll()).await {
                            Ok(value) => value,
                            Err(SdkError::PairingCode("NotFound")) if run.hello.is_none() => {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                continue;
                            }
                            Err(error) => return Err(error),
                        }
                    };
                    let had_hello = run.hello.is_some();
                    run.discovery(&reply, &mut sign)?;
                    if !had_hello {
                        continue;
                    }
                }
                // Node discovery credit admits at most two polls per second per role.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .map_err(|_| SdkError::PairingCode("ResumeRequired"))?
    }
}

impl HttpRelay {
    /// Run A3 using the same closed full transport port as the coordinator.
    /// # Errors
    /// Refuses changed operands, invalid peer proof, expiry or relay failure.
    pub async fn negotiate_full_epoch(
        &self,
        origin: &str,
        trust: &FullResumeTrust,
        keys: &mut FullResumeKeyOwner,
        sign: impl FnMut(&FullResumeProofSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<FullEpoch, SdkError> {
        (self as &dyn FullPairingTransport).negotiate_full_epoch(origin, trust, keys, sign).await
    }
}

mod packet;
#[cfg(test)]
pub(crate) use packet::FirstForwardPosition;
pub use packet::FullPacketEpoch;

#[cfg(test)]
mod tests;
