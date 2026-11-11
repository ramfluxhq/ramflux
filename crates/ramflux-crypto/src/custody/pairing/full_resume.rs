// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Endpoint H1 trust is the local SAS context/grant/lease, never a node's replacement keys.
use super::{
    FullDataKeys, FullSenderSetup, HpkeSecrets, PairingRole, open_full_receiver, setup_full_sender,
};
use crate::{CryptoError, verify_canonical_signature};
use ramflux_protocol::custody::{
    Envelope,
    pairing::{
        PairingWire,
        context_v3::TranscriptV3,
        full_transfer::{
            DataBinding,
            lease::{BranchKeys, DataGrant, DataLease, ResumeProof},
            relay::{FullDiscovery, HpkeConfirmFull, ResumeTokenFull},
        },
    },
};
use ramflux_protocol::{canonical_json_bytes, decode_base64url, encode_base64url};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, CryptoError>;
/// Created from both-human-confirmed SAS by its owner; saved only in the local encrypted stage.
/// No Debug/serde: no node response can deserialize into this trust owner.
pub struct FullResumeTrust {
    role: PairingRole,
    context: TranscriptV3,
    grant: DataGrant,
    lease: Zeroizing<Vec<u8>>,
    th: [u8; 32],
}
impl FullResumeTrust {
    pub(super) fn from_confirmed(
        role: PairingRole,
        context: TranscriptV3,
        grant: DataGrant,
        lease: &Envelope<DataLease>,
        th: [u8; 32],
    ) -> Result<Self> {
        context.validate()?;
        grant.validate()?;
        let a = &context.initiator;
        let b = &context.responder;
        if lease.body.grant != grant
            || a.branch_key != grant.branch_keys.source
            || b.branch_key != grant.branch_keys.destination
            || a.device_ref != grant.source_ref
            || b.device_ref != grant.destination_ref
            || a.common.transfer_id.as_deref() != Some(grant.transfer_id.as_str())
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        Ok(Self { role, context, grant, lease: Zeroizing::new(canonical_json_bytes(lease)?), th })
    }
    /// Select the still-unused SAS private half, or fresh keys after loss/restart.
    /// # Errors
    /// Refuses a private half that does not match this endpoint's own SAS key.
    pub fn key_owner(&self, mut sas: Option<HpkeSecrets>) -> Result<FullResumeKeyOwner> {
        if let Some(key) = &mut sas {
            let expected = match self.role {
                PairingRole::Initiator => self.context.initiator.hpke_key.as_deref(),
                PairingRole::Responder => self.context.responder.hpke_key.as_deref(),
            };
            if expected != Some(encode_base64url(key.public_key()).as_str()) {
                key.cleanup();
                return Err(CryptoError::Pairing("WrongContext"));
            }
        }
        Ok(FullResumeKeyOwner { unused_sas: sas })
    }
    /// Freeze the own actual key and exact received peer proposal for this attempt.
    /// # Errors
    /// Refuses a changed lease/grant. Every peer key requires its SAS-pinned branch proof.
    pub fn begin(
        &self,
        received_lease: &Envelope<DataLease>,
        own: HpkeSecrets,
        peer: [u8; 32],
        epoch: String,
    ) -> Result<FullResumeAttempt> {
        let own_public = encode_base64url(own.public_key());
        let peer_public = encode_base64url(peer);
        let keys = match self.role {
            PairingRole::Initiator => BranchKeys { source: own_public, destination: peer_public },
            PairingRole::Responder => BranchKeys { source: peer_public, destination: own_public },
        };
        let mut attempt = FullResumeAttempt {
            role: self.role,
            own: Some(own),
            peer,
            keys,
            epoch,
            lease_id: received_lease.body.lease_id.clone(),
            grant: self.grant.clone(),
            th: self.th,
            peer_branch_key: match self.role {
                PairingRole::Initiator => self.context.responder.branch_key.clone(),
                PairingRole::Responder => self.context.initiator.branch_key.clone(),
            },
            checked: None,
            base_record_hash: self.context.initiator.common.record_hash.clone(),
        };
        let same_lease = received_lease.body.grant == self.grant
            && Zeroizing::new(canonical_json_bytes(received_lease)?).as_slice()
                == self.lease.as_slice();
        if !same_lease {
            return attempt.fail();
        }
        attempt.keys.validate()?;
        let decoded =
            decode_base64url(&attempt.epoch).map_err(|_| CryptoError::Pairing("WrongContext"))?;
        if decoded.len() != 32 || encode_base64url(decoded) != attempt.epoch {
            return attempt.fail();
        }
        Ok(attempt)
    }
}
/// Owns the fresh HPKE secret until both matching proofs authenticate under the local SAS key.
pub struct FullResumeAttempt {
    role: PairingRole,
    own: Option<HpkeSecrets>,
    peer: [u8; 32],
    keys: BranchKeys,
    epoch: String,
    lease_id: String,
    grant: DataGrant,
    th: [u8; 32],
    peer_branch_key: String,
    checked: Option<ResumeProof>,
    base_record_hash: String,
}
impl Drop for FullResumeAttempt {
    fn drop(&mut self) {
        if let Some(own) = &mut self.own {
            own.cleanup();
        }
    }
}
impl FullResumeAttempt {
    fn fail<T>(&mut self) -> Result<T> {
        if let Some(mut own) = self.own.take() {
            own.cleanup();
        }
        self.checked = None;
        Err(CryptoError::Pairing("WrongContext"))
    }
    /// Return only the exact frozen template with this endpoint's original role for its signer.
    /// Check the complete discovery reply against the locally frozen lease/epoch/keys
    /// before any original-branch signer can receive its proof template.
    /// # Errors
    /// Refuses another lease/profile, changed proposal, absent peer or changed template.
    pub fn discovery_proof_to_sign(&mut self, discovery: &FullDiscovery) -> Result<ResumeProof> {
        if discovery.validate().is_err()
            || discovery.lease_id != self.lease_id
            || discovery.epoch != self.epoch
            || discovery.hpke_keys.source != self.keys.source
            || discovery.hpke_keys.destination.as_deref() != Some(self.keys.destination.as_str())
        {
            return self.fail();
        }
        let Some(template) = &discovery.template else {
            return self.fail();
        };
        self.proof_to_sign(template)
    }
    /// # Errors
    /// Refuses node substitution of either key/epoch/lease or replacement of a checked nonce.
    pub fn proof_to_sign(&mut self, template: &ResumeProof) -> Result<ResumeProof> {
        if self.own.is_none() {
            return self.fail();
        }
        if template.validate().is_err()
            || template.role != "initiator"
            || template.lease_id != self.lease_id
            || template.epoch != self.epoch
            || template.hpke_keys != self.keys
        {
            return self.fail();
        }
        let mut own_body = template.clone();
        own_body.role = match self.role {
            PairingRole::Initiator => "initiator",
            PairingRole::Responder => "responder",
        }
        .into();
        if self.checked.as_ref().is_some_and(|previous| previous != &own_body) {
            return self.fail();
        }
        self.checked = Some(own_body.clone());
        Ok(own_body)
    }
    /// H1 gate before ANY Auth-HPKE call. The verifying key is exclusively the local SAS key.
    /// # Errors
    /// Refuses missing/foreign peer proofs, node-held signing keys, another epoch or lease.
    pub fn verify_token(mut self, token: &ResumeTokenFull) -> Result<VerifiedFullResume> {
        let Some(body) = self.checked.as_ref() else {
            return self.fail();
        };
        if token.validate().is_err()
            || token.role != body.role
            || token.epoch != self.epoch
            || token.lease_id != self.lease_id
            || body.require_peer(&token.peer_proof.body).is_err()
        {
            return self.fail();
        }
        if verify_canonical_signature(
            &token.peer_proof.body.signing_bytes()?,
            &token.peer_proof.signature,
            &self.peer_branch_key,
        )
        .is_err()
        {
            return self.fail();
        }
        let own = self.own.take().ok_or(CryptoError::Pairing("WrongContext"))?;
        Ok(VerifiedFullResume {
            role: self.role,
            own: Some(own),
            peer: self.peer,
            epoch: self.epoch.clone(),
            lease_id: self.lease_id.clone(),
            base_record_hash: self.base_record_hash.clone(),
            grant: self.grant.clone(),
            th: self.th,
        })
    }
}
/// Only the verified peer-proof gate constructs this HPKE setup owner.
pub struct VerifiedFullResume {
    role: PairingRole,
    own: Option<HpkeSecrets>,
    peer: [u8; 32],
    epoch: String,
    lease_id: String,
    base_record_hash: String,
    grant: DataGrant,
    th: [u8; 32],
}
impl Drop for VerifiedFullResume {
    fn drop(&mut self) {
        if let Some(own) = &mut self.own {
            own.cleanup();
        }
    }
}
impl VerifiedFullResume {
    fn require_binding(&self, binding: &DataBinding) -> Result<()> {
        binding.validate()?;
        if binding.base_record_hash != self.base_record_hash
            || binding.epoch != self.epoch
            || binding.transfer_id != self.grant.transfer_id
            || binding.source_ref != self.grant.source_ref
            || binding.destination_ref != self.grant.destination_ref
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        Ok(())
    }
    /// # Errors
    /// Refuses another role/binding; no sender setup is possible before peer proof verification.
    pub fn setup_sender(mut self, binding: &DataBinding) -> Result<FullSenderSetup> {
        self.require_binding(binding)?;
        if self.role != PairingRole::Initiator {
            return Err(CryptoError::Pairing("WrongRole"));
        }
        setup_full_sender(
            self.own.take().ok_or(CryptoError::Pairing("WrongContext"))?,
            &self.peer,
            &self.th,
            binding,
        )
    }
    /// # Errors
    /// Refuses another role/binding or confirmation; uses the locally pinned full-v3 TH.
    pub fn open_receiver(
        &mut self,
        enc: &[u8; 32],
        confirmation: &[u8],
        binding: &DataBinding,
    ) -> Result<FullDataKeys> {
        self.require_binding(binding)?;
        if self.role != PairingRole::Responder {
            return Err(CryptoError::Pairing("WrongRole"));
        }
        open_full_receiver(
            self.own.take().ok_or(CryptoError::Pairing("WrongContext"))?,
            &self.peer,
            enc,
            confirmation,
            &self.th,
            binding,
        )
    }
    /// Open a polled control using only locally frozen operands for info/AAD.
    /// # Errors
    /// Refuses foreign scope before consuming the private half; an HPKE attempt always destroys it.
    pub fn open_control(
        &mut self,
        control: &HpkeConfirmFull,
        local_binding: &DataBinding,
    ) -> Result<FullDataKeys> {
        self.require_binding(local_binding)?;
        control.validate().map_err(|_| CryptoError::Pairing("WrongContext"))?;
        if control.lease_id != self.lease_id
            || control.epoch != self.epoch
            || control.role != "initiator"
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        let enc =
            decode_base64url(&control.enc).map_err(|_| CryptoError::Pairing("WrongContext"))?;
        let enc = enc.as_slice().try_into().map_err(|_| CryptoError::Pairing("WrongContext"))?;
        let confirmation = Zeroizing::new(
            decode_base64url(&control.confirmation)
                .map_err(|_| CryptoError::Pairing("WrongContext"))?,
        );
        self.open_receiver(enc, &confirmation, local_binding)
    }
}

/// Memory-only single-use key source. Its state is never part of the resume record.
pub struct FullResumeKeyOwner {
    unused_sas: Option<HpkeSecrets>,
}
impl Drop for FullResumeKeyOwner {
    fn drop(&mut self) {
        if let Some(key) = &mut self.unused_sas {
            key.cleanup();
        }
    }
}
impl FullResumeKeyOwner {
    /// # Errors
    /// Refuses unavailable CSPRNG entropy when the SAS private half is already gone.
    pub fn next_key(&mut self) -> Result<HpkeSecrets> {
        self.unused_sas.take().map_or_else(HpkeSecrets::new, Ok)
    }
}
