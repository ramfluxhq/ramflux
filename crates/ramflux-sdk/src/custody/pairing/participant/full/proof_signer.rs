// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Narrow data-resume signer: weak ordinary-unlock liveness, no parked frontend DB loan.
use super::{LocalPairingParticipant, SdkError, custody, encode_base64url, wrong};
use crate::custody::pairing::FullResumeProofSigningRequest;
use ed25519_dalek::Signer as _;
use ramflux_crypto::custody::pairing::{FullResumeTrust, PairingRole};
use ramflux_protocol::custody::DeviceRef;
use ramflux_storage::FullLocalUnlockGuard;
use std::sync::Arc;

/// No Debug/serde/clone and no arbitrary-byte/publication signing operation.
pub(crate) struct FullProofSigner {
    unlock: FullLocalUnlockGuard,
    reference: DeviceRef,
    branch_key: String,
    vault_ref: String,
    lease_id: String,
    expires_at: u64,
    role: PairingRole,
    vault: Arc<dyn custody::PrimaryVault>,
}
impl FullProofSigner {
    fn require_live(&self) -> Result<(), SdkError> {
        self.unlock.require_unlocked()?;
        if custody::network_now()? >= self.expires_at {
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        Ok(())
    }
    pub(crate) fn sign(
        &self,
        request: &FullResumeProofSigningRequest<'_>,
    ) -> Result<String, SdkError> {
        self.require_live()?;
        if request.own_ref() != &self.reference
            || request.own_branch_key() != self.branch_key
            || request.proof().lease_id != self.lease_id
            || request.proof().role != self.role.as_str()
        {
            return Err(wrong());
        }
        let bytes = request
            .proof()
            .signing_bytes()
            .map_err(|error| crate::custody::pairing::transport::wire(&error))?;
        let branch = self.vault.load_branch(
            &self.vault_ref,
            &self.reference.account_anchor,
            &self.reference,
        )?;
        self.require_live()?;
        if encode_base64url(branch.signing.signing_key.verifying_key().to_bytes())
            != self.branch_key
        {
            return Err(wrong());
        }
        let signature = encode_base64url(branch.signing.signing_key.sign(&bytes).to_bytes());
        self.require_live()?;
        Ok(signature)
    }
}
impl LocalPairingParticipant {
    pub(crate) fn prepare_full_proof_signer(
        &self,
        operation: &str,
        generation: u64,
        trust: &FullResumeTrust,
    ) -> Result<FullProofSigner, SdkError> {
        let saved = trust.local_stage_record()?;
        let lease: ramflux_protocol::custody::Envelope<
            ramflux_protocol::custody::pairing::full_transfer::lease::DataLease,
        > = ramflux_protocol::custody::decode(&saved.lease, 16_384)?;
        let (reference, branch_key) = match saved.role {
            PairingRole::Initiator => (&saved.grant.source_ref, &saved.grant.branch_keys.source),
            PairingRole::Responder => {
                (&saved.grant.destination_ref, &saved.grant.branch_keys.destination)
            }
        };
        let unlock = {
            let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
            self.full_selected_db(db, Some(&reference.account_anchor))?;
            let row = db
                .pairing_live_rows()?
                .into_iter()
                .find(|row| row.operation_id == operation)
                .ok_or_else(wrong)?;
            if row.generation != generation {
                return Err(wrong());
            }
            let stage =
                db.open_full_transfer_stage(operation, saved.role, custody::network_now()?)?;
            if stage.resume_record()?.stage_digest()? != saved.stage_digest()? {
                return Err(wrong());
            }
            db.full_local_unlock_guard()?
        };
        self.with_full_branch(reference, branch_key, |_| Ok(()))?;
        let vault_ref = self.full_branch_vault_ref(reference)?;
        unlock.require_unlocked()?;
        Ok(FullProofSigner {
            unlock,
            reference: reference.clone(),
            branch_key: branch_key.clone(),
            vault_ref,
            vault: self.vault.clone(),
            lease_id: lease.body.lease_id,
            expires_at: trust.lease_expires_at(),
            role: saved.role,
        })
    }
}
