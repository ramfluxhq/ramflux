// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing recipient private unlock: prompt off-loan, verify on the actual frontend.
use super::{
    Arc, DeviceRef, Envelope, Invitation, SdkError, SecretUtf8, StageExisting, StageNew,
    acquire_existing_secret, encode_base64url, load_reservation, random_32, require_existing_refs,
    stored_data_vault_ref, verify_invitation, write_existing_install, write_floor_live,
};

/// Owns the private reply until a short frontend check. No database, data key or
/// borrowed client crosses the provider wait. Dropping wipes the reply.
pub(crate) struct ExistingFrontendUnlock {
    participant: Arc<super::super::LocalPairingParticipant>,
    invitation: Envelope<Invitation>,
    frontend_generation: u64,
    ceremony_generation: u64,
    reference: DeviceRef,
    branch_ref: String,
    data_ref: String,
    secret: SecretUtf8,
    reservation_id: String,
}
impl ExistingFrontendUnlock {
    pub(crate) fn acquire(
        participant: Arc<super::super::LocalPairingParticipant>,
        invitation: Envelope<Invitation>,
        frontend_generation: u64,
        ceremony_generation: u64,
    ) -> Result<Self, SdkError> {
        verify_invitation(&invitation)?;
        if invitation.body.recipient_mode != "existing" {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let native = crate::custody::load_account(
            &participant.root,
            &participant.account_id,
            crate::custody::network_now()?,
        )?;
        let reference = invitation
            .body
            .destination_ref
            .clone()
            .ok_or(SdkError::PairingField("destination_ref"))?;
        let branch_ref = native.branch_vault_ref().to_owned();
        let data_ref = stored_data_vault_ref(&participant.root, &participant.account_id)?;
        let request = StageExisting {
            new: StageNew {
                root: &participant.root,
                account_id: &participant.account_id,
                invitation: &invitation,
                vault: participant.vault.as_ref(),
                provider: participant.provider.as_ref(),
                frontend_generation,
            },
            recipient_ref: reference.clone(),
            branch_vault_ref: &branch_ref,
            data_vault_ref: &data_ref,
        };
        require_existing_refs(&request, &native)?;
        let (secret, reservation) = acquire_existing_secret(&request)?;
        Ok(Self {
            participant,
            invitation,
            frontend_generation,
            ceremony_generation,
            reference,
            branch_ref,
            data_ref,
            secret,
            reservation_id: reservation.reservation_id,
        })
    }
    pub(crate) fn finish(self, client: &crate::RamfluxClient) -> Result<DeviceRef, SdkError> {
        let participant = &self.participant;
        let db = client.account_db()?;
        participant.full_selected_db(db, None)?;
        let stored = load_reservation(&participant.root, &participant.account_id)?
            .ok_or(SdkError::PairingCode("Retired"))?;
        if stored.frontend_generation != self.frontend_generation
            || stored.reservation_id != self.reservation_id
        {
            return Err(SdkError::PairingCode("Retired"));
        }
        client.verify_active_account_secret(&participant.account_id, self.secret.as_bytes())?;
        let request = StageExisting {
            new: StageNew {
                root: &participant.root,
                account_id: &participant.account_id,
                invitation: &self.invitation,
                vault: participant.vault.as_ref(),
                provider: participant.provider.as_ref(),
                frontend_generation: self.frontend_generation,
            },
            recipient_ref: self.reference,
            branch_vault_ref: &self.branch_ref,
            data_vault_ref: &self.data_ref,
        };
        let native = crate::custody::load_account(
            &participant.root,
            &participant.account_id,
            crate::custody::network_now()?,
        )?;
        require_existing_refs(&request, &native)?;
        let staged = write_existing_install(&request, &encode_base64url(*random_32()?))?;
        write_floor_live(db, &request.new, &staged, self.ceremony_generation)?;
        Ok(staged.recipient_ref)
    }
}
