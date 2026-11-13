// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! New recipient G1/G2/G3 after independently querying its exact retained native candidate.
use super::{LocalPairingParticipant, wrong};
use crate::{
    SdkError,
    custody::pairing::{
        Installation, full_generation::owner::FullGenerationPreparation, install_store::Install,
    },
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::CustodyAuthority;

impl LocalPairingParticipant {
    pub(crate) fn install_new_full_generation(
        &self,
        install: &Install,
    ) -> Result<CustodyAuthority, SdkError> {
        if install.recipient_mode != "new" || install.account_id != self.account_id {
            return Err(wrong());
        }
        let operation = &install.operation_id;
        // The query receipt owns no database, vault key or frontend loan.
        let observation = self.full_recipient_publication_query(operation)?.observe()?;
        let authority = observation.authority().clone();
        let pinned = {
            let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
            observation.acknowledge(db)?;
            let stage = db.open_full_transfer_stage(
                operation,
                PairingRole::Responder,
                crate::custody::network_now()?,
            )?;
            // Every earlier copy is stale after J3/J6 bookkeeping. Rebase from B's
            // actual current generation, retaining the frozen independently verified source.
            stage.pin_receiver_base(&stage.resume_record()?.base_manifest_hash)?
        };
        let copy = pinned.copy()?;
        let replay = {
            let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
            let now = crate::custody::network_now()?;
            db.open_full_transfer_stage(operation, PairingRole::Responder, now)?
                .into_receiver_replay_work(copy, now)?
        };
        let copy = replay.replay()?;
        let preparation = {
            let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
            let now = crate::custody::network_now()?;
            let stage = db.open_full_transfer_stage(operation, PairingRole::Responder, now)?;
            FullGenerationPreparation::pin(
                &Installation { root: &self.root, db, vault: self.vault.as_ref(), now },
                &stage,
                copy,
                install.clone(),
                &authority,
            )?
        };
        let prepared = preparation.prepare()?;
        let committed = {
            let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
            let now = crate::custody::network_now()?;
            let stage = db.open_full_transfer_stage(operation, PairingRole::Responder, now)?;
            prepared.select(
                &Installation { root: &self.root, db, vault: self.vault.as_ref(), now },
                &stage,
                &authority,
            )?
        };
        let selected = committed.open_selected()?;
        committed.finish(
            &Installation {
                root: &self.root,
                db: &selected,
                vault: self.vault.as_ref(),
                now: crate::custody::network_now()?,
            },
            &authority,
        )?;
        *self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))? = Some(selected);
        Ok(authority)
    }
}
