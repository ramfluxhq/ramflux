// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing B retains its ordinary writer through copy/G1, then hands back only completed G3.
use super::{PairingActor, SdkError};
use crate::custody::pairing::{
    Installation, full_generation::owner::FullGenerationPreparation, install_store::Install,
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::CustodyAuthority;

impl PairingActor {
    pub(super) async fn install_linked_full_generation(
        &self,
        install: Install,
    ) -> Result<CustodyAuthority, SdkError> {
        if install.recipient_mode != "existing" || install.account_id != self.identity.account_id {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let writer = self.local_writer.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let local = participant.clone();
        let operation = install.operation_id.clone();
        let query = writer
            .request(move |db| local.full_recipient_publication_query_with_db(db, &operation))
            .await?;
        let observation = self.full_runtime.clone().run_blocking(move || query.observe()).await?;
        let authority = observation.authority().clone();
        let operation = install.operation_id.clone();
        let pinned = writer
            .request(move |db| {
                observation.acknowledge(db)?;
                let stage = db.open_full_transfer_stage(
                    &operation,
                    PairingRole::Responder,
                    crate::custody::network_now()?,
                )?;
                Ok(stage.pin_receiver_base(&stage.resume_record()?.base_manifest_hash)?)
            })
            .await?;
        let copy = self.full_runtime.clone().run_blocking(move || Ok(pinned.copy()?)).await?;
        let operation = install.operation_id.clone();
        let replay = writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                let stage = db.open_full_transfer_stage(&operation, PairingRole::Responder, now)?;
                Ok(stage.into_receiver_replay_work(copy, now)?)
            })
            .await?;
        let copy = self.full_runtime.clone().run_blocking(move || Ok(replay.replay()?)).await?;
        let local = participant.clone();
        let native = authority.clone();
        let preparation = writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                let stage = db.open_full_transfer_stage(
                    &install.operation_id,
                    PairingRole::Responder,
                    now,
                )?;
                FullGenerationPreparation::pin(
                    &Installation { root: &local.root, db, vault: local.vault.as_ref(), now },
                    &stage,
                    copy,
                    install,
                    &native,
                )
            })
            .await?;
        let prepared =
            self.full_runtime.clone().run_blocking(move || preparation.prepare()).await?;
        let committed =
            writer.select_full_generation(participant.clone(), prepared, authority.clone()).await?;
        let native = authority.clone();
        self.full_runtime
            .clone()
            .run_blocking(move || {
                let selected = committed.open_selected()?;
                committed.finish(
                    &Installation {
                        root: &participant.root,
                        db: &selected,
                        vault: participant.vault.as_ref(),
                        now: crate::custody::network_now()?,
                    },
                    &native,
                )?;
                let mut slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
                if slot.is_some() {
                    return Err(SdkError::PairingCode("WrongContext"));
                }
                *slot = Some(selected);
                Ok(())
            })
            .await?;
        Ok(authority)
    }
}

impl PairingActor {
    /// Return an existing B's exact completed generation to its original frontend owner.
    /// The original password/vault provider and device branch remain frontend-owned.
    /// # Errors
    /// Refuses foreign/replaced frontends, incomplete G3, wrong local keys or cancellation.
    pub(crate) fn service_linked_installation(
        &mut self,
        client: &mut crate::RamfluxClient,
        service: &mut crate::custody::pairing::PairingLocalWriterService,
    ) -> Result<bool, SdkError> {
        let installed = self.ceremony.as_ref().is_some_and(|ceremony| {
            ceremony.role == PairingRole::Responder
                && ceremony.full.as_ref().is_some_and(|full| {
                    full.common.recipient_mode == "existing"
                        && full.publication.destination_installed()
                })
        });
        if !installed {
            return Ok(false);
        }
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let mut slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let Some(selected) = slot.as_ref() else {
            return Ok(false);
        };
        self.local_writer
            .as_ref()
            .ok_or(SdkError::PairingCode("WrongContext"))?
            .require_prior_frontend(client, service)?;
        let now = crate::custody::network_now()?;
        let native = crate::custody::load_account(&participant.root, &participant.account_id, now)?;
        let install = crate::custody::pairing::install_store::read_installed(
            &participant.root,
            &participant.account_id,
        )?
        .ok_or(SdkError::PairingCode("PublicationPending"))?;
        let adoption =
            selected.pairing_adoption()?.ok_or(SdkError::PairingCode("PublicationPending"))?;
        crate::custody::pairing::full_generation::require_completed_full_generation(
            &participant.root,
            &native,
            &install,
            &adoption,
        )?;
        let signal = service.work_signal();
        // Bind succeeds against the positively verified selected writer before either
        // frontend field changes. There is no second opener or copied data key.
        let prior_port = self.local_writer.take();
        let replacement = match self.bind_selected_writer(selected, signal) {
            Ok(replacement) => replacement,
            Err(error) => {
                self.local_writer = prior_port;
                return Err(error);
            }
        };
        client.born_v3_account = Some(Box::new(native));
        client.active_account_db = slot.take();
        *client.native_head_freshness.get_mut() = Default::default();
        *client.profile_read_cache.get_mut() = None;
        *service = replacement;
        Ok(true)
    }
}
