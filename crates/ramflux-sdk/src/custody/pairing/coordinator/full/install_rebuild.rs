// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Published but unselected crash recovery rebuilds G1 from the actual current B generation.
use super::{PairingActor, SdkError};
use crate::custody::pairing::{
    FullRecipientNativeObservation, Installation,
    full_generation::owner::FullGenerationPreparation, install_store::Install,
};
use ramflux_protocol::custody::CustodyAuthority;

impl PairingActor {
    pub(super) async fn rebuild_unselected_install(
        &self,
        install: Install,
        observation: FullRecipientNativeObservation,
    ) -> Result<(Install, CustodyAuthority, u64), SdkError> {
        let authority = observation.authority().clone();
        let native = authority.clone();
        let operation = install.operation_id.clone();
        let (cancel, expires) = self
            .installation_loan(move |db| {
                observation.acknowledge(db)?;
                let now = crate::custody::network_now()?;
                let verified = ramflux_crypto::custody::verify_publication(&native, now)?;
                let stage = db.open_full_recipient_install_stage(&operation, &verified, now)?;
                Ok((stage.io_cancel_handle(), stage.reference().lease_expires_at.0))
            })
            .await?;
        self.full_runtime.register_stage(cancel.clone())?;
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let root = participant.root.clone();
        let install = self.full_runtime.clone().run_blocking(move || {
            crate::bus::backup_jobs::full_generation::FullGenerationDirectory::discard_crashed_unselected(&root, &install)
        }).await?;
        let copy = self.replay_installation_base(&install, &authority, cancel.clone()).await?;
        let local = participant.clone();
        let native = authority;
        let bound_cancel = cancel.clone();
        let preparation = self
            .installation_loan(move |db| {
                let now = crate::custody::network_now()?;
                let verified = ramflux_crypto::custody::verify_publication(&native, now)?;
                let mut stage =
                    db.open_full_recipient_install_stage(&install.operation_id, &verified, now)?;
                stage.bind_local_io_cancellation(&bound_cancel)?;
                FullGenerationPreparation::pin_reconciliation(
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
        let install = prepared.install().clone();
        let (committed, authority) =
            Box::pin(self.select_rebuilt_install(prepared, cancel)).await?;
        self.finish_linked_generation(committed, authority.clone()).await?;
        Ok((install, authority, expires))
    }
    async fn select_rebuilt_install(
        &self,
        prepared: crate::custody::pairing::full_generation::owner::FullGenerationPrepared,
        cancel: ramflux_storage::FullStageIoCancel,
    ) -> Result<
        (
            crate::custody::pairing::full_generation::owner::FullGenerationCommitted,
            CustodyAuthority,
        ),
        SdkError,
    > {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let install = prepared.install();
        let operation = install.operation_id.clone();
        let local = participant.clone();
        let query = self
            .installation_loan(move |db| {
                local.full_recipient_publication_query_with_db(db, &operation)
            })
            .await?;
        let observation = self.full_runtime.clone().run_blocking(move || query.observe()).await?;
        let authority = observation.authority().clone();
        let committed = if let Some(writer) = &self.local_writer {
            writer.select_reconciled_full_generation(participant, prepared, observation).await?
        } else {
            self.installation_loan(move |db| {
                observation.acknowledge(db)?;
                let now = crate::custody::network_now()?;
                let native = observation.authority();
                let verified = ramflux_crypto::custody::verify_publication(native, now)?;
                let mut stage = db.open_full_recipient_install_stage(
                    &prepared.install().operation_id,
                    &verified,
                    now,
                )?;
                stage.bind_local_io_cancellation(&cancel)?;
                prepared.select_reconciliation(
                    &Installation {
                        root: &participant.root,
                        db,
                        vault: participant.vault.as_ref(),
                        now,
                    },
                    &stage,
                    native,
                )
            })
            .await?
        };
        Ok((committed, authority))
    }
    async fn replay_installation_base(
        &self,
        install: &Install,
        authority: &CustodyAuthority,
        cancel: ramflux_storage::FullStageIoCancel,
    ) -> Result<ramflux_storage::FullReceiverBaseCopy, SdkError> {
        let operation = install.operation_id.clone();
        let native = authority.clone();
        let bound_cancel = cancel.clone();
        let pinned = self
            .installation_loan(move |db| {
                let now = crate::custody::network_now()?;
                let verified = ramflux_crypto::custody::verify_publication(&native, now)?;
                let mut stage = db.open_full_recipient_install_stage(&operation, &verified, now)?;
                stage.bind_local_io_cancellation(&bound_cancel)?;
                Ok(stage.pin_receiver_base()?)
            })
            .await?;
        let copy = self.full_runtime.clone().run_blocking(move || Ok(pinned.copy()?)).await?;
        let operation = install.operation_id.clone();
        let native = authority.clone();
        let replay = self
            .installation_loan(move |db| {
                let now = crate::custody::network_now()?;
                let verified = ramflux_crypto::custody::verify_publication(&native, now)?;
                let mut stage = db.open_full_recipient_install_stage(&operation, &verified, now)?;
                stage.bind_local_io_cancellation(&cancel)?;
                Ok(stage.into_receiver_replay_work(copy)?)
            })
            .await?;
        self.full_runtime.clone().run_blocking(move || Ok(replay.replay()?)).await
    }
}
