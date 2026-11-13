// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact selected-G2 recovery uses installation-only owners and fresh own-native observations.
use super::{PairingActor, PairingWire, SdkError};
use crate::custody::pairing::{
    Installation, full_generation::owner::FullGenerationCommitted, install_store,
};
use ramflux_protocol::custody::pairing::local_dto::{
    FullStatus, LocalResult, Outcome, StatusRequest,
};

pub(in crate::custody::pairing::coordinator) struct RecoveredInstallation {
    pub(super) install: install_store::Install,
    pub(super) status: FullStatus,
}
impl PairingActor {
    pub(super) fn installation_loan<R: Send + 'static>(
        &self,
        action: impl FnOnce(&ramflux_storage::AccountDb) -> Result<R, SdkError> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<R, SdkError>> + '_ {
        Box::pin(async move {
            if let Some(writer) = &self.local_writer {
                return writer.request(action).await;
            }
            let participant =
                self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
            let runtime = self.full_runtime.clone();
            self.full_runtime
                .clone()
                .run_blocking(move || {
                    let _local = runtime.local_work()?;
                    let slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
                    action(slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?)
                })
                .await
        })
    }
    /// Reconcile an already selected recipient generation without restoring data or human consent.
    /// # Errors
    /// Refuses another operation/generation, missing G2, corrupt bytes, lock or stale own native head.
    pub fn recover_full_installation<'a>(
        &'a mut self,
        request: &'a StatusRequest,
    ) -> impl std::future::Future<Output = Result<Option<LocalResult>, SdkError>> + 'a {
        Box::pin(async move {
            self.require_open()?;
            request.validate().map_err(|error| super::wire(&error))?;
            if self.ceremony.is_some() {
                return Err(SdkError::PairingCode("Busy"));
            }
            if let Some(recovered) = &self.recovered_installation {
                return recovered.result(request).map(Some);
            }
            if let Some(result) = Box::pin(self.restore_installed_status(request)).await? {
                return Ok(Some(result));
            }
            let pending = self.pending_install(request).await?;
            let Some((install, query, selected)) = pending else { return Ok(None) };
            let observation =
                self.full_runtime.clone().run_blocking(move || query.observe()).await?;
            let (install, authority, expires) = if selected {
                let authority = observation.authority().clone();
                let expires =
                    Box::pin(self.recover_selected_install(install.clone(), observation)).await?;
                (install, authority, expires)
            } else {
                Box::pin(self.rebuild_unselected_install(install, observation)).await?
            };
            self.identity.is_primary = true;
            self.identity.local_ref = install.recipient_ref.clone();
            self.identity.base_record_hash =
                ramflux_protocol::custody::object_hash(&authority.publication.record)?;
            self.identity.base_epoch = authority.publication.record.body.device_set_epoch;
            self.identity.master_public_key = Some(
                authority.publication.record.body.master_certificate.body.master_public_key.clone(),
            );
            self.recovered_installation = Some(RecoveredInstallation {
                status: super::installed_status::installed_progress(
                    request, expires, 0, 0, None, false,
                ),
                install,
            });
            self.recovered_installation
                .as_ref()
                .ok_or(SdkError::PairingCode("WrongContext"))?
                .result(request)
                .map(Some)
        })
    }
    async fn recover_selected_install(
        &self,
        install: install_store::Install,
        observation: crate::custody::pairing::FullRecipientNativeObservation,
    ) -> Result<u64, SdkError> {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let native = observation.authority().clone();
        let local = participant.clone();
        let saved = install.clone();
        let (preparation, cancel, expires) = self
            .installation_loan(move |db| {
                observation.acknowledge(db)?;
                let now = crate::custody::network_now()?;
                let verified = ramflux_crypto::custody::verify_publication(&native, now)?;
                let stage =
                    db.open_full_recipient_install_stage(&saved.operation_id, &verified, now)?;
                let preparation = FullGenerationCommitted::pin_recovery(
                    &Installation { root: &local.root, db, vault: local.vault.as_ref(), now },
                    &stage,
                    saved,
                    &native,
                )?;
                Ok((preparation, stage.io_cancel_handle(), stage.reference().lease_expires_at.0))
            })
            .await?;
        self.full_runtime.register_stage(cancel.clone())?;
        let prepared = self.full_runtime.clone().run_blocking(move || preparation.verify()).await?;
        Box::pin(self.finish_recovered_install(install, prepared, cancel)).await?;
        Ok(expires)
    }
    async fn pending_install(
        &self,
        request: &StatusRequest,
    ) -> Result<
        Option<(
            install_store::Install,
            crate::custody::pairing::FullRecipientPublicationQuery,
            bool,
        )>,
        SdkError,
    > {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let local = participant.clone();
        let owned = request.clone();
        let pending = self
            .installation_loan(move |db| {
                let Some(head) = db.pairing_head()? else { return Ok(None) };
                let live = db
                    .pairing_live_rows()?
                    .into_iter()
                    .find(|row| row.operation_id == owned.operation_id)
                    .ok_or(SdkError::PairingCode("NotFound"))?;
                if head.operation_id != owned.operation_id
                    || head.generation != owned.generation
                    || live.generation != owned.generation
                    || live.role != "responder"
                {
                    return Err(SdkError::PairingCode("WrongContext"));
                }
                let install = install_store::read_pending(
                    &local.root,
                    &local.account_id,
                    &owned.operation_id,
                )?
                .ok_or(SdkError::PairingCode("PublicationPending"))?;
                let selected =
                    ramflux_storage::AccountIndex::open(&local.root)?.account(&local.account_id)?;
                let selected = if let Some(full) = &install.full_transfer {
                    if selected.db_relative_path == full.db_relative_path
                        && selected.object_dir_relative_path == full.object_relative_path
                    {
                        true
                    } else if selected.db_relative_path
                        == full.expected_prior_generation.db_relative_path
                        && selected.object_dir_relative_path
                            == full.expected_prior_generation.object_relative_path
                    {
                        false
                    } else {
                        return Err(SdkError::PairingCode("PublicationPending"));
                    }
                } else {
                    false
                };
                let query =
                    local.full_recipient_publication_query_with_db(db, &owned.operation_id)?;
                Ok(Some((install, query, selected)))
            })
            .await?;
        Ok(pending)
    }
    async fn finish_recovered_install(
        &self,
        install: install_store::Install,
        prepared: crate::custody::pairing::full_generation::owner::FullGenerationRecoveryPrepared,
        cancel: ramflux_storage::FullStageIoCancel,
    ) -> Result<ramflux_protocol::custody::CustodyAuthority, SdkError> {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let operation = install.operation_id.clone();
        let local = participant.clone();
        let query = self
            .installation_loan(move |db| {
                local.full_recipient_publication_query_with_db(db, &operation)
            })
            .await?;
        let observation = self.full_runtime.clone().run_blocking(move || query.observe()).await?;
        let local = participant;
        let saved = install.clone();
        self.installation_loan(move |db| {
            observation.acknowledge(db)?;
            let native = observation.authority();
            let now = crate::custody::network_now()?;
            let verified = ramflux_crypto::custody::verify_publication(native, now)?;
            let mut stage =
                db.open_full_recipient_install_stage(&saved.operation_id, &verified, now)?;
            stage.bind_local_io_cancellation(&cancel)?;
            let local = Installation { root: &local.root, db, vault: local.vault.as_ref(), now };
            let committed = prepared.accept(&local, &stage, native)?;
            drop(stage);
            committed.finish(&local, native)?;
            Ok(native.clone())
        })
        .await
    }
}
impl RecoveredInstallation {
    pub(super) fn result(&self, request: &StatusRequest) -> Result<LocalResult, SdkError> {
        if request.operation_id != self.status.operation_id
            || request.generation != self.status.generation
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        self.local_result()
    }
    pub(in crate::custody::pairing::coordinator) fn local_result(
        &self,
    ) -> Result<LocalResult, SdkError> {
        self.status.validate().map_err(|error| super::wire(&error))?;
        Ok(LocalResult {
            schema: "ramflux.pairing.LocalResult.v2".into(),
            version: 2,
            outcome: Outcome::FullStatus { value: Box::new(self.status.clone()) },
        })
    }
}
