// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact G2 selection is the sole request allowed to retire its original writer.
use super::{LocalWriterPort, Work};
use crate::{
    SdkError,
    custody::pairing::{
        Installation, LocalPairingParticipant,
        full_generation::owner::{FullGenerationCommitted, FullGenerationPrepared},
    },
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::CustodyAuthority;
use std::sync::Arc;

impl LocalWriterPort {
    pub(in crate::custody::pairing::coordinator) async fn select_full_generation(
        &self,
        participant: Arc<LocalPairingParticipant>,
        prepared: FullGenerationPrepared,
        authority: CustodyAuthority,
    ) -> Result<FullGenerationCommitted, SdkError> {
        self.require_participant(&participant)?;
        let cancellation = self.scope.runtime.stage_owner()?;
        #[cfg(test)]
        let scope = self.scope.clone();
        self.request_with(false, move |reply| {
            Box::new(Work {
                action: move |db: &ramflux_storage::AccountDb| {
                    #[cfg(test)]
                    if let Ok(remaining) = scope.install_races.try_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |value| value.checked_sub(1),
                    ) {
                        db.seed_full_transfer_object_veto_for_test(
                            &format!("install-race-{remaining}"),
                            "install-race-manifest",
                            10 + u64::from(remaining),
                        )?;
                    }
                    let now = crate::custody::network_now()?;
                    let operation = prepared.install().operation_id.clone();
                    let mut stage =
                        db.open_full_transfer_stage(&operation, PairingRole::Responder, now)?;
                    stage.bind_local_io_cancellation(&cancellation)?;
                    prepared.select(
                        &Installation {
                            root: &participant.root,
                            db,
                            vault: participant.vault.as_ref(),
                            now,
                        },
                        &stage,
                        &authority,
                    )
                },
                reply,
            })
        })
        .await
    }
    pub(in crate::custody::pairing::coordinator) async fn select_reconciled_full_generation(
        &self,
        participant: Arc<LocalPairingParticipant>,
        prepared: FullGenerationPrepared,
        observation: crate::custody::pairing::FullRecipientNativeObservation,
    ) -> Result<FullGenerationCommitted, SdkError> {
        self.require_participant(&participant)?;
        let cancellation = self.scope.runtime.stage_owner()?;
        self.request_with(false, move |reply| {
            Box::new(Work {
                action: move |db: &ramflux_storage::AccountDb| {
                    observation.acknowledge(db)?;
                    let now = crate::custody::network_now()?;
                    let authority = observation.authority();
                    let verified = ramflux_crypto::custody::verify_publication(authority, now)?;
                    let mut stage = db.open_full_recipient_install_stage(
                        &prepared.install().operation_id,
                        &verified,
                        now,
                    )?;
                    stage.bind_local_io_cancellation(&cancellation)?;
                    prepared.select_reconciliation(
                        &Installation {
                            root: &participant.root,
                            db,
                            vault: participant.vault.as_ref(),
                            now,
                        },
                        &stage,
                        authority,
                    )
                },
                reply,
            })
        })
        .await
    }
    pub(in crate::custody::pairing::coordinator) async fn rebase_full_generation(
        &self,
        participant: Arc<LocalPairingParticipant>,
        install: crate::custody::pairing::install_store::Install,
        authority: CustodyAuthority,
    ) -> Result<FullGenerationCommitted, SdkError> {
        self.require_participant(&participant)?;
        let runtime = self.scope.runtime.clone();
        let cancellation = runtime.stage_owner()?;
        self.request_with(false, move |reply| Box::new(Work {
            action: move |db: &ramflux_storage::AccountDb| {
                db.with_full_transfer_install_fence(|| {
                    runtime.require_live()?;
                    let now = crate::custody::network_now()?;
                    let mut stage = db.open_full_transfer_stage(&install.operation_id, PairingRole::Responder, now)?;
                    stage.bind_local_io_cancellation(&cancellation)?;
                    let pinned = stage.pin_receiver_base(&stage.resume_record()?.base_manifest_hash)?;
                    drop(stage);
                    let copy = pinned.copy()?;
                    let mut stage = db.open_full_transfer_stage(&install.operation_id, PairingRole::Responder, now)?;
                    stage.bind_local_io_cancellation(&cancellation)?;
                    let copy = stage.into_receiver_replay_work(copy, now)?.replay()?;
                    let mut stage = db.open_full_transfer_stage(&install.operation_id, PairingRole::Responder, now)?;
                    stage.bind_local_io_cancellation(&cancellation)?;
                    let local = Installation { root: &participant.root, db, vault: participant.vault.as_ref(), now };
                    let preparation = crate::custody::pairing::full_generation::owner::FullGenerationPreparation::pin(&local, &stage, copy, install, &authority)?;
                    let prepared = preparation.prepare()?;
                    runtime.require_live()?;
                    prepared.select(&local, &stage, &authority)
                })
            }, reply,
        })).await
    }
    pub(in crate::custody::pairing::coordinator) fn require_prior_frontend(
        &self,
        client: &crate::RamfluxClient,
        service: &super::PairingLocalWriterService,
    ) -> Result<(), SdkError> {
        self.scope.runtime.require_live()?;
        if !Arc::ptr_eq(&self.scope, &service.scope) {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let db = client.account_db()?;
        if db.local_account_id != self.scope.account
            || std::fs::canonicalize(db.account_index_root())? != self.scope.root
            || std::fs::canonicalize(&db.path)? != self.scope.path
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        Ok(())
    }
}

#[cfg(test)]
impl super::PairingActor {
    pub(crate) fn set_install_races_for_test(&self, count: u8) -> Result<(), SdkError> {
        if count > 3 {
            return Err(SdkError::PairingCode("InvalidInput"));
        }
        self.local_writer
            .as_ref()
            .ok_or(SdkError::PairingCode("WrongContext"))?
            .scope
            .install_races
            .store(count, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}
