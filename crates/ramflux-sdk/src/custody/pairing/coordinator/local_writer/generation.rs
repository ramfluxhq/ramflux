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
        self.request_with(false, move |reply| {
            Box::new(Work {
                action: move |db: &ramflux_storage::AccountDb| {
                    let now = crate::custody::network_now()?;
                    let operation = prepared.install().operation_id.clone();
                    let stage =
                        db.open_full_transfer_stage(&operation, PairingRole::Responder, now)?;
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
