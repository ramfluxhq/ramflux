// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cold installed status is backed by G3 owners; it creates no epoch or approval.
use super::{PairingActor, PairingWire, SdkError, install_recovery::RecoveredInstallation};
use crate::custody::pairing::{full_generation, install_store};
use ramflux_protocol::custody::pairing::{
    full_transfer::{FullError, U64},
    local_dto::{FullStatus, FullStatusStage, FullTailStatus, LocalResult, StatusRequest},
};
mod local;
impl PairingActor {
    pub(super) async fn restore_installed_status(
        &mut self,
        request: &StatusRequest,
    ) -> Result<Option<LocalResult>, SdkError> {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let local = participant.clone();
        let owned = request.clone();
        let snapshot =
            self.installation_loan(move |db| local::snapshot(&local, &owned, db)).await?;
        let Some((install, unlock, has_head)) = snapshot else { return Ok(None) };
        let cleanup = has_head.then(|| (participant.clone(), install.clone()));
        let local = participant;
        let anchor = install.account_anchor.clone();
        let current = self
            .full_runtime
            .clone()
            .run_blocking(move || {
                unlock.require_unlocked()?;
                let current = local.full_native_head(&anchor)?;
                unlock.require_unlocked()?;
                Ok(current)
            })
            .await?;
        let owned = request.clone();
        let (scope, result) = self
            .installation_loan(move |db| {
                let now = crate::custody::network_now()?;
                // The ordinary tail reader intentionally refuses a retained install Head.
                // Finish only the locally agreed G3 cleanup after our fresh native read,
                // then use that unchanged strict reader; this restores no data epoch.
                if let Some((owner, installed)) = cleanup {
                    local::finish_interrupted_cleanup(&owner, &installed, db)?;
                }
                let scope = db.full_installed_recipient_tail_scope(
                    &owned.operation_id,
                    owned.generation,
                    now,
                )?;
                db.observe_full_installed_tail_native_head(
                    &owned.operation_id,
                    owned.generation,
                    &current,
                    now,
                )?;
                let result = if scope.merged || scope.abandoned {
                    None
                } else {
                    installed_authority_result(&scope.grant, &current, now, scope.lease_expires_at)
                };
                Ok((scope, result))
            })
            .await?;
        // These are public progress totals only. Neither the historic installed marker
        // nor a live relay lease reconstructs a data session or confirms a candidate.
        let tail_status = tail_disposition(&scope);
        let status = installed_progress(
            request,
            scope.lease_expires_at,
            scope.bytes_total,
            scope.cut,
            result,
            tail_status,
        );
        status.validate().map_err(|error| super::wire(&error))?;
        self.recovered_installation = Some(RecoveredInstallation { install, status });
        self.recovered_installation
            .as_ref()
            .ok_or(SdkError::PairingCode("WrongContext"))?
            .result(request)
            .map(Some)
    }
}

pub(super) fn installed_progress(
    request: &StatusRequest,
    expires: u64,
    total: u64,
    cut: u64,
    result: Option<FullError>,
    tail_status: FullTailStatus,
) -> FullStatus {
    FullStatus {
        attachment_absent: U64(0),
        bytes_durable: U64(total),
        bytes_total: U64(total),
        cut: U64(cut),
        generation: request.generation,
        lease_expires_at: expires,
        operation_id: request.operation_id.clone(),
        result,
        role: "responder".into(),
        stage: FullStatusStage::Installed,
        tail_status,
    }
}

pub(super) fn installed_authority_result(
    grant: &ramflux_protocol::custody::pairing::full_transfer::lease::DataGrant,
    current: &ramflux_crypto::custody::VerifiedRecord,
    now: u64,
    expires: u64,
) -> Option<FullError> {
    match ramflux_crypto::custody::pairing::verify_full_tail_authority(grant, current, now) {
        Ok(()) => (now >= expires).then_some(FullError::LeaseExpired),
        Err(ramflux_crypto::CryptoError::Pairing("LeaseExpired")) => Some(FullError::LeaseExpired),
        Err(_) => Some(FullError::HeadChanged),
    }
}

pub(super) fn tail_disposition(scope: &ramflux_storage::FullInstalledTailScope) -> FullTailStatus {
    if scope.abandoned {
        FullTailStatus::Abandoned
    } else if scope.merged {
        FullTailStatus::Merged
    } else {
        FullTailStatus::Pending
    }
}
