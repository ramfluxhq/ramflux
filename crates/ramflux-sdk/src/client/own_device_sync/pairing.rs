// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment history over the generation-1 own-device history path. The job is finished when the
//! gateway has durably accepted every history page for the target's inbox (the transfer row is
//! done); an explicit target acknowledgement is a post-Demo-B design follow-up.
use crate::{GatewaySessionAccess, RamfluxClient, SdkError};
use ramflux_storage::PairingOwnSyncJob;
/// Whether the durable history transfer for an enrolled device has finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairingHistoryProgress {
    /// Pages remain; the transfer is durable and resumes after a restart.
    Pending,
    /// The gateway durably accepted every page for the target.
    Complete,
}
impl RamfluxClient {
    pub(crate) async fn export_pairing_history(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        job: &PairingOwnSyncJob,
    ) -> Result<PairingHistoryProgress, SdkError> {
        let root = &job.source_ref.account_anchor;
        if self.born_v3_account.is_none()
            || self.own_account_anchor()? != *root
            || job.target_ref.account_anchor != *root
            || engine.config().device_id != job.source_ref.device_id
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        self.require_native_publication_settled(root)?;
        // The directory projection omits a sibling that has not published a prekey yet.
        // Absence is not a finished job: the enrollment authority is the admission gate.
        self.reject_projected_history_drift(engine, job, root).await?;
        let now = crate::custody::network_now()?;
        let current = self
            .current_custody_authority(root, now)?
            .ok_or(SdkError::PairingCode("UpdateRequired"))?;
        current.authorize(&job.source_ref, "sync", now)?;
        // The enrollment head is a floor, not a snapshot: later heads (layer renewals, other
        // enrollments) keep the job valid, while both devices must still be authorized above.
        let epoch = current.envelope().body.device_set_epoch;
        if epoch < job.record_epoch
            || (epoch == job.record_epoch
                && ramflux_protocol::custody::object_hash(current.envelope())? != job.record_hash)
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        if !authority_has_device(&current, &job.target_ref) {
            return history_target_wait(&current, &job.target_ref);
        }
        current.authorize(&job.target_ref, "sync", now)?;
        let _ = pool;
        self.queue_pairing_history(root, &job.target_ref.device_id)
    }

    async fn reject_projected_history_drift(
        &self,
        engine: &impl GatewaySessionAccess,
        job: &PairingOwnSyncJob,
        root: &str,
    ) -> Result<(), SdkError> {
        let manifest =
            self.cache_verified_device_manifest(engine.config(), root, "pairing_history").await?;
        let Some(target) =
            manifest.devices.iter().find(|device| device.device_id == job.target_ref.device_id)
        else {
            return Ok(());
        };
        if target.principal_commitment != root || target.device_epoch != job.target_ref.device_epoch
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        Ok(())
    }

    fn queue_pairing_history(
        &mut self,
        root: &str,
        device_id: &str,
    ) -> Result<PairingHistoryProgress, SdkError> {
        let target = self.device_identity_for_root(root, device_id)?;
        match self.generated_history_transfer_done(&target)? {
            Some(true) => Ok(PairingHistoryProgress::Complete),
            Some(false) => Ok(PairingHistoryProgress::Pending),
            None => match self.stage_generated_history_transfer(&target) {
                Ok(_) => Ok(PairingHistoryProgress::Pending),
                // The sibling is not sync-admitted or its prekey is not published yet.
                Err(SdkError::GeneratedRefused { .. } | SdkError::InboundPending(_)) => {
                    Ok(PairingHistoryProgress::Pending)
                }
                Err(error) => Err(error),
            },
        }
    }
}

fn authority_has_device(
    current: &ramflux_crypto::custody::VerifiedRecord,
    target: &ramflux_protocol::custody::DeviceRef,
) -> bool {
    current.envelope().body.devices.iter().any(|device| {
        device.device_id == target.device_id && device.device_epoch == target.device_epoch
    })
}

fn history_target_wait(
    current: &ramflux_crypto::custody::VerifiedRecord,
    target: &ramflux_protocol::custody::DeviceRef,
) -> Result<PairingHistoryProgress, SdkError> {
    let same_device =
        current.envelope().body.devices.iter().any(|device| device.device_id == target.device_id);
    if same_device {
        Err(SdkError::PairingCode("HeadChanged"))
    } else {
        Ok(PairingHistoryProgress::Pending)
    }
}
