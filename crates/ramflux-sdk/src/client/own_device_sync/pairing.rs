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
        let target = self
            .assert_manifest_active_device_cached(
                engine.config(),
                root,
                &job.target_ref.device_id,
                "pairing_history",
            )
            .await?;
        let now = crate::custody::network_now()?;
        let current = self
            .current_custody_authority(root, now)?
            .ok_or(SdkError::PairingCode("UpdateRequired"))?;
        current.authorize(&job.source_ref, "sync", now)?;
        current.authorize(&job.target_ref, "sync", now)?;
        // The enrollment head is a floor, not a snapshot: later heads (layer renewals, other
        // enrollments) keep the job valid, while both devices must still be authorized above.
        let epoch = current.envelope().body.device_set_epoch;
        if epoch < job.record_epoch
            || (epoch == job.record_epoch
                && ramflux_protocol::custody::object_hash(current.envelope())? != job.record_hash)
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        if target.principal_commitment != *root
            || target.device_epoch != job.target_ref.device_epoch
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let _ = pool;
        let target = self.device_identity_for_root(root, &job.target_ref.device_id)?;
        match self.generated_history_transfer_done(&target)? {
            Some(true) => Ok(PairingHistoryProgress::Complete),
            Some(false) => Ok(PairingHistoryProgress::Pending),
            None => {
                self.stage_generated_history_transfer(&target)?;
                Ok(PairingHistoryProgress::Pending)
            }
        }
    }
}
