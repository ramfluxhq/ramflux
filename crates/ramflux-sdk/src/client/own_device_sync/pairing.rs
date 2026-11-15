// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment history authority checks; the generation-1 history carrier is P13 work.
use crate::{GatewaySessionAccess, RamfluxClient, SdkError};
use ramflux_storage::PairingOwnSyncJob;
impl RamfluxClient {
    pub(crate) async fn export_pairing_history(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        job: &PairingOwnSyncJob,
    ) -> Result<(), SdkError> {
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
        if ramflux_protocol::custody::object_hash(current.envelope())? != job.record_hash {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        if target.principal_commitment != *root
            || target.device_epoch != job.target_ref.device_epoch
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        // P13 TODO (MU-ACTIVATION-01): the generation-1 carrier for enrollment history is not
        // built yet. The retired own-device-sync exporter is intentionally not restored, so the
        // job stays unfinished (it completes only on target acknowledgement) and is retried.
        let _ = (pool, target.target_delivery_id);
        Err(SdkError::PairingCode("TodoP13HistoryCarrier"))
    }
}
