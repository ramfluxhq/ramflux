// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment history uses the existing bounded exporter and ordinary encrypted control route.
use crate::{GatewayDirectMessage, GatewaySessionAccess, RamfluxClient, SdkError};
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
        if target.principal_commitment != *root
            || target.device_epoch != job.target_ref.device_epoch
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let options = self
            .relay_transfer_options(None, None, None)?
            .ok_or(SdkError::PairingCode("UpdateRequired"))?;
        let exported = Box::pin(self.export_own_device_sync(
            engine,
            pool,
            root,
            &job.target_ref.device_id,
            &options.relay_endpoint,
            None,
            64 * 1024,
        ))
        .await?;
        let now = crate::custody::network_now()?;
        let current = self
            .current_custody_authority(root, now)?
            .ok_or(SdkError::PairingCode("UpdateRequired"))?;
        current.authorize(&job.source_ref, "sync", now)?;
        current.authorize(&job.target_ref, "sync", now)?;
        let bytes =
            zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(&exported.envelope)?);
        let identity = crate::new_surface_message_id()?;
        let conversation = ramflux_crypto::blake3_256_base64url(
            "ramflux.pairing.own_history.route.v1",
            &ramflux_protocol::canonical_json_bytes(&(&job.source_ref, &job.target_ref))?,
        );
        let message = GatewayDirectMessage {
            conversation_id: conversation,
            message_id: identity.clone(),
            envelope_id: identity,
            source_principal_id: engine.config().principal_id.clone(),
            sender_id: engine.config().device_id.clone(),
            recipient_device_id: Some(job.target_ref.device_id.clone()),
            recipient_principal_commitment: Some(root.clone()),
            target_delivery_id: target.target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: self.content_ttl()?,
        };
        self.send_plaintext_direct_message_without_franking(
            engine,
            message,
            &bytes,
            crate::client::routed::Route::control(),
        )
        .await?;
        Ok(())
    }
}
