// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Best-effort plain-copy admission, local membership and confirmation-gated release.
use crate::prelude::*;
use serde_json::json;
impl RamfluxClient {
    pub(crate) fn local_own_copy_manifest(
        &self,
    ) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
        let local = self.owned_device_identity()?;
        let manifest = self
            .account_db()?
            .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                "identity/manifest-root/{}",
                local.root_commitment()
            ))?
            .ok_or_else(|| {
                SdkError::InboundPending("own-device local manifest unavailable".into())
            })?;
        super::identity_authority::verify_manifest(&manifest, local.root_commitment())?;
        if manifest.signed_device_set != self.observed_device_set(local.root_commitment())? {
            return Err(SdkError::InboundPending("own-device local manifest needs refresh".into()));
        }
        Ok(manifest)
    }
    pub(super) async fn refreshed_own_copy_manifest(
        &self,
        gateway: &GatewaySessionConfig,
    ) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
        if let Ok(manifest) = self.local_own_copy_manifest() {
            return Ok(manifest);
        }
        let local = self.owned_device_identity()?;
        let epoch =
            self.observed_device_set(local.root_commitment())?.map(|set| set.device_set_epoch);
        let db = self.account_db()?;
        let now = now_unix_timestamp();
        let old = db.load_actor_state::<serde_json::Value>("own-device/manifest-refresh")?;
        if old.as_ref().is_some_and(|row| {
            row["epoch"] == json!(epoch) && row["next_at"].as_i64().is_some_and(|at| at > now)
        }) {
            return Err(SdkError::InboundPending("own-device manifest refresh backed off".into()));
        }
        db.persist_actor_state(
            "own-device/manifest-refresh",
            &json!({"epoch":epoch,"next_at":now.saturating_add(60)}),
        )?;
        self.cache_verified_device_manifest(
            gateway,
            local.root_commitment(),
            "own_sent_device_set_change",
        )
        .await?;
        self.local_own_copy_manifest()
    }
    pub(super) fn own_sent_has_siblings(&self) -> Result<bool, SdkError> {
        let local = self.owned_device_identity()?;
        let set = self
            .observed_device_set(local.root_commitment())?
            .ok_or_else(|| SdkError::InboundPending("own-device signed set unavailable".into()))?;
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), &set)?;
        Ok(set.devices.iter().any(|d| {
            d.status == ramflux_protocol::DeviceSetStatus::Active
                && d.device_id != local.device_id()
        }))
    }
    pub(crate) fn queue_own_sent_copy(
        &self,
        message: &str,
        stage: impl FnOnce() -> Result<String, SdkError>,
    ) -> Option<String> {
        let result = (|| {
            if !self.own_sent_has_siblings()? {
                return Ok(None);
            }
            self.account_db()?.write_transaction(|| stage().map(Some))
        })();
        match result {
            Ok(ticket) => ticket,
            Err(error) => {
                self.own_sent_copy_failure(message, &error);
                None
            }
        }
    }
    fn own_sent_copy_failure(&self, message: &str, error: &SdkError) {
        tracing::warn!(%error,"sent message own-device copy failed");
        let record = (|| -> Result<(), SdkError> {
            let db = self.account_db()?;
            db.write_transaction(|| {
                let count = db
                    .load_actor_state::<u64>("own-device/sent-failures")?
                    .unwrap_or(0)
                    .saturating_add(1);
                db.persist_actor_state("own-device/sent-failures", &count)?;
                let mut row = db.client_record("message", message)?.unwrap_or_else(|| json!({}));
                row["own_device_copy_state"] = json!("failed");
                db.persist_client_record("message", message, &row)?;
                Ok(())
            })
        })();
        if let Err(error) = record {
            tracing::warn!(%error,"own-device failure bookkeeping unavailable");
        }
    }
    pub(crate) fn finish_own_sent_copy(
        &self,
        message: &str,
        ticket: Option<&str>,
        confirmed: bool,
    ) {
        if let Some(ticket) = ticket
            && let Err(error) = crate::bus::own_device_copy::finish_held(self, ticket, confirmed)
        {
            self.own_sent_copy_failure(message, &error);
        }
    }
    pub(crate) fn queue_own_sent_dm(
        &self,
        message: &GatewayDirectMessage,
        content: &[u8],
    ) -> Option<String> {
        self.queue_own_sent_copy(&message.message_id, || {
            let peer = self.own_sent_peer(message)?;
            let recipients = self.own_original_recipient(message)?;
            self.stage_own_sent_message(super::own_sent_message::OwnSentInput {
                envelope: &message.envelope_id,
                conversation: &message.conversation_id,
                message: &message.message_id,
                sender: &message.sender_id,
                original_recipients: &recipients,
                group: None,
                peer: Some(&peer),
                body: content,
                ciphertext: &message.encrypted_body,
                at: message.created_at,
            })?;
            Ok(message.envelope_id.clone())
        })
    }
}
