// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable reset retry and encrypted acknowledgement, independent of inbox retry retention.
use super::reset_policy::{MAX_RESET_LIFETIME, ResetWork};
use super::{
    GatewayDirectMessage, GatewaySessionEngine, Kind, Opened, RamfluxClient, Route, SdkError,
};
impl RamfluxClient {
    pub(super) async fn send_pair_reset(
        &self,
        engine: &mut GatewaySessionEngine,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        self.send_pair_control(engine, remote, "pair.session.reset.v1").await
    }
    fn pair_delivery_id(
        &self,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<String, SdkError> {
        let record = self.trusted_device(remote.storage_key())?;
        if let Some(target) = record.get("target_delivery_id").and_then(serde_json::Value::as_str) {
            return Ok(target.to_owned());
        }
        // Older verified manifests cached delivery aliases only in the identity directory.
        if let Some(principal) = record.get("principal_id").and_then(serde_json::Value::as_str)
            && let Some(identity) = self.account_db()?.client_record("identity", principal)?
            && let Some(target) = identity
                .get("devices")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .find(|device| {
                    device["device_id"] == remote.device_id() || device["id"] == remote.device_id()
                })
                .and_then(|device| device.get("target_delivery_id"))
                .and_then(serde_json::Value::as_str)
        {
            return Ok(target.to_owned());
        }
        Ok(remote.device_id().to_owned())
    }
    async fn send_pair_control(
        &self,
        engine: &mut GatewaySessionEngine,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        kind: &str,
    ) -> Result<(), SdkError> {
        let id = format!(
            "pair-control-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        );
        let root = remote.root_commitment().to_owned();
        let wire_remote = remote.device_id().to_owned();
        let target_delivery_id = self.pair_delivery_id(remote)?;
        let mut message = GatewayDirectMessage {
            conversation_id: id.clone(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: engine.config.principal_id.clone(),
            recipient_device_id: Some(wire_remote),
            recipient_principal_commitment: Some(root),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: super::now_unix_timestamp(),
            ttl: 300,
        };
        let sealed = self
            .seal_routed_as(
                engine,
                &message,
                &serde_json::to_vec(&serde_json::json!({"type":kind,"rejected_bootstrap_floor":if kind=="pair.session.reset.v1"{self.bootstrap_high_water(&self.local_device_identity(&engine.config.device_id)?,remote)?}else{0}}))?,
                Route::control(),
            )
            .await?;
        if kind == "pair.session.reset.v1" {
            self.account_db()?.persist_actor_state(
                &format!("dm-pair/reset/{}", sealed.ciphertext.session_id),
                &true,
            )?;
        }
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        engine
            .submit_envelope(super::gateway_direct_message_envelope(
                &engine.config,
                &message,
                None,
            )?)
            .await?;
        // Submission is transport acceptance, not peer confirmation. Work remains durable.
        Ok(())
    }
    pub(super) fn legacy_upgrade_reset_work(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<ResetWork>, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<Vec<ResetWork>, SdkError> {
            let mut retained = Vec::new();
            for key in db.actor_state_keys("dm-pair/reset-work/")? {
                let Some(mut item) = db.load_actor_state::<ResetWork>(&key)? else { continue };
                let remote = self.device_identity(&item.remote).ok();
                let bound = remote
                    .as_ref()
                    .map(|remote| Self::reset_work_key(local, remote))
                    .transpose()?;
                if bound.as_deref() == Some(&key)
                    && (item.local == local.storage_key() || item.local == local.device_id())
                {
                    // The existing pair key proves the root context; spelling alone never does.
                    local.storage_key().clone_into(&mut item.local);
                    if let Some(remote) = &remote {
                        remote.storage_key().clone_into(&mut item.remote);
                    }
                    db.persist_actor_state(&key, &item)?;
                    retained.push(item);
                } else if item.local == local.device_id() || item.local == local.storage_key() {
                    db.persist_actor_state(
                        &format!(
                            "legacy/reset-work/{}",
                            ramflux_protocol::encode_base64url(key.as_bytes())
                        ),
                        &item,
                    )?;
                    db.remove_actor_state(&key)?;
                }
            }
            Ok(retained)
        })
    }

    pub(crate) async fn retry_pair_resets(
        &self,
        engine: &mut GatewaySessionEngine,
        at: i64,
    ) -> Result<(), SdkError> {
        let local = self.local_device_identity(&engine.config.device_id)?;
        let work = self.legacy_upgrade_reset_work(&local)?;
        let mut attempted = false;
        for mut item in work.into_iter().filter(|work| work.local == local.storage_key()) {
            let remote = self.device_identity(&item.remote)?;
            if !self.pair_recovery_allowed(&local, &remote)? {
                self.remove_device_pair(&remote, "retry_relationship_ended")?;
                continue;
            }
            let first = self.normalize_reset_work(&mut item)?;
            if at >= first.saturating_add(MAX_RESET_LIFETIME) {
                self.mark_pair_manual(&local, &remote, at)?;
                continue;
            }
            if !attempted && item.next_at <= at {
                attempted = true;
                if self.begin_pair_recovery(&local, &remote, at)?
                    && let Err(error) = self.send_pair_reset(engine, &remote).await
                {
                    tracing::debug!(%error,"device pair reset remains pending");
                }
            }
        }
        Ok(())
    }
    pub(super) async fn reply_pair_reset(
        &self,
        engine: &mut GatewaySessionEngine,
        opened: &Opened,
        body: &[u8],
    ) {
        if opened.routing.kind == Kind::Control
            && serde_json::from_slice::<serde_json::Value>(body)
                .is_ok_and(|value| value["type"] == "pair.session.reset.v1")
            && self
                .pair_recovery_allowed(&opened.local_device, &opened.remote_device)
                .is_ok_and(|allowed| allowed)
            && let Err(error) = self
                .send_pair_control(engine, &opened.remote_device, "pair.session.reset.ack.v1")
                .await
        {
            tracing::debug!(%error,"encrypted reset acknowledgement will be retried on the next request");
        }
    }
}
