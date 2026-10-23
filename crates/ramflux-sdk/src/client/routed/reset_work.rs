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
        remote: &str,
    ) -> Result<(), SdkError> {
        self.send_pair_control(engine, remote, "pair.session.reset.v1").await
    }
    fn pair_delivery_id(&self, remote: &str) -> Result<String, SdkError> {
        let record = self.trusted_device(remote)?;
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
                .find(|device| device["device_id"] == remote || device["id"] == remote)
                .and_then(|device| device.get("target_delivery_id"))
                .and_then(serde_json::Value::as_str)
        {
            return Ok(target.to_owned());
        }
        Ok(remote.to_owned())
    }
    async fn send_pair_control(
        &self,
        engine: &mut GatewaySessionEngine,
        remote: &str,
        kind: &str,
    ) -> Result<(), SdkError> {
        let id = format!(
            "pair-control-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        );
        let target_delivery_id = self.pair_delivery_id(remote)?;
        let mut message = GatewayDirectMessage {
            conversation_id: id.clone(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: engine.config.principal_id.clone(),
            recipient_device_id: Some(remote.to_owned()),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: super::now_unix_timestamp(),
            ttl: 300,
        };
        let sealed = self
            .seal_routed_as(
                engine,
                &message,
                &serde_json::to_vec(&serde_json::json!({"type":kind}))?,
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
    pub(crate) async fn retry_pair_resets(
        &self,
        engine: &mut GatewaySessionEngine,
        at: i64,
    ) -> Result<(), SdkError> {
        let work = self.account_db()?.list_actor_states::<ResetWork>("dm-pair/reset-work/")?;
        let local = engine.config.device_id.clone();
        let mut attempted = false;
        for item in work.into_iter().filter(|work| work.local == local) {
            if !self.pair_recovery_allowed(&item.local, &item.remote)? {
                self.remove_device_pair(&item.remote, "retry_relationship_ended")?;
                continue;
            }
            let first = self.reset_first_at(&item)?;
            if at >= first.saturating_add(MAX_RESET_LIFETIME) {
                self.mark_pair_manual(&item.local, &item.remote, at)?;
                continue;
            }
            if !attempted && item.next_at <= at {
                attempted = true;
                if self.begin_pair_recovery(&item.local, &item.remote, at)?
                    && let Err(error) = self.send_pair_reset(engine, &item.remote).await
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
            && let Err(error) = self
                .send_pair_control(engine, &opened.remote_device, "pair.session.reset.ack.v1")
                .await
        {
            tracing::debug!(%error,"encrypted reset acknowledgement will be retried on the next request");
        }
    }
}
