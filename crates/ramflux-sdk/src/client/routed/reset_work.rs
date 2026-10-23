// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable reset retry and encrypted acknowledgement, independent of inbox retry retention.
use super::session::pair_key;
use super::{
    GatewayDirectMessage, GatewaySessionEngine, Kind, Opened, RamfluxClient, Route, SdkError,
};
#[derive(serde::Serialize, serde::Deserialize)]
struct ResetWork {
    local: String,
    remote: String,
    attempts: u32,
    next_at: i64,
}
fn work_key(local: &str, remote: &str) -> Result<String, SdkError> {
    Ok(format!("dm-pair/reset-work/{}", pair_key(local, remote)?))
}
impl RamfluxClient {
    pub(super) fn begin_pair_recovery(
        &self,
        local: &str,
        remote: &str,
        at: i64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let key = work_key(local, remote)?;
        let existing = db.load_actor_state::<ResetWork>(&key)?;
        if existing.as_ref().is_some_and(|work| at < work.next_at) {
            return Ok(false);
        }
        db.write_transaction(|| -> Result<(), SdkError> {
            // A passive peer may miss every retry. Start another bootstrap before our own
            // unacknowledged send counter exceeds its receive skip window.
            let replace = existing.is_none()
                || self.active_pair(local, remote)?.is_some_and(|(state, _)| {
                    state.send_counter > u64::try_from(state.max_skip).unwrap_or(u64::MAX)
                });
            if replace {
                if let Some((session, _)) = self.active_pair(local, remote)? {
                    self.archive_pair(local, remote, &session.session_id)?;
                }
                db.remove_actor_state(&pair_key(local, remote)?)?;
            }
            let attempts = existing.as_ref().map_or(1, |work| work.attempts.saturating_add(1));
            let delay = 60_i64.saturating_mul(1_i64 << attempts.saturating_sub(1).min(3)).min(300);
            db.persist_actor_state(
                &key,
                &ResetWork {
                    local: local.to_owned(),
                    remote: remote.to_owned(),
                    attempts,
                    next_at: at.saturating_add(delay),
                },
            )?;
            let pair = pair_key(local, remote)?;
            db.persist_actor_state(&format!("{pair}/reset-pending"), &true)?;
            db.persist_actor_state(&format!("{pair}/reset-at"), &at)?;
            db.append_journal(
                &format!("pair-reset-attempt:{key}:{at}"),
                "session.reset",
                &serde_json::json!({
                    "device_id": remote,
                    "reason": "receive_state_unrecoverable",
                    "attempt": attempts,
                }),
                at,
                None,
            )?;
            Ok(())
        })?;
        self.finish_pair_retirement()?;
        Ok(true)
    }
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
        for item in
            work.into_iter().filter(|work| work.local == local && work.next_at <= at).take(1)
        {
            if self.account_db()?.client_record("device", &item.remote)?.is_none() {
                self.account_db()?.remove_actor_state(&work_key(&item.local, &item.remote)?)?;
                self.account_db()?.remove_actor_state(&format!(
                    "{}/reset-pending",
                    pair_key(&item.local, &item.remote)?
                ))?;
                continue;
            }
            if self.begin_pair_recovery(&item.local, &item.remote, at)?
                && let Err(error) = self.send_pair_reset(engine, &item.remote).await
            {
                tracing::debug!(%error,"device pair reset remains pending");
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
