// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated fresh-X3DH recovery; a reset never travels outside the encrypted route.
use super::{
    GatewayDirectMessage, GatewayInboxEntry, GatewaySessionEngine, RamfluxClient, Route, SdkError,
    now_unix_timestamp,
};
impl RamfluxClient {
    pub(super) fn finish_pair_retirement(&self) -> Result<(), SdkError> {
        if self.account_db()?.load_actor_state::<bool>("secrets/retired")?.unwrap_or(false) {
            self.account_db()?.checkpoint_retired_secrets()?;
            self.account_db()?.remove_actor_state("secrets/retired")?;
        }
        Ok(())
    }
    pub(super) async fn open_routed_with_recovery(
        &self,
        engine: &mut GatewaySessionEngine,
        entry: &GatewayInboxEntry,
    ) -> Result<super::Opened, SdkError> {
        match self.open_routed(entry, &engine.config.device_id) {
            Ok(opened) => Ok(opened),
            Err(error) => {
                if matches!(
                    error,
                    SdkError::PairRecoveryRequired
                        | SdkError::Crypto(ramflux_crypto::CryptoError::MaxSkipExceeded)
                ) {
                    self.request_pair_recovery(engine, entry).await?;
                }
                Err(error)
            }
        }
    }

    pub(super) fn retire_pair(&self, id: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.persist_actor_state(&format!("dm-pair/retired/{id}"), &true)?;
        db.persist_actor_state("secrets/retired", &true)?;
        for prefix in ["session", "bootstrap"] {
            db.remove_actor_state(&format!("dm-pair/{prefix}/{id}"))?;
        }
        Ok(())
    }
    pub(crate) fn pair_recovery_pending(
        &self,
        local: &str,
        remote: &str,
    ) -> Result<bool, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<bool>(&format!(
                "{}/reset-pending",
                super::session::pair_key(local, remote)?
            ))?
            .unwrap_or(false))
    }
    pub(super) fn begin_pair_recovery(
        &self,
        local: &str,
        remote: &str,
        at: i64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let key = format!("{}/reset-at", super::session::pair_key(local, remote)?);
        if db.load_actor_state::<i64>(&key)?.is_some_and(|last| at.saturating_sub(last) < 60) {
            return Ok(false);
        }
        db.write_transaction(|| -> Result<(), SdkError> {
            if let Some((session, _)) = self.active_pair(local, remote)? {
                self.retire_pair(&session.session_id)?;
            }
            db.remove_actor_state(&super::session::pair_key(local, remote)?)?;
            db.persist_actor_state(&key, &at)?;
            db.persist_actor_state(
                &format!("{}/reset-pending", super::session::pair_key(local, remote)?),
                &true,
            )?;
            db.append_journal(
                &format!("pair-reset-start:{key}:{at}"),
                "session.reset",
                &serde_json::json!({"device_id":remote,"reason":"receive_state_unrecoverable"}),
                at,
                None,
            )?;
            Ok(())
        })?;
        db.checkpoint_retired_secrets()?;
        Ok(true)
    }
    pub(super) async fn request_pair_recovery(
        &self,
        engine: &mut GatewaySessionEngine,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        // The triggering packet must have a valid signature from the pinned device. A stranger
        // cannot induce key churn, prekey requests or outgoing traffic.
        self.authenticated_envelope_sender(entry)?;
        let local = engine.config.device_id.clone();
        let remote = &entry.envelope.source_device_id;
        let own = entry.envelope.source_principal_id == engine.config.principal_id;
        if !own
            && self.active_pair(&local, remote)?.is_none()
            && !self.pair_recovery_pending(&local, remote)?
            && !self.friend_link_peer_is_accepted(&entry.envelope.source_principal_id)?
        {
            return Ok(());
        }
        let at = now_unix_timestamp();
        if !self.begin_pair_recovery(&local, remote, at)? {
            return Ok(());
        }
        let id = format!(
            "pair-reset-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        );
        let mut message = GatewayDirectMessage {
            conversation_id: id.clone(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: engine.config.principal_id.clone(),
            recipient_device_id: Some(remote.clone()),
            target_delivery_id: remote.clone(),
            encrypted_body: Vec::new(),
            created_at: at,
            ttl: 300,
        };
        let sealed = self
            .seal_routed_as(
                engine,
                &message,
                br#"{"type":"pair.session.reset.v1"}"#,
                Route::control(),
            )
            .await?;
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        let envelope = super::gateway_direct_message_envelope(&engine.config, &message, None)?;
        engine.submit_envelope(envelope).await?;
        self.account_db()?.remove_actor_state(&format!(
            "{}/reset-pending",
            super::session::pair_key(&local, remote)?
        ))?;
        Ok(())
    }
}
