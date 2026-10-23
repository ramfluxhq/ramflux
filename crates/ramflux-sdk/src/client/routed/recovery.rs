// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated fresh-X3DH recovery; a reset never travels outside the encrypted route.
use super::{GatewayInboxEntry, GatewaySessionEngine, RamfluxClient, SdkError, now_unix_timestamp};
impl RamfluxClient {
    pub(crate) fn finish_pair_retirement(&self) -> Result<(), SdkError> {
        if self.account_db()?.load_actor_state::<bool>("secrets/retired")?.unwrap_or(false)
            && self.account_db()?.checkpoint_retired_secrets_if_committed()?
        {
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

    pub(super) fn retire_pair(&self, local: &str, remote: &str, id: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let pair = super::session::pair_key(local, remote)?;
        let successor = db.load_actor_state::<String>(&pair)?;
        db.persist_actor_state(&format!("dm-pair/retired/{id}"), &serde_json::json!({"pair":pair,"superseded_by":successor,"retired_at":now_unix_timestamp()}))?;
        db.persist_actor_state("secrets/retired", &true)?;
        for prefix in ["session", "bootstrap"] {
            db.remove_actor_state(&format!("dm-pair/{prefix}/{id}"))?;
        }
        db.prune_pair_metadata()?;
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
        if !self.pair_recovery_allowed(&local, remote)? {
            return Ok(());
        }
        let at = now_unix_timestamp();
        if self.begin_pair_recovery(&local, remote, at)? {
            self.send_pair_reset(engine, remote).await?;
        }
        Ok(())
    }
}
