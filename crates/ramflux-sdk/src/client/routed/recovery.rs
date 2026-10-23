// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated fresh-X3DH recovery; a reset never travels outside the encrypted route.
use super::{GatewayInboxEntry, GatewaySessionEngine, RamfluxClient, SdkError, now_unix_timestamp};
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
        if self.begin_pair_recovery(&local, remote, at)? {
            self.send_pair_reset(engine, remote).await?;
        }
        Ok(())
    }
}
