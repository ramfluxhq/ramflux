// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Abandon unsupported unconfirmed send candidates while retaining receive-only state.
use super::{RamfluxClient, SdkDmX3dhHeader, SdkError};
pub(super) type SendPair = (ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>, [u8; 32]);
impl RamfluxClient {
    pub(super) fn sendable_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Option<SendPair>, SdkError> {
        if self
            .account_db()?
            .load_actor_state::<bool>(&self.device_revocation_key(remote.storage_key())?)?
            .unwrap_or(false)
        {
            return Err(SdkError::InboundRejected("recipient device is revoked".into()));
        }
        if self.require_cached_root_authority(remote.storage_key()).is_err() {
            return Ok(None);
        }
        let Some((session, bundle)) = self.active_pair(local, remote)? else { return Ok(None) };
        let header = self.account_db()?.load_actor_state::<SdkDmX3dhHeader>(&format!(
            "dm-pair/bootstrap/{}",
            session.session_id
        ))?;
        if header.as_ref().is_some_and(|header| {
            header.bootstrap_ordering_version != Some(2) || header.bootstrap_sequence.is_none()
        }) && self.abandon_unconfirmed_candidate(local, remote, u64::MAX)?
        {
            return Ok(None);
        }
        Ok(Some((session, header, bundle)))
    }
    pub(super) fn abandon_unconfirmed_candidate(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        floor: u64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let pair = RamfluxClient::pair_key(
                local,
                remote,
            )?;
            let Some(id) = db.load_actor_state::<String>(&pair)? else { return Ok(false) };
            if !db.load_actor_state::<bool>(&format!("dm-pair/local/{id}"))?.unwrap_or(false)
                || db.load_actor_state::<bool>(&format!("dm-pair/confirmed/{id}"))?.unwrap_or(false)
            {
                return Ok(false);
            }
            let Some(header) =
                db.load_actor_state::<SdkDmX3dhHeader>(&format!("dm-pair/bootstrap/{id}"))?
            else {
                return Ok(false);
            };
            if header.bootstrap_ordering_version == Some(2)
                && header.bootstrap_sequence.is_some_and(|seq| seq > floor)
            {
                return Ok(false);
            }
            self.archive_pair(local, remote, &id)?;
            db.remove_actor_state(&pair)?;
            db.remove_actor_state(&format!("dm-pair/bootstrap/{id}"))?;
            db.append_journal(
                &format!("pair-candidate-upgrade:{id}"),
                "session.reset",
                &serde_json::json!({"device_id":remote.storage_key(),"reason":"unconfirmed_bootstrap_replaced"}),
                super::now_unix_timestamp(),
                None,
            )?;
            Ok(true)
        })
    }
}
