// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair erasure and retry eligibility driven by verified device and relationship lifecycle.
use super::session::pair_key;
use super::{RamfluxClient, SdkError, now_unix_timestamp};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(super) fn require_pair_device_active(&self, local: &str) -> Result<(), SdkError> {
        if self
            .account_db()?
            .load_actor_state::<bool>(&format!("device/revoked/{local}"))?
            .unwrap_or(false)
        {
            return Err(SdkError::InboundRejected("local device is revoked".to_owned()));
        }
        Ok(())
    }
    pub(super) fn pair_recovery_allowed(
        &self,
        local: &str,
        remote: &str,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if db.load_actor_state::<bool>(&format!("device/revoked/{local}"))?.unwrap_or(false) {
            return Ok(false);
        }
        if db.load_actor_state::<bool>(&format!("device/revoked/{remote}"))?.unwrap_or(false) {
            return Ok(false);
        }
        let Some(record) = db.client_record("device", remote)? else { return Ok(false) };
        let Some(principal) = record["principal_id"].as_str() else { return Ok(false) };
        if record["revoked"] == true || self.friend_rejection_reason(principal)?.is_some() {
            return Ok(false);
        }
        if let Some(identity) = db.client_record("identity", principal)?
            && let Some(devices) = identity["devices"].as_array()
            && !devices.iter().any(|device| device["device_id"] == remote || device["id"] == remote)
        {
            return Ok(false);
        }
        let own =
            self.device_branch.as_ref().is_some_and(|device| device.principal_id == principal);
        Ok(own
            || self.friend_link_peer_is_accepted(principal)?
            || db.actor_state_exists(&pair_key(local, remote)?)?
            || self.pair_recovery_pending(local, remote)?)
    }
    pub(crate) fn apply_verified_device_revocation(
        &self,
        remote: &str,
        principal: &str,
    ) -> Result<(), SdkError> {
        let own = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if own.principal_id != principal {
            return Err(super::invalid("revocation principal mismatch"));
        }
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            if remote == own.device_id {
                for peer in db.pair_peer_devices(&own.device_id)? {
                    self.remove_device_pair(&peer, "own_device_revoked")?;
                }
            } else {
                self.remove_device_pair(remote, "own_device_revoked")?;
            }
            db.remove_actor_state(&format!("directory/device/{remote}"))?;
            db.persist_actor_state(&format!("device/revoked/{remote}"), &true)?;
            Ok(())
        })?;
        self.finish_pair_retirement()
    }
    pub(crate) fn remove_device_pair(&self, remote: &str, reason: &str) -> Result<(), SdkError> {
        let Some(local) = self.device_branch.as_ref().map(|device| device.device_id.clone()) else {
            return Ok(());
        };
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            for id in db.pair_session_ids(&local, remote)? {
                self.retire_pair(&local, remote, &id)?;
            }
            let pair = pair_key(&local, remote)?;
            db.remove_actor_state(&pair)?;
            db.remove_actor_state(&format!("{pair}/archive"))?;
            db.remove_actor_state(&format!("{pair}/reset-pending"))?;
            db.remove_actor_state(&format!("dm-pair/reset-work/{pair}"))?;
            db.remove_actor_state(&format!("{pair}/manual"))?;
            db.prune_pair_metadata()?;
            let at = now_unix_timestamp();
            db.append_journal(
                &format!("pair-removed:{pair}:{reason}:{at}"),
                "session.reset",
                &json!({"device_id":remote,"state":"removed","reason":reason}),
                at,
                None,
            )?;
            Ok(())
        })?;
        self.finish_pair_retirement()
    }
    pub(super) fn mark_pair_manual(
        &self,
        local: &str,
        remote: &str,
        at: i64,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(||->Result<(),SdkError>{
            self.remove_device_pair(remote,"retry_lifetime_exhausted")?;
            db.persist_actor_state(&format!("{}/manual",pair_key(local,remote)?),&json!({"local_device_id":local,"device_id":remote,"state":"needs_manual_recovery","at":at}))?;
            db.append_journal(&format!("pair-manual:{}:{at}",pair_key(local,remote)?),"session.reset",&json!({"device_id":remote,"state":"needs_manual_recovery","reason":"retry_lifetime_exhausted"}),at,None)?;
            Ok(())
        })?;
        self.finish_pair_retirement()
    }
    pub(crate) fn remove_principal_pairs(&self, peer: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let own = self.device_branch.as_ref().map(|device| device.principal_id.as_str());
        for key in db.actor_state_keys("directory/device/")? {
            let device = key.trim_start_matches("directory/device/");
            let record = db.client_record("device", device)?.unwrap_or(Value::Null);
            if (record["principal_id"] == peer || record["principal_commitment"] == peer)
                && record["principal_id"].as_str() != own
            {
                self.remove_device_pair(device, "contact_removed_or_blocked")?;
            }
        }
        Ok(())
    }
    pub(crate) fn retire_devices_absent_from_manifest(
        &self,
        manifest: &crate::prekey::SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for key in db.actor_state_keys("directory/device/")? {
            let device = key.trim_start_matches("directory/device/");
            let record = db.client_record("device", device)?.unwrap_or(Value::Null);
            if record["principal_id"] == manifest.principal_id
                && !manifest.devices.iter().any(|entry| entry.device_id == device)
            {
                self.remove_device_pair(device, "verified_manifest_device_removed")?;
                db.remove_actor_state(&key)?;
            }
        }
        Ok(())
    }
    pub(crate) fn pair_recovery_metadata(&self, principal: &str) -> Result<Vec<Value>, SdkError> {
        let db = self.account_db()?;
        let mut result = Vec::new();
        for key in
            db.actor_state_keys("dm-pair/")?.into_iter().filter(|key| key.ends_with("/manual"))
        {
            if let Some(marker) = db.load_actor_state::<Value>(&key)?
                && let Some(remote) = marker["device_id"].as_str()
                && db
                    .client_record("device", remote)?
                    .is_some_and(|device| device["principal_id"] == principal)
            {
                result.push(marker);
            }
        }
        Ok(result)
    }
}
