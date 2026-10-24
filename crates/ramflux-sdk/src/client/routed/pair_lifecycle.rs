// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair erasure and retry eligibility driven by verified device and relationship lifecycle.
use super::{RamfluxClient, SdkError, now_unix_timestamp};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(super) fn require_pair_device_active(&self, local: &str) -> Result<(), SdkError> {
        if self
            .account_db()?
            .load_actor_state::<bool>(
                &self.device_revocation_key(&self.local_device_reference(local)?)?,
            )?
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
        if ramflux_protocol::parse_qualified_device_id(remote)?.is_none() {
            return Ok(false);
        }
        let db = self.account_db()?;
        if db
            .load_actor_state::<bool>(
                &self.device_revocation_key(&self.local_device_reference(local)?)?,
            )?
            .unwrap_or(false)
        {
            return Ok(false);
        }
        if db.load_actor_state::<bool>(&self.device_revocation_key(remote)?)?.unwrap_or(false) {
            return Ok(false);
        }
        let Some(record) = db.client_record("device", remote)? else { return Ok(false) };
        let Some(principal) = record["principal_id"].as_str() else { return Ok(false) };
        if record["revoked"] == true || self.friend_rejection_reason(principal)?.is_some() {
            return Ok(false);
        }
        let own =
            self.device_branch.as_ref().is_some_and(|device| device.principal_id == principal);
        Ok(own
            || self.friend_link_peer_is_accepted(principal)?
            || db.actor_state_exists(&RamfluxClient::pair_key(
                &self.local_device_identity(local)?,
                &self.device_identity(remote)?,
            )?)?
            || self.pair_recovery_pending(local, remote)?)
    }
    pub(crate) fn apply_verified_device_revocation(
        &self,
        remote: &str,
        principal: &str,
    ) -> Result<(), SdkError> {
        let own = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let identity = self.account_db()?.client_record("identity", principal)?;
        let commitment = if own.principal_id == principal {
            self.identity_root
                .as_ref()
                .map(|r| ramflux_crypto::identity_root_commitment(&r.signing_key.verifying_key()))
        } else {
            identity
                .as_ref()
                .and_then(|v| v["contact_identity_commitment"].as_str())
                .map(str::to_owned)
        }
        .ok_or_else(|| super::invalid("revocation root unavailable"))?;
        let record = self
            .account_db()?
            .load_actor_state::<ramflux_protocol::SignedDeviceSetRecord>(&format!(
                "identity/signed_set/{commitment}"
            ))?
            .ok_or_else(|| super::invalid("revocation requires signed authority"))?;
        let raw = crate::client::identity_authority::device_namespace::wire_device_id(remote)?;
        let reference = ramflux_protocol::qualified_device_id(&commitment, &raw)?;
        if ramflux_protocol::parse_qualified_device_id(remote)?
            .is_some_and(|(root, _)| root != commitment)
        {
            return Err(super::invalid("revocation root address mismatch"));
        }
        if record.principal_id != principal
            || !record.devices.iter().any(|d| {
                d.device_id == raw && d.status == ramflux_protocol::DeviceSetStatus::Revoked
            })
        {
            return Err(super::invalid("revocation is not root-authorized"));
        }
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            if raw == own.device_id && principal == own.principal_id {
                for peer in db.pair_peer_devices(&own.device_id)? {
                    self.remove_device_pair(&peer, "root_signed_device_revoked")?;
                }
            } else {
                self.remove_device_pair(&reference, "root_signed_device_revoked")?;
            }
            db.remove_actor_state(&format!("directory/device/{reference}"))?;
            db.persist_actor_state(&self.device_revocation_key(&reference)?, &true)?;
            Ok(())
        })?;
        self.finish_pair_retirement()
    }
    pub(crate) fn remove_device_pair(&self, remote: &str, reason: &str) -> Result<(), SdkError> {
        let reference = self.device_reference(remote)?;
        let remote = reference.as_str();
        let Some(local) = self.device_branch.as_ref().map(|device| device.device_id.clone()) else {
            return Ok(());
        };
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            for id in db.pair_session_ids(&local, remote)? {
                self.retire_pair(&local, remote, &id)?;
            }
            let pair = RamfluxClient::pair_key(
                &self.local_device_identity(&local)?,
                &self.device_identity(remote)?,
            )?;
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
        let remote = self.device_reference(remote)?;
        let remote = remote.as_str();
        let db = self.account_db()?;
        db.write_transaction(||->Result<(),SdkError>{
            self.remove_device_pair(remote,"retry_lifetime_exhausted")?;
            db.persist_actor_state(&format!("{}/manual",RamfluxClient::pair_key(&self.local_device_identity(local)?, &self.device_identity(remote)?)?),&json!({"local_device_id":local,"device_id":remote,"state":"needs_manual_recovery","at":at}))?;
            db.append_journal(&format!("pair-manual:{}:{at}",RamfluxClient::pair_key(&self.local_device_identity(local)?, &self.device_identity(remote)?)?),"session.reset",&json!({"device_id":remote,"state":"needs_manual_recovery","reason":"retry_lifetime_exhausted"}),at,None)?;
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
    pub(crate) fn pair_recovery_metadata(&self, principal: &str) -> Result<Vec<Value>, SdkError> {
        let db = self.account_db()?;
        let mut result = Vec::new();
        for key in
            db.actor_state_keys("dm-pair/")?.into_iter().filter(|key| key.ends_with("/manual"))
        {
            if let Some(marker) = db.load_actor_state::<Value>(&key)?
                && let Some(remote) = marker["device_id"].as_str()
                && ramflux_protocol::parse_qualified_device_id(remote)?.is_some()
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
