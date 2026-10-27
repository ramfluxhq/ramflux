// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable device-pair sessions, including simultaneous bootstrap selection.
use super::{
    Deserialize, GatewayDirectMessage, GatewaySessionEngine, RamfluxClient, SdkDmEncryptedEnvelope,
    SdkDmX3dhHeader, SdkError, Serialize, associated_data, dm_device_id_hash, invalid,
    prekey_bundle_hash,
};
use crate::prekey::sdk_fetch_prekey_bundle;

#[derive(Serialize, Deserialize)]
struct Pair {
    #[serde(default)]
    root_addressed: bool,
    local: String,
    remote: String,
    bundle: [u8; 32],
    snapshot: ramflux_crypto::DmSessionSnapshot,
}

impl RamfluxClient {
    pub(crate) fn pair_key(
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<String, SdkError> {
        pair_key(local, remote)
    }

    pub(crate) fn persist_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        bundle: &[u8; 32],
        session: &ramflux_crypto::DmSession,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            let record = Pair {
                root_addressed: true,
                local: local.storage_key().to_owned(),
                remote: remote.storage_key().to_owned(),
                bundle: *bundle,
                snapshot: session.snapshot(),
            };
            let record_key = format!("dm-pair/session/{}", session.session_id);
            let new = !db.actor_state_exists(&record_key)?;
            db.persist_actor_state(&record_key, &record)?;
            self.consume_pending_one_time_prekey(&session.session_id)?;
            let key = RamfluxClient::pair_key(local, remote)?;
            let current = db.load_actor_state::<String>(&key)?;
            let local_origin = db
                .load_actor_state::<bool>(&format!("dm-pair/local/{}", session.session_id))?
                .unwrap_or(false);
            if (new && local_origin)
                || (current.is_none()
                    && !self.archived_pairs(local, remote)?.contains(&session.session_id))
            {
                self.promote_pair(local, remote, &session.session_id)?;
            }
            Ok(())
        })?;
        self.pending_opk_consumptions.borrow_mut().remove(&session.session_id);
        self.finish_pair_retirement()
    }
    pub(super) fn confirm_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        session: &ramflux_crypto::DmSession,
        reset: bool,
        bootstrap: bool,
    ) -> Result<(), SdkError> {
        self.confirm_pair_record(local, remote, session, reset, bootstrap)
    }
    fn load_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        id: &str,
    ) -> Result<Option<(ramflux_crypto::DmSession, [u8; 32])>, SdkError> {
        if let Some(retired) = self
            .account_db()?
            .load_actor_state::<serde_json::Value>(&format!("dm-pair/retired/{id}"))?
        {
            let current = self
                .account_db()?
                .load_actor_state::<String>(&RamfluxClient::pair_key(local, remote)?)?;
            if let Some(current) = current
                && retired["superseded_by"] == current
                && self
                    .account_db()?
                    .load_actor_state::<bool>(&format!("dm-pair/confirmed/{current}"))?
                    .unwrap_or(false)
            {
                return Err(SdkError::InboundRejected(
                    "evicted state predates the confirmed pair".to_owned(),
                ));
            }
            return Err(SdkError::PairRecoveryRequired);
        }
        let current = self
            .account_db()?
            .load_actor_state::<String>(&RamfluxClient::pair_key(local, remote)?)?;
        let mut order = current.into_iter().collect::<Vec<_>>();
        order.extend(self.archived_pairs(local, remote)?);
        if !order.iter().any(|candidate| candidate == id)
            && !self.account_db()?.actor_state_exists(&format!("backup/inactive-pair/{id}"))?
        {
            return Ok(None);
        }
        let Some(record) =
            self.account_db()?.load_actor_state::<Pair>(&format!("dm-pair/session/{id}"))?
        else {
            return Ok(None);
        };
        if !record.root_addressed
            || record.local != local.storage_key()
            || record.remote != remote.storage_key()
        {
            return Err(invalid("device-pair session identity mismatch"));
        }
        let session = ramflux_crypto::DmSession::from_snapshot(record.snapshot)?;
        if session.session_id != id {
            return Err(invalid("device-pair session id mismatch"));
        }
        Ok(Some((session, record.bundle)))
    }
    pub(crate) fn active_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Option<(ramflux_crypto::DmSession, [u8; 32])>, SdkError> {
        let Some(id) = self
            .account_db()?
            .load_actor_state::<String>(&RamfluxClient::pair_key(local, remote)?)?
        else {
            return Ok(None);
        };
        self.load_pair(local, remote, &id)
    }
    pub(super) async fn send_pair_session(
        &self,
        engine: &mut GatewaySessionEngine,
        message: &GatewayDirectMessage,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>, [u8; 32]), SdkError> {
        let local = self.local_device_identity(&engine.config.device_id)?;
        self.require_pair_device_active(&local)?;
        let recipient = Self::qualified_recipient(message)?;
        let recipient = recipient.as_str();
        if let Ok(remote) = self.device_identity(recipient)
            && let Some(pair) = self.sendable_pair(&local, &remote)?
        {
            return Ok(pair);
        }
        if self
            .account_db()?
            .client_record("device", recipient)?
            .as_ref()
            .is_none_or(|record| record.get("x25519_identity_public").is_none())
            || self
                .device_identity(recipient)
                .and_then(|identity| self.require_cached_root_authority(&identity))
                .is_err()
        {
            self.resolve_target_principal_commitment(
                &engine.config,
                message.recipient_principal_commitment.as_deref(),
                message
                    .recipient_device_id
                    .as_deref()
                    .ok_or_else(|| invalid("recipient absent"))?,
            )
            .await?;
        }
        let lookup = self.root_qualified_device_lookup(recipient)?;
        let bundle = engine
            .fetch_prekey_bundle(&lookup)
            .await?
            .bundle
            .ok_or_else(|| invalid("recipient prekey missing"))?;
        self.new_send_pair(&local, message, bundle)
    }
    pub(crate) fn send_pair_session_from_url(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        message: &GatewayDirectMessage,
        url: Option<&str>,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>, [u8; 32]), SdkError> {
        self.require_pair_device_active(local)?;
        let remote = Self::qualified_recipient(message)?;
        let remote = remote.as_str();
        if let Ok(remote) = self.device_identity(remote)
            && let Some(pair) = self.sendable_pair(local, &remote)?
        {
            return Ok(pair);
        }
        let bundle = sdk_fetch_prekey_bundle(
            url.ok_or_else(|| invalid("prekey url missing"))?,
            &self.root_qualified_device_lookup(remote)?,
        )?
        .bundle
        .ok_or_else(|| invalid("recipient prekey missing"))?;
        self.new_send_pair(local, message, bundle)
    }
    pub(super) fn new_send_pair(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        message: &GatewayDirectMessage,
        bundle: ramflux_crypto::PrekeyBundle,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>, [u8; 32]), SdkError> {
        let remote = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("recipient device required"))?;
        self.verify_root_bound_prekey(
            &self.device_identity(&Self::qualified_recipient(message)?)?,
            &bundle,
        )?;
        let hash = prekey_bundle_hash(&bundle)?;
        let aad = associated_data(&message.envelope_id, local.device_id(), remote, &hash)?;
        let (session, header) = self.create_send_dm_session_with_aad(
            message,
            remote,
            bundle,
            local.device_id(),
            Some(&aad),
        )?;
        let mut header = header.ok_or_else(|| invalid("new pair bootstrap missing"))?;
        header.bootstrap_envelope_id = Some(message.envelope_id.clone());
        self.account_db()?
            .persist_actor_state(&format!("dm-pair/bootstrap/{}", session.session_id), &header)?;
        Ok((session, Some(header), hash))
    }
    pub(super) fn recv_pair_session(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope_id: &str,
        envelope: &SdkDmEncryptedEnvelope,
    ) -> Result<(ramflux_crypto::DmSession, [u8; 32]), SdkError> {
        let wire_remote = crate::client::identity_authority::device_namespace::wire_device_id(
            remote.storage_key(),
        )?;
        if envelope.ciphertext.sender_device_id_hash != dm_device_id_hash(&wire_remote)
            || envelope.ciphertext.recipient_device_id_hash != dm_device_id_hash(local.device_id())
        {
            return Err(invalid("v2 ciphertext device binding mismatch"));
        }
        if let Some(header) = envelope.x3dh.as_ref() {
            self.verify_initiator_identity(remote, header)?;
        }
        if let Some(record) = self.load_pair(local, remote, &envelope.ciphertext.session_id)? {
            return Ok(record);
        }
        let header = envelope.x3dh.as_ref().ok_or(SdkError::PairRecoveryRequired)?;
        self.require_current_device_authorization(remote)?;
        self.check_bootstrap_sequence(local, remote, header)?;
        if header.recipient_device_id != local.device_id()
            || header.initiator_device_id_hash != dm_device_id_hash(&wire_remote)
            || header.recipient_device_id_hash != dm_device_id_hash(local.device_id())
        {
            return Err(invalid("v2 X3DH device binding mismatch"));
        }
        let aad = associated_data(
            header.bootstrap_envelope_id.as_deref().unwrap_or(envelope_id),
            &wire_remote,
            local.device_id(),
            &header.prekey_bundle_hash,
        )?;
        let session = self.create_recv_dm_session_with_aad(header, &aad)?;
        if session.session_id != envelope.ciphertext.session_id
            || header.session_id != session.session_id
        {
            return Err(invalid("v2 bootstrap session mismatch"));
        }
        Ok((session, header.prekey_bundle_hash))
    }
}
pub(super) fn pair_key(
    local: &ramflux_crypto::RootQualifiedDeviceRef,
    remote: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<String, SdkError> {
    let bytes =
        ramflux_protocol::canonical_json_bytes(&(local.storage_key(), remote.storage_key()))?;
    Ok(format!(
        "dm-pair/active/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.root_bound_dm_pair.v1", &bytes)
    ))
}
