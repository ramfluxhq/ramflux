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
    local: String,
    remote: String,
    bundle: [u8; 32],
    snapshot: ramflux_crypto::DmSessionSnapshot,
}

impl RamfluxClient {
    pub(crate) fn pair_history_snapshots(
        &self,
        source: &str,
    ) -> Result<Vec<crate::own_device_sync::SdkOwnDevicePairSessionSnapshot>, SdkError> {
        Ok(self
            .account_db()?
            .list_actor_states::<Pair>("dm-pair/session/")?
            .into_iter()
            .filter(|pair| pair.local == source)
            .map(|pair| crate::own_device_sync::SdkOwnDevicePairSessionSnapshot {
                local_device_id: pair.local,
                remote_device_id: pair.remote,
                prekey_bundle_hash: pair.bundle,
                snapshot: pair.snapshot,
            })
            .collect())
    }
    pub(crate) fn archive_pair_history(
        &self,
        pair: &crate::own_device_sync::SdkOwnDevicePairSessionSnapshot,
        source: &str,
        snapshot_id: &str,
    ) -> Result<(), SdkError> {
        let session = ramflux_crypto::DmSession::from_snapshot(pair.snapshot.clone())?;
        if pair.local_device_id != source
            || session.sender_device_id_hash != dm_device_id_hash(source)
            || session.recipient_device_id_hash != dm_device_id_hash(&pair.remote_device_id)
        {
            return Err(invalid("own-device pair history source binding mismatch"));
        }
        self.account_db()?.persist_actor_state(
            &format!("own-device/pair-history/{source}/{snapshot_id}/{}", session.session_id),
            pair,
        )?;
        Ok(())
    }
    pub(crate) fn persist_pair(
        &self,
        local: &str,
        remote: &str,
        bundle: &[u8; 32],
        session: &ramflux_crypto::DmSession,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let record = Pair {
            local: local.to_owned(),
            remote: remote.to_owned(),
            bundle: *bundle,
            snapshot: session.snapshot(),
        };
        db.persist_actor_state(&format!("dm-pair/session/{}", session.session_id), &record)?;
        let key = pair_key(local, remote)?;
        let active = db.load_actor_state::<String>(&key)?;
        let local_origin = db
            .load_actor_state::<bool>(&format!("dm-pair/local/{}", session.session_id))?
            .unwrap_or(false);
        let active_local = active
            .as_ref()
            .map(|id| db.load_actor_state::<bool>(&format!("dm-pair/local/{id}")))
            .transpose()?
            .flatten()
            .unwrap_or(false);
        if active.is_none() || (local_origin && !active_local) {
            db.persist_actor_state(&key, &session.session_id)?;
        }
        Ok(())
    }
    fn load_pair(
        &self,
        local: &str,
        remote: &str,
        id: &str,
    ) -> Result<Option<(ramflux_crypto::DmSession, [u8; 32])>, SdkError> {
        let Some(record) =
            self.account_db()?.load_actor_state::<Pair>(&format!("dm-pair/session/{id}"))?
        else {
            return Ok(None);
        };
        if record.local != local || record.remote != remote {
            return Err(invalid("device-pair session identity mismatch"));
        }
        let session = ramflux_crypto::DmSession::from_snapshot(record.snapshot)?;
        if session.session_id != id {
            return Err(invalid("device-pair session id mismatch"));
        }
        Ok(Some((session, record.bundle)))
    }
    pub(super) fn active_pair(
        &self,
        local: &str,
        remote: &str,
    ) -> Result<Option<(ramflux_crypto::DmSession, [u8; 32])>, SdkError> {
        let Some(id) = self.account_db()?.load_actor_state::<String>(&pair_key(local, remote)?)?
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
        let recipient = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("recipient device required"))?;
        if let Some((session, bundle)) = self.active_pair(&engine.config.device_id, recipient)? {
            let header = self.account_db()?.load_actor_state::<SdkDmX3dhHeader>(&format!(
                "dm-pair/bootstrap/{}",
                session.session_id
            ))?;
            return Ok((session, header, bundle));
        }
        if self
            .account_db()?
            .client_record("device", recipient)?
            .as_ref()
            .is_none_or(|record| record.get("x25519_identity_public").is_none())
        {
            self.resolve_target_principal_commitment(&engine.config, None, recipient).await?;
        }
        let bundle = engine
            .fetch_prekey_bundle(recipient)
            .await?
            .bundle
            .ok_or_else(|| invalid("recipient prekey missing"))?;
        self.new_send_pair(&engine.config.device_id, message, bundle)
    }
    pub(super) fn send_pair_session_from_url(
        &self,
        local: &str,
        message: &GatewayDirectMessage,
        url: Option<&str>,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>, [u8; 32]), SdkError> {
        let remote = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("recipient device required"))?;
        if let Some((session, bundle)) = self.active_pair(local, remote)? {
            let header = self.account_db()?.load_actor_state::<SdkDmX3dhHeader>(&format!(
                "dm-pair/bootstrap/{}",
                session.session_id
            ))?;
            return Ok((session, header, bundle));
        }
        let bundle =
            sdk_fetch_prekey_bundle(url.ok_or_else(|| invalid("prekey url missing"))?, remote)?
                .bundle
                .ok_or_else(|| invalid("recipient prekey missing"))?;
        self.new_send_pair(local, message, bundle)
    }
    fn new_send_pair(
        &self,
        local: &str,
        message: &GatewayDirectMessage,
        bundle: ramflux_crypto::PrekeyBundle,
    ) -> Result<(ramflux_crypto::DmSession, Option<SdkDmX3dhHeader>, [u8; 32]), SdkError> {
        let remote = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("recipient device required"))?;
        let record = self.trusted_device(remote)?;
        let identity: [u8; 32] = serde_json::from_value(
            record
                .get("x25519_identity_public")
                .cloned()
                .ok_or_else(|| invalid("recipient identity missing"))?,
        )?;
        if bundle.device_id != remote || bundle.identity_key != identity {
            return Err(invalid("recipient prekey differs from verified device identity"));
        }
        let key = record
            .get("signing_public_key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("recipient signing key missing"))?;
        ramflux_crypto::verify_prekey_bundle(
            &ramflux_crypto::verifying_key_from_base64url(key)?,
            &bundle,
        )?;
        let hash = prekey_bundle_hash(&bundle)?;
        let aad = associated_data(&message.envelope_id, local, remote, &hash)?;
        let (session, header) =
            self.create_send_dm_session_with_aad(message, remote, bundle, local, Some(&aad))?;
        let mut header = header.ok_or_else(|| invalid("new pair bootstrap missing"))?;
        header.bootstrap_envelope_id = Some(message.envelope_id.clone());
        self.account_db()?
            .persist_actor_state(&format!("dm-pair/bootstrap/{}", session.session_id), &header)?;
        Ok((session, Some(header), hash))
    }
    pub(super) fn recv_pair_session(
        &self,
        local: &str,
        remote: &str,
        envelope_id: &str,
        envelope: &SdkDmEncryptedEnvelope,
    ) -> Result<(ramflux_crypto::DmSession, [u8; 32]), SdkError> {
        if envelope.ciphertext.sender_device_id_hash != dm_device_id_hash(remote)
            || envelope.ciphertext.recipient_device_id_hash != dm_device_id_hash(local)
        {
            return Err(invalid("v2 ciphertext device binding mismatch"));
        }
        if let Some(header) = envelope.x3dh.as_ref() {
            self.verify_initiator_identity(remote, header)?;
        }
        if let Some(record) = self.load_pair(local, remote, &envelope.ciphertext.session_id)? {
            return Ok(record);
        }
        let header = envelope
            .x3dh
            .as_ref()
            .ok_or_else(|| invalid("new device-pair session requires X3DH"))?;
        if header.recipient_device_id != local
            || header.initiator_device_id_hash != dm_device_id_hash(remote)
            || header.recipient_device_id_hash != dm_device_id_hash(local)
        {
            return Err(invalid("v2 X3DH device binding mismatch"));
        }
        let aad = associated_data(
            header.bootstrap_envelope_id.as_deref().unwrap_or(envelope_id),
            remote,
            local,
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
fn pair_key(local: &str, remote: &str) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&(local, remote))?;
    Ok(format!(
        "dm-pair/active/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.dm_pair.v2", &bytes)
    ))
}
