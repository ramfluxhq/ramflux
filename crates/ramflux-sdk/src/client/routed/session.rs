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
        if active.as_deref().is_none_or(|id| session.session_id.as_str() <= id) {
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
    fn active_pair(
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
            return Ok((session, None, bundle));
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
            return Ok((session, None, bundle));
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
        let hash = prekey_bundle_hash(&bundle)?;
        let aad = associated_data(&message.envelope_id, local, remote, &hash)?;
        let (session, header) =
            self.create_send_dm_session_with_aad(message, remote, bundle, local, Some(&aad))?;
        Ok((session, header, hash))
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
        let aad = associated_data(envelope_id, remote, local, &header.prekey_bundle_hash)?;
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
