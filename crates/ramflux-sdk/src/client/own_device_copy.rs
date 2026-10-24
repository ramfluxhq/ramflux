// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inline per-message own-device controls: one ciphertext, existing pair-wrapped recipient keys.
use crate::prelude::*;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroize;
const DOMAIN: &str = "ramflux.sdk.own_device_message.v1";
pub(crate) const PREFIX: &[u8] = b"ramflux.own_device_message.v1\n";
pub(crate) const MAX_PACKET_BYTES: usize = 512 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnDeviceMessage {
    pub schema: String,
    pub id: String,
    pub principal: String,
    pub root: String,
    pub source: String,
    pub conversation: String,
    pub group: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub nonce: String,
    pub ciphertext: String,
    pub slots: Vec<SdkObjectKeySlot>,
    pub signature: String,
}
impl OwnDeviceMessage {
    fn validate_scope(
        &self,
        client: &RamfluxClient,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if self.schema != DOMAIN
            || self.root != client.surface_local_root_commitment()?
            || self.principal != local.principal_id
            || self.source != entry.envelope.source_device_id
            || self.principal != entry.envelope.source_principal_id
            || self.slots.len() > 1024
            || self.id.is_empty()
            || self.id.len() > 256
            || self.conversation.is_empty()
            || self.conversation.len() > 256
            || self.group.as_ref().is_some_and(|id| id.is_empty() || id.len() > 256)
            || self.created_at > now_unix_timestamp().saturating_add(300)
            || self.expires_at < now_unix_timestamp()
            || self.expires_at <= self.created_at
            || self.expires_at > self.created_at.saturating_add(600)
            || entry.envelope.delivery_class != ramflux_protocol::DeliveryClass::SelfDeviceControl
        {
            return Err(invalid("own-device message scope or lifetime mismatch"));
        }
        Ok(())
    }
    fn signing(&self) -> Result<Value, SdkError> {
        let mut body = serde_json::to_value(self)?;
        body.as_object_mut().ok_or_else(|| invalid("own-device body missing"))?.remove("signature");
        Ok(json!({"domain":DOMAIN,"body":body}))
    }
    fn aad(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(
            DOMAIN,
            &self.id,
            &self.principal,
            &self.root,
            &self.source,
            &self.conversation,
            &self.group,
            self.created_at,
            self.expires_at,
        ))?)
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid("own-device message byte budget exceeded"));
        }
        Ok(bytes)
    }
}
fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}
#[derive(Clone, Copy)]
pub(crate) struct OwnMessageInput<'a> {
    pub id: &'a str,
    pub created_at: i64,
    pub conversation: &'a str,
    pub group: Option<&'a str>,
    pub body: &'a [u8],
}
impl RamfluxClient {
    pub(crate) async fn prepare_own_device_message(
        &self,
        engine: &mut GatewaySessionEngine,
        input: OwnMessageInput<'_>,
    ) -> Result<Option<OwnDeviceMessage>, SdkError> {
        let root = self.surface_local_root_commitment()?;
        let manifest = self
            .cache_verified_device_manifest(&engine.config, &root, "own_device_message")
            .await?;
        let source = engine.config.device_id.clone();
        if !manifest.devices.iter().any(|device| device.device_id == source) {
            return Err(invalid("own-device source is not active"));
        }
        let targets = manifest
            .devices
            .into_iter()
            .filter(|device| device.device_id != source)
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Ok(None);
        }
        let now = input.created_at;
        let mut packet = OwnDeviceMessage {
            schema: DOMAIN.into(),
            id: ramflux_protocol::hash_base64url(
                DOMAIN,
                &ramflux_protocol::canonical_json_bytes(&(&root, &source, input.id))?,
            ),
            principal: engine.config.principal_id.clone(),
            root,
            source: source.clone(),
            conversation: input.conversation.into(),
            group: input.group.map(str::to_owned),
            created_at: now,
            expires_at: now.saturating_add(600),
            nonce: ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..12]),
            ciphertext: String::new(),
            slots: Vec::new(),
            signature: String::new(),
        };
        let key = zeroize::Zeroizing::new(ramflux_crypto::random_32()?);
        let nonce = ramflux_protocol::decode_base64url(&packet.nonce)
            .map_err(|_| invalid("own-device nonce"))?;
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| invalid("own-device key"))?;
        packet.ciphertext = ramflux_protocol::encode_base64url(
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload { msg: input.body, aad: &packet.aad()? },
                )
                .map_err(|_| invalid("own-device encryption failed"))?,
        );
        for target in targets {
            let request: LocalBusMessageSubmitRequest = serde_json::from_value(
                json!({"conversation_id":input.conversation,"message_id":input.id,"envelope_id":packet.id,"source_principal_id":packet.principal,"sender_id":source,"recipient_device_id":target.device_id,"recipient_principal_commitment":packet.root,"target_delivery_id":target.target_delivery_id,"encrypted_body_base64":"","created_at":now,"ttl":600}),
            )?;
            let message = request.into_gateway_message_with_body(Vec::new());
            packet.slots.push(
                self.make_pair_object_slot(engine, &message, &packet.id, &key, input.conversation)
                    .await?,
            );
        }
        packet.signature = ramflux_crypto::sign_with_device_branch(
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &packet.signing()?,
        )?;
        packet.bytes()?;
        Ok(Some(packet))
    }
    pub(crate) async fn receive_own_device_message(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| invalid("own-device encoding"))?;
        let Some(raw) = bytes.strip_prefix(PREFIX) else { return Ok(false) };
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid("own-device message byte budget exceeded"));
        }
        let packet: OwnDeviceMessage = ramflux_protocol::parse_i_json(raw)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        packet.validate_scope(self, entry)?;
        let receipt = format!("own-device/message-receipt/{}", packet.id);
        let fingerprint = ramflux_protocol::hash_base64url(DOMAIN, &bytes);
        if let Some(old) = self.account_db()?.load_actor_state::<String>(&receipt)? {
            if old != fingerprint {
                return Err(invalid("own-device message id conflict"));
            }
            return Ok(true);
        }
        let manifest = self
            .cache_verified_device_manifest(gateway, &packet.root, "own_device_message_receive")
            .await?;
        let source = manifest
            .devices
            .iter()
            .find(|device| device.device_id == packet.source)
            .ok_or_else(|| invalid("own-device sender is not active"))?;
        if !manifest.devices.iter().any(|device| device.device_id == local.device_id) {
            return Err(invalid("own-device recipient is not active"));
        }
        // Fanout changes outer routing fields. The immutable inner signature authenticates them.
        ramflux_crypto::verify_device_branch_signature(
            &source.branch_public_key,
            &packet.signing()?,
            &packet.signature,
        )?;
        let slots = packet
            .slots
            .iter()
            .filter(|slot| slot.recipient_device_id == local.device_id)
            .collect::<Vec<_>>();
        if slots.len() != 1 {
            return Err(invalid("own-device recipient slot ambiguity"));
        }
        let slot = slots[0];
        if slot.object_id != packet.id
            || slot.conversation_id != packet.conversation
            || slot.version != 2
            || slot.ciphertext.sender_device_id_hash != dm_device_id_hash(&packet.source)
        {
            return Err(invalid("own-device key slot scope mismatch"));
        }
        let mut deferred = match self.decrypt_object_key_slot(slot) {
            Ok(deferred) => deferred,
            Err(SdkError::PairRecoveryRequired) => {
                self.begin_pair_recovery(&local.device_id, &packet.source, now_unix_timestamp())?;
                return Err(SdkError::PairRecoveryRequired);
            }
            Err(error) => return Err(error),
        };
        let key = zeroize::Zeroizing::new(deferred.object_key);
        deferred.object_key.zeroize();
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| invalid("own-device key"))?;
        let nonce = ramflux_protocol::decode_base64url(&packet.nonce)
            .map_err(|_| invalid("own-device nonce"))?;
        if nonce.len() != 12 {
            return Err(invalid("own-device nonce length"));
        }
        let ciphertext = ramflux_protocol::decode_base64url(&packet.ciphertext)
            .map_err(|_| invalid("own-device ciphertext encoding"))?;
        let plaintext = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload { msg: &ciphertext, aad: &packet.aad()? },
                )
                .map_err(|_| invalid("own-device decryption failed"))?,
        );
        self.account_db()?.write_transaction(|| {
            if !self.receive_surface_control(
                entry,
                &packet.conversation,
                packet.group.as_deref(),
                &plaintext,
            )? {
                return Err(invalid("unsupported own-device control"));
            }
            self.commit_pair_object_slot(slot, &key)?;
            self.account_db()?.persist_actor_state(&receipt, &fingerprint)?;
            Ok::<_, SdkError>(())
        })?;
        Ok(true)
    }
}
