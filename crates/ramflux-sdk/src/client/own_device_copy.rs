// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private per-message own-device controls with opaque, pair-wrapped recipient key slots.
use crate::prelude::*;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroize;
pub(crate) const DOMAIN: &str = "ramflux.sdk.own_device_message.v2";
pub(crate) const PREFIX: &[u8] = b"ramflux.own_device_message.v2\n";
pub(crate) const MAX_PACKET_BYTES: usize = 512 * 1024;
pub(crate) const TOO_LARGE: &str = "own-device message byte budget exceeded";
const RECEIPTS: &str = "own-device/message-receipt/";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnDeviceMessage {
    pub schema: String,
    pub id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub slots: Vec<OwnKeySlot>,
    pub signature: String,
}
impl OwnDeviceMessage {
    fn recipient_slot(&self, device: &str) -> Result<&OwnKeySlot, SdkError> {
        let mut slots = self.slots.iter().filter(|slot| slot.recipient_device_id == device);
        let slot = slots.next().ok_or_else(|| invalid("own-device recipient slot ambiguity"))?;
        if slots.next().is_some() {
            return Err(invalid("own-device recipient slot ambiguity"));
        }
        Ok(slot)
    }
}
/// Only the recipient selector and cryptographic bootstrap are needed outside AEAD.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnKeySlot {
    pub recipient_device_id: String,
    x3dh: Option<SdkDmX3dhHeader>,
    ciphertext: ramflux_crypto::DmCiphertext,
}
impl OwnKeySlot {
    fn object_slot(&self, id: &str, root: &str) -> SdkObjectKeySlot {
        SdkObjectKeySlot {
            schema: "ramflux.sdk.object_key_slot.dm.v2".into(),
            version: 2,
            object_id: id.into(),
            conversation_id: String::new(),
            recipient_device_id: self.recipient_device_id.clone(),
            source_principal_commitment: Some(root.into()),
            x3dh: self.x3dh.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateContext {
    message: String,
    principal: String,
    root: String,
    source: String,
    conversation: String,
    group: Option<String>,
    created_at: i64,
    expires_at: i64,
}
impl PrivateContext {
    fn validate(
        &self,
        id: &str,
        principal: &str,
        root: &str,
        source: &str,
        now: i64,
    ) -> Result<(), SdkError> {
        if self.principal != principal
            || self.root != root
            || self.source != source
            || self.conversation.is_empty()
            || self.conversation.len() > 256
            || self.group.as_ref().is_some_and(|s| s.is_empty() || s.len() > 256)
            || self.message.is_empty()
            || self.message.len() > 256
            || self.created_at > now.saturating_add(300)
            || self.expires_at < now
            || self.expires_at <= self.created_at
            || self.expires_at > self.created_at.saturating_add(600)
            || id != copy_id(&self.root, &self.source, &self.message)?
        {
            return Err(invalid("own-device private scope or lifetime mismatch"));
        }
        Ok(())
    }
}
impl Drop for PrivateContext {
    fn drop(&mut self) {
        self.message.zeroize();
        self.principal.zeroize();
        self.root.zeroize();
        self.source.zeroize();
        self.conversation.zeroize();
        self.group.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    fingerprint: String,
    source: String,
    target: String,
    valid_until: i64,
    expires_at: i64,
}
impl Receipt {
    fn validate(
        &self,
        source: &str,
        target: &str,
        fingerprint: &str,
        now: i64,
    ) -> Result<(), SdkError> {
        if self.valid_until < now || self.source != source || self.target != target {
            return Err(invalid("own-device replay scope or lifetime mismatch"));
        }
        if self.fingerprint != fingerprint {
            return Err(invalid("own-device message id conflict"));
        }
        Ok(())
    }
}
impl OwnDeviceMessage {
    fn open(
        &self,
        key: &[u8; 32],
    ) -> Result<(PrivateContext, zeroize::Zeroizing<Vec<u8>>), SdkError> {
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| invalid("own-device key"))?;
        let nonce = ramflux_protocol::decode_base64url(&self.nonce)
            .map_err(|_| invalid("own-device nonce"))?;
        if nonce.len() != 12 {
            return Err(invalid("own-device nonce length"));
        }
        let ciphertext = ramflux_protocol::decode_base64url(&self.ciphertext)
            .map_err(|_| invalid("own-device ciphertext encoding"))?;
        let plaintext = zeroize::Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &self.aad()? })
                .map_err(|_| invalid("own-device decryption failed"))?,
        );
        let split = plaintext
            .iter()
            .position(|b| *b == b'\n')
            .filter(|n| *n <= 4096)
            .ok_or_else(|| invalid("own-device private context missing"))?;
        let context: PrivateContext = ramflux_protocol::parse_i_json(&plaintext[..split])?;
        let body = zeroize::Zeroizing::new(plaintext[split + 1..].to_vec());
        Ok((context, body))
    }
    fn validate(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        if self.schema != DOMAIN
            || self.id.is_empty()
            || self.id.len() > 256
            || self.slots.is_empty()
            || self.slots.len() > 1024
            || entry.envelope.delivery_class != ramflux_protocol::DeliveryClass::SelfDeviceControl
        {
            return Err(invalid("own-device message scope mismatch"));
        }
        Ok(())
    }
    fn signing(&self) -> Result<Value, SdkError> {
        let mut body = serde_json::to_value(self)?;
        body.as_object_mut().ok_or_else(|| invalid("own-device body missing"))?.remove("signature");
        Ok(json!({"domain":DOMAIN,"body":body}))
    }
    fn aad(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(DOMAIN, &self.id))?)
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid(TOO_LARGE));
        }
        Ok(bytes)
    }
}
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(reason.into())
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
        if input.body.len() > MAX_PACKET_BYTES {
            return Err(invalid(TOO_LARGE));
        }
        let root = self.surface_local_root_commitment()?;
        let manifest = self
            .cache_verified_device_manifest(&engine.config, &root, "own_device_message")
            .await?;
        let source = engine.config.device_id.clone();
        if !manifest.devices.iter().any(|d| d.device_id == source) {
            return Err(invalid("own-device source is not active"));
        }
        let targets =
            manifest.devices.into_iter().filter(|d| d.device_id != source).collect::<Vec<_>>();
        if targets.is_empty() {
            return Ok(None);
        }
        let context = PrivateContext {
            message: input.id.into(),
            principal: engine.config.principal_id.clone(),
            root,
            source: source.clone(),
            conversation: input.conversation.into(),
            group: input.group.map(str::to_owned),
            created_at: input.created_at,
            expires_at: input.created_at.saturating_add(600),
        };
        let mut packet = OwnDeviceMessage {
            schema: DOMAIN.into(),
            id: copy_id(&context.root, &source, input.id)?,
            nonce: ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..12]),
            ciphertext: String::new(),
            slots: Vec::new(),
            signature: String::new(),
        };
        let mut plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&context)?);
        plaintext.push(b'\n');
        plaintext.extend_from_slice(input.body);
        let key = zeroize::Zeroizing::new(ramflux_crypto::random_32()?);
        let nonce = ramflux_protocol::decode_base64url(&packet.nonce)
            .map_err(|_| invalid("own-device nonce"))?;
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| invalid("own-device key"))?;
        packet.ciphertext = ramflux_protocol::encode_base64url(
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload { msg: &plaintext, aad: &packet.aad()? },
                )
                .map_err(|_| invalid("own-device encryption failed"))?,
        );
        for target in targets {
            let request: LocalBusMessageSubmitRequest = serde_json::from_value(
                json!({"conversation_id":packet.id,"message_id":packet.id,"envelope_id":packet.id,"source_principal_id":context.principal,"sender_id":source,"recipient_device_id":target.device_id,"recipient_principal_commitment":context.root,"target_delivery_id":target.target_delivery_id,"encrypted_body_base64":"","created_at":input.created_at,"ttl":600}),
            )?;
            let message = request.into_gateway_message_with_body(Vec::new());
            let slot = self.make_pair_object_slot(engine, &message, &packet.id, &key, "").await?;
            packet.slots.push(OwnKeySlot {
                recipient_device_id: slot.recipient_device_id,
                x3dh: slot.x3dh,
                ciphertext: slot.ciphertext,
            });
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
        if bytes.starts_with(b"ramflux.own_device_message.v1\n") {
            return Err(invalid("legacy own-device message requires a fresh copy"));
        }
        let Some(raw) = bytes.strip_prefix(PREFIX) else { return Ok(false) };
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid(TOO_LARGE));
        }
        let packet: OwnDeviceMessage = ramflux_protocol::parse_i_json(raw)?;
        packet.validate(entry)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if entry.envelope.source_principal_id != local.principal_id {
            return Err(invalid("own-device principal mismatch"));
        }
        let root = self.surface_local_root_commitment()?;
        let now = now_unix_timestamp();
        let db = self.account_db()?;
        db.retain_expiring_actor_states(RECEIPTS, now, 4096)?;
        let receipt_key = format!("{RECEIPTS}{}", packet.id);
        let fingerprint = ramflux_protocol::hash_base64url(DOMAIN, &bytes);
        if let Some(old) = db.load_actor_state::<Receipt>(&receipt_key)? {
            old.validate(&entry.envelope.source_device_id, &local.device_id, &fingerprint, now)?;
            return Ok(true);
        }
        let manifest = self
            .cache_verified_device_manifest(gateway, &root, "own_device_message_receive")
            .await?;
        let source = manifest
            .devices
            .iter()
            .find(|d| d.device_id == entry.envelope.source_device_id)
            .ok_or_else(|| invalid("own-device sender is not active"))?;
        if !manifest.devices.iter().any(|d| d.device_id == local.device_id) {
            return Err(invalid("own-device recipient is not active"));
        }
        ramflux_crypto::verify_device_branch_signature(
            &source.branch_public_key,
            &packet.signing()?,
            &packet.signature,
        )?;
        let recipient = packet.recipient_slot(&local.device_id)?;
        let slot = recipient.object_slot(&packet.id, &manifest.principal_commitment);
        if slot.ciphertext.sender_device_id_hash
            != dm_device_id_hash(&entry.envelope.source_device_id)
        {
            return Err(invalid("own-device key slot scope mismatch"));
        }
        let mut deferred = match self.decrypt_object_key_slot(&slot) {
            Ok(deferred) => deferred,
            Err(SdkError::PairRecoveryRequired) => {
                self.begin_pair_recovery(
                    &self.owned_device_identity()?,
                    &self.authenticated_device_identity(entry)?,
                    now,
                )?;
                return Err(SdkError::PairRecoveryRequired);
            }
            Err(error) => return Err(error),
        };
        let key = zeroize::Zeroizing::new(deferred.object_key);
        deferred.object_key.zeroize();
        let (context, body) = packet.open(&key)?;
        context.validate(
            &packet.id,
            &local.principal_id,
            &root,
            &entry.envelope.source_device_id,
            now,
        )?;
        db.write_transaction(|| {
            // The packet signature and root-signed active set above authenticate this source;
            // generic envelope signatures are not the own-device packet's signature scheme.
            let source_identity =
                self.device_identity_for_root(&root, &entry.envelope.source_device_id)?;
            if !self.receive_surface_control_from(
                entry,
                &source_identity,
                &context.conversation,
                context.group.as_deref(),
                &body,
            )? {
                return Err(invalid("unsupported own-device control"));
            }
            self.commit_inline_pair_key_slot(&slot, &key)?;
            db.persist_actor_state(
                &receipt_key,
                &Receipt {
                    fingerprint,
                    source: context.source.clone(),
                    target: local.device_id.clone(),
                    valid_until: context.expires_at,
                    expires_at: context.expires_at.saturating_add(300),
                },
            )?;
            db.retain_expiring_actor_states(RECEIPTS, now, 4096)?;
            Ok::<_, SdkError>(())
        })?;
        Ok(true)
    }
}
pub(crate) fn copy_id(root: &str, source: &str, message: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&(root, source, message))?,
    ))
}
