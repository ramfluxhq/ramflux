// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private per-message own-device controls with opaque, pair-wrapped recipient key slots.
use crate::client::identity_authority::NativeOperation;
use crate::prelude::*;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroize;
pub(crate) const DOMAIN: &str = "ramflux.sdk.own_device_message.v2";
#[cfg(test)]
pub(crate) const PREFIX: &[u8] = b"ramflux.own_device_message.v2\n";
pub(crate) const MAX_PACKET_BYTES: usize = 512 * 1024;
pub(crate) const TOO_LARGE: &str = "own-device message byte budget exceeded";
pub(crate) mod receipts;
pub(crate) use receipts::MAX_DELIVERY_ROWS;
mod generated;
mod generated_authority;
pub(crate) mod w1;
pub(super) const RECEIPTS: &str = "own-device/message-receipt/";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnDeviceMessage {
    pub schema: String,
    pub id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub slots: Vec<OwnKeySlot>,
    pub signature: String,
    #[serde(skip)]
    pub(crate) context_delivery: Option<super::surface::OwnContextDelivery>,
}
/// Only the recipient selector and cryptographic bootstrap are needed outside AEAD.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnKeySlot {
    pub recipient_device_id: String,
    x3dh: Option<SdkDmX3dhHeader>,
    ciphertext: ramflux_crypto::DmCiphertext,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateContext {
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
    pub(super) fn validate(
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
            || self.expires_at
                > self.created_at.saturating_add(i64::from(crate::DEFAULT_OFFLINE_RETENTION_SECS))
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
    #[serde(flatten)]
    scope: ReceiptScope,
    valid_until: i64,
    expires_at: i64,
    #[serde(default)]
    acknowledged: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ReceiptScope {
    Names { source: String, target: String },
    Private { private_scope: String },
}
impl Receipt {
    #[cfg(test)]
    fn validate(
        &self,
        db: &ramflux_storage::AccountDb,
        source: &str,
        target: &str,
        fingerprint: &str,
        now: i64,
    ) -> Result<(), SdkError> {
        let matches = match &self.scope {
            ReceiptScope::Names { source: old_source, target: old_target } => {
                old_source == source && old_target == target
            }
            ReceiptScope::Private { private_scope } => {
                *private_scope == db.own_sent_receipt_scope(source, target)?
            }
        };
        if self.valid_until < now || !matches {
            return Err(invalid("own-device replay scope or lifetime mismatch"));
        }
        if self.fingerprint != fingerprint {
            return Err(invalid("own-device message id conflict"));
        }
        Ok(())
    }
}
impl OwnDeviceMessage {
    pub(super) fn open(
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
    fn aad(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(DOMAIN, &self.id))?)
    }
}
fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(reason.into())
}
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) enum OwnPayloadKind {
    RawInner,
    /// A compared-safety confirmation carried as its own exact origin Inner.
    ContactInner,
    Sent,
    Control,
    Surface,
    Task,
}
#[derive(Clone, Copy)]
pub(crate) struct OwnMessageInput<'a> {
    pub payload_kind: OwnPayloadKind,
    pub id: &'a str,
    pub created_at: i64,
    pub conversation: &'a str,
    pub group: Option<&'a str>,
    pub body: &'a [u8],
}
pub(crate) struct OwnCopyDraft {
    group: Option<String>,
    pub(super) payload_kind: OwnPayloadKind,
    pub(crate) packet: OwnDeviceMessage,
    pub(super) key: zeroize::Zeroizing<[u8; 32]>,
    pub(super) messages: Vec<GatewayDirectMessage>,
    pub(super) source: ramflux_protocol::message::QualifiedDevice,
    pub(super) siblings: Vec<ramflux_protocol::message::QualifiedDevice>,
    pub(super) conversation: String,
    pub(super) created_at: i64,
    pub(super) expires_at: i64,
}

impl RamfluxClient {
    pub(crate) fn restrict_own_copy_target(
        draft: &mut OwnCopyDraft,
        target: &ramflux_protocol::message::QualifiedDevice,
    ) -> Result<(), SdkError> {
        draft.messages.retain(|message| {
            message.recipient_principal_commitment.as_deref()
                == Some(target.account_anchor.as_str())
                && message.recipient_device_id.as_deref() == Some(target.device_id.as_str())
        });
        draft.siblings.retain(|sibling| {
            sibling.account_anchor == target.account_anchor.as_str()
                && sibling.device_id == target.device_id.as_str()
                && sibling.device_epoch == target.device_epoch
        });
        if draft.messages.len() != 1 || draft.siblings.len() != 1 {
            return Err(invalid("own history target is not an active sibling"));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn prepare_own_copy_draft(
        &self,
        config: &GatewaySessionConfig,
        input: OwnMessageInput<'_>,
        manifest: SdkDeviceManifestResponse,
    ) -> Result<Option<OwnCopyDraft>, SdkError> {
        self.prepare_own_copy_draft_until(
            config,
            input,
            manifest,
            input.created_at.saturating_add(i64::from(self.content_ttl()?)),
        )
    }
    pub(crate) fn prepare_own_copy_draft_until(
        &self,
        config: &GatewaySessionConfig,
        input: OwnMessageInput<'_>,
        manifest: SdkDeviceManifestResponse,
        expires_at: i64,
    ) -> Result<Option<OwnCopyDraft>, SdkError> {
        if input.body.len() > MAX_PACKET_BYTES {
            return Err(invalid(TOO_LARGE));
        }
        let root = self.surface_local_root_commitment()?;
        let source = config.device_id.clone();
        self.require_native_operation(
            &self.device_identity_for_root(&root, &source)?,
            NativeOperation::Sync,
        )?;
        let source_epoch = manifest
            .devices
            .iter()
            .find(|device| device.device_id == source)
            .map(|device| device.device_epoch)
            .ok_or_else(|| invalid("own-device source is not active"))?;
        let _ = Self::candidate_target_plan(|| {
            Self::own_copy_selection_request(
                input.id,
                &source,
                &manifest,
                ramflux_protocol::message::KindId::KindMessage,
            )
        })?;
        let targets =
            manifest.devices.into_iter().filter(|d| d.device_id != source).collect::<Vec<_>>();
        if targets.is_empty() {
            return Ok(None);
        }
        let target_keys = targets
            .iter()
            .map(|target| {
                serde_json::to_string(&(
                    &target.device_id,
                    &target.target_delivery_id,
                    &target.branch_public_key,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (body, context_delivery) = if matches!(input.payload_kind, OwnPayloadKind::Surface) {
            self.prepare_own_surface_context(input.body, &target_keys)?
        } else {
            (zeroize::Zeroizing::new(input.body.to_vec()), None)
        };
        let context = PrivateContext {
            message: input.id.into(),
            principal: config.principal_id.clone(),
            root,
            source: source.clone(),
            conversation: input.conversation.into(),
            group: input.group.map(str::to_owned),
            created_at: input.created_at,
            expires_at,
        };
        let mut packet = OwnDeviceMessage {
            schema: DOMAIN.into(),
            id: copy_id(&context.root, &source, input.id)?,
            nonce: ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..12]),
            ciphertext: String::new(),
            slots: Vec::new(),
            signature: String::new(),
            context_delivery,
        };
        let mut plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&context)?);
        plaintext.push(b'\n');
        plaintext.extend_from_slice(&body);
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
        let (messages, siblings) =
            self.own_copy_target_messages(&context, &packet, &source, &targets, input.created_at)?;
        Ok(Some(OwnCopyDraft {
            group: context.group.clone(),
            payload_kind: input.payload_kind,
            packet,
            key,
            messages,
            source: generated::qualified(&context.root, &source, source_epoch),
            siblings,
            conversation: context.conversation.clone(),
            created_at: input.created_at,
            expires_at,
        }))
    }

    fn own_copy_target_messages(
        &self,
        context: &PrivateContext,
        packet: &OwnDeviceMessage,
        source: &str,
        targets: &[crate::prekey::SdkDeviceManifestEntry],
        created_at: i64,
    ) -> Result<
        (Vec<GatewayDirectMessage>, Vec<ramflux_protocol::message::QualifiedDevice>),
        SdkError,
    > {
        let mut messages = Vec::new();
        let mut siblings = Vec::new();
        for target in targets {
            self.require_native_operation(
                &self.device_identity_for_root(&context.root, &target.device_id)?,
                NativeOperation::Sync,
            )?;
            let request: LocalBusMessageSubmitRequest = serde_json::from_value(
                json!({"conversation_id":packet.id,"message_id":packet.id,"envelope_id":packet.id,"source_principal_id":context.principal,"sender_id":source,"recipient_device_id":target.device_id,"recipient_principal_commitment":context.root,"target_delivery_id":target.target_delivery_id,"encrypted_body_base64":"","created_at":created_at,"ttl":self.content_ttl()?}),
            )?;
            messages.push(request.into_gateway_message_with_body(Vec::new()));
            siblings.push(generated::qualified(
                &context.root,
                &target.device_id,
                target.device_epoch,
            ));
        }
        Ok((messages, siblings))
    }

    pub(crate) fn own_copy_material_requests(
        &self,
        config: &GatewaySessionConfig,
        draft: &OwnCopyDraft,
    ) -> Result<Vec<crate::client::routed::SendMaterialRequest>, SdkError> {
        draft
            .messages
            .iter()
            .map(|message| self.routed_send_material_request(config, message))
            .collect()
    }

    fn persist_own_device_receipt(
        &self,
        key: &str,
        context: &PrivateContext,
        fingerprint: String,
        scope: ReceiptScope,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        let owner = if matches!(scope, ReceiptScope::Private { .. }) {
            self.own_sent_receipt_owner(source, &context.message)?
        } else {
            None
        };
        self.account_db()?.persist_message_actor_state(
            owner.as_deref().unwrap_or(&context.message),
            key,
            &Receipt {
                fingerprint,
                scope,
                valid_until: context.expires_at,
                expires_at: context.expires_at.saturating_add(300),
                acknowledged: false,
            },
        )?;
        Ok(())
    }
}
pub(crate) fn copy_id(root: &str, source: &str, message: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&(root, source, message))?,
    ))
}

#[cfg(test)]
mod receipt_compatibility {
    use super::*;
    #[test]
    fn own_copy_private_context_accepts_configured_retention_and_legacy_lifetime()
    -> Result<(), SdkError> {
        let created_at = 2_000_000_000;
        let mut context = PrivateContext {
            message: "message".into(),
            principal: "principal".into(),
            root: "root".into(),
            source: "device".into(),
            conversation: "conversation".into(),
            group: None,
            created_at,
            expires_at: created_at + i64::from(crate::DEFAULT_OFFLINE_RETENTION_SECS),
        };
        let id = copy_id("root", "device", "message")?;
        context.validate(&id, "principal", "root", "device", created_at + 7200)?;
        context.expires_at += 1;
        assert!(context.validate(&id, "principal", "root", "device", created_at).is_err());
        context.expires_at = created_at + 600;
        context.validate(&id, "principal", "root", "device", created_at)?;
        Ok(())
    }
    #[test]
    fn names_and_private_receipts_default_acknowledgement_without_changing_scope()
    -> Result<(), SdkError> {
        for scope in
            [json!({"source":"source","target":"target"}), json!({"private_scope":"opaque"})]
        {
            for acknowledged in [None, Some(false), Some(true)] {
                let mut value = scope.clone();
                value["fingerprint"] = json!("fingerprint");
                value["valid_until"] = json!(600);
                value["expires_at"] = json!(900);
                if let Some(acknowledged) = acknowledged {
                    value["acknowledged"] = json!(acknowledged);
                }
                let receipt: Receipt = serde_json::from_value(value)?;
                assert_eq!(receipt.acknowledged, acknowledged.unwrap_or(false));
                let roundtrip = serde_json::to_value(receipt)?;
                for (key, value) in scope.as_object().ok_or_else(|| invalid("scope"))? {
                    assert_eq!(&roundtrip[key], value);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod rekey_tests;
