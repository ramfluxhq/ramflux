// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed group wrapper around the existing sender-key primitive (OV-GROUP-AUTHOR).
use crate::{RamfluxClient, SdkError};
use crate::group::SdkGroupEncryptedEnvelope;
use prost::Message as _;
use ramflux_protocol::message as g;

fn refused(detail: &str) -> SdkError { SdkError::InboundRejected(format!("generated group: {detail}")) }
fn decode_hash(value: &str) -> Result<Vec<u8>, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| refused("invalid native hash"))?;
    if bytes.len() != 32 { return Err(refused("native hash must be 32 bytes")); }
    Ok(bytes)
}
fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], SdkError> {
    value.try_into().map_err(|_| refused("native crypto field size mismatch"))
}
fn hash(value: &[u8]) -> Result<String, SdkError> {
    fixed::<32>(value)?;
    Ok(ramflux_protocol::encode_base64url(value))
}

pub(crate) fn to_native(value: &g::GroupSealedContent) -> Result<SdkGroupEncryptedEnvelope, SdkError> {
    if !value.native_authority_proof.is_empty() { return Err(refused("embedded author proof is forbidden in v1")); }
    let author = value.author.as_ref().ok_or_else(|| refused("author missing"))?;
    if value.content_commitment != value.commitment { return Err(refused("content commitment mismatch")); }
    let head = if value.group_state_hash.is_empty() { None } else { Some(hash(&value.group_state_hash)?) };
    Ok(SdkGroupEncryptedEnvelope {
        schema: if head.is_some() { "ramflux.sdk.group_sender_key.message.v2" } else { "ramflux.sdk.group_sender_key.message.v1" }.into(),
        version: if head.is_some() { 2 } else { 1 }, group_id: value.group_id.clone(), sender_id: author.device_id.clone(),
        group_key_epoch: value.key_epoch, group_state_hash: head,
        ciphertext: ramflux_crypto::DmCiphertext {
            session_id: hash(&value.session_id)?, counter: value.counter, nonce: fixed(&value.nonce)?, ciphertext: value.ciphertext.clone(),
            ratchet_public_key: if value.ratchet_public_key.is_empty() { None } else { Some(fixed(&value.ratchet_public_key)?) },
            previous_chain_length: value.previous_chain_length,
            sender_device_id_hash: fixed(&value.sender_device_hash)?, recipient_device_id_hash: fixed(&value.recipient_device_hash)?,
            device_epoch: value.device_epoch, message_event_id: String::from_utf8(value.event_id.clone()).map_err(|_| refused("native event id is not UTF-8"))?,
            canonical_header_bytes: value.canonical_crypto_header.clone(), header_hash: hash(&value.header_hash)?,
            key_commitment: hash(&value.key_commitment)?, franking_commitment: hash(&value.franking_commitment)?,
            commitment: hash(&value.commitment)?, ciphertext_hash: hash(&value.ciphertext_hash)?,
        },
    })
}

fn from_native(value: SdkGroupEncryptedEnvelope, author: g::QualifiedDevice) -> Result<g::Message, SdkError> {
    let cipher = value.ciphertext;
    let commitment = decode_hash(&cipher.commitment)?;
    Ok(g::Message { sealed_group: Some(g::GroupSealedContent {
        group_id: value.group_id, author: Some(author), key_epoch: value.group_key_epoch,
        group_state_hash: value.group_state_hash.as_deref().map(decode_hash).transpose()?.unwrap_or_default(),
        session_id: decode_hash(&cipher.session_id)?, counter: cipher.counter, nonce: cipher.nonce.to_vec(), ciphertext: cipher.ciphertext,
        ratchet_public_key: cipher.ratchet_public_key.map_or_else(Vec::new, |key| key.to_vec()), previous_chain_length: cipher.previous_chain_length,
        canonical_crypto_header: cipher.canonical_header_bytes, key_commitment: decode_hash(&cipher.key_commitment)?,
        content_commitment: commitment.clone(), ciphertext_hash: decode_hash(&cipher.ciphertext_hash)?, native_authority_proof: Vec::new(),
        sender_device_hash: cipher.sender_device_id_hash.to_vec(), recipient_device_hash: cipher.recipient_device_id_hash.to_vec(),
        device_epoch: cipher.device_epoch, event_id: cipher.message_event_id.into_bytes(), header_hash: decode_hash(&cipher.header_hash)?,
        franking_commitment: decode_hash(&cipher.franking_commitment)?, commitment,
    }), ..Default::default() })
}

impl RamfluxClient {
    pub(crate) fn check_generated_group_source(
        &self,
        group: &g::GroupSealedContent,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        entry: &crate::GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if !group.native_authority_proof.is_empty() {
            return Err(refused("embedded author proof is forbidden in v1"));
        }
        let author = group.author.as_ref().ok_or_else(|| refused("author missing"))?;
        if author.account_anchor != source.root_commitment() || author.device_id != source.device_id() {
            return Err(refused("author differs from pair-session peer"));
        }
        let record = self.account_db()?.client_device_record(source)?.ok_or_else(|| refused("author device authority missing"))?;
        if record["device_epoch"].as_u64() != Some(author.device_epoch) { return Err(refused("author epoch mismatch")); }
        self.require_routed_group_member(&group.group_id, entry)?;
        if !self.group_state(&group.group_id)?.members.contains(source.device_id()) {
            return Err(refused("author is not a current member"));
        }
        self.require_generated_group_epoch(&group.group_id, source, group.key_epoch, false)?;
        let head = if group.group_state_hash.is_empty() { None } else { Some(hash(&group.group_state_hash)?) };
        self.validate_group_key_head(&group.group_id, group.key_epoch, head.as_deref())?;
        let state = self.load_group_key_at_head(&group.group_id, source, group.key_epoch, "recv", head.as_deref())?;
        let expected = state.group_state_hash.as_deref().map(decode_hash).transpose()?.unwrap_or_default();
        if group.group_state_hash != expected { return Err(refused("group state hash differs from pinned epoch")); }
        Ok(())
    }

    pub(crate) fn require_generated_group_epoch(&self, group: &str, source: &ramflux_crypto::RootQualifiedDeviceRef, epoch: u64, moderator: bool) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if let Some(current) = db.shared_group_state(group)? {
            let role = current.view().effective_role(source.root_commitment(), source.device_id())
                .ok_or_else(|| refused("source has no current group role"))?;
            let admin = |role| matches!(role, ramflux_protocol::SharedGroupRole::Owner | ramflux_protocol::SharedGroupRole::Admin);
            if moderator && !admin(role) { return Err(refused("source is not a current moderator")); }
            let historical = db.shared_group_state_at_epoch(group, epoch)?
                .ok_or_else(|| SdkError::InboundPending("named group epoch snapshot is not verified locally".into()))?;
            let past_role = historical.view().effective_role(source.root_commitment(), source.device_id())
                .ok_or_else(|| refused("source was not a member at named epoch"))?;
            if moderator && !admin(past_role) { return Err(refused("source was not a moderator at named epoch")); }
        } else {
            let role = db.group_member_role(group, source)?.ok_or_else(|| refused("source has no current group role"))?;
            if moderator && !matches!(role.as_str(), "owner" | "admin") { return Err(refused("source is not a current moderator")); }
            if db.group_member_joined_epoch(group, source)?.is_none_or(|joined| joined > epoch) { return Err(refused("source was not a member at named epoch")); }
        }
        Ok(())
    }

    /// Encrypt an exact generated Message through the native group primitive, then wrap it.
    /// # Errors
    /// Refuses recursive group wrapping, invalid content, membership/key or crypto failures.
    pub fn encrypt_generated_group_message(&self, group: &str, sender: &str, message: &g::Message) -> Result<g::Message, SdkError> {
        g::validation::validate_message(message).map_err(|_| refused("invalid group Message"))?;
        if message.sealed_group.is_some() { return Err(refused("recursive sealed group")); }
        let exact = zeroize::Zeroizing::new(message.encode_to_vec());
        let native = self.encrypt_group_message(group, sender, &exact)?;
        let source = self.local_device_identity(sender)?;
        from_native(serde_json::from_slice(&native)?, g::QualifiedDevice {
            account_anchor: source.root_commitment().into(), device_id: source.device_id().into(),
            device_epoch: self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch,
        })
    }
}
