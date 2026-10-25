// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable delivery intents created only with authenticated, stored peer messages.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub(crate) const PREFIX: &str = "delivery-receipt/pending/";
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Work {
    #[serde(default)]
    pub status_id: String,
    pub conversation: String,
    pub message: String,
    #[serde(default)]
    pub wire_message: Option<String>,
    pub receiver: String,
    pub sender: String,
    pub root: Option<String>,
    pub at: i64,
    pub attempts: u32,
    pub next_at: i64,
    pub packet: Option<ramflux_protocol::Envelope>,
}
pub(crate) fn id(
    conversation: &str,
    message: &str,
    receiver: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<String, SdkError> {
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.delivery-receipt.v1",
        &ramflux_protocol::canonical_json_bytes(&(conversation, message, receiver.storage_key()))?,
    ))
}
fn origin_key(conversation: &str, message: &str) -> Result<String, SdkError> {
    Ok(format!(
        "message/origin/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.delivery-receipt.v1",
            &ramflux_protocol::canonical_json_bytes(&(conversation, message, ""))?
        )
    ))
}
impl RamfluxClient {
    pub(crate) fn message_origin(
        &self,
        conversation: &str,
        message: &str,
    ) -> Result<Option<Value>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&origin_key(conversation, message)?)?)
    }
    pub(crate) fn stage_delivery_receipt(
        &self,
        conversation: &str,
        message: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let Some(local_branch) = self.device_branch.as_ref() else {
            return Ok(());
        };
        let local = self.owned_device_identity()?;
        let source = self.authenticated_device_identity(entry)?;
        let db = self.account_db()?;
        let device = self.trusted_device(&source)?;
        let root = Some(source.root_commitment().to_owned());
        if entry.envelope.source_principal_id == local_branch.principal_id
            || source.root_commitment() == local.root_commitment()
        {
            return Ok(());
        }
        let key = id(conversation, message, &local)?;
        let status_key = format!("delivery-receipt/status/{key}");
        if db.actor_state_exists(&status_key)? {
            return Ok(());
        }
        let at = now_unix_timestamp();
        let work = Work {
            status_id: key.clone(),
            conversation: conversation.into(),
            message: message.into(),
            wire_message: Some(entry.envelope.envelope_id.clone()),
            receiver: local.storage_key().into(),
            sender: source.storage_key().into(),
            root: root.clone(),
            at,
            attempts: 0,
            next_at: at,
            packet: None,
        };
        let sender = source.device_id();
        let label = device["label"].as_str().unwrap_or(sender);
        db.persist_actor_state(&origin_key(conversation, message)?, &json!({"sender_device_id":sender,"sender_root_commitment":root,"sender_device_display":root.as_ref().map(|root|format!("{label}@{root}"))}))?;
        db.persist_actor_state(&format!("{PREFIX}{key}"), &work)?;
        db.persist_actor_state(&status_key, &json!({"state":"pending","delivered_at":at}))?;
        Ok(())
    }
    pub(crate) fn delivery_receipt_status(
        &self,
        conversation: &str,
        message: &str,
        receiver: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Option<Value>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&format!(
            "delivery-receipt/status/{}",
            id(conversation, message, receiver)?
        ))?)
    }
}
