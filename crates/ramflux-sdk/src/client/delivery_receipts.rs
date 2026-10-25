// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable delivery intents created only with authenticated, stored peer messages.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub(crate) const PREFIX: &str = "delivery-receipt/pending/";
pub(crate) const MAX_PENDING: u32 = 256;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Work {
    pub conversation: String,
    pub message: String,
    pub receiver: String,
    pub sender: String,
    pub root: Option<String>,
    pub at: i64,
    pub attempts: u32,
    pub next_at: i64,
    pub packet: Option<ramflux_protocol::Envelope>,
}
pub(crate) fn id(conversation: &str, message: &str, receiver: &str) -> Result<String, SdkError> {
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.delivery-receipt.v1",
        &ramflux_protocol::canonical_json_bytes(&(conversation, message, receiver))?,
    ))
}
fn origin_key(conversation: &str, message: &str) -> Result<String, SdkError> {
    Ok(format!("message/origin/{}", id(conversation, message, "")?))
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
        let Some(local) = self.device_branch.as_ref() else { return Ok(()) };
        let db = self.account_db()?;
        let sender = &entry.envelope.source_device_id;
        let device = db.client_record("device", sender)?.unwrap_or_else(|| json!({}));
        let root = device["principal_commitment"]
            .as_str()
            .map(str::to_owned)
            .or(db.device_directory_entry(sender)?.map(|entry| entry.principal_commitment));
        let own_root = self.surface_local_root_commitment()?;
        if entry.envelope.source_principal_id == local.principal_id
            || sender == &local.device_id
            || root.as_deref() == Some(&own_root)
        {
            return Ok(());
        }
        let key = id(conversation, message, &local.device_id)?;
        let status_key = format!("delivery-receipt/status/{key}");
        if db.actor_state_exists(&status_key)? {
            return Ok(());
        }
        let (rows, bytes) = db.actor_state_usage(PREFIX)?;
        if rows >= u64::from(MAX_PENDING) || bytes >= 1024 * 1024 {
            // The enclosing receive transaction rolls back; normal inbox backoff retries admission.
            return Err(SdkError::InboundPending("delivery receipt queue full".into()));
        }
        let at = now_unix_timestamp();
        let work = Work {
            conversation: conversation.into(),
            message: message.into(),
            receiver: local.device_id.clone(),
            sender: sender.clone(),
            root: root.clone(),
            at,
            attempts: 0,
            next_at: at,
            packet: None,
        };
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
        receiver: &str,
    ) -> Result<Option<Value>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&format!(
            "delivery-receipt/status/{}",
            id(conversation, message, receiver)?
        ))?)
    }
}
