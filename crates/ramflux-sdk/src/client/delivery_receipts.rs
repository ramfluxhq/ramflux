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
pub(super) fn origin_key(conversation: &str, message: &str) -> Result<String, SdkError> {
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
        let local = match self.owned_device_identity() {
            Ok(local) => local,
            // A receipt is auxiliary: legacy SDK clients without a local root must still
            // commit the authenticated message, and cannot sign a peer receipt yet.
            Err(SdkError::IdentityRootMissing) => return Ok(()),
            Err(error) => return Err(error),
        };
        let source = self.authenticated_device_identity(entry)?;
        let db = self.account_db()?;
        let device = self.trusted_device(&source)?;
        let root = Some(source.root_commitment().to_owned());
        if source.root_commitment() == local.root_commitment() {
            db.persist_actor_state(&origin_key(conversation, message)?, &json!({
                "sender_device_id":source.device_id(),"sender_root_commitment":source.root_commitment(),
                "sender_device_display":source.storage_key(),"direction":"outgoing",
                "envelope_id":entry.envelope.envelope_id
            }))?;
            return Ok(());
        }
        if entry.envelope.source_principal_id == local_branch.principal_id {
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
        db.persist_receipt_state(&status_key, &json!({"state":"pending","delivered_at":at}), at)?;
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

impl RamfluxClient {
    pub(crate) fn restage_failed_delivery_receipt(
        &self,
        conversation: &str,
        message: &str,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Option<i64>, SdkError> {
        if local != &self.owned_device_identity()? {
            return Err(SdkError::InboundRejected("receipt retry is not the owned device".into()));
        }
        let status_id = id(conversation, message, local)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            db.reserve_receipt_write()?;
            let status_key = format!("delivery-receipt/status/{status_id}");
            let Some(status) = db.load_actor_state::<Value>(&status_key)? else { return Ok(None) };
            if status["state"] != "failed" {
                return Ok(None);
            }
            let mut work: Work = if status["retry_work"].is_null() {
                // Older failed statuses predate saved retry work. Their existing authenticated
                // origin still identifies the peer; retain the legacy logical-message receipt.
                let Some(origin) = self.message_origin(conversation, message)? else {
                    return Ok(None);
                };
                let (Some(root), Some(sender)) = (
                    origin["sender_root_commitment"].as_str(),
                    origin["sender_device_id"].as_str(),
                ) else {
                    return Ok(None);
                };
                let source = self.device_identity_for_root(root, sender)?;
                Work {
                    status_id: status_id.clone(),
                    conversation: conversation.into(),
                    message: message.into(),
                    wire_message: None,
                    receiver: local.storage_key().into(),
                    sender: source.storage_key().into(),
                    root: Some(root.into()),
                    at: 0,
                    attempts: 0,
                    next_at: 0,
                    packet: None,
                }
            } else {
                serde_json::from_value(status["retry_work"].clone())?
            };
            if work.conversation != conversation
                || work.message != message
                || work.receiver != local.storage_key()
            {
                return Err(SdkError::InboundRejected("receipt retry binding differs".into()));
            }
            work.at = now_unix_timestamp();
            work.next_at = work.at;
            work.attempts = 0;
            work.packet = None;
            db.persist_actor_state(&format!("{PREFIX}{status_id}"), &work)?;
            db.persist_receipt_state(
                &status_key,
                &json!({"state":"pending","delivered_at":work.at}),
                work.at,
            )?;
            Ok(Some(work.at))
        })
    }
}
