// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group authorization and additive conversation-link projection after authentication.
use super::{GatewayInboxEntry, RamfluxClient, SdkError, SdkGroupEncryptedEnvelope, invalid};
use serde_json::{Value, json};
use std::collections::BTreeSet;
impl RamfluxClient {
    pub(super) fn require_routed_group_member(
        &self,
        group: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let state =
            self.group_state(group).map_err(|error| SdkError::InboundPending(error.to_string()))?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if !state.members.contains(&local.device_id) {
            return Err(SdkError::InboundPending(
                "local group membership not yet available".to_owned(),
            ));
        }
        self.pin_local_group_member(group)?;
        self.require_group_sender_pin(
            group,
            &entry.envelope.source_principal_id,
            &entry.envelope.source_device_id,
        )?;
        Ok(())
    }
    pub(super) fn merge_routed_group_link(
        &self,
        group: &str,
        conversation: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let mut record = db.client_record("group", group)?.unwrap_or_else(|| json!({}));
        let mut links = record
            .get("conversation_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if let Some(id) = record.get("conversation_id").and_then(Value::as_str) {
            links.insert(id.to_owned());
        }
        links.insert(conversation.to_owned());
        record["conversation_id"] =
            if links.len() == 1 { json!(conversation) } else { Value::Null };
        record["conversation_ids"] = json!(links);
        db.persist_client_record("group", group, &record)?;
        let mut thread = db
            .client_record("conversation", conversation)?
            .unwrap_or_else(|| json!({"title":null,"direct_route":null}));
        thread["kind"] = json!("group");
        thread["group_id"] = json!(group);
        db.persist_client_record("conversation", conversation, &thread)?;
        Ok(())
    }
    pub(crate) fn legacy_group_binding(
        &self,
        conversation: &str,
        group: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        if self.v2_blocks_legacy(&self.inbound_device_reference(entry)?)? {
            return Ok(false);
        }
        let Some(thread) = self.account_db()?.client_record("conversation", conversation)? else {
            return Ok(false);
        };
        if thread["kind"] != "group" || thread["group_id"] != group {
            return Ok(false);
        }
        let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| invalid("invalid legacy group encoding"))?;
        if let Ok(envelope) = serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&bytes) {
            return Ok(envelope.group_id == group);
        }
        Ok(self
            .legacy_routing_binding(
                &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id,
                entry,
            )?
            .as_deref()
            == Some(conversation))
    }
    pub(crate) fn v2_blocks_legacy(&self, remote: &str) -> Result<bool, SdkError> {
        if std::env::var("RAMFLUX_ALLOW_LEGACY_V1").as_deref() == Ok("1") {
            return Ok(false);
        }
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        Ok(self.active_pair(local, remote)?.is_some())
    }
}
