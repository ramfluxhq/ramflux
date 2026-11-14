// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group authorization and additive conversation-link projection after authentication.
use super::{GatewayInboxEntry, RamfluxClient, SdkError, invalid};
use crate::client::identity_authority::HeadUse;
use serde_json::{Value, json};
use std::collections::BTreeSet;
impl RamfluxClient {
    pub(crate) fn require_routed_group_member(
        &self,
        group: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if !self
            .local_is_group_member(group)
            .map_err(|error| SdkError::InboundPending(error.to_string()))?
        {
            return Err(SdkError::InboundPending(
                "local group membership not yet available".to_owned(),
            ));
        }
        if let Some(state) = self.account_db()?.shared_group_state(group)? {
            self.ensure_shared_group_device(
                &state,
                &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
            )?;
            self.ensure_shared_group_device(&state, &self.owned_device_identity()?)?;
        }
        self.pin_local_group_member(group)?;
        self.require_group_sender_pin(
            group,
            &entry.envelope.source_principal_id,
            &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
        )?;
        Ok(())
    }
    pub(crate) fn merge_routed_group_link(
        &self,
        group: &str,
        conversation: &str,
    ) -> Result<(), SdkError> {
        ramflux_protocol::message::dm_scope::validate_group(conversation)
            .map_err(|_| invalid("reserved DM conversation namespace"))?;
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
    #[cfg(test)]
    pub(crate) fn v2_blocks_legacy(&self, remote: &str) -> Result<bool, SdkError> {
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        Ok(self
            .active_pair(&self.local_device_identity(local)?, &self.device_identity(remote)?)?
            .is_some())
    }
}
