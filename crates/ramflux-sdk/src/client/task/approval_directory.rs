// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded task approval read-model scans over private packet keys.
use super::{approval::Packet, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::NeedsMe;
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn task_remote_approval_page(
        &self,
        after: &str,
        limit: u32,
    ) -> Result<Vec<(String, Option<Value>)>, SdkError> {
        let db = self.account_db()?;
        // Use both namespace bounds on the primary-key index. Even the final short page
        // must not scan unrelated task or message state after this namespace.
        db.actor_state_key_page_after("task/approval_in/", after, limit.min(101))?
            .into_iter()
            .map(|key| {
                let row = db
                    .load_actor_state::<Packet>(&key)?
                    .map(|packet| self.task_remote_approval_row(&packet))
                    .transpose()?
                    .flatten();
                Ok((key, row))
            })
            .collect()
    }
    pub(crate) fn task_remote_approval_by_id(&self, id: &str) -> Result<Option<Value>, SdkError> {
        let Some(id) = id.strip_prefix("task_approval_") else {
            return Ok(None);
        };
        self.account_db()?
            .load_actor_state::<Packet>(&key("approval_in", id))?
            .map(|packet| self.task_remote_approval_row(&packet))
            .transpose()
            .map(Option::flatten)
    }
    pub(crate) fn task_remote_approvals(&self) -> Result<Vec<Value>, SdkError> {
        let mut result = Vec::new();
        let mut after = String::new();
        let mut scanned = 0;
        loop {
            // Legacy callers get a finite scan; cursor callers advance over skipped rows.
            let page = self.task_remote_approval_page(&after, (1025_u32 - scanned).min(101))?;
            if page.is_empty() {
                break;
            }
            for (key, row) in page {
                scanned += 1;
                if scanned > 1024 {
                    return Err(invalid("legacy approval scan limit; use cursor/limit"));
                }
                after = key;
                if let Some(row) = row {
                    result.push(row);
                }
            }
        }
        Ok(result)
    }
    fn task_remote_approval_row(&self, packet: &Packet) -> Result<Option<Value>, SdkError> {
        let db = self.account_db()?;
        let local = self
            .device_branch
            .as_ref()
            .map(|branch| branch.principal_id.clone())
            .or(db
                .client_record("self", "account")?
                .and_then(|row| row["principal_id"].as_str().map(str::to_owned)))
            .ok_or(SdkError::IdentityRootMissing)?;
        let id = packet.id()?;
        let request = packet.request();
        if request.binding.requester != local
            || packet.deadline() <= crate::time::now_unix_timestamp()
            || db.actor_state_exists(&key("approval_decision_in", &id))?
        {
            return Ok(None);
        }
        let target = NeedsMe::Approval { grant_id: request.grant_body.grant_id.clone() };
        if self
            .task_approval_binding(
                &request.binding.conversation_id,
                &request.binding.task_id,
                &request.binding.step_id,
                &target,
            )
            .ok()
            .as_ref()
            != Some(&request.binding)
        {
            return Ok(None);
        }
        let mut value = serde_json::to_value(&request.approval)?;
        value["confirmation_mode"] = json!("task_requester");
        value["risk_level"] = serde_json::to_value(request.grant_body.capability.default_risk())?;
        value["expires_at"] = json!(packet.deadline());
        value["details"] = json!({"arguments":request.approval.details["arguments"],"arguments_hash":request.grant_body.arguments_hash,"single_use":request.grant_body.single_use,"full_delegation":request.grant_body.full_delegation,"task_binding":request.binding});
        value["approval_id"] = json!(format!("task_approval_{id}"));
        value["id"] = value["approval_id"].clone();
        value["conversation_id"] = json!(request.binding.conversation_id);
        value["decision_id"] = json!(request.approval.approval_id);
        value["task_binding"] = serde_json::to_value(&request.binding)?;
        value["grant_id"] = json!(request.grant_body.grant_id);
        value["details"]["requested_grant_id"] = json!(request.grant_body.grant_id);
        Ok(Some(value))
    }
}
