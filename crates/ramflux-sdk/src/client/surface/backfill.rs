// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Finish deferred content projections at the account writer's outbox boundary.
use super::{Carrier, Outcome, SurfaceSender, invalid, key};
use crate::{RamfluxClient, SdkError};
use serde_json::json;
impl RamfluxClient {
    pub(crate) fn project_deferred_surface(
        &self,
        conversation: &str,
        message: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let Some(bytes) = db.message_content(message)? else {
            return Ok(());
        };
        if !bytes.starts_with(super::carrier::PREFIX) {
            return Ok(());
        }
        db.surface_transaction(|| {
            let outcome = if let Ok(Some(carrier)) = Carrier::decode(&bytes) {
                let row = db.client_message_metadata(message)?.ok_or_else(|| invalid("surface message metadata missing"))?;
                let source = row["sender_id"].as_str().ok_or_else(|| invalid("surface message sender missing"))?;
                let thread = db.client_record("conversation",conversation)?.ok_or_else(|| invalid("surface conversation missing"))?;
                let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                let outbound = source == local.device_id || source == local.principal_id;
                let valid_sender = if let Some(group) = thread["group_id"].as_str() {
                    let members = self.group_state(group)?.members;
                    source == carrier.sender_device_id && members.contains(source)
                        && (members.contains(&local.device_id) || members.contains(&local.principal_id))
                } else {
                    (source == carrier.sender_device_id || source == carrier.sender_principal_id)
                        && thread["participants"].as_array().is_some_and(|ids| ids.iter().any(|id| id == &carrier.sender_principal_id))
                };
                if valid_sender {
                    self.project_surface_message(conversation,message,SurfaceSender { principal: &carrier.sender_principal_id, device: &carrier.sender_device_id },&bytes,outbound)?.ok_or_else(|| invalid("surface carrier disappeared"))?
                } else {
                    let error = json!({"code":"surface_member_removed"});
                    self.surface_error(conversation,message,Some(&carrier.surface_id),&error)?;
                    let result = Outcome::rejected(error);
                    db.persist_actor_state(&key("message",message),&json!({"surface_id":carrier.surface_id,"accepted":false,"fallback_text":result.fallback_text}))?;
                    result
                }
            } else {
                let error = json!({"code":"invalid_carrier"});
                self.surface_error(conversation,message,None,&error)?;
                Outcome::rejected(error)
            };
            db.replace_surface_message_content(conversation,message,outcome.fallback_text.as_bytes())?;
            Ok(())
        })
    }
}
