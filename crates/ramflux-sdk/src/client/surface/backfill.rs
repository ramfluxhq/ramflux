// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Finish deferred content projections using authenticated device and envelope provenance.
use super::{Carrier, Outcome, invalid, key, origin::Origin};
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
        let row = db
            .client_message_metadata(message)?
            .ok_or_else(|| invalid("surface message metadata missing"))?;
        let device =
            row["sender_id"].as_str().ok_or_else(|| invalid("surface message sender missing"))?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let origin = if let Some(origin) = db.load_actor_state::<Origin>(&key("origin", message))? {
            origin
        } else if let Some(group) = db
            .client_record("conversation", conversation)?
            .and_then(|thread| thread["group_id"].as_str().map(str::to_owned))
        {
            let source = self
                .group_route_identity(&group, device)?
                .ok_or_else(|| invalid("surface sender root binding unavailable"))?;
            let record = db
                .client_device_record(&source)?
                .ok_or_else(|| invalid("surface sender device unavailable"))?;
            let principal = record["principal_id"]
                .as_str()
                .ok_or_else(|| invalid("surface sender principal unavailable"))?
                .to_owned();
            Origin {
                principal,
                device: device.into(),
                envelope_id: message.into(),
                expires_at: i64::MAX,
                group_epoch: None,
            }
        } else {
            let carrier =
                Carrier::decode(&bytes)?.ok_or_else(|| invalid("surface origin unavailable"))?;
            self.verify_surface_carrier(
                &carrier,
                &carrier.sender_principal_id,
                &carrier.sender_device_id,
            )?;
            Origin {
                principal: carrier.sender_principal_id,
                device: carrier.sender_device_id,
                envelope_id: message.into(),
                expires_at: i64::MAX,
                group_epoch: None,
            }
        };
        let principal = origin.principal.clone();
        let source = self.peer_device_identity(&principal, &origin.device)?;
        db.surface_transaction(|| {
            let sender = origin.sender();
            let outcome = if let Ok(Some(carrier)) = Carrier::decode(&bytes) {
                let thread = db
                    .client_record("conversation", conversation)?
                    .ok_or_else(|| invalid("surface conversation missing"))?;
                let member = if let Some(group) = thread["group_id"].as_str() {
                    db.group_member_role(group, &source)?.is_some()
                        && db.group_member_role(group, &self.owned_device_identity()?)?.is_some()
                } else {
                    thread["participants"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id == &principal))
                };
                if member
                    && origin.device == device
                    && origin.principal == principal
                    && carrier.sender_device_id == device
                    && carrier.sender_principal_id == principal
                {
                    self.project_surface_message(
                        conversation,
                        message,
                        sender,
                        &bytes,
                        device == local.device_id && principal == local.principal_id,
                    )?
                    .ok_or_else(|| invalid("surface carrier disappeared"))?
                } else {
                    let error = json!({"code":"surface_sender_or_membership_mismatch"});
                    self.surface_error(conversation, message, sender, None, &error)?;
                    Outcome::rejected(error)
                }
            } else {
                let error = json!({"code":"invalid_carrier"});
                self.surface_error(conversation, message, sender, None, &error)?;
                Outcome::rejected(error)
            };
            db.replace_surface_message_content(
                conversation,
                message,
                outcome.fallback_text.as_bytes(),
            )?;
            Ok(())
        })
    }
}
