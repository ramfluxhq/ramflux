// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restart-visible requester action identities, without creator execution authority.
use super::{Carrier, PayloadKind, invalid, key};
use crate::{RamfluxClient, SdkError};
use serde_json::{Value, json};

impl RamfluxClient {
    pub(super) fn retained_task_surface_actions(
        &self,
        reference: &str,
        selected: Option<&str>,
    ) -> Result<Vec<Value>, SdkError> {
        let prefix = key("authored", reference) + "/";
        let mut result = Vec::new();
        let mut after = prefix.clone();
        // The authored namespace is already bounded to 256 records / 4 MiB per surface.
        for _ in 0..3 {
            let page = self.account_db()?.surface_history_page::<Value>(&prefix, &after, 100)?;
            if page.is_empty() {
                break;
            }
            // surface_history_page returns values only; authored keys are not exposed as cursors.
            for row in &page {
                let carrier: Carrier =
                    serde_json::from_value(row.get("carrier").unwrap_or(row).clone())?;
                let (storage, _) = super::authored::authored_key(&carrier)?;
                after = storage;
                if carrier.payload_kind != PayloadKind::Action {
                    continue;
                }
                let wire = ramflux_protocol::decode_base64url(&carrier.wire_base64)
                    .map_err(|_| invalid("retained task action wire invalid"))?;
                let action = ramflux_protocol::A2uiSurfaceAction::from_wire_bytes(&wire)?;
                let Some(binding) = action.task_binding() else { continue };
                let id = ramflux_protocol::hash_base64url(
                    "ramflux.surface.action_delivery.v1",
                    &ramflux_protocol::canonical_json_bytes(&(
                        reference,
                        &carrier.sender_principal_id,
                        &carrier.message_id,
                    ))?,
                );
                if selected.is_some_and(|selected| selected != id) {
                    continue;
                }
                result.push(json!({"id":id,"action_receipt_id":id,"message_id":carrier.message_id,
                    "sender_principal_id":carrier.sender_principal_id,"sender_device_id":carrier.sender_device_id,
                    "version":action.version(),"task_binding":binding,"carrier":carrier,
                    "actionable":false,"receipt_verified":false,"delivery_state":row["delivery_state"]}));
            }
            if page.len() < 100 {
                break;
            }
        }
        Ok(result)
    }
}
