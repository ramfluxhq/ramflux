// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete per-member route resolution before any group send side effects.

use crate::prelude::*;
use serde_json::{Value, json};

pub(super) fn directory(client: &RamfluxClient, group_id: &str) -> Result<Vec<Value>, SdkError> {
    let stored = client
        .group_member_routes(group_id)?
        .into_iter()
        .map(|route| (route.member_id.clone(), route))
        .collect::<BTreeMap<_, _>>();
    let db = client.account_db()?;
    let mut rows = Vec::new();
    for member in client.group_state(group_id)?.members {
        let mut route = stored
            .get(&member)
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| json!({"member_id":member}));
        if let Some(peer) = db.client_record("device", &member)?
            && let Some(principal) = peer.get("principal_id").and_then(Value::as_str)
            && let Some(identity) = db.client_record("identity", principal)?
        {
            route["principal_id"] = json!(principal);
            if let Some(device) =
                identity.get("devices").and_then(Value::as_array).and_then(|devices| {
                    devices.iter().find(|device| {
                        device.get("device_id").and_then(Value::as_str) == Some(member.as_str())
                    })
                })
            {
                route["member_principal_commitment"] =
                    identity["contact_identity_commitment"].clone();
                route["device_signing_public_key"] = device["signing_public_key"].clone();
                route["target_delivery_id"] = device["target_delivery_id"].clone();
            } else {
                route["member_principal_commitment"] = Value::Null;
                route["device_signing_public_key"] = Value::Null;
                route["target_delivery_id"] = Value::Null;
            }
        }
        for field in [
            "principal_id",
            "member_principal_commitment",
            "device_signing_public_key",
            "target_delivery_id",
            "federation",
        ] {
            if route.get(field).is_none() {
                route[field] = Value::Null;
            }
        }
        route["delivery_target_known"] = json!(complete(&route));
        rows.push(route);
    }
    Ok(rows)
}

pub(super) fn resolve(
    account: &LocalBusAccountState,
    body: &LocalBusGroupSendRequest,
) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
    let rows = directory(&account.client, &body.group_id)?;
    let mut missing = Vec::new();
    let mut routes = Vec::new();
    for row in rows {
        if row["member_id"] == body.sender_id {
            continue;
        }
        if complete(&row) {
            routes.push(serde_json::from_value(row)?);
        } else {
            missing.push(row["member_id"].clone());
        }
    }
    if !missing.is_empty() {
        return Err(SdkError::LocalBus(format!(
            "group routes unresolved: {}",
            serde_json::to_string(
                &json!({"group_id":body.group_id,"unreachable_members":missing})
            )?
        )));
    }
    Ok(routes)
}

fn complete(row: &Value) -> bool {
    ["member_principal_commitment", "device_signing_public_key", "target_delivery_id"]
        .iter()
        .all(|field| row.get(field).and_then(Value::as_str).is_some_and(|text| !text.is_empty()))
}
