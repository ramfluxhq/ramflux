// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete per-member route resolution before any group send side effects.

use crate::prelude::*;
use serde_json::{Value, json};

pub(super) fn directory(client: &RamfluxClient, group_id: &str) -> Result<Vec<Value>, SdkError> {
    if let Some(state) = client.account_db()?.shared_group_state(group_id)? {
        return shared_directory(client, &state);
    }
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
        let peer = client.group_device_metadata(group_id, &member)?;
        if let Some(peer) = peer
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

pub(super) async fn resolve_current(
    account: &LocalBusAccountState,
    body: &LocalBusGroupSendRequest,
) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
    if let Some(state) = account.client.account_db()?.shared_group_state(&body.group_id)? {
        let gateway =
            account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
        let roots = state
            .view()
            .members
            .iter()
            .map(|member| member.identity.root_commitment.as_str())
            .collect::<BTreeSet<_>>();
        for root in roots {
            account.client.cache_verified_device_manifest(gateway, root, "group-send").await?;
        }
    }
    resolve(account, body)
}

pub(super) fn resolve(
    account: &LocalBusAccountState,
    body: &LocalBusGroupSendRequest,
) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
    let rows = directory(&account.client, &body.group_id)?;
    let mut missing = Vec::new();
    let mut routes = Vec::new();
    for row in rows {
        if row["member_id"] == body.sender_id
            && (account.client.account_db()?.shared_group_state(&body.group_id)?.is_none()
                || row["member_principal_commitment"] == account.principal_commitment)
        {
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

fn shared_directory(
    client: &RamfluxClient,
    state: &ramflux_crypto::VerifiedGroupState,
) -> Result<Vec<Value>, SdkError> {
    let mut rows = Vec::new();
    let roots = state
        .view()
        .members
        .iter()
        .map(|m| m.identity.root_commitment.as_str())
        .collect::<BTreeSet<_>>();
    for root in roots {
        let before = rows.len();
        // The signed set includes permanent tombstones and active devices whose material is not
        // ready. Only the current manifest's usable material participates in delivery fanout.
        let manifest =
            client.account_db()?.load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(
                &format!("identity/manifest-root/{root}"),
            )?;
        let names = manifest
            .map(|manifest| {
                manifest.devices.into_iter().map(|d| d.device_id).collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        for name in names {
            if state.view().effective_role(root, &name).is_none() {
                continue;
            }
            let trusted = client
                .device_identity_for_root(root, &name)
                .and_then(|identity| client.trusted_device(&identity));
            let mut row = json!({"member_id":name,"member_principal_commitment":root,
                "principal_id":null,"device_signing_public_key":null,"target_delivery_id":null,
                "federation":null});
            if let Ok(record) = trusted {
                row["principal_id"] = record["principal_id"].clone();
                row["device_signing_public_key"] = record["signing_public_key"].clone();
                row["target_delivery_id"] = record["target_delivery_id"].clone();
                let identity = client.device_identity_for_root(root, &name)?;
                let key =
                    crate::group::group_member_route_event_id(&state.view().group_id, &identity)?;
                if let Some(bytes) = client.event_body(&key)? {
                    let stored: LocalBusGroupMemberRoute = serde_json::from_slice(&bytes)?;
                    if stored.member_id == name
                        && stored.member_principal_commitment.as_deref() == Some(root)
                    {
                        row["federation"] = serde_json::to_value(stored.federation)?;
                    }
                }
            } else {
                continue;
            }
            row["delivery_target_known"] = json!(complete(&row));
            rows.push(row);
            if rows.len() > 1024 {
                return Err(SdkError::LocalBus("group device fanout budget exceeded".into()));
            }
        }
        if rows.len() == before {
            let member = state
                .view()
                .members
                .iter()
                .find(|m| m.identity.root_commitment == root)
                .ok_or(StorageError::GroupPermissionDenied)?;
            rows.push(
                json!({"member_id":member.identity.device_id,"member_principal_commitment":root,
                "principal_id":member.identity.principal_id,"device_signing_public_key":null,
                "target_delivery_id":null,"federation":null,"delivery_target_known":false}),
            );
        }
    }
    Ok(rows)
}
