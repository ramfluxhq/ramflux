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
            account.client.shared_group_manifest(gateway, &body.group_id, root).await?;
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
    let routes = match client.shared_group_member_routes(state) {
        Ok(routes) => routes,
        Err(SdkError::InboundPending(_)) => {
            // Reader clients have no process-local current-head freshness. Keep the signed
            // roster visible, without advertising a usable route or refreshing authority.
            // resolve() fails closed on these incomplete rows; resolve_current() must fetch
            // current manifests before any group send can obtain complete routes.
            return Ok(state
                .view()
                .members
                .iter()
                .map(|member| {
                    let identity = &member.identity;
                    json!({"member_id":identity.device_id,
                    "principal_id":identity.principal_id,
                    "member_principal_commitment":identity.root_commitment,
                    "device_signing_public_key":null,"target_delivery_id":null,
                    "federation":null,"delivery_target_known":false})
                })
                .collect());
        }
        Err(error) => return Err(error),
    };
    routes
        .into_iter()
        .map(|route| {
            let principal = route
                .member_principal_commitment
                .as_deref()
                .map(|root| client.observed_device_set(root))
                .transpose()?
                .flatten()
                .map(|record| record.principal_id);
            let mut row = serde_json::to_value(route)?;
            for field in [
                "member_principal_commitment",
                "device_signing_public_key",
                "target_delivery_id",
                "federation",
            ] {
                if row.get(field).is_none() {
                    row[field] = Value::Null;
                }
            }
            row["principal_id"] = json!(principal);
            row["delivery_target_known"] = json!(complete(&row));
            Ok(row)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};

    #[tokio::test]
    async fn native_group_read_projection_survives_missing_freshness_without_authorizing_routes()
    -> TestResult {
        let owner = Fixture::with_device("group-reader-owner", "owner-device").await?;
        let peer = Fixture::with_device("group-reader-peer", "peer-device").await?;
        owner.client.persist_fetched_identity_directory(&peer.manifest)?;
        let primary = owner
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native owner")?
            .group_primary(owner.vault.as_ref())?;
        owner.client.shared_group_create_with_primary(
            "group",
            "thread",
            None,
            &owner.config.target_delivery_id,
            Some(&primary),
        )?;
        owner.client.shared_group_change_with_primary(
            "group",
            &owner.config.target_delivery_id,
            ramflux_protocol::group_state::GroupStateChange::Add {
                member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        let peer_identity = owner.client.device_identity_for_root(
            &peer.manifest.principal_commitment,
            &peer.config.device_id,
        )?;
        assert!(owner.client.trusted_device(&peer_identity).is_ok());
        *owner.client.native_head_freshness.borrow_mut() =
            crate::client::identity_authority::NativeHeadFreshness::default();
        assert!(matches!(
            owner.client.trusted_device(&peer_identity),
            Err(SdkError::InboundPending(_))
        ));
        let view = crate::bus::read_model::row(&owner.client, "conversation", "thread")?;
        assert_eq!(view["group_id"], "group");
        let rows = directory(&owner.client, "group")?;
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["delivery_target_known"] == false
            && row["target_delivery_id"].is_null()
            && row["device_signing_public_key"].is_null()));
        let request = serde_json::from_value(
            json!({"group_id":"group","conversation_id":"thread",
            "message_id":"cannot-send","sender_id":owner.config.device_id,"encrypted_body_base64":""}),
        )?;
        let account = LocalBusAccountState::disconnected(
            owner.client,
            owner.config,
            owner.manifest.principal_commitment,
        );
        assert!(resolve(&account, &request).is_err(), "read projection lent send authority");
        assert!(matches!(
            account.client.trusted_device(&peer_identity),
            Err(SdkError::InboundPending(_))
        ));
        Ok(())
    }
}
