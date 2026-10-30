// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared group mutations and bounded state distribution on the existing account actor.
mod outbox;
mod recovery;
mod requests;
use crate::prelude::*;
pub(crate) use outbox::enqueue;
pub(super) use outbox::flush;
use ramflux_protocol::group_state::{GroupMemberIdentity, GroupStateChange};
pub(super) use recovery::stage;
pub(super) use requests::flush as flush_requests;
#[cfg(test)]
pub(in crate::bus) use requests::flush_with_clock as flush_requests_with_clock;
use serde_json::{Value, json};

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    body[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SdkError::LocalBus(format!("{key} is required")))
}
fn local_creator_matches(creator: &str, root: &str, device: &str) -> Result<bool, SdkError> {
    Ok(if creator == device {
        true
    } else {
        ramflux_protocol::parse_qualified_device_id(creator)?.is_some_and(
            |(candidate_root, candidate_device)| {
                candidate_root == root && candidate_device == device
            },
        )
    })
}
async fn validate_local_creator(
    account: &mut LocalBusAccountState,
    body: &Value,
) -> Result<(), SdkError> {
    if account.client.born_v3_account.is_some() {
        account.ensure_gateway_live().await?;
    }
    let local = account.client.owned_device_identity()?;
    if local_creator_matches(
        required(body, "creator_id")?,
        local.root_commitment(),
        local.device_id(),
    )? {
        Ok(())
    } else {
        Err(StorageError::GroupPermissionDenied.into())
    }
}
pub(super) async fn dispatch(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<Option<Value>, SdkError> {
    let method = request.method.as_str();
    let body = &request.body;
    if let Some(response) = consent_dispatch(method, body, account)? {
        return Ok(Some(response));
    }
    if method != "group.create"
        && method != "group.name.set"
        && !matches!(
            method,
            "group.member.add"
                | "group.member.remove"
                | "group.member.kick"
                | "group.role.set"
                | "group.owner.transfer"
        )
    {
        return Ok(None);
    }
    let group = required(body, "group_id")?;
    let previous = account.client.account_db()?.shared_group_state(group)?;
    if method != "group.create" && previous.is_none() {
        return Ok(None);
    }
    if body["actor_id"].as_str().is_some_and(|actor| actor != account.gateway_config.device_id) {
        return Err(StorageError::GroupPermissionDenied.into());
    }
    let target = account.gateway_config.target_delivery_id.clone();
    let change = if method == "group.create" {
        validate_local_creator(account, body).await?;
        None
    } else if method == "group.member.add" {
        let member = verified_member(account, body).await?;
        Some(GroupStateChange::Add { member, role: required(body, "role")?.parse()? })
    } else if method == "group.owner.transfer" {
        Some(ownership_transfer(account, body).await?)
    } else if method == "group.name.set" {
        Some(GroupStateChange::SetName { name: required(body, "name")?.into() })
    } else {
        selected_change(
            previous.as_ref().ok_or(StorageError::GroupPermissionDenied)?,
            body,
            method,
        )?
    };
    let route = federation_route(body, change.as_ref())?;
    if let (Some(previous), Some(change)) = (&previous, &change)
        && account.client.owned_device_identity()?.root_commitment()
            != previous.creator().identity.root_commitment
    {
        let request = account.client.stage_group_change_request(
            group,
            &target,
            change.clone(),
            body["request_id"].as_str(),
        )?;
        if let Some(route) = &route
            && let Some(mut record) = account.client.group_change_record(&request, false)?
        {
            record.federation.clone_from(&route.federation);
            account.client.persist_group_request(&record)?;
        }
        let result = pending_metadata(&account.client, group, &request)?;
        return Ok(Some(result));
    }
    account.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
        if let Some(change) = change {
            account.client.shared_group_change(group, &target, change)?
        } else {
            let conversation = body["conversation_id"].as_str().unwrap_or(group);
            let name = body["name"].as_str().or_else(|| body["title"].as_str()).map(str::to_owned);
            account.client.shared_group_create(group, conversation, name, &target)?
        };
        if let Some(route) = &route {
            account.client.persist_group_member_route(group, route)?;
            account.client.persist_shared_group_federation_route(
                group,
                route
                    .member_principal_commitment
                    .as_deref()
                    .ok_or(StorageError::GroupPermissionDenied)?,
                route.federation.as_ref().ok_or(StorageError::GroupPermissionDenied)?,
            )?;
        }
        Ok(())
    })?;
    // The actor's sync tick drains durable delivery. Mutations return after their atomic commit,
    // so one offline member cannot keep a local group command waiting on network retries.
    let mut result =
        account.client.shared_group_metadata(group)?.ok_or(StorageError::GroupPermissionDenied)?;
    result["accepted"] = json!(true);
    Ok(Some(result))
}

fn selected_change(
    previous: &ramflux_crypto::VerifiedGroupState,
    body: &Value,
    method: &str,
) -> Result<Option<GroupStateChange>, SdkError> {
    Ok({
        let selected = required(body, "member_id")?;
        let explicit = body["member_principal_commitment"].as_str();
        let address = if explicit.is_none()
            && !previous.view().members.iter().any(|m| m.identity.device_id == selected)
        {
            ramflux_protocol::parse_qualified_device_id(selected)?
        } else {
            None
        };
        let member = address.as_ref().map_or(selected, |(_, device)| device.as_str());
        let selected_root = explicit.or_else(|| address.as_ref().map(|(root, _)| root.as_str()));
        let matches = previous
            .view()
            .members
            .iter()
            .filter(|m| {
                m.identity.device_id == member
                    && selected_root.is_none_or(|root| root == m.identity.root_commitment)
            })
            .collect::<Vec<_>>();
        if matches.is_empty()
            && method != "group.role.set"
            && let Some(root) = selected_root
            && previous.view().effective_role(root, member).is_some()
        {
            Some(GroupStateChange::Remove {
                root_commitment: root.into(),
                device_id: member.into(),
            })
        } else {
            if matches.len() != 1 {
                return Err(SdkError::LocalBus(
                    "member requires an unambiguous root-qualified identity".into(),
                ));
            }
            let identity = &matches[0].identity;
            Some(if method == "group.role.set" {
                GroupStateChange::SetRole {
                    root_commitment: identity.root_commitment.clone(),
                    device_id: member.into(),
                    role: required(body, "role")?.parse()?,
                }
            } else {
                GroupStateChange::Remove {
                    root_commitment: identity.root_commitment.clone(),
                    device_id: member.into(),
                }
            })
        }
    })
}
async fn verified_member(
    account: &LocalBusAccountState,
    body: &Value,
) -> Result<GroupMemberIdentity, SdkError> {
    let selected = required(body, "member_id")?;
    let explicit = body["member_principal_commitment"].as_str();
    // An explicit root makes member_id a literal device name, including address-shaped names.
    let address = if explicit.is_none() {
        ramflux_protocol::parse_qualified_device_id(selected)?
    } else {
        None
    };
    let device = address.as_ref().map_or(selected, |(_, device)| device.as_str());
    let gateway = account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
    let expected = explicit.or_else(|| address.as_ref().map(|(root, _)| root.as_str()));
    let manifest = if let Some(federation) = body.get("federation").filter(|value| !value.is_null())
    {
        let federation: LocalBusFederationRoute = serde_json::from_value(federation.clone())?;
        let url = federation.recipient_prekey_url.ok_or_else(|| {
            SdkError::LocalBus("federated group member requires recipient_prekey_url".into())
        })?;
        let root =
            account.client.resolve_federated_target_principal_commitment(&url, expected, device)?;
        crate::client::contact::fetch_verified_device_manifest_from_url(&url, &root)?
    } else {
        let root =
            account.client.resolve_target_principal_commitment(gateway, expected, device).await?;
        crate::client::contact::fetch_verified_device_manifest(gateway, &root).await?
    };
    let root = manifest.principal_commitment.clone();
    let member =
        manifest.devices.iter().find(|m| m.device_id == device).ok_or_else(|| {
            SdkError::LocalBus("member is absent from its verified manifest".into())
        })?;
    if body["member_signing_public_key"].as_str().is_some_and(|key| key != member.branch_public_key)
        || body["target_delivery_id"]
            .as_str()
            .is_some_and(|target| target != member.target_delivery_id)
    {
        return Err(SdkError::Storage(StorageError::GroupPermissionDenied));
    }
    let identity = GroupMemberIdentity {
        principal_id: manifest.principal_id.clone(),
        root_commitment: root,
        device_id: device.into(),
        signing_public_key: member.branch_public_key.clone(),
        target_delivery_id: member.target_delivery_id.clone(),
    };
    account.client.persist_identity_directory(&manifest)?;
    Ok(identity)
}

fn federation_route(
    body: &Value,
    change: Option<&GroupStateChange>,
) -> Result<Option<LocalBusGroupMemberRoute>, SdkError> {
    let route = if let Some(GroupStateChange::Add { member, .. }) = change {
        let federation: Option<LocalBusFederationRoute> = body
            .get("federation")
            .filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        federation.map(|federation| LocalBusGroupMemberRoute {
            member_id: member.device_id.clone(),
            member_principal_commitment: Some(member.root_commitment.clone()),
            device_signing_public_key: Some(member.signing_public_key.clone()),
            target_delivery_id: Some(member.target_delivery_id.clone()),
            federation: Some(federation),
        })
    } else {
        None
    };
    Ok(route)
}

fn consent_dispatch(
    method: &str,
    body: &Value,
    account: &LocalBusAccountState,
) -> Result<Option<Value>, SdkError> {
    if method == "group.requests.list" {
        return account.client.group_change_statuses(body["group_id"].as_str()).map(Some);
    }
    if method == "group.invitations.list" {
        return account.client.group_invitations().map(Some);
    }
    if matches!(method, "group.invitation.accept" | "group.invitation.decline") {
        return account
            .client
            .decide_group_invitation(
                required(body, "group_id")?,
                method == "group.invitation.accept",
                &account.target_delivery_id,
            )
            .map(Some);
    }
    Ok(None)
}

async fn ownership_transfer(
    account: &LocalBusAccountState,
    body: &Value,
) -> Result<GroupStateChange, SdkError> {
    let identity = verified_member(account, body).await?;
    let actor = body
        .get("creator_actor")
        .cloned()
        .map(serde_json::from_value::<ramflux_protocol::GroupStateActor>)
        .transpose()?
        .ok_or_else(|| SdkError::LocalBus("creator_actor certificate is required".into()))?;
    ramflux_crypto::verify_group_state_actor(&actor)?;
    if actor.identity != identity {
        return Err(StorageError::GroupPermissionDenied.into());
    }
    let group = required(body, "group_id")?;
    let state = account
        .client
        .account_db()?
        .shared_group_state(group)?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let gateway = account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
    let acceptance = account
        .client
        .group_transfer_authorization(gateway, &state, &actor, &account.target_delivery_id)
        .await?;
    Ok(GroupStateChange::TransferOwnership { creator: actor, acceptance: Box::new(acceptance) })
}

fn pending_metadata(
    client: &RamfluxClient,
    group: &str,
    request: &ramflux_protocol::GroupChangeRequest,
) -> Result<Value, SdkError> {
    let mut result =
        client.shared_group_metadata(group)?.ok_or(StorageError::GroupPermissionDenied)?;
    let live = request.expires_at > now_unix_timestamp();
    result["accepted"] = json!(live);
    result["pending"] = json!(live);
    result["status"] = json!(if live { "waiting_for_owner" } else { "expired" });
    result["request_id"] = json!(request.request_id);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_group_creator_accepts_only_the_local_raw_or_exact_qualified_device()
    -> Result<(), SdkError> {
        let local = ramflux_protocol::qualified_device_id("anchor", "phone")?;
        let foreign_root = ramflux_protocol::qualified_device_id("other", "phone")?;
        let foreign_device = ramflux_protocol::qualified_device_id("anchor", "tablet")?;
        assert!(local_creator_matches("phone", "anchor", "phone")?);
        assert!(local_creator_matches(&local, "anchor", "phone")?);
        assert!(!local_creator_matches(&foreign_root, "anchor", "phone")?);
        assert!(!local_creator_matches(&foreign_device, "anchor", "phone")?);
        Ok(())
    }
}
