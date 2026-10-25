// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared group mutations and bounded state distribution on the existing account actor.
mod outbox;
mod recovery;
use crate::prelude::*;
pub(crate) use outbox::enqueue;
pub(super) use outbox::flush;
use ramflux_protocol::group_state::{GroupMemberIdentity, GroupStateChange};
pub(super) use recovery::stage;
use serde_json::{Value, json};

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    body[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SdkError::LocalBus(format!("{key} is required")))
}
pub(super) async fn dispatch(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<Option<Value>, SdkError> {
    let method = request.method.as_str();
    let body = &request.body;
    if method != "group.create"
        && method != "group.name.set"
        && !matches!(
            method,
            "group.member.add" | "group.member.remove" | "group.member.kick" | "group.role.set"
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
        if required(body, "creator_id")? != account.gateway_config.device_id {
            return Err(SdkError::Storage(StorageError::GroupPermissionDenied));
        }
        None
    } else if method == "group.member.add" {
        let member = verified_member(account, body).await?;
        Some(GroupStateChange::Add { member, role: required(body, "role")?.parse()? })
    } else if method == "group.name.set" {
        Some(GroupStateChange::SetName { name: required(body, "name")?.into() })
    } else {
        selected_change(
            previous.as_ref().ok_or(StorageError::GroupPermissionDenied)?,
            body,
            method,
        )?
    };
    account.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
        if let Some(change) = change {
            account.client.shared_group_change(group, &target, change)?
        } else {
            let conversation = body["conversation_id"].as_str().unwrap_or(group);
            let name = body["name"].as_str().or_else(|| body["title"].as_str()).map(str::to_owned);
            account.client.shared_group_create(group, conversation, name, &target)?
        };
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
    let root = account
        .client
        .resolve_target_principal_commitment(
            gateway,
            explicit.or_else(|| address.as_ref().map(|(root, _)| root.as_str())),
            device,
        )
        .await?;
    let manifest = crate::client::contact::fetch_verified_device_manifest(gateway, &root).await?;
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
