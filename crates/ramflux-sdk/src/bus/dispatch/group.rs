// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
#[cfg(test)]
pub(crate) mod native_contract_tests;
#[cfg(test)]
mod native_selector_tests;

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_group_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let native = request
        .account_id
        .as_deref()
        .and_then(|id| state.accounts.get(id))
        .is_some_and(|account| account.client.born_v3_account.is_some());
    let result = dispatch_group_bus_request_inner(request, state).await;
    result.map_err(|error| group_operation_error(&request.method, error, native))
}

pub(super) fn group_operation_error(method: &str, error: SdkError, native: bool) -> SdkError {
    let Some(operation) = crate::GroupOperation::for_method(method) else { return error };
    if !native
        || matches!(&error, SdkError::GroupRefused { .. })
        || crate::bus::io::local_bus_error_code(&error) != "ValidationFailed"
    {
        return error;
    }
    SdkError::GroupRefused { operation, source: Box::new(error) }
}

#[allow(clippy::too_many_lines)]
async fn dispatch_group_bus_request_inner(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    if let Some(group) = request.body.get("group_id").and_then(serde_json::Value::as_str) {
        // Controls also need a canonical link when an earlier CLI version cached aliases.
        crate::bus::group_conversation::resolve(
            &local_bus_account(state, account_id)?.client,
            group,
            group,
        )?;
    }
    if let Some(response) = super::super::shared_group_sync::dispatch(
        request,
        local_bus_account_mut(state, account_id)?,
    )
    .await?
    {
        return Ok(local_bus_ok(response));
    }
    match request.method.as_str() {
        // Native shared-group sync consumes these; reaching here means no local shared state.
        "group.create"
        | "group.leave"
        | "group.member.add"
        | "group.member.remove"
        | "group.role.set"
        | "group.member.kick" => Err(SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Content,
            reason: "group has no native shared state on this account".into(),
        }),
        "group.history" => {
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(history::read(&account.client, request)?))
        }
        "group.members" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusGroupRequest = serde_json::from_value(request.body.clone())?;
            let metadata = match account.client.shared_group_metadata(&body.group_id)? {
                Some(value) => value,
                None => serde_json::to_value(account.client.group_state(&body.group_id)?)?,
            };
            Ok(local_bus_ok(metadata))
        }
        "group.list" => {
            let account = local_bus_account(state, account_id)?;
            let groups = account
                .client
                .groups()?
                .into_iter()
                .map(|group| group_list_row(account, group))
                .collect::<Result<Vec<_>, SdkError>>()?;
            Ok(local_bus_ok(serde_json::json!({ "groups": groups })))
        }
        "group.send" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_send_request(request, account)).await
        }
        "group.read" => {
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_group_receive_request(request, account).await
        }
        "group.sender_key.export" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusGroupSenderKeyExportRequest =
                serde_json::from_value(request.body.clone())?;
            let distribution = account
                .client
                .export_group_sender_key_distribution(&body.group_id, &body.sender_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "distribution_base64": ramflux_protocol::encode_base64url(&distribution),
            })))
        }
        "group.sender_key.import" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusGroupSenderKeyImportRequest =
                serde_json::from_value(request.body.clone())?;
            let distribution = ramflux_protocol::decode_base64url(&body.distribution_base64)
                .map_err(|error| {
                    SdkError::LocalBus(format!("invalid sender key distribution: {error}"))
                })?;
            let distribution =
                account.client.import_group_sender_key_distribution(&distribution)?;
            let mut value = serde_json::to_value(distribution)?;
            value["durable_reader"] = serde_json::json!("message.read");
            Ok(local_bus_ok(value))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

#[cfg(test)]
fn create_group_member_onboard_event_for_authorized_local_actor(
    account: &LocalBusAccountState,
    group: &GroupState,
    body: &LocalBusGroupMemberAddRequest,
    route: &LocalBusGroupMemberRoute,
) -> Result<Option<ramflux_protocol::GroupEvent>, SdkError> {
    if route.target_delivery_id.is_none() && route.federation.is_none() {
        return Ok(None);
    }
    let actor_device_id = account
        .client
        .device_branch
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .device_id
        .clone();
    let Some(actor_role) = group.roles.get(&actor_device_id) else {
        return Ok(None);
    };
    if actor_role != "owner" && actor_role != "admin" {
        return Ok(None);
    }
    Ok(Some(account.client.create_signed_group_member_join_event(
        &body.group_id,
        &actor_device_id,
        &body.member_id,
        &body.role,
        &account.principal_commitment,
    )?))
}

async fn resolve_federated_group_member_principal_commitment(
    client: &RamfluxClient,
    federation: &LocalBusFederationRoute,
    member_principal_commitment: Option<&str>,
    member_id: &str,
    timeout: Duration,
) -> Result<String, SdkError> {
    let base = crate::client::recipient_home::required_public_base(
        client,
        member_principal_commitment.unwrap_or(""),
        Some(federation.target_node_id.as_str()),
    )
    .await?;
    client
        .resolve_federated_target_principal_commitment_async(
            crate::client::contact::RemoteManifest { url: &base, timeout },
            member_principal_commitment,
            member_id,
        )
        .await
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_group_send_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let mut body: LocalBusGroupSendRequest = serde_json::from_value(request.body.clone())?;
    let directed_transport = body.envelope_id.is_some()
        && body.source_principal_id.is_some()
        && body.target_delivery_id.is_some();
    if account.client.born_v3_account.is_some() && !directed_transport {
        normalize_native_group_request(&mut body, &account.gateway_config, &account.client)?;
    }
    account.client.assert_shared_group_send_capacity(&body.group_id, &body.sender_id)?;
    if !directed_transport
        && account.client.account_db()?.shared_group_state(&body.group_id)?.is_some()
    {
        // A current device of the member account (paired or recovered) holds the account's role;
        // project it before any per-device lookup (own copies, sender keys) reads it.
        account.client.pin_local_group_member(&body.group_id)?;
    }
    let mut fanout_routes = if directed_transport {
        None
    } else {
        Some(super::super::group_delivery::resolve_current(account, &body).await?)
    };
    let group_state = account.client.group_state(&body.group_id)?;
    if !group_state.members.contains(&body.sender_id) {
        return Err(StorageError::GroupPermissionDenied.into());
    }
    let client_message_id = body.message_id.clone();
    let content = if let Some(content) = body.content.clone() {
        if body.plaintext_body_base64.is_some() || !body.encrypted_body_base64.is_empty() {
            return Err(SdkError::LocalBus("group typed content excludes opaque body".into()));
        }
        content
    } else {
        let bytes = zeroize::Zeroizing::new(
            ramflux_protocol::decode_base64url(body.plaintext_body_base64.as_deref().ok_or_else(
                || SdkError::LocalBus("group.send requires plaintext content".into()),
            )?)
            .map_err(|error| SdkError::LocalBus(format!("invalid group body: {error}")))?,
        );
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| SdkError::LocalBus("group Message text must be UTF-8".into()))?;
        ramflux_protocol::message::Content {
            value: Some(ramflux_protocol::message::content::Value::Message(
                ramflux_protocol::message::Message { text: text.into(), ..Default::default() },
            )),
        }
    };
    account.client.validate_user_authored_content(&content, &body.conversation_id)?;
    if let Some(ramflux_protocol::message::content::Value::Surface(surface)) =
        content.value.as_ref()
        && let Some(ramflux_protocol::message::surface::Payload::Delivery(delivery)) =
            surface.payload.as_ref()
        && let Some(carrier) = delivery.carrier.as_ref()
        && matches!(
            carrier.payload,
            Some(ramflux_protocol::message::surface_carrier::Payload::Action(_))
        )
        && let Some(routes) = fanout_routes.as_mut()
    {
        let directory = super::super::group_delivery::directory(&account.client, &body.group_id)?;
        routes.retain(|route| {
            directory.iter().any(|row| {
                row["member_id"] == route.member_id
                    && row["principal_id"] == carrier.author_principal_id
            })
        });
        if routes.is_empty() {
            return Err(SdkError::LocalBus("surface author group route unavailable".into()));
        }
    }
    if let Some(routes) = &fanout_routes {
        let engine = account.session_client().await?;
        let checked = async {
            for route in routes {
                resolve_group_route_principal_commitment(
                    &account.client,
                    engine.config(),
                    route,
                    &route.member_id,
                    account.timeouts.http,
                )
                .await?;
            }
            Ok::<_, SdkError>(())
        }
        .await;
        account.apply_session_metadata(engine);
        checked?;
    }
    let mut authored = GatewayDirectMessage {
        conversation_id: body.conversation_id.clone(),
        message_id: body.message_id.clone(),
        envelope_id: body.envelope_id.clone().unwrap_or_else(|| body.message_id.clone()),
        source_principal_id: account.gateway_config.principal_id.clone(),
        sender_id: body.sender_id.clone(),
        recipient_device_id: None,
        recipient_principal_commitment: None,
        target_delivery_id: account.gateway_config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: account.client.content_ttl()?,
    };
    let prepared =
        account.client.prepare_authored_content(&mut authored, Some(&body.group_id), &content)?;
    body.message_id.clone_from(&authored.message_id);
    account.client.project_authored_message(&authored, &prepared.exact, &prepared.wire)?;
    let encrypted_body = &prepared.wire;
    let mut response = serde_json::json!({
        "group_id": body.group_id,
        "conversation_id": body.conversation_id,
        "message_id": body.message_id,
        "client_message_id":client_message_id,
    });
    Box::pin(async {
        if let (Some(envelope_id), Some(source_principal_id), Some(target_delivery_id)) = (
            body.envelope_id.clone(),
            body.source_principal_id.clone(),
            body.target_delivery_id.clone(),
        ) {
            let created_at = prepared.created_at;
            let recipients =
                super::super::group_delivery::directory(&account.client, &body.group_id)?;
            let recipient = recipients
                .iter()
                .filter(|row| {
                    row.get("target_delivery_id").and_then(serde_json::Value::as_str)
                        == Some(target_delivery_id.as_str())
                })
                .collect::<Vec<_>>();
            let [recipient] = recipient.as_slice() else {
                return Err(SdkError::LocalBus(
                    "group override requires one verified recipient device route".to_owned(),
                ));
            };
            if let Some(ramflux_protocol::message::content::Value::Surface(surface)) =
                content.value.as_ref()
                && let Some(ramflux_protocol::message::surface::Payload::Delivery(delivery)) =
                    surface.payload.as_ref()
                && let Some(carrier) = delivery.carrier.as_ref()
                && matches!(
                    carrier.payload,
                    Some(ramflux_protocol::message::surface_carrier::Payload::Action(_))
                )
                && recipient["principal_id"] != carrier.author_principal_id
            {
                return Err(SdkError::LocalBus("surface action must target its author".into()));
            }
            let recipient_device = recipient
                .get("member_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| SdkError::LocalBus("group recipient device missing".to_owned()))?
                .to_owned();
            let mut message = GatewayDirectMessage {
                conversation_id: body.conversation_id,
                message_id: body.message_id,
                envelope_id,
                source_principal_id,
                sender_id: body.sender_id,
                recipient_device_id: Some(recipient_device),
                recipient_principal_commitment: recipient["member_principal_commitment"]
                    .as_str()
                    .map(str::to_owned),
                target_delivery_id,
                encrypted_body: Vec::new(),
                created_at,
                ttl: account.client.content_ttl()?,
            };
            if let Some(federation) = body.federation.as_ref() {
                let mut engine = account.session_client().await?;
                let sealed = account
                    .client
                    .seal_federated_message_async(
                        &engine,
                        crate::client::federation::SealForward {
                            message: &message,
                            plaintext: encrypted_body,
                            federation,
                            route: crate::client::routed::Route::group_message(&body.group_id),
                            timeout: account.timeouts.http,
                        },
                    )
                    .await;
                let forwarded = account
                    .client
                    .forward_federated_sealed_async(
                        &mut engine,
                        &mut message,
                        sealed?,
                        federation,
                        account.timeouts.http,
                    )
                    .await;
                account.apply_session_metadata(engine);
                response["federated_submitted"] = serde_json::to_value(forwarded?)?;
            } else {
                let mut engine = account.session_client().await?;
                let entry = async {
                    let sealed = account
                        .client
                        .seal_routed_as(
                            &mut engine,
                            &message,
                            encrypted_body,
                            crate::client::routed::Route::group_message(&body.group_id),
                        )
                        .await?;
                    // GroupMessage has no Direct report payload; into_parts still carries committed_a0 (None).
                    engine
                        .submit_envelope(gateway_envelope_from_sealed(
                            &engine.sealing_config()?,
                            &mut message,
                            sealed,
                            None,
                        )?)
                        .await
                }
                .await;
                account.apply_session_metadata(engine);
                response["submitted"] = serde_json::to_value(entry?)?;
            }
        } else {
            let routes = fanout_routes.unwrap_or_default();
            let mut sender_key_distribution = Vec::new();
            for route in routes.iter().cloned() {
                if let Some(distribution) =
                    dispatch_group_sender_key_distribution(account, &body.group_id, route, None)
                        .await?
                {
                    sender_key_distribution.push(distribution);
                }
            }
            let mut local = Vec::new();
            let mut federated = Vec::new();
            for route in routes {
                let target_delivery_id = route.target_delivery_id.clone().ok_or_else(|| {
                    SdkError::LocalBus(format!("group route lost for member {}", route.member_id))
                })?;
                let created_at = prepared.created_at;
                let mut message = GatewayDirectMessage {
                    conversation_id: body.conversation_id.clone(),
                    message_id: body.message_id.clone(),
                    envelope_id: ramflux_protocol::hash_base64url(
                        "ramflux.group.message.transport.v1",
                        &ramflux_protocol::canonical_json_bytes(&(
                            &body.message_id,
                            &route.member_principal_commitment,
                            &route.member_id,
                            &target_delivery_id,
                        ))?,
                    ),
                    source_principal_id: body
                        .source_principal_id
                        .clone()
                        .unwrap_or_else(|| account.gateway_config.principal_id.clone()),
                    sender_id: body.sender_id.clone(),
                    recipient_device_id: Some(route.member_id.clone()),
                    recipient_principal_commitment: route.member_principal_commitment.clone(),
                    target_delivery_id,
                    encrypted_body: encrypted_body.clone(),
                    created_at,
                    ttl: account.client.content_ttl()?,
                };
                if let Some(federation) = route.federation.as_ref() {
                    let engine = account.session_client().await?;
                    let sealed = account
                        .client
                        .seal_federated_message_async(
                            &engine,
                            crate::client::federation::SealForward {
                                message: &message,
                                plaintext: &message.encrypted_body,
                                federation,
                                route: crate::client::routed::Route::group_message(&body.group_id),
                                timeout: account.timeouts.http,
                            },
                        )
                        .await;
                    account.apply_session_metadata(engine);
                    let mut engine = account.session_client().await?;
                    let forwarded = account
                        .client
                        .forward_federated_sealed_async(
                            &mut engine,
                            &mut message,
                            sealed?,
                            federation,
                            account.timeouts.http,
                        )
                        .await;
                    account.apply_session_metadata(engine);
                    federated.push(serde_json::to_value(forwarded?)?);
                } else {
                    let mut engine = account.session_client().await?;
                    let sealed = account
                        .client
                        .seal_routed_as(
                            &mut engine,
                            &message,
                            &message.encrypted_body,
                            crate::client::routed::Route::group_message(&body.group_id),
                        )
                        .await;
                    let entry = match sealed {
                        Ok(sealed) => {
                            engine
                                .submit_envelope(gateway_envelope_from_sealed(
                                    &engine.sealing_config()?,
                                    &mut message,
                                    sealed,
                                    None,
                                )?)
                                .await
                        }
                        Err(error) => Err(error),
                    };
                    account.apply_session_metadata(engine);
                    local.push(serde_json::to_value(entry?)?);
                }
            }
            response["submitted"] = serde_json::Value::Array(local);
            response["federated_submitted"] = serde_json::Value::Array(federated);
            response["sender_key_distribution"] = serde_json::Value::Array(sender_key_distribution);
        }
        Ok(local_bus_ok(response))
    })
    .await
}

fn normalize_native_group_request(
    body: &mut LocalBusGroupSendRequest,
    gateway: &GatewaySessionConfig,
    client: &RamfluxClient,
) -> Result<(), SdkError> {
    normalize_native_group_sender(body, gateway)?;
    body.conversation_id =
        crate::bus::group_conversation::resolve(client, &body.group_id, &body.conversation_id)?;
    Ok(())
}

fn normalize_native_group_sender(
    body: &mut LocalBusGroupSendRequest,
    gateway: &GatewaySessionConfig,
) -> Result<(), SdkError> {
    if body.sender_id != gateway.principal_id
        && body.sender_id != gateway.device_id
        && body.sender_id != gateway.target_delivery_id
    {
        return Err(StorageError::GroupPermissionDenied.into());
    }
    body.sender_id.clone_from(&gateway.device_id);
    Ok(())
}

pub(crate) async fn dispatch_group_sender_key_distribution(
    account: &mut LocalBusAccountState,
    group_id: &str,
    route: LocalBusGroupMemberRoute,
    _membership_event: Option<&ramflux_protocol::GroupEvent>,
) -> Result<Option<serde_json::Value>, SdkError> {
    let mut engine = account.session_client().await?;
    let result = async {
        let sender_id = engine.config().device_id.clone();
        let recipient_device_id = route.member_id.as_str();
        if sender_id == recipient_device_id
            && route.member_principal_commitment.as_deref() == Some(&account.principal_commitment) {
            return Ok(None);
        }
        let member_principal_commitment = resolve_group_route_principal_commitment(
            &account.client,
            engine.config(),
            &route,
            recipient_device_id,
            account.timeouts.http,
        )
        .await?;
        let distribution =
            account.client.export_group_sender_key_distribution(group_id, &sender_id)?;
        let decoded_distribution: SdkGroupSenderKeyDistribution =
            serde_json::from_slice(&distribution)?;
        let sender = account.client.owned_device_identity()?;
        let recipient = account.client.device_identity_for_root(&member_principal_commitment, recipient_device_id)?;
        let envelope_id = group_distribution_envelope_id(
            &account.client, group_id, &sender, &recipient, &decoded_distribution)?;
        let submitted_key = format!("group-distribution/submitted/{envelope_id}");
        if account.client.account_db()?.load_actor_state::<bool>(&submitted_key)?.unwrap_or(false) {
            return Ok(Some(serde_json::json!({
                "message_id": envelope_id,
                "recipient_device_id": recipient_device_id,
                "already_submitted": true,
            })));
        }
        let qualified = account.client.root_qualified_device_lookup(recipient.storage_key())?;
        let prekey = group_sender_key_prekey(
            account,
            &mut engine,
            &route,
            &member_principal_commitment,
            &qualified,
        )
        .await?;
        let target_delivery_id =
            route.target_delivery_id.clone().or(prekey.target_delivery_id).ok_or_else(|| {
                SdkError::LocalBus(format!(
                    "missing target delivery id for group sender-key recipient {recipient_device_id}"
                ))
            })?;
        let conversation_id = group_sender_key_distribution_conversation_id(
            group_id,
            &sender_id,
            recipient_device_id,
        );
        let (created_at, ttl) = stable_distribution_header(&account.client, &envelope_id)?;
        let mut message = GatewayDirectMessage {
            conversation_id,
            message_id: envelope_id.clone(),
            envelope_id,
            source_principal_id: engine.config().principal_id.clone(),
            sender_id: sender_id.clone(),
            recipient_device_id: Some(recipient_device_id.to_owned()),
            recipient_principal_commitment: Some(member_principal_commitment.clone()),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at,
            ttl,
        };
        let payload_bytes = group_distribution_payload(
            &account.client, engine.config(), group_id, &recipient)?;
        normalize_generated_group_distribution(&mut message, &payload_bytes)?;
        let value = send_group_sender_key_distribution_message(
            &account.client,
            &mut engine,
            &route,
            DistributionMessage { message, payload: &payload_bytes, group_id, timeout: account.timeouts.http },
        )
        .await?;
        account.client.account_db()?.persist_actor_state(&submitted_key, &true)?;
        Ok(Some(value))
    }
    .await;
    account.apply_session_metadata(engine);
    result
}

async fn group_sender_key_prekey(
    account: &LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    route: &LocalBusGroupMemberRoute,
    commitment: &str,
    qualified: &str,
) -> Result<crate::prekey::SdkPrekeyResponse, SdkError> {
    let caller = route.federation.as_ref().map(|federation| federation.target_node_id.as_str());
    let foreign = crate::client::recipient_home::foreign_target(&account.client, commitment)?;
    if (foreign.is_some() || caller.is_some())
        && let Some(base) =
            crate::client::recipient_home::directory_base(&account.client, commitment, caller, true)
                .await?
    {
        return crate::prekey::http_async::get(
            &base,
            &format!("/mvp1/prekey/{qualified}"),
            account.timeouts.http,
        )
        .await;
    }
    engine.fetch_prekey_bundle(qualified).await
}

fn stable_distribution_header(
    client: &RamfluxClient,
    envelope: &str,
) -> Result<(i64, u32), SdkError> {
    let db = client.account_db()?;
    let key = format!("group-distribution/header/{envelope}");
    db.write_transaction(|| {
        if let Some(header) = db.load_actor_state::<(i64, u32)>(&key)? {
            return Ok(header);
        }
        let header = (now_unix_timestamp(), client.content_ttl()?);
        db.persist_actor_state(&key, &header)?;
        Ok(header)
    })
}

fn group_distribution_envelope_id(
    client: &RamfluxClient,
    group: &str,
    sender: &ramflux_crypto::RootQualifiedDeviceRef,
    recipient: &ramflux_crypto::RootQualifiedDeviceRef,
    distribution: &SdkGroupSenderKeyDistribution,
) -> Result<String, SdkError> {
    let mut key = crate::group::distribution_envelope_key(
        group,
        sender,
        recipient,
        distribution.group_key_epoch,
    )?;
    if let Some(head) = &distribution.group_state_hash {
        key.push('/');
        key.push_str(head);
    }
    key.push('/');
    key.push_str(&ramflux_protocol::hash_base64url(
        "ramflux.group.distribution.content.v3",
        &serde_json::to_vec(distribution)?,
    ));
    if let Some(id) = client.account_db()?.load_actor_state::<String>(&key)? {
        return Ok(id);
    }
    let id =
        format!("envelope_{}", ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?));
    client.account_db()?.persist_actor_state(&key, &id)?;
    Ok(id)
}

fn group_distribution_payload(
    client: &RamfluxClient,
    config: &GatewaySessionConfig,
    group_id: &str,
    recipient: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<Vec<u8>, SdkError> {
    if let Some(state) = client.account_db()?.shared_group_state(group_id)? {
        let state = ramflux_crypto::resign_group_state_snapshot(
            client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &client.owned_group_actor(&config.target_delivery_id)?,
            &state,
        )?;
        client.shared_group_packet_for_recipient(&state, recipient)
    } else {
        Err(SdkError::InboundRejected("verified shared group state required".into()))
    }
}

fn normalize_generated_group_distribution(
    message: &mut GatewayDirectMessage,
    payload: &[u8],
) -> Result<(), SdkError> {
    let inner = <ramflux_protocol::message::Inner as prost::Message>::decode(payload)
        .map_err(|_| SdkError::ReplayMismatch)?;
    message
        .conversation_id
        .clone_from(&inner.identity.as_ref().ok_or(SdkError::ReplayMismatch)?.conversation_id);
    message.message_id =
        RamfluxClient::shared_group_packet_message_id(payload, &message.message_id)?;

    Ok(())
}

struct DistributionMessage<'a> {
    message: GatewayDirectMessage,
    payload: &'a [u8],
    group_id: &'a str,
    timeout: Duration,
}
async fn send_group_sender_key_distribution_message(
    client: &RamfluxClient,
    engine: &mut impl GatewaySessionAccess,
    route: &LocalBusGroupMemberRoute,
    request: DistributionMessage<'_>,
) -> Result<serde_json::Value, SdkError> {
    let DistributionMessage { message, payload, group_id, timeout } = request;
    let kind = crate::client::routed::Route::group_control(group_id);
    if let Some(federation) = route.federation.as_ref() {
        let response = client
            .send_plaintext_federated_message_async(
                engine,
                crate::client::federation::PlaintextForward {
                    content: None,
                    message,
                    plaintext: payload,
                    federation,
                    route: kind,
                    franking: false,
                    timeout,
                },
            )
            .await?;
        return Ok(serde_json::to_value(response)?);
    }
    let entry = client
        .send_plaintext_direct_message_without_franking(engine, message, payload, kind)
        .await?;
    Ok(serde_json::to_value(entry)?)
}

pub(super) async fn resolve_group_route_principal_commitment(
    client: &RamfluxClient,
    gateway: &GatewaySessionConfig,
    route: &LocalBusGroupMemberRoute,
    recipient_device_id: &str,
    timeout: Duration,
) -> Result<String, SdkError> {
    if let Some(federation) = route.federation.as_ref() {
        return resolve_federated_group_member_principal_commitment(
            client,
            federation,
            route.member_principal_commitment.as_deref(),
            recipient_device_id,
            timeout,
        )
        .await;
    }
    client
        .resolve_target_principal_commitment(
            gateway,
            route.member_principal_commitment.as_deref(),
            recipient_device_id,
        )
        .await
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_group_receive_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let mut body: LocalBusGroupReceiveRequest = serde_json::from_value(request.body.clone())?;
    let activated = crate::bus::push_receiver::apply_w1::account_is_active(account)?;
    match crate::bus::account_runtime::head_refresh::take_receive_preparation() {
        Some(true) => {
            if !activated {
                account.client.account_db()?.refuse_legacy_receive()?;
            }
        }
        Some(false) => {
            super::super::sync_driver::run(account).await?;
        }
        None => {
            if !crate::bus::push_receiver::apply_w1::receive_executor_bound(account)? {
                super::super::sync_driver::run(account).await?;
            }
        }
    }
    if !crate::bus::couriers::head_refresh::inbound::blocked_roots(account, &body.group_id)?
        .is_empty()
    {
        return Err(crate::bus::account_runtime::head_refresh::pending(account));
    }
    body.conversation_id = crate::bus::group_conversation::resolve(
        &account.client,
        &body.group_id,
        &body.conversation_id,
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "durable_reader": "message.read",
        "conversation_id": body.conversation_id,
        "snapshot_sequence": account.client.account_db()?.journal_bounds()?.head_seq,
    })))
}

fn group_list_row(
    account: &LocalBusAccountState,
    group: GroupState,
) -> Result<serde_json::Value, SdkError> {
    let db = account.client.account_db()?;
    let shared = db.shared_group_state(&group.group_id)?;
    if shared.is_some() {
        return account
            .client
            .shared_group_metadata(&group.group_id)?
            .ok_or(StorageError::GroupPermissionDenied.into());
    }
    let saved = db.client_record("group", &group.group_id)?;
    let mut metadata = serde_json::to_value(group)?;
    if let Some(state) = shared.as_ref() {
        metadata["name"] = serde_json::json!(state.view().name);
        metadata["name_epoch"] = serde_json::json!(state.view().name_epoch);
    }
    let conversation =
        shared.as_ref().map(|state| state.view().conversation_id.clone()).or_else(|| {
            saved
                .as_ref()
                .and_then(|row| row.get("conversation_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    metadata["conversation_id"] =
        conversation.map_or(serde_json::Value::Null, |id| serde_json::json!(id));
    Ok(metadata)
}

pub(crate) mod history;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn group_wrapper_preserves_existing_typed_error_contracts() {
        let cases = [
            (SdkError::NetworkingPending, "NetworkingPending"),
            (SdkError::CustodyVaultUnavailable, "CustodyVaultUnavailable"),
            (
                SdkError::CustodyVault(crate::custody::CustodyVaultReason::Locked),
                "CustodyVaultUnavailable",
            ),
            (
                SdkError::CustodyVault(crate::custody::CustodyVaultReason::ModeMismatch),
                "CustodySetupInvalid",
            ),
            (
                SdkError::Protocol(ramflux_protocol::ProtocolError::GroupTransferRequiresSync),
                "transfer_requires_sync",
            ),
            (
                SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
                    ramflux_protocol::GroupStateLimit::Members,
                )),
                "GroupStateCapacity",
            ),
            (SdkError::CapabilityDenied("group".into()), "CapabilityDenied"),
        ];
        for (error, expected) in cases {
            let wrapped = group_operation_error("group.send", error, true);
            assert_eq!(crate::bus::io::local_bus_error_code(&wrapped), expected);
        }
        let transfer = group_operation_error(
            "group.member.remove",
            SdkError::Protocol(ramflux_protocol::ProtocolError::GroupTransferRequiresSync),
            true,
        );
        assert_eq!(
            crate::bus::io::local_bus_error_body(&transfer).reason_code.as_deref(),
            Some("head_or_removal_floor_mismatch")
        );
        let generic =
            group_operation_error("group.send", SdkError::LocalBus("denied".into()), true);
        assert_eq!(crate::bus::io::local_bus_error_code(&generic), "GroupSendRefused");
    }

    #[test]
    fn native_group_send_bus_accepts_own_device_id() -> Result<(), SdkError> {
        let gateway = gateway_config("native-principal", "native-device", "native-target");
        let mut body = LocalBusGroupSendRequest {
            content: None,
            group_id: "group".into(),
            conversation_id: "thread".into(),
            message_id: "message".into(),
            sender_id: "native-device".into(),
            encrypted_body_base64: String::new(),
            plaintext_body_base64: None,
            envelope_id: None,
            source_principal_id: None,
            target_delivery_id: None,
            federation: None,
            ttl: None,
        };
        normalize_native_group_sender(&mut body, &gateway)?;
        assert_eq!(body.sender_id, "native-device");
        body.sender_id = "native-principal".into();
        normalize_native_group_sender(&mut body, &gateway)?;
        assert_eq!(body.sender_id, "native-device");
        Ok(())
    }

    fn gateway_config(principal: &str, device: &str, target: &str) -> GatewaySessionConfig {
        GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            gateway_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            server_name: "localhost".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: principal.to_owned(),
            device_id: device.to_owned(),
            target_delivery_id: target.to_owned(),
            prekey_http_url: None,
        })
    }

    pub(super) fn account_state(
        test_name: &str,
        account_id: &str,
        principal: &str,
        device: &str,
        seed: [u8; 32],
    ) -> Result<(ramflux_test_support::TestPath, LocalBusAccountState), SdkError> {
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [0x31; 32]);
        client.create_device_branch(principal, device, 1, seed);
        let root = ramflux_test_support::TestPath::new()
            .expect("test: create group dispatch directory")
            .child(test_name);
        client.open_account_index(&root)?;
        client.create_account(account_id, principal)?;
        client.unlock_account(account_id, b"dispatch-group-test")?;
        let own = client.device_root(&client.local_device_reference(device)?)?;
        let gateway = gateway_config(principal, device, &format!("target_{device}"))
            .with_account_identity(&client)?;
        Ok((root, LocalBusAccountState::disconnected(client, gateway, own)))
    }

    fn member_add_body(group_id: &str, member_id: &str) -> LocalBusGroupMemberAddRequest {
        LocalBusGroupMemberAddRequest {
            group_id: group_id.to_owned(),
            member_id: member_id.to_owned(),
            role: "member".to_owned(),
            member_signing_public_key: Some(format!("{member_id}_key")),
            member_principal_commitment: Some(ramflux_protocol::encode_base64url(
                ramflux_protocol::blake3_hash_bytes(
                    "ramflux.test.group.member.v1",
                    member_id.as_bytes(),
                ),
            )),
            target_delivery_id: Some(format!("target_{member_id}")),
            federation: None,
        }
    }

    fn federation_route() -> LocalBusFederationRoute {
        LocalBusFederationRoute {
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            required_capability: "opaque_delivery".to_owned(),
        }
    }

    #[test]
    fn dispatch_onboard_event_skips_signed_role_local_seed_for_non_admin_signer()
    -> Result<(), SdkError> {
        let (_directory, bob) = account_state(
            "bob_s44_seed",
            "bob_s44_account",
            "principal_bob",
            "bob_device_s44",
            [0x44; 32],
        )?;
        bob.client.create_group("group_s44", "alice_device_s44")?;
        let body = member_add_body("group_s44", "bob_device_s44");
        let group = bob.client.add_group_member(&body.group_id, &body.member_id, &body.role)?;
        let route = LocalBusGroupMemberRoute {
            member_id: body.member_id.clone(),
            member_principal_commitment: body.member_principal_commitment.clone(),
            device_signing_public_key: body.member_signing_public_key.clone(),
            target_delivery_id: body.target_delivery_id.clone(),
            federation: body.federation.clone(),
        };

        assert_eq!(group.roles.get("alice_device_s44").map(String::as_str), Some("owner"));
        assert_eq!(group.roles.get("bob_device_s44").map(String::as_str), Some("member"));
        let event = create_group_member_onboard_event_for_authorized_local_actor(
            &bob, &group, &body, &route,
        )?;
        assert!(event.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn federated_group_member_resolve_requires_remote_manifest_base() -> Result<(), SdkError>
    {
        let (_directory, account) = account_state(
            "alice_federated_missing_manifest_base",
            "alice_account",
            "principal_alice",
            "alice_device",
            [0x42; 32],
        )?;
        let Err(error) = resolve_federated_group_member_principal_commitment(
            &account.client,
            &federation_route(),
            Some("bob_commitment"),
            "bob_device",
            Duration::from_secs(600),
        )
        .await
        else {
            return Err(SdkError::LocalBus(
                "missing pinned home should fail before local gateway resolve".to_owned(),
            ));
        };
        assert!(error.to_string().contains("pinned home"));
        Ok(())
    }

    fn verified_member_add_body(
        client: &RamfluxClient,
        group: &str,
        principal: &str,
        device: &str,
        seed: [u8; 32],
    ) -> Result<LocalBusGroupMemberAddRequest, SdkError> {
        let manifest = crate::client::identity_authority::test_support::remote_manifest(
            principal, device, seed,
        )?;
        client.observe_device_manifest_json(
            serde_json::to_value(&manifest)?,
            &manifest.principal_commitment,
        )?;
        let mut body = member_add_body(group, device);
        body.member_principal_commitment = Some(manifest.principal_commitment);
        body.member_signing_public_key = Some(manifest.devices[0].branch_public_key.clone());
        Ok(body)
    }
    #[test]
    fn dispatch_onboard_event_owner_can_sign_multiple_direct_adds() -> Result<(), SdkError> {
        let (_directory, alice) = account_state(
            "alice_s44_seed",
            "alice_s44_account",
            "principal_alice",
            "alice_device_s44",
            [0x42; 32],
        )?;
        alice.client.create_group("group_s44", "alice_device_s44")?;

        let bob_body = verified_member_add_body(
            &alice.client,
            "group_s44",
            "bob",
            "bob_device_s44",
            [81; 32],
        )?;
        let bob_group = alice.client.account_db()?.add_group_member(
            &bob_body.group_id,
            &bob_body.member_id,
            &bob_body.role,
        )?;
        let bob_route = LocalBusGroupMemberRoute {
            member_id: bob_body.member_id.clone(),
            member_principal_commitment: bob_body.member_principal_commitment.clone(),
            device_signing_public_key: bob_body.member_signing_public_key.clone(),
            target_delivery_id: bob_body.target_delivery_id.clone(),
            federation: bob_body.federation.clone(),
        };
        alice.client.persist_group_member_route("group_s44", &bob_route)?;
        let bob_event = create_group_member_onboard_event_for_authorized_local_actor(
            &alice, &bob_group, &bob_body, &bob_route,
        )?;
        assert!(bob_event.is_some());

        let carol_body = verified_member_add_body(
            &alice.client,
            "group_s44",
            "carol",
            "carol_device_s44",
            [91; 32],
        )?;
        let carol_group = alice.client.account_db()?.add_group_member(
            &carol_body.group_id,
            &carol_body.member_id,
            &carol_body.role,
        )?;
        let carol_route = LocalBusGroupMemberRoute {
            member_id: carol_body.member_id.clone(),
            member_principal_commitment: carol_body.member_principal_commitment.clone(),
            device_signing_public_key: carol_body.member_signing_public_key.clone(),
            target_delivery_id: carol_body.target_delivery_id.clone(),
            federation: carol_body.federation.clone(),
        };
        alice.client.persist_group_member_route("group_s44", &carol_route)?;
        let carol_event = create_group_member_onboard_event_for_authorized_local_actor(
            &alice,
            &carol_group,
            &carol_body,
            &carol_route,
        )?;
        assert!(carol_event.is_some());
        Ok(())
    }
}
