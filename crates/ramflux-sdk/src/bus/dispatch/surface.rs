// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface authoring through the existing message paths; only the account actor mutates state.
use crate::client::surface::{Carrier, PayloadKind, command_id, invalid};
use crate::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    conversation_id: String,
    message_id: String,
    wire_base64: String,
    #[serde(default)]
    author_principal_id: Option<String>,
}
pub(crate) async fn dispatch_surface(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    _connection: &LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let id = request_account_id(request)?;
    if request.method == "surface.request_resync" {
        let reference = required(&request.body, "surface_ref")?;
        return request_resync(local_bus_account_mut(state, id)?, reference)
            .await
            .map(local_bus_ok);
    }
    if request.method == "surface.resync" {
        let reference = required(&request.body, "surface_ref")?;
        let message = request.body["message_id"]
            .as_str()
            .map(str::to_owned)
            .map_or_else(crate::new_surface_message_id, Ok)?;
        let account = local_bus_account_mut(state, id)?;
        let candidate = account.client.prepare_surface_resync(reference, &message)?;
        let carrier = account.client.reuse_authored_surface(&candidate)?.unwrap_or(candidate);
        let response = super::surface_transport::send(account, &carrier).await?;
        return Ok(local_bus_ok(response));
    }
    let body: Send = serde_json::from_value(request.body.clone())?;
    let raw = ramflux_protocol::decode_base64url(&body.wire_base64)
        .map_err(|_| invalid("invalid surface wire encoding"))?;
    let kind =
        if request.method == "surface.send" { PayloadKind::Event } else { PayloadKind::Action };
    let surface_id = match kind {
        PayloadKind::Event => {
            command_id(ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&raw)?.command())
                .to_owned()
        }
        PayloadKind::Action => {
            ramflux_protocol::A2uiSurfaceAction::from_wire_bytes(&raw)?.surface_id().to_owned()
        }
        PayloadKind::ActionReceipt => return Err(invalid("action receipts are internal")),
    };
    let (carrier, preflight) = {
        let account = local_bus_account(state, id)?;
        let client = &account.client;
        let _thread = client
            .account_db()?
            .client_record("conversation", &body.conversation_id)?
            .ok_or_else(|| invalid("surface requires an existing conversation"))?;
        let carrier = prepare_carrier(client, &body, kind.clone(), &raw, &surface_id)?;
        let preflight = if let Some(outcome) = client.surface_delivery_receipt(&carrier)? {
            outcome
        } else {
            client.preflight_surface(&carrier)?
        };
        (carrier, preflight)
    };
    if let Some(receipt) =
        local_bus_account(state, id)?.client.surface_delivery_receipt(&carrier)?
        && (!receipt.accepted
            || local_bus_account(state, id)?.client.surface_outgoing_submitted(&carrier)?)
    {
        let mut response = serde_json::to_value(receipt)?;
        response["replayed"] = json!(true);
        return Ok(local_bus_ok(response));
    }
    if !preflight.accepted {
        let result = local_bus_account(state, id)?.client.project_surface_message(
            &body.conversation_id,
            &body.message_id,
            crate::client::surface::SurfaceSender {
                principal: &carrier.sender_principal_id,
                device: &carrier.sender_device_id,
                envelope_id: &body.message_id,
                expires_at: None,
                group_epoch: None,
            },
            &carrier.bytes()?,
            true,
        )?;
        return Ok(local_bus_ok(serde_json::to_value(result)?));
    }
    let response =
        super::surface_transport::send(local_bus_account_mut(state, id)?, &carrier).await?;
    Ok(local_bus_ok(response))
}

pub(crate) fn read_surface(
    client: &RamfluxClient,
    request: &LocalBusFrame,
) -> Result<Value, SdkError> {
    match request.method.as_str() {
        "surface.get" => {
            let after = request.body["history_after"].as_u64().unwrap_or(0);
            let action = request.body["action_id"].as_str();
            if let Some(reference) = request.body["surface_ref"].as_str() {
                client.surface_get_ref(reference, after, action)
            } else if request.body["conversation_id"].is_string()
                || request.body["author_principal_id"].is_string()
            {
                let reference = client.resolve_surface_reference(
                    required(&request.body, "surface_id")?,
                    request.body["conversation_id"].as_str(),
                    request.body["author_principal_id"].as_str(),
                )?;
                reference.map_or(Ok(Value::Null), |reference| {
                    client.surface_get_ref(&reference, after, action)
                })
            } else {
                client.surface_get(required(&request.body, "surface_id")?, after, action)
            }
        }
        "surface.list" => client.surface_list(
            required(&request.body, "conversation_id")?,
            request.body["cursor"].as_str().unwrap_or(""),
            request.body["limit"]
                .as_u64()
                .map(u32::try_from)
                .transpose()
                .map_err(|_| invalid("invalid surface list limit"))?
                .unwrap_or(50),
        ),
        _ => Err(invalid("unsupported surface read")),
    }
}
fn required<'a>(body: &'a Value, field: &str) -> Result<&'a str, SdkError> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("surface read identifier required"))
}

fn prepare_carrier(
    client: &RamfluxClient,
    body: &Send,
    kind: PayloadKind,
    raw: &[u8],
    surface_id: &str,
) -> Result<Carrier, SdkError> {
    let device = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let create = kind == PayloadKind::Event
        && matches!(
            ramflux_protocol::A2uiConversationEvent::from_wire_bytes(raw)?.command(),
            ramflux_protocol::A2uiConversationCommand::CreateSurface(_)
        );
    let owner = if create {
        if body.author_principal_id.as_deref().is_some_and(|author| author != device.principal_id) {
            return Err(invalid("surface create author must be the authenticated account"));
        }
        device.principal_id.clone()
    } else if let Some(reference) = client.resolve_surface_reference(
        surface_id,
        Some(&body.conversation_id),
        body.author_principal_id.as_deref(),
    )? {
        client
            .surface_state_ref(&reference)?
            .ok_or_else(|| invalid("surface view has no state"))?
            .0
            .author_principal_id
    } else {
        body.author_principal_id.clone().unwrap_or_else(|| device.principal_id.clone())
    };
    let mut carrier = Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        payload_kind: kind,
        conversation_id: body.conversation_id.clone(),
        surface_id: surface_id.to_owned(),
        message_id: body.message_id.clone(),
        sender_principal_id: device.principal_id.clone(),
        sender_device_id: device.device_id.clone(),
        author_principal_id: owner,
        wire_base64: body.wire_base64.clone(),
        signature: String::new(),
        snapshot: None,
    };
    if let Some(previous) = client.reuse_authored_surface(&carrier)? {
        return Ok(previous);
    }
    client.attach_surface_snapshot(&mut carrier)?;
    client.sign_surface_carrier(carrier)
}

pub(super) async fn request_resync(
    account: &mut LocalBusAccountState,
    reference: &str,
) -> Result<Value, SdkError> {
    let Some(request) = account.client.prepare_surface_resync_request(reference)? else {
        return Ok(json!({"rate_limited":true,"retry_after_seconds":60}));
    };
    let root = if account
        .client
        .device_branch
        .as_ref()
        .is_some_and(|local| local.principal_id == request.author)
    {
        account.client.surface_local_root_commitment()?
    } else {
        account
            .client
            .account_db()?
            .client_record("identity", &request.author)?
            .and_then(|identity| {
                identity["contact_identity_commitment"].as_str().map(str::to_owned)
            })
            .ok_or_else(|| invalid("surface author root is unknown"))?
    };
    let mut engine = account.take_live_engine().await?;
    let result=async {
        let manifest=account.client.cache_verified_device_manifest(&engine.config,&root,"surface_resync_author").await?;
        if manifest.principal_id!=request.author || manifest.devices.is_empty() {return Err(invalid("surface resync author manifest mismatch"));}
        let body=serde_json::to_vec(&request)?;
        let mut failure=None;
        let mut submitted=0;
        for device in manifest.devices {
            if request.author==engine.config.principal_id && device.device_id==engine.config.device_id {continue;}
            let request:LocalBusMessageSubmitRequest=serde_json::from_value(json!({"conversation_id":request.conversation_id,"message_id":crate::new_surface_message_id()?,"envelope_id":crate::new_surface_message_id()?,"source_principal_id":engine.config.principal_id,"sender_id":engine.config.device_id,"recipient_device_id":device.device_id,"recipient_principal_commitment":root,"target_delivery_id":device.target_delivery_id,"encrypted_body_base64":"","created_at":now_unix_timestamp(),"ttl":600}))?;
            let message=request.into_gateway_message_with_body(Vec::new());
            match account.client.send_plaintext_direct_message_without_franking(&mut engine,message,&body,crate::client::routed::Route::control()).await {
                Ok(_)=>submitted+=1,
                Err(error)=>{failure.get_or_insert(error);}
            }
        }
        if submitted==0 && let Some(error)=failure {return Err(error);}
        Ok(json!({"submitted_devices":submitted,"rate_limited":false,"retry_after_seconds":60}))
    }.await;
    account.put_engine(engine);
    result
}
