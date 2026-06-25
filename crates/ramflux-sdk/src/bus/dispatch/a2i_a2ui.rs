// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) async fn dispatch_a2i_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    match request.method.as_str() {
        "a2i.append" => {
            let body: LocalBusA2iAppendRequest = serde_json::from_value(request.body.clone())?;
            let event = A2iControlEvent {
                event_id: body.event_id,
                event_type: body.event_type,
                source_device_id: body.source_device_id,
                target_device_id: body.target_device_id,
                control_domain: body.control_domain,
                action: body.action,
                subject_base64: body.subject_base64,
                created_at: body.created_at,
                acknowledged: false,
            };
            let mut engine = account.take_live_engine().await?;
            let entry = account
                .client
                .send_a2i_control_event_via_gateway(&mut engine, &event, body.target_delivery_id)
                .await;
            account.put_engine(engine);
            let entry = entry?;
            Ok(local_bus_ok(serde_json::json!({
                "event": event,
                "submitted": entry,
            })))
        }
        "a2i.list" | "a2i.list_pending" => {
            let mut engine = account.take_live_engine().await?;
            let received = account.client.receive_a2i_control_events(&mut engine, 100).await;
            account.put_engine(engine);
            let received = received?;
            for event in received {
                account.pending_a2i.entry(event.event_id.clone()).or_insert(event);
            }
            Ok(local_bus_ok(serde_json::json!({
                "events": account.pending_a2i.values().cloned().collect::<Vec<_>>(),
            })))
        }
        "a2i.acknowledge" => {
            let body: LocalBusA2iAcknowledgeRequest = serde_json::from_value(request.body.clone())?;
            let event = account.pending_a2i.get_mut(&body.event_id).ok_or_else(|| {
                SdkError::LocalBus(format!("a2i event not found: {}", body.event_id))
            })?;
            event.acknowledged = true;
            Ok(local_bus_ok(serde_json::to_value(event)?))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

pub(crate) fn dispatch_a2ui_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "a2ui.render" => {
            let body: LocalBusA2uiRenderRequest = serde_json::from_value(request.body.clone())?;
            let supported = body.supported_catalogs.into_iter().collect::<BTreeSet<_>>();
            let permissions = body.granted_permissions.into_iter().collect::<BTreeSet<_>>();
            let rendered =
                ramflux_sync::render_a2ui_surface(&body.surface, &supported, &permissions)?;
            Ok(local_bus_ok(serde_json::to_value(rendered)?))
        }
        "a2ui.action" => {
            let account_id = request_account_id(request)?.to_owned();
            let account = local_bus_account_mut(state, &account_id)?;
            let body: LocalBusA2uiActionRequest = serde_json::from_value(request.body.clone())?;
            let signed_action = sign_and_verify_a2ui_action(account, &body.surface, body.action)?;
            let submitted_body = a2ui_action_submitted_event_body(&signed_action);
            connection.push_event(local_bus_event(
                request,
                &account_id,
                "a2ui",
                "ramflux.a2ui.action_submitted",
                submitted_body.clone(),
            ));
            let result_body = a2ui_action_result_event_body(&signed_action, true);
            connection.push_event(local_bus_event(
                request,
                &account_id,
                "a2ui",
                "ramflux.a2ui.action_result",
                result_body.clone(),
            ));
            Ok(local_bus_ok(serde_json::json!({
                "accepted": true,
                "surface_id": signed_action.surface_id,
                "component_id": signed_action.component_id,
                "permission": signed_action.permission,
                "source_device_id": signed_action.source_device_id,
                "target_device_id": signed_action.target_device_id,
                "action": signed_action,
                "event": submitted_body,
                "result": result_body,
            })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn sign_and_verify_a2ui_action(
    account: &LocalBusAccountState,
    surface: &A2uiSurface,
    mut action: A2uiAction,
) -> Result<A2uiAction, SdkError> {
    let device = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    if action.source_device_id != device.device_id {
        return Err(SdkError::LocalBus(format!(
            "A2UI action source device mismatch: expected {}, got {}",
            device.device_id, action.source_device_id
        )));
    }
    if action.signature.is_empty() {
        action.signature = ramflux_crypto::sign_with_device_branch(
            device,
            &ramflux_sync::a2ui_action_signing_body(&action),
        )?;
    }
    let public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    ramflux_sync::verify_a2ui_action_signature(surface, &action, &public_key)?;
    Ok(action)
}

fn a2ui_action_submitted_event_body(action: &A2uiAction) -> serde_json::Value {
    serde_json::json!({
        "event_type": "ramflux.a2ui.action_submitted",
        "surface_id": action.surface_id,
        "surface_hash": action.surface_hash,
        "component_id": action.component_id,
        "permission": action.permission,
        "source_device_id": action.source_device_id,
        "target_device_id": action.target_device_id,
        "created_at": action.created_at,
        "nonce": action.nonce,
        "signature": action.signature,
    })
}

fn a2ui_action_result_event_body(action: &A2uiAction, accepted: bool) -> serde_json::Value {
    serde_json::json!({
        "event_type": "ramflux.a2ui.action_result",
        "surface_id": action.surface_id,
        "surface_hash": action.surface_hash,
        "component_id": action.component_id,
        "permission": action.permission,
        "source_device_id": action.source_device_id,
        "target_device_id": action.target_device_id,
        "created_at": action.created_at,
        "nonce": action.nonce,
        "accepted": accepted,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ramflux_sync::{A2uiComponent, a2ui_surface_hash};

    fn test_state() -> LocalBusDaemonState {
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_a2ui_test", [0x31; 32]);
        client.create_device_branch("principal_a2ui_test", "app_device_a2ui", 1, [0x32; 32]);
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("valid bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("valid gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_a2ui_test".to_owned(),
            device_id: "app_device_a2ui".to_owned(),
            target_delivery_id: "target_a2ui_test".to_owned(),
            prekey_http_url: None,
        });
        LocalBusDaemonState {
            config: LocalBusConfig::new("bus.sock", "data"),
            accounts: BTreeMap::from([(
                "acct".to_owned(),
                LocalBusAccountState::disconnected(client, gateway),
            )]),
            active_account_id: Some("acct".to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    fn test_connection(connection_id: u64) -> LocalBusConnectionState {
        let (outbound, _inbound) = mpsc::channel(8);
        let mut connection = LocalBusConnectionState::new(connection_id, outbound);
        connection.topics.extend([
            "ramflux.a2ui.action_submitted".to_owned(),
            "ramflux.a2ui.action_result".to_owned(),
        ]);
        connection
    }

    fn surface() -> A2uiSurface {
        A2uiSurface {
            surface_id: "surface_a2ui_test".to_owned(),
            catalog: "ramflux.basic.v1".to_owned(),
            catalog_version: "1".to_owned(),
            components: vec![A2uiComponent {
                id: "approve".to_owned(),
                component_type: "approval_card".to_owned(),
                action_permission: Some("mcp.approve".to_owned()),
                children: Vec::new(),
            }],
        }
    }

    fn action(surface: &A2uiSurface) -> A2uiAction {
        A2uiAction {
            surface_id: surface.surface_id.clone(),
            surface_hash: a2ui_surface_hash(surface).expect("surface hash"),
            component_id: "approve".to_owned(),
            permission: "mcp.approve".to_owned(),
            source_device_id: "app_device_a2ui".to_owned(),
            target_device_id: "cli_ai_device".to_owned(),
            created_at: 1_760_000_700,
            nonce: "nonce_bus_a2ui".to_owned(),
            signature: String::new(),
        }
    }

    fn request(surface: &A2uiSurface, action: &A2uiAction) -> LocalBusFrame {
        LocalBusFrame::request(
            "req_a2ui",
            Some("acct".to_owned()),
            "a2ui",
            "a2ui.action",
            serde_json::json!({
                "surface": surface,
                "action": action,
            }),
        )
    }

    #[test]
    fn a2ui_action_bus_signs_and_emits_canonical_events() {
        let mut state = test_state();
        let surface = surface();
        let mut connection = test_connection(1);
        let result = dispatch_a2ui_bus_request(
            &request(&surface, &action(&surface)),
            &mut state,
            &mut connection,
        )
        .expect("a2ui action");
        assert_eq!(result.response_body["accepted"], true);
        assert!(
            result.response_body["action"]["signature"]
                .as_str()
                .is_some_and(|signature| !signature.is_empty())
        );
        let events = connection.drain_events();
        assert_eq!(
            events.iter().map(|event| event.method.as_str()).collect::<Vec<_>>(),
            ["ramflux.a2ui.action_submitted", "ramflux.a2ui.action_result"]
        );
    }

    #[test]
    fn a2ui_action_bus_rejects_tampered_binding_or_pseudo_signature() {
        let mut state = test_state();
        let surface = surface();
        let mut tampered = action(&surface);
        tampered.component_id = "other".to_owned();
        assert!(
            dispatch_a2ui_bus_request(
                &request(&surface, &tampered),
                &mut state,
                &mut test_connection(1),
            )
            .is_err()
        );

        let mut pseudo = action(&surface);
        pseudo.signature = "attended-local:approve".to_owned();
        assert!(
            dispatch_a2ui_bus_request(
                &request(&surface, &pseudo),
                &mut state,
                &mut test_connection(2),
            )
            .is_err()
        );
    }
}
