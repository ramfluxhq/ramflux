// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) async fn dispatch_a2i_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "a2i.list" | "a2i.list_pending" => list_a2i(request, state),
        "a2i.acknowledge" => acknowledge_a2i(request, state),
        "a2i.append" => append_a2i(request, state).await,
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn list_a2i(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = super::local_bus_account(state, account_id)?;
    let pending = request.method == "a2i.list_pending";
    Ok(super::local_bus_ok(account.client.a2i_events_json(pending)?))
}

fn acknowledge_a2i(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusA2iAcknowledgeRequest = serde_json::from_value(request.body.clone())?;
    let account_id = request_account_id(request)?;
    let account = super::local_bus_account_mut(state, account_id)?;
    let row = account.client.acknowledge_stored_a2i(&body.event_id)?;
    for cached in account.pending_a2i.values_mut() {
        if cached.event_id == row.event_id {
            cached.acknowledged = true;
        }
    }
    Ok(super::local_bus_ok(serde_json::to_value(row)?))
}

fn request_event(body: &LocalBusA2iAppendRequest) -> A2iControlEvent {
    A2iControlEvent {
        event_id: body.event_id.clone(),
        event_type: body.event_type.clone(),
        source_device_id: body.source_device_id.clone(),
        source_principal_id: None,
        source_principal_commitment: None,
        target_device_id: body.target_device_id.clone(),
        control_domain: body.control_domain.clone(),
        action: body.action.clone(),
        subject_base64: body.subject_base64.clone(),
        created_at: body.created_at,
        acknowledged: false,
    }
}

async fn append_a2i(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusA2iAppendRequest = serde_json::from_value(request.body.clone())?;
    let event = request_event(&body);
    let account_id = request_account_id(request)?;
    let account = super::local_bus_account_mut(state, account_id)?;
    account.client.validate_a2i_sender(account.gateway_config.principal_id.as_str(), &event)?;
    let mut engine = account.session_client().await?;
    let entry = account.client.deliver_a2i(&mut engine, &event, body.target_delivery_id).await?;
    account.apply_session_metadata(engine);
    Ok(super::local_bus_ok(serde_json::to_value(entry)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_state() -> LocalBusDaemonState {
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_a2ui_test", [0x31; 32]);
        client.create_device_branch("principal_a2ui_test", "app_device_a2ui", 1, [0x32; 32]);
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("test: valid bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("test: valid gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_a2ui_test".to_owned(),
            device_id: "app_device_a2ui".to_owned(),
            target_delivery_id: "target_a2ui_test".to_owned(),
            prekey_http_url: None,
        });
        LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new("bus.sock", "data"),
            accounts: BTreeMap::from([(
                "acct".to_owned(),
                LocalBusAccountState::disconnected(
                    client,
                    gateway,
                    "principal_a2ui_test".to_owned(),
                ),
            )]),
            active_account_id: Some("acct".to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn a2i_bus_methods_refuse_before_account_or_gateway_access() {
        let mut state = test_state();
        for method in ["a2i.append", "a2i.list", "a2i.list_pending", "a2i.acknowledge"] {
            let request = LocalBusFrame::request(
                "refused",
                Some("acct".into()),
                "a2i",
                method,
                serde_json::json!({"event_id":"old-event"}),
            );
            assert!(dispatch_a2i_bus_request(&request, &mut state).await.is_err());
            assert_eq!(
                state.accounts.get("acct").expect("test: fixture account").pending_a2i.len(),
                0
            );
        }
    }
}
