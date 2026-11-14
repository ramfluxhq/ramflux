// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn dispatch_a2i_bus_request(
    _request: &LocalBusFrame,
    _state: &mut LocalBusDaemonState,
) -> impl std::future::Future<Output = Result<LocalBusDispatchResult, SdkError>> {
    // Retained legacy rows cannot supply the missing native binding/grant authority.
    std::future::ready(RamfluxClient::refuse_a2i_binding_authority())
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
            assert!(matches!(
                dispatch_a2i_bus_request(&request, &mut state).await,
                Err(SdkError::GeneratedRefused {
                    code: crate::error::GeneratedRefusalCode::Authority,
                    ..
                })
            ));
            assert_eq!(
                state.accounts.get("acct").expect("test: fixture account").pending_a2i.len(),
                0
            );
        }
    }
}
