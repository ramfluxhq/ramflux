// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native roster reads require public authority, never a legacy recovery manifest.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
#[tokio::test]
async fn native_device_list_uses_the_certified_roster_without_a_legacy_manifest() -> TestResult {
    let native = Fixture::new("native-device-roster").await?;
    let root = native.root.0.clone();
    let anchor = native.manifest.principal_commitment.clone();
    let state = LocalBusDaemonState {
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        accounts: BTreeMap::from([(
            "native-device-roster".into(),
            LocalBusAccountState::disconnected(native.client, native.config, anchor.clone()),
        )]),
        active_account_id: Some("native-device-roster".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    assert!(!local_bus_account_manifest_path(&root, "native-device-roster").exists());
    let request = LocalBusFrame::request(
        "roster",
        Some("native-device-roster".into()),
        "device",
        "device.list",
        serde_json::json!({}),
    );
    let reply = dispatch_device_list(&request, &state)?.response_body;
    assert_eq!(reply["local_device_id"], "primary");
    assert_eq!(reply["devices"][0]["device_id"], "primary");
    assert_eq!(reply["devices"][0]["device_epoch"], 1);
    assert_eq!(reply["devices"][0]["is_local"], true);
    assert_eq!(
        reply["devices"][0]["target_delivery_id"],
        ramflux_protocol::qualified_device_id(&anchor, "primary")?
    );
    assert!(
        reply["devices"][0]["capability_scope"]
            .as_array()
            .ok_or("capabilities")?
            .iter()
            .any(|scope| scope == "sync")
    );
    Ok(())
}

#[tokio::test]
async fn native_device_revoke_refuses_missing_native_config_before_legacy_manifest() -> TestResult {
    let native = Fixture::new("native-revoke-route").await?;
    let root = native.root.0.clone();
    let mut gateway = native.config;
    gateway.custody = None;
    let mut state = LocalBusDaemonState {
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        accounts: BTreeMap::from([(
            "native-revoke-route".into(),
            LocalBusAccountState::disconnected(
                native.client,
                gateway,
                native.manifest.principal_commitment,
            ),
        )]),
        active_account_id: Some("native-revoke-route".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    assert!(!local_bus_account_manifest_path(&root, "native-revoke-route").exists());
    let request = LocalBusFrame::request(
        "native-revoke",
        Some("native-revoke-route".into()),
        "device",
        "device.revoke",
        serde_json::json!({"device_id":"secondary"}),
    );
    let result = dispatch_device_revoke(
        &request,
        &mut state,
        LocalBusDeviceRevokeRequest { device_id: "secondary".into() },
    )
    .await;
    assert!(
        matches!(result, Err(SdkError::NetworkingPending)),
        "native requests must not enter the legacy root/manifest path"
    );
    assert!(!local_bus_account_manifest_path(&root, "native-revoke-route").exists());
    Ok(())
}
