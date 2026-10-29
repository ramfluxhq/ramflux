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
