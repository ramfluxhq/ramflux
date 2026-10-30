// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 selectors reach the signed shared-group path without a legacy identity root.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn native_principal_creates_and_renames_a_signed_group() -> TestResult {
    let owner = Fixture::with_device("native-bus-owner", "owner-device").await?;
    let mut account = LocalBusAccountState::disconnected(
        owner.client,
        owner.config,
        owner.manifest.principal_commitment.clone(),
    );
    let mut setup =
        LocalBusConfig::new(owner.root.0.join("bus.sock"), owner.root.0.join("bus-data"));
    setup.custody_vault = Some(owner.vault);
    account.native_setup = Some(setup);
    account.put_engine(GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(crate::bus::dispatch::surface_transport::fixture::RecordingGateway::new(
            Arc::new(Mutex::new(Vec::new())),
        )),
    ));

    let create = LocalBusFrame::request(
        "native-group-create",
        Some("native-bus-owner".into()),
        "ramflux.sdk.v1",
        "group.create",
        json!({
            "group_id": "native-bus-group",
            "conversation_id": "native-bus-thread",
            "creator_id": owner.manifest.principal_id,
            "name": "Native group"
        }),
    );
    let created = dispatch(&create, &mut account).await?.ok_or("group create was not handled")?;
    assert_eq!(created["name"], "Native group");
    let state = account
        .client
        .account_db()?
        .shared_group_state("native-bus-group")?
        .ok_or("signed group state missing")?;
    assert!(state.creator().native_authority.is_some());
    assert!(account.client.identity_root.is_none());

    let rename = LocalBusFrame::request(
        "native-group-rename",
        Some("native-bus-owner".into()),
        "ramflux.sdk.v1",
        "group.name.set",
        json!({"group_id":"native-bus-group","name":"Renamed native group"}),
    );
    let renamed = dispatch(&rename, &mut account).await?.ok_or("group rename was not handled")?;
    assert_eq!(renamed["name"], "Renamed native group");
    assert!(account.client.identity_root.is_none());
    Ok(())
}

#[tokio::test]
async fn cached_native_principal_selects_its_only_active_device() -> TestResult {
    let owner = Fixture::new("native-member-owner").await?;
    let member = Fixture::with_device("native-member-peer", "peer-device").await?;
    owner.client.persist_fetched_identity_directory(&member.manifest)?;
    let selected = cached_principal_member(&owner.client, &member.manifest.principal_id)?
        .ok_or("native principal selector was not resolved")?;
    assert_eq!(selected.0, member.manifest.principal_commitment);
    assert_eq!(selected.1, "peer-device");
    Ok(())
}
