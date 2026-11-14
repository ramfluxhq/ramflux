// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact state events and identity directory rows share one safety-verification source.
use super::*;
use serde_json::json;
#[tokio::test]
async fn contact_changes_publish_reachability_kind_and_current_safety_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let account =
        Box::pin(crate::client::native_test_support::Fixture::with_device("local", "device-local"))
            .await?
            .into_bus();
    let client = &account.client;
    let db = client.account_db()?;
    let mut peer =
        Box::pin(crate::client::native_test_support::Fixture::with_device("peer", "peer-device"))
            .await?
            .into_bus();
    let _sibling = Box::pin(crate::client::native_test_support::bus::sibling(
        &mut peer,
        "peer-secondary",
        "secondary",
    ))
    .await?;
    let manifest =
        peer.client.native_bus_fixture.as_ref().ok_or("peer native material")?.manifest.clone();
    client.persist_fetched_identity_directory(&manifest)?;
    let mut identity = db
        .client_record("identity", &manifest.principal_id)?
        .ok_or_else(|| SdkError::LocalBus("fixture identity absent".into()))?;
    identity["devices"] = json!([]);
    identity["kind_asserted"] = serde_json::Value::Null;
    db.persist_client_record("identity", &manifest.principal_id, &identity)?;
    db.persist_client_record(
        "commitment",
        &manifest.principal_commitment,
        &json!({"principal_id":manifest.principal_id}),
    )?;
    let mut entry = ramflux_storage::AccountOutboxEntry {
        sequence: 1,
        table_name: "runtime_actor_state".into(),
        change_kind: "update".into(),
        row_id: 1,
        keys: json!({"state_kind":format!("directory/identity/{}", manifest.principal_id)}),
    };
    let before = super::super::journal::project(client, &entry)?;
    assert!(before.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["reachable"] == false
        && row["verified"] == false));
    client.establish_friend_link(
        "contact",
        &client.own_account_anchor()?,
        &manifest.principal_commitment,
    )?;
    identity["devices"] = json!([{"device_id":"peer-device","target_delivery_id":"peer-target"}]);
    identity["kind_asserted"] = json!("human");
    db.persist_client_record("identity", &manifest.principal_id, &identity)?;
    let resolved = super::super::journal::project(client, &entry)?;
    assert!(resolved.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["reachable"] == true
        && row["kind_asserted"] == "human"
        && row["verified"] == false));
    client.establish_friend_link(
        "contact",
        &client.own_account_anchor()?,
        &manifest.principal_commitment,
    )?;
    client.mark_contact_safety_verified(&manifest.principal_commitment, "device-local")?;
    entry.table_name = "contact_verification_projection".into();
    entry.keys = json!({"contact_identity_commitment":manifest.principal_commitment});
    let verified = super::super::journal::project(client, &entry)?;
    assert!(verified.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["verified"] == true
        && row["safety_state"] == "verified"));
    assert!(verified.iter().any(|(topic, _, _)| topic == "safety.changed"));
    crate::client::native_test_support::bus::revoke_device(&mut peer, "secondary")?;
    let changed =
        &peer.client.native_bus_fixture.as_ref().ok_or("updated peer native material")?.manifest;
    client.persist_fetched_identity_directory(changed)?;
    let stale = super::super::journal::project(client, &entry)?;
    assert!(stale.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["verified"] == false
        && row["safety_state"] == "verification_stale"));
    drop(account);
    Ok(())
}

#[test]
fn owned_profile_publication_preserves_self_device_routes_during_daemon_initialization()
-> Result<(), SdkError> {
    let root = root("owned-profile-route");
    let account = account(&root, "local", None, Arc::new(AtomicBool::new(false)))?;
    let record = account.client.prepare_owned_authority(None)?;
    account.client.accept_owned_record(&record)?;
    super::super::read_model::initialize(&account)?;
    let row = super::super::read_model::row(&account.client, "identity", "local")?;
    assert_eq!(row["kind"], "human");
    assert_eq!(row["kind_verified"], true);
    assert!(row["devices"].as_array().is_some_and(|devices| {
        devices.iter().any(|device| {
            device["device_id"] == account.gateway_config.device_id
                && device["target_delivery_id"] == account.gateway_config.target_delivery_id
        })
    }));
    drop(account);
    Ok(())
}
