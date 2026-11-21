// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact state events and identity directory rows share one safety-verification source.
use super::*;
use serde_json::json;

fn opened(
    result: Result<crate::client::native_test_support::Fixture, Box<dyn std::error::Error>>,
) -> Result<crate::client::native_test_support::Fixture, SdkError> {
    result.map_err(|error| SdkError::LocalBus(error.to_string()))
}

#[tokio::test]
async fn contact_changes_publish_reachability_kind_and_current_safety_verification()
-> Result<(), SdkError> {
    let local =
        opened(crate::client::native_test_support::Fixture::new("contact-state-local").await)?;
    let peer =
        opened(crate::client::native_test_support::Fixture::new("contact-state-peer").await)?;
    let client = &local.client;
    client.persist_observed_identity_directory_now(&peer.manifest)?;
    let own = local.manifest.principal_commitment.clone();
    let peer_root = peer.manifest.principal_commitment.clone();
    let peer_id = peer.manifest.principal_id.clone();
    client.establish_friend_link("contact", &own, &peer_root)?;
    let db = client.account_db()?;
    let mut identity = db
        .client_record("identity", &peer_id)?
        .ok_or_else(|| SdkError::LocalBus("fixture identity absent".into()))?;
    identity["devices"] = json!([]);
    identity["kind_asserted"] = serde_json::Value::Null;
    db.persist_client_record("identity", &peer_id, &identity)?;
    let mut entry = ramflux_storage::AccountOutboxEntry {
        sequence: 1,
        table_name: "runtime_actor_state".into(),
        change_kind: "update".into(),
        row_id: 1,
        keys: json!({"state_kind": format!("directory/identity/{peer_id}")}),
    };
    let before = super::super::journal::project(client, &entry)?;
    assert!(before.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["reachable"] == false
        && row["verified"] == false));
    identity["devices"] = json!([{"device_id":"peer-device","target_delivery_id":"peer-target"}]);
    identity["kind_asserted"] = json!("bot");
    db.persist_client_record("identity", &peer_id, &identity)?;
    let resolved = super::super::journal::project(client, &entry)?;
    assert!(resolved.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["reachable"] == true
        && row["kind_asserted"] == "bot"
        && row["verified"] == false));
    crate::client::contact_verification_cas::verify_linked_contact(client, &peer_root)?;
    assert!(db.actor_state_exists(&format!("identity/safety_verified_set/{peer_root}"))?);
    entry.table_name = "contact_verification_projection".into();
    entry.keys = json!({"contact_identity_commitment": peer_root});
    let verified = super::super::journal::project(client, &entry)?;
    assert!(verified.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["verified"] == true
        && row["safety_state"] == "verified"));
    assert!(verified.iter().any(|(topic, _, _)| topic == "safety.changed"));
    let mut native = peer
        .manifest
        .custody
        .as_deref()
        .ok_or_else(|| SdkError::LocalBus("fixture custody absent".into()))?
        .clone();
    let primary = peer.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    body.profile.display_name = "Renamed Peer".into();
    native.publication.record = primary.sign_record(body)?;
    client.observe_custody_manifest(&native, &peer_root, crate::custody::network_now()?)?;
    let stale = super::super::journal::project(client, &entry)?;
    assert!(stale.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["verified"] == false
        && row["safety_state"] == "verification_stale"));
    drop(local);
    drop(peer);
    Ok(())
}

#[tokio::test]
async fn owned_profile_publication_preserves_self_device_routes_during_daemon_initialization()
-> Result<(), SdkError> {
    let fixture =
        opened(crate::client::native_test_support::Fixture::new("owned-profile-route").await)?;
    let account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment.clone(),
    );
    super::super::read_model::initialize(&account)?;
    let row = super::super::read_model::row(
        &account.client,
        "identity",
        &account.gateway_config.principal_id,
    )?;
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
