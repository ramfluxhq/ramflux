// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact state events and identity directory rows share one safety-verification source.
use super::*;
use serde_json::json;
#[test]
fn contact_changes_publish_reachability_kind_and_current_safety_verification()
-> Result<(), SdkError> {
    let root = root("contact-state");
    let account = account(&root, "local", None, Arc::new(AtomicBool::new(false)))?;
    let client = &account.client;
    let db = client.account_db()?;
    client.establish_friend_link("contact", "local", "peer")?;
    let manifest = crate::client::identity_authority::test_support::remote_manifest(
        "peer",
        "peer-device",
        [89; 32],
    )?;
    client.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    let mut identity = db
        .client_record("identity", "peer")?
        .ok_or_else(|| SdkError::LocalBus("fixture identity absent".into()))?;
    let device_hash = identity["device_set_hash"]
        .as_str()
        .ok_or_else(|| SdkError::LocalBus("fixture hash absent".into()))?
        .to_owned();
    identity["devices"] = json!([]);
    identity["kind_asserted"] = serde_json::Value::Null;
    db.persist_client_record("identity", "peer", &identity)?;
    db.persist_client_record(
        "commitment",
        &manifest.principal_commitment,
        &json!({"principal_id":"peer"}),
    )?;
    let mut entry = ramflux_storage::AccountOutboxEntry {
        sequence: 1,
        table_name: "runtime_actor_state".into(),
        change_kind: "update".into(),
        row_id: 1,
        keys: json!({"state_kind":"directory/identity/peer"}),
    };
    let before = super::super::journal::project(client, &entry)?;
    assert!(before.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["reachable"] == false
        && row["verified"] == false));
    identity["devices"] = json!([{"device_id":"peer-device","target_delivery_id":"peer-target"}]);
    identity["kind_asserted"] = json!("bot");
    db.persist_client_record("identity", "peer", &identity)?;
    let resolved = super::super::journal::project(client, &entry)?;
    assert!(resolved.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["reachable"] == true
        && row["kind_asserted"] == "bot"
        && row["verified"] == false));
    db.mark_contact_verified(ContactVerificationUpdate {
        contact_identity_commitment: &manifest.principal_commitment,
        safety_number_hash: "safety",
        device_set_hash: &device_hash,
        lineage_head: "lineage",
        verified_at: now_unix_timestamp(),
        verified_by_device_id: "local",
    })?;
    db.persist_actor_state(
        &format!("identity/safety_verified_set/{}", manifest.principal_commitment),
        &crate::client::identity_authority::set_fingerprint(
            manifest
                .signed_device_set
                .as_ref()
                .ok_or_else(|| SdkError::LocalBus("fixture set absent".into()))?,
        )?,
    )?;
    entry.table_name = "contact_verification_projection".into();
    entry.keys = json!({"contact_identity_commitment":manifest.principal_commitment});
    let verified = super::super::journal::project(client, &entry)?;
    assert!(verified.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["verified"] == true
        && row["safety_state"] == "verified"));
    assert!(verified.iter().any(|(topic, _, _)| topic == "safety.changed"));
    identity["device_set_hash"] = json!("changed-device-set");
    db.persist_client_record("identity", "peer", &identity)?;
    let stale = super::super::journal::project(client, &entry)?;
    assert!(stale.iter().any(|(topic, row, _)| topic == "contact.changed"
        && row["verified"] == false
        && row["safety_state"] == "verification_stale"));
    drop(account);
    std::fs::remove_dir_all(root)?;
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
    std::fs::remove_dir_all(root)?;
    Ok(())
}
