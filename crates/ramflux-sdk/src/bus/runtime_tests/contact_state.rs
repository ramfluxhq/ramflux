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
    let mut identity = json!({"id":"peer","principal_id":"peer","contact_identity_commitment":"root-peer","device_set_hash":"devices-peer","devices":[],"kind_asserted":null});
    db.persist_client_record("identity", "peer", &identity)?;
    db.persist_client_record("commitment", "root-peer", &json!({"principal_id":"peer"}))?;
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
        contact_identity_commitment: "root-peer",
        safety_number_hash: "safety",
        device_set_hash: "devices-peer",
        lineage_head: "lineage",
        verified_at: now_unix_timestamp(),
        verified_by_device_id: "local",
    })?;
    entry.table_name = "contact_verification_projection".into();
    entry.keys = json!({"contact_identity_commitment":"root-peer"});
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
