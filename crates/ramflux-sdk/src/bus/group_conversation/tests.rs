// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Saved native links are repaired before networking and before control dispatch.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicBool};

fn create_group(owner: &Fixture, group: &str, thread: &str) -> TestResult {
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native account")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        group,
        thread,
        Some("Original".into()),
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    Ok(())
}

fn polluted_link(db: &AccountDb, group: &str, thread: &str) -> TestResult<Value> {
    let mut value = json!({"conversation_id":null,"conversation_ids":[thread,"operator-thread"],
        "custom":"preserved","safety_changes":[{"kind":"verified"}]});
    db.persist_client_record("group", group, &value)?;
    db.persist_client_record(
        "conversation",
        "operator-thread",
        &json!({
            "kind":"group","group_id":group,"title":"Old empty selector","participants":[]
        }),
    )?;
    value["conversation_id"] = thread.into();
    value["conversation_ids"] = json!([thread]);
    Ok(value)
}

#[tokio::test]
async fn native_group_link_repairs_at_account_open_before_any_group_command() -> TestResult {
    let id = "native-link-open";
    let owner = Fixture::new(id).await?;
    create_group(&owner, "z-group", "signed-thread")?;
    let db = owner.client.account_db()?;
    // Put the signed group beyond the first directory page, mixed with unsigned old groups.
    for index in 0..100 {
        db.create_group(&format!("a-page-{index:03}"), "old-owner")?;
    }
    let legacy_link = json!({"conversation_id":null,"conversation_ids":["old-a","old-b"]});
    db.persist_client_record("group", "a-page-000", &legacy_link)?;
    let expected = polluted_link(db, "z-group", "signed-thread")?;
    let selector = db.client_record("conversation", "operator-thread")?;
    let root = owner.root.0.clone();
    drop(owner.client);
    for _ in 0..2 {
        let mut reopened = RamfluxClient::new();
        reopened.open_account_index(&root)?;
        reopened.unlock_account(id, b"native fixture data passphrase")?;
        let db = reopened.account_db()?;
        assert_eq!(db.client_record("group", "z-group")?, Some(expected.clone()));
        assert_eq!(db.client_record("group", "a-page-000")?, Some(legacy_link.clone()));
        assert_eq!(db.client_record("conversation", "operator-thread")?, selector);
    }
    Ok(())
}

#[tokio::test]
async fn native_group_link_open_leaves_legacy_signed_groups_unchanged() -> TestResult {
    let root = crate::bus::runtime_tests::root("legacy-link-open");
    let account = crate::bus::runtime_tests::account(
        &root,
        "legacy",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    account.client.shared_group_create("legacy-group", "legacy-thread", None, "target")?;
    let db = account.client.account_db()?;
    polluted_link(db, "legacy-group", "legacy-thread")?;
    let original = db.client_record("group", "legacy-group")?;
    drop(account);
    let mut reopened = RamfluxClient::new();
    reopened.open_account_index(&root)?;
    reopened.unlock_account("legacy", b"actor-test-secret")?;
    assert!(reopened.born_v3_account.is_none());
    assert_eq!(reopened.account_db()?.client_record("group", "legacy-group")?, original);
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn native_group_link_repairs_before_rename_and_preserves_metadata_on_second_command()
-> TestResult {
    let owner = Fixture::new("native-link-rename").await?;
    create_group(&owner, "group", "group")?;
    let root = owner.root.0.clone();
    let mut setup = LocalBusConfig::new(root.join("bus.sock"), &root);
    setup.custody_vault = Some(owner.vault);
    let mut account = LocalBusAccountState::disconnected(
        owner.client,
        owner.config,
        owner.manifest.principal_commitment,
    );
    account.native_setup = Some(setup.clone());
    // Pollution happens after opening, so the startup repair cannot satisfy this regression.
    let expected = polluted_link(account.client.account_db()?, "group", "group")?;
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: setup,
        accounts: BTreeMap::from([("native-link-rename".into(), account)]),
        active_account_id: Some("native-link-rename".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    for name in ["First rename", "Second rename"] {
        let request = LocalBusFrame::request(
            name,
            Some("native-link-rename".into()),
            "ramflux.sdk.v1",
            "group.name.set",
            json!({"group_id":"group","name":name}),
        );
        let result =
            crate::bus::dispatch::group::dispatch_group_bus_request(&request, &mut state).await?;
        assert_eq!(result.response_body["name"], name);
        let db = state.accounts.get("native-link-rename").ok_or("account")?.client.account_db()?;
        assert_eq!(db.client_record("group", "group")?, Some(expected.clone()));
        assert!(db.client_record("conversation", "operator-thread")?.is_some());
    }
    Ok(())
}
