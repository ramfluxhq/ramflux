// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Saved native links are repaired before networking and before control dispatch.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::{Value, json};
use std::fmt::Write as _;
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

#[derive(Clone, Default)]
struct StartupWarnings(Arc<std::sync::Mutex<Vec<String>>>);

impl tracing::Subscriber for StartupWarnings {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.level() == &tracing::Level::WARN
            && metadata.target() == "ramflux_sdk::bus::group_conversation"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields<'a>(&'a mut String);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                let _ = write!(self.0, " {field}={value:?}");
            }
        }
        if self.enabled(event.metadata()) {
            let mut line = event.metadata().level().to_string();
            event.record(&mut Fields(&mut line));
            self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn native_group_link_open_isolates_corrupt_groups_and_keeps_command_errors() -> TestResult {
    let id = "native-link-corrupt";
    let owner = Fixture::new(id).await?;
    for group in ["a-corrupt-state", "b-forged-state", "z-healthy"] {
        create_group(&owner, group, &format!("signed-{group}"))?;
        polluted_link(owner.client.account_db()?, group, &format!("signed-{group}"))?;
    }
    let db = owner.client.account_db()?;
    // The healthy group sorts onto page two, after both failing groups and old unsigned ones.
    for index in 0..98 {
        db.create_group(&format!("m-page-{index:03}"), "old-owner")?;
    }
    let corrupt_links = [
        db.client_record("group", "a-corrupt-state")?,
        db.client_record("group", "b-forged-state")?,
    ];
    let expected = polluted_link(db, "z-healthy", "signed-z-healthy")?;
    let corrupt_key =
        format!("group-state/{}", ramflux_protocol::encode_base64url("a-corrupt-state"));
    let private_body = "private-record-body-sentinel";
    db.persist_actor_state(&corrupt_key, &private_body)?;
    let forged_key =
        format!("group-state/{}", ramflux_protocol::encode_base64url("b-forged-state"));
    let mut forged =
        db.shared_group_state("b-forged-state")?.ok_or("signed state")?.snapshot().clone();
    forged.signature = ramflux_protocol::encode_base64url([0; 64]);
    db.persist_actor_state(&forged_key, &forged)?;
    let root = owner.root.0.clone();
    drop(owner.client);
    let mut reopened = RamfluxClient::new();
    reopened.open_account_index(&root)?;
    let logs = StartupWarnings::default();
    tracing::subscriber::with_default(logs.clone(), || {
        reopened.unlock_account(id, b"native fixture data passphrase")
    })?;
    let db = reopened.account_db()?;
    assert_eq!(db.client_record("group", "z-healthy")?, Some(expected));
    assert_eq!(db.client_record("group", "a-corrupt-state")?, corrupt_links[0]);
    assert_eq!(db.client_record("group", "b-forged-state")?, corrupt_links[1]);
    assert_eq!(db.load_actor_state::<String>(&corrupt_key)?.as_deref(), Some(private_body));
    {
        let warnings = logs.0.lock().map_err(|_| "warning log lock")?;
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("group_id=a-corrupt-state"), "{warnings:?}");
        assert!(warnings[0].contains("error_class=\"record_decode\""), "{warnings:?}");
        assert!(warnings[1].contains("group_id=b-forged-state"), "{warnings:?}");
        assert!(warnings[1].contains("error_class=\"state_verification\""), "{warnings:?}");
        assert!(warnings.iter().all(|line| !line.contains(private_body)), "{warnings:?}");
    }
    let mut setup = LocalBusConfig::new(root.join("bus.sock"), &root);
    setup.custody_vault = Some(owner.vault);
    let mut account = LocalBusAccountState::disconnected(
        reopened,
        owner.config,
        owner.manifest.principal_commitment,
    );
    account.native_setup = Some(setup.clone());
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: setup,
        accounts: BTreeMap::from([(id.into(), account)]),
        active_account_id: Some(id.into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    for group in ["a-corrupt-state", "b-forged-state"] {
        let request = LocalBusFrame::request(
            group,
            Some(id.into()),
            "ramflux.sdk.v1",
            "group.name.set",
            json!({"group_id":group,"name":"Must not be applied"}),
        );
        let error = crate::bus::dispatch::group::dispatch_group_bus_request(&request, &mut state)
            .await
            .err()
            .ok_or("corrupt group command unexpectedly succeeded")?;
        let SdkError::GroupRefused { operation, source } = error else {
            return Err("expected typed group refusal".into());
        };
        assert_eq!(operation, crate::GroupOperation::Rename);
        if group == "a-corrupt-state" {
            assert!(matches!(*source, SdkError::Storage(StorageError::Serde(_))), "{source:?}");
        } else {
            assert!(matches!(*source, SdkError::Storage(StorageError::Crypto(_))), "{source:?}");
        }
    }
    Ok(())
}
