// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Real transfer packet selection must distinguish storage failure from malformed persisted rows.
use super::*;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::{Fixture as Native, TestResult};
use crate::client::shared_group::{TransferBody, TransferControl};

async fn staged_account_async() -> TestResult<LocalBusAccountState> {
    let account = Native::with_device("owner", "owner").await?.into_bus();
    let client = &account.client;
    let state = client.fixture_group_create("group", "thread", None, "owner")?;
    let actor = client.fixture_group_actor("owner")?;
    let now = now_unix_timestamp();
    let body: TransferBody = serde_json::from_value(serde_json::json!({
        "kind":"probe", "probe":{
            "id":ramflux_protocol::encode_base64url([1;32]),
            "actor":actor,"creator":actor,"base":state.snapshot(),
            "required":[{"root":actor.identity.root_commitment,"device":"other-device"}],
            "issued_at":now,"expires_at":now+60
        }
    }))?;
    client.stage_group_transfer_control(TransferControl::sign(client, body)?)?;
    Ok(account)
}

fn staged_account() -> Result<LocalBusAccountState, SdkError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(staged_account_async())
        .map_err(|error| SdkError::LocalBus(error.to_string()))
}

#[test]
fn shared_group_packet_selection_propagates_real_sqlite_write_refusal() -> Result<(), SdkError> {
    let mut account = staged_account()?;
    assert_eq!(pending_packets(&account.client, now_unix_timestamp())?.len(), 1);
    // Selection rewrites a row only when its stored bytes differ from the canonical record, so
    // store the row with an extra field to make the next selection a real write.
    let db = account.client.account_db()?;
    let id = maintenance::page(db, TRANSFER_SEND_PREFIX, now_unix_timestamp(), 512)?.remove(0);
    let mut stored =
        db.load_actor_state::<serde_json::Value>(&id)?.ok_or(SdkError::LocalBus("row".into()))?;
    stored["stored_before_canonical_rewrite"] = serde_json::json!(true);
    db.persist_actor_state(&id, &stored)?;
    let reader = account.client.account_db()?.open_reader()?;
    account.client.active_account_db = Some(reader);
    assert!(matches!(
        pending_packets(&account.client, now_unix_timestamp()),
        Err(SdkError::Storage(StorageError::Sqlite(_)))
    ));
    assert_eq!(account.client.account_db()?.actor_state_usage(maintenance::BACKOFF)?.0, 0);
    drop(account);
    Ok(())
}

#[test]
fn shared_group_packet_selection_backs_off_bad_row_without_hiding_healthy_packet()
-> Result<(), SdkError> {
    let account = staged_account()?;
    let db = account.client.account_db()?;
    let bad = format!("{TRANSFER_SEND_PREFIX}!bad");
    db.persist_actor_state(&bad, &serde_json::json!({"bad":true}))?;
    let now = now_unix_timestamp();
    assert_eq!(pending_packets(&account.client, now)?.len(), 1);
    let marker_key = format!("{}{bad}", maintenance::BACKOFF);
    let marker = db.load_actor_state::<serde_json::Value>(&marker_key)?;
    assert!(marker.is_some());
    assert_eq!(pending_packets(&account.client, now + 1)?.len(), 1);
    assert_eq!(db.load_actor_state::<serde_json::Value>(&marker_key)?, marker);
    assert_eq!(
        db.load_actor_state::<serde_json::Value>(&bad)?,
        Some(serde_json::json!({"bad":true}))
    );
    drop(account);
    Ok(())
}

#[tokio::test]
async fn bad_deadline_item_does_not_abort_later_courier_work() -> Result<(), SdkError> {
    let mut account =
        staged_account_async().await.map_err(|error| SdkError::LocalBus(error.to_string()))?;
    let bad = "group-transfer/pending/!bad";
    account.client.account_db()?.persist_actor_state(bad, &serde_json::json!({"bad":true}))?;
    assert!(background::prepare_for_test(&mut account)?);
    let db = account.client.account_db()?;
    assert!(db.actor_state_exists(&format!("{}{bad}", maintenance::BACKOFF))?);
    assert!(db.load_actor_state::<String>("group-courier/cursor")?.is_some());
    drop(account);
    Ok(())
}
