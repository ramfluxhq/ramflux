// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real transfer packet selection must distinguish storage failure from malformed persisted rows.
use super::*;
use crate::client::shared_group::{TransferBody, TransferControl};
use std::sync::{Arc, atomic::AtomicBool};

fn staged_account(root: &Path) -> Result<LocalBusAccountState, SdkError> {
    let account =
        crate::bus::runtime_tests::account(root, "owner", None, Arc::new(AtomicBool::new(false)))?;
    let client = &account.client;
    let state = client.shared_group_create("group", "thread", None, "target")?;
    let actor = client.owned_group_actor("target")?;
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

#[test]
fn shared_group_packet_selection_propagates_real_sqlite_write_refusal() -> Result<(), SdkError> {
    let root = crate::bus::runtime_tests::root("transfer-packet-storage");
    let mut account = staged_account(&root)?;
    assert_eq!(pending_packets(&account.client, now_unix_timestamp())?.len(), 1);
    let reader = account.client.account_db()?.open_reader()?;
    account.client.active_account_db = Some(reader);
    assert!(matches!(
        pending_packets(&account.client, now_unix_timestamp()),
        Err(SdkError::Storage(StorageError::Sqlite(_)))
    ));
    assert_eq!(account.client.account_db()?.actor_state_usage(maintenance::BACKOFF)?.0, 0);
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_group_packet_selection_backs_off_bad_row_without_hiding_healthy_packet()
-> Result<(), SdkError> {
    let root = crate::bus::runtime_tests::root("transfer-packet-backoff");
    let account = staged_account(&root)?;
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
    std::fs::remove_dir_all(root)?;
    Ok(())
}
