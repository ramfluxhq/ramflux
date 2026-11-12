// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Producer and courier-plan rows for outgoing own-root history.
use super::producer::{Cursor, MAX_PAGE_ITEMS, Outgoing, RESTART_AFTER_IDLE_SECS};
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn history_chain_restart_keeps_item_cursor_and_starts_at_page_zero() -> TestResult {
    let own = Fixture::new("history-producer-restart").await?;
    let mut row = Outgoing::new(&own.client.owned_device_identity()?, 1)?;
    let first = row.transfer_id.clone();
    assert_eq!(first.len(), 32);
    assert!(!row.chain_expired(i64::MAX), "page zero never needs a restart");
    row.next_page = 3;
    row.last_digest = vec![9; 32];
    row.last_submit_at = 100;
    row.cursor = Some(Cursor { conversation: "c".into(), created_at: 7, message: "m".into() });
    assert!(!row.chain_expired(100 + RESTART_AFTER_IDLE_SECS - 1));
    assert!(row.chain_expired(100 + RESTART_AFTER_IDLE_SECS));
    row.restart_chain()?;
    assert_eq!((row.next_page, row.last_digest.clone()), (0, vec![0; 32]));
    assert_ne!(row.transfer_id, first, "a restarted chain never reuses its transfer id");
    assert_eq!(row.cursor.as_ref().map(|cursor| cursor.message.as_str()), Some("m"));
    assert!(row.in_flight.is_none());
    Ok(())
}

#[tokio::test]
async fn history_staging_refuses_the_local_device_and_a_foreign_root() -> TestResult {
    let own = Fixture::new("history-producer-own").await?;
    let peer = Fixture::new("history-producer-peer").await?;
    assert!(
        own.client.stage_generated_history_transfer(&own.client.owned_device_identity()?).is_err(),
        "a device never transfers history to itself"
    );
    assert!(
        own.client.stage_generated_history_transfer(&peer.client.owned_device_identity()?).is_err(),
        "history pages never leave the account root"
    );
    assert_eq!(own.client.account_db()?.actor_state_keys("history-out/")?, Vec::<String>::new());
    assert_eq!(own.client.start_generated_history_transfers()?, 0, "no sibling, no transfer");
    Ok(())
}

#[tokio::test]
async fn history_producer_finishes_an_empty_store_without_a_page() -> TestResult {
    let own = Fixture::new("history-producer-empty").await?;
    assert!(own.client.build_generated_history_page(&[1; 32], 0, &[0; 32], None)?.is_none());
    Ok(())
}

#[tokio::test]
async fn history_producer_skips_rows_without_first_hand_evidence() -> TestResult {
    let own = Fixture::new("history-producer-skip").await?;
    own.client.send_direct_message("legacy", "old-history", "alice", b"no retained origin")?;
    let built = own
        .client
        .build_generated_history_page(&[1; 32], 0, &[0; 32], None)?
        .ok_or("the skipped row must still advance the cursor")?;
    assert!(built.page.items.is_empty(), "a row without origin evidence is never forwarded");
    assert!(built.owners.is_empty());
    assert_eq!(built.skipped, 1);
    assert_eq!(built.after.message, "old-history");
    assert!(
        own.client
            .build_generated_history_page(&[1; 32], 0, &[0; 32], Some(&built.after))?
            .is_none(),
        "the cursor is strictly increasing"
    );
    Ok(())
}

#[tokio::test]
async fn history_courier_stays_dormant_before_schema_activation() -> TestResult {
    let own = Fixture::new("history-producer-dormant").await?;
    if !crate::client::target_selection::schema_v1_selected() {
        assert!(own.client.prepare_generated_history_delivery(&own.config)?.is_none());
    }
    Ok(())
}

#[test]
fn history_page_digest_binds_transfer_page_previous_and_exact_items() -> TestResult {
    use prost::Message as _;
    let item = g::HistoryItem { exact_inner: vec![1, 2, 3], ..Default::default() }.encode_to_vec();
    let base = g::history_chain::digest(&[1; 32], 0, &[0; 32], &[&item])?;
    assert_ne!(base, g::history_chain::digest(&[2; 32], 0, &[0; 32], &[&item])?);
    assert_ne!(base, g::history_chain::digest(&[1; 32], 1, &[0; 32], &[&item])?);
    assert_ne!(base, g::history_chain::digest(&[1; 32], 0, &[3; 32], &[&item])?);
    assert_ne!(base, g::history_chain::digest(&[1; 32], 0, &[0; 32], &[&item, &item])?);
    let over = vec![item.as_slice(); MAX_PAGE_ITEMS + 1];
    assert!(g::history_chain::digest(&[1; 32], 0, &[0; 32], &over).is_err());
    Ok(())
}

#[tokio::test]
async fn history_cached_page_is_erased_with_any_carried_owner() -> TestResult {
    let own = Fixture::new("history-producer-erase").await?;
    own.client.send_direct_message("c", "first", "alice", b"a")?;
    own.client.send_direct_message("c", "second", "alice", b"b")?;
    let db = own.client.account_db()?;
    let key = super::producer::page_key("sibling");
    db.write_transaction(|| {
        db.persist_actor_state(&key, &serde_json::json!({"sealed": "page"}))?;
        db.bind_message_container_reference("first", &key)?;
        db.bind_message_container_reference("second", &key)?;
        Ok::<_, SdkError>(())
    })?;
    assert!(db.actor_state_exists(&key)?);
    db.delete_direct_message("c", "second", "local", "erase-second")?;
    assert!(
        !db.actor_state_exists(&key)?,
        "erasing any carried owner invalidates the whole cached page"
    );
    Ok(())
}
