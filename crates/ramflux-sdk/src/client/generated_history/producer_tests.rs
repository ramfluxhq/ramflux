// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Producer and courier-plan rows for outgoing own-root history.
use super::producer::{Cursor, MAX_PAGE_ITEMS, Outgoing, RESTART_AFTER_IDLE_SECS};
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn history_chain_restart_reexports_prefix_and_starts_at_page_zero() -> TestResult {
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
    assert!(row.cursor.is_none(), "gateway acceptance never proves an imported prefix");
    assert!(row.in_flight.is_none());
    Ok(())
}

#[tokio::test]
async fn history_staging_refuses_the_local_device_and_a_foreign_root() -> TestResult {
    let own = Fixture::new("history-producer-own").await?;
    let peer = Fixture::new("history-producer-peer").await?;
    assert_eq!(
        own.client.history_target_epoch(&peer.client.owned_device_identity()?)?,
        None,
        "a foreign root is excluded before any history target lookup"
    );
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
    let id = ramflux_protocol::encode_base64url([7; 32]);
    own.client.send_direct_message("legacy", &id, "alice", b"no retained origin")?;
    let built = own
        .client
        .build_generated_history_page(&[1; 32], 0, &[0; 32], None)?
        .ok_or("the skipped row must still advance the cursor")?;
    assert!(built.page.items.is_empty(), "a row without origin evidence is never forwarded");
    assert_eq!(built.owners.len(), 0);
    assert_eq!(built.skipped, 1);
    assert_eq!(built.after.message, id);
    assert!(
        own.client
            .build_generated_history_page(&[1; 32], 0, &[0; 32], Some(&built.after))?
            .is_none(),
        "the cursor is strictly increasing"
    );
    Ok(())
}

#[tokio::test]
async fn history_courier_has_no_work_without_retained_history() -> TestResult {
    let own = Fixture::new("history-producer-dormant").await?;
    assert!(own.client.prepare_generated_history_delivery(&own.config)?.is_none());
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

/// The 32-byte secrets a stored pair snapshot holds: root key, both chain keys and the
/// private ratchet key. Zero or absent entries are not secrets.
fn live_pair_secrets(db: &ramflux_storage::AccountDb) -> TestResult<Vec<[u8; 32]>> {
    const MAX_SESSIONS: usize = 16;
    const FIELDS: [&str; 4] =
        ["root_key", "sending_chain_key", "receiving_chain_key", "dhs_private"];
    let mut secrets = Vec::new();
    for key in db.actor_state_keys("dm-pair/session/")?.into_iter().take(MAX_SESSIONS) {
        let record: serde_json::Value =
            db.load_actor_state(&key)?.ok_or("stored pair session record")?;
        for field in FIELDS {
            let Some(values) = record["snapshot"][field].as_array() else { continue };
            let bytes = values
                .iter()
                .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Option<Vec<u8>>>()
                .ok_or("pair secret is a byte array")?;
            let secret = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "pair secret width")?;
            if secret != [0; 32] {
                secrets.push(secret);
            }
        }
    }
    Ok(secrets)
}

fn holds_bytes(haystack: &[u8], needle: &[u8; 32]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Rule 14: live pair secrets are never part of an own-device history export. The page is
/// built from a real first-hand receive, so the store holds the live pair for that peer.
#[tokio::test]
async fn history_export_never_contains_live_pair_secrets() -> TestResult {
    use prost::Message as _;
    let mut source = Fixture::new("history-secret-source").await?;
    let peer = Fixture::new("history-secret-peer").await?;
    let (original, retained, _) = Box::pin(
        crate::client::native_test_support::history::receive_first_hand(&mut source, &peer),
    )
    .await?;
    let secrets = live_pair_secrets(source.client.account_db()?)?;
    assert!(
        secrets.len() >= 3,
        "the receive must leave a live pair with root, chain and ratchet secrets: {}",
        secrets.len()
    );
    let control = [vec![0xa5; 7], secrets[0].to_vec(), vec![0x5a; 7]].concat();
    assert!(holds_bytes(&control, &secrets[0]), "the byte scan must find a planted secret");

    let built = source
        .client
        .build_generated_history_page(&[1; 32], 0, &[0; 32], None)?
        .ok_or("the first-hand row must produce a history page")?;
    assert_eq!(built.page.items.len(), 1, "the export must carry the first-hand message");
    assert_eq!(built.page.items[0], retained, "the item is the exact retained evidence");
    assert_eq!(built.owners, vec![ramflux_protocol::encode_base64url(&original.id)]);
    let (_, inner) = source.client.encode_generated_history_page(&built)?;
    let mut produced = vec![built.page.encode_to_vec(), inner];
    produced.extend(built.page.items.iter().map(prost::Message::encode_to_vec));
    for (index, bytes) in produced.iter().enumerate() {
        assert!(!bytes.is_empty(), "produced history bytes {index} must not be empty");
        for secret in &secrets {
            assert!(
                !holds_bytes(bytes, secret),
                "a live pair secret appears in produced history bytes {index}"
            );
        }
    }
    Ok(())
}
