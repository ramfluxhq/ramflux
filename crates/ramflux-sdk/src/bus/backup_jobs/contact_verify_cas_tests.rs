// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A native archive never reinstalls contact-safety evidence or its origin bytes.
use super::native_tests::{self, ARCHIVE_SECRET, LOCAL_SECRET};
use super::tests::{call, finished};
use crate::client::native_test_support::Fixture;
use crate::custody::tests::{Root, TestVault, create};
use crate::prelude::*;
use ramflux_crypto::backup_stream::BackupStreamDecoder;
use ramflux_protocol::message as g;
use serde_json::json;
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const MERGED: &str = "directory/conversation/cas-restore";

fn grant_rows(path: &std::path::Path, key: &ramflux_storage::AccountDbKey) -> TestResult<i64> {
    use std::fmt::Write;
    let mut hex = zeroize::Zeroizing::new(String::new());
    for byte in key.bytes() {
        write!(&mut *hex, "{byte:02x}")?;
    }
    let db = rusqlite::Connection::open(path)?;
    let pragma = zeroize::Zeroizing::new(format!("PRAGMA key=\"x'{}'\"", hex.as_str()));
    db.execute_batch(&pragma)?;
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM runtime_actor_state WHERE state_kind LIKE 'identity/contact_safety_confirmation/%' OR state_kind LIKE 'identity/contact_safety_origin_inner/%'",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

fn unpack_archive(
    archive: &std::path::Path,
    snapshot: &std::path::Path,
) -> TestResult<ramflux_storage::AccountDbKey> {
    let mut file = std::io::BufReader::new(std::fs::File::open(archive)?);
    let decoder = BackupStreamDecoder::open(&mut file, ARCHIVE_SECRET.as_bytes())?;
    let mut unpack = super::format::Unpack::new(std::fs::File::create(snapshot)?);
    decoder.decrypt(&mut file, &mut unpack)?;
    let metadata = unpack.finish()?;
    Ok(ramflux_storage::AccountDbKey::from_bytes(metadata.database_key))
}

fn live_grants(root: &std::path::Path, grant: &str, origin: &str) -> TestResult<(bool, bool)> {
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.unlock_account("account", LOCAL_SECRET.as_bytes())?;
    let db = client.account_db()?;
    Ok((db.actor_state_exists(grant)?, db.actor_state_exists(origin)?))
}

fn history_denial(root: &std::path::Path, inner: Vec<u8>, grant: &str, origin: &str) -> TestResult {
    let mut restored = RamfluxClient::new();
    restored.open_account_index(root)?;
    restored.unlock_account("account", LOCAL_SECRET.as_bytes())?;
    let item = g::HistoryItem {
        exact_inner: inner,
        source_evidence: None,
        tombstone: None,
        exact_original_identity: Vec::new(),
        original_metadata_evidence: None,
    };
    assert!(
        !restored.import_generated_history_message(&restored.owned_device_identity()?, &item)?,
        "history replay cannot import a verification grant"
    );
    assert!(!restored.account_db()?.actor_state_exists(grant)?);
    assert!(!restored.account_db()?.actor_state_exists(origin)?);
    Ok(())
}

async fn install_without_importing_grant(
    root: &std::path::Path,
    archive: &std::path::Path,
    grant: &str,
    origin: &str,
) -> TestResult {
    let target = native_tests::supervisor(root)?;
    let id = native_tests::verify(&target, archive).await?;
    call(&target, "account.restore.install", None, json!({"job_id": id})).await?;
    finished(&target, &id, crate::backup::BackupJobState::Done).await?;
    target.shutdown().await?;
    let mut reopened = RamfluxClient::new();
    reopened.open_account_index(root)?;
    reopened.unlock_account("account", LOCAL_SECRET.as_bytes())?;
    assert_eq!(
        reopened.account_db()?.load_actor_state::<serde_json::Value>(MERGED)?,
        Some(json!({"merged": true})),
        "live data merge restores a non-grant row"
    );
    assert!(reopened.account_db()?.actor_state_exists(grant)?, "matching live evidence survives");
    reopened.account_db()?.remove_actor_state(grant)?;
    reopened.account_db()?.remove_actor_state(origin)?;
    drop(reopened);
    let again = native_tests::supervisor(root)?;
    let second = native_tests::verify(&again, archive).await?;
    call(&again, "account.restore.install", None, json!({"job_id": second})).await?;
    finished(&again, &second, crate::backup::BackupJobState::Done).await?;
    again.shutdown().await?;
    assert_eq!(live_grants(root, grant, origin)?, (false, false), "a fresh grant is not imported");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn verify_cas_restore_never_imports_a_grant() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let root = Root::new()?;
            let vault = Arc::new(TestVault::default());
            let account =
                create(&root.0, "account", vault.as_ref(), crate::custody::network_now()?)?;
            let mut client = RamfluxClient::new();
            client.open_account_index(&root.0)?;
            client.seal_new_account_data(
                "account",
                &account.record().body.account_anchor,
                LOCAL_SECRET.as_bytes(),
            )?;
            client.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            client.initialize_born_v3_branch("primary", vault.clone()).await?;
            let peer = Fixture::new("cas-restore-peer").await?;
            let peer_root = peer.manifest.principal_commitment.clone();
            let grant_key = format!("identity/contact_safety_confirmation/{peer_root}");
            let origin_key = format!("identity/contact_safety_origin_inner/{peer_root}");
            client.persist_observed_identity_directory_now(&peer.manifest)?;
            client.establish_friend_link(
                "restore-link",
                &client.own_account_anchor()?,
                &peer_root,
            )?;
            let verified = crate::client::contact_verification_cas::verify_linked_contact(
                &client, &peer_root,
            )?;
            assert_eq!(verified.verification_state, "verified");
            let origin_text = client
                .account_db()?
                .load_actor_state::<String>(&origin_key)?
                .ok_or("destination origin")?;
            let origin_bytes = ramflux_protocol::decode_base64url(&origin_text)
                .map_err(|_| "destination origin bytes")?;
            let db = client.account_db()?;
            db.persist_actor_state(MERGED, &json!({"merged": true}))?;
            drop(client);
            let source = native_tests::supervisor(&root.0)?;
            let archive = root.0.join("data.rfb");
            native_tests::make_archive(&source, &archive).await?;
            source.shutdown().await?;
            let snapshot = root.0.join("unpacked.db");
            let key = unpack_archive(&archive, &snapshot)?;
            assert_eq!(
                grant_rows(&snapshot, &key)?,
                0,
                "sanitize strips confirmation and origin bytes"
            );
            let mut live = RamfluxClient::new();
            live.open_account_index(&root.0)?;
            live.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            assert!(
                live.account_db()?.actor_state_exists(&grant_key)?,
                "export leaves the live grant"
            );
            live.account_db()?.remove_actor_state(MERGED)?;
            drop(live);
            vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
            let locked = crate::bus::supervisor::Supervisor::new(LocalBusConfig::new(
                root.0.join("locked.sock"),
                &root.0,
            ))?;
            let locked_id = native_tests::verify(&locked, &archive).await?;
            assert!(matches!(
                call(&locked, "account.restore.install", None, json!({"job_id": locked_id})).await,
                Err(SdkError::AccountDbNotUnlocked)
            ));
            finished(&locked, &locked_id, crate::backup::BackupJobState::Verified).await?;
            locked.shutdown().await?;
            assert_eq!(
                live_grants(&root.0, &grant_key, &origin_key)?,
                (true, true),
                "a failed restore preserves the destination"
            );
            let mut cleared = RamfluxClient::new();
            cleared.open_account_index(&root.0)?;
            cleared.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            assert!(cleared.account_db()?.load_actor_state::<serde_json::Value>(MERGED)?.is_none());
            drop(cleared);
            vault.fail.store(false, std::sync::atomic::Ordering::SeqCst);
            install_without_importing_grant(&root.0, &archive, &grant_key, &origin_key).await?;
            history_denial(&root.0, origin_bytes, &grant_key, &origin_key)?;
            let mut reopened = RamfluxClient::new();
            reopened.open_account_index(&root.0)?;
            reopened.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            reopened.initialize_born_v3_branch("primary", vault.clone()).await?;
            let renewed = crate::client::contact_verification_cas::verify_linked_contact(
                &reopened, &peer_root,
            )?;
            assert_eq!(renewed.verification_state, "verified", "fresh comparison re-verifies");
            Ok(())
        }))
        .await
}
