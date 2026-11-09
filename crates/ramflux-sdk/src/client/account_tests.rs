// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account client tests moved out of production `account.rs` so the P19 writer
//! inventory counts production TEXT only (S6b P24b1 r4 L1).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WRITER_CHILD: &str = "client::account::tests::account_writer_sdk_process_fixture";
const WRITER_ROOT_ENV: &str = "RAMFLUX_SDK_WRITER_TEST_ROOT";

fn temp_root(test_name: &str) -> PathBuf {
    let nanos =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir()
        .join(format!("ramflux-sdk-account-{test_name}-{}-{nanos}", std::process::id()))
}

fn wrapped_db_key(
    root: &Path,
    local_account_id: &str,
    secret: &[u8],
) -> Result<AccountDbKey, SdkError> {
    let index = AccountIndex::open(root)?;
    let vault_secret = FileVaultSecretSource::new(index.root()).vault_secret(local_account_id)?;
    let wrapped = index
        .load_wrapped_db_key(local_account_id)?
        .ok_or_else(|| SdkError::LocalBus(format!("missing wrapped key for {local_account_id}")))?;
    Ok(unwrap_with_vault_secret(&account_db_key_encryption_key(&vault_secret, secret), &wrapped)?)
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn writer_child(root: &Path) -> Result<ChildGuard, Box<dyn std::error::Error>> {
    Ok(ChildGuard(
        Command::new(std::env::current_exe()?)
            .args(["--exact", WRITER_CHILD, "--nocapture"])
            .env(WRITER_ROOT_ENV, root)
            .stdin(Stdio::null())
            .spawn()?,
    ))
}

fn wait_for_writer_child(root: &Path) -> Result<ChildGuard, Box<dyn std::error::Error>> {
    let mut child = writer_child(root)?;
    let ready = root.join("sdk-writer-ready");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(child.0.try_wait()?.is_none(), "writer child exited before readiness");
        assert!(Instant::now() < deadline, "writer child startup timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(child)
}

#[test]
fn account_writer_sdk_process_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::var_os(WRITER_ROOT_ENV) else {
        return Ok(());
    };
    let index = AccountIndex::open(root)?;
    let _lease = index.acquire_account_writer("acct")?;
    std::fs::write(index.root().join("sdk-writer-ready"), [])?;
    std::thread::sleep(Duration::from_secs(60));
    Ok(())
}

#[test]
fn first_unlock_does_not_write_a_wrapped_key_before_process_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("first-unlock-process-race");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    assert!(index.load_wrapped_db_key("acct")?.is_none());
    let holder = wait_for_writer_child(&root)?;

    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    assert!(matches!(
        client.unlock_account("acct", b"losing-secret"),
        Err(SdkError::Storage(StorageError::AccountWriterBusy(ref account))) if account == "acct"
    ));
    assert!(matches!(
        client.seal_new_account_data("acct", "principal", b"losing-secret"),
        Err(SdkError::Storage(StorageError::AccountWriterBusy(ref account))) if account == "acct"
    ));
    assert!(
        index.load_wrapped_db_key("acct")?.is_none(),
        "a refused first unlock must not publish its generated wrapped key"
    );
    assert!(
        !FileVaultSecretSource::new(&root).vault_secret_path("acct").exists(),
        "a refused first unlock must not create vault material"
    );

    drop(holder);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn secret_verification_does_not_create_vault_material_before_process_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("verify-secret-process-race");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let holder = wait_for_writer_child(&root)?;

    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    assert!(matches!(
        client.verify_active_account_secret("acct", b"losing-secret"),
        Err(SdkError::Storage(StorageError::AccountWriterBusy(ref account))) if account == "acct"
    ));
    assert!(matches!(
        verify_stored_data_secret(&root, "acct", b"losing-secret"),
        Err(SdkError::Storage(StorageError::AccountWriterBusy(ref account))) if account == "acct"
    ));
    assert!(
        !FileVaultSecretSource::new(&root).vault_secret_path("acct").exists(),
        "a refused verification must not create vault material"
    );

    drop(holder);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn account_unlock_uses_random_wrapped_key_and_rewraps_on_secret_change() -> Result<(), SdkError> {
    let root = temp_root("wrapped-key-default");
    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    client.create_account("acct_a", "principal_a")?;
    client.create_account("acct_b", "principal_b")?;
    client.unlock_account("acct_a", b"shared-secret")?;
    client.append_event("evt_a_1", "test.event", b"persisted")?;
    client.unlock_account("acct_b", b"shared-secret")?;

    let key_a = wrapped_db_key(&root, "acct_a", b"shared-secret")?;
    let key_b = wrapped_db_key(&root, "acct_b", b"shared-secret")?;
    assert_ne!(key_a, key_b);

    let mut restored = RamfluxClient::new();
    restored.open_account_index(&root)?;
    restored.unlock_account("acct_a", b"shared-secret")?;
    assert_eq!(restored.event_body("evt_a_1")?, Some(b"persisted".to_vec()));

    let mut wrong_secret = RamfluxClient::new();
    wrong_secret.open_account_index(&root)?;
    assert!(matches!(
        wrong_secret.unlock_account("acct_a", b"wrong-secret"),
        Err(SdkError::Storage(ref error @ StorageError::Integrity(_)))
            if error.to_string() == "wrong passphrase or damaged local key"
    ));

    restored.rekey_active_account("acct_a", b"new-secret")?;
    let rewrapped_key_a = wrapped_db_key(&root, "acct_a", b"new-secret")?;
    assert_eq!(rewrapped_key_a, key_a);
    let mut old_secret_after_rekey = RamfluxClient::new();
    old_secret_after_rekey.open_account_index(&root)?;
    assert!(matches!(
        old_secret_after_rekey.unlock_account("acct_a", b"shared-secret"),
        Err(SdkError::Storage(StorageError::Integrity(_)))
    ));
    let mut new_secret_after_rekey = RamfluxClient::new();
    new_secret_after_rekey.open_account_index(&root)?;
    new_secret_after_rekey.unlock_account("acct_a", b"new-secret")?;
    assert_eq!(new_secret_after_rekey.event_body("evt_a_1")?, Some(b"persisted".to_vec()));

    std::fs::remove_file(FileVaultSecretSource::new(&root).vault_secret_path("acct_a"))?;
    let mut missing_vault_secret = RamfluxClient::new();
    missing_vault_secret.open_account_index(&root)?;
    assert!(matches!(
        missing_vault_secret.unlock_account("acct_a", b"new-secret"),
        Err(SdkError::Storage(StorageError::Integrity(_)))
    ));

    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn concurrent_account_writers_avoid_deferred_upgrade_locks_for_fifty_cycles() -> Result<(), SdkError>
{
    let root = temp_root("concurrent-writers");
    let mut actor = RamfluxClient::new();
    actor.open_account_index(&root)?;
    actor.create_account("acct", "principal")?;
    actor.unlock_account("acct", b"account-secret")?;

    let (start_tx, start_rx) = std::sync::mpsc::sync_channel::<usize>(1);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<Result<(), SdkError>>(1);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
    let worker_root = root.clone();
    let worker = std::thread::spawn(move || -> Result<(), SdkError> {
        let mut background = RamfluxClient::new();
        let opened = background
            .open_account_index(&worker_root)
            .and_then(|()| background.unlock_account("acct", b"account-secret"));
        ready_tx.send(opened.as_ref().map_err(ToString::to_string).copied()).ok();
        opened?;
        while let Ok(round) = start_rx.recv() {
            let result =
                background.set_projection_checkpoint(&format!("background-{round}"), "written");
            if done_tx.send(result).is_err() {
                break;
            }
        }
        Ok(())
    });
    ready_rx
        .recv()
        .map_err(|error| SdkError::LocalBus(error.to_string()))?
        .map_err(SdkError::LocalBus)?;

    for round in 0..50 {
        actor.account_db()?.write_transaction(|| {
            let _ = actor.projection_checkpoint("missing")?;
            start_tx.send(round).map_err(|error| SdkError::LocalBus(error.to_string()))?;
            std::thread::sleep(std::time::Duration::from_millis(20));
            actor.set_projection_checkpoint(&format!("actor-{round}"), "written")
        })?;
        done_rx.recv().map_err(|error| SdkError::LocalBus(error.to_string()))??;
    }

    drop(start_tx);
    worker.join().map_err(|_| SdkError::LocalBus("writer worker panicked".to_owned()))??;
    for round in 0..50 {
        assert_eq!(
            actor.projection_checkpoint(&format!("actor-{round}"))?.as_deref(),
            Some("written")
        );
        assert_eq!(
            actor.projection_checkpoint(&format!("background-{round}"))?.as_deref(),
            Some("written")
        );
    }
    drop(actor);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn persist_gateway_receive_cursor_refuses_activated_ledger() -> Result<(), SdkError> {
    let root = temp_root("receive-activation-legacy-cursor");
    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    client.create_account("acct", "principal")?;
    client.unlock_account("acct", b"secret")?;
    const { assert!(!ramflux_storage::FIRST_ACTIVATION_DEFAULT) };
    client.persist_gateway_receive_cursor("t", 1)?;
    assert_eq!(
        client.account_db()?.activate_receive_ledger(ramflux_storage::ReceiveMigrate {
            target: "t",
            incarnation: "e",
        })?,
        ramflux_storage::ReceiveMigrateResult::Migrated
    );
    assert_eq!(
        client.account_db()?.receive_activation()?,
        ramflux_storage::ReceiveActivation::Activated
    );
    let refused = client.persist_gateway_receive_cursor("t", 2);
    assert!(
        matches!(
            refused,
            Err(SdkError::Storage(StorageError::Integrity(
                ramflux_storage::LEGACY_RECEIVE_ACTIVATED
            )))
        ),
        "{refused:?}"
    );
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
