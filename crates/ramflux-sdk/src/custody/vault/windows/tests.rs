// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DPAPI vault tests for the M2 acceptance. They run only on Windows.
//!
//! The second-user test needs a second local account. It is ignored unless the job provides
//! `RAMFLUX_TEST_SECOND_USER` and `RAMFLUX_TEST_SECOND_USER_PASSWORD`.

use ramflux_crypto::custody::SelfSigningKey;
use zeroize::Zeroizing;

use super::{VAULT_CLASS_WINDOWS_DPAPI, WindowsDpapiVault, dpapi};
use crate::SdkError;
use crate::custody::PrimaryVault;
use crate::platform::pipe::win32::files;
use crate::platform::pipe::win32::test_tokens::impersonate_user;

const PRIMARY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
const BRANCH: &str = "branch:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn text(error: impl std::fmt::Display) -> String {
    let reason = super::last_unavailable();
    if reason.is_empty() { error.to_string() } else { format!("{error} | unavailable: {reason}") }
}

fn vault() -> Result<(tempfile::TempDir, WindowsDpapiVault), String> {
    super::clear_unavailable();
    let root = tempfile::tempdir().map_err(text)?;
    let vault = WindowsDpapiVault::for_data_root(root.path());
    Ok((root, vault))
}

fn key(fill: u8) -> SelfSigningKey {
    SelfSigningKey::from_vault_seed(&Zeroizing::new([fill; 32]))
}

fn refused<T>(result: Result<T, SdkError>, what: &str) -> Result<(), String> {
    match result {
        Err(SdkError::CustodyVaultUnavailable) => Ok(()),
        Err(error) => Err(format!("{what}: unexpected error {error}")),
        Ok(_) => Err(format!("{what}: succeeded")),
    }
}

/// Bound a worker that cannot be cancelled. The caller releases a stalled worker itself.
fn join_within<T: Send + 'static>(
    action: impl FnOnce() -> Result<T, String> + Send + 'static,
    budget: std::time::Duration,
) -> Result<T, String> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(action());
    });
    match receiver.recv_timeout(budget) {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err("test: worker exceeded its deadline".to_owned())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("test: worker ended without a result".to_owned())
        }
    }
}

#[test]
fn primary_seed_round_trips_and_records_its_own_class() -> Result<(), String> {
    let (_root, vault) = vault()?;
    vault.preflight().map_err(text)?;
    if vault.vault_class() != VAULT_CLASS_WINDOWS_DPAPI
        || vault.vault_class() == crate::custody::VAULT_CLASS_PROTECTED
    {
        return Err("the DPAPI vault must record its own class".to_owned());
    }
    let stored = key(7);
    vault.store_new(PRIMARY, &stored).map_err(text)?;
    let loaded = vault.load_primary(PRIMARY).map_err(text)?;
    if loaded.public_key() != stored.public_key() {
        return Err("loaded another key".to_owned());
    }
    Ok(())
}

#[test]
fn store_is_insert_only_and_delete_is_idempotent() -> Result<(), String> {
    let (_root, vault) = vault()?;
    vault.store_new(PRIMARY, &key(1)).map_err(text)?;
    refused(vault.store_new(PRIMARY, &key(2)), "second store")?;
    let kept = vault.load_primary(PRIMARY).map_err(text)?;
    if kept.public_key() != key(1).public_key() {
        return Err("the first entry was replaced".to_owned());
    }
    vault.delete(PRIMARY).map_err(text)?;
    vault.delete(PRIMARY).map_err(text)?;
    refused(vault.load_primary(PRIMARY), "load after delete")
}

#[test]
fn branch_and_provisioning_entries_round_trip_with_their_lengths() -> Result<(), String> {
    let (_root, vault) = vault()?;
    let seeds = Zeroizing::new([9_u8; 64]);
    vault.store_branch(BRANCH, &seeds).map_err(text)?;
    // A branch entry is 64 bytes: it never loads as a primary seed.
    refused(vault.load_primary(BRANCH), "branch entry as primary")?;
    vault.store_provisioning_secret("agent-provisioning:x", b"pass phrase").map_err(text)?;
    let secret = vault.load_provisioning_secret("agent-provisioning:x").map_err(text)?;
    if secret.as_slice() != b"pass phrase" {
        return Err("provisioning secret changed".to_owned());
    }
    refused(vault.store_provisioning_secret("agent-provisioning:y", &[]), "empty secret")?;
    refused(vault.store_provisioning_secret("bad\nreference", b"x"), "control character")
}

#[test]
fn the_file_holds_no_plaintext_seed_and_belongs_to_the_user() -> Result<(), String> {
    let (_root, vault) = vault()?;
    let seed = [0x5a_u8; 32];
    vault
        .store_new(PRIMARY, &SelfSigningKey::from_vault_seed(&Zeroizing::new(seed)))
        .map_err(text)?;
    let path = vault.entry_path(PRIMARY).map_err(text)?;
    let bytes = std::fs::read(&path).map_err(text)?;
    if bytes.windows(seed.len()).any(|window| window == seed) {
        return Err("the seed is on disk in the clear".to_owned());
    }
    if bytes.windows(PRIMARY.len()).any(|window| window == PRIMARY.as_bytes()) {
        return Err("the reference is on disk in the clear".to_owned());
    }
    let me = files::current_user().map_err(text)?;
    let file_owner = files::path_owner(&path).map_err(text)?;
    let directory_owner = files::path_owner(&vault.directory).map_err(text)?;
    if !files::owner_matches_user(&file_owner, &me).map_err(text)?
        || !files::owner_matches_user(&directory_owner, &me).map_err(text)?
    {
        return Err("vault files must belong to the current user".to_owned());
    }
    Ok(())
}

#[test]
fn a_damaged_or_transplanted_blob_is_refused() -> Result<(), String> {
    let (_root, vault) = vault()?;
    vault.store_new(PRIMARY, &key(3)).map_err(text)?;
    vault.store_new(OTHER, &key(4)).map_err(text)?;
    let primary = vault.entry_path(PRIMARY).map_err(text)?;
    let other = vault.entry_path(OTHER).map_err(text)?;

    // A blob copied over another entry was protected with other entropy and names another
    // reference inside the record.
    let original = std::fs::read(&primary).map_err(text)?;
    std::fs::write(&primary, std::fs::read(&other).map_err(text)?).map_err(text)?;
    refused(vault.load_primary(PRIMARY), "transplanted blob")?;

    let mut damaged = original.clone();
    let last = damaged.len().checked_sub(1).ok_or("empty blob")?;
    damaged[last] ^= 0x01;
    std::fs::write(&primary, &damaged).map_err(text)?;
    refused(vault.load_primary(PRIMARY), "damaged blob")?;

    std::fs::write(&primary, &original[..original.len() / 2]).map_err(text)?;
    refused(vault.load_primary(PRIMARY), "truncated blob")?;

    std::fs::write(&primary, vec![0_u8; dpapi::MAX_BLOB_BYTES + 1]).map_err(text)?;
    refused(vault.load_primary(PRIMARY), "oversized blob")?;

    std::fs::write(&primary, &original).map_err(text)?;
    vault.load_primary(PRIMARY).map(|_| ()).map_err(text)
}

#[test]
fn the_record_check_rejects_a_changed_record() -> Result<(), String> {
    let record = WindowsDpapiVault::encode(PRIMARY, &[1_u8; 32]).map_err(text)?;
    let secret = WindowsDpapiVault::decode(PRIMARY, &record).map_err(text)?;
    if secret.as_slice() != [1_u8; 32] {
        return Err("record did not round trip".to_owned());
    }
    refused(WindowsDpapiVault::decode(OTHER, &record), "record for another reference")?;
    for index in 0..record.len() {
        let mut changed = record.to_vec();
        changed[index] ^= 0x80;
        refused(WindowsDpapiVault::decode(PRIMARY, &changed), "changed record")?;
    }
    refused(WindowsDpapiVault::decode(PRIMARY, &record[..record.len() - 1]), "short record")
}

#[test]
fn entropy_is_required_to_unprotect() -> Result<(), String> {
    let protected = dpapi::protect(b"secret", b"entropy-a").map_err(text)?;
    if dpapi::unprotect(&protected, b"entropy-b").is_ok() {
        return Err("another entropy opened the blob".to_owned());
    }
    let opened = dpapi::unprotect(&protected, b"entropy-a").map_err(text)?;
    if opened.as_slice() != b"secret" {
        return Err("round trip changed the data".to_owned());
    }
    Ok(())
}

#[test]
fn debug_output_names_no_path_and_no_secret() -> Result<(), String> {
    let (root, vault) = vault()?;
    let shown = format!("{vault:?}");
    let directory = root.path().to_string_lossy().into_owned();
    if shown.contains(&directory) || !shown.starts_with("WindowsDpapiVault") {
        return Err(format!("unexpected debug output: {shown}"));
    }
    Ok(())
}

#[test]
fn home_authorization_stays_unavailable_without_user_presence() -> Result<(), String> {
    let (_root, vault) = vault()?;
    match vault.home_authorization_preflight() {
        Err(_) => Ok(()),
        Ok(()) => Err("DPAPI alone must not grant user presence".to_owned()),
    }
}

#[test]
#[ignore = "needs a second local user: RAMFLUX_TEST_SECOND_USER and RAMFLUX_TEST_SECOND_USER_PASSWORD"]
fn a_second_user_cannot_read_or_unprotect_an_entry() -> Result<(), String> {
    let user = std::env::var("RAMFLUX_TEST_SECOND_USER").map_err(text)?;
    let password = std::env::var("RAMFLUX_TEST_SECOND_USER_PASSWORD").map_err(text)?;
    // A directory the second user can read, so the refusal comes from the vault's access list.
    let (root, control) = crate::platform::fs::tests::shared_tempdir()?;
    let vault = WindowsDpapiVault::for_data_root(root.path());
    vault.store_new(PRIMARY, &key(5)).map_err(text)?;
    let path = vault.entry_path(PRIMARY).map_err(text)?;
    let protected = std::fs::read(&path).map_err(text)?;
    let entropy = WindowsDpapiVault::entropy(PRIMARY);

    let other_vault = vault.clone();
    let (opened, unprotected, loaded) = join_within(
        move || {
            let guard = impersonate_user(&user, &password).map_err(text)?;
            std::fs::read(&control)
                .map_err(|error| format!("the control file is not readable: {error}"))?;
            // The access list refuses the file; the blob itself, had it leaked, does not open
            // under another user's DPAPI keys.
            let opened = std::fs::File::open(&path).map(|_| ());
            let unprotected = dpapi::unprotect(&protected, &entropy).map(|_| ());
            let loaded = other_vault.load_primary(PRIMARY).map(|_| ());
            drop(guard);
            Ok((opened, unprotected, loaded))
        },
        std::time::Duration::from_secs(15),
    )?;

    match opened {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Ok(()) => return Err("a second user opened the vault file".to_owned()),
        Err(error) => return Err(text(error)),
    }
    if unprotected.is_ok() {
        return Err("a second user unprotected the blob".to_owned());
    }
    refused(loaded, "second user load")?;
    vault.load_primary(PRIMARY).map(|_| ()).map_err(text)
}

/// A worker that never finishes is refused inside `budget` and is then released, so the
/// thread is not still running when the test returns.
#[test]
fn a_stalled_worker_fails_inside_its_deadline() -> Result<(), String> {
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let started = std::time::Instant::now();
    let outcome = join_within(
        move || {
            let _ = release_rx.recv();
            let _ = done_tx.send(());
            Ok(())
        },
        std::time::Duration::from_millis(200),
    );
    if outcome.is_ok() {
        return Err("a stalled worker returned a result".to_owned());
    }
    if started.elapsed() >= std::time::Duration::from_secs(2) {
        return Err("the stalled worker was not refused inside its deadline".to_owned());
    }
    release_tx.send(()).map_err(text)?;
    done_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .map_err(|_| "test: stalled worker was still running after it was released".to_owned())?;
    Ok(())
}

fn directory_names(path: &std::path::Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path).map_err(text)? {
        names.push(entry.map_err(text)?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

/// The vault directory itself is a junction. Admission refuses before a blob is written
/// through it, and the shared target is unchanged.
#[test]
fn a_junction_vault_directory_is_refused_before_any_blob() -> Result<(), String> {
    let parent = tempfile::tempdir().map_err(text)?;
    let target = parent.path().join("shared");
    std::fs::create_dir(&target).map_err(text)?;
    let sentinel = target.join("sentinel.bin");
    std::fs::write(&sentinel, b"shared-bytes").map_err(text)?;
    let names = directory_names(&target)?;
    let bytes = std::fs::read(&sentinel).map_err(text)?;
    let data = parent.path().join("data");
    std::fs::create_dir(&data).map_err(text)?;
    files::plant_mount_point(&data.join("vault"), &target).map_err(text)?;
    let vault = WindowsDpapiVault::for_data_root(&data);
    refused(vault.store_new(PRIMARY, &key(7)), "junction vault")?;
    if std::fs::read(&sentinel).map_err(text)? != bytes || directory_names(&target)? != names {
        return Err(format!(
            "junction vault admission changed the shared target | {}",
            super::last_unavailable()
        ));
    }
    Ok(())
}
