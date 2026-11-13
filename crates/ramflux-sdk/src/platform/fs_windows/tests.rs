// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Windows store tests for the M2 acceptance: owner-only files, the data-root lock, atomic
//! replacement, long paths, the data root location, and a database that opens only as the
//! same user.
//!
//! The second-user tests need a second local account. They are ignored unless the job provides
//! `RAMFLUX_TEST_SECOND_USER` and `RAMFLUX_TEST_SECOND_USER_PASSWORD`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::*;
use crate::platform::pipe::win32::test_tokens::impersonate_user;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Failure text for the data-root test: token, built SDDL, read-back SDDL, and the last
/// labeled Win32 call. The read-back does not record a new call name.
fn explain_root(error: impl std::fmt::Display, root: &Path) -> String {
    let call = crate::platform::pipe::win32::last_call();
    let token = crate::platform::pipe::win32::diag::token_line();
    let built = match crate::platform::pipe::win32::files::owner_only_sddl(true) {
        Ok(text) => text,
        Err(error) => format!("build-failed:{error}"),
    };
    let root_sd = crate::platform::pipe::win32::diag::object_sddl(root, false);
    let parent_sd = match root.parent() {
        Some(parent) => crate::platform::pipe::win32::diag::object_sddl(parent, false),
        None => "no parent".to_owned(),
    };
    format!(
        "{error} | {token} | built={built} | root={root_sd} | parent={parent_sd} | last_labeled_call={call}"
    )
}

fn second_user() -> Result<(String, String), String> {
    Ok((
        std::env::var("RAMFLUX_TEST_SECOND_USER").map_err(text)?,
        std::env::var("RAMFLUX_TEST_SECOND_USER_PASSWORD").map_err(text)?,
    ))
}

/// Run `action` on a thread that impersonates the second user.
fn as_second_user<T: Send + 'static>(
    action: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (user, password) = second_user()?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let outcome = (|| {
            let guard = impersonate_user(&user, &password).map_err(text)?;
            let result = action();
            drop(guard);
            Ok(result)
        })();
        let _ = sender.send(outcome);
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(15))
        .map_err(|_| "test: impersonating thread exceeded its deadline".to_owned())?
}

/// A directory the second user can otherwise read, with a control file that proves it. The
/// default temporary directory lies inside the first user's profile, which already refuses
/// other users, so a refusal there would say nothing about the owner-only access list.
pub(crate) fn shared_tempdir() -> Result<(tempfile::TempDir, PathBuf), String> {
    let public = std::env::var_os("PUBLIC").ok_or("PUBLIC is not set")?;
    let dir = tempfile::Builder::new().prefix("rf-test-").tempdir_in(public).map_err(text)?;
    let control = dir.path().join("control");
    std::fs::write(&control, b"control").map_err(text)?;
    Ok((dir, control))
}

/// The second user reads the control file: the directory itself does not refuse them.
fn control_is_readable(control: &Path) -> Result<(), String> {
    let control = control.to_path_buf();
    as_second_user(move || std::fs::read(control))?
        .map(|_| ())
        .map_err(|error| format!("the control file is not readable by the second user: {error}"))
}

fn denied<T>(result: std::io::Result<T>, what: &str) -> Result<(), String> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Ok(_) => Err(format!("{what}: a second user was let in")),
        Err(error) => Err(format!("{what}: {error}")),
    }
}

fn owned_by_me(path: &Path) -> Result<(), String> {
    let owner = files::path_owner(path).map_err(text)?;
    let user = files::current_user().map_err(text)?;
    if files::owner_matches_user(&owner, &user).map_err(text)? {
        Ok(())
    } else {
        Err(format!("{} is not owned by the current user", path.display()))
    }
}

#[test]
fn owner_only_dir_and_file_belong_to_the_user_and_create_new_is_exclusive() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let nested = dir.path().join("accounts");
    create_owner_only_dir(&nested).map_err(text)?;
    set_owner_only_dir(&nested).map_err(text)?;
    owned_by_me(&nested)?;
    match create_owner_only_dir(&nested) {
        Err(SdkError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Ok(()) => return Err("an existing directory was created again".to_owned()),
        Err(error) => return Err(text(error)),
    }
    let file = nested.join("manifest.json");
    let mut created = create_new_owner_only(&file).map_err(text)?;
    created.write_all(b"{}").map_err(text)?;
    drop(created);
    set_owner_only_file(&file).map_err(text)?;
    owned_by_me(&file)?;
    match create_new_owner_only(&file) {
        Err(SdkError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Ok(_) => Err("create_new replaced an existing file".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[test]
fn truncate_append_and_read_write_keep_their_unix_meaning() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("state");
    open_owner_only_truncate(&path).map_err(text)?.write_all(b"first-long").map_err(text)?;
    open_owner_only_truncate(&path).map_err(text)?.write_all(b"next").map_err(text)?;
    open_owner_only_append(&path).map_err(text)?.write_all(b"+more").map_err(text)?;
    let mut contents = String::new();
    open_owner_only_read_write(&path).map_err(text)?.read_to_string(&mut contents).map_err(text)?;
    if contents != "next+more" {
        return Err(format!("unexpected contents {contents:?}"));
    }
    owned_by_me(&path)
}

#[test]
fn second_exclusive_lock_is_would_block() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("daemon.lock");
    let first = open_owner_only_read_write(&path).map_err(text)?;
    try_lock_exclusive(&first).map_err(text)?;
    let second = open_owner_only_read_write(&path).map_err(text)?;
    match try_lock_exclusive(&second) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(()) => return Err("second exclusive lock was acquired".to_owned()),
        Err(error) => return Err(text(error)),
    }
    unlock(&first).map_err(text)?;
    try_lock_exclusive(&second).map_err(text)
}

#[test]
fn replace_is_one_step_and_no_replace_refuses_an_existing_name() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let target = dir.path().join("manifest.json");
    let temporary = dir.path().join("manifest.json.tmp");
    create_new_owner_only(&target).map_err(text)?.write_all(b"old").map_err(text)?;
    create_new_owner_only(&temporary).map_err(text)?.write_all(b"new").map_err(text)?;
    let before = open_owner_only_read_write(&target).map_err(text)?;
    let (device, inode) = file_device_inode(&before).map_err(text)?;
    if !same_device_inode(&target, device, inode).map_err(text)? {
        return Err("identity of an unchanged file did not match".to_owned());
    }
    drop(before);
    replace_file(&temporary, &target).map_err(text)?;
    if std::fs::read(&target).map_err(text)? != b"new" || temporary.exists() {
        return Err("replace did not move the new contents into place".to_owned());
    }
    if same_device_inode(&target, device, inode).map_err(text)? {
        return Err("the replaced path kept the old identity".to_owned());
    }
    if same_device_inode(&temporary, device, inode).map_err(text)? {
        return Err("a missing path matched an identity".to_owned());
    }

    let other = dir.path().join("other");
    std::fs::write(&other, b"other").map_err(text)?;
    match rename_no_replace(&other, &target) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Ok(()) => return Err("no-replace move replaced a file".to_owned()),
        Err(error) => return Err(text(error)),
    }
    if std::fs::read(&target).map_err(text)? != b"new" {
        return Err("a refused move changed the destination".to_owned());
    }
    let fresh = dir.path().join("fresh");
    rename_no_replace(&other, &fresh).map_err(text)?;
    sync_path(&fresh).map_err(text)?;
    sync_path(dir.path()).map_err(text)
}

#[test]
fn paths_longer_than_the_legacy_limit_work() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let mut deep = dir.path().to_path_buf();
    while deep.as_os_str().len() < 400 {
        deep.push("a-directory-name-of-forty-characters-xxxx");
        create_owner_only_dir(&deep).map_err(text)?;
    }
    let file = deep.join("account.db");
    create_new_owner_only(&file).map_err(text)?.write_all(b"long").map_err(text)?;
    set_owner_only_file(&file).map_err(text)?;
    let moved = deep.join("account.db.next");
    rename_no_replace(&file, &moved).map_err(text)?;
    replace_file(&moved, &file).map_err(text)?;
    owned_by_me(&file)?;
    let lock = open_owner_only_read_write(&deep.join("daemon.lock")).map_err(text)?;
    try_lock_exclusive(&lock).map_err(text)
}

#[test]
fn the_default_data_root_is_local_and_a_roaming_root_is_refused() -> Result<(), String> {
    let local = files::known_folder(KnownFolder::LocalAppData).map_err(text)?;
    let roaming = files::known_folder(KnownFolder::RoamingAppData).map_err(text)?;
    let root = default_data_root(DEFAULT_PROFILE).map_err(text)?;
    if root != local.join("ramflux").join("default") {
        return Err(format!("unexpected data root {}", root.display()));
    }
    refuse_roaming(&root).map_err(text)?;
    for refused in [roaming.clone(), roaming.join("ramflux").join("default")] {
        match refuse_roaming(&refused) {
            Err(SdkError::LocalBusPermissionDenied) => {}
            other => return Err(format!("roaming root was not refused: {other:?}")),
        }
    }
    // A sibling whose name only starts with the roaming folder's name is not inside it.
    let sibling = PathBuf::from(format!("{}-other", roaming.display()));
    refuse_roaming(&sibling).map_err(text)?;
    for bad in ["", "..", "a/b", "a\\b", "con:1"] {
        if default_data_root(bad).is_ok() {
            return Err(format!("profile {bad:?} was accepted"));
        }
    }
    Ok(())
}

#[test]
fn ensure_data_root_creates_owner_only_directories() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let root = dir.path().join("ramflux").join("profile");
    ensure_data_root(&root).map_err(|error| explain_root(error, &root))?;
    ensure_data_root(&root).map_err(|error| explain_root(error, &root))?;
    owned_by_me(&root)?;
    owned_by_me(&dir.path().join("ramflux"))
}

#[test]
fn a_final_symbolic_link_is_refused() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let target = dir.path().join("target");
    create_new_owner_only(&target).map_err(text)?.write_all(b"x").map_err(text)?;
    let link = dir.path().join("link");
    // Creating a symbolic link needs a privilege or developer mode. Without it there is no
    // link to refuse, and the plain-file case below still runs.
    if std::os::windows::fs::symlink_file(&target, &link).is_ok()
        && open_owner_only_no_follow(&link).is_ok()
    {
        return Err("a final symbolic link was followed".to_owned());
    }
    open_owner_only_no_follow(&target).map(|_| ()).map_err(text)
}

#[test]
#[ignore = "needs a second local user: RAMFLUX_TEST_SECOND_USER and RAMFLUX_TEST_SECOND_USER_PASSWORD"]
fn a_second_user_cannot_open_owner_only_files_or_take_the_lock() -> Result<(), String> {
    let (dir, control) = shared_tempdir()?;
    control_is_readable(&control)?;
    let root = dir.path().join("ramflux").join("profile");
    ensure_data_root(&root).map_err(text)?;
    let file = root.join("manifest.json");
    create_new_owner_only(&file).map_err(text)?.write_all(b"{}").map_err(text)?;
    let lock = root.join("daemon.lock");
    drop(open_owner_only_read_write(&lock).map_err(text)?);

    let (listed, read, written, locked, created) = as_second_user({
        let (root, file, lock) = (root.clone(), file.clone(), lock.clone());
        move || {
            (
                std::fs::read_dir(&root).map(|_| ()),
                std::fs::read(&file).map(|_| ()),
                std::fs::OpenOptions::new().write(true).open(&file).map(|_| ()),
                std::fs::OpenOptions::new().read(true).write(true).open(&lock).map(|_| ()),
                std::fs::write(root.join("planted"), b"x"),
            )
        }
    })?;
    denied(listed, "list the data root")?;
    denied(read, "read a file")?;
    denied(written, "write a file")?;
    denied(locked, "open the lock file")?;
    denied(created, "create a file in the data root")
}

#[test]
#[ignore = "needs a second local user: RAMFLUX_TEST_SECOND_USER and RAMFLUX_TEST_SECOND_USER_PASSWORD"]
fn the_sqlcipher_file_opens_only_as_the_same_user() -> Result<(), String> {
    const KEY: &str = "x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'";
    let (dir, control) = shared_tempdir()?;
    control_is_readable(&control)?;
    let root = dir.path().join("ramflux").join("profile");
    ensure_data_root(&root).map_err(text)?;
    let database = root.join("account.db");
    // The store creates its files inside the owner-only root, so they inherit its access list.
    let open = |path: &Path| -> Result<rusqlite::Connection, rusqlite::Error> {
        let connection = rusqlite::Connection::open(path)?;
        connection.pragma_update(None, "key", KEY)?;
        Ok(connection)
    };
    {
        let connection = open(&database).map_err(text)?;
        connection
            .execute_batch("CREATE TABLE marker (value TEXT); INSERT INTO marker VALUES ('kept');")
            .map_err(text)?;
    }
    owned_by_me(&database)?;

    // The second user holds the correct key and still cannot open the file.
    let (raw, through_sqlite) = as_second_user({
        let database = database.clone();
        move || {
            let raw = std::fs::File::open(&database).map(|_| ());
            let through_sqlite = rusqlite::Connection::open(&database).and_then(|connection| {
                connection.pragma_update(None, "key", KEY)?;
                connection.query_row("SELECT value FROM marker", [], |row| row.get::<_, String>(0))
            });
            (raw, through_sqlite)
        }
    })?;
    denied(raw, "open the database file")?;
    if let Ok(value) = through_sqlite {
        return Err(format!("a second user read {value:?} from the database"));
    }

    let connection = open(&database).map_err(text)?;
    let value: String =
        connection.query_row("SELECT value FROM marker", [], |row| row.get(0)).map_err(text)?;
    if value == "kept" { Ok(()) } else { Err(format!("unexpected value {value:?}")) }
}
