// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::{LinuxVaultInstallation as Vault, LinuxVaultMode, cleanup::observer};
use super::*;
use std::{os::unix::fs::PermissionsExt, time::Duration};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn service() -> Result<SecretService, dbus_secret_service::Error> {
    SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0)
}
fn root() -> Result<tempfile::TempDir, std::io::Error> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
fn collection(ss: &SecretService) -> Result<dbus_secret_service::Collection<'_>, Error> {
    let (_sender, cancel) = watch::channel(false);
    local_collection(ss, &cancel, Instant::now() + Duration::from_secs(30))
}
fn prepare() -> TestResult {
    let ss = service()?;
    if collection(&ss).is_err() {
        // A fresh disposable HOME contains only this synthetic login collection.
        // Relabeling it provisions a dedicated local fixture without a GUI prompt.
        ss.get_default_collection()?.set_label(COLLECTION)?;
    }
    Ok(())
}

#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_installation_init_is_serial_and_crash_safe() -> TestResult {
    prepare()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mode = LinuxVaultMode::DesktopSecretService;
    for cut in 1..=24 {
        let dir = root()?;
        let child = || {
            let mut command =
                std::process::Command::new(std::env::current_exe().unwrap_or_default());
            command
                .args([
                    "--ignored",
                    "--exact",
                    "custody::vault::linux::secret_service::tests::ss_child",
                ])
                .env("RF_SS_ROOT", dir.path())
                .env("RF_SS_CUT", cut.to_string());
            command
        };
        let output = child().output()?;
        assert_eq!(
            output.status.code(),
            Some(93),
            "cut {cut}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ss = service()?;
        let collection = collection(&ss)?;
        let before = collection
            .get_all_items()?
            .into_iter()
            .map(|item| Ok((item.path.clone(), read(&item)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join(".init.lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        assert_eq!(rt.block_on(Vault::initialize(dir.path().into(), mode)), Err(Error::Busy));
        let busy = child().env("RF_SS_BUSY", "1").output()?;
        assert!(busy.status.success(), "competing process must refuse exact Busy");
        drop(lock);
        if dir.path().join("init.pending").exists() {
            assert_eq!(rt.block_on(Vault::status(dir.path().into(), mode)), Err(Error::Pending));
        }
        rt.block_on(Vault::initialize(dir.path().into(), mode))?;
        rt.block_on(Vault::status(dir.path().into(), mode))?;
        for (path, key) in before {
            let item = dbus_secret_service::Item::new(&ss, path);
            assert!(read(&item)?.bytes() == key.bytes(), "published key overwritten at {cut}");
        }
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 2);
    }
    Ok(())
}
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_owned_buffers_clear_on_all_exits() -> TestResult {
    prepare()?;
    observer::begin();
    let (_sender, cancel) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let id = "a123456789abcdef0123456789abcdef";
    ensure(id, 0, true, &cancel, deadline, &|_| {})?;
    ensure(id, 0, false, &cancel, deadline, &|_| {})?;
    let ss = service()?;
    let collection = collection(&ss)?;
    let attrs = HashMap::from([
        ("target", COLLECTION),
        ("service", SERVICE),
        ("username", "rf-primary-kek:a123456789abcdef0123456789abcdef"),
    ]);
    let item = collection.search_items(attrs.clone())?.remove(0);
    for len in [0, 31, 33] {
        let sample = zeroize::Zeroizing::new(vec![0x73; len]);
        item.set_secret(&sample, "application/octet-stream")?;
        assert!(matches!(read(&item), Err(Error::Length)));
    }
    item.set_secret(&[0x73; 32], "application/octet-stream")?;
    let duplicate = collection.create_item(
        "duplicate",
        attrs,
        &[0x73; 32],
        false,
        "application/octet-stream",
    )?;
    assert_eq!(ensure(id, 0, false, &cancel, deadline, &|_| {}), Err(Error::Corrupt));
    duplicate.delete()?;
    for (id, realm, error) in [
        ("", 0, Error::Corrupt),
        ("a123456789abcdef0123456789abcde", 0, Error::Corrupt),
        ("a123456789abcdef0123456789abcdef00", 0, Error::Corrupt),
        ("A123456789abcdef0123456789abcdef", 0, Error::Corrupt),
        (id, 3, Error::Realm),
    ] {
        assert_eq!(ensure(id, realm, true, &cancel, deadline, &|_| {}), Err(error));
    }
    assert_eq!(ensure(id, 0, true, &cancel, Instant::now(), &|_| {}), Err(Error::Timeout));
    let (sender, cancelled) = watch::channel(false);
    sender.send(true)?;
    assert_eq!(ensure(id, 0, true, &cancelled, deadline, &|_| {}), Err(Error::Cancelled));
    let (signal, stopping) = watch::channel(false);
    assert_eq!(
        ensure(id, 0, false, &stopping, deadline, &|event| {
            if event == "ss-existing-readback" {
                let _ = signal.send(true);
            }
        }),
        Err(Error::Cancelled)
    );
    let (signal, stopping) = watch::channel(false);
    assert_eq!(
        ensure("b123456789abcdef0123456789abcdef", 0, true, &stopping, deadline, &|event| {
            if event == "ss-generated" {
                let _ = signal.send(true);
            }
        }),
        Err(Error::Cancelled)
    );
    item.delete()?;
    assert_eq!(ensure(id, 0, false, &cancel, deadline, &|_| {}), Err(Error::Corrupt));
    let observations = observer::take();
    for label in ["p05-response", "p05-readback", "p05-generated"] {
        assert!(observations.iter().any(|o| o.label == label), "missing {label}");
    }
    for o in observations {
        assert!(o.bytes.iter().all(|b| *b == 0), "P05 uncleared {}", o.label);
    }
    Ok(())
}

#[test]
#[ignore = "child entry point"]
fn ss_child() -> TestResult {
    let root = std::path::PathBuf::from(std::env::var_os("RF_SS_ROOT").ok_or("root")?);
    let cut: usize = std::env::var("RF_SS_CUT")?.parse()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (_sender, mut receiver) = watch::channel(false);
    let count = std::cell::Cell::new(0);
    let result = rt.block_on(super::super::init::attempt(
        &root,
        LinuxVaultMode::DesktopSecretService,
        true,
        &mut receiver,
        Instant::now() + Duration::from_secs(30),
        &|_| {
            if std::env::var_os("RF_SS_BUSY").is_none() {
                count.set(count.get() + 1);
                if count.get() == cut {
                    std::process::exit(93);
                }
            }
        },
    ));
    if std::env::var_os("RF_SS_BUSY").is_some() {
        assert_eq!(result, Err(Error::Busy));
        return Ok(());
    }
    result?;
    Err("unreached crash cut".into())
}
#[test]
#[ignore = "private collection locked only after other fixture tests"]
fn locked_collection_refuses_without_prompt() -> TestResult {
    let ss = service()?;
    let collection = collection(&ss)?;
    let (_sender, cancel) = watch::channel(false);
    collection.set_label("fixture-other")?;
    assert_eq!(
        ensure(
            "a123456789abcdef0123456789abcdef",
            0,
            true,
            &cancel,
            Instant::now() + Duration::from_secs(30),
            &|_| {}
        ),
        Err(Error::Missing)
    );
    collection.set_label(COLLECTION)?;
    collection.lock()?;
    assert_eq!(
        ensure(
            "a123456789abcdef0123456789abcdef",
            0,
            true,
            &cancel,
            Instant::now() + Duration::from_secs(30),
            &|_| {}
        ),
        Err(Error::Provider)
    );
    assert!(collection.is_locked()?);
    Ok(())
}
