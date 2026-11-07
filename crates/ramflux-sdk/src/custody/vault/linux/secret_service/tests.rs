// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::{
    LinuxVaultInstallation as Vault, LinuxVaultMode,
    cleanup::observer,
    test_proc::{DEADLINE, run_output},
};
use super::*;
use std::{os::unix::fs::PermissionsExt, time::Duration};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const VAULT: &str = "b0000000000000000000000000000001";
const OTHER_VAULT: &str = "b0000000000000000000000000000002";
const KEY: &str = "a123456789abcdef0123456789abcdef";
fn ident<'a>(vault: &'a str, key: &'a str, realm: usize) -> Identity<'a> {
    Identity { vault_id: vault, key_id: key, realm }
}
fn expected_attributes(vault: &str, key: &str, realm: usize) -> HashMap<String, String> {
    HashMap::from([
        ("target".to_owned(), COLLECTION.to_owned()),
        ("service".to_owned(), format!("ramflux.linux-vault.{vault}.{}", realm + 1)),
        ("username".to_owned(), key.to_owned()),
    ])
}
fn find<'a>(
    collection: &'a dbus_secret_service::Collection<'a>,
    vault: &str,
    key: &str,
    realm: usize,
) -> Result<Vec<dbus_secret_service::Item<'a>>, Box<dyn std::error::Error>> {
    let attributes = expected_attributes(vault, key, realm);
    Ok(collection
        .search_items(attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())?)
}
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
    for cut in 1..=39 {
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
        let output = run_output(&mut child(), DEADLINE)?;
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
        let busy = run_output(child().env("RF_SS_BUSY", "1"), DEADLINE)?;
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
    let _session = observer::begin(&["p05-response", "p05-readback", "p05-generated"]);
    let (_sender, cancel) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let id = "a123456789abcdef0123456789abcdef";
    ensure(&ident(VAULT, id, 0), true, &cancel, deadline, &|_| {})?;
    ensure(&ident(VAULT, id, 0), false, &cancel, deadline, &|_| {})?;
    let ss = service()?;
    let collection = collection(&ss)?;
    let owned = expected_attributes(VAULT, id, 0);
    let attrs: HashMap<&str, &str> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
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
    assert_eq!(
        ensure(&ident(VAULT, id, 0), false, &cancel, deadline, &|_| {}),
        Err(Error::Corrupt)
    );
    duplicate.delete()?;
    for (id, realm, error) in [
        ("", 0, Error::Corrupt),
        ("a123456789abcdef0123456789abcde", 0, Error::Corrupt),
        ("a123456789abcdef0123456789abcdef00", 0, Error::Corrupt),
        ("A123456789abcdef0123456789abcdef", 0, Error::Corrupt),
        (id, 3, Error::Realm),
    ] {
        assert_eq!(ensure(&ident(VAULT, id, realm), true, &cancel, deadline, &|_| {}), Err(error));
    }
    for bad_vault in ["", "b000", "B0000000000000000000000000000001", &"b".repeat(33)] {
        assert_eq!(
            ensure(&ident(bad_vault, id, 0), true, &cancel, deadline, &|_| {}),
            Err(Error::Corrupt)
        );
    }
    assert_eq!(
        ensure(&ident(VAULT, id, 0), true, &cancel, Instant::now(), &|_| {}),
        Err(Error::Timeout)
    );
    let (sender, cancelled) = watch::channel(false);
    sender.send(true)?;
    assert_eq!(
        ensure(&ident(VAULT, id, 0), true, &cancelled, deadline, &|_| {}),
        Err(Error::Cancelled)
    );
    let (signal, stopping) = watch::channel(false);
    assert_eq!(
        ensure(&ident(VAULT, id, 0), false, &stopping, deadline, &|event| {
            if event == "ss-existing-readback" {
                let _ = signal.send(true);
            }
        }),
        Err(Error::Cancelled)
    );
    let (signal, stopping) = watch::channel(false);
    assert_eq!(
        ensure(
            &ident(VAULT, "b123456789abcdef0123456789abcdef", 0),
            true,
            &stopping,
            deadline,
            &|event| {
                if event == "ss-generated" {
                    let _ = signal.send(true);
                }
            }
        ),
        Err(Error::Cancelled)
    );
    item.delete()?;
    assert_eq!(
        ensure(&ident(VAULT, id, 0), false, &cancel, deadline, &|_| {}),
        Err(Error::Corrupt)
    );
    let observations = observer::take();
    for label in ["p05-response", "p05-readback", "p05-generated"] {
        assert!(observations.iter().any(|o| o.label == label), "missing {label}");
    }
    for o in observations {
        assert!(o.bytes.iter().all(|b| *b == 0), "P05 uncleared {}", o.label);
    }
    Ok(())
}

fn clean(collection: &dbus_secret_service::Collection<'_>, vault: &str, key: &str) -> TestResult {
    for realm in 0..3 {
        for item in find(collection, vault, key, realm)? {
            item.delete()?;
        }
    }
    Ok(())
}

/// D5a identity: exact attributes on the created item, and a different vault id with the same key
/// id never adopts or collides with it.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_item_identity_is_d5a_and_vault_scoped() -> TestResult {
    prepare()?;
    let (_sender, cancel) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let ss = service()?;
    let collection = collection(&ss)?;
    clean(&collection, VAULT, KEY)?;
    clean(&collection, OTHER_VAULT, KEY)?;
    for realm in 0..3 {
        ensure(&ident(VAULT, KEY, realm), true, &cancel, deadline, &|_| {})?;
        let items = find(&collection, VAULT, KEY, realm)?;
        assert_eq!(items.len(), 1, "realm {realm}");
        // Independent exact-attribute check of what was persisted.
        let stored = items[0].get_attributes()?;
        assert_eq!(
            stored.get("service"),
            Some(&format!("ramflux.linux-vault.{VAULT}.{}", realm + 1))
        );
        assert_eq!(stored.get("username").map(String::as_str), Some(KEY));
        assert_eq!(stored.get("target").map(String::as_str), Some(COLLECTION));
    }
    let original = read(&find(&collection, VAULT, KEY, 0)?[0])?;
    // Same key id under another vault is a different identity: it creates its own item.
    ensure(&ident(OTHER_VAULT, KEY, 0), true, &cancel, deadline, &|_| {})?;
    assert_eq!(find(&collection, VAULT, KEY, 0)?.len(), 1);
    assert_eq!(find(&collection, OTHER_VAULT, KEY, 0)?.len(), 1);
    assert!(
        read(&find(&collection, VAULT, KEY, 0)?[0])?.bytes() == original.bytes(),
        "the original vault item is untouched"
    );
    // A pre-contract item for this key id is refused, never adopted.
    clean(&collection, OTHER_VAULT, KEY)?;
    let legacy = attributes_of(LEGACY_SERVICE, &format!("rf-primary-kek:{KEY}"))?;
    let legacy_item = collection.create_item(
        "legacy",
        legacy.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        &[0x11; 32],
        false,
        "application/octet-stream",
    )?;
    assert_eq!(
        ensure(&ident(OTHER_VAULT, KEY, 0), true, &cancel, deadline, &|_| {}),
        Err(Error::Corrupt)
    );
    assert!(find(&collection, OTHER_VAULT, KEY, 0)?.is_empty(), "no create beside a legacy item");
    legacy_item.delete()?;
    clean(&collection, VAULT, KEY)?;
    Ok(())
}

/// Differing readback: the item changed between the create reply and the readback is refused.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_differing_readback_is_refused() -> TestResult {
    prepare()?;
    let (_sender, cancel) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let ss = service()?;
    let collection = collection(&ss)?;
    clean(&collection, VAULT, KEY)?;
    let swap = |event: &str| {
        if event == "ss-set-reply"
            && let Ok(ss) = service()
            && let Ok(collection) = self::collection(&ss)
            && let Ok(items) = find(&collection, VAULT, KEY, 1)
        {
            for item in items {
                let _ = item.set_secret(&[0x5a; 32], "application/octet-stream");
            }
        }
    };
    assert_eq!(
        ensure(&ident(VAULT, KEY, 1), true, &cancel, deadline, &swap),
        Err(Error::Corrupt),
        "a substituted readback must refuse"
    );
    assert_eq!(find(&collection, VAULT, KEY, 1)?.len(), 1, "exactly one create call");
    clean(&collection, VAULT, KEY)?;
    Ok(())
}

/// Duplicate collection labels and a foreign-collection item are refused with exact errors.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_refuses_duplicate_and_foreign_collections() -> TestResult {
    prepare()?;
    let (_sender, cancel) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let ss = service()?;
    let local = collection(&ss)?;
    clean(&local, VAULT, KEY)?;
    // Foreign collection holding an item with the exact contract attributes.
    // The always-present in-memory `session` collection is another collection, created without
    // any prompt.
    let foreign = ss.get_collection_by_alias("session")?;
    let owned = expected_attributes(VAULT, KEY, 2);
    let planted = foreign.create_item(
        "planted",
        owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        &[0x22; 32],
        false,
        "application/octet-stream",
    )?;
    for create in [true, false] {
        assert_eq!(
            ensure(&ident(VAULT, KEY, 2), create, &cancel, deadline, &|_| {}),
            Err(Error::Corrupt),
            "foreign item, create={create}"
        );
    }
    assert!(find(&local, VAULT, KEY, 2)?.is_empty(), "nothing was created beside it");
    planted.delete()?;
    // Two collections carrying the local label are ambiguous.
    foreign.set_label(COLLECTION)?;
    let duplicate = ensure(&ident(VAULT, KEY, 2), true, &cancel, deadline, &|_| {});
    foreign.set_label("session")?;
    assert_eq!(duplicate, Err(Error::Corrupt), "duplicate collection label");
    assert!(find(&collection(&ss)?, VAULT, KEY, 2)?.is_empty());
    Ok(())
}

/// Set succeeded, the reply was lost (process killed before it could use the reply): restart
/// reconciles by reading the one existing item and never creates a second key.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_set_succeeded_reply_lost_reconciles() -> TestResult {
    prepare()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let dir = root()?;
    let output = run_output(
        std::process::Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "custody::vault::linux::secret_service::tests::ss_child",
            ])
            .env("RF_SS_ROOT", dir.path())
            .env("RF_SS_CUT", "0")
            .env("RF_SS_PLANT", "1"),
        DEADLINE,
    )?;
    assert_eq!(output.status.code(), Some(93), "{}", String::from_utf8_lossy(&output.stderr));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("init.pending"))?)?;
    let vault = manifest["vault_id"].as_str().ok_or("vault id")?.to_owned();
    let keys: Vec<String> = manifest["key_ids"]
        .as_array()
        .ok_or("key ids")?
        .iter()
        .map(|k| k.as_str().unwrap_or_default().to_owned())
        .collect();
    let ss = service()?;
    let collection = collection(&ss)?;
    let planted = find(&collection, &vault, &keys[0], 0)?;
    assert_eq!(planted.len(), 1, "the lost-reply create left exactly one item");
    let original = read(&planted[0])?;
    rt.block_on(Vault::initialize(dir.path().into(), LinuxVaultMode::DesktopSecretService))?;
    rt.block_on(Vault::status(dir.path().into(), LinuxVaultMode::DesktopSecretService))?;
    let after = find(&collection, &vault, &keys[0], 0)?;
    assert_eq!(after.len(), 1, "no second set for an uncertain write");
    assert!(read(&after[0])?.bytes() == original.bytes(), "original key retained");
    for (realm, key) in keys.iter().enumerate() {
        assert_eq!(find(&collection, &vault, key, realm)?.len(), 1);
    }
    clean_manifest(&collection, &vault, &keys)?;
    Ok(())
}
fn clean_manifest(
    collection: &dbus_secret_service::Collection<'_>,
    vault: &str,
    keys: &[String],
) -> TestResult {
    for (realm, key) in keys.iter().enumerate() {
        for item in find(collection, vault, key, realm)? {
            item.delete()?;
        }
    }
    Ok(())
}

/// The initializer's own `create_item` reaches the provider and succeeds, but its reply is lost
/// (uncertain error after the real create). The installation stays pending, and the retry adopts
/// the one created item: no second create, the original key retained.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_lost_create_reply_is_adopted_exactly_once() -> TestResult {
    prepare()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let dir = root()?;
    let mode = LinuxVaultMode::DesktopSecretService;
    LOSE_CREATE_REPLY.store(true, std::sync::atomic::Ordering::SeqCst);
    let lost = rt.block_on(Vault::initialize(dir.path().into(), mode));
    assert!(!LOSE_CREATE_REPLY.load(std::sync::atomic::Ordering::SeqCst), "seam was used");
    assert_eq!(lost, Err(Error::Timeout), "uncertain outcome surfaces, never success");
    assert!(dir.path().join("init.pending").exists(), "intent retained");
    assert!(!dir.path().join("descriptor.json").exists());
    assert!(!dir.path().join("init.progress").exists(), "an unconfirmed realm is not progress");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("init.pending"))?)?;
    let vault = manifest["vault_id"].as_str().ok_or("vault id")?.to_owned();
    let keys: Vec<String> = manifest["key_ids"]
        .as_array()
        .ok_or("key ids")?
        .iter()
        .map(|k| k.as_str().unwrap_or_default().to_owned())
        .collect();
    let ss = service()?;
    let collection = collection(&ss)?;
    let created = find(&collection, &vault, &keys[0], 0)?;
    assert_eq!(created.len(), 1, "the initializer's create happened exactly once");
    let original = read(&created[0])?;
    let path = created[0].path.clone();
    assert_eq!(rt.block_on(Vault::status(dir.path().into(), mode)), Err(Error::Pending));
    rt.block_on(Vault::initialize(dir.path().into(), mode))?;
    rt.block_on(Vault::status(dir.path().into(), mode))?;
    let after = find(&collection, &vault, &keys[0], 0)?;
    assert_eq!(after.len(), 1, "retry did not create a second item");
    assert!(after[0].path == path, "same item");
    assert!(read(&after[0])?.bytes() == original.bytes(), "the original key was retained");
    for (realm, key) in keys.iter().enumerate() {
        assert_eq!(find(&collection, &vault, key, realm)?.len(), 1, "realm {realm}");
    }
    clean_manifest(&collection, &vault, &keys)?;
    Ok(())
}

/// Corrupt progress with every provider item present and consistent: only the malformed record
/// can cause the refusal. Valid bytes are the control.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_corrupt_progress_is_refused_with_valid_provider_state() -> TestResult
{
    prepare()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let dir = root()?;
    let mode = LinuxVaultMode::DesktopSecretService;
    let (signal, mut stopping) = watch::channel(false);
    let stopped = rt.block_on(super::super::init::attempt(
        dir.path(),
        mode,
        true,
        &mut stopping,
        Instant::now() + Duration::from_secs(30),
        &|event| {
            if event == "ss-progress" {
                let _ = signal.send(true);
            }
        },
    ));
    assert_eq!(stopped, Err(Error::Cancelled));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("init.pending"))?)?;
    let vault = manifest["vault_id"].as_str().ok_or("vault id")?.to_owned();
    let key = manifest["key_ids"][0].as_str().ok_or("key id")?.to_owned();
    let keys: Vec<String> = manifest["key_ids"]
        .as_array()
        .ok_or("key ids")?
        .iter()
        .map(|k| k.as_str().unwrap_or_default().to_owned())
        .collect();
    let ss = service()?;
    let collection = collection(&ss)?;
    assert_eq!(find(&collection, &vault, &key, 0)?.len(), 1, "realm 0 item present");
    let progress = dir.path().join("init.progress");
    for (what, bytes) in [
        ("wrong prefix", &b"xsp1:100"[..]),
        ("truncated", b"ssp1:10"),
        ("extra flag", b"ssp1:1000"),
        ("invalid flag", b"ssp1:1x0"),
        ("no prefix", b"100"),
    ] {
        let _ = std::fs::remove_file(&progress);
        std::fs::write(&progress, bytes)?;
        std::fs::set_permissions(&progress, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            rt.block_on(Vault::initialize(dir.path().into(), mode)),
            Err(Error::Corrupt),
            "{what}"
        );
        assert_eq!(find(&collection, &vault, &key, 0)?.len(), 1, "{what}: nothing created");
    }
    // Control: the same state with a valid record completes.
    let _ = std::fs::remove_file(&progress);
    std::fs::write(&progress, b"ssp1:100")?;
    std::fs::set_permissions(&progress, std::fs::Permissions::from_mode(0o600))?;
    rt.block_on(Vault::initialize(dir.path().into(), mode))?;
    rt.block_on(Vault::status(dir.path().into(), mode))?;
    clean_manifest(&collection, &vault, &keys)?;
    Ok(())
}

/// Durable realm progress: an acknowledged item that disappears before the descriptor commit is a
/// refusal, never a silently regenerated KEK under the same identity.
#[test]
#[ignore = "private unlocked gnome-keyring fixture"]
fn linux_vault_secret_service_missing_completed_realm_never_regenerates() -> TestResult {
    prepare()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let dir = root()?;
    let mode = LinuxVaultMode::DesktopSecretService;
    // Stop right after realm 0 progress is durable.
    let (signal, mut stopping) = watch::channel(false);
    let result = rt.block_on(super::super::init::attempt(
        dir.path(),
        mode,
        true,
        &mut stopping,
        Instant::now() + Duration::from_secs(30),
        &|event| {
            if event == "ss-progress" {
                let _ = signal.send(true);
            }
        },
    ));
    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(std::fs::read(dir.path().join("init.progress"))?, b"ssp1:100");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("init.pending"))?)?;
    let vault = manifest["vault_id"].as_str().ok_or("vault id")?.to_owned();
    let key = manifest["key_ids"][0].as_str().ok_or("key id")?.to_owned();
    let ss = service()?;
    let collection = collection(&ss)?;
    let items = find(&collection, &vault, &key, 0)?;
    assert_eq!(items.len(), 1);
    for item in items {
        item.delete()?;
    }
    assert_eq!(rt.block_on(Vault::initialize(dir.path().into(), mode)), Err(Error::Corrupt));
    assert!(find(&collection, &vault, &key, 0)?.is_empty(), "no replacement was generated");
    assert_eq!(std::fs::read(dir.path().join("init.progress"))?, b"ssp1:100");
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
        &|event| {
            if event == "ss-generated" && std::env::var_os("RF_SS_PLANT").is_some() {
                plant(&root);
            }
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
/// Simulates `create_item` having succeeded whose reply never reached the initializer: create
/// the realm 0 item out of band, then die before the initializer could continue.
fn plant(root: &std::path::Path) {
    let Ok(bytes) = std::fs::read(root.join("init.pending")) else { std::process::exit(94) };
    let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        std::process::exit(94)
    };
    let (Some(vault), Some(key)) = (manifest["vault_id"].as_str(), manifest["key_ids"][0].as_str())
    else {
        std::process::exit(94)
    };
    let Ok(ss) = service() else { std::process::exit(94) };
    let Ok(collection) = collection(&ss) else { std::process::exit(94) };
    let owned = expected_attributes(vault, key, 0);
    let created = collection.create_item(
        "Ramflux local vault KEK",
        owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        &[0x41; 32],
        false,
        "application/octet-stream",
    );
    std::process::exit(if created.is_ok() { 93 } else { 94 });
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
            &ident(VAULT, KEY, 0),
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
            &ident(VAULT, KEY, 0),
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
