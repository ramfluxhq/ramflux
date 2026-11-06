// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::{
    cleanup::observer,
    durability::recording::{Op, RecordingOps},
    test_proc::{DEADLINE, run_output},
};
use super::*;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
#[ignore = "requires actual systemd host credential key; run privileged fixture"]
async fn linux_vault_owned_buffers_clear_on_all_exits() -> TestResult {
    observer::begin();
    let (sender, mut cancel) = watch::channel(false);
    let mode = LinuxVaultMode::SystemdHost;
    let deadline = Instant::now() + Duration::from_secs(30);
    {
        let mut input = Secret::<32>::new("p04-fixture-key");
        input.bytes_mut().fill(0x73);
        let (blob, len) = systemd::pipe::<{ systemd::CAP + 1 }>(
            mode,
            0,
            true,
            input.bytes(),
            &mut cancel,
            deadline,
        )
        .await?;
        pipe_refusals(input.bytes(), &mut cancel, deadline).await?;
        let key = systemd::decrypt(mode, 0, &blob.bytes()[..len], &mut cancel, deadline).await?;
        assert!(&key.bytes()[..32] == input.bytes(), "readback mismatch");
        assert!(matches!(
            systemd::decrypt(mode, 1, &blob.bytes()[..len], &mut cancel, deadline).await,
            Err(Error::Provider)
        ));
        let error =
            systemd::pipe::<2>(mode, 0, false, &blob.bytes()[..len], &mut cancel, deadline).await;
        assert!(matches!(error, Err(Error::Length)));
        assert!(matches!(
            systemd::pipe::<33>(mode, 0, false, &blob.bytes()[..len], &mut cancel, Instant::now())
                .await,
            Err(Error::Timeout)
        ));
        let signal = sender.clone();
        systemd::test_hook::set(Box::new(move || {
            let _ = signal.send(true);
        }));
        assert!(matches!(
            systemd::decrypt(mode, 0, &blob.bytes()[..len], &mut cancel, deadline).await,
            Err(Error::Cancelled)
        ));
    }
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let (_keep, mut fresh) = watch::channel(false);
    attempt(directory.path(), mode, true, &mut fresh, deadline, &|_| {}).await?;
    let interrupted = tempfile::tempdir()?;
    std::fs::set_permissions(interrupted.path(), std::fs::Permissions::from_mode(0o700))?;
    let (signal, mut stopping) = watch::channel(false);
    let result = attempt(interrupted.path(), mode, true, &mut stopping, deadline, &|event| {
        if event == "generated" {
            let _ = signal.send(true);
        }
    })
    .await;
    assert_eq!(result, Err(Error::Cancelled));
    let injected = directory.path().join("injected-test-credential");
    let mut sample = Secret::<32>::new("p04-injected-fixture");
    sample.bytes_mut().fill(0x62);
    std::fs::write(&injected, sample.bytes())?;
    std::fs::set_permissions(&injected, std::fs::Permissions::from_mode(0o400))?;
    LinuxVaultInstallation::read_credential(&injected)?;
    drop(sample);
    let observations = observer::take();
    for label in [
        "p04-fixture-key",
        "p04-child-stdin",
        "p04-child-output",
        "p04-generated-key",
        "p04-runtime-read",
        "p04-injected-fixture",
    ] {
        assert!(observations.iter().any(|o| o.label == label), "missing {label}");
    }
    for o in observations {
        assert!(o.bytes.iter().all(|b| *b == 0), "P04 uncleared {}", o.label);
    }
    Ok(())
}

#[test]
fn manifest_bounds_and_cross_fields() -> TestResult {
    let mode = LinuxVaultMode::SystemdHost;
    let root = Path::new("/private/vault");
    let m = Manifest::new(root, mode)?;
    m.validate(root, mode)?;
    let bytes = serde_json::to_vec(&m)?;
    assert_eq!(parse(&bytes, root, mode)?, m);
    for i in 0..9 {
        let mut bad = m.clone();
        match i {
            0 => bad.version = 2,
            1 => bad.root = "/other".into(),
            2 => bad.mode = "systemd-tpm2".into(),
            3 => bad.class = "hardware".into(),
            4 => bad.vault_id = "A".repeat(32),
            5 => bad.key_ids[0] = "a".repeat(31),
            6 => bad.key_ids[0] = bad.key_ids[1].clone(),
            7 => bad.names[1] = String::new(),
            _ => bad.names.swap(0, 1),
        }
        assert_eq!(bad.validate(root, mode), Err(Error::Corrupt));
    }
    let mut trailing = bytes;
    trailing.push(b' ');
    assert_eq!(parse(&trailing, root, mode), Err(Error::Corrupt));
    assert_eq!(mode_name(LinuxVaultMode::DesktopSecretService), "desktop-secret-service");
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let fd = root_fd(dir.path())?;
    for (length, cap) in [(0, 4096), (4097, 4096), (16385, 16384)] {
        let path = dir.path().join("bad");
        std::fs::write(&path, vec![0x78; length])?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(read(&fd, "bad", cap), Err(Error::Length));
    }
    assert!(matches!(root_fd(Path::new("relative")), Err(Error::Metadata)));
    assert!(matches!(root_fd(Path::new("/")), Err(Error::Metadata)));
    Ok(())
}

fn private_dir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
fn put(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> TestResult {
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Received-byte parser matrix: each predicate is isolated (one field differs from a valid
/// manifest), exact error asserted, with inclusive positive controls.
#[test]
fn init_manifest_refusal_matrix_is_isolated_and_exact() -> TestResult {
    let mode = LinuxVaultMode::SystemdHost;
    let root = Path::new("/private/vault");
    let good = Manifest::new(root, mode)?;
    let encode = |m: &Manifest| serde_json::to_vec(m);
    let (a, b, c) = ("a".repeat(32), "b".repeat(32), "c".repeat(32));
    let mut cases: Vec<(&str, Manifest)> = Vec::new();
    let mut m = good.clone();
    (m.key_ids[0], m.key_ids[1], m.key_ids[2]) = (a.clone(), a.clone(), c.clone());
    cases.push(("key ids (0,1) equal", m));
    let mut m = good.clone();
    (m.key_ids[0], m.key_ids[1], m.key_ids[2]) = (a.clone(), b.clone(), b.clone());
    cases.push(("key ids (1,2) equal", m));
    let mut m = good.clone();
    (m.key_ids[0], m.key_ids[1], m.key_ids[2]) = (a.clone(), b.clone(), a.clone());
    cases.push(("key ids (0,2) equal", m));
    for (what, id) in [
        ("vault id 31 bytes", "a".repeat(31)),
        ("vault id 33 bytes", "a".repeat(33)),
        ("vault id empty", String::new()),
        ("vault id uppercase", "A".repeat(32)),
        ("vault id non-hex letter", "g".repeat(32)),
        ("vault id non-ascii 32 bytes", "\u{e9}".repeat(16)),
    ] {
        let mut m = good.clone();
        m.vault_id = id;
        cases.push((what, m));
    }
    for index in 0..3 {
        for (what, id) in [
            ("key id 31 bytes", "a".repeat(31)),
            ("key id 33 bytes", "a".repeat(33)),
            ("key id uppercase", "F".repeat(32)),
            ("key id punctuation", "-".repeat(32)),
            ("key id non-ascii 32 bytes", "\u{e9}".repeat(16)),
        ] {
            let mut m = good.clone();
            m.key_ids[index] = id;
            cases.push((what, m));
        }
    }
    for (what, manifest) in cases {
        assert_eq!(parse(&encode(&manifest)?, root, mode), Err(Error::Corrupt), "{what}");
    }
    // Inclusive controls: all-zero and all-f identifiers are valid when distinct.
    let mut edge = good.clone();
    (edge.vault_id, edge.key_ids) = ("0".repeat(32), ["0".repeat(32), "f".repeat(32), c]);
    assert_eq!(parse(&encode(&edge)?, root, mode), Ok(edge));
    // Unknown field and non-canonical spacing are received-byte refusals too.
    let mut value: serde_json::Value = serde_json::from_slice(&encode(&good)?)?;
    value["extra"] = serde_json::Value::Null;
    assert_eq!(parse(&serde_json::to_vec(&value)?, root, mode), Err(Error::Corrupt));
    assert_eq!(parse(&serde_json::to_vec_pretty(&good)?, root, mode), Err(Error::Corrupt));
    Ok(())
}

/// Real file reader: inclusive 4096/16384 limits and every filesystem metadata predicate.
#[test]
fn init_reader_limits_and_metadata_predicates_are_exact() -> TestResult {
    let dir = private_dir()?;
    let fd = root_fd(dir.path())?;
    assert_eq!(systemd::CAP, 16384);
    for cap in [4096, systemd::CAP] {
        put(dir.path(), "edge", &vec![0x78; cap], 0o600)?;
        assert_eq!(read(&fd, "edge", cap)?.len(), cap, "{cap} accepted");
        put(dir.path(), "edge", &vec![0x78; cap + 1], 0o600)?;
        assert_eq!(read(&fd, "edge", cap), Err(Error::Length), "{} refused", cap + 1);
        put(dir.path(), "edge", &[], 0o600)?;
        assert_eq!(read(&fd, "edge", cap), Err(Error::Length), "empty refused");
    }
    assert_eq!(read(&fd, "absent", 4096), Err(Error::Missing));
    assert_eq!(optional(&fd, "absent", 4096), Ok(None));
    // One predicate at a time against an otherwise valid 0600 single-link regular file.
    put(dir.path(), "ok", b"x", 0o600)?;
    assert_eq!(read(&fd, "ok", 4096)?, b"x");
    for bad in [0o640, 0o644, 0o400, 0o700, 0o604] {
        put(dir.path(), "mode", b"x", bad)?;
        assert_eq!(read(&fd, "mode", 4096), Err(Error::Metadata), "mode {bad:o}");
    }
    std::fs::hard_link(dir.path().join("ok"), dir.path().join("second-link"))?;
    assert_eq!(read(&fd, "ok", 4096), Err(Error::Metadata), "link count 2");
    std::fs::remove_file(dir.path().join("second-link"))?;
    std::os::unix::fs::symlink("ok", dir.path().join("link"))?;
    assert_eq!(read(&fd, "link", 4096), Err(Error::Metadata), "symlink");
    fs::mknodat(&fd, "fifo", fs::FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)?;
    assert_eq!(read(&fd, "fifo", 4096), Err(Error::Metadata), "fifo");
    std::fs::create_dir(dir.path().join("subdir"))?;
    std::fs::set_permissions(dir.path().join("subdir"), std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(read(&fd, "subdir", 4096), Err(Error::Metadata), "directory as file");
    Ok(())
}

/// Root and injected-credential path predicates, one at a time.
#[test]
fn init_root_and_credential_metadata_predicates_are_exact() -> TestResult {
    let dir = private_dir()?;
    let base = dir.path();
    assert!(root_fd(base).is_ok());
    for bad in [0o750, 0o755, 0o500, 0o701] {
        let sub = base.join(format!("root-{bad:o}"));
        std::fs::create_dir(&sub)?;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(bad))?;
        assert!(matches!(root_fd(&sub), Err(Error::Metadata)), "root mode {bad:o}");
    }
    std::os::unix::fs::symlink(base, base.join("root-link"))?;
    assert!(matches!(root_fd(&base.join("root-link")), Err(Error::Metadata)), "symlink root");
    put(base, "plain", b"x", 0o600)?;
    assert!(matches!(root_fd(&base.join("plain")), Err(Error::Metadata)), "file as root");
    std::fs::create_dir(base.join("sub"))?;
    assert!(matches!(root_fd(&base.join("sub/../plain")), Err(Error::Metadata)), "dot-dot");
    assert!(matches!(root_fd(&base.join("nothing")), Err(Error::Missing)), "missing root");
    assert!(matches!(root_fd(Path::new("relative")), Err(Error::Metadata)));
    assert!(matches!(root_fd(Path::new("/")), Err(Error::Metadata)));
    // Credential reader: exactly one regular 0400 single-link 32-byte file.
    put(base, "key", &[7; 32], 0o400)?;
    assert_eq!(LinuxVaultInstallation::read_credential(&base.join("key")), Ok(()));
    for len in [0, 31, 33, 4096] {
        put(base, "len", &vec![7; len], 0o400)?;
        assert_eq!(
            LinuxVaultInstallation::read_credential(&base.join("len")),
            Err(Error::Length),
            "length {len}"
        );
    }
    for bad in [0o600, 0o440, 0o444] {
        put(base, "perm", &[7; 32], bad)?;
        assert_eq!(
            LinuxVaultInstallation::read_credential(&base.join("perm")),
            Err(Error::Metadata),
            "credential mode {bad:o}"
        );
    }
    // A credential the process cannot even open is an I/O refusal, not a metadata one.
    put(base, "unreadable", &[7; 32], 0o200)?;
    assert_eq!(LinuxVaultInstallation::read_credential(&base.join("unreadable")), Err(Error::Io));
    std::fs::hard_link(base.join("key"), base.join("key-twin"))?;
    assert_eq!(
        LinuxVaultInstallation::read_credential(&base.join("key")),
        Err(Error::Metadata),
        "link count 2"
    );
    std::os::unix::fs::symlink("key", base.join("key-link"))?;
    assert_eq!(
        LinuxVaultInstallation::read_credential(&base.join("key-link")),
        Err(Error::Metadata),
        "symlink credential"
    );
    std::os::unix::fs::symlink(base, base.join("dir-link"))?;
    assert_eq!(
        LinuxVaultInstallation::read_credential(&base.join("dir-link/key")),
        Err(Error::Metadata),
        "symlink directory component"
    );
    let fd = root_fd(base)?;
    fs::mknodat(&fd, "fifo-key", fs::FileType::Fifo, Mode::RUSR, 0)?;
    assert_eq!(
        LinuxVaultInstallation::read_credential(&base.join("fifo-key")),
        Err(Error::Metadata),
        "fifo credential"
    );
    std::fs::create_dir(base.join("dir-key"))?;
    std::fs::set_permissions(base.join("dir-key"), std::fs::Permissions::from_mode(0o400))?;
    assert_eq!(
        LinuxVaultInstallation::read_credential(&base.join("dir-key")),
        Err(Error::Metadata),
        "directory credential"
    );
    assert_eq!(
        LinuxVaultInstallation::read_credential(&base.join("missing-key")),
        Err(Error::Missing)
    );
    assert_eq!(
        LinuxVaultInstallation::read_credential(Path::new("relative")),
        Err(Error::Metadata)
    );
    Ok(())
}

/// Durability operation oracle: publication and intent removal perform the real fsync, rename
/// and unlink steps in order, on the expected objects, and injected syscall failures surface as
/// errors without a durable success.
#[test]
fn init_publication_and_intent_removal_follow_the_durable_order() -> TestResult {
    let dir = private_dir()?;
    let fd = root_fd(dir.path())?;
    let root_ino = format!("dir:ino{}", std::fs::metadata(dir.path())?.ino());
    let ops = RecordingOps::new(None);
    publish(&fd, "descriptor.json", b"payload", &ops, &|_| {})?;
    assert_eq!(*ops.log.borrow(), [Op::FileSync, Op::Rename, Op::DirSync]);
    let published = std::fs::metadata(dir.path().join("descriptor.json"))?.ino();
    assert_eq!(
        *ops.identity.borrow(),
        [
            format!("file:ino{published}"),
            ".descriptor.json.staging->descriptor.json".to_owned(),
            root_ino.clone()
        ],
        "the fsynced file is the one that was published; the parent is the realm directory"
    );
    assert_eq!(std::fs::read(dir.path().join("descriptor.json"))?, b"payload");
    put(dir.path(), "init.pending", b"intent", 0o600)?;
    let ops = RecordingOps::new(None);
    retire_intent(&fd, &ops, &|_| {})?;
    assert_eq!(*ops.log.borrow(), [Op::Unlink, Op::DirSync], "unlink before parent fsync");
    assert_eq!(*ops.identity.borrow(), ["init.pending".to_owned(), root_ino.clone()]);
    assert!(!dir.path().join("init.pending").exists());
    let ops = RecordingOps::new(None);
    retire_intent(&fd, &ops, &|_| {})?;
    assert_eq!(*ops.log.borrow(), [Op::DirSync], "a missing intent still gets the parent fsync");
    // Injected failures replace the syscall; each is an exact error to the caller.
    for (fail, expect_log, destination) in [
        (Op::FileSync, vec![Op::FileSync], false),
        (Op::Rename, vec![Op::FileSync, Op::Rename], false),
        (Op::DirSync, vec![Op::FileSync, Op::Rename, Op::DirSync], true),
    ] {
        let case = private_dir()?;
        let case_fd = root_fd(case.path())?;
        let ops = RecordingOps::new(Some(fail));
        assert_eq!(publish(&case_fd, "slot", b"x", &ops, &|_| {}), Err(Error::Io), "{fail:?}");
        assert_eq!(*ops.log.borrow(), expect_log, "{fail:?}");
        assert_eq!(case.path().join("slot").exists(), destination, "{fail:?}");
    }
    for (fail, expect_log, intent_left) in
        [(Op::Unlink, vec![Op::Unlink], true), (Op::DirSync, vec![Op::Unlink, Op::DirSync], false)]
    {
        let case = private_dir()?;
        put(case.path(), "init.pending", b"intent", 0o600)?;
        let case_fd = root_fd(case.path())?;
        let ops = RecordingOps::new(Some(fail));
        assert_eq!(retire_intent(&case_fd, &ops, &|_| {}), Err(Error::Io), "{fail:?}");
        assert_eq!(*ops.log.borrow(), expect_log, "{fail:?}");
        assert_eq!(case.path().join("init.pending").exists(), intent_left, "{fail:?}");
    }
    Ok(())
}

#[test]
#[ignore = "actual systemd provider and process crash fixture"]
fn linux_vault_installation_init_is_serial_and_crash_safe() -> TestResult {
    for cut in 1..=37 {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let result = run_output(
            Command::new(std::env::current_exe()?)
                .args(["--ignored", "--exact", "custody::vault::linux::init::tests::init_child"])
                .env("RF_INIT_CHILD", dir.path())
                .env("RF_INIT_CUT", cut.to_string()),
            DEADLINE,
        )?;
        assert_eq!(
            result.status.code(),
            Some(93),
            "cut {cut}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        // Independently retain every already-published encrypted slot before restart.
        let before = std::fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".cred"))
            .map(|e| Ok((e.file_name(), std::fs::read(e.path())?)))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        rt.block_on(async {
            let fd = root_fd(dir.path())?;
            let lock = open(&fd, ".init.lock", OFlags::RDWR)?;
            fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
            assert_eq!(
                LinuxVaultInstallation::initialize(dir.path().into(), LinuxVaultMode::SystemdHost)
                    .await,
                Err(Error::Busy)
            );
            let contender = run_output(
                Command::new(std::env::current_exe().map_err(|_| Error::Io)?)
                    .args([
                        "--ignored",
                        "--exact",
                        "custody::vault::linux::init::tests::init_child",
                    ])
                    .env("RF_INIT_CHILD", dir.path())
                    .env("RF_INIT_CUT", "0")
                    .env("RF_INIT_EXPECT_BUSY", "1"),
                DEADLINE,
            )
            .map_err(|_| Error::Io)?;
            assert!(contender.status.success(), "second process must get exact Busy");
            drop(lock);
            if dir.path().join("init.pending").exists() {
                assert_eq!(
                    LinuxVaultInstallation::status(dir.path().into(), LinuxVaultMode::SystemdHost)
                        .await,
                    Err(Error::Pending)
                );
            }
            LinuxVaultInstallation::initialize(dir.path().into(), LinuxVaultMode::SystemdHost)
                .await?;
            LinuxVaultInstallation::status(dir.path().into(), LinuxVaultMode::SystemdHost).await?;
            LinuxVaultInstallation::initialize(dir.path().into(), LinuxVaultMode::SystemdHost).await
        })?;
        for (name, bytes) in before {
            assert_eq!(
                std::fs::read(dir.path().join(name))?,
                bytes,
                "published key replaced at {cut}"
            );
        }
        assert_eq!(
            std::fs::read_dir(dir.path())?.count(),
            5,
            "bounded committed remnants at {cut}"
        );
    }
    Ok(())
}
#[test]
#[ignore = "child entry point"]
fn init_child() -> TestResult {
    let root = PathBuf::from(std::env::var_os("RF_INIT_CHILD").ok_or("child root")?);
    let cut_at: usize = std::env::var("RF_INIT_CUT")?.parse()?;
    let count = std::cell::Cell::new(0);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (_sender, mut receiver) = watch::channel(false);
    let result = rt.block_on(attempt(
        &root,
        LinuxVaultMode::SystemdHost,
        true,
        &mut receiver,
        Instant::now() + Duration::from_secs(90),
        &|_| {
            count.set(count.get() + 1);
            if count.get() == cut_at {
                std::process::exit(93);
            }
        },
    ));
    if std::env::var_os("RF_INIT_EXPECT_BUSY").is_some() {
        assert_eq!(result, Err(Error::Busy));
        return Ok(());
    }
    result?;
    Err("unreached cut".into())
}

async fn pipe_refusals(
    input: &[u8],
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> TestResult {
    let mode = LinuxVaultMode::SystemdHost;
    assert!(matches!(
        systemd::pipe::<33>(mode, 3, true, input, cancel, deadline).await,
        Err(Error::Realm)
    ));
    assert!(matches!(
        systemd::pipe::<33>(LinuxVaultMode::DesktopSecretService, 0, true, input, cancel, deadline)
            .await,
        Err(Error::Mode)
    ));
    let mut too_large = Secret::<{ systemd::CAP + 1 }>::new("p04-oversize-input");
    too_large.bytes_mut().fill(0x61);
    assert!(matches!(
        systemd::pipe::<33>(mode, 0, true, too_large.bytes(), cancel, deadline).await,
        Err(Error::Length)
    ));
    let (short_blob, short_len) =
        systemd::pipe::<{ systemd::CAP + 1 }>(mode, 0, true, &input[..31], cancel, deadline)
            .await?;
    assert!(matches!(
        systemd::decrypt(mode, 0, &short_blob.bytes()[..short_len], cancel, deadline).await,
        Err(Error::Length)
    ));
    Ok(())
}
