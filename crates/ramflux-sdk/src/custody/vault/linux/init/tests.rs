// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::cleanup::observer;
use super::*;
use std::{os::unix::fs::PermissionsExt, process::Command};
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
    assert_eq!(mode_name(LinuxVaultMode::DesktopSecretService), Err(Error::Mode));
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

#[test]
#[ignore = "actual systemd provider and process crash fixture"]
fn linux_vault_installation_init_is_serial_and_crash_safe() -> TestResult {
    for cut in 1..=36 {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let result = Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact", "custody::vault::linux::init::tests::init_child"])
            .env("RF_INIT_CHILD", dir.path())
            .env("RF_INIT_CUT", cut.to_string())
            .output()?;
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
            let contender = Command::new(std::env::current_exe().map_err(|_| Error::Io)?)
                .args(["--ignored", "--exact", "custody::vault::linux::init::tests::init_child"])
                .env("RF_INIT_CHILD", dir.path())
                .env("RF_INIT_CUT", "0")
                .env("RF_INIT_EXPECT_BUSY", "1")
                .output()
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
