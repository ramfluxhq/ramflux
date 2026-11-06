// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real hosted-Linux fixture smoke only; this does not accept a vault provider.
#![cfg(target_os = "linux")]

use std::{os::unix::fs::MetadataExt, path::Path, process::Command};

#[test]
#[ignore = "requires scripts/linux-vault-ci.sh private Linux user and D-Bus fixture"]
fn linux_vault_platform_fixture_is_private() -> Result<(), Box<dyn std::error::Error>> {
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(uid, 0, "fixture must run as a disposable unprivileged user");
    let root = std::env::var("RF_LINUX_VAULT_FIXTURE_ROOT")?;
    for name in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"] {
        let value = std::env::var(name)?;
        let path = Path::new(&value);
        assert!(path.starts_with(&root) && path != Path::new(&root));
        let metadata = std::fs::symlink_metadata(path)?;
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o777, 0o700);
    }
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")?;
    let socket = address
        .strip_prefix("unix:path=")
        .ok_or("private Unix D-Bus required")?
        .split(',')
        .next()
        .ok_or("missing bus socket")?;
    assert!(Path::new(socket).starts_with(&root));
    assert!(
        Command::new("dbus-send")
            .args([
                "--session",
                "--print-reply",
                "--reply-timeout=5000",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.ListNames",
            ])
            .output()?
            .status
            .success()
    );
    let version = Command::new("systemd-creds").arg("--version").output()?;
    assert!(version.status.success());
    let text = std::str::from_utf8(&version.stdout)?;
    let number: u32 = text.split_whitespace().nth(1).ok_or("missing systemd version")?.parse()?;
    assert!(number >= 252);
    assert_eq!(
        std::fs::read_to_string(Path::new(&root).join("systemd-credential-probe"))?,
        "fixture-ok\n"
    );
    let rf = if let Some(copy) = std::env::var_os("RF_LINUX_VAULT_FIXTURE_RF") {
        let copy = std::path::PathBuf::from(copy);
        assert_eq!(copy, Path::new(&root).join("rf"));
        copy
    } else {
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_rf"))
    };
    assert!(rf.is_file(), "archive must retain its own compile-time rf binary");
    assert!(Command::new(&rf).arg("--help").output()?.status.success());
    Ok(())
}
