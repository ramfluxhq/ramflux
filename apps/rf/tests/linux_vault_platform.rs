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

#[tokio::test]
#[ignore = "requires privileged private systemd fixture"]
async fn linux_vault_systemd_credential_roundtrip_and_mode_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    use ramflux_sdk::custody::{
        LinuxVaultInitError as Error, LinuxVaultInstallation as Vault, LinuxVaultMode,
    };
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let fixture = std::path::PathBuf::from(
        std::env::var_os("RF_LINUX_VAULT_FIXTURE_ROOT").ok_or("fixture root")?,
    );
    let root = fixture.join("root-vault");
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let trace = fixture.join("init-exec.trace");
    let rf = Path::new(env!("CARGO_BIN_EXE_rf"));
    for expected in [3, 0] {
        let output = Command::new("strace")
            .args(["-qq", "-f", "-e", "execve", "-o"])
            .arg(&trace)
            .arg(rf)
            .args(["vault", "init", "--mode", "systemd-host", "--vault-root"])
            .arg(&root)
            .output()?;
        assert!(output.status.success(), "real rf bootstrap refused");
        assert_eq!(
            std::fs::read_to_string(&trace)?
                .lines()
                .filter(|line| line.contains("\"encrypt\""))
                .count(),
            expected,
            "independent provider exec oracle"
        );
        assert_eq!(
            std::str::from_utf8(&output.stdout)?,
            "vault_ready software_encrypted_file_systemd_host\n"
        );
    }
    Vault::status(root.clone(), LinuxVaultMode::SystemdHost).await?;
    assert_eq!(Vault::status(root.clone(), LinuxVaultMode::SystemdTpm2).await, Err(Error::Corrupt));
    let descriptor: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("descriptor.json"))?)?;
    for (i, name) in ["rf-primary-kek", "rf-device-kek", "rf-data-kek"].iter().enumerate() {
        let id = descriptor["key_ids"][i].as_str().ok_or("key id")?;
        let blob = root.join(format!("{name}.{id}.cred"));
        let unit = format!("rfv-p04-{}-{i}", std::process::id());
        // Use a fixed shell script with public credential id as an argument; no KEK output.
        let probe = |loaded: &str| -> Result<std::process::Output, std::io::Error> {
            Command::new("systemd-run")
                .args(["--quiet", "--wait", "--pipe", "--collect"])
                .arg(format!("--unit={unit}"))
                .arg(format!("--property=LoadCredentialEncrypted={loaded}:{}", blob.display()))
                .args([
                    "--property=RuntimeMaxSec=30s",
                    "/bin/sh",
                    "-ec",
                    "test \"$(wc -c < \"$CREDENTIALS_DIRECTORY/$1\")\" -eq 32",
                    "probe",
                    loaded,
                ])
                .output()
        };
        let positive = probe(name)?;
        assert!(positive.status.success(), "systemd matched-name load failed");
        assert!(positive.stdout.is_empty(), "no plaintext output");
        assert!(!probe("rf-wrong-kek")?.status.success(), "systemd must enforce encrypted name");
    }
    let wrong = fixture.join("wrong-key");
    for len in [0, 31, 32, 33] {
        std::fs::write(&wrong, zeroize::Zeroizing::new(vec![0x6b; len]).as_slice())?;
        std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o400))?;
        assert_eq!(
            Vault::check_credential(wrong.clone()).await,
            if len == 32 { Ok(()) } else { Err(Error::Length) }
        );
        std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::remove_file(&wrong)?;
    assert_eq!(Vault::check_credential(wrong.clone()).await, Err(Error::Missing));
    let tpm = fixture.join("tpm-vault");
    std::fs::create_dir(&tpm)?;
    std::fs::set_permissions(&tpm, std::fs::Permissions::from_mode(0o700))?;
    // Hosted fixture deliberately has no TPM; success would require separate hardware qualification.
    assert_eq!(
        Vault::initialize(tpm.clone(), LinuxVaultMode::SystemdTpm2).await,
        Err(Error::Provider)
    );
    assert!(!tpm.join("descriptor.json").exists());
    Ok(())
}
