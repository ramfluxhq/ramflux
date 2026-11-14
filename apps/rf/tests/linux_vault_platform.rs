// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real hosted-Linux provider contracts in private systemd and Secret Service fixtures.
#![cfg(target_os = "linux")]

use std::{
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

type BoxError = Box<dyn std::error::Error>;
/// Every fixture subprocess is bounded below CI's 60 s nextest slow-timeout and fails loudly.
const DEADLINE: Duration = Duration::from_secs(30);
const _: () = assert!(DEADLINE.as_secs() >= 10 && DEADLINE.as_secs() <= 40);

/// Kills the child's whole process group and reaps the leader on every exit path.
struct GroupReaper(Child);
impl Drop for GroupReaper {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
/// Runs `command` in its own process group under `deadline`, capturing output through private
/// files (a full pipe cannot stall the child). Records the group id in `leader`.
fn bounded_with(
    command: &mut Command,
    deadline: Duration,
    leader: &mut u32,
) -> Result<Output, BoxError> {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let stem = ramflux_test_support::TestPath::new()?.child(format!(
        "rf-vault-proc-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::SeqCst)
    ));
    let (out, err) = (stem.with_extension("out"), stem.with_extension("err"));
    let result = (|| -> Result<Output, BoxError> {
        command
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(&err)?)
            .process_group(0);
        let mut child = GroupReaper(command.spawn()?);
        *leader = child.0.id();
        let end = Instant::now() + deadline;
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok(Output {
                    status,
                    stdout: std::fs::read(&out)?,
                    stderr: std::fs::read(&err)?,
                });
            }
            if Instant::now() >= end {
                return Err(format!("subprocess timed out after {deadline:?}").into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&err);
    result
}
/// Like [`bounded`] for commands that print a secret: stdout is an in-memory pipe (never a file)
/// and the buffer is zeroized on drop. The output is tiny, so the pipe cannot fill and stall.
fn bounded_secret(
    command: &mut Command,
) -> Result<(std::process::ExitStatus, zeroize::Zeroizing<Vec<u8>>), BoxError> {
    use std::io::Read;
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0);
    let mut child = GroupReaper(command.spawn()?);
    let end = Instant::now() + DEADLINE;
    loop {
        if let Some(status) = child.0.try_wait()? {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            if let Some(mut out) = child.0.stdout.take() {
                out.read_to_end(&mut bytes)?;
            }
            return Ok((status, bytes));
        }
        if Instant::now() >= end {
            return Err(format!("subprocess timed out after {DEADLINE:?}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn bounded(command: &mut Command) -> Result<Output, BoxError> {
    bounded_with(command, DEADLINE, &mut 0)
}

#[test]
fn bounded_subprocess_kills_and_reaps_a_stalled_group() -> Result<(), BoxError> {
    let started = Instant::now();
    let mut leader = 0;
    let err =
        bounded_with(Command::new("sleep").arg("60"), Duration::from_millis(300), &mut leader)
            .err()
            .ok_or("a stalled subprocess must fail loudly")?;
    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(started.elapsed() < DEADLINE);
    let group = rustix::process::Pid::from_raw(leader.cast_signed()).ok_or("pid")?;
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        match rustix::process::test_kill_process_group(group) {
            Err(rustix::io::Errno::SRCH) => break,
            _ if Instant::now() >= end => return Err("stalled group still alive".into()),
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let early = bounded(Command::new("sh").args(["-c", "exit 3"]))?;
    assert_eq!(early.status.code(), Some(3));
    Ok(())
}

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
        bounded(Command::new("dbus-send").args([
            "--session",
            "--print-reply",
            "--reply-timeout=5000",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ListNames",
        ]))?
        .status
        .success()
    );
    let version = bounded(Command::new("systemd-creds").arg("--version"))?;
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
    assert!(bounded(Command::new(&rf).arg("--help"))?.status.success());
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
        let output = bounded(
            Command::new("strace")
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/ramflux-no-bus")
                .args(["-qq", "-f", "-e", "execve,connect", "-o"])
                .arg(&trace)
                .arg(rf)
                .args(["vault", "init", "--mode", "systemd-host", "--vault-root"])
                .arg(&root),
        )?;
        assert!(output.status.success(), "real rf bootstrap refused");
        assert!(!std::fs::read_to_string(&trace)?.contains("ramflux-no-bus"));
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
    primary_contract(&root, LinuxVaultMode::SystemdHost).await?;
    Vault::status(root.clone(), LinuxVaultMode::SystemdHost).await?;
    assert_eq!(Vault::status(root.clone(), LinuxVaultMode::SystemdTpm2).await, Err(Error::Corrupt));
    let descriptor: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("descriptor.json"))?)?;
    for (i, name) in ["rf-primary-kek", "rf-device-kek", "rf-data-kek"].iter().enumerate() {
        let id = descriptor["key_ids"][i].as_str().ok_or("key id")?;
        let blob = root.join(format!("{name}.{id}.cred"));
        let unit = format!("rfv-p04-{}-{i}", std::process::id());
        // Use a fixed shell script with public credential id as an argument; no KEK output.
        let probe = |loaded: &str| -> Result<Output, BoxError> {
            bounded(
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
                    ]),
            )
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

#[tokio::test]
#[ignore = "private unlocked gnome-keyring fixture"]
async fn linux_vault_secret_service_has_no_headless_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    use ramflux_sdk::custody::{LinuxVaultInstallation as Vault, LinuxVaultMode};
    use std::os::unix::fs::PermissionsExt;
    let root = std::path::PathBuf::from(
        std::env::var_os("RF_LINUX_VAULT_FIXTURE_ROOT").ok_or("fixture root")?,
    )
    .join("ss-vault");
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    Vault::initialize(root.clone(), LinuxVaultMode::DesktopSecretService).await?;
    Vault::status(root.clone(), LinuxVaultMode::DesktopSecretService).await?;
    let descriptor = std::fs::read(root.join("descriptor.json"))?;
    Vault::initialize(root.clone(), LinuxVaultMode::DesktopSecretService).await?;
    assert_eq!(descriptor, std::fs::read(root.join("descriptor.json"))?);
    let rf = std::env::var_os("RF_LINUX_VAULT_FIXTURE_RF")
        .map_or_else(|| env!("CARGO_BIN_EXE_rf").into(), std::path::PathBuf::from);
    // A child with no bus cannot fall back, and does not touch persisted state.
    let missing = bounded(
        Command::new(&rf)
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/ramflux-fixture")
            .args(["vault", "status", "--mode", "desktop-secret-service", "--vault-root"])
            .arg(&root),
    )?;
    assert!(!missing.status.success());
    assert!(String::from_utf8(missing.stderr)?.contains("vault_provider"));
    assert_eq!(descriptor, std::fs::read(root.join("descriptor.json"))?);
    Ok(())
}

#[tokio::test]
#[ignore = "private D-Bus and real gnome-keyring fixture"]
async fn linux_vault_primary_branch_and_data_contract() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    start_keyring()?;
    let collection_ss = wait_for_secret_service()?;
    let collection = collection_ss.get_default_collection()?;
    collection.set_label("ramflux-local-vault")?;
    let root = std::path::PathBuf::from(
        std::env::var_os("RF_LINUX_VAULT_FIXTURE_ROOT").ok_or("fixture root")?,
    )
    .join("p06-ss-vault");
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    ramflux_sdk::custody::LinuxVaultInstallation::initialize(
        root.clone(),
        ramflux_sdk::custody::LinuxVaultMode::DesktopSecretService,
    )
    .await?;
    primary_contract(&root, ramflux_sdk::custody::LinuxVaultMode::DesktopSecretService).await
}

/// Starts the private-bus keyring and waits for it to exit, under the fixture deadline. The
/// password goes through stdin only; a stalled daemon is killed and reaped, never awaited forever.
fn start_keyring() -> Result<(), BoxError> {
    use std::io::Write;
    let mut child = Command::new("gnome-keyring-daemon")
        .args(["--unlock", "--components=secrets"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| -> Result<(), BoxError> {
        child.stdin.take().ok_or("keyring stdin")?.write_all(b"rf-disposable-fixture-only")?;
        let end = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("gnome-keyring-daemon failed: {status}").into())
                };
            }
            if Instant::now() >= end {
                return Err(format!("gnome-keyring-daemon timed out after {DEADLINE:?}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
/// One connect-and-open-default-collection probe.
fn probe_secret_service() -> Result<(), String> {
    let ss = dbus_secret_service::SecretService::connect_with_max_prompt_timeout(
        dbus_secret_service::EncryptionType::Dh,
        0,
    )
    .map_err(|e| e.to_string())?;
    ss.get_default_collection().map(drop).map_err(|e| e.to_string())
}
/// The daemon registers `org.freedesktop.secrets` on the private bus after its launcher exits, so
/// a connection attempt right away can see `ServiceUnknown`. Poll until the service answers and
/// its default collection is usable. Each blocking D-Bus attempt runs on its own thread and is
/// waited for at most 5 s (and never past the deadline), so a stalled service cannot stretch the
/// total beyond the fixture deadline; the last error is reported loudly.
fn wait_for_secret_service() -> Result<dbus_secret_service::SecretService, BoxError> {
    let end = Instant::now() + DEADLINE;
    loop {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(probe_secret_service());
        });
        let remaining = end.saturating_duration_since(Instant::now());
        let last = match receiver.recv_timeout(remaining.min(Duration::from_secs(5))) {
            Ok(Ok(())) => {
                return Ok(dbus_secret_service::SecretService::connect_with_max_prompt_timeout(
                    dbus_secret_service::EncryptionType::Dh,
                    0,
                )?);
            }
            Ok(Err(last)) => last,
            Err(_) => "attempt stalled".to_owned(),
        };
        if Instant::now() >= end {
            return Err(format!("Secret Service not ready after {DEADLINE:?}: {last}").into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn primary_contract(
    root: &Path,
    mode: ramflux_sdk::custody::LinuxVaultMode,
) -> Result<(), Box<dyn std::error::Error>> {
    use ramflux_sdk::SdkError;
    use ramflux_sdk::custody::{
        CustodyVaultReason, LinuxDataCredentials, LinuxPrimaryVault, LinuxVaultConfig,
        LinuxVaultRole as Role, PrimaryVault,
    };
    use zeroize::Zeroizing;
    let mode_name = if mode == ramflux_sdk::custody::LinuxVaultMode::DesktopSecretService {
        "desktop-secret-service"
    } else {
        "systemd-host"
    };
    let paths = contract_paths(root, mode_name)?;
    let reference = ramflux_protocol::encode_base64url([6; 32]);
    let branch = format!("branch:{reference}");
    let provisioning = format!("agent-provisioning:{reference}");
    let config = LinuxVaultConfig::new(mode_name, Role::AttendedPrimary, paths.clone())?;
    let primary =
        LinuxPrimaryVault::open(root.into(), "p06-account".into(), reference.clone(), config)
            .await?;
    assert_eq!(primary.vault_class(), mode.strength_class());
    primary.preflight()?;
    assert!(matches!(
        primary.home_authorization_preflight(),
        Err(SdkError::HomeMigrationRefused(
            ramflux_protocol::home_migration::Refusal::CustodyUserPresenceUnavailable
        ))
    ));
    let key = ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&Zeroizing::new([7; 32]));
    primary.store_new(&reference, &key)?;
    assert_eq!(primary.load_primary(&reference)?.public_key(), key.public_key());
    assert!(matches!(primary.store_new(&reference, &key), Err(SdkError::CustodyVaultUnavailable)));
    primary.store_branch(&branch, &Zeroizing::new([8; 64]))?;
    let device = ramflux_protocol::custody::DeviceRef {
        account_anchor: "anchor".into(),
        device_id: "desktop".into(),
        device_epoch: 1,
    };
    drop(primary.load_branch(&branch, "principal", &device)?);
    reference_binding_contract(root, (mode_name, &paths), &primary, &key, &device).await?;
    for length in [1, 8192] {
        let secret = Zeroizing::new(vec![0x63; length]);
        primary.store_provisioning_secret(&provisioning, &secret)?;
        assert_eq!(primary.load_provisioning_secret(&provisioning)?.as_slice(), secret.as_slice());
        primary.delete(&provisioning)?;
    }
    for length in [0, 8193] {
        assert!(matches!(
            primary.store_provisioning_secret(&provisioning, &Zeroizing::new(vec![0x63; length])),
            Err(SdkError::CustodyVaultUnavailable)
        ));
    }
    let mut service_paths = paths.clone();
    service_paths.primary = None;
    let device_config = LinuxVaultConfig::new(mode_name, Role::Device, service_paths)?;
    let service = LinuxPrimaryVault::open(
        root.into(),
        "p06-account".into(),
        reference.clone(),
        device_config,
    )
    .await?;
    drop(service.load_branch(&branch, "principal", &device)?);
    assert!(matches!(
        service.load_primary(&reference),
        Err(SdkError::CustodyVault(CustodyVaultReason::PrimaryUnavailable))
    ));
    assert!(matches!(
        service.store_new(&reference, &key),
        Err(SdkError::CustodyVault(CustodyVaultReason::PrimaryUnavailable))
    ));
    let mut data_paths = paths;
    data_paths.primary = None;
    data_paths.device = None;
    let data = LinuxDataCredentials::open(
        root.into(),
        "p06-account".into(),
        LinuxVaultConfig::new(mode_name, Role::DataOnly, data_paths)?,
    )
    .await?;
    data_contract(&data)?;
    primary.delete(&reference)?;
    primary.delete(&reference)?;
    primary.delete(&branch)?;
    primary.delete(&branch)?;
    assert!(matches!(
        service.load_branch(&branch, "principal", &device),
        Err(SdkError::CustodyVault(CustodyVaultReason::Missing))
    ));
    Ok(())
}

/// Reference binding, one predicate at a time (see the seeding note inside).
async fn reference_binding_contract(
    root: &Path,
    (mode_name, paths): (&str, &ramflux_sdk::custody::LinuxCredentialPaths),
    primary: &ramflux_sdk::custody::LinuxPrimaryVault,
    key: &ramflux_crypto::custody::SelfSigningKey,
    device: &ramflux_protocol::custody::DeviceRef,
) -> Result<(), Box<dyn std::error::Error>> {
    use ramflux_sdk::SdkError;
    use ramflux_sdk::custody::{
        LinuxPrimaryVault, LinuxVaultConfig, LinuxVaultRole as Role, PrimaryVault,
    };
    use zeroize::Zeroizing;
    // Reference binding, one predicate at a time. A second provider bound to another canonical
    // reference seeds valid entries in the same account; `primary` must refuse each of them by its
    // binding alone (the entries exist, so "missing" cannot be the reason), and leave them intact.
    let foreign = ramflux_protocol::encode_base64url([9; 32]);
    let foreign_branch = format!("branch:{foreign}");
    let foreign_provisioning = format!("agent-provisioning:{foreign}");
    let other = LinuxPrimaryVault::open(
        root.into(),
        "p06-account".into(),
        foreign.clone(),
        LinuxVaultConfig::new(mode_name, Role::AttendedPrimary, paths.clone())?,
    )
    .await?;
    other.store_new(&foreign, key)?;
    other.store_branch(&foreign_branch, &Zeroizing::new([5; 64]))?;
    other.store_provisioning_secret(&foreign_provisioning, b"foreign-secret")?;
    let refused =
        |result: Result<(), SdkError>| matches!(result, Err(SdkError::CustodyVaultUnavailable));
    assert!(refused(primary.load_primary(&foreign).map(drop)), "load_primary binding");
    assert!(refused(primary.load_branch(&foreign_branch, "principal", device).map(drop)));
    assert!(refused(primary.load_provisioning_secret(&foreign_provisioning).map(drop)));
    assert!(refused(primary.delete(&foreign)), "delete primary binding");
    assert!(refused(primary.delete(&foreign_branch)), "delete branch binding");
    assert!(refused(primary.delete(&foreign_provisioning)), "delete provisioning binding");
    // Stores of an unseeded foreign reference would succeed without the guard.
    let unseeded = ramflux_protocol::encode_base64url([10; 32]);
    assert!(refused(primary.store_new(&unseeded, key)), "store_new binding");
    assert!(refused(primary.store_branch(&format!("branch:{unseeded}"), &Zeroizing::new([5; 64]))));
    assert!(refused(
        primary.store_provisioning_secret(&format!("agent-provisioning:{unseeded}"), b"x")
    ));
    assert!(
        matches!(other.load_primary(&unseeded), Err(SdkError::CustodyVaultUnavailable)),
        "the refused store created nothing"
    );
    // Controls: every seeded entry is intact and readable through its own binding.
    assert_eq!(other.load_primary(&foreign)?.public_key(), key.public_key());
    drop(other.load_branch(&foreign_branch, "principal", device)?);
    assert_eq!(
        other.load_provisioning_secret(&foreign_provisioning)?.as_slice(),
        b"foreign-secret"
    );
    other.delete(&foreign)?;
    other.delete(&foreign_branch)?;
    other.delete(&foreign_provisioning)?;
    Ok(())
}

fn contract_paths(
    root: &Path,
    mode_name: &str,
) -> Result<ramflux_sdk::custody::LinuxCredentialPaths, Box<dyn std::error::Error>> {
    use ramflux_sdk::custody::LinuxCredentialPaths as Paths;
    use std::os::unix::fs::PermissionsExt;
    let mut paths = Paths::default();
    if mode_name == "systemd-host" {
        let descriptor: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("descriptor.json"))?)?;
        for (i, slot) in
            [&mut paths.primary, &mut paths.device, &mut paths.data].into_iter().enumerate()
        {
            let name = ["rf-primary-kek", "rf-device-kek", "rf-data-kek"][i];
            let id = descriptor["key_ids"][i].as_str().ok_or("key id")?;
            let (status, bytes) = bounded_secret(
                Command::new("systemd-creds")
                    .arg("decrypt")
                    .arg(format!("--name={name}"))
                    .arg(root.join(format!("{name}.{id}.cred")))
                    .arg("-"),
            )?;
            assert!(status.success());
            assert_eq!(bytes.len(), 32);
            let path = root.join(format!("injected-{i}"));
            std::fs::write(&path, bytes.as_slice())?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
            *slot = Some(path);
        }
    }
    Ok(paths)
}

fn data_contract(
    data: &ramflux_sdk::custody::LinuxDataCredentials,
) -> Result<(), Box<dyn std::error::Error>> {
    use ramflux_sdk::SdkError;
    use zeroize::Zeroizing;
    for length in [1, 8192] {
        let secret = Zeroizing::new(vec![0x64; length]);
        data.store_new(&secret)?;
        assert_eq!(data.load()?.as_slice(), secret.as_slice());
        assert!(matches!(data.store_new(&secret), Err(SdkError::CustodyVaultUnavailable)));
        data.delete()?;
        data.delete()?;
    }
    for length in [0, 8193] {
        assert!(matches!(
            data.store_new(&Zeroizing::new(vec![0x64; length])),
            Err(SdkError::CustodyVaultUnavailable)
        ));
    }
    Ok(())
}
