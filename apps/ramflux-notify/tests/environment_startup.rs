// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise production startup without listeners, a container engine or provider credentials.
#![cfg(unix)]
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ramflux-notify-env-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::create_dir(root.join("data"))?;
        std::fs::create_dir(root.join("secrets"))?;
        let key = root.join("secrets/route.key");
        std::fs::write(&key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(root.join("providers.json"), "[]")?;
        Ok(Self(root))
    }
    fn command(&self, provider: Option<&std::ffi::OsStr>) -> Command {
        let config =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config/notify.toml");
        let mut command = Command::new(env!("CARGO_BIN_EXE_ramflux-notify"));
        command
            .env_clear()
            .args(["--config"])
            .arg(config)
            .arg("--once")
            .env("RAMFLUX_NODE_STATE_DIR", self.0.join("data"))
            .env("RAMFLUX_NOTIFY_ROUTE_KEY_FILE", self.0.join("secrets/route.key"));
        if let Some(provider) = provider {
            command.env("RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE", provider);
        }
        command
    }
    fn run(&self, provider: Option<&std::ffi::OsStr>) -> std::io::Result<Output> {
        self.command(provider).output()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn an_unexpanded_optional_credential_path_fails_closed_without_its_value()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let literal = "${RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE:-}";
    let output = fixture.run(Some(literal.as_ref()))?;
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{logs}");
    assert!(logs.contains("RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE"), "{logs}");
    assert!(!logs.contains(literal), "configuration values must stay redacted");
    Ok(())
}

#[test]
fn absent_empty_and_concrete_optional_provider_settings_keep_notify_startup_working()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let path = fixture.0.join("providers.json");
    for value in [None, Some(std::ffi::OsStr::new("")), Some(path.as_os_str())] {
        let output = fixture.run(value)?;
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn an_unexpanded_required_route_secret_still_fails_closed_without_logging_its_value()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let literal = "${RAMFLUX_NOTIFY_ROUTE_KEY_FILE:-/run/secrets/key}";
    let output = fixture.command(None).env("RAMFLUX_NOTIFY_ROUTE_KEY_FILE", literal).output()?;
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "a required encryption secret cannot be disabled");
    assert!(logs.contains("RAMFLUX_NOTIFY_ROUTE_KEY_FILE"), "{logs}");
    assert!(!logs.contains(literal), "configuration values must stay redacted");
    Ok(())
}

#[test]
fn an_unexpanded_privacy_key_cannot_silently_select_an_ephemeral_key()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let literal = "/private/${DO_NOT_LOG}/privacy.key";
    let output = fixture.command(None).env("RAMFLUX_NODE_PRIVACY_KEY_FILE", literal).output()?;
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
    assert!(logs.contains("RAMFLUX_NODE_PRIVACY_KEY_FILE"), "{logs}");
    assert!(!logs.contains(literal));
    Ok(())
}

#[test]
fn an_unexpanded_optional_runtime_uses_its_default_with_a_key_only_warning()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let literal = "${DO_NOT_LOG:-current}";
    let output = fixture.command(None).env("RAMFLUX_NOTIFY_RUNTIME", literal).output()?;
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{logs}");
    assert!(logs.contains("RAMFLUX_NOTIFY_RUNTIME"), "{logs}");
    assert!(!logs.contains(literal));
    Ok(())
}

#[test]
fn public_default_admin_tokens_are_refused_at_shared_service_startup()
-> Result<(), Box<dyn std::error::Error>> {
    for key in [
        "RAMFLUX_ROUTER_ADMIN_TOKEN",
        "RAMFLUX_ROUTER_FEDERATION_FORWARD_TOKEN",
        "RAMFLUX_FEDERATION_ADMIN_TOKEN",
    ] {
        let fixture = Fixture::new()?;
        let output = fixture.command(None).env(key, "ramflux-local-admin-token").output()?;
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{key} unexpectedly allowed startup: {logs}");
        assert!(logs.contains(key), "{logs}");
        assert!(!logs.contains("ramflux-local-admin-token"), "token must stay redacted");
    }
    Ok(())
}
