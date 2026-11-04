// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Released migration startup requires the configured node signer.
use std::io::Write;
#[test]
fn migration_enabled_startup_refuses_without_matching_node_signer()
-> Result<(), Box<dyn std::error::Error>> {
    const NAME: &str =
        "migration_startup_tests::migration_enabled_startup_refuses_without_matching_node_signer";
    if std::env::var_os("RAMFLUX_MIGRATION_PREFLIGHT_CHILD").is_none() {
        let path = std::env::temp_dir().join(format!(
            "rf-migration-preflight-{}-{}",
            std::process::id(),
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(ramflux_protocol::encode_base64url([8; 32]).as_bytes())?;
        drop(file);
        let result = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", NAME])
            .env("RAMFLUX_MIGRATION_PREFLIGHT_CHILD", "1")
            .env("RAMFLUX_HOME_MIGRATION_ENABLED", "1")
            .env("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE", &path)
            .output();
        std::fs::remove_file(path)?;
        let output = result?;
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return Ok(());
    }
    assert!(ramflux_node_core::home_migration_enabled()?);
    let mut config: ramflux_node_core::NodeServiceConfig = serde_json::from_value(
        serde_json::json!({
            "node_id": "A", "service_id": "ramflux-federation", "redb_path": "unused.redb",
            "mesh": {"listen_addr": "127.0.0.1:0", "ca_cert": "unused.pem", "service_cert": "unused.pem", "service_key": "unused.key", "allowed_service_ids": [], "endpoints": {}}
        }),
    )?;
    assert!(super::validate_enabled_migration_config(&config).is_err());
    config.node_service_signing_seed_b64url =
        Some(ramflux_node_core::RedactedString::new("invalid"));
    assert!(super::validate_enabled_migration_config(&config).is_err());
    config.node_service_signing_seed_b64url =
        Some(ramflux_node_core::RedactedString::new(ramflux_protocol::encode_base64url([9; 32])));
    let error = super::validate_enabled_migration_config(&config)
        .err()
        .ok_or("mismatched mounted identity accepted")?;
    assert!(error.to_string().contains("differs from federation identity"));
    config.node_service_signing_seed_b64url =
        Some(ramflux_node_core::RedactedString::new(ramflux_protocol::encode_base64url([8; 32])));
    super::validate_enabled_migration_config(&config)?;
    Ok(())
}
