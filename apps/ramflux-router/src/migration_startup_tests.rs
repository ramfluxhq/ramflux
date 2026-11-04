// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit enabled preflight tests leave the production release interlock closed.
#[test]
fn migration_enabled_startup_refuses_without_matching_node_signer()
-> Result<(), Box<dyn std::error::Error>> {
    const NAME: &str =
        "migration_startup_tests::migration_enabled_startup_refuses_without_matching_node_signer";
    if std::env::var_os("RAMFLUX_MIGRATION_PREFLIGHT_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", NAME])
            .env("RAMFLUX_MIGRATION_PREFLIGHT_CHILD", "1")
            .env(
                super::ROUTER_FEDERATION_FORWARD_URL_ENV,
                "http://127.0.0.1:1/internal/home-node-migration/forward",
            )
            .output()?;
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return Ok(());
    }
    let mut config: ramflux_node_core::NodeServiceConfig = serde_json::from_value(
        serde_json::json!({
            "node_id": "A", "service_id": "ramflux-router", "redb_path": "unused.redb",
            "mesh": {"listen_addr": "127.0.0.1:0", "ca_cert": "unused.pem", "service_cert": "unused.pem", "service_key": "unused.key", "allowed_service_ids": [], "endpoints": {}}
        }),
    )?;
    assert!(super::validate_enabled_migration_config(&config).is_err());
    config.node_service_signing_seed_b64url =
        Some(ramflux_node_core::RedactedString::new("invalid"));
    assert!(super::validate_enabled_migration_config(&config).is_err());
    config.node_service_signing_seed_b64url =
        Some(ramflux_node_core::RedactedString::new(ramflux_protocol::encode_base64url([8; 32])));
    super::validate_enabled_migration_config(&config)?;
    Ok(())
}
