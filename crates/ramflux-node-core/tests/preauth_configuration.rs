// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Service dependency builds never inherit the unit-test fixture key exemption.
use ramflux_node_core::{GatewayPreAuthPolicy, GatewayState, NodeCoreError};

#[test]
fn enabled_service_requires_a_separate_mounted_cookie_key() -> Result<(), Box<dyn std::error::Error>>
{
    let mut state = GatewayState::new();
    state.set_pre_auth_policy(GatewayPreAuthPolicy {
        enabled: true,
        per_source_ip_handshake_rate: 1,
        ..Default::default()
    })?;
    assert!(matches!(
        state.validate_pre_auth_configuration(),
        Err(NodeCoreError::PreAuthConfigInvalid)
    ));
    assert!(matches!(
        state.check_pre_auth("fixture-source", None, 100),
        Err(NodeCoreError::PreAuthConfigInvalid)
    ));
    assert!(
        state
            .check_pre_auth(
                "fixture-source",
                Some(ramflux_node_core::DEFAULT_PRE_AUTH_COOKIE_SECRET),
                100
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn gateway_pre_auth_bounds_are_checked_when_loading_config()
-> Result<(), Box<dyn std::error::Error>> {
    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let file = ConfigFile(std::env::temp_dir().join(format!(
        "preauth-config-{}.toml",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    )));
    let base = "node_id='test'\nservice_id='ramflux-gateway'\nredb_path='unused.redb'\n[mesh]\nlisten_addr='127.0.0.1:0'\nca_cert='unused'\nservice_cert='unused'\nservice_key='unused'\nallowed_service_ids=['ramflux-gateway']\n[mesh.endpoints]\nrouter='127.0.0.1:1'\n[gateway]\npublic_listen_addr='127.0.0.1:0'\n[gateway.pre_auth]\n";
    for (policy, valid) in [
        ("enabled=false\n", true),
        (
            "enabled=true\nper_source_ip_handshake_rate=0\nwindow_seconds=0\ncookie_ttl_seconds=0\nauth_deadline_ms=0\n",
            true,
        ),
        ("enabled=true\nper_source_ip_handshake_rate=61\n", false),
        ("window_seconds=3601\n", false),
        ("cookie_ttl_seconds=3601\n", false),
        ("auth_deadline_ms=10001\n", false),
    ] {
        std::fs::write(&file.0, format!("{base}{policy}"))?;
        let result = ramflux_node_core::load_config(&file.0, "ramflux-gateway");
        if valid {
            result?;
        } else {
            assert!(matches!(result, Err(NodeCoreError::PreAuthConfigInvalid)));
        }
    }
    Ok(())
}
