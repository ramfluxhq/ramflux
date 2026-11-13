// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Default-off preview release contract in isolated child environments.
#[cfg(test)]
mod tests {
    use super::super::*;
    const CHILD: &str = "RAMFLUX_PAIRING_ACTIVATION_CHILD";
    const EXACT: &str = "pairing_http::tests::activation::tests::pairing_activation_is_complete_and_old_paths_stay_safe";
    #[tokio::test]
    async fn pairing_activation_is_complete_and_old_paths_stay_safe() -> TestResult {
        tokio::time::timeout(std::time::Duration::from_secs(60), Box::pin(check()))
            .await
            .map_err(|_| "test: default-off release contract exceeded its deadline")?
    }
    async fn check() -> TestResult {
        if std::env::var_os(CHILD).is_none() {
            let root = tempfile::tempdir()?;
            for (index, flag) in [None, Some("1"), Some("2")].into_iter().enumerate() {
                let sentinel = root.path().join(format!("case-{index}"));
                let mut command = tokio::process::Command::new(std::env::current_exe()?);
                command
                    .args(["--exact", EXACT])
                    .env(CHILD, &sentinel)
                    .env_remove("RAMFLUX_DEVICE_PAIRING_ENABLED")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .kill_on_drop(true);
                if let Some(flag) = flag {
                    command.env("RAMFLUX_DEVICE_PAIRING_ENABLED", flag);
                }
                assert!(
                    command.spawn()?.wait().await?.success(),
                    "test: isolated preview activation case {index} failed"
                );
                assert!(sentinel.is_file(), "test: isolated activation filter ran zero tests");
            }
            return Ok(());
        }
        if std::env::var("RAMFLUX_DEVICE_PAIRING_ENABLED").as_deref() == Ok("2") {
            assert!(
                ramflux_sdk::custody::pairing::PairingConfig::from_env().is_err(),
                "test: SDK accepted an invalid pairing startup selector"
            );
            assert!(
                ramflux_node_core::device_pairing_enabled().is_err(),
                "test: node accepted an invalid pairing startup selector"
            );
        } else {
            require_dormant_discovery()?;
            if std::env::var_os("RAMFLUX_DEVICE_PAIRING_ENABLED").is_none() {
                require_absent_routes()?;
                super::super::super::continuity_tests::native_issue_refused_when_disabled()?;
            }
        }
        let sentinel = std::env::var_os(CHILD).ok_or("test: child completion path missing")?;
        std::fs::write(sentinel, b"accepted")?;
        Ok(())
    }
    fn require_absent_routes() -> TestResult {
        let (context, _root) = public_context(None)?;
        let limits = crate::http_limits::defaults(true);
        for path in [PAIRING_CLAIM_PATH, PAIRING_SEND_PATH, PAIRING_POLL_PATH, PAIRING_CLOSE_PATH] {
            let response = exchange(&post(path, b"{}", ""), context.clone(), limits)?;
            assert!(
                response.starts_with("HTTP/1.1 404"),
                "test: default-off pairing route {path} was exposed: {response}"
            );
        }
        let response =
            exchange(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", context, limits)?;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "test: disabling pairing broke ordinary health: {response}"
        );
        Ok(())
    }
    fn require_dormant_discovery() -> TestResult {
        let config: ramflux_node_core::NodeServiceConfig = serde_json::from_value(
            serde_json::json!({
                "node_id":"preview", "service_id":"ramflux-federation", "redb_path":"unused.redb",
                "mesh":{"listen_addr":"127.0.0.1:0","ca_cert":"unused.pem","service_cert":"unused.pem",
                    "service_key":"unused.key","allowed_service_ids":[],"endpoints":{}}
            }),
        )?;
        let mut surface = crate::discovery::federation_discovery_surface(&config, [8; 32]);
        surface.node_ca_cert_pem = "test-ca".into();
        surface
            .node_capabilities
            .extend(["device_pairing_v2".into(), "primary_transfer_full_v1".into()]);
        let client = surface.client_record()?;
        let server = surface.well_known_record()?;
        for capabilities in [&client.client_capabilities, &server.node_capabilities] {
            assert!(
                !capabilities.iter().any(|value| matches!(
                    value.as_str(),
                    "device_pairing_v2" | "primary_transfer_full_v1"
                )),
                "test: preview discovery advertised an unaccepted pairing capability"
            );
            assert!(
                capabilities.iter().any(|value| value == "opaque_delivery"),
                "test: preview pairing interlock removed ordinary discovery capabilities"
            );
        }
        ramflux_node_core::verify_federation_server_record(&server, server.updated_at)?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::client_discovery_signing_bytes(&client)?,
            &client.signature,
            &client.node_public_key,
        )?;
        Ok(())
    }
}
