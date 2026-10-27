// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real TLS and relay-handler proof for capture failures masquerading as readiness failures.
use super::*;
use crate::test_support::{
    V3_AUDIENCE_NODE, V3_OWNER_SEED, client_quic_request, issue_test_ca_and_service_cert,
    temp_cert_root, test_config, v3_pinned_cache, v3_pk, v3_state_with, v3_stored_chunk,
    v3_temp_store,
};
use std::time::Duration;

const CHILD_MODE: &str = "RAMFLUX_RELAY_TEST_CAPTURE_DIAGNOSTIC_MODE";

#[test]
fn capture_failure_preserves_close_reason_after_successful_tls()
-> Result<(), Box<dyn std::error::Error>> {
    if let Ok(mode) = std::env::var(CHILD_MODE) {
        return exercise_relay(&mode);
    }
    let root = temp_cert_root("capture_diagnostics_child")?;
    for mode in ["unresolved", "writable", "wrong-san"] {
        let capture = if mode == "unresolved" {
            "${RAMFLUX_RELAY_ITEST_CAPTURE_FILE:-/var/lib/ramflux/relay/itest-object-v3-capture.jsonl}".into()
        } else {
            root.join(format!("{mode}.jsonl"))
        };
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "quic_service::failure_diagnostics_tests::capture_failure_preserves_close_reason_after_successful_tls",
                "--nocapture",
            ])
            .env(CHILD_MODE, mode)
            .env("RAMFLUX_RELAY_ITEST_CAPTURE_FILE", &capture)
            .env_remove("RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT")
            .env_remove("RAMFLUX_RELAY_ITEST_HOLD_MARKER")
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{mode}: {stderr}");
        assert!(output.status.success(), "{mode}: {stdout}\n{stderr}");
        assert!(stdout.contains("1 passed"), "child did not run: {stdout}");
        if mode == "writable" {
            let record: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(capture)?)?;
            assert_eq!(record["route"], "/healthz");
            assert_eq!(record["status"], 200);
        }
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn exercise_relay(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_cert_root("relay_capture_diagnostics")?;
    let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
    let config = test_config(&certs.tls, "unused-retention:0");
    let server_config = validate_relay_client_quic_tls(&config)?;
    let store = v3_temp_store()?;
    let metrics = RelayClientQuicMetrics::default();
    let context = RelayClientQuicContext {
        metrics: metrics.clone(),
        trust_snapshot_cache: Arc::new(Mutex::new(v3_pinned_cache()?)),
        node_id: Arc::from(V3_AUDIENCE_NODE),
        state: v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?,
        store,
        config: Arc::new(config),
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let addr = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await
                && let Ok(connection) = incoming.await
            {
                handle_relay_client_quic_connection(connection, context).await;
            }
        });
        let server_name = if mode == "wrong-san" { "wrong-relay.invalid" } else { "ramflux-relay" };
        let result = ramflux_transport::QuicGatewayClient::connect(
            "127.0.0.1:0".parse()?,
            addr,
            server_name,
            std::path::Path::new(&certs.tls.ca_cert),
            Duration::from_secs(3),
        )
        .await;
        if mode == "wrong-san" {
            let refusal = result.err().ok_or("wrong SAN must fail TLS")?;
            assert!(
                matches!(&refusal, ramflux_transport::TransportError::Tls(_)),
                "wrong SAN must be a typed TLS validation refusal: {refusal}"
            );
            let error = refusal.to_string();
            eprintln!("{error}");
            assert!(error.contains("certificate not valid for name"), "{error}");
            assert_eq!(metrics.ingress_total(), 0);
        } else {
            let client = result?;
            let response = client.request(&client_quic_request("GET", "/healthz")).await;
            assert_eq!(metrics.ingress_total(), 1, "TLS and request dispatch completed");
            if mode == "unresolved" {
                let refusal = response.err().ok_or("capture failure must close connection")?;
                assert!(matches!(&refusal, ramflux_transport::TransportError::Quic(_)));
                let error = refusal.to_string();
                eprintln!("{error}");
                assert!(error.contains("itest-quic-fault: capture write failed"), "{error}");
                assert!(error.contains("ApplicationClosed"), "{error}");
                assert!(error.contains("phase=request"), "{error}");
            } else {
                assert_eq!(response?.status, 200);
            }
            client.close();
        }
        tokio::time::timeout(Duration::from_secs(3), server).await??;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
