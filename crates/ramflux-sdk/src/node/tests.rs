// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{NodePinSource, NodeProfile, NodeStore};
use crate::prelude::*;
use ramflux_protocol::WellKnownClientRecord;

// A scoped client is an explicit network fixture, isolated from parallel tests and production.
tokio::task_local! {
    pub(crate) static DISCOVERY_CLIENT: reqwest::Client;
}

struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Result<Self, SdkError> {
        Ok(Self(std::env::temp_dir().join(format!(
            "ramflux-node-test-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ))))
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record(seed: u8) -> Result<WellKnownClientRecord, SdkError> {
    let mut record = WellKnownClientRecord {
        schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.to_owned(),
        node_id: "node.example.com".to_owned(),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed([seed; 32]),
        node_ca_cert_pem: "test CA".to_owned(),
        gateway_quic_addr: "127.0.0.1:7443".to_owned(),
        gateway_tcp_addr: "127.0.0.1:7444".to_owned(),
        gateway_server_name: "gateway.example.com".to_owned(),
        relay_quic_addr: "127.0.0.1:17447".to_owned(),
        relay_server_name: "relay.example.com".to_owned(),
        prekey_http_url: "https://node.example.com".to_owned(),
        signaling_turn_addr: "node.example.com:3478".to_owned(),
        protocol_versions: vec!["v1".to_owned()],
        client_capabilities: vec!["prekey".to_owned()],
        updated_at: 1000,
        expires_at: 2000,
        signature: String::new(),
    };
    record.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::client_discovery_signing_bytes(&record)?,
        [seed; 32],
    );
    Ok(record)
}

#[test]
fn tofu_key_change_warning_survives_restart_until_operator_pin() -> Result<(), SdkError> {
    let root = TestRoot::new()?;
    let first = record(1)?;
    let mut store = NodeStore::default();
    let profile = store.confirm(first.clone(), NodePinSource::Tofu, None, 1500)?;
    assert!(profile.safety_warnings.contains("tofu_unverified"));
    let changed = record(2)?;
    assert!(store.observe(&changed));
    store.save(&root.0)?;
    let mut store = NodeStore::load(&root.0, &[])?;
    assert!(!store.observe(&first));
    assert!(store.profiles[&first.node_id].safety_warnings.contains("key_changed"));
    assert!(store.confirm(changed.clone(), NodePinSource::Tofu, None, 1500).is_err());
    assert!(
        store
            .confirm(changed.clone(), NodePinSource::Operator, Some(&first.node_public_key), 1500)
            .is_err()
    );
    let profile = store.confirm(
        changed.clone(),
        NodePinSource::Operator,
        Some(&changed.node_public_key),
        1500,
    )?;
    assert!(profile.safety_warnings.is_empty());
    assert_eq!(profile.pin_source, NodePinSource::Operator);
    assert!(store.confirm(changed, NodePinSource::Tofu, None, 1500).is_err());
    Ok(())
}

#[test]
fn disabled_builtin_remains_disabled_after_restart_and_requires_pin() -> Result<(), SdkError> {
    let root = TestRoot::new()?;
    let mut builtin = NodeProfile::from_record(record(1)?, 1500);
    builtin.builtin = true;
    builtin.pin_source = NodePinSource::Builtin;
    builtin.safety_warnings.clear();
    let mut injected = serde_json::to_value(&builtin)?;
    let fields =
        injected.as_object_mut().ok_or_else(|| super::node_error("profile is not an object"))?;
    for name in ["discovery_url", "signaling_turn_addr", "protocol_versions", "client_capabilities"]
    {
        fields.remove(name);
    }
    let from_client: NodeProfile = serde_json::from_value(injected)?;
    assert_eq!(from_client.discovery_url, "");
    let mut store = NodeStore::load(&root.0, &[from_client])?;
    store
        .profiles
        .get_mut(&builtin.node_id)
        .ok_or_else(|| super::node_error("missing builtin"))?
        .enabled = false;
    store.save(&root.0)?;
    let store = NodeStore::load(&root.0, &[builtin.clone()])?;
    assert!(store.selected(Some(&builtin.node_id), false).is_err());
    assert!(store.selected(Some(&builtin.node_id), true)?.is_some());
    builtin.node_public_key.clear();
    assert!(NodeStore::load(&root.0, &[builtin]).is_err());
    Ok(())
}

fn manifest() -> Result<LocalBusPersistedAccount, SdkError> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.local_bus.account_manifest.v1", "node_id":"node.example.com",
        "local_account_id":"bound", "principal_id":"principal", "principal_commitment":"commitment", "device_id":"device", "target_delivery_id":"target", "account_secret":"test secret", "root_seed":vec![1;32], "device_seed":vec![2;32], "client_mode":"headless_ai",
        "gateway":{"bind_addr":"0.0.0.0:0", "gateway_addr":"127.0.0.1:1", "server_name":"override", "ca_cert":"override.pem", "principal_id":"principal", "device_id":"device", "target_delivery_id":"target", "prekey_http_url":null}
    }))?)
}

#[test]
fn node_removal_is_refused_for_a_closed_bound_account() -> Result<(), SdkError> {
    let root = TestRoot::new()?;
    let manifest = manifest()?;
    write_local_bus_account_manifest(&root.0, &manifest)?;
    assert!(
        crate::bus::dispatch::node::refuse_bound_node_removal(&root.0, "node.example.com").is_err()
    );
    crate::bus::dispatch::node::refuse_bound_node_removal(&root.0, "other.example.com")?;
    let backup = serde_json::to_value(manifest)?;
    assert!(backup.get("enabled").is_none());
    assert!(backup.get("default_node_id").is_none());
    Ok(())
}

#[test]
fn profile_endpoints_take_priority_over_environment_and_development_options()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "RAMFLUX_NODE_PROFILE_TEST_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "node::tests::profile_endpoints_take_priority_over_environment_and_development_options"])
            .env(CHILD,"1").env("RAMFLUX_SDK_RELAY_QUIC_ADDR","bad override")
            .env_remove("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME").env_remove("RAMFLUX_SDK_RELAY_QUIC_CA_CERT").status()?;
        assert!(status.success());
        return Ok(());
    }
    let root = TestRoot::new()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let profile = NodeProfile::from_record(record(1)?, 1500);
        let endpoint = profile.gateway_config(&root.0, manifest()?.gateway).await?;
        assert_eq!(endpoint.gateway_addr.to_string(), profile.gateway.quic_addr);
        assert_eq!(endpoint.server_name, profile.gateway.server_name);
        assert_eq!(std::fs::read_to_string(&endpoint.ca_cert)?, profile.ca_cert_pem);
        let mut client = RamfluxClient::new();
        client.node_relay_options = Some(profile.relay_options(&root.0, "principal").await?);
        let options = client
            .relay_transfer_options(Some("http://override".to_owned()), None, None)?
            .ok_or_else(|| super::node_error("missing relay options"))?;
        assert_eq!(options.relay_quic_peer_addr.as_deref(), Some("127.0.0.1:17447"));
        assert_eq!(options.relay_owner_home_node_id.as_deref(), Some("node.example.com"));
        Ok::<_, SdkError>(())
    })?;
    Ok(())
}

#[test]
fn structured_bus_error_retains_nested_socket_errno_without_inference() -> Result<(), SdkError> {
    let io = std::io::Error::from_raw_os_error(65);
    let expected_kind = format!("{:?}", io.kind());
    let error = SdkError::Transport(ramflux_transport::TransportError::Io(io));
    let body = crate::bus::io::local_bus_error_body(&error);
    let encoded = serde_json::to_value(&body)?;
    assert_eq!(encoded["cause"]["raw_os_error"], 65);
    assert_eq!(encoded["cause"]["kind"], expected_kind);
    // Existing peers can still send error bodies with no cause field.
    let legacy: LocalBusErrorBody = serde_json::from_value(
        serde_json::json!({"code":"ValidationFailed","message":"failed","retry_after_ms":null}),
    )?;
    assert!(legacy.cause.is_none());
    let timeout = crate::bus::io::local_bus_error_body(&SdkError::Io(std::io::Error::from(
        std::io::ErrorKind::TimedOut,
    )));
    assert_eq!(serde_json::to_value(timeout)?["cause"]["raw_os_error"], serde_json::Value::Null);
    Ok(())
}

#[tokio::test]
async fn discovery_retains_socket_source_and_strips_request_url() -> Result<(), SdkError> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let origin = format!("http://127.0.0.1:{port}/private?token=secret");
    let error = super::fetch_client_record(&origin)
        .await
        .err()
        .ok_or_else(|| super::node_error("expected connect failure"))?;
    let encoded = serde_json::to_value(crate::bus::io::local_bus_error_body(&error))?;
    assert_eq!(encoded["cause"]["kind"], "ConnectionRefused");
    assert!(encoded["cause"]["raw_os_error"].is_number());
    let diagnostic = format!("{error:?}");
    assert!(!diagnostic.contains("http://") && !diagnostic.contains("token=secret"));
    assert!(super::fetch_client_record("http://user:password@127.0.0.1").await.is_err());
    Ok(())
}

#[tokio::test]
async fn gateway_probe_retains_tcp_socket_cause_in_failed_health_response() -> Result<(), SdkError>
{
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    let root = TestRoot::new()?;
    let mut profile = record(1)?;
    profile.gateway_tcp_addr = addr.to_string();
    let probe = super::probe_gateway_pre_account(&profile, &root.0.join("missing.pem")).await;
    assert_eq!(probe.transport["tcp"], "failed");
    assert_eq!(probe.errors["tcp"]["cause"]["kind"], "ConnectionRefused");
    assert!(probe.errors["tcp"]["cause"]["raw_os_error"].is_number());
    Ok(())
}
