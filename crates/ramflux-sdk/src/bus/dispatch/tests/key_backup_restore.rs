// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native group regressions recover through the actual legacy key export/import functions.
use super::*;
pub(crate) async fn recover_alice(root: &Path) -> Result<RamfluxClient, SdkError> {
    std::fs::create_dir_all(root)?;
    let gateway = GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::GatewaySessionNotEstablished)?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::GatewaySessionNotEstablished)?,
        server_name: "test".into(),
        ca_cert: root.join("ca.pem"),
        principal_id: "alice".into(),
        device_id: "alice".into(),
        target_delivery_id: "alice".into(),
        prekey_http_url: None,
    };
    let mut seed_client = RamfluxClient::new();
    let identity = seed_client.create_identity_root("alice", [41; 32]);
    let manifest = LocalBusPersistedAccount {
        schema: "ramflux.local_bus.account_manifest.v1".into(),
        local_account_id: "alice".into(),
        principal_id: "alice".into(),
        principal_commitment: ramflux_crypto::identity_root_commitment(
            &identity.signing_key.verifying_key(),
        ),
        device_id: "alice".into(),
        target_delivery_id: "alice".into(),
        account_secret: "routed-test".into(),
        root_seed: [41; 32],
        device_seed: [42; 32],
        client_mode: LocalBusClientMode::AttendedCli,
        gateway,
        devices: vec![],
        label: None,
        kind: Some("human".into()),
        activation_pending: false,
        node_id: None,
        node_tcp_addr: None,
        node_relay: None,
    };
    let secret = "legacy key recovery regression";
    let file = encrypt_account_backup(&manifest, Vec::new(), &mut secret.to_owned())?;
    let path = root.join("key-only.rfb");
    std::fs::write(&path, serde_json::to_vec(&file)?)?;
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root),
        accounts: BTreeMap::new(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let _ = local_bus_account_backup_import(
        &mut state,
        &mut LocalBusAccountBackupImportRequest {
            input_path: path.to_string_lossy().into_owned(),
            passphrase: secret.into(),
        },
        None,
    )
    .await?;
    Ok(state.accounts.remove("alice").ok_or(SdkError::AccountDbNotUnlocked)?.client)
}
