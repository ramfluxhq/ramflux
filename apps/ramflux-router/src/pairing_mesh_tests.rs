// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production `enable_custody` attach and `handle_mesh_request_value` pairing hook.
use crate::handlers::handle_mesh_request_value;
use crate::router_runtime::RouterHandle;
use ramflux_node_core::pairing_relay::{
    PAIRING_CLAIM_PATH, PAIRING_CLOSE_PATH, PAIRING_POLL_PATH, PAIRING_SEND_PATH,
    PairingMeshForward, PairingMeshReply, encode_pairing_mesh_body,
};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Issued};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, RelayFrame, Send, Sent,
};
use ramflux_protocol::encode_base64url;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = anyhow::Result<()>;

struct PairingEnv {
    _guard: MutexGuard<'static, ()>,
    previous: Vec<(String, Option<String>)>,
}

fn pairing_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn env_keys() -> &'static [&'static str] {
    &[
        "RAMFLUX_DEVICE_PAIRING_ENABLED",
        "RAMFLUX_CUSTODY_NODE_RECORD_FILE",
        "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY",
        "RAMFLUX_FEDERATION_PUBLIC_ORIGIN",
    ]
}

#[allow(unsafe_code)]
fn pairing_env(values: &[(&str, &str)]) -> PairingEnv {
    let guard = pairing_env_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous =
        env_keys().iter().map(|key| ((*key).to_owned(), std::env::var(key).ok())).collect();
    // SAFETY: `guard` is held for the whole set/restore window.
    unsafe {
        for (key, value) in values {
            std::env::set_var(key, value);
        }
    }
    PairingEnv { _guard: guard, previous }
}

#[allow(unsafe_code)]
fn set_pairing_enabled(enabled: bool) {
    // SAFETY: The caller holds PairingEnv and its process-wide environment lock.
    unsafe {
        std::env::set_var("RAMFLUX_DEVICE_PAIRING_ENABLED", if enabled { "1" } else { "0" });
    }
}

#[allow(unsafe_code)]
impl Drop for PairingEnv {
    fn drop(&mut self) {
        // SAFETY: `self._guard` is held until this drop returns.
        unsafe {
            for (key, value) in &self.previous {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

fn id(tag: u8) -> String {
    let mut bytes = [0_u8; 32];
    bytes[0] = tag;
    bytes[31] = 1;
    encode_base64url(bytes)
}

fn wall() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn spec(account: u8, wall: u64) -> CreateSpec {
    let account_anchor = id(account);
    CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: account_anchor.clone(),
        primary_ref: DeviceRef {
            account_anchor,
            device_id: format!("device-{account}"),
            device_epoch: 1,
        },
        base_record_hash: id(2),
        base_epoch: 1,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into()],
        lease_not_before: wall,
        lease_expires_at: wall + 86_400,
        data_selection: vec![],
        ttl_seconds: 300,
    }
}

fn node_config(
    node_id: &str,
    seed: [u8; 32],
) -> anyhow::Result<ramflux_node_core::NodeServiceConfig> {
    let mut config: ramflux_node_core::NodeServiceConfig =
        serde_json::from_value(serde_json::json!({
            "node_id": node_id,
            "service_id": "ramflux-router",
            "redb_path": "unused.redb",
            "mesh": {
                "listen_addr": "127.0.0.1:0",
                "ca_cert": "unused.pem",
                "service_cert": "unused.pem",
                "service_key": "unused.key",
                "allowed_service_ids": [],
                "endpoints": {}
            }
        }))?;
    config.node_service_signing_seed_b64url =
        Some(ramflux_node_core::RedactedString::new(encode_base64url(seed)));
    Ok(config)
}

fn write_node_record(path: &std::path::Path, node_id: &str, now: u64) -> anyhow::Result<String> {
    let key = ramflux_crypto::fixture_signing_key();
    let public = ramflux_crypto::fixture_public_key_base64url();
    let body = ramflux_protocol::custody::NodeIdentityRecord {
        schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
        version: 1,
        node_id: node_id.into(),
        node_signing_public_key: public.clone(),
        client_tls_certificate_sha256: Some(encode_base64url([29; 32])),
        epoch: 1,
        previous_record_hash: None,
        issued_at: now,
        receipt_keys: vec![],
        revoked_receipt_key_ids: vec![],
        proxy_keys: vec![],
        revoked_proxy_key_ids: vec![],
        channel_binding_modes: vec![ramflux_protocol::custody::BindingMode::DirectExporter],
    };
    let record = ramflux_crypto::custody::sign_node_identity_record(&key, body)?;
    std::fs::write(path, ramflux_protocol::canonical_json_bytes(&record)?)?;
    Ok(public)
}

fn mesh(
    handle: &RouterHandle,
    peer: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<crate::handlers::MeshResponse> {
    let forward = serde_json::to_vec(&PairingMeshForward {
        body: encode_pairing_mesh_body(body),
        source: "203.0.113.10".into(),
    })?;
    handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: path.into(),
            body: forward,
        },
        handle,
        peer,
    )
}

fn inner_reply(response: &crate::handlers::MeshResponse) -> anyhow::Result<PairingMeshReply> {
    Ok(serde_json::from_slice(&response.body)?)
}

fn decode_ok<T: PairingWire>(response: &crate::handlers::MeshResponse) -> anyhow::Result<T> {
    anyhow::ensure!(response.status == "200 OK", "outer {}", response.status);
    let reply = inner_reply(response)?;
    anyhow::ensure!(reply.status == "200 OK", "inner {}", reply.status);
    let body = ramflux_protocol::decode_base64url(&reply.body)
        .map_err(|_| anyhow::anyhow!("mesh body"))?;
    T::from_wire_bytes(&body).map_err(|error| anyhow::anyhow!("{error}"))
}

fn native_create(handle: &RouterHandle, account: u8) -> anyhow::Result<(Created, String)> {
    let store = handle.pairing_relay().ok_or_else(|| anyhow::anyhow!("pairing store missing"))?;
    let wall = wall()?;
    let mut store = store.lock().map_err(|_| anyhow::anyhow!("pairing lock"))?;
    let issued: Issued = store.issue(spec(account, wall))?;
    let node_key = issued.ticket.body.node_key.clone();
    let created = store.create(Create {
        schema: "ramflux.pairing.Create.v2".into(),
        version: 2,
        ticket: issued.ticket,
        spec: spec(account, wall),
    })?;
    Ok((created, node_key))
}

fn wire_bytes<T: PairingWire>(value: &T) -> anyhow::Result<Vec<u8>> {
    value.to_wire_bytes().map_err(|error| anyhow::anyhow!("{error}"))
}

fn relay_cycle(handle: &RouterHandle, created: &Created) -> TestResult {
    let _: Claimed = decode_ok(&mesh(
        handle,
        "ramflux-federation",
        PAIRING_CLAIM_PATH,
        &wire_bytes(&Claim {
            schema: "ramflux.pairing.Claim.v2".into(),
            version: 2,
            invitation_id: created.invitation.body.invitation_id.clone(),
            issuer_seq: created.invitation.body.issuer_seq,
            recipient_token: created.recipient_token.clone(),
            claim_nonce: id(9),
        })?,
    )?)?;
    let _: Sent = decode_ok(&mesh(
        handle,
        "ramflux-federation",
        PAIRING_SEND_PATH,
        &wire_bytes(&Send {
            schema: "ramflux.pairing.Send.v2".into(),
            version: 2,
            invitation_id: created.invitation.body.invitation_id.clone(),
            issuer_seq: created.invitation.body.issuer_seq,
            role: "responder".into(),
            token: created.recipient_token.clone(),
            seq: 0,
            frame: RelayFrame::Confirm {
                role: "responder".into(),
                transcript_hash: encode_base64url([1; 32]),
                mac: encode_base64url([2; 32]),
            },
        })?,
    )?)?;
    let _: Polled = decode_ok(&mesh(
        handle,
        "ramflux-federation",
        PAIRING_POLL_PATH,
        &wire_bytes(&Poll {
            schema: "ramflux.pairing.Poll.v2".into(),
            version: 2,
            invitation_id: created.invitation.body.invitation_id.clone(),
            issuer_seq: created.invitation.body.issuer_seq,
            role: "initiator".into(),
            token: created.primary_token.clone(),
            after_seq: None,
        })?,
    )?)?;
    let _: Closed = decode_ok(&mesh(
        handle,
        "ramflux-federation",
        PAIRING_CLOSE_PATH,
        &wire_bytes(&Close {
            schema: "ramflux.pairing.Close.v2".into(),
            version: 2,
            invitation_id: created.invitation.body.invitation_id.clone(),
            issuer_seq: created.invitation.body.issuer_seq,
            role: "initiator".into(),
            token: created.primary_token.clone(),
            reason: "done".into(),
        })?,
    )?)?;
    Ok(())
}

fn wired_handle(
    name: &str,
) -> anyhow::Result<(
    ramflux_test_support::TestPath,
    ramflux_test_support::TestPath,
    RouterHandle,
    PairingEnv,
    String,
)> {
    let (redb, state, store) = crate::router_runtime::tests::test_router(name)?;
    let record = redb.with_extension("node-record.json");
    let now = wall()?;
    let public = write_node_record(&record, "node", now)?;
    let env = pairing_env(&[
        ("RAMFLUX_DEVICE_PAIRING_ENABLED", "1"),
        (
            "RAMFLUX_CUSTODY_NODE_RECORD_FILE",
            record.to_str().ok_or_else(|| anyhow::anyhow!("record"))?,
        ),
        ("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", &public),
        ("RAMFLUX_FEDERATION_PUBLIC_ORIGIN", "https://relay.example:443"),
    ]);
    let handle = RouterHandle::tokio(state, store, None);
    handle.enable_custody(&node_config("node", ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES)?)?;
    Ok((redb, record, handle, env, public))
}

#[test]
fn pairing_mesh_requires_federation_peer() -> TestResult {
    let (path, state, store) = crate::router_runtime::tests::test_router("pairing-mesh-peer")?;
    let handle = RouterHandle::tokio(state, store, None);
    let response = mesh(&handle, "ramflux-gateway", PAIRING_CLAIM_PATH, b"{}")?;
    assert_eq!(response.status, "403 Forbidden");
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[test]
fn enable_custody_requires_ticket_key_match() -> TestResult {
    let (redb, state, store) =
        crate::router_runtime::tests::test_router("pairing-mesh-key-mismatch")?;
    let record = redb.with_extension("node-record.json");
    let now = wall()?;
    let public = write_node_record(&record, "node", now)?;
    let env = pairing_env(&[
        ("RAMFLUX_DEVICE_PAIRING_ENABLED", "1"),
        (
            "RAMFLUX_CUSTODY_NODE_RECORD_FILE",
            record.to_str().ok_or_else(|| anyhow::anyhow!("record"))?,
        ),
        ("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", &public),
        ("RAMFLUX_FEDERATION_PUBLIC_ORIGIN", "https://relay.example:443"),
    ]);
    let handle = RouterHandle::tokio(state, store, None);
    let Err(error) = handle.enable_custody(&node_config("node", [9; 32])?) else {
        anyhow::bail!("mismatched ticket key attached");
    };
    anyhow::ensure!(
        error.to_string().contains("pairing ticket signing key does not match node identity"),
        "{error}"
    );
    drop(env);
    let _ = std::fs::remove_file(redb);
    let _ = std::fs::remove_file(record);
    Ok(())
}

#[test]
fn enable_custody_wires_pairing_mesh_through_router_entry() -> TestResult {
    let (redb, record, handle, env, public) = wired_handle("pairing-mesh-wiring")?;
    let (created, node_key) = native_create(&handle, 1)?;
    assert_eq!(node_key, public);
    relay_cycle(&handle, &created)?;
    let forbidden = mesh(&handle, "ramflux-gateway", PAIRING_CLAIM_PATH, b"{}")?;
    assert_eq!(forbidden.status, "403 Forbidden");
    set_pairing_enabled(false);
    let absent = mesh(&handle, "ramflux-federation", PAIRING_CLAIM_PATH, b"{}")?;
    assert_eq!(absent.status, "200 OK");
    assert_eq!(inner_reply(&absent)?.status, "404 Not Found");
    drop(env);
    let _ = std::fs::remove_file(redb);
    let _ = std::fs::remove_file(record);
    Ok(())
}
