// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Server-document verification only; client signatures and bootstrap pins remain separate checks.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_000;
fn discovery() -> wire::Discovery {
    let public = crate::public_key_base64url_from_seed([7; 32]);
    wire::Discovery {
        client: ramflux_protocol::WellKnownClientRecord {
            schema: "ramflux.well_known_client.v1".into(),
            node_id: "peer.example".into(),
            node_public_key: public.clone(),
            node_ca_cert_pem: "fixture-ca".into(),
            gateway_quic_addr: "peer.example:443".into(),
            gateway_tcp_addr: "peer.example:443".into(),
            gateway_server_name: "peer.example".into(),
            relay_quic_addr: "peer.example:443".into(),
            relay_server_name: "peer.example".into(),
            prekey_http_url: "https://peer.example".into(),
            signaling_turn_addr: "peer.example:443".into(),
            protocol_versions: vec!["v1".into()],
            client_capabilities: vec![wire::CAPABILITY.into(), wire::EPHEMERAL_CAPABILITY.into()],
            updated_at: NOW,
            expires_at: NOW + 60,
            signature: String::new(),
        },
        server: serde_json::json!({
            "schema":"ramflux.well_known_server.v1", "node_id":"peer.example", "node_public_key":public,
            "node_ca_cert_pem":"fixture-ca", "node_endpoint":"https://peer.example",
            "protocol_versions":["v1"], "transport_backends":["quic"],
            "node_capabilities":[wire::CAPABILITY, wire::EPHEMERAL_CAPABILITY], "node_policy_hash":"policy",
            "updated_at":NOW, "expires_at":NOW+60, "signature":""
        }),
    }
}
fn signed(value: &mut wire::Discovery) -> TestResult {
    let signature = crate::sign_protocol_object_with_seed(&value.server, [7; 32])?;
    value
        .server
        .as_object_mut()
        .ok_or("server object")?
        .insert("signature".into(), signature.into());
    Ok(())
}
#[test]
fn cr_signed_server_discovery_requires_freshness_schema_and_capability() -> TestResult {
    let mut value = discovery();
    signed(&mut value)?;
    verify_server(&value, "peer.example", &value.client.node_public_key, NOW)?;
    let mut stale = value.clone();
    let expired = NOW - ramflux_protocol::DISCOVERY_CLOCK_SKEW_SECONDS - 1;
    stale
        .server
        .as_object_mut()
        .ok_or("server object")?
        .insert("expires_at".into(), expired.into());
    signed(&mut stale)?;
    assert!(
        verify_server(&stale, "peer.example", &value.client.node_public_key, NOW).is_err(),
        "a valid node signature cannot revive an expired server discovery record"
    );
    let mut changed = value.clone();
    changed.server.as_object_mut().ok_or("server object")?.insert("schema".into(), "legacy".into());
    signed(&mut changed)?;
    assert!(
        verify_server(&changed, "peer.example", &value.client.node_public_key, NOW).is_err(),
        "a signed different schema cannot authorize contact discovery"
    );
    let mut changed = value.clone();
    changed
        .server
        .as_object_mut()
        .ok_or("server object")?
        .insert("node_capabilities".into(), serde_json::json!([]));
    signed(&mut changed)?;
    assert!(
        verify_server(&changed, "peer.example", &value.client.node_public_key, NOW).is_err(),
        "both discovery surfaces must advertise the same audited reach capability"
    );
    Ok(())
}
