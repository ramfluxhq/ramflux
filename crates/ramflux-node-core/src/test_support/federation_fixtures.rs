// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared federation forward fixtures. Compiled only for node-core tests or with the
//! default-off `test-support` feature; never part of the production build.

#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

use crate::{
    DeviceAuthKeyResponse, FederatedEnvelopeForwardRequest, FederationPeerRoute,
    FederationTrustStatus, GATEWAY_SESSION_PROTOCOL_VERSION, GatewayOpenFrame,
    default_federation_forward_signed_fields,
};
use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};

pub fn gateway_registered_key(
    open: &GatewayOpenFrame,
) -> Result<DeviceAuthKeyResponse, ramflux_crypto::CryptoError> {
    let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([0x92; 32]);
    let keys = ramflux_crypto::device_key_commitments(
        &ramflux_crypto::fixture_public_key_base64url(),
        &ramflux_protocol::encode_base64url(agreement.public),
    )?;
    let set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: open.device_id.clone(),
                device_epoch: 1,
                signing_key_commitment: keys.0,
                agreement_key_commitment: keys.1,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    Ok(DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: Some(ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        )),
        signed_device_set: Some(set),
        principal_id: "alice".into(),
        device_id: open.device_id.clone(),
        device_epoch: 1,
        branch_public_key: ramflux_crypto::fixture_public_key_base64url(),
        target_delivery_id: open.target_delivery_id.clone(),
        revoked: false,
    })
}

pub fn envelope(
    envelope_id: &str,
    target_delivery_id: &str,
    delivery_class: DeliveryClass,
) -> Envelope {
    Envelope {
        schema: "ramflux.envelope.v1".to_owned(),
        version: 1,
        domain: "ramflux.envelope.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "alice".to_owned(),
        source_device_id: "alice_device".to_owned(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class,
        priority: Priority::Normal,
        ttl: 3_600,
        created_at: 1_760_000_000,
        encrypted_payload: "ciphertext".to_owned(),
        payload_hash: "payload_hash".to_owned(),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    }
}

pub fn signed_fields() -> SignedFields {
    SignedFields {
        signing_key_id: "fixture".to_owned(),
        signature_alg: SignatureAlg::Ed25519,
        signature: "sig".to_owned(),
    }
}

// A self-contained, committed test CA certificate. The federation admission
// logic treats `*_ca_cert_pem` as opaque pinning data (non-empty check + string
// equality only — never parsed as X.509), so a static public cert is sufficient
// and keeps the test suite compilable in clean checkouts. The previous
// `include_str!` of `deploy/certs/ca.pem` broke CI because that cert is issued at
// realnet startup and intentionally git-ignored, so it is absent in CI checkouts.
const TEST_FEDERATION_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBVTCCAQegAwIBAgIUUKW1inJxPZdXqkdecz2mcSAm9/swBQYDK2VwMCAxHjAc\n\
BgNVBAMMFVJhbWZsdXggTG9jYWwgTWVzaCBDQTAeFw0yNjA2MjkwNDQ1MDlaFw0z\n\
NjA2MjYwNDQ1MDlaMCAxHjAcBgNVBAMMFVJhbWZsdXggTG9jYWwgTWVzaCBDQTAq\n\
MAUGAytlcAMhAA3XGSY9j10c/7rAbTdXbkmEEC7xrUsb9QovaLCuc3IRo1MwUTAd\n\
BgNVHQ4EFgQU2j3DVamGrSfTx33tGcz+KeNscg4wHwYDVR0jBBgwFoAU2j3DVamG\n\
rSfTx33tGcz+KeNscg4wDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQAWvMVmy8e3\n\
scSsEjZJSqdZaUTvIdRvMF4sHne9xvtnN8v+aqxgPsyTmNH0ySSmTwT28sNyF15U\n\
81vAV6JvZYsI\n\
-----END CERTIFICATE-----\n";

pub fn test_federation_ca_pem() -> String {
    TEST_FEDERATION_CA_PEM.to_owned()
}

pub fn gateway_open_frame(device_id: &str, stream_nonce: &str) -> GatewayOpenFrame {
    GatewayOpenFrame {
        protocol_version: GATEWAY_SESSION_PROTOCOL_VERSION.to_owned(),
        transport_kind: "quic_quinn".to_owned(),
        client_instance_id: "client_a".to_owned(),
        device_id: device_id.to_owned(),
        target_delivery_id: "target_a".to_owned(),
        stream_nonce: stream_nonce.to_owned(),
        previous_session_id: None,
        resume_token_hash: None,
        last_seen_inbox_seq: None,
        max_inflight_downstream: 32,
        max_inflight_upstream: 32,
        pre_auth_cookie: None,
        pre_auth_now: None,
        source_ip_hash: None,
    }
}

pub fn signed_federation_handshake(
    source_node_id: &str,
    target_node_id: &str,
    seed: [u8; 32],
) -> Result<ramflux_protocol::FederationHandshake, Box<dyn std::error::Error>> {
    let mut handshake = federation_handshake(source_node_id, target_node_id);
    handshake.signed.signing_key_id = format!("{source_node_id}#federation");
    handshake.signed.signature = String::new();
    handshake.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&handshake, seed)?;
    Ok(handshake)
}

pub fn federation_handshake(
    source_node_id: &str,
    target_node_id: &str,
) -> ramflux_protocol::FederationHandshake {
    ramflux_protocol::FederationHandshake {
        schema: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        handshake_id: format!("hs_{source_node_id}_{target_node_id}"),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        source_capabilities: vec!["opaque_delivery".to_owned()],
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned()],
        trust_state_hash: "trust_state_hash".to_owned(),
        nonce: "nonce_hs".to_owned(),
        created_at: 1_760_000_000,
    }
}

pub fn federation_route_with_key(
    node_id: &str,
    node_public_key: &str,
    endpoint: &str,
    trust_status: FederationTrustStatus,
) -> FederationPeerRoute {
    FederationPeerRoute {
        node_id: node_id.to_owned(),
        endpoint: endpoint.to_owned(),
        node_public_key_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            node_public_key.as_bytes(),
        ),
        node_capabilities: vec!["opaque_delivery".to_owned()],
        trust_status,
        updated_at: 1_760_000_000,
        expires_at: 1_760_086_400,
        route_update_proof_hash: "route_update_proof_hash".to_owned(),
    }
}

pub fn federation_forward_request(
    envelope_id: &str,
    target_delivery_id: &str,
) -> FederatedEnvelopeForwardRequest {
    FederatedEnvelopeForwardRequest {
        migration_evidence: None,
        signed: default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: "node_a.example".to_owned(),
        target_node_id: "node_b.example".to_owned(),
        delivery_class: "opaque_event".to_owned(),
        required_capability: "opaque_delivery".to_owned(),
        envelope: envelope(envelope_id, target_delivery_id, DeliveryClass::OpaqueEvent),
    }
}

pub fn root_bound_forward(
    root: &ramflux_crypto::IdentityRoot,
    device: &str,
    record: Option<ramflux_protocol::SignedDeviceSetRecord>,
    id: &str,
) -> Result<FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>> {
    let mut forward = federation_forward_request(id, "root-replay-target");
    let open = gateway_open_frame(device, "root-forward");
    let mut authority = gateway_registered_key(&open)?;
    let devices = authority.signed_device_set.as_ref().ok_or("set")?.devices.clone();
    authority.principal_id.clone_from(&root.principal_id);
    authority.root_public_key =
        Some(ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes()));
    authority.signed_device_set = Some(match record {
        Some(record) => record,
        None => ramflux_crypto::sign_device_set(
            root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 1,
                devices,
            },
        )?,
    });
    let source = authority.authenticated_device_identity()?;
    forward.envelope.source_principal_id.clone_from(&root.principal_id);
    forward.envelope.source_device_id = device.into();
    forward
        .envelope
        .ext
        .ext
        .insert("source_root_commitment".into(), serde_json::json!(source.root_commitment()));
    forward.envelope.signed.signature = ramflux_crypto::sign_protocol_object(&forward.envelope)?;
    forward
        .envelope
        .ext
        .ext
        .insert("source_device_authority".into(), serde_json::to_value(authority)?);
    Ok(forward)
}
