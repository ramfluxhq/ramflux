// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ungated signed-submit fixtures shared by default-feature and local-mint tests.

pub(crate) fn test_runtime() -> anyhow::Result<crate::GatewaySessionRuntime> {
    let root = ramflux_crypto::create_identity_root("agent", [3; 32]);
    let branch = ramflux_crypto::create_device_branch("agent", "agent-device", 1, [4; 32]);
    Ok(crate::GatewaySessionRuntime {
        call_session_generation: None,
        session_push: None,
        ephemeral: false,
        push_limit: 256,
        source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?,
        session_id: "agent-session".into(),
        resume_token: "resume".into(),
        principal_id: "agent".into(),
        device_id: "agent-device".into(),
        target_delivery_id: "agent-target".into(),
        device_epoch: 1,
        branch_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        supports_forward_ack: true,
        ephemeral_rate: std::sync::Arc::default(),
    })
}

pub(crate) fn test_envelope(now: i64) -> anyhow::Result<ramflux_protocol::Envelope> {
    let envelope = serde_json::from_value(serde_json::json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":"group-distribution","source_principal_id":"agent","source_device_id":"agent-device","target_delivery_id":"alice-target",
        "delivery_class":"opaque_event","priority":"normal","ttl":300,"created_at":now,"encrypted_payload":"opaque","payload_hash":"opaque-hash"
    }))?;
    Ok(envelope)
}

pub(crate) fn signed_submit(
    runtime: &super::GatewaySessionRuntime,
    now: i64,
) -> anyhow::Result<ramflux_node_core::GatewaySubmitFrame> {
    let mut envelope = test_envelope(now)?;
    envelope.ext.ext.insert(
        "source_root_commitment".into(),
        serde_json::json!(runtime.source_identity.root_commitment()),
    );
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
        [4; 32],
    );
    let mut signed_request: ramflux_protocol::SignedRequest = serde_json::from_value(
        serde_json::json!({
            "schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1",
            "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
            "source_device_id":"agent-device","request_id":"submit-once","method":"POST","path":"/gateway/session/submit",
            "device_proof_hash":"already_authed","body_hash":"opaque-hash","nonce":"submit-nonce","created_at":now,"expires_at":now+60
        }),
    )?;
    signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&envelope)?,
    );
    signed_request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&signed_request)?,
        [4; 32],
    );
    Ok(ramflux_node_core::GatewaySubmitFrame {
        call_context: None,
        signed_request,
        envelope,
        call_intent: None,
        wake_id: None,
        call_ref: None,
        call_terminal: None,
    })
}
