#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn gateway_heartbeat_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

pub(crate) fn gateway_session_state(
    session: &GatewaySessionEstablishedFrame,
    fallback_inbox_seq: u64,
) -> GatewaySessionState {
    GatewaySessionState {
        session_id: session.session_id.clone(),
        gateway_id: session.gateway_id.clone(),
        resume_token: session.resume_token.clone(),
        resume_window_seconds: session.resume_window_seconds,
        accepted_inbox_seq: session
            .accepted_cursor
            .as_ref()
            .map_or(fallback_inbox_seq, |cursor| cursor.inbox_seq),
    }
}

pub(crate) fn gateway_fresh_open_frame(
    config: &GatewaySessionConfig,
) -> Result<GatewayOpenFrame, SdkError> {
    Ok(gateway_open_frame_with_nonce(config, gateway_fresh_stream_nonce()?))
}

fn gateway_open_frame_with_nonce(
    config: &GatewaySessionConfig,
    stream_nonce: String,
) -> GatewayOpenFrame {
    GatewayOpenFrame {
        protocol_version: GATEWAY_SESSION_PROTOCOL_VERSION.to_owned(),
        transport_kind: config.transport_kind.wire_name().to_owned(),
        client_instance_id: config.client_instance_id.clone(),
        device_id: config.device_id.clone(),
        target_delivery_id: config.target_delivery_id.clone(),
        stream_nonce,
        previous_session_id: config.previous_session_id.clone(),
        resume_token_hash: config.resume_token.as_ref().map(|token| {
            ramflux_crypto::blake3_256_base64url(
                "ramflux.gateway.resume_token.v1",
                token.as_bytes(),
            )
        }),
        last_seen_inbox_seq: Some(config.last_seen_inbox_seq),
        max_inflight_downstream: config.max_inflight_downstream,
        max_inflight_upstream: config.max_inflight_upstream,
        pre_auth_cookie: config.pre_auth_cookie.clone(),
        pre_auth_now: config.pre_auth_now,
        source_ip_hash: config.source_ip_hash.clone(),
    }
}

pub(crate) fn gateway_auth_frame(
    config: &GatewaySessionConfig,
    open: &GatewayOpenFrame,
) -> Result<GatewayAuthFrame, SdkError> {
    let device_branch = config.device_branch.as_ref().ok_or_else(|| {
        SdkError::GatewaySessionRejected(format!(
            "missing registered device branch for {}",
            config.device_id
        ))
    })?;
    let mut device_proof = ramflux_protocol::DeviceProof {
        schema: "ramflux.device_proof.v1".to_owned(),
        version: 1,
        domain: "ramflux.device_proof.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_device_signed_fields(&config.device_id, ""),
        principal_id: config.principal_id.clone(),
        device_id: config.device_id.clone(),
        device_epoch: config.device_epoch,
        branch_proof_hash: config.branch_proof_hash.clone(),
        capability_scope: config.capability_scope.clone(),
        nonce: open.stream_nonce.clone(),
        expires_at: config.auth_expires_at,
    };
    device_proof.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        device_branch.as_ref(),
        &device_proof,
    )?;
    let device_proof_bytes = ramflux_protocol::canonical_json_bytes(&device_proof)?;
    let mut signed_request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_device_signed_fields(&config.device_id, ""),
        source_device_id: config.device_id.clone(),
        request_id: format!("req_sdk_auth_{}", open.stream_nonce),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/gateway/session/auth".to_owned(),
        device_proof_hash: ramflux_crypto::blake3_256_base64url(
            GATEWAY_DEVICE_PROOF_HASH_DOMAIN,
            &device_proof_bytes,
        ),
        body_hash: gateway_open_hash(open)?,
        nonce: open.stream_nonce.clone(),
        created_at: config.now,
        expires_at: config.auth_expires_at,
    };
    signed_request.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        device_branch.as_ref(),
        &signed_request,
    )?;
    Ok(GatewayAuthFrame { signed_request, device_proof })
}

pub(crate) fn gateway_open_hash(open: &GatewayOpenFrame) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(open)?;
    Ok(ramflux_crypto::blake3_256_base64url(GATEWAY_OPEN_HASH_DOMAIN, &bytes))
}

pub(crate) fn gateway_stream_nonce(config: &GatewaySessionConfig, counter: u64) -> String {
    let input = format!(
        "{}:{}:{}:{}:{}",
        config.client_instance_id, config.device_id, config.target_delivery_id, config.now, counter
    );
    ramflux_crypto::blake3_256_base64url(GATEWAY_NONCE_DOMAIN, input.as_bytes())
}

fn gateway_fresh_stream_nonce() -> Result<String, SdkError> {
    let random = ramflux_crypto::random_32()?;
    Ok(ramflux_crypto::blake3_256_base64url(GATEWAY_NONCE_DOMAIN, &random))
}

pub(crate) fn sdk_signed_fields(signature: &str) -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: "fixture".to_owned(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: signature.to_owned(),
    }
}

pub(crate) fn sdk_device_signed_fields(
    device_id: &str,
    signature: &str,
) -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: format!("device:{device_id}"),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: signature.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_resume_auth_attempts_use_fresh_replay_keys() -> Result<(), SdkError> {
        let mut config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse().map_err(|err| {
                SdkError::GatewaySessionRejected(format!("test bind addr parse failed: {err}"))
            })?,
            gateway_addr: "127.0.0.1:443".parse().map_err(|err| {
                SdkError::GatewaySessionRejected(format!("test gateway addr parse failed: {err}"))
            })?,
            server_name: "localhost".to_owned(),
            ca_cert: PathBuf::from("test-ca.pem"),
            principal_id: "principal_test".to_owned(),
            device_id: "device_test".to_owned(),
            target_delivery_id: "target_test".to_owned(),
            prekey_http_url: None,
        })
        .with_device_branch(ramflux_crypto::create_device_branch(
            "principal_test",
            "device_test",
            1,
            [7_u8; 32],
        ));
        config.previous_session_id = Some("session_previous".to_owned());
        config.resume_token = Some("resume_previous".to_owned());

        let first_open = gateway_fresh_open_frame(&config)?;
        let first_auth = gateway_auth_frame(&config, &first_open)?;
        let second_open = gateway_fresh_open_frame(&config)?;
        let second_auth = gateway_auth_frame(&config, &second_open)?;

        assert_ne!(first_open.stream_nonce, second_open.stream_nonce);
        assert_ne!(first_auth.signed_request.request_id, second_auth.signed_request.request_id);
        assert_ne!(
            first_auth.signed_request.replay_tuple_key(),
            second_auth.signed_request.replay_tuple_key()
        );
        assert_eq!(
            first_auth.signed_request.replay_tuple_key(),
            first_auth.signed_request.replay_tuple_key()
        );
        Ok(())
    }
}
