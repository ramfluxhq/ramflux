// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registration preserves signed v2 authority across gateway ingress and the real mTLS hop.
use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
use crate::{RouterMeshClient, quic_dispatch::dispatch_quic_json_request};
use ramflux_crypto::{BranchAuthorization, DeviceSetSigningInput, X25519KeyPair};
use ramflux_node_core::{IdentityRegisterRequest, RouterCore, RouterRedbStore};
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry, encode_base64url};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn registration(now: i64) -> Result<IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("peer", [31; 32]);
    let branch = ramflux_crypto::create_device_branch("peer", "device", 1, [32; 32]);
    let agreement = X25519KeyPair::from_seed([33; 32]);
    let branch_public_key = encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let keys = ramflux_crypto::device_key_commitments(
        &branch_public_key,
        &encode_base64url(agreement.public),
    )?;
    let proof = ramflux_crypto::authorize_device_branch_v2(
        &root,
        &branch,
        BranchAuthorization {
            audience: ramflux_node_core::IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.into()],
            issued_at: now,
            expires_at: now + 3600,
            principal_kind: PrincipalKind::Human,
            agreement_identity_public_key: agreement.public,
        },
    )?;
    let set = ramflux_crypto::sign_device_set(
        &root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![SignedDeviceSetEntry {
                device_id: "device".into(),
                device_epoch: 1,
                signing_key_commitment: keys.0,
                agreement_key_commitment: keys.1,
                status: DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    Ok(IdentityRegisterRequest {
        root_public_key: encode_base64url(root.signing_key.verifying_key().to_bytes()),
        principal_commitment: ramflux_crypto::identity_root_commitment(
            &root.signing_key.verifying_key(),
        ),
        branch_public_key,
        proof,
        device_set: Some(set),
        target_delivery_id: "delivery".into(),
        gateway_id: "gateway-b".into(),
        session_id: "session-b".into(),
        push_alias_hash: None,
        now,
        registration_pow: None,
        source_ip_hash: Some("caller-claim".into()),
    })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_registration_survives_gateway_forwarding_and_bad_signature_does_not_burn_proof()
-> TestResult {
    let directory = temp_cert_root("registration-forward")?;
    let gateway = issue_test_ca_and_service_cert(&directory, "mesh", "ramflux-gateway")?;
    let router = issue_test_ca_and_service_cert(&directory, "mesh", "ramflux-router")?;
    let mut client_tls = gateway.tls.clone();
    client_tls.ca_cert = router.tls.ca_cert.clone();
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router.tls)?;
    let endpoint = server.local_addr()?.to_string();
    let state = Arc::new(RouterCore::new());
    let store = Arc::new(RouterRedbStore::open(directory.join("router.redb"))?);
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let honest = registration(now - 7200)?;
    let renewed = registration(now)?;
    let expected_proof = honest.proof.clone();
    let source = Arc::clone(&state);
    let durable = Arc::clone(&store);
    let worker = std::thread::spawn(move || -> Result<(), String> {
        for index in 0..5 {
            let mut stream = server
                .accept_authenticated_with_pem_roots(
                    &router.tls,
                    std::slice::from_ref(&gateway.ca_pem),
                )
                .map_err(|e| e.to_string())?
                .stream;
            let request = ramflux_transport::read_mesh_http_request(&mut stream)
                .map_err(|e| e.to_string())?
                .ok_or("request")?;
            if request.path != "/mvp1/identity/register" {
                return Err(format!("unexpected path {}", request.path));
            }
            let mut forwarded: IdentityRegisterRequest =
                ramflux_protocol::parse_i_json(&request.body).map_err(|e| e.to_string())?;
            if forwarded.proof.key_binding != expected_proof.key_binding {
                return Err("forwarding dropped v2 key binding".into());
            }
            if forwarded.source_ip_hash.as_deref() == Some("caller-claim") {
                return Err("forwarding trusted caller source".into());
            }
            forwarded.now = if index < 2 { now - 7200 } else { now };
            let response = match source.register_identity_durable(&forwarded, &durable) {
                Ok(response) => serde_json::to_value(response).map_err(|e| e.to_string())?,
                Err(_) => serde_json::json!(ramflux_protocol::IdentityRegistrationFailure {
                    error: ramflux_protocol::IdentityRegistrationFailureBody {
                        reason_code: ramflux_protocol::IdentityDirectoryReason::InvalidRegistration
                    }
                }),
            };
            ramflux_transport::write_mesh_json_response(&mut stream, "200 OK", &response)
                .map_err(|e| e.to_string())?;
            ramflux_transport::close_mesh_server_stream(&mut stream).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let client = RouterMeshClient {
        endpoint,
        server_name: "ramflux-router".into(),
        tls: client_tls,
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: None,
    };
    let send=|registration:&IdentityRegisterRequest| -> Result<ramflux_transport::GatewayQuicRequest,Box<dyn std::error::Error>> {
        let wire=serde_json::to_vec(&serde_json::json!({"method":"POST","path":"/mvp1/identity/register","body":registration}))?;
        let crate::ingress::Ingress::Request(request)=crate::ingress::parse(&wire,"127.0.0.1".parse()?)? else {return Err("wrong ingress".into());};
        Ok(request)
    };
    let mut bad = honest.clone();
    bad.proof.signature = encode_base64url([0; 64]);
    let rejected = dispatch_quic_json_request(&client, send(&bad)?, "127.0.0.1".parse()?).await?;
    assert_eq!(rejected.status, 409);
    assert_eq!(rejected.body["error"]["reason_code"], "invalid_registration");
    assert_eq!(store.identity_registry_write_count(), 0);
    let accepted =
        dispatch_quic_json_request(&client, send(&honest)?, "127.0.0.1".parse()?).await?;
    assert_eq!(accepted.status, 200);
    assert_eq!(accepted.body["session_bound"], true);
    assert_eq!(store.identity_registry_write_count(), 1);
    let mut live = state.session("delivery").ok_or("registered session")?;
    live.session_id = "live-session".into();
    live.gateway_id = "live-gateway".into();
    live.session_seq = 9;
    live.last_cursor = Some("cursor-8".into());
    state.upsert_session(live.clone())?;
    let response =
        dispatch_quic_json_request(&client, send(&renewed)?, "127.0.0.1".parse()?).await?;
    assert_eq!(response.status, 200);
    assert_eq!(state.session("delivery"), Some(live));
    for replay in [&honest, &renewed] {
        let response =
            dispatch_quic_json_request(&client, send(replay)?, "127.0.0.1".parse()?).await?;
        assert_eq!(response.status, 409);
    }
    worker.join().map_err(|_| "router worker panicked")?.map_err(std::io::Error::other)?;
    drop(store);
    drop(state);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
