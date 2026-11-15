// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native home-relay proof fixture using real TLS exporters and signed proxy receipts.
use ramflux_crypto::custody::*;
use ramflux_protocol::custody::*;
use std::sync::Arc;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) fn node(now: u64) -> super::TestResult<VerifiedNodeRecord> {
    let key = ramflux_crypto::fixture_signing_key();
    let proxy = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let record = sign_node_identity_record(
        &key,
        NodeIdentityRecord {
            schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: "node".into(),
            node_signing_public_key: ramflux_crypto::fixture_public_key_base64url(),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: now,
            receipt_keys: Vec::new(),
            revoked_receipt_key_ids: Vec::new(),
            proxy_keys: vec![ProxyKey {
                key_id: ramflux_protocol::encode_base64url([10; 32]),
                public_key: ramflux_protocol::encode_base64url(proxy.verifying_key().to_bytes()),
                not_before: now.saturating_sub(1),
                sign_until: now + 3600,
                overlap_until: now + 606_000,
                status: ReceiptKeyStatus::Active,
                proxy_id: "gateway".into(),
                audiences: vec!["node".into()],
            }],
            revoked_proxy_key_ids: Vec::new(),
            channel_binding_modes: vec![BindingMode::HomeRelayReceipt],
        },
    )?;
    Ok(verify_node_identity_record(
        &record,
        "node",
        &ramflux_crypto::fixture_public_key_base64url(),
        now,
    )?)
}

pub(super) async fn serve(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    router: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    service: Arc<ramflux_node_core::CustodyService>,
    node: VerifiedNodeRecord,
) -> TestResult {
    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
    let connection_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    // A revoke proof consists only of open, challenge, prove, and optional discovery.
    for _ in 0..8 {
        let bytes = ramflux_transport::read_custody_tcp_frame(&mut stream).await?;
        let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let now = crate::custody::network_now()?;
        let request = match frame {
            CustodyClientFrame::CustodyOpen { binding_mode } => {
                assert_eq!(
                    binding_mode,
                    BindingMode::HomeRelayReceipt,
                    "test: production revoke changed binding mode"
                );
                CustodyMeshRequest::NodeIdentity { record_hash: None }
            }
            CustodyClientFrame::NodeIdentity { record_hash } => {
                CustodyMeshRequest::NodeIdentity { record_hash }
            }
            CustodyClientFrame::Challenge { device_ref, action } => CustodyMeshRequest::Challenge {
                device_ref,
                action,
                binding_mode: BindingMode::HomeRelayReceipt,
                client_source: "127.0.0.1".into(),
                connection_id: connection_id.clone(),
            },
            CustodyClientFrame::Prove { action, proof } => {
                let nonce: [u8; 32] =
                    ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                        .try_into()
                        .map_err(|_| "test: nonce")?;
                let exporter = ramflux_transport::custody_tcp_exporter(&stream, &nonce)?;
                let receipt = sign_proxy_acceptance(
                    &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                    &node,
                    &proof,
                    &branch_exporter_hash(&exporter),
                    ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                    now,
                )?;
                CustodyMeshRequest::Prove {
                    action,
                    proof,
                    receipt: Some(Box::new(receipt)),
                    connection_id: connection_id.clone(),
                }
            }
            _ => return Err("test: unexpected native revoke frame".into()),
        };
        let response = service.mesh(&router, &store, request, "ramflux-gateway", now);
        let published = matches!(response, CustodyServerFrame::Published { .. });
        ramflux_transport::write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?)
            .await?;
        if published {
            return Ok(());
        }
    }
    Err("test: native revoke exceeded frame bound".into())
}
