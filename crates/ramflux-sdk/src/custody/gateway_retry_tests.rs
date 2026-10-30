// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary gateway sessions share bounded native retries over real proxy-bound TLS.
use super::*;
use crate::{GatewayClientFrame, GatewayServerFrame, GatewaySessionEstablishedFrame};
use ramflux_crypto::custody::{
    VerifiedNodeRecord, sign_node_identity_record, sign_proxy_acceptance,
};

pub(super) fn node(original: &VerifiedNodeRecord, now: u64) -> Result<VerifiedNodeRecord> {
    let proxy = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let mut body = original.envelope().body.clone();
    body.channel_binding_modes = vec![BindingMode::HomeRelayReceipt];
    body.proxy_keys = vec![ProxyKey {
        key_id: ramflux_protocol::encode_base64url([79; 32]),
        public_key: ramflux_protocol::encode_base64url(proxy.verifying_key().to_bytes()),
        not_before: now - 1,
        sign_until: now + 600,
        overlap_until: now + 605_400,
        status: ReceiptKeyStatus::Active,
        proxy_id: "ramflux-gateway".into(),
        audiences: vec!["node".into()],
    }];
    let record = sign_node_identity_record(&ramflux_crypto::fixture_signing_key(), body)?;
    Ok(ramflux_crypto::custody::verify_node_identity_record(
        &record,
        "node",
        &ramflux_crypto::fixture_public_key_base64url(),
        now,
    )?)
}

pub(super) async fn public_lookup(
    bytes: &[u8],
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
) -> Result<bool> {
    let Ok(request) = serde_json::from_slice::<ramflux_transport::GatewayQuicRequest>(bytes) else {
        return Ok(false);
    };
    assert_eq!(request.method, "GET");
    assert!(request.path.starts_with("/mvp1/device-manifest/"));
    ramflux_transport::write_gateway_session_json(
        stream,
        &ramflux_transport::GatewayQuicResponse { status: 200, body: serde_json::Value::Null },
    )
    .await?;
    Ok(true)
}

pub(super) fn dispatch(
    context: &Context,
    stream: &ramflux_transport::GatewayTcpTlsStream,
    connection: &str,
    frame: CustodyClientFrame,
) -> Result<CustodyServerFrame> {
    let now = crate::custody::network_now()?;
    let request = match frame {
        CustodyClientFrame::CustodyOpen { binding_mode } => {
            assert_eq!(binding_mode, BindingMode::HomeRelayReceipt);
            let CustodyServerFrame::NodeIdentity { record, audience, .. } = context.service.mesh(
                &context.router,
                &context.store,
                CustodyMeshRequest::NodeIdentity { record_hash: None },
                "ramflux-gateway",
                now,
            ) else {
                return Err("missing node identity".into());
            };
            return Ok(CustodyServerFrame::NodeIdentity {
                record,
                audience,
                binding_mode,
                proxy_key_custody: Some("software".into()),
            });
        }
        CustodyClientFrame::Challenge { device_ref, action } => CustodyMeshRequest::Challenge {
            device_ref,
            action,
            binding_mode: BindingMode::HomeRelayReceipt,
            client_source: "127.0.0.1".into(),
            connection_id: connection.into(),
        },
        CustodyClientFrame::Prove { action, proof } => {
            let nonce = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                .try_into()
                .map_err(|_| "nonce")?;
            let material = ramflux_transport::custody_tcp_exporter(stream, &nonce)?;
            let observed = ramflux_crypto::custody::branch_exporter_hash(&material);
            assert_eq!(proof.body.transport_binding, observed);
            let receipt = sign_proxy_acceptance(
                &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                context.node.as_ref().ok_or("proxy node")?,
                &proof,
                &observed,
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                now,
            )?;
            CustodyMeshRequest::Prove {
                action,
                proof,
                receipt: Some(Box::new(receipt)),
                connection_id: connection.into(),
            }
        }
        _ => return Err("unexpected native frame".into()),
    };
    Ok(context.service.mesh(&context.router, &context.store, request, "ramflux-gateway", now))
}

pub(super) async fn ordinary(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    session: &str,
) -> Result {
    let open: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    let GatewayClientFrame::Open { open } = open else { return Err("ordinary open".into()) };
    assert_eq!(open.device_id, "primary");
    let auth: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    assert!(matches!(auth, GatewayClientFrame::Auth { .. }));
    ramflux_transport::write_gateway_session_json(
        stream,
        &GatewayServerFrame::SessionEstablished {
            session: GatewaySessionEstablishedFrame {
                session_id: session.into(),
                gateway_id: "ordinary-test".into(),
                accepted_cursor: None,
                resume_token: "test-resume".into(),
                resume_window_seconds: 60,
            },
        },
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn ordinary_native_gateway_busy_retries_outlive_the_legacy_timeout_with_fresh_proofs()
-> Result {
    tokio::time::timeout(Duration::from_secs(120), async {
        let points = [
            Point::Open,
            Point::Open,
            Point::Open,
            Point::Open,
            Point::Open,
            Point::RegisterChallenge,
            Point::RegisterProve,
        ];
        let fixture = Fixture::with_mode(&points, true).await?;
        let network = &fixture.config;
        let account = crate::custody::load_account(
            &network.account_root,
            &network.account_id,
            crate::custody::network_now()?,
        )?;
        let endpoint = crate::GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: network.gateway_address,
            server_name: network.server_name.clone(),
            ca_cert: network.ca_certificate.clone(),
            principal_id: account.record().body.principal_id.clone(),
            device_id: "primary".into(),
            target_delivery_id: ramflux_protocol::qualified_device_id(
                &account.record().body.account_anchor,
                "primary",
            )?,
            prekey_http_url: None,
        };
        let mut config = crate::GatewaySessionConfig::auto(endpoint).with_native_custody(
            crate::GatewayCustodyConfig {
                account_root: network.account_root.clone(),
                account_id: network.account_id.clone(),
                node_id: network.node_id.clone(),
                node_public_key: network.node_public_key.clone(),
                vault: fixture.vault.clone(),
            },
        );
        config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
        config.tcp_gateway_addr = Some(network.gateway_address);
        let started = std::time::Instant::now();
        let engine = crate::GatewaySessionEngine::connect(config).await?;
        assert!(started.elapsed() > Duration::from_secs(15));
        assert!(started.elapsed() <= Duration::from_secs(90));
        assert_eq!(engine.active_transport_kind(), crate::GatewaySessionTransportKind::TcpTls);
        assert_eq!(engine.session().gateway_id, "ordinary-test");
        assert_eq!(
            crate::custody::load_account(
                &network.account_root,
                &network.account_id,
                crate::custody::network_now()?,
            )?
            .state(),
            crate::custody::CreationState::Live
        );
        let script = fixture.script.lock().map_err(|_| "script lock")?;
        assert_eq!(script.busy_at, points);
        assert_eq!(script.accepted, 9);
        assert_eq!(script.publish_proofs, 1);
        assert_eq!(script.proofs.len(), 4);
        for column in 0..3 {
            let unique: std::collections::BTreeSet<_> = script
                .proofs
                .iter()
                .map(|proof| match column {
                    0 => &proof.0,
                    1 => &proof.1,
                    _ => &proof.2,
                })
                .collect();
            assert_eq!(unique.len(), script.proofs.len());
        }
        fixture.server.abort();
        Ok(())
    })
    .await?
}

#[tokio::test(start_paused = true)]
async fn legacy_connection_deadline_stays_fifteen_seconds() {
    let start = tokio::time::Instant::now();
    let legacy: std::result::Result<(), crate::SdkError> =
        crate::gateway::engine::gateway_connection_timeout(
            false,
            "legacy connect",
            std::future::pending(),
        )
        .await;
    assert!(matches!(legacy, Err(crate::SdkError::GatewaySessionRejected(_))));
    assert_eq!(start.elapsed(), Duration::from_secs(15));
}
