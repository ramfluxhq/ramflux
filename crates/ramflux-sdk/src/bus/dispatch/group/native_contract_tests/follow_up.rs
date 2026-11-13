// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public receive APIs preserve bare fetch errors while inbound scheduling retains context.
use super::*;

#[tokio::test]
async fn public_receivers_preserve_bare_directory_errors_and_log_kind() -> TestResult {
    let (mut alice, _bob, entry) = Box::pin(renamed_group_fixture()).await?;
    *alice.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let cert = rcgen::generate_simple_self_signed(vec!["directory.test".into()])?;
    alice.config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    alice.config.gateway_addr = address;
    alice.config.tcp_gateway_addr = Some(address);
    alice.config.server_name = "directory.test".into();
    alice.config.ca_cert = alice.root.0.join("directory.pem");
    std::fs::write(&alice.config.ca_cert, cert.cert.pem())?;
    let pool = crate::bus::state::LocalBusAccountState::disconnected(
        crate::RamfluxClient::new(),
        alice.config.clone(),
        alice.manifest.principal_commitment.clone(),
    )
    .relay_quic_pool()?;
    for control in [false, true] {
        let mut gateway = crate::bus::dispatch::surface_transport::fixture::RecordingGateway::new(
            std::sync::Arc::default(),
        );
        gateway.inbox = vec![entry.clone()];
        let mut engine =
            GatewaySessionEngine::with_test_transport(alice.config.clone(), Box::new(gateway));
        let error = if control {
            alice.client.receive_a2i_control_events(&mut engine, 32).await.err()
        } else {
            alice
                .client
                .receive_gateway_plaintext_deliveries(&mut engine, &pool, 32, "thread", false, None)
                .await
                .err()
        }
        .ok_or("directory outage must fail")?;
        if control {
            assert!(
                matches!(
                    error,
                    SdkError::GeneratedRefused {
                        code: crate::error::GeneratedRefusalCode::Authority,
                        ..
                    }
                ),
                "A2I must refuse before fetching a directory: {error:?}"
            );
        } else {
            assert!(
                matches!(error, SdkError::Transport(_)),
                "public receiver must preserve bare transport error: {error:?}"
            );
        }
    }
    let pending = SdkError::DirectoryAuthorityUnavailable {
        root: "peer".into(),
        source: Box::new(SdkError::InboundPending("refresh".into())),
    };
    assert_eq!(crate::bus::sync_driver::inbound_failure_kind(&pending), "InboundPending");
    Ok(())
}
