// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A malformed directory response must not consume a legacy distribution's ratchet.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
async fn manifest_gateway(
    root: &std::path::Path,
    valid: serde_json::Value,
) -> Result<
    (
        std::net::SocketAddr,
        PathBuf,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<Result<(), SdkError>>,
    ),
    SdkError,
> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["lookup.test".into()])
        .map_err(|e| invalid(&e.to_string()))?;
    let ca = root.join("lookup.pem");
    std::fs::write(&ca, cert.cert.pem())?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
        .map_err(|e| invalid(&e.to_string()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        while let Ok((socket, _)) = listener.accept().await {
            let stream = tokio_rustls::TlsStream::Server(acceptor.accept(socket).await?);
            let (mut receive, mut send) = tokio::io::split(stream);
            let request: ramflux_transport::GatewayQuicRequest =
                ramflux_transport::read_gateway_session_json(&mut receive).await?;
            assert_eq!(request.method, "GET");
            assert!(request.path.starts_with("/mvp1/device-manifest/"));
            let first = observed.fetch_add(1, Ordering::SeqCst) == 0;
            ramflux_transport::write_gateway_session_json(
                &mut send,
                &ramflux_transport::GatewayQuicResponse {
                    status: 200,
                    body: if first { serde_json::json!({"malformed":true}) } else { valid.clone() },
                },
            )
            .await?;
        }
        Ok(())
    });
    Ok((address, ca, calls, server))
}
#[tokio::test]
async fn malformed_gateway_success_during_bootstrap_is_held_and_the_same_distribution_retries()
-> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    alice.client.create_group("bootstrap", "alice")?;
    alice.client.add_group_member("bootstrap", "bob", "member")?;
    let manifest = super::super::r9::manifest(&alice)?;
    let event = alice.client.create_signed_group_member_join_event(
        "bootstrap",
        "alice",
        "bob",
        "member",
        &manifest.principal_commitment,
    )?;
    let wrapper = SdkGroupSenderKeyDistributionEnvelope {
        schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".into(),
        version: 1,
        membership_event_base64: Some(ramflux_protocol::encode_base64url(serde_json::to_vec(
            &event,
        )?)),
        actor_manifest_url: None,
        distribution_base64: ramflux_protocol::encode_base64url(
            alice.client.export_group_sender_key_distribution("bootstrap", "alice")?,
        ),
    };
    let conversation = group_sender_key_distribution_conversation_id("bootstrap", "alice", "bob");
    let msg = message("bootstrap-distribution", &conversation);
    let bundle = bob.client.load_x3dh_private_state("bob")?.bundle;
    let (mut session, x3dh) =
        alice.client.create_send_dm_session_from_bundle(&msg, "bob", bundle, "alice")?;
    let encrypted = SdkDmEncryptedEnvelope {
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
        version: 1,
        x3dh,
        ciphertext: session
            .encrypt(&serde_json::to_vec(&wrapper)?, dm_associated_data(&conversation))?,
    };
    let entry = packet(&alice, serde_json::to_vec(&encrypted)?, "bootstrap-distribution")?;
    let (address, ca, calls, server) =
        manifest_gateway(&bob.root, serde_json::to_value(manifest)?).await?;
    let mut config = bob.config()?;
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "lookup.test".into();
    config.ca_cert = ca;
    let result = bob
        .client
        .append_group_gateway_delivery_for_recipient_with_gateway(
            &config,
            "bootstrap-thread",
            "bootstrap",
            "bootstrap-distribution",
            &entry,
            "bob",
        )
        .await;
    assert!(matches!(&result, Err(SdkError::InboundPending(_))));
    assert!(matches!(
        bob.client.isolate_legacy_group_delivery(&entry, result)?,
        crate::client::group_quarantine::LegacyGroupDelivery::Held
    ));
    assert!(bob.client.load_dm_session(&conversation, "recv").is_err());
    assert!(bob.client.group_state("bootstrap").is_err());
    assert!(
        !bob.client
            .account_db()?
            .journal_after(0, 100)?
            .iter()
            .any(|e| e.topic == "message.undeliverable")
    );
    let result = bob
        .client
        .append_group_gateway_delivery_for_recipient_with_gateway(
            &config,
            "bootstrap-thread",
            "bootstrap",
            "bootstrap-distribution",
            &entry,
            "bob",
        )
        .await?;
    assert!(matches!(result, GroupGatewayDeliveryResult::SenderKeyDistribution(_)));
    assert!(bob.client.load_dm_session(&conversation, "recv").is_ok());
    assert_eq!(bob.client.group_state("bootstrap")?.group_epoch, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
    let _ = server.await;
    Ok(())
}
