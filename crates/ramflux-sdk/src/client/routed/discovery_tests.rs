// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-contact Root hints are lookup context, never an alternative trust anchor.
use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn first_contact_fetches_only_the_hinted_root_manifest_and_verifies_the_chain() -> TestResult
{
    let sender = Fixture::new("alice", 91)?;
    let staging = Fixture::new("bob", 101)?;
    let receiver = Fixture::new("bob", 101)?;
    let entry = seal(&sender, &staging, message("first-root-hint", "new-thread"), b"hello")?;
    let mut malformed = entry.clone();
    let mut wrapper = decode(&malformed.envelope)?;
    wrapper.source_principal_commitment = Some("../../admin".into());
    malformed.envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(serde_json::to_vec(&wrapper)?);
    assert!(matches!(receiver.client.ensure_inbound_device(&receiver.config()?, &malformed).await,
        Err(SdkError::InboundRejected(reason)) if reason.ends_with("invalid sender root hint")));
    let manifest = crate::client::identity_authority::test_support::manifest(&sender.client)?;
    assert!(receiver.client.ensure_inbound_device(&receiver.config()?, &entry).await.is_err());
    assert!(receiver.client.account_db()?.client_record("device", "alice")?.is_none());
    receiver.client.establish_friend_link(
        "accepted-root",
        "bob",
        &manifest.principal_commitment,
    )?;
    let expected_path = format!("/mvp1/device-manifest/{}", manifest.principal_commitment);
    assert_eq!(
        decode(&entry.envelope)?.source_principal_commitment.as_deref(),
        Some(manifest.principal_commitment.as_str())
    );
    assert!(receiver.client.account_db()?.client_record("device", "alice")?.is_none());
    let certified = rcgen::generate_simple_self_signed(vec!["discovery.test".into()])?;
    let ca = receiver.root.join("ca.pem");
    std::fs::write(&ca, certified.cert.pem())?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    )?;
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (socket, _) =
                tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
            let mut stream =
                tokio_rustls::TlsAcceptor::from(Arc::clone(&config)).accept(socket).await?;
            let len = stream.read_u32().await?;
            if len > 65536 {
                return Err(std::io::Error::other("oversized request"));
            }
            let mut bytes = vec![0; len as usize];
            stream.read_exact(&mut bytes).await?;
            let request: ramflux_transport::GatewayQuicRequest = serde_json::from_slice(&bytes)?;
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, expected_path);
            let bytes = serde_json::to_vec(&ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(&manifest)?,
            })?;
            stream.write_u32(u32::try_from(bytes.len()).map_err(std::io::Error::other)?).await?;
            stream.write_all(&bytes).await?;
            stream.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let gateway = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: address,
        server_name: "discovery.test".into(),
        ca_cert: ca,
        principal_id: "bob".into(),
        device_id: "bob".into(),
        target_delivery_id: "bob".into(),
        prekey_http_url: None,
    });
    let mut unsigned = entry.clone();
    unsigned.envelope.signed.signature = "invalid".into();
    assert!(receiver.client.ensure_inbound_device(&gateway, &unsigned).await.is_err());
    assert!(receiver.client.account_db()?.client_record("device", "alice")?.is_none());
    assert!(receiver.client.account_db()?.client_record("identity", "alice")?.is_none());
    receiver.client.ensure_inbound_device(&gateway, &entry).await?;
    server.await??;
    let opened = receiver.client.open_routed(&entry, "bob")?;
    assert_eq!(&*opened.body, b"hello");
    Ok(())
}

#[test]
fn signed_root_hint_cannot_override_an_existing_verified_owner() -> TestResult {
    let sender = Fixture::new("alice", 111)?;
    let receiver = Fixture::new("bob", 121)?;
    let mut entry = seal(&sender, &receiver, message("wrong-root-hint", "thread"), b"hello")?;
    receiver.client.authenticated_envelope_sender(&entry)?;
    let mut wrapper = decode(&entry.envelope)?;
    wrapper.source_principal_commitment = Some("different-root".into());
    entry.envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(serde_json::to_vec(&wrapper)?);
    entry.envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        entry.envelope.encrypted_payload.as_bytes(),
    );
    entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or("branch")?,
        &entry.envelope,
    )?;
    assert!(receiver.client.authenticated_envelope_sender(&entry).is_err());
    Ok(())
}

#[tokio::test]
async fn a_non_string_signed_root_hint_is_rejected_before_manifest_discovery() -> TestResult {
    let sender = Fixture::new("alice", 91)?;
    let receiver = Fixture::new("bob", 101)?;
    let mut entry = seal(&sender, &receiver, message("malformed-root-header", "thread"), b"body")?;
    entry.envelope.ext.ext.insert("source_root_commitment".into(), serde_json::json!(true));
    assert!(matches!(receiver.client.ensure_inbound_device(&receiver.config()?,&entry).await,
        Err(SdkError::InboundRejected(reason)) if reason.ends_with("invalid sender root hint")));
    Ok(())
}

#[test]
fn saved_group_root_selects_proof_material_but_never_authenticates_an_unproven_device() -> TestResult
{
    let sender = Fixture::new("alice", 81)?;
    let staging = Fixture::new("bob", 82)?;
    let receiver = Fixture::new("bob", 82)?;
    let entry = seal(&sender, &staging, message("group-proof", "group-thread"), b"body")?;
    let identity = sender.client.owned_device_identity()?;
    let public = ramflux_protocol::encode_base64url(
        sender
            .client
            .device_branch
            .as_ref()
            .ok_or("branch")?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    receiver.client.create_group("g", "bob")?;
    let db = receiver.client.account_db()?;
    db.add_group_member("g", "alice", "member")?;
    db.persist_group_member_device_key("g", &identity, &public)?;
    db.bind_group_member_key_identity(
        "g",
        &identity,
        "alice",
        identity.root_commitment(),
        &public,
    )?;
    assert!(receiver.client.device_identity_for_root(identity.root_commitment(), "alice").is_err());
    assert!(receiver.client.inbound_relationship_names_root(
        "alice",
        identity.root_commitment(),
        "alice"
    )?);
    assert!(!receiver.client.inbound_relationship_names_root(
        "mallory",
        identity.root_commitment(),
        "alice"
    )?);
    assert!(receiver.client.authenticated_device_identity(&entry).is_err());
    let manifest = crate::client::identity_authority::test_support::manifest(&sender.client)?;
    receiver.client.persist_root_verified_directory(&manifest)?;
    assert_eq!(receiver.client.authenticated_device_identity(&entry)?, identity);
    let mut forged = entry;
    forged.envelope.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(receiver.client.authenticated_device_identity(&forged).is_err());
    Ok(())
}
