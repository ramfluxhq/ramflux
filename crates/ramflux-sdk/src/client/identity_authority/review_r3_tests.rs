// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-name foreign devices cannot block own revocation or retain retired sibling secrets.
use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn tls_own_revocation_ignores_a_friends_same_name_and_retires_qualified_sessions()
-> TestResult {
    let owner = Actor::new("alice", "one", 71, 72, 1)?;
    let sibling = Actor::new("alice", "two", 71, 73, 1)?;
    let friend = Actor::new("mallory", "two", 81, 82, 1)?;
    let mut own = owner.manifest()?;
    own.devices.extend(sibling.manifest()?.devices);
    sign_set(&owner, &mut own, 2)?;
    let foreign = friend.manifest()?;
    observe(&owner.client, &own)?;
    observe(&owner.client, &foreign)?;
    owner.client.establish_friend_link("foreign-friend", "alice", "mallory")?;
    assert!(matches!(
        owner.client.account_db()?.client_record("device", "two"),
        Err(StorageError::AmbiguousDeviceId(_))
    ));
    let own_ref = ramflux_protocol::qualified_device_id(&own.principal_commitment, "two")?;
    let foreign_ref = ramflux_protocol::qualified_device_id(&foreign.principal_commitment, "two")?;
    let own_pair = ramflux_crypto::DmSession::initiator(
        [1; 32],
        dm_device_id_hash("one"),
        dm_device_id_hash("two"),
        [2; 32],
    )?;
    let foreign_pair = ramflux_crypto::DmSession::initiator(
        [3; 32],
        dm_device_id_hash("one"),
        dm_device_id_hash("two"),
        [4; 32],
    )?;
    owner.client.persist_pair("one", &own_ref, &[5; 32], &own_pair)?;
    owner.client.persist_pair("one", &foreign_ref, &[6; 32], &foreign_pair)?;
    assert_eq!(
        owner.client.account_db()?.pair_session_ids("one", &own_ref)?,
        vec![own_pair.session_id.clone()]
    );
    let (gateway, server) =
        publication_server(&owner.path, own.signed_device_set.ok_or("set")?).await?;
    let record = owner.client.revoke_owned_device(&gateway, "two").await?;
    server.await??;
    assert_eq!(record.device_set_epoch, 3);
    assert!(
        record.devices.iter().any(|d| d.device_id == "two" && d.status == DeviceSetStatus::Revoked)
    );
    assert_eq!(owner.client.account_db()?.pair_session_ids("one", &own_ref)?, Vec::<String>::new());
    assert!(
        !owner
            .client
            .account_db()?
            .actor_state_exists(&format!("dm-pair/session/{}", own_pair.session_id))?
    );
    assert!(owner.client.active_pair("one", &own_ref)?.is_none());
    assert_eq!(
        owner.client.active_pair("one", &foreign_ref)?.ok_or("foreign pair")?.0.session_id,
        foreign_pair.session_id
    );
    assert_eq!(
        owner
            .client
            .account_db()?
            .load_actor_state::<bool>(&owner.client.device_revocation_key(&own_ref)?)?,
        Some(true)
    );
    assert_eq!(
        owner
            .client
            .account_db()?
            .load_actor_state::<bool>(&owner.client.device_revocation_key(&foreign_ref)?)?,
        None
    );
    Ok(())
}
async fn publication_server(
    root: &Path,
    old: SignedDeviceSetRecord,
) -> Result<
    (GatewaySessionConfig, tokio::task::JoinHandle<Result<(), std::io::Error>>),
    Box<dyn std::error::Error>,
> {
    let certified = rcgen::generate_simple_self_signed(vec!["own-revoke.test".into()])?;
    let ca = root.join("revoke-ca.pem");
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        for index in 0..2 {
            let (socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await??;
            let mut stream =
                tokio_rustls::TlsAcceptor::from(Arc::new(config.clone())).accept(socket).await?;
            let len = stream.read_u32().await?;
            if len > 65536 {
                return Err(std::io::Error::other("test request too large"));
            }
            let mut bytes = vec![0; len as usize];
            stream.read_exact(&mut bytes).await?;
            let request: ramflux_transport::GatewayQuicRequest = serde_json::from_slice(&bytes)?;
            let body = if index == 0 {
                assert_eq!(request.method, "GET");
                serde_json::to_value(&old)?
            } else {
                assert_eq!(request.method, "POST");
                request.body["record"].clone()
            };
            let response =
                serde_json::to_vec(&ramflux_transport::GatewayQuicResponse { status: 200, body })?;
            stream.write_u32(u32::try_from(response.len()).map_err(std::io::Error::other)?).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
        }
        Ok(())
    });
    let gateway = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: address,
        server_name: "own-revoke.test".into(),
        ca_cert: ca,
        principal_id: "alice".into(),
        device_id: "one".into(),
        target_delivery_id: "one".into(),
        prekey_http_url: None,
    });
    Ok((gateway, server))
}

#[tokio::test]
async fn own_import_checks_pending_local_fences_even_when_the_node_still_reports_active()
-> TestResult {
    let source = Actor::new("alice", "one", 101, 102, 1)?;
    let target = Actor::new("alice", "two", 101, 103, 1)?;
    let mut manifest = source.manifest()?;
    manifest.devices.extend(target.manifest()?.devices);
    sign_set(&source, &mut manifest, 1)?;
    observe(&target.client, &manifest)?;
    let reference = ramflux_protocol::qualified_device_id(&manifest.principal_commitment, "one")?;
    target
        .client
        .account_db()?
        .persist_actor_state(&target.client.device_revocation_key(&reference)?, &true)?;
    let mut envelope = crate::client::own_device_sync::tests::envelope("one", "two");
    envelope.principal_commitment = manifest.principal_commitment.clone();
    envelope.created_at = now_unix_timestamp();
    envelope.expires_at = envelope.created_at + 3600;
    envelope.history_ref.key_slot.conversation_id =
        crate::own_device_sync::own_device_sync_slot_conversation_id(
            &envelope.snapshot_id,
            &envelope.history_ref.object_id,
            &envelope.target_device_id,
        );
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        source.client.device_branch.as_ref().ok_or("branch")?,
        &crate::own_device_sync::own_device_sync_signing_body(&envelope),
    )?;
    let (gateway, server) = super::gateway::manifest_server(&target.path, manifest.clone()).await?;
    let error = target
        .client
        .verify_own_device_sync_envelope(&gateway, &manifest.principal_commitment, &envelope)
        .await
        .err()
        .ok_or("pending revoked source was accepted")?;
    server.await??;
    assert!(error.to_string().contains("locally fenced"), "{error}");
    assert_eq!(
        target.client.account_db()?.client_directory_ids("object", "", 100)?,
        Vec::<String>::new()
    );
    Ok(())
}
#[test]
fn root_bound_enrollment_rejects_address_shaped_literal_device_names() -> TestResult {
    let root = ramflux_crypto::create_identity_root("alice", [111; 32]);
    for name in [
        "root~junk".to_owned(),
        "legacy~name".to_owned(),
        ramflux_protocol::qualified_device_id("root", "phone")?,
    ] {
        let branch = ramflux_crypto::create_device_branch("alice", &name, 1, [112; 32]);
        assert!(
            ramflux_crypto::authorize_device_branch_v2(
                &root,
                &branch,
                ramflux_crypto::BranchAuthorization {
                    audience: "ramflux-node",
                    capability_scope: vec!["device.delivery.bind".into()],
                    issued_at: 1,
                    expires_at: 3600,
                    principal_kind: PrincipalKind::Human,
                    agreement_identity_public_key: X25519KeyPair::from_seed([113; 32]).public
                }
            )
            .is_err()
        );
    }
    Ok(())
}
