// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production device.revoke through an authenticated loopback TLS control endpoint.
use super::r5::settle;
use super::*;
use crate::bus::protocol::{
    LocalBusAccountCreateRequest, LocalBusClientMode, LocalBusFrame, LocalBusPersistedAccount,
};
use crate::bus::state::{LocalBusAccountState, LocalBusDaemonState};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
async fn revoke_endpoint(
    root: &std::path::Path,
    expected_root: String,
    old: ramflux_protocol::SignedDeviceSetRecord,
) -> Result<(GatewayQuicEndpointConfig, tokio::task::JoinHandle<Result<(), SdkError>>), SdkError> {
    let certified = rcgen::generate_simple_self_signed(vec!["revoke.test".to_owned()])
        .map_err(|error| invalid(&error.to_string()))?;
    let ca = root.join("revoke-ca.pem");
    std::fs::write(&ca, certified.cert.pem())?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        )
        .map_err(|error| invalid(&error.to_string()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        for index in 0..2 {
            let (socket, _) = listener.accept().await?;
            let mut stream = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls.clone()))
                .accept(socket)
                .await?;
            let length = stream.read_u32().await?;
            if length > 65536 {
                return Err(invalid("unexpected revoke request size"));
            }
            let mut bytes = vec![0; usize::try_from(length).map_err(|_| invalid("length"))?];
            stream.read_exact(&mut bytes).await?;
            let request: ramflux_transport::GatewayQuicRequest = serde_json::from_slice(&bytes)?;
            let body = if index == 0 {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, format!("/mvp2/device-set/{}", old.principal_commitment));
                serde_json::to_value(&old)?
            } else {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/mvp2/device-set");
                assert_eq!(request.body["root_public_key"], expected_root);
                let next: ramflux_protocol::SignedDeviceSetRecord =
                    serde_json::from_value(request.body["record"].clone())?;
                ramflux_crypto::verify_signed_device_set(
                    &ramflux_crypto::verifying_key_from_base64url(&expected_root)?,
                    &next,
                )?;
                ramflux_crypto::validate_device_set_transition(&old, &next)?;
                serde_json::to_value(next)?
            };
            let response =
                serde_json::to_vec(&ramflux_transport::GatewayQuicResponse { status: 200, body })?;
            stream
                .write_u32(u32::try_from(response.len()).map_err(|_| invalid("response"))?)
                .await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
        }
        Ok(())
    });
    Ok((
        GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| invalid("address"))?,
            gateway_addr: address,
            server_name: "revoke.test".into(),
            ca_cert: ca,
            principal_id: "bob".into(),
            device_id: "bob".into(),
            target_delivery_id: "bob".into(),
            prekey_http_url: None,
        },
        server,
    ))
}
async fn revoked_fixture(target: &str) -> Result<(Fixture, Fixture), SdkError> {
    let mut alice = Fixture::owned("alice", "bob", 61, 42)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    assert!(bob.client.begin_pair_recovery(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&alice.reference()?)?,
        now_unix_timestamp()
    )?);
    let public = ramflux_crypto::public_key_base64url_from_seed([61; 32]);
    let commitment = crate::prekey::identity_root_public_key_commitment(&public)?;
    let old =
        bob.client.observed_device_set(&commitment)?.ok_or_else(|| invalid("own signed set"))?;
    let (gateway, server) = revoke_endpoint(&bob.root, public, old).await?;
    let body = LocalBusAccountCreateRequest {
        label: None,
        kind: None,
        node_id: None,
        local_account_id: "bob".into(),
        principal_id: "bob".into(),
        principal_commitment: commitment.clone(),
        device_id: "bob".into(),
        target_delivery_id: "bob".into(),
        account_secret: "routed-test".into(),
        root_seed: [61; 32],
        device_seed: [62; 32],
        client_mode: LocalBusClientMode::AttendedCli,
        gateway: gateway.clone(),
    };
    let mut manifest = LocalBusPersistedAccount::from_create_request(&body);
    let mut peer = manifest.devices[0].clone();
    peer.device_id = "alice".into();
    peer.is_local = false;
    manifest.devices.push(peer);
    crate::bus::daemon::write_local_bus_account_manifest(&bob.root, &manifest)?;
    let account = LocalBusAccountState::disconnected(
        std::mem::take(&mut bob.client),
        GatewaySessionConfig::auto(gateway),
        commitment,
    );
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: crate::bus::LocalBusConfig::new(bob.root.join("rfd.sock"), &bob.root),
        accounts: BTreeMap::from([("bob".into(), account)]),
        active_account_id: Some("bob".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let request = LocalBusFrame::request(
        "revoke",
        Some("bob".into()),
        "device",
        "device.revoke",
        json!({"device_id":target}),
    );
    let response =
        crate::bus::dispatch::device::dispatch_device_bus_request(&request, &mut state).await?;
    assert_eq!(response.response_body["revoked"], true);
    server.await.map_err(|error| invalid(&error.to_string()))??;
    bob.client = std::mem::take(
        &mut state.accounts.get_mut("bob").ok_or_else(|| invalid("account"))?.client,
    );
    Ok((alice, bob))
}
#[tokio::test]
async fn revoking_an_own_device_via_the_production_method_erases_pair_work_and_rejects_stale_cache()
-> Result<(), SdkError> {
    let (alice, bob) = Box::pin(revoked_fixture("alice")).await?;
    let work = format!(
        "dm-pair/reset-work/{}",
        RamfluxClient::pair_key(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&alice.reference()?)?
        )?
    );
    assert!(bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work)?.is_none());
    assert!(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&alice.reference()?)?
            )?
            .is_none()
    );
    assert_eq!(
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?.len(),
        0
    );
    assert!(super::review::trust(&bob, &alice).is_err());
    assert!(matches!(
        bob.client.trusted_device(&alice.reference()?),
        Err(SdkError::InboundRejected(_))
    ));
    Ok(())
}

#[tokio::test]
async fn revoking_the_current_device_clears_all_pairs_and_fences_pair_traffic()
-> Result<(), SdkError> {
    let (alice, mut bob) = Box::pin(revoked_fixture("bob")).await?;
    assert_eq!(
        bob.client
            .account_db()?
            .list_actor_states::<serde_json::Value>("dm-pair/reset-work/")?
            .len(),
        0
    );
    assert_eq!(
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?.len(),
        0
    );
    let (mut be, sent) = super::session_record::Wire::engine(&bob, &alice)?;
    let incoming = seal(
        &alice,
        &bob,
        super::r5::outgoing(&alice, &bob, "revoked-local-incoming"),
        b"old traffic",
    )?;
    assert!(
        bob.client
            .apply_routed_entry(&mut be, &super::review::pool()?, &incoming, false)
            .await
            .is_err()
    );
    assert!(
        bob.client
            .send_plaintext_direct_message_via_gateway(
                &mut be,
                super::r5::outgoing(&bob, &alice, "revoked-local-outgoing"),
                b"do not send"
            )
            .await
            .is_err()
    );
    bob.client.retry_pair_resets(&mut be, now_unix_timestamp() + 86400).await?;
    assert!(sent.lock().map_err(|_| invalid("mutex"))?.is_empty());
    assert_eq!(
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?.len(),
        0
    );
    Ok(())
}
