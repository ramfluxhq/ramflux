// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native custody handoff continues over the same authenticated transport into signed Open.
use super::*;
use crate::pre_auth_transport_tests::{
    auth_for,
    support::{Client, Fixture as Gateway, Route},
};
use ramflux_node_core::{GatewayOpenFrame, GatewayServerFrame};

pub(crate) async fn signed_handoff_matrix() -> Result {
    let account = authority(ramflux_node_core::now_unix_seconds())?;
    let gateway = Gateway::new_custody(Some(&account.node)).await?;
    for (index, route) in [Route::Quinn, Route::Tcp].into_iter().enumerate() {
        let peer = format!("127.0.0.{}", 50 + index);
        // New custody proofs and session grants on every connection; replay never calibrates rejection.
        let response =
            attempt(&gateway, route, &peer, &account, None, if index == 0 { 10 } else { 0 })
                .await?;
        assert!(
            matches!(response, GatewayServerFrame::SessionEstablished { .. }),
            "native signed Open: {response:?}"
        );
        let response = attempt(&gateway, route, &peer, &account, None, 0).await?;
        let GatewayServerFrame::Nack { reason } = response else {
            return Err("native retry challenge missing".into());
        };
        let cookie = reason
            .strip_prefix("pre_auth_cookie_required:")
            .ok_or("native pre-auth refusal prefix")?
            .to_owned();
        for control in [0, 1, 2, 3, 0] {
            let response =
                attempt(&gateway, route, &peer, &account, Some(cookie.clone()), control).await?;
            match control {
                0 => assert!(
                    matches!(response, GatewayServerFrame::SessionEstablished { .. }),
                    "native cookie retry: {response:?}"
                ),
                1 | 2 => assert!(
                    matches!(response,GatewayServerFrame::Nack {ref reason} if reason.contains("open frame body hash mismatch")),
                    "native post-sign hint: {response:?}"
                ),
                _ => assert!(
                    matches!(response,GatewayServerFrame::Nack {ref reason} if reason.starts_with("auth rejected:")),
                    "native wrong key: {response:?}"
                ),
            }
        }
        eprintln!(
            "preauth custody {route:?}: live exporter proofs, one-use handoff, signed Open, cookie retry, changed hints, wrong key PASS"
        );
    }
    migrated_custody_stream_keeps_its_captured_peer(&gateway, &account).await?;
    unbound_custody_privacy_control(&account).await?;
    Ok(())
}
async fn custody_exchange(
    client: &mut Client,
    frame: &CustodyClientFrame,
) -> Result<CustodyServerFrame> {
    client.stream.send_frame(&serde_json::to_vec(frame)?).await?;
    let bytes =
        tokio::time::timeout(Duration::from_secs(15), client.stream.recv_custody_frame()).await??;
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) async fn handoff(
    gateway: &Gateway,
    route: Route,
    peer: &str,
    account: &AuthorityFixture,
    bootstrap: bool,
) -> Result<Client> {
    let mut client = gateway.connect(route, peer).await?;
    let response = custody_exchange(
        &mut client,
        &CustodyClientFrame::CustodyOpen { binding_mode: BindingMode::HomeRelayReceipt },
    )
    .await?;
    assert!(
        matches!(response, CustodyServerFrame::NodeIdentity { .. }),
        "node discovery: {response:?}"
    );
    complete_handoff(client, account, bootstrap).await
}
async fn complete_handoff(
    mut client: Client,
    account: &AuthorityFixture,
    bootstrap: bool,
) -> Result<Client> {
    let reference = DeviceRef {
        account_anchor: account.publication.record.body.account_anchor.clone(),
        device_id: "primary".into(),
        device_epoch: 1,
    };
    let bundle = ramflux_crypto::create_prekey_bundle(
        &account.branch,
        &ramflux_crypto::X25519KeyPair::from_seed([4; 32]),
        "signed",
        &ramflux_crypto::X25519KeyPair::from_seed([70; 32]),
        None,
        None,
    )?;
    let all_actions = [
        CustodyProofAction::Publish { publication: Box::new(account.publication.clone()) },
        CustodyProofAction::Register { prekey_bundle: serde_json::to_value(bundle)? },
        CustodyProofAction::OpenSession,
    ];
    let actions =
        if bootstrap { all_actions.to_vec() } else { vec![CustodyProofAction::OpenSession] };
    for action in actions {
        let response = custody_exchange(
            &mut client,
            &CustodyClientFrame::Challenge {
                device_ref: reference.clone(),
                action: action.clone(),
            },
        )
        .await?;
        let CustodyServerFrame::Challenge { challenge } = response else {
            return Err(format!("native challenge: {response:?}").into());
        };
        let nonce = ramflux_protocol::decode_base64url(&challenge.challenge_nonce)?
            .try_into()
            .map_err(|_| "challenge nonce")?;
        let material = client.stream.custody_exporter(&nonce)?;
        let now = ramflux_node_core::now_unix_seconds();
        let proof = sign_branch_proof_v3(
            &account.branch,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: reference.clone(),
                certificate_hash: object_hash(
                    account.publication.record.body.devices[0]
                        .branch_certificate
                        .as_ref()
                        .ok_or("branch cert")?,
                )?,
                record_hash: object_hash(&account.publication.record)?,
                proof_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                challenge_nonce: challenge.challenge_nonce,
                action_hash: challenge.action_hash,
                audience: challenge.audience,
                binding_mode: BindingMode::HomeRelayReceipt,
                transport_binding: branch_exporter_hash(&material),
                issued_at: now,
                expires_at: now + 60,
            },
        )?;
        let response = custody_exchange(
            &mut client,
            &CustodyClientFrame::Prove { action, proof: Box::new(proof) },
        )
        .await?;
        if let CustodyServerFrame::SessionEstablished { session } = response {
            client
                .stream
                .send_frame(&serde_json::to_vec(&CustodyClientFrame::GatewayHandoff {
                    session_id: session.session_id,
                })?)
                .await?;
            return Ok(client);
        }
        assert!(
            matches!(
                response,
                CustodyServerFrame::Published { .. } | CustodyServerFrame::Registered { .. }
            ),
            "native proof: {response:?}"
        );
    }
    Err("custody session missing".into())
}
async fn attempt(
    gateway: &Gateway,
    route: Route,
    peer: &str,
    account: &AuthorityFixture,
    cookie: Option<String>,
    control: u8,
) -> Result<GatewayServerFrame> {
    let client = handoff(gateway, route, peer, account, control == 10).await?;
    exchange_open(client, account, cookie, control).await
}
async fn exchange_open(
    mut client: Client,
    account: &AuthorityFixture,
    cookie: Option<String>,
    control: u8,
) -> Result<GatewayServerFrame> {
    let anchor = &account.publication.record.body.account_anchor;
    let mut open = GatewayOpenFrame {
        protocol_version: ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION.into(),
        transport_kind: "quic_quinn".into(),
        client_instance_id: "preauth-native".into(),
        device_id: "primary".into(),
        target_delivery_id: ramflux_protocol::qualified_device_id(anchor, "primary")?,
        stream_nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        previous_session_id: None,
        resume_token_hash: None,
        last_seen_inbox_seq: None,
        max_inflight_downstream: 4,
        max_inflight_upstream: 4,
        pre_auth_cookie: cookie,
        source_ip_hash: Some("native-signed-hint".into()),
        pre_auth_now: Some(1),
    };
    let auth = auth_for(&open, if control == 3 { [55; 32] } else { [3; 32] }, "alice", anchor)?;
    if control == 1 {
        open.source_ip_hash = Some("native-changed-after-sign".into());
    }
    if control == 2 {
        open.pre_auth_now = Some(2);
    }
    Ok(client.exchange(open, auth).await?)
}

async fn migrated_custody_stream_keeps_its_captured_peer(
    gateway: &Gateway,
    account: &AuthorityFixture,
) -> Result {
    let before: std::net::IpAddr = "127.30.0.1".parse()?;
    let after: std::net::IpAddr = "127.31.0.1".parse()?;
    let captured = gateway.context.hub.capture_next_stream()?;
    let mut endpoint = quinn::Endpoint::client(std::net::SocketAddr::new(before, 0))?;
    endpoint.set_default_client_config(ramflux_transport::quic_gateway_client_config(
        &gateway.tls.ca_cert,
    )?);
    let connection = endpoint.connect(gateway.quic, "localhost")?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    let bytes = serde_json::to_vec(&CustodyClientFrame::CustodyOpen {
        binding_mode: BindingMode::HomeRelayReceipt,
    })?;
    send.write_all(&u32::try_from(bytes.len())?.to_be_bytes()).await?;
    send.write_all(&bytes[..1]).await?;
    assert_eq!(tokio::time::timeout(Duration::from_secs(15), captured).await??.ip(), before);
    endpoint.rebind(std::net::UdpSocket::bind(std::net::SocketAddr::new(after, 0))?)?;
    let next_capture = gateway.context.hub.capture_next_stream()?;
    let (mut request, mut reply) = connection.open_bi().await?;
    ramflux_transport::write_quic_json_frame(
        &mut request,
        &ramflux_transport::GatewayQuicRequest {
            method: "GET".into(),
            path: "/ordinary-not-found".into(),
            body: serde_json::Value::Null,
        },
    )
    .await?;
    let reply: ramflux_transport::GatewayQuicResponse =
        ramflux_transport::read_quic_json_frame(&mut reply).await?;
    assert_eq!(reply.status, 404);
    assert_eq!(tokio::time::timeout(Duration::from_secs(15), next_capture).await??.ip(), after);
    send.write_all(&bytes[1..]).await?;
    let response: CustodyServerFrame = ramflux_transport::read_quic_json_frame(&mut recv).await?;
    assert!(
        matches!(response, CustodyServerFrame::NodeIdentity { .. }),
        "custody discovery after migration: {response:?}"
    );
    let limiter = &gateway.context.custody.as_ref().ok_or("custody pools missing")?.quic;
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(limiter.acquire(before, None, std::time::Instant::now())?);
    }
    assert!(
        limiter.acquire(before, None, std::time::Instant::now()).is_err(),
        "custody permit was re-bucketed to the migrated peer"
    );
    drop(limiter.acquire(after, None, std::time::Instant::now())?);
    let client = Client::direct_quinn(connection.clone(), send, recv);
    let client = complete_handoff(client, account, false).await?;
    let response = exchange_open(client, account, None, 0).await?;
    assert!(
        matches!(response, GatewayServerFrame::SessionEstablished { .. }),
        "migrated handoff: {response:?}"
    );
    let key_before = crate::pre_auth::source_key(before);
    let key_after = crate::pre_auth::source_key(after);
    {
        let state = crate::gateway_state(&gateway.context.state)?;
        assert!(state.has_pre_auth_source(&key_before));
        assert!(
            !state.has_pre_auth_source(&key_after),
            "handoff must retain accepted-stream source"
        );
    }
    let (send, recv) = connection.open_bi().await?;
    let mut client = Client::direct_quinn(connection.clone(), send, recv);
    let open = crate::pre_auth_transport_tests::open("after-custody-migration", 1, None)?;
    let auth = crate::pre_auth_transport_tests::auth(&open, [32; 32])?;
    let response = client.exchange(open, auth).await?;
    assert!(matches!(response, GatewayServerFrame::SessionEstablished { .. }));
    assert!(crate::gateway_state(&gateway.context.state)?.has_pre_auth_source(&key_after));
    drop(held);
    connection.close(0u32.into(), b"custody migration complete");
    eprintln!(
        "preauth custody migration: frozen capacity/proxy/handoff source and refreshed next stream PASS"
    );
    Ok(())
}
async fn unbound_custody_privacy_control(account: &AuthorityFixture) -> Result {
    let mut body = account.node.envelope().body.clone();
    body.channel_binding_modes.push(BindingMode::NoChannelBinding);
    let record = sign_node_identity_record(&ed25519_dalek::SigningKey::from_bytes(&[8; 32]), body)?;
    let node = verify_node_identity_record(
        &record,
        "test-node",
        &ramflux_crypto::public_key_base64url_from_seed([8; 32]),
        ramflux_node_core::now_unix_seconds(),
    )?;
    let gateway = Gateway::new_custody(Some(&node)).await?;
    let before = crate::ingress_log::snapshot().no_channel_binding;
    for route in [Route::Quinn, Route::Tcp] {
        let mut client = gateway.connect(route, "127.0.0.250").await?;
        let response = custody_exchange(
            &mut client,
            &CustodyClientFrame::CustodyOpen { binding_mode: BindingMode::NoChannelBinding },
        )
        .await?;
        assert!(matches!(
            response,
            CustodyServerFrame::NodeIdentity { binding_mode: BindingMode::NoChannelBinding, .. }
        ));
    }
    assert_eq!(crate::ingress_log::snapshot().no_channel_binding, before + 2);
    eprintln!("preauth custody privacy: opted-in unbound TCP/Quinn counted without peer data PASS");
    Ok(())
}
