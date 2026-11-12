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
async fn handoff(
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
    let mut client = handoff(gateway, route, peer, account, control == 10).await?;
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
