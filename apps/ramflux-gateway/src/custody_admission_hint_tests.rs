// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Listener saturation and real gateway Prove retries carry node-owned hints.
use super::*;
use ramflux_protocol::custody::RetryScope;
fn assert_node_hint(frame: &CustodyServerFrame, maximum: u32) {
    assert!(
        matches!(frame, CustodyServerFrame::Refused { code: CustodyRefusal::Busy, capacity: None, retry: Some(hint) } if hint.scope==RetryScope::NodeCapacity && (1000..=maximum).contains(&hint.retry_after_ms)),
        "{frame:?}"
    );
}
#[tokio::test]
async fn refusal_frames_carry_hint_over_tcp_and_quic() -> Result {
    super::super::quic_refusal_hint_and_slot_reuse().await?;
    let fixture = Fixture::new()?;
    let limiter = CustodyIngressLimiter::new(1);
    let occupied = limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?;
    let pools = Pools { tcp: Arc::clone(&limiter), quic: Arc::clone(&limiter) };
    let (mut client, mut server) = tcp_pair(&fixture).await?;
    assert!(admit_tcp(&mut server, "127.0.0.1".parse()?, Some(&pools)).await?.is_none());
    assert_node_hint(&decode(&read_custody_tcp_frame(&mut client).await?, 4096)?, 10_000);
    assert!(!occupied.is_revoked());
    drop(occupied);

    let router = Arc::new(RouterCore::new());
    let store = Arc::new(RouterRedbStore::open(fixture.root.join("hint-router.redb"))?);
    store.bootstrap_router(&router)?;
    let now = ramflux_node_core::now_unix_seconds();
    let node = authority(now)?.node;
    let service = Arc::new(CustodyService::new(node.clone(), false, &store, now)?);
    let (mesh, serving) = gateway::start_mesh(&fixture.root, Arc::clone(&router), store, service)?;
    let (_fixture_directory_0, mut context) = crate::session::tests::test_gateway_context()?;
    context.router = mesh;
    context.node_id = "test-node".into();
    context.remote_addr = "127.0.0.1:12345".parse()?;
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let occupied = limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?;
    occupied.mark_authenticated("existing-account")?;
    let mut incoming = Client::connect(&fixture, &limiter, &node).await?;
    let account = Account::new("hint-account", 40)?;
    let action = account.actions()?[0].clone();
    let response = incoming
        .proxy
        .frame(
            &context,
            CustodyClientFrame::Challenge {
                device_ref: account.reference(),
                action: action.clone(),
            },
            None,
            &incoming.permit,
        )
        .await?;
    let CustodyServerFrame::Challenge { challenge } = response else {
        return Err(format!("challenge: {response:?}").into());
    };
    let nonce = ramflux_protocol::decode_base64url(&challenge.challenge_nonce)?
        .try_into()
        .map_err(|_| "nonce")?;
    let material = ramflux_transport::custody_tcp_exporter(&incoming.tls, &nonce)?;
    let observed =
        branch_exporter_hash(&ramflux_transport::custody_tcp_exporter(&incoming.observed, &nonce)?);
    let proof = sign_branch_proof_v3(
        &account.branch,
        BranchProofV3 {
            schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
            version: 3,
            device_ref: account.reference(),
            certificate_hash: object_hash(
                account.publication.record.body.devices[0]
                    .branch_certificate
                    .as_ref()
                    .ok_or("certificate")?,
            )?,
            record_hash: object_hash(&account.publication.record)?,
            proof_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            challenge_nonce: challenge.challenge_nonce,
            action_hash: challenge.action_hash,
            audience: challenge.audience,
            binding_mode: BindingMode::HomeRelayReceipt,
            transport_binding: branch_exporter_hash(&material),
            issued_at: now,
            expires_at: now + 300,
        },
    )?;
    let response = incoming
        .proxy
        .frame(
            &context,
            CustodyClientFrame::Prove { action, proof: Box::new(proof) },
            Some(&observed),
            &incoming.permit,
        )
        .await?;
    write_custody_tcp_frame(&mut incoming.observed, &serde_json::to_vec(&response)?).await?;
    let received: CustodyServerFrame =
        decode(&read_custody_tcp_frame(&mut incoming.tls).await?, 4096)?;
    assert_node_hint(&received, 30_000);
    assert!(!incoming.proxy.authenticated);
    assert!(!occupied.is_revoked());
    serving.abort();
    Ok(())
}
