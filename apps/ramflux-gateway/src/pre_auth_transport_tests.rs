// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh signed exchanges calibrate the actual transport-to-admission boundary.
pub(crate) mod support;
use ramflux_node_core::{GatewayAuthFrame, GatewayOpenFrame, GatewayServerFrame};
use ramflux_protocol::{Ext, SignatureAlg, SignedFields};
use std::time::Duration;
use support::{Fixture, Route, routes};

fn open(claim: &str, now: u64, cookie: Option<String>) -> anyhow::Result<GatewayOpenFrame> {
    Ok(GatewayOpenFrame {
        protocol_version: ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION.into(),
        transport_kind: "quic_quinn".into(),
        client_instance_id: "preauth-matrix".into(),
        device_id: "device".into(),
        target_delivery_id: "delivery".into(),
        stream_nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        previous_session_id: None,
        resume_token_hash: None,
        last_seen_inbox_seq: None,
        max_inflight_downstream: 4,
        max_inflight_upstream: 4,
        pre_auth_cookie: cookie,
        pre_auth_now: Some(now),
        // Shape-valid claims calibrate restoring source trust without tripping snapshot validation.
        source_ip_hash: Some(ramflux_crypto::blake3_256_base64url(
            "preauth.client_claim.fixture",
            claim.as_bytes(),
        )),
    })
}
fn fields() -> SignedFields {
    SignedFields {
        signing_key_id: "device".into(),
        signature_alg: SignatureAlg::Ed25519,
        signature: String::new(),
    }
}
fn auth(open: &GatewayOpenFrame, seed: [u8; 32]) -> anyhow::Result<GatewayAuthFrame> {
    let root = ramflux_crypto::create_identity_root("peer", [31; 32]);
    let branch = ramflux_crypto::create_device_branch("peer", "device", 1, [32; 32]);
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    auth_for(open, seed, "peer", source.root_commitment())
}
pub(crate) fn auth_for(
    open: &GatewayOpenFrame,
    seed: [u8; 32],
    principal: &str,
    commitment: &str,
) -> anyhow::Result<GatewayAuthFrame> {
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let mut proof = ramflux_protocol::DeviceProof {
        schema: "ramflux.device_proof.v1".into(),
        version: 1,
        domain: "ramflux.device_proof.v1".into(),
        ext: Ext::default(),
        signed: fields(),
        principal_id: principal.into(),
        device_id: open.device_id.clone(),
        device_epoch: 1,
        branch_proof_hash: "registration".into(),
        capability_scope: vec!["gateway_session".into()],
        nonce: open.stream_nonce.clone(),
        expires_at: now + 60,
    };
    proof.ext.ext.insert("source_root_commitment".into(), commitment.into());
    proof.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&proof, seed)?;
    let mut request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".into(),
        version: 1,
        domain: "ramflux.signed_request.v1".into(),
        ext: Ext::default(),
        signed: fields(),
        source_device_id: open.device_id.clone(),
        request_id: format!("preauth-{}", open.stream_nonce),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/gateway/session/auth".into(),
        device_proof_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_node_core::GATEWAY_DEVICE_PROOF_HASH_DOMAIN,
            &ramflux_protocol::canonical_json_bytes(&proof)?,
        ),
        body_hash: ramflux_node_core::gateway_open_hash(open),
        nonce: open.stream_nonce.clone(),
        created_at: now,
        expires_at: now + 60,
    };
    request.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&request, seed)?;
    Ok(GatewayAuthFrame { signed_request: request, device_proof: proof })
}
fn established(frame: &GatewayServerFrame) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(frame, GatewayServerFrame::SessionEstablished { .. }),
        "expected SessionEstablished, received {frame:?}"
    );
    Ok(())
}
fn cookie(frame: GatewayServerFrame) -> anyhow::Result<String> {
    let GatewayServerFrame::Nack { reason } = frame else {
        anyhow::bail!("expected cookie challenge, received {frame:?}")
    };
    reason
        .strip_prefix("pre_auth_cookie_required:")
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("unexpected refusal: {reason}"))
}
async fn exchange(
    fixture: &Fixture,
    route: Route,
    peer: &str,
    open: GatewayOpenFrame,
) -> anyhow::Result<GatewayServerFrame> {
    let auth = auth(&open, [32; 32])?;
    fixture.connect(route, peer).await?.exchange(open, auth).await
}

#[tokio::test]
#[ignore = "requires the same-tree router binary; explicit preauth PR CI job"]
async fn preauth_claim_rotation_transport_matrix() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120),async {
        let fixture=Fixture::new().await?;
        for (index,route) in routes().into_iter().enumerate(){
            let peer=format!("127.0.0.{}",10+index);
            established(&exchange(&fixture,route,&peer,open("claim-original",1,None)?).await?)?;
            cookie(exchange(&fixture,route,&peer,open("claim-rotated",1,None)?).await?)?;
            cookie(exchange(&fixture,route,&peer,open("claim-original",86_400,None)?).await?)?;
            cookie(exchange(&fixture,route,&peer,open("both-rotated",172_800,None)?).await?)?;
            // A shared table must retain this peer's debt on every other carrier too.
            for other in routes(){cookie(exchange(&fixture,other,&peer,open("across-transports",1,None)?).await?)?;}
            let distinct=format!("127.0.0.{}",200+index);
            established(&exchange(&fixture,route,&distinct,open("claim-original",1,None)?).await?)?;
            eprintln!("preauth claim rotation {route:?}: allowance, source/time/both rotation, cross-carrier debt, distinct-peer control PASS");
        }
        Ok(())
    }).await?
}

#[tokio::test]
#[ignore = "requires the same-tree router binary; explicit preauth PR CI job"]
async fn preauth_signed_open_transport_matrix() -> anyhow::Result<()> {
    if !custody_child().await? {
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .try_init()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    tokio::time::timeout(Duration::from_secs(120),async {
        let fixture=Fixture::new().await?;
        for (index,route) in routes().into_iter().enumerate(){
            let peer=format!("127.0.0.{}",30+index);
            let original=open("signed-hint",9_007_199_254_740_991,None)?;
            let bytes=ramflux_protocol::canonical_json_bytes(&original)?;
            let hash=ramflux_node_core::gateway_open_hash(&original);
            established(&exchange(&fixture,route,&peer,original.clone()).await?)?;
            assert_eq!(ramflux_protocol::canonical_json_bytes(&original)?,bytes);
            assert_eq!(ramflux_node_core::gateway_open_hash(&original),hash);
            let cookie=cookie(exchange(&fixture,route,&peer,open("retry-probe",1,None)?).await?)?;
            let retry=open("new-signed-hint",0,Some(cookie.clone()))?;
            established(&exchange(&fixture,route,&peer,retry).await?)?;
            for mutate_time in [false,true] {
                let mut tampered=open("signed-before-change",1,Some(cookie.clone()))?;
                let signature=auth(&tampered,[32;32])?;
                if mutate_time {tampered.pre_auth_now=Some(2);} else {tampered.source_ip_hash=Some("changed-after-sign".into());}
                let response=fixture.connect(route,&peer).await?.exchange(tampered,signature).await?;
                anyhow::ensure!(matches!(response,GatewayServerFrame::Nack {ref reason} if reason.contains("open frame body hash mismatch")),"post-sign hint change was not rejected by hash validation: {response:?}");
            }
            let wrong=open("wrong-key",1,Some(cookie.clone()))?;
            let signature=auth(&wrong,[55;32])?;
            let response=fixture.connect(route,&peer).await?.exchange(wrong,signature).await?;
            anyhow::ensure!(matches!(response,GatewayServerFrame::Nack {ref reason} if reason.starts_with("auth rejected:") && !reason.contains("replay")),"wrong-key control did not reach signature enforcement: {response:?}");
            established(&exchange(&fixture,route,&peer,open("fresh-positive-control",1,Some(cookie))?).await?)?;
            eprintln!("preauth signed Open {route:?}: original hash, cookie retry, two changed hints, wrong-key and fresh-positive controls PASS");
        }
        privacy_controls(&fixture).await?;
        migration_snapshots(&fixture).await?;
        crate::custody::tests::pre_auth_matrix::signed_handoff_matrix().await.map_err(|e|anyhow::anyhow!("{e}"))?;
        Ok(())
    }).await?
}

async fn custody_child() -> anyhow::Result<bool> {
    if std::env::var("RAMFLUX_TEST_PREAUTH_CUSTODY_CHILD").as_deref() == Ok("1") {
        return Ok(true);
    }
    let output = tokio::task::spawn_blocking(|| {
        std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "pre_auth_transport_tests::preauth_signed_open_transport_matrix",
                "--ignored",
                "--nocapture",
            ])
            .env("RAMFLUX_TEST_PREAUTH_CUSTODY_CHILD", "1")
            .env(
                "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY",
                ramflux_crypto::public_key_base64url_from_seed([8; 32]),
            )
            .env("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED", ramflux_protocol::encode_base64url([9; 32]))
            .output()
    })
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        logs.contains("gateway public stream failed"),
        "privacy logging observer did not see the planted decoder failure"
    );
    for sentinel in ["PREAUTH-PRIVATE-SENTINEL", "127.0.0.250"] {
        anyhow::ensure!(!logs.contains(sentinel), "public ingress log exposed a private sentinel");
    }
    eprintln!("{logs}");
    Ok(false)
}

async fn migration_snapshots(fixture: &Fixture) -> anyhow::Result<()> {
    for (index, route) in
        routes().into_iter().filter(|route| !matches!(route, Route::Tcp)).enumerate()
    {
        let before = format!("127.0.0.{}", 90 + index * 2);
        let after = format!("127.0.0.{}", 91 + index * 2);
        let remote = match route {
            Route::Quinn => fixture.quic,
            Route::Tcp => fixture.tcp,
            #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
            Route::Compio => fixture.compio,
        };
        let mut endpoint = quinn::Endpoint::client(format!("{before}:0").parse()?)?;
        endpoint.set_default_client_config(ramflux_transport::quic_gateway_client_config(
            &fixture.tls.ca_cert,
        )?);
        let connection = endpoint.connect(remote, "localhost")?.await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        let original = open("migration-original", 1, None)?;
        let signature = auth(&original, [32; 32])?;
        ramflux_transport::write_quic_json_message(
            &mut send,
            &ramflux_node_core::GatewayClientFrame::Open { open: original },
        )
        .await?;
        // Observe committed gate debt, then move the live connection while it awaits Auth.
        let expected = crate::pre_auth::source_key(before.parse()?);
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let value = serde_json::to_value(&*crate::gateway_state(&fixture.context.state)?)?;
                if value["pre_auth_handshakes_by_source_ip"].get(&expected).is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        endpoint.rebind(std::net::UdpSocket::bind(format!("{after}:0"))?)?;
        ramflux_transport::write_quic_json_message(
            &mut send,
            &ramflux_node_core::GatewayClientFrame::Auth { auth: signature },
        )
        .await?;
        let response: GatewayServerFrame =
            ramflux_transport::read_quic_json_frame(&mut recv).await?;
        established(&response)?;
        let (mut send2, mut recv2) = connection.open_bi().await?;
        let second = open("migration-next-stream", 1, None)?;
        let signature = auth(&second, [32; 32])?;
        ramflux_transport::write_quic_json_message(
            &mut send2,
            &ramflux_node_core::GatewayClientFrame::Open { open: second },
        )
        .await?;
        ramflux_transport::write_quic_json_message(
            &mut send2,
            &ramflux_node_core::GatewayClientFrame::Auth { auth: signature },
        )
        .await?;
        let response: GatewayServerFrame =
            ramflux_transport::read_quic_json_frame(&mut recv2).await?;
        established(&response)?;
        let expected = crate::pre_auth::source_key(after.parse()?);
        let value = serde_json::to_value(&*crate::gateway_state(&fixture.context.state)?)?;
        anyhow::ensure!(
            value["pre_auth_handshakes_by_source_ip"].get(&expected).is_some(),
            "{route:?}: next stream did not capture migrated peer"
        );
        connection.close(0u32.into(), b"matrix complete");
        eprintln!(
            "preauth migration {route:?}: in-Auth snapshot frozen, next stream observes migrated peer PASS"
        );
    }
    Ok(())
}

async fn privacy_controls(fixture: &Fixture) -> anyhow::Result<()> {
    for route in routes() {
        let mut client = fixture.connect(route, "127.0.0.250").await?;
        let frame = ramflux_node_core::GatewayClientFrame::Open {
            open: open(
                "PREAUTH-PRIVATE-SENTINEL-source",
                1,
                Some("PREAUTH-PRIVATE-SENTINEL-cookie".into()),
            )?,
        };
        let mut value = serde_json::to_value(frame)?;
        value["open"]["pre_auth_now"] = "PREAUTH-PRIVATE-SENTINEL-clock".into();
        client.stream.send_frame(&serde_json::to_vec(&value)?).await?;
        anyhow::ensure!(
            client.stream.recv_frame().await.is_err(),
            "invalid hint type must terminate ingress"
        );
    }
    eprintln!(
        "preauth privacy sentinel: planted decoder failures traverse every public carrier; aggregate log observed PASS"
    );
    Ok(())
}
