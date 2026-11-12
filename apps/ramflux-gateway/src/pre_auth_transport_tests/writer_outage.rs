// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Competing established signed operations cannot consume the network runtime's workers.
use super::*;
use ramflux_node_core::{GatewayClientFrame, GatewayRelayTokenV3IssueRequest};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

fn signed_operation(index: usize) -> anyhow::Result<GatewayClientFrame> {
    let now = ramflux_node_core::now_unix_seconds();
    // Issuer material is deliberately absent: a valid signed wrapper must commit first,
    // then return the ordinary business refusal. No token is issued by this fixture.
    let body: ramflux_node_core::RelayTokenV3IssueRequest = serde_json::from_value(
        serde_json::json!({
            "requester_device_id":"device", "requester_device_hash":"hash", "requester_public_key":"key", "requester_device_epoch":1,
            "owner_signing_key_id":"device", "owner_public_key":"key", "owner_home_node_id":"node", "owner_principal_id":"peer", "owner_device_epoch":1,
            "issuer_node_id":"node", "gateway_instance_id":"gateway", "audience_node_id":"node", "relay_instance_id":null,
            "object_id":"object", "manifest_hash":"manifest", "chunk_id":"chunk", "capabilities":[], "authorization_kind":"owner_session", "authorization_binding_hash":"binding", "delete_after_ack":false,
            "issued_at":now, "expires_at":now+60, "nonce":format!("operation-{index}"),
            "issuer_certificate": {"schema":"fixture", "version":1, "cert_id":"cert", "node_id":"node", "gateway_instance_id":"gateway", "attestation_public_key":"key", "attestation_key_id":"key", "not_before":now, "not_after":now+60, "issued_at":now, "node_root_signing_key_id":"root", "node_root_signature":"unused", "revoked_at":null}
        }),
    )?;
    let mut signed_request = auth(&open("wrapper", 0, None)?, [32; 32])?.signed_request;
    signed_request.path = "/relay/v1/token/v3/issue".into();
    signed_request.device_proof_hash = "already_authed".into();
    signed_request.request_id = format!("writer-outage-{index}");
    signed_request.nonce = format!("writer-outage-{index}");
    signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&body)?,
    );
    signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&signed_request, [32; 32])?;
    Ok(GatewayClientFrame::RelayTokenV3Issue {
        request: Box::new(GatewayRelayTokenV3IssueRequest { signed_request, body }),
    })
}
async fn response(client: &mut support::Client) -> anyhow::Result<GatewayServerFrame> {
    Ok(serde_json::from_slice(&client.stream.recv_frame().await?)?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires same-tree router; explicit gateway admission CI row"]
async fn competing_signed_writes_preserve_network_progress_and_bounded_pending()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fixture = Fixture::new().await?;
        let mut clients = Vec::new();
        for index in 0..10 {
            let mut client = fixture.connect(Route::Tcp, &format!("127.0.0.{}", 110+index)).await?;
            let open = open("writer-outage", 0, None)?;
            established(&client.exchange(open.clone(), auth(&open, [32;32])?).await?)?;
            clients.push(client);
        }
        let (entered, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        fixture.context.store.pause_next_admission_commit(entered, waiting)?;
        let store = fixture.context.store.clone();
        let checkpoint = crate::gateway_state(&fixture.context.state)?.admission_checkpoint(ramflux_node_core::now_unix_seconds());
        let worker = std::thread::spawn(move || store.save_admission_checkpoint(&checkpoint));
        observed.recv_timeout(Duration::from_secs(5))?;
        // A wall-clock watchdog releases the gate even if a broken implementation blocks
        // both Tokio workers. The heartbeat deadline then fails by assertion, not a hang.
        let recovered = Arc::new(AtomicBool::new(false));
        let control = recovered.clone();
        let (finish, watchdog) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let completed = watchdog.recv_timeout(Duration::from_secs(8)).is_ok();
            control.store(completed, Ordering::SeqCst);
            let _ = release.send(());
        });
        let before = fixture.context.store.durable_commit_count();
        for (index, client) in clients.iter_mut().take(8).enumerate() {
            client.stream.send_frame(&serde_json::to_vec(&signed_operation(index)?)?).await?;
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while fixture.context.store.pending_network_writes() < 8 { tokio::task::yield_now().await; }
        }).await?;
        assert_eq!(fixture.context.store.pending_network_writes(), 8);
        let overflow = clients.get_mut(8).ok_or_else(|| anyhow::anyhow!("overflow client"))?;
        overflow.stream.send_frame(&serde_json::to_vec(&signed_operation(8)?)?).await?;
        assert!(matches!(response(overflow).await?, GatewayServerFrame::Nack {reason} if reason.contains("gateway_writer_busy")), "overflow must return typed retryable busy");
        let heartbeat = clients.get_mut(9).ok_or_else(|| anyhow::anyhow!("heartbeat client"))?;
        heartbeat.stream.send_frame(&serde_json::to_vec(&GatewayClientFrame::Heartbeat { now:7331 })?).await?;
        assert!(matches!(response(heartbeat).await?, GatewayServerFrame::Heartbeat {now:7331}), "heartbeat stalled behind competing signed writes");
        cookie(exchange(&fixture, Route::Tcp, "127.0.0.119", open("outage-open", 0, None)?).await?)?;
        assert_eq!(fixture.context.store.durable_commit_count(), before, "uncommitted signed work was acknowledged");
        assert!(tokio::time::timeout(Duration::from_millis(20), response(clients.first_mut().ok_or_else(|| anyhow::anyhow!("first client"))?)).await.is_err(), "signed work answered before commit");
        finish.send(())?;
        watchdog.join().map_err(|_| anyhow::anyhow!("watchdog panic"))?;
        assert!(recovered.load(Ordering::SeqCst), "network progress required watchdog to release blocked writer");
        worker.join().map_err(|_| anyhow::anyhow!("checkpoint panic"))??;
        for client in clients.iter_mut().take(8) {
            assert!(matches!(response(client).await?, GatewayServerFrame::Nack {reason} if reason.contains("capability is missing")), "valid signed operation did not recover to its business refusal");
        }
        assert_eq!(fixture.context.store.durable_commit_count()-before, 9);
        assert_eq!(fixture.context.store.pending_network_writes(), 0);
        let client = clients.get_mut(8).ok_or_else(|| anyhow::anyhow!("recovery client"))?;
        client.stream.send_frame(&serde_json::to_vec(&signed_operation(9)?)?).await?;
        assert!(matches!(response(client).await?, GatewayServerFrame::Nack {reason} if reason.contains("capability is missing")));
        assert_eq!(fixture.context.store.durable_commit_count()-before, 10);
        Ok(())
    }).await?
}
