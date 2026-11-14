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

pub(super) fn signed_operation(index: usize, device: &str) -> anyhow::Result<GatewayClientFrame> {
    let now = ramflux_node_core::now_unix_seconds();
    // Issuer material is deliberately absent: a valid signed wrapper must commit first,
    // then return the ordinary business refusal. No token is issued by this fixture.
    let body: ramflux_node_core::RelayTokenV3IssueRequest = serde_json::from_value(
        serde_json::json!({
            "requester_device_id":device, "requester_device_hash":"hash", "requester_public_key":"key", "requester_device_epoch":1,
            "owner_signing_key_id":"device", "owner_public_key":"key", "owner_home_node_id":"node", "owner_principal_id":"peer", "owner_device_epoch":1,
            "issuer_node_id":"node", "gateway_instance_id":"gateway", "audience_node_id":"node", "relay_instance_id":null,
            "object_id":"object", "manifest_hash":"manifest", "chunk_id":"chunk", "capabilities":[], "authorization_kind":"owner_session", "authorization_binding_hash":"binding", "delete_after_ack":false,
            "issued_at":now, "expires_at":now+60, "nonce":format!("operation-{index}"),
            "issuer_certificate": {"schema":"fixture", "version":1, "cert_id":"cert", "node_id":"node", "gateway_instance_id":"gateway", "attestation_public_key":"key", "attestation_key_id":"key", "not_before":now, "not_after":now+60, "issued_at":now, "node_root_signing_key_id":"root", "node_root_signature":"unused", "revoked_at":null}
        }),
    )?;
    let mut signed_request = auth(&open("wrapper", 0, None)?, [32; 32])?.signed_request;
    signed_request.source_device_id = device.into();
    signed_request.signed.signing_key_id = device.into();
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
pub(super) async fn response(client: &mut support::Client) -> anyhow::Result<GatewayServerFrame> {
    Ok(serde_json::from_slice(&client.stream.recv_frame().await?)?)
}
fn overflow_operations() -> anyhow::Result<Vec<GatewayClientFrame>> {
    let template = |index| -> anyhow::Result<ramflux_protocol::SignedRequest> {
        match signed_operation(index, "outage-device-8")? {
            GatewayClientFrame::RelayTokenV3Issue { request } => Ok(request.signed_request),
            _ => anyhow::bail!("token wrapper fixture"),
        }
    };
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let mut envelope = crate::session::submit_fixtures::test_envelope(now)?;
    envelope.source_principal_id = "outage-principal-8".into();
    envelope.source_device_id = "outage-device-8".into();
    envelope.target_delivery_id = "outage-delivery-9".into();
    envelope.signed.signing_key_id = "outage-device-8".into();
    let root = ramflux_crypto::create_identity_root("outage-principal-8", [72; 32]);
    envelope.ext.ext.insert(
        "source_root_commitment".into(),
        serde_json::json!(ramflux_crypto::identity_root_commitment(
            &root.signing_key.verifying_key()
        )),
    );
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
        [32; 32],
    );
    let signed_request = operation_wrapper(template(81)?, "/gateway/session/submit", &envelope)?;
    let operations = vec![
        signed_operation(80, "outage-device-8")?,
        GatewayClientFrame::Submit {
            submit: ramflux_node_core::GatewaySubmitFrame {
                call_intent: None,
                wake_id: None,
                call_ref: None,
                call_terminal: None,
                call_context: None,
                signed_request,
                envelope,
            },
        },
    ];
    #[cfg(feature = "itest-local-mint")]
    let operations = {
        let mut operations = operations;
        let branch = ramflux_crypto::create_device_branch(
            "outage-principal-8",
            "outage-device-8",
            1,
            [32; 32],
        );
        let body = crate::session::tests::test_relay_token_issue_body(
            &branch,
            ramflux_node_core::ObjectRelayCapability::Put,
        )?;
        let signed_request = operation_wrapper(template(82)?, "/relay/v1/token/issue", &body)?;
        operations.push(GatewayClientFrame::RelayTokenIssue {
            request: ramflux_node_core::RelayTokenIssueRequest { signed_request, body },
        });
        operations
    };
    Ok(operations)
}
fn operation_wrapper<T: serde::Serialize>(
    mut request: ramflux_protocol::SignedRequest,
    path: &str,
    body: &T,
) -> anyhow::Result<ramflux_protocol::SignedRequest> {
    request.path = path.into();
    request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(body)?,
    );
    request.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&request, [32; 32])?;
    Ok(request)
}
async fn busy_operations(
    client: &mut support::Client,
    operations: &[GatewayClientFrame],
) -> anyhow::Result<()> {
    for operation in operations {
        client.stream.send_frame(&serde_json::to_vec(operation)?).await?;
        let GatewayServerFrame::Nack { reason } = response(client).await? else {
            anyhow::bail!("busy operation was acknowledged")
        };
        let error = ramflux_sdk::SdkError::gateway_nack_for_test(reason.clone());
        assert!(
            matches!(error, ramflux_sdk::SdkError::GatewayWriterBusy),
            "busy NACK lost SDK GatewayWriterBusy typed outcome: {error}"
        );
        assert_eq!(
            reason, "gateway_writer_busy: retryable",
            "busy wire discriminator was prefixed"
        );
    }
    Ok(())
}
async fn recover_operations(
    client: &mut support::Client,
    operations: &[GatewayClientFrame],
    store: &ramflux_node_core::GatewayRedbStore,
    before: usize,
) -> anyhow::Result<()> {
    for (index, operation) in operations.iter().enumerate() {
        client.stream.send_frame(&serde_json::to_vec(operation)?).await?;
        let reply = response(client).await?;
        if let GatewayServerFrame::Nack { reason } = &reply {
            assert!(
                !matches!(
                    ramflux_sdk::SdkError::gateway_nack_for_test(reason.clone()),
                    ramflux_sdk::SdkError::GatewayWriterBusy
                ),
                "writer did not recover"
            );
            if matches!(operation, GatewayClientFrame::RelayTokenV3Issue { .. }) {
                assert!(
                    reason.starts_with("relay v3 token issue rejected: "),
                    "non-busy context lost"
                );
            }
        }
        let expected = before + index + 1;
        assert_eq!(store.durable_commit_count(), expected, "retry did not commit signed operation");
        client.stream.send_frame(&serde_json::to_vec(operation)?).await?;
        let GatewayServerFrame::Nack { reason } = response(client).await? else {
            anyhow::bail!("duplicate operation was acknowledged")
        };
        assert!(
            reason.to_ascii_lowercase().contains("replay"),
            "duplicate did not reach replay refusal: {reason}"
        );
        assert!(
            matches!(
                ramflux_sdk::SdkError::gateway_nack_for_test(reason),
                ramflux_sdk::SdkError::GatewaySessionRejected(_)
            ),
            "real replay refusal became busy"
        );
        assert_eq!(store.durable_commit_count(), expected, "replay committed again");
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires same-tree router; explicit gateway admission CI row"]
async fn competing_signed_writes_preserve_network_progress_and_bounded_pending()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fixture = Fixture::new().await?;
        let mut clients = Vec::new();
        for index in 0..10 {
            let device = format!("outage-device-{index}");
            let principal = format!("outage-principal-{index}");
            let delivery = format!("outage-delivery-{index}");
            let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
            let mut registration = crate::registration_forward_tests::registration_for(now, &principal, &device, &delivery, [u8::try_from(index+64)?;32]).map_err(|error|anyhow::anyhow!("{error}"))?;
            registration.gateway_id = fixture.context.gateway_id.clone();
            let _: ramflux_node_core::IdentityRegistrationResponse = crate::router_post_json_async(&fixture.context.router, "/mvp1/identity/register", &registration).await?;
            let mut client = fixture.connect(Route::Tcp, &format!("127.0.0.{}", 110+index)).await?;
            let mut open = open("writer-outage", 0, None)?;
            open.device_id = device; open.target_delivery_id = delivery;
            let auth = auth_for(&open, [32;32], &principal, &registration.principal_commitment)?;
            established(&client.exchange(open, auth).await?)?;
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
        // both Tokio workers. The progress barrier then fails by assertion, not a hang.
        let recovered = Arc::new(AtomicBool::new(false));
        let control = recovered.clone();
        let released = Arc::new(AtomicBool::new(false));
        let gate_released = released.clone();
        let (finish, watchdog) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let completed = watchdog.recv_timeout(Duration::from_secs(8)).is_ok();
            control.store(completed, Ordering::SeqCst);
            gate_released.store(true, Ordering::SeqCst);
            let _ = release.send(());
        });
        let before = fixture.context.store.durable_commit_count();
        for (index, client) in clients.iter_mut().take(8).enumerate() {
            client.stream.send_frame(&serde_json::to_vec(&signed_operation(index, &format!("outage-device-{index}"))?)?).await?;
        }
        while fixture.context.store.pending_network_writes() < 8 {
            assert!(!released.load(Ordering::SeqCst), "network workers blocked before bounded pending admission");
            tokio::task::yield_now().await;
        }
        assert_eq!(fixture.context.store.pending_network_writes(), 8);
        let overflow = clients.get_mut(8).ok_or_else(|| anyhow::anyhow!("overflow client"))?;
        let operations=overflow_operations()?;
        busy_operations(overflow,&operations).await?;
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
        recover_operations(client,&operations,&fixture.context.store,before+9).await?;
        assert_eq!(fixture.context.store.durable_commit_count()-before,9+operations.len());
        Ok(())
    }).await?
}
