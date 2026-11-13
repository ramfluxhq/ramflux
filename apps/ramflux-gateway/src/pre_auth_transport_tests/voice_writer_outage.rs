// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Saturated production voice adapters preserve bounded SDK call state.
use super::writer_outage::{response, signed_operation};
use super::*;
use ramflux_node_core::GatewayClientFrame;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

async fn establishment_busy(fixture: &Fixture) -> anyhow::Result<()> {
    struct Sink(Vec<Vec<u8>>);
    impl ramflux_transport::GatewaySessionFrameSink for Sink {
        fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
            Ok(())
        }
        fn send_frame<'a>(
            &'a mut self,
            body: &'a [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), ramflux_transport::TransportError>>
                    + Send
                    + 'a,
            >,
        > {
            self.0.push(body.to_vec());
            Box::pin(async { Ok(()) })
        }
    }
    let mut sink = Sink(Vec::new());
    let opening = open("establishment-busy", 0, None)?;
    let authentication = auth(&opening, [32; 32])?;
    let key: ramflux_node_core::DeviceAuthKeyResponse = crate::router_get_json_async(
        &fixture.context.router,
        &format!(
            "/mvp1/device-auth-key/{}",
            ramflux_protocol::qualified_device_id(
                authentication.device_proof.ext.ext["source_root_commitment"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("root"))?,
                "device"
            )?
        ),
    )
    .await?;
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
        &ramflux_crypto::create_identity_root("peer", [31; 32]),
        &ramflux_crypto::create_device_branch("peer", "device", 1, [32; 32]),
    )?;
    assert!(
        crate::session::establish_gateway_session_or_reject(
            &mut sink,
            &fixture.context,
            &opening,
            &authentication,
            key,
            source
        )
        .await?
        .is_none()
    );
    let reply: GatewayServerFrame = serde_json::from_slice(
        sink.0.first().ok_or_else(|| anyhow::anyhow!("establishment reply"))?,
    )?;
    assert!(
        matches!(reply,GatewayServerFrame::Nack {reason} if reason=="gateway_writer_busy: retryable"),
        "establishment discarded typed busy"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires same-tree router; explicit gateway admission CI row"]
#[allow(
    clippy::too_many_lines,
    reason = "one causal writer outage covers wire replies, call effects, progress and recovery"
)]
async fn saturated_writer_voice_renew_preserves_active_call_and_initial_media() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(30), async {
        let fixture = Fixture::new().await?;
        let mut clients = Vec::new();
        let mut registrations = Vec::new();
        for index in 0..10 {
            let device = format!("outage-device-{index}");
            let principal = format!("outage-principal-{index}");
            let delivery = format!("outage-delivery-{index}");
            let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
            let mut registration = crate::registration_forward_tests::registration_for(now, &principal, &device, &delivery, [u8::try_from(index+64)?;32]).map_err(|error|anyhow::anyhow!("{error}"))?;
            registration.gateway_id = fixture.context.gateway_id.clone();
            let _: ramflux_node_core::IdentityRegistrationResponse = crate::router_post_json_async(&fixture.context.router, "/mvp1/identity/register", &registration).await?;
            let branch = ramflux_crypto::create_device_branch(&principal,&device,1,[32;32]);
            let prekey = ramflux_node_core::PrekeyPublishRequest {
                device_id:device.clone(),
                bundle:ramflux_crypto::create_prekey_bundle(&branch,&ramflux_crypto::X25519KeyPair::from_seed([33;32]),"voice-prekey",&ramflux_crypto::X25519KeyPair::from_seed([34;32]),None,None)?,
            };
            let _: ramflux_node_core::PrekeyResponse = crate::router_post_json_async(&fixture.context.router,"/mvp1/prekey/publish",&prekey).await?;
            let mut client = fixture.connect(Route::Tcp, &format!("127.0.0.{}", 110+index)).await?;
            let mut open = open("writer-outage", 0, None)?;
            open.device_id = device; open.target_delivery_id = delivery;
            let auth = auth_for(&open, [32;32], &principal, &registration.principal_commitment)?;
            established(&client.exchange(open, auth).await?)?;
            clients.push(client);
            registrations.push(registration);
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
        let now = ramflux_node_core::now_unix_seconds();
        let endpoint = |index: usize| -> anyhow::Result<ramflux_protocol::CallEndpoint> {
            let r = registrations.get(index).ok_or_else(|| anyhow::anyhow!("registration"))?;
            Ok(ramflux_protocol::CallEndpoint { principal_id:r.proof.principal_id.clone(), device_id:r.proof.device_id.clone(), root_public_key:r.root_public_key.clone() })
        };
        let scope = ramflux_protocol::VoiceAllocationRequest { call_id:ramflux_protocol::encode_base64url([5;16]), caller:endpoint(8)?, callee:endpoint(9)? };
        let mut consent = ramflux_protocol::VoiceLeaseConsent { scope:scope.clone(), lease_id:ramflux_protocol::encode_base64url([8;16]), expires_at:now+300, signature:String::new() };
        consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(&ramflux_protocol::voice_lease_consent_bytes(&consent)?, &ramflux_crypto::create_device_branch("outage-principal-9", "outage-device-9", 1,[32;32]));
        let mut requests = Vec::new();
        for (index, body) in [
            (8, ramflux_protocol::VoiceLeaseRequest::Renew {consent:Box::new(consent.clone())}),
            (8, ramflux_protocol::VoiceLeaseRequest::Allocate {scope:scope.clone()}),
            (9, ramflux_protocol::VoiceLeaseRequest::Accept {consent:Box::new(consent.clone())}),
        ] {
            let mut signed_request = match signed_operation(index, &format!("outage-device-{index}"))? { GatewayClientFrame::RelayTokenV3Issue {request} => request.signed_request, _ => panic!("test: unexpected fixture variant or missing fixture value") };
            signed_request.path = "/voice/v1/lease".into();
            signed_request.request_id = format!("voice-busy-{}",requests.len());
            signed_request.nonce = signed_request.request_id.clone();
            signed_request.body_hash = ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::ENVELOPE, &ramflux_protocol::canonical_json_bytes(&body)?);
            signed_request.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&signed_request,[32;32])?;
            let request = GatewayClientFrame::VoiceLease {request:Box::new(ramflux_protocol::VoiceLeaseFrame {signed_request,body})};
            let client = clients.get_mut(index).ok_or_else(||anyhow::anyhow!("voice client"))?;
            client.stream.send_frame(&serde_json::to_vec(&request)?).await?;
            let reply = response(client).await?;
            let active = requests.is_empty();
            let mut call = ramflux_sdk::VoiceAdmissionProbe::new(scope.clone(),active,index==9,i64::try_from(now)?)?;
            let before = call.snapshot()?;
            call.apply(&serde_json::to_vec(&reply)?, i64::try_from(now)?)?;
            let after = call.snapshot()?;
            assert_eq!(after["row"]["state"], before["row"]["state"], "writer busy terminated active call or initial lease");
            assert_eq!(after["allocation"],before["allocation"],"busy lost/extended valid allocation");
            assert_eq!(after["pending"],before["pending"],"busy acknowledged uncommitted lease");
            assert_eq!(after["receive_key_present"],before["receive_key_present"]);
            assert!(matches!(reply,GatewayServerFrame::Nack {reason} if reason=="gateway_writer_busy: retryable"),"voice busy must stay typed");
            assert_eq!(after["next_refresh"],now+1);
            call.expire(i64::try_from(now+if active {60} else {45})?)?;
            assert_eq!(call.snapshot()?["row"]["state"],"ended","busy extended existing deadline");
            requests.push((index,request));
        }
        establishment_busy(&fixture).await?;
        // Auth also exposes busy distinctly rather than a terminal establishment refusal.
        let mut joining = fixture.connect(Route::Tcp,"127.0.0.130").await?;
        let joining_open = open("joining-busy",0,None)?;
        let joining_auth = auth(&joining_open,[32;32])?;
        assert!(matches!(joining.exchange(joining_open,joining_auth).await?,GatewayServerFrame::Nack {reason} if reason=="gateway_writer_busy: retryable"));
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
        for (index, request) in requests {
            let client = clients.get_mut(index).ok_or_else(||anyhow::anyhow!("voice recovery client"))?;
            client.stream.send_frame(&serde_json::to_vec(&request)?).await?;
            let recovered_reply = response(client).await?;
            assert!(matches!(&recovered_reply,GatewayServerFrame::VoiceLease {response} if matches!(**response,ramflux_protocol::VoiceLeaseResponse::Refused {reason:ramflux_protocol::VoiceCallFailureReason::RelayUnavailable})),"valid signed voice did not recover past admission and current authority: {recovered_reply:?}");
            // The exact retry committed once; an uncommitted busy reply consumed no replay identity.
            client.stream.send_frame(&serde_json::to_vec(&request)?).await?;
            let refused_reply = response(client).await?;
            assert!(matches!(&refused_reply,GatewayServerFrame::VoiceLease {response} if matches!(**response,ramflux_protocol::VoiceLeaseResponse::Refused {reason:ramflux_protocol::VoiceCallFailureReason::AuthorityRefused})),"real replay refusal must stay terminal");
            let mut active = ramflux_sdk::VoiceAdmissionProbe::new(scope.clone(),true,false,i64::try_from(now)?)?;
            active.apply(&serde_json::to_vec(&refused_reply)?,i64::try_from(now)?)?;
            assert_eq!(active.snapshot()?["row"]["state"],"ended","true authority refusal became retryable");
        }
        assert_eq!(fixture.context.store.durable_commit_count()-before,12);
        Ok(())
    }).await?
}
