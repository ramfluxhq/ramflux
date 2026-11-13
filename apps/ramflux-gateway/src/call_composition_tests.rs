// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native router and gateway admission through the resident SDK host and call courier.

use ramflux_node_core::{GatewayServerFrame, test_support::notification_authority::NativeScenario};
use ramflux_sdk::{GatewaySessionState, NativeCallAccount};
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

#[derive(Clone, Copy)]
enum ReplyMode {
    Positive,
    Missing,
    Foreign,
    Stale,
    Contradictory,
}
struct Replies {
    first: Option<GatewayServerFrame>,
    mode: ReplyMode,
    answered_only: bool,
    count: usize,
    decisions: Vec<(String, ramflux_protocol::CallResolutionState)>,
}
#[derive(Clone)]
struct Sink {
    sender: mpsc::Sender<Vec<u8>>,
    replies: Option<Arc<Mutex<Replies>>>,
}
struct Source(mpsc::Receiver<Vec<u8>>);
struct Stream {
    sink: Sink,
    source: Source,
}
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            if body.len() > 64 * 1024 {
                return Err(TransportError::FrameTooLarge { len: body.len() });
            }
            let frame: GatewayServerFrame = if self.replies.is_some() {
                serde_json::from_slice(body)?
            } else {
                self.sender
                    .send(body.to_vec())
                    .await
                    .map_err(|_| TransportError::ShutdownDraining)?;
                return Ok(());
            };
            let mut output = vec![frame.clone()];
            if let Some(state) = &self.replies {
                let mut state = state.lock().map_err(|_| TransportError::ShutdownDraining)?;
                if let GatewayServerFrame::CallResolved {
                    context,
                    state: resolution,
                    media_allowed,
                    wake_resolved,
                } = &frame
                {
                    state.count += 1;
                    if state.decisions.len() >= 16 {
                        return Err(TransportError::ShutdownDraining);
                    }
                    state.decisions.push((context.call_ref.clone(), *resolution));
                    if state.first.is_none() {
                        state.first = Some(frame.clone());
                    } else if !state.answered_only
                        || *resolution == ramflux_protocol::CallResolutionState::Answered
                    {
                        match state.mode {
                            ReplyMode::Positive => {}
                            ReplyMode::Missing => output.clear(),
                            ReplyMode::Foreign => {
                                output = state.first.clone().into_iter().collect();
                            }
                            ReplyMode::Stale => {
                                let mut context = context.clone();
                                context.session_generation =
                                    ramflux_protocol::encode_base64url([17; 32]);
                                output = vec![GatewayServerFrame::CallResolved {
                                    context,
                                    state: *resolution,
                                    media_allowed: *media_allowed,
                                    wake_resolved: *wake_resolved,
                                }];
                            }
                            ReplyMode::Contradictory => output.insert(
                                0,
                                GatewayServerFrame::CallResolved {
                                    context: context.clone(),
                                    state: *resolution,
                                    media_allowed: false,
                                    wake_resolved: *wake_resolved,
                                },
                            ),
                        }
                    }
                }
            }
            for frame in output {
                self.sender
                    .send(serde_json::to_vec(&frame)?)
                    .await
                    .map_err(|_| TransportError::ShutdownDraining)?;
            }
            Ok(())
        })
    }
}
impl GatewaySessionFrameSource for Source {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async { self.0.recv().await.ok_or(TransportError::ShutdownDraining) })
    }
}
impl GatewaySessionFrameSink for Stream {
    fn finish(&mut self) -> Result<(), TransportError> {
        self.sink.finish()
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        self.sink.send_frame(body)
    }
}
impl GatewaySessionFrameSource for Stream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.source.recv_frame()
    }
}

struct Tasks(Vec<tokio::task::JoinHandle<anyhow::Result<()>>>);
impl Tasks {
    async fn check(&mut self) -> anyhow::Result<()> {
        while let Some(index) = self.0.iter().position(tokio::task::JoinHandle::is_finished) {
            let task = self.0.swap_remove(index);
            task.await.map_err(|e| anyhow::anyhow!("native fixture task join: {e}"))??;
        }
        Ok(())
    }
}

fn acknowledge(
    system: &NativeScenario,
    bytes: &[u8],
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let request: ramflux_node_core::TargetAckRequest = ramflux_protocol::parse_i_json(bytes)?;
    let cursor = system
        .router
        .apply_ack_batch(&system.router_store, &request.target_delivery_id, &[request.ack])?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("native ACK response missing"))??;
    Ok((&cursor).into())
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn router_postcard(
    request: ramflux_transport::MeshQuicPostcardAcceptedRequest,
    system: &NativeScenario,
) -> anyhow::Result<()> {
    if request.path == "/mvp0/ack-bound" {
        let response = acknowledge(system, &request.body)?;
        request.write_postcard_response(200, &response).await?;
        return Ok(());
    }
    anyhow::ensure!(
        request.method == "POST" && request.path == "/mvp0/envelope",
        "unexpected postcard route"
    );
    anyhow::ensure!(request.body.len() <= 64 * 1024, "bounded envelope");
    let envelope: ramflux_protocol::Envelope = ramflux_protocol::parse_i_json(&request.body)?;
    let target = envelope.target_delivery_id.clone();
    let (outcome, inbox_seq) = ramflux_node_core::publication::capture(|| {
        let source =
            system.router.authenticated_envelope_source_durable(&envelope, &system.router_store)?;
        let replay = ramflux_node_core::envelope_replay_tuple_key(&source, &envelope);
        let expiry = envelope
            .created_at
            .checked_add(i64::from(envelope.ttl))
            .ok_or_else(|| anyhow::anyhow!("native envelope expiry overflow"))?;
        let lease = system.router_store.acquire_submission(&target)?;
        system.router.prepare_publication_target(&system.router_store, &target)?;
        let outcome = system.router.submit_envelope(&source, envelope);
        let (outcome, entry) = match outcome {
            ramflux_node_core::RouterSubmitOutcome::Online(entry) => (
                "online",
                ramflux_node_core::InboxEntry {
                    inbox_seq: entry.inbox_seq,
                    target_delivery_id: entry.target_delivery_id,
                    envelope: entry.envelope,
                },
            ),
            ramflux_node_core::RouterSubmitOutcome::OfflineQueued(queued) => {
                ("offline_queued", queued.entry)
            }
            other => anyhow::bail!("native router refused: {other:?}"),
        };
        let inbox_seq = entry.inbox_seq;
        system.router_store.record_leased_submission(
            &replay,
            expiry,
            Some(&entry),
            Some(source.root_commitment()),
            Some(lease),
        )?;
        Ok::<_, anyhow::Error>((outcome, inbox_seq))
    })?
    .published()
    .await?;
    request
        .write_postcard_response(
            200,
            &ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: outcome.into(),
                target_delivery_id: target,
                inbox_seq: Some(inbox_seq),
                cursor: None,
                nack: None,
            },
        )
        .await?;
    Ok(())
}

async fn router_connection(
    connection: ramflux_transport::MeshQuicConnection,
    system: Arc<NativeScenario>,
) -> anyhow::Result<()> {
    for _ in 0..64 {
        let accepted = tokio::time::timeout(
            Duration::from_secs(20),
            ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(
                &connection,
            ),
        )
        .await??;
        match accepted {
            ramflux_transport::MeshQuicAcceptedWireRequest::Postcard(request) => {
                router_postcard(request, &system).await?;
            }
            ramflux_transport::MeshQuicAcceptedWireRequest::Json(accepted) => {
                let request = &accepted.request;
                let now = ramflux_node_core::now_unix_seconds();
                let body = if request.path == "/mvp0/ack-bound" {
                    serde_json::to_value(acknowledge(
                        &system,
                        &ramflux_protocol::canonical_json_bytes(&request.body)?,
                    )?)?
                } else if let Some(root) = request.path.strip_prefix("/mvp1/device-manifest/") {
                    serde_json::to_value(system.router.ordinary_device_manifest(
                        root,
                        now,
                        &system.router_store,
                    )?)?
                } else if let Some(target) = request.path.strip_prefix("/mvp1/device-auth-key/") {
                    serde_json::to_value(system.router.mvp1_device_auth_key_checked(target)?)?
                } else if let Some(target) =
                    request.path.strip_prefix(ramflux_node_core::DELIVERY_OWNER_EPOCH_PREFIX)
                {
                    serde_json::to_value(
                        system
                            .router
                            .mvp1_owner_for_delivery(target)
                            .ok_or_else(|| anyhow::anyhow!("native delivery owner missing"))?,
                    )?
                } else if let Some(target) = request.path.strip_prefix("/mvp1/prekey/") {
                    serde_json::to_value(
                        system
                            .router
                            .custody_prekey_response(target, now, &system.router_store)?
                            .ok_or_else(|| anyhow::anyhow!("native prekey missing"))?,
                    )?
                } else if let Some(target) = request.path.strip_prefix("/mvp1/inbox/") {
                    let target =
                        target.split('?').next().ok_or_else(|| anyhow::anyhow!("inbox target"))?;
                    serde_json::to_value(system.router.mvp1_inbox(target, 0, 128))?
                } else if let Some(target) = request.path.strip_prefix("/mvp0/cursor/") {
                    serde_json::to_value(
                        system
                            .router
                            .cursor_state(target)
                            .as_ref()
                            .map(ramflux_node_core::InboxCursorResponse::from),
                    )?
                } else {
                    anyhow::bail!("unexpected native router route {}", request.path)
                };
                accepted.write_json_response(200, &body).await?;
            }
        }
    }
    anyhow::bail!("native router fixture exceeded its request bound")
}

async fn attach_native(
    account: NativeCallAccount,
    context: &crate::state::GatewayQuicContext,
    replies: &Arc<Mutex<Replies>>,
    tasks: &mut Tasks,
) -> anyhow::Result<ramflux_sdk::AccountSessionHarness> {
    let branch =
        account.config.device_branch.as_ref().ok_or_else(|| anyhow::anyhow!("native branch"))?;
    let mut runtime = crate::session::submit_fixtures::test_runtime()?;
    runtime.source_identity = account.identity.clone();
    runtime.device_id = "primary".into();
    runtime.principal_id = account.config.principal_id.clone();
    runtime.target_delivery_id = account.config.target_delivery_id.clone();
    runtime.branch_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    runtime.call_session_generation = Some(ramflux_protocol::encode_base64url([27; 32]));
    let (to_gateway, input) = mpsc::channel(4);
    let (to_sdk, received) = mpsc::channel(4);
    let send: crate::GatewaySendHandle = Arc::new(tokio::sync::Mutex::new(Box::new(Sink {
        sender: to_sdk,
        replies: Some(Arc::clone(replies)),
    })));
    let session = GatewaySessionState {
        call_session_generation: runtime.call_session_generation.clone(),
        session_id: runtime.session_id.clone(),
        gateway_id: context.gateway_id.clone(),
        resume_token: runtime.resume_token.clone(),
        resume_window_seconds: 60,
        accepted_inbox_seq: 0,
    };
    let session_context = context.clone();
    tasks.0.push(tokio::spawn(crate::session::run_gateway_session_loop_until_closed(
        send,
        Box::new(Source(input)),
        session_context,
        runtime,
        None,
        None,
    )));
    let host = Box::pin(account.attach(
        session,
        Box::new(Stream {
            sink: Sink { sender: to_gateway, replies: None },
            source: Source(received),
        }),
    ))
    .await?;
    Ok(host)
}

async fn run(mode: ReplyMode, follow: Option<&'static str>) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(50),Box::pin(async {
        let temp=tempfile::TempDir::new()?;
        let system=Arc::new(NativeScenario::new(temp.path()).map_err(|e|anyhow::anyhow!("{e}"))?);
        let mut alice=NativeCallAccount::new(&temp.path().join("alice"),"alice").await?;
        let mut bob=NativeCallAccount::new(&temp.path().join("bob"),"bob").await?;
        let now=ramflux_node_core::now_unix_seconds();
        for account in [&alice,&bob] {
            system.router.publish_custody_record(&ramflux_node_core::CustodyPublication {record:account.publication.record.clone(),compacted_ids:None},now,&system.router_store)?;
            let bundle=account.manifest.get("devices").and_then(|v|v.get(0)).and_then(|v|v.get("prekey_bundle")).ok_or_else(||anyhow::anyhow!("fixture bundle"))?;
            system.router.publish_custody_prekey(&ramflux_node_core::PrekeyPublishRequest {device_id:"primary".into(),bundle:serde_json::from_value(bundle.clone())?},now,&system.router_store)?;
        }
        let mut context=crate::session::tests::test_gateway_context_at(&temp.path().join("context.redb"))?;
        context.store=Arc::clone(&system.gateway);
        context.store.configure_replay(ramflux_node_core::test_support::federation_fixtures::gateway_replay_fixture_config(),0)?;
        let certs=temp.path().join("certs");std::fs::create_dir(&certs)?;
        let gateway=crate::clients::tests::issue_test_ca_and_service_cert(&certs,"node-test","ramflux-gateway").map_err(|e|anyhow::anyhow!("{e}"))?;
        let router=crate::clients::tests::issue_test_ca_and_service_cert(&certs,"node-test","ramflux-router").map_err(|e|anyhow::anyhow!("{e}"))?;
        let gateway_ca=gateway.ca_pem.clone();
        let mesh=ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0",&router.tls,Arc::new(move||Ok(vec![gateway_ca.clone()])))?;
        context.router=crate::RouterMeshClient {endpoint:"127.0.0.1:0".into(),server_name:"ramflux-router".into(),tls:gateway.tls.clone(),client:ramflux_transport::MeshHttpClient::new(),async_mesh:Some(crate::RouterAsyncMeshClient {endpoint:mesh.local_addr()?.to_string(),server_name:"ramflux-router".into(),tls:gateway.tls,peer_ca_pems:vec![router.ca_pem]})};
        let native=Arc::clone(&system);
        let mut tasks=Tasks(vec![tokio::spawn(async move {
            let mut connections=tokio::task::JoinSet::new();
            loop {tokio::select! {
                connection=mesh.accept_connection(),if connections.len()<8=>{connections.spawn(router_connection(connection?,Arc::clone(&native)));},
                result=connections.join_next(),if !connections.is_empty()=>{if let Some(result)=result {result??;}},
            }}
        })]);
        let public=rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls=ramflux_transport::MeshTlsConfig {ca_cert:temp.path().join("public-ca.pem"),service_cert:temp.path().join("public.pem"),service_key:temp.path().join("public.key")};
        std::fs::write(&tls.ca_cert,public.cert.pem())?;std::fs::write(&tls.service_cert,public.cert.pem())?;std::fs::write(&tls.service_key,public.signing_key.serialize_pem())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        alice.config.transport_kind=ramflux_sdk::GatewaySessionTransportKind::TcpTls;
        alice.config.tcp_gateway_addr=Some(listener.local_addr()?);
        alice.config.server_name="localhost".into();alice.config.ca_cert=tls.ca_cert.clone();
        let listener_context=crate::pre_auth_transport_tests::support::listener_context(&context);
        tasks.0.push(tokio::spawn(crate::serve::serve_gateway_tcp_listener(listener,ramflux_transport::tcp_gateway_server_config(&tls)?,listener_context)));
        bob.config.transport_kind=alice.config.transport_kind;
        bob.config.tcp_gateway_addr=alice.config.tcp_gateway_addr;
        bob.config.server_name=alice.config.server_name.clone();
        bob.config.ca_cert=alice.config.ca_cert.clone();
        bob.prepare_call_peer(alice.manifest.clone())?;
        let replies=Arc::new(Mutex::new(Replies {first:None,mode,answered_only:false,count:0,decisions:Vec::new()}));
        let mut host=Box::pin(attach_native(alice,&context,&replies,&mut tasks)).await?;
        let ids=host.stage_calls(bob.manifest.clone())?;
        let first=ids.first().ok_or_else(||anyhow::anyhow!("first call"))?;
        let second=ids.get(1).ok_or_else(||anyhow::anyhow!("second call"))?;
        host.wait_call_attempt(first).await?;
        tasks.check().await?;
        assert!(host.call_media(first)?,"matching A resolution never reached its actual LiveCall: {:?}",host.call_error(first));
        host.wait_call_attempt(second).await?;
        assert_eq!(host.call_media(second)?,matches!(mode,ReplyMode::Positive),"B consumed a missing, foreign, stale or contradictory decision");
        assert!(replies.lock().map_err(|_|anyhow::anyhow!("replies"))?.count>=2,"test never exercised the complete gateway submit handler twice");
        if let Some(action)=follow {
            if action=="cancel" {
                host.call_action(first,"end")?;
                host.wait_call_attempt(first).await?;
                assert!(!host.call_media(first)?,"cancelled caller regained media");
            } else {
                let mut owner=Box::pin(attach_native(bob,&context,&replies,&mut tasks)).await?;
                owner.wait_call_present(first).await?;
                owner.wait_call_attempt(first).await?;
                assert!(owner.call_media(first)?,"real incoming Ringing courier never resolved: {:?}",owner.call_error(first));
                let owner_action=if action.starts_with("answer") {"answer"} else {action};
                if action=="answer_missing" || action=="answer_foreign" {
                    let mut state = replies.lock().map_err(|_|anyhow::anyhow!("replies"))?;
                    state.mode = if action=="answer_missing" { ReplyMode::Missing } else { ReplyMode::Foreign };
                    state.answered_only = true;
                }
                owner.call_action(first,owner_action)?;
                assert!(!owner.call_media(first)?,"owner answer reused an earlier Ringing media decision before its submit");
                owner.wait_call_attempt(first).await?;
                tasks.check().await?;
                if action=="answer" { assert!(owner.call_media(first)?,"accepted owner answer held media: {:?}",owner.call_error(first)); }
                else if action.starts_with("answer_") {assert!(!owner.call_media(first)?,"owner answer consumed a missing or foreign operation decision");}
                else { assert!(!owner.call_media(first)?,"terminal owner action released media"); }
                owner.stop().await;
            }
            let state=replies.lock().map_err(|_|anyhow::anyhow!("replies"))?;
            let expected=match action {"answer"|"answer_missing"|"answer_foreign"=>ramflux_protocol::CallResolutionState::Answered,"reject"=>ramflux_protocol::CallResolutionState::Rejected,"cancel"=>ramflux_protocol::CallResolutionState::Cancelled,_=>ramflux_protocol::CallResolutionState::Ended};
            assert!(state.decisions.iter().any(|(_,decision)|*decision==expected),"top-level gateway never committed the owner action");
        }
        host.stop().await;
        for task in tasks.0.drain(..) { task.abort(); let _=task.await; }
        Ok(())
    })).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_two_call_positive() -> anyhow::Result<()> {
    run(ReplyMode::Positive, None).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_missing_resolution() -> anyhow::Result<()> {
    run(ReplyMode::Missing, None).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_foreign_resolution() -> anyhow::Result<()> {
    run(ReplyMode::Foreign, None).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_stale_resolution() -> anyhow::Result<()> {
    run(ReplyMode::Stale, None).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_contradictory_resolution() -> anyhow::Result<()> {
    run(ReplyMode::Contradictory, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_caller_cancel() -> anyhow::Result<()> {
    run(ReplyMode::Positive, Some("cancel")).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_owner_answer() -> anyhow::Result<()> {
    run(ReplyMode::Positive, Some("answer")).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_owner_reject() -> anyhow::Result<()> {
    run(ReplyMode::Positive, Some("reject")).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_owner_answer_missing_decision() -> anyhow::Result<()> {
    run(ReplyMode::Positive, Some("answer_missing")).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_courier_native_owner_answer_foreign_decision() -> anyhow::Result<()> {
    run(ReplyMode::Positive, Some("answer_foreign")).await
}
