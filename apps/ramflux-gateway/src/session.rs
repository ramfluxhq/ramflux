// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

use crate::{
    GatewayQuicContext, GatewaySendHandle, GatewaySessionHub, GatewaySessionRuntime,
    NotifyHttpClient, RouterMeshClient, dispatch_quic_json_request, gateway_state,
    notify_offline_wake, router_cursor, router_get_json, router_inbox, router_post_json,
};

const DEFAULT_GATEWAY_RESUME_WINDOW_SECONDS: u64 = 300;

pub(crate) async fn handle_gateway_quic_connection(
    connection: quinn::Connection,
    router: RouterMeshClient,
    notify: NotifyHttpClient,
    state: Arc<Mutex<ramflux_node_core::GatewayState>>,
    store: Arc<ramflux_node_core::GatewayRedbStore>,
    hub: Arc<GatewaySessionHub>,
) {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let router = router.clone();
                let notify = notify.clone();
                let state = Arc::clone(&state);
                let store = Arc::clone(&store);
                let context = GatewayQuicContext {
                    router,
                    notify,
                    state,
                    store,
                    hub: Arc::clone(&hub),
                    remote_addr: connection.remote_address(),
                };
                tokio::spawn(async move {
                    if let Err(error) = handle_gateway_quic_stream(send, recv, context).await {
                        tracing::warn!(%error, "gateway QUIC stream failed");
                    }
                });
            }
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return,
            Err(error) => {
                tracing::warn!(%error, "gateway QUIC connection closed");
                return;
            }
        }
    }
}

pub(crate) async fn handle_gateway_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    context: GatewayQuicContext,
) -> anyhow::Result<()> {
    let first_frame: serde_json::Value = ramflux_transport::read_quic_json_frame(&mut recv).await?;
    if first_frame.get("frame_type").is_some() {
        let frame: ramflux_node_core::GatewayClientFrame = serde_json::from_value(first_frame)?;
        handle_gateway_session_stream(send, recv, context, frame).await?;
    } else {
        let request: ramflux_transport::GatewayQuicRequest = serde_json::from_value(first_frame)?;
        let response = dispatch_quic_json_request(&context.router, request)?;
        ramflux_transport::write_quic_json_frame(&mut send, &response).await?;
    }
    Ok(())
}

pub(crate) async fn handle_gateway_session_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    context: GatewayQuicContext,
    first_frame: ramflux_node_core::GatewayClientFrame,
) -> anyhow::Result<()> {
    handle_gateway_session_transport(Box::new(send), Box::new(recv), context, first_frame).await
}

pub(crate) async fn handle_gateway_tcp_tls_stream(
    stream: ramflux_transport::GatewayTcpTlsStream,
    context: GatewayQuicContext,
) -> anyhow::Result<()> {
    let (mut recv, send) = tokio::io::split(stream);
    let first_frame: serde_json::Value =
        ramflux_transport::read_gateway_session_json(&mut recv).await?;
    if first_frame.get("frame_type").is_some() {
        let frame: ramflux_node_core::GatewayClientFrame = serde_json::from_value(first_frame)?;
        handle_gateway_session_transport(Box::new(send), Box::new(recv), context, frame).await?;
    } else {
        let mut send = Box::new(send);
        let request: ramflux_transport::GatewayQuicRequest = serde_json::from_value(first_frame)?;
        let response = dispatch_quic_json_request(&context.router, request)?;
        ramflux_transport::write_gateway_session_json(&mut *send, &response).await?;
    }
    Ok(())
}

pub(crate) async fn handle_gateway_session_transport(
    mut send: Box<dyn ramflux_transport::GatewaySessionFrameSink + Send>,
    mut recv: Box<dyn ramflux_transport::GatewaySessionFrameSource + Send>,
    context: GatewayQuicContext,
    first_frame: ramflux_node_core::GatewayClientFrame,
) -> anyhow::Result<()> {
    let ramflux_node_core::GatewayClientFrame::Open { open } = first_frame else {
        write_gateway_frame(
            &mut *send,
            &ramflux_node_core::GatewayServerFrame::Nack {
                reason: "first gateway frame must be open".to_owned(),
            },
        )
        .await?;
        return Ok(());
    };
    match pre_auth_gate_for_gateway_open(&open, &context) {
        Ok(Some(challenge)) => {
            write_gateway_frame(
                &mut *send,
                &ramflux_node_core::GatewayServerFrame::Nack {
                    reason: format!("pre_auth_cookie_required:{}", challenge.pre_auth_cookie),
                },
            )
            .await?;
            return Ok(());
        }
        Ok(None) => {}
        Err(error) => {
            write_gateway_frame(
                &mut *send,
                &ramflux_node_core::GatewayServerFrame::Nack {
                    reason: format!("pre_auth_rejected:{error}"),
                },
            )
            .await?;
            return Ok(());
        }
    }

    let Some(auth_frame) = read_gateway_auth_frame(&mut *send, &mut *recv, &context).await? else {
        return Ok(());
    };

    let registered_auth_key: Option<ramflux_node_core::ItestMvp1DeviceAuthKeyResponse> =
        router_get_json(&context.router, &format!("/mvp1/device-auth-key/{}", open.device_id))?;
    let Some(registered_auth_key) = registered_auth_key else {
        write_gateway_frame(
            &mut *send,
            &ramflux_node_core::GatewayServerFrame::Nack {
                reason: format!("auth rejected: unregistered device {}", open.device_id),
            },
        )
        .await?;
        return Ok(());
    };

    let auth_now = i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX);
    let auth_result = {
        let mut gateway = gateway_state(&context.state)?;
        let result = ramflux_node_core::validate_gateway_auth_with_replay(
            &open,
            &auth_frame,
            auth_now,
            gateway.replay_guard_state_mut(),
            &registered_auth_key,
        );
        if result.is_ok() {
            context.store.save_state(&gateway)?;
        }
        result
    };
    if let Err(error) = auth_result {
        write_gateway_frame(
            &mut *send,
            &ramflux_node_core::GatewayServerFrame::Nack {
                reason: format!("auth rejected: {error}"),
            },
        )
        .await?;
        return Ok(());
    }

    let runtime = establish_gateway_session(&mut *send, &context, &open, &auth_frame).await?;
    let target_delivery_id = runtime.target_delivery_id.clone();
    let session_id = runtime.session_id.clone();
    let send: GatewaySendHandle = Arc::new(AsyncMutex::new(send));
    context.hub.register(target_delivery_id.clone(), session_id.clone(), Arc::clone(&send)).await;
    let result = run_gateway_session_loop(send, recv, context.clone(), runtime).await;
    context.hub.unregister(&target_delivery_id, &session_id).await;
    result
}

pub(crate) async fn read_gateway_auth_frame(
    send: &mut (impl ramflux_transport::GatewaySessionFrameSink + ?Sized),
    recv: &mut (impl ramflux_transport::GatewaySessionFrameSource + ?Sized),
    context: &GatewayQuicContext,
) -> anyhow::Result<Option<ramflux_node_core::GatewayAuthFrame>> {
    let read_timeout = gateway_state(&context.state)?.pre_auth_read_timeout();
    match tokio::time::timeout(
        read_timeout,
        ramflux_transport::read_gateway_session_json::<ramflux_node_core::GatewayClientFrame>(recv),
    )
    .await
    {
        Ok(Ok(ramflux_node_core::GatewayClientFrame::Auth { auth })) => Ok(Some(auth)),
        Ok(Ok(_other)) => {
            write_gateway_frame(
                send,
                &ramflux_node_core::GatewayServerFrame::Nack {
                    reason: "second gateway frame must be auth".to_owned(),
                },
            )
            .await?;
            Ok(None)
        }
        Ok(Err(error)) => Err(error.into()),
        Err(_elapsed) => {
            let mut gateway = gateway_state(&context.state)?;
            gateway.record_slowloris_timeout();
            context.store.save_state(&gateway)?;
            Ok(None)
        }
    }
}

pub(crate) async fn establish_gateway_session(
    send: &mut (impl ramflux_transport::GatewaySessionFrameSink + ?Sized),
    context: &GatewayQuicContext,
    open: &ramflux_node_core::GatewayOpenFrame,
    auth_frame: &ramflux_node_core::GatewayAuthFrame,
) -> anyhow::Result<GatewaySessionRuntime> {
    let now = ramflux_node_core::now_unix_seconds();
    let resume_window_seconds = gateway_resume_window_seconds();
    let session_id =
        match gateway_session_id_for_open(context, open, auth_frame, now, resume_window_seconds) {
            Some(session_id) => session_id,
            None => fresh_gateway_session_id(&open.device_id)?,
        };
    let descriptor = ramflux_node_core::SessionDescriptor {
        target_delivery_id: open.target_delivery_id.clone(),
        device_id: open.device_id.clone(),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: session_id.clone(),
        device_epoch: auth_frame.device_proof.device_epoch,
        session_seq: now,
        last_cursor: open.last_seen_inbox_seq.map(|seq| format!("inbox_seq:{seq}")),
        push_alias_hash: None,
        lifecycle: ramflux_node_core::SessionLifecycle::Live,
    };
    let _: ramflux_node_core::SessionDescriptor =
        router_post_json(&context.router, "/s1/session/upsert", &descriptor)?;
    let resume_token = {
        let mut gateway = gateway_state(&context.state)?;
        let resume = gateway.issue_resume_token(ramflux_node_core::GatewayResumeIssueInput {
            session_id: &session_id,
            target_delivery_id: &open.target_delivery_id,
            device_id: &open.device_id,
            device_epoch: auth_frame.device_proof.device_epoch,
            issued_at: now,
            window_seconds: resume_window_seconds,
        });
        gateway.open_session(ramflux_node_core::GatewaySession {
            session_id: session_id.clone(),
            target_delivery_id: open.target_delivery_id.clone(),
            device_id: open.device_id.clone(),
            opened_at: now,
            last_heartbeat_at: now,
            lifecycle: ramflux_node_core::GatewaySessionLifecycle::Live,
        });
        context.store.save_state(&gateway)?;
        resume.token
    };
    let accepted_cursor = router_cursor(&context.router, &open.target_delivery_id)?;
    write_gateway_frame(
        send,
        &ramflux_node_core::GatewayServerFrame::SessionEstablished {
            session: ramflux_node_core::GatewaySessionEstablishedFrame {
                session_id: session_id.clone(),
                gateway_id: "ramflux-gateway".to_owned(),
                accepted_cursor,
                resume_token: resume_token.clone(),
                resume_window_seconds,
            },
        },
    )
    .await?;
    Ok(GatewaySessionRuntime {
        session_id,
        resume_token,
        target_delivery_id: open.target_delivery_id.clone(),
    })
}

fn gateway_session_id_for_open(
    context: &GatewayQuicContext,
    open: &ramflux_node_core::GatewayOpenFrame,
    auth_frame: &ramflux_node_core::GatewayAuthFrame,
    now: u64,
    resume_window_seconds: u64,
) -> Option<String> {
    let previous_session_id = open.previous_session_id.as_deref()?;
    let resume_token_hash = open.resume_token_hash.as_deref()?;
    let mut gateway = gateway_state(&context.state).ok()?;
    let metadata =
        gateway.validate_resume_token_hash(ramflux_node_core::GatewayResumeValidateInput {
            resume_token_hash,
            previous_session_id,
            target_delivery_id: &open.target_delivery_id,
            device_id: &open.device_id,
            device_epoch: auth_frame.device_proof.device_epoch,
            now,
            window_seconds: resume_window_seconds,
        })?;
    tracing::debug!(
        session_id = metadata.session_id,
        target_delivery_id = metadata.target_delivery_id,
        "gateway session resume token accepted"
    );
    Some(metadata.session_id)
}

fn gateway_resume_window_seconds() -> u64 {
    std::env::var("RAMFLUX_GATEWAY_RESUME_WINDOW_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_GATEWAY_RESUME_WINDOW_SECONDS)
}

fn fresh_gateway_session_id(device_id: &str) -> anyhow::Result<String> {
    let random = ramflux_crypto::random_32()?;
    let nonce = ramflux_protocol::encode_base64url(&random[..16]);
    Ok(format!("s1_{}_{}_{}", device_id, ramflux_node_core::now_unix_seconds(), nonce))
}

pub(crate) async fn run_gateway_session_loop(
    send: GatewaySendHandle,
    mut recv: Box<dyn ramflux_transport::GatewaySessionFrameSource + Send>,
    context: GatewayQuicContext,
    runtime: GatewaySessionRuntime,
) -> anyhow::Result<()> {
    loop {
        let frame = match ramflux_transport::read_gateway_session_json::<
            ramflux_node_core::GatewayClientFrame,
        >(&mut *recv)
        .await
        {
            Ok(frame) => frame,
            Err(error) => {
                tracing::debug!(%error, "gateway session read ended");
                return Ok(());
            }
        };
        match frame {
            ramflux_node_core::GatewayClientFrame::Submit { submit } => {
                handle_gateway_submit(&send, &context, &runtime, &submit).await?;
            }
            ramflux_node_core::GatewayClientFrame::IdentityRegister { mut request } => {
                request.source_ip_hash =
                    request.source_ip_hash.or_else(|| Some(context.remote_addr.ip().to_string()));
                let response: ramflux_node_core::ItestMvp1IdentityRegistrationResponse =
                    router_post_json(&context.router, "/mvp1/identity/register", &request)?;
                write_gateway_handle(
                    &send,
                    &ramflux_node_core::GatewayServerFrame::IdentityRegistered { response },
                )
                .await?;
            }
            ramflux_node_core::GatewayClientFrame::PrekeyPublish { request } => {
                let response: ramflux_node_core::ItestMvp1PrekeyResponse =
                    router_post_json(&context.router, "/mvp1/prekey/publish", &request)?;
                write_gateway_handle(
                    &send,
                    &ramflux_node_core::GatewayServerFrame::PrekeyPublished { response },
                )
                .await?;
            }
            ramflux_node_core::GatewayClientFrame::PrekeyFetch { device_id } => {
                let response: ramflux_node_core::ItestMvp1PrekeyResponse =
                    router_get_json(&context.router, &format!("/mvp1/prekey/{device_id}"))?;
                write_gateway_handle(
                    &send,
                    &ramflux_node_core::GatewayServerFrame::Prekey { response },
                )
                .await?;
            }
            ramflux_node_core::GatewayClientFrame::Ack { ack } => {
                handle_gateway_ack(&send, &context, &runtime, &ack).await?;
            }
            ramflux_node_core::GatewayClientFrame::Cursor { target_delivery_id } => {
                let cursor = router_cursor(&context.router, &target_delivery_id)?;
                write_gateway_handle(
                    &send,
                    &ramflux_node_core::GatewayServerFrame::Cursor { cursor },
                )
                .await?;
            }
            ramflux_node_core::GatewayClientFrame::Resume { resume } => {
                handle_gateway_resume(&send, &context, &runtime, &resume).await?;
            }
            ramflux_node_core::GatewayClientFrame::Nack { nack } => {
                handle_gateway_nack(&send, &context, &runtime, &nack).await?;
            }
            ramflux_node_core::GatewayClientFrame::Heartbeat { now } => {
                write_gateway_handle(
                    &send,
                    &ramflux_node_core::GatewayServerFrame::Heartbeat { now },
                )
                .await?;
            }
            ramflux_node_core::GatewayClientFrame::Close { reason } => {
                handle_gateway_close(&send, &context, &runtime, reason).await?;
                return Ok(());
            }
            ramflux_node_core::GatewayClientFrame::Open { .. }
            | ramflux_node_core::GatewayClientFrame::Auth { .. } => {
                write_gateway_handle(
                    &send,
                    &ramflux_node_core::GatewayServerFrame::Nack {
                        reason: "unexpected gateway session frame".to_owned(),
                    },
                )
                .await?;
            }
        }
    }
}

pub(crate) async fn handle_gateway_submit(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<()> {
    let submit_now = i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX);
    let replay_rejection = {
        let mut gateway = gateway_state(&context.state)?;
        let result = gateway
            .replay_guard_state_mut()
            .check_signed_request(&submit.signed_request, submit_now);
        let rejection = result.err().map(|error| format!("submit replay rejected: {error}"));
        context.store.save_state(&gateway)?;
        rejection
    };
    if let Some(reason) = replay_rejection {
        write_gateway_handle(send, &ramflux_node_core::GatewayServerFrame::Nack { reason }).await?;
        return Ok(());
    }
    let response: ramflux_node_core::ItestMvp0SubmitResponse =
        router_post_json(&context.router, "/mvp0/envelope", &submit.envelope)?;
    if response.outcome.starts_with("rejected_") {
        write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack { reason: response.outcome.clone() },
        )
        .await?;
        return Ok(());
    }
    let after = response.inbox_seq.unwrap_or(1).saturating_sub(1);
    let inbox = router_inbox(&context.router, &response.target_delivery_id, after, 1)?;
    let Some(entry) = inbox.entries.into_iter().next() else {
        return Err(anyhow::anyhow!(
            "gateway submit did not find inbox entry for {} after seq {}",
            response.target_delivery_id,
            after
        ));
    };
    let frame = ramflux_node_core::GatewayServerFrame::Deliver { entry };
    write_gateway_handle(send, &frame).await?;
    if response.outcome == "offline_queued" {
        let notify = context.notify.clone();
        let target_delivery_id = response.target_delivery_id.clone();
        let envelope = submit.envelope.clone();
        match tokio::task::spawn_blocking(move || {
            notify_offline_wake(&notify, &target_delivery_id, &envelope)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "offline notify wake dispatch failed");
            }
            Err(error) => {
                tracing::warn!(%error, "offline notify wake task failed");
            }
        }
        write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::InBandWake {
                target_delivery_id: response.target_delivery_id.clone(),
                delivery_class: ramflux_protocol::DeliveryClass::NotificationWake,
            },
        )
        .await?;
    }
    if response.outcome == "online" && response.target_delivery_id != runtime.target_delivery_id {
        let _sent = context.hub.send_to(&response.target_delivery_id, &frame).await?;
    }
    Ok(())
}

pub(crate) async fn handle_gateway_ack(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    ack: &ramflux_protocol::Ack,
) -> anyhow::Result<()> {
    let request = ramflux_node_core::ItestMvp0BoundAckRequest {
        target_delivery_id: runtime.target_delivery_id.clone(),
        ack: ack.clone(),
    };
    let cursor: ramflux_node_core::ItestMvp0CursorResponse =
        match router_post_json(&context.router, "/mvp0/ack-bound", &request) {
            Ok(cursor) => cursor,
            Err(error) => {
                write_gateway_handle(
                    send,
                    &ramflux_node_core::GatewayServerFrame::Nack {
                        reason: format!("ack rejected: {error}"),
                    },
                )
                .await?;
                return Ok(());
            }
        };
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Ack { cursor: cursor.clone() },
    )
    .await?;
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Cursor { cursor: Some(cursor) },
    )
    .await
}

pub(crate) async fn handle_gateway_nack(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    nack: &ramflux_protocol::Nack,
) -> anyhow::Result<()> {
    let request = ramflux_node_core::ItestMvp0BoundNackRequest {
        target_delivery_id: runtime.target_delivery_id.clone(),
        nack: nack.clone(),
    };
    let cursor: ramflux_node_core::ItestMvp0CursorResponse =
        match router_post_json(&context.router, "/mvp0/nack-bound", &request) {
            Ok(cursor) => cursor,
            Err(error) => {
                write_gateway_handle(
                    send,
                    &ramflux_node_core::GatewayServerFrame::Nack {
                        reason: format!("nack rejected: {error}"),
                    },
                )
                .await?;
                return Ok(());
            }
        };
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Cursor { cursor: Some(cursor) },
    )
    .await
}

pub(crate) async fn handle_gateway_resume(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    resume: &ramflux_node_core::GatewayResumeFrame,
) -> anyhow::Result<()> {
    if resume.resume_token != runtime.resume_token {
        write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack {
                reason: "invalid resume token".to_owned(),
            },
        )
        .await?;
        return Ok(());
    }
    let inbox = router_inbox(
        &context.router,
        &resume.target_delivery_id,
        resume.after_inbox_seq,
        resume.limit,
    )?;
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Resume { entries: inbox.entries },
    )
    .await
}

pub(crate) async fn handle_gateway_close(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    reason: String,
) -> anyhow::Result<()> {
    {
        let mut gateway = gateway_state(&context.state)?;
        gateway.drain(&runtime.session_id)?;
        context.store.save_state(&gateway)?;
    }
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Drain {
            session_id: runtime.session_id.clone(),
            reason: format!("client_close:{reason}"),
        },
    )
    .await?;
    write_gateway_handle(send, &ramflux_node_core::GatewayServerFrame::Close { reason }).await?;
    let mut send = send.lock().await;
    ramflux_transport::GatewaySessionFrameSink::finish(&mut **send)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}

pub(crate) async fn write_gateway_handle(
    send: &GatewaySendHandle,
    frame: &ramflux_node_core::GatewayServerFrame,
) -> anyhow::Result<()> {
    let mut send = send.lock().await;
    write_gateway_frame(&mut **send, frame).await
}

pub(crate) async fn write_gateway_frame(
    send: &mut (impl ramflux_transport::GatewaySessionFrameSink + ?Sized),
    frame: &ramflux_node_core::GatewayServerFrame,
) -> anyhow::Result<()> {
    #[cfg(feature = "itest-http")]
    delay_itest_gateway_frame().await;
    ramflux_transport::write_gateway_session_json(send, frame).await?;
    Ok(())
}

#[cfg(feature = "itest-http")]
async fn delay_itest_gateway_frame() {
    if let Ok(delay_ms) = std::env::var("RAMFLUX_ITEST_GATEWAY_FRAME_DELAY_MS")
        && let Ok(delay_ms) = delay_ms.parse::<u64>()
        && delay_ms > 0
    {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
}

pub(crate) fn pre_auth_gate_for_gateway_open(
    open: &ramflux_node_core::GatewayOpenFrame,
    context: &GatewayQuicContext,
) -> anyhow::Result<Option<ramflux_node_core::GatewayPreAuthChallengeResponse>> {
    let source_ip_hash =
        open.source_ip_hash.clone().unwrap_or_else(|| context.remote_addr.ip().to_string());
    let now = open.pre_auth_now.unwrap_or_else(ramflux_node_core::now_unix_seconds);
    let mut gateway = gateway_state(&context.state)?;
    let decision =
        match gateway.check_pre_auth(&source_ip_hash, open.pre_auth_cookie.as_deref(), now) {
            Ok(decision) => decision,
            Err(error) => {
                context.store.save_state(&gateway)?;
                return Err(error.into());
            }
        };
    context.store.save_state(&gateway)?;
    Ok(match decision {
        ramflux_node_core::GatewayPreAuthDecision::Accepted => None,
        ramflux_node_core::GatewayPreAuthDecision::Challenge(challenge) => Some(challenge),
    })
}

#[cfg(test)]
mod tests {
    use super::fresh_gateway_session_id;

    #[test]
    fn fresh_gateway_session_id_has_session_level_entropy() -> anyhow::Result<()> {
        let first = fresh_gateway_session_id("device_test")?;
        let second = fresh_gateway_session_id("device_test")?;

        assert!(first.starts_with("s1_device_test_"));
        assert!(second.starts_with("s1_device_test_"));
        assert_ne!(first, second);
        assert!(first.rsplit_once('_').is_some_and(|(_prefix, nonce)| !nonce.is_empty()));
        Ok(())
    }
}
