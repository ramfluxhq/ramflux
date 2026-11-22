// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Renew a live native custody grant, or end the session with the real reason.

use ramflux_protocol::custody::{
    CUSTODY_RPC_PATH, CustodyMeshRequest, CustodyServerFrame, CustodySession,
};

use crate::custody::GatewayGrant;
use crate::state::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};

pub(crate) async fn wait_native_grant(grant: Option<&GatewayGrant>) {
    if let Some(grant) = grant {
        tokio::time::sleep_until(tokio::time::Instant::from_std(grant.deadline())).await;
    } else {
        std::future::pending::<()>().await;
    }
}

pub(crate) async fn close_native_grant(
    send: &GatewaySendHandle,
    reason: &str,
) -> anyhow::Result<()> {
    crate::session::write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Close { reason: reason.to_owned() },
    )
    .await?;
    let mut sink = send.lock().await;
    ramflux_transport::GatewaySessionFrameSink::finish(&mut **sink)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}

/// Returns true when the session must end.
/// # Errors
/// Returns an error when the refusal or the renewal reply cannot be written.
pub(crate) async fn refuse_stale_native(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    grant: Option<&GatewayGrant>,
    frame: &ramflux_node_core::GatewayClientFrame,
) -> anyhow::Result<bool> {
    if matches!(frame, ramflux_node_core::GatewayClientFrame::GrantRenew) {
        return Ok(false);
    }
    let Some(grant) = grant else { return Ok(false) };
    if let Err(error) = crate::session::validate_native_frame(context, runtime, grant, frame).await
    {
        tracing::debug!(%error, "native session authority no longer permits request");
        crate::session::write_gateway_handle(send, &stale_native_response(frame)).await?;
        return Ok(true);
    }
    Ok(false)
}

fn stale_native_response(
    frame: &ramflux_node_core::GatewayClientFrame,
) -> ramflux_node_core::GatewayServerFrame {
    if matches!(frame, ramflux_node_core::GatewayClientFrame::VoiceLease { .. }) {
        ramflux_node_core::GatewayServerFrame::VoiceLease {
            response: Box::new(ramflux_protocol::VoiceLeaseResponse::Refused {
                reason: ramflux_protocol::VoiceCallFailureReason::AuthorityRefused,
            }),
        }
    } else {
        ramflux_node_core::GatewayServerFrame::Nack {
            reason: "native_session_authority_refused".into(),
        }
    }
}

/// Returns true when the session must end.
/// # Errors
/// Returns an error when the router call or the client write fails.
pub(crate) async fn apply_native_renewal(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    native: Option<&mut GatewayGrant>,
) -> anyhow::Result<bool> {
    let Some(grant) = native else {
        nack_unexpected(send).await?;
        return Ok(false);
    };
    if !grant.live(ramflux_node_core::now_unix_seconds()) {
        close_native_grant(send, "grant_expired").await?;
        return Ok(true);
    }
    if let Some(session) = request_native_renewal(context, grant).await? {
        let expires_at = session.expires_at;
        grant.replace_renewed(session);
        crate::session::write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::GrantRenewed { expires_at },
        )
        .await?;
        Ok(false)
    } else {
        close_native_grant(send, "renewal_refused").await?;
        Ok(true)
    }
}

async fn request_native_renewal(
    context: &GatewayQuicContext,
    grant: &GatewayGrant,
) -> anyhow::Result<Option<CustodySession>> {
    let request = CustodyMeshRequest::RenewNativeSession {
        session_id: grant.session().session_id.clone(),
        connection_id: grant.connection_id().to_owned(),
    };
    let frame = crate::router_post_json_async::<_, CustodyServerFrame>(
        &context.router,
        CUSTODY_RPC_PATH,
        &request,
    )
    .await?;
    Ok(accepted_renewal(grant.session().session_id.as_str(), frame))
}

fn accepted_renewal(session_id: &str, frame: CustodyServerFrame) -> Option<CustodySession> {
    match frame {
        CustodyServerFrame::SessionEstablished { session } if session.session_id == session_id => {
            Some(session)
        }
        _ => None,
    }
}

async fn nack_unexpected(send: &GatewaySendHandle) -> anyhow::Result<()> {
    crate::session::write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Nack {
            reason: "unexpected gateway session frame".to_owned(),
        },
    )
    .await
}
