// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anonymous direct group sessions (MLS-SPEC r1.2 2.1, 5). A `member` session opens with
//! `GroupOpen` (one `open` token), an `ident` session with `GroupIdent` (one signed or
//! invite-authorised op). Neither carries an account, a device or a session id, and the device
//! authorisation of the DM frames (`mls_dm.rs`) is never called here.
//!
//! The gateway keeps only the session kind, the group, the 32 MiB upload reservation and a
//! subscribe cursor in this task's memory, plus the per-source counters of `group_gate`. Calls to
//! the router carry the kind, the group and the op body, nothing about the source. This module
//! writes no log line and no trace event: no source key, address, session id or op can reach one.
use std::time::Duration;

use ramflux_node_core::{
    GROUP_BODY_B64_MAX, GROUP_HOST_ROUTER_PATH, GatewayClientFrame as Client,
    GatewayServerFrame as Server, GroupDirectKind, GroupHostCall, GroupHostReply, UploadCap,
};
use ramflux_transport::TransportError;

use crate::group_gate::{SourceGuard, gate, now_ms};
use crate::session::write_gateway_frame;
use crate::state::GatewayQuicContext;

type Sink = Box<dyn ramflux_transport::GatewaySessionFrameSink + Send>;
type Source = Box<dyn ramflux_transport::GatewaySessionFrameSource + Send>;

/// A member session with no frame for this long is closed.
const MEMBER_IDLE: Duration = Duration::from_secs(300);
/// An ident session must send its one op within this time.
const IDENT_WAIT: Duration = Duration::from_secs(10);
/// How often a subscribed member session asks the host whether the log grew.
const SUBSCRIBE_POLL: Duration = Duration::from_secs(3);
/// Longest echoed request id.
const REQUEST_ID_MAX: usize = 64;
/// Largest frame (the transport's complete-frame bound).
const FRAME_MAX: usize = ramflux_protocol::message::outer::MAX_COMPLETE_FRAME_BYTES;

/// Whether `frame` starts a group session.
pub(crate) fn starts_direct_group(frame: &Client) -> bool {
    matches!(frame, Client::GroupOpen { .. } | Client::GroupIdent { .. })
}

struct State {
    kind: GroupDirectKind,
    group_id: String,
    uploads: UploadCap,
    subscribed: Option<u64>,
}

/// Runs one group session from its first frame to its end.
///
/// # Errors
/// Only a failed write to the client.
pub(crate) async fn run(
    mut send: Sink,
    mut recv: Source,
    context: GatewayQuicContext,
    first: Client,
) -> anyhow::Result<()> {
    let source = crate::pre_auth::source_key(context.remote_addr.ip());
    let guard = match gate().begin(&source, now_ms()) {
        Ok(guard) => guard,
        Err(status) => {
            return write_gateway_frame(&mut *send, &Server::GroupOpened { status: status.into() })
                .await;
        }
    };
    drop(source);
    let Some(mut state) = open(&mut *send, &context, first).await? else {
        return Ok(());
    };
    let ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + SUBSCRIBE_POLL, SUBSCRIBE_POLL);
    serve(&mut send, &mut recv, &context, &mut state, &guard, ticker).await
}

async fn open(
    send: &mut (dyn ramflux_transport::GatewaySessionFrameSink + Send),
    context: &GatewayQuicContext,
    first: Client,
) -> anyhow::Result<Option<State>> {
    let (kind, group_id, status) = match first {
        Client::GroupOpen { group_id, open_token, nonce } => {
            let parts = (
                ramflux_node_core::group_decode_b64::<32>(&group_id),
                ramflux_node_core::group_decode_b64::<32>(&nonce),
                ramflux_node_core::group_decode_b64::<68>(&open_token),
            );
            let status = if let (Some(_), Some(nonce), Some(token)) = parts {
                let mut body = nonce.to_vec();
                body.extend_from_slice(&token);
                let body = ramflux_protocol::encode_base64url(&body);
                call(context, GroupDirectKind::Member, &group_id, "open", body).await.status
            } else {
                "bad_request".to_owned()
            };
            (GroupDirectKind::Member, group_id, status)
        }
        Client::GroupIdent { group_id } => {
            let status = if ramflux_node_core::group_decode_b64::<32>(&group_id).is_some() {
                "ok"
            } else {
                "bad_request"
            };
            (GroupDirectKind::Ident, group_id, status.to_owned())
        }
        _ => return Ok(None),
    };
    let opened = status == "ok";
    write_gateway_frame(send, &Server::GroupOpened { status }).await?;
    Ok(opened.then_some(State { kind, group_id, uploads: UploadCap::default(), subscribed: None }))
}

async fn serve(
    send: &mut Sink,
    recv: &mut Source,
    context: &GatewayQuicContext,
    state: &mut State,
    guard: &SourceGuard,
    mut ticker: tokio::time::Interval,
) -> anyhow::Result<()> {
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let wait = match state.kind {
        GroupDirectKind::Member => MEMBER_IDLE,
        GroupDirectKind::Ident => IDENT_WAIT,
    };
    loop {
        let deadline = tokio::time::Instant::now() + wait;
        let incoming = recv.recv_frame();
        tokio::pin!(incoming);
        let bytes = loop {
            tokio::select! {
                read = tokio::time::timeout_at(deadline, &mut incoming) => match read {
                    Ok(Ok(bytes)) => break bytes,
                    _ => return Ok(()),
                },
                _ = ticker.tick(), if state.subscribed.is_some() => {
                    poll(send, context, state).await?;
                }
            }
        };
        let Some(_request) = ramflux_node_core::begin_service_request() else {
            return Ok(());
        };
        let parsed = if bytes.len() > FRAME_MAX {
            None
        } else {
            ramflux_protocol::parse_i_json::<Client>(&bytes).ok()
        };
        let Some(Client::Group { request_id, op, body }) = parsed else {
            let reason = "group_direct_frame_invalid".to_owned();
            return write_gateway_frame(&mut **send, &Server::Nack { reason }).await;
        };
        if request_id.len() > REQUEST_ID_MAX {
            let reason = "group_direct_frame_invalid".to_owned();
            return write_gateway_frame(&mut **send, &Server::Nack { reason }).await;
        }
        let reply = answer(context, state, guard, &op, body).await;
        write_gateway_frame(&mut **send, &Server::GroupReply { request_id, reply }).await?;
        if state.kind == GroupDirectKind::Ident {
            return Ok(());
        }
    }
}

/// One frame op: the session split, the size, the per-source count, the upload reservation, then
/// the router.
async fn answer(
    context: &GatewayQuicContext,
    state: &mut State,
    guard: &SourceGuard,
    op: &str,
    body: String,
) -> GroupHostReply {
    if !ramflux_node_core::group_frame_op_allowed(state.kind, op) {
        return GroupHostReply::status("session_scope");
    }
    if body.len() > GROUP_BODY_B64_MAX {
        return GroupHostReply::status("bad_request");
    }
    if !guard.allow_op(now_ms()) {
        return GroupHostReply::status("rate_limited");
    }
    match op {
        "subscribe" => {
            let reply = call(context, state.kind, &state.group_id, "status", String::new()).await;
            if reply.status == "ok" {
                state.subscribed = Some(log_seq(&reply).unwrap_or(0));
            }
            reply
        }
        "blob.put" => blob_put(context, state, body).await,
        _ => call(context, state.kind, &state.group_id, op, body).await,
    }
}

/// Chunk 0 reserves its declared bytes against the session cap; later chunks must belong to an
/// upload this session began.
async fn blob_put(context: &GatewayQuicContext, state: &mut State, body: String) -> GroupHostReply {
    let Some(head) = ramflux_node_core::group_decode_body(&body)
        .and_then(|bytes| ramflux_node_core::group_blob_put_head(&bytes))
    else {
        return GroupHostReply::status("bad_request");
    };
    if head.idx == 0 {
        if !state.uploads.begin(head.blob_ref, head.total_bytes) {
            return GroupHostReply::status("upload_cap");
        }
    } else if !state.uploads.holds(&head.blob_ref) {
        return GroupHostReply::status("blob_bad");
    }
    let reply = call(context, state.kind, &state.group_id, "blob.put", body).await;
    let complete = reply_bytes(&reply).and_then(|bytes| bytes.get(4).copied()) == Some(1);
    if reply.status != "ok" || complete {
        state.uploads.finish(&head.blob_ref);
    }
    reply
}

/// Tells a subscribed session the log grew (the client reads to fetch the entries).
async fn poll(
    send: &mut Sink,
    context: &GatewayQuicContext,
    state: &mut State,
) -> anyhow::Result<()> {
    let reply = call(context, state.kind, &state.group_id, "status", String::new()).await;
    let (Some(seen), Some(now)) = (state.subscribed, log_seq(&reply)) else {
        return Ok(());
    };
    if now > seen {
        state.subscribed = Some(now);
        write_gateway_frame(&mut **send, &Server::GroupLogGrew { log_seq: now }).await?;
    }
    Ok(())
}

fn reply_bytes(reply: &GroupHostReply) -> Option<Vec<u8>> {
    ramflux_protocol::decode_base64url(&reply.body).ok()
}

/// `log_seq` of a `status` reply (`epoch u64, log_seq u64, ...`).
fn log_seq(reply: &GroupHostReply) -> Option<u64> {
    if reply.status != "ok" {
        return None;
    }
    let bytes = reply_bytes(reply)?;
    Some(u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?))
}

async fn call(
    context: &GatewayQuicContext,
    session: GroupDirectKind,
    group_id: &str,
    op: &str,
    body: String,
) -> GroupHostReply {
    let call = GroupHostCall { session, group_id: group_id.to_owned(), op: op.to_owned(), body };
    match crate::router_post_json_async::<_, GroupHostReply>(
        &context.router,
        GROUP_HOST_ROUTER_PATH,
        &call,
    )
    .await
    {
        Ok(reply) => reply,
        Err(TransportError::HttpStatus { status: 503, .. }) => {
            GroupHostReply::status("unavailable")
        }
        Err(_) => GroupHostReply::status("internal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reply_yields_the_log_sequence_only_when_ok() {
        let mut body = vec![0_u8; 8];
        body.extend(77_u64.to_be_bytes());
        body.extend([0_u8; 20]);
        let reply = GroupHostReply::ok(&body);
        assert_eq!(log_seq(&reply), Some(77));
        assert_eq!(log_seq(&GroupHostReply::status("not_found")), None);
        assert_eq!(log_seq(&GroupHostReply::ok(&[1, 2, 3])), None);
    }

    #[test]
    fn only_the_two_opening_frames_start_a_direct_group() {
        let ident = Client::GroupIdent { group_id: String::new() };
        let op =
            Client::Group { request_id: String::new(), op: "read".into(), body: String::new() };
        assert!(starts_direct_group(&ident));
        assert!(!starts_direct_group(&op));
        assert!(!starts_direct_group(&Client::KeyPackageStatus {}));
    }
}
