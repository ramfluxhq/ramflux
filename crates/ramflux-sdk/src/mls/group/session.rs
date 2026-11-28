// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anonymous group socket. The first frame is `GroupOpen` or `GroupIdent`. No `Open`, no `Auth`.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

use crate::gateway::{GatewayClientFrame, GatewayServerFrame, GatewaySessionConfig, GroupHostReply};
use crate::SdkError;

use super::host::{b64, b64_bytes, fail};

static LIVE: Mutex<BTreeSet<[u8; 32]>> = Mutex::new(BTreeSet::new());

pub(crate) struct GroupSocket {
    _transport: crate::gateway::engine::GatewaySessionClientTransport,
    stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    group_id: [u8; 32],
    member: bool,
    seq: u64,
    pub(crate) last_log_seq: Option<u64>,
}

pub(crate) fn member_live(group_id: &[u8; 32]) -> bool {
    LIVE.lock().is_ok_and(|live| live.contains(group_id))
}

fn reserve(group_id: &[u8; 32]) -> Result<(), SdkError> {
    let mut live = LIVE.lock().map_err(|_| fail("internal", "member session set"))?;
    if !live.insert(*group_id) {
        return Err(fail("already_open", "a member session is already live"));
    }
    Ok(())
}

fn release(group_id: &[u8; 32]) {
    if let Ok(mut live) = LIVE.lock() {
        live.remove(group_id);
    }
}

impl Drop for GroupSocket {
    fn drop(&mut self) {
        if self.member {
            release(&self.group_id);
        }
    }
}

pub(crate) async fn open(
    endpoint: &str,
    data_root: &Path,
    first: GatewayClientFrame,
    group_id: [u8; 32],
    member: bool,
) -> Result<GroupSocket, SdkError> {
    if member {
        reserve(&group_id)?;
    }
    match open_inner(endpoint, data_root, first, group_id, member).await {
        Ok(socket) => Ok(socket),
        Err(error) => {
            if member {
                release(&group_id);
            }
            Err(error)
        }
    }
}

async fn open_inner(
    endpoint: &str,
    data_root: &Path,
    first: GatewayClientFrame,
    group_id: [u8; 32],
    member: bool,
) -> Result<GroupSocket, SdkError> {
    let record = crate::node::fetch_client_record(endpoint).await?;
    let profile = crate::node::NodeProfile::from_record(record, 0);
    let quic = profile
        .gateway_config(
            data_root,
            crate::gateway::GatewayQuicEndpointConfig {
                bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                gateway_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 9)),
                server_name: String::new(),
                ca_cert: data_root.join("group-ca-unused.pem"),
                principal_id: String::new(),
                device_id: String::new(),
                target_delivery_id: String::new(),
                prekey_http_url: None,
            },
        )
        .await?;
    let mut config = GatewaySessionConfig::quic(quic);
    config.timeout = std::time::Duration::from_secs(60);
    let (transport, mut stream, _kind) =
        crate::gateway::engine::open_gateway_session_transport(&config).await?;
    crate::gateway::engine::write_gateway_client_frame(&mut *stream, &first).await?;
    let opened = read_opened(&mut *stream).await?;
    if opened != "ok" {
        return Err(fail(status_code(&opened), opened));
    }
    let mut socket = GroupSocket {
        _transport: transport,
        stream,
        group_id,
        member,
        seq: 0,
        last_log_seq: None,
    };
    if member {
        let reply = socket.call("subscribe", &[]).await?;
        if reply.status != "ok" {
            return Err(fail(status_code(&reply.status), reply.status));
        }
    }
    Ok(socket)
}

async fn read_opened(
    stream: &mut (dyn ramflux_transport::GatewaySessionTransport + Send),
) -> Result<String, SdkError> {
    loop {
        let (frame, _bytes) =
            crate::gateway::engine::read_gateway_server_frame_bytes(&mut *stream).await?;
        match frame {
            GatewayServerFrame::GroupOpened { status } => return Ok(status),
            GatewayServerFrame::Nack { reason } | GatewayServerFrame::Close { reason } => {
                return Err(fail("internal", reason));
            }
            _ => {}
        }
    }
}

impl GroupSocket {
    pub(crate) async fn call(&mut self, op: &str, body: &[u8]) -> Result<GroupHostReply, SdkError> {
        self.seq = self.seq.saturating_add(1);
        let request_id = format!("{:016x}", self.seq);
        let frame = GatewayClientFrame::Group {
            request_id: request_id.clone(),
            op: op.to_owned(),
            body: if body.is_empty() { String::new() } else { b64(body) },
        };
        crate::gateway::engine::write_gateway_client_frame(&mut *self.stream, &frame).await?;
        loop {
            let (frame, _bytes) =
                crate::gateway::engine::read_gateway_server_frame_bytes(&mut *self.stream).await?;
            match frame {
                GatewayServerFrame::GroupReply { request_id: got, reply } if got == request_id => {
                    return Ok(reply);
                }
                GatewayServerFrame::GroupLogGrew { log_seq } => {
                    self.last_log_seq = Some(log_seq);
                }
                GatewayServerFrame::Nack { reason } | GatewayServerFrame::Close { reason } => {
                    return Err(fail("internal", reason));
                }
                _ => {}
            }
        }
    }

    pub(crate) fn group_id(&self) -> &[u8; 32] {
        &self.group_id
    }
}

pub(crate) fn status_code(status: &str) -> &'static str {
    match status {
        "ok" => "ok",
        "not_found" => "not_found",
        "invite_invalid" => "invite_invalid",
        "join_key_stale" => "join_key_stale",
        "join_rate_limited" => "join_rate_limited",
        "already_joined" => "already_member",
        "pending_full" => "queue_full",
        "leaf_cap" => "group_full",
        "quota" | "paced" => "rate_limited",
        "bad_request" => "bad_request",
        "unauthorized" => "unauthorized",
        _ => "internal",
    }
}

pub(crate) fn reply_bytes(reply: &GroupHostReply) -> Result<Vec<u8>, SdkError> {
    if reply.body.is_empty() {
        Ok(Vec::new())
    } else {
        b64_bytes(&reply.body)
    }
}

static HELD: tokio::sync::Mutex<std::collections::BTreeMap<[u8; 32], GroupSocket>> =
    tokio::sync::Mutex::const_new(std::collections::BTreeMap::new());

/// One member-session operation. Reuses the live socket, so a second read does not spend an open
/// token. `open_frame` runs only when no socket is held.
pub(crate) async fn member_op<F, Fut>(
    endpoint: &str,
    data_root: &Path,
    group_id: [u8; 32],
    op: &str,
    body: &[u8],
    open_frame: F,
) -> Result<GroupHostReply, SdkError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<GatewayClientFrame, SdkError>>,
{
    let mut held = HELD.lock().await;
    if let Some(socket) = held.get_mut(&group_id) {
        match socket.call(op, body).await {
            Ok(reply) => return Ok(reply),
            Err(_error) => {
                held.remove(&group_id);
            }
        }
    }
    let first = open_frame().await?;
    let socket = open(endpoint, data_root, first, group_id, true).await?;
    let socket = held.entry(group_id).or_insert(socket);
    socket.call(op, body).await
}

pub(crate) async fn ident_call(
    endpoint: &str,
    data_root: &Path,
    group_id: [u8; 32],
    op: &str,
    body: &[u8],
) -> Result<GroupHostReply, SdkError> {
    let mut socket = open(
        endpoint,
        data_root,
        GatewayClientFrame::GroupIdent { group_id: b64(&group_id) },
        group_id,
        false,
    )
    .await?;
    socket.call(op, body).await
}
