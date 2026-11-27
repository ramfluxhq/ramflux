// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large-group requests on a gateway session (`LargeGroup` frame).
//!
//! The session only carries the request. The host authenticates it by the pseudonym signatures
//! inside the body and is never given the session, device, principal or source identity, so none of
//! them can reach the `lg_*` tables.

use crate::{GatewaySendHandle, push_registration::reply_or_log};
use ramflux_node_core::GatewayServerFrame;
use ramflux_node_core::large_group::LargeGroupHost;
use std::path::Path;
use std::sync::{Arc, OnceLock};

static HOST: OnceLock<Arc<LargeGroupHost>> = OnceLock::new();

/// Largest accepted request body after base64url decoding.
const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Opens the host beside the gateway state file; called once at startup.
pub(crate) fn install(config: &ramflux_node_core::NodeServiceConfig) -> anyhow::Result<()> {
    let state = ramflux_node_core::effective_redb_path(config);
    let dir =
        state.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let debug = ramflux_node_core::environment::var("RAMFLUX_LG_DEBUG").as_deref() == Ok("1");
    let host =
        LargeGroupHost::open(&dir.join("large-group.redb"), &dir.join("large-group-keys"), debug)
            .map_err(|reason| anyhow::anyhow!("large-group host unavailable: {reason}"))?;
    HOST.set(Arc::new(host)).map_err(|_| anyhow::anyhow!("large-group host already installed"))
}

/// Answers one request frame.
pub(crate) async fn handle(send: &GatewaySendHandle, request_id: String, op: String, body: String) {
    let (status, out) = match (HOST.get(), ramflux_protocol::decode_base64url(&body)) {
        (Some(host), Ok(bytes)) if bytes.len() <= MAX_REQUEST_BYTES => {
            let reply = host.handle(&op, &bytes);
            (reply.status.to_owned(), ramflux_protocol::encode_base64url(&reply.body))
        }
        (None, _) => ("unavailable".to_owned(), String::new()),
        _ => ("bad_request".to_owned(), String::new()),
    };
    reply_or_log(send, &GatewayServerFrame::LargeGroup { request_id, status, body: out }).await;
}
