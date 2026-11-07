// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant source-router route `/s9/attachments/renew/source` (P25 N5b). Only the local
//! federation service may call it: `peer_node` is stamped there from the verified TLS
//! node id, so it is trusted solely because of the transport identity checked here.
//! The router computes the current-home verdict and forwards to the relay authority.
//! Without a configured backend the route answers 503 and does nothing.
use ramflux_node_core::attachment::{HomeVerdict, RenewalRefusal};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

pub(crate) const SOURCE_PATH: &str = "/s9/attachments/renew/source";
pub(crate) const FEDERATION_SERVICE_ID: &str = "ramflux-federation";
const RELAY_CHALLENGE_PATH: &str = "/s9/attachment-authority/challenge";
const RELAY_RENEW_PATH: &str = "/s9/attachment-authority/renew";
/// Design section 1: bodies are at most 16 KiB at every hop, in and out.
pub(crate) const MAX_BODY: usize = 16 * 1024;
/// One budget covers the whole route.
pub(crate) const ROUTE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Computes the verdict and reaches the relay authority. Production wiring (P20/S10a)
/// supplies the floor, the resolver and the router-to-relay mesh client.
pub(crate) trait SourceBackend {
    fn now(&self) -> u64;
    /// `deadline` is the end of the shared route budget; the call must not outlive it.
    /// # Errors
    /// The typed refusal of the verdict computation.
    fn verdict(
        &self,
        account_anchor: &str,
        peer_node: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<HomeVerdict, RenewalRefusal>;
    /// Sends `body` to the relay authority `path` and returns the relay's JSON reply,
    /// bounded by the same `deadline`.
    /// # Errors
    /// The typed refusal when the relay cannot be reached.
    fn relay(
        &self,
        path: &str,
        body: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal>;
}

/// The budget left before each backend call; an elapsed budget is `Busy`.
fn ensure_budget(deadline: Instant) -> Result<(), RenewalRefusal> {
    if deadline.checked_duration_since(Instant::now()).is_some_and(|d| !d.is_zero()) {
        Ok(())
    } else {
        Err(RenewalRefusal::Busy)
    }
}

/// What federation sends: the peer stamped from TLS, and the relay request without a verdict.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SourceEnvelope {
    Challenge { peer_node: String, request: Value },
    Forward { peer_node: String, request: Value },
}

#[derive(Debug, Serialize)]
enum Refused {
    Refused { code: RenewalRefusal },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SourceReply {
    pub(crate) status: &'static str,
    pub(crate) body: Vec<u8>,
}

fn refused(code: RenewalRefusal) -> SourceReply {
    SourceReply {
        status: "200 OK",
        body: serde_json::to_vec(&Refused::Refused { code }).unwrap_or_default(),
    }
}
fn text(status: &'static str, body: &str) -> SourceReply {
    SourceReply { status, body: body.as_bytes().to_vec() }
}

/// Anchor and home node the requester claims, read from the received bytes.
fn requester_of(kind: &SourceEnvelope) -> Result<(String, String), RenewalRefusal> {
    match kind {
        SourceEnvelope::Challenge { request, .. } => {
            let r = request.get("requester").ok_or(RenewalRefusal::Invalid)?;
            let field = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_owned);
            Ok((
                field("account_anchor").ok_or(RenewalRefusal::Invalid)?,
                field("home_node_id").ok_or(RenewalRefusal::Invalid)?,
            ))
        }
        SourceEnvelope::Forward { request, .. } => {
            let bytes: Vec<u8> = serde_json::from_value(
                request.get("attestation").cloned().ok_or(RenewalRefusal::Invalid)?,
            )
            .map_err(|_| RenewalRefusal::Invalid)?;
            let w = ramflux_protocol::large_attachment::ForwardAttestation::decode(&bytes)
                .map_err(|_| RenewalRefusal::Invalid)?;
            Ok((w.requester.account_anchor, w.requester.home_node_id))
        }
    }
}

/// `deadline` is when the shared route budget ends (received time plus [`ROUTE_BUDGET`]).
pub(crate) fn route(
    peer_service_id: &str,
    body: &[u8],
    backend: Option<&dyn SourceBackend>,
    deadline: Instant,
) -> SourceReply {
    if peer_service_id != FEDERATION_SERVICE_ID {
        return text("403 Forbidden", "attachment source requires federation identity");
    }
    if body.len() > MAX_BODY {
        return text("413 Payload Too Large", "body");
    }
    let Some(backend) = backend else {
        return text("503 Service Unavailable", "attachment source is not configured");
    };
    let Ok(envelope) = serde_json::from_slice::<SourceEnvelope>(body) else {
        return refused(RenewalRefusal::Invalid);
    };
    match serve(&envelope, backend, deadline) {
        Ok(reply) => SourceReply { status: "200 OK", body: reply },
        Err(code) => refused(code),
    }
}

fn serve(
    envelope: &SourceEnvelope,
    backend: &dyn SourceBackend,
    deadline: Instant,
) -> Result<Vec<u8>, RenewalRefusal> {
    let (anchor, requester_home) = requester_of(envelope)?;
    let (peer_node, mut request, path) = match envelope {
        SourceEnvelope::Challenge { peer_node, request } => {
            (peer_node, request.clone(), RELAY_CHALLENGE_PATH)
        }
        SourceEnvelope::Forward { peer_node, request } => {
            (peer_node, request.clone(), RELAY_RENEW_PATH)
        }
    };
    ensure_budget(deadline)?;
    let verdict = backend.verdict(&anchor, peer_node, backend.now(), deadline)?;
    if verdict.home_node != *peer_node
        || *peer_node != requester_home
        || verdict.account_anchor != anchor
    {
        return Err(RenewalRefusal::HomeMismatch);
    }
    let object = request.as_object_mut().ok_or(RenewalRefusal::Invalid)?;
    object.insert("peer_node".into(), Value::String(peer_node.clone()));
    object.insert(
        "home_verdict".into(),
        serde_json::to_value(&verdict).map_err(|_| RenewalRefusal::Invalid)?,
    );
    if path == RELAY_CHALLENGE_PATH {
        object.insert("home_node".into(), Value::String(peer_node.clone()));
    }
    let out = serde_json::to_vec(&request).map_err(|_| RenewalRefusal::Invalid)?;
    if out.len() > MAX_BODY {
        return Err(RenewalRefusal::Invalid);
    }
    ensure_budget(deadline)?;
    backend.relay(path, out, deadline)
}

#[cfg(test)]
mod tests;
