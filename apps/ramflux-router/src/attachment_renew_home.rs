// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant B-router routes `/s9/attachments/renew/{challenge,forward}` (P25 N6b). The
//! home router routes a renewal only by a pin-verified registration receipt: the
//! candidate source is read from the receipt, the pin for that source comes from the
//! local federation, and the whole capability is verified against that pin before any
//! federation call. Every refusal happens before the federation hop; nothing is minted,
//! nothing is stored, and there is no gateway-peer or local fallback.
use ramflux_node_core::{AuthorityPin, attachment::RenewalRefusal};
use ramflux_protocol::large_attachment::AttachmentRegistrationReceipt;
use serde::Serialize;
use serde_json::Value;
use std::time::{Duration, Instant};

pub(crate) const CHALLENGE_PATH: &str = "/s9/attachments/renew/challenge";
pub(crate) const FORWARD_PATH: &str = "/s9/attachments/renew/forward";
pub(crate) const GATEWAY_SERVICE_ID: &str = "ramflux-gateway";
/// Design section 1: bodies are at most 16 KiB.
pub(crate) const MAX_BODY: usize = 16 * 1024;
pub(crate) const ROUTE_BUDGET: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Challenge,
    Forward,
}

/// The only two things the route can reach: the local federation's pin answer, and the
/// local federation's renewal hop. There is deliberately no other method.
pub(crate) trait HomeBackend {
    fn now(&self) -> u64;
    /// The attachment authority pin of `source_node`.
    /// # Errors
    /// `SourceUnknown` (not an admitted node), `CapabilityUnavailable` (withdrawn or not
    /// negotiated), or a transport refusal.
    fn pin(&self, source_node: &str, deadline: Instant) -> Result<AuthorityPin, RenewalRefusal>;
    /// Hands the request to the local federation for `source_node`.
    /// # Errors
    /// The typed refusal of the federation hop.
    fn federation(
        &self,
        source_node: &str,
        kind: Kind,
        request: Value,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HomeReply {
    pub(crate) status: &'static str,
    pub(crate) body: Vec<u8>,
}
#[derive(Serialize)]
enum Refused {
    Refused { code: RenewalRefusal },
}
fn refused(code: RenewalRefusal) -> HomeReply {
    HomeReply {
        status: "200 OK",
        body: serde_json::to_vec(&Refused::Refused { code }).unwrap_or_default(),
    }
}
fn text(status: &'static str, body: &str) -> HomeReply {
    HomeReply { status, body: body.as_bytes().to_vec() }
}
fn ensure_budget(deadline: Instant) -> Result<(), RenewalRefusal> {
    if deadline.checked_duration_since(Instant::now()).is_some_and(|d| !d.is_zero()) {
        Ok(())
    } else {
        Err(RenewalRefusal::Busy)
    }
}

/// The complete registered capability each envelope carries: `capability` in a challenge
/// request, `grant` in a forwarded renewal.
fn capability_of(kind: Kind, request: &Value) -> Result<Vec<u8>, RenewalRefusal> {
    let field = match kind {
        Kind::Challenge => "capability",
        Kind::Forward => "grant",
    };
    request
        .get(field)
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or(RenewalRefusal::CapabilityInvalid)
}

pub(crate) fn route(
    peer_service_id: &str,
    path: &str,
    body: &[u8],
    backend: Option<&dyn HomeBackend>,
    deadline: Instant,
) -> HomeReply {
    if peer_service_id != GATEWAY_SERVICE_ID {
        return text("403 Forbidden", "attachment renewal requires gateway identity");
    }
    let kind = match path {
        CHALLENGE_PATH => Kind::Challenge,
        FORWARD_PATH => Kind::Forward,
        _ => return text("404 Not Found", "unknown route"),
    };
    let Some(backend) = backend else {
        return text("503 Service Unavailable", "attachment renewal is not configured");
    };
    if body.len() > MAX_BODY {
        return text("413 Payload Too Large", "body");
    }
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return refused(RenewalRefusal::Invalid);
    };
    match serve(kind, request, backend, deadline) {
        Ok(reply) => HomeReply { status: "200 OK", body: reply },
        Err(code) => refused(code),
    }
}

fn serve(
    kind: Kind,
    request: Value,
    backend: &dyn HomeBackend,
    deadline: Instant,
) -> Result<Vec<u8>, RenewalRefusal> {
    let capability = capability_of(kind, &request)?;
    // Candidate only: nothing below trusts it until the pin has verified the capability.
    let (source, generation) = AttachmentRegistrationReceipt::peek_source(&capability)
        .map_err(|_| RenewalRefusal::CapabilityInvalid)?;
    ensure_budget(deadline)?;
    let pin = backend.pin(&source, deadline)?;
    if generation != pin.generation {
        return Err(RenewalRefusal::AuthorityGenerationMismatch);
    }
    AttachmentRegistrationReceipt::decode_capability(
        &capability,
        &source,
        pin.generation,
        &pin.key,
        backend.now(),
    )
    .map_err(|_| RenewalRefusal::CapabilityInvalid)?;
    ensure_budget(deadline)?;
    backend.federation(&source, kind, request, deadline)
}

#[cfg(test)]
mod tests;
