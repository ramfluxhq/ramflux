// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The ordinary native gateway stream preserves the exact reach R/Z session correlation.
use super::{
    GatewayClientFrame, GatewayServerFrame, GatewaySessionEngine, frame_dispatch::ExpectedReply,
};
use crate::SdkError;
use ramflux_protocol::contact_reach::{self as wire, Operation, OperationResult, Reason, Request};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    frame_type: ResultKind,
    response: wire::Response,
}
#[derive(serde::Serialize, serde::Deserialize)]
enum ResultKind {
    #[serde(rename = "contact_foreign_result")]
    ContactForeignResult,
}

pub(super) fn decode_reply(bytes: &[u8]) -> Result<Option<GatewayServerFrame>, SdkError> {
    // This is a bounded discriminant probe; the selected exact closed codec follows below.
    if bytes.len() > wire::MAX_FRAME_BYTES {
        return Err(SdkError::ReachRefused(Reason::ForeignPayloadTooLarge));
    }
    let value: serde_json::Value = ramflux_protocol::parse_i_json(bytes)?;
    if value.get("frame_type").and_then(serde_json::Value::as_str) != Some("contact_foreign_result")
    {
        return Ok(None);
    }
    let frame: Reply = wire::decode(bytes, wire::MAX_FRAME_BYTES)?;
    Ok(Some(GatewayServerFrame::ContactForeignResult { response: Box::new(frame.response) }))
}
impl GatewaySessionEngine {
    /// Submit one already prepared operation through the currently authenticated native gateway.
    /// No signing key crosses RPC; a new gateway session never continues a prior snapshot lease.
    /// # Errors
    /// Refuses inactive capability, nonnative sessions, changed correlation or typed remote errors.
    pub async fn reach_operation(
        &mut self,
        operation: Operation,
    ) -> Result<OperationResult, SdkError> {
        if !wire::enabled() || self.config.custody.is_none() {
            return Err(SdkError::ReachRefused(Reason::ForeignCapabilityMissing));
        }
        let request = Request {
            request_id: match &operation {
                Operation::Query { query } => query.nonce.clone(),
                _ => ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            },
            session_id: self.session.session_id.clone(),
            session_generation: 1,
            remaining_ms: u64::try_from(self.config.timeout.as_millis().min(10_000))
                .map_err(|_| SdkError::ReachRefused(Reason::ForeignUnavailable))?,
            operation,
        };
        request.validate()?;
        let frame = GatewayClientFrame::ContactForeign { request: Box::new(request.clone()) };
        if ramflux_protocol::canonical_json_bytes(&frame)?.len() > wire::MAX_FRAME_BYTES {
            return Err(SdkError::ReachRefused(Reason::ForeignPayloadTooLarge));
        }
        let deadline = std::time::Duration::from_millis(request.remaining_ms);
        tokio::time::timeout(deadline, async {
            self.write_frame(&frame).await?;
            let GatewayServerFrame::ContactForeignResult { response } =
                self.read_reply(ExpectedReply::ContactForeign).await?
            else {
                return Err(SdkError::ReachRefused(Reason::ForeignInvalidFrame));
            };
            request.validate_response(&response)?;
            crate::contact_reach::remote_result(response.result)
        })
        .await
        .map_err(|_| SdkError::ReachRefused(Reason::ForeignUnavailable))?
    }
}

// Reach adds metadata outside the original bounded delivery. The original frame without
// that metadata must still fit its old budget; this never raises an envelope/content limit.
pub(super) fn permits_metadata_overhead(bytes: &[u8]) -> Result<bool, SdkError> {
    if !wire::enabled() || bytes.len() > wire::MAX_FRAME_BYTES {
        return Ok(false);
    }
    let mut frame: serde_json::Value = ramflux_protocol::parse_i_json(bytes)?;
    let kind = frame.get("frame_type").and_then(serde_json::Value::as_str).unwrap_or("").to_owned();
    let mut found = false;
    match kind.as_str() {
        "deliver" => {
            let Some(entry) = frame.get_mut("entry") else { return Ok(false) };
            found = strip_bound_metadata(entry)?;
        }
        "entry" => {
            let Some(entry) = frame.get_mut("record").and_then(|v| v.get_mut("entry")) else {
                return Ok(false);
            };
            found = strip_bound_metadata(entry)?;
        }
        "resume" | "resume_page" => {
            let Some(entries) = frame.get_mut("entries").and_then(serde_json::Value::as_array_mut)
            else {
                return Ok(false);
            };
            for record in entries {
                let entry =
                    if kind == "resume_page" { record.get_mut("entry") } else { Some(record) };
                let Some(entry) = entry else { return Ok(false) };
                if !strip_bound_metadata(entry)? {
                    return Ok(false);
                }
                found = true;
            }
        }
        _ => {}
    }
    Ok(found
        && ramflux_protocol::canonical_json_bytes(&frame)?.len()
            <= ramflux_transport::MAX_GATEWAY_FRAME_BYTES)
}
fn strip_bound_metadata(value: &mut serde_json::Value) -> Result<bool, SdkError> {
    let entry: super::GatewayInboxEntry =
        wire::decode(&ramflux_protocol::canonical_json_bytes(value)?, wire::MAX_FRAME_BYTES)?;
    let Some(reach) = entry.reach else { return Ok(false) };
    reach.route.body.validate()?;
    if ramflux_protocol::canonical_json_bytes(&reach.route)?.len() > 4096
        || reach.cost.as_ref().is_some_and(|cost| {
            ramflux_protocol::canonical_json_bytes(cost).map_or(true, |bytes| bytes.len() > 2048)
        })
        || reach.route.body.envelope_hash
            != ramflux_protocol::custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, &entry.envelope)?
    {
        return Err(SdkError::ReachRefused(Reason::ReachRouteInvalid));
    }
    let object =
        value.as_object_mut().ok_or(SdkError::ReachRefused(Reason::ForeignInvalidFrame))?;
    object.remove("reach");
    Ok(true)
}
