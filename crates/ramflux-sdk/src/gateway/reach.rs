// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The ordinary native gateway stream preserves the exact reach R/Z session correlation.
use super::{
    GatewayClientFrame, GatewayServerFrame, GatewaySessionEngine, frame_dispatch::ExpectedReply,
};
use crate::SdkError;
use ramflux_protocol::contact_reach::{self as wire, Operation, OperationResult, Reason, Request};

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
            request_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
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
            if response.request_id != request.request_id
                || response.session_id != request.session_id
                || response.session_generation != request.session_generation
            {
                return Err(SdkError::ReachRefused(Reason::ForeignInvalidFrame));
            }
            request.operation.validate_result(&response.result)?;
            if let OperationResult::Error { reason, .. } = response.result {
                return Err(SdkError::ReachRefused(reason));
            }
            Ok(response.result)
        })
        .await
        .map_err(|_| SdkError::ReachRefused(Reason::ForeignUnavailable))?
    }
}
