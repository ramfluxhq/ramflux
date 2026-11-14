// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The source reply is distinct from admission; pre-forward errors cannot claim a stored envelope.
use super::Response;
use ramflux_node_core::NodeCoreError;
use ramflux_protocol::contact_reach::{
    self as wire, OperationResult, Reason, SourceSubmitRequest, SourceSubmitResponse,
    SourceSubmitResponseKind,
};

pub(super) fn route(request: &SourceSubmitRequest) -> Result<Response, NodeCoreError> {
    let reason = if wire::enabled() {
        match ramflux_node_core::check_reach_entry_bound(&request.submission) {
            Err(NodeCoreError::PayloadTooLarge) => Reason::ForeignPayloadTooLarge,
            Err(_) => Reason::ReachRouteInvalid,
            Ok(()) => {
                // The peer/router forward result needs an audited lossless mapping.
                // No admission, source spool or outbound attempt has occurred here.
                Reason::ForeignUnavailable
            }
        }
    } else {
        Reason::FeatureDisabled
    };
    let response = SourceSubmitResponse {
        kind: SourceSubmitResponseKind::SubmitResult,
        request_id: request.request_id.clone(),
        result: OperationResult::Error { reason, retry_after_ms: None, current_revision: None },
    };
    response.validate().map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    Ok(Response {
        frame: ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(response)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?,
        },
        _reservation: None,
    })
}
