// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source authentication precedes a signed peer attempt; ambiguous attempts retain frozen bytes.
use super::{Context, Response, budget, remaining};
use ramflux_node_core::NodeCoreError;
use ramflux_protocol::contact_reach::{self as wire, OperationResult, Reason, SourceSubmitRequest};
use std::time::{Duration, Instant};

mod forward;
mod source;

fn error(reason: Reason) -> OperationResult {
    OperationResult::Error {
        reason,
        retry_after_ms: (reason == Reason::ForeignRateLimited).then_some(1000),
        current_revision: None,
    }
}

pub(super) fn route(
    request: &SourceSubmitRequest,
    context: Context<'_>,
) -> Result<Response, NodeCoreError> {
    let mut permit = None;
    let result = if wire::enabled() {
        budget::reserve(&request.target_node_id, false).and_then(|reserved| {
            permit = Some(reserved);
            dispatch(request, context)
        })
    } else {
        Err(Reason::FeatureDisabled)
    };
    let response = wire::SourceSubmitResponse {
        kind: wire::SourceSubmitResponseKind::SubmitResult,
        request_id: request.request_id.clone(),
        result: result.unwrap_or_else(error),
    };
    request
        .validate_response(&response)
        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    Ok(Response {
        frame: ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(response)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?,
        },
        _reservation: permit,
    })
}

fn dispatch(
    request: &SourceSubmitRequest,
    context: Context<'_>,
) -> Result<OperationResult, Reason> {
    request.validate().map_err(|_| Reason::ForeignInvalidFrame)?;
    ramflux_node_core::check_reach_entry_bound(&request.submission).map_err(
        |error| match error {
            NodeCoreError::PayloadTooLarge => Reason::ForeignPayloadTooLarge,
            _ => Reason::ReachRouteInvalid,
        },
    )?;
    if request.submission.envelope.delivery_class != ramflux_protocol::DeliveryClass::Message {
        return Err(Reason::ForeignCapabilityMissing);
    }
    if request.target_node_id == context.node.node_id {
        // The source router owns same-node admission; never construct a foreign peer identity.
        return Err(Reason::ForeignUnavailable);
    }
    let deadline = context
        .received
        .checked_add(Duration::from_millis(request.remaining_ms))
        .ok_or(Reason::ForeignUnavailable)?;
    remaining(deadline)?;
    let now = context
        .store
        .contact_clock_floor(crate::now_unix_seconds().map_err(|_| Reason::ForeignUnavailable)?)
        .map_err(|_| Reason::ForeignUnavailable)?;
    source::verify(request, context, deadline, now)?;
    let forward = forward::signed(request, context.node)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Reason::ForeignUnavailable)?;
    let (target, discovery) = runtime
        .block_on(super::discover(&request.target_node_id, deadline, now))
        .map_err(|_| Reason::ForeignUnavailable)?;
    remaining(deadline)?;
    // Every failure from this point may follow receiving admission. Do not report a preflight error.
    Ok(forward::send(request, &forward, &target, &discovery, context, deadline))
}
