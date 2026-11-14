// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-router snapshots authenticate the current source without allocating foreign trust.
use super::{Context, Instant, Reason, SourceSubmitRequest, remaining};
use ramflux_protocol::contact_reach::{self as wire, PeerQueryResult};

pub(super) fn verify(
    request: &SourceSubmitRequest,
    context: Context<'_>,
    deadline: Instant,
) -> Result<u64, Reason> {
    let query = wire::PeerQueryRequest {
        kind: wire::PeerQueryKind::Query,
        request_id: request.request_id.clone(),
        remaining_ms: remaining(deadline)?,
        query: wire::Query {
            version: 1,
            source_node: context.node.node_id.clone(),
            target_node: context.node.node_id.clone(),
            account_anchor: request.submission.route.body.source.account_anchor.clone(),
            card_hash: None,
            nonce: request.request_id.clone(),
            base: None,
            device_ref: None,
        },
    };
    let response = super::super::source_proxy(&query, context.router, deadline)
        .map_err(|_| Reason::ForeignUnavailable)?;
    let PeerQueryResult::Query { reply } = response.result else {
        return Err(Reason::ForeignPolicyDenied);
    };
    // The source may have advanced while the authenticated own-router read was in flight.
    // Commit this observation before using the reply or attempting the peer delivery.
    let now = context
        .store
        .contact_clock_floor(crate::now_unix_seconds().map_err(|_| Reason::ForeignUnavailable)?)
        .map_err(|_| Reason::ForeignUnavailable)?;
    let current = ramflux_crypto::contact_reach::verify_peer_reply(
        &reply,
        &query.query,
        &context.node.node_public_key,
        None,
        now,
    )
    .map_err(|_| Reason::ForeignPolicyDenied)?;
    if current.node() != context.node.node_id || current.expires_at() <= now {
        return Err(Reason::ForeignPolicyDenied);
    }
    ramflux_crypto::contact_reach::verify_current_source_submission(
        &request.submission,
        current.authority(),
        now,
    )
    .map_err(|_| Reason::ReachRouteInvalid)?;
    remaining(deadline)?;
    Ok(now)
}
