// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway-only durable session mesh adapters.
use super::MeshResponse;
use ramflux_node_core::{SessionPushError, SessionPushReason};
use std::collections::BTreeSet;

fn reply(value: &impl serde::Serialize) -> anyhow::Result<MeshResponse> {
    Ok(MeshResponse::json("200 OK", serde_json::to_vec(value)?))
}
fn refused(reason: SessionPushReason, id: Option<String>) -> anyhow::Result<MeshResponse> {
    Ok(MeshResponse::json(
        "400 Bad Request",
        serde_json::to_vec(&SessionPushError::new(reason, id))?,
    ))
}
pub(super) fn route(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    peer: &str,
) -> anyhow::Result<Option<MeshResponse>> {
    let capable_page = path.starts_with("/mvp1/inbox/")
        && path.split('?').nth(1).is_some_and(|q| q.split('&').any(|p| p == "session_push=1"));
    let entry = path.starts_with("/mvp1/inbox-entry/");
    let establishment = path == "/s1/session"
        && serde_json::from_slice::<serde_json::Value>(body)
            .is_ok_and(|v| v["session_push"] == true);
    let handled = establishment
        || path == "/mvp0/ack-bound-batch"
        || path == "/mvp0/issued-seqs"
        || path == "/mvp1/session-push-capabilities"
        || capable_page
        || entry
        || path == "/mvp0/ack-bound";
    if !handled {
        return Ok(None);
    }
    if peer != "ramflux-gateway" {
        return Ok(Some(MeshResponse::text(
            "403 Forbidden",
            "session push requires authenticated gateway",
        )));
    }
    let result = match (method, path) {
        ("POST", "/s1/session") if establishment => {
            let request: ramflux_node_core::SessionPushSessionRequest =
                serde_json::from_slice(body)?;
            let id = router.store().initialize_inbox(&request.session.target_delivery_id)?;
            router
                .state()
                .prepare_publication_target(router.store(), &request.session.target_delivery_id)?;
            let session = super::handle_s1_session_upsert(body, router.state(), router.store())?;
            reply(&ramflux_node_core::SessionPushSessionResponse { session, incarnation_id: id })
        }
        ("GET", "/mvp1/session-push-capabilities") => {
            reply(&ramflux_node_core::SessionPushCapabilities { capabilities: Vec::new() })
        }
        ("POST", "/mvp0/ack-bound-batch") => {
            match serde_json::from_slice::<ramflux_node_core::SessionAckBatchRequest>(body) {
                Ok(request) => match router.state().session_ack_batch(router.store(), &request) {
                    Ok(response) => reply(&response),
                    Err(error) => {
                        Ok(MeshResponse::json("400 Bad Request", serde_json::to_vec(&error)?))
                    }
                },
                Err(_) => refused(SessionPushReason::InvalidSeq, None),
            }
        }
        ("POST", "/mvp0/ack-bound") => bound_ack(body, router),
        ("POST", "/mvp0/issued-seqs") => issued(body, router),
        ("GET", _) if capable_page => page(path, router),
        ("GET", _) if entry => point(path, router),
        _ => return Ok(None),
    }?;
    Ok(Some(result))
}
fn issued(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    let Ok(request) = serde_json::from_slice::<ramflux_node_core::IssuedSeqsRequest>(body) else {
        return refused(SessionPushReason::InvalidSeq, None);
    };
    let targets = &request.targets;
    if targets.is_empty()
        || targets.len() > 1024
        || targets.iter().any(String::is_empty)
        || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
    {
        return refused(SessionPushReason::InvalidSeq, None);
    }
    let issued = targets.iter().map(|target| router.state().session_push_status(target)).collect();
    reply(&ramflux_node_core::IssuedSeqsResponse { issued })
}
fn bound_ack(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let request: ramflux_node_core::TargetAckRequest = serde_json::from_value(value.clone())?;
    let status = router.state().session_push_status(&request.target_delivery_id);
    let seq = request.ack.ext.ext.get("inbox_seq").and_then(serde_json::Value::as_u64);
    if request.ack.ext.ext.contains_key("inbox_seq")
        && seq.is_none_or(|seq| seq == 0 || seq > status.inbox_seq)
    {
        return refused(SessionPushReason::InvalidSeq, status.incarnation_id);
    }
    if let Some(id) = value.get("incarnation_id") {
        let Some(id) = id.as_str() else {
            return refused(SessionPushReason::IncarnationMismatch, status.incarnation_id);
        };
        let Some(seq) = seq else {
            return refused(SessionPushReason::InvalidSeq, status.incarnation_id);
        };
        let batch = ramflux_node_core::SessionAckBatchRequest {
            target_delivery_id: request.target_delivery_id,
            incarnation_id: id.into(),
            inbox_seqs: vec![seq],
        };
        return match router.state().session_ack_batch(router.store(), &batch) {
            Ok(response) => reply(&response),
            Err(error) => Ok(MeshResponse::json("400 Bad Request", serde_json::to_vec(&error)?)),
        };
    }
    reply(&super::handle_mvp0_ack_bound(body, router)?)
}
fn query<'a>(path: &'a str, name: &str) -> Option<&'a str> {
    path.split_once('?')?
        .1
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}
fn page(path: &str, router: &crate::router_runtime::RouterHandle) -> anyhow::Result<MeshResponse> {
    let target = path.strip_prefix("/mvp1/inbox/").unwrap_or("").split('?').next().unwrap_or("");
    let id = query(path, "incarnation_id").unwrap_or("");
    if let Err(error) = router.state().check_inbox_incarnation(target, id) {
        return refused(error.reason, error.incarnation_id);
    }
    let after = query(path, "after").unwrap_or("0").parse::<u64>();
    let limit = query(path, "limit").unwrap_or("100").parse::<usize>();
    let (Ok(after), Ok(limit)) = (after, limit) else {
        return refused(
            SessionPushReason::InvalidLimit,
            router.state().session_push_status(target).incarnation_id,
        );
    };
    match router.state().resume_page(
        target,
        after,
        limit,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    ) {
        Ok(mut response) => {
            if response.incarnation_id.as_deref() != Some(id) {
                return refused(SessionPushReason::IncarnationMismatch, response.incarnation_id);
            }
            response.frame_type.clear();
            let mut value = serde_json::to_value(response)?;
            value
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("page object"))?
                .remove("frame_type");
            reply(&value)
        }
        Err(error) => refused(
            match error {
                ramflux_node_core::PageError::InvalidLimit => SessionPushReason::InvalidLimit,
                ramflux_node_core::PageError::CursorAhead => SessionPushReason::CursorAhead,
                ramflux_node_core::PageError::HeaderTooLarge => SessionPushReason::PayloadTooLarge,
                ramflux_node_core::PageError::Serialization => SessionPushReason::InternalError,
            },
            router.state().session_push_status(target).incarnation_id,
        ),
    }
}
fn point(path: &str, router: &crate::router_runtime::RouterHandle) -> anyhow::Result<MeshResponse> {
    if query(path, "incarnation_id").is_none() {
        return super::entry_fetch::reply(path, router.state());
    }
    let bare = path.split('?').next().unwrap_or("");
    let target = bare
        .strip_prefix("/mvp1/inbox-entry/")
        .unwrap_or("")
        .rsplit_once('/')
        .map_or("", |(target, _)| target);
    let status = router.state().session_push_status(target);
    let seq = bare.rsplit_once('/').and_then(|(_, seq)| seq.parse::<u64>().ok());
    if seq.is_none_or(|seq| seq == 0 || seq > status.inbox_seq) {
        return refused(SessionPushReason::InvalidSeq, status.incarnation_id);
    }
    if let Some(id) = query(path, "incarnation_id")
        && let Err(error) = router.state().check_inbox_incarnation(target, id)
    {
        return refused(error.reason, error.incarnation_id);
    }
    super::entry_fetch::reply(path, router.state())
}

/// Decorate only mesh replies; unchanged Rust literals and legacy frames remain valid.
pub(super) fn decorate(
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    response: &mut MeshResponse,
    peer: &str,
) -> anyhow::Result<()> {
    if response.status != "200 OK" || response.content_type != "application/json" {
        return Ok(());
    }
    if path == "/mvp0/envelope" {
        let delivery: ramflux_node_core::EnvelopeSubmitResponse =
            serde_json::from_slice(&response.body)?;
        let envelope: ramflux_protocol::Envelope = serde_json::from_slice(body)?;
        let (id, deadline) = metadata(router, &envelope, delivery.inbox_seq, peer)?;
        response.body = serde_json::to_vec(&ramflux_node_core::SessionPushSubmitResponse {
            delivery,
            incarnation_id: id,
            retain_until: deadline,
        })?;
    } else if path == "/mvp0/envelope/forwarded" {
        let request: ramflux_node_core::ForwardedEnvelopeRequest = serde_json::from_slice(body)?;
        let mut wire: serde_json::Value = serde_json::from_slice(&response.body)?;
        if let Some(delivery) = wire.get_mut("delivery") {
            let old: ramflux_node_core::EnvelopeSubmitResponse =
                serde_json::from_value(delivery.clone())?;
            let (id, deadline) = metadata(router, &request.envelope, old.inbox_seq, peer)?;
            *delivery = serde_json::to_value(ramflux_node_core::SessionPushSubmitResponse {
                delivery: old,
                incarnation_id: id,
                retain_until: deadline,
            })?;
        }
        response.body = serde_json::to_vec(&wire)?;
    } else if path == "/mvp10/own-devices/fanout" {
        let request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest =
            serde_json::from_slice(body)?;
        let old: ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse =
            serde_json::from_slice(&response.body)?;
        let source = router.state().authenticated_envelope_source_from(
            &request.envelope,
            Some(router.store()),
            super::envelope_origin_for_peer(peer)?,
        )?;
        let mut delivered = Vec::with_capacity(old.delivered.len());
        for delivery in old.delivered {
            let mut envelope = request.envelope.clone();
            envelope.target_delivery_id.clone_from(&delivery.target_delivery_id);
            envelope.envelope_id = ramflux_node_core::mvp10_fanout_envelope_id(
                &envelope.envelope_id,
                &delivery.device_id,
            );
            let (id, deadline) = assignment_metadata(
                router,
                &envelope,
                delivery.inbox_seq,
                source.root_commitment(),
            )?;
            delivered.push(ramflux_node_core::SessionPushFanoutDelivery {
                delivery,
                incarnation_id: id,
                retain_until: deadline,
            });
        }
        response.body = serde_json::to_vec(&ramflux_node_core::SessionPushFanoutResponse {
            principal_id: old.principal_id,
            source_device_id: old.source_device_id,
            delivered,
        })?;
    }
    Ok(())
}
fn metadata(
    router: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    seq: Option<u64>,
    peer: &str,
) -> anyhow::Result<(Option<String>, Option<i64>)> {
    let Some(seq) = seq else {
        return Ok((None, None));
    };
    let source = router.state().authenticated_envelope_source_from(
        envelope,
        Some(router.store()),
        super::envelope_origin_for_peer(peer)?,
    )?;
    assignment_metadata(router, envelope, Some(seq), source.root_commitment())
}
fn assignment_metadata(
    router: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    seq: Option<u64>,
    root: &str,
) -> anyhow::Result<(Option<String>, Option<i64>)> {
    let Some(seq) = seq else {
        return Ok((None, None));
    };
    if let Some(assignment) = router.store().sender_assignment(
        root,
        envelope,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )? {
        return Ok((Some(assignment.inbox_incarnation_id), Some(assignment.retain_until)));
    }
    Ok(router.state().session_delivery_metadata(&envelope.target_delivery_id, seq))
}
#[cfg(test)]
mod tests;
