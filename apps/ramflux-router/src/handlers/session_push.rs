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
    peer: &ramflux_node_core::MeshPeerIdentity,
) -> anyhow::Result<Option<MeshResponse>> {
    if (method, path) == ("POST", "/mvp0/nack-bound") {
        return bound_nack(ramflux_protocol::parse_i_json(body)?, router, &peer.service_id)
            .map(Some);
    }
    let capable_page = path.starts_with("/mvp1/inbox/")
        && path.split('?').nth(1).is_some_and(|q| q.split('&').any(|p| p == "session_push=1"));
    let entry = path.starts_with("/mvp1/inbox-entry/");
    let establishment = path == "/s1/session"
        && ramflux_protocol::parse_i_json::<serde_json::Value>(body)
            .is_ok_and(|v| v["session_push"] == true);
    let handled = establishment
        || path == "/mvp0/ack-bound-batch"
        || path == "/mvp0/issued-seqs"
        || path == "/mvp1/session-push-capabilities"
        || path == "/mvp0/ephemeral-registrations"
        || path == "/mvp0/envelope-ephemeral"
        || capable_page
        || entry
        || path == "/mvp0/ack-bound";
    if !handled {
        return Ok(None);
    }
    if peer.service_id != "ramflux-gateway" {
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
            if request.ephemeral {
                router.state().bind_ephemeral_capability(
                    &session.target_delivery_id,
                    &session.gateway_id,
                    &session.session_id,
                );
            }
            reply(&ramflux_node_core::SessionPushSessionResponse { session, incarnation_id: id })
        }
        ("GET", "/mvp1/session-push-capabilities") => {
            reply(&ramflux_node_core::SessionPushCapabilities {
                capabilities: vec![
                    ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
                ],
                router_boot_id: router.state().router_boot_id().to_owned(),
            })
        }
        ("POST", "/mvp0/ephemeral-registrations") => reassert(body, router, peer),
        ("POST", "/mvp0/envelope-ephemeral") => envelope_ephemeral(body, router),
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
fn bound_nack(
    mut value: serde_json::Value,
    router: &crate::router_runtime::RouterHandle,
    peer: &str,
) -> anyhow::Result<MeshResponse> {
    let incarnation = value.as_object_mut().and_then(|body| body.remove("incarnation_id"));
    if incarnation.is_some() && peer != "ramflux-gateway" {
        return Ok(MeshResponse::text(
            "403 Forbidden",
            "session push requires authenticated gateway",
        ));
    }
    let request: ramflux_node_core::TargetNackRequest = serde_json::from_value(value)?;
    let Some(id) = incarnation else {
        return reply(&router.apply_bound_nack(&request)?);
    };
    let id = id.as_str().unwrap_or("");
    match router.state().session_nack(router.store(), &request, id) {
        Ok(cursor) => reply(&serde_json::json!({"incarnation_id":id,"cursor":cursor})),
        Err(error) => Ok(MeshResponse::json("400 Bad Request", serde_json::to_vec(&error)?)),
    }
}

fn envelope_now_ms(
    #[cfg_attr(not(test), allow(unused_variables))] router: &crate::router_runtime::RouterHandle,
) -> u64 {
    #[cfg(test)]
    if let Some(now) = router.ephemeral_now_ms() {
        return now;
    }
    ramflux_node_core::now_unix_seconds().saturating_mul(1_000)
}

fn envelope_ephemeral(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    let request = ramflux_protocol::parse_i_json::<ramflux_node_core::EphemeralRouteRequest>(body)?;
    let result = router.state().route_ephemeral(
        &request.envelope,
        request.expires_at_ms,
        envelope_now_ms(router),
    );
    reply(&result.into_response())
}

fn reassert(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    peer: &ramflux_node_core::MeshPeerIdentity,
) -> anyhow::Result<MeshResponse> {
    let Ok(request) =
        serde_json::from_slice::<ramflux_node_core::EphemeralRegistrationsRequest>(body)
    else {
        return refused(SessionPushReason::InvalidSeq, None);
    };
    let Some(instance_id) = peer.instance_id.as_deref() else {
        return Ok(MeshResponse::json(
            "403 Forbidden",
            serde_json::json!({"reason": "gateway_instance_missing"}).to_string().into_bytes(),
        ));
    };
    if request.items.iter().any(|item| item.gateway_id.is_empty()) {
        return Ok(MeshResponse::json(
            "400 Bad Request",
            serde_json::json!({"reason": "gateway_id_empty"}).to_string().into_bytes(),
        ));
    }
    if request.items.iter().any(|item| item.gateway_id != instance_id) {
        return Ok(super::gateway_instance_mismatch());
    }
    if peer.node_id != router.node_id() {
        return Ok(super::gateway_identity_forbidden("gateway_node_mismatch"));
    }
    match router.state().reassert_ephemeral_registrations(&request.router_boot_id, &request.items) {
        Ok(applied) => reply(&ramflux_node_core::EphemeralRegistrationsResponse { applied }),
        Err(ramflux_node_core::EphemeralReassertionError::BootMismatch) => {
            refused(SessionPushReason::BootMismatch, None)
        }
        Err(ramflux_node_core::EphemeralReassertionError::TooManyItems) => {
            refused(SessionPushReason::InvalidSeq, None)
        }
    }
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
    let value: serde_json::Value = ramflux_protocol::parse_i_json(body)?;
    let request: ramflux_node_core::TargetAckRequest = serde_json::from_value(value.clone())?;
    let status = router.state().session_push_status(&request.target_delivery_id);
    let seq = request.ack.ext.ext.get("inbox_seq").and_then(serde_json::Value::as_u64);
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
    if request.ack.ext.ext.contains_key("inbox_seq")
        && seq.is_none_or(|seq| seq == 0 || seq > status.inbox_seq)
    {
        return refused(SessionPushReason::InvalidSeq, status.incarnation_id);
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
    if let Some(id) = query(path, "incarnation_id")
        && let Err(error) = router.state().check_inbox_incarnation(target, id)
    {
        return refused(error.reason, error.incarnation_id);
    }
    let status = router.state().session_push_status(target);
    let seq = bare.rsplit_once('/').and_then(|(_, seq)| seq.parse::<u64>().ok());
    if seq.is_none_or(|seq| seq == 0 || seq > status.inbox_seq) {
        return refused(SessionPushReason::InvalidSeq, status.incarnation_id);
    }
    super::entry_fetch::reply(path, router.state())
}

#[cfg(test)]
mod capability_binding;
#[cfg(test)]
mod ephemeral_reassertion;
#[cfg(test)]
mod ephemeral_route;
#[cfg(test)]
mod tests;
