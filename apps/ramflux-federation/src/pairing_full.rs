// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full relay pre-body admission and raw forwarding. The node owns all authenticated permits.
use super::{
    http_response::HttpResponse, pairing_http::PairingHttpSurface,
    pairing_scratch::FullScratchGuard,
};
use ramflux_node_core::{
    NodeCoreError, NodeHttpRequest,
    pairing_relay::{
        FULL_MESH_ADMIT_PATH, FullArm, FullMeshAdmit, FullMeshPermit, PAIRING_CLAIM_PATH,
        PairingRelayError, SecretAuthorization, is_pairing_path, pairing_client_addr,
        pairing_request_is_tls,
    },
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{PACKET_BYTES, SecretBase64, relay::FullClaim},
    native::Failure,
};
use ramflux_transport::{RawMeshPost, RawMeshResponse};
use std::{cell::RefCell, net::IpAddr, time::Instant};
use zeroize::Zeroizing;

pub(crate) struct ReadContext<'a> {
    pub(crate) surface: &'a PairingHttpSurface,
    pub(crate) peer: IpAddr,
    pub(crate) deadline: Instant,
    pub(crate) refusal: &'a RefCell<Option<HttpResponse>>,
}
pub(crate) struct PublicPermit {
    arm: FullArm,
    authorization: SecretAuthorization,
    nonce: Zeroizing<[u8; 32]>,
    cookie: Zeroizing<String>,
    scratch: FullScratchGuard,
}
fn header<'a>(raw: &'a str, name: &str) -> Result<Option<&'a str>, PairingRelayError> {
    let mut found = None;
    for line in raw.split("\r\n").skip(1).take_while(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or(PairingRelayError::WrongContext)?;
        if key.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(PairingRelayError::WrongContext);
            }
            found = Some(value.trim_matches([' ', '\t']));
        }
    }
    Ok(found)
}
fn full_headers(raw: &str) -> bool {
    raw.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.eq_ignore_ascii_case("x-ramflux-pairing-arm")
                || (key.eq_ignore_ascii_case("authorization")
                    && value.trim_start().starts_with("PairingFull"))
        })
    })
}
fn response_limit(arm: FullArm) -> usize {
    if arm == FullArm::Poll { PACKET_BYTES } else { 8192 }
}
fn arm_name(arm: FullArm) -> &'static str {
    match arm {
        FullArm::Send => "send",
        FullArm::Poll => "poll",
        FullArm::Close => "close",
        FullArm::SendControl => "send_control",
        FullArm::PollControl => "poll_control",
    }
}
fn raw(
    surface: &PairingHttpSurface,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    cap: usize,
    deadline: Instant,
) -> Result<RawMeshResponse, PairingRelayError> {
    surface
        .router
        .client
        .post_raw(&RawMeshPost {
            endpoint: &surface.router.endpoint,
            path,
            tls: &surface.router.tls,
            server_name: &surface.router.server_name,
            headers,
            body,
            max_response_bytes: cap,
            deadline,
        })
        .map_err(|_| PairingRelayError::Busy { retry_after_ms: 1000 })
}
/// Called on original headers before a large body allocation/read. Refusals are stashed as
/// closed typed bytes so the public reader can return the exact refusal without reading a body.
pub(crate) fn admit(
    ctx: &ReadContext<'_>,
    method: &str,
    path: &str,
    original: &str,
    length: usize,
) -> Result<Option<PublicPermit>, NodeCoreError> {
    if !is_pairing_path(path) || path == PAIRING_CLAIM_PATH {
        return Ok(None);
    }
    if !full_headers(original) && length <= ramflux_node_core::pairing_relay::PAIRING_MAX_BODY_BYTES
    {
        return Ok(None);
    }
    match admit_inner(ctx, method, path, original, length) {
        Ok(permit) => Ok(Some(permit)),
        Err(reply) => {
            *ctx.refusal.borrow_mut() = Some(reply.full_pairing(None, ctx.deadline));
            Err(NodeCoreError::HttpRequestRejected { status: "400 Bad Request" })
        }
    }
}
fn admit_inner(
    ctx: &ReadContext<'_>,
    method: &str,
    path: &str,
    original: &str,
    length: usize,
) -> Result<PublicPermit, HttpResponse> {
    let surface = ctx.surface;
    let peer = ctx.peer;
    let deadline = ctx.deadline;
    let prepare =
        || -> Result<(FullArm, SecretAuthorization, Zeroizing<[u8; 32]>), PairingRelayError> {
            let tls = pairing_request_is_tls(
                false,
                peer,
                &surface.trusted_proxies,
                header(original, "x-forwarded-proto")?,
            );
            let _ = source(surface, peer, original)?;
            let arm = FullArm::from_header(method, path, tls, original)?;
            if length == 0 || length > arm.body_limit() {
                return Err(PairingRelayError::WrongContext);
            }
            let authorization = SecretAuthorization::new(
                header(original, "authorization")?.ok_or(PairingRelayError::WrongContext)?.into(),
            );
            let nonce = Zeroizing::new(
                ramflux_crypto::random_32().map_err(|_| PairingRelayError::WrongContext)?,
            );
            Ok((arm, authorization, nonce))
        };
    let (arm, authorization, nonce) = prepare().map_err(|error| failure(&error))?;
    let request = FullMeshAdmit {
        arm,
        authorization: authorization.clone(),
        content_length: length as u64,
        request_nonce: SecretBase64::from_bytes(nonce.as_ref()),
    };
    let bytes = request.encode_secret().map_err(|_| failure(&PairingRelayError::WrongContext))?;
    let mut reply = raw(surface, FULL_MESH_ADMIT_PATH, &[], &bytes, 1024, deadline)
        .map_err(|error| failure(&error))?;
    if reply.status != 200 {
        return Err(failure(&PairingRelayError::WrongContext));
    }
    let cookie = if let Ok(value) = FullMeshPermit::from_wire_bytes(&reply.body) {
        value.permit.decode(32).map_err(|_| failure(&PairingRelayError::WrongContext))?
    } else {
        if Failure::from_wire_bytes(&reply.body).is_ok() {
            return Err(HttpResponse::raw_json("200 OK", std::mem::take(&mut *reply.body)));
        }
        return Err(failure(&PairingRelayError::WrongContext));
    };
    let scratch = surface
        .full_scratch
        .reserve(length, response_limit(arm))
        .map_err(|error| failure(&error))?;
    Ok(PublicPermit {
        arm,
        authorization,
        nonce,
        cookie: Zeroizing::new(ramflux_protocol::encode_base64url(cookie.as_slice())),
        scratch,
    })
}
pub(crate) fn forward(
    surface: &PairingHttpSurface,
    permit: PublicPermit,
    request: &mut NodeHttpRequest,
    deadline: Instant,
) -> HttpResponse {
    let body = Zeroizing::new(std::mem::take(&mut request.body));
    let nonce = Zeroizing::new(ramflux_protocol::encode_base64url(permit.nonce.as_ref()));
    let headers = [
        ("authorization", permit.authorization.as_str()),
        ("x-ramflux-pairing-arm", arm_name(permit.arm)),
        ("x-ramflux-pairing-nonce", nonce.as_str()),
        ("x-ramflux-pairing-permit", permit.cookie.as_str()),
    ];
    let reply = match raw(
        surface,
        permit.arm.mesh_path(),
        &headers,
        &body,
        response_limit(permit.arm),
        deadline,
    ) {
        Ok(mut reply) if reply.status == 200 => {
            HttpResponse::raw_json("200 OK", std::mem::take(&mut *reply.body))
        }
        Ok(_) => failure(&PairingRelayError::WrongContext),
        Err(error) => failure(&error),
    };
    reply.full_pairing(Some(permit.scratch), deadline)
}
pub(crate) fn claim(
    surface: &PairingHttpSurface,
    source: IpAddr,
    request: &NodeHttpRequest,
    deadline: Instant,
) -> Option<HttpResponse> {
    if request.path != PAIRING_CLAIM_PATH || FullClaim::from_wire_bytes(&request.body).is_err() {
        return None;
    }
    let source = source.to_string();
    let result = raw(
        surface,
        PAIRING_CLAIM_PATH,
        &[("x-ramflux-pairing-source", &source)],
        &request.body,
        8192,
        deadline,
    );
    Some(
        match result {
            Ok(mut reply) if reply.status == 200 => {
                HttpResponse::raw_json("200 OK", std::mem::take(&mut *reply.body))
            }
            Ok(_) => failure(&PairingRelayError::WrongContext),
            Err(error) => failure(&error),
        }
        .full_pairing(None, deadline),
    )
}
pub(crate) fn failure(error: &PairingRelayError) -> HttpResponse {
    let reply = Failure {
        schema: "ramflux.pairing.Failure.v2".into(),
        version: 2,
        code: error.code().into(),
        retry_after_ms: match error {
            PairingRelayError::Busy { retry_after_ms } => Some(*retry_after_ms),
            _ => None,
        },
    };
    HttpResponse::raw_json(
        "200 OK",
        reply.to_wire_bytes().unwrap_or_else(|_| b"{\"error\":\"request rejected\"}".to_vec()),
    )
}
/// Shared trusted-proxy source derivation for the full public reader callback.
pub(crate) fn source(
    surface: &PairingHttpSurface,
    peer: IpAddr,
    raw: &str,
) -> Result<IpAddr, PairingRelayError> {
    pairing_client_addr(peer, &surface.trusted_proxies, header(raw, "x-forwarded-for")?)
        .map_err(|_| PairingRelayError::WrongContext)
}

/// A small full request with all A2 headers removed is still recognized before legacy dispatch.
pub(crate) fn full_body_without_permit(body: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Header {
        kind: String,
    }
    let Ok(header) = ramflux_protocol::parse_i_json_secret::<Header>(body) else {
        return false;
    };
    matches!(
        header.kind.as_str(),
        "send_full" | "send_full_control" | "poll_full" | "poll_full_control" | "close_full"
    )
}
