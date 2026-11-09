// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-free pairing HTTP dispatch. Tokens relay SAS bytes only; no session or admin path.
use super::{PairingRelayError, PairingRelayStore};
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::Failure;
use ramflux_protocol::custody::pairing::relay::{Claim, Close, Poll, Send};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

pub const PAIRING_HTTP_PREFIX: &str = "/client/pairing/v1/";
pub const PAIRING_CLAIM_PATH: &str = "/client/pairing/v1/claim";
pub const PAIRING_SEND_PATH: &str = "/client/pairing/v1/send";
pub const PAIRING_POLL_PATH: &str = "/client/pairing/v1/poll";
pub const PAIRING_CLOSE_PATH: &str = "/client/pairing/v1/close";
pub const PAIRING_MAX_HEADER_BYTES: usize = 16 * 1024;
pub const PAIRING_MAX_BODY_BYTES: usize = 16 * 1024;
pub const PAIRING_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Pairing header/body/deadline. Ordinary public traffic keeps the existing 8KiB/64KiB/10s caps.
#[must_use]
pub fn pairing_http_limits() -> crate::HttpRequestLimits {
    crate::HttpRequestLimits {
        max_header_bytes: PAIRING_MAX_HEADER_BYTES,
        max_body_bytes: PAIRING_MAX_BODY_BYTES,
        read_timeout: PAIRING_REQUEST_TIMEOUT,
        request_timeout: PAIRING_REQUEST_TIMEOUT,
    }
}

#[must_use]
pub fn is_pairing_path(path: &str) -> bool {
    matches!(path, PAIRING_CLAIM_PATH | PAIRING_SEND_PATH | PAIRING_POLL_PATH | PAIRING_CLOSE_PATH)
}

pub struct PairingHttpResponse {
    pub status: &'static str,
    pub body: Vec<u8>,
}

/// Dispatch a pairing HTTP body. Headers, cookies and admin tokens are ignored: they cannot
/// authorize an account. The bearer in the closed body is the only credential.
#[must_use]
pub fn handle_pairing_http(
    store: &Mutex<PairingRelayStore>,
    source: IpAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> PairingHttpResponse {
    if method != "POST" {
        return text("405 Method Not Allowed", "method not allowed");
    }
    let Ok(mut store) = store.lock() else {
        return text("500 Internal Server Error", "internal server error");
    };
    match path {
        PAIRING_CLAIM_PATH => {
            run(&mut store, body, |store, claim: Claim| store.claim(source, &claim))
        }
        PAIRING_SEND_PATH => run(&mut store, body, |store, send: Send| store.send(&send)),
        PAIRING_POLL_PATH => run(&mut store, body, |store, poll: Poll| store.poll(&poll)),
        PAIRING_CLOSE_PATH => run(&mut store, body, |store, close: Close| store.close(&close)),
        _ => text("404 Not Found", "not found"),
    }
}

fn run<T, R>(
    store: &mut PairingRelayStore,
    body: &[u8],
    op: impl FnOnce(&mut PairingRelayStore, T) -> Result<R, PairingRelayError>,
) -> PairingHttpResponse
where
    T: PairingWire,
    R: PairingWire,
{
    match T::from_wire_bytes(body) {
        Err(_) => text("400 Bad Request", "request rejected"),
        Ok(request) => match op(store, request) {
            Ok(reply) => match reply.to_wire_bytes() {
                Ok(body) => PairingHttpResponse { status: "200 OK", body },
                Err(_) => text("500 Internal Server Error", "internal server error"),
            },
            Err(error) => failure(error),
        },
    }
}

fn failure(error: PairingRelayError) -> PairingHttpResponse {
    let reply = Failure {
        schema: "ramflux.pairing.Failure.v2".into(),
        version: 2,
        code: error.code().into(),
        retry_after_ms: match error {
            PairingRelayError::Busy { retry_after_ms } => Some(retry_after_ms),
            _ => None,
        },
    };
    match reply.to_wire_bytes() {
        Ok(body) => PairingHttpResponse { status: "200 OK", body },
        Err(_) => text("500 Internal Server Error", "internal server error"),
    }
}

fn text(status: &'static str, body: &str) -> PairingHttpResponse {
    PairingHttpResponse { status, body: body.as_bytes().to_vec() }
}
