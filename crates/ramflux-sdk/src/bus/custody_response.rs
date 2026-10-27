// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary bus response envelopes with directly serialized, zeroizing secret bodies.
use crate::{LocalBusFrame, SdkError};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct Response<'a, T> {
    bus_protocol: &'static str,
    frame_id: String,
    kind: &'static str,
    request_id: &'a str,
    account_id: Option<&'a str>,
    sdk_api: &'a str,
    method: &'a str,
    body: T,
    trace_id: Option<&'a str>,
    ok: bool,
}

pub(super) fn success<T: Serialize>(
    request: &LocalBusFrame,
    body: T,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    crate::custody::serialize_secret(
        &Response {
            bus_protocol: "ramflux.local_bus.v1",
            frame_id: format!("frame_resp_{}", request.request_id),
            kind: "response",
            request_id: &request.request_id,
            account_id: request.account_id.as_deref(),
            sdk_api: &request.sdk_api,
            method: &request.method,
            body,
            trace_id: request.trace_id.as_deref(),
            ok: true,
        },
        8192,
    )
}

pub(super) fn error(
    request: &LocalBusFrame,
    error: &SdkError,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    crate::custody::serialize_secret(&super::io::local_bus_error(request, error), 8192)
}

#[derive(Serialize)]
pub(super) struct Pending {
    pub ceremony: &'static str,
    pub ceremony_id: String,
    pub expires_in_ms: u64,
}
#[derive(Serialize)]
pub(super) struct Phrase {
    pub phrase: Zeroizing<String>,
}
#[derive(Serialize)]
pub(super) struct Challenge {
    pub positions: [u8; 3],
}
#[derive(Serialize)]
pub(super) struct Cancelled {
    pub cancelled: bool,
}
