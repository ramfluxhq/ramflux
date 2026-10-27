// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Buffered federation responses with bounded writes and graceful close.
use ramflux_node_core::{HttpRequestLimits, NodeCoreError};
use std::{
    net::TcpStream,
    time::{Duration, Instant},
};

pub(crate) struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}
impl HttpResponse {
    pub(crate) fn json<T: serde::Serialize>(value: &T) -> Result<Self, NodeCoreError> {
        Ok(Self {
            status: "200 OK",
            content_type: "application/json",
            body: serde_json::to_vec(value).map_err(|e| NodeCoreError::ItestJson(e.to_string()))?,
        })
    }
    pub(crate) fn text(status: &'static str, body: &str) -> Self {
        Self { status, content_type: "text/plain; charset=utf-8", body: body.as_bytes().to_vec() }
    }
    pub(crate) fn write(
        self,
        stream: &mut TcpStream,
        limits: HttpRequestLimits,
        accepted_at: Instant,
    ) -> Result<(), NodeCoreError> {
        let deadline = accepted_at + limits.request_timeout;
        // A request which exhausted its read budget may send only its bounded timeout rejection.
        let deadline = if self.status == "408 Request Timeout" && deadline <= Instant::now() {
            Instant::now() + Duration::from_millis(100)
        } else {
            deadline
        };
        ramflux_node_core::write_http_response_with_deadline(
            stream,
            self.status,
            self.content_type,
            &self.body,
            deadline,
        )?;
        ramflux_node_core::finish_http_response(stream, deadline)
    }
}
