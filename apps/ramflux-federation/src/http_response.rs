// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Buffered federation responses with bounded writes and graceful close.
use ramflux_node_core::{HttpRequestLimits, NodeCoreError};
#[cfg(test)]
use std::io::Write;
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
    pub(crate) fn raw_json(status: &'static str, body: Vec<u8>) -> Self {
        let content_type =
            if status == "200 OK" { "application/json" } else { "text/plain; charset=utf-8" };
        Self { status, content_type, body }
    }
    pub(crate) fn text(status: &'static str, body: &str) -> Self {
        Self { status, content_type: "text/plain; charset=utf-8", body: body.as_bytes().to_vec() }
    }
    /// Write the HTTP/1.1 response to any `Write` sink (TLS terminator tests).
    #[cfg(test)]
    pub(crate) fn write_plain(&self, dest: &mut impl Write) -> std::io::Result<()> {
        write!(
            dest,
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        )?;
        dest.write_all(&self.body)
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
        self.write_until(stream, deadline)
    }
    pub(crate) fn write_admin(
        self,
        stream: &mut TcpStream,
        limits: HttpRequestLimits,
        accepted_at: Instant,
    ) -> Result<(), NodeCoreError> {
        let deadline = accepted_at + limits.request_timeout;
        if self.status != "408 Request Timeout" && deadline <= Instant::now() {
            return Self::text(
                "504 Gateway Timeout",
                "admin operation completed after its response deadline; outcome unknown",
            )
            .write_until(stream, Instant::now() + Duration::from_millis(100));
        }
        self.write(stream, limits, accepted_at)
    }
    fn write_until(self, stream: &mut TcpStream, deadline: Instant) -> Result<(), NodeCoreError> {
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
