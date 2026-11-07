// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Size- and time-bounded mesh QUIC ingress. The caller authenticates the peer from the
//! connection first; this reader then enforces a byte cap on the received frame before it
//! allocates anything, hands back the request body exactly as received (never parsed and
//! re-serialized), and bounds every read and write by one absolute deadline. A response
//! never waits for the peer to finish its send side.
use crate::{
    GatewayQuicResponse, MeshQuicConnection, MeshQuicServer, TransportError,
    quic_gateway::write_quic_raw_frame,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::time::Instant;

/// Room for the method and path around the body inside one request frame.
pub const LIMITED_ENVELOPE_SLACK: usize = 512;

/// Only the body of a request frame, as received.
#[derive(Deserialize)]
pub(crate) struct RawBodyOnly {
    pub(crate) body: Box<RawValue>,
}

#[derive(Deserialize)]
struct RawRequest {
    method: String,
    path: String,
    body: Box<RawValue>,
}

/// Writes one response frame and returns once the stream is acknowledged or the deadline
/// passes. It never drains the peer's send side.
pub struct MeshQuicLimitedResponder {
    send: quinn::SendStream,
    _recv: quinn::RecvStream,
}

pub struct MeshQuicLimitedRequest {
    pub method: String,
    pub path: String,
    /// The body bytes exactly as received.
    pub body: Vec<u8>,
    pub responder: MeshQuicLimitedResponder,
}

pub enum MeshQuicLimitedIngress {
    Request(MeshQuicLimitedRequest),
    /// The frame or its body exceeded the cap; nothing past the length prefix was
    /// allocated for an oversized frame.
    TooLarge(MeshQuicLimitedResponder),
}

fn expired() -> TransportError {
    TransportError::Quic("mesh request deadline exceeded".into())
}

impl MeshQuicConnection {
    /// Closes the connection with an application code; no stream is read.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(quinn::VarInt::from_u32(code), reason);
    }
}

impl MeshQuicLimitedResponder {
    /// # Errors
    /// Serialization failure, write failure, or the deadline.
    pub async fn respond<T: serde::Serialize>(
        mut self,
        status: u16,
        value: &T,
        deadline: Instant,
    ) -> Result<(), TransportError> {
        let at = tokio::time::Instant::from_std(deadline);
        if Instant::now() >= deadline {
            return Err(expired());
        }
        let frame = serde_json::to_vec(&GatewayQuicResponse {
            status,
            body: serde_json::to_value(value)?,
        })?;
        tokio::time::timeout_at(at, write_quic_raw_frame(&mut self.send, &frame))
            .await
            .map_err(|_| expired())??;
        self.send.finish().map_err(|error| TransportError::Quic(error.to_string()))?;
        // Wait for the peer to acknowledge the finished stream, but only until the deadline.
        let _ = tokio::time::timeout_at(at, self.send.stopped()).await;
        Ok(())
    }
}

impl MeshQuicServer {
    /// Accepts one request stream and reads its frame under `max_body` and `deadline`.
    /// # Errors
    /// Transport failures, malformed frames, or the deadline.
    pub async fn accept_limited_request(
        connection: &MeshQuicConnection,
        max_body: usize,
        deadline: Instant,
    ) -> Result<MeshQuicLimitedIngress, TransportError> {
        let at = tokio::time::Instant::from_std(deadline);
        let stream = tokio::time::timeout_at(at, Self::accept_bi_on_connection(connection))
            .await
            .map_err(|_| expired())??;
        let (send, mut recv) = (stream.send, stream.recv);
        let responder = |send, recv| MeshQuicLimitedResponder { send, _recv: recv };
        let mut prefix = [0_u8; 4];
        tokio::time::timeout_at(at, recv.read_exact(&mut prefix))
            .await
            .map_err(|_| expired())?
            .map_err(|error| TransportError::Quic(format!("request length: {error}")))?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len > max_body.saturating_add(LIMITED_ENVELOPE_SLACK) {
            return Ok(MeshQuicLimitedIngress::TooLarge(responder(send, recv)));
        }
        let mut frame = vec![0_u8; len];
        tokio::time::timeout_at(at, recv.read_exact(&mut frame))
            .await
            .map_err(|_| expired())?
            .map_err(|error| TransportError::Quic(format!("request frame: {error}")))?;
        let parsed: RawRequest = serde_json::from_slice(&frame)?;
        if parsed.body.get().len() > max_body {
            return Ok(MeshQuicLimitedIngress::TooLarge(responder(send, recv)));
        }
        Ok(MeshQuicLimitedIngress::Request(MeshQuicLimitedRequest {
            method: parsed.method,
            path: parsed.path,
            body: parsed.body.get().as_bytes().to_vec(),
            responder: responder(send, recv),
        }))
    }
}

/// Sends one request frame exactly as given (no normalization) and returns the decoded
/// response. For ingress tests that must control the wire bytes, such as padded bodies.
/// # Errors
/// TLS, QUIC or framing failures, or the deadline.
pub async fn mesh_quic_exchange_raw_frame(
    endpoint: &str,
    tls: &crate::MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    frame: &[u8],
    deadline: Instant,
) -> Result<GatewayQuicResponse, TransportError> {
    let at = tokio::time::Instant::from_std(deadline);
    let addr = tokio::net::lookup_host(endpoint)
        .await?
        .next()
        .ok_or_else(|| TransportError::Quic("no address".into()))?;
    let mut client = quinn::Endpoint::client("0.0.0.0:0".parse().map_err(|_| expired())?)?;
    client.set_default_client_config(crate::tls_config::mesh_quic_client_config_with_pem_roots(
        tls,
        peer_ca_pems,
    )?);
    let connecting =
        client.connect(addr, server_name).map_err(|e| TransportError::Quic(e.to_string()))?;
    let connection = tokio::time::timeout_at(at, connecting)
        .await
        .map_err(|_| expired())?
        .map_err(|e| TransportError::Quic(e.to_string()))?;
    let (mut send, mut recv) =
        connection.open_bi().await.map_err(|e| TransportError::Quic(e.to_string()))?;
    tokio::time::timeout_at(at, write_quic_raw_frame(&mut send, frame))
        .await
        .map_err(|_| expired())??;
    let response = tokio::time::timeout_at(at, crate::quic_gateway::read_quic_raw_frame(&mut recv))
        .await
        .map_err(|_| expired())??;
    Ok(ramflux_protocol::parse_i_json(&response)?)
}
