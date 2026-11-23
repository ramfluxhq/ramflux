// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Route admission precedes body reads for the JSON mesh frame.
use crate::{GatewayQuicRequest, TransportError};
use std::time::Instant;

/// The sender writes method and path before body (the `GatewayQuicRequest` wire order).
/// Frames without those routing headers are refused before reading a body value.
#[derive(serde::Deserialize)]
struct RoutingHeader {
    method: String,
    path: String,
    #[serde(rename = "body")]
    _body: (),
}

pub(crate) struct RouteHeader {
    bytes: Vec<u8>,
    quoted: bool,
    escaped: bool,
    start: usize,
    last: Option<String>,
}
impl RouteHeader {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new(), quoted: false, escaped: false, start: 0, last: None }
    }
    pub(crate) fn push(&mut self, byte: u8) -> Result<Option<(String, String)>, TransportError> {
        if self.bytes.len() >= 16 * 1024 {
            return Err(TransportError::NotAuthenticated);
        }
        self.bytes.push(byte);
        if self.quoted {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.quoted = false;
                self.last = Some(serde_json::from_slice(
                    self.bytes.get(self.start..).ok_or(TransportError::NotAuthenticated)?,
                )?);
            }
        } else if byte == b'"' {
            self.quoted = true;
            self.start = self.bytes.len().saturating_sub(1);
        } else if byte == b':' && self.last.as_deref() == Some("body") {
            let mut header = self.bytes.clone();
            header.extend_from_slice(b"null}");
            let route: RoutingHeader =
                serde_json::from_slice(&header).map_err(|_| TransportError::NotAuthenticated)?;
            return Ok(Some((route.method, route.path)));
        } else if matches!(byte, b'{' | b'[') && self.bytes.len() > 1 {
            return Err(TransportError::NotAuthenticated);
        }
        Ok(None)
    }
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) fn decode(
    frame: &[u8],
    method: &str,
    path: &str,
) -> Result<GatewayQuicRequest, TransportError> {
    let request: GatewayQuicRequest = ramflux_protocol::parse_i_json(frame)?;
    if request.method != method || request.path != path {
        return Err(TransportError::NotAuthenticated);
    }
    Ok(request)
}
pub(crate) fn expired() -> TransportError {
    TransportError::Quic("federation ingress deadline exceeded".into())
}

impl super::MeshQuicServer {
    /// Accept a bounded mesh frame, enforcing routing policy before allocating/reading its body.
    /// # Errors
    /// Admission, malformed frame, size, transport or absolute deadline failure.
    pub async fn accept_admitted_request(
        connection: &super::MeshQuicConnection,
        cap: &(dyn Fn(&str, &str) -> usize + Sync),
        admit: &(dyn Fn(&str, &str) -> bool + Sync),
        deadline: Instant,
    ) -> Result<super::MeshQuicAcceptedRequest, TransportError> {
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let (mut send, mut recv) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connection.connection.accept_bi(),
            )
            .await
            .map_err(|_| expired())?
            .map_err(|e| TransportError::Quic(e.to_string()))?;
            let mut prefix = [0; 4];
            recv.read_exact(&mut prefix).await.map_err(|e| TransportError::Quic(e.to_string()))?;
            let len = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| expired())?;
            let mut header = RouteHeader::new();
            let route = loop {
                if header.bytes.len() >= len {
                    return Err(TransportError::NotAuthenticated);
                }
                let mut byte = [0];
                recv.read_exact(&mut byte)
                    .await
                    .map_err(|e| TransportError::Quic(e.to_string()))?;
                match header.push(byte[0]) {
                    Ok(Some(route)) => break route,
                    Ok(None) => {}
                    Err(error) => {
                        refuse(&mut send, &mut recv).await?;
                        return Err(error);
                    }
                }
            };
            if !admit(&route.0, &route.1) {
                refuse(&mut send, &mut recv).await?;
                return Err(TransportError::NotAuthenticated);
            }
            let mut frame = header.into_bytes();
            let remaining = len.saturating_sub(frame.len());
            if remaining > cap(&route.0, &route.1).saturating_add(512) {
                return Err(TransportError::FrameTooLarge { len });
            }
            let start = frame.len();
            frame.resize(len, 0);
            recv.read_exact(frame.get_mut(start..).ok_or_else(expired)?)
                .await
                .map_err(|e| TransportError::Quic(e.to_string()))?;
            let request = match decode(&frame, &route.0, &route.1) {
                Ok(request) => request,
                Err(error) => {
                    if ramflux_protocol::is_i_json_rejection(&error) {
                        write_error(
                            &mut send,
                            &mut recv,
                            400,
                            ramflux_protocol::i_json_rejection_body(),
                        )
                        .await?;
                    }
                    return Err(error);
                }
            };
            let raw: crate::mesh_quic_limited::RawBodyOnly = serde_json::from_slice(&frame)?;
            if raw.body.get().len() > cap(&route.0, &route.1) {
                return Err(TransportError::FrameTooLarge { len });
            }
            Ok(super::MeshQuicAcceptedRequest {
                request,
                raw_body: None,
                control: None,
                send,
                recv,
            })
        })
        .await
        .map_err(|_| expired())?
    }
}
async fn refuse(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<(), TransportError> {
    write_error(send, recv, 403, serde_json::json!({"error":"mesh route requires verified peer"}))
        .await
}
async fn write_error(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    status: u16,
    body: serde_json::Value,
) -> Result<(), TransportError> {
    let _ = recv.stop(quinn::VarInt::from_u32(u32::from(status)));
    crate::write_quic_json_message(send, &crate::GatewayQuicResponse { status, body }).await?;
    send.finish().map_err(|e| TransportError::Quic(e.to_string()))?;
    let _ = send.stopped().await;
    Ok(())
}
