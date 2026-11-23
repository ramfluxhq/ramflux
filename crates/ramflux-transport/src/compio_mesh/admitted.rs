// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compio uses the same route-header decoder and admission contract as Quinn.
use super::{
    CompioMeshQuicAcceptedRequest, CompioMeshQuicConnection, CompioMeshQuicServer,
    compio_finish_send_stream, compio_read_exact, compio_write_json_message,
};
use crate::{
    TransportError,
    mesh_quic::admitted::{RouteHeader, decode, expired},
};
use std::time::Instant;
impl CompioMeshQuicServer {
    /// Enforce routing policy before reading the body of a bounded JSON mesh frame.
    /// # Errors
    /// Admission, framing, size, transport or absolute deadline failure.
    pub async fn accept_admitted_request(
        connection: &CompioMeshQuicConnection,
        cap: &(dyn Fn(&str, &str) -> usize + Sync),
        admit: &(dyn Fn(&str, &str) -> bool + Sync),
        deadline: Instant,
    ) -> Result<CompioMeshQuicAcceptedRequest, TransportError> {
        compio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
            let (mut send, mut recv) = compio::time::timeout(
                std::time::Duration::from_secs(2),
                connection.connection.accept_bi(),
            )
            .await
            .map_err(|_| expired())?
            .map_err(|e| TransportError::Quic(e.to_string()))?;
            let mut prefix = [0; 4];
            compio_read_exact(&mut recv, &mut prefix).await?;
            let len = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| expired())?;
            let mut header = RouteHeader::new();
            let mut count = 0;
            let route = loop {
                if count >= len {
                    return Err(TransportError::NotAuthenticated);
                }
                let mut byte = [0];
                compio_read_exact(&mut recv, &mut byte).await?;
                count += 1;
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
            if len.saturating_sub(frame.len()) > cap(&route.0, &route.1).saturating_add(512) {
                return Err(TransportError::FrameTooLarge { len });
            }
            let start = frame.len();
            frame.resize(len, 0);
            compio_read_exact(&mut recv, frame.get_mut(start..).ok_or_else(expired)?).await?;
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
            Ok(CompioMeshQuicAcceptedRequest {
                request,
                raw_body: None,
                control: None,
                peer_spiffe_uri: connection.peer_spiffe_uri.clone(),
                send,
                recv,
            })
        })
        .await
        .map_err(|_| expired())?
    }
}
async fn refuse(
    send: &mut compio_quic::SendStream,
    recv: &mut compio_quic::RecvStream,
) -> Result<(), TransportError> {
    write_error(send, recv, 403, serde_json::json!({"error":"mesh route requires verified peer"}))
        .await
}
async fn write_error(
    send: &mut compio_quic::SendStream,
    recv: &mut compio_quic::RecvStream,
    status: u16,
    body: serde_json::Value,
) -> Result<(), TransportError> {
    let _ = recv.stop(compio_quic::VarInt::from_u32(u32::from(status)));
    compio_write_json_message(send, &crate::GatewayQuicResponse { status, body }).await?;
    compio_finish_send_stream(send)?;
    let _ = send.stopped().await;
    Ok(())
}
