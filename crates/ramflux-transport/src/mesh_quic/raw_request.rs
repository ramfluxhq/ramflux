// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original JSON replies and admission owned by the actual pooled transport work.
use super::{
    MeshQuicCircuitBreakers, MeshQuicClientJob, MeshQuicClientRequestJob,
    MeshQuicClientRequestPayload, MeshQuicClientResponse, MeshQuicClientResponsePayload,
    MeshQuicPoolRegistry, mesh_quic_cached_request, mesh_quic_client_runtime,
};
use crate::{GatewayQuicRequest, MeshTlsConfig, TransportError};
use std::{sync::Arc, time::Instant};

/// A raw JSON exchange with an absolute deadline and caller-owned admission budget.
pub struct MeshQuicRawPost<'a, T> {
    pub endpoint: &'a str,
    pub path: &'a str,
    pub tls: &'a MeshTlsConfig,
    pub server_name: &'a str,
    pub peer_ca_pems: &'a [String],
    pub value: &'a T,
    pub deadline: tokio::time::Instant,
    pub admission: tokio::sync::OwnedSemaphorePermit,
}

pub(super) struct RawRequestControl {
    pub deadline: tokio::time::Instant,
    pub admission: tokio::sync::OwnedSemaphorePermit,
    pub completion: tokio::sync::oneshot::Sender<()>,
}

fn deadline_error() -> TransportError {
    TransportError::Quic("mesh request deadline exceeded".into())
}

/// Return the original mesh response frame, without decoding its JSON body.
/// The request is written to the wire at most once: no cached-connection re-send.
/// Cancellation drops the actual request future.
/// Admission stays with that work even if this caller is aborted. A timed-out caller
/// waits for transport termination before returning.
/// # Errors
/// Returns serialization, transport, runtime shutdown or absolute-deadline errors.
pub async fn mesh_quic_post_raw_with_peer_ca_pems_async<T: serde::Serialize>(
    post: MeshQuicRawPost<'_, T>,
) -> Result<Vec<u8>, TransportError> {
    if tokio::time::Instant::now() >= post.deadline {
        return Err(deadline_error());
    }
    let (response, mut receiver) = tokio::sync::oneshot::channel();
    let (completion, finished) = tokio::sync::oneshot::channel();
    mesh_quic_client_runtime()
        .jobs
        .send(MeshQuicClientJob {
            request: MeshQuicClientRequestJob {
                endpoint: post.endpoint.into(),
                server_name: post.server_name.into(),
                tls: post.tls.clone(),
                peer_ca_pems: post.peer_ca_pems.to_vec(),
                request: MeshQuicClientRequestPayload::RawJson(GatewayQuicRequest {
                    method: "POST".into(),
                    path: post.path.into(),
                    body: serde_json::to_value(post.value)?,
                }),
                expected_gateway_instance: None,
                enqueued_at: Instant::now(),
            },
            response: MeshQuicClientResponse::Async(response),
            raw: Some(RawRequestControl {
                deadline: post.deadline,
                admission: post.admission,
                completion,
            }),
        })
        .map_err(|_| TransportError::Quic("mesh QUIC runtime stopped".into()))?;
    if let Ok(result) = tokio::time::timeout_at(post.deadline, &mut receiver).await {
        match result.map_err(|_| TransportError::Quic("mesh QUIC runtime stopped".into()))?? {
            MeshQuicClientResponsePayload::RawJson(bytes) => Ok(bytes),
            _ => Err(crate::quic_errors::wire("unexpected raw mesh response kind")),
        }
    } else {
        drop(receiver);
        // The worker owns the permit and must drop the live request before acknowledging.
        let _terminated = finished.await;
        Err(deadline_error())
    }
}

pub(super) async fn run(
    pools: Arc<MeshQuicPoolRegistry>,
    breakers: Arc<MeshQuicCircuitBreakers>,
    request: MeshQuicClientRequestJob,
    mut response: MeshQuicClientResponse,
    control: RawRequestControl,
    pool_size: usize,
) {
    let result = {
        let work = mesh_quic_cached_request(pools, breakers, request, pool_size, false);
        tokio::pin!(work);
        tokio::select! {
            biased;
            () = response.closed() => Err(TransportError::Quic("mesh request cancelled".into())),
            result = tokio::time::timeout_at(control.deadline, &mut work) => {
                result.unwrap_or_else(|_| Err(deadline_error()))
            }
        }
    }; // Drop all stream/connect/retry futures before releasing admission or completing the call.
    drop(control.admission);
    response.send(result);
    let _completed = control.completion.send(());
}
