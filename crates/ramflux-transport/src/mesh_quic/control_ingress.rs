// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Eight-KiB notification control ingress and response lifetime admission.

use super::{
    MeshQuicAcceptedBiStream, MeshQuicAcceptedRequest, MeshQuicConnection, MeshQuicServer,
    TransportError, raw_attachment_body,
};
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

pub(crate) struct ControlRequest {
    pub(crate) deadline: Instant,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

fn deadline_error() -> TransportError {
    TransportError::Quic("notification control deadline exceeded".into())
}

pub(crate) fn admit() -> Result<ControlRequest, TransportError> {
    static ADMISSION: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let admission = Arc::clone(ADMISSION.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(64))))
        .try_acquire_owned()
        .map_err(|_| TransportError::BackpressureRejected { capacity: 64, in_flight: 64 })?;
    Ok(ControlRequest { deadline, _admission: admission })
}

impl MeshQuicServer {
    /// Accept a stream on a connection dedicated to notification controls.
    /// # Errors
    /// Refuses transport, admission, original byte-cap and five-second read failures.
    pub async fn accept_control_request_on_connection(
        connection: &MeshQuicConnection,
    ) -> Result<MeshQuicAcceptedRequest, TransportError> {
        let stream = Self::accept_bi_on_connection(connection).await?;
        Self::read_control_request_from_bi(stream).await
    }

    /// Decode notification controls before the generic mesh decoder can allocate a large frame.
    /// The 64-process admission is retained through the actual response, including cancellation.
    /// # Errors
    /// Refuses oversized or non-I-JSON original bodies, capacity and the absolute deadline.
    pub async fn read_control_request_from_bi(
        stream: MeshQuicAcceptedBiStream,
    ) -> Result<MeshQuicAcceptedRequest, TransportError> {
        let control = admit()?;
        let deadline = control.deadline;
        let MeshQuicAcceptedBiStream { send, mut recv, .. } = stream;
        let frame = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            crate::quic_gateway::read_quic_raw_frame_limited(&mut recv, 8192 + 512),
        )
        .await
        .map_err(|_| deadline_error())??;
        let raw_body = raw_attachment_body(&frame, 8192)?;
        let request = ramflux_protocol::parse_i_json(&frame)?;
        Ok(MeshQuicAcceptedRequest {
            request,
            raw_body: Some(raw_body),
            send,
            recv,
            control: Some(control),
        })
    }
}
