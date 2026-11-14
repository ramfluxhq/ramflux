// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, identity-pinned internal authority RPCs on the existing mesh runtime.

use crate::{
    MeshQuicRawPost, MeshTlsConfig, TransportError,
    mesh_quic::mesh_quic_post_raw_with_deadline_sync,
};
use std::{
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};

const CONTROL_BYTES: usize = 8192;
const READ_BYTES: usize = 65536;
const FRAME_OVERHEAD_BYTES: usize = 512;

#[derive(Clone)]
pub struct MeshAuthorityClient {
    endpoint: String,
    peer_identity: String,
    server_name: String,
    tls: MeshTlsConfig,
    admission: Arc<tokio::sync::Semaphore>,
}

impl MeshAuthorityClient {
    #[must_use]
    pub fn new(
        endpoint: String,
        peer_identity: String,
        server_name: String,
        tls: MeshTlsConfig,
        admission: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self { endpoint, peer_identity, server_name, tls, admission }
    }

    /// Call only from a blocking worker or synchronous startup, with no state/store lock held.
    /// # Errors
    /// Refuses oversized original bytes, wrong identity, capacity and the one absolute deadline.
    pub fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
        deadline: Instant,
    ) -> Result<serde_json::Value, TransportError> {
        if ramflux_protocol::canonical_json_bytes(body)?.len() > CONTROL_BYTES {
            return Err(TransportError::FrameTooLarge { len: CONTROL_BYTES + 1 });
        }
        let cap = if path == "/internal/router/notify-owner/v1"
            || path == "/internal/gateway/notify-call/v1"
        {
            READ_BYTES
        } else {
            CONTROL_BYTES
        };
        let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
        // This channel is same-node only; explicitly trust its configured mesh CA.
        // The shared mesh client's peer-root API intentionally rejects an empty list.
        let mut ca_pem = String::new();
        std::fs::File::open(&self.tls.ca_cert)?.take(65_537).read_to_string(&mut ca_pem)?;
        if ca_pem.len() > READ_BYTES {
            return Err(TransportError::FrameTooLarge { len: ca_pem.len() });
        }

        let admission = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| TransportError::BackpressureRejected { capacity: 64, in_flight: 64 })?;
        let bytes = mesh_quic_post_raw_with_deadline_sync(MeshQuicRawPost {
            endpoint: &self.endpoint,
            path,
            tls: &self.tls,
            server_name: &self.server_name,
            peer_ca_pems: std::slice::from_ref(&ca_pem),
            value: body,
            deadline: tokio::time::Instant::from_std(deadline),
            admission,
            expected_peer_spiffe: Some(&self.peer_identity),
            max_response_frame_bytes: cap + FRAME_OVERHEAD_BYTES,
        })?;
        ramflux_protocol::validate_i_json_bytes(&bytes)?;
        let reply: OriginalReply<'_> = serde_json::from_slice(&bytes)?;
        if reply.body.get().len() > cap {
            return Err(TransportError::FrameTooLarge { len: reply.body.get().len() });
        }
        if !(200..300).contains(&reply.status) {
            return Err(TransportError::HttpStatus {
                status: reply.status,
                body: "authority refused".into(),
            });
        }
        Ok(ramflux_protocol::parse_i_json(reply.body.get().as_bytes())?)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalReply<'a> {
    status: u16,
    #[serde(borrow)]
    body: &'a serde_json::value::RawValue,
}

#[cfg(test)]
mod tests;
