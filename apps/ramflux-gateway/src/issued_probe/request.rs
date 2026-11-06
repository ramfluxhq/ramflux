// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Raw probe replies and one shared admission budget through actual transport termination.
use crate::RouterMeshClient;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) struct Requests(pub(crate) Arc<Semaphore>);
impl Default for Requests {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(4)))
    }
}
impl Requests {
    async fn admit(&self, deadline: tokio::time::Instant) -> anyhow::Result<OwnedSemaphorePermit> {
        Ok(tokio::time::timeout_at(deadline, self.0.clone().acquire_owned()).await??)
    }
}
pub(super) struct Reply {
    pub bytes: Vec<u8>,
    pub mesh_frame: bool,
}

pub(super) async fn post(
    router: &RouterMeshClient,
    targets: Vec<String>,
    requests: &Requests,
) -> anyhow::Result<Reply> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1500);
    let http_deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    let value = ramflux_node_core::IssuedSeqsRequest { targets };
    let admission = requests.admit(deadline).await?;
    if let Some(mesh) = &router.async_mesh {
        let result = ramflux_transport::mesh_quic_post_raw_with_peer_ca_pems_async(
            ramflux_transport::MeshQuicRawPost {
                endpoint: &mesh.endpoint,
                path: "/mvp0/issued-seqs",
                tls: &mesh.tls,
                server_name: &mesh.server_name,
                peer_ca_pems: &mesh.peer_ca_pems,
                value: &value,
                deadline,
                admission,
            },
        )
        .await;
        match result {
            Ok(bytes) => return Ok(Reply { bytes, mesh_frame: true }),
            Err(ramflux_transport::TransportError::Quic(_)) => {}
            Err(error) => return Err(error.into()),
        }
    } else {
        return http(router, &value, http_deadline, admission).await;
    }
    // QUIC has terminated and released its permit before an HTTP fallback can enter.
    let admission = requests.admit(deadline).await?;
    http(router, &value, http_deadline, admission).await
}
async fn http(
    router: &RouterMeshClient,
    value: &ramflux_node_core::IssuedSeqsRequest,
    deadline: std::time::Instant,
    admission: OwnedSemaphorePermit,
) -> anyhow::Result<Reply> {
    let router = router.clone();
    let body = serde_json::to_vec(value)?;
    let bytes = tokio::task::spawn_blocking(move || {
        let _admission = admission;
        let tls = ramflux_transport::BoundedHttpTls::new(&router.tls, &router.server_name, None)?;
        ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &router.endpoint,
            path: "/mvp0/issued-seqs",
            body: &body,
            tls: Some(&tls),
            deadline,
            max_bytes: ramflux_node_core::ENTRY_FRAME_BYTE_CAP,
        })
    })
    .await??;
    Ok(Reply { bytes, mesh_frame: false })
}
