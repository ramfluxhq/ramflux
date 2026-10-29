// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration entrypoints for the production gateway dispatchers.
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::{Arc, Mutex};
type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// Gateway forwarding configuration using real mesh TLS endpoints.
#[derive(Clone)]
pub struct Gateway {
    router: crate::RouterMeshClient,
    context: crate::GatewayQuicContext,
}
impl Gateway {
    /// Creates a gateway runtime backed by its own durable database.
    /// # Errors
    /// Returns storage errors.
    pub fn open(config: &ramflux_node_core::NodeServiceConfig) -> anyhow::Result<Self> {
        let router = crate::RouterMeshClient {
            endpoint: config
                .mesh
                .endpoints
                .get("router")
                .ok_or_else(|| anyhow::anyhow!("router endpoint"))?
                .clone(),
            server_name: "ramflux-router".into(),
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: config.mesh.ca_cert.clone().into(),
                service_cert: config.mesh.service_cert.clone().into(),
                service_key: config.mesh.service_key.clone().into(),
            },
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: None,
        };
        let store = Arc::new(ramflux_node_core::GatewayRedbStore::open(&config.redb_path)?);
        let state = ramflux_node_core::GatewayState::new();
        store.save_state(&state)?;
        let context = crate::GatewayQuicContext {
            node_id: config.node_id.clone(),
            gateway_id: "ramflux-gateway".into(),
            peers: crate::GatewayPeerDirectory::empty(config),
            router: router.clone(),
            notify: crate::NotifyHttpClient {
                endpoint: "http://127.0.0.1:1".into(),
                signer: ramflux_node_core::NodeServiceSigningKey::from_seed([42; 32]),
                mesh: None,
            },
            #[cfg(feature = "itest-local-mint")]
            relay_service_key: vec![],
            state: Arc::new(Mutex::new(state)),
            store,
            hub: Arc::new(crate::GatewaySessionHub::default()),
            remote_addr: "127.0.0.1:50000".parse()?,
        };
        Ok(Self { router, context })
    }

    /// Runs an anonymous request through the production gateway dispatcher.
    /// # Errors
    /// Returns mesh transport errors.
    pub async fn anonymous(
        &self,
        request: ramflux_transport::GatewayQuicRequest,
    ) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
        crate::dispatch_quic_json_request(&self.router, request, self.context.remote_addr.ip())
            .await
    }

    /// Runs one frame under an authenticated runtime through the production session loop.
    /// # Errors
    /// Returns session or mesh transport errors.
    pub async fn frame(
        &self,
        identity: ramflux_crypto::RootQualifiedDeviceRef,
        body: Vec<u8>,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let frames = Arc::new(Mutex::new(Vec::new()));
        let runtime = crate::GatewaySessionRuntime {
            supports_forward_ack: true,
            session_id: "test-session".into(),
            resume_token: "test-resume".into(),
            principal_id: "integration".into(),
            device_id: identity.device_id().into(),
            target_delivery_id: identity.storage_key().into(),
            device_epoch: 1,
            branch_public_key: String::new(),
            source_identity: identity,
        };
        let send: crate::GatewaySendHandle =
            Arc::new(tokio::sync::Mutex::new(Box::new(Sink(Arc::clone(&frames)))));
        crate::session::run_gateway_session_loop(
            send,
            Box::new(Source(Some(body))),
            self.context.clone(),
            runtime,
        )
        .await?;
        let result = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?.clone();
        Ok(result)
    }
}
struct Sink(Arc<Mutex<Vec<Vec<u8>>>>);
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| TransportError::Quic("frame mutex".into()))?
                .push(body.to_vec());
            Ok(())
        })
    }
}
struct Source(Option<Vec<u8>>);
impl GatewaySessionFrameSource for Source {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.0.take().ok_or_else(|| TransportError::Quic("integration frame complete".into()))
        })
    }
}
