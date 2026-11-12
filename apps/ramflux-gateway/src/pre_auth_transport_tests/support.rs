// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real gateway carriers share one admission state and talk to a separate router process.
use ramflux_node_core::{
    GatewayAuthFrame, GatewayClientFrame, GatewayOpenFrame, GatewayServerFrame,
};
use ramflux_transport::{GatewaySessionTransport, MeshTlsConfig, QuicGatewayClient};
use std::net::SocketAddr;
use std::time::Duration;

pub(crate) struct Fixture {
    pub context: crate::GatewayQuicContext,
    pub tls: MeshTlsConfig,
    pub tcp: SocketAddr,
    pub quic: SocketAddr,
    #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
    pub compio: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
    thread: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
    _router: crate::real_router_fixture::Child,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
        {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}
impl Fixture {
    pub async fn new() -> anyhow::Result<Self> {
        Self::new_custody(None).await
    }
    pub async fn new_custody(
        node: Option<&ramflux_crypto::custody::VerifiedNodeRecord>,
    ) -> anyhow::Result<Self> {
        let (router, mut context) =
            crate::real_router_fixture::real_router_with_custody(node).await?;
        if node.is_some() {
            context.custody = Some(crate::custody::Pools {
                tcp: ramflux_node_core::CustodyIngressLimiter::with_pools(
                    256,
                    Some(1024),
                    4,
                    Duration::from_secs(10),
                ),
                quic: ramflux_node_core::CustodyIngressLimiter::with_pools(
                    256,
                    Some(1024),
                    4,
                    Duration::from_secs(10),
                ),
            });
        }
        let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
        let request = crate::registration_forward_tests::registration(now)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let _: ramflux_node_core::IdentityRegistrationResponse =
            crate::router_post_json_async(&context.router, "/mvp1/identity/register", &request)
                .await?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = MeshTlsConfig {
            ca_cert: router.root().join("public-ca.pem"),
            service_cert: router.root().join("public.pem"),
            service_key: router.root().join("public.key"),
        };
        std::fs::write(&tls.ca_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
        crate::gateway_state(&context.state)?.set_pre_auth_policy(
            ramflux_node_core::GatewayPreAuthPolicy {
                enabled: true,
                per_source_ip_handshake_rate: 1,
                window_seconds: 3600,
                ..Default::default()
            },
        )?;
        context.store.save_state(&*crate::gateway_state(&context.state)?)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tcp = listener.local_addr()?;
        let endpoint = quinn::Endpoint::server(
            ramflux_transport::quic_gateway_server_config(&tls)?,
            "127.0.0.1:0".parse()?,
        )?;
        let quic = endpoint.local_addr()?;
        let listener_context = listener_context(&context);
        let tasks = vec![
            tokio::spawn(crate::serve::serve_gateway_tcp_listener(
                listener,
                ramflux_transport::tcp_gateway_server_config(&tls)?,
                listener_context.clone(),
            )),
            tokio::spawn(crate::serve::serve_gateway_quic_endpoint(
                endpoint,
                listener_context.clone(),
            )),
        ];
        #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
        let (compio, stop, thread) = start_compio(tls.clone(), listener_context).await?;
        Ok(Self {
            context,
            tls,
            tcp,
            quic,
            tasks,
            _router: router,
            #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
            compio,
            #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
            stop: Some(stop),
            #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
            thread: Some(thread),
        })
    }
    pub async fn connect(&self, route: Route, peer: &str) -> anyhow::Result<Client> {
        let bind = format!("{peer}:0").parse()?;
        if matches!(route, Route::Tcp) {
            let (_, stream) = ramflux_transport::TcpTlsGatewayClient::connect(
                bind,
                self.tcp,
                "localhost",
                &self.tls.ca_cert,
                Duration::from_secs(10),
            )
            .await?;
            return Ok(Client { stream: Box::new(stream), _connection: None });
        }
        let address = match route {
            Route::Quinn => self.quic,
            Route::Tcp => self.tcp,
            #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
            Route::Compio => self.compio,
        };
        let connection = QuicGatewayClient::connect_pooled(
            bind,
            address,
            "localhost",
            ramflux_transport::quic_gateway_client_config(&self.tls.ca_cert)?,
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let stream = connection.open_bidi_stream().await?;
        Ok(Client { stream: Box::new(stream), _connection: Some(connection) })
    }
}
pub(crate) fn listener_context(
    c: &crate::GatewayQuicContext,
) -> crate::serve::GatewayListenerContext {
    crate::serve::GatewayListenerContext {
        custody: c.custody.clone(),
        node_id: c.node_id.clone(),
        gateway_id: c.gateway_id.clone(),
        peers: c.peers.clone(),
        router: c.router.clone(),
        notify: c.notify.clone(),
        #[cfg(feature = "itest-local-mint")]
        relay_service_key: c.relay_service_key.clone(),
        state: c.state.clone(),
        store: c.store.clone(),
        hub: c.hub.clone(),
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Route {
    Quinn,
    Tcp,
    #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
    Compio,
}
pub(crate) fn routes() -> Vec<Route> {
    vec![
        Route::Quinn,
        Route::Tcp,
        #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
        Route::Compio,
    ]
}
pub(crate) struct Client {
    pub stream: Box<dyn GatewaySessionTransport + Send>,
    _connection: Option<QuicGatewayClient>,
}
impl Client {
    pub async fn exchange(
        &mut self,
        open: GatewayOpenFrame,
        auth: GatewayAuthFrame,
    ) -> anyhow::Result<GatewayServerFrame> {
        self.stream.send_frame(&serde_json::to_vec(&GatewayClientFrame::Open { open })?).await?;
        // A challenged server may already have closed its receive half.
        let _ =
            self.stream.send_frame(&serde_json::to_vec(&GatewayClientFrame::Auth { auth })?).await;
        let bytes =
            tokio::time::timeout(Duration::from_secs(15), self.stream.recv_frame()).await??;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
async fn start_compio(
    tls: MeshTlsConfig,
    context: crate::serve::GatewayListenerContext,
) -> anyhow::Result<(
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<anyhow::Result<()>>,
)> {
    let (ready, started) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = compio::runtime::Runtime::new()?;
        runtime.block_on(async move {
            let server=ramflux_transport::CompioGatewayQuicServer::bind("127.0.0.1:0",&tls).await?;
            ready.send(server.local_addr()?).map_err(|_|anyhow::anyhow!("compio readiness receiver closed"))?;
            tokio::select! {_=stopped=>Ok(()),result=crate::compio_gateway::serve_gateway_compio_endpoint(server,context)=>result}
        })
    });
    let address = tokio::time::timeout(Duration::from_secs(15), started).await??;
    Ok((address, stop, thread))
}
