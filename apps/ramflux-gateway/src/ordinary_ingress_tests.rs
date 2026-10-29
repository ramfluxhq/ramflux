// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared TCP/QUIC listeners keep ordinary requests independent of custody capacity.
use super::*;
use ramflux_protocol::custody::{
    BindingMode, CustodyClientFrame, CustodyRefusal, CustodyServerFrame,
};
use ramflux_transport::{GatewayQuicRequest, GatewayQuicResponse};
use std::time::{Duration, Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn context(custody: Option<crate::custody::Pools>) -> anyhow::Result<GatewayListenerContext> {
    let context = crate::session::tests::test_gateway_context()?;
    Ok(GatewayListenerContext {
        custody,
        node_id: context.node_id,
        gateway_id: context.gateway_id,
        peers: context.peers,
        router: context.router,
        notify: context.notify,
        #[cfg(feature = "itest-local-mint")]
        relay_service_key: context.relay_service_key,
        state: context.state,
        store: context.store,
        hub: context.hub,
    })
}

fn full_pool(
    same_ip: bool,
) -> Result<(
    Arc<ramflux_node_core::CustodyIngressLimiter>,
    Vec<ramflux_node_core::CustodyIngressPermit>,
)> {
    let limiter =
        ramflux_node_core::CustodyIngressLimiter::with_pools(256, 1024, 4, Duration::from_secs(10));
    let tick = Instant::now();
    let mut held = Vec::new();
    // Model 64 distinct source /24s, four idle custody holders each. Only source
    // metadata is simulated; ordinary clients use the actual production socket loops.
    for share in 0..64 {
        let source =
            if same_ip && share == 0 { "127.0.0.1".to_owned() } else { format!("192.0.{share}.1") };
        for _ in 0..4 {
            held.push(limiter.acquire(source.parse()?, None, tick).ok_or("custody holder")?);
        }
    }
    assert!(limiter.acquire("203.0.113.1".parse()?, None, tick).is_none());
    Ok((limiter, held))
}

#[tokio::test]
async fn ordinary_tcp_and_relay_pool_quic_work_with_64_times_four_idle_custody_holders() -> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        for same_ip in [true, false] {
            let (tcp, tcp_holders) = full_pool(same_ip)?;
            let (quic, quic_holders) = full_pool(same_ip)?;
            exercise(Some(crate::custody::Pools { tcp, quic }), CustodyRefusal::Busy).await?;
            assert!(tcp_holders.iter().chain(&quic_holders).all(|permit| !permit.is_revoked()));
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn ordinary_tcp_and_relay_pool_quic_work_without_custody_configuration() -> Result {
    tokio::time::timeout(Duration::from_secs(15), exercise(None, CustodyRefusal::Unsupported))
        .await?
}

async fn exercise(pools: Option<crate::custody::Pools>, refusal: CustodyRefusal) -> Result {
    let root = std::env::temp_dir().join(format!(
        "ramflux-ordinary-ingress-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    std::fs::create_dir(&root)?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: root.join("ca.pem"),
        service_cert: root.join("public.pem"),
        service_key: root.join("public.key"),
    };
    std::fs::write(&tls.ca_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_address = listener.local_addr()?;
    let endpoint = quinn::Endpoint::server(
        ramflux_transport::quic_gateway_server_config(&tls)?,
        "127.0.0.1:0".parse()?,
    )?;
    let quic_address = endpoint.local_addr()?;
    let full = pools.is_some();
    let context = context(pools)?;
    let tcp_server = tokio::spawn(serve_gateway_tcp_listener(
        listener,
        ramflux_transport::tcp_gateway_server_config(&tls)?,
        context.clone(),
    ));
    let quic_server = tokio::spawn(serve_gateway_quic_endpoint(endpoint, context));
    let run = requests(tcp_address, quic_address, &tls, full, refusal).await;
    tcp_server.abort();
    quic_server.abort();
    let _ = tokio::join!(tcp_server, quic_server);
    run
}

async fn requests(
    tcp_address: SocketAddr,
    quic_address: SocketAddr,
    tls: &ramflux_transport::MeshTlsConfig,
    full: bool,
    refusal: CustodyRefusal,
) -> Result {
    // Hold real idle sockets as well as the exact 64-by-four limiter state.
    // macOS cannot bind arbitrary external source prefixes, so the limiter's
    // attack source metadata above is supplied explicitly.
    let mut idle = Vec::new();
    if full {
        for _ in 0..256 {
            idle.push(tokio::net::TcpStream::connect(tcp_address).await?);
        }
    }
    let request = GatewayQuicRequest {
        method: "GET".into(),
        path: "/ordinary-not-found".into(),
        body: serde_json::Value::Null,
    };
    let expected =
        GatewayQuicResponse { status: 404, body: serde_json::json!({"error":"not found"}) };
    let custody_open =
        CustodyClientFrame::CustodyOpen { binding_mode: BindingMode::HomeRelayReceipt };
    let refused = CustodyServerFrame::Refused { code: refusal };
    let (_, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        "127.0.0.1:0".parse()?,
        tcp_address,
        "localhost",
        &tls.ca_cert,
        Duration::from_secs(5),
    )
    .await?;
    ramflux_transport::GatewaySessionFrameSink::send_frame(
        &mut stream,
        &serde_json::to_vec(&request)?,
    )
    .await?;
    let bytes = ramflux_transport::GatewaySessionFrameSource::recv_frame(&mut stream).await?;
    assert_eq!(serde_json::from_slice::<GatewayQuicResponse>(&bytes)?, expected);
    let (_, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        "127.0.0.1:0".parse()?,
        tcp_address,
        "localhost",
        &tls.ca_cert,
        Duration::from_secs(5),
    )
    .await?;
    ramflux_transport::GatewaySessionFrameSink::send_frame(
        &mut stream,
        &serde_json::to_vec(&custody_open)?,
    )
    .await?;
    let bytes = ramflux_transport::GatewaySessionFrameSource::recv_frame(&mut stream).await?;
    assert_eq!(serde_json::from_slice::<CustodyServerFrame>(&bytes)?, refused);
    // Use the exact pooled client API used by the relay; eight simultaneous
    // streams exceed the custody per-connection cap even without a full H.
    let client = Arc::new(
        ramflux_transport::QuicGatewayClient::connect_pooled(
            "127.0.0.1:0".parse()?,
            quic_address,
            "localhost",
            ramflux_transport::quic_gateway_client_config(&tls.ca_cert)?,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?,
    );
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let client = Arc::clone(&client);
        let request = request.clone();
        requests.spawn(async move { client.request_pooled(&request).await });
    }
    while let Some(response) = requests.join_next().await {
        assert_eq!(
            response?.map_err(|error| std::io::Error::other(format!("{error:?}")))?,
            expected
        );
    }
    assert!(client.is_live());
    // A custody stream on that same pooled connection is still refused.
    let mut stream = client.open_bidi_stream().await?;
    ramflux_transport::GatewaySessionFrameSink::send_frame(
        &mut stream,
        &serde_json::to_vec(&custody_open)?,
    )
    .await?;
    let bytes = ramflux_transport::GatewaySessionFrameSource::recv_frame(&mut stream).await?;
    assert_eq!(serde_json::from_slice::<CustodyServerFrame>(&bytes)?, refused);
    assert_eq!(
        client
            .request_pooled(&request)
            .await
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?,
        expected
    );
    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
}
