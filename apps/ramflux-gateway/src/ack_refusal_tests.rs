// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! All legacy ACK consumers retain a typed, nonfatal router refusal.
use super::{sink, test_runtime};
use ramflux_node_core::GatewayServerFrame;
fn ack() -> anyhow::Result<ramflux_protocol::Ack> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "ack_id":"ack-test","envelope_id":"entry-1","receiver_device_id":"receiver",
        "received_at":1_760_000_010,"ext":{"inbox_seq":1}
    }))?)
}
type RefusalRouter =
    (crate::RouterMeshClient, std::thread::JoinHandle<Result<(), String>>, std::path::PathBuf);
fn refusal_router() -> anyhow::Result<RefusalRouter> {
    use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
    let root =
        temp_cert_root("ack-refusal-relays").map_err(|e| anyhow::Error::msg(e.to_string()))?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router.tls)?;
    let mut client_tls = gateway.tls;
    client_tls.ca_cert.clone_from(&router.tls.ca_cert);
    let client = crate::RouterMeshClient {
        endpoint: server.local_addr()?.to_string(),
        server_name: "ramflux-router".into(),
        tls: client_tls,
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: None,
    };
    let task = std::thread::spawn(move || -> Result<(), String> {
        for _ in 0..(2 + usize::from(cfg!(feature = "itest-http"))) {
            let mut stream = server
                .accept_authenticated_with_pem_roots(
                    &router.tls,
                    std::slice::from_ref(&gateway.ca_pem),
                )
                .map_err(|e| e.to_string())?
                .stream;
            let request = ramflux_transport::read_mesh_http_request(&mut stream)
                .map_err(|e| e.to_string())?
                .ok_or("missing ACK")?;
            if request.path != "/mvp0/ack" && request.path != "/mvp0/ack-bound" {
                return Err(format!("unexpected path {}", request.path));
            }
            ramflux_transport::write_mesh_json_response(
                &mut stream,
                "200 OK",
                &serde_json::json!({"reason":"ack_backpressure_retry"}),
            )
            .map_err(|e| e.to_string())?;
            ramflux_transport::close_mesh_server_stream(&mut stream).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    Ok((client, task, root))
}
#[tokio::test]
async fn legacy_ack_relays_forward_backpressure() -> anyhow::Result<()> {
    let (router, task, root) = refusal_router()?;
    let (_fixture_directory_0, fixture_value_0) = super::super::tests::test_gateway_context()?;
    let mut context = fixture_value_0;
    context.router = router;
    let (send, frames) = sink();
    super::super::handle_gateway_ack(&send, &context, &test_runtime()?, &ack()?).await?;
    {
        let frames = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?;
        anyhow::ensure!(frames.len() == 1, "refusal must produce exactly one frame");
        anyhow::ensure!(
            matches!(&frames[0],GatewayServerFrame::Nack{reason} if reason=="ack_backpressure_retry"),
            "typed Nack, no cursor"
        );
    }
    let response = crate::quic_dispatch::dispatch_quic_json_request(
        &context.router,
        ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp0/ack".into(),
            body: serde_json::to_value(ack()?)?,
        },
        std::net::Ipv4Addr::LOCALHOST.into(),
        &context.gateway_id,
    )
    .await?;
    anyhow::ensure!(
        response.status == 200
            && response.body == serde_json::json!({"reason":"ack_backpressure_retry"}),
        "typed QUIC refusal"
    );
    #[cfg(feature = "itest-http")]
    http_refusal(&context.router)?;
    task.join().map_err(|_| anyhow::anyhow!("router thread"))?.map_err(anyhow::Error::msg)?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[cfg(feature = "itest-http")]
fn http_refusal(router: &crate::RouterMeshClient) -> anyhow::Result<()> {
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let (mut server, _) = listener.accept()?;
    let request = ramflux_node_core::NodeHttpRequest {
        method: "POST".into(),
        path: "/mvp0/ack".into(),
        body: serde_json::to_vec(&ack()?)?,
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    };
    crate::itest_http::dispatch_protected_itest_request(
        &mut server,
        router,
        &request,
        "ramflux-gateway",
    )?;
    drop(server);
    let mut bytes = String::new();
    client.read_to_string(&mut bytes)?;
    let (_, body) = bytes.split_once("\r\n\r\n").ok_or_else(|| anyhow::anyhow!("HTTP response"))?;
    anyhow::ensure!(
        serde_json::from_str::<serde_json::Value>(body)?
            == serde_json::json!({"reason":"ack_backpressure_retry"}),
        "typed HTTP refusal"
    );
    Ok(())
}
