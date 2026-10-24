// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-authentication directory rejection at the actual gateway dispatch boundaries.
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::{Arc, Mutex};
type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
struct Sink(Arc<Mutex<Vec<Vec<u8>>>>);
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| TransportError::Quic("test sink mutex".into()))?
                .push(body.to_vec());
            Ok(())
        })
    }
}
struct NoReceive;
impl GatewaySessionFrameSource for NoReceive {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async {
            Err(TransportError::Quic(
                "directory must reject before reading authentication or using the router".into(),
            ))
        })
    }
}
#[tokio::test]
async fn an_unauthenticated_directory_frame_is_rejected_before_reading_or_contacting_the_router()
-> anyhow::Result<()> {
    let frames = Arc::new(Mutex::new(Vec::new()));
    super::handle_gateway_session_transport(
        Box::new(Sink(frames.clone())),
        Box::new(NoReceive),
        super::tests::test_gateway_context()?,
        ramflux_node_core::GatewayClientFrame::PrincipalManifestFetch {
            principal_id: "alice".into(),
        },
    )
    .await?;
    let output = frames.lock().map_err(|_| anyhow::anyhow!("test sink mutex"))?;
    assert_eq!(output.len(), 1);
    let response: ramflux_node_core::GatewayServerFrame = serde_json::from_slice(&output[0])?;
    assert_eq!(
        response,
        ramflux_node_core::GatewayServerFrame::Nack {
            reason: ramflux_protocol::GATEWAY_FIRST_FRAME_NACK_REASON.into()
        }
    );
    Ok(())
}
#[tokio::test]
async fn raw_name_lookup_rejects_known_and_unknown_queries_before_router_io() -> anyhow::Result<()>
{
    let context = super::tests::test_gateway_context()?;
    let mut bodies = Vec::new();
    for name in ["alice", "unknown"] {
        let response = crate::dispatch_quic_json_request(
            &context.router,
            ramflux_transport::GatewayQuicRequest {
                method: "GET".into(),
                path: format!("/mvp1/principal-manifest/{name}"),
                body: serde_json::Value::Null,
            },
        )
        .await?;
        assert_eq!(response.status, 401);
        assert_eq!(response.body["reason_code"], "authentication_required");
        bodies.push(response.body);
    }
    assert_eq!(bodies[0], bodies[1]);
    Ok(())
}
