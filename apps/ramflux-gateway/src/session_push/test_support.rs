// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Causal mesh request barriers and raw client wire capture.
use super::{Value, json};
use ramflux_transport::{
    GatewaySessionFrameSink, MeshQuicAcceptedWireRequest as Wire, MeshQuicServer, TransportError,
};
use std::sync::{Arc, Mutex};
pub(super) const ID: &str = "0123456789abcdef0123456789abcdef";
pub(super) struct Sink(pub Arc<Mutex<Vec<Value>>>);
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| TransportError::LockPoisoned)?
                .push(serde_json::from_slice(body)?);
            Ok(())
        })
    }
}
pub(super) fn sink() -> (crate::GatewaySendHandle, Arc<Mutex<Vec<Value>>>) {
    let rows = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(tokio::sync::Mutex::new(Box::new(Sink(rows.clone())))), rows)
}
pub(super) fn runtime() -> anyhow::Result<crate::GatewaySessionRuntime> {
    Ok(crate::GatewaySessionRuntime {
        session_push: Some(ID.into()),
        source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
            &ramflux_crypto::create_identity_root("agent", [3; 32]),
            &ramflux_crypto::create_device_branch("agent", "agent-device", 1, [4; 32]),
        )?,
        session_id: "session".into(),
        resume_token: "resume".into(),
        principal_id: "agent".into(),
        device_id: "agent-device".into(),
        target_delivery_id: "target".into(),
        branch_public_key: ramflux_crypto::public_key_base64url_from_seed([4; 32]),
        device_epoch: 1,
        supports_forward_ack: false,
    })
}
pub(super) struct Request {
    pub path: String,
    pub body: Value,
    pub respond: tokio::sync::oneshot::Sender<(u16, Value)>,
}
pub(super) struct Fixture {
    pub context: crate::GatewayQuicContext,
    pub requests: tokio::sync::mpsc::Receiver<Request>,
    task: tokio::task::JoinHandle<()>,
    root: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    pub fn new(label: &str) -> anyhow::Result<Self> {
        use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
        let root = temp_cert_root(label).map_err(|e| anyhow::anyhow!("{e}"))?;
        let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let server = MeshQuicServer::bind_with_pem_roots_provider(
            "127.0.0.1:0",
            &router.tls,
            Arc::new(move || Ok(vec![gateway.ca_pem.clone()])),
        )?;
        let mut context = crate::session::tests::test_gateway_context()?;
        context.router = crate::RouterMeshClient {
            endpoint: "127.0.0.1:0".into(),
            server_name: "ramflux-router".into(),
            tls: gateway.tls.clone(),
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: Some(crate::RouterAsyncMeshClient {
                endpoint: server.local_addr()?.to_string(),
                server_name: "ramflux-router".into(),
                tls: gateway.tls,
                peer_ca_pems: vec![router.ca_pem],
            }),
        };
        let (send, requests) = tokio::sync::mpsc::channel(32);
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                 result=server.accept_connection()=> {let Ok(connection)=result else {return;};let send=send.clone();tasks.spawn(async move {let _=serve(connection,send).await;});}
                 _=tasks.join_next(),if !tasks.is_empty()=>{}
                }
            }
        });
        Ok(Self { context, requests, task, root })
    }
    pub async fn next(&mut self) -> anyhow::Result<Request> {
        tokio::time::timeout(std::time::Duration::from_secs(10), self.requests.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("mesh server closed"))
    }
}
async fn serve(
    connection: ramflux_transport::MeshQuicConnection,
    send: tokio::sync::mpsc::Sender<Request>,
) -> anyhow::Result<()> {
    loop {
        let accepted =
            MeshQuicServer::accept_json_or_postcard_request_on_connection(&connection).await?;
        let (path, body) = match &accepted {
            Wire::Json(a) => (a.request.path.clone(), a.request.body.clone()),
            Wire::Postcard(a) => (a.path.clone(), serde_json::from_slice(&a.body)?),
        };
        let (respond, response) = tokio::sync::oneshot::channel();
        send.send(Request { path, body, respond }).await?;
        let (status, value) =
            tokio::time::timeout(std::time::Duration::from_secs(12), response).await??;
        match accepted {
            Wire::Json(a) => a.write_json_response(status, &value).await?,
            Wire::Postcard(a) => a.write_postcard_response(status, &value).await?,
        }
    }
}
pub(super) fn cursor() -> Value {
    json!({"target_delivery_id":"target","inbox_seq":0,"last_envelope_id":null,"acked_envelope_ids":[],"nacked_envelope_ids":{}})
}
pub(super) fn ack(seq: u64) -> Value {
    json!({"schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1","signing_key_id":"device","signature_alg":"ed25519","signature":"fixture","ack_id":"ack","envelope_id":"envelope","receiver_device_id":"agent-device","received_at":1,"ext":{"inbox_seq":seq}})
}
pub(super) fn nack(seq: u64) -> Value {
    json!({"schema":"ramflux.nack.v1","version":1,"domain":"ramflux.nack.v1","signing_key_id":"device","signature_alg":"ed25519","signature":"fixture","nack_id":"nack","envelope_id":"envelope","receiver_device_id":"agent-device","reason":"invalid_signature","received_at":1,"ext":{"inbox_seq":seq}})
}

pub(super) struct Source(pub std::collections::VecDeque<Vec<u8>>);
impl ramflux_transport::GatewaySessionFrameSource for Source {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>,
    > {
        let next = self.0.pop_front();
        Box::pin(async move {
            next.ok_or_else(|| {
                TransportError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            })
        })
    }
}
