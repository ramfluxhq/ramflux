// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded TLS directory serving genuine native publications to the production fetch adapter.
use super::*;
use crate::GatewaySessionTransportKind;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

const MAX_PUBLICATIONS: usize = 8;
const MAX_REQUESTS: usize = 16;

pub(crate) struct Directory {
    root: tempfile::TempDir,
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    paths: Arc<std::sync::Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<Result<(), crate::SdkError>>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Directory {
    pub(crate) async fn new(manifests: Vec<SdkDeviceManifestResponse>) -> TestResult<Self> {
        Self::with_malformed_first(manifests, false).await
    }
    pub(crate) async fn malformed_once(
        manifests: Vec<SdkDeviceManifestResponse>,
    ) -> TestResult<Self> {
        Self::with_malformed_first(manifests, true).await
    }
    async fn with_malformed_first(
        manifests: Vec<SdkDeviceManifestResponse>,
        malformed_first: bool,
    ) -> TestResult<Self> {
        assert!(
            manifests.len() <= MAX_PUBLICATIONS,
            "native directory fixture exceeds its publication budget"
        );
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["native-directory.example".into()])?;
        std::fs::write(root.path().join("ca.pem"), cert.cert.pem())?;
        let tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let requested = paths.clone();
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            for _ in 0..MAX_REQUESTS {
                let (socket, _) = bounded(listener.accept()).await??;
                let stream =
                    tokio_rustls::TlsStream::Server(bounded(acceptor.accept(socket)).await??);
                let (mut receive, mut send) = tokio::io::split(stream);
                let request: ramflux_transport::GatewayQuicRequest =
                    bounded(ramflux_transport::read_gateway_session_json(&mut receive)).await??;
                requested
                    .lock()
                    .map_err(|_| crate::SdkError::LocalBus("test: directory paths mutex".into()))?
                    .push(request.path.clone());
                let root = request.path.strip_prefix("/mvp1/device-manifest/");
                let manifest =
                    manifests.iter().find(|row| Some(row.principal_commitment.as_str()) == root);
                let first = observed.fetch_add(1, Ordering::SeqCst) == 0;
                let response = if request.method == "GET" {
                    ramflux_transport::GatewayQuicResponse {
                        status: if manifest.is_some() { 200 } else { 404 },
                        body: if first && malformed_first {
                            serde_json::json!({"malformed": true})
                        } else {
                            manifest
                                .map(serde_json::to_value)
                                .transpose()?
                                .unwrap_or(serde_json::Value::Null)
                        },
                    }
                } else {
                    return Err(crate::SdkError::LocalBus(
                        "test: unexpected native directory method".into(),
                    ));
                };
                bounded(ramflux_transport::write_gateway_session_json(&mut send, &response))
                    .await??;
            }
            Ok(())
        });
        Ok(Self { root, address, requests, paths, server })
    }
    pub(crate) fn configure(&self, fixture: &mut Fixture) {
        self.configure_session(&mut fixture.config);
    }
    pub(crate) fn configure_session(&self, config: &mut GatewaySessionConfig) {
        config.transport_kind = GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = self.address;
        config.tcp_gateway_addr = Some(self.address);
        config.server_name = "native-directory.example".into();
        config.ca_cert = self.root.path().join("ca.pem");
    }
    pub(crate) fn requests_for(&self, root: &str) -> Result<usize, crate::SdkError> {
        Ok(self
            .paths
            .lock()
            .map_err(|_| crate::SdkError::LocalBus("test: directory paths mutex".into()))?
            .iter()
            .filter(|path| path.strip_prefix("/mvp1/device-manifest/") == Some(root))
            .count())
    }
    pub(crate) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}
async fn bounded<F: std::future::Future>(future: F) -> Result<F::Output, crate::SdkError> {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .map_err(|_| crate::SdkError::LocalBus("test: native directory deadline".into()))
}
