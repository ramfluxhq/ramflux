// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated loopback directory and recording gateway for group surface load tests.
use crate::prelude::*;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;
pub(super) struct RecordingGateway {
    last: Option<GatewayClientFrame>,
    pub fail_after: Option<usize>,
    pub frame_lengths: Arc<Mutex<Vec<usize>>>,
    pub delivered: Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
}
impl RecordingGateway {
    pub fn new(delivered: Arc<Mutex<Vec<ramflux_protocol::Envelope>>>) -> Self {
        Self { last: None, fail_after: None, frame_lengths: Arc::default(), delivered }
    }
}
impl GatewaySessionFrameSink for RecordingGateway {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            assert!(
                bytes.len() + 64 * 1024 < ramflux_transport::MAX_GATEWAY_FRAME_BYTES,
                "actual encoded gateway frame exceeds transport limit"
            );
            if self.fail_after.is_some_and(|limit| {
                matches!(
                    serde_json::from_slice::<GatewayClientFrame>(bytes),
                    Ok(GatewayClientFrame::Submit { .. })
                ) && self.delivered.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
                    >= limit
            }) {
                return Err(TransportError::Quic("injected submit failure".into()));
            }
            self.frame_lengths
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(bytes.len());
            self.last = Some(
                serde_json::from_slice(bytes).map_err(|e| TransportError::Quic(e.to_string()))?,
            );
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for RecordingGateway {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let response = match self.last.take() {
                Some(GatewayClientFrame::Submit { submit }) => {
                    self.delivered
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(submit.envelope.clone());
                    GatewayServerFrame::Deliver {
                        entry: GatewayInboxEntry {
                            inbox_seq: 1,
                            target_delivery_id: submit.envelope.target_delivery_id.clone(),
                            envelope: submit.envelope,
                        },
                    }
                }
                Some(GatewayClientFrame::PrekeyFetch { device_id }) => GatewayServerFrame::Prekey {
                    response: crate::prekey::SdkPrekeyResponse {
                        target_delivery_id: Some(
                            device_id.trim_start_matches("device-").to_owned(),
                        ),
                        device_id,
                        bundle: None,
                        principal_commitment: String::new(),
                    },
                },
                Some(GatewayClientFrame::Resume { .. }) => {
                    GatewayServerFrame::Resume { entries: Vec::new() }
                }
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                _ => GatewayServerFrame::Nack { reason: "unexpected group test frame".into() },
            };
            serde_json::to_vec(&response).map_err(|e| TransportError::Quic(e.to_string()))
        })
    }
}
pub(super) fn manifest(
    client: &RamfluxClient,
) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
    let root = client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let commitment = crate::identity_root_public_key_commitment(&root_public_key)?;
    let branch_proof = ramflux_crypto::authorize_device_branch(
        root,
        branch,
        "ramflux-node",
        vec!["device.delivery.bind".into()],
        1_700_000_000,
        4_000_000_000,
    )?;
    let identity = ramflux_crypto::X25519KeyPair::from_seed([44; 32]);
    let signed = ramflux_crypto::X25519KeyPair::from_seed([45; 32]);
    Ok(crate::prekey::SdkDeviceManifestResponse {
        principal_id: branch.principal_id.clone(),
        principal_commitment: commitment.clone(),
        root_public_key,
        devices: vec![crate::prekey::SdkDeviceManifestEntry {
            principal_id: branch.principal_id.clone(),
            principal_commitment: commitment,
            device_id: branch.device_id.clone(),
            device_epoch: 1,
            branch_public_key: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            target_delivery_id: branch.principal_id.clone(),
            branch_proof,
            prekey_bundle: ramflux_crypto::create_prekey_bundle(
                branch,
                &identity,
                "signed-key",
                &signed,
                None,
                None,
            )?,
            branch_authorized_event_id: format!("device.branch_authorized:{}:1", branch.device_id),
        }],
    })
}
pub(super) async fn directory(
    root: &Path,
    manifests: BTreeMap<String, serde_json::Value>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let certified = rcgen::generate_simple_self_signed(vec!["test-gateway".into()])?;
    std::fs::write(root.join("ca.pem"), certified.cert.pem())?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let manifests = Arc::new(manifests);
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let manifests = manifests.clone();
            tokio::spawn(async move {
                let result = async {
                    let mut stream = acceptor.accept(tcp).await?;
                    let len = stream.read_u32().await?;
                    if len > 1024 * 1024 {
                        return Err(std::io::Error::other("test frame too large"));
                    }
                    let mut bytes = vec![0; len as usize];
                    stream.read_exact(&mut bytes).await?;
                    let request: ramflux_transport::GatewayQuicRequest =
                        serde_json::from_slice(&bytes)?;
                    let commitment =
                        request.path.strip_prefix("/mvp1/device-manifest/").unwrap_or("");
                    let body =
                        manifests.get(commitment).cloned().unwrap_or(serde_json::Value::Null);
                    let response = serde_json::to_vec(
                        &serde_json::json!({"status":if body.is_null(){404}else{200},"body":body}),
                    )?;
                    stream
                        .write_u32(u32::try_from(response.len()).map_err(std::io::Error::other)?)
                        .await?;
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                    Ok::<_, std::io::Error>(())
                }
                .await;
                if let Err(error) = result {
                    eprintln!("group test directory: {error}");
                }
            });
        }
    });
    Ok((address, task))
}
