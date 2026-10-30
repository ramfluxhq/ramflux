// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated loopback directory and recording gateway for group surface load tests.
use crate::prelude::*;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;
pub(in crate::bus) struct RecordingGateway {
    last: Option<GatewayClientFrame>,
    cursor: Option<GatewayCursor>,
    pub inbox: Vec<GatewayInboxEntry>,
    pub fail_after: Option<usize>,
    pub fail_target: Option<String>,
    pub fail_own_ack: bool,
    pub prekeys: BTreeMap<String, crate::prekey::SdkPrekeyResponse>,
    pub own: Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
    pub frame_lengths: Arc<Mutex<Vec<usize>>>,
    pub delivered: Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
}
impl RecordingGateway {
    fn own_response(
        &mut self,
        fanout: crate::GatewayOwnDeviceFanoutFrame,
    ) -> Result<GatewayServerFrame, TransportError> {
        let bytes = ramflux_protocol::decode_base64url(&fanout.envelope.encrypted_payload)
            .map_err(|e| TransportError::Quic(e.to_string()))?;
        let raw = bytes
            .strip_prefix(crate::client::own_device_copy::PREFIX)
            .ok_or_else(|| TransportError::Quic("expected per-message own copy".into()))?;
        let packet: crate::client::own_device_copy::OwnDeviceMessage =
            serde_json::from_slice(raw).map_err(|e| TransportError::Quic(e.to_string()))?;
        self.own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(fanout.envelope);
        if self.fail_own_ack {
            return Err(TransportError::Quic("injected lost own-copy ACK".into()));
        }
        Ok(GatewayServerFrame::OwnDeviceFanout {
            response: crate::GatewayOwnDeviceFanoutResponse {
                principal_id: fanout.principal_id,
                source_device_id: fanout.source_device_id,
                delivered: packet
                    .slots
                    .into_iter()
                    .map(|slot| crate::GatewayOwnDeviceFanoutDelivery {
                        device_id: slot.recipient_device_id,
                        target_delivery_id: "sibling".into(),
                        outcome: "online".into(),
                        inbox_seq: Some(1),
                    })
                    .collect(),
            },
        })
    }
    pub fn new(delivered: Arc<Mutex<Vec<ramflux_protocol::Envelope>>>) -> Self {
        Self {
            last: None,
            cursor: None,
            inbox: Vec::new(),
            fail_after: None,
            fail_target: None,
            fail_own_ack: false,
            prekeys: BTreeMap::new(),
            own: Arc::default(),
            frame_lengths: Arc::default(),
            delivered,
        }
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
            if let Ok(GatewayClientFrame::Submit { submit }) = serde_json::from_slice(bytes)
                && self.fail_target.as_ref() == Some(&submit.envelope.target_delivery_id)
            {
                return Err(TransportError::Quic("injected target failure".into()));
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
            if self.last.is_none()
                && let Some(cursor) = self.cursor.take()
            {
                return serde_json::to_vec(&GatewayServerFrame::Cursor { cursor: Some(cursor) })
                    .map_err(|e| TransportError::Quic(e.to_string()));
            }
            let response = match self.last.take() {
                Some(GatewayClientFrame::Submit { submit }) => {
                    self.delivered
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(submit.envelope.clone());
                    GatewayServerFrame::Deliver {
                        entry: GatewayInboxEntry {
                            forwarded: false,
                            inbox_seq: 1,
                            target_delivery_id: submit.envelope.target_delivery_id.clone(),
                            envelope: submit.envelope,
                        },
                    }
                }
                Some(GatewayClientFrame::OwnDeviceFanout { fanout }) => {
                    self.own_response(fanout)?
                }
                Some(GatewayClientFrame::PrekeyFetch { device_id }) => GatewayServerFrame::Prekey {
                    response: self.prekeys.get(&device_id).cloned().unwrap_or_else(|| {
                        crate::prekey::SdkPrekeyResponse {
                            target_delivery_id: Some(
                                device_id.trim_start_matches("device-").to_owned(),
                            ),
                            device_id,
                            bundle: None,
                            principal_commitment: String::new(),
                        }
                    }),
                },
                Some(GatewayClientFrame::Resume { .. }) => {
                    GatewayServerFrame::Resume { entries: std::mem::take(&mut self.inbox) }
                }
                Some(GatewayClientFrame::Ack { ack }) => {
                    let cursor = GatewayCursor {
                        target_delivery_id: "sender".into(),
                        inbox_seq: 1,
                        last_envelope_id: Some(ack.envelope_id.clone()),
                        acked_envelope_ids: vec![ack.envelope_id],
                        nacked_envelope_ids: BTreeMap::new(),
                    };
                    self.cursor = Some(cursor.clone());
                    GatewayServerFrame::Ack { cursor }
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
pub(in crate::bus::dispatch) fn manifest(
    client: &RamfluxClient,
) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
    crate::client::identity_authority::test_support::public_manifest(client)
}
pub(in crate::bus::dispatch) async fn directory(
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
