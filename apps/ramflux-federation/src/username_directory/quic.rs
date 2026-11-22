// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-request QUIC adapter. Only the witness actor can write account response bytes.
use super::{Result, directory, error, refuse, source::Sources, tcp, tls, wire};
use rustls::pki_types::CertificateDer;
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, mpsc},
    task::{Context, Poll, Wake},
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinSet};

struct WakeActor;
impl Wake for WakeActor {
    fn wake(self: Arc<Self>) {}
}

pub struct Writer {
    send: quinn::SendStream,
    connection: quinn::Connection,
    pub chain: Vec<CertificateDer<'static>>,
    completed: bool,
}

impl Writer {
    pub fn try_write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let waker = Arc::new(WakeActor).into();
        let mut context = Context::from_waker(&waker);
        let chunk = bytes
            .get(..bytes.len().min(8192))
            .ok_or_else(|| std::io::Error::other("directory QUIC write bound"))?;
        match Pin::new(&mut self.send).poll_write(&mut context, chunk) {
            Poll::Ready(Ok(count)) => {
                if count == bytes.len() {
                    self.send.finish().map_err(std::io::Error::other)?;
                    self.completed = true;
                }
                Ok(count)
            }
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }
}

struct CloseOnDrop(Option<quinn::Connection>);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0u32.into(), b"username request closed");
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.send.reset(0u32.into());
            self.connection.close(0u32.into(), b"username response fenced");
        }
    }
}

pub fn start(
    address: SocketAddr,
    tls: rustls::ServerConfig,
    node: String,
    seed: [u8; 32],
    sender: mpsc::SyncSender<tcp::Incoming>,
    slots: Arc<Semaphore>,
    sources: Arc<Sources>,
) -> Result<()> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut limits = quinn::TransportConfig::default();
    limits
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .receive_window(quinn::VarInt::from_u32((directory::MAX_REPORT_BYTES + 65536) as u32))
        .stream_receive_window(quinn::VarInt::from_u32(
            (directory::MAX_REPORT_BYTES + 65536) as u32,
        ))
        .send_window(16384)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    config.transport_config(Arc::new(limits));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let endpoint = {
        let _entered = runtime.enter();
        quinn::Endpoint::server(config, address)?
    };
    ramflux_node_core::spawn_service_worker("username-quic-read", move |shutdown| {
        runtime.block_on(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { incoming.refuse(); continue; };
                        if !sources.admit(incoming.remote_address().ip()) { incoming.refuse(); continue; }
                        let node = node.clone(); let sender = sender.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let deadline = Instant::now() + Duration::from_secs(10);
                            if let Ok(Ok(request)) = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), accept(incoming, &node, &seed, deadline)).await {
                                let _ = sender.try_send(request);
                            }
                        });
                    }
                }
            }
            endpoint.close(0u32.into(), b"shutdown"); tasks.shutdown().await;
        });
    })?;
    Ok(())
}

async fn accept(
    incoming: quinn::Incoming,
    node: &str,
    seed: &[u8; 32],
    deadline: Instant,
) -> Result<tcp::Incoming> {
    let connection = incoming.await?;
    let mut closing = CloseOnDrop(Some(connection.clone()));
    let source = connection.remote_address().ip();
    let handshake = connection
        .handshake_data()
        .ok_or_else(|| error("QUIC handshake data"))?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| error("QUIC handshake type"))?;
    if handshake.protocol.as_deref() != Some(tls::ALPN) {
        return refuse("directory ALPN mismatch");
    }
    let chain = *connection
        .peer_identity()
        .ok_or_else(|| error("QUIC peer identity"))?
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| error("QUIC peer certificate type"))?;
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, tls::EXPORTER, b"")
        .map_err(|_| error("QUIC TLS exporter"))?;
    let (mut send, mut recv) = connection.accept_bi().await?;
    let mut challenge = [0; 32];
    recv.read_exact(&mut challenge).await?;
    let identity = directory::DirectorySigner::from_seed(seed).channel_identity(
        node,
        &exporter,
        &ramflux_protocol::encode_base64url(challenge),
        crate::now_unix_seconds()?,
    )?;
    send.write_all(&wire::encode(&identity)?).await?;
    let mut prefix = [0; 4];
    recv.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > directory::MAX_REPORT_BYTES {
        return refuse("QUIC report bound");
    }
    let mut body = vec![0; length];
    recv.read_exact(&mut body).await?;
    let report = directory::decode_reporting_request(&body)?;
    let path = report.request.path().into();
    let mut extra = [0; 1];
    if recv.read(&mut extra).await?.is_some() {
        return refuse("QUIC request trailing bytes");
    }
    let connection = closing.0.take().ok_or_else(|| error("QUIC connection ownership"))?;
    Ok(tcp::Incoming {
        transport: tcp::Transport::Quic(Box::new(Writer {
            send,
            connection,
            chain,
            completed: false,
        })),
        source,
        exporter,
        path,
        body,
        deadline,
    })
}
