// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real endpoint/connection drivers over a bounded, deterministic datagram socket.
use crate::*;
use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};
use tokio::time::timeout;

#[derive(Debug, Default)]
struct Wire {
    held: AtomicBool,
    pause_after_recv: AtomicBool,
    suppress_send: AtomicBool,
    history: Mutex<Vec<Vec<u8>>>,
    packets: Mutex<VecDeque<Vec<u8>>>,
    wake: Mutex<Option<Waker>>,
    last: Mutex<Vec<u8>>,
}
#[derive(Debug)]
struct Socket {
    local: SocketAddr,
    remote: SocketAddr,
    inbound: Arc<Wire>,
    outbound: Arc<Wire>,
}
#[derive(Debug)]
struct Writable;
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }
    fn try_send(&self, t: &udp::Transmit<'_>) -> io::Result<()> {
        assert!(t.segment_size.is_none());
        if t.destination != self.remote {
            return Ok(());
        }
        {
            let mut history = self.outbound.history.lock().unwrap();
            if history.len() < 128 {
                history.push(t.contents.to_vec());
            }
        }
        if self.outbound.suppress_send.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut packets = self.outbound.packets.lock().unwrap();
        if packets.len() < 128 {
            packets.push_back(t.contents.to_vec());
        }
        if t.contents.len() > self.outbound.last.lock().unwrap().len() {
            *self.outbound.last.lock().unwrap() = t.contents.to_vec();
        }
        drop(packets);
        if let Some(wake) = self.outbound.wake.lock().unwrap().take() {
            wake.wake();
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if self.inbound.held.load(Ordering::SeqCst) {
            *self.inbound.wake.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut packets = self.inbound.packets.lock().unwrap();
        if let Some(packet) = packets.pop_front() {
            if self.inbound.pause_after_recv.swap(false, Ordering::SeqCst) {
                self.inbound.held.store(true, Ordering::SeqCst);
            }
            assert!(packet.len() <= bufs[0].len());
            bufs[0][..packet.len()].copy_from_slice(&packet);
            metas[0] = udp::RecvMeta {
                addr: self.remote,
                len: packet.len(),
                stride: packet.len(),
                ecn: None,
                dst_ip: Some(self.local.ip()),
            };
            Poll::Ready(Ok(1))
        } else {
            *self.inbound.wake.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn may_fragment(&self) -> bool {
        false
    }
}
#[derive(Debug, Default)]
struct Gate {
    closed: AtomicBool,
    wake: Mutex<Option<Waker>>,
}
impl Gate {
    fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(w) = self.wake.lock().unwrap().take() {
            w.wake();
        }
    }
}
struct Gated {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
    gate: Arc<Gate>,
}
impl Future for Gated {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        if self.gate.closed.load(Ordering::SeqCst) {
            *self.gate.wake.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        } else {
            self.inner.as_mut().poll(cx)
        }
    }
}
#[derive(Debug)]
struct RuntimeGate {
    gate: Arc<Gate>,
    spawned: AtomicUsize,
}
impl Runtime for RuntimeGate {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        TokioRuntime.new_timer(at)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if self.spawned.fetch_add(1, Ordering::SeqCst) == 0 {
            TokioRuntime.spawn(future);
        } else {
            TokioRuntime.spawn(Box::pin(Gated {
                inner: future,
                gate: self.gate.clone(),
            }));
        }
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }
}

async fn until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn pair(
    byte_limit: usize,
    item_limit: usize,
    total_bytes: usize,
    total_items: usize,
    source_bytes: usize,
    source_items: usize,
) -> (
    Endpoint,
    Endpoint,
    Connection,
    Connection,
    Arc<Gate>,
    Arc<Wire>,
) {
    let a: SocketAddr = "127.0.0.1:12000".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:12001".parse().unwrap();
    let incoming = Arc::new(Wire::default());
    let outgoing = Arc::new(Wire::default());
    let server_socket = Arc::new(Socket {
        local: a,
        remote: b,
        inbound: incoming.clone(),
        outbound: outgoing.clone(),
    });
    let client_socket = Arc::new(Socket {
        local: b,
        remote: a,
        inbound: outgoing,
        outbound: incoming.clone(),
    });
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut server_config =
        ServerConfig::with_single_cert(vec![cert.cert.der().clone()], key).unwrap();
    let mut transport = TransportConfig::default();
    transport.initial_rtt(Duration::from_millis(10));
    let transport = Arc::new(transport);
    server_config.transport_config(transport.clone());
    let mut config = EndpointConfig::default();
    config
        .control_credit_limits(proto::ControlLimits {
            bytes: 32768,
            items: 32,
        })
        .unwrap();
    let gate = Arc::new(Gate::default());
    let mut server = Endpoint::new_with_abstract_socket(
        config,
        Some(server_config),
        server_socket,
        Arc::new(RuntimeGate {
            gate: gate.clone(),
            spawned: AtomicUsize::new(0),
        }),
    )
    .unwrap();
    server
        .set_packet_queue_limits(PacketQueueLimits {
            owners: 8,
            bytes_total: total_bytes,
            items_total: total_items,
            bytes_per_owner: byte_limit,
            items_per_owner: item_limit,
            bytes_per_source: source_bytes,
            items_per_source: source_items,
        })
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        client_socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(transport);
    client.set_default_client_config(client_config);
    let connect = client.connect(a, "localhost").unwrap();
    let accept = async { server.accept().await.unwrap().await.unwrap() };
    let (client_conn, server_conn) = tokio::join!(connect, accept);
    let client_conn = client_conn.unwrap();
    until(|| server.rawq_pool().snapshot().0.items == 0).await;
    (server, client, server_conn, client_conn, gate, incoming)
}

#[tokio::test]
async fn packet_credit_covers_enqueue_processing_and_backing_release() {
    for (bytes, items, total_bytes, total_items, source_bytes, source_items, reason) in [
        (65536, 2, 524288, 16, 65536, 128, 1),
        (4096, 64, 32768, 512, 65536, 128, 0),
        (65536, 64, 524288, 512, 4096, 128, 2),
        (65536, 64, 524288, 512, 65536, 2, 3),
        (65536, 64, 4096, 512, 65536, 128, 4),
        (65536, 64, 524288, 2, 65536, 128, 5),
    ] {
        let (server, client, server_conn, client_conn, gate, wire) = pair(
            bytes,
            items,
            total_bytes,
            total_items,
            source_bytes,
            source_items,
        )
        .await;
        let bytes = bytes.min(total_bytes).min(source_bytes);
        let items = items.min(total_items).min(source_items);
        let pool = server.rawq_pool();
        gate.closed.store(true, Ordering::SeqCst);
        let before = pool.snapshot();
        let observed_before = server.rawq_observed();
        let mut send = client_conn.open_uni().await.unwrap();
        send.write_all(&[0x5a; 8192]).await.unwrap();
        send.finish().unwrap();
        until(|| {
            let s = pool.snapshot();
            s.2 > before.2 || s.0.items > items || s.0.bytes > bytes
        })
        .await;
        let full = pool.snapshot();
        let observed_full = server.rawq_observed();
        assert_eq!(
            observed_full.1 - observed_before.1,
            full.0.items,
            "uncharged raw event delivered"
        );
        assert!(
            full.0.items > 0 && full.0.items <= items,
            "real enqueue item ceiling violated"
        );
        assert!(
            full.0.bytes > 0 && full.0.bytes <= bytes,
            "real enqueue byte ceiling violated"
        );
        assert!(
            pool.refusal_classes()[reason] > 0,
            "wrong raw admission boundary refused the packet"
        );
        let replay = wire.last.lock().unwrap().clone();
        assert!(!replay.is_empty());
        {
            let mut pending = wire.packets.lock().unwrap();
            for _ in 0..4 {
                pending.push_back(replay.clone());
            }
        }
        if let Some(wake) = wire.wake.lock().unwrap().take() {
            wake.wake();
        }
        until(|| pool.snapshot().2 >= full.2 + 4).await;
        assert_eq!(
            pool.snapshot().1,
            full.1,
            "full raw queue allocated packet backing before admission"
        );
        assert_eq!(
            server.rawq_observed(),
            observed_full,
            "refused raw packet was copied or delivered"
        );
        gate.open();
        let mut recv = timeout(Duration::from_secs(5), server_conn.accept_uni())
            .await
            .unwrap()
            .unwrap();
        let chunk = timeout(Duration::from_secs(5), recv.read_chunk(usize::MAX, true))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let held = pool.snapshot().0;
        assert!(
            held.bytes > 0 && held.items > 0,
            "popped and processed stream backing lost its raw owner"
        );
        let mut payload = chunk.bytes.to_vec();
        let held_bytes = pool.snapshot().0.bytes;
        drop(chunk);
        assert!(
            pool.snapshot().0.bytes < held_bytes,
            "last held chunk did not return its allocation credit"
        );
        while let Some(next) = timeout(Duration::from_secs(5), recv.read_chunk(usize::MAX, true))
            .await
            .unwrap()
            .unwrap()
        {
            payload.extend_from_slice(&next.bytes);
        }
        assert_eq!(payload, vec![0x5a; 8192]);
        until(|| pool.snapshot().0.items == 0).await;
        client_conn.close(0u32.into(), b"done");
        drop((client_conn, server_conn, client, server));
    }
}

#[tokio::test]
async fn control_credit_preserves_cid_close_and_drained() {
    control_driver::r10_driver_matrix().await;
    let (server, client, server_conn, client_conn, gate, _) =
        pair(65536, 2, 524288, 16, 65536, 128).await;
    let pool = server.rawq_pool();
    gate.closed.store(true, Ordering::SeqCst);
    let before = pool.snapshot().2;
    let mut send = client_conn.open_uni().await.unwrap();
    send.write_all(&[0x42; 8192]).await.unwrap();
    until(|| pool.snapshot().2 > before || pool.snapshot().0.items > 2).await;
    assert_eq!(pool.snapshot().0.items, 2);
    for _ in 0..32 {
        server.close(7u32.into(), &[0x61; 1024]);
    }
    gate.open();
    assert!(matches!(
        timeout(Duration::from_secs(5), server_conn.closed())
            .await
            .unwrap(),
        ConnectionError::LocallyClosed
    ));
    timeout(Duration::from_secs(5), server.wait_idle())
        .await
        .unwrap();
    assert_eq!(
        server.open_connections(),
        0,
        "actual Close timer must reach Drained despite raw saturation"
    );
    drop((send, server_conn, client_conn));
    until(|| pool.snapshot().0.items == 0).await;
    drop((server, client));
}

#[tokio::test]
async fn owner_slots_refuse_capacity_and_rebind_sparse_protocol_handles() {
    // Retain real stream backing through protocol retirement so slot0 stays occupied.
    let (server, client, server_conn, client_conn, _gate, _wire) =
        pair(65536, 64, 524288, 512, 65536, 128).await;
    let mut send = client_conn.open_uni().await.unwrap();
    send.write_all(b"keep-owner-slot").await.unwrap();
    send.finish().unwrap();
    let mut recv = server_conn.accept_uni().await.unwrap();
    let chunk = recv.read_chunk(usize::MAX, true).await.unwrap().unwrap();
    assert_eq!(&chunk.bytes[..], b"keep-owner-slot");
    server_conn.close(0u32.into(), b"retire");
    timeout(Duration::from_secs(5), server.wait_idle())
        .await
        .unwrap();
    assert!(server.rawq_pool().snapshot().0.items > 0);
    let connect = client
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let accept = async { server.accept().await.unwrap().await.unwrap() };
    let (new_client, new_server) = tokio::join!(connect, accept);
    let new_client = new_client.unwrap();
    let bindings = server.rawq_owner_bindings();
    assert_eq!(bindings.len(), 1);
    assert_ne!(
        bindings[0].0, bindings[0].1,
        "protocol handle must map independently of a retained old raw slot"
    );
    drop((chunk, recv, send, server_conn, client_conn));
    let mut clients = vec![new_client];
    let mut servers = vec![new_server];
    for _ in 1..8 {
        let connect = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let accept = async { server.accept().await.unwrap().await.unwrap() };
        let (c, s) = tokio::join!(connect, accept);
        clients.push(c.unwrap());
        servers.push(s);
    }
    assert_eq!(server.open_connections(), 8);
    let attempt = client
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let incoming = timeout(Duration::from_secs(5), server.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(incoming.accept(),Err(ConnectionError::ApplicationClosed(ref reason)) if reason.error_code==VarInt::from_u32(0x524c))
    );
    let config = client.default_client_config.clone().unwrap();
    assert!(matches!(
        server.connect_with(config, client.local_addr().unwrap(), "localhost"),
        Err(ConnectError::EndpointCapacity)
    ));
    assert!(server.rawq_pool().refusal_classes()[6] >= 2);
    assert_eq!(server.open_connections(), 8);
    drop((attempt, clients, servers, server, client));
}

mod control_driver;
