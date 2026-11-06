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
mod allocator;

#[derive(Debug, Default)]
struct Wire {
    write_blocked: AtomicBool,
    write_wake: Mutex<Option<Waker>>,
    send_attempts: AtomicUsize,
    delivered: AtomicUsize,
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
struct Writable(Arc<Wire>);
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.0.write_blocked.load(Ordering::SeqCst) { *self.0.write_wake.lock().unwrap()=Some(cx.waker().clone()); Poll::Pending } else { Poll::Ready(Ok(())) }
    }
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(self.outbound.clone()))
    }
    fn try_send(&self, t: &udp::Transmit<'_>) -> io::Result<()> {
        self.outbound.send_attempts.fetch_add(1,Ordering::SeqCst);
        if self.outbound.write_blocked.load(Ordering::SeqCst) { return Err(io::ErrorKind::WouldBlock.into()); }
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
            self.outbound.delivered.fetch_add(1, Ordering::SeqCst);
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

#[track_caller]
fn until(mut ready: impl FnMut() -> bool) -> impl Future<Output=()> {
    let caller=std::panic::Location::caller();
    async move {
    timeout(Duration::from_secs(10), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_|panic!("condition did not become ready at {caller}"));
    }
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
        let mut recv = timeout(Duration::from_secs(10), server_conn.accept_uni())
            .await
            .unwrap()
            .unwrap();
        let chunk = timeout(Duration::from_secs(10), recv.read_chunk(usize::MAX, true))
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
        while let Some(next) = timeout(Duration::from_secs(10), recv.read_chunk(usize::MAX, true))
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
        timeout(Duration::from_secs(10), server_conn.closed())
            .await
            .unwrap(),
        ConnectionError::LocallyClosed
    ));
    timeout(Duration::from_secs(10), server.wait_idle())
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
    timeout(Duration::from_secs(10), server.wait_idle())
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
    let incoming = timeout(Duration::from_secs(10), server.accept())
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

mod stateless_response_tests;

#[tokio::test]
async fn stateless_responses_bound_allocations_and_sender_tasks() { stateless_response_tests::run().await; }

#[tokio::test]
async fn metadata_credit_exhaustion_propagates_resource_limit() {
    send_metadata_cases().await;
}

#[tokio::test]
async fn send_metadata_credit_covers_allocation_families(){
    metadata_retransmit_box_and_reset_children_refuse_before_wire().await;
    send_metadata_cases().await;
    metadata_pending_retransmit_transfer_refuses_in_real_pto().await;
    metadata_receiver_drop_propagates_pending_refusal().await;
}

async fn send_metadata_cases(){
    metadata_send_ack_ranges_refuse_before_third_range().await;
    metadata_record_growth_refuses_before_ping_or_record_effects().await;
    metadata_scratch_and_ack_growth_use_real_driver_boundaries().await;
    metadata_stream_frame_growth_aborts_wire_packet_before_effects().await;
    metadata_frame_backing_follows_real_ack_and_release().await;
    // B1 checkpoint: send deque and STREAM metadata backing. Remaining classes are not certified.
    for limit in [0, 192] {
        let (client_endpoint, server_endpoint, client, server, gate, _) =
            pair(65536,64,524288,512,65536,128).await;
        // pair's first returned connection is on the endpoint behind this gate.
        // Charge that actual sender while its driver cannot dequeue/transmit the segments.
        gate.closed.store(true,Ordering::SeqCst);
        let probe=client.control_test(|p|p.metadata_test_limit(limit));
        let mut stream=client.open_uni().await.unwrap();
        if limit!=0 {
            for _ in 0..4 { stream.write_chunk(bytes::Bytes::from_static(b"x")).await.unwrap(); }
            let (capacity,offset)=client.control_test(|p|p.metadata_test_send_storage());
            assert_eq!((capacity,offset),(4*std::mem::size_of::<bytes::Bytes>(),4));
            assert_eq!((probe.stats().used,probe.stats().allocations),(192,1));
            assert_eq!(probe.stats().refusals,0,"exactly full credit remains valid");
        }
        let before=probe.stats();
        let mut source=[bytes::Bytes::from_static(b"must-not-be-consumed")];
        assert!(matches!(stream.write_chunks(&mut source).await,
            Err(crate::WriteError::ConnectionLost(ConnectionError::LocallyClosed))));
        assert_eq!(&source[0][..],b"must-not-be-consumed");
        assert_eq!(probe.stats().used,before.used);
        assert_eq!(probe.stats().allocations,before.allocations,"refusal precedes actual deque allocation");
        assert_eq!(client.control_test(|p|p.metadata_test_send_storage()).0,if limit==0 {0}else{4*std::mem::size_of::<bytes::Bytes>()});
        gate.open();
        assert!(matches!(timeout(Duration::from_secs(10),client.closed()).await.unwrap(),ConnectionError::LocallyClosed));
        assert!(matches!(timeout(Duration::from_secs(10),server.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref reason) if reason.error_code==VarInt::from_u32(0x524c)));
        timeout(Duration::from_secs(10),client_endpoint.wait_idle()).await.unwrap();
        assert_eq!(client_endpoint.open_connections(),0);
        let held=probe.stats().used;
        assert_eq!(held,limit,"Drained does not refund retained send backing");
        drop((stream,client,server,client_endpoint,server_endpoint));
        until(||probe.stats().used==0).await;
    }
}


async fn metadata_stream_frame_growth_aborts_wire_packet_before_effects() {
    let (endpoint, peer_endpoint, connection, peer, gate, _) = pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    let record_charge=connection.control_test(|p|p.metadata_test_next_record_charge());
    let probe=connection.control_test(|p|p.metadata_test_limit(384+record_charge));
    let mut first=connection.open_uni().await.unwrap();
    let mut second=connection.open_uni().await.unwrap();
    first.write_chunk(bytes::Bytes::from_static(b"a")).await.unwrap();
    second.write_chunk(bytes::Bytes::from_static(b"b")).await.unwrap();
    assert_eq!(probe.stats().used,384);
    assert_eq!(probe.stats().allocations,2);
    let received=peer.stats().frame_rx.stream;
    gate.open();
    assert!(matches!(timeout(Duration::from_secs(10),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
    assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref close) if close.error_code==VarInt::from_u32(0x524c)));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::SentFrameMetadata));
    assert_eq!(probe.stats().allocations,3,"only two send deques and the record table allocate before refused metadata spill");
    assert_eq!(peer.stats().frame_rx.stream,received,"partial packet never reaches the wire");
    timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
    assert_eq!(probe.stats().used,384+record_charge);
    drop((first,second,connection,peer,endpoint,peer_endpoint));
    until(||probe.stats().used==0).await;
}


async fn metadata_frame_backing_follows_real_ack_and_release() {
    let (endpoint, peer_endpoint, connection, peer, gate, wire)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);wire.held.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|p.metadata_test_limit(4096));
    let mut first=connection.open_uni().await.unwrap();let mut second=connection.open_uni().await.unwrap();
    first.write_chunk(bytes::Bytes::from_static(b"first")).await.unwrap();
    second.write_chunk(bytes::Bytes::from_static(b"second")).await.unwrap();
    gate.open();
    until(||connection.control_test(|p|p.metadata_test_frame_storage())>0).await;
    let mut received=Vec::new();let mut receivers=Vec::new();
    for _ in 0..2 {
        let mut recv=timeout(Duration::from_secs(10),peer.accept_uni()).await.unwrap().unwrap();
        let chunk=recv.read_chunk(16,true).await.unwrap().unwrap();
        received.push(chunk.bytes.to_vec());receivers.push(recv);
    }
    received.sort();assert_eq!(received,vec![b"first".to_vec(),b"second".to_vec()]);
    let frame_capacity=connection.control_test(|p|p.metadata_test_frame_storage());
    let record_bytes=connection.control_test(|p|p.metadata_test_record_storage());
    let record_charge=((record_bytes+63)&!63)+64;
    assert!(record_bytes>0);
    assert_eq!(frame_capacity,128);assert_eq!(probe.stats().used,576+record_charge);
    assert_eq!(probe.stats().allocations,4);
    wire.held.store(false,Ordering::SeqCst);if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
    until(||connection.control_test(|p|p.metadata_test_frame_storage())==0).await;
    assert_eq!(connection.control_test(|p|p.metadata_test_send_storage()).0,256,"actual deque backing is retained after ACK");
    assert_eq!(probe.stats().used,384+record_charge,"empty send deques retain their actual capacity after ACK");
    first.reset(0u32.into()).unwrap();second.reset(0u32.into()).unwrap();
    assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),64);
    assert_eq!(probe.stats().used,record_charge+128);
    assert!(connection.close_reason().is_none());
    connection.close(0u32.into(),b"done");
    drop((first,second,connection,peer,endpoint,peer_endpoint,receivers));
}


async fn metadata_record_growth_refuses_before_ping_or_record_effects() {
    let (endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|{let probe=p.metadata_test_limit(0);p.ping();probe});
    let received=peer.stats().frame_rx.ping;
    gate.open();
    assert!(matches!(timeout(Duration::from_secs(10),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
    assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::SentRecords));
    assert_eq!(probe.stats().allocations,0);
    assert_eq!(connection.control_test(|p|p.metadata_test_record_storage()),0);
    assert_eq!(peer.stats().frame_rx.ping,received,"refused builder emits no PING effects");
    timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
    drop((connection,peer,endpoint,peer_endpoint));assert_eq!(probe.stats().used,0);
}


async fn metadata_scratch_and_ack_growth_use_real_driver_boundaries() {
    for loss in [false,true] {
        let(endpoint,peer_endpoint,connection,peer,_,wire)=pair(65536,64,524288,512,65536,128).await;
        wire.held.store(true,Ordering::SeqCst);
        let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
        for _ in 0..8 {
            let before=connection.stats().udp_tx.datagrams;
            connection.control_test(|p|p.ping());
            until(||connection.stats().udp_tx.datagrams>before).await;
        }
        let numbers=connection.control_test(|p|p.metadata_test_sent_numbers());assert!(numbers.len()>=6);
        let before=numbers.len();
        let acked=if loss{vec![*numbers.last().unwrap()]}else{vec![numbers[0],numbers[2],numbers[4]]};
        let number=connection.control_test(|p|p.metadata_test_next_received());
        let packet=peer.control_test(|p|p.control_test_ack_packet(number,&acked));
        wire.packets.lock().unwrap().clear();probe.freeze_at_live_allocations();
        wire.packets.lock().unwrap().push_back(packet);wire.held.store(false,Ordering::SeqCst);
        if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
        assert!(matches!(timeout(Duration::from_secs(10),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
        assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
        assert_eq!(probe.stats().failed_class,Some(if loss{proto::MetadataClass::LossScratch}else{proto::MetadataClass::AckScratch}));
        assert_eq!(connection.stats().path.lost_packets,0,"refused loss scratch does not retire lost records");
        assert_eq!(connection.control_test(|p|p.metadata_test_sent_numbers()).len(),before-usize::from(loss));
        timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
        drop((connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
    }
    let(endpoint,peer_endpoint,connection,peer,_,wire)=pair(65536,64,524288,512,65536,128).await;
    connection.control_test_transmit(true);
    let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
    while connection.control_test(|p|p.metadata_test_ack_ranges())<2 {
        let number=connection.control_test(|p|p.metadata_test_next_received()+1);
        let packet=peer.control_test(|p|p.control_test_packet(number,false,&[0x01]));
        wire.packets.lock().unwrap().push_back(packet);if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
        until(||connection.control_test(|p|p.metadata_test_next_received())>number).await;
    }
    let number=connection.control_test(|p|p.metadata_test_next_received()+1);
    let before=connection.stats().frame_rx.ping;
    let packet=peer.control_test(|p|p.control_test_packet(number,false,&[0x01]));
    probe.freeze_at_live_allocations();wire.packets.lock().unwrap().push_back(packet);if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
    assert!(matches!(timeout(Duration::from_secs(10),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::PendingAcks));
    assert_eq!(connection.stats().frame_rx.ping,before,"pending ACK capacity refuses before frame effects");
    let observed=connection.control_test(|p|p.control_test_probe(number));assert_eq!(observed[7],0);assert_eq!(observed[13],0);
    connection.control_test_transmit(false);
    assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
    drop((connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
}


async fn metadata_send_ack_ranges_refuse_before_third_range() {
    let(endpoint,peer_endpoint,connection,peer,gate,wire)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    wire.held.store(true,Ordering::SeqCst);
    // Only injected ACKs may reach this sender. Clearing queued datagrams does not
    // stop a peer driver from producing a delayed ordinary ACK afterwards.
    wire.suppress_send.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
    let mut stream=connection.open_uni().await.unwrap();
    gate.open();
    for _ in 0..6 {
        let before=connection.stats().frame_tx.stream;
        stream.write_chunk(bytes::Bytes::from_static(b"x")).await.unwrap();
        until(||connection.stats().frame_tx.stream>before).await;
    }
    let packets=connection.control_test(|p|p.metadata_test_stream_packets());
    let mut acked=Vec::new();
    for offset in [1,3,5] {acked.push(packets.iter().find(|(_,o)|*o==offset).unwrap().0);}
    for (index,packet_number) in acked.into_iter().enumerate() {
        gate.closed.store(true,Ordering::SeqCst);
        wire.held.store(true,Ordering::SeqCst);
        let number=connection.control_test(|p|p.metadata_test_next_received());
        let packet=peer.control_test(|p|p.control_test_ack_packet(number,&[packet_number]));
        wire.packets.lock().unwrap().clear();
        if index==2 {probe.freeze_at_live_allocations();}
        wire.packets.lock().unwrap().push_back(packet);
        wire.held.store(false,Ordering::SeqCst);
        if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
        gate.open();
        if index<2 {
            until(||connection.control_test(|p|p.metadata_test_send_ranges()).0==index+1).await;
            // Force the formerly racy ordering: an ordinary cumulative ACK is built
            // after the controlled ACK. It must be discarded at the actual send site.
            let delivered=wire.delivered.load(Ordering::SeqCst);
            let acks=peer.stats().frame_tx.acks;
            peer.control_test(|p|p.metadata_test_force_ack());
            until(||peer.stats().frame_tx.acks>acks).await;
            assert_eq!(wire.delivered.load(Ordering::SeqCst),delivered,"ordinary ACK escaped the controlled-ACK fixture");
            assert_eq!(connection.control_test(|p|p.metadata_test_send_ranges()).0,index+1);
        }
    }
    assert!(matches!(timeout(Duration::from_secs(10),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
    assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::SendRanges));
    assert_eq!(connection.control_test(|p|p.metadata_test_send_ranges()).0,2,"refused third disjoint ACK range is never inserted");
    assert!(probe.stats().peak<=1<<20);
    timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
    drop((stream,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
}


async fn metadata_retransmit_box_and_reset_children_refuse_before_wire(){
    // Pending producer refuses before growing its reset vector and wakes the real driver.
    let(endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|p.metadata_test_limit(0));
    let mut stream=connection.open_uni().await.unwrap();let refused=stream.reset(0u32.into());
    assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),0,"refused producer allocated pending reset backing");
    assert!(refused.is_err());
    assert_eq!(probe.stats().allocations,0);
    gate.open();assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::PendingRetransmits));
    timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();drop((stream,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
    for child in [false,true] {
        let(endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
        gate.closed.store(true,Ordering::SeqCst);
        let record_charge=connection.control_test(|p|p.metadata_test_next_record_charge());
        let box_charge=connection.control_test(|p|p.metadata_test_box_charge());
        let probe=connection.control_test(|p|p.metadata_test_limit(128+record_charge+if child{box_charge}else{0}));
        let mut stream=connection.open_uni().await.unwrap();
        stream.reset(0u32.into()).unwrap();
        assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),64);
        let before=peer.stats().frame_rx.reset_stream;
        gate.open();
        assert!(matches!(timeout(Duration::from_secs(10),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
        assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
        assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::RetransmitOwners));
        assert_eq!(peer.stats().frame_rx.reset_stream,before,"refused box/child never emits RESET");
        assert_eq!(probe.stats().allocations,if child{3}else{2});
        assert_eq!(connection.control_test(|p|p.metadata_test_retransmit_storage()),(0,0));
        timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
        drop((stream,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
    }

}

async fn metadata_pending_retransmit_transfer_refuses_in_real_pto(){
    for refuse in [true,false] {
        let(endpoint,peer_endpoint,connection,peer,gate,wire)=pair(65536,64,524288,512,65536,128).await;
        gate.closed.store(true,Ordering::SeqCst);wire.held.store(true,Ordering::SeqCst);
        let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
        let mut stream=connection.open_uni().await.unwrap();stream.reset(0u32.into()).unwrap();gate.open();
        until(||peer.stats().frame_rx.reset_stream>0).await;
        until(||connection.control_test(|p|p.metadata_test_retransmit_storage()).1>0).await;
        gate.closed.store(true,Ordering::SeqCst);
        connection.control_test(|p|p.metadata_test_release_empty_pending_reset());
        assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),0);
        let reset_count=peer.stats().frame_rx.reset_stream;
        if refuse {probe.freeze_at_live_allocations();}
        gate.open();
        if refuse {
            assert!(matches!(timeout(Duration::from_secs(5),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
            assert!(matches!(timeout(Duration::from_secs(5),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
            assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::PendingRetransmits));
            assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),0);
            assert_eq!(peer.stats().frame_rx.reset_stream,reset_count,"refused PTO transfer emits no later reset");
            timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
        } else {
            until(||peer.stats().frame_rx.reset_stream>reset_count).await;
            assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),64,"dequeued transfer retains its actual backing");
            assert!(probe.stats().peak<=1<<20);assert_eq!(probe.stats().refusals,0);
            wire.held.store(false,Ordering::SeqCst);if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
            until(||connection.control_test(|p|p.metadata_test_retransmit_storage())==(0,0)).await;
            assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),64,"ACK does not free retained pending capacity");
            connection.close(0u32.into(),b"done");
        }
        drop((stream,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
    }
}


async fn metadata_receiver_drop_propagates_pending_refusal(){
    let(endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
    let mut remote_send=peer.open_uni().await.unwrap();remote_send.write_all(b"x").await.unwrap();
    let recv=timeout(Duration::from_secs(5),connection.accept_uni()).await.unwrap().unwrap();
    gate.closed.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|p.metadata_test_limit(0));
    let before=peer.stats().frame_rx.stop_sending;
    drop(recv);
    assert_eq!(connection.control_test(|p|p.metadata_test_pending_storage()),0);
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::PendingRetransmits));
    gate.open();
    assert!(matches!(timeout(Duration::from_secs(5),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    assert_eq!(peer.stats().frame_rx.stop_sending,before,"refused drop producer emits no ordinary control");
    timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
    drop((remote_send,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
}

#[tokio::test]
async fn receive_backing_credit_follows_last_bytes_owner(){
    receive_backing_copy_refuses_before_stream().await;
    receive_backing_shared_payload_and_owner().await;
}

#[tokio::test]
async fn receive_owner_metadata_survives_final_payload_drop(){
    receive_owner_refuses_before_stream().await;
    receive_backing_shared_payload_and_owner().await;
}

async fn receive_backing_shared_payload_and_owner(){
    let(endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
    let raw=endpoint.rawq_pool();
    peer.control_test_transmit(true);
    let mut send1=peer.open_uni().await.unwrap();let mut send2=peer.open_uni().await.unwrap();
    send1.write_chunk(bytes::Bytes::from_static(b"first")).await.unwrap();
    send2.write_chunk(bytes::Bytes::from_static(b"second")).await.unwrap();
    peer.control_test_transmit(false);gate.open();
    let mut recv1=timeout(Duration::from_secs(5),connection.accept_uni()).await.unwrap().unwrap();
    let mut recv2=timeout(Duration::from_secs(5),connection.accept_uni()).await.unwrap().unwrap();
    let first=recv1.read_chunk(64,true).await.unwrap().unwrap().bytes;
    let second=recv2.read_chunk(64,true).await.unwrap().unwrap().bytes;
    let mut data=[first.to_vec(),second.to_vec()];data.sort();
    assert_eq!(data,[b"first".to_vec(),b"second".to_vec()]);
    assert_eq!(connection.stats().frame_rx.stream,2);
    let capacity=probe.stats().receive_backing_capacity;
    let admitted_payload_len=probe.stats().receive_payload_len;
    assert!(admitted_payload_len>first.len()+second.len(),"packet payload includes STREAM framing");
    assert_eq!(capacity,admitted_payload_len,"physical copy capacity matches independently observed decrypted packet length");
    let payload_charge=((capacity+63)&!63)+64;
    let owner_charge=((probe.stats().receive_owner_layout+63)&!63)+64;
    let backing_charge=payload_charge+owner_charge;
    assert_eq!(probe.stats().receive_owner_allocations,1,"two STREAM frames share one wrapper");
    let view=first.slice(1..);let held=view.clone();drop((first,view));
    let held_data=held.to_vec();let second_data=second.to_vec();
    recv1.stop(0u32.into()).unwrap();recv2.stop(0u32.into()).unwrap();
    let resets=connection.stats().frame_rx.reset_stream;
    send2.reset(0u32.into()).unwrap();
    until(||connection.stats().frame_rx.reset_stream>resets).await;
    assert_eq!(&held[..],&held_data[..],"held view survives STOP_SENDING and RESET_STREAM");
    assert_eq!(&second[..],&second_data[..]);
    assert!(raw.snapshot().0.items>=1,"stop does not destroy the retained packet owner");
    assert!(probe.stats().used>=backing_charge);
    connection.close(0u32.into(),b"done");
    timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
    drop((recv1,recv2,send1,send2,connection,peer,endpoint,peer_endpoint));
    until(||probe.stats().used==backing_charge).await;
    assert_eq!(raw.snapshot().0.items,1,"two STREAM views retain one shared packet owner");
    assert!(!held.is_empty());assert!(!second.is_empty());
    drop(second);
    assert_eq!(probe.stats().used,backing_charge,"one remaining slice/clone retains the full allocation");
    assert_eq!(raw.snapshot().0.items,1);
    drop(held);until(||probe.stats().used==0&&raw.snapshot().0.items==0).await;
}

async fn receive_backing_copy_refuses_before_stream(){
    // A refused copy closes before a STREAM frame or allocator effect is committed.
    let(endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    let probe=connection.control_test(|p|p.metadata_test_limit(0));
    let before=connection.stats().frame_rx.stream;
    let mut send=peer.open_uni().await.unwrap();send.write_all(b"uncommitted").await.unwrap();gate.open();
    until(||connection.close_reason().is_some()||connection.stats().frame_rx.stream>before).await;
    assert_eq!(connection.stats().frame_rx.stream,before,"unadmitted receive backing produced a STREAM effect");
    assert!(matches!(timeout(Duration::from_secs(5),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
    assert!(matches!(timeout(Duration::from_secs(5),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::StreamAssemblers));
    assert!(probe.stats().receive_payload_len>0,"the refused input length is observed before allocation");
    assert_eq!(probe.stats().receive_backing_capacity,0);assert_eq!(probe.stats().allocations,0);
    assert_eq!(connection.stats().frame_rx.stream,before,"refused payload does not produce STREAM effects");
    timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
    drop((send,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
}

async fn receive_owner_refuses_before_stream() {
    let(endpoint,peer_endpoint,connection,peer,gate,wire)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);
    wire.held.store(true,Ordering::SeqCst);
    wire.suppress_send.store(true,Ordering::SeqCst);
    let number=connection.control_test(|p|p.metadata_test_next_received());
    // STREAM with explicit length, client-initiated unidirectional stream 2, one byte.
    let(packet,payload_len)=peer.control_test(|p|p.control_test_packet_with_payload_len(number,false,&[0x0a,2,1,0x5a]));
    let owner_layout=connection.control_test(|p|p.metadata_test_receive_owner_layout());
    let payload_charge=((payload_len+63)&!63)+64;
    let owner_charge=((owner_layout+63)&!63)+64;
    let probe=connection.control_test(|p|p.metadata_test_limit(payload_charge+owner_charge-1));
    let before=connection.stats().frame_rx.stream;
    wire.packets.lock().unwrap().clear();
    wire.packets.lock().unwrap().push_back(packet);
    wire.held.store(false,Ordering::SeqCst);
    if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}
    gate.open();
    until(||connection.close_reason().is_some()||connection.stats().frame_rx.stream>before).await;
    assert_eq!(connection.stats().frame_rx.stream,before,"unadmitted owner wrapper produced a STREAM effect");
    assert!(matches!(timeout(Duration::from_secs(5),connection.closed()).await.unwrap(),ConnectionError::LocallyClosed));
    assert!(matches!(timeout(Duration::from_secs(5),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    let stats=probe.stats();
    assert_eq!(stats.receive_payload_len,payload_len,"wire builder observation precedes receive admission");
    assert_eq!(stats.receive_backing_capacity,payload_len,"payload was allocated before the separate wrapper refusal");
    assert_eq!(stats.receive_owner_layout,owner_layout);
    assert_eq!(stats.receive_owner_allocations,0,"refused wrapper never reaches allocation");
    assert_eq!(stats.allocations,1,"only the admitted payload copy allocated");
    assert_eq!(stats.failed_class,Some(proto::MetadataClass::StreamAssemblers));
    assert!(stats.peak<=stats.limit);
    timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
    drop((connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
}

#[tokio::test]
async fn receive_assemblers_charge_compaction_peaks() {
    // Refuse the replacement heap, refuse its copy, then admit the real read compaction.
    for case in 0..3 {
        let(endpoint,peer_endpoint,connection,peer,gate,_)=pair(65536,64,524288,512,65536,128).await;
        gate.closed.store(true,Ordering::SeqCst);
        let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
        let mut send=peer.open_uni().await.unwrap();
        let before=connection.stats().frame_rx.stream;
        send.write_chunk(bytes::Bytes::from_static(b"abc")).await.unwrap();gate.open();
        until(||connection.stats().frame_rx.stream>before).await;
        gate.closed.store(true,Ordering::SeqCst);
        let before=connection.stats().frame_rx.stream;
        send.write_chunk(bytes::Bytes::from_static(b"def")).await.unwrap();gate.open();
        until(||connection.stats().frame_rx.stream>before).await;
        gate.closed.store(true,Ordering::SeqCst);
        let mut recv=timeout(Duration::from_secs(5),connection.accept_uni()).await.unwrap().unwrap();
        let storage=connection.control_test(|p|p.metadata_test_receive_storage());
        assert_eq!(storage.1,2,"two actual retained receive descriptors");
        let descriptor=connection.control_test(|p|p.metadata_test_receive_descriptor_size());
        let replacement_bytes=storage.1*descriptor;
        let replacement_charge=((replacement_bytes+63)&!63)+64;
        let before=probe.stats();
        if case<2 { probe.freeze_with_additional_bytes(if case==0 {0}else{replacement_charge}); }
        // Box before observation; poll once while the connection driver is gated.
        // Only the actual replacement heap has this layout in this operation.
        let mut read=Box::pin(recv.read_chunk(64,false));
        let(result,heap_allocations)=allocator::heap_allocations(replacement_bytes,|| {
            match read.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(result)=>result,
                Poll::Pending=>panic!("buffered compaction read did not complete synchronously"),
            }
        });
        drop(read);
        if case<2 {
            assert!(matches!(result,Err(ReadError::ConnectionLost(ConnectionError::LocallyClosed))));
            assert_eq!(connection.control_test(|p|p.metadata_test_receive_storage()),storage,"read refusal restores the removed receive owner and its old heap");
            assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::StreamAssemblers));
            assert_eq!(heap_allocations,usize::from(case==1),"allocator observed an unadmitted replacement heap");
            gate.open();
            assert!(matches!(timeout(Duration::from_secs(5),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
        } else {
            assert_eq!(heap_allocations,1,"allocator must observe the admitted replacement heap");
            let bytes=result.unwrap().unwrap().bytes;
            assert_eq!(&bytes[..],b"abcdef");
            assert_eq!(connection.control_test(|p|p.metadata_test_receive_storage()),(replacement_bytes,0));
            assert_eq!(probe.stats().receive_backing_capacity,6,"real compaction copy capacity matches returned data");
            assert_eq!(probe.stats().receive_owner_allocations,before.receive_owner_allocations+1);
            assert!(probe.stats().peak>before.used,"old heap and backing overlap the replacements");
            let held=bytes.slice(1..);let clone=held.clone();drop((bytes,held));
            let owner_charge=((probe.stats().receive_owner_layout+63)&!63)+64;
            gate.open();connection.close(0u32.into(),b"done");
            timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
            drop((recv,send,connection,peer,endpoint,peer_endpoint));
            until(||probe.stats().used==128+owner_charge).await;
            assert_eq!(&clone[..],b"bcdef");drop(clone);until(||probe.stats().used==0).await;
            continue;
        }
        timeout(Duration::from_secs(5),endpoint.wait_idle()).await.unwrap();
        drop((recv,send,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
    }
}

async fn inject_unordered_history_byte(connection:&Connection,peer:&Connection,gate:&Arc<Gate>,wire:&Arc<Wire>,offset:u8,byte:u8) {
    gate.closed.store(true,Ordering::SeqCst);wire.held.store(true,Ordering::SeqCst);wire.suppress_send.store(true,Ordering::SeqCst);
    let packet=peer.control_test(|p|p.control_test_fresh_packet(&[0x0e,2,offset,1,byte]));
    let before=connection.stats().frame_rx.stream;
    wire.packets.lock().unwrap().clear();wire.packets.lock().unwrap().push_back(packet);
    wire.held.store(false,Ordering::SeqCst);if let Some(w)=wire.wake.lock().unwrap().take(){w.wake();}gate.open();
    until(||connection.stats().frame_rx.stream>before||connection.close_reason().is_some()).await;
    gate.closed.store(true,Ordering::SeqCst);
}

#[tokio::test]
async fn unordered_history_credit_survives_chunk_consumption() {
    for refuse in [true,false] {
        let(endpoint,peer_endpoint,connection,peer,gate,wire)=pair(65536,64,524288,512,65536,128).await;
        gate.closed.store(true,Ordering::SeqCst);let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));
        let send=peer.open_uni().await.unwrap();assert_eq!(VarInt::from(send.id()).into_inner(),2);
        inject_unordered_history_byte(&connection,&peer,&gate,&wire,1,b'a').await;
        let mut recv=timeout(Duration::from_secs(10),connection.accept_uni()).await.unwrap().unwrap();
        let first=timeout(Duration::from_secs(10),recv.read_chunk(16,false)).await.unwrap().unwrap().unwrap().bytes;assert_eq!(&first[..],b"a");drop(first);
        inject_unordered_history_byte(&connection,&peer,&gate,&wire,3,b'b').await;
        let second=timeout(Duration::from_secs(10),recv.read_chunk(16,false)).await.unwrap().unwrap().unwrap().bytes;assert_eq!(&second[..],b"b");drop(second);
        assert_eq!(connection.control_test(|p|p.metadata_test_unordered_history_storage()),(0,2));
        assert_eq!(connection.control_test(|p|p.metadata_test_receive_storage()).1,0);
        if refuse {
            // Incoming packet payload and owner may allocate; the history spill may not.
            let layout=connection.control_test(|p|p.metadata_test_receive_owner_layout());
            let extra=128+((layout+63)&!63)+64;
            probe.freeze_with_additional_bytes(extra);
        }
        inject_unordered_history_byte(&connection,&peer,&gate,&wire,5,b'c').await;
        if refuse {
            assert_eq!(connection.control_test(|p|p.metadata_test_unordered_history_storage()),(0,2),"unadmitted unordered history grew physical backing");
            assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::UnorderedHistory));
            assert_eq!(connection.control_test(|p|p.metadata_test_receive_storage()).1,0,"refused history inserted application data");
            gate.open();assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
        } else {
            let third=timeout(Duration::from_secs(10),recv.read_chunk(16,false)).await.unwrap().unwrap().unwrap().bytes;assert_eq!(&third[..],b"c");drop(third);
            assert_eq!(connection.control_test(|p|p.metadata_test_unordered_history_storage()),(64,3));
            assert!(probe.stats().used>=128,"consuming data does not refund retained receipt storage");
            inject_unordered_history_byte(&connection,&peer,&gate,&wire,3,b'!').await;
            let mut read=Box::pin(recv.read_chunk(16,false));
            assert!(read.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),"retransmitted consumed byte was delivered twice");drop(read);
            inject_unordered_history_byte(&connection,&peer,&gate,&wire,7,b'd').await;
            let bytes=timeout(Duration::from_secs(10),recv.read_chunk(16,false)).await.unwrap().unwrap().unwrap().bytes;assert_eq!(&bytes[..],b"d");
            assert_eq!(connection.control_test(|p|p.metadata_test_unordered_history_storage()),(64,4));
            let clone=bytes.slice(..).clone();drop(bytes);let owner_charge=((probe.stats().receive_owner_layout+63)&!63)+64;
            gate.open();connection.close(0u32.into(),b"done");timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();
            drop((recv,send,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==128+owner_charge).await;
            assert_eq!(&clone[..],b"d");drop(clone);until(||probe.stats().used==0).await;continue;
        }
        timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();drop((recv,send,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
    }
    unordered_history_transition_refusal_restores_receiver().await;
}

async fn unordered_history_transition_refusal_restores_receiver() {
    let(endpoint,peer_endpoint,connection,peer,gate,wire)=pair(65536,64,524288,512,65536,128).await;
    gate.closed.store(true,Ordering::SeqCst);let probe=connection.control_test(|p|p.metadata_test_limit(1<<20));let send=peer.open_uni().await.unwrap();
    for offset in [1,3,5] {inject_unordered_history_byte(&connection,&peer,&gate,&wire,offset,b'x').await;}
    let mut recv=timeout(Duration::from_secs(10),connection.accept_uni()).await.unwrap().unwrap();
    let storage=connection.control_test(|p|p.metadata_test_receive_storage());assert_eq!(storage.1,3);
    probe.freeze_at_live_allocations();let error=timeout(Duration::from_secs(10),recv.read_chunk(16,false)).await.unwrap().unwrap_err();
    assert!(matches!(error,ReadError::ConnectionLost(ConnectionError::LocallyClosed)));
    assert_eq!(probe.stats().failed_class,Some(proto::MetadataClass::UnorderedHistory));
    assert_eq!(connection.control_test(|p|p.metadata_test_receive_storage()),storage,"refused transition lost removed receive owner");
    assert_eq!(connection.control_test(|p|p.metadata_test_unordered_history_storage()),(0,0),"refused transition committed unordered mode");
    gate.open();assert!(matches!(timeout(Duration::from_secs(10),peer.closed()).await.unwrap(),ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0x524c)));
    timeout(Duration::from_secs(10),endpoint.wait_idle()).await.unwrap();drop((recv,send,connection,peer,endpoint,peer_endpoint));until(||probe.stats().used==0).await;
}
