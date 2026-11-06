// SPDX-License-Identifier: MIT OR Apache-2.0
//! Binding control credits through real Tokio endpoint and connection drivers.
use super::*;
struct Harness {
    server: Endpoint,
    client: Endpoint,
    server_conn: Connection,
    client_conn: Connection,
    incoming: Arc<Wire>,
    outgoing: Arc<Wire>,
    handshakes: Option<(Connecting, Connecting)>,
}
fn inject(wire: &Wire, bytes: Vec<u8>) {
    wire.packets.lock().unwrap().push_back(bytes);
    if let Some(w) = wire.wake.lock().unwrap().take() {
        w.wake();
    }
}
fn release(wire: &Wire) {
    wire.held.store(false, Ordering::SeqCst);
    if let Some(w) = wire.wake.lock().unwrap().take() {
        w.wake();
    }
}
fn probe(c: &Connection, number: u64) -> [u64; 15] {
    c.control_test(|p| p.control_test_probe(number))
}
fn ceilings(p: [u64; 15]) {
    assert!(p[0] <= 4 && p[1] <= 4);
    assert!(p[0] * 512 <= 4096 && p[1] * 1024 <= 4096);
}
async fn harness(hold_flight: bool) -> Harness {
    let a: SocketAddr = "127.0.0.1:12000".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:12001".parse().unwrap();
    let incoming = Arc::new(Wire::default());
    let outgoing = Arc::new(Wire::default());
    outgoing.held.store(hold_flight, Ordering::SeqCst);
    let server_socket = Arc::new(Socket {
        local: a,
        remote: b,
        inbound: incoming.clone(),
        outbound: outgoing.clone(),
    });
    let client_socket = Arc::new(Socket {
        local: b,
        remote: a,
        inbound: outgoing.clone(),
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
            bytes: 4096,
            items: 4,
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
            bytes_total: 524288,
            items_total: 512,
            bytes_per_owner: 65536,
            items_per_owner: 64,
            bytes_per_source: 65536,
            items_per_source: 128,
        })
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = Endpoint::new_with_abstract_socket(
        {
            let mut c = EndpointConfig::default();
            c.control_credit_limits(proto::ControlLimits {
                bytes: 4096,
                items: 4,
            })
            .unwrap();
            c
        },
        None,
        client_socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(transport);
    client.set_default_client_config(client_config);
    client
        .set_packet_queue_limits(PacketQueueLimits {
            owners: 8,
            bytes_total: 524288,
            items_total: 512,
            bytes_per_owner: 65536,
            items_per_owner: 64,
            bytes_per_source: 65536,
            items_per_source: 128,
        })
        .unwrap();
    let connect = client.connect(a, "localhost").unwrap();
    let client_conn = connect.control_test_connection();
    let accept = timeout(Duration::from_secs(10), server.accept())
        .await
        .unwrap()
        .unwrap()
        .accept()
        .unwrap();
    let server_conn = accept.control_test_connection();
    if hold_flight {
        until(|| outgoing.packets.lock().unwrap().len() >= 2).await;
    } else {
        let (c, s) = tokio::join!(connect, accept);
        c.unwrap();
        s.unwrap();
        until(|| server.rawq_pool().snapshot().0.items == 0).await;
        return Harness {
            server,
            client,
            server_conn,
            client_conn,
            incoming,
            outgoing,
            handshakes: None,
        };
    }
    Harness {
        server,
        client,
        server_conn,
        client_conn,
        incoming,
        outgoing,
        handshakes: Some((connect, accept)),
    }
}

async fn discarded_head_commits_key_ready_tail_with_live_driver() {
    let h = harness(false).await;
    h.outgoing.suppress_send.store(true, Ordering::SeqCst);
    h.incoming.suppress_send.store(true, Ordering::SeqCst);
    let initial = h.incoming.history.lock().unwrap()[0].clone();
    assert!(initial[0] & 0x80 != 0);
    let tail = h
        .client_conn
        .control_test(|p| p.control_test_packet(100, false, b"\x0b\x02\x04tail"));
    let mut coalesced = initial;
    coalesced.extend_from_slice(&tail);
    let before = probe(&h.server_conn, 100);
    inject(&h.incoming, coalesced);
    let mut recv = timeout(Duration::from_secs(10), h.server_conn.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let chunk = recv.read_chunk(usize::MAX, true).await.unwrap().unwrap();
    assert_eq!(&chunk.bytes[..], b"tail");
    assert!(
        h.server.rawq_pool().snapshot().0.items > 0,
        "whole backing retained by tail chunk"
    );
    let committed = probe(&h.server_conn, 100);
    ceilings(committed);
    assert_eq!(committed[4], before[4] + 1, "only the key-ready tail authenticates");
    assert_eq!(committed[13], 1, "valid tail enters dedup");
    assert!(recv.read_chunk(usize::MAX, true).await.unwrap().is_none());
    let held = h.server.rawq_pool().snapshot().0.bytes;
    drop(chunk);
    assert!(h.server.rawq_pool().snapshot().0.bytes < held, "final chunk releases backing credit");
    drop(recv);
    until(|| h.server.rawq_pool().snapshot().0.items == 0).await;
    h.server.close(0u32.into(), b"done");
}

async fn committed_handshake_head_parks_tail_and_resumes_once_in_driver() {
    let mut h = harness(true).await;
    h.client.control_test_forward(true);
    h.client_conn.control_test_reverse(true);
    let mut flight = Vec::new();
    for packet in h.outgoing.packets.lock().unwrap().drain(..) {
        flight.extend_from_slice(&packet);
    }
    let before = probe(&h.client_conn, 0);
    h.outgoing.pause_after_recv.store(true, Ordering::SeqCst);
    let flight_len = flight.len();
    inject(&h.outgoing, flight);
    release(&h.outgoing);
    until(|| probe(&h.client_conn, 0)[5] != u64::MAX).await;
    h.outgoing.held.store(true, Ordering::SeqCst);
    let parked = probe(&h.client_conn, 0);
    ceilings(parked);
    assert!(parked[4] > before[4], "handshake heads committed");
    assert_eq!(
        parked[10], 0,
        "CID tail effects must not occur while parked"
    );
    assert_eq!(
        probe(&h.client_conn, parked[5])[13],
        0,
        "parked tail not deduped"
    );
    assert_eq!(
        probe(&h.client_conn, parked[5])[7],
        0,
        "parked tail not ACKed"
    );
    let counts = h.client_conn.control_test_counts();
    let raw = h.client.rawq_pool().snapshot().0;
    assert!(
        raw.bytes >= flight_len && raw.items == 1,
        "whole datagram backs the single pending remainder"
    );
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        probe(&h.client_conn, 0)[3],
        parked[3],
        "unchanged generation cannot retry"
    );
    h.client.control_test_forward(false);
    until(|| probe(&h.client_conn, 0)[2] > parked[2] || probe(&h.client_conn, 0)[1] > 0).await;
    assert_eq!(
        probe(&h.client_conn, 0)[5],
        parked[5],
        "reverse consumer independently retains credit"
    );
    assert_eq!(h.client.rawq_pool().snapshot().0.bytes, raw.bytes, "parked whole-datagram backing survives independent forward drain");
    h.client_conn.control_test_reverse(false);
    until(|| probe(&h.client_conn, 0)[5] == u64::MAX).await;
    let resumed = probe(&h.client_conn, 0);
    ceilings(resumed);
    assert_eq!(
        resumed[4],
        parked[4] + 1,
        "no head replay or double tail commit"
    );
    assert!(resumed[10] > parked[10]);
    assert_eq!(probe(&h.client_conn, parked[5])[13], 1, "tail dedup commits only after resume");
    assert_eq!(
        h.client_conn.control_test_counts().0 - counts.0,
        1,
        "one credit wake"
    );
    until(|| h.client.rawq_pool().snapshot().0.items == 0).await;
    release(&h.outgoing);
    let (c, s) = h.handshakes.take().unwrap();
    timeout(Duration::from_secs(10), async {
        let (c, s) = tokio::join!(c, s);
        c.unwrap();
        s.unwrap();
    })
    .await
    .unwrap();
    h.client.close(0u32.into(), b"done");
}

async fn full_directions_pause_raw_duplicate_retransmit_and_concurrent_timer() {
    let h = harness(false).await;
    h.outgoing.suppress_send.store(true, Ordering::SeqCst);
    h.incoming.suppress_send.store(true, Ordering::SeqCst);
    h.server.control_test_forward(true);
    h.server_conn.control_test_reverse(true);
    let (first, last) = h.server_conn.control_test(|p| p.control_test_cids());
    assert!(last >= first + 3);
    let packet = |pn, seq: u64, repeats: usize| {
        h.client_conn.control_test(|p| {
            let mut frames = Vec::new();
            for _ in 0..repeats {
                frames.extend_from_slice(&[0x19, seq as u8]);
            }
            p.control_test_packet(pn, false, &frames)
        })
    };
    let before = probe(&h.server_conn, 100);
    inject(&h.incoming, packet(100, first + 1, 2));
    inject(&h.incoming, packet(101, first + 2, 2));
    until(|| probe(&h.server_conn, 100)[0] == 4).await;
    let full = probe(&h.server_conn, 100);
    ceilings(full);
    assert_eq!(full[1], 4, "both directions actually full");
    let pending = packet(102, first + 3, 1);
    inject(&h.incoming, pending.clone());
    until(|| probe(&h.server_conn, 102)[5] == 102).await;
    let parked = probe(&h.server_conn, 102);
    let counts = h.server_conn.control_test_counts();
    assert_eq!(parked[13], 0, "pending producer not deduped");
    assert_eq!(parked[6], before[6] + 4);
    assert_eq!(parked[7], 0, "parked packet never ACKed");
    inject(&h.incoming, pending.clone());
    inject(
        &h.incoming,
        h.client_conn
            .control_test(|p| p.control_test_packet(104, false, &[0x01])),
    );
    until(|| h.server.rawq_pool().snapshot().0.items >= 3).await;
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        h.server_conn.control_test_counts().1,
        counts.1,
        "raw lane pauses behind producer"
    );
    h.server_conn
        .control_test(|p| p.control_test_timer(Instant::now()));
    until(|| probe(&h.server_conn, 102)[9] == 1).await;
    ceilings(probe(&h.server_conn, 102));
    h.server.control_test_forward(false);
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    let half = probe(&h.server_conn, 102);
    ceilings(half);
    assert_eq!(
        half[5], 102,
        "forward drain alone cannot free reverse owner"
    );
    h.server_conn.control_test_reverse(false);
    until(|| {
        probe(&h.server_conn, 102)[5] == u64::MAX
            && probe(&h.server_conn, 102)[9] == 0
            && probe(&h.server_conn, 102)[6] >= before[6] + 5
            && probe(&h.server_conn, 102)[0] == 0
            && probe(&h.server_conn, 102)[1] == 0
            && h.server_conn.control_test_counts().1 >= counts.1 + 2
    })
    .await;
    let done = probe(&h.server_conn, 102);
    ceilings(done);
    assert_eq!(
        done[6],
        before[6] + 5,
        "pending producer once and duplicate zero"
    );
    assert!(done[3] > parked[3]);
    assert!(
        h.server_conn.control_test_counts().0 > counts.0,
        "real credit waker ran"
    );
    let issued = h.server_conn.control_test(|p| p.control_test_cids());
    inject(&h.incoming, packet(103, first + 3, 1));
    until(|| {
        probe(&h.server_conn, 103)[6] == done[6] + 1
            && probe(&h.server_conn, 103)[0] == 0
            && probe(&h.server_conn, 103)[1] == 0
    })
    .await;
    assert_eq!(
        h.server_conn.control_test(|p| p.control_test_cids()),
        issued,
        "later RETIRE retransmission must not issue another local CID"
    );
    let retransmitted = probe(&h.server_conn, 103);
    inject(&h.incoming, pending);
    until(|| h.server_conn.control_test_counts().1 >= counts.1 + 4).await;
    assert_eq!(
        probe(&h.server_conn, 102)[6],
        retransmitted[6],
        "valid duplicate cannot replay effects"
    );
    assert_eq!(
        h.server_conn.control_test(|p| p.control_test_cids()),
        issued,
        "duplicate RETIRE must not issue another local CID"
    );
    h.server.close(0u32.into(), b"done");
    timeout(Duration::from_secs(10), h.server.wait_idle())
        .await
        .unwrap();
    assert_eq!(h.server.open_connections(), 0);
}

fn varint(bytes: &[u8], at: &mut usize) -> usize {
    let n = 1usize << (bytes[*at] >> 6);
    let mut value = (bytes[*at] & 63) as usize;
    *at += 1;
    for _ in 1..n {
        value = (value << 8) | bytes[*at] as usize;
        *at += 1;
    }
    value
}
fn initial_end(bytes: &[u8]) -> usize {
    let mut at = 5;
    let n = bytes[at] as usize;
    at += 1 + n;
    let n = bytes[at] as usize;
    at += 1 + n;
    let n = varint(bytes, &mut at);
    at += n;
    let n = varint(bytes, &mut at);
    at + n
}

async fn repeated_retire_oversize_cancels_coalesced_tail_and_drains() {
    let h = harness(true).await;
    h.client.control_test_forward(true);
    let first = h.outgoing.packets.lock().unwrap().pop_front().unwrap();
    let end = initial_end(&first);
    assert!(end < first.len(), "coalesced Initial + Handshake fixture");
    h.outgoing.packets.lock().unwrap().clear();
    inject(&h.outgoing, first[..end].to_vec());
    release(&h.outgoing);
    until(|| probe(&h.client_conn, 99)[4] > 0).await;
    h.outgoing.held.store(true, Ordering::SeqCst);
    let committed = probe(&h.client_conn, 99);
    ceilings(committed);
    let mut oversize = h.server_conn.control_test(|p| {
        p.control_test_packet(99, true, &[0x19, 0, 0x19, 0, 0x19, 0, 0x19, 0, 0x19, 0])
    });
    oversize.extend_from_slice(&first[end..]);
    inject(&h.outgoing, oversize);
    release(&h.outgoing);
    let error = timeout(Duration::from_secs(10), h.client_conn.closed())
        .await
        .unwrap();
    assert!(
        matches!(error,ConnectionError::TransportError(ref e) if e.reason=="control_packet_oversize")
    );
    let closed = probe(&h.client_conn, 99);
    ceilings(closed);
    assert_eq!(
        closed[4], committed[4],
        "oversize and valid tail both uncommitted"
    );
    assert_eq!(closed[6], committed[6]);
    assert_eq!(closed[10], committed[10]);
    assert_eq!(closed[12], 0, "oversize handshake not ACKed");
    assert_eq!(closed[14], 0, "oversize handshake not deduped");
    assert_eq!(closed[7], 0);
    assert_eq!(closed[5], u64::MAX);

    h.client.control_test_forward(false);
    timeout(Duration::from_secs(10), h.client.wait_idle())
        .await
        .unwrap();
    assert_eq!(h.client.open_connections(), 0);
    until(|| h.client.rawq_pool().snapshot().0.items == 0).await;
}

async fn metadata_terminal_adapter_cancels_parked_tail_and_notifies_driver() {
    let h = harness(true).await;
    h.client.control_test_forward(true);
    h.client_conn.control_test_reverse(true);
    let mut flight = Vec::new();
    for packet in h.outgoing.packets.lock().unwrap().drain(..) {
        flight.extend_from_slice(&packet);
    }
    h.outgoing.pause_after_recv.store(true, Ordering::SeqCst);
    inject(&h.outgoing, flight);
    release(&h.outgoing);
    until(|| probe(&h.client_conn, 0)[5] != u64::MAX).await;
    let committed = probe(&h.client_conn, 0);
    ceilings(committed);
    assert!(committed[0] > 0 && committed[1] > 0);
    let pending = committed[5];
    assert_eq!(probe(&h.client_conn, pending)[13], 0);
    h.client_conn.control_test(|p| {
        p.resource_exhausted(Instant::now());
        p.resource_exhausted(Instant::now());
    });
    assert!(matches!(
        timeout(Duration::from_secs(10), h.client_conn.closed())
            .await
            .unwrap(),
        ConnectionError::LocallyClosed
    ));
    let closed = probe(&h.client_conn, pending);
    ceilings(closed);
    assert_eq!(closed[5], u64::MAX);
    assert_eq!(closed[4], committed[4]);
    assert_eq!(closed[13], 0);
    assert_eq!(
        (closed[0], closed[1]),
        (committed[0], committed[1]),
        "committed control owners survive terminal adapter"
    );
    h.client_conn.control_test_reverse(false);
    h.client.control_test_forward(false);
    timeout(Duration::from_secs(10), h.client.wait_idle())
        .await
        .unwrap();
    assert_eq!(h.client.open_connections(), 0);
    until(|| h.client.rawq_pool().snapshot().0.items == 0).await;
}

pub(super) async fn r10_driver_matrix() {
    discarded_head_commits_key_ready_tail_with_live_driver().await;
    committed_handshake_head_parks_tail_and_resumes_once_in_driver().await;
    full_directions_pause_raw_duplicate_retransmit_and_concurrent_timer().await;
    repeated_retire_oversize_cancels_coalesced_tail_and_drains().await;
    metadata_terminal_adapter_cancels_parked_tail_and_notifies_driver().await;
}
