// SPDX-License-Identifier: MIT OR Apache-2.0
//! Focused control-admission checks; complete raw/runtime oracles are separate.
use super::*;
use crate::tests::util::{client_config, server_config, Pair};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn packet(number: u8, sequence: u8, repeats: usize) -> Packet {
    let payload: Vec<u8> = (0..repeats).flat_map(|_| [0x19, sequence]).collect();
    Packet {
        header: Header::Short {
            spin: false,
            key_phase: false,
            dst_cid: ConnectionId::new(&[7; 8]),
            number: PacketNumber::U8(number),
        },
        header_data: Bytes::from_static(&[0x40]),
        payload: BytesMut::from(payload.as_slice()),
        plaintext: None,
    }
}

#[test]
fn pending_packet_reserves_both_directions_and_wakes_once_after_consumption() {
    let mut pair = Pair::default();
    let (client, _) = pair.connect();
    let now = pair.time;
    let conn = pair.client_conn_mut(client);
    conn.set_control_credit_limits(ControlLimits {
        bytes: 2048,
        items: 4,
    })
    .unwrap();
    let (first, last) = conn.local_cid_state.active_seq();
    assert!(last > first);
    let remote = conn.path.remote;
    // Each real retirement emits a forward control with a reserved reverse CID response.
    for (number, sequence) in [(100, first), (101, last)] {
        conn.handle_authenticated_packet(
            now,
            remote,
            None,
            Ok((packet(number, sequence as u8, 1), Some(number as u64), None)),
            false,
        );
    }
    assert_eq!(conn.endpoint_events.len(), 2);
    let next = first + 1;
    assert!(next < last);
    let authenticated_before = conn.total_authed_packets;
    conn.handle_authenticated_packet(
        now,
        remote,
        None,
        Ok((packet(102, next as u8, 1), Some(102), None)),
        false,
    );
    assert!(conn.pending_control.is_some());
    assert_eq!(conn.total_authed_packets, authenticated_before);
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(conn.poll_control_resume(&mut cx));
    let event = conn.poll_endpoint_events().unwrap();
    assert_eq!(wake.0.load(Ordering::SeqCst), 0);
    drop(event);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert!(!conn.poll_control_resume(&mut cx));
    assert_eq!(conn.total_authed_packets, authenticated_before + 1);
    assert_eq!(conn.endpoint_events.len(), 2);
    assert!(!conn.poll_control_resume(&mut cx));
    assert_eq!(conn.total_authed_packets, authenticated_before + 1);
    let state = conn.control.as_ref().unwrap().lock().unwrap();
    assert_eq!(state.used.forward, 2);
    assert_eq!(state.used.reverse, 2);
}

#[test]
fn oversize_packet_closes_before_dedup_and_drains_on_close_timer() {
    let mut pair = Pair::default();
    let (client, _) = pair.connect();
    let now = pair.time;
    let conn = pair.client_conn_mut(client);
    conn.set_control_credit_limits(ControlLimits {
        bytes: 2048,
        items: 4,
    })
    .unwrap();
    let sequence = conn.local_cid_state.active_seq().0;
    let remote = conn.path.remote;
    let before = conn.total_authed_packets;
    conn.handle_authenticated_packet(
        now,
        remote,
        None,
        Ok((packet(100, sequence as u8, 3), Some(100), None)),
        false,
    );
    assert!(conn.control_resource_closed);
    assert_eq!(conn.total_authed_packets, before);
    assert!(conn.state.is_closed());
    assert!(matches!(conn.poll(), Some(Event::ConnectionLost { .. })));
    assert!(conn.poll().is_none());
    let deadline = conn.timers.get(Timer::Close).unwrap();
    conn.handle_timeout(deadline);
    assert!(conn.state.is_drained());
    assert!(conn.poll_endpoint_events().unwrap().is_drained());
}

#[test]
fn configured_credit_preserves_real_tls_handshake() {
    let mut config = EndpointConfig::default();
    config
        .control_credit_limits(ControlLimits {
            bytes: 8192,
            items: 8,
        })
        .unwrap();
    let mut pair = Pair::new(Arc::new(config), server_config());
    pair.connect_with(client_config());
    assert!(!pair.drive_bounded());
}

struct DropOwner(Arc<AtomicUsize>);
impl Drop for DropOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn coalesced_handshake_parks_tail_until_both_control_directions_return() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let mut flight = Vec::new();
    let mut packets = 0;
    while let Some((_, _, bytes)) = pair.client.inbound.pop_front() {
        packets += 1;
        flight.extend_from_slice(&bytes);
    }
    assert!(
        packets >= 2,
        "fixture must contain the real server crypto and CID flights"
    );
    let now = pair.time;
    let remote = pair.server.addr;
    let mut response = Vec::new();
    let Some(crate::DatagramEvent::ConnectionEvent(handle, event)) = pair.client.handle(
        now,
        remote,
        None,
        None,
        BytesMut::from(flight.as_slice()),
        &mut response,
    ) else {
        panic!("client flight routing");
    };
    assert_eq!(client, handle);
    let drops = Arc::new(AtomicUsize::new(0));
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let conn = pair.client_conn_mut(client);
        conn.set_control_credit_limits(ControlLimits {
            bytes: 4096,
            items: 4,
        })
        .unwrap();
        conn.handle_event_with_owner(event, Arc::new(DropOwner(drops.clone())));
        assert!(
            conn.state.is_established(),
            "committed handshake head stays established"
        );
        assert!(
            conn.pending_control.is_some(),
            "CID tail must fit total but not remaining credit"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(conn.poll_control_resume(&mut cx));
        let state = conn.control.as_ref().unwrap().lock().unwrap();
        assert!(state.used.forward <= 4 && state.used.reverse <= 4);
    }
    let committed_heads = pair.client_conn_mut(client).total_authed_packets;
    let events = pair.client_conn_mut(client).endpoint_events.len();
    assert_eq!(events, 2);
    for _ in 0..events {
        let event = pair.client_conn_mut(client).poll_endpoint_events().unwrap();
        if let Some(reply) = pair.client.handle_event(client, event) {
            assert_eq!(
                wake.0.load(Ordering::SeqCst),
                0,
                "reply still owns reverse credit"
            );
            pair.client_conn_mut(client).handle_event(reply);
        }
    }
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    let conn = pair.client_conn_mut(client);
    assert!(!conn.poll_control_resume(&mut cx));
    assert_eq!(conn.total_authed_packets, committed_heads + 1);
    assert!(!conn.poll_control_resume(&mut cx));
    assert_eq!(
        conn.total_authed_packets,
        committed_heads + 1,
        "no head replay or tail double commit"
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn discarded_initial_head_allows_valid_tail_and_keeps_owner_until_stream_chunk_drop() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    let initial = pair.server.inbound.front().unwrap().2.clone();
    pair.drive_server();
    let server = pair.server.assert_accept();
    pair.drive();
    let now = pair.time;
    let remote = pair.client.addr;
    let stream = pair.client_streams(client).open(crate::Dir::Uni).unwrap();
    pair.client_send(client, stream).write(b"tail").unwrap();
    pair.client_send(client, stream).finish().unwrap();
    pair.drive_client();
    let (_, _, tail) = pair.server.inbound.pop_front().unwrap();
    assert_eq!(tail[0] & 0x80, 0, "key-ready 1-RTT tail");
    let mut bytes = initial.to_vec();
    bytes.extend_from_slice(&tail);
    let mut response = Vec::new();
    let Some(crate::DatagramEvent::ConnectionEvent(handle, event)) = pair.server.handle(
        now,
        remote,
        None,
        None,
        BytesMut::from(bytes.as_slice()),
        &mut response,
    ) else {
        panic!("server coalesced routing");
    };
    assert_eq!(handle, server);
    let drops = Arc::new(AtomicUsize::new(0));
    let conn = pair.server_conn_mut(server);
    conn.set_control_credit_limits(ControlLimits {
        bytes: 8192,
        items: 8,
    })
    .unwrap();
    let before = conn.total_authed_packets;
    conn.handle_event_with_owner(event, Arc::new(DropOwner(drops.clone())));
    assert_eq!(
        conn.total_authed_packets,
        before + 1,
        "only valid tail commits; old Initial keys are gone"
    );
    let mut recv = conn.recv_stream(stream);
    let mut chunks = recv.read(true).unwrap();
    let chunk = chunks.next(usize::MAX).unwrap().unwrap();
    assert_eq!(&chunk.bytes[..], b"tail");
    assert!(chunks.next(usize::MAX).unwrap().is_none());
    let _ = chunks.finalize();
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(chunk);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "last stream backing releases the admitted datagram owner"
    );
}
