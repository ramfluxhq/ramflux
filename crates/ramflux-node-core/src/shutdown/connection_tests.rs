// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::connections::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn sockets() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let peer = TcpStream::connect(listener.local_addr()?)?;
    let (socket, _) = listener.accept()?;
    Ok((socket, peer))
}

#[test]
fn capacity_rejects_and_guard_drop_releases_slot() -> Result<(), Box<dyn std::error::Error>> {
    let set = ConnectionSet::new(1);
    let (socket, _peer) = sockets()?;
    let guard = set.register(&socket)?.ok_or("first admission refused")?;
    let (other, mut peer) = sockets()?;
    assert!(set.register(&other)?.is_none());
    peer.set_read_timeout(Some(Duration::from_secs(1)))?;
    assert_eq!(peer.read(&mut [0; 1])?, 0);
    drop(guard);
    assert!(set.is_empty());
    Ok(())
}

#[test]
fn drain_count_reaches_zero_after_context_clones_drop() -> Result<(), Box<dyn std::error::Error>> {
    let set = ConnectionSet::new(DEFAULT_CONNECTION_LIMIT);
    let store = Arc::new(());
    for _ in 0..2000 {
        let (socket, _peer) = sockets()?;
        let registration = socket.try_clone()?;
        set.spawn(&registration, (socket, Arc::clone(&store)), |_, _| {})?;
    }
    assert_eq!(set.wait_empty(Instant::now() + Duration::from_secs(5)), 0);
    assert_eq!(Arc::strong_count(&store), 1);
    Ok(())
}

#[test]
fn idle_read_is_interrupted_without_waiting_for_socket_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let set = ConnectionSet::new(1);
    let (socket, _peer) = sockets()?;
    let registration = socket.try_clone()?;
    set.spawn(&registration, socket, |socket, _| {
        let _ = socket.read(&mut [0; 1]);
    })?;
    set.stop_idle();
    assert_eq!(set.wait_empty(Instant::now() + Duration::from_secs(1)), 0);
    Ok(())
}

#[test]
fn force_close_interrupts_blocked_response_write() -> Result<(), Box<dyn std::error::Error>> {
    let set = ConnectionSet::new(1);
    let (socket, _peer) = sockets()?;
    let registration = socket.try_clone()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    set.spawn(&registration, socket, move |socket, connection| {
        let Some(_request) = connection.begin_request() else {
            return;
        };
        let _ = sender.send(());
        let bytes = vec![0; 65536];
        while socket.write_all(&bytes).is_ok() {}
    })?;
    receiver.recv_timeout(Duration::from_secs(1))?;
    set.stop_idle();
    assert!(!set.is_empty());
    set.force_close();
    assert_eq!(set.wait_empty(Instant::now() + Duration::from_secs(1)), 0);
    Ok(())
}
