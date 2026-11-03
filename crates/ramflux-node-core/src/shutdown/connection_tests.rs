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
        set.spawn(socket, Arc::clone(&store), |_, _, _| {})?;
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
    set.spawn(socket, (), |mut socket, (), _| {
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
    let (sender, receiver) = std::sync::mpsc::channel();
    set.spawn(socket, (), move |mut socket, (), connection| {
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

#[test]
fn connection_context_drops_before_membership_even_when_slow()
-> Result<(), Box<dyn std::error::Error>> {
    struct SlowContext(Arc<ConnectionSet>, Arc<std::sync::atomic::AtomicBool>);
    impl Drop for SlowContext {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_millis(25));
            self.1.store(self.0.len() == 1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let set = ConnectionSet::new(1);
    let (socket, _peer) = sockets()?;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    set.spawn(socket, SlowContext(Arc::clone(&set), Arc::clone(&observed)), |_, _, _| {})?;
    assert_eq!(set.wait_empty(Instant::now() + Duration::from_secs(2)), 0);
    assert!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        "membership released before context"
    );
    Ok(())
}
