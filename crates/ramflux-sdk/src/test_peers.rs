// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Release-controlled loopback peers with cancellation for accepted and idle listeners.
use std::io::{Read, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

struct Peer {
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    arrived: Arc<AtomicBool>,
    expired: Arc<AtomicBool>,
    release: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}
#[derive(Default)]
pub(crate) struct Peers {
    peers: Vec<Peer>,
}
impl Peers {
    pub(crate) fn spawn(&mut self, read_request: bool) -> std::io::Result<String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let arrived = Arc::new(AtomicBool::new(false));
        let expired = Arc::new(AtomicBool::new(false));
        let (release, released) = mpsc::channel();
        let (s, r, a, e) = (stop.clone(), ready.clone(), arrived.clone(), expired.clone());
        let thread = std::thread::spawn(move || {
            let start = Instant::now();
            let stopped = || {
                if start.elapsed() >= Duration::from_secs(30) {
                    e.store(true, Ordering::Release);
                }
                s.load(Ordering::Acquire) || e.load(Ordering::Acquire)
            };
            r.store(true, Ordering::Release);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped() {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error),
                }
            };
            socket.set_nonblocking(false)?;
            if read_request {
                // Optional demonstration delay is never enabled in ordinary tests.
                if std::env::var_os("RAMFLUX_TEST_PEER_READ_DELAY").is_some() {
                    let delay = Instant::now();
                    while delay.elapsed() < Duration::from_secs(2) && !stopped() {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                socket.set_read_timeout(Some(Duration::from_millis(10)))?;
                let mut buffer = [0; 4096];
                loop {
                    if stopped() {
                        return Ok(());
                    }
                    match socket.read(&mut buffer) {
                        Ok(0) => return Ok(()),
                        Ok(_) => break,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                            ) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            a.store(true, Ordering::Release);
            while !stopped() {
                if released.recv_timeout(Duration::from_millis(10)).is_ok() {
                    break;
                }
            }
            let _ = socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n");
            Ok(())
        });
        self.peers.push(Peer { stop, ready, arrived, expired, release, thread: Some(thread) });
        Ok(url)
    }
    pub(crate) fn ready(&self) -> usize {
        self.peers.iter().filter(|p| p.ready.load(Ordering::Acquire)).count()
    }
    pub(crate) fn accepted(&self) -> usize {
        self.peers.iter().filter(|p| p.arrived.load(Ordering::Acquire)).count()
    }
    pub(crate) fn guard_expired(&self) -> bool {
        self.peers.iter().any(|p| p.expired.load(Ordering::Acquire))
    }
    pub(crate) fn finish(&mut self) -> std::io::Result<Duration> {
        let start = Instant::now();
        for peer in &self.peers {
            peer.stop.store(true, Ordering::Release);
            let _ = peer.release.send(());
        }
        let mut failure = None;
        for peer in &mut self.peers {
            if let Some(thread) = peer.thread.take() {
                if let Err(error) =
                    thread.join().unwrap_or_else(|_| Err(std::io::Error::other("peer panicked")))
                {
                    failure = Some(error);
                }
            }
        }
        let elapsed = start.elapsed();
        eprintln!("test peer cleanup: {} listeners, {elapsed:?}", self.peers.len());
        if let Some(error) = failure {
            return Err(error);
        }
        if self.guard_expired() {
            return Err(std::io::Error::other("peer guard expired"));
        }
        Ok(elapsed)
    }
}
impl Drop for Peers {
    fn drop(&mut self) {
        if self.peers.iter().any(|p| p.thread.is_some()) {
            let _ = self.finish();
        }
    }
}
pub(crate) async fn wait_for(predicate: impl FnMut() -> bool, seconds: u64) {
    wait_until(predicate, Instant::now() + Duration::from_secs(seconds)).await;
}

pub(crate) async fn wait_until(mut predicate: impl FnMut() -> bool, deadline: Instant) {
    while !predicate() {
        assert!(Instant::now() < deadline, "wall hang guard expired");
        tokio::task::yield_now().await;
    }
}
