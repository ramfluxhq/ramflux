// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded watchdog closes expired sockets even when TLS control records keep arriving.
use crate::{MeshTlsServerStream, TransportError};
use std::{
    collections::BTreeMap,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
struct Watchdog {
    sockets: Mutex<BTreeMap<(Instant, u64), TcpStream>>,
    changed: Condvar,
    sequence: AtomicU64,
}
static WATCHDOG: OnceLock<Result<Arc<Watchdog>, String>> = OnceLock::new();
/// Dropping a completed request cancels its socket deadline without retaining idle connections.
pub struct MeshRequestDeadline {
    key: (Instant, u64),
    watchdog: Arc<Watchdog>,
}
impl Drop for MeshRequestDeadline {
    fn drop(&mut self) {
        self.watchdog
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
        self.watchdog.changed.notify_one();
    }
}
/// Keep the returned guard alive until the response completes, including handler execution.
/// # Errors
/// Rejects expired deadlines, watchdog saturation, failed socket cloning or thread startup.
pub fn mesh_request_deadline(
    stream: &MeshTlsServerStream,
    deadline: Instant,
) -> Result<MeshRequestDeadline, TransportError> {
    register(&stream.sock, deadline)
}
fn register(socket: &TcpStream, deadline: Instant) -> Result<MeshRequestDeadline, TransportError> {
    if Instant::now() >= deadline {
        return Err(error("mesh request deadline exceeded"));
    }
    let watchdog = WATCHDOG.get_or_init(start).as_ref().map_err(|message| error(message))?.clone();
    let sequence = watchdog
        .sequence
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        .map_err(|_| error("mesh deadline sequence exhausted"))?;
    let key = (deadline, sequence);
    let socket = socket.try_clone()?;
    {
        let mut sockets =
            watchdog.sockets.lock().map_err(|_| error("mesh deadline state unavailable"))?;
        if sockets.len() >= 1024 {
            return Err(error("mesh deadline capacity refused"));
        }
        sockets.insert(key, socket);
    }
    watchdog.changed.notify_one();
    Ok(MeshRequestDeadline { key, watchdog })
}
fn start() -> Result<Arc<Watchdog>, String> {
    let watchdog = Arc::new(Watchdog {
        sockets: Mutex::new(BTreeMap::new()),
        changed: Condvar::new(),
        sequence: AtomicU64::new(0),
    });
    let worker = watchdog.clone();
    std::thread::Builder::new()
        .name("mesh-request-deadlines".into())
        .spawn(move || {
            loop {
                let mut sockets =
                    worker.sockets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some((&key, _)) = sockets.first_key_value() else {
                    drop(
                        worker
                            .changed
                            .wait(sockets)
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    );
                    continue;
                };
                if let Some(left) = key.0.checked_duration_since(Instant::now()) {
                    drop(
                        worker
                            .changed
                            .wait_timeout(sockets, left)
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    );
                    continue;
                }
                let socket = sockets.remove(&key);
                drop(sockets);
                if let Some(socket) = socket {
                    let _ = socket.shutdown(Shutdown::Both);
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(watchdog)
}
fn error(message: &str) -> TransportError {
    TransportError::Http(message.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, time::Duration};
    #[test]
    fn absolute_deadline_closes_a_socket_without_waiting_for_an_application_read()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let _guard = register(&server, Instant::now() + Duration::from_millis(20))?;
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte)?, 0);
        Ok(())
    }
}
