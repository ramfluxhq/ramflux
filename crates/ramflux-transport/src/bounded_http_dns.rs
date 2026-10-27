// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A fixed resolver pool bounds queued work even if an operating-system resolver stalls.
use crate::TransportError;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::Instant,
};
struct Job {
    endpoint: String,
    deadline: Instant,
    response: mpsc::SyncSender<Result<Vec<SocketAddr>, String>>,
}
struct Resolver {
    jobs: mpsc::SyncSender<Job>,
}
static RESOLVER: OnceLock<Result<Resolver, String>> = OnceLock::new();
pub(crate) fn resolve(
    endpoint: &str,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, TransportError> {
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        return Ok(vec![address]);
    }
    let resolver = RESOLVER.get_or_init(start).as_ref().map_err(|message| error(message))?;
    let (response, receiver) = mpsc::sync_channel(1);
    resolver
        .jobs
        .try_send(Job { endpoint: endpoint.into(), deadline, response })
        .map_err(|_| error("bounded resolver is busy"))?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| error("HTTP exchange deadline exceeded"))?;
    receiver
        .recv_timeout(remaining)
        .map_err(|_| error("HTTP resolution deadline exceeded"))?
        .map_err(|message| error(&message))
}
fn start() -> Result<Resolver, String> {
    let (jobs, receiver) = mpsc::sync_channel::<Job>(16);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..4 {
        let receiver = receiver.clone();
        std::thread::Builder::new()
            .name(format!("bounded-http-dns-{index}"))
            .spawn(move || {
                loop {
                    let job =
                        receiver.lock().unwrap_or_else(std::sync::PoisonError::into_inner).recv();
                    let Ok(job) = job else {
                        break;
                    };
                    if Instant::now() >= job.deadline {
                        continue;
                    }
                    let result = job
                        .endpoint
                        .to_socket_addrs()
                        .map(|addresses| addresses.take(16).collect())
                        .map_err(|_| "HTTP name resolution failed".into());
                    let _ = job.response.send(result);
                }
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(Resolver { jobs })
}
fn error(message: &str) -> TransportError {
    TransportError::Http(message.into())
}
