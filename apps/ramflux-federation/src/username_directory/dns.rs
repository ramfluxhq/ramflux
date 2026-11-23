// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A fixed resolver pool bounds stalled operating-system lookups and queued requests.
use super::{Result, error, refuse};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::Instant,
};

struct Job {
    host: String,
    port: u16,
    reply: mpsc::SyncSender<std::io::Result<Vec<SocketAddr>>>,
}
static RESOLVER: OnceLock<Option<mpsc::SyncSender<Job>>> = OnceLock::new();

pub fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let sender = RESOLVER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<Job>(16);
            let receiver = Arc::new(Mutex::new(receiver));
            for index in 0..2 {
                let receiver = Arc::clone(&receiver);
                if std::thread::Builder::new()
                    .name(format!("username-dns-{index}"))
                    .spawn(move || {
                        loop {
                            let job = {
                                let Ok(receiver) = receiver.lock() else {
                                    return;
                                };
                                receiver.recv()
                            };
                            let Ok(job) = job else {
                                return;
                            };
                            let result = (job.host.as_str(), job.port)
                                .to_socket_addrs()
                                .map(|ips| ips.take(9).collect());
                            let _ = job.reply.try_send(result);
                        }
                    })
                    .is_err()
                {
                    return None;
                }
            }
            Some(sender)
        })
        .as_ref()
        .ok_or_else(|| error("username resolver unavailable"))?;
    let (reply, response) = mpsc::sync_channel(1);
    sender
        .try_send(Job { host: host.into(), port, reply })
        .map_err(|_| error("username resolver capacity"))?;
    let wait = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| error("username DNS deadline"))?;
    let addresses = response.recv_timeout(wait).map_err(|_| error("username DNS deadline"))??;
    if addresses.is_empty() || addresses.len() > 8 {
        return refuse("username DNS address bound");
    }
    Ok(addresses)
}
