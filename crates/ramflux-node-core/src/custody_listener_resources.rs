// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Listener descriptor reservation and recoverable accept failures.
use crate::{CustodyPoolSettings, NodeCoreError};
use std::{collections::HashSet, io, time::Duration};
/// Raise the soft descriptor ceiling to the hard limit and check listener reservations.
/// # Errors
/// Refuses an unsupported platform, a failed resource-limit update or insufficient descriptors.
pub fn custody_listener_resources(
    settings: CustodyPoolSettings,
    listeners: usize,
) -> Result<(), NodeCoreError> {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        let limit = getrlimit(Resource::Nofile);
        if limit.current != limit.maximum {
            setrlimit(Resource::Nofile, Rlimit { current: limit.maximum, maximum: limit.maximum })
                .map_err(|e| {
                    NodeCoreError::InvalidConfiguration(format!(
                        "cannot raise RLIMIT_NOFILE soft to hard: {e}"
                    ))
                })?;
        }
        validate_nofile(
            settings.handshakes * listeners,
            settings.authenticated * listeners,
            getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (settings, listeners);
        Err(NodeCoreError::InvalidConfiguration(
            "custody listeners require RLIMIT_NOFILE support".into(),
        ))
    }
}
fn validate_nofile(h: usize, a: usize, soft: u64) -> Result<(), NodeCoreError> {
    if (h as u64) + (a as u64) + 512 > soft {
        return Err(NodeCoreError::InvalidConfiguration(format!(
            "custody descriptors H={h} + A={a} + 512 exceed RLIMIT_NOFILE soft={soft}"
        )));
    }
    Ok(())
}
/// Log each accept error kind once; consecutive failures back off from 50 ms to one second.
#[derive(Default)]
pub struct ListenerAcceptBackoff {
    seen: HashSet<io::ErrorKind>,
    failures: u32,
}
impl ListenerAcceptBackoff {
    #[must_use]
    pub fn failure(&mut self, error: &io::Error) -> Duration {
        if self.seen.insert(error.kind()) {
            tracing::warn!(%error,kind=?error.kind(),"listener accept failed; retrying");
        }
        let delay = Duration::from_millis((50_u64 << self.failures.min(5)).min(1000));
        self.failures = self.failures.saturating_add(1);
        delay
    }
    pub fn success(&mut self) {
        self.failures = 0;
    }
}
/// Accept a TCP holder before any TLS work; saturation closes only the newcomer.
pub async fn custody_accept_tcp(
    listener: &tokio::net::TcpListener,
    limiter: &std::sync::Arc<crate::CustodyIngressLimiter>,
    backoff: &mut ListenerAcceptBackoff,
) -> (tokio::net::TcpStream, std::net::SocketAddr, crate::CustodyIngressPermit) {
    loop {
        let (socket, peer) = custody_accept(|| listener.accept(), backoff).await;
        if let Some(permit) = limiter.acquire(peer.ip(), None, std::time::Instant::now()) {
            return (socket, peer, permit);
        }
    }
}
/// Retry transient and resource-exhaustion accept failures without terminating the listener.
pub async fn custody_accept<T, F, Fut>(mut accept: F, backoff: &mut ListenerAcceptBackoff) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    loop {
        match accept().await {
            Ok(value) => {
                backoff.success();
                return value;
            }
            Err(error) => tokio::time::sleep(backoff.failure(&error)).await,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn low_nofile_refuses_with_all_three_numbers() -> Result<(), Box<dyn std::error::Error>> {
        let e = validate_nofile(512, 2048, 3000).err().ok_or("accepted low nofile")?.to_string();
        for n in ["512", "2048", "3000"] {
            assert!(e.contains(n));
        }
        assert!(validate_nofile(512, 2048, 3072).is_ok());
        Ok(())
    }
    #[tokio::test]
    async fn accept_error_injection_keeps_serving() {
        let mut calls = 0;
        let mut backoff = ListenerAcceptBackoff::default();
        let result = custody_accept(
            || {
                calls += 1;
                std::future::ready(if calls <= 3 {
                    Err(io::Error::from(io::ErrorKind::Other))
                } else {
                    Ok(7)
                })
            },
            &mut backoff,
        )
        .await;
        assert_eq!(result, 7);
        assert_eq!(calls, 4);
    }
    #[tokio::test]
    async fn injected_accept_error_on_real_socket_still_serves_next_client()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let server = async {
            let mut backoff = ListenerAcceptBackoff::default();
            let (mut socket, _) = custody_accept(
                || async {
                    if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                        Err(io::Error::from(io::ErrorKind::Other))
                    } else {
                        listener.accept().await
                    }
                },
                &mut backoff,
            )
            .await;
            socket.write_all(&[9]).await
        };
        let client = async {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            let mut byte = [0];
            socket.read_exact(&mut byte).await?;
            assert_eq!(byte, [9]);
            Ok::<_, io::Error>(())
        };
        let (server, client) = tokio::join!(server, client);
        server?;
        client?;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        Ok(())
    }
    #[test]
    fn backoff_is_bounded_and_logs_once_per_kind() {
        let mut b = ListenerAcceptBackoff::default();
        let e = io::Error::from(io::ErrorKind::Other);
        assert_eq!(b.failure(&e), Duration::from_millis(50));
        for _ in 0..20 {
            assert!(b.failure(&e) <= Duration::from_secs(1));
        }
        assert_eq!(b.seen.len(), 1);
        b.success();
        assert_eq!(b.failure(&e), Duration::from_millis(50));
    }
}
