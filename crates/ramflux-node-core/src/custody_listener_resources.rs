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
        let soft = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
        let reservation = |count: usize| {
            count.checked_mul(listeners).ok_or_else(|| {
                NodeCoreError::InvalidConfiguration(
                    "custody descriptor reservation overflows".into(),
                )
            })
        };
        if settings.authenticated.is_none() {
            static LOG: std::sync::Once = std::sync::Once::new();
            LOG.call_once(|| {
                tracing::info!(
                    soft_nofile = soft,
                    "custody authenticated ceiling is RLIMIT_NOFILE; no configured session cap"
                );
            });
        }
        validate_nofile(
            reservation(settings.handshakes)?,
            reservation(settings.authenticated.unwrap_or(0))?,
            soft,
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
/// Back off resource failures from 50 ms to one second; peer errors never delay acceptance.
#[derive(Default)]
pub struct ListenerAcceptBackoff {
    seen: HashSet<io::ErrorKind>,
    failures: u32,
}
impl ListenerAcceptBackoff {
    #[must_use]
    pub fn failure(&mut self, error: &io::Error) -> Duration {
        let resource = error.kind() == io::ErrorKind::OutOfMemory;
        #[cfg(unix)]
        let resource = resource
            || [
                rustix::io::Errno::MFILE,
                rustix::io::Errno::NFILE,
                rustix::io::Errno::NOBUFS,
                rustix::io::Errno::NOMEM,
            ]
            .iter()
            .any(|errno| error.raw_os_error() == Some(errno.raw_os_error()));
        if resource {
            self.resource_failure(error)
        } else {
            tracing::debug!(%error, "listener connection ended; accepting next peer");
            Duration::ZERO
        }
    }
    /// A failed descriptor clone or worker spawn is always a resource failure.
    #[must_use]
    pub fn resource_failure(&mut self, error: &io::Error) -> Duration {
        if self.seen.insert(error.kind()) {
            tracing::warn!(%error,kind=?error.kind(),"listener accept failed; retrying");
        }
        let delay = Duration::from_millis((50_u64 << self.failures.min(5)).min(1000));
        self.failures = self.failures.saturating_add(1);
        delay
    }
    /// Wait only for resource errors; peer failures do not call sleep, even with a zero duration.
    pub fn wait_after_failure(&mut self, error: &io::Error) {
        let delay = self.failure(error);
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
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
        if let Ok(permit) = limiter.acquire(peer.ip(), None, std::time::Instant::now()) {
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
            Err(error) => {
                let delay = backoff.failure(&error);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
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
                    Err(io::Error::from(io::ErrorKind::OutOfMemory))
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
                        Err(io::Error::from(io::ErrorKind::OutOfMemory))
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
    fn peer_errors_never_delay_or_escalate_resource_backoff() {
        let mut backoff = ListenerAcceptBackoff::default();
        for kind in [
            io::ErrorKind::NotConnected,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
            io::ErrorKind::Other,
        ] {
            assert_eq!(backoff.failure(&io::Error::from(kind)), Duration::ZERO);
        }
        #[cfg(unix)]
        for errno in [rustix::io::Errno::NOTCONN, rustix::io::Errno::INVAL] {
            assert_eq!(
                backoff.failure(&io::Error::from_raw_os_error(errno.raw_os_error())),
                Duration::ZERO
            );
        }
        assert_eq!(backoff.failures, 0);
        #[cfg(unix)]
        for errno in [
            rustix::io::Errno::MFILE,
            rustix::io::Errno::NFILE,
            rustix::io::Errno::NOBUFS,
            rustix::io::Errno::NOMEM,
        ] {
            backoff.success();
            assert_eq!(
                backoff.failure(&io::Error::from_raw_os_error(errno.raw_os_error())),
                Duration::from_millis(50)
            );
        }
        backoff.success();
        assert_eq!(
            backoff.resource_failure(&io::Error::other("spawn failed")),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn backoff_is_bounded_and_logs_once_per_kind() {
        let mut b = ListenerAcceptBackoff::default();
        let e = io::Error::from(io::ErrorKind::OutOfMemory);
        assert_eq!(b.failure(&e), Duration::from_millis(50));
        for _ in 0..20 {
            assert!(b.failure(&e) <= Duration::from_secs(1));
        }
        assert_eq!(b.seen.len(), 1);
        b.success();
        assert_eq!(b.failure(&e), Duration::from_millis(50));
    }
}
