// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded local federation HTTP forwarding, used only for migrated destinations.
use ramflux_node_core::NodeCoreError;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DNS_JOB_LIMIT: usize = 32;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(12);

// TCP mesh workers have no runtime context. Keep one IO driver for both ingress paths;
// never create a runtime per message. DNS admission also bounds queued blocking jobs.
fn io_runtime() -> Result<&'static tokio::runtime::Runtime, NodeCoreError> {
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(DNS_JOB_LIMIT)
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(http_error)
}

fn http_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::ItestHttp(error.to_string())
}

async fn deadline<T>(
    phase: &'static str,
    duration: Duration,
    work: impl Future<Output = Result<T, NodeCoreError>>,
) -> Result<T, NodeCoreError> {
    tokio::time::timeout(duration, work)
        .await
        .map_err(|_| NodeCoreError::ForwardTimeout { phase })?
}

pub(crate) fn post(
    url: &str,
    body: &serde_json::Value,
    total: Duration,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, NodeCoreError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| http_error("unsupported forward URL"))?;
    let (host, path) = rest.find('/').map_or((rest, "/"), |index| rest.split_at(index));
    let body = serde_json::to_vec(body).map_err(http_error)?;
    io_runtime()?.handle().block_on(deadline("total", total, async {
        let addresses = resolve(host);
        let response = exchange(host, path, &body, addresses).await?;
        serde_json::from_slice(&response).map_err(http_error)
    }))
}

async fn resolve(host: &str) -> Result<SocketAddr, NodeCoreError> {
    static ADMISSION: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    // Literal addresses need neither a job nor an owned hostname allocation.
    if let Ok(address) = host.parse::<SocketAddr>() {
        return Ok(address);
    }
    let admission = ADMISSION.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(DNS_JOB_LIMIT)));
    let host = host.to_owned();
    resolve_job(admission, move || {
        host.to_socket_addrs()
            .map_err(http_error)?
            .next()
            .ok_or_else(|| http_error("cannot resolve forward host"))
    })
    .await
}

async fn resolve_job(
    admission: &Arc<tokio::sync::Semaphore>,
    work: impl FnOnce() -> Result<SocketAddr, NodeCoreError> + Send + 'static,
) -> Result<SocketAddr, NodeCoreError> {
    let permit = Arc::clone(admission)
        .try_acquire_owned()
        .map_err(|_| NodeCoreError::ForwardTimeout { phase: "dns" })?;
    tokio::task::spawn_blocking(move || {
        // A DNS timeout detaches this worker. Keep admission until getaddrinfo
        // really returns, so later requests cannot accumulate an unbounded queue.
        let _permit = permit;
        work()
    })
    .await
    .map_err(http_error)?
}

async fn exchange(
    host: &str,
    path: &str,
    body: &[u8],
    resolver: impl Future<Output = Result<SocketAddr, NodeCoreError>>,
) -> Result<Vec<u8>, NodeCoreError> {
    let addresses = deadline("dns", DNS_TIMEOUT, resolver).await?;
    deadline("socket", SOCKET_TIMEOUT, async {
        let mut stream = tokio::net::TcpStream::connect(addresses).await.map_err(http_error)?;
        let mut raw = Vec::new();
        std::io::Write::write_fmt(&mut raw, format_args!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())).map_err(http_error)?;
        stream.write_all(&raw).await.map_err(http_error)?;
        stream.write_all(body).await.map_err(http_error)?;
        raw.clear();
        let mut byte = [0];
        while !raw.ends_with(b"\r\n\r\n") {
            if raw.len() >= 64 * 1024 { return Err(http_error("forward response header too large")); }
            stream.read_exact(&mut byte).await.map_err(http_error)?;
            raw.push(byte[0]);
        }
        let header = std::str::from_utf8(&raw).map_err(http_error)?;
        let mut lines = header.lines();
        let status = lines.next().ok_or_else(|| http_error("missing forward response status"))?;
        if !(status.starts_with("HTTP/1.1 2") || status.starts_with("HTTP/1.0 2")) {
            return Err(http_error(format!("non-success forward response: {status}")));
        }
        let mut length = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length") {
                if length.is_some() { return Err(http_error("duplicate content length")); }
                length = Some(value.trim().parse::<usize>().map_err(http_error)?);
            }
        }
        let length = length.filter(|length| *length <= 1024 * 1024)
            .ok_or_else(|| http_error("missing or excessive forward response length"))?;
        let mut response = vec![0; length];
        stream.read_exact(&mut response).await.map_err(http_error)?;
        Ok(response)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timed_out_dns_jobs_keep_admission_and_excess_work_fails_fast() -> anyhow::Result<()> {
        let admission = Arc::new(tokio::sync::Semaphore::new(2));
        let (entered, mut receiver) = tokio::sync::mpsc::channel(2);
        let address = "127.0.0.1:80".parse::<SocketAddr>()?;
        let mut releases = Vec::new();
        let mut jobs = Vec::new();
        for _ in 0..2 {
            let admission = Arc::clone(&admission);
            let entered = entered.clone();
            let (release, wait) = std::sync::mpsc::channel();
            releases.push(release);
            jobs.push(tokio::spawn(async move {
                deadline(
                    "dns",
                    Duration::from_millis(20),
                    resolve_job(&admission, move || {
                        entered.blocking_send(()).map_err(http_error)?;
                        wait.recv_timeout(Duration::from_secs(5)).map_err(http_error)?;
                        Ok(address)
                    }),
                )
                .await
            }));
        }
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("DNS worker did not enter"))?;
        }
        for job in jobs {
            assert!(matches!(job.await?, Err(NodeCoreError::ForwardTimeout { phase: "dns" })));
        }
        assert_eq!(admission.available_permits(), 0);
        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let attempted = Arc::clone(&executed);
        let refused = tokio::time::timeout(
            Duration::from_millis(100),
            resolve_job(&admission, move || {
                attempted.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(address)
            }),
        )
        .await?;
        assert!(matches!(refused, Err(NodeCoreError::ForwardTimeout { phase: "dns" })));
        assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
        for release in releases {
            release.send(())?;
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while admission.available_permits() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // Once real work finishes, capacity becomes usable again.
        assert_eq!(resolve_job(&admission, move || Ok(address)).await?, address);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn hanging_dns_returns_typed_forward_timeout() -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            DNS_TIMEOUT + Duration::from_secs(1),
            exchange("unresolved.example:80", "/", b"{}", std::future::pending()),
        )
        .await?;
        assert!(matches!(result, Err(NodeCoreError::ForwardTimeout { phase: "dns" })));
        assert_eq!(start.elapsed(), DNS_TIMEOUT);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn trickling_peer_cannot_renew_socket_deadline() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sent = std::sync::Arc::clone(&writes);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 1024];
            let received = stream.read(&mut request).await?;
            assert!(received > 0, "missing forward request");
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").await?;
            while stream.write_all(b" ").await.is_ok() {
                sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok::<(), std::io::Error>(())
        });
        // Real IO plus paused time requires explicit ticks to avoid auto-advancing
        // before the operating system has delivered the listener readiness event.
        let work = tokio::time::timeout(
            SOCKET_TIMEOUT + Duration::from_secs(1),
            exchange("localhost", "/", b"{}", async { Ok(address) }),
        );
        tokio::pin!(work);
        let start = tokio::time::Instant::now();
        let result = loop {
            tokio::select! {
                result = &mut work => break result?,
                () = tokio::task::yield_now() => {
                    std::thread::sleep(Duration::from_millis(1));
                    tokio::time::advance(Duration::from_millis(100)).await;
                }
            }
        };
        server.abort();
        assert!(
            writes.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "peer did not trickle response bytes"
        );
        assert!(matches!(result, Err(NodeCoreError::ForwardTimeout { phase: "socket" })));
        assert!(start.elapsed() <= SOCKET_TIMEOUT + Duration::from_millis(100));
        Ok(())
    }
}
