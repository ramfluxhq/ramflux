// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection policy for hosts on IPv6-only and NAT64 mobile networks: a bind address
//! chosen per destination family, host-name resolution at each connect, and a staggered
//! attempt over the resolved addresses.
//!
//! These are hooks. Nothing in the desktop connect path calls them yet, so no behaviour
//! changes on macOS or Linux. They open no socket themselves: the caller supplies the
//! connect future (a gateway session with transport `Auto`), and the pinned CA of that
//! session is untouched. The QUIC / TCP+TLS race and the per-network transport memory
//! live with the session and the network monitor, not here.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use crate::SdkError;

/// Delay between attempts on successive resolved addresses.
pub const ADDRESS_STAGGER: Duration = Duration::from_millis(250);
/// OPEN-VALUE: resolved addresses tried per connect. Bounds work on a hostile resolver.
pub const MAX_ADDRESSES: usize = 8;

/// Local bind address able to reach `remote`: the unspecified address of the same family.
/// A v4 wildcard bind cannot reach an IPv6 gateway, which is every gateway on an IPv6-only
/// (NAT64) network.
#[must_use]
pub const fn bind_addr_for(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Bind address a session uses for `remote`. A configured wildcard of the other family
/// (today's default is the IPv4 wildcard) can never reach `remote`, so it is replaced by
/// the wildcard of the remote's family. Every other configured address is kept as it is,
/// which leaves each connect that works today unchanged.
#[must_use]
pub fn effective_bind_addr(configured: SocketAddr, remote: SocketAddr) -> SocketAddr {
    let wildcard = configured.ip().is_unspecified() && configured.port() == 0;
    if wildcard && configured.is_ipv4() != remote.is_ipv4() {
        bind_addr_for(remote)
    } else {
        configured
    }
}

/// A gateway named by host and port, as a mobile node profile must carry it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayHost {
    host: String,
    port: u16,
}

impl GatewayHost {
    /// Accept a DNS name or an IPv6 literal. An IPv4 literal is refused: the resolver
    /// cannot synthesize a NAT64 address for it, so the profile would fail on an IPv6-only
    /// network.
    ///
    /// # Errors
    /// Returns an error for an empty host, a zero port, or an IPv4 literal.
    pub fn for_mobile(host: &str, port: u16) -> Result<Self, SdkError> {
        let host = host.trim().trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || port == 0 {
            return Err(SdkError::LocalBus("gateway host and port are required".to_owned()));
        }
        if host.parse::<Ipv4Addr>().is_ok() {
            return Err(SdkError::LocalBus(
                "a mobile node profile must name the gateway by host, not by IPv4 literal"
                    .to_owned(),
            ));
        }
        Ok(Self { host: host.to_owned(), port })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Resolve with the system resolver (`getaddrinfo`, unspecified family) now. The
    /// result is never cached: each connect resolves again. Order is the resolver's.
    ///
    /// # Errors
    /// Returns an error when resolution fails or yields no address.
    pub async fn resolve(&self) -> Result<Vec<SocketAddr>, SdkError> {
        let found = tokio::net::lookup_host((self.host.as_str(), self.port)).await?;
        let addresses = dedup_in_order(found, MAX_ADDRESSES);
        if addresses.is_empty() {
            return Err(SdkError::LocalBus("gateway host resolved to no address".to_owned()));
        }
        Ok(addresses)
    }
}

fn dedup_in_order(found: impl Iterator<Item = SocketAddr>, limit: usize) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();
    for address in found {
        if addresses.len() >= limit {
            break;
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

type Attempt<'a, T> = Pin<Box<dyn Future<Output = Result<T, SdkError>> + 'a>>;

/// Try `addresses` in order. Attempt `n + 1` starts `stagger` after attempt `n`, or at once
/// when every earlier attempt has already failed. The first success wins and every other
/// attempt is dropped before this returns.
///
/// # Errors
/// Returns the last attempt's error when all fail, or an error for an empty list.
pub async fn connect_staggered<'a, T, F, Fut>(
    addresses: &[SocketAddr],
    stagger: Duration,
    mut connect: F,
) -> Result<(T, SocketAddr), SdkError>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, SdkError>> + 'a,
{
    let mut waiting = addresses.iter().copied();
    let mut active: Vec<(SocketAddr, Attempt<'a, T>)> = Vec::new();
    let mut last_error = None;
    let mut timer = Box::pin(tokio::time::sleep(stagger));
    std::future::poll_fn(move |context| {
        loop {
            let mut index = 0;
            while index < active.len() {
                match active[index].1.as_mut().poll(context) {
                    Poll::Ready(Ok(value)) => {
                        let address = active[index].0;
                        // Dropping the others cancels them before the caller continues.
                        active.clear();
                        return Poll::Ready(Ok((value, address)));
                    }
                    Poll::Ready(Err(error)) => {
                        last_error = Some(error);
                        drop(active.swap_remove(index));
                    }
                    Poll::Pending => index += 1,
                }
            }
            let due = active.is_empty() || timer.as_mut().poll(context).is_ready();
            if !due {
                return Poll::Pending;
            }
            let Some(address) = waiting.next() else {
                if active.is_empty() {
                    return Poll::Ready(Err(last_error.take().unwrap_or_else(|| {
                        SdkError::LocalBus("no gateway address to connect to".to_owned())
                    })));
                }
                return Poll::Pending;
            };
            active.push((address, Box::pin(connect(address))));
            timer.as_mut().reset(tokio::time::Instant::now() + stagger);
            // Loop: the new attempt and the reset timer must be polled to register wakers.
        }
    })
    .await
}

/// One address to hand to a gateway session: where to connect and what to bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionEndpoint {
    pub gateway_addr: SocketAddr,
    pub bind_addr: SocketAddr,
}

impl SessionEndpoint {
    #[must_use]
    pub const fn for_remote(gateway_addr: SocketAddr) -> Self {
        Self { gateway_addr, bind_addr: bind_addr_for(gateway_addr) }
    }
}

impl GatewayHost {
    /// Resolve now and pair every address with a bind address of its family, in resolver
    /// order. The caller builds one session configuration per endpoint (transport `Auto`)
    /// and passes them to [`connect_staggered`].
    ///
    /// # Errors
    /// Returns an error when resolution fails or yields no address.
    pub async fn session_endpoints(&self) -> Result<Vec<SessionEndpoint>, SdkError> {
        Ok(self.resolve().await?.into_iter().map(SessionEndpoint::for_remote).collect())
    }
}

#[cfg(test)]
mod tests;
