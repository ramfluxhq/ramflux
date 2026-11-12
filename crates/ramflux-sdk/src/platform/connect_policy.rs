// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection policy for hosts on mobile networks: a bind address chosen per destination
//! family, host-name resolution at each connect, a staggered attempt over the resolved
//! addresses, and the raced QUIC / TCP+TLS choice for `Auto`.
//!
//! These are hooks. Nothing in the desktop connect path calls them yet, so no behaviour
//! changes on macOS or Linux. They open no socket themselves: the caller supplies the
//! connect futures, and the pinned CA of the gateway session is untouched.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::{GatewaySessionTransportKind, SdkError};

/// Delay between attempts on successive resolved addresses.
pub const ADDRESS_STAGGER: Duration = Duration::from_millis(250);
/// Head start QUIC gets over TCP+TLS on `Auto`.
pub const TCP_RACE_DELAY: Duration = Duration::from_millis(300);
/// How long the winning transport is remembered for one network.
pub const TRANSPORT_MEMORY: Duration = Duration::from_secs(600);
/// OPEN-VALUE: resolved addresses tried per connect. Bounds work on a hostile resolver.
pub const MAX_ADDRESSES: usize = 8;
/// OPEN-VALUE: networks remembered at once.
const MAX_REMEMBERED_NETWORKS: usize = 32;

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

/// Which transport an `Auto` connect ended on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaceWinner {
    Quic,
    TcpTls,
}

impl RaceWinner {
    #[must_use]
    pub const fn transport_kind(self) -> GatewaySessionTransportKind {
        match self {
            Self::Quic => GatewaySessionTransportKind::Quic,
            Self::TcpTls => GatewaySessionTransportKind::TcpTls,
        }
    }
}

/// Race QUIC against TCP+TLS for `Auto`. `preferred` (from [`TransportMemory`]) starts
/// first; the other starts `delay` later, or at once when the first has failed. Each
/// future must complete its TLS handshake and nothing more: the loser is dropped before
/// this returns, so only the winner ever reaches the custody handoff.
///
/// # Errors
/// Returns the TCP+TLS error when both fail (it is the transport of last resort).
pub async fn race_quic_tcp<T, Q, C>(
    quic: Q,
    tcp: C,
    preferred: Option<RaceWinner>,
    delay: Duration,
) -> Result<(T, RaceWinner), SdkError>
where
    Q: Future<Output = Result<T, SdkError>>,
    C: Future<Output = Result<T, SdkError>>,
{
    let tcp_first = preferred == Some(RaceWinner::TcpTls);
    let mut quic = Box::pin(quic);
    let mut tcp = Box::pin(tcp);
    let mut timer = Box::pin(tokio::time::sleep(delay));
    let mut quic_error = None;
    let mut tcp_error = None;
    let mut second_started = false;
    std::future::poll_fn(move |context| {
        loop {
            let poll_quic = quic_error.is_none() && (!tcp_first || second_started);
            let poll_tcp = tcp_error.is_none() && (tcp_first || second_started);
            if poll_quic {
                match quic.as_mut().poll(context) {
                    Poll::Ready(Ok(value)) => return Poll::Ready(Ok((value, RaceWinner::Quic))),
                    Poll::Ready(Err(error)) => quic_error = Some(error),
                    Poll::Pending => {}
                }
            }
            if poll_tcp {
                match tcp.as_mut().poll(context) {
                    Poll::Ready(Ok(value)) => return Poll::Ready(Ok((value, RaceWinner::TcpTls))),
                    Poll::Ready(Err(error)) => tcp_error = Some(error),
                    Poll::Pending => {}
                }
            }
            if quic_error.is_some() && tcp_error.is_some() {
                let error = tcp_error.take().or_else(|| quic_error.take());
                return Poll::Ready(Err(error.unwrap_or_else(|| {
                    SdkError::LocalBus("gateway connect failed".to_owned())
                })));
            }
            if second_started {
                return Poll::Pending;
            }
            let first_failed = if tcp_first { tcp_error.is_some() } else { quic_error.is_some() };
            if first_failed || timer.as_mut().poll(context).is_ready() {
                second_started = true;
                // Loop: the second transport must be polled once to register its waker.
                continue;
            }
            return Poll::Pending;
        }
    })
    .await
}

/// Last transport that completed a handshake, per network, for [`TRANSPORT_MEMORY`].
///
/// The network key is an opaque string chosen by the host (for example a digest of the
/// interface kind and its network identifier). It stays in memory, is never written to
/// disk and never sent anywhere.
#[derive(Debug, Default)]
pub struct TransportMemory {
    networks: BTreeMap<String, (RaceWinner, Instant)>,
}

impl TransportMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the transport that won on `network` at `now`.
    pub fn remember(&mut self, network: &str, winner: RaceWinner, now: Instant) {
        self.networks.retain(|_, (_, at)| now.saturating_duration_since(*at) < TRANSPORT_MEMORY);
        if self.networks.len() >= MAX_REMEMBERED_NETWORKS && !self.networks.contains_key(network)
        {
            let oldest =
                self.networks.iter().min_by_key(|(_, (_, at))| *at).map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.networks.remove(&oldest);
            }
        }
        self.networks.insert(network.to_owned(), (winner, now));
    }

    /// Transport to start first on `network`, when one won there within the last ten
    /// minutes. The other transport is still raced; memory only swaps the head start.
    #[must_use]
    pub fn preferred(&self, network: &str, now: Instant) -> Option<RaceWinner> {
        self.networks
            .get(network)
            .filter(|(_, at)| now.saturating_duration_since(*at) < TRANSPORT_MEMORY)
            .map(|(winner, _)| *winner)
    }

    /// Forget a network, for example after its remembered transport failed.
    pub fn forget(&mut self, network: &str) {
        self.networks.remove(network);
    }
}

#[cfg(test)]
mod tests;
