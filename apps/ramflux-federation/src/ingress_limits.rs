// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source addresses grant scheduling headroom only, never request authority.
use crate::mesh_auth::AuthLevel;
use ramflux_node_core::NodeCoreError;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Pool {
    Handshake,
    EstablishedHandshake,
    Connection,
    EstablishedConnection,
    Request,
    EstablishedRequest,
}
#[derive(Default)]
struct Limits {
    active: BTreeMap<(Pool, IpAddr), usize>,
    established: BTreeMap<IpAddr, Instant>,
}
static LIMITS: OnceLock<Mutex<Limits>> = OnceLock::new();

fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip @ IpAddr::V4(_) => ip,
    }
}
fn group(ip: IpAddr) -> IpAddr {
    match normalized(ip) {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & 0xffff_ff00)),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
    }
}

/// Called only after TLS peer verification or signed-envelope authentication succeeds.
/// This bounded, expiring address hint cannot bypass any certificate/signature policy.
pub(crate) fn remember_verified(ip: IpAddr) {
    if let Ok(mut limits) = LIMITS.get_or_init(Mutex::default).lock() {
        let now = Instant::now();
        limits.established.retain(|_, until| *until > now);
        let ip = normalized(ip);
        if limits.established.len() < 128 || limits.established.contains_key(&ip) {
            limits.established.insert(ip, now + Duration::from_secs(3600));
        }
    }
}

pub(crate) struct IngressPermit {
    ip: IpAddr,
    pool: Pool,
}
impl IngressPermit {
    fn acquire(ip: IpAddr, kind: Pool) -> Result<Self, NodeCoreError> {
        let ip = normalized(ip);
        let mut limits = LIMITS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| crate::inbound_trust::refused())?;
        let now = Instant::now();
        limits.established.retain(|_, until| *until > now);
        let pool = if limits.established.contains_key(&ip) {
            match kind {
                Pool::Handshake => Pool::EstablishedHandshake,
                Pool::Connection => Pool::EstablishedConnection,
                Pool::Request => Pool::EstablishedRequest,
                other => other,
            }
        } else {
            kind
        };
        let (total, per_group, headroom) = match pool {
            Pool::Handshake | Pool::Connection => (16, 2, 4),
            Pool::Request => (8, 2, 2),
            Pool::EstablishedHandshake | Pool::EstablishedConnection => (16, 4, 4),
            Pool::EstablishedRequest => (32, 4, 4),
        };
        let mut count = 0;
        let mut source_count = 0;
        for ((row_pool, source), active) in &limits.active {
            if *row_pool == pool {
                count += active;
                if group(*source) == group(ip) {
                    source_count += active;
                }
            }
        }
        // Repeat sources cannot consume the final slots reserved for new network groups.
        if count >= total
            || source_count >= per_group
            || (source_count > 0 && count >= total - headroom)
            || limits.active.get(&(pool, ip)).copied().unwrap_or(0) >= 2
        {
            return Err(NodeCoreError::Capacity { resource: "federation ingress" });
        }
        *limits.active.entry((pool, ip)).or_default() += 1;
        Ok(Self { ip, pool })
    }
}
impl Drop for IngressPermit {
    fn drop(&mut self) {
        if let Ok(mut limits) = LIMITS.get_or_init(Mutex::default).lock() {
            let key = (self.pool, self.ip);
            if let Some(count) = limits.active.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    limits.active.remove(&key);
                }
            }
        }
    }
}

pub(crate) struct HandshakePermit {
    _permit: IngressPermit,
}
impl HandshakePermit {
    pub(crate) fn acquire(ip: IpAddr) -> Result<Self, ramflux_transport::TransportError> {
        IngressPermit::acquire(ip, Pool::Handshake)
            .map(|permit| Self { _permit: permit })
            .map_err(|_| ramflux_transport::TransportError::NotAuthenticated)
    }
}
pub(crate) struct AnonymousPermit {
    _permit: IngressPermit,
}
impl AnonymousPermit {
    pub(crate) fn acquire(
        auth: &AuthLevel,
        ip: IpAddr,
        connection: bool,
    ) -> Result<Option<Self>, NodeCoreError> {
        if !auth.anonymous() {
            remember_verified(ip);
            return Ok(None);
        }
        IngressPermit::acquire(ip, if connection { Pool::Connection } else { Pool::Request })
            .map(|permit| Some(Self { _permit: permit }))
    }
}
