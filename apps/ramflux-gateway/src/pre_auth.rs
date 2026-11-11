// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-authentication admission uses transport-observed source buckets.

use std::net::{IpAddr, Ipv4Addr};

/// Preserve the node's IPv6 /64 and IPv4-mapped policy. The well-known NAT64
/// prefix (`64:ff9b::/96`) represents the same source as its embedded IPv4 address;
/// network-specific translation prefixes are not inferred from arbitrary IPv6.
#[must_use]
pub(crate) fn source_key(peer: IpAddr) -> String {
    let source = match peer {
        IpAddr::V6(ip) if ip.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0] => {
            let octets = ip.octets();
            IpAddr::V4(Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
        }
        source => source,
    };
    ramflux_node_core::source_ip_hash(&source.to_string())
}

#[cfg(test)]
#[path = "pre_auth_tests.rs"]
mod tests;
