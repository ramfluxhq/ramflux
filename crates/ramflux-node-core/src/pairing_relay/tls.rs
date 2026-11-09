// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing TLS evidence: the listener itself, or a trusted proxy asserting https.
use std::net::IpAddr;

const TRUSTED_PROXIES_ENV: &str = "RAMFLUX_FEDERATION_TRUSTED_PROXIES";

/// Parse the trusted-proxy allowlist. Unset or empty means refuse (no implicit trust).
/// # Errors
/// Rejects a non-IP entry.
pub fn trusted_proxies_from_env() -> Result<Vec<IpAddr>, crate::NodeCoreError> {
    let Ok(raw) = crate::environment::var(TRUSTED_PROXIES_ENV) else {
        return Ok(Vec::new());
    };
    parse_trusted_proxies(&raw)
}

/// Parse a comma-separated IPv4/IPv6 allowlist. Empty input is an empty allowlist.
/// # Errors
/// Rejects a non-IP entry.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<IpAddr>, crate::NodeCoreError> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let ip = item.parse::<IpAddr>().map_err(|_| {
            crate::NodeCoreError::Unauthorized(format!(
                "{TRUSTED_PROXIES_ENV} entries must be IP addresses"
            ))
        })?;
        out.push(ip);
    }
    Ok(out)
}

/// Pairing counts as TLS when the listener terminated TLS, or the peer is an allowlisted
/// proxy that asserts `X-Forwarded-Proto: https`. Untrusted peers cannot assert TLS.
#[must_use]
pub fn pairing_request_is_tls(
    listener_is_tls: bool,
    peer: IpAddr,
    trusted_proxies: &[IpAddr],
    forwarded_proto: Option<&str>,
) -> bool {
    if listener_is_tls {
        return true;
    }
    trusted_peer(peer, trusted_proxies)
        && forwarded_proto.is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

/// Client address for /24 claim budgets: X-Forwarded-For from a trusted proxy
/// (rightmost untrusted hop), otherwise the socket peer. Untrusted X-Forwarded-* is ignored.
/// A present hop that is not a bare IP is refused; it does not fall back to the proxy.
///
/// # Errors
/// Returns `"forwarded client invalid"` when a hop is empty-only or not a bare IPv4/IPv6 address.
pub fn pairing_client_addr(
    peer: IpAddr,
    trusted_proxies: &[IpAddr],
    forwarded_for: Option<&str>,
) -> Result<IpAddr, &'static str> {
    if !trusted_peer(peer, trusted_proxies) {
        return Ok(peer);
    }
    Ok(rightmost_untrusted_hop(forwarded_for, trusted_proxies)?.unwrap_or(peer))
}

fn trusted_peer(peer: IpAddr, trusted_proxies: &[IpAddr]) -> bool {
    trusted_proxies.contains(&peer)
}

fn rightmost_untrusted_hop(
    forwarded_for: Option<&str>,
    trusted_proxies: &[IpAddr],
) -> Result<Option<IpAddr>, &'static str> {
    let Some(header) = forwarded_for else {
        return Ok(None);
    };
    let mut saw_hop = false;
    for hop in header.split(',').rev() {
        let hop = hop.trim();
        if hop.is_empty() {
            continue;
        }
        saw_hop = true;
        let ip = hop.parse::<IpAddr>().map_err(|_| "forwarded client invalid")?;
        if !trusted_peer(ip, trusted_proxies) {
            return Ok(Some(ip));
        }
    }
    if !saw_hop {
        return Err("forwarded client invalid");
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn empty_allowlist_refuses_plain_and_ignores_forwarded_headers() -> TestResult {
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let trusted = parse_trusted_proxies("")?;
        assert_eq!(trusted, Vec::<IpAddr>::new());
        assert!(!pairing_request_is_tls(false, peer, &trusted, Some("https")));
        assert_eq!(
            pairing_client_addr(peer, &trusted, Some("203.0.113.9, 198.51.100.1")),
            Ok(peer)
        );
        assert!(pairing_request_is_tls(true, peer, &trusted, None));
        Ok(())
    }

    #[test]
    fn trusted_proxy_https_uses_rightmost_untrusted_hop() -> TestResult {
        let proxy = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let trusted = parse_trusted_proxies("127.0.0.1")?;
        assert!(pairing_request_is_tls(false, proxy, &trusted, Some("https")));
        assert!(!pairing_request_is_tls(false, proxy, &trusted, Some("http")));
        assert!(!pairing_request_is_tls(false, proxy, &trusted, None));
        assert_eq!(
            pairing_client_addr(proxy, &trusted, Some("198.51.100.7, 203.0.113.10")),
            Ok(client)
        );
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let trusted_v6 = parse_trusted_proxies("::1")?;
        let client6: IpAddr = "2001:db8::1".parse()?;
        assert_eq!(pairing_client_addr(v6, &trusted_v6, Some("2001:db8::1")), Ok(client6));
        Ok(())
    }

    #[test]
    fn untrusted_peer_cannot_assert_https_or_rewrite_the_client() -> TestResult {
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let trusted = parse_trusted_proxies("127.0.0.1")?;
        assert!(!pairing_request_is_tls(false, peer, &trusted, Some("https")));
        assert_eq!(pairing_client_addr(peer, &trusted, Some("203.0.113.9")), Ok(peer));
        Ok(())
    }

    #[test]
    fn invalid_allowlist_entry_fails_closed() {
        assert!(parse_trusted_proxies("127.0.0.1,not-an-ip").is_err());
    }

    #[test]
    fn unparsable_forwarded_hop_is_refused() -> TestResult {
        let proxy = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let trusted = parse_trusted_proxies("127.0.0.1")?;
        for hop in ["[2001:db8::1]", "192.0.2.7:4443", "", "  ,  "] {
            assert_eq!(
                pairing_client_addr(proxy, &trusted, Some(hop)),
                Err("forwarded client invalid")
            );
        }
        Ok(())
    }
}
