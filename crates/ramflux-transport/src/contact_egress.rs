// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public-only discovery. Signed routing evidence never authorizes a private-network dial.
use crate::TransportError;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

fn refused() -> TransportError {
    TransportError::Http("contact public egress refused".into())
}
/// True only for the public-unicast subset accepted by the contact bootstrap profile.
#[must_use]
pub fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    let denied = [
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ];
    !denied.into_iter().any(|(network, bits)| ip & (u32::MAX << (32 - bits)) == network)
}
fn public_v6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    let global = 0x2000_u128 << 112;
    if bits & (u128::MAX << 125) != global {
        return false;
    }
    ![
        (0x2001_u128 << 112, 23),
        ((0x2001_u128 << 112) | (0x0db8_u128 << 96), 32),
        (0x2002_u128 << 112, 16),
        (0x3fff_u128 << 112, 20),
    ]
    .into_iter()
    .any(|(network, prefix)| bits & (u128::MAX << (128 - prefix)) == network)
}

/// A DNS-validated origin with addresses fixed for the ensuing TLS connection.
/// Its fields are private so no caller can manufacture an unchecked dial target.
pub struct PublicTarget {
    url: reqwest::Url,
    host: String,
    addresses: Vec<SocketAddr>,
}
impl PublicTarget {
    /// Resolve one exact HTTPS node origin under the common ten-second deadline.
    /// # Errors
    /// Refuses private/mixed addresses, redirects, credentialed origins and excessive DNS chains.
    pub async fn resolve(
        origin: &str,
        node: &str,
        deadline: Instant,
    ) -> Result<Self, TransportError> {
        let url = reqwest::Url::parse(origin).map_err(|_| refused())?;
        if url.scheme() != "https"
            || url.host_str() != Some(node)
            || url.port_or_known_default() != Some(443)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || node.parse::<IpAddr>().is_ok()
            || node.is_empty()
            || node.len() > 253
            || node.ends_with('.')
            || node
                .bytes()
                .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'))
        {
            return Err(refused());
        }
        let mut builder = hickory_resolver::Resolver::builder_tokio().map_err(|_| refused())?;
        let options = builder.options_mut();
        options.timeout = Duration::from_secs(5);
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = 8;
        options.cache_size = 0;
        options.preserve_intermediates = true;
        let resolver = builder.build().map_err(|_| refused())?;
        let fqdn = format!("{node}.");
        let left = deadline.checked_duration_since(Instant::now()).ok_or_else(refused)?;
        let lookup =
            tokio::time::timeout(left.min(Duration::from_secs(10)), resolver.lookup_ip(fqdn))
                .await
                .map_err(|_| refused())?
                .map_err(|_| refused())?;
        let aliases = lookup
            .as_lookup()
            .answers()
            .iter()
            .filter(|r| r.record_type().to_string() == "CNAME")
            .take(9)
            .count();
        if aliases > 8 {
            return Err(refused());
        }
        let mut addresses = Vec::new();
        for address in lookup.iter().take(65) {
            if !public_address(address) || addresses.len() >= 64 {
                return Err(refused());
            }
            addresses.push(SocketAddr::new(address, 443));
        }
        if addresses.is_empty() {
            return Err(refused());
        }
        Ok(Self { url, host: node.into(), addresses })
    }

    /// Fetch one fixed well-known path, pinning the validated DNS answers to TLS hostname checks.
    /// # Errors
    /// Refuses cross-origin paths, redirects, HTTP failures and bodies exceeding the explicit cap.
    pub async fn get(
        &self,
        path: &str,
        deadline: Instant,
        limit: usize,
    ) -> Result<Vec<u8>, TransportError> {
        if !path.starts_with("/.well-known/ramflux/")
            || path.contains('?')
            || path.contains('#')
            || !(1..=1024 * 1024).contains(&limit)
        {
            return Err(refused());
        }
        let left = deadline.checked_duration_since(Instant::now()).ok_or_else(refused)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&self.host, &self.addresses)
            .timeout(left.min(Duration::from_secs(10)))
            .build()
            .map_err(|e| TransportError::HttpClient(e.without_url()))?;
        let mut url = self.url.clone();
        url.set_path(path);
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|e| TransportError::HttpClient(e.without_url()))?
            .error_for_status()
            .map_err(|e| TransportError::HttpClient(e.without_url()))?;
        if response.content_length().is_some_and(|n| n > u64::try_from(limit).unwrap_or(u64::MAX)) {
            return Err(refused());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) =
            response.chunk().await.map_err(|e| TransportError::HttpClient(e.without_url()))?
        {
            if bytes.len().checked_add(chunk.len()).is_none_or(|n| n > limit) {
                return Err(refused());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contact_egress_refuses_private_translated_and_documentation_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "fc00::1",
            "2001:db8::1",
            "2002:808:808::1",
            "3fff::1",
        ] {
            assert!(
                !public_address(address.parse()?),
                "special-purpose address must never authorize public contact egress: {address}"
            );
        }
        for address in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"] {
            assert!(
                public_address(address.parse()?),
                "normal public unicast control must remain usable: {address}"
            );
        }
        Ok(())
    }
}
