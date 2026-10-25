// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-keyed source pseudonyms retain IPv6 prefix admission without exposing an address hash.
use crate::{NodeCoreError, NodeSecret};
use std::sync::OnceLock;
static MOUNTED_KEY: OnceLock<NodeSecret> = OnceLock::new();

pub(crate) fn configure_node_privacy() -> Result<(), NodeCoreError> {
    if let Some(path) = std::env::var_os("RAMFLUX_NODE_PRIVACY_KEY_FILE") {
        let key = NodeSecret::from_file(path)?;
        MOUNTED_KEY.set(key).map_err(|_| {
            NodeCoreError::Unauthorized("node privacy key already initialized".into())
        })?;
    }
    Ok(())
}
#[must_use]
pub fn source_ip_hash(source_ip: &str) -> String {
    source_ip_hash_with_key(
        source_ip,
        MOUNTED_KEY.get().unwrap_or_else(|| NodeSecret::process_key()),
    )
}

#[must_use]
pub fn source_ip_hash_with_key(source_ip: &str, secret: &NodeSecret) -> String {
    let key = match source_ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) => ip.to_ipv4_mapped().map_or_else(
            || {
                let s = ip.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            },
            |ip| ip.to_string(),
        ),
        _ => source_ip.to_owned(),
    };
    secret.pseudonym("ramflux.source_ip_hash.v2", key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_keys_separate_ip_buckets_and_preserve_ipv6_prefixes() -> Result<(), NodeCoreError> {
        let a = NodeSecret::ephemeral()?;
        let b = NodeSecret::ephemeral()?;
        assert_eq!(
            source_ip_hash_with_key("2001:db8:1:2::1", &a),
            source_ip_hash_with_key("2001:db8:1:2::ffff", &a)
        );
        assert_eq!(
            source_ip_hash_with_key("::ffff:192.0.2.1", &a),
            source_ip_hash_with_key("192.0.2.1", &a)
        );
        assert_ne!(
            source_ip_hash_with_key("192.0.2.1", &a),
            source_ip_hash_with_key("192.0.2.1", &b)
        );
        assert_ne!(
            source_ip_hash_with_key("192.0.2.1", &a),
            ramflux_crypto::blake3_256_base64url("ramflux.source_ip_hash.v1", b"192.0.2.1")
        );
        Ok(())
    }
}
