// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent source/root admission tables; authentication runs outside bucket locks.
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
struct Window {
    started: Instant,
    touched: u64,
    count: u32,
    highest_epoch: u64,
}
struct Limits {
    principal: u32,
    source: u32,
    buckets: usize,
}
#[derive(Default)]
struct Buckets {
    windows: BTreeMap<String, Window>,
    order: BTreeSet<(u64, String)>,
    sequence: u64,
}
impl Buckets {
    fn charge(
        &mut self,
        key: String,
        limit: u32,
        capacity: usize,
        epoch: Option<u64>,
        now: Instant,
    ) -> anyhow::Result<()> {
        let mut window = if let Some(window) = self.windows.remove(&key) {
            self.order.remove(&(window.touched, key.clone()));
            window
        } else {
            if self.windows.len() >= capacity
                && let Some((_, oldest)) = self.order.pop_first()
            {
                self.windows.remove(&oldest);
            }
            Window { started: now, touched: 0, count: 0, highest_epoch: 0 }
        };
        if now.saturating_duration_since(window.started) >= Duration::from_secs(60) {
            window.started = now;
            window.count = 0;
            window.highest_epoch = 0;
        }
        self.sequence = self.sequence.wrapping_add(1);
        window.touched = self.sequence;
        let replay = epoch.is_some_and(|epoch| epoch <= window.highest_epoch);
        let admitted = replay || window.count < limit;
        if admitted && !replay {
            window.count += 1;
            if let Some(epoch) = epoch {
                window.highest_epoch = epoch;
            }
        }
        self.order.insert((window.touched, key.clone()));
        self.windows.insert(key, window);
        if !admitted {
            anyhow::bail!("device-set publication rate exceeded");
        }
        Ok(())
    }
}
struct Limiter {
    limits: Limits,
    sources: Mutex<Buckets>,
    roots: Mutex<Buckets>,
}
impl Limiter {
    fn admit(
        &self,
        request: &ramflux_node_core::DeviceSetPublishRequest,
        source: IpAddr,
        now: Instant,
    ) -> anyhow::Result<()> {
        let source_key = source_key(source);
        {
            self.sources.lock().unwrap_or_else(std::sync::PoisonError::into_inner).charge(
                source_key,
                self.limits.source,
                self.limits.buckets,
                None,
                now,
            )?;
        }
        // Signature/canonicalization work holds neither table's mutex. The source limit
        // covers invalid claims; valid fresh roots cannot evict source history.
        request.verify_signature()?;
        let key = request.record.principal_commitment.clone();
        self.roots.lock().unwrap_or_else(std::sync::PoisonError::into_inner).charge(
            key,
            self.limits.principal,
            self.limits.buckets,
            Some(request.record.device_set_epoch),
            now,
        )
    }
}
fn source_key(source: IpAddr) -> String {
    match source {
        IpAddr::V4(ip) => format!("s:{ip}"),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return format!("s:{mapped}");
            }
            let segments = ip.segments();
            format!(
                "s:{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
    }
}
fn configured() -> Result<Limiter, String> {
    fn value(name: &str, default: u32, max: u32) -> Result<u32, String> {
        let value = std::env::var(name)
            .map_or(Ok(default), |v| v.parse::<u32>().map_err(|_| format!("invalid {name}")))?;
        if value == 0 || value > max {
            return Err(format!("{name} out of range"));
        }
        Ok(value)
    }
    Ok(Limiter {
        limits: Limits {
            principal: value("RAMFLUX_GATEWAY_DEVICE_SET_PER_PRINCIPAL_PER_MINUTE", 60, 10000)?,
            source: value("RAMFLUX_GATEWAY_DEVICE_SET_PER_SOURCE_PER_MINUTE", 120, 20000)?,
            buckets: usize::try_from(value("RAMFLUX_GATEWAY_DEVICE_SET_MAX_BUCKETS", 4096, 65536)?)
                .map_err(|_| "bucket size".to_owned())?,
        },
        sources: Mutex::new(Buckets::default()),
        roots: Mutex::new(Buckets::default()),
    })
}
pub(crate) fn admit(
    request: &ramflux_node_core::DeviceSetPublishRequest,
    source: IpAddr,
) -> anyhow::Result<()> {
    static LIMITER: OnceLock<Result<Limiter, String>> = OnceLock::new();
    let limiter = LIMITER.get_or_init(configured).as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
    limiter.admit(request, source, Instant::now())
}
pub(crate) fn admit_request(
    request: &ramflux_transport::GatewayQuicRequest,
    source: IpAddr,
) -> anyhow::Result<()> {
    if request.method == "POST" && request.path == "/mvp2/device-set" {
        admit(&serde_json::from_value(request.body.clone())?, source)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn signed(seed: u8) -> anyhow::Result<ramflux_node_core::DeviceSetPublishRequest> {
        signed_epoch(seed, 1)
    }
    fn signed_epoch(
        seed: u8,
        epoch: u64,
    ) -> anyhow::Result<ramflux_node_core::DeviceSetPublishRequest> {
        let root = ramflux_crypto::create_identity_root(&format!("root-{seed}"), [seed; 32]);
        Ok(ramflux_node_core::DeviceSetPublishRequest {
            root_public_key: ramflux_protocol::encode_base64url(
                root.signing_key.verifying_key().to_bytes(),
            ),
            record: ramflux_crypto::sign_device_set(
                &root,
                ramflux_crypto::DeviceSetSigningInput {
                    principal_kind: ramflux_protocol::PrincipalKind::Human,
                    device_set_epoch: epoch,
                    devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                        device_id: "device".into(),
                        device_epoch: 1,
                        signing_key_commitment: ramflux_protocol::encode_base64url([1; 32]),
                        agreement_key_commitment: ramflux_protocol::encode_base64url([2; 32]),
                        status: ramflux_protocol::DeviceSetStatus::Active,
                        revoked_at: None,
                    }],
                },
            )?,
        })
    }
    fn limiter(buckets: usize) -> Limiter {
        Limiter {
            limits: Limits { principal: 2, source: 120, buckets },
            sources: Mutex::new(Buckets::default()),
            roots: Mutex::new(Buckets::default()),
        }
    }
    #[test]
    fn invalid_claims_cannot_spend_a_victims_root_quota() -> anyhow::Result<()> {
        let limiter = limiter(8);
        let now = Instant::now();
        let victim = signed(11)?;
        let mut junk = victim.clone();
        junk.record.signature = "forged".into();
        for _ in 0..60 {
            assert!(limiter.admit(&junk, "127.0.0.1".parse()?, now).is_err());
        }
        assert!(
            !limiter
                .roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .windows
                .contains_key(&victim.record.principal_commitment)
        );
        limiter.admit(&victim, "127.0.0.2".parse()?, now)?;
        for _ in 0..60 {
            limiter.admit(&victim, "127.0.0.3".parse()?, now)?;
        }
        limiter.admit(&signed_epoch(11, 2)?, "127.0.0.2".parse()?, now)?;
        assert!(limiter.admit(&signed_epoch(11, 3)?, "127.0.0.2".parse()?, now).is_err());
        Ok(())
    }
    #[test]
    fn full_table_evicts_lru_and_ipv6_addresses_share_a_prefix_quota() -> anyhow::Result<()> {
        let limiter = limiter(4);
        let now = Instant::now();
        for seed in 1..40 {
            limiter.admit(
                &signed(seed)?,
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, seed)),
                now,
            )?;
            assert!(
                limiter
                    .sources
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .windows
                    .len()
                    <= 4
            );
            assert!(
                limiter
                    .roots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .windows
                    .len()
                    <= 4
            );
        }
        limiter.admit(&signed(99)?, "127.0.0.99".parse()?, now)?;
        assert_eq!(
            source_key("2001:db8:1:2::1".parse()?),
            source_key("2001:db8:1:2::ffff".parse()?)
        );
        assert_eq!(source_key("::ffff:192.0.2.1".parse()?), source_key("192.0.2.1".parse()?));
        let mut limiter = super::tests::limiter(4096);
        limiter.limits.source = 1;
        limiter.admit(&signed(71)?, "2001:db8:1:2::1".parse()?, now)?;
        assert!(limiter.admit(&signed(72)?, "2001:db8:1:2::2".parse()?, now).is_err());
        limiter.admit(&signed(72)?, "2001:db8:1:2::2".parse()?, now + Duration::from_secs(60))?;
        Ok(())
    }
    #[test]
    fn forty_prefixes_cannot_reset_source_quota_by_churning_valid_roots() -> anyhow::Result<()> {
        let mut limiter = limiter(64);
        limiter.limits.source = 3;
        let now = Instant::now();
        let mut admitted = 0;
        for seed in 1..=200u8 {
            let source = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, seed % 40 + 1));
            admitted += usize::from(limiter.admit(&signed(seed)?, source, now).is_ok());
        }
        assert_eq!(admitted, 40 * 3);
        let sources = limiter.sources.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(sources.windows.len(), 40);
        assert_eq!(sources.order.len(), 40);
        drop(sources);
        let roots = limiter.roots.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(roots.windows.len(), 64);
        assert_eq!(roots.order.len(), 64);
        Ok(())
    }
    #[test]
    fn ordered_eviction_and_window_expiry_keep_both_indexes_bounded() -> anyhow::Result<()> {
        let mut buckets = Buckets::default();
        let now = Instant::now();
        buckets.charge("a".into(), 1, 2, None, now)?;
        buckets.charge("b".into(), 1, 2, None, now)?;
        assert!(buckets.charge("a".into(), 1, 2, None, now).is_err());
        buckets.charge("c".into(), 1, 2, None, now)?;
        assert!(buckets.windows.contains_key("a"));
        assert!(!buckets.windows.contains_key("b"));
        buckets.charge("a".into(), 1, 2, None, now + Duration::from_secs(60))?;
        assert_eq!(buckets.windows.len(), 2);
        assert_eq!(buckets.order.len(), 2);
        Ok(())
    }
}
