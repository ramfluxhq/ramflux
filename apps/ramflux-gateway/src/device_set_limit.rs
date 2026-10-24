// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source admission before authentication; root admission only after signature verification.
use std::{
    collections::BTreeMap,
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
struct Limiter {
    limits: Limits,
    windows: BTreeMap<String, Window>,
    sequence: u64,
}
impl Limiter {
    fn charge(&mut self, key: String, limit: u32, now: Instant) -> anyhow::Result<()> {
        self.windows
            .retain(|_, w| now.saturating_duration_since(w.started) < Duration::from_secs(60));
        if !self.windows.contains_key(&key)
            && self.windows.len() >= self.limits.buckets
            && let Some(oldest) =
                self.windows.iter().min_by_key(|(_, w)| w.touched).map(|(key, _)| key.clone())
        {
            self.windows.remove(&oldest);
        }
        self.sequence = self.sequence.wrapping_add(1);
        let window = self.windows.entry(key).or_insert(Window {
            started: now,
            touched: self.sequence,
            count: 0,
            highest_epoch: 0,
        });
        window.touched = self.sequence;
        if window.count >= limit {
            anyhow::bail!("device-set publication rate exceeded");
        }
        window.count += 1;
        Ok(())
    }
    fn admit(
        &mut self,
        request: &ramflux_node_core::DeviceSetPublishRequest,
        source: IpAddr,
        now: Instant,
    ) -> anyhow::Result<()> {
        self.charge(source_key(source), self.limits.source, now)?;
        request.verify_signature()?;
        let key = format!("p:{}", request.record.principal_commitment);
        if let Some(window) = self.windows.get_mut(&key)
            && request.record.device_set_epoch <= window.highest_epoch
        {
            // Publicly replayable signed records cannot exhaust the owner's mutation quota.
            // Source admission still limits every request, and the node rejects stale/conflicting epochs.
            window.touched = self.sequence;
            return Ok(());
        }
        self.charge(key.clone(), self.limits.principal, now)?;
        if let Some(window) = self.windows.get_mut(&key) {
            window.highest_epoch = request.record.device_set_epoch;
        }
        Ok(())
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
fn configured() -> Result<Mutex<Limiter>, String> {
    fn value(name: &str, default: u32, max: u32) -> Result<u32, String> {
        let value = std::env::var(name)
            .map_or(Ok(default), |v| v.parse::<u32>().map_err(|_| format!("invalid {name}")))?;
        if value == 0 || value > max {
            return Err(format!("{name} out of range"));
        }
        Ok(value)
    }
    Ok(Mutex::new(Limiter {
        limits: Limits {
            principal: value("RAMFLUX_GATEWAY_DEVICE_SET_PER_PRINCIPAL_PER_MINUTE", 60, 10000)?,
            source: value("RAMFLUX_GATEWAY_DEVICE_SET_PER_SOURCE_PER_MINUTE", 120, 20000)?,
            buckets: usize::try_from(value("RAMFLUX_GATEWAY_DEVICE_SET_MAX_BUCKETS", 4096, 65536)?)
                .map_err(|_| "bucket size".to_owned())?,
        },
        windows: BTreeMap::new(),
        sequence: 0,
    }))
}
pub(crate) fn admit(
    request: &ramflux_node_core::DeviceSetPublishRequest,
    source: IpAddr,
) -> anyhow::Result<()> {
    static LIMITER: OnceLock<Result<Mutex<Limiter>, String>> = OnceLock::new();
    let limiter = LIMITER.get_or_init(configured).as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
    limiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner).admit(
        request,
        source,
        Instant::now(),
    )
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
            windows: BTreeMap::new(),
            sequence: 0,
        }
    }
    #[test]
    fn invalid_claims_cannot_spend_a_victims_root_quota() -> anyhow::Result<()> {
        let mut limiter = limiter(8);
        let now = Instant::now();
        let victim = signed(11)?;
        let mut junk = victim.clone();
        junk.record.signature = "forged".into();
        for _ in 0..60 {
            assert!(limiter.admit(&junk, "127.0.0.1".parse()?, now).is_err());
        }
        assert!(
            !limiter.windows.contains_key(&format!("p:{}", victim.record.principal_commitment))
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
        let mut limiter = limiter(4);
        let now = Instant::now();
        for seed in 1..40 {
            limiter.admit(
                &signed(seed)?,
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, seed)),
                now,
            )?;
            assert!(limiter.windows.len() <= 4);
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
}
