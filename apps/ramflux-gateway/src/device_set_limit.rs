// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded publication admission by principal and actual peer address, before router work.
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
struct Window {
    started: Instant,
    count: u32,
}
struct Limits {
    principal: u32,
    source: u32,
    buckets: usize,
}
struct Limiter {
    limits: Limits,
    windows: BTreeMap<String, Window>,
}
impl Limiter {
    fn admit(&mut self, principal: &str, source: IpAddr, now: Instant) -> anyhow::Result<()> {
        let keys = [
            (format!("p:{principal}"), self.limits.principal),
            (format!("s:{source}"), self.limits.source),
        ];
        self.windows
            .retain(|_, w| now.saturating_duration_since(w.started) < Duration::from_secs(60));
        let additional = keys.iter().filter(|(key, _)| !self.windows.contains_key(key)).count();
        if self.windows.len().saturating_add(additional) > self.limits.buckets {
            anyhow::bail!("device-set admission table full");
        }
        for (key, limit) in &keys {
            if self.windows.get(key).is_some_and(|w| w.count >= *limit) {
                anyhow::bail!("device-set publication rate exceeded");
            }
        }
        for (key, _) in keys {
            self.windows.entry(key).or_insert(Window { started: now, count: 0 }).count += 1;
        }
        Ok(())
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
    }))
}
pub(crate) fn admit(principal: &str, source: IpAddr) -> anyhow::Result<()> {
    static LIMITER: OnceLock<Result<Mutex<Limiter>, String>> = OnceLock::new();
    if principal.len() != 43 || ramflux_protocol::decode_base64url(principal)?.len() != 32 {
        anyhow::bail!("invalid device-set commitment");
    }
    let limiter = LIMITER.get_or_init(configured).as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
    limiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner).admit(
        principal,
        source,
        Instant::now(),
    )
}
pub(crate) fn admit_request(
    request: &ramflux_transport::GatewayQuicRequest,
    source: IpAddr,
) -> anyhow::Result<()> {
    if request.method == "POST" && request.path == "/mvp2/device-set" {
        let principal = request.body["record"]["principal_commitment"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("device-set commitment missing"))?;
        admit(principal, source)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn principal_source_and_memory_budgets_are_atomic_and_expire() -> anyhow::Result<()> {
        let mut limiter = Limiter {
            limits: Limits { principal: 2, source: 3, buckets: 8 },
            windows: BTreeMap::new(),
        };
        let now = Instant::now();
        let first = "127.0.0.1".parse()?;
        let second = "127.0.0.2".parse()?;
        limiter.admit("one", first, now)?;
        limiter.admit("one", first, now)?;
        assert!(limiter.admit("one", second, now).is_err());
        limiter.admit("two", first, now)?;
        assert!(limiter.admit("three", first, now).is_err());
        for i in 0..1000 {
            let _ = limiter.admit(&i.to_string(), second, now);
        }
        assert!(limiter.windows.len() <= 8);
        limiter.admit("one", first, now + Duration::from_secs(60))?;
        Ok(())
    }
}
