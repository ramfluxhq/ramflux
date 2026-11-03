// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validated startup configuration for pre-authentication work and optional node capacity.
use crate::NodeCoreError;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn value(name: &str) -> Result<String, NodeCoreError> {
    if name == "RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL" {
        return Ok(if std::env::var_os(name).is_some_and(|value| !value.is_empty()) {
            "configured".into()
        } else {
            String::new()
        });
    }
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(String::new()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(NodeCoreError::InvalidConfiguration(format!("{name} must be valid UTF-8")))
        }
    }
}
fn parse(name: &str, value: &str, default: usize, max: usize) -> Result<usize, NodeCoreError> {
    if value.is_empty() {
        return Ok(default);
    }
    value.parse::<usize>().ok().filter(|n| (1..=max).contains(n)).ok_or_else(|| {
        NodeCoreError::InvalidConfiguration(format!("{name} must be an integer in 1..={max}"))
    })
}

/// Listener handshake bounds and an optional operator-selected authenticated ceiling.
#[derive(Clone, Copy, Debug)]
pub struct CustodyPoolSettings {
    pub handshakes: usize,
    pub authenticated: Option<usize>,
    pub preauth_per_source: usize,
    pub auth_timeout: Duration,
}
impl CustodyPoolSettings {
    /// # Errors
    /// Rejects malformed, zero, non-UTF-8 or out-of-range settings.
    pub fn from_env() -> Result<Self, NodeCoreError> {
        Self::from_values(value)
    }
    fn from_values(
        mut value: impl FnMut(&str) -> Result<String, NodeCoreError>,
    ) -> Result<Self, NodeCoreError> {
        const OLD: &str = "RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL";
        const A: &str = "RAMFLUX_CUSTODY_AUTHENTICATED_POOL";
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !value(OLD)?.is_empty() && !WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                setting = OLD,
                "ignored: authenticated sessions are not capped per principal"
            );
        }
        let authenticated = value(A)?;
        Ok(Self {
            handshakes: parse(
                "RAMFLUX_CUSTODY_HANDSHAKE_POOL",
                &value("RAMFLUX_CUSTODY_HANDSHAKE_POOL")?,
                256,
                65_536,
            )?,
            authenticated: if authenticated.is_empty() {
                None
            } else {
                Some(parse(A, &authenticated, 1, 1_048_576)?)
            },
            preauth_per_source: parse(
                "RAMFLUX_CUSTODY_PREAUTH_HANDSHAKES_PER_SOURCE",
                &value("RAMFLUX_CUSTODY_PREAUTH_HANDSHAKES_PER_SOURCE")?,
                4,
                4096,
            )?,
            auth_timeout: Duration::from_millis(parse(
                "RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS",
                &value("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS")?,
                10_000,
                10_000,
            )? as u64),
        })
    }
    #[must_use]
    pub fn limiter(self) -> Arc<super::CustodyIngressLimiter> {
        super::CustodyIngressLimiter::with_pools(
            self.handshakes,
            self.authenticated,
            self.preauth_per_source,
            self.auth_timeout,
        )
    }
}

/// Router-only challenge issuance limits; a single prefix limit covers every prefix tier.
#[derive(Clone, Copy, Debug)]
pub struct CustodyIssuanceSettings {
    pub(crate) ip: usize,
    pub(crate) prefix: usize,
    pub(crate) node: usize,
}
impl Default for CustodyIssuanceSettings {
    fn default() -> Self {
        Self { ip: 16, prefix: 32, node: 1024 }
    }
}
impl CustodyIssuanceSettings {
    /// # Errors
    /// Rejects invalid thresholds or any tuple that violates IP <= prefix <= node.
    pub fn new(ip: usize, prefix: usize, node: usize) -> Result<Self, NodeCoreError> {
        for (name, number) in [
            ("RAMFLUX_CUSTODY_CHALLENGES_PER_IP_PER_MINUTE", ip),
            ("RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE", prefix),
            ("RAMFLUX_CUSTODY_CHALLENGES_PER_NODE_PER_MINUTE", node),
        ] {
            if !(1..=65_536).contains(&number) {
                return Err(NodeCoreError::InvalidConfiguration(format!(
                    "{name} must be an integer in 1..=65536"
                )));
            }
        }
        if ip > prefix || prefix > node {
            return Err(NodeCoreError::InvalidConfiguration(
                "RAMFLUX_CUSTODY_CHALLENGES_PER_IP_PER_MINUTE <= RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE <= RAMFLUX_CUSTODY_CHALLENGES_PER_NODE_PER_MINUTE is required".into(),
            ));
        }
        Ok(Self { ip, prefix, node })
    }
    /// # Errors
    /// Rejects malformed, non-UTF-8, out-of-range or unordered router settings.
    pub fn from_env() -> Result<Self, NodeCoreError> {
        Self::from_values(value)
    }
    fn from_values(
        mut value: impl FnMut(&str) -> Result<String, NodeCoreError>,
    ) -> Result<Self, NodeCoreError> {
        let mut read = |name, default| -> Result<_, NodeCoreError> {
            parse(name, &value(name)?, default, 65_536)
        };
        Self::new(
            read("RAMFLUX_CUSTODY_CHALLENGES_PER_IP_PER_MINUTE", 16)?,
            read("RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE", 32)?,
            read("RAMFLUX_CUSTODY_CHALLENGES_PER_NODE_PER_MINUTE", 1024)?,
        )
    }
}
/// # Errors
/// Rejects deadlines outside 1..=10000 milliseconds; empty selects ten seconds.
pub fn custody_auth_timeout() -> Result<Duration, NodeCoreError> {
    Ok(Duration::from_millis(parse(
        "RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS",
        &value("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS")?,
        10_000,
        10_000,
    )? as u64))
}

#[cfg(test)]
mod tests;
