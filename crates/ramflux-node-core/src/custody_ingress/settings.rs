// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validated startup configuration for custody listener admission.
use crate::NodeCoreError;
use std::{sync::Arc, time::Duration};
fn setting(name: &str, default: usize, max: usize) -> Result<usize, NodeCoreError> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(NodeCoreError::InvalidConfiguration(format!("{name} must be valid UTF-8")));
        }
    };
    parse(name, &value, default, max)
}
fn parse(name: &str, value: &str, default: usize, max: usize) -> Result<usize, NodeCoreError> {
    if value.is_empty() {
        return Ok(default);
    }
    value.parse::<usize>().ok().filter(|n| (1..=max).contains(n)).ok_or_else(|| {
        NodeCoreError::InvalidConfiguration(format!("{name} must be an integer in 1..={max}"))
    })
}
/// Validated per-listener hard ceilings. Empty settings select the defaults.
#[derive(Clone, Copy, Debug)]
pub struct CustodyPoolSettings {
    pub handshakes: usize,
    pub authenticated: usize,
    pub per_principal: usize,
    pub auth_timeout: Duration,
}
impl CustodyPoolSettings {
    /// # Errors
    /// Rejects malformed, zero, non-UTF-8 or out-of-range pool and deadline settings.
    pub fn from_env() -> Result<Self, NodeCoreError> {
        Ok(Self {
            handshakes: setting("RAMFLUX_CUSTODY_HANDSHAKE_POOL", 256, 65536)?,
            authenticated: setting("RAMFLUX_CUSTODY_AUTHENTICATED_POOL", 1024, 65536)?,
            per_principal: custody_authenticated_session_limit()?,
            auth_timeout: custody_auth_timeout()?,
        })
    }
    #[must_use]
    pub fn limiter(self) -> Arc<super::CustodyIngressLimiter> {
        super::CustodyIngressLimiter::with_pools(
            self.handshakes,
            self.authenticated,
            self.per_principal,
            self.auth_timeout,
        )
    }
}
/// # Errors
/// Rejects deadlines outside 1..=10000 milliseconds; empty selects ten seconds.
pub fn custody_auth_timeout() -> Result<Duration, NodeCoreError> {
    Ok(Duration::from_millis(setting("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS", 10000, 10000)? as u64))
}
/// # Errors
/// Rejects per-principal settings outside 1..=64.
pub fn custody_authenticated_session_limit() -> Result<usize, NodeCoreError> {
    setting("RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL", 4, 64)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_pool_settings_are_refused() {
        for name in ["RAMFLUX_CUSTODY_HANDSHAKE_POOL", "RAMFLUX_CUSTODY_AUTHENTICATED_POOL"] {
            for invalid in ["0", "65537", "-1", "abc", " "] {
                assert!(parse(name, invalid, 256, 65536).is_err());
            }
            assert_eq!(parse(name, "", 256, 65536).ok(), Some(256));
            assert_eq!(parse(name, "65536", 256, 65536).ok(), Some(65536));
        }
        assert!(parse("timeout", "10001", 10000, 10000).is_err());
    }
}
