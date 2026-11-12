// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, versioned transport admission and runtime-only cookie keys.
use super::{GatewayPreAuthPolicy, GatewayRedbStore, GatewayState, NodeCoreError};
use crate::{GATEWAY_STATE_TABLE, GatewayPreAuthMetrics, NodeSecret, RedactedString};
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const KEY: &str = "pre_auth_admission_v1";
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    version: u32,
    source_scheme: String,
    high_water_unix_seconds: u64,
    buckets: BTreeMap<String, Vec<u64>>,
    metrics: GatewayPreAuthMetrics,
}

pub(super) fn validate_policy(policy: &GatewayPreAuthPolicy) -> Result<(), NodeCoreError> {
    if policy.enabled && policy.per_source_ip_handshake_rate > 60
        || policy.window_seconds > 3600
        || policy.cookie_ttl_seconds > 3600
        || policy.auth_deadline_ms > 10_000
    {
        return Err(NodeCoreError::PreAuthConfigInvalid);
    }
    Ok(())
}

impl GatewayState {
    /// Apply nonsecret runtime policy while retaining source debt and resume signing bytes.
    /// # Errors
    /// Rejects configuration outside the admission bounds.
    pub fn configure_pre_auth_policy(
        &mut self,
        config: &crate::GatewayPreAuthConfig,
    ) -> Result<(), NodeCoreError> {
        let policy = GatewayPreAuthPolicy {
            enabled: config.enabled,
            per_source_ip_handshake_rate: config.per_source_ip_handshake_rate,
            window_seconds: config.window_seconds,
            cookie_ttl_seconds: config.cookie_ttl_seconds,
            auth_deadline_ms: config.auth_deadline_ms,
            cookie_secret: self.pre_auth_policy.cookie_secret.clone(),
        };
        self.set_pre_auth_policy(policy)
    }

    /// # Errors
    /// Rejects invalid mounts, fixture bytes and keys shared with privacy or resume signing.
    pub fn configure_pre_auth_cookie_key(&mut self, path: &Path) -> Result<(), NodeCoreError> {
        let key = NodeSecret::from_file(path)?;
        let encoded = key.with_bytes(|bytes| ramflux_protocol::encode_base64url(bytes));
        let resume_decoded =
            ramflux_protocol::decode_base64url(&self.pre_auth_policy.cookie_secret).ok();
        let reused_resume = key.with_bytes(|bytes| {
            resume_decoded.as_deref() == Some(bytes.as_slice())
                || self.pre_auth_policy.cookie_secret.as_bytes() == bytes.as_slice()
        });
        if encoded == self.pre_auth_policy.cookie_secret
            || reused_resume
            || crate::source_ip_hash_with_key("preauth-key-separation", &key)
                == crate::source_ip_hash("preauth-key-separation")
        {
            return Err(NodeCoreError::PreAuthConfigInvalid);
        }
        self.pre_auth_cookie_key = Some(RedactedString::new(encoded));
        Ok(())
    }

    /// # Errors
    /// Rejects invalid configuration, unmigrated debt, or a missing mounted production key.
    pub fn validate_pre_auth_configuration(&self) -> Result<(), NodeCoreError> {
        validate_policy(&self.pre_auth_policy)?;
        if self.pre_auth_policy.enabled {
            if self.pre_auth_legacy {
                return Err(NodeCoreError::PreAuthMigrationRequired);
            }
            if self.pre_auth_cookie_key.is_none() && !cfg!(test) {
                return Err(NodeCoreError::PreAuthConfigInvalid);
            }
        }
        Ok(())
    }

    /// Sample under the caller's state lock, before pruning or admission.
    /// # Errors
    /// Rejects pre-epoch clocks and rollback; equality is allowed.
    pub fn observe_pre_auth_time(&mut self, time: SystemTime) -> Result<u64, NodeCoreError> {
        let now = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NodeCoreError::PreAuthClockInvalid)?
            .as_secs();
        if self.pre_auth_policy.enabled && now < self.pre_auth_time_floor {
            return Err(NodeCoreError::PreAuthClockRollback);
        }
        if self.pre_auth_policy.enabled {
            self.pre_auth_time_floor = now;
        }
        Ok(now)
    }

    /// # Errors
    /// Rejects invalid time, rollback, configuration and admission failures.
    pub fn check_pre_auth_system_time(
        &mut self,
        source: &str,
        cookie: Option<&str>,
        time: SystemTime,
    ) -> Result<crate::GatewayPreAuthDecision, NodeCoreError> {
        if !self.pre_auth_policy.enabled {
            return Ok(crate::GatewayPreAuthDecision::Accepted);
        }
        let now = self.observe_pre_auth_time(time)?;
        self.check_pre_auth(source, cookie, now)
    }

    pub(super) fn admission_bytes(&self) -> Result<Vec<u8>, NodeCoreError> {
        let snapshot = Admission {
            version: 1,
            source_scheme: "transport-peer-v2".into(),
            high_water_unix_seconds: self.pre_auth_time_floor,
            buckets: self.pre_auth_handshakes_by_source_ip.clone(),
            metrics: self.pre_auth_metrics.clone(),
        };
        validate_snapshot(&snapshot, &self.pre_auth_policy)?;
        let bytes = crate::serialize_snapshot_value(&snapshot)?;
        if bytes.len() > MAX_BYTES {
            return Err(NodeCoreError::PreAuthSnapshotInvalid);
        }
        Ok(bytes)
    }
}

fn validate_snapshot(
    snapshot: &Admission,
    policy: &GatewayPreAuthPolicy,
) -> Result<(), NodeCoreError> {
    let rate = policy.per_source_ip_handshake_rate.min(60) as usize;
    if snapshot.version != 1
        || snapshot.source_scheme != "transport-peer-v2"
        || snapshot.buckets.len() > 4096
        || snapshot.buckets.iter().any(|(key, events)| {
            key.len() != 43
                || !ramflux_protocol::decode_base64url(key).is_ok_and(|bytes| {
                    bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == *key
                })
                || events.len() > rate
                || events.iter().any(|at| *at > snapshot.high_water_unix_seconds)
                || events.windows(2).any(|pair| pair[0] > pair[1])
        })
    {
        return Err(NodeCoreError::PreAuthSnapshotInvalid);
    }
    Ok(())
}

impl GatewayRedbStore {
    pub(super) fn load_pre_auth_admission(
        &self,
        state: &mut GatewayState,
    ) -> Result<(), NodeCoreError> {
        let read = self.db.begin_read().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        let table =
            read.open_table(GATEWAY_STATE_TABLE).map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        if let Some(raw) = table.get(KEY).map_err(|e| NodeCoreError::Redb(e.to_string()))? {
            if raw.value().len() > MAX_BYTES {
                return Err(NodeCoreError::PreAuthSnapshotInvalid);
            }
            let snapshot: Admission = serde_json::from_slice(raw.value())
                .map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)?;
            validate_snapshot(&snapshot, &state.pre_auth_policy)?;
            state.pre_auth_time_floor = snapshot.high_water_unix_seconds;
            state.pre_auth_handshakes_by_source_ip = snapshot.buckets;
            state.pre_auth_metrics = snapshot.metrics;
        } else {
            // Old keys and timestamps have no trustworthy source provenance. Do not decode debt.
            for key in [crate::GATEWAY_PRE_AUTH_RATE_STATE_KEY, crate::GATEWAY_PRE_AUTH_METRICS_KEY]
            {
                if let Some(raw) = table.get(key).map_err(|e| NodeCoreError::Redb(e.to_string()))? {
                    if raw.value().len() > MAX_BYTES {
                        return Err(NodeCoreError::PreAuthSnapshotInvalid);
                    }
                    let value: serde_json::Value = serde_json::from_slice(raw.value())
                        .map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)?;
                    state.pre_auth_legacy |= value
                        .as_object()
                        .is_none_or(|object| object.values().any(|v| v.as_u64() != Some(0)));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "gateway_pre_auth_tests.rs"]
mod tests;
