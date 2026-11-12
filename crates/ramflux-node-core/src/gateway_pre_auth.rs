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
const RESERVATION_KEY: &str = "pre_auth_reservation_v2";
const POLICY_REVISION_KEY: &str = "pre_auth_policy_revision_v2";
pub const PRE_AUTH_CHECKPOINT_SECONDS: u64 = 30;
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    version: u32,
    source_scheme: String,
    high_water_unix_seconds: u64,
    buckets: BTreeMap<String, Vec<u64>>,
    metrics: GatewayPreAuthMetrics,
}

/// Bounded admission-only copy; no sessions, frame queues or replay entries.
#[derive(Clone)]
pub struct GatewayAdmissionCheckpoint {
    policy: GatewayPreAuthPolicy,
    admission: Admission,
    revision: u64,
    deadline: u64,
    prior_cooldown: u64,
}
impl GatewayAdmissionCheckpoint {
    fn entries(&self) -> Result<Vec<(&'static str, Vec<u8>)>, NodeCoreError> {
        validate_snapshot(
            &self.admission,
            self.policy.per_source_ip_handshake_rate.min(60) as usize,
        )?;
        let bytes = crate::serialize_snapshot_value(&self.admission)?;
        if bytes.len() > MAX_BYTES {
            return Err(NodeCoreError::PreAuthSnapshotInvalid);
        }
        Ok(vec![
            (crate::GATEWAY_PRE_AUTH_POLICY_KEY, crate::serialize_snapshot_value(&self.policy)?),
            (KEY, bytes),
            (POLICY_REVISION_KEY, crate::serialize_snapshot_value(&self.revision)?),
            (
                RESERVATION_KEY,
                crate::serialize_snapshot_value(&(
                    self.deadline,
                    self.policy.window_seconds,
                    self.prior_cooldown,
                ))?,
            ),
        ])
    }
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
    /// Rejects invalid configuration, a missing mounted production key.
    pub fn validate_pre_auth_configuration(&self) -> Result<(), NodeCoreError> {
        validate_policy(&self.pre_auth_policy)?;
        if self.pre_auth_policy.enabled && self.pre_auth_cookie_key.is_none() {
            return Err(NodeCoreError::PreAuthConfigInvalid);
        }
        Ok(())
    }

    /// Unit fixtures must explicitly install their public fixture key.
    #[cfg(test)]
    pub(crate) fn set_fixture_pre_auth_cookie_key(&mut self) {
        self.pre_auth_cookie_key =
            Some(RedactedString::new(self.pre_auth_policy.cookie_secret.clone()));
    }

    pub(super) fn pre_auth_entries(&self) -> Result<Vec<(&'static str, Vec<u8>)>, NodeCoreError> {
        validate_policy(&self.pre_auth_policy)?;
        Ok(vec![
            (
                crate::GATEWAY_PRE_AUTH_POLICY_KEY,
                crate::serialize_snapshot_value(&self.pre_auth_policy)?,
            ),
            (KEY, self.admission_bytes()?),
            (POLICY_REVISION_KEY, crate::serialize_snapshot_value(&self.pre_auth_policy_revision)?),
        ])
    }

    /// Sample under the caller's state lock, before pruning or admission.
    /// # Errors
    /// Rejects pre-epoch clocks and rollback; equality is allowed.
    pub fn observe_pre_auth_time(&mut self, time: SystemTime) -> Result<u64, NodeCoreError> {
        let now = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NodeCoreError::PreAuthClockInvalid)?
            .as_secs();
        if now < self.pre_auth_time_floor {
            return Err(NodeCoreError::PreAuthClockRollback);
        }
        self.pre_auth_time_floor = now;
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
        let now = self.observe_pre_auth_time(time)?;
        if self.observe_admission_checkpoint_health(now) {
            return Err(NodeCoreError::PreAuthCheckpointUnavailable);
        }
        self.check_pre_auth(source, cookie, now)
    }

    /// Observe reservation liveness without changing the trusted admission clock.
    /// Returns true while checkpoint coverage is unavailable.
    pub fn observe_admission_checkpoint_health(&mut self, now: u64) -> bool {
        let unavailable = self.pre_auth_runtime_deadline.is_some_and(|deadline| now > deadline);
        if unavailable && !self.pre_auth_checkpoint_stalled {
            self.pre_auth_metrics.checkpoint_outages =
                self.pre_auth_metrics.checkpoint_outages.saturating_add(1);
            self.pre_auth_checkpoint_stalled = true;
        }
        unavailable
    }

    /// Reserve the next checkpoint interval before serving Opens. The caller must
    /// publish this deadline only after committing the checkpoint.
    #[must_use]
    pub fn admission_checkpoint(&self, now: u64) -> GatewayAdmissionCheckpoint {
        let floor = self.pre_auth_time_floor.max(now);
        GatewayAdmissionCheckpoint {
            policy: self.pre_auth_policy.clone(),
            admission: Admission {
                version: 1,
                source_scheme: "transport-peer-v2".into(),
                high_water_unix_seconds: floor,
                buckets: self.pre_auth_handshakes_by_source_ip.clone(),
                metrics: self.pre_auth_metrics.clone(),
            },
            revision: self.pre_auth_policy_revision,
            deadline: floor.saturating_add(PRE_AUTH_CHECKPOINT_SECONDS),
            prior_cooldown: self.pre_auth_restart_until,
        }
    }

    /// Exact final floor after all request owners have drained; releases the future reservation.
    #[must_use]
    pub fn final_admission_checkpoint(&self, now: u64) -> GatewayAdmissionCheckpoint {
        let mut checkpoint = self.admission_checkpoint(now);
        checkpoint.deadline = checkpoint.admission.high_water_unix_seconds;
        checkpoint
    }
    /// Decide whether startup must wait for a crash reservation, without evaluating admission.
    /// # Errors
    /// Refuses a host clock below the committed floor, invalid time or a malformed reservation.
    pub fn admission_startup_delay(
        &self,
        time: SystemTime,
    ) -> Result<std::time::Duration, NodeCoreError> {
        let now = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NodeCoreError::PreAuthClockInvalid)?
            .as_secs();
        if now < self.pre_auth_committed_floor {
            return Err(NodeCoreError::PreAuthClockRollback);
        }
        let barrier = UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(self.pre_auth_time_floor))
            .ok_or(NodeCoreError::PreAuthSnapshotInvalid)?;
        let delay = barrier.duration_since(time).unwrap_or(std::time::Duration::ZERO);
        if delay > std::time::Duration::from_secs(PRE_AUTH_CHECKPOINT_SECONDS) {
            return Err(NodeCoreError::PreAuthSnapshotInvalid);
        }
        Ok(delay)
    }

    /// Publish a committed reservation; concurrent debt stays in memory.
    pub fn install_admission_checkpoint(&mut self, checkpoint: &GatewayAdmissionCheckpoint) {
        if self.pre_auth_policy_revision == checkpoint.revision {
            self.pre_auth_committed_floor =
                self.pre_auth_committed_floor.max(checkpoint.admission.high_water_unix_seconds);
            self.pre_auth_runtime_deadline = Some(checkpoint.deadline);
            self.pre_auth_checkpoint_stalled = false;
        }
    }

    /// Record a bounded aggregate worker failure; Opens never emit individual logs.
    pub fn record_admission_checkpoint_failure(&mut self) {
        self.pre_auth_metrics.checkpoint_failures =
            self.pre_auth_metrics.checkpoint_failures.saturating_add(1);
    }

    pub(super) fn admission_bytes(&self) -> Result<Vec<u8>, NodeCoreError> {
        let snapshot = Admission {
            version: 1,
            source_scheme: "transport-peer-v2".into(),
            high_water_unix_seconds: self.pre_auth_time_floor,
            buckets: self.pre_auth_handshakes_by_source_ip.clone(),
            metrics: self.pre_auth_metrics.clone(),
        };
        validate_snapshot(
            &snapshot,
            self.pre_auth_policy.per_source_ip_handshake_rate.min(60) as usize,
        )?;
        let bytes = crate::serialize_snapshot_value(&snapshot)?;
        if bytes.len() > MAX_BYTES {
            return Err(NodeCoreError::PreAuthSnapshotInvalid);
        }
        Ok(bytes)
    }
}

fn validate_snapshot(snapshot: &Admission, rate: usize) -> Result<(), NodeCoreError> {
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
    /// Commit admission metadata without holding the caller's gateway state lock.
    /// # Errors
    /// Rejects stale policy snapshots, invalid data and storage failures.
    pub fn save_admission_checkpoint(
        &self,
        checkpoint: &GatewayAdmissionCheckpoint,
    ) -> Result<(), NodeCoreError> {
        self.write_guard()?.save_admission_checkpoint(checkpoint)
    }

    pub(super) fn save_admission_checkpoint_unlocked(
        &self,
        checkpoint: &GatewayAdmissionCheckpoint,
    ) -> Result<(), NodeCoreError> {
        let entries = checkpoint.entries()?;
        let write = self.db.begin_write().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        {
            let mut table = write
                .open_table(GATEWAY_STATE_TABLE)
                .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
            let revision: u64 = table
                .get(POLICY_REVISION_KEY)
                .map_err(|e| NodeCoreError::Redb(e.to_string()))?
                .map(|raw| serde_json::from_slice(raw.value()))
                .transpose()
                .map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)?
                .unwrap_or_default();
            if revision > checkpoint.revision {
                return Err(NodeCoreError::PreAuthCheckpointStale);
            }
            for (key, bytes) in &entries {
                table
                    .insert(*key, bytes.as_slice())
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
            }
        }
        self.before_admission_commit()?;
        write.commit().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.durable_commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

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
            validate_snapshot(&snapshot, 60)?;
            state.pre_auth_time_floor = snapshot.high_water_unix_seconds;
            state.pre_auth_committed_floor = snapshot.high_water_unix_seconds;
            state.pre_auth_handshakes_by_source_ip = snapshot.buckets;
            state.pre_auth_metrics = snapshot.metrics;
        }
        if let Some(raw) =
            table.get(POLICY_REVISION_KEY).map_err(|e| NodeCoreError::Redb(e.to_string()))?
        {
            state.pre_auth_policy_revision = serde_json::from_slice(raw.value())
                .map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)?;
        }
        if let Some(raw) =
            table.get(RESERVATION_KEY).map_err(|e| NodeCoreError::Redb(e.to_string()))?
        {
            let (floor, window, prior_cooldown): (u64, u64, u64) =
                serde_json::from_slice(raw.value())
                    .map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)?;
            if window > 3600 || prior_cooldown > floor.saturating_add(3600) {
                return Err(NodeCoreError::PreAuthSnapshotInvalid);
            }
            state.pre_auth_time_floor = state.pre_auth_time_floor.max(floor);
            if floor > state.pre_auth_committed_floor.saturating_add(PRE_AUTH_CHECKPOINT_SECONDS) {
                return Err(NodeCoreError::PreAuthSnapshotInvalid);
            }
            state.pre_auth_restart_until = if floor == state.pre_auth_committed_floor {
                prior_cooldown
            } else {
                prior_cooldown
                    .max(floor.saturating_add(window.max(state.pre_auth_policy.window_seconds)))
            };
        }
        state.pre_auth_handshakes_by_source_ip.retain(|_, events| !events.is_empty());
        state.pre_auth_expiry = state
            .pre_auth_handshakes_by_source_ip
            .iter()
            .filter_map(|(source, events)| events.last().map(|at| (*at, source.clone())))
            .collect();
        state.pre_auth_expiry_by_source =
            state.pre_auth_expiry.iter().map(|(at, source)| (source.clone(), *at)).collect();
        Ok(())
    }
}

#[cfg(test)]
#[path = "gateway_pre_auth_tests.rs"]
mod tests;
