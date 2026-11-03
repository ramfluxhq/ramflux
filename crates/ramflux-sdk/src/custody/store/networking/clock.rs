// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Derive a bounded deadline and share its monotonic anchor across account reloads.
use super::{AccountNetworkingReason, NetworkingView, capacity_hint};
use crate::custody::{CAPACITY_RETRY_AFTER_MS, CAPACITY_RETRY_AFTER_SECS, store::StoredAuthority};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::time::Instant;

type Source = (Option<String>, AccountNetworkingReason, u64);
struct Anchor {
    source: Source,
    reason: AccountNetworkingReason,
    deadline: u64,
    until: Instant,
    monotonic: bool,
    clamped: bool,
}

fn normalized(
    reason: &AccountNetworkingReason,
    deadline: u64,
    now: u64,
) -> (AccountNetworkingReason, u64, bool) {
    let mut reason = reason.clone();
    let AccountNetworkingReason::NodeBusy { retry_after_ms, capacity } = &mut reason else {
        return (reason, deadline, false);
    };
    let daily = capacity.is_some();
    *capacity = capacity.filter(|hint| capacity_hint::valid(*hint, now));
    if daily && capacity.is_none() {
        *retry_after_ms = CAPACITY_RETRY_AFTER_MS;
    }
    *retry_after_ms = (*retry_after_ms).clamp(1000, 3_600_000);
    let bound = if capacity.is_some() {
        capacity_hint::MAX_RESET_AHEAD_SECS
    } else {
        (*retry_after_ms).div_ceil(1000)
    };
    let clamped = deadline > now.saturating_add(bound);
    let deadline = if clamped {
        if daily {
            *capacity = None;
            *retry_after_ms = CAPACITY_RETRY_AFTER_MS;
            now.saturating_add(CAPACITY_RETRY_AFTER_SECS)
        } else {
            // Preserve a relative hint's identity so persisting a clock correction
            // can keep the already captured monotonic anchor.
            now.saturating_add(bound)
        }
    } else {
        deadline
    };
    if capacity.is_some() {
        *retry_after_ms = CAPACITY_RETRY_AFTER_MS;
    }
    (reason, deadline, clamped)
}

pub(super) fn clamp(stored: &mut StoredAuthority, now: u64) -> bool {
    let (Some(reason), Some(deadline)) = (&stored.networking_reason, stored.capacity_retry_at)
    else {
        return false;
    };
    let (reason, deadline, _) = normalized(reason, deadline, now);
    let changed = stored.networking_reason.as_ref() != Some(&reason)
        || stored.capacity_retry_at != Some(deadline);
    stored.networking_reason = Some(reason);
    stored.capacity_retry_at = Some(deadline);
    changed
}

fn anchors() -> std::sync::MutexGuard<'static, BTreeMap<PathBuf, Anchor>> {
    static ANCHORS: OnceLock<Mutex<BTreeMap<PathBuf, Anchor>>> = OnceLock::new();
    ANCHORS.get_or_init(Mutex::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn begin_refusal(path: &Path) {
    let _ = anchors().remove(path);
}

pub(super) fn persisted(path: &Path, stored: &StoredAuthority) {
    let (Some(reason), Some(deadline)) = (&stored.networking_reason, stored.capacity_retry_at)
    else {
        return;
    };
    let mut anchors = anchors();
    if let Some(anchor) = anchors.get_mut(path)
        && anchor.source.0 == stored.networking_node
        && anchor.reason == *reason
    {
        // A normalized write is the same refusal, not a new monotonic cooldown.
        anchor.source = (stored.networking_node.clone(), reason.clone(), deadline);
        anchor.deadline = deadline;
    }
}

pub(super) fn view(
    reason: Option<&AccountNetworkingReason>,
    deadline: Option<u64>,
    node: Option<&str>,
    path: &Path,
    now: u64,
) -> Option<NetworkingView> {
    let hint = reason.and_then(|reason| match reason {
        AccountNetworkingReason::NodeBusy { capacity, .. } => *capacity,
        _ => None,
    });
    capacity_hint::log_view_discard(hint, path, node, now);
    let mut anchors = anchors();
    let Some(reason) = reason else {
        anchors.remove(path);
        return None;
    };
    let deadline = deadline.filter(|_| matches!(reason, AccountNetworkingReason::NodeBusy { .. }));
    let Some(deadline) = deadline else {
        anchors.remove(path);
        let mut cause = reason.clone();
        if let AccountNetworkingReason::NodeBusy { capacity, .. } = &mut cause {
            *capacity = capacity.filter(|hint| capacity_hint::valid(*hint, now));
        }
        return Some(NetworkingView { cause, remaining_ms: None, resets_at: None, clamped: false });
    };
    let source = (node.map(str::to_owned), reason.clone(), deadline);
    let (cause, bounded, clamped) = normalized(reason, deadline, now);
    let instant = Instant::now();
    let reuse = anchors.get(path).is_some_and(|old| {
        old.source == source && (old.monotonic || !clamped || old.clamped)
            || old.source.0 == source.0 && old.reason == cause && old.deadline == bounded
    });
    if clamped && (!reuse || anchors.get(path).is_some_and(|anchor| !anchor.clamped)) {
        tracing::info!(clamped = true, "clamped persisted custody capacity deadline");
    }
    if !reuse {
        anchors.insert(
            path.to_owned(),
            Anchor {
                source: source.clone(),
                reason: cause.clone(),
                deadline: bounded,
                until: instant + Duration::from_secs(bounded.saturating_sub(now)),
                monotonic: matches!(
                    cause,
                    AccountNetworkingReason::NodeBusy { capacity: None, .. }
                ),
                clamped,
            },
        );
    }
    let anchor = anchors.get_mut(path)?;
    if clamped {
        anchor.clamped = true;
        // Keep the normalized source in sync after every rollback and persistence pass.
        // The monotonic deadline remains the one captured for this cooldown.
        anchor.deadline = bounded;
    }
    anchor.source = source;
    let remaining = if anchor.monotonic {
        let duration = anchor.until.saturating_duration_since(instant);
        duration.as_secs().saturating_add(u64::from(duration.subsec_nanos() > 0))
    } else {
        anchor.deadline.saturating_sub(now)
    };
    if remaining == 0 {
        return None;
    }
    let mut cause = anchor.reason.clone();
    let mut resets_at = None;
    if let AccountNetworkingReason::NodeBusy { retry_after_ms, capacity } = &mut cause {
        *retry_after_ms = remaining.saturating_mul(1000);
        *capacity = capacity.filter(|hint| hint.resets_at_unix > now);
        resets_at = capacity.map(|hint| hint.resets_at_unix);
    }
    Some(NetworkingView {
        cause,
        remaining_ms: Some(remaining.saturating_mul(1000)),
        resets_at,
        clamped: anchor.clamped,
    })
}
