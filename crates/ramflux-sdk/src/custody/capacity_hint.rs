// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Presentation and persisted pending-account handling for server-owned daily reset times.
use super::BornAccount;
use crate::SdkError;
use ramflux_protocol::custody::{CapacityHint, CapacityScope};

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub(crate) const MAX_RESET_AHEAD_SECS: u64 = 2 * 86_400;

pub(crate) fn valid(hint: CapacityHint, now: u64) -> bool {
    hint.resets_at_unix > now && hint.resets_at_unix <= now.saturating_add(MAX_RESET_AHEAD_SECS)
}

/// Log a persisted rejected hint once per account binding and value, across reloads.
/// The authority remains unchanged; status reads only update this diagnostic cache.
pub(crate) fn log_view_discard(
    hint: Option<CapacityHint>,
    path: &std::path::Path,
    node: Option<&str>,
    now: u64,
) {
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };
    type Rejected = (Option<String>, CapacityHint);
    static REJECTED: OnceLock<Mutex<BTreeMap<PathBuf, Rejected>>> = OnceLock::new();
    let mut rejected = REJECTED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(hint) = hint.filter(|hint| !valid(*hint, now)) else {
        rejected.remove(path);
        return;
    };
    let source = (node.map(str::to_owned), hint);
    if rejected.get(path) == Some(&source) {
        return;
    }
    rejected.insert(path.to_owned(), source);
    drop(rejected);
    let _ = accepted(hint, now);
}

pub(crate) fn accepted(hint: CapacityHint, now: u64) -> Option<CapacityHint> {
    if valid(hint, now) {
        Some(hint)
    } else {
        tracing::warn!(
            discarded_resets_at_unix = hint.resets_at_unix,
            local_now_unix = now,
            "discarding custody capacity reset outside the future two-day window"
        );
        None
    }
}

pub(crate) fn node_identity(node_id: &str, node_public_key: &str) -> String {
    let mut hash = blake3::Hasher::new();
    for value in [node_id, node_public_key] {
        hash.update(&(value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().to_hex().to_string()
}

pub(crate) fn message(hint: &CapacityHint) -> String {
    let scope = match hint.scope {
        CapacityScope::PrefixDaily => "for your network",
        CapacityScope::GlobalDaily => "for the whole network",
    };
    let reset = i64::try_from(hint.resets_at_unix)
        .ok()
        .and_then(|timestamp| time::OffsetDateTime::from_unix_timestamp(timestamp).ok())
        .and_then(|timestamp| timestamp.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| format!("Unix {} (UTC)", hint.resets_at_unix));
    format!("the network's new-account quota {scope} is used; it resets at {reset}")
}

pub(crate) fn retry_after_ms(hint: CapacityHint, now: u64) -> u64 {
    hint.resets_at_unix.saturating_sub(now).saturating_mul(1000).max(super::CAPACITY_RETRY_AFTER_MS)
}

pub(super) fn check_account(account: &BornAccount, now: u64) -> Result<(), SdkError> {
    account.check_capacity_deadline(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountNetworkingReason;
    #[test]
    fn capacity_hint_messages_preserve_category_and_unhinted_wording() {
        for scope in [CapacityScope::PrefixDaily, CapacityScope::GlobalDaily] {
            let hint = CapacityHint { scope, resets_at_unix: 172_800 };
            let error = SdkError::CustodyCapacity { capacity: hint };
            assert_eq!(
                error.custody_refusal(),
                Some(ramflux_protocol::custody::CustodyRefusal::Capacity)
            );
            let expected = format!(
                "custody networking refused: Capacity; the network's new-account quota {} is used; it resets at 1970-01-03T00:00:00Z",
                if scope == CapacityScope::PrefixDaily {
                    "for your network"
                } else {
                    "for the whole network"
                }
            );
            assert_eq!(error.to_string(), expected);
            let body = crate::bus::io::local_bus_error_body(&error);
            assert_eq!(body.code, "ValidationFailed");
            assert_eq!(
                body.details.as_ref().map(|v| v["capacity"]["resets_at_unix"].clone()),
                Some(172_800.into())
            );
            assert_eq!(retry_after_ms(hint, 170_000), 2_800_000);
            assert_eq!(retry_after_ms(hint, 172_700), 300_000);
        }
        let generic = SdkError::CustodyNetwork(ramflux_protocol::custody::CustodyRefusal::Capacity);
        assert_eq!(generic.to_string(), "custody networking refused: Capacity");
        assert_eq!(generic.capacity_hint(), None);
    }

    #[test]
    fn capacity_hint_survives_pending_account_reload_without_guessing_a_reset()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::custody::tests::{Root, TestVault, create};
        let root = Root::new()?;
        let now = crate::custody::network_now()?;
        let mut account = create(&root.0, "daily-hint", &TestVault::default(), now)?;
        account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
        let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: now + 3600 };
        account.set_networking_reason(
            &root.0,
            Some(AccountNetworkingReason::NodeBusy {
                retry_after_ms: 3_600_000,
                capacity: Some(hint),
            }),
        )?;
        drop(account);
        let restored = crate::custody::load_account(&root.0, "daily-hint", now)?;
        assert_eq!(
            check_account(&restored, hint.resets_at_unix - 1).err().and_then(|e| e.capacity_hint()),
            Some(hint)
        );
        check_account(&restored, hint.resets_at_unix)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "capacity_hint/wire_tests.rs"]
mod wire_tests;
