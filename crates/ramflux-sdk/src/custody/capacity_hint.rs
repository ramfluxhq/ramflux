// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Presentation and persisted pending-account handling for server-owned daily reset times.
use super::BornAccount;
use crate::{AccountNetworkingReason, SdkError};
use ramflux_protocol::custody::{CapacityHint, CapacityScope};

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
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
    if let Some(AccountNetworkingReason::NodeBusy { capacity: Some(capacity), .. }) =
        account.networking_reason()
        && capacity.resets_at_unix > now
    {
        return Err(SdkError::CustodyCapacity { capacity: *capacity });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
