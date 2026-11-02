// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capacity deadline bounds, node changes, and write-free blocked retries.
use super::*;
use crate::custody::tests::{Root, TestVault, create};
use ramflux_protocol::custody::{CapacityHint, CapacityScope, CustodyRefusal};
use std::os::unix::fs::MetadataExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn reason(reset: u64, relative: u64) -> AccountNetworkingReason {
    AccountNetworkingReason::NodeBusy {
        retry_after_ms: relative,
        capacity: Some(CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: reset }),
    }
}

#[test]
fn custody_capacity_reset_bound_and_past_hint_keep_only_the_retry_floor() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "bounded-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    for reset in [now.saturating_sub(1), now + 2 * 86_400 + 1, u64::MAX] {
        account.set_networking_reason_at(&root.0, None, now)?;
        account.set_networking_reason_at(&root.0, Some(reason(reset, 300_000)), now)?;
        assert_eq!(account.stored.capacity_retry_at, Some(now + 300));
        assert!(account.check_capacity_deadline(now + 299).is_err());
        account.check_capacity_deadline(now + 300)?;
        assert!(account.presented_networking_reason(now + 300).is_none());
        if reset > now {
            assert_eq!(
                account.networking_reason(),
                Some(&AccountNetworkingReason::NodeBusy {
                    retry_after_ms: 300_000,
                    capacity: None,
                })
            );
        }
    }
    let edge = now + 2 * 86_400;
    account.set_networking_reason_at(&root.0, Some(reason(edge, 300_000)), now)?;
    assert_eq!(account.stored.capacity_retry_at, Some(edge));
    Ok(())
}

#[test]
fn custody_capacity_hint_changes_node_and_key_without_blocking_the_new_node() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "node-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    account.set_networking_reason_at(&root.0, Some(reason(now + 3600, 300_000)), now)?;
    let mut restored = load_account(&root.0, "node-capacity", now)?;
    restored.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    assert_eq!(
        restored.check_capacity_deadline(now).err().and_then(|e| e.custody_refusal()),
        Some(CustodyRefusal::Capacity)
    );
    for (node, key) in [("node-b", "key-a"), ("node-b", "key-b")] {
        restored.bind_capacity_node(&root.0, node, key, now)?;
        assert!(
            restored.check_capacity_deadline(now).is_ok(),
            "a different node retained the old capacity deadline"
        );
        assert!(restored.networking_reason().is_none());
        assert!(load_account(&root.0, "node-capacity", now)?.networking_reason().is_none());
        restored.set_networking_reason_at(&root.0, Some(reason(now + 3600, 300_000)), now)?;
    }
    Ok(())
}

#[test]
fn custody_capacity_blocked_retry_loop_writes_once_and_displays_remaining_delay() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "stable-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let path = directory(&root.0, "stable-capacity")?.join("authority.json");
    let before = fs::metadata(&path)?.ino();
    account.set_networking_reason_at(&root.0, Some(reason(now + 3600, 3_600_000)), now)?;
    let inode = fs::metadata(&path)?.ino();
    assert_ne!(inode, before, "the first refusal must be persisted");
    let bytes = fs::read(&path)?;
    for elapsed in [1, 2, 10, 100, 3599] {
        let error = crate::custody::capacity_hint::check_account(&account, now + elapsed)
            .err()
            .ok_or("retry unexpectedly admitted")?;
        let capacity = error.capacity_hint().ok_or("hint disappeared")?;
        account.set_networking_reason_at(
            &root.0,
            Some(reason(capacity.resets_at_unix, (3600 - elapsed) * 1000)),
            now + elapsed,
        )?;
        assert_eq!(fs::metadata(&path)?.ino(), inode, "a blocked retry rewrote authority.json");
        assert_eq!(fs::read(&path)?, bytes);
        assert_eq!(
            account.presented_networking_reason(now + elapsed),
            Some(reason(now + 3600, (3600 - elapsed) * 1000,))
        );
    }
    assert!(account.presented_networking_reason(now + 3600).is_none());
    assert_eq!(fs::metadata(&path)?.ino(), inode, "display expiry must not write");
    Ok(())
}

#[test]
fn custody_capacity_old_unbound_hint_is_discarded_on_first_node_binding() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "old-capacity", &TestVault::default(), now)?;
    account.set_networking_reason_at(&root.0, Some(reason(now + 3600, 300_000)), now)?;
    let path = directory(&root.0, "old-capacity")?.join("authority.json");
    let mut legacy: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    let fields = legacy.as_object_mut().ok_or("authority object missing")?;
    fields.remove("networking_node");
    fields.remove("capacity_retry_at");
    fs::write(path, ramflux_protocol::canonical_json_bytes(&legacy)?)?;
    let mut account = load_account(&root.0, "old-capacity", now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    account.check_capacity_deadline(now)?;
    assert!(account.networking_reason().is_none());
    Ok(())
}

#[derive(Clone, Default)]
struct Logs(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
impl tracing::Subscriber for Logs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push(format!("{field}={value:?}"));
            }
        }
        let mut fields = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        fields.push(event.metadata().level().to_string());
        event.record(&mut Fields(&mut fields));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn custody_capacity_rejected_reset_logs_the_discarded_value() -> TestResult {
    let logs = Logs::default();
    let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: u64::MAX };
    let accepted =
        tracing::subscriber::with_default(logs.clone(), || capacity_hint::accepted(hint, 1000));
    assert!(accepted.is_none());
    let text = logs.0.lock().map_err(|_| "log lock")?.join(" ");
    assert_eq!(text.matches("WARN").count(), 1, "{text}");
    assert!(text.contains("discarded_resets_at_unix=18446744073709551615"), "{text}");
    Ok(())
}
