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

#[tokio::test(start_paused = true)]
async fn custody_capacity_reset_bound_and_past_hint_keep_only_the_retry_floor() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "bounded-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    for reset in [now.saturating_sub(1), now + 2 * 86_400 + 1, u64::MAX] {
        account.set_networking_reason_at(&root.0, None, now)?;
        account.set_networking_reason_at(&root.0, Some(reason(reset, 300_000)), now)?;
        assert_eq!(account.stored.capacity_retry_at, Some(now + 300));
        assert!(account.check_capacity_deadline(now + 299).is_err());
        tokio::time::advance(std::time::Duration::from_secs(300)).await;
        account.check_capacity_deadline(now + 300)?;
        assert!(account.networking_view(now + 300).is_none());
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
            account.networking_view(now + elapsed).map(|view| view.cause),
            Some(reason(now + 3600, (3600 - elapsed) * 1000,))
        );
    }
    assert!(account.networking_view(now + 3600).is_none());
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
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
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
    for reset in [999, 1000, u64::MAX] {
        let logs = Logs::default();
        let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: reset };
        let accepted =
            tracing::subscriber::with_default(logs.clone(), || capacity_hint::accepted(hint, 1000));
        assert!(accepted.is_none());
        let text = logs.0.lock().map_err(|_| "log lock")?.join(" ");
        assert_eq!(text.matches("WARN").count(), 1, "{text}");
        assert!(text.contains(&format!("discarded_resets_at_unix={reset}")), "{text}");
    }
    Ok(())
}

// Mutation: replace the normalized deadline clamp with `let clamped = false`.
#[tokio::test(start_paused = true)]
async fn custody_capacity_clock_rollback_clamps_load_and_persist_and_keeps_monotonic_anchor()
-> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    // The signed authority must predate every simulated wall-clock value.
    let mut account = create(&root.0, "clock-capacity", &TestVault::default(), now - 7 * 86_400)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let path = directory(&root.0, "clock-capacity")?.join("authority.json");
    let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    saved["networking_reason"] = serde_json::to_value(AccountNetworkingReason::NodeBusy {
        retry_after_ms: CAPACITY_RETRY_AFTER_MS,
        capacity: None,
    })?;
    saved["capacity_retry_at"] = (now + 3 * 86_400).into();
    fs::write(&path, ramflux_protocol::canonical_json_bytes(&saved)?)?;
    let mut loaded = load_account(&root.0, "clock-capacity", now)?;
    let view = loaded.networking_view(now).ok_or("missing clamped view")?;
    assert!(view.remaining_ms.is_some_and(|ms| ms > 0 && ms <= 300_000));
    assert!(view.clamped);
    loaded.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    assert_eq!(saved["capacity_retry_at"], now + 300, "persist must also clamp");
    tokio::time::advance(std::time::Duration::from_secs(299)).await;
    let backwards = now.saturating_sub(3 * 86_400);
    for wall in [backwards, now.saturating_sub(6 * 86_400)] {
        let mut loaded = load_account(&root.0, "clock-capacity", wall)?;
        assert_eq!(loaded.networking_view(wall).ok_or("floor vanished")?.remaining_ms, Some(1000));
        loaded.bind_capacity_node(&root.0, "node-a", "key-a", wall)?;
        let loaded = load_account(&root.0, "clock-capacity", wall)?;
        assert_eq!(
            loaded.networking_view(wall).ok_or("persist renewed floor")?.remaining_ms,
            Some(1000)
        );
    }
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let loaded = load_account(&root.0, "clock-capacity", backwards)?;
    loaded.check_capacity_deadline(backwards)?;
    assert!(loaded.networking_view(backwards).is_none());
    Ok(())
}

// Mutation: accept a hint whose reset is equal to or before the local wall time.
#[test]
fn custody_capacity_past_persisted_reset_is_unhinted_in_view_and_error() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "past-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let path = directory(&root.0, "past-capacity")?.join("authority.json");
    for reset in [now - 1, now] {
        let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        saved["networking_reason"] = serde_json::to_value(reason(reset, 300_000))?;
        saved["capacity_retry_at"] = (now + 300).into();
        fs::write(&path, ramflux_protocol::canonical_json_bytes(&saved)?)?;
        let loaded = load_account(&root.0, "past-capacity", now)?;
        let view = loaded.networking_view(now).ok_or("floor missing")?;
        assert!(view.resets_at.is_none());
        assert!(matches!(view.cause, AccountNetworkingReason::NodeBusy { capacity: None, .. }));
        let error = loaded.check_capacity_deadline(now).err().ok_or("floor missing")?;
        assert_eq!(error.capacity_hint(), None);
        assert!(!error.to_string().contains("resets at"));
    }
    Ok(())
}

#[test]
fn custody_capacity_clamp_logs_once_and_marks_all_views_until_expiry() -> TestResult {
    // Other custody tests initialize the process-wide daemon logger. Capture INFO in a
    // fresh test process so those global filters cannot hide this event from the subscriber.
    if std::env::var_os("RAMFLUX_CLAMP_LOG_TEST_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "custody::store::networking::tests::custody_capacity_clamp_logs_once_and_marks_all_views_until_expiry", "--nocapture"])
            .env("RAMFLUX_CLAMP_LOG_TEST_CHILD", "1")
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}\n{stderr}");
        return Ok(());
    }
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "clamp-log", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let path = directory(&root.0, "clamp-log")?.join("authority.json");
    let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    saved["networking_reason"] = serde_json::to_value(AccountNetworkingReason::NodeBusy {
        retry_after_ms: CAPACITY_RETRY_AFTER_MS,
        capacity: None,
    })?;
    saved["capacity_retry_at"] = (now + 3 * 86_400).into();
    fs::write(&path, ramflux_protocol::canonical_json_bytes(&saved)?)?;
    let logs = Logs::default();
    tracing::subscriber::with_default(logs.clone(), || -> TestResult {
        for _ in 0..3 {
            let mut loaded = load_account(&root.0, "clamp-log", now)?;
            assert!(loaded.networking_view(now).ok_or("clamp missing")?.clamped);
            loaded.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
            assert!(loaded.networking_view(now).ok_or("clamp lost after persist")?.clamped);
        }
        Ok(())
    })?;
    let text = logs.0.lock().map_err(|_| "log lock")?.join(" ");
    assert_eq!(text.matches("INFO").count(), 1, "{text}");
    assert!(text.contains("clamped=true"), "{text}");
    Ok(())
}

#[test]
fn custody_capacity_hinted_corrupt_deadline_is_clamped_on_load_and_persist() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "hinted-clamp", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let path = directory(&root.0, "hinted-clamp")?.join("authority.json");
    let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    saved["networking_reason"] = serde_json::to_value(reason(now + 3600, 300_000))?;
    saved["capacity_retry_at"] = (now + 3 * 86_400).into();
    fs::write(&path, ramflux_protocol::canonical_json_bytes(&saved)?)?;
    let mut loaded = load_account(&root.0, "hinted-clamp", now)?;
    let view = loaded.networking_view(now).ok_or("clamped view missing")?;
    assert!(view.remaining_ms.is_some_and(|ms| ms > 0 && ms <= 300_000));
    assert!(view.clamped);
    assert!(matches!(view.cause, AccountNetworkingReason::NodeBusy { capacity: None, .. }));
    loaded.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    assert_eq!(saved["capacity_retry_at"], now + 300);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn custody_capacity_forward_wall_step_keeps_the_active_capture_and_allows_a_new_refusal()
-> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "forward-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let cause = AccountNetworkingReason::NodeBusy {
        retry_after_ms: CAPACITY_RETRY_AFTER_MS,
        capacity: None,
    };
    account.set_networking_reason_at(&root.0, Some(cause.clone()), now)?;
    let path = directory(&root.0, "forward-capacity")?.join("authority.json");
    let captured = fs::read(&path)?;
    let inode = fs::metadata(&path)?.ino();
    assert_eq!(account.networking_view(now).ok_or("floor missing")?.remaining_ms, Some(300_000));
    tokio::time::advance(std::time::Duration::from_secs(100)).await;
    let forward = now + 86_400;
    account.set_networking_reason_at(&root.0, Some(cause.clone()), forward)?;
    assert!(fs::read(&path)? == captured, "a wall-clock step rewrote the active refusal");
    assert_eq!(fs::metadata(&path)?.ino(), inode);
    assert_eq!(
        account.networking_view(forward).ok_or("active floor missing")?.remaining_ms,
        Some(200_000)
    );
    tokio::time::advance(std::time::Duration::from_secs(200)).await;
    assert!(account.networking_view(forward + 200).is_none());
    account.set_networking_reason_at(&root.0, Some(cause), forward + 200)?;
    assert_eq!(
        account.networking_view(forward + 200).ok_or("new refusal missing")?.remaining_ms,
        Some(300_000)
    );
    tokio::time::advance(std::time::Duration::from_secs(299)).await;
    let repeated_wall = forward + 200 - 3600;
    account.set_networking_reason_at(
        &root.0,
        Some(AccountNetworkingReason::NodeBusy {
            retry_after_ms: CAPACITY_RETRY_AFTER_MS,
            capacity: None,
        }),
        repeated_wall,
    )?;
    assert_eq!(
        account.networking_view(repeated_wall).ok_or("rollback floor missing")?.remaining_ms,
        Some(1000)
    );
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert!(account.networking_view(repeated_wall).is_none());
    // A new refusal can share the same wall second after a correction; it is a new floor.
    account.set_networking_reason_at(
        &root.0,
        Some(AccountNetworkingReason::NodeBusy {
            retry_after_ms: CAPACITY_RETRY_AFTER_MS,
            capacity: None,
        }),
        repeated_wall,
    )?;
    assert_eq!(
        account.networking_view(repeated_wall).map(|view| view.remaining_ms),
        Some(Some(300_000)),
        "a new refusal at the repeated wall second lost its floor"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn custody_capacity_server_retry_hint_is_shared_by_two_store_handles() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut first = create(&root.0, "shared-short-hint", &TestVault::default(), now)?;
    first.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    for retry_ms in [30_000, 600_000, 1201] {
        first.set_networking_reason_at(&root.0, None, now)?;
        let error = SdkError::CustodyAdmission {
            code: CustodyRefusal::Capacity,
            retry: ramflux_protocol::custody::RetryHint::new(
                ramflux_protocol::custody::RetryScope::PreAuthSource,
                retry_ms,
            ),
        };
        let cause = Some(AccountNetworkingReason::NodeBusy {
            retry_after_ms: u64::from(error.retry_hint().ok_or("retry hint")?.retry_after_ms),
            capacity: None,
        });
        first.set_networking_error_at(&root.0, cause, &error, now)?;
        // A second process has no in-memory monotonic anchor from the writer.
        clock::begin_refusal(&first.networking_path);
        let mut second = load_account(&root.0, "shared-short-hint", now)?;
        let seconds = u64::from(retry_ms).div_ceil(1000);
        assert_eq!(second.stored.capacity_retry_at, Some(now + seconds));
        let blocked = second.check_capacity_deadline(now).err().ok_or("second handle admitted")?;
        assert_eq!(blocked.custody_refusal(), Some(CustodyRefusal::Capacity));
        assert_eq!(
            second.networking_view(now).ok_or("hint missing")?.remaining_ms,
            Some(seconds * 1000)
        );
        let path = directory(&root.0, "shared-short-hint")?.join("authority.json");
        let bytes = fs::read(&path)?;
        second.set_networking_error_at(
            &root.0,
            Some(AccountNetworkingReason::NodeBusy {
                retry_after_ms: u64::from(
                    blocked.retry_hint().ok_or("blocked retry hint")?.retry_after_ms,
                ),
                capacity: None,
            }),
            &blocked,
            now,
        )?;
        assert_eq!(fs::read(&path)?, bytes, "a blocked second process renewed the deadline");
        tokio::time::advance(std::time::Duration::from_secs(seconds)).await;
        let second = load_account(&root.0, "shared-short-hint", now + seconds)?;
        second.check_capacity_deadline(now + seconds)?;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn custody_capacity_short_hint_keeps_anchor_across_clock_rollback() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut first = create(&root.0, "short-clock", &TestVault::default(), now - 7 * 86_400)?;
    first.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    first.set_networking_error_at(
        &root.0,
        Some(AccountNetworkingReason::NodeBusy { retry_after_ms: 30_000, capacity: None }),
        &SdkError::CustodyAdmission {
            code: CustodyRefusal::Capacity,
            retry: ramflux_protocol::custody::RetryHint::new(
                ramflux_protocol::custody::RetryScope::NodeCapacity,
                30_000,
            ),
        },
        now,
    )?;
    assert_eq!(first.networking_view(now).ok_or("missing hint")?.remaining_ms, Some(30_000));
    tokio::time::advance(std::time::Duration::from_secs(29)).await;
    let backwards = now - 3600;
    let mut second = load_account(&root.0, "short-clock", backwards)?;
    second.bind_capacity_node(&root.0, "node-a", "key-a", backwards)?;
    let restored = load_account(&root.0, "short-clock", backwards)?;
    assert_eq!(restored.networking_view(backwards).ok_or("hint lost")?.remaining_ms, Some(1000));
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    restored.check_capacity_deadline(backwards)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn unhinted_busy_has_no_shared_deadline_or_decaying_view() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut first = create(&root.0, "unhinted-busy", &TestVault::default(), now)?;
    first.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let error = SdkError::CustodyNetwork(CustodyRefusal::Busy);
    let cause = AccountNetworkingReason::NodeBusy { retry_after_ms: 16_000, capacity: None };
    // A new Busy at the same wall second must also clear an old hinted deadline.
    let capacity = SdkError::CustodyAdmission {
        code: CustodyRefusal::Capacity,
        retry: ramflux_protocol::custody::RetryHint::new(
            ramflux_protocol::custody::RetryScope::NodeCapacity,
            16_000,
        ),
    };
    first.set_networking_error_at(&root.0, Some(cause.clone()), &capacity, now)?;
    assert_eq!(first.stored.capacity_retry_at, Some(now + 16));
    first.set_networking_error_at(&root.0, Some(cause.clone()), &error, now)?;
    let path = directory(&root.0, "unhinted-busy")?.join("authority.json");
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    assert!(saved.get("capacity_retry_at").is_none_or(serde_json::Value::is_null));
    assert_eq!(first.stored.capacity_retry_at, None);
    clock::begin_refusal(&first.networking_path);
    tokio::time::advance(std::time::Duration::from_secs(4)).await;
    let second = load_account(&root.0, "unhinted-busy", now + 4)?;
    second.check_capacity_deadline(now + 4)?;
    let view = serde_json::to_value(second.networking_view(now + 4).ok_or("missing Busy")?)?;
    assert_eq!(view, serde_json::to_value(&cause)?);
    assert_eq!(error.custody_refusal(), Some(CustodyRefusal::Busy));
    Ok(())
}

#[test]
fn hinted_busy_does_not_install_a_shared_capacity_deadline() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut first = create(&root.0, "hinted-busy", &TestVault::default(), now)?;
    first.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    for retry_after_ms in [16_000, 30_000, 300_000] {
        let error = SdkError::CustodyAdmission {
            code: CustodyRefusal::Busy,
            retry: ramflux_protocol::custody::RetryHint::new(
                ramflux_protocol::custody::RetryScope::PreAuthSource,
                retry_after_ms,
            ),
        };
        first.set_networking_error_at(
            &root.0,
            Some(AccountNetworkingReason::NodeBusy {
                retry_after_ms: u64::from(retry_after_ms),
                capacity: None,
            }),
            &error,
            now,
        )?;
        assert_eq!(first.stored.capacity_retry_at, None);
        load_account(&root.0, "hinted-busy", now)?.check_capacity_deadline(now)?;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn hinted_busy_after_capacity_clears_shared_deadline_and_preserves_hint_view() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "busy-after-capacity", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let path = directory(&root.0, "busy-after-capacity")?.join("authority.json");
    for retry_after_ms in [30_000, 300_000] {
        let retry = ramflux_protocol::custody::RetryHint::new(
            ramflux_protocol::custody::RetryScope::PreAuthSource,
            retry_after_ms,
        );
        let cause = AccountNetworkingReason::NodeBusy {
            retry_after_ms: u64::from(retry_after_ms),
            capacity: None,
        };
        account.set_networking_error_at(
            &root.0,
            Some(cause.clone()),
            &SdkError::CustodyAdmission { code: CustodyRefusal::Capacity, retry },
            now,
        )?;
        assert_eq!(account.stored.capacity_retry_at, Some(now + u64::from(retry_after_ms) / 1000));
        assert!(account.check_capacity_deadline(now).is_err());
        // The same view shape must not hide a change from Capacity to hinted Busy.
        account.set_networking_error_at(
            &root.0,
            Some(cause.clone()),
            &SdkError::CustodyAdmission { code: CustodyRefusal::Busy, retry },
            now,
        )?;
        assert_eq!(account.stored.capacity_retry_at, None);
        let bytes = fs::read(&path)?;
        let saved: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert!(saved.get("capacity_retry_at").is_none_or(serde_json::Value::is_null));
        // Simulate another process, then read both before and after the old deadline.
        clock::begin_refusal(&account.networking_path);
        tokio::time::advance(std::time::Duration::from_secs(301)).await;
        for elapsed in [0, 1, 301] {
            let loaded = load_account(&root.0, "busy-after-capacity", now + elapsed)?;
            loaded.check_capacity_deadline(now + elapsed)?;
            let view = loaded.networking_view(now + elapsed).ok_or("Busy hint disappeared")?;
            assert_eq!(serde_json::to_value(view)?, serde_json::to_value(&cause)?);
            assert_eq!(fs::read(&path)?, bytes, "a view read rewrote the Busy hint");
        }
    }
    Ok(())
}

// Mutation: drop only the final capacity.filter(reset > now) in clock::view.
// The first read captures a valid hint; the second persisted load reuses that
// anchor while the longer retry floor is still active after the reset.
#[test]
fn custody_persisted_reload_after_captured_reset_requires_the_output_filter() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "captured-reset", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    account.set_networking_reason_at(&root.0, Some(reason(now + 1, 300_000)), now)?;
    let captured = load_account(&root.0, "captured-reset", now)?;
    assert_eq!(captured.networking_view(now).ok_or("capture missing")?.resets_at, Some(now + 1));
    let loaded = load_account(&root.0, "captured-reset", now + 2)?;
    let view = loaded.networking_view(now + 2).ok_or("retry floor missing")?;
    assert!(view.resets_at.is_none());
    assert!(matches!(view.cause, AccountNetworkingReason::NodeBusy { capacity: None, .. }));
    let error = loaded.check_capacity_deadline(now + 2).err().ok_or("retry floor missing")?;
    assert!(error.capacity_hint().is_none());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn legacy_unhinted_capacity_persists_300s_shared_deadline_and_blocks_second_handle()
-> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut first = create(&root.0, "legacy-capacity", &TestVault::default(), now)?;
    first.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let error = SdkError::CustodyNetwork(CustodyRefusal::Capacity);
    first.set_networking_error_at(
        &root.0,
        Some(AccountNetworkingReason::NodeBusy { retry_after_ms: 300_000, capacity: None }),
        &error,
        now,
    )?;
    let second = load_account(&root.0, "legacy-capacity", now)?;
    assert_eq!(second.stored.capacity_retry_at, Some(now + 300));
    assert_eq!(
        second
            .check_capacity_deadline(now + 299)
            .err()
            .ok_or("retry admitted early")?
            .custody_refusal(),
        Some(CustodyRefusal::Capacity)
    );
    tokio::time::advance(std::time::Duration::from_secs(300)).await;
    load_account(&root.0, "legacy-capacity", now + 300)?.check_capacity_deadline(now + 300)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn daily_reset_capacity_then_busy_clears_shared_deadline() -> TestResult {
    let root = Root::new()?;
    let now = capacity_hint::unix_now();
    let mut account = create(&root.0, "daily-busy", &TestVault::default(), now)?;
    account.bind_capacity_node(&root.0, "node-a", "key-a", now)?;
    let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: now + 3600 };
    let cause = reason(now + 3600, 300_000);
    account.set_networking_error_at(
        &root.0,
        Some(cause.clone()),
        &SdkError::CustodyCapacity { capacity: hint },
        now,
    )?;
    assert_eq!(account.stored.capacity_retry_at, Some(now + 3600));
    assert!(account.check_capacity_deadline(now).is_err());
    let busy = SdkError::CustodyAdmission {
        code: CustodyRefusal::Busy,
        retry: ramflux_protocol::custody::RetryHint::new(
            ramflux_protocol::custody::RetryScope::PreAuthSource,
            300_000,
        ),
    };
    account.set_networking_error_at(&root.0, Some(cause.clone()), &busy, now)?;
    assert_eq!(account.stored.capacity_retry_at, None);
    let path = directory(&root.0, "daily-busy")?.join("authority.json");
    let bytes = fs::read(&path)?;
    let saved: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(saved["capacity_retry_at"].is_null());
    clock::begin_refusal(&account.networking_path);
    for elapsed in [0, 1, 3601] {
        let loaded = load_account(&root.0, "daily-busy", now + elapsed)?;
        loaded.check_capacity_deadline(now + elapsed)?;
        assert_eq!(loaded.networking_reason(), Some(&cause));
        let view = loaded.networking_view(now + elapsed).ok_or("missing Busy")?;
        assert!(view.remaining_ms.is_none());
        assert_eq!(fs::read(&path)?, bytes);
    }
    Ok(())
}
