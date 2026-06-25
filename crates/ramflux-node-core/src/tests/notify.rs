// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

#[test]
fn notification_policy_uses_six_canonical_delivery_classes() {
    let cases = [
        (
            ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification,
            300,
            ramflux_protocol::PushPriority::Normal,
        ),
        (
            ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            86_400,
            ramflux_protocol::PushPriority::Normal,
        ),
        (
            ramflux_protocol::NotificationDeliveryClass::AiTaskNotification,
            1_800,
            ramflux_protocol::PushPriority::Low,
        ),
        (
            ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification,
            600,
            ramflux_protocol::PushPriority::Normal,
        ),
        (
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification,
            60,
            ramflux_protocol::PushPriority::High,
        ),
        (
            ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification,
            60,
            ramflux_protocol::PushPriority::High,
        ),
    ];

    for (delivery_class, ttl, priority) in cases {
        assert_eq!(notification_default_ttl(&delivery_class), ttl);
        assert_eq!(
            notification_default_priority(&delivery_class, &ramflux_protocol::PushPriority::Normal),
            priority
        );
    }
}

#[test]
fn notification_collapse_keys_follow_delivery_class_table() {
    let mut wake = notification_wake("wake_call_1", 0);
    wake.delivery_class = ramflux_protocol::NotificationDeliveryClass::CallWakeNotification;
    assert_eq!(canonical_collapse_key(&wake, "device_1"), "wake:wake_call_1");

    wake.delivery_class = ramflux_protocol::NotificationDeliveryClass::UserContentNotification;
    assert_eq!(canonical_collapse_key(&wake, "device_1"), "target:device_1:content");

    wake.delivery_class = ramflux_protocol::NotificationDeliveryClass::AiTaskNotification;
    let task_key = canonical_collapse_key(&wake, "device_1");
    assert!(task_key.starts_with("target:device_1:task:"));
    assert!(!task_key.contains("conversation_id"));
}

#[test]
fn notification_dnd_actions_are_coarse_and_non_semantic() {
    let mut wake = notification_wake("wake_ai_1", 0);
    wake.delivery_class = ramflux_protocol::NotificationDeliveryClass::AiTaskNotification;
    wake.priority = ramflux_protocol::PushPriority::Low;
    assert_eq!(
        delivery_action_for_wake(&normalized_notification_wake(&wake, "device_1"), true),
        NotifyDeliveryAction::DropLowPriorityDueToDnd
    );

    wake.delivery_class = ramflux_protocol::NotificationDeliveryClass::UserContentNotification;
    assert_eq!(
        delivery_action_for_wake(&normalized_notification_wake(&wake, "device_1"), true),
        NotifyDeliveryAction::DeferWithRetryAfter
    );

    wake.delivery_class = ramflux_protocol::NotificationDeliveryClass::CallWakeNotification;
    assert_eq!(
        delivery_action_for_wake(&normalized_notification_wake(&wake, "device_1"), true),
        NotifyDeliveryAction::Accept
    );
}

#[test]
fn provider_attempts_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let wake = notification_wake("wake_redacted", 0);
    let entry = NotifyQueueEntry {
        queue_id: "wake_redacted".to_owned(),
        device_delivery_id: "device_1".to_owned(),
        wake: wake.clone(),
        push_alias_hash: "push_alias_hash".to_owned(),
        queued_at: 1_760_000_000,
        expires_at: 1_760_000_300,
        attempt_count: 0,
        status: NotifyQueueStatus::Pending,
        dnd_active: false,
    };
    let prepared = PreparedProviderPush {
        route: DevicePushRoute {
            device_delivery_id: "device_1".to_owned(),
            provider: PushProviderKind::WebPush,
            credential_id: Some("credential_1".to_owned()),
            token: "raw_token_must_not_log".to_owned(),
            endpoint: "https://push.example.test:443/webpush".to_owned(),
            webpush_p256dh: None,
            webpush_auth: None,
            registered_at: 1_760_000_000,
            expires_at: 1_760_010_000,
        },
        credential: ProviderCredential::WebPush(WebPushProviderCredential {
            credential_id: "credential_1".to_owned(),
            vapid_public_key_ref: "env:VAPID_PUBLIC".to_owned(),
            vapid_private_key_ref: "env:VAPID_PRIVATE".to_owned(),
            subject: "mailto:ops@example.test".to_owned(),
            provider_ca_pem_ref: None,
        }),
        payload: ProviderPushPayload {
            wake_id: wake.wake_id,
            provider: PushProviderKind::WebPush,
            delivery_class: wake.delivery_class,
            priority: wake.priority,
            ttl: 300,
            collapse_key: Some("target:device_1:content".to_owned()),
            encrypted_hint: Some("encrypted_hint".to_owned()),
        },
        push_alias_hash: "push_alias_hash".to_owned(),
        collapse_key_hash: "collapse_key_hash".to_owned(),
        action: NotifyDeliveryAction::Accept,
    };

    let attempt = redacted_provider_attempt(&entry, &prepared, true, None);
    let attempt_json = serde_json::to_string(&attempt)?;
    assert!(!attempt_json.contains("raw_token_must_not_log"));
    assert!(!attempt_json.contains("encrypted_hint"));
    assert!(!attempt_json.contains("push.example.test"));
    assert!(attempt_json.contains("push_alias_hash"));
    assert!(attempt_json.contains("collapse_key_hash"));
    Ok(())
}

#[test]
#[ignore = "set RAMFLUX_NOTIFY_BENCH=1 to run the notify commit-writer throughput bench"]
fn notify_commit_writer_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_NOTIFY_BENCH").as_deref() != Ok("1") {
        eprintln!("WRITER_BENCH skipped set RAMFLUX_NOTIFY_BENCH=1 to run");
        return Ok(());
    }

    let thread_count = notify_bench_env_usize("RAMFLUX_NOTIFY_BENCH_THREADS", 64).max(1);
    let total_ops = notify_bench_env_usize("RAMFLUX_NOTIFY_BENCH_TOTAL", 200_000).max(1);
    let store_path = temp_store_path("notify_commit_writer_throughput_bench")?;
    let store = std::sync::Arc::new(NotifyRedbStore::open(&store_path)?);
    let started = std::sync::Arc::new(std::sync::Barrier::new(thread_count + 1));
    let ops_per_thread = total_ops.div_ceil(thread_count);
    let mut workers = Vec::with_capacity(thread_count);

    for thread_index in 0..thread_count {
        let worker_store = std::sync::Arc::clone(&store);
        let worker_started = std::sync::Arc::clone(&started);
        let first_op = thread_index * ops_per_thread;
        let end_op = total_ops.min(first_op + ops_per_thread);
        workers.push(std::thread::spawn(move || -> Result<usize, NodeCoreError> {
            worker_started.wait();
            for op_index in first_op..end_op {
                let wake = notification_wake(&format!("wake_commit_writer_bench_{op_index}"), 300);
                let device_delivery_id = format!("device_commit_writer_bench_{}", op_index % 1024);
                worker_store.queue_wake_for_async_accept(
                    &device_delivery_id,
                    &wake,
                    1_760_000_000 + u64::try_from(op_index % 60).unwrap_or(0),
                    false,
                )?;
            }
            Ok(end_op.saturating_sub(first_op))
        }));
    }

    let begun_at = std::time::Instant::now();
    started.wait();
    let mut completed_ops = 0usize;
    for worker in workers {
        let worker_result = worker
            .join()
            .map_err(|_| std::io::Error::other("notify commit-writer bench worker panicked"))?;
        completed_ops += worker_result?;
    }
    let elapsed = begun_at.elapsed();
    let completed_ops_f64 = f64::from(u32::try_from(completed_ops).unwrap_or(u32::MAX));
    let ops_per_sec = completed_ops_f64 / elapsed.as_secs_f64();
    eprintln!(
        "WRITER_BENCH ops_per_sec={ops_per_sec:.2} total_ops={completed_ops} threads={thread_count} elapsed_ms={:.2}",
        elapsed.as_secs_f64() * 1000.0
    );
    let _removed = std::fs::remove_file(store_path);
    Ok(())
}

fn notify_bench_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|value| value.parse::<usize>().ok()).unwrap_or(default)
}
