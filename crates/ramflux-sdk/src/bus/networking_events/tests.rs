// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Count actual journal projections, including expiry without another networking attempt.
use super::*;
use crate::bus::native_account::{record_networking_at, status_at};
use crate::client::native_test_support::Fixture;
use ramflux_protocol::custody::{CapacityHint, CapacityScope};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn projected(account: &LocalBusAccountState) -> Result<Vec<Value>, SdkError> {
    let db = account.client.account_db()?;
    let mut bodies = Vec::new();
    for entry in db.pending_outbox(1024)? {
        let events = crate::bus::journal::project(&account.client, &entry)?;
        bodies.extend(
            events
                .iter()
                .filter(|(topic, _, _)| topic == "account.networking.changed")
                .map(|(_, body, _)| body.clone()),
        );
        db.journal_outbox(entry.sequence, &events, crate::time::now_unix_timestamp())?;
    }
    Ok(bodies)
}

// Mutation: compare the entire countdown body instead of cause_and_binding().
#[tokio::test(start_paused = true)]
async fn custody_three_blocked_attempts_emit_once_then_binding_and_expiry_emit_once() -> TestResult
{
    let fixture = Fixture::new("event-cadence").await?;
    let now = crate::custody::network_now()?;
    let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: now + 3600 };
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let _ = projected(&account)?;
    for elapsed in [0, 1, 2] {
        record_networking_at(
            &mut account,
            Some(&SdkError::CustodyCapacity { capacity: hint }),
            now + elapsed,
        )?;
    }
    let events = projected(&account)?;
    assert_eq!(events.len(), 1, "blocked attempts must not publish countdown updates");
    let first = events.first().ok_or("first event")?;
    assert_eq!(
        first["networking_reason"],
        status_at(&account, "event-cadence", now)?["networking_reason"]
    );
    assert_eq!(first["networking_reason"]["remaining_ms"], 3_600_000);
    assert_eq!(projected(&account)?, Vec::<Value>::new());
    account.gateway_config.custody.as_mut().ok_or("custody config")?.node_public_key =
        ramflux_protocol::encode_base64url([8; 32]);
    record_networking_at(
        &mut account,
        Some(&SdkError::CustodyCapacity { capacity: hint }),
        now + 3,
    )?;
    let rebound = projected(&account)?;
    assert_eq!(rebound.len(), 1, "a binding change must publish even with the same cause");
    assert_ne!(rebound[0]["node_binding"], first["node_binding"]);
    assert!(!refresh_expired_at(&account, hint.resets_at_unix - 1)?);
    assert_eq!(projected(&account)?, Vec::<Value>::new());
    assert!(
        refresh_expired_at(&account, hint.resets_at_unix)?,
        "expiry must not need a new blocked attempt"
    );
    let ended = projected(&account)?;
    assert_eq!(ended.len(), 1);
    assert!(ended[0]["networking_reason"].is_null());
    assert!(!refresh_expired_at(&account, hint.resets_at_unix + 1)?);
    assert_eq!(projected(&account)?, Vec::<Value>::new());
    Ok(())
}

#[derive(Clone, Default)]
struct Warnings(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
impl tracing::Subscriber for Warnings {
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
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{field}={value:?} ");
            }
        }
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

// Mutation: remove the previously-seen hint guard from log_view_discard().
#[tokio::test(start_paused = true)]
async fn custody_expired_hint_two_status_reads_log_once() -> TestResult {
    if std::env::var_os("RAMFLUX_HINT_EXPIRY_LOG_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "bus::networking_events::tests::custody_expired_hint_two_status_reads_log_once",
                "--nocapture",
            ])
            .env("RAMFLUX_HINT_EXPIRY_LOG_CHILD", "1")
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}\n{stderr}");
        return Ok(());
    }
    let fixture = Fixture::new("expired-status").await?;
    let now = crate::custody::network_now()?;
    let config = fixture.config.custody.as_ref().ok_or("custody config")?;
    let mut native = crate::custody::load_account(&fixture.root.0, "expired-status", now)?;
    native.bind_capacity_node(&fixture.root.0, &config.node_id, &config.node_public_key, now)?;
    native.set_networking_reason_at(
        &fixture.root.0,
        Some(AccountNetworkingReason::NodeBusy {
            retry_after_ms: 300_000,
            capacity: Some(CapacityHint {
                scope: CapacityScope::PrefixDaily,
                resets_at_unix: now + 1,
            }),
        }),
        now,
    )?;
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    record_networking_at(&mut account, None, now)?;
    assert_eq!(
        status_at(&account, "expired-status", now)?["networking_reason"]["capacity"]["resets_at_unix"],
        now + 1
    );
    let warnings = Warnings::default();
    tracing::subscriber::with_default(warnings.clone(), || -> TestResult {
        for _ in 0..2 {
            let status = status_at(&account, "expired-status", now + 2)?;
            assert!(status["networking_reason"]["capacity"].is_null());
            assert!(status["networking_reason"]["resets_at"].is_null());
        }
        assert!(
            refresh_expired_at(&account, now + 2)?,
            "hint expiry is a cause transition even while the floor remains"
        );
        Ok(())
    })?;
    let logs = warnings.0.lock().map_err(|_| "log lock")?;
    assert_eq!(logs.len(), 1, "expired status reads must emit one warning: {logs:?}");
    assert!(logs[0].contains("discarded_resets_at_unix"));
    Ok(())
}
