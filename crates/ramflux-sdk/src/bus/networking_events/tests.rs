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

#[tokio::test(start_paused = true)]
async fn capacity_to_busy_same_hint_emits_networking_changed() -> TestResult {
    let fixture = Fixture::new("capacity-busy-events").await?;
    let now = crate::custody::network_now()?;
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let _ = projected(&account)?;
    let retry = ramflux_protocol::custody::RetryHint::new(
        ramflux_protocol::custody::RetryScope::PreAuthSource,
        300_000,
    );
    record_networking_at(
        &mut account,
        Some(&SdkError::CustodyAdmission {
            code: ramflux_protocol::custody::CustodyRefusal::Capacity,
            retry,
        }),
        now,
    )?;
    let capacity = projected(&account)?;
    assert_eq!(capacity.len(), 1);
    assert!(capacity[0]["networking_reason"]["remaining_ms"].is_number());
    record_networking_at(
        &mut account,
        Some(&SdkError::CustodyAdmission {
            code: ramflux_protocol::custody::CustodyRefusal::Busy,
            retry,
        }),
        now,
    )?;
    let busy = projected(&account)?;
    assert_eq!(busy.len(), 1);
    assert!(busy[0]["networking_reason"]["remaining_ms"].is_null());
    record_networking_at(
        &mut account,
        Some(&SdkError::CustodyAdmission {
            code: ramflux_protocol::custody::CustodyRefusal::Busy,
            retry,
        }),
        now,
    )?;
    assert_eq!(projected(&account)?, Vec::<Value>::new());
    Ok(())
}

fn snapshot() -> super::super::connection_manager::NetworkingSnapshot {
    use super::super::connection_manager::{ConnectionPhase, NetworkingSnapshot, NetworkingState};
    NetworkingSnapshot {
        state: NetworkingState::Live,
        phase: ConnectionPhase::Live,
        generation: 1,
        attempt: 1,
        attempt_started: None,
        attempt_started_at_ms: None,
        next_retry_at_ms: None,
        retry_after_ms: None,
        last_reason: None,
        cause: None,
        active_transport_kind: None,
        session_id: None,
    }
}

async fn session_account(
    id: &str,
) -> Result<(crate::custody::tests::Root, LocalBusAccountState), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(id).await?;
    let mut native =
        crate::custody::load_account(&fixture.root.0, id, crate::custody::network_now()?)?;
    native.mark_live_for_test(&fixture.root.0)?;
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    account.client.born_v3_account = Some(Box::new(native));
    record_networking_at(&mut account, None, crate::custody::network_now()?)?;
    let _ = projected(&account)?;
    Ok((fixture.root, account))
}

#[tokio::test]
async fn session_loss_and_reconnect_of_live_account_emit_pending_then_live() -> TestResult {
    use super::super::connection_manager::{ConnectionPhase, NetworkingState};
    let (_root, account) = session_account("session-cycle").await?;
    let mut view = snapshot();
    record_session(&account, &view)?;
    let mut events = projected(&account)?;
    view.state = NetworkingState::NetworkingPending;
    view.phase = ConnectionPhase::Backoff;
    record_session(&account, &view)?;
    events.extend(projected(&account)?);
    view = snapshot();
    view.generation += 1;
    record_session(&account, &view)?;
    events.extend(projected(&account)?);
    assert_eq!(events.len(), 3);
    for event in &events {
        assert_eq!(event["state"], "live");
    }
    assert_eq!(events[0]["session"]["state"], "live");
    assert_eq!(events[1]["session"]["state"], "networking_pending");
    assert_eq!(events[2]["session"]["state"], "live");
    Ok(())
}

#[tokio::test]
async fn repeated_attempt_failures_with_same_cause_emit_once() -> TestResult {
    let (_root, account) = session_account("session-dedupe").await?;
    let mut view = snapshot();
    view.cause = Some(AccountNetworkingReason::NodeBusy { retry_after_ms: 1000, capacity: None });
    record_session(&account, &view)?;
    view.generation += 1;
    view.retry_after_ms = Some(42);
    view.cause = Some(AccountNetworkingReason::NodeBusy { retry_after_ms: 42, capacity: None });
    assert!(!record_session(&account, &view)?);
    assert_eq!(projected(&account)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn same_kind_refusal_code_or_capacity_change_emits_event() -> TestResult {
    use ramflux_protocol::custody::CustodyRefusal;
    let (_root, account) = session_account("session-semantics").await?;
    let mut view = snapshot();
    for code in [CustodyRefusal::PrincipalIdTaken, CustodyRefusal::Busy] {
        view.cause = Some(AccountNetworkingReason::RegistrationRefused { code });
        assert!(record_session(&account, &view)?);
    }
    for reason in [
        ramflux_protocol::home_migration::Refusal::HomeFork,
        ramflux_protocol::home_migration::Refusal::BaseMismatch,
    ] {
        view.cause = Some(AccountNetworkingReason::RegistrationRefused {
            code: CustodyRefusal::HomeMigration { reason, nack: None },
        });
        assert!(record_session(&account, &view)?);
    }
    for (scope, resets_at_unix) in [
        (CapacityScope::PrefixDaily, 100),
        (CapacityScope::PrefixDaily, 200),
        (CapacityScope::GlobalDaily, 200),
    ] {
        view.cause = Some(AccountNetworkingReason::NodeBusy {
            retry_after_ms: 1000,
            capacity: Some(CapacityHint { scope, resets_at_unix }),
        });
        assert!(record_session(&account, &view)?);
    }
    assert_eq!(projected(&account)?.len(), 7);
    Ok(())
}

#[tokio::test]
async fn custody_record_preserves_session_and_session_record_preserves_custody() -> TestResult {
    let (_root, mut account) = session_account("session-halves").await?;
    let view = snapshot();
    record_session(&account, &view)?;
    let first = projected(&account)?.pop().ok_or("session event")?;
    account.gateway_config.custody.as_mut().ok_or("custody config")?.node_id =
        "other.example".into();
    record_networking_at(&mut account, None, crate::custody::network_now()?)?;
    let second = projected(&account)?.pop().ok_or("custody event")?;
    assert_eq!(first["session"], second["session"]);
    let mut changed = snapshot();
    changed.phase = super::super::connection_manager::ConnectionPhase::Backoff;
    record_session(&account, &changed)?;
    let third = projected(&account)?.pop().ok_or("changed session")?;
    for field in ["account_id", "state", "node_binding", "networking_reason"] {
        assert_eq!(second[field], third[field]);
    }
    Ok(())
}
