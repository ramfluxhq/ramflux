// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production deadline/courier regressions for operational failures and bad-data backoff.
use super::*;
use crate::client::shared_group::maintenance;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
struct Warnings(Arc<AtomicUsize>);
impl tracing::Subscriber for Warnings {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN
            && event.metadata().target().ends_with("::shared_group::maintenance")
        {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

#[test]
fn storage_failure_stops_real_deadlines_without_bad_data_backoff() -> Result<(), SdkError> {
    let mut f = Fixture::new("deadline-storage-failure")?;
    f.pending(&f.probe)?;
    let reader = f.phone.account_db()?.open_reader()?;
    f.phone.active_account_db = Some(reader);
    let warnings = Warnings::default();
    let _subscriber = tracing::subscriber::set_default(warnings.clone());
    assert!(matches!(
        f.phone.advance_group_transfer_deadlines(f.probe.expires_at + 301),
        Err(SdkError::Storage(StorageError::Sqlite(_)))
    ));
    assert_eq!(f.phone.account_db()?.actor_state_usage(maintenance::BACKOFF)?.0, 0);
    assert_eq!(warnings.0.load(Ordering::Relaxed), 0);
    f.close()
}

#[test]
fn operational_failure_stops_scan_after_first_real_sqlite_or_io_failure() -> Result<(), SdkError> {
    let f = Fixture::new("deadline-first-operational-error")?;
    let db = f.phone.account_db()?;
    for id in ["test-deadline/a", "test-deadline/b"] {
        db.persist_actor_state(id, &1)?;
    }
    let reader = db.open_reader()?;
    for filesystem in [false, true] {
        let mut visited = 0;
        let result = maintenance::scan(db, "test-deadline/", now_unix_timestamp(), 128, |_| {
            visited += 1;
            if filesystem {
                std::fs::read(f.path.join("does-not-exist"))?;
                Ok(())
            } else {
                reader.write_transaction(|| -> Result<(), SdkError> { Ok(()) })
            }
        });
        if filesystem {
            assert!(matches!(result, Err(SdkError::Io(_))));
        } else {
            assert!(matches!(result, Err(SdkError::Storage(StorageError::Sqlite(_)))));
        }
        assert_eq!(visited, 1, "a failed database/filesystem must not be retried for every key");
        assert_eq!(db.actor_state_usage(maintenance::BACKOFF)?.0, 0);
    }
    drop(reader);
    f.close()
}

#[test]
fn normal_cancellation_scan_does_not_require_writer_transaction() -> Result<(), SdkError> {
    let mut f = Fixture::new("cancel-read-only")?;
    f.phone.stage_group_transfer_control(TransferControl::sign(
        &f.phone,
        TransferBody::Probe { probe: Box::new(f.probe.clone()) },
    )?)?;
    let reader = f.phone.account_db()?.open_reader()?;
    f.phone.active_account_db = Some(reader);
    f.phone.advance_group_transfer_deadlines(f.probe.issued_at)?;
    f.close()
}

#[test]
fn broken_pending_page_backs_off_and_later_healthy_proposal_advances() -> Result<(), SdkError> {
    let f = Fixture::new("pending-backoff-page")?;
    let db = f.phone.account_db()?;
    f.pending(&f.probe)?;
    db.write_transaction(|| -> Result<(), SdkError> {
        for n in 0..128 {
            db.persist_actor_state(
                &format!("{PENDING}!bad-{n:03}"),
                &serde_json::json!({"bad":true}),
            )?;
        }
        Ok(())
    })?;
    let now = f.probe.expires_at + 301;
    let warnings = Warnings::default();
    let _subscriber = tracing::subscriber::set_default(warnings.clone());
    f.phone.advance_group_transfer_deadlines(now)?;
    assert!(db.actor_state_exists(&key(PENDING, "group"))?, "first scan stays bounded");
    assert_eq!(db.actor_state_usage(maintenance::BACKOFF)?.0, 128);
    // The SQL eligibility filter must apply before LIMIT, even at the same clock instant.
    f.phone.advance_group_transfer_deadlines(now)?;
    assert!(!db.actor_state_exists(&key(PENDING, "group"))?, "poisoned rows must not pin page one");
    assert_eq!(warnings.0.load(Ordering::Relaxed), 1);
    f.close()
}

#[test]
fn broken_lease_backoff_survives_reader_restart_and_never_releases_a_fence() -> Result<(), SdkError>
{
    let f = Fixture::new("lease-backoff-repair")?;
    f.laptop.reserve_group_transfer(&f.probe, &f.base)?;
    let db = f.laptop.account_db()?;
    let id = key(LEASE, "group");
    let valid = db
        .load_actor_state::<serde_json::Value>(&id)?
        .ok_or(StorageError::AuthorizationRejected)?;
    db.persist_actor_state(&id, &serde_json::json!({"broken":true}))?;
    let now = f.probe.expires_at + 301;
    f.laptop.advance_group_transfer_deadlines(now)?;
    let reader = db.open_reader()?;
    assert_eq!(maintenance::page(&reader, LEASE, now, 4096)?, Vec::<String>::new());
    assert!(db.actor_state_exists(&id)?, "backoff must not delete security state");
    assert!(f.laptop.check_group_transfer_lease("group", None).is_err());
    db.persist_actor_state(&id, &valid)?;
    f.laptop.advance_group_transfer_deadlines(now + 299)?;
    assert!(db.actor_state_exists(&id)?, "backoff must persist between ticks");
    f.laptop.advance_group_transfer_deadlines(now + 300)?;
    assert!(!db.actor_state_exists(&id)?);
    assert_eq!(db.actor_state_usage(maintenance::BACKOFF)?.0, 0);
    drop(reader);
    f.close()
}

#[test]
fn bad_item_warnings_are_rate_limited_across_retry_and_connection_restart() -> Result<(), SdkError>
{
    let f = Fixture::new("deadline-warning-rate")?;
    let db = f.phone.account_db()?;
    db.persist_actor_state(&format!("{PENDING}!bad"), &serde_json::json!({"bad":true}))?;
    let now = f.probe.expires_at + 301;
    let warnings = Warnings::default();
    let _subscriber = tracing::subscriber::set_default(warnings.clone());
    f.phone.advance_group_transfer_deadlines(now)?;
    f.phone.advance_group_transfer_deadlines(now + 300)?;
    f.phone.advance_group_transfer_deadlines(now + 600)?;
    assert_eq!(warnings.0.load(Ordering::Relaxed), 1);
    let reader = db.open_reader()?;
    assert_eq!(maintenance::page(&reader, PENDING, now + 601, 128)?, Vec::<String>::new());
    f.phone.advance_group_transfer_deadlines(now + 900)?;
    assert_eq!(warnings.0.load(Ordering::Relaxed), 2);
    drop(reader);
    f.close()
}
