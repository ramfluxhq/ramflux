// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Coalesced WAL maintenance shared by workers for the same account database.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Schedule {
    pending: bool,
    running: bool,
    finalizing_erasure: bool,
    last_attempt: Option<Instant>,
}

type AccountSchedules = BTreeMap<PathBuf, Arc<Mutex<Schedule>>>;

pub(crate) struct BackgroundCheckpoint {
    enabled: AtomicBool,
    account: Arc<Mutex<Schedule>>,
    database_path: Option<PathBuf>,
}

impl BackgroundCheckpoint {
    pub(crate) fn for_path(path: &Path) -> Self {
        static ACCOUNTS: OnceLock<Mutex<AccountSchedules>> = OnceLock::new();
        let (account, database_path) = if path == Path::new(":memory:") {
            (Arc::default(), None)
        } else {
            let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
            let mut accounts = ACCOUNTS
                .get_or_init(Mutex::default)
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Keep only scheduling metadata for one interval after the last worker closes.
            accounts.retain(|_, account| {
                Arc::strong_count(account) > 1
                    || account
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .last_attempt
                        .is_some_and(|last| {
                            Instant::now().saturating_duration_since(last) < INTERVAL
                        })
            });
            (accounts.entry(path.clone()).or_default().clone(), Some(path))
        };
        Self { enabled: AtomicBool::new(false), account, database_path }
    }

    pub(crate) fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn request(&self) {
        self.account.lock().unwrap_or_else(std::sync::PoisonError::into_inner).pending = true;
    }

    pub(crate) fn maintain(&self, db: &rusqlite::Connection) {
        self.run_if_due(db, Instant::now());
    }

    pub(crate) fn wait_timeout(&self) -> Option<Duration> {
        if !self.enabled() {
            return None;
        }
        let schedule = self.account.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !schedule.pending || schedule.running {
            return None;
        }
        Some(schedule.last_attempt.map_or(Duration::ZERO, |last| {
            INTERVAL.saturating_sub(Instant::now().saturating_duration_since(last))
        }))
    }

    fn run_if_due(&self, db: &rusqlite::Connection, now: Instant) -> bool {
        if !self.enabled() || !db.is_autocommit() {
            return false;
        }
        let finalizing_erasure = {
            let mut schedule =
                self.account.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !schedule.pending
                || schedule.running
                || schedule
                    .last_attempt
                    .is_some_and(|last| now.saturating_duration_since(last) < INTERVAL)
            {
                return false;
            }
            schedule.pending = false;
            schedule.running = true;
            schedule.last_attempt = Some(now);
            schedule.finalizing_erasure
        };
        let erasure_pending = durable_erasure_pending(db);
        let truncate = finalizing_erasure || matches!(erasure_pending, Ok(true));
        let result = erasure_pending.and_then(|_| checkpoint(db, truncate));
        let mut schedule = self.account.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        schedule.running = false;
        match result {
            Ok((busy, frames, _copied))
                if truncate && busy == 0 && frames == 0 && self.wal_is_empty() =>
            {
                if finalizing_erasure {
                    schedule.finalizing_erasure = false;
                } else if let Err(error) = db.execute(
                    "UPDATE runtime_privacy_maintenance SET erasure_pending=0 WHERE singleton=1",
                    [],
                ) {
                    schedule.pending = true;
                    tracing::warn!(%error, "erasure checkpoint completion deferred");
                } else {
                    // Clearing the durable flag creates one new WAL frame. A later turn removes
                    // that frame without delaying a queued request behind two checkpoint calls.
                    schedule.finalizing_erasure = true;
                    schedule.pending = true;
                }
            }
            Ok((busy, frames, copied)) => {
                schedule.pending |= busy != 0 || frames > copied || truncate;
            }
            Err(error) => {
                schedule.pending = true;
                tracing::warn!(%error, "background WAL checkpoint deferred");
            }
        }
        true
    }

    fn wal_is_empty(&self) -> bool {
        let Some(path) = &self.database_path else { return true };
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        std::fs::metadata(PathBuf::from(wal)).map_or(true, |metadata| metadata.len() == 0)
    }
}

pub(crate) fn durable_erasure_pending(db: &rusqlite::Connection) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT erasure_pending<>0 FROM runtime_privacy_maintenance WHERE singleton=1",
        [],
        |row| row.get(0),
    )
}

fn checkpoint(db: &rusqlite::Connection, truncate: bool) -> rusqlite::Result<(i64, i64, i64)> {
    let prior: i64 = db.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    db.busy_timeout(Duration::ZERO)?;
    let mode = if truncate { "TRUNCATE" } else { "PASSIVE" };
    let result = db.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    });
    let restore = u64::try_from(prior.max(0))
        .map(Duration::from_millis)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
        .and_then(|duration| db.busy_timeout(duration));
    match (result, restore) {
        (Ok(values), Ok(())) => Ok(values),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_requests_coalesce_and_share_the_account_rate_limit() -> rusqlite::Result<()> {
        let root = crate::tests::temp_root("checkpoint-rate");
        let first = BackgroundCheckpoint::for_path(&root.join("account.sqlite"));
        let second = BackgroundCheckpoint::for_path(&root.join("account.sqlite"));
        let other = BackgroundCheckpoint::for_path(&root.join("other.sqlite"));
        let db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE runtime_privacy_maintenance(singleton INTEGER PRIMARY KEY,erasure_pending INTEGER NOT NULL); INSERT INTO runtime_privacy_maintenance VALUES(1,0);")?;
        let now = Instant::now();
        first.enable();
        second.enable();
        other.enable();
        first.request();
        other.request();
        assert!(first.run_if_due(&db, now));
        for _ in 0..100 {
            first.request();
            second.request();
        }
        assert!(!second.run_if_due(&db, now + Duration::from_millis(999)));
        assert!(other.run_if_due(&db, now));
        assert!(second.run_if_due(&db, now + INTERVAL));
        assert!(!first.run_if_due(&db, now + INTERVAL * 2));
        db.execute_batch("BEGIN")?;
        first.request();
        assert!(!first.run_if_due(&db, now + INTERVAL * 3));
        db.execute_batch("ROLLBACK")?;
        assert!(first.run_if_due(&db, now + INTERVAL * 3));
        Ok(())
    }

    #[test]
    fn closing_and_reopening_an_account_preserves_the_checkpoint_rate_limit() -> rusqlite::Result<()>
    {
        let path = crate::tests::temp_root("checkpoint-reopen").join("account.sqlite");
        let db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE runtime_privacy_maintenance(singleton INTEGER PRIMARY KEY,erasure_pending INTEGER NOT NULL); INSERT INTO runtime_privacy_maintenance VALUES(1,0);")?;
        let now = Instant::now() + Duration::from_secs(60);
        let first = BackgroundCheckpoint::for_path(&path);
        first.enable();
        first.request();
        assert!(first.run_if_due(&db, now));
        drop(first);
        let reopened = BackgroundCheckpoint::for_path(&path);
        reopened.enable();
        reopened.request();
        assert!(!reopened.run_if_due(&db, now + Duration::from_millis(999)));
        assert!(reopened.run_if_due(&db, now + INTERVAL));
        Ok(())
    }

    #[test]
    fn a_pinned_reader_keeps_erasure_pending_until_a_later_truncate_attempt()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::tests::temp_root("checkpoint-pinned-reader");
        std::fs::create_dir_all(&root)?;
        let path = root.join("account.sqlite");
        let db = rusqlite::Connection::open(&path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=0; CREATE TABLE data(value TEXT); CREATE TABLE runtime_privacy_maintenance(singleton INTEGER PRIMARY KEY,erasure_pending INTEGER NOT NULL); INSERT INTO runtime_privacy_maintenance VALUES(1,0); INSERT INTO data VALUES('private'); PRAGMA wal_checkpoint(TRUNCATE);")?;
        let reader = rusqlite::Connection::open(&path)?;
        reader.execute_batch("BEGIN; SELECT * FROM data;")?;
        db.execute_batch("UPDATE data SET value='erased'; UPDATE runtime_privacy_maintenance SET erasure_pending=1;")?;
        let checkpoint = BackgroundCheckpoint::for_path(&path);
        checkpoint.enable();
        checkpoint.request();
        let now = Instant::now();
        assert!(checkpoint.run_if_due(&db, now));
        assert!(checkpoint.account.lock().map_err(|_| "checkpoint lock")?.pending);
        assert!(!checkpoint.run_if_due(&db, now + INTERVAL / 2));
        reader.execute_batch("COMMIT")?;
        assert!(checkpoint.run_if_due(&db, now + INTERVAL));
        assert_eq!(
            db.query_row("SELECT erasure_pending FROM runtime_privacy_maintenance", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        assert!(checkpoint.run_if_due(&db, now + INTERVAL * 2));
        assert!(!checkpoint.account.lock().map_err(|_| "checkpoint lock")?.pending);
        drop(reader);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
