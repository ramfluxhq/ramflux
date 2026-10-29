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
    last_attempt: Option<Instant>,
}

type AccountSchedules = BTreeMap<PathBuf, Arc<Mutex<Schedule>>>;

pub(crate) struct BackgroundCheckpoint {
    enabled: AtomicBool,
    account: Arc<Mutex<Schedule>>,
}

impl BackgroundCheckpoint {
    pub(crate) fn for_path(path: &Path) -> Self {
        static ACCOUNTS: OnceLock<Mutex<AccountSchedules>> = OnceLock::new();
        let account = if path == Path::new(":memory:") {
            Arc::default()
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
            accounts.entry(path).or_default().clone()
        };
        Self { enabled: AtomicBool::new(false), account }
    }

    pub(crate) fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
        self.request();
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

    fn run_if_due(&self, db: &rusqlite::Connection, now: Instant) -> bool {
        if !self.enabled() || !db.is_autocommit() {
            return false;
        }
        {
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
        }
        let result = db.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))
        });
        let mut schedule = self.account.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        schedule.running = false;
        match result {
            Ok((busy, frames, copied)) => schedule.pending |= busy != 0 || frames > copied,
            Err(error) => {
                schedule.pending = true;
                tracing::warn!(%error, "background WAL checkpoint deferred");
            }
        }
        true
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
        let now = Instant::now();
        first.enable();
        second.enable();
        other.enable();
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
        let now = Instant::now() + Duration::from_secs(60);
        let first = BackgroundCheckpoint::for_path(&path);
        first.enable();
        assert!(first.run_if_due(&db, now));
        drop(first);
        let reopened = BackgroundCheckpoint::for_path(&path);
        reopened.enable();
        assert!(!reopened.run_if_due(&db, now + Duration::from_millis(999)));
        assert!(reopened.run_if_due(&db, now + INTERVAL));
        Ok(())
    }

    #[test]
    fn a_pinned_reader_defers_remaining_wal_pages_until_a_later_passive_attempt()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::tests::temp_root("checkpoint-pinned-reader");
        std::fs::create_dir_all(&root)?;
        let path = root.join("account.sqlite");
        let db = rusqlite::Connection::open(&path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE data(value TEXT); INSERT INTO data VALUES('private'); PRAGMA wal_checkpoint(TRUNCATE);")?;
        let reader = rusqlite::Connection::open(&path)?;
        reader.execute_batch("BEGIN; SELECT * FROM data;")?;
        db.execute("UPDATE data SET value='erased'", [])?;
        let checkpoint = BackgroundCheckpoint::for_path(&path);
        checkpoint.enable();
        let now = Instant::now();
        assert!(checkpoint.run_if_due(&db, now));
        assert!(checkpoint.account.lock().map_err(|_| "checkpoint lock")?.pending);
        assert!(!checkpoint.run_if_due(&db, now + INTERVAL / 2));
        reader.execute_batch("COMMIT")?;
        assert!(checkpoint.run_if_due(&db, now + INTERVAL));
        assert!(!checkpoint.account.lock().map_err(|_| "checkpoint lock")?.pending);
        drop(reader);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
