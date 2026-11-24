// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Close and reopen one worker's SQLite descriptor without dropping the `Connection` arc.
//! The account key stays in the caller's memory. Setup SQL may contain that key and is never logged.

use super::{Connection, Job, Worker};
use crate::database_checkpoint::BackgroundCheckpoint;
use rusqlite::{Error, OpenFlags};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, MutexGuard};
use std::thread::JoinHandle;

pub(super) enum WorkerMsg {
    Job(Job),
    Park(SyncSender<Result<(), Error>>),
    Unpark { setup_sql: Option<zeroize::Zeroizing<String>>, reply: SyncSender<Result<(), Error>> },
}

pub(super) struct Started {
    pub sender: SyncSender<WorkerMsg>,
    pub checkpoints: Arc<BackgroundCheckpoint>,
    pub handle: JoinHandle<()>,
}

struct Loop {
    receiver: Receiver<WorkerMsg>,
    db: Option<rusqlite::Connection>,
    path: PathBuf,
    flags: OpenFlags,
    checkpoints: Arc<BackgroundCheckpoint>,
    writer: Option<Arc<crate::account_writer::AccountWriter>>,
    generation: u64,
}

pub(super) fn released_error() -> Error {
    Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        Some("files released".to_owned()),
    )
}

pub(super) fn start(
    path: PathBuf,
    flags: OpenFlags,
    writer: Option<Arc<crate::account_writer::AccountWriter>>,
    generation: u64,
) -> Result<Started, Error> {
    let (sender, receiver) = mpsc::sync_channel(64);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("ramflux-db".to_owned())
        .spawn(move || {
            let opened = open_sqlite(&path, flags);
            match opened {
                Ok(db) => {
                    let checkpoints = Arc::new(BackgroundCheckpoint::for_path(&path));
                    if ready_tx.send(Ok(Arc::clone(&checkpoints))).is_ok() {
                        serve(Loop {
                            receiver,
                            db: Some(db),
                            path,
                            flags,
                            checkpoints,
                            writer,
                            generation,
                        });
                    }
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            }
        })
        .map_err(|_| Error::InvalidQuery)?;
    let checkpoints = ready_rx.recv().map_err(|_| Error::InvalidQuery)??;
    Ok(Started { sender, checkpoints, handle })
}

fn open_sqlite(path: &std::path::Path, flags: OpenFlags) -> Result<rusqlite::Connection, Error> {
    let db = rusqlite::Connection::open_with_flags(path, flags)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(db)
}

fn serve(mut worker: Loop) {
    loop {
        match recv_next(&worker.receiver, &worker.checkpoints) {
            Next::Message(WorkerMsg::Job(job)) => {
                run_job(worker.db.as_mut(), job, &worker.checkpoints);
            }
            Next::Message(WorkerMsg::Park(reply)) => park_db(&mut worker.db, &reply),
            Next::Message(WorkerMsg::Unpark { setup_sql, reply }) => {
                unpark_db(&mut worker.db, &worker.path, worker.flags, setup_sql.as_ref(), &reply);
            }
            Next::Timeout => {}
            Next::Disconnected => break,
        }
        maintain(
            worker.db.as_ref(),
            &worker.checkpoints,
            worker.writer.as_ref(),
            worker.generation,
        );
    }
}

enum Next {
    Message(WorkerMsg),
    Timeout,
    Disconnected,
}

fn recv_next(receiver: &Receiver<WorkerMsg>, checkpoints: &BackgroundCheckpoint) -> Next {
    let incoming = if let Some(wait) = checkpoints.wait_timeout() {
        receiver.recv_timeout(wait)
    } else {
        receiver.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected)
    };
    match incoming {
        Ok(message) => Next::Message(message),
        Err(mpsc::RecvTimeoutError::Timeout) => Next::Timeout,
        Err(mpsc::RecvTimeoutError::Disconnected) => Next::Disconnected,
    }
}

fn run_job(db: Option<&mut rusqlite::Connection>, job: Job, checkpoints: &BackgroundCheckpoint) {
    let Some(db) = db else {
        job(None);
        return;
    };
    let changes = db.total_changes();
    let transaction = !db.is_autocommit();
    job(Some(db));
    if checkpoints.enabled()
        && (db.total_changes() != changes || transaction && db.is_autocommit())
        && crate::database_checkpoint::durable_erasure_pending(db).unwrap_or(true)
    {
        checkpoints.request();
    }
}

fn park_db(db: &mut Option<rusqlite::Connection>, reply: &SyncSender<Result<(), Error>>) {
    let result = match db.take() {
        Some(connection) => close_parked(connection),
        None => Ok(()),
    };
    let _ = reply.send(result);
}

/// Checkpoint, then `sqlite3_close`. Dropping the connection discards a busy close and
/// leaves the descriptor open; the caller must see that failure. A checkpoint error still
/// attempts the close, so the descriptor is not abandoned on the way out.
fn close_parked(connection: rusqlite::Connection) -> Result<(), Error> {
    if !connection.is_autocommit() {
        let _ = connection.execute_batch("ROLLBACK;");
    }
    let checkpoint = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    let closed = match connection.close() {
        Ok(()) => Ok(()),
        Err((connection, _)) => match connection.close() {
            Ok(()) => Ok(()),
            Err((connection, error)) => {
                drop(connection);
                Err(error)
            }
        },
    };
    checkpoint.and(closed)
}

fn unpark_db(
    db: &mut Option<rusqlite::Connection>,
    path: &std::path::Path,
    flags: OpenFlags,
    setup_sql: Option<&zeroize::Zeroizing<String>>,
    reply: &SyncSender<Result<(), Error>>,
) {
    if db.is_some() {
        let _ = reply.send(Ok(()));
        return;
    }
    let opened = open_sqlite(path, flags).and_then(|connection| {
        if let Some(sql) = setup_sql {
            connection.execute_batch(sql.as_str())?;
        }
        Ok(connection)
    });
    match opened {
        Ok(connection) => {
            *db = Some(connection);
            let _ = reply.send(Ok(()));
        }
        Err(error) => {
            let _ = reply.send(Err(error));
        }
    }
}

fn maintain(
    db: Option<&rusqlite::Connection>,
    checkpoints: &BackgroundCheckpoint,
    writer: Option<&Arc<crate::account_writer::AccountWriter>>,
    account_generation: u64,
) {
    let Some(db) = db else {
        return;
    };
    if let Some(owner) = writer {
        if let Ok(selected) = owner.generation.try_read()
            && *selected == account_generation
        {
            checkpoints.maintain(db);
        }
    } else {
        checkpoints.maintain(db);
    }
}

impl Connection {
    pub(crate) fn release_sqlite(&self) -> Result<(), Error> {
        let _gate = self.lock_gate()?;
        if self.inner.sqlite_closed.load(Ordering::Acquire) {
            return Ok(());
        }
        self.inner.released.store(true, Ordering::Release);
        let (sender, receiver) = mpsc::sync_channel(1);
        self.send_msg(WorkerMsg::Park(sender))?;
        let result = receiver.recv().map_err(|_| Error::InvalidQuery)?;
        self.inner.sqlite_closed.store(true, Ordering::Release);
        self.release_locks();
        result
    }

    pub(crate) fn reopen_sqlite(
        &self,
        setup_sql: Option<zeroize::Zeroizing<String>>,
    ) -> Result<(), Error> {
        let _gate = self.lock_gate()?;
        if !self.inner.released.load(Ordering::Acquire)
            && !self.inner.sqlite_closed.load(Ordering::Acquire)
        {
            return Ok(());
        }
        self.reacquire_locks()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.send_msg(WorkerMsg::Unpark { setup_sql, reply: sender })?;
        match receiver.recv() {
            Ok(Ok(())) => {
                self.inner.sqlite_closed.store(false, Ordering::Release);
                self.inner.released.store(false, Ordering::Release);
                Ok(())
            }
            Ok(Err(error)) => {
                self.release_locks();
                Err(error)
            }
            Err(_) => {
                self.release_locks();
                Err(Error::InvalidQuery)
            }
        }
    }

    fn lock_gate(&self) -> Result<MutexGuard<'_, ()>, Error> {
        self.inner.gate.lock().map_err(|_| Error::InvalidQuery)
    }

    fn send_msg(&self, message: WorkerMsg) -> Result<(), Error> {
        self.inner
            .sender
            .as_ref()
            .ok_or(Error::InvalidQuery)?
            .send(message)
            .map_err(|_| Error::InvalidQuery)
    }

    fn release_locks(&self) {
        if let Some(writer) = &self.inner.account_writer {
            writer.release_lock();
        }
        if let Ok(mut lease) = self.inner.generation_reader.lock() {
            lease.take();
        }
    }

    fn reacquire_locks(&self) -> Result<(), Error> {
        if let Some(writer) = &self.inner.account_writer {
            writer.reacquire_lock().map_err(|_| Error::InvalidQuery)?;
        }
        if !self.inner.keeps_generation_lease {
            return Ok(());
        }
        let mut lease = self.inner.generation_reader.lock().map_err(|_| Error::InvalidQuery)?;
        if lease.is_none() {
            *lease = Some(
                crate::account_generation::GenerationReadLease::acquire(&self.inner.path)
                    .map_err(|_| Error::InvalidQuery)?,
            );
        }
        Ok(())
    }
}

impl Worker {
    pub(super) fn lock_gate_for_dispatch(&self) -> Result<MutexGuard<'_, ()>, Error> {
        self.gate.lock().map_err(|_| Error::InvalidQuery)
    }
}
